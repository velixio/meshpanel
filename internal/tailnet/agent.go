package tailnet

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// HostInfo is what the agent learns about a machine from Tailscale.
type HostInfo struct {
	OS        string
	OSVersion string
	Device    string
	Tailscale string
	Hostname  string
	Endpoints []string
	HomeDERP  int
	Updated   time.Time
}

// AgentState is the agent's health for the Settings page.
type AgentState struct {
	Running  bool
	Error    string
	LastSync time.Time
	Peers    int
}

var osNames = map[string]string{"linux": "Linux", "windows": "Windows", "macOS": "macOS", "darwin": "macOS", "iOS": "iOS", "android": "Android", "freebsd": "FreeBSD", "openbsd": "OpenBSD", "js": "Browser"}

func hostInfoFrom(h *tailcfg.Hostinfo, eps []netip.AddrPort, derp int, now time.Time) HostInfo {
	hi := HostInfo{OS: h.OS, Device: h.DeviceModel, Hostname: h.Hostname, HomeDERP: derp, Updated: now}
	if n, ok := osNames[h.OS]; ok {
		hi.OS = n
	}
	switch {
	case h.Distro != "":
		hi.OSVersion = strings.TrimSpace(h.Distro + " " + h.DistroVersion)
		if h.OSVersion != "" {
			hi.OSVersion += " (kernel " + h.OSVersion + ")"
		}
	default:
		hi.OSVersion = h.OSVersion
	}
	// "1.84.0-t1234abcd-g…" → "1.84.0"
	hi.Tailscale, _, _ = strings.Cut(h.IPNVersion, "-")
	for _, ep := range eps {
		hi.Endpoints = append(hi.Endpoints, ep.String())
	}
	return hi
}

// Agent is a long-lived tailnet node that reads every peer's host info.
type Agent struct {
	HS         HS
	HSUser     string
	Hostname   string
	ControlURL string
	Dir        string
	Interval   time.Duration
	Debug      bool

	mu    sync.RWMutex
	info  map[string]HostInfo
	state AgentState
}

func (a *Agent) Info(nodeKey string) (HostInfo, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	hi, ok := a.info[nodeKey]
	return hi, ok
}

func (a *Agent) State() AgentState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

func (a *Agent) store(info map[string]HostInfo, at time.Time, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.state.Error = err.Error()
		return
	}
	a.info = info
	a.state = AgentState{Running: true, LastSync: at, Peers: len(info)}
}

func (a *Agent) fail(err error) {
	a.mu.Lock()
	a.state.Running = false
	a.state.Error = err.Error()
	a.mu.Unlock()
}

// Run starts the node and refreshes host info until ctx ends. Failures are
// retried with backoff; the panel keeps working without the agent.
func (a *Agent) Run(ctx context.Context) {
	if a.Interval <= 0 {
		a.Interval = time.Minute
	}
	backoff := 10 * time.Second
	for ctx.Err() == nil {
		err := a.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		a.fail(err)
		slog.Warn("tailnet agent stopped; retrying", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 10*time.Minute)
	}
}

func (a *Agent) runOnce(ctx context.Context) error {
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return err
	}
	s := &tsnet.Server{Dir: a.Dir, Hostname: a.Hostname, ControlURL: a.ControlURL, Logf: quietLogf, UserLogf: quietLogf}
	if a.Debug {
		s.Logf = log.New(os.Stderr, "tsnet-agent: ", log.LstdFlags).Printf
	}
	if !stateExists(a.Dir) {
		key, err := authKey(ctx, a.HS, a.HSUser, false, true)
		if err != nil {
			return err
		}
		s.AuthKey = key
	}
	defer s.Close()
	uctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	_, err := s.Up(uctx)
	cancel()
	if err != nil {
		return fmt.Errorf("joining the tailnet at %s: %w", a.ControlURL, err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	slog.Info("tailnet agent connected", "hostname", a.Hostname, "user", a.HSUser)
	t := time.NewTicker(a.Interval)
	defer t.Stop()
	for {
		if err := a.refresh(ctx, lc); err != nil {
			slog.Debug("tailnet agent refresh", "err", err)
			a.store(nil, time.Time{}, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// tsLocal is the part of tailscale's local client the agent uses.
type tsLocal interface {
	Status(ctx context.Context) (*ipnstate.Status, error)
	WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error)
}

type peerRef struct{ key, ip string }

// peerRefs lists self and every peer with a tailnet address.
func peerRefs(st *ipnstate.Status) []peerRef {
	var out []peerRef
	add := func(ps *ipnstate.PeerStatus) {
		if ps == nil || len(ps.TailscaleIPs) == 0 {
			return
		}
		k, err := ps.PublicKey.MarshalText()
		if err != nil {
			return
		}
		out = append(out, peerRef{key: string(k), ip: ps.TailscaleIPs[0].String()})
	}
	add(st.Self)
	for _, p := range st.Peer {
		add(p)
	}
	return out
}

func (a *Agent) refresh(ctx context.Context, lc tsLocal) error {
	st, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	out := map[string]HostInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sema := make(chan struct{}, 8)
	for _, p := range peerRefs(st) {
		wg.Add(1)
		sema <- struct{}{}
		go func(p peerRef) {
			defer wg.Done()
			defer func() { <-sema }()
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w, err := lc.WhoIs(wctx, p.ip)
			if err != nil || w == nil || w.Node == nil {
				return
			}
			hi := hostInfoFrom(w.Node.Hostinfo.AsStruct(), w.Node.Endpoints, int(w.Node.HomeDERP), now)
			mu.Lock()
			out[p.key] = hi
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	a.store(out, now, nil)
	return nil
}
