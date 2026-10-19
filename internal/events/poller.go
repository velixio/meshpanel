package events

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/meshpanel/meshpanel/internal/hs"
)

const expiringWindow = 7 * 24 * time.Hour

// Differ turns successive node snapshots into events. The first snapshot
// only primes it.
type Differ struct {
	prev     map[string]hs.Node
	primed   bool
	expiring map[string]bool // node ids already reported as expiring
	expired  map[string]bool
}

func NewDiffer() *Differ {
	return &Differ{expiring: map[string]bool{}, expired: map[string]bool{}}
}

func nodeEvent(k Kind, n hs.Node, now time.Time) Event {
	return Event{Kind: k, At: now, NodeID: n.ID, NodeName: n.DisplayName(), HSUser: n.UserName(), Tags: n.Tags}
}

func (d *Differ) Diff(all []hs.Node, now time.Time) []Event {
	// Browser SSH sessions come and go as ephemeral nodes; they are not
	// devices anyone wants alerts about.
	next := make([]hs.Node, 0, len(all))
	for _, n := range all {
		if !n.IsWebSSH() {
			next = append(next, n)
		}
	}
	cur := make(map[string]hs.Node, len(next))
	for _, n := range next {
		cur[n.ID] = n
	}
	var out []Event
	if d.primed {
		for _, n := range next {
			p, ok := d.prev[n.ID]
			if !ok {
				out = append(out, nodeEvent(NodeAdded, n, now))
				continue
			}
			if p.Online != n.Online {
				k := NodeOffline
				if n.Online {
					k = NodeOnline
				}
				out = append(out, nodeEvent(k, n, now))
			}
			if p.DisplayName() != n.DisplayName() {
				e := nodeEvent(NodeRenamed, n, now)
				e.Data = map[string]any{"from": p.DisplayName()}
				out = append(out, e)
			}
			if !slices.Equal(sorted(p.Tags), sorted(n.Tags)) {
				out = append(out, nodeEvent(NodeTagsChanged, n, now))
			}
			for _, r := range added(p.AvailableRoutes, n.AvailableRoutes) {
				e := nodeEvent(RouteAdvertised, n, now)
				e.Data = map[string]any{"route": r, "risk": hs.RouteRisk(r)}
				out = append(out, e)
			}
			for _, r := range added(p.ApprovedRoutes, n.ApprovedRoutes) {
				e := nodeEvent(RouteApproved, n, now)
				e.Data = map[string]any{"route": r}
				out = append(out, e)
			}
		}
		for id, p := range d.prev {
			if _, ok := cur[id]; !ok {
				out = append(out, nodeEvent(NodeDeleted, p, now))
			}
		}
	}
	for _, n := range next {
		if n.Expiry == nil || n.Expiry.IsZero() {
			delete(d.expiring, n.ID)
			delete(d.expired, n.ID)
			continue
		}
		left := n.Expiry.Sub(now)
		switch {
		case left <= 0:
			if !d.expired[n.ID] && d.primed {
				e := nodeEvent(KeyExpired, n, now)
				out = append(out, e)
			}
			d.expired[n.ID] = true
		case left < expiringWindow:
			if !d.expiring[n.ID] && d.primed {
				e := nodeEvent(KeyExpiring, n, now)
				e.Data = map[string]any{"expiry": n.Expiry.UTC().Format(time.RFC3339), "days": int(left.Hours() / 24)}
				out = append(out, e)
			}
			d.expiring[n.ID] = true
			delete(d.expired, n.ID)
		default:
			delete(d.expiring, n.ID)
			delete(d.expired, n.ID)
		}
	}
	for id := range d.expiring {
		if _, ok := cur[id]; !ok {
			delete(d.expiring, id)
		}
	}
	d.prev = cur
	d.primed = true
	return out
}

func sorted(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

func added(old, cur []string) []string {
	var out []string
	for _, r := range cur {
		if !slices.Contains(old, r) {
			out = append(out, r)
		}
	}
	return out
}

// Source is the part of hs.Client the poller needs.
type Source interface {
	ListNodes(context.Context) ([]hs.Node, error)
	ListUsers(context.Context) ([]hs.User, error)
}

// Poller reads headscale on an interval, keeps the latest snapshot for page
// rendering, and publishes diffs and health transitions.
type Poller struct {
	src      Source
	bus      *Bus
	interval time.Duration
	differ   *Differ
	now      func() time.Time
	kick     chan struct{}

	mu      sync.RWMutex
	nodes   []hs.Node
	users   []hs.User
	healthy bool
	lastErr error
	lastOK  time.Time
	known   map[string]bool // user names, for user add/delete events
	downed  bool
}

func NewPoller(src Source, bus *Bus, interval time.Duration) *Poller {
	return &Poller{src: src, bus: bus, interval: interval, differ: NewDiffer(), now: time.Now, kick: make(chan struct{}, 1)}
}

func (p *Poller) Run(ctx context.Context) {
	p.Tick(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.kick:
		}
		p.Tick(ctx)
	}
}

// Refresh asks for an immediate poll (after a change made through the panel).
func (p *Poller) Refresh() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *Poller) Tick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	nodes, err := p.src.ListNodes(ctx)
	var users []hs.User
	if err == nil {
		users, err = p.src.ListUsers(ctx)
	}
	now := p.now()
	if err != nil {
		p.mu.Lock()
		p.healthy, p.lastErr = false, err
		first := !p.downed
		p.downed = true
		p.mu.Unlock()
		if first {
			slog.Warn("headscale unreachable", "err", err)
			p.bus.Publish(Event{Kind: HeadscaleDown, At: now, Text: err.Error()})
		}
		return
	}
	evs := p.differ.Diff(nodes, now)
	p.mu.Lock()
	wasDown := p.downed
	p.nodes, p.users, p.healthy, p.lastErr, p.lastOK, p.downed = nodes, users, true, nil, now, false
	names := map[string]bool{}
	for _, u := range users {
		names[u.Name] = true
	}
	if p.known != nil {
		for n := range names {
			if !p.known[n] {
				evs = append(evs, Event{Kind: UserAdded, At: now, HSUser: n})
			}
		}
		for n := range p.known {
			if !names[n] {
				evs = append(evs, Event{Kind: UserDeleted, At: now, HSUser: n})
			}
		}
	}
	p.known = names
	p.mu.Unlock()
	if wasDown {
		slog.Info("headscale reachable again")
		p.bus.Publish(Event{Kind: HeadscaleUp, At: now})
	}
	for _, e := range evs {
		p.bus.Publish(e)
	}
}

func (p *Poller) Snapshot() []hs.Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.nodes)
}

func (p *Poller) Users() []hs.User {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.users)
}

func (p *Poller) Healthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy
}

func (p *Poller) LastError() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastErr
}

func (p *Poller) Node(id string) (hs.Node, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, n := range p.nodes {
		if n.ID == id {
			return n, true
		}
	}
	return hs.Node{}, false
}
