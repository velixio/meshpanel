// Package webhook sends meshpanel events to HTTP endpoints: generic JSON
// (signed with HMAC-SHA256), Slack incoming webhooks, or Discord webhooks.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/notify"
)

// Kinds are the events a webhook can subscribe to, in UI order.
var Kinds = func() []events.Kind {
	var k []events.Kind
	for _, w := range events.WatchableKinds {
		k = append(k, w.Kind)
	}
	return append(k, events.RegistrationPending, events.RegistrationDecided, events.Security, events.HeadscaleDown, events.HeadscaleUp)
}()

func deliverable(k events.Kind) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

type NodeRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// Payload is the generic JSON body.
type Payload struct {
	Event   string         `json:"event"`
	Text    string         `json:"text"`
	At      time.Time      `json:"at"`
	Node    *NodeRef       `json:"node,omitempty"`
	User    string         `json:"user,omitempty"`
	Tags    []string       `json:"tags,omitempty"`
	Actor   string         `json:"actor,omitempty"`
	Channel string         `json:"channel,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

func payload(ev events.Event) Payload {
	p := Payload{Event: string(ev.Kind), Text: notify.Text(ev), At: ev.At, User: ev.HSUser, Tags: ev.Tags, Actor: ev.Actor, Channel: ev.Channel, Data: ev.Data}
	if p.At.IsZero() {
		p.At = time.Now()
	}
	if ev.NodeName != "" || ev.NodeID != "" {
		p.Node = &NodeRef{ID: ev.NodeID, Name: ev.NodeName}
	}
	return p
}

// Body renders the request body for a webhook's format.
func Body(format string, ev events.Event) ([]byte, error) {
	p := payload(ev)
	switch format {
	case "slack":
		return json.Marshal(map[string]string{"text": p.Text})
	case "discord":
		return json.Marshal(map[string]string{"content": p.Text})
	}
	return json.Marshal(p)
}

func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type job struct {
	hook    *db.Webhook
	ev      events.Event
	attempt int
}

// Dispatcher delivers events to configured webhooks with retries.
type Dispatcher struct {
	db      *db.DB
	client  *http.Client
	queue   chan job
	backoff []time.Duration
	once    sync.Once
}

func New(d *db.DB) *Dispatcher {
	disp := &Dispatcher{
		db: d, queue: make(chan job, 256),
		backoff: []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second},
	}
	disp.client = newClient(blockedTarget)
	return disp
}

// allowLoopback is for tests whose receivers listen on 127.0.0.1.
func (d *Dispatcher) allowLoopback() {
	d.client = newClient(func(ip netip.Addr) bool { return !ip.IsLoopback() && blockedTarget(ip) })
}

// blockedTarget refuses addresses a webhook must never reach: the panel's
// own host, link-local and other cloud metadata endpoints, unspecified and
// multicast, including IPv4 hidden inside IPv6 (NAT64, 6to4, compatible).
// Private LAN ranges stay allowed (internal chat servers).
func blockedTarget(ip netip.Addr) bool {
	ip = ip.Unmap()
	if v4, ok := embeddedV4(ip); ok && blockedTarget(v4) {
		return true
	}
	for _, p := range metadataPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || ownAddr(ip)
}

// metadataPrefixes are cloud metadata services outside link-local.
var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::/64"),      // AWS IMDS over IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	nat64L    = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour = netip.MustParsePrefix("2002::/16")
	compat    = netip.MustParsePrefix("::/96")
)

// embeddedV4 extracts an IPv4 address carried inside an IPv6 one.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip), nat64L.Contains(ip), compat.Contains(ip):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// ownAddr reports whether ip belongs to one of this host's interfaces (its
// LAN and tailnet addresses reach the panel and headscale like loopback).
// Loopback itself is left to IsLoopback so tests can allow it.
func ownAddr(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if own, ok := netip.AddrFromSlice(n.IP); ok && !own.IsLoopback() && own.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

var errBlocked = errors.New("this address is not allowed for webhooks (loopback, link-local and similar are blocked)")

// newClient checks the address actually dialed, so DNS tricks can't sneak
// past a check made on the hostname. Redirects are not followed.
func newClient(blocked func(netip.Addr) bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || blocked(ap.Addr()) {
				return errBlocked
			}
			return nil
		},
	}
	tr := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 4, IdleConnTimeout: time.Minute}
	return &http.Client{
		Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (d *Dispatcher) startWorkers(ctx context.Context) {
	d.once.Do(func() { d.spawn(ctx) })
}

func (d *Dispatcher) spawn(ctx context.Context) {
	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-d.queue:
					d.deliver(ctx, j)
				}
			}
		}()
	}
}

// Handle queues an event for every webhook that wants it.
func (d *Dispatcher) Handle(ctx context.Context, ev events.Event) {
	if !deliverable(ev.Kind) {
		return
	}
	d.startWorkers(context.WithoutCancel(ctx))
	hooks, err := d.db.ListWebhooks(ctx)
	if err != nil {
		slog.Error("webhooks: listing", "err", err)
		return
	}
	for _, h := range hooks {
		if !h.Enabled || !h.Wants(string(ev.Kind)) {
			continue
		}
		select {
		case d.queue <- job{hook: h, ev: ev}:
		default:
			slog.Warn("webhooks: queue full, dropping event", "hook", h.Name, "kind", ev.Kind)
		}
	}
}

// Send delivers one event now (used by the "Send test" button).
func (d *Dispatcher) Send(ctx context.Context, h *db.Webhook, ev events.Event) error {
	return d.deliverOnce(ctx, h, ev)
}

// deliver makes one attempt. A failure is retried later by a timer, not by
// sleeping here: a worker stuck waiting on one broken endpoint would hold up
// delivery to every healthy one. Blocked addresses never succeed, so they
// aren't retried at all.
func (d *Dispatcher) deliver(ctx context.Context, j job) {
	err := d.deliverOnce(ctx, j.hook, j.ev)
	if err == nil {
		return
	}
	if errors.Is(err, errBlocked) || j.attempt >= len(d.backoff) {
		slog.Warn("webhook delivery failed", "hook", j.hook.Name, "err", err)
		return
	}
	next := job{hook: j.hook, ev: j.ev, attempt: j.attempt + 1}
	time.AfterFunc(d.backoff[j.attempt], func() {
		if ctx.Err() != nil {
			return
		}
		select {
		case d.queue <- next:
		default:
			slog.Warn("webhooks: queue full, dropping retry", "hook", j.hook.Name)
		}
	})
}

type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

func (d *Dispatcher) deliverOnce(ctx context.Context, h *db.Webhook, ev events.Event) error {
	body, err := Body(h.Format, ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "meshpanel-webhook")
	req.Header.Set("X-Meshpanel-Event", string(ev.Kind))
	req.Header.Set("X-Meshpanel-Signature", Sign(h.Secret, body))
	resp, err := d.client.Do(req)
	if err != nil && errors.Is(err, errBlocked) {
		err = errBlocked
	} else if err != nil {
		// Don't hand back dial details (they'd make a port scanner).
		err = errors.New("could not connect to the webhook URL")
	}
	status := 0
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		status = resp.StatusCode
		if status >= 300 {
			err = statusError{status}
		}
	}
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	_ = d.db.RecordWebhookResult(context.WithoutCancel(ctx), h.ID, status, errText)
	return err
}

// Run delivers bus events until ctx ends.
func (d *Dispatcher) Run(ctx context.Context, bus *events.Bus) {
	d.startWorkers(ctx)
	ch, cancel := bus.Subscribe(256)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			d.Handle(ctx, ev)
		}
	}
}
