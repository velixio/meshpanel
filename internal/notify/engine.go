// Package notify turns bus events into per-person notifications according
// to their watch rules, with offline debouncing, flap collapsing and quiet
// hours. Security events go to admins and ignore quiet hours.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

const (
	flapWindow    = 10 * time.Minute
	flapThreshold = 3
	flapSilence   = 30 * time.Minute
)

// Delivery is one message for one person. Quiet deliveries are recorded in
// the dashboard feed but not pushed to Telegram.
type Delivery struct {
	AccountID int64
	Kind      events.Kind
	Text      string
	Quiet     bool
}

// Sender pushes a delivery out (Telegram). It may be nil.
type Sender interface {
	Send(ctx context.Context, accountID int64, text string) error
}

type key struct {
	rule int64
	node string
}

type Engine struct {
	db       *db.DB
	snapshot func() []hs.Node
	now      func() time.Time

	mu         sync.Mutex
	pendingOff map[key]pendingAlert
	flaps      map[string][]time.Time
	silenced   map[string]time.Time
	notSeen    map[key]bool
}

type pendingAlert struct {
	due     time.Time
	ev      events.Event
	account int64
}

func NewEngine(d *db.DB, snapshot func() []hs.Node) *Engine {
	return &Engine{
		db: d, snapshot: snapshot, now: time.Now,
		pendingOff: map[key]pendingAlert{}, flaps: map[string][]time.Time{},
		silenced: map[string]time.Time{}, notSeen: map[key]bool{},
	}
}

type target struct {
	acc   *db.Account
	caps  perm.Cap
	scope perm.Scope
}

func (e *Engine) accounts(ctx context.Context) map[int64]target {
	all, err := e.db.ListAccounts(ctx)
	if err != nil {
		slog.Error("notify: listing accounts", "err", err)
		return nil
	}
	m := make(map[int64]target, len(all))
	for _, a := range all {
		if a.Disabled {
			continue
		}
		caps := perm.Effective(a.Role, perm.Cap(a.ExtraCaps))
		m[a.ID] = target{acc: a, caps: caps, scope: perm.ScopeFor(caps, a.HSUser)}
	}
	return m
}

func matches(r *db.WatchRule, ev events.Event) bool {
	switch r.SubjectType {
	case "all":
		return true
	case "node":
		return ev.NodeID != "" && ev.NodeID == r.Subject
	case "user":
		return ev.HSUser != "" && ev.HSUser == r.Subject
	case "tag":
		for _, t := range ev.Tags {
			if t == r.Subject {
				return true
			}
		}
	}
	return false
}

// visible enforces ownership scope: a member never hears about devices
// they could not see in the dashboard.
func visible(t target, ev events.Event) bool {
	if t.scope.All {
		return true
	}
	return t.scope.HSUser != "" && ev.HSUser == t.scope.HSUser
}

func (e *Engine) deliver(t target, kind events.Kind, text string, security bool) Delivery {
	quiet := !security && inQuiet(t.acc.QuietStart, t.acc.QuietEnd, t.acc.Timezone, e.now())
	return Delivery{AccountID: t.acc.ID, Kind: kind, Text: text, Quiet: quiet}
}

// Handle processes one event and returns what should be delivered now.
func (e *Engine) Handle(ev events.Event) []Delivery {
	ctx := context.Background()
	accs := e.accounts(ctx)
	if isSecurity(ev.Kind) {
		var out []Delivery
		for _, t := range accs {
			if t.caps.Has(perm.ConfigureIAM) {
				out = append(out, e.deliver(t, ev.Kind, Text(ev), true))
			}
		}
		return out
	}
	rules, err := e.db.ListWatches(ctx, 0)
	if err != nil {
		slog.Error("notify: listing rules", "err", err)
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()

	flapping := false
	if ev.Kind == events.NodeOnline || ev.Kind == events.NodeOffline {
		if until, ok := e.silenced[ev.NodeID]; ok && now.Before(until) {
			return nil
		}
		ts := append(e.flaps[ev.NodeID], now)
		cut := 0
		for cut < len(ts) && now.Sub(ts[cut]) > flapWindow {
			cut++
		}
		ts = ts[cut:]
		e.flaps[ev.NodeID] = ts
		if len(ts) > flapThreshold {
			flapping = true
			e.silenced[ev.NodeID] = now.Add(flapSilence)
			delete(e.flaps, ev.NodeID)
		}
	}

	var out []Delivery
	for _, r := range rules {
		t, ok := accs[r.AccountID]
		if !ok || !matches(r, ev) || !visible(t, ev) {
			continue
		}
		k := key{r.ID, ev.NodeID}
		switch {
		case flapping:
			if r.Wants(string(events.NodeOnline)) || r.Wants(string(events.NodeOffline)) {
				delete(e.pendingOff, k)
				out = append(out, e.deliver(t, ev.Kind,
					fmt.Sprintf("〰️ %s is flapping (going on and offline repeatedly). Alerts for it are paused for 30 minutes.", nodeLabel(ev)), false))
			}
		case ev.Kind == events.NodeOffline && r.Wants(string(ev.Kind)):
			if r.OfflineDebounce > 0 {
				e.pendingOff[k] = pendingAlert{due: now.Add(r.OfflineDebounce), ev: ev, account: r.AccountID}
			} else {
				out = append(out, e.deliver(t, ev.Kind, Text(ev), false))
			}
		case ev.Kind == events.NodeOnline:
			if _, was := e.pendingOff[k]; was {
				// It came back before we told anyone it left.
				delete(e.pendingOff, k)
				continue
			}
			if r.Wants(string(ev.Kind)) {
				out = append(out, e.deliver(t, ev.Kind, Text(ev), false))
			}
		case r.Wants(string(ev.Kind)):
			out = append(out, e.deliver(t, ev.Kind, Text(ev), false))
		}
	}
	return out
}

// Tick fires debounced offline alerts that are due and not-seen alerts.
func (e *Engine) Tick() []Delivery {
	ctx := context.Background()
	accs := e.accounts(ctx)
	rules, err := e.db.ListWatches(ctx, 0)
	if err != nil {
		return nil
	}
	byID := map[int64]*db.WatchRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var out []Delivery
	for k, p := range e.pendingOff {
		if now.Before(p.due) {
			continue
		}
		delete(e.pendingOff, k)
		if t, ok := accs[p.account]; ok && byID[k.rule] != nil {
			out = append(out, e.deliver(t, p.ev.Kind, Text(p.ev), false))
		}
	}
	if e.snapshot != nil {
		nodes := e.snapshot()
		for _, r := range rules {
			if r.NotSeenHours <= 0 || !r.Wants(string(events.NodeNotSeen)) {
				continue
			}
			t, ok := accs[r.AccountID]
			if !ok {
				continue
			}
			for _, n := range nodes {
				ev := events.Event{Kind: events.NodeNotSeen, NodeID: n.ID, NodeName: n.DisplayName(), HSUser: n.UserName(), Tags: n.Tags}
				k := key{r.ID, n.ID}
				stale := !n.Online && n.LastSeen != nil && now.Sub(*n.LastSeen) > time.Duration(r.NotSeenHours)*time.Hour
				if !stale {
					delete(e.notSeen, k)
					continue
				}
				if e.notSeen[k] || !matches(r, ev) || !visible(t, ev) {
					continue
				}
				e.notSeen[k] = true
				ev.Data = map[string]any{"hours": r.NotSeenHours}
				out = append(out, e.deliver(t, ev.Kind, Text(ev), false))
			}
		}
	}
	return out
}

// Run consumes the bus until ctx ends, recording every delivery in the feed
// and pushing non-quiet ones through sender.
func (e *Engine) Run(ctx context.Context, bus *events.Bus, sender Sender) {
	ch, cancel := bus.Subscribe(256)
	defer cancel()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		var ds []Delivery
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			ds = e.Handle(ev)
		case <-t.C:
			ds = e.Tick()
		}
		for _, d := range ds {
			if err := e.db.AddNotification(ctx, d.AccountID, string(d.Kind), d.Text); err != nil {
				slog.Error("notify: recording", "err", err)
			}
			if d.Quiet || sender == nil {
				continue
			}
			if err := sender.Send(ctx, d.AccountID, d.Text); err != nil {
				slog.Debug("notify: send", "account", d.AccountID, "err", err)
			}
		}
	}
}

func isSecurity(k events.Kind) bool {
	return k == events.Security || k == events.HeadscaleDown || k == events.HeadscaleUp
}

// inQuiet reports whether now falls in [start, end) in tz; windows may
// cross midnight. Empty bounds mean no quiet hours.
func inQuiet(start, end, tz string, now time.Time) bool {
	if start == "" || end == "" || start == end {
		return false
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	parse := func(s string) (int, bool) {
		var h, m int
		if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h > 23 || m > 59 {
			return 0, false
		}
		return h*60 + m, true
	}
	s, ok1 := parse(start)
	en, ok2 := parse(end)
	if !ok1 || !ok2 {
		return false
	}
	l := now.In(loc)
	cur := l.Hour()*60 + l.Minute()
	if s < en {
		return cur >= s && cur < en
	}
	return cur >= s || cur < en
}

func nodeLabel(ev events.Event) string {
	name := ev.NodeName
	if name == "" {
		name = "a device"
	}
	if ev.HSUser != "" {
		return fmt.Sprintf("%s (%s)", name, ev.HSUser)
	}
	return name
}

// Text renders the human message for an event.
func Text(ev events.Event) string {
	n := nodeLabel(ev)
	str := func(k string) string {
		if v, ok := ev.Data[k]; ok {
			return fmt.Sprint(v)
		}
		return ""
	}
	switch ev.Kind {
	case events.NodeOnline:
		return "🟢 " + n + " is online"
	case events.NodeOffline:
		return "🔴 " + n + " went offline"
	case events.NodeAdded:
		return "🆕 New device: " + n
	case events.NodeDeleted:
		return "🗑️ Device deleted: " + n
	case events.NodeRenamed:
		return fmt.Sprintf("✏️ %s was renamed (was %s)", n, str("from"))
	case events.NodeTagsChanged:
		return fmt.Sprintf("🏷️ Tags changed on %s: %s", n, strings.Join(ev.Tags, ", "))
	case events.RouteAdvertised:
		msg := fmt.Sprintf("🛣️ %s advertises route %s", n, str("route"))
		switch str("risk") {
		case "exit":
			msg += " (exit node)"
		case "wide":
			msg += " (wide subnet)"
		}
		return msg + ". It needs approval."
	case events.RouteApproved:
		return fmt.Sprintf("✅ Route %s approved on %s", str("route"), n)
	case events.KeyExpiring:
		return fmt.Sprintf("⏳ Key for %s expires in %s days", n, str("days"))
	case events.KeyExpired:
		return "⌛ Key for " + n + " has expired. The device must sign in again."
	case events.NodeNotSeen:
		return fmt.Sprintf("👻 %s has not been seen for over %s hours", n, str("hours"))
	case events.HeadscaleDown:
		return "🚨 headscale is not responding: " + ev.Text
	case events.HeadscaleUp:
		return "✅ headscale is responding again"
	case events.Security:
		return "🔐 " + ev.Text
	}
	if ev.Text != "" {
		return ev.Text
	}
	return string(ev.Kind) + ": " + n
}
