package notify

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
)

var t0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

type env struct {
	e    *Engine
	d    *db.DB
	ravi *db.Account
	anna *db.Account
	now  time.Time
	snap []hs.Node
}

func setup(t *testing.T) *env {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	ravi, _ := d.CreateAccount(ctx, db.Account{Username: "ravi", Role: "member", HSUser: "ravi"})
	anna, _ := d.CreateAccount(ctx, db.Account{Username: "anna", Role: "admin", HSUser: "anna"})
	v := &env{d: d, ravi: ravi, anna: anna, now: t0}
	v.e = NewEngine(d, func() []hs.Node { return v.snap })
	v.e.now = func() time.Time { return v.now }
	return v
}

func (v *env) rule(t *testing.T, acc *db.Account, typ, subj string, debounce time.Duration, kinds ...events.Kind) {
	t.Helper()
	var ks []string
	for _, k := range kinds {
		ks = append(ks, string(k))
	}
	if _, err := v.d.CreateWatch(context.Background(), db.WatchRule{AccountID: acc.ID, SubjectType: typ, Subject: subj, Events: ks, OfflineDebounce: debounce}); err != nil {
		t.Fatal(err)
	}
}

func ev(k events.Kind, node, user string) events.Event {
	return events.Event{Kind: k, NodeID: node, NodeName: "node-" + node, HSUser: user}
}

func TestRuleMatchesUserSubject(t *testing.T) {
	v := setup(t)
	v.rule(t, v.anna, "user", "ravi", 0, events.NodeAdded)
	got := v.e.Handle(ev(events.NodeAdded, "1", "ravi"))
	if len(got) != 1 || got[0].AccountID != v.anna.ID || !strings.Contains(got[0].Text, "node-1") {
		t.Fatalf("%+v", got)
	}
	if len(v.e.Handle(ev(events.NodeAdded, "2", "bob"))) != 0 {
		t.Fatal("other user's device matched")
	}
	if len(v.e.Handle(ev(events.NodeOnline, "1", "ravi"))) != 0 {
		t.Fatal("unselected event matched")
	}
}

func TestRuleScopedToOwnDevices(t *testing.T) {
	v := setup(t)
	// A member with an "all" rule (should not exist, but defend anyway) only
	// hears about their own devices.
	v.rule(t, v.ravi, "all", "", 0, events.NodeAdded)
	if len(v.e.Handle(ev(events.NodeAdded, "5", "anna"))) != 0 {
		t.Fatal("member alerted about another user's device")
	}
	if len(v.e.Handle(ev(events.NodeAdded, "6", "ravi"))) != 1 {
		t.Fatal("member not alerted about own device")
	}
}

func TestDebounceSuppressesFlap(t *testing.T) {
	v := setup(t)
	v.rule(t, v.anna, "node", "1", 2*time.Minute, events.NodeOffline, events.NodeOnline)
	if got := v.e.Handle(ev(events.NodeOffline, "1", "ravi")); len(got) != 0 {
		t.Fatalf("offline sent immediately: %+v", got)
	}
	v.now = v.now.Add(time.Minute)
	if got := v.e.Handle(ev(events.NodeOnline, "1", "ravi")); len(got) != 0 {
		t.Fatalf("online after a suppressed offline was sent: %+v", got)
	}
	v.now = v.now.Add(5 * time.Minute)
	if got := v.e.Tick(); len(got) != 0 {
		t.Fatalf("cancelled offline fired: %+v", got)
	}
	v.e.Handle(ev(events.NodeOffline, "1", "ravi"))
	v.now = v.now.Add(2*time.Minute + time.Second)
	got := v.e.Tick()
	if len(got) != 1 || !strings.Contains(got[0].Text, "offline") {
		t.Fatalf("debounced offline: %+v", got)
	}
	if again := v.e.Tick(); len(again) != 0 {
		t.Fatal("offline fired twice")
	}
	if back := v.e.Handle(ev(events.NodeOnline, "1", "ravi")); len(back) != 1 {
		t.Fatal("online after a sent offline should alert")
	}
}

func TestFlappingCollapse(t *testing.T) {
	v := setup(t)
	v.rule(t, v.anna, "node", "1", 0, events.NodeOffline, events.NodeOnline)
	var sent []Delivery
	for i := 0; i < 8; i++ {
		k := events.NodeOffline
		if i%2 == 1 {
			k = events.NodeOnline
		}
		sent = append(sent, v.e.Handle(ev(k, "1", "ravi"))...)
		v.now = v.now.Add(30 * time.Second)
	}
	flaps := 0
	for _, d := range sent {
		if strings.Contains(d.Text, "flapping") {
			flaps++
		}
	}
	if flaps != 1 || len(sent) > 5 {
		t.Fatalf("sent %d, flapping %d: %+v", len(sent), flaps, sent)
	}
}

func TestQuietHoursSecurityBypass(t *testing.T) {
	v := setup(t)
	v.anna.QuietStart, v.anna.QuietEnd, v.anna.Timezone = "11:00", "13:00", "UTC"
	v.d.UpdateAccount(context.Background(), v.anna)
	v.rule(t, v.anna, "all", "", 0, events.NodeAdded)
	got := v.e.Handle(ev(events.NodeAdded, "1", "ravi"))
	if len(got) != 1 || !got[0].Quiet {
		t.Fatalf("quiet-hours delivery should be marked quiet: %+v", got)
	}
	sec := v.e.Handle(events.Event{Kind: events.Security, Text: "5 failed logins for anna"})
	if len(sec) == 0 || sec[0].Quiet {
		t.Fatalf("security alert suppressed: %+v", sec)
	}
	for _, d := range sec {
		if d.AccountID == v.ravi.ID {
			t.Fatal("security alert went to a member")
		}
	}
}

func TestQuietWindowAcrossMidnight(t *testing.T) {
	if !inQuiet("22:00", "07:00", "UTC", time.Date(2026, 1, 1, 23, 30, 0, 0, time.UTC)) ||
		!inQuiet("22:00", "07:00", "UTC", time.Date(2026, 1, 1, 6, 0, 0, 0, time.UTC)) ||
		inQuiet("22:00", "07:00", "UTC", time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)) ||
		inQuiet("", "", "UTC", t0) {
		t.Fatal("quiet window math")
	}
}

func TestNotSeen(t *testing.T) {
	v := setup(t)
	if _, err := v.d.CreateWatch(context.Background(), db.WatchRule{AccountID: v.anna.ID, SubjectType: "user", Subject: "ravi", Events: []string{string(events.NodeNotSeen)}, NotSeenHours: 24}); err != nil {
		t.Fatal(err)
	}
	seen := t0.Add(-30 * time.Hour)
	v.snap = []hs.Node{{ID: "1", GivenName: "laptop", User: &hs.User{Name: "ravi"}, LastSeen: &seen}}
	if got := v.e.Tick(); len(got) != 1 || !strings.Contains(got[0].Text, "laptop") {
		t.Fatalf("%+v", got)
	}
	if len(v.e.Tick()) != 0 {
		t.Fatal("not-seen repeated")
	}
}
