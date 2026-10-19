package events

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/hs"
)

var t0 = time.Unix(1_800_000_000, 0)

func n(id string, online bool) hs.Node {
	return hs.Node{ID: id, GivenName: "node-" + id, Online: online, User: &hs.User{ID: "1", Name: "ravi"}}
}

func kinds(evs []Event) map[Kind]int {
	m := map[Kind]int{}
	for _, e := range evs {
		m[e.Kind]++
	}
	return m
}

func TestDiffOnlineOffline(t *testing.T) {
	d := NewDiffer()
	d.Diff([]hs.Node{n("1", true), n("2", false)}, t0)
	evs := d.Diff([]hs.Node{n("1", false), n("2", true)}, t0)
	k := kinds(evs)
	if k[NodeOffline] != 1 || k[NodeOnline] != 1 || len(evs) != 2 {
		t.Fatalf("events %+v", evs)
	}
	for _, e := range evs {
		if e.HSUser != "ravi" || e.NodeName == "" {
			t.Fatalf("event lacks context %+v", e)
		}
	}
}

func TestDiffFirstSnapshotIsSilent(t *testing.T) {
	d := NewDiffer()
	if evs := d.Diff([]hs.Node{n("1", true)}, t0); len(evs) != 0 {
		t.Fatalf("first snapshot emitted %+v", evs)
	}
}

func TestDiffAddedDeleted(t *testing.T) {
	d := NewDiffer()
	d.Diff([]hs.Node{n("1", true)}, t0)
	k := kinds(d.Diff([]hs.Node{n("2", true)}, t0))
	if k[NodeAdded] != 1 || k[NodeDeleted] != 1 {
		t.Fatalf("%v", k)
	}
}

func TestDiffRenameAndTags(t *testing.T) {
	d := NewDiffer()
	a := n("1", true)
	d.Diff([]hs.Node{a}, t0)
	b := a
	b.GivenName = "new"
	b.Tags = []string{"tag:x"}
	k := kinds(d.Diff([]hs.Node{b}, t0))
	if k[NodeRenamed] != 1 || k[NodeTagsChanged] != 1 {
		t.Fatalf("%v", k)
	}
}

func TestDiffRoutesAdvertised(t *testing.T) {
	d := NewDiffer()
	a := n("1", true)
	d.Diff([]hs.Node{a}, t0)
	b := a
	b.AvailableRoutes = []string{"10.0.0.0/24"}
	evs := d.Diff([]hs.Node{b}, t0)
	if kinds(evs)[RouteAdvertised] != 1 || evs[0].Data["route"] != "10.0.0.0/24" {
		t.Fatalf("%+v", evs)
	}
	c := b
	c.ApprovedRoutes = []string{"10.0.0.0/24"}
	if kinds(d.Diff([]hs.Node{c}, t0))[RouteApproved] != 1 {
		t.Fatal("approve not seen")
	}
}

func TestDiffKeyExpiringOnce(t *testing.T) {
	d := NewDiffer()
	a := n("1", true)
	exp := t0.Add(3 * 24 * time.Hour)
	a.Expiry = &exp
	// Primed while 8 days out: nodes already expiring at startup stay quiet,
	// so a restart doesn't re-alert.
	d.Diff([]hs.Node{a}, t0.Add(-5*24*time.Hour))
	if kinds(d.Diff([]hs.Node{a}, t0.Add(time.Minute)))[KeyExpiring] != 1 {
		t.Fatal("expiring not reported")
	}
	if kinds(d.Diff([]hs.Node{a}, t0.Add(2*time.Minute)))[KeyExpiring] != 0 {
		t.Fatal("expiring reported twice")
	}
	if kinds(d.Diff([]hs.Node{a}, exp.Add(time.Minute)))[KeyExpired] != 1 {
		t.Fatal("expired not reported")
	}
}

func TestBusNonBlocking(t *testing.T) {
	b := NewBus()
	ch, cancel := b.Subscribe(1)
	defer cancel()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			b.Publish(Event{Kind: NodeOnline})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publish blocked on a slow subscriber")
	}
	<-ch
}

type fakeHS struct {
	mu    sync.Mutex
	nodes []hs.Node
	err   error
}

func (f *fakeHS) ListNodes(context.Context) ([]hs.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes, f.err
}
func (f *fakeHS) ListUsers(context.Context) ([]hs.User, error) { return nil, f.err }

func TestPollerHealthTransitions(t *testing.T) {
	f := &fakeHS{nodes: []hs.Node{n("1", true)}}
	b := NewBus()
	ch, cancel := b.Subscribe(16)
	defer cancel()
	p := NewPoller(f, b, time.Hour)
	ctx := context.Background()
	p.Tick(ctx)
	if len(p.Snapshot()) != 1 || !p.Healthy() {
		t.Fatal("snapshot")
	}
	f.err = errors.New("down")
	p.Tick(ctx)
	p.Tick(ctx)
	f.err = nil
	p.Tick(ctx)
	var got []Kind
	for len(ch) > 0 {
		got = append(got, (<-ch).Kind)
	}
	if len(got) != 2 || got[0] != HeadscaleDown || got[1] != HeadscaleUp {
		t.Fatalf("got %v", got)
	}
}

func TestDiffIgnoresWebSSHNodes(t *testing.T) {
	d := NewDiffer()
	d.Diff([]hs.Node{n("1", true)}, t0)
	ssh := hs.Node{ID: "9", Name: "meshpanel-ssh-ravi", User: &hs.User{Name: "ravi"}, Online: true}
	if evs := d.Diff([]hs.Node{n("1", true), ssh}, t0); len(evs) != 0 {
		t.Fatalf("SSH session node raised %+v", evs)
	}
	if evs := d.Diff([]hs.Node{n("1", true)}, t0); len(evs) != 0 {
		t.Fatalf("SSH session node removal raised %+v", evs)
	}
}
