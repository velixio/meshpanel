package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
)

type recv struct {
	mu     sync.Mutex
	bodies [][]byte
	sigs   []string
	kinds  []string
	fail   atomic.Int32 // respond 500 this many times first
}

func (rc *recv) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	if rc.fail.Load() > 0 {
		rc.fail.Add(-1)
		w.WriteHeader(500)
		return
	}
	rc.mu.Lock()
	rc.bodies = append(rc.bodies, b)
	rc.sigs = append(rc.sigs, r.Header.Get("X-Meshpanel-Signature"))
	rc.kinds = append(rc.kinds, r.Header.Get("X-Meshpanel-Event"))
	rc.mu.Unlock()
}

func (rc *recv) count() int { rc.mu.Lock(); defer rc.mu.Unlock(); return len(rc.bodies) }

func setup(t *testing.T, format string, kinds ...string) (*Dispatcher, *recv, *db.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	rc := &recv{}
	srv := httptest.NewServer(http.HandlerFunc(rc.handler))
	t.Cleanup(srv.Close)
	if _, err := d.CreateWebhook(context.Background(), db.Webhook{Name: "ops", URL: srv.URL, Format: format, Events: kinds, Secret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	disp := New(d)
	disp.allowLoopback() // test receivers listen on 127.0.0.1
	disp.backoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	return disp, rc, d
}

func wait(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestDeliverSignedJSON(t *testing.T) {
	disp, rc, _ := setup(t, "json")
	disp.Handle(context.Background(), events.Event{Kind: events.NodeAdded, NodeID: "7", NodeName: "ravi-iphone", HSUser: "ravi", At: time.Unix(1_800_000_000, 0)})
	wait(t, func() bool { return rc.count() == 1 })
	var p Payload
	if err := json.Unmarshal(rc.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.Event != "node_added" || p.Node == nil || p.Node.Name != "ravi-iphone" || p.User != "ravi" || p.Text == "" {
		t.Fatalf("%+v", p)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(rc.bodies[0])
	if rc.sigs[0] != "sha256="+hex.EncodeToString(mac.Sum(nil)) || rc.kinds[0] != "node_added" {
		t.Fatalf("signature %q kind %q", rc.sigs[0], rc.kinds[0])
	}
}

func TestSlackAndDiscordFormats(t *testing.T) {
	for format, field := range map[string]string{"slack": "text", "discord": "content"} {
		disp, rc, _ := setup(t, format)
		disp.Handle(context.Background(), events.Event{Kind: events.NodeOffline, NodeName: "nas", HSUser: "office"})
		wait(t, func() bool { return rc.count() == 1 })
		var m map[string]any
		json.Unmarshal(rc.bodies[0], &m)
		if s, _ := m[field].(string); s == "" || len(m) != 1 {
			t.Fatalf("%s body %s", format, rc.bodies[0])
		}
	}
}

func TestKindFilter(t *testing.T) {
	disp, rc, _ := setup(t, "json", "security")
	disp.Handle(context.Background(), events.Event{Kind: events.NodeOnline, NodeName: "x"})
	disp.Handle(context.Background(), events.Event{Kind: events.Security, Text: "5 failed sign-ins"})
	wait(t, func() bool { return rc.count() == 1 })
	time.Sleep(50 * time.Millisecond)
	if rc.count() != 1 || rc.kinds[0] != "security" {
		t.Fatalf("kinds %v", rc.kinds)
	}
}

func TestInternalEventsNotSent(t *testing.T) {
	disp, rc, _ := setup(t, "json")
	disp.Handle(context.Background(), events.Event{Kind: events.Changed})
	time.Sleep(80 * time.Millisecond)
	if rc.count() != 0 {
		t.Fatal("internal refresh event delivered")
	}
}

func TestRetryOn500AndRecordResult(t *testing.T) {
	disp, rc, d := setup(t, "json")
	rc.fail.Store(2)
	disp.Handle(context.Background(), events.Event{Kind: events.NodeAdded, NodeName: "x"})
	wait(t, func() bool { return rc.count() == 1 })
	wait(t, func() bool {
		hs, _ := d.ListWebhooks(context.Background())
		return hs[0].LastStatus == 200 && hs[0].LastError == ""
	})
}

func TestBlocksInternalTargets(t *testing.T) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "t.db"))
	defer d.Close()
	hit := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer srv.Close()
	disp := New(d)
	for _, u := range []string{srv.URL, "http://169.254.169.254/latest/meta-data", "http://[::1]:9/", "http://0.0.0.0:9/"} {
		err := disp.Send(context.Background(), &db.Webhook{URL: u, Format: "json", Secret: "x"}, events.Event{Kind: events.NodeAdded})
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: err = %v", u, err)
		}
	}
	if hit.Load() != 0 {
		t.Fatal("request reached a loopback address")
	}
}

func TestNoRedirects(t *testing.T) {
	disp, _, d := setup(t, "json")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer target.Close()
	err := disp.Send(context.Background(), &db.Webhook{URL: target.URL, Format: "json", Secret: "x"}, events.Event{Kind: events.NodeAdded})
	if err == nil {
		t.Fatal("redirect treated as success")
	}
	_ = d
}

func TestBlockedTarget(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1":              true,
		"169.254.169.254":        true,
		"::ffff:169.254.169.254": true,
		"64:ff9b::a9fe:a9fe":     true, // NAT64 169.254.169.254
		"::a9fe:a9fe":            true, // IPv4-compatible
		"2002:a9fe:a9fe::":       true, // 6to4
		"fd00:ec2::254":          true,
		"100.100.100.200":        true,
		"192.0.2.10":             false, // private-ish ranges stay allowed
		"203.0.113.5":            false,
		"64:ff9b::cb00:7105":     false, // NAT64 203.0.113.5
	} {
		if got := blockedTarget(netip.MustParseAddr(addr)); got != want {
			t.Errorf("blockedTarget(%s) = %v, want %v", addr, got, want)
		}
	}
}
