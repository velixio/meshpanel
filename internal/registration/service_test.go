package registration

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
)

const authID = "hskey-authreq-0123456789abcdef01234567"

type fakeHS struct {
	calls    atomic.Int32
	lastUser string
	fail     error
	node     string // GivenName AuthRegister reports (default "ravi-iphone")
	taken    map[string]bool
	renamed  []string
	expiry   []string // "never" or the RFC 3339 time passed to SetKeyExpiry
	mu       sync.Mutex
}

func (f *fakeHS) SetKeyExpiry(_ context.Context, id string, never bool, at time.Time) (hs.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if never {
		f.expiry = append(f.expiry, "never")
	} else {
		f.expiry = append(f.expiry, at.UTC().Format(time.RFC3339))
	}
	return hs.Node{ID: id}, nil
}

func (f *fakeHS) RenameNode(_ context.Context, id, name string) (hs.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.taken[name] {
		return hs.Node{}, errors.New("name taken")
	}
	f.renamed = append(f.renamed, name)
	return hs.Node{ID: id, GivenName: name}, nil
}

func (f *fakeHS) AuthRegister(_ context.Context, user, id string) (hs.Node, error) {
	f.calls.Add(1)
	time.Sleep(20 * time.Millisecond) // widen the race window
	f.mu.Lock()
	f.lastUser = user
	f.mu.Unlock()
	if f.fail != nil {
		return hs.Node{}, f.fail
	}
	name := f.node
	if name == "" {
		name = "ravi-iphone"
	}
	return hs.Node{ID: "9", GivenName: name, IPAddresses: []string{"100.64.0.9"}}, nil
}
func (f *fakeHS) AuthApprove(context.Context, string) error { f.calls.Add(1); return f.fail }
func (f *fakeHS) AuthReject(context.Context, string) error  { return nil }

func setup(t *testing.T) (*Service, *fakeHS, *db.DB, *db.Account, *db.Account) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	ravi, _ := d.CreateAccount(ctx, db.Account{Username: "ravi", Role: "member", HSUser: "ravi"})
	anna, _ := d.CreateAccount(ctx, db.Account{Username: "anna", Role: "admin", HSUser: "anna"})
	f := &fakeHS{}
	return New(d, f, events.NewBus()), f, d, ravi, anna
}

func TestRegistrationApproveOnce(t *testing.T) {
	s, f, _, ravi, anna := setup(t)
	ctx := context.Background()
	p, err := s.Create(ctx, KindRegister, authID, ravi, "1.2.3.4", "iPhone")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch := []string{"web", "telegram"}[i]
			_, errs[i] = s.Decide(ctx, p.ID, true, anna, ch, "")
		}(i)
	}
	wg.Wait()
	if f.calls.Load() != 1 {
		t.Fatalf("headscale called %d times", f.calls.Load())
	}
	var already *AlreadyDecidedError
	okCount, alreadyCount := 0, 0
	for _, e := range errs {
		switch {
		case e == nil:
			okCount++
		case errors.As(e, &already):
			alreadyCount++
			if already.By != "anna" {
				t.Fatalf("decided by %q", already.By)
			}
		default:
			t.Fatalf("unexpected %v", e)
		}
	}
	if okCount != 1 || alreadyCount != 1 {
		t.Fatalf("ok=%d already=%d", okCount, alreadyCount)
	}
	got, _ := s.Get(ctx, p.ID)
	if got.Status != db.StatusApproved || got.NodeName != "ravi-iphone" || got.NodeIP != "100.64.0.9" {
		t.Fatalf("final %+v", got)
	}
}

func TestCreateIdempotent(t *testing.T) {
	s, _, _, ravi, _ := setup(t)
	ctx := context.Background()
	a, _ := s.Create(ctx, KindRegister, authID, ravi, "", "")
	b, _ := s.Create(ctx, KindRegister, authID, ravi, "", "")
	if a.ID != b.ID {
		t.Fatal("reload created a second request")
	}
}

func TestCreateRejectsBadID(t *testing.T) {
	s, _, _, ravi, _ := setup(t)
	if _, err := s.Create(context.Background(), KindRegister, "nope", ravi, "", ""); err != ErrBadAuthID {
		t.Fatalf("err %v", err)
	}
}

func TestRegistrationExpiry(t *testing.T) {
	s, f, d, ravi, anna := setup(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	d.SetClock(func() time.Time { return now })
	s.now = func() time.Time { return now }
	p, _ := s.Create(ctx, KindRegister, authID, ravi, "", "")
	if p.ExpiresAt.Sub(p.CreatedAt) != 15*time.Minute {
		t.Fatalf("ttl %v", p.ExpiresAt.Sub(p.CreatedAt))
	}
	now = now.Add(16 * time.Minute)
	exp, _ := s.ExpireSweep(ctx)
	if len(exp) != 1 {
		t.Fatalf("expired %d", len(exp))
	}
	if _, err := s.Decide(ctx, p.ID, true, anna, "web", ""); err == nil || f.calls.Load() != 0 {
		t.Fatal("approved an expired request")
	}
}

func TestApproveAsOtherUser(t *testing.T) {
	s, f, _, ravi, anna := setup(t)
	ctx := context.Background()
	p, _ := s.Create(ctx, KindRegister, authID, ravi, "", "")
	if _, err := s.Decide(ctx, p.ID, true, anna, "web", "office"); err != nil {
		t.Fatal(err)
	}
	if f.lastUser != "office" {
		t.Fatalf("registered as %q", f.lastUser)
	}
}

func TestHeadscaleFailureMarksFailed(t *testing.T) {
	s, f, _, ravi, anna := setup(t)
	ctx := context.Background()
	f.fail = &hs.APIError{Status: 404, Detail: "auth request not found"}
	p, _ := s.Create(ctx, KindRegister, authID, ravi, "", "")
	if _, err := s.Decide(ctx, p.ID, true, anna, "web", ""); err == nil {
		t.Fatal("no error")
	}
	got, _ := s.Get(ctx, p.ID)
	if got.Status != db.StatusFailed || got.Error == "" {
		t.Fatalf("got %+v", got)
	}
}

func TestDenyDoesNotRegister(t *testing.T) {
	s, f, _, ravi, anna := setup(t)
	ctx := context.Background()
	p, _ := s.Create(ctx, KindRegister, authID, ravi, "", "")
	got, err := s.Decide(ctx, p.ID, false, anna, "telegram", "")
	if err != nil || got.Status != db.StatusDenied || f.calls.Load() != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestUnlinkedRequesterNeedsUser(t *testing.T) {
	s, _, d, _, anna := setup(t)
	ctx := context.Background()
	x, _ := d.CreateAccount(ctx, db.Account{Username: "x", Role: "member"})
	p, _ := s.Create(ctx, KindRegister, authID, x, "", "")
	if _, err := s.Decide(ctx, p.ID, true, anna, "web", ""); err != ErrNoHSUser {
		t.Fatalf("err %v", err)
	}
	got, _ := s.Get(ctx, p.ID)
	if got.Status != db.StatusPending {
		t.Fatal("request consumed by a failed precondition")
	}
}

const iphoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"

func TestGenericHostnameGetsFriendlyName(t *testing.T) {
	for _, reported := range []string{"localhost", "localhost-ab12", "Localhost"} {
		s, f, _, ravi, anna := setup(t)
		f.node = reported
		ctx := context.Background()
		p, _ := s.Create(ctx, KindRegister, authID, ravi, "1.2.3.4", iphoneUA)
		got, err := s.Decide(ctx, p.ID, true, anna, "web", "")
		if err != nil || got.NodeName != "ravi-iphone" || len(f.renamed) != 1 || f.renamed[0] != "ravi-iphone" {
			t.Fatalf("%s: %+v renamed=%v err=%v", reported, got, f.renamed, err)
		}
		if got.NodeIP != "100.64.0.9" {
			t.Fatalf("lost the IP: %q", got.NodeIP)
		}
	}
}

func TestRealHostnameIsKept(t *testing.T) {
	s, f, _, ravi, anna := setup(t)
	f.node = "annas-pixel"
	ctx := context.Background()
	p, _ := s.Create(ctx, KindRegister, authID, ravi, "1.2.3.4", iphoneUA)
	got, _ := s.Decide(ctx, p.ID, true, anna, "web", "")
	if got.NodeName != "annas-pixel" || len(f.renamed) != 0 {
		t.Fatalf("renamed a real hostname: %+v %v", got, f.renamed)
	}
}

func TestFriendlyNameSkipsTakenAndUnknown(t *testing.T) {
	s, f, _, ravi, anna := setup(t)
	f.node, f.taken = "localhost", map[string]bool{"ravi-iphone": true}
	ctx := context.Background()
	p, _ := s.Create(ctx, KindRegister, authID, ravi, "1.2.3.4", iphoneUA)
	got, _ := s.Decide(ctx, p.ID, true, anna, "web", "")
	if got.NodeName != "ravi-iphone-2" {
		t.Fatalf("taken name: %q", got.NodeName)
	}
	s2, f2, _, ravi2, anna2 := setup(t)
	f2.node = "localhost"
	p2, _ := s2.Create(ctx, KindRegister, authID, ravi2, "1.2.3.4", "curl/8")
	got2, _ := s2.Decide(ctx, p2.ID, true, anna2, "web", "")
	if got2.NodeName != "localhost" || len(f2.renamed) != 0 {
		t.Fatalf("unknown device renamed: %+v", got2)
	}
}

func TestDeviceSlug(t *testing.T) {
	for ua, want := range map[string]string{
		iphoneUA: "iphone",
		"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit": "ipad",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit":      "android-pixel-8",
		"Mozilla/5.0 (Linux; Android 13; K) AppleWebKit":            "android",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)":           "mac",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)":                 "windows",
		"curl/8": "", "": "",
	} {
		if got := DeviceSlug(ua); got != want {
			t.Errorf("%q: %q, want %q", ua, got, want)
		}
	}
}

func TestNewDeviceKeyLifetime(t *testing.T) {
	for setting, want := range map[string]string{"": "", "never": "never", "90": "days:90", "bogus": "", "0": "", "-5": ""} {
		s, f, d, ravi, anna := setup(t)
		d.SetSetting(context.Background(), KeyLifetimeSetting, setting)
		ctx := context.Background()
		p, _ := s.Create(ctx, KindRegister, authID, ravi, "1.2.3.4", iphoneUA)
		got, err := s.Decide(ctx, p.ID, true, anna, "web", "")
		if err != nil || got.NodeIP != "100.64.0.9" {
			t.Fatalf("%q: %+v %v", setting, got, err)
		}
		switch {
		case want == "":
			if len(f.expiry) != 0 {
				t.Errorf("%q: expiry set to %v", setting, f.expiry)
			}
		case want == "never":
			if len(f.expiry) != 1 || f.expiry[0] != "never" {
				t.Errorf("%q: %v", setting, f.expiry)
			}
		default:
			at, _ := time.Parse(time.RFC3339, func() string {
				if len(f.expiry) == 1 {
					return f.expiry[0]
				}
				return ""
			}())
			if d := time.Until(at); d < 89*24*time.Hour || d > 91*24*time.Hour {
				t.Errorf("%q: expiry %v (%v away)", setting, f.expiry, d)
			}
		}
	}
}
