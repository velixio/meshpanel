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
	mu       sync.Mutex
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
	return hs.Node{ID: "9", GivenName: "ravi-iphone", IPAddresses: []string{"100.64.0.9"}}, nil
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
