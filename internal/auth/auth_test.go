package auth

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash format %q", h)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "wrong") {
		t.Fatal("verify mismatch")
	}
	if _, err := HashPassword("short"); err != ErrPasswordTooShort {
		t.Fatalf("short password: %v", err)
	}
}

func TestTOTPWindow(t *testing.T) {
	secret, uri := NewTOTPSecret("Acme", "ravi")
	if !strings.HasPrefix(uri, "otpauth://totp/Acme:ravi?") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("uri %q", uri)
	}
	now := time.Unix(1_800_000_000, 0)
	code := totpAt(secret, now)
	if !validateTOTPAt(secret, code, now) || !validateTOTPAt(secret, code, now.Add(30*time.Second)) {
		t.Fatal("code rejected within window")
	}
	if validateTOTPAt(secret, code, now.Add(90*time.Second)) {
		t.Fatal("code accepted outside window")
	}
	// RFC 6238 test vector (SHA1, secret "12345678901234567890").
	if got := totpAt("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0)); got != "287082" {
		t.Fatalf("rfc vector = %s", got)
	}
}

func TestBackupCodeSingleUse(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	a, _ := d.CreateAccount(ctx, db.Account{Username: "ravi", Role: "member"})
	codes, err := NewBackupCodes(ctx, d, a.ID)
	if err != nil || len(codes) != 10 {
		t.Fatalf("codes %v %v", codes, err)
	}
	if !UseBackupCode(ctx, d, a.ID, codes[3]) {
		t.Fatal("valid code rejected")
	}
	if UseBackupCode(ctx, d, a.ID, codes[3]) {
		t.Fatal("code reused")
	}
}

func TestLimiterBackoff(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("ip:1"); !ok {
			t.Fatalf("blocked after %d failures", i)
		}
		l.Fail("ip:1")
	}
	if ok, _ := l.Allow("ip:1"); !ok {
		t.Fatal("5 failures should still be allowed once more")
	}
	l.Fail("ip:1")
	ok, retry := l.Allow("ip:1")
	if ok || retry != 2*time.Second {
		t.Fatalf("after 6 failures ok=%v retry=%v", ok, retry)
	}
	now = now.Add(3 * time.Second)
	if ok, _ := l.Allow("ip:1"); !ok {
		t.Fatal("still blocked after backoff")
	}
	l.Reset("ip:1")
	if ok, _ := l.Allow("ip:1"); !ok {
		t.Fatal("reset failed")
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	a, _ := d.CreateAccount(ctx, db.Account{Username: "ravi", Role: "member"})
	now := time.Unix(2_000_000_000, 0)
	s := NewSessions(d)
	s.now = func() time.Time { return now }
	tok, err := s.Create(ctx, a.ID, "1.2.3.4", "ua", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, acc, err := s.Lookup(ctx, tok); err != nil || acc.Username != "ravi" {
		t.Fatalf("lookup: %v", err)
	}
	now = now.Add(6 * 24 * time.Hour)
	if _, _, err := s.Lookup(ctx, tok); err != nil {
		t.Fatalf("active session expired: %v", err)
	}
	now = now.Add(7*24*time.Hour + time.Minute)
	if _, _, err := s.Lookup(ctx, tok); err != ErrNoSession {
		t.Fatalf("idle session alive: %v", err)
	}
}

func TestSessionAbsoluteExpiry(t *testing.T) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "t.db"))
	defer d.Close()
	ctx := context.Background()
	a, _ := d.CreateAccount(ctx, db.Account{Username: "ravi", Role: "member"})
	now := time.Unix(2_000_000_000, 0)
	s := NewSessions(d)
	s.now = func() time.Time { return now }
	tok, _ := s.Create(ctx, a.ID, "", "", true)
	for i := 0; i < 7; i++ { // 35 days, never idle more than 5
		now = now.Add(5 * 24 * time.Hour)
		if _, _, err := s.Lookup(ctx, tok); err != nil {
			if i < 6 {
				t.Fatalf("day %d: %v", (i+1)*5, err)
			}
			return
		}
	}
	if _, _, err := s.Lookup(ctx, tok); err != ErrNoSession {
		t.Fatalf("session older than 30 days alive: %v", err)
	}
}
