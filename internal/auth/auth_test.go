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

func TestTOTPStepReported(t *testing.T) {
	secret, _ := NewTOTPSecret("Acme", "ravi")
	now := time.Unix(1_800_000_000, 0)
	step, ok := ValidateTOTPStep(secret, totpAt(secret, now), now)
	if !ok || step != now.Unix()/30 {
		t.Fatalf("step %d ok %v", step, ok)
	}
	prev, ok := ValidateTOTPStep(secret, totpAt(secret, now.Add(-30*time.Second)), now)
	if !ok || prev != step-1 {
		t.Fatalf("previous-step code: %d %v", prev, ok)
	}
}

func TestSecretSealing(t *testing.T) {
	SetSecretKey("0123456789abcdef0123456789abcdef")
	defer SetSecretKey("")
	sealed := SealSecret("JBSWY3DPEHPK3PXP")
	if sealed == "JBSWY3DPEHPK3PXP" || !strings.HasPrefix(sealed, "enc1:") {
		t.Fatalf("not sealed: %q", sealed)
	}
	if got := openSecret(sealed); got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round trip %q", got)
	}
	if got := openSecret("JBSWY3DPEHPK3PXP"); got != "JBSWY3DPEHPK3PXP" {
		t.Fatal("legacy plaintext secrets must still work")
	}
	code := totpAt("JBSWY3DPEHPK3PXP", time.Now())
	if !ValidateTOTP(sealed, code) {
		t.Fatal("ValidateTOTP must accept sealed secrets")
	}
	SetSecretKey("another-secret-another-secret-xx")
	if openSecret(sealed) != "" {
		t.Fatal("wrong key must not decrypt")
	}
}

func TestLimiterAcquireCountsInFlight(t *testing.T) {
	l := NewLimiterWith(2, time.Minute)
	got := 0
	for i := 0; i < 10; i++ { // ten parallel attempts, none finished yet
		if ok, _ := l.Acquire("k"); ok {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("%d attempts in flight, want 2", got)
	}
	l.Release("k", true)
	l.Release("k", true)
	if ok, _ := l.Acquire("k"); !ok {
		t.Fatal("past the free attempts, one at a time should still be allowed")
	}
	if ok, _ := l.Acquire("k"); ok {
		t.Fatal("a second parallel attempt past the free ones was allowed")
	}
}
