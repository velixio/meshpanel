// Package auth holds meshpanel's credential primitives: argon2id passwords,
// TOTP, backup codes, login rate limiting and server-side sessions.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const MinPasswordLen = 10

var ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLen)

// OWASP's recommended argon2id baseline (19 MiB, 2 passes, 1 lane). Kept
// modest so a burst of logins doesn't balloon the panel's memory.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

// argonSlots caps concurrent argon2 runs so a flood of logins queues instead
// of allocating 19 MiB per request until the process runs out of memory.
var argonSlots = make(chan struct{}, max(runtime.NumCPU(), 2))

func idKey(pw, salt []byte, t, m uint32, p uint8, n uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(pw, salt, t, m, p, n)
}

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < MinPasswordLen {
		return "", ErrPasswordTooShort
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := idKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// dummyHash is verified against when an account doesn't exist, so a missing
// username costs the same time as a wrong password. Built on first use.
var (
	dummyOnce sync.Once
	dummyHash string
)

// VerifyPassword reports whether pw matches hash. An empty hash verifies
// against a dummy to keep timing uniform, and always fails.
func VerifyPassword(hash, pw string) bool {
	ok := verify(hash, pw)
	if hash == "" {
		dummyOnce.Do(func() { dummyHash, _ = HashPassword("meshpanel-timing-equalizer") })
		verify(dummyHash, pw)
		return false
	}
	return ok
}

func verify(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := idKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// RandomToken returns n random bytes, base64url encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is how bearer-style tokens (sessions, invites) are stored: a
// database leak does not yield usable cookies.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

var ErrInvalidCredentials = errors.New("invalid username or password")
