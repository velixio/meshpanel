package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"strings"
	"sync"
)

// TOTP secrets are stored sealed with a key derived from the server's
// session_secret, so a copy of the database alone can't mint 2FA codes.
// Changing session_secret makes existing 2FA secrets unreadable; reset them
// with `meshpanel user reset-2fa`.

const sealedPrefix = "enc1:"

var (
	keyMu  sync.RWMutex
	sealer cipher.AEAD
)

// SetSecretKey derives the sealing key; an empty secret turns sealing off.
func SetSecretKey(secret string) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if secret == "" {
		sealer = nil
		return
	}
	k := sha256.Sum256([]byte("meshpanel totp seal v1\x00" + secret))
	block, _ := aes.NewCipher(k[:])
	sealer, _ = cipher.NewGCM(block)
}

// SealSecret encrypts a secret for storage (plaintext if no key is set).
func SealSecret(plain string) string {
	keyMu.RLock()
	a := sealer
	keyMu.RUnlock()
	if a == nil || plain == "" {
		return plain
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte(plain), nil))
}

// openSecret decrypts a stored secret; legacy plaintext passes through.
// It returns "" when the secret can't be decrypted.
func openSecret(stored string) string {
	if !strings.HasPrefix(stored, sealedPrefix) {
		return stored
	}
	keyMu.RLock()
	a := sealer
	keyMu.RUnlock()
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, sealedPrefix))
	if a == nil || err != nil || len(raw) < a.NonceSize() {
		slog.Warn("cannot decrypt a 2FA secret (was server.session_secret changed?)")
		return ""
	}
	plain, err := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], nil)
	if err != nil {
		slog.Warn("cannot decrypt a 2FA secret (was server.session_secret changed?)")
		return ""
	}
	return string(plain)
}

// OpenSecret is openSecret for callers that need the plain secret (to show
// it during enrollment).
func OpenSecret(stored string) string { return openSecret(stored) }
