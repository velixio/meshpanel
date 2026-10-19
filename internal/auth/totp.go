package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a 160-bit base32 secret and its otpauth:// URI.
func NewTOTPSecret(issuer, account string) (secret, uri string) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	secret = b32.EncodeToString(raw)
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return secret, "otpauth://totp/" + label + "?" + q.Encode()
}

func totpAt(secret string, t time.Time) string {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

func validateTOTPAt(secret, code string, now time.Time) bool {
	_, ok := ValidateTOTPStep(secret, code, now)
	return ok
}

// ValidateTOTPStep checks a code against the current step and one either
// side, and returns the matching step so callers can refuse reuse. secret
// may be sealed (see SealSecret).
func ValidateTOTPStep(secret, code string, now time.Time) (int64, bool) {
	secret = openSecret(secret)
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 || secret == "" {
		return 0, false
	}
	for _, skew := range []int64{0, -1, 1} {
		step := now.Unix()/30 + skew
		want := totpAt(secret, time.Unix(step*30, 0))
		if want != "" && hmac.Equal([]byte(want), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

// ValidateTOTP accepts the current code and one step either side.
func ValidateTOTP(secret, code string) bool { return validateTOTPAt(secret, code, time.Now()) }

func normalizeBackupCode(c string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

// NewBackupCodes replaces the account's backup codes with 10 fresh ones and
// returns them for one-time display. Only hashes are stored.
func NewBackupCodes(ctx context.Context, d *db.DB, accountID int64) ([]string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j, b := range raw {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(b)%len(alphabet)])
		}
		codes[i] = sb.String()
		hashes[i] = HashToken(normalizeBackupCode(codes[i]))
	}
	if err := d.ReplaceBackupCodes(ctx, accountID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// UseBackupCode consumes a backup code; each works once.
func UseBackupCode(ctx context.Context, d *db.DB, accountID int64, code string) bool {
	ok, err := d.ConsumeBackupCode(ctx, accountID, HashToken(normalizeBackupCode(code)))
	return err == nil && ok
}

// TOTPCode returns the code for t (used by tests and the CLI).
func TOTPCode(secret string, t time.Time) string { return totpAt(secret, t) }
