package auth

import (
	"context"
	"errors"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
)

const (
	CookieName      = "mp_session"
	SessionIdle     = 7 * 24 * time.Hour
	SessionAbsolute = 30 * 24 * time.Hour
	// touchEvery limits last_seen writes to one per minute per session.
	touchEvery = time.Minute
)

var ErrNoSession = errors.New("no valid session")

// Sessions stores sessions server-side; the cookie holds only a random
// token whose SHA-256 is the row id.
type Sessions struct {
	db  *db.DB
	now func() time.Time
}

func NewSessions(d *db.DB) *Sessions { return &Sessions{db: d, now: time.Now} }

// Create starts a session. mfaOK=false creates a half-session that is only
// good for the 2FA step.
func (s *Sessions) Create(ctx context.Context, accountID int64, ip, ua string, mfaOK bool) (string, error) {
	tok := RandomToken(32)
	now := s.now()
	err := s.db.CreateSession(ctx, db.Session{
		ID: HashToken(tok), AccountID: accountID, CSRF: RandomToken(24), MFAOK: mfaOK,
		IP: ip, UserAgent: truncate(ua, 300), CreatedAt: now, LastSeenAt: now,
	})
	return tok, err
}

// Lookup resolves a cookie token, enforcing idle and absolute lifetimes and
// skipping disabled accounts.
func (s *Sessions) Lookup(ctx context.Context, tok string) (*db.Session, *db.Account, error) {
	if tok == "" {
		return nil, nil, ErrNoSession
	}
	sess, err := s.db.GetSession(ctx, HashToken(tok))
	if err != nil {
		return nil, nil, ErrNoSession
	}
	now := s.now()
	idle := SessionIdle
	if !sess.MFAOK {
		idle = 10 * time.Minute
	}
	if now.Sub(sess.LastSeenAt) > idle || now.Sub(sess.CreatedAt) > SessionAbsolute {
		_ = s.db.DeleteSession(ctx, sess.ID)
		return nil, nil, ErrNoSession
	}
	acc, err := s.db.GetAccount(ctx, sess.AccountID)
	if err != nil || acc.Disabled {
		return nil, nil, ErrNoSession
	}
	if now.Sub(sess.LastSeenAt) > touchEvery {
		_ = s.db.TouchSession(ctx, sess.ID, now)
		sess.LastSeenAt = now
	}
	return sess, acc, nil
}

func (s *Sessions) Revoke(ctx context.Context, id string) error { return s.db.DeleteSession(ctx, id) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
