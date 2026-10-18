package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Session struct {
	ID         string
	AccountID  int64
	CSRF       string
	MFAOK      bool
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

const sessionCols = `id, account_id, csrf, mfa_ok, ip, user_agent, created_at, last_seen_at`

func scanSession(s scanner) (*Session, error) {
	var x Session
	var c, l int64
	err := s.Scan(&x.ID, &x.AccountID, &x.CSRF, &x.MFAOK, &x.IP, &x.UserAgent, &c, &l)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	x.CreatedAt, x.LastSeenAt = fromUnix(c), fromUnix(l)
	return &x, nil
}

func (d *DB) CreateSession(ctx context.Context, s Session) error {
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO sessions(`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.AccountID, s.CSRF, s.MFAOK, s.IP, s.UserAgent, unix(s.CreatedAt), unix(s.LastSeenAt))
	return err
}

func (d *DB) GetSession(ctx context.Context, id string) (*Session, error) {
	return scanSession(d.SQL.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = ?`, id))
}

func (d *DB) TouchSession(ctx context.Context, id string, at time.Time) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, at.Unix(), id)
	return err
}

func (d *DB) MarkSessionMFA(ctx context.Context, id string) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE sessions SET mfa_ok = 1 WHERE id = ?`, id)
	return err
}

func (d *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (d *DB) DeleteSessionsFor(ctx context.Context, accountID int64, except string) error {
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM sessions WHERE account_id = ? AND id != ?`, accountID, except)
	return err
}

func (d *DB) ListSessions(ctx context.Context, accountID int64) ([]*Session, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE account_id = ? AND mfa_ok = 1 ORDER BY last_seen_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---- backup codes ----

func (d *DB) ReplaceBackupCodes(ctx context.Context, accountID int64, hashes []string) error {
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM backup_codes WHERE account_id = ?`, accountID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_codes(account_id, code_hash) VALUES (?, ?)`, accountID, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ConsumeBackupCode marks the unused code with this hash as used. It reports
// whether one was found.
func (d *DB) ConsumeBackupCode(ctx context.Context, accountID int64, hash string) (bool, error) {
	res, err := d.SQL.ExecContext(ctx, `UPDATE backup_codes SET used_at = ? WHERE id = (
		SELECT id FROM backup_codes WHERE account_id = ? AND code_hash = ? AND used_at = 0 LIMIT 1)`,
		d.now().Unix(), accountID, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (d *DB) RemainingBackupCodes(ctx context.Context, accountID int64) int {
	var n int
	_ = d.SQL.QueryRowContext(ctx, `SELECT count(*) FROM backup_codes WHERE account_id = ? AND used_at = 0`, accountID).Scan(&n)
	return n
}

// ---- invites ----

type Invite struct {
	TokenHash string
	Username  string
	Role      string
	HSUser    string
	CreatedBy int64
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

func (d *DB) CreateInvite(ctx context.Context, in Invite) error {
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO invites(token_hash, username, role, hs_user, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		in.TokenHash, in.Username, in.Role, in.HSUser, in.CreatedBy, unix(in.CreatedAt), unix(in.ExpiresAt))
	return err
}

// GetInvite returns an unused, unexpired invite.
func (d *DB) GetInvite(ctx context.Context, tokenHash string) (*Invite, error) {
	var in Invite
	var c, e, u int64
	err := d.SQL.QueryRowContext(ctx, `SELECT token_hash, username, role, hs_user, created_by, created_at, expires_at, used_at FROM invites WHERE token_hash = ?`, tokenHash).
		Scan(&in.TokenHash, &in.Username, &in.Role, &in.HSUser, &in.CreatedBy, &c, &e, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	in.CreatedAt, in.ExpiresAt, in.UsedAt = fromUnix(c), fromUnix(e), fromUnix(u)
	if u != 0 || d.now().After(in.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &in, nil
}

// UseInvite atomically marks an invite used; false means it was already used.
func (d *DB) UseInvite(ctx context.Context, tokenHash string) (bool, error) {
	res, err := d.SQL.ExecContext(ctx, `UPDATE invites SET used_at = ? WHERE token_hash = ? AND used_at = 0 AND expires_at > ?`,
		d.now().Unix(), tokenHash, d.now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (d *DB) ListInvites(ctx context.Context) ([]*Invite, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT token_hash, username, role, hs_user, created_by, created_at, expires_at, used_at FROM invites WHERE used_at = 0 AND expires_at > ? ORDER BY created_at DESC`, d.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invite
	for rows.Next() {
		var in Invite
		var c, e, u int64
		if err := rows.Scan(&in.TokenHash, &in.Username, &in.Role, &in.HSUser, &in.CreatedBy, &c, &e, &u); err != nil {
			return nil, err
		}
		in.CreatedAt, in.ExpiresAt = fromUnix(c), fromUnix(e)
		out = append(out, &in)
	}
	return out, rows.Err()
}

func (d *DB) DeleteInvite(ctx context.Context, tokenHash string) error {
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM invites WHERE token_hash = ?`, tokenHash)
	return err
}
