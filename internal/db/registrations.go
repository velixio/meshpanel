package db

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

const (
	StatusPending   = "pending"
	StatusApproving = "approving"
	StatusApproved  = "approved"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"
	StatusFailed    = "failed"
)

type Pending struct {
	ID          int64
	Kind        string // register | ssh
	AuthID      string
	RequesterID int64
	HSUser      string
	IP          string
	UserAgent   string
	Status      string
	DecidedBy   string
	DecidedVia  string
	DecidedAt   time.Time
	NodeName    string
	NodeIP      string
	Error       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

func (p *Pending) Open() bool { return p.Status == StatusPending }

const pendingCols = `id, kind, auth_id, requester_id, hs_user, ip, user_agent, status, decided_by, decided_via, decided_at, node_name, node_ip, error, created_at, expires_at`

func scanPending(s scanner) (*Pending, error) {
	var p Pending
	var da, ca, ea int64
	err := s.Scan(&p.ID, &p.Kind, &p.AuthID, &p.RequesterID, &p.HSUser, &p.IP, &p.UserAgent, &p.Status, &p.DecidedBy,
		&p.DecidedVia, &da, &p.NodeName, &p.NodeIP, &p.Error, &ca, &ea)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.DecidedAt, p.CreatedAt, p.ExpiresAt = fromUnix(da), fromUnix(ca), fromUnix(ea)
	return &p, nil
}

func (d *DB) InsertPending(ctx context.Context, p Pending) (*Pending, error) {
	res, err := d.SQL.ExecContext(ctx, `INSERT INTO pending_registrations(kind, auth_id, requester_id, hs_user, ip, user_agent, status, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`, p.Kind, p.AuthID, p.RequesterID, p.HSUser, p.IP, p.UserAgent, unix(p.CreatedAt), unix(p.ExpiresAt))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetPending(ctx, id)
}

func (d *DB) GetPending(ctx context.Context, id int64) (*Pending, error) {
	return scanPending(d.SQL.QueryRowContext(ctx, `SELECT `+pendingCols+` FROM pending_registrations WHERE id = ?`, id))
}

// FindOpenPending returns the open request for authID by requester, if any.
func (d *DB) FindOpenPending(ctx context.Context, authID string, requesterID int64) (*Pending, error) {
	return scanPending(d.SQL.QueryRowContext(ctx, `SELECT `+pendingCols+` FROM pending_registrations
		WHERE auth_id = ? AND requester_id = ? AND status IN ('pending','approving','approved') ORDER BY id DESC LIMIT 1`, authID, requesterID))
}

// ClaimPending moves a pending request to approving (or straight to a final
// status) only if it is still pending. False means someone else decided.
func (d *DB) ClaimPending(ctx context.Context, id int64, to, by, via string) (bool, error) {
	res, err := d.SQL.ExecContext(ctx, `UPDATE pending_registrations SET status = ?, decided_by = ?, decided_via = ?, decided_at = ?
		WHERE id = ? AND status = 'pending' AND expires_at > ?`, to, by, via, d.now().Unix(), id, d.now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (d *DB) FinishPending(ctx context.Context, id int64, status, nodeName, nodeIP, errText string) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE pending_registrations SET status = ?, node_name = ?, node_ip = ?, error = ? WHERE id = ?`,
		status, nodeName, nodeIP, errText, id)
	return err
}

// ExpirePending marks overdue pending requests expired and returns them.
func (d *DB) ExpirePending(ctx context.Context) ([]*Pending, error) {
	now := d.now().Unix()
	rows, err := d.SQL.QueryContext(ctx, `SELECT `+pendingCols+` FROM pending_registrations WHERE status = 'pending' AND expires_at <= ?`, now)
	if err != nil {
		return nil, err
	}
	var out []*Pending
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	rows.Close()
	for _, p := range out {
		if _, err := d.SQL.ExecContext(ctx, `UPDATE pending_registrations SET status = 'expired' WHERE id = ? AND status = 'pending'`, p.ID); err != nil {
			return nil, err
		}
		p.Status = StatusExpired
	}
	return out, nil
}

func (d *DB) ListPending(ctx context.Context, openOnly bool, limit int) ([]*Pending, error) {
	q := `SELECT ` + pendingCols + ` FROM pending_registrations`
	if openOnly {
		q += ` WHERE status = 'pending' AND expires_at > ` + strconv.FormatInt(d.now().Unix(), 10)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	rows, err := d.SQL.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Pending
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
