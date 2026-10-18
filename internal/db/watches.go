package db

import (
	"context"
	"strings"
	"time"
)

type WatchRule struct {
	ID              int64
	AccountID       int64
	SubjectType     string // node | user | tag | all
	Subject         string // node id, headscale user name, or tag
	SubjectLabel    string // display only, filled by callers
	Events          []string
	OfflineDebounce time.Duration
	NotSeenHours    int
	CreatedAt       time.Time
}

func (w *WatchRule) Wants(kind string) bool {
	for _, e := range w.Events {
		if e == kind {
			return true
		}
	}
	return false
}

const watchCols = `id, account_id, subject_type, subject, events, offline_debounce, not_seen_hours, created_at`

func scanWatch(s scanner) (*WatchRule, error) {
	var w WatchRule
	var evs string
	var deb, c int64
	if err := s.Scan(&w.ID, &w.AccountID, &w.SubjectType, &w.Subject, &evs, &deb, &w.NotSeenHours, &c); err != nil {
		return nil, err
	}
	if evs != "" {
		w.Events = strings.Split(evs, ",")
	}
	w.OfflineDebounce = time.Duration(deb) * time.Second
	w.CreatedAt = fromUnix(c)
	return &w, nil
}

func (d *DB) CreateWatch(ctx context.Context, w WatchRule) (int64, error) {
	res, err := d.SQL.ExecContext(ctx, `INSERT INTO watch_rules(account_id, subject_type, subject, events, offline_debounce, not_seen_hours, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, w.AccountID, w.SubjectType, w.Subject, strings.Join(w.Events, ","),
		int64(w.OfflineDebounce/time.Second), w.NotSeenHours, d.now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListWatches returns rules for one account, or every rule when accountID is 0.
func (d *DB) ListWatches(ctx context.Context, accountID int64) ([]*WatchRule, error) {
	q := `SELECT ` + watchCols + ` FROM watch_rules`
	args := []any{}
	if accountID != 0 {
		q += ` WHERE account_id = ?`
		args = append(args, accountID)
	}
	rows, err := d.SQL.QueryContext(ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WatchRule
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// DeleteWatch deletes a rule owned by accountID (0 = any owner).
func (d *DB) DeleteWatch(ctx context.Context, id, accountID int64) error {
	if accountID == 0 {
		_, err := d.SQL.ExecContext(ctx, `DELETE FROM watch_rules WHERE id = ?`, id)
		return err
	}
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM watch_rules WHERE id = ? AND account_id = ?`, id, accountID)
	return err
}

type Notification struct {
	ID        int64
	AccountID int64
	Kind      string
	Text      string
	CreatedAt time.Time
}

func (d *DB) AddNotification(ctx context.Context, accountID int64, kind, text string) error {
	var acc any = accountID
	if accountID == 0 {
		acc = nil
	}
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO notifications(account_id, kind, text, created_at) VALUES (?, ?, ?, ?)`, acc, kind, text, d.now().Unix())
	if err == nil {
		// Keep the feed bounded.
		_, _ = d.SQL.ExecContext(ctx, `DELETE FROM notifications WHERE id <= (SELECT id FROM notifications ORDER BY id DESC LIMIT 1 OFFSET 5000)`)
	}
	return err
}

// ListNotifications returns an account's notifications plus global ones.
func (d *DB) ListNotifications(ctx context.Context, accountID int64, limit int) ([]*Notification, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT id, COALESCE(account_id, 0), kind, text, created_at FROM notifications
		WHERE account_id = ? OR account_id IS NULL ORDER BY id DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Notification
	for rows.Next() {
		var n Notification
		var c int64
		if err := rows.Scan(&n.ID, &n.AccountID, &n.Kind, &n.Text, &c); err != nil {
			return nil, err
		}
		n.CreatedAt = fromUnix(c)
		out = append(out, &n)
	}
	return out, rows.Err()
}
