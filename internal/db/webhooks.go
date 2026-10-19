package db

import (
	"context"
	"strings"
	"time"
)

type Webhook struct {
	ID         int64
	Name       string
	URL        string
	Format     string
	Events     []string // empty means every event
	Secret     string
	Enabled    bool
	LastStatus int
	LastError  string
	LastAt     time.Time
	CreatedAt  time.Time
}

func (w *Webhook) Wants(kind string) bool {
	if len(w.Events) == 0 {
		return true
	}
	for _, e := range w.Events {
		if e == kind {
			return true
		}
	}
	return false
}

const webhookCols = `id, name, url, format, events, secret, enabled, last_status, last_error, last_at, created_at`

func (d *DB) CreateWebhook(ctx context.Context, w Webhook) (int64, error) {
	res, err := d.SQL.ExecContext(ctx, `INSERT INTO webhooks(name, url, format, events, secret, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)`,
		w.Name, w.URL, w.Format, strings.Join(w.Events, ","), w.Secret, d.now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) ListWebhooks(ctx context.Context) ([]*Webhook, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT `+webhookCols+` FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Webhook
	for rows.Next() {
		var w Webhook
		var evs string
		var la, ca int64
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Format, &evs, &w.Secret, &w.Enabled, &w.LastStatus, &w.LastError, &la, &ca); err != nil {
			return nil, err
		}
		if evs != "" {
			w.Events = strings.Split(evs, ",")
		}
		w.LastAt, w.CreatedAt = fromUnix(la), fromUnix(ca)
		out = append(out, &w)
	}
	return out, rows.Err()
}

func (d *DB) GetWebhook(ctx context.Context, id int64) (*Webhook, error) {
	all, err := d.ListWebhooks(ctx)
	if err != nil {
		return nil, err
	}
	for _, w := range all {
		if w.ID == id {
			return w, nil
		}
	}
	return nil, ErrNotFound
}

func (d *DB) DeleteWebhook(ctx context.Context, id int64) error {
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
	return err
}

func (d *DB) RecordWebhookResult(ctx context.Context, id int64, status int, errText string) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE webhooks SET last_status = ?, last_error = ?, last_at = ? WHERE id = ?`, status, errText, d.now().Unix(), id)
	return err
}
