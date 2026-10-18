package db

import (
	"context"
	"strings"
	"time"
)

type AuditEntry struct {
	ID      int64
	At      time.Time
	ActorID int64
	Actor   string
	Channel string
	Action  string
	Target  string
	Before  string
	After   string
	IP      string
}

func (d *DB) InsertAudit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = d.now()
	}
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO audit_log(at, actor_id, actor, channel, action, target, before, after, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.Unix(), e.ActorID, e.Actor, e.Channel, e.Action, e.Target, e.Before, e.After, e.IP)
	return err
}

type AuditFilter struct {
	Query  string // matches actor, action or target
	Since  time.Time
	Until  time.Time
	Limit  int
	Offset int
}

func (d *DB) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditEntry, error) {
	q := `SELECT id, at, actor_id, actor, channel, action, target, before, after, ip FROM audit_log WHERE 1=1`
	var args []any
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + strings.NewReplacer("%", `\%`, "_", `\_`).Replace(s) + "%"
		q += ` AND (actor LIKE ? ESCAPE '\' OR action LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}
	if !f.Since.IsZero() {
		q += ` AND at >= ?`
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		q += ` AND at < ?`
		args = append(args, f.Until.Unix())
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)
	rows, err := d.SQL.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.ActorID, &e.Actor, &e.Channel, &e.Action, &e.Target, &e.Before, &e.After, &e.IP); err != nil {
			return nil, err
		}
		e.At = fromUnix(at)
		out = append(out, &e)
	}
	return out, rows.Err()
}
