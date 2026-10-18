package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type TelegramLink struct {
	AccountID int64
	ChatID    int64
	Name      string
	LinkedAt  time.Time
}

func (d *DB) CreateLinkToken(ctx context.Context, token string, accountID int64, ttl time.Duration) error {
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO telegram_link_tokens(token, account_id, expires_at) VALUES (?, ?, ?)`,
		token, accountID, d.now().Add(ttl).Unix())
	return err
}

// UseLinkToken consumes a valid token and returns its account.
func (d *DB) UseLinkToken(ctx context.Context, token string) (int64, error) {
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var acc int64
	err = tx.QueryRowContext(ctx, `SELECT account_id FROM telegram_link_tokens WHERE token = ? AND used_at = 0 AND expires_at > ?`,
		token, d.now().Unix()).Scan(&acc)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE telegram_link_tokens SET used_at = ? WHERE token = ?`, d.now().Unix(), token); err != nil {
		return 0, err
	}
	return acc, tx.Commit()
}

// LinkChat binds a Telegram chat to an account, replacing earlier links of
// either side.
func (d *DB) LinkChat(ctx context.Context, accountID, chatID int64, name string) error {
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM telegram_links WHERE account_id = ? OR chat_id = ?`, accountID, chatID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO telegram_links(account_id, chat_id, tg_name, linked_at) VALUES (?, ?, ?, ?)`,
		accountID, chatID, name, d.now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) UnlinkAccount(ctx context.Context, accountID int64) error {
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM telegram_links WHERE account_id = ?`, accountID)
	return err
}

func (d *DB) UnlinkChat(ctx context.Context, chatID int64) error {
	_, err := d.SQL.ExecContext(ctx, `DELETE FROM telegram_links WHERE chat_id = ?`, chatID)
	return err
}

func (d *DB) LinkForAccount(ctx context.Context, accountID int64) (*TelegramLink, error) {
	var l TelegramLink
	var at int64
	err := d.SQL.QueryRowContext(ctx, `SELECT account_id, chat_id, tg_name, linked_at FROM telegram_links WHERE account_id = ?`, accountID).
		Scan(&l.AccountID, &l.ChatID, &l.Name, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	l.LinkedAt = fromUnix(at)
	return &l, err
}

func (d *DB) AccountForChat(ctx context.Context, chatID int64) (int64, error) {
	var id int64
	err := d.SQL.QueryRowContext(ctx, `SELECT account_id FROM telegram_links WHERE chat_id = ?`, chatID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (d *DB) ListLinks(ctx context.Context) ([]*TelegramLink, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT account_id, chat_id, tg_name, linked_at FROM telegram_links`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TelegramLink
	for rows.Next() {
		var l TelegramLink
		var at int64
		if err := rows.Scan(&l.AccountID, &l.ChatID, &l.Name, &at); err != nil {
			return nil, err
		}
		l.LinkedAt = fromUnix(at)
		out = append(out, &l)
	}
	return out, rows.Err()
}

type TelegramAction struct {
	ID        string
	Kind      string
	TargetID  int64
	Arg       string
	ExpiresAt time.Time
	UsedAt    time.Time
}

func (d *DB) CreateAction(ctx context.Context, a TelegramAction) error {
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO telegram_actions(id, kind, target_id, arg, expires_at) VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.Kind, a.TargetID, a.Arg, unix(a.ExpiresAt))
	return err
}

// GetAction returns an unused, unexpired action.
func (d *DB) GetAction(ctx context.Context, id string) (*TelegramAction, error) {
	var a TelegramAction
	var e, u int64
	err := d.SQL.QueryRowContext(ctx, `SELECT id, kind, target_id, arg, expires_at, used_at FROM telegram_actions WHERE id = ?`, id).
		Scan(&a.ID, &a.Kind, &a.TargetID, &a.Arg, &e, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.ExpiresAt, a.UsedAt = fromUnix(e), fromUnix(u)
	if u != 0 || !d.now().Before(a.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &a, nil
}

// UseActionsFor marks every action for a target used, so stale buttons die.
func (d *DB) UseActionsFor(ctx context.Context, targetID int64) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE telegram_actions SET used_at = ? WHERE target_id = ? AND used_at = 0`, d.now().Unix(), targetID)
	if err == nil {
		_, _ = d.SQL.ExecContext(ctx, `DELETE FROM telegram_actions WHERE expires_at < ?`, d.now().Add(-24*time.Hour).Unix())
	}
	return err
}

type TelegramMessage struct {
	ChatID    int64
	MessageID int
}

func (d *DB) AddMessage(ctx context.Context, refKind string, refID, chatID int64, msgID int) error {
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO telegram_messages(ref_kind, ref_id, chat_id, message_id) VALUES (?, ?, ?, ?)`, refKind, refID, chatID, msgID)
	return err
}

func (d *DB) MessagesFor(ctx context.Context, refKind string, refID int64) ([]TelegramMessage, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT chat_id, message_id FROM telegram_messages WHERE ref_kind = ? AND ref_id = ?`, refKind, refID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TelegramMessage
	for rows.Next() {
		var m TelegramMessage
		if err := rows.Scan(&m.ChatID, &m.MessageID); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
