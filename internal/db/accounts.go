package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrLastOwner = errors.New("cannot remove or demote the last owner")

type Account struct {
	ID           int64
	Username     string
	DisplayName  string
	Email        string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	Role         string
	ExtraCaps    uint64
	HSUser       string
	Theme        string
	QuietStart   string
	QuietEnd     string
	Timezone     string
	Disabled     bool
	CreatedAt    time.Time
	LastLoginAt  time.Time
}

// Name is what the UI and Telegram show for this person.
func (a *Account) Name() string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.Username
}

const accountCols = `id, username, display_name, email, password_hash, totp_secret, totp_enabled, role, extra_caps, hs_user, theme, quiet_start, quiet_end, timezone, disabled, created_at, last_login_at`

type scanner interface{ Scan(...any) error }

func scanAccount(s scanner) (*Account, error) {
	var a Account
	var created, last int64
	var extra int64
	err := s.Scan(&a.ID, &a.Username, &a.DisplayName, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.TOTPEnabled,
		&a.Role, &extra, &a.HSUser, &a.Theme, &a.QuietStart, &a.QuietEnd, &a.Timezone, &a.Disabled, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.ExtraCaps = uint64(extra)
	a.CreatedAt, a.LastLoginAt = fromUnix(created), fromUnix(last)
	return &a, nil
}

func (d *DB) CreateAccount(ctx context.Context, a Account) (*Account, error) {
	if a.Theme == "" {
		a.Theme = "paper"
	}
	if a.Timezone == "" {
		a.Timezone = "UTC"
	}
	res, err := d.SQL.ExecContext(ctx, `INSERT INTO accounts(username, display_name, email, password_hash, totp_secret, totp_enabled, role, extra_caps, hs_user, theme, timezone, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Username, a.DisplayName, a.Email, a.PasswordHash, a.TOTPSecret, a.TOTPEnabled, a.Role, int64(a.ExtraCaps), a.HSUser, a.Theme, a.Timezone, d.now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetAccount(ctx, id)
}

func (d *DB) GetAccount(ctx context.Context, id int64) (*Account, error) {
	return scanAccount(d.SQL.QueryRowContext(ctx, `SELECT `+accountCols+` FROM accounts WHERE id = ?`, id))
}

func (d *DB) GetAccountByUsername(ctx context.Context, username string) (*Account, error) {
	return scanAccount(d.SQL.QueryRowContext(ctx, `SELECT `+accountCols+` FROM accounts WHERE username = ?`, username))
}

func (d *DB) ListAccounts(ctx context.Context) ([]*Account, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT `+accountCols+` FROM accounts ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) CountAccounts(ctx context.Context) (int, error) {
	var n int
	err := d.SQL.QueryRowContext(ctx, `SELECT count(*) FROM accounts`).Scan(&n)
	return n, err
}

// ownersExcept counts active owners other than id.
func ownersExcept(ctx context.Context, tx *sql.Tx, id int64) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE role = 'owner' AND disabled = 0 AND id != ?`, id).Scan(&n)
	return n, err
}

// guardOwner runs fn in a transaction, refusing when it would leave no owner.
func (d *DB) guardOwner(ctx context.Context, id int64, removesOwner bool, fn func(*sql.Tx) error) error {
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM accounts WHERE id = ?`, id).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if role == "owner" && removesOwner {
		n, err := ownersExcept(ctx, tx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLastOwner
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) SetRole(ctx context.Context, id int64, role string) error {
	return d.guardOwner(ctx, id, role != "owner", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE accounts SET role = ? WHERE id = ?`, role, id)
		return err
	})
}

func (d *DB) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	return d.guardOwner(ctx, id, disabled, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE accounts SET disabled = ? WHERE id = ?`, disabled, id); err != nil {
			return err
		}
		if disabled {
			_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id = ?`, id)
			return err
		}
		return nil
	})
}

func (d *DB) DeleteAccount(ctx context.Context, id int64) error {
	return d.guardOwner(ctx, id, true, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, id)
		return err
	})
}

// UpdateAccount writes the editable profile fields (not role, which goes
// through SetRole for the last-owner guard).
func (d *DB) UpdateAccount(ctx context.Context, a *Account) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE accounts SET display_name = ?, email = ?, password_hash = ?, totp_secret = ?, totp_enabled = ?,
		extra_caps = ?, hs_user = ?, theme = ?, quiet_start = ?, quiet_end = ?, timezone = ? WHERE id = ?`,
		a.DisplayName, a.Email, a.PasswordHash, a.TOTPSecret, a.TOTPEnabled, int64(a.ExtraCaps), a.HSUser, a.Theme,
		a.QuietStart, a.QuietEnd, a.Timezone, a.ID)
	return err
}

func (d *DB) TouchLogin(ctx context.Context, id int64) error {
	_, err := d.SQL.ExecContext(ctx, `UPDATE accounts SET last_login_at = ? WHERE id = ?`, d.now().Unix(), id)
	return err
}

// AccountsByHSUser maps headscale user names to the panel accounts linked to them.
func (d *DB) AccountsByHSUser(ctx context.Context) (map[string]*Account, error) {
	all, err := d.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*Account, len(all))
	for _, a := range all {
		if a.HSUser != "" {
			m[a.HSUser] = a
		}
	}
	return m, nil
}

// UseTOTPStep records step as used. It returns false when this or a later
// step was already used: the code has been seen before.
func (d *DB) UseTOTPStep(ctx context.Context, id, step int64) (bool, error) {
	res, err := d.SQL.ExecContext(ctx, `UPDATE accounts SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
