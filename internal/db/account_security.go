package db

import (
	"context"
	"database/sql"
)

// changeAccountSecurity applies credential changes and revokes all sessions in
// one transaction, so failed cleanup cannot leave partially reset credentials.
func (d *DB) changeAccountSecurity(ctx context.Context, id int64, change func(*sql.Tx) error) error {
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM accounts WHERE id = ?`, id).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if err = change(tx); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAccountPassword changes only the password hash and signs out every session.
func (d *DB) SetAccountPassword(ctx context.Context, id int64, hash string) error {
	return d.changeAccountSecurity(ctx, id, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE accounts SET password_hash = ? WHERE id = ?`, hash, id)
		return err
	})
}

// ResetAccountTwoFactor removes the authenticator, replay state, backup codes,
// and sessions together. Password authentication will require fresh enrollment.
func (d *DB) ResetAccountTwoFactor(ctx context.Context, id int64) error {
	return d.changeAccountSecurity(ctx, id, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE accounts SET totp_enabled = 0, totp_secret = '', totp_last_step = 0 WHERE id = ?`, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM backup_codes WHERE account_id = ?`, id)
		return err
	})
}
