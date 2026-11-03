// Package db is meshpanel's SQLite store. It uses the pure-Go modernc driver
// so the binary builds without cgo.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var ErrNotFound = errors.New("not found")

type DB struct {
	SQL  *sql.DB
	now  func() time.Time
	path string
}

// Open opens (creating if needed) the database at path and runs migrations.
func Open(path string) (*DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	path = absolute
	if _, err := os.Stat(path); err == nil {
		if err = CheckFileAccess(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, &AccessError{Path: path, Err: err}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, &AccessError{Path: filepath.Dir(path), Err: err}
	}
	d, err := openSQLite(path, false)
	if err != nil {
		return nil, err
	}
	if err := d.migrate(); err != nil {
		d.SQL.Close()
		return nil, err
	}
	return d, nil
}

// OpenExisting opens only an existing database without creating directories or
// running migrations. Diagnostics must not initialize a missing installation.
func OpenExisting(path string) (*DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = CheckFileAccess(absolute); err != nil {
		return nil, err
	}
	return openSQLite(absolute, true)
}

// openSQLite shares connection settings while distinguishing first-time setup
// from a diagnostic connection that must never create a database.
func openSQLite(path string, existing bool) (*DB, error) {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	if existing {
		q.Set("mode", "rw")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
	}
	for _, p := range []string{"foreign_keys(1)", "busy_timeout(5000)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	s, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	s.SetMaxOpenConns(1)
	return &DB{SQL: s, now: time.Now, path: path}, nil
}

func (d *DB) Close() error { return d.SQL.Close() }

// Now is the clock used for stored timestamps; tests may replace it.
func (d *DB) Now() time.Time { return d.now() }

func (d *DB) SetClock(f func() time.Time) { d.now = f }

func migrationFiles() []string {
	names, _ := fs.Glob(migrationsFS, "migrations/*.sql")
	sort.Strings(names)
	return names
}

func (d *DB) migrate() error {
	if _, err := d.SQL.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	for _, name := range migrationFiles() {
		var exists int
		if err := d.SQL.QueryRow(`SELECT count(*) FROM schema_migrations WHERE name = ?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := d.SQL.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)`, name, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Backup writes a consistent snapshot of the database to dest.
func (d *DB) Backup(ctx context.Context, dest string) error {
	_, err := d.SQL.ExecContext(ctx, `VACUUM INTO ?`, dest)
	return err
}

func (d *DB) GetSetting(ctx context.Context, key string) string {
	var v string
	_ = d.SQL.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v
}

func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := d.SQL.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}
