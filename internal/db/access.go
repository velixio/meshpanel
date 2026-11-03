package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	sysunix "golang.org/x/sys/unix"
	"modernc.org/sqlite"
)

// AccessError identifies an inaccessible database path without altering it.
type AccessError struct {
	Path string
	Err  error
}

// Error describes the database path that failed its access check.
func (e *AccessError) Error() string {
	return fmt.Sprintf("database write access to %s: %v", e.Path, e.Err)
}

// Unwrap preserves the underlying filesystem error for callers.
func (e *AccessError) Unwrap() error { return e.Err }

// IsReadOnly recognizes SQLite's primary and extended read-only errors and
// filesystem access failures found by the database preflight.
func IsReadOnly(err error) bool {
	var access *AccessError
	if errors.As(err, &access) {
		return true
	}
	var sqlErr *sqlite.Error
	return errors.As(err, &sqlErr) && sqlErr.Code()&0xff == 8
}

// CheckFileAccess checks effective-user access to existing database files and
// their directory. It never creates, removes, chmods, or chowns any path.
func CheckFileAccess(path string) error {
	paths := []struct {
		path     string
		mode     uint32
		optional bool
	}{
		{filepath.Dir(path), sysunix.W_OK | sysunix.X_OK, false},
		{path, sysunix.R_OK | sysunix.W_OK, false},
		{path + "-wal", sysunix.R_OK | sysunix.W_OK, true},
		{path + "-shm", sysunix.R_OK | sysunix.W_OK, true},
	}
	for _, p := range paths {
		if p.optional {
			if _, err := os.Stat(p.path); os.IsNotExist(err) {
				continue
			}
		}
		if err := sysunix.Faccessat(sysunix.AT_FDCWD, p.path, p.mode, sysunix.AT_EACCESS); err != nil {
			return &AccessError{Path: p.path, Err: err}
		}
	}
	return nil
}

// CheckWritable tests the current SQLite connection with a zero-row update in
// a rolled-back transaction. No stored values, rows, or schema are changed.
func (d *DB) CheckWritable(ctx context.Context) error {
	if d.path != "" {
		if err := CheckFileAccess(d.path); err != nil {
			return err
		}
	}
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE settings SET value = value WHERE 0`); err != nil {
		return err
	}
	return tx.Rollback()
}

// Path returns the configured absolute database path for diagnostic messages.
func (d *DB) Path() string { return d.path }

// shellQuote protects paths and account names in administrator-facing examples.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// AccessInstructions reports actual ownership and conservative manual recovery
// commands. It performs no repair and never suggests deleting or recreating data.
func AccessInstructions(path string) string {
	absolute, err := filepath.Abs(path)
	if err == nil {
		path = absolute
	}
	uid, gid := strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid())
	username, group := uid, gid
	if u, err := user.LookupId(uid); err == nil {
		username = u.Username
	}
	if g, err := user.LookupGroupId(gid); err == nil {
		group = g.Name
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Database: %s\nProcess user/group: %s:%s (uid %s, gid %s)\n", path, username, group, uid, gid)
	files := []string{}
	for _, p := range []string{filepath.Dir(path), path, path + "-wal", path + "-shm"} {
		st, err := os.Stat(p)
		if err != nil {
			if !os.IsNotExist(err) || p == path || p == filepath.Dir(path) {
				fmt.Fprintf(&out, "%s: %v\n", p, err)
			}
			continue
		}
		owner := ""
		if stat, ok := st.Sys().(*syscall.Stat_t); ok {
			owner = fmt.Sprintf("uid %d, gid %d", stat.Uid, stat.Gid)
		}
		fmt.Fprintf(&out, "%s: mode %04o, %s\n", p, st.Mode().Perm(), owner)
		if p != filepath.Dir(path) && st.Mode().IsRegular() {
			files = append(files, shellQuote(p))
		}
	}
	out.WriteString("No automatic permission changes are made. Do not delete or recreate the database, WAL, or SHM files.\n")
	out.WriteString("Check the service identity and sandbox:\nsudo systemctl show meshpanel -p User -p Group -p ReadWritePaths -p ProtectSystem\n")
	if os.Geteuid() == 0 {
		out.WriteString("Root access does not prove that the service can write. Run doctor as the configured service user (normally: sudo -u meshpanel /usr/bin/meshpanel doctor -c /etc/meshpanel/config.yaml).\n")
	} else if len(files) > 0 {
		out.WriteString("If these files have incorrect ownership or owner write permissions, use the following for meshpanel.service:\nsudo systemctl stop meshpanel\n")
		fmt.Fprintf(&out, "sudo chown -- %s %s\nsudo chmod u+rw -- %s\nsudo systemctl start meshpanel\n", shellQuote(username+":"+group), strings.Join(files, " "), strings.Join(files, " "))
	}
	fmt.Fprintf(&out, "The service user also needs write/search access to %s. Check filesystem mount permissions, ACLs, and systemd ReadWritePaths if ownership is already correct. Restart Meshpanel after repairs to reopen SQLite connections.", filepath.Dir(path))
	return out.String()
}
