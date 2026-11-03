package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckWritablePreservesData checks real write probing and SQLite read-only detection without changing stored rows.
func TestCheckWritablePreservesData(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	if _, err := d.SQL.Exec(`INSERT INTO settings(key,value) VALUES('keep','original')`); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckWritable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	err := d.CheckWritable(ctx)
	if !IsReadOnly(fmt.Errorf("wrapped: %w", err)) {
		t.Fatalf("expected read-only error, got %v", err)
	}
	var value string
	if err := d.SQL.QueryRow(`SELECT value FROM settings WHERE key='keep'`).Scan(&value); err != nil || value != "original" {
		t.Fatalf("data changed: %q, %v", value, err)
	}
	if _, err := os.Stat(d.Path()); err != nil {
		t.Fatal(err)
	}
}

// TestOpenExistingNeverInitializes ensures diagnostics leave a missing installation untouched.
func TestOpenExistingNeverInitializes(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "missing")
	if d, err := OpenExisting(filepath.Join(parent, "panel.db")); err == nil {
		d.Close()
		t.Fatal("opened missing database")
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("directory created: %v", err)
	}
}

// TestCheckFileAccessPreservesPermissions verifies inaccessible files are reported without repair or removal.
func TestCheckFileAccessPreservesPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses owner permissions")
	}
	d := openTest(t)
	if err := os.Chmod(d.Path(), 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d.Path(), 0600) })
	if err := d.CheckWritable(context.Background()); !IsReadOnly(err) {
		t.Fatalf("expected access failure: %v", err)
	}
	st, err := os.Stat(d.Path())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0400 {
		t.Fatalf("permissions changed: %v", st.Mode())
	}
}
