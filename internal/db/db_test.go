package db

import (
	"context"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestMigrationsIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.db")
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	d, err = Open(p)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer d.Close()
	var n int
	if err := d.SQL.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n != len(migrationFiles()) {
		t.Fatalf("migrations recorded = %d (%v)", n, err)
	}
}

func TestLastOwnerGuard(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	a, err := d.CreateAccount(ctx, Account{Username: "boss", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetRole(ctx, a.ID, "admin"); err != ErrLastOwner {
		t.Fatalf("demote last owner: %v", err)
	}
	if err := d.DeleteAccount(ctx, a.ID); err != ErrLastOwner {
		t.Fatalf("delete last owner: %v", err)
	}
	b, _ := d.CreateAccount(ctx, Account{Username: "boss2", Role: "owner"})
	if err := d.SetRole(ctx, a.ID, "admin"); err != nil {
		t.Fatalf("demote with second owner: %v", err)
	}
	if err := d.DeleteAccount(ctx, b.ID); err != ErrLastOwner {
		t.Fatalf("delete new last owner: %v", err)
	}
}

func TestUsernameUnique(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	if _, err := d.CreateAccount(ctx, Account{Username: "Ravi", Role: "member"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, Account{Username: "ravi", Role: "member"}); err == nil {
		t.Fatal("case-insensitive duplicate accepted")
	}
}
