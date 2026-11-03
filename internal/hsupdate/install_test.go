package hsupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fixture creates an isolated binary, configuration, and SQLite data tree for upgrade tests.
func fixture(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	c := Config{Binary: filepath.Join(dir, "bin", "headscale"), ConfigDir: filepath.Join(dir, "config"), DataDir: filepath.Join(dir, "data"), BackupDir: filepath.Join(dir, "backups"), Service: "headscale.service", HealthURL: "http://127.0.0.1:8045/health"}
	for _, p := range []string{filepath.Dir(c.Binary), c.ConfigDir, c.DataDir, c.BackupDir} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{c.Binary: "old", filepath.Join(c.ConfigDir, "config.yaml"): "database:\n  type: sqlite\n  sqlite:\n    path: " + filepath.Join(c.DataDir, "db.sqlite") + "\n", filepath.Join(c.DataDir, "db.sqlite"): "database", filepath.Join(c.DataDir, "db.sqlite-wal"): "wal", filepath.Join(dir, "new"): "new"}
	for p, b := range files {
		if err := os.WriteFile(p, []byte(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return c, filepath.Join(dir, "new")
}

// TestInstallLifecycle checks replacement ordering, backup contents, and service recovery.
func TestInstallLifecycle(t *testing.T) {
	for _, fail := range []string{"", "backup", "health", "start", "stop"} {
		t.Run(fail, func(t *testing.T) {
			c, binary := fixture(t)
			var service []string
			stopped := false
			i := Installer{Config: c, Healthy: func(context.Context) error {
				if fail == "health" {
					return errors.New("unhealthy")
				}
				return nil
			}}
			i.Run = func(ctx context.Context, name string, args ...string) error {
				if name == "/usr/bin/systemctl" {
					service = append(service, args[0])
					if args[0] == "stop" {
						stopped = true
					}
					if args[0] == fail {
						return errors.New("service failure")
					}
					return nil
				}
				if name == "/usr/bin/cp" {
					if !stopped {
						t.Fatal("backup before stopping")
					}
					if fail == "backup" {
						return errors.New("disk full")
					}
				}
				return command(ctx, name, args...)
			}
			backup, err := i.Install(context.Background(), binary)
			if (err != nil) != (fail != "") {
				t.Fatalf("err=%v", err)
			}
			got, _ := os.ReadFile(c.Binary)
			if fail == "backup" || fail == "stop" {
				if string(got) != "old" {
					t.Fatal("changed binary before backup")
				}
			} else {
				if string(got) != "new" {
					t.Fatalf("binary=%s", got)
				}
				for _, p := range []string{"headscale", "config/config.yaml", "data/db.sqlite", "data/db.sqlite-wal"} {
					if _, err := os.Stat(filepath.Join(backup, p)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if fail == "backup" && !strings.HasSuffix(strings.Join(service, ","), "start") {
				t.Fatal("did not restart original service after backup failure")
			}
		})
	}
}

// TestInstallRefusesConcurrentOperation ensures a held lock prevents a second installation.
func TestInstallRefusesConcurrentOperation(t *testing.T) {
	c, binary := fixture(t)
	f, err := os.OpenFile(filepath.Join(c.BackupDir, "update.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_, err = (Installer{Config: c}).Install(context.Background(), binary)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("err=%v", err)
	}
}

// TestConfigRejectsUnsafePaths covers ambiguous paths, overlapping backups, and invalid service targets.
func TestConfigRejectsUnsafePaths(t *testing.T) {
	c, _ := fixture(t)
	for _, mutate := range []func(*Config){func(c *Config) { c.Binary = "headscale" }, func(c *Config) { c.BackupDir = c.DataDir + "/backup" }, func(c *Config) { c.Service = "--bad" }, func(c *Config) { c.HealthURL = "https://remote/health" }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("trusted unowned/missing config")
	}
}

// TestInstallRejectsUnsupportedDatabase ensures unsupported databases never reach service operations.
func TestInstallRejectsUnsupportedDatabase(t *testing.T) {
	c, binary := fixture(t)
	if err := os.WriteFile(filepath.Join(c.ConfigDir, "config.yaml"), []byte("database:\n  type: postgres\n"), 0600); err != nil {
		t.Fatal(err)
	}
	i := Installer{Config: c, Run: func(context.Context, string, ...string) error {
		t.Fatal("service changed for unsupported database")
		return nil
	}}
	if _, err := i.Install(context.Background(), binary); err == nil {
		t.Fatal("accepted postgres")
	}
}

// TestCancelledBackupRestartsWithFreshContext covers client/timeout cancellation
// after systemd has stopped Headscale but before the binary was replaced.
func TestCancelledBackupRestartsWithFreshContext(t *testing.T) {
	c, binary := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recovered := false
	i := Installer{Config: c, Run: func(runCtx context.Context, name string, args ...string) error {
		if name == "/usr/bin/systemctl" {
			if args[0] == "start" {
				recovered = runCtx.Err() == nil
			}
			return nil
		}
		if name == "/usr/bin/cp" {
			cancel()
			return context.Canceled
		}
		return command(runCtx, name, args...)
	}}
	if _, err := i.Install(ctx, binary); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if !recovered {
		t.Fatal("recovery inherited canceled context")
	}
	b, _ := os.ReadFile(c.Binary)
	if string(b) != "old" {
		t.Fatal("replaced binary after cancellation")
	}
}
