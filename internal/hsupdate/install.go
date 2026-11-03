// Package hsupdate manages local Headscale patch upgrades through a root-owned
// configuration. The web process cannot choose paths, commands or repositories.
package hsupdate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/meshpanel/meshpanel/internal/update"
	"gopkg.in/yaml.v3"
)

const ConfigPath = "/etc/meshpanel/headscale-update.yaml"

// Config describes a local systemd installation using SQLite. It is separate
// from the panel configuration because the privileged helper must trust it.
type Config struct {
	Binary    string `yaml:"binary"`
	ConfigDir string `yaml:"config_dir"`
	DataDir   string `yaml:"data_dir"`
	BackupDir string `yaml:"backup_dir"`
	Service   string `yaml:"service"`
	HealthURL string `yaml:"health_url"`
}

// Load accepts only root-owned configuration and parent directories that cannot
// be modified by the service account. Symlinks are rejected at this boundary.
func Load(path string) (Config, error) {
	var c Config
	if !filepath.IsAbs(path) {
		return c, errors.New("helper config path must be absolute")
	}
	if err := trustedPath(path); err != nil {
		return c, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = yaml.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

// trustedPath checks the full path before privileged execution or writes.
func trustedPath(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("%s must be root-owned, not a symlink, and not writable by group or others", p)
		}
		if p == "/" {
			break
		}
	}
	return nil
}

// Validate rejects ambiguous paths and installations this helper cannot back up.
func (c Config) Validate() error {
	for _, p := range []string{c.Binary, c.ConfigDir, c.DataDir, c.BackupDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) == "/" {
			return errors.New("binary, config_dir, data_dir and backup_dir must be absolute non-root paths")
		}
	}
	for _, p := range []string{c.ConfigDir, c.DataDir} {
		if within(p, c.BackupDir) || within(c.BackupDir, p) {
			return errors.New("backup_dir must be separate from configuration and data directories")
		}
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*\.service$`).MatchString(c.Service) {
		return errors.New("service must be a systemd .service unit name")
	}
	u, err := url.Parse(c.HealthURL)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || u.Port() == "" {
		return errors.New("health_url must use the local Headscale HTTP listener")
	}
	return nil
}

// within reports whether path is contained in parent after lexical normalization.
func within(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

var versionRE = regexp.MustCompile(`(?:^|\s)(v?\d+\.\d+\.\d+)(?:$|\s)`)

// Current reads the installed binary's version without contacting the panel.
func Current(ctx context.Context, c Config) (string, error) {
	if err := trustedPath(c.Binary); err != nil {
		return "", err
	}
	st, err := os.Lstat(c.Binary)
	if err != nil {
		return "", err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return "", errors.New("Headscale binary must be a root-owned regular file, not writable by group or others")
	}
	out, err := exec.CommandContext(ctx, c.Binary, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Headscale version: %w", err)
	}
	m := versionRE.FindStringSubmatch(string(out))
	if len(m) != 2 {
		return "", errors.New("cannot determine installed Headscale version")
	}
	return m[1], nil
}

// Installer replaces a verified binary after a stopped-service backup. Run is
// injectable so tests exercise recovery without controlling a real service.
type Installer struct {
	Config          Config
	Run             func(context.Context, string, ...string) error
	Healthy         func(context.Context) error
	ExpectedCurrent string
}

// command runs a fixed helper executable and includes diagnostic output on failure.
func command(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Install serializes CLI/UI updates, checks the SQLite backup coverage, then
// replaces the binary atomically. Failed post-start checks retain backups for
// manual recovery: a migrated database must never be blindly downgraded.
func (i Installer) Install(ctx context.Context, binary string) (backup string, err error) {
	c := i.Config
	if err = c.Validate(); err != nil {
		return "", err
	}
	run := i.Run
	if run == nil {
		run = command
	}
	if err = os.MkdirAll(c.BackupDir, 0700); err != nil {
		return "", err
	}
	lock, err := os.OpenFile(filepath.Join(c.BackupDir, "update.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", errors.New("a Headscale update is already running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if i.ExpectedCurrent != "" {
		current, checkErr := Current(ctx, c)
		if checkErr != nil {
			return "", checkErr
		}
		if current != i.ExpectedCurrent {
			return "", errors.New("Headscale version changed during download; check again")
		}
	}
	b, err := os.ReadFile(filepath.Join(c.ConfigDir, "config.yaml"))
	if err != nil {
		return "", err
	}
	var hs struct {
		Database struct {
			Type   string `yaml:"type"`
			SQLite struct {
				Path string `yaml:"path"`
			} `yaml:"sqlite"`
		} `yaml:"database"`
	}
	if err = yaml.Unmarshal(b, &hs); err != nil {
		return "", err
	}
	if hs.Database.Type != "sqlite" || !filepath.IsAbs(hs.Database.SQLite.Path) || !within(c.DataDir, hs.Database.SQLite.Path) {
		return "", errors.New("automatic updates require SQLite with its absolute database path inside data_dir")
	}
	for _, dir := range []string{c.ConfigDir, c.DataDir} {
		st, statErr := os.Lstat(dir)
		if statErr != nil {
			return "", statErr
		}
		if !st.IsDir() {
			return "", errors.New("config_dir and data_dir must be real directories, not symlinks")
		}
	}
	dbPath, resolveErr := filepath.EvalSymlinks(hs.Database.SQLite.Path)
	if resolveErr != nil {
		return "", resolveErr
	}
	realData, resolveErr := filepath.EvalSymlinks(c.DataDir)
	if resolveErr != nil {
		return "", resolveErr
	}
	if !within(realData, dbPath) {
		return "", errors.New("SQLite database resolves outside data_dir")
	}
	if err = run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", c.Service); err != nil {
		return "", errors.New("Headscale must be running before an update")
	}
	backup, err = os.MkdirTemp(c.BackupDir, "before-update-")
	if err != nil {
		return "", err
	}
	// Prepare on the destination filesystem so replacement is one atomic rename.
	tmp, err := os.CreateTemp(filepath.Dir(c.Binary), ".headscale-update-")
	if err != nil {
		return backup, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err = run(ctx, "/usr/bin/install", "-m", "0755", binary, tmp.Name()); err != nil {
		return backup, err
	}
	started := false
	defer func() {
		if !started {
			recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, run(recovery, "/usr/bin/systemctl", "start", c.Service))
		}
	}()
	if err = run(ctx, "/usr/bin/systemctl", "stop", c.Service); err != nil {
		return backup, err
	}
	for _, p := range []struct{ src, dst string }{{c.Binary, "headscale"}, {c.ConfigDir, "config"}, {c.DataDir, "data"}} {
		if err = run(ctx, "/usr/bin/cp", "-a", "--", p.src, filepath.Join(backup, p.dst)); err != nil {
			return backup, err
		}
	}
	if err = os.Rename(tmp.Name(), c.Binary); err != nil {
		return backup, err
	}
	if err = run(ctx, "/usr/bin/systemctl", "start", c.Service); err != nil {
		return backup, fmt.Errorf("updated binary could not start; backup at %s: %w", backup, err)
	}
	started = true
	health := i.Healthy
	if health == nil {
		health = func(ctx context.Context) error { return waitHealthy(ctx, c.HealthURL) }
	}
	if err = health(ctx); err != nil {
		return backup, fmt.Errorf("Headscale health check failed; backup at %s: %w", backup, err)
	}
	return backup, nil
}

// waitHealthy polls the local endpoint for up to 30 seconds without following redirects.
func waitHealthy(ctx context.Context, raw string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// Upgrade fetches the latest release again inside the privileged process and
// refuses to install a version different from the one the owner confirmed.
func Upgrade(ctx context.Context, c Config, want string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	// Check the parent before creation; never follow a service-controlled path.
	if err := trustedPath(filepath.Dir(c.BackupDir)); err != nil {
		return "", err
	}
	if err := os.MkdirAll(c.BackupDir, 0700); err != nil {
		return "", err
	}
	if err := trustedPath(c.BackupDir); err != nil {
		return "", err
	}
	st, err := os.Stat(c.BackupDir)
	if err != nil {
		return "", err
	}
	if st.Mode().Perm()&0077 != 0 {
		return "", errors.New("backup_dir must have mode 0700")
	}

	current, err := Current(ctx, c)
	if err != nil {
		return "", err
	}
	u := update.NewHeadscale(current)
	rel, err := u.Latest(ctx, true)
	if err != nil {
		return "", err
	}
	if want != "" && want != rel.Tag {
		return "", errors.New("latest Headscale release changed; check again and confirm the new version")
	}
	dir, err := os.MkdirTemp("", "meshpanel-headscale-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path, err := u.DownloadHeadscale(ctx, rel, dir)
	if err != nil {
		return "", err
	}
	backup, err := (Installer{Config: c, ExpectedCurrent: current}).Install(ctx, path)
	if err != nil {
		return "", fmt.Errorf("Headscale update failed (backup: %s): %w", backup, err)
	}
	return fmt.Sprintf("Headscale %s installed and healthy. Backup: %s", rel.Tag, backup), nil
}
