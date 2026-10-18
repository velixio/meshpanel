package hsconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Applier makes headscale pick up a change and undoes it if headscale does
// not come back healthy.
type Applier struct {
	Run        func(ctx context.Context, cmd string) error
	RestartCmd string
	ReloadCmd  string
	// ConfigTest validates a config file before restarting (optional).
	ConfigTest func(ctx context.Context, path string) error
	Health     func(ctx context.Context) error
	Timeout    time.Duration

	mu sync.Mutex
}

// RunCommand executes cmd without a shell, splitting on spaces.
func RunCommand(ctx context.Context, cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return errors.New("no command configured")
	}
	c := exec.CommandContext(ctx, parts[0], parts[1:]...)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if msg != "" {
			return fmt.Errorf("%s: %w: %s", cmd, err, msg)
		}
		return fmt.Errorf("%s: %w", cmd, err)
	}
	return nil
}

// HeadscaleConfigTest returns a ConfigTest that runs `<binary> configtest -c <path>`,
// or nil when the binary is not installed.
func HeadscaleConfigTest(binary string) func(context.Context, string) error {
	if binary == "" {
		return nil
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil
	}
	return func(ctx context.Context, path string) error {
		return RunCommand(ctx, binary+" configtest -c "+path)
	}
}

func (a *Applier) timeout() time.Duration {
	if a.Timeout <= 0 {
		return 30 * time.Second
	}
	return a.Timeout
}

func (a *Applier) waitHealthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	var last error
	for {
		if last = a.Health(ctx); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("headscale not healthy after %s: %w", a.timeout(), last)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// ApplyConfig patches config.yaml, restarts headscale and waits for it. On
// any failure the previous file is restored (and headscale restarted again
// if it had been restarted).
func (a *Applier) ApplyConfig(ctx context.Context, ed *Editor, changes []Change) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	backup, err := ed.PatchWithBackup(changes)
	if err != nil {
		return err
	}
	rollback := func(cause error, restart bool) error {
		if rerr := Restore(ed.Path, backup); rerr != nil {
			return fmt.Errorf("%v; restoring the backup %s also failed: %w", cause, backup, rerr)
		}
		if restart {
			if rerr := a.Run(ctx, a.RestartCmd); rerr != nil {
				return fmt.Errorf("%v; previous config restored but restarting headscale failed: %w", cause, rerr)
			}
			_ = a.waitHealthy(ctx)
		}
		return fmt.Errorf("%w (previous config restored)", cause)
	}
	if a.ConfigTest != nil {
		if err := a.ConfigTest(ctx, ed.Path); err != nil {
			return rollback(fmt.Errorf("headscale rejected the new config: %w", err), false)
		}
	}
	if err := a.Run(ctx, a.RestartCmd); err != nil {
		return rollback(fmt.Errorf("restarting headscale: %w", err), true)
	}
	if err := a.waitHealthy(ctx); err != nil {
		return rollback(err, true)
	}
	return nil
}

// ApplyPolicyFile writes a policy file (policy.mode: file) and reloads.
func (a *Applier) ApplyPolicyFile(ctx context.Context, path, content string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	backup, err := backupFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeFile(path, []byte(content), 0o640); err != nil {
		return err
	}
	fail := func(cause error) error {
		if backup != "" {
			if rerr := Restore(path, backup); rerr != nil {
				return fmt.Errorf("%v; restoring the policy also failed: %w", cause, rerr)
			}
			_ = a.Run(ctx, a.ReloadCmd)
		}
		return fmt.Errorf("%w (previous policy restored)", cause)
	}
	if err := a.Run(ctx, a.ReloadCmd); err != nil {
		return fail(fmt.Errorf("reloading headscale: %w", err))
	}
	if err := a.waitHealthy(ctx); err != nil {
		return fail(err)
	}
	return nil
}
