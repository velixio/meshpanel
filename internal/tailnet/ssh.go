package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrBusy       = errors.New("too many SSH sessions are open")
	ErrNoIdentity = errors.New("your account isn't linked to a headscale user, so there is no tailnet identity to SSH as")
)

// Node is a tailnet node that can dial other nodes.
type Node interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	Close() error
}

// NodeFactory starts a short-lived node registered under hsUser.
type NodeFactory interface {
	Start(ctx context.Context, hsUser string) (Node, error)
}

// Manager runs browser SSH sessions, each on its own ephemeral node owned by
// the person's headscale user, so Tailscale SSH policy applies to them.
type Manager struct {
	Nodes      NodeFactory
	MaxTotal   int
	MaxPerUser int

	mu     sync.Mutex
	total  int
	perAcc map[int64]int
}

func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total
}

func (m *Manager) acquire(account int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.perAcc == nil {
		m.perAcc = map[int64]int{}
	}
	if m.MaxTotal > 0 && m.total >= m.MaxTotal {
		return fmt.Errorf("%w: the server allows %d at a time", ErrBusy, m.MaxTotal)
	}
	if m.MaxPerUser > 0 && m.perAcc[account] >= m.MaxPerUser {
		return fmt.Errorf("%w: you already have %d open; close one first", ErrBusy, m.perAcc[account])
	}
	m.total++
	m.perAcc[account]++
	return nil
}

func (m *Manager) release(account int64) {
	m.mu.Lock()
	m.total--
	if m.perAcc[account]--; m.perAcc[account] <= 0 {
		delete(m.perAcc, account)
	}
	m.mu.Unlock()
}

// Open runs one session to target (a tailnet IP) as sshUser until it ends.
func (m *Manager) Open(ctx context.Context, account int64, hsUser, target, sshUser string, t Term, size Size) error {
	if hsUser == "" {
		return ErrNoIdentity
	}
	if err := m.acquire(account); err != nil {
		return err
	}
	defer m.release(account)

	t.Status("connecting", "Joining the tailnet as "+hsUser+"…")
	sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	node, err := m.Nodes.Start(sctx, hsUser)
	cancel()
	if err != nil {
		return fmt.Errorf("joining the tailnet: %w", err)
	}
	defer node.Close()

	t.Status("connecting", "Connecting to "+target+"…")
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, err := node.Dial(dctx, "tcp", net.JoinHostPort(target, "22"))
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return errors.New("nothing is listening on port 22 (enable Tailscale SSH with `tailscale set --ssh`, or run sshd)")
		}
		return fmt.Errorf("can't reach %s on port 22: %w (check the access policy allows you to reach it)", target, err)
	}
	defer conn.Close()
	return Relay(ctx, conn, sshUser, t, size)
}

var notLabel = regexp.MustCompile(`[^a-z0-9-]+`)

// sshHostname makes the ephemeral node's name, e.g. meshpanel-ssh-ravi.
func sshHostname(hsUser string) string {
	s := strings.Trim(notLabel.ReplaceAllString(strings.ToLower(hsUser), "-"), "-")
	if s == "" {
		return "meshpanel-ssh"
	}
	name := "meshpanel-ssh-" + s
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	return name
}

// IsSSHNode reports whether a node name belongs to a web SSH session.
func IsSSHNode(name string) bool { return strings.HasPrefix(name, "meshpanel-ssh") }
