package tailnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeNode struct {
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	closed chan struct{}
	once   sync.Once
}

func (n *fakeNode) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return n.dial(ctx, network, addr)
}
func (n *fakeNode) Close() error { n.once.Do(func() { close(n.closed) }); return nil }

type fakeFactory struct {
	mu    sync.Mutex
	nodes []*fakeNode
	users []string
	mk    func() *fakeNode
}

func (f *fakeFactory) Start(ctx context.Context, hsUser string) (Node, error) {
	n := f.mk()
	f.mu.Lock()
	f.nodes = append(f.nodes, n)
	f.users = append(f.users, hsUser)
	f.mu.Unlock()
	return n, nil
}

func blockingTerm() (*fakeTerm, *io.PipeWriter) {
	r, w := io.Pipe()
	return &fakeTerm{in: r, resizes: make(chan Size)}, w
}

func TestSSHLimits(t *testing.T) {
	var addrs []string
	var mu sync.Mutex
	f := &fakeFactory{mk: func() *fakeNode {
		return &fakeNode{closed: make(chan struct{}), dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			mu.Lock()
			addrs = append(addrs, addr)
			mu.Unlock()
			cli, srv := tcpPairNoT()
			go (&sshServer{}).serve(nil, srv)
			return cli, nil
		}}
	}}
	m := &Manager{Nodes: f, MaxTotal: 2, MaxPerUser: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t1, w1 := blockingTerm()
	defer w1.Close()
	go m.Open(ctx, 1, "ravi", "100.64.0.1", "root", t1, Size{80, 24})
	waitFor(t, func() bool { t1.mu.Lock(); defer t1.mu.Unlock(); return contains(t1.states, "connected") })

	t2, _ := blockingTerm()
	if err := m.Open(ctx, 1, "ravi", "100.64.0.2", "root", t2, Size{80, 24}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second session for same account: %v", err)
	}
	t3, w3 := blockingTerm()
	defer w3.Close()
	go m.Open(ctx, 2, "anna", "100.64.0.3", "root", t3, Size{80, 24})
	waitFor(t, func() bool { t3.mu.Lock(); defer t3.mu.Unlock(); return contains(t3.states, "connected") })
	t4, _ := blockingTerm()
	if err := m.Open(ctx, 3, "bob", "100.64.0.4", "root", t4, Size{80, 24}); !errors.Is(err, ErrBusy) {
		t.Fatalf("session over the total limit: %v", err)
	}
	if m.Active() != 2 {
		t.Fatalf("active = %d", m.Active())
	}
	mu.Lock()
	if addrs[0] != "100.64.0.1:22" {
		t.Fatalf("dialed %v", addrs)
	}
	mu.Unlock()
	if f.users[0] != "ravi" || f.users[1] != "anna" {
		t.Fatalf("nodes started as %v", f.users)
	}
	// Ending a session frees its slot.
	w1.Close()
	waitFor(t, func() bool { return m.Active() == 1 })
}

func TestSSHCleanupOnError(t *testing.T) {
	f := &fakeFactory{mk: func() *fakeNode {
		return &fakeNode{closed: make(chan struct{}), dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}}
	}}
	m := &Manager{Nodes: f, MaxTotal: 5, MaxPerUser: 5}
	term, _ := blockingTerm()
	err := m.Open(context.Background(), 1, "ravi", "100.64.0.1", "root", term, Size{})
	if err == nil || !strings.Contains(err.Error(), "port 22") {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-f.nodes[0].closed:
	case <-time.After(time.Second):
		t.Fatal("node not closed after failure")
	}
	if m.Active() != 0 {
		t.Fatal("slot leaked")
	}
}

func TestSSHNeedsIdentity(t *testing.T) {
	m := &Manager{Nodes: &fakeFactory{}, MaxTotal: 5, MaxPerUser: 5}
	term, _ := blockingTerm()
	if err := m.Open(context.Background(), 1, "", "100.64.0.1", "root", term, Size{}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v", err)
	}
}

func TestSanitizeHostname(t *testing.T) {
	for in, want := range map[string]string{"ravi": "meshpanel-ssh-ravi", "Anna.Lee@x": "meshpanel-ssh-anna-lee-x", "": "meshpanel-ssh"} {
		if got := SSHHostname(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}

func tcpPairNoT() (net.Conn, net.Conn) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	cli, _ := net.Dial("tcp", ln.Addr().String())
	return cli, <-ch
}

type failingFactory struct{ err error }

func (f failingFactory) Start(context.Context, string) (Node, error) { return nil, f.err }

func TestSSHJoinTimeoutIsExplained(t *testing.T) {
	m := &Manager{Nodes: failingFactory{fmt.Errorf("tsnet.Up: %w", context.DeadlineExceeded)}, MaxTotal: 1, MaxPerUser: 1}
	term, _ := blockingTerm()
	err := m.Open(context.Background(), 1, "ravi", "100.64.0.1", "root", term, Size{})
	if err == nil || !strings.Contains(err.Error(), "control URL") {
		t.Fatalf("err = %v", err)
	}
}
