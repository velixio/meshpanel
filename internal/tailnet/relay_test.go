package tailnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshServer serves one connection: echoes stdin back to stdout and records
// PTY sizes. If password is set, only password auth with it is accepted.
type sshServer struct {
	banner   string
	password string
	mu       sync.Mutex
	sizes    []Size
	term     string
	user     string
}

func (s *sshServer) serve(t *testing.T, conn net.Conn) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{}
	if s.banner != "" {
		b := s.banner
		cfg.BannerCallback = func(ssh.ConnMetadata) string { return b }
	}
	if s.password == "" {
		cfg.NoClientAuth = true
	} else {
		cfg.PasswordCallback = func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == s.password {
				return nil, nil
			}
			return nil, errors.New("bad password")
		}
	}
	cfg.AddHostKey(signer)
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.user = sc.User()
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, _ := nc.Accept()
		go func() {
			for r := range creqs {
				switch r.Type {
				case "pty-req":
					tl := binary.BigEndian.Uint32(r.Payload)
					term := string(r.Payload[4 : 4+tl])
					p := r.Payload[4+tl:]
					s.mu.Lock()
					s.term = term
					s.sizes = append(s.sizes, Size{Cols: int(binary.BigEndian.Uint32(p)), Rows: int(binary.BigEndian.Uint32(p[4:]))})
					s.mu.Unlock()
					r.Reply(true, nil)
				case "window-change":
					s.mu.Lock()
					s.sizes = append(s.sizes, Size{Cols: int(binary.BigEndian.Uint32(r.Payload)), Rows: int(binary.BigEndian.Uint32(r.Payload[4:]))})
					s.mu.Unlock()
				case "shell":
					r.Reply(true, nil)
					go func() {
						io.Copy(ch, ch)
						ch.Close()
					}()
				default:
					r.Reply(false, nil)
				}
			}
		}()
	}
}

type fakeTerm struct {
	in      io.Reader
	mu      sync.Mutex
	out     bytes.Buffer
	resizes chan Size
	answers []string
	asked   []string
	states  []string
	msgs    []string
}

func (f *fakeTerm) Read(p []byte) (int, error) { return f.in.Read(p) }
func (f *fakeTerm) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}
func (f *fakeTerm) Resizes() <-chan Size { return f.resizes }
func (f *fakeTerm) Prompt(_ context.Context, q string, echo bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, q)
	if len(f.answers) == 0 {
		return "", errors.New("no answer")
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, nil
}
func (f *fakeTerm) Status(state, msg string) {
	f.mu.Lock()
	f.states = append(f.states, state)
	f.msgs = append(f.msgs, msg)
	f.mu.Unlock()
}
func (f *fakeTerm) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestRelayEcho(t *testing.T) {
	cli, srvConn := tcpPair(t)
	srv := &sshServer{}
	go srv.serve(t, srvConn)
	inR, inW := io.Pipe()
	term := &fakeTerm{in: inR, resizes: make(chan Size, 1)}
	done := make(chan error, 1)
	go func() { done <- Relay(context.Background(), cli, "root", term, Size{Cols: 100, Rows: 30}) }()
	inW.Write([]byte("hello\n"))
	waitFor(t, func() bool { return strings.Contains(term.output(), "hello") })
	inW.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end after stdin closed")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.user != "root" || srv.term != "xterm-256color" || len(srv.sizes) == 0 || srv.sizes[0] != (Size{100, 30}) {
		t.Fatalf("server saw user=%q term=%q sizes=%v", srv.user, srv.term, srv.sizes)
	}
	if !contains(term.states, "connected") {
		t.Fatalf("states %v", term.states)
	}
}

func TestRelayPasswordPrompt(t *testing.T) {
	cli, srvConn := tcpPair(t)
	srv := &sshServer{password: "s3cret"}
	go srv.serve(t, srvConn)
	inR, inW := io.Pipe()
	defer inW.Close()
	term := &fakeTerm{in: inR, resizes: make(chan Size), answers: []string{"s3cret"}}
	go Relay(context.Background(), cli, "ravi", term, Size{80, 24})
	inW.Write([]byte("ping"))
	waitFor(t, func() bool { return strings.Contains(term.output(), "ping") })
	if len(term.asked) == 0 || !strings.Contains(strings.ToLower(term.asked[0]), "password") {
		t.Fatalf("asked %v", term.asked)
	}
}

func TestRelayWrongPasswordFails(t *testing.T) {
	cli, srvConn := tcpPair(t)
	srv := &sshServer{password: "s3cret"}
	go srv.serve(t, srvConn)
	term := &fakeTerm{in: strings.NewReader(""), resizes: make(chan Size), answers: []string{"nope"}}
	err := Relay(context.Background(), cli, "ravi", term, Size{80, 24})
	if err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestRelayClosesOnClientGone(t *testing.T) {
	cli, srvConn := tcpPair(t)
	srv := &sshServer{}
	go srv.serve(t, srvConn)
	inR, _ := io.Pipe()
	term := &fakeTerm{in: inR, resizes: make(chan Size)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Relay(ctx, cli, "root", term, Size{80, 24}) }()
	waitFor(t, func() bool { term.mu.Lock(); defer term.mu.Unlock(); return contains(term.states, "connected") })
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay kept running after the browser went away")
	}
}

func TestRelayResize(t *testing.T) {
	cli, srvConn := tcpPair(t)
	srv := &sshServer{}
	go srv.serve(t, srvConn)
	inR, inW := io.Pipe()
	defer inW.Close()
	rs := make(chan Size, 1)
	term := &fakeTerm{in: inR, resizes: rs}
	go Relay(context.Background(), cli, "root", term, Size{80, 24})
	waitFor(t, func() bool { term.mu.Lock(); defer term.mu.Unlock(); return contains(term.states, "connected") })
	rs <- Size{Cols: 132, Rows: 40}
	waitFor(t, func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return len(srv.sizes) >= 2 && srv.sizes[len(srv.sizes)-1] == Size{132, 40}
	})
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// tcpPair returns two ends of a loopback TCP connection. (net.Pipe is
// unbuffered, and both SSH sides write their version line first.)
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-ch
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

// Tailscale SSH "check" rules send a sign-in link in the banner; the
// terminal surfaces it so the person can approve without copying text.
func TestRelaySurfacesCheckLink(t *testing.T) {
	cli, srvConn := tcpPair(t)
	link := "https://hs.example.com/auth/hskey-authreq-0123456789abcdef01234567"
	srv := &sshServer{banner: "# Tailscale SSH requires an additional check.\n# To authenticate, visit: " + link + "\n"}
	go srv.serve(t, srvConn)
	inR, inW := io.Pipe()
	defer inW.Close()
	term := &fakeTerm{in: inR, resizes: make(chan Size)}
	go Relay(context.Background(), cli, "root", term, Size{80, 24})
	waitFor(t, func() bool {
		term.mu.Lock()
		defer term.mu.Unlock()
		for i, s := range term.states {
			if s == "check" && term.msgs[i] == link {
				return true
			}
		}
		return false
	})
	if !strings.Contains(term.output(), "To authenticate") {
		t.Fatal("banner text not shown in the terminal")
	}
}
