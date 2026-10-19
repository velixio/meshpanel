// Package tailnet embeds Tailscale (tsnet) in meshpanel for two optional
// features: a host-info agent, and a browser SSH terminal that connects as
// the signed-in person's own headscale user.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

var checkLinkRe = regexp.MustCompile(`https?://[^\s"'<>]+/auth/hskey-authreq-[0-9A-Za-z_-]{24}`)

// Size is a terminal size in character cells.
type Size struct {
	Cols int `json:"c"`
	Rows int `json:"r"`
}

// Term is the browser side of a session.
type Term interface {
	io.ReadWriter // keystrokes in, output out
	Resizes() <-chan Size
	// Prompt asks the person a question (a password, an OTP); echo says
	// whether the answer may be shown while typing.
	Prompt(ctx context.Context, question string, echo bool) (string, error)
	// Status reports progress: connecting, authenticating, connected, closed.
	Status(state, msg string)
}

// Relay runs an SSH client over conn and connects it to t until either side
// ends or ctx is cancelled.
func Relay(ctx context.Context, conn net.Conn, user string, t Term, initial Size) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Unblock the handshake and copies when the browser goes away.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	t.Status("authenticating", "")
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			// Tailscale SSH authenticates by tailnet identity and accepts
			// "none"; regular sshd falls through to the prompts below.
			ssh.PasswordCallback(func() (string, error) {
				return t.Prompt(ctx, user+"'s password: ", false)
			}),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				if instruction != "" {
					fmt.Fprintf(t, "%s\r\n", instruction)
				}
				answers := make([]string, len(questions))
				for i, q := range questions {
					a, err := t.Prompt(ctx, q, echos[i])
					if err != nil {
						return nil, err
					}
					answers[i] = a
				}
				return answers, nil
			}),
		},
		// The transport is WireGuard to the node's tailnet address, which
		// already authenticates the peer; there is no known_hosts to check.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback: func(msg string) error {
			// Tailscale SSH "check" rules send a sign-in link; surface it so
			// the browser can offer a button instead of copy-paste.
			if link := checkLinkRe.FindString(msg); link != "" {
				t.Status("check", link)
			}
			_, err := io.WriteString(t, strings.ReplaceAll(msg, "\n", "\r\n"))
			return err
		},
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), cfg)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return friendlySSHError(err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening session: %w", err)
	}
	defer sess.Close()
	if initial.Cols <= 0 || initial.Rows <= 0 {
		initial = Size{Cols: 80, Rows: 24}
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 115200, ssh.TTY_OP_OSPEED: 115200}
	if err := sess.RequestPty("xterm-256color", initial.Rows, initial.Cols, modes); err != nil {
		return fmt.Errorf("requesting a terminal: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	sess.Stdout = t
	sess.Stderr = t
	if err := sess.Shell(); err != nil {
		return fmt.Errorf("starting a shell: %w", err)
	}
	t.Status("connected", "")

	var once sync.Once
	finished := make(chan struct{})
	finish := func() { once.Do(func() { close(finished) }) }
	go func() {
		io.Copy(stdin, t)
		stdin.Close()
		finish()
	}()
	go func() {
		sess.Wait()
		finish()
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-finished:
			return nil
		case s, ok := <-t.Resizes():
			if !ok {
				continue
			}
			if s.Cols > 0 && s.Rows > 0 {
				_ = sess.WindowChange(s.Rows, s.Cols)
			}
		}
	}
}

func friendlySSHError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"):
		return errors.New("authentication failed: Tailscale SSH policy doesn't allow you as this user, or the password was wrong")
	case strings.Contains(msg, "connection refused"):
		return errors.New("nothing is listening on port 22 (enable Tailscale SSH with `tailscale set --ssh`, or run sshd)")
	}
	return fmt.Errorf("ssh: %w", err)
}
