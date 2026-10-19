package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/meshpanel/meshpanel/internal/tailnet"
)

type fakeSSH struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeSSH) Open(ctx context.Context, account int64, hsUser, target, sshUser string, t tailnet.Term, size tailnet.Size) error {
	f.mu.Lock()
	f.calls = append(f.calls, hsUser+"@"+target+" as "+sshUser)
	f.mu.Unlock()
	t.Status("connected", "")
	t.Write([]byte("welcome\r\n"))
	buf := make([]byte, 16)
	n, _ := t.Read(buf)
	t.Write(buf[:n])
	return nil
}
func (f *fakeSSH) Active() int { return 0 }

type fakeAgent struct{}

func (fakeAgent) Info(k string) (tailnet.HostInfo, bool) {
	return tailnet.HostInfo{OS: "iOS", OSVersion: "18.1", Tailscale: "1.86.2", Device: "iPhone16,1"}, true
}
func (fakeAgent) State() tailnet.AgentState { return tailnet.AgentState{Running: true, Peers: 3} }

func withSSH(h *harness) *fakeSSH {
	f := &fakeSSH{}
	h.s.SSH = f
	h.s.Agent = fakeAgent{}
	h.s.Cfg.WebSSH.DefaultUser = "root"
	return f
}

func TestSSHDisabled(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("anna", "admin", "anna")
	c := h.client()
	c.login("anna", secret)
	if code, _, _ := c.get("/admin/machines/1/ssh"); code != http.StatusNotFound {
		t.Fatalf("ssh page with SSH off: %d", code)
	}
	_, body, _ := c.get("/admin/machines/1")
	if strings.Contains(body, "/ssh\"") {
		t.Fatal("SSH button shown while disabled")
	}
}

func TestSSHScope(t *testing.T) {
	h := newHarness(t)
	withSSH(h)
	_, secret := h.account("ravi", "member", "ravi")
	c := h.client()
	c.login("ravi", secret)
	if code, _, _ := c.get("/admin/machines/1/ssh"); code != 200 {
		t.Fatalf("own machine: %d", code)
	}
	if code, _, _ := c.get("/admin/machines/2/ssh"); code != http.StatusNotFound {
		t.Fatalf("someone else's machine: %d", code)
	}
	if code, _, _ := c.get("/admin/machines/2/ssh/ws?user=root"); code != http.StatusNotFound {
		t.Fatalf("ws to someone else's machine: %d", code)
	}
}

func TestSSHRequiresHSUser(t *testing.T) {
	h := newHarness(t)
	withSSH(h)
	_, secret := h.account("admin2", "admin", "")
	c := h.client()
	c.login("admin2", secret)
	code, body, _ := c.get("/admin/machines/1/ssh")
	if code != http.StatusForbidden || !strings.Contains(body, "headscale user") {
		t.Fatalf("%d", code)
	}
}

func TestSSHViewerNotAllowed(t *testing.T) {
	h := newHarness(t)
	withSSH(h)
	_, secret := h.account("v", "viewer", "anna")
	c := h.client()
	c.login("v", secret)
	if code, _, _ := c.get("/admin/machines/1/ssh"); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
}

func TestSSHWebSocketSession(t *testing.T) {
	h := newHarness(t)
	f := withSSH(h)
	_, secret := h.account("ravi", "member", "ravi")
	c := h.client()
	c.login("ravi", secret)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, strings.Replace(h.srv.URL, "http", "ws", 1)+"/admin/machines/1/ssh/ws?user=deploy&c=100&r=30", &websocket.DialOptions{HTTPClient: c.c})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	var got strings.Builder
	for !strings.Contains(got.String(), "welcome") {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if typ == websocket.MessageBinary {
			got.Write(b)
		}
	}
	ws.Write(ctx, websocket.MessageBinary, []byte("ls\r"))
	for !strings.Contains(got.String(), "ls") {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if typ == websocket.MessageBinary {
			got.Write(b)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 || f.calls[0] != "ravi@100.64.0.1 as deploy" {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestSSHRejectsBadLoginName(t *testing.T) {
	h := newHarness(t)
	withSSH(h)
	_, secret := h.account("anna", "admin", "anna")
	c := h.client()
	c.login("anna", secret)
	if code, _, _ := c.get("/admin/machines/1/ssh/ws?user=root;rm%20-rf"); code != http.StatusBadRequest {
		t.Fatalf("%d", code)
	}
}

func TestMachinePageShowsDeviceInfoAndSSH(t *testing.T) {
	h := newHarness(t)
	withSSH(h)
	_, secret := h.account("ravi", "member", "ravi")
	c := h.client()
	c.login("ravi", secret)
	_, body, _ := c.get("/admin/machines/1")
	for _, want := range []string{"iPhone16,1", "1.86.2", "/admin/machines/1/ssh"} {
		if !strings.Contains(body, want) {
			t.Errorf("machine page lacks %q", want)
		}
	}
	_, list, _ := c.get("/admin/machines")
	if !strings.Contains(list, "iOS 18.1") {
		t.Error("machine list lacks the OS line")
	}
}
