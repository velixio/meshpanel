package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/config"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/registration"
)

// ---- fakes ----

type fakeHS struct {
	HS
	mu         sync.Mutex
	renamed    map[string]string
	registered []string
	users      []hs.User
}

func (f *fakeHS) RenameNode(_ context.Context, id, name string) (hs.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renamed == nil {
		f.renamed = map[string]string{}
	}
	f.renamed[id] = name
	return hs.Node{ID: id, GivenName: name}, nil
}
func (f *fakeHS) AuthRegister(_ context.Context, user, id string) (hs.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered = append(f.registered, user+"/"+id)
	return hs.Node{ID: "99", GivenName: "new-phone", IPAddresses: []string{"100.64.0.99"}}, nil
}
func (f *fakeHS) AuthApprove(context.Context, string) error { return nil }
func (f *fakeHS) AuthReject(context.Context, string) error  { return nil }
func (f *fakeHS) Health(context.Context) error              { return nil }
func (f *fakeHS) ListUsers(context.Context) ([]hs.User, error) {
	return f.users, nil
}
func (f *fakeHS) CreateUser(_ context.Context, name, _, _ string) (hs.User, error) {
	u := hs.User{ID: "u-" + name, Name: name}
	f.users = append(f.users, u)
	return u, nil
}

type fakePoller struct{ nodes []hs.Node }

func (p *fakePoller) Snapshot() []hs.Node { return p.nodes }
func (p *fakePoller) Users() []hs.User {
	return []hs.User{{ID: "1", Name: "ravi"}, {ID: "2", Name: "anna"}}
}
func (p *fakePoller) Node(id string) (hs.Node, bool) {
	for _, n := range p.nodes {
		if n.ID == id {
			return n, true
		}
	}
	return hs.Node{}, false
}
func (p *fakePoller) Healthy() bool    { return true }
func (p *fakePoller) LastError() error { return nil }
func (p *fakePoller) Refresh()         {}

// ---- harness ----

type harness struct {
	t   *testing.T
	srv *httptest.Server
	s   *Server
	d   *db.DB
	hs  *fakeHS
	cfg *config.Config
}

const testPassword = "correct horse battery"

func newHarness(t *testing.T) *harness {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := config.Default()
	cfg.Server.CookieSecure = false
	cfg.Server.TrustedProxies = []string{"127.0.0.1/32", "::1"}
	cfg.Server.SessionSecret = strings.Repeat("x", 32)
	bus := events.NewBus()
	f := &fakeHS{}
	poller := &fakePoller{nodes: []hs.Node{
		{ID: "1", GivenName: "ravi-phone", User: &hs.User{ID: "1", Name: "ravi"}, Online: true, IPAddresses: []string{"100.64.0.1"}, NodeKey: "nodekey:01"},
		{ID: "2", GivenName: "anna-laptop", User: &hs.User{ID: "2", Name: "anna"}, IPAddresses: []string{"100.64.0.2"}, NodeKey: "nodekey:02"},
	}}
	s, err := New(Deps{
		Cfg: cfg, DB: d, HS: f, Poller: poller, Bus: bus, Reg: registration.New(d, f, bus),
		Sessions: auth.NewSessions(d), Limiter: auth.NewLimiter(), Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, s: s, d: d, hs: f, cfg: cfg}
	h.srv = httptest.NewServer(s.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

type client struct {
	h *harness
	c *http.Client
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{h: h, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

func (c *client) get(path string) (int, string, http.Header) {
	c.h.t.Helper()
	resp, err := c.c.Get(c.h.srv.URL + path)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// post fetches csrfFrom first to obtain a token, then posts the form.
func (c *client) post(csrfFrom, path string, form url.Values) (int, string, http.Header) {
	c.h.t.Helper()
	_, body, _ := c.get(csrfFrom)
	m := csrfRe.FindStringSubmatch(body)
	if form == nil {
		form = url.Values{}
	}
	if m != nil {
		form.Set("_csrf", m[1])
	}
	req, _ := http.NewRequest("POST", c.h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.c.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// account creates an enrolled account and returns its TOTP secret.
func (h *harness) account(username, role, hsUser string) (*db.Account, string) {
	h.t.Helper()
	hash, _ := auth.HashPassword(testPassword)
	secret, _ := auth.NewTOTPSecret("t", username)
	a, err := h.d.CreateAccount(context.Background(), db.Account{Username: username, Role: role, HSUser: hsUser, PasswordHash: hash, TOTPSecret: secret, TOTPEnabled: true})
	if err != nil {
		h.t.Fatal(err)
	}
	return a, secret
}

func (c *client) login(username, secret string) {
	c.h.t.Helper()
	code, _, hdr := c.post("/admin/login", "/admin/login", url.Values{"username": {username}, "password": {testPassword}})
	if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "/login/2fa") {
		c.h.t.Fatalf("password step: %d %s", code, hdr.Get("Location"))
	}
	code, _, hdr = c.post("/admin/login/2fa", "/admin/login/2fa", url.Values{"code": {auth.TOTPCode(secret, time.Now())}})
	if code != http.StatusSeeOther {
		c.h.t.Fatalf("2fa step: %d", code)
	}
}

// ---- Task 7 tests ----

func TestSetupOnlyWhenEmpty(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	if code, _, _ := c.get("/admin/setup"); code != 200 {
		t.Fatalf("setup on empty db: %d", code)
	}
	code, _, hdr := c.post("/admin/setup", "/admin/setup", url.Values{"username": {"boss"}, "password": {testPassword}, "confirm": {testPassword}})
	if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "/2fa/enroll") {
		t.Fatalf("setup post: %d %q", code, hdr.Get("Location"))
	}
	a, err := h.d.GetAccountByUsername(context.Background(), "boss")
	if err != nil || a.Role != "owner" || a.TOTPEnabled {
		t.Fatalf("owner: %+v %v", a, err)
	}
	if code, _, _ := h.client().get("/admin/setup"); code != http.StatusNotFound {
		t.Fatalf("setup after first account: %d", code)
	}
}

func TestLoginRequires2FA(t *testing.T) {
	h := newHarness(t)
	_, _ = h.account("anna", "admin", "anna")
	c := h.client()
	c.post("/admin/login", "/admin/login", url.Values{"username": {"anna"}, "password": {testPassword}})
	if code, _, hdr := c.get("/admin/"); code != http.StatusFound || !strings.Contains(hdr.Get("Location"), "/login") {
		t.Fatalf("dashboard with half session: %d %s", code, hdr.Get("Location"))
	}
	code, _, _ := c.post("/admin/login/2fa", "/admin/login/2fa", url.Values{"code": {"000000"}})
	if code == http.StatusSeeOther {
		t.Fatal("wrong code accepted")
	}
}

func TestLoginFullFlow(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("anna", "admin", "anna")
	c := h.client()
	c.login("anna", secret)
	code, body, _ := c.get("/admin/")
	if code != 200 || !strings.Contains(body, "Overview") {
		t.Fatalf("overview: %d", code)
	}
}

func TestCSRFRejected(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("anna", "admin", "anna")
	c := h.client()
	c.login("anna", secret)
	req, _ := http.NewRequest("POST", h.srv.URL+"/admin/machines/1/rename", strings.NewReader("name=evil"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := c.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || h.hs.renamed["1"] != "" {
		t.Fatalf("post without token: %d renamed=%v", resp.StatusCode, h.hs.renamed)
	}
	req, _ = http.NewRequest("POST", h.srv.URL+"/admin/machines/1/rename", strings.NewReader("name=evil"))
	req.Header.Set("Origin", "https://evil.example")
	resp, _ = c.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin post: %d", resp.StatusCode)
	}
}

func TestTrustedProxyIP(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1, 127.0.0.1")
	if got := h.s.realIP(r); got != "10.0.0.1" {
		t.Fatalf("rightmost untrusted = %s", got)
	}
	r.RemoteAddr = "198.51.100.7:5555"
	if got := h.s.realIP(r); got != "198.51.100.7" {
		t.Fatalf("untrusted peer spoofed XFF: %s", got)
	}
}

func TestLockoutAfterFailures(t *testing.T) {
	h := newHarness(t)
	h.account("anna", "admin", "anna")
	ch, cancel := h.s.Bus.Subscribe(16)
	defer cancel()
	c := h.client()
	for i := 0; i < 6; i++ {
		c.post("/admin/login", "/admin/login", url.Values{"username": {"anna"}, "password": {"wrong password!"}})
	}
	_, body, _ := c.post("/admin/login", "/admin/login", url.Values{"username": {"anna"}, "password": {testPassword}})
	if !strings.Contains(body, "Too many attempts") {
		t.Fatal("not locked out")
	}
	var sec bool
	for len(ch) > 0 {
		if (<-ch).Kind == events.Security {
			sec = true
		}
	}
	if !sec {
		t.Fatal("no security alert after repeated failures")
	}
}

func TestNextRedirectIsLocal(t *testing.T) {
	h := newHarness(t)
	for in, want := range map[string]string{
		"/register/hskey-authreq-0123": "/register/hskey-authreq-0123",
		"//evil.example/x":             "/admin/",
		"https://evil.example/":        "/admin/",
		"/\\evil":                      "/admin/",
		"":                             "/admin/",
	} {
		if got := h.s.localPath(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}

var _ = errors.New
