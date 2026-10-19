// Package web is meshpanel's HTTP layer: server-rendered pages (html/template
// plus htmx), the phone registration flow at /register and /auth, and live
// updates over WebSocket.
package web

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/config"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/hsconfig"
	"github.com/meshpanel/meshpanel/internal/registration"
	"github.com/meshpanel/meshpanel/internal/tailnet"
)

//go:embed templates static
var assets embed.FS

// HS is the headscale surface the web layer uses (hs.Client satisfies it).
type HS interface {
	GetNode(ctx context.Context, id string) (hs.Node, error)
	DeleteNode(ctx context.Context, id string) error
	ExpireNode(ctx context.Context, id string) (hs.Node, error)
	SetKeyExpiryDisabled(ctx context.Context, id string, disabled bool) (hs.Node, error)
	RenameNode(ctx context.Context, id, name string) (hs.Node, error)
	SetTags(ctx context.Context, id string, tags []string) (hs.Node, error)
	ApproveRoutes(ctx context.Context, id string, routes []string) (hs.Node, error)
	ListUsers(ctx context.Context) ([]hs.User, error)
	CreateUser(ctx context.Context, name, display, email string) (hs.User, error)
	RenameUser(ctx context.Context, id, name string) (hs.User, error)
	DeleteUser(ctx context.Context, id string) error
	ListPreAuthKeys(ctx context.Context) ([]hs.PreAuthKey, error)
	CreatePreAuthKey(ctx context.Context, r hs.CreateKeyReq) (hs.PreAuthKey, error)
	ExpirePreAuthKey(ctx context.Context, id string) error
	DeletePreAuthKey(ctx context.Context, id string) error
	GetPolicy(ctx context.Context) (hs.Policy, error)
	SetPolicy(ctx context.Context, policy string) (hs.Policy, error)
	CheckPolicy(ctx context.Context, policy string) error
	AuthRegister(ctx context.Context, user, authID string) (hs.Node, error)
	Health(ctx context.Context) error
}

// Snapshotter is the poller's read side.
type Snapshotter interface {
	Snapshot() []hs.Node
	Users() []hs.User
	Node(id string) (hs.Node, bool)
	Healthy() bool
	LastError() error
	Refresh()
}

// Telegram is the bot surface the web layer uses (nil when disabled).
type Telegram interface {
	LinkURL(ctx context.Context, accountID int64) (string, error)
	BotName(ctx context.Context) (string, error)
	SetGroupChat(id int64)
}

type Deps struct {
	Cfg       *config.Config
	DB        *db.DB
	HS        HS
	Poller    Snapshotter
	Bus       *events.Bus
	Reg       *registration.Service
	TG        Telegram
	Sessions  *auth.Sessions
	Limiter   *auth.Limiter
	HSConfig  *hsconfig.Editor  // nil when headscale.config_path is unset
	Applier   *hsconfig.Applier // nil when config editing is unavailable
	Version   string
	HSVersion func() string
	Agent     HostInfoSource // nil unless agent.enabled
	SSH       SSHOpener      // nil unless web_ssh.enabled
	// SessionNodes recognises meshpanel's own browser-SSH nodes (by the
	// pre-auth key it minted, not by name). nil when SSH is off.
	SessionNodes interface{ Owns(hs.Node) bool }
}

// HostInfoSource is the tailnet agent's cache.
type HostInfoSource interface {
	Info(nodeKey string) (tailnet.HostInfo, bool)
	State() tailnet.AgentState
}

// SSHOpener runs browser SSH sessions.
type SSHOpener interface {
	Open(ctx context.Context, account int64, hsUser, target, sshUser string, t tailnet.Term, size tailnet.Size) error
	Active() int
}

type Server struct {
	Deps
	base    string
	trusted []netip.Prefix
	tmpl    *templates
	static  http.Handler
	start   time.Time
	assetV  string
}

func New(d Deps) (*Server, error) {
	s := &Server{Deps: d, base: d.Cfg.Server.BasePath, start: time.Now()}
	// Asset URLs change with every release (and every restart of dev builds).
	s.assetV = d.Version
	if s.assetV == "" || s.assetV == "dev" {
		s.assetV = strconv.FormatInt(s.start.Unix(), 36)
	}
	for _, p := range d.Cfg.Server.TrustedProxies {
		if !strings.Contains(p, "/") {
			if a, err := netip.ParseAddr(p); err == nil {
				s.trusted = append(s.trusted, netip.PrefixFrom(a, a.BitLen()))
			}
			continue
		}
		if pr, err := netip.ParsePrefix(p); err == nil {
			s.trusted = append(s.trusted, pr.Masked())
		}
	}
	t, err := loadTemplates(s)
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	sub, _ := fs.Sub(assets, "static")
	fsrv := http.StripPrefix(s.base+"/static/", http.FileServer(http.FS(sub)))
	s.static = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		fsrv.ServeHTTP(w, r)
	})
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	b := s.base

	// Unauthenticated.
	mux.Handle("GET "+b+"/static/", s.static)
	mux.HandleFunc("GET "+b+"/healthz", s.healthz)
	mux.HandleFunc("GET "+b+"/login", s.loginPage)
	mux.HandleFunc("POST "+b+"/login", s.loginPost)
	mux.HandleFunc("GET "+b+"/login/2fa", s.twoFAPage)
	mux.HandleFunc("POST "+b+"/login/2fa", s.twoFAPost)
	mux.HandleFunc("POST "+b+"/logout", s.logout)
	mux.HandleFunc("GET "+b+"/setup", s.setupPage)
	mux.HandleFunc("POST "+b+"/setup", s.setupPost)
	mux.HandleFunc("GET "+b+"/invite/{token}", s.invitePage)
	mux.HandleFunc("POST "+b+"/invite/{token}", s.invitePost)
	mux.HandleFunc("GET "+b+"/2fa/enroll", s.enrollPage)
	mux.HandleFunc("POST "+b+"/2fa/enroll", s.enrollPost)

	// Phone flow, at the root as headscale's URLs are.
	mux.HandleFunc("GET /register/{id}", s.registerPage(registration.KindRegister))
	mux.HandleFunc("GET /auth/{id}", s.registerPage(registration.KindSSH))
	mux.HandleFunc("POST /register/{id}", s.registerConfirm(registration.KindRegister))
	mux.HandleFunc("POST /auth/{id}", s.registerConfirm(registration.KindSSH))
	mux.HandleFunc("POST /register/{id}/decide", s.registerSelfDecide)
	mux.HandleFunc("POST /auth/{id}/decide", s.registerSelfDecide)
	mux.HandleFunc("POST /register/{id}/cancel", s.registerCancel)
	mux.HandleFunc("POST /auth/{id}/cancel", s.registerCancel)
	mux.HandleFunc("GET /register/{id}/status", s.registerStatus)
	mux.HandleFunc("GET /auth/{id}/status", s.registerStatus)

	// Dashboard.
	page := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.authed(h)) }
	page("GET "+b+"/{$}", s.overview)
	page("GET "+b+"/ws", s.ws)
	page("GET "+b+"/search", s.search)
	page("GET "+b+"/approvals", s.approvals)
	page("POST "+b+"/approvals/{id}", s.approvalDecide)

	page("GET "+b+"/machines", s.machines)
	page("GET "+b+"/machines/{id}", s.machine)
	page("POST "+b+"/machines/{id}/{action}", s.machineAction)
	page("GET "+b+"/machines/{id}/ssh", s.sshPage)
	page("GET "+b+"/machines/{id}/ssh/ws", s.sshWS)
	page("POST "+b+"/machines/register", s.machineRegisterByID)

	page("GET "+b+"/users", s.users)
	page("POST "+b+"/users", s.userCreate)
	page("POST "+b+"/users/{id}/{action}", s.userAction)

	page("GET "+b+"/people", s.people)
	page("POST "+b+"/people/invite", s.inviteCreate)
	page("POST "+b+"/people/invites/{hash}/revoke", s.inviteRevoke)
	page("GET "+b+"/people/{id}", s.person)
	page("POST "+b+"/people/{id}/{action}", s.personAction)

	page("GET "+b+"/keys", s.keys)
	page("POST "+b+"/keys", s.keyCreate)
	page("POST "+b+"/keys/{id}/{action}", s.keyAction)

	page("GET "+b+"/access", s.access)
	page("POST "+b+"/access", s.accessPost)

	page("GET "+b+"/dns", s.dns)
	page("POST "+b+"/dns", s.dnsPost)

	page("GET "+b+"/alerts", s.alerts)
	page("POST "+b+"/alerts/rules", s.ruleCreate)
	page("POST "+b+"/alerts/rules/{id}/delete", s.ruleDelete)
	page("POST "+b+"/alerts/quiet", s.quietPost)
	page("POST "+b+"/alerts/telegram/link", s.telegramLink)
	page("POST "+b+"/alerts/telegram/unlink", s.telegramUnlink)

	page("GET "+b+"/audit", s.auditPage)
	page("GET "+b+"/audit.csv", s.auditCSV)

	page("GET "+b+"/settings", s.settings)
	page("POST "+b+"/settings/{section}", s.settingsPost)

	page("GET "+b+"/account", s.account)
	page("POST "+b+"/account/{action}", s.accountPost)

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b+"/", http.StatusFound)
	})
	mux.HandleFunc("GET "+b, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b+"/", http.StatusFound)
	})

	return s.recoverer(s.securityHeaders(s.withSession(s.csrf(mux))))
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Meshpanel", "1")
	if s.Poller != nil && !s.Poller.Healthy() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"ok":false,"headscale":false}`))
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

// localPath accepts only same-site paths for ?next= redirects.
func (s *Server) localPath(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return s.base + "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Host != "" || u.Scheme != "" {
		return s.base + "/"
	}
	return next
}
