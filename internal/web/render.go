package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/registration"
)

type templates struct {
	pages map[string]*template.Template
}

func loadTemplates(s *Server) (*templates, error) {
	funcs := s.funcs()
	common := template.New("").Funcs(funcs)
	for _, f := range []string{"templates/layout.html", "templates/partials.html"} {
		b, err := fs.ReadFile(assets, f)
		if err != nil {
			return nil, err
		}
		if _, err := common.New(path.Base(f)).Parse(string(b)); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	files, err := fs.Glob(assets, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	t := &templates{pages: map[string]*template.Template{}}
	for _, f := range files {
		b, err := fs.ReadFile(assets, f)
		if err != nil {
			return nil, err
		}
		c, err := common.Clone()
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(path.Base(f), ".html")
		if _, err := c.New(name).Parse(string(b)); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		t.pages[name] = c
	}
	return t, nil
}

// Brand is the company's look, set in Settings.
type Brand struct {
	Name     string
	Accent   string
	AccentFG string
	Logo     template.URL
}

func (s *Server) brand(ctx context.Context) Brand {
	b := Brand{Name: s.DB.GetSetting(ctx, "brand.name"), Accent: s.DB.GetSetting(ctx, "brand.accent")}
	if b.Name == "" {
		b.Name = "meshpanel"
	}
	if logo := s.DB.GetSetting(ctx, "brand.logo"); strings.HasPrefix(logo, "data:image/") {
		b.Logo = template.URL(logo)
	}
	if b.Accent != "" {
		b.AccentFG = contrastFG(b.Accent)
	}
	return b
}

// contrastFG picks black or white text for a #rrggbb background.
func contrastFG(hex string) string {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return "#ffffff"
	}
	v, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return "#ffffff"
	}
	lin := func(c uint64) float64 {
		f := float64(c) / 255
		if f <= 0.03928 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	l := 0.2126*lin(v>>16&0xff) + 0.7152*lin(v>>8&0xff) + 0.0722*lin(v&0xff)
	if l > 0.4 {
		return "#111111"
	}
	return "#ffffff"
}

type flash struct {
	Kind string
	Msg  string
}

// Page is what every template receives.
type Page struct {
	Title        string
	Nav          string
	Me           *db.Account
	Caps         perm.Cap
	Scope        perm.Scope
	CSRF         string
	Base         string
	Theme        string
	Brand        Brand
	Flash        *flash
	PendingCount int
	Healthy      bool
	HSError      string
	PublicURL    string
	Version      string
	Data         any
}

func (s *Server) page(w http.ResponseWriter, r *http.Request, nav, title string, data any) *Page {
	p := &Page{
		Title: title, Nav: nav, CSRF: s.csrfToken(w, r), Base: s.base, Theme: "paper",
		Brand: s.brand(r.Context()), PublicURL: s.Cfg.Server.PublicURL, Version: s.Version, Data: data, Healthy: true,
	}
	if id := who(r); id != nil {
		p.Me, p.Caps, p.Scope = id.Account, id.Caps, id.Scope
		p.Theme = id.Account.Theme
		if id.Session.MFAOK {
			p.PendingCount = s.pendingCountFor(r.Context(), id)
		}
	} else if c, err := r.Cookie("mp_theme"); err == nil && validTheme(c.Value) {
		p.Theme = c.Value
	}
	if s.Poller != nil && !s.Poller.Healthy() {
		p.Healthy = false
		if err := s.Poller.LastError(); err != nil {
			p.HSError = err.Error()
		}
	}
	if c, err := r.Cookie("mp_flash"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			kind, msg, _ := strings.Cut(v, "|")
			p.Flash = &flash{Kind: kind, Msg: msg}
		}
		http.SetCookie(w, &http.Cookie{Name: "mp_flash", Value: "", Path: "/", MaxAge: -1})
	}
	return p
}

func validTheme(t string) bool {
	return t == "paper" || t == "midnight" || t == "console" || t == "system"
}

func (s *Server) pendingCountFor(ctx context.Context, id *identity) int {
	ps, err := s.DB.ListPending(ctx, true, 100)
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range ps {
		if canDecide(id, p) && p.RequesterID != id.Account.ID {
			n++
		}
	}
	return n
}

func canDecide(id *identity, p *db.Pending) bool {
	if p.Kind == registration.KindSSH {
		return id.Caps.Has(perm.ApproveSSH)
	}
	return perm.CanApprove(id.Caps, id.Account.HSUser, p.HSUser)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p *Page) {
	t, ok := s.tmpl.pages[name]
	if !ok {
		http.Error(w, "missing template "+name, http.StatusInternalServerError)
		return
	}
	layout := "layout"
	if t.Lookup("auth-page") != nil && (t.Lookup("content") == nil || p.Me == nil || !who(r).Full()) {
		layout = "auth"
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, layout, p); err != nil {
		slog.Error("render", "page", name, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int, title, msg string) {
	p := s.page(w, r, "", title, map[string]string{"Title": title, "Message": msg})
	w.WriteHeader(code)
	s.render(w, r, "error", p)
}

// done redirects back with a toast.
func (s *Server) done(w http.ResponseWriter, r *http.Request, to, kind, msg string) {
	if msg != "" {
		http.SetCookie(w, &http.Cookie{Name: "mp_flash", Value: url.QueryEscape(kind + "|" + msg), Path: "/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	if to == "" {
		to = s.back(r)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) ok(w http.ResponseWriter, r *http.Request, to, msg string) {
	s.done(w, r, to, "ok", msg)
}

func (s *Server) failed(w http.ResponseWriter, r *http.Request, to string, err error) {
	s.done(w, r, to, "danger", friendly(err))
}

// back is the referring dashboard page, or the overview.
func (s *Server) back(r *http.Request) string {
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && (u.Host == "" || strings.EqualFold(u.Host, r.Host)) {
			return s.localPath(u.RequestURI())
		}
	}
	return s.base + "/"
}

// friendly makes an error short enough for a toast.
func friendly(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "headscale: ")
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

// audit records an action taken through the web UI.
func (s *Server) audit(r *http.Request, action, target string, before, after any) {
	id := who(r)
	e := db.AuditEntry{Channel: "web", Action: action, Target: target, IP: clientIP(r), Before: jsonish(before), After: jsonish(after)}
	if id != nil {
		e.ActorID, e.Actor = id.Account.ID, id.Account.Username
	}
	if err := s.DB.InsertAudit(r.Context(), e); err != nil {
		slog.Error("audit write failed", "err", err)
	}
	if s.Bus != nil {
		s.Bus.Publish(events.Event{Kind: events.Changed, Actor: e.Actor, Channel: "web", Text: action})
	}
	if s.Poller != nil {
		s.Poller.Refresh()
	}
}

func jsonish(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func qrDataURI(text string) template.URL {
	png, err := qrcode.Encode(text, qrcode.Medium, 360)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"icon": func(name string) template.HTML {
			return template.HTML(`<svg class="icon" aria-hidden="true"><use href="` + s.base + `/static/icons.svg#` + template.HTMLEscapeString(name) + `"/></svg>`)
		},
		"has":  func(c perm.Cap, name string) bool { return c.Has(perm.Parse([]string{name})) },
		"ago":  func(t any) string { return ago(toTime(t), time.Now()) },
		"unix": func(t any) int64 { return toTime(t).Unix() },
		"date": func(t any) string {
			tt := toTime(t)
			if tt.IsZero() {
				return "—"
			}
			return tt.Local().Format("2 Jan 2006, 15:04")
		},
		"until":    func(t any) string { return until(toTime(t), time.Now()) },
		"initials": initials,
		"join":     strings.Join,
		"lower":    strings.ToLower,
		"contains": func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		},
		"risk": hs.RouteRisk,
		"ip": func(n hs.Node) string {
			if len(n.IPAddresses) > 0 {
				return n.IPAddresses[0]
			}
			return ""
		},
		"device": registration.DescribeUA,
		"qr":     qrDataURI,
		"add":    func(a, b int) int { return a + b },
		"pct": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a * 100 / b
		},
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"roleHelp": func(r string) string { return perm.RoleHelp[r] },
		"capName":  func(c perm.Cap) string { return strings.Join(c.Names(), ", ") },
		"json":     func(v any) string { b, _ := json.Marshal(v); return string(b) },
		"deref": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
		"now": time.Now,
	}
}

func toTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case *time.Time:
		if t != nil {
			return *t
		}
	}
	return time.Time{}
}

func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < 45*time.Second:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()+0.5))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()+0.5))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24+0.5))
	}
	return t.Local().Format("2 Jan 2006")
}

func until(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := t.Sub(now)
	switch {
	case d <= 0:
		return "expired"
	case d < time.Hour:
		return fmt.Sprintf("in %dm", int(d.Minutes()+0.5))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()+0.5))
	}
	return fmt.Sprintf("in %dd", int(d.Hours()/24+0.5))
}

func initials(name string) string {
	f := strings.Fields(strings.NewReplacer(".", " ", "_", " ", "-", " ", "@", " ").Replace(name))
	switch len(f) {
	case 0:
		return "?"
	case 1:
		r := []rune(f[0])
		if len(r) > 1 {
			return string(r[:2])
		}
		return string(r)
	}
	return string([]rune(f[0])[:1]) + string([]rune(f[1])[:1])
}
