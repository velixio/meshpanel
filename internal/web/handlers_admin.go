package web

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/tailnet"
	"github.com/meshpanel/meshpanel/internal/webhook"
)

// ---------- audit ----------

type auditData struct {
	Entries []*db.AuditEntry
	Query   string
	Page    int
	More    bool
}

func (s *Server) auditFilter(r *http.Request) (db.AuditFilter, int) {
	q := r.URL.Query()
	pg, _ := strconv.Atoi(q.Get("page"))
	if pg < 1 {
		pg = 1
	}
	f := db.AuditFilter{Query: q.Get("q"), Limit: 100, Offset: (pg - 1) * 100}
	if d, err := time.Parse("2006-01-02", q.Get("since")); err == nil {
		f.Since = d
	}
	return f, pg
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ReadAudit) {
		return
	}
	f, pg := s.auditFilter(r)
	f.Limit++
	entries, err := s.DB.ListAudit(r.Context(), f)
	d := auditData{Query: f.Query, Page: pg}
	if len(entries) > 100 {
		entries, d.More = entries[:100], true
	}
	d.Entries = entries
	p := s.page(w, r, "audit", "Audit log", d)
	if err != nil {
		p.Flash = &flash{Kind: "danger", Msg: friendly(err)}
	}
	s.render(w, r, "audit", p)
}

func (s *Server) auditCSV(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ReadAudit) {
		return
	}
	f, _ := s.auditFilter(r)
	f.Limit, f.Offset = 100000, 0
	entries, err := s.DB.ListAudit(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="meshpanel-audit-`+time.Now().Format("2006-01-02")+`.csv"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "actor", "channel", "action", "target", "before", "after", "ip"})
	for _, e := range entries {
		cw.Write([]string{e.At.UTC().Format(time.RFC3339), csvSafe(e.Actor), e.Channel, e.Action, csvSafe(e.Target), csvSafe(e.Before), csvSafe(e.After), e.IP})
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ---------- settings ----------

type settingsData struct {
	HSVersion      string
	VersionTested  bool
	VersionErr     string
	Socket         string
	Healthy        bool
	HSError        string
	PolicyMode     string
	ConfigPath     string
	ConfigWritable bool
	ApplyReady     bool
	TGEnabled      bool
	TGBot          string
	TGErr          string
	GroupChat      string
	Brand          Brand
	Users          []hs.User
	Uptime         string
	AgentOn        bool
	Agent          tailnet.AgentState
	SSHOn          bool
	SSHActive      int
	Webhooks       []*db.Webhook
	HookKinds      []events.Kind
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ConfigureIAM) {
		return
	}
	ctx := r.Context()
	d := settingsData{
		Socket: s.Cfg.Headscale.Socket, Healthy: s.Poller.Healthy(), ApplyReady: s.Applier != nil,
		TGEnabled: s.TG != nil, GroupChat: s.DB.GetSetting(ctx, "telegram.group_chat"), Brand: s.brand(ctx),
		Users: s.Poller.Users(), Uptime: time.Since(s.start).Round(time.Minute).String(),
	}
	if err := s.Poller.LastError(); err != nil {
		d.HSError = err.Error()
	}
	if s.Agent != nil {
		d.AgentOn, d.Agent = true, s.Agent.State()
	}
	d.Webhooks, _ = s.DB.ListWebhooks(ctx)
	d.HookKinds = webhook.Kinds
	if s.SSH != nil {
		d.SSHOn, d.SSHActive = true, s.SSH.Active()
	}
	if s.HSVersion != nil {
		d.HSVersion = s.HSVersion()
		d.VersionTested = hs.IsTested(d.HSVersion)
	}
	if s.HSConfig != nil {
		d.ConfigPath, d.ConfigWritable = s.HSConfig.Path, s.HSConfig.Writable()
	}
	if pol, err := s.HS.GetPolicy(ctx); err == nil {
		d.PolicyMode, _ = s.policyMode(pol.UpdatedAt.IsZero())
	}
	if s.TG != nil {
		if n, err := s.TG.BotName(ctx); err != nil {
			d.TGErr = friendly(err)
		} else {
			d.TGBot = n
		}
	}
	s.render(w, r, "settings", s.page(w, r, "settings", "Settings", d))
}

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func (s *Server) settingsPost(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ConfigureIAM) {
		return
	}
	ctx := r.Context()
	here := s.base + "/settings"
	switch r.PathValue("section") {
	case "brand":
		if err := r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			s.failed(w, r, here, err)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if len(name) > 40 {
			name = name[:40]
		}
		accent := strings.TrimSpace(r.FormValue("accent"))
		if r.FormValue("reset_accent") == "1" {
			accent = ""
		}
		if accent != "" && !hexColor.MatchString(accent) {
			s.failed(w, r, here, errors.New("accent must be a color like #2563eb"))
			return
		}
		_ = s.DB.SetSetting(ctx, "brand.name", name)
		_ = s.DB.SetSetting(ctx, "brand.accent", strings.ToLower(accent))
		if r.FormValue("remove_logo") == "1" {
			_ = s.DB.SetSetting(ctx, "brand.logo", "")
		} else if f, hdr, err := r.FormFile("logo"); err == nil {
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, 256<<10+1))
			if err != nil || len(b) > 256<<10 {
				s.failed(w, r, here, errors.New("logo must be under 256 KB"))
				return
			}
			mime := http.DetectContentType(b)
			if strings.HasSuffix(strings.ToLower(hdr.Filename), ".svg") {
				mime = "image/svg+xml"
			}
			if mime != "image/png" && mime != "image/jpeg" && mime != "image/webp" && mime != "image/svg+xml" && mime != "image/gif" {
				s.failed(w, r, here, errors.New("logo must be PNG, JPEG, WebP, GIF or SVG"))
				return
			}
			_ = s.DB.SetSetting(ctx, "brand.logo", "data:"+mime+";base64,"+base64.StdEncoding.EncodeToString(b))
		}
		s.audit(r, "settings.brand", name, nil, accent)
		s.ok(w, r, here, "Branding saved.")
	case "webhook_add":
		r.ParseForm()
		u, err := url.Parse(strings.TrimSpace(r.PostFormValue("url")))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			s.failed(w, r, here, errors.New("the webhook URL must be an http:// or https:// address"))
			return
		}
		format := r.PostFormValue("format")
		if format != "slack" && format != "discord" {
			format = "json"
		}
		valid := map[string]bool{}
		for _, k := range webhook.Kinds {
			valid[string(k)] = true
		}
		var kinds []string
		for _, k := range r.PostForm["event"] {
			if valid[k] {
				kinds = append(kinds, k)
			}
		}
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			name = u.Host
		}
		if _, err := s.DB.CreateWebhook(ctx, db.Webhook{Name: name, URL: u.String(), Format: format, Events: kinds, Secret: auth.RandomToken(24)}); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "webhook.create", name, nil, map[string]any{"host": u.Host, "format": format, "events": kinds})
		s.ok(w, r, here, "Webhook added.")
	case "webhook_delete", "webhook_test":
		hid, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
		hook, err := s.DB.GetWebhook(ctx, hid)
		if err != nil {
			s.failed(w, r, here, errors.New("webhook not found"))
			return
		}
		if r.PathValue("section") == "webhook_delete" {
			_ = s.DB.DeleteWebhook(ctx, hid)
			s.audit(r, "webhook.delete", hook.Name, nil, nil)
			s.ok(w, r, here, "Webhook removed.")
			return
		}
		if s.Webhooks == nil {
			s.failed(w, r, here, errors.New("webhooks are not running"))
			return
		}
		err = s.Webhooks.Send(ctx, hook, events.Event{Kind: events.NodeAdded, NodeName: "test-device", HSUser: who(r).Account.HSUser, Actor: who(r).Account.Username, Text: "test"})
		if err != nil {
			s.failed(w, r, here, fmt.Errorf("test delivery failed: %w", err))
			return
		}
		s.ok(w, r, here, "Test event delivered.")
	case "telegram":
		raw := strings.TrimSpace(r.PostFormValue("group_chat"))
		var id int64
		if raw != "" {
			v, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				s.failed(w, r, here, errors.New("the group chat id is a number, usually starting with -100"))
				return
			}
			id = v
		}
		_ = s.DB.SetSetting(ctx, "telegram.group_chat", raw)
		if s.TG != nil {
			s.TG.SetGroupChat(id)
		}
		s.audit(r, "settings.telegram_group", raw, nil, nil)
		s.ok(w, r, here, "Telegram group saved.")
	default:
		http.NotFound(w, r)
	}
}

// ---------- my account ----------

type accountData struct {
	Sessions []*db.Session
	Current  string
	Codes    int
	NewCodes []string
	Error    string
}

func (s *Server) accountData(r *http.Request) accountData {
	id := who(r)
	d := accountData{Current: id.Session.ID, Codes: s.DB.RemainingBackupCodes(r.Context(), id.Account.ID)}
	d.Sessions, _ = s.DB.ListSessions(r.Context(), id.Account.ID)
	return d
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "account", s.page(w, r, "", "My account", s.accountData(r)))
}

func (s *Server) accountPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	acc := id.Account
	here := s.base + "/account"
	switch r.PathValue("action") {
	case "profile":
		acc.DisplayName = strings.TrimSpace(r.PostFormValue("display_name"))
		acc.Email = strings.TrimSpace(r.PostFormValue("email"))
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.ok(w, r, here, "Profile saved.")
	case "theme":
		t := r.PostFormValue("theme")
		if !validTheme(t) {
			t = "paper"
		}
		acc.Theme = t
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "mp_theme", Value: t, Path: "/", MaxAge: 365 * 86400, SameSite: http.SameSiteLaxMode})
		s.ok(w, r, here, "Theme changed.")
	case "password":
		if !auth.VerifyPassword(acc.PasswordHash, r.PostFormValue("current")) {
			s.failed(w, r, here, errors.New("your current password is wrong"))
			return
		}
		if r.PostFormValue("password") != r.PostFormValue("confirm") {
			s.failed(w, r, here, errors.New("the new passwords don't match"))
			return
		}
		hash, err := auth.HashPassword(r.PostFormValue("password"))
		if err != nil {
			s.failed(w, r, here, err)
			return
		}
		acc.PasswordHash = hash
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		_ = s.DB.DeleteSessionsFor(ctx, acc.ID, id.Session.ID)
		s.audit(r, "account.password", acc.Username, nil, nil)
		s.ok(w, r, here, "Password changed. Other sessions were signed out.")
	case "codes":
		step, ok := auth.ValidateTOTPStep(acc.TOTPSecret, r.PostFormValue("code"), time.Now())
		if ok {
			ok, _ = s.DB.UseTOTPStep(ctx, acc.ID, step)
		}
		if !ok {
			s.failed(w, r, here, errors.New("enter the current code from your authenticator app (each code works once)"))
			return
		}
		codes, err := auth.NewBackupCodes(ctx, s.DB, acc.ID)
		if err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "account.backup_codes", acc.Username, nil, nil)
		d := s.accountData(r)
		d.NewCodes = codes
		s.render(w, r, "account", s.page(w, r, "", "My account", d))
	case "revoke":
		sid := r.PostFormValue("session")
		for _, sess := range s.accountDataSessions(r) {
			if sess.ID == sid && sid != id.Session.ID {
				_ = s.DB.DeleteSession(ctx, sid)
			}
		}
		s.ok(w, r, here, "Session signed out.")
	case "revoke_others":
		_ = s.DB.DeleteSessionsFor(ctx, acc.ID, id.Session.ID)
		s.ok(w, r, here, "Signed out of all other sessions.")
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) accountDataSessions(r *http.Request) []*db.Session {
	ss, _ := s.DB.ListSessions(r.Context(), who(r).Account.ID)
	return ss
}
