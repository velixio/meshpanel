package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

type authForm struct {
	Next     string
	Error    string
	Username string
	Context  string // "register" | "ssh" | "" — shown as a banner on phone flows
	Device   string
	IP       string
	Invite   *db.Invite
	QR       any
	Secret   string
	Codes    []string
}

func (s *Server) authContext(next string, r *http.Request) authForm {
	f := authForm{Next: s.localPath(next)}
	switch {
	case strings.HasPrefix(f.Next, "/register/"):
		f.Context = "register"
	case strings.HasPrefix(f.Next, "/auth/"):
		f.Context = "ssh"
	}
	if f.Context != "" {
		f.Device = r.UserAgent()
		f.IP = clientIP(r)
	}
	return f
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.DB.CountAccounts(r.Context()); n == 0 {
		http.Redirect(w, r, s.base+"/setup", http.StatusFound)
		return
	}
	if id := who(r); id != nil && id.Session.MFAOK {
		http.Redirect(w, r, s.localPath(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	s.render(w, r, "login", s.page(w, r, "", "Sign in", s.authContext(r.URL.Query().Get("next"), r)))
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	form := s.authContext(r.PostFormValue("next"), r)
	form.Username = username
	fail := func(msg string) {
		form.Error = msg
		p := s.page(w, r, "", "Sign in", form)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", p)
	}
	// Full backoff per IP and per (account, IP); only a gentle cap per
	// account, so failures from one place can't lock the owner out.
	ipKey, pairKey, userKey := "ip:"+clientIP(r), "pair:"+username+"|"+clientIP(r), "user:"+username
	type slot struct {
		lim *auth.Limiter
		key string
	}
	var held []slot
	failed := true
	defer func() {
		for _, h := range held {
			if n := h.lim.Release(h.key, failed); failed && h.key == userKey && (n == 5 || n%20 == 0) {
				s.securityAlert(fmt.Sprintf("%d failed sign-ins for %q, latest from %s", n, username, clientIP(r)))
			}
		}
	}()
	for _, l := range []slot{{s.Limiter, ipKey}, {s.Limiter, pairKey}, {s.userLimit, userKey}} {
		if ok, wait := l.lim.Acquire(l.key); !ok {
			failed = false // a refused attempt isn't a new failure
			fail(fmt.Sprintf("Too many attempts. Try again in %s.", wait.Round(time.Second)))
			return
		}
		held = append(held, l)
	}
	acc, err := s.DB.GetAccountByUsername(ctx, username)
	hash := ""
	if err == nil && !acc.Disabled {
		hash = acc.PasswordHash
	}
	if !auth.VerifyPassword(hash, r.PostFormValue("password")) {
		fail("Wrong username or password.")
		return
	}
	failed = false
	s.Limiter.Reset(ipKey)
	s.Limiter.Reset(pairKey)
	if id := who(r); id != nil {
		_ = s.Sessions.Revoke(ctx, id.Session.ID)
	}
	tok, err := s.Sessions.Create(ctx, acc.ID, clientIP(r), r.UserAgent(), false)
	if err != nil {
		fail("Could not start a session. Try again.")
		return
	}
	s.setSessionCookie(w, tok)
	next := url.QueryEscape(form.Next)
	if !acc.TOTPEnabled {
		http.Redirect(w, r, s.base+"/2fa/enroll?next="+next, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.base+"/login/2fa?next="+next, http.StatusSeeOther)
}

func (s *Server) securityAlert(text string) {
	if s.Bus != nil {
		s.Bus.Publish(events.Event{Kind: events.Security, Text: text})
	}
	_ = s.DB.InsertAudit(context.Background(), db.AuditEntry{Actor: "system", Channel: "system", Action: "security", Target: text})
}

// halfSession returns the caller's password-verified, 2FA-pending session.
func halfSession(r *http.Request) *identity {
	id := who(r)
	if id == nil || id.Session.MFAOK {
		return nil
	}
	return id
}

func (s *Server) twoFAPage(w http.ResponseWriter, r *http.Request) {
	id := halfSession(r)
	if id == nil {
		http.Redirect(w, r, s.base+"/login", http.StatusFound)
		return
	}
	form := s.authContext(r.URL.Query().Get("next"), r)
	form.Username = id.Account.Username
	s.render(w, r, "twofa", s.page(w, r, "", "Two-factor code", form))
}

func (s *Server) twoFAPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := halfSession(r)
	if id == nil || !id.Account.TOTPEnabled {
		http.Redirect(w, r, s.base+"/login", http.StatusSeeOther)
		return
	}
	form := s.authContext(r.PostFormValue("next"), r)
	form.Username = id.Account.Username
	key := "2fa:" + id.Account.Username
	if ok, wait := s.Limiter.Acquire(key); !ok {
		form.Error = fmt.Sprintf("Too many attempts. Try again in %s.", wait.Round(time.Second))
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, r, "twofa", s.page(w, r, "", "Two-factor code", form))
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	usedBackup := false
	step, ok := auth.ValidateTOTPStep(id.Account.TOTPSecret, code, time.Now())
	if ok {
		// Each code works once, even inside its 90-second window.
		if fresh, err := s.DB.UseTOTPStep(ctx, id.Account.ID, step); err != nil || !fresh {
			ok = false
		}
	}
	if !ok && len(code) > 6 {
		ok = auth.UseBackupCode(ctx, s.DB, id.Account.ID, code)
		usedBackup = ok
	}
	if n := s.Limiter.Release(key, !ok); n == 5 {
		s.securityAlert(fmt.Sprintf("5 wrong 2FA codes for %q from %s", id.Account.Username, clientIP(r)))
	}
	if !ok {
		form.Error = "That code didn't work. Check your authenticator app's time and try again."
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "twofa", s.page(w, r, "", "Two-factor code", form))
		return
	}
	s.Limiter.Reset(key)
	s.userLimit.Reset("user:" + id.Account.Username)
	s.finishLogin(w, r, id, form.Next)
	if usedBackup {
		left := s.DB.RemainingBackupCodes(ctx, id.Account.ID)
		s.audit(r, "login.backup_code", id.Account.Username, nil, fmt.Sprintf("%d codes left", left))
	}
}

// finishLogin swaps the half-session for a full one (a fresh token, so a
// sniffed pre-2FA cookie is worthless) and redirects.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, id *identity, next string) {
	ctx := r.Context()
	_ = s.Sessions.Revoke(ctx, id.Session.ID)
	tok, err := s.Sessions.Create(ctx, id.Account.ID, clientIP(r), r.UserAgent(), true)
	if err != nil {
		s.renderError(w, r, 500, "Sign-in failed", "Could not create a session.")
		return
	}
	s.setSessionCookie(w, tok)
	_ = s.DB.TouchLogin(ctx, id.Account.ID)
	_ = s.DB.InsertAudit(ctx, db.AuditEntry{ActorID: id.Account.ID, Actor: id.Account.Username, Channel: "web", Action: "login", IP: clientIP(r)})
	http.Redirect(w, r, s.localPath(next), http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if id := who(r); id != nil {
		_ = s.Sessions.Revoke(r.Context(), id.Session.ID)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, s.base+"/login", http.StatusSeeOther)
}

// ---------- first-run setup ----------

// SetupToken is the one-time code the setup form asks for.
func (s *Server) SetupToken() string { return s.setupToken }

func (s *Server) setupOpen(ctx context.Context) bool {
	n, err := s.DB.CountAccounts(ctx)
	return err == nil && n == 0
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if !s.setupOpen(r.Context()) {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "setup", s.page(w, r, "", "Set up meshpanel", authForm{}))
}

func validateNewAccount(username, pw, confirm string) error {
	if !usernameRe.MatchString(username) {
		return errors.New("Usernames are 2–32 characters: lowercase letters, digits, dot, dash or underscore.")
	}
	if pw != confirm {
		return errors.New("The passwords don't match.")
	}
	if len([]rune(pw)) < auth.MinPasswordLen {
		return auth.ErrPasswordTooShort
	}
	return nil
}

func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.setupOpen(ctx) {
		http.NotFound(w, r)
		return
	}
	username := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	form := authForm{Username: username}
	pw := r.PostFormValue("password")
	err := validateNewAccount(username, pw, r.PostFormValue("confirm"))
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.PostFormValue("setup_token"))), []byte(s.setupToken)) != 1 {
		err = errors.New("Wrong setup code. It's in meshpanel's log (journalctl -u meshpanel).")
	}
	if err != nil {
		form.Error = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "setup", s.page(w, r, "", "Set up meshpanel", form))
		return
	}
	hash, _ := auth.HashPassword(pw)
	hsUser := strings.TrimSpace(r.PostFormValue("hs_user"))
	acc, err := s.DB.CreateAccount(ctx, db.Account{
		Username: username, DisplayName: strings.TrimSpace(r.PostFormValue("display_name")),
		PasswordHash: hash, Role: "owner", HSUser: hsUser,
	})
	if err != nil {
		form.Error = "Could not create the account. " + internal(err)
		s.render(w, r, "setup", s.page(w, r, "", "Set up meshpanel", form))
		return
	}
	s.startEnrollment(w, r, acc, s.base+"/")
}

func (s *Server) startEnrollment(w http.ResponseWriter, r *http.Request, acc *db.Account, next string) {
	tok, err := s.Sessions.Create(r.Context(), acc.ID, clientIP(r), r.UserAgent(), false)
	if err != nil {
		s.renderError(w, r, 500, "Something went wrong", internal(err))
		return
	}
	s.setSessionCookie(w, tok)
	http.Redirect(w, r, s.base+"/2fa/enroll?next="+url.QueryEscape(next), http.StatusSeeOther)
}

// ---------- invites ----------

func (s *Server) invitePage(w http.ResponseWriter, r *http.Request) {
	in, err := s.DB.GetInvite(r.Context(), auth.HashToken(r.PathValue("token")))
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "Invite not valid", "This invite link expired or was already used. Ask your admin for a new one.")
		return
	}
	s.render(w, r, "invite", s.page(w, r, "", "Join", authForm{Invite: in, Username: in.Username}))
}

func (s *Server) invitePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hash := auth.HashToken(r.PathValue("token"))
	in, err := s.DB.GetInvite(ctx, hash)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "Invite not valid", "This invite link expired or was already used.")
		return
	}
	form := authForm{Invite: in, Username: in.Username}
	pw := r.PostFormValue("password")
	if err := validateNewAccount(in.Username, pw, r.PostFormValue("confirm")); err != nil {
		form.Error = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "invite", s.page(w, r, "", "Join", form))
		return
	}
	if ok, _ := s.DB.UseInvite(ctx, hash); !ok {
		s.renderError(w, r, http.StatusGone, "Invite already used", "This invite was used a moment ago.")
		return
	}
	hsUser := in.HSUser
	if hsUser == "" {
		hsUser = in.Username
	}
	if err := s.ensureHSUser(ctx, hsUser, r.PostFormValue("display_name")); err != nil {
		form.Error = "Could not create your headscale user: " + friendly(err)
		s.render(w, r, "invite", s.page(w, r, "", "Join", form))
		return
	}
	pwHash, _ := auth.HashPassword(pw)
	acc, err := s.DB.CreateAccount(ctx, db.Account{
		Username: in.Username, DisplayName: strings.TrimSpace(r.PostFormValue("display_name")),
		PasswordHash: pwHash, Role: in.Role, HSUser: hsUser,
	})
	if err != nil {
		form.Error = "Could not create the account. " + internal(err)
		s.render(w, r, "invite", s.page(w, r, "", "Join", form))
		return
	}
	_ = s.DB.InsertAudit(ctx, db.AuditEntry{ActorID: acc.ID, Actor: acc.Username, Channel: "web", Action: "invite.accept", Target: acc.Username, IP: clientIP(r)})
	s.startEnrollment(w, r, acc, s.base+"/")
}

// ensureHSUser creates the headscale user if it does not exist yet.
func (s *Server) ensureHSUser(ctx context.Context, name, display string) error {
	users, err := s.HS.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Name == name {
			return nil
		}
	}
	_, err = s.HS.CreateUser(ctx, name, display, "")
	return err
}

// ---------- TOTP enrollment ----------

func (s *Server) enrollPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	if id == nil {
		http.Redirect(w, r, s.base+"/login", http.StatusFound)
		return
	}
	acc := id.Account
	reset := r.URL.Query().Get("reset") == "1" && id.Session.MFAOK
	if acc.TOTPEnabled && !reset {
		http.Redirect(w, r, s.base+"/", http.StatusFound)
		return
	}
	if acc.TOTPSecret == "" || (reset && r.URL.Query().Get("keep") == "") {
		secret, _ := auth.NewTOTPSecret(s.brand(ctx).Name, acc.Username)
		sealed := auth.SealSecret(secret)
		if reset {
			// Stage the new secret without disabling the old one yet.
			_ = s.DB.SetSetting(ctx, fmt.Sprintf("pending_totp.%d", acc.ID), sealed)
		} else {
			acc.TOTPSecret = sealed
			if err := s.DB.UpdateAccount(ctx, acc); err != nil {
				s.renderError(w, r, 500, "Something went wrong", internal(err))
				return
			}
		}
	}
	secret := auth.OpenSecret(acc.TOTPSecret)
	if reset {
		secret = auth.OpenSecret(s.DB.GetSetting(ctx, fmt.Sprintf("pending_totp.%d", acc.ID)))
	}
	uri := "otpauth://totp/" + url.PathEscape(s.brand(ctx).Name) + ":" + url.PathEscape(acc.Username) +
		"?secret=" + secret + "&issuer=" + url.QueryEscape(s.brand(ctx).Name) + "&algorithm=SHA1&digits=6&period=30"
	form := s.authContext(r.URL.Query().Get("next"), r)
	form.Username, form.Secret, form.QR = acc.Username, secret, qrDataURI(uri)
	p := s.page(w, r, "", "Set up two-factor", form)
	s.render(w, r, "enroll", p)
}

func (s *Server) enrollPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	if id == nil {
		http.Redirect(w, r, s.base+"/login", http.StatusSeeOther)
		return
	}
	acc := id.Account
	if acc.TOTPEnabled && !id.Session.MFAOK {
		// Already enrolled: a password-only session signs in at /login/2fa,
		// never here (this would skip the one-use check and reset backup codes).
		http.Redirect(w, r, s.base+"/login/2fa", http.StatusSeeOther)
		return
	}
	reset := id.Session.MFAOK && acc.TOTPEnabled
	secret := acc.TOTPSecret
	pendingKey := fmt.Sprintf("pending_totp.%d", acc.ID)
	if reset {
		secret = s.DB.GetSetting(ctx, pendingKey)
	}
	key := "2fa:" + acc.Username
	allowed, _ := s.Limiter.Acquire(key)
	step, valid := auth.ValidateTOTPStep(secret, r.PostFormValue("code"), time.Now())
	if allowed && valid && secret != "" {
		// Each code works once, here as at sign-in.
		if fresh, err := s.DB.UseTOTPStep(ctx, acc.ID, step); err != nil || !fresh {
			valid = false
		}
	}
	if allowed {
		s.Limiter.Release(key, !valid || secret == "")
	}
	if !allowed || secret == "" || !valid {
		q := url.Values{"next": {r.PostFormValue("next")}}
		if reset {
			q.Set("reset", "1")
			q.Set("keep", "1")
		}
		s.done(w, r, s.base+"/2fa/enroll?"+q.Encode(), "danger", "That code didn't match. Scan the QR code again and enter the current code.")
		return
	}
	s.Limiter.Reset(key)
	acc.TOTPSecret, acc.TOTPEnabled = secret, true
	if err := s.DB.UpdateAccount(ctx, acc); err != nil {
		s.renderError(w, r, 500, "Something went wrong", internal(err))
		return
	}
	_ = s.DB.SetSetting(ctx, pendingKey, "")
	codes, err := auth.NewBackupCodes(ctx, s.DB, acc.ID)
	if err != nil {
		s.renderError(w, r, 500, "Something went wrong", internal(err))
		return
	}
	_ = s.DB.InsertAudit(ctx, db.AuditEntry{ActorID: acc.ID, Actor: acc.Username, Channel: "web", Action: "2fa.enroll", Target: acc.Username, IP: clientIP(r)})
	next := s.localPath(r.PostFormValue("next"))
	if !id.Session.MFAOK {
		_ = s.Sessions.Revoke(ctx, id.Session.ID)
		tok, err := s.Sessions.Create(ctx, acc.ID, clientIP(r), r.UserAgent(), true)
		if err != nil {
			s.renderError(w, r, 500, "Sign-in failed", internal(err))
			return
		}
		s.setSessionCookie(w, tok)
		_ = s.DB.TouchLogin(ctx, acc.ID)
	}
	form := authForm{Next: next, Codes: codes, Username: acc.Username}
	s.render(w, r, "codes", s.page(w, r, "", "Backup codes", form))
}

// hsUserExists reports whether name is a headscale user in the latest snapshot.
func hsUserExists(users []hs.User, name string) bool {
	for _, u := range users {
		if u.Name == name {
			return true
		}
	}
	return false
}

var _ = perm.UIAccess
