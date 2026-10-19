package web

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/perm"
)

type ctxKey int

const (
	keyIdentity ctxKey = iota
	keyIP
)

// identity is who is making the request. Session may be a half-session
// (password checked, 2FA pending) when MFAOK is false.
type identity struct {
	Session *db.Session
	Account *db.Account
	Caps    perm.Cap
	Scope   perm.Scope
}

func (id *identity) Full() bool { return id != nil && id.Session.MFAOK && id.Account.TOTPEnabled }

func who(r *http.Request) *identity {
	id, _ := r.Context().Value(keyIdentity).(*identity)
	return id
}

func clientIP(r *http.Request) string {
	ip, _ := r.Context().Value(keyIP).(string)
	return ip
}

// realIP honours X-Forwarded-For only from configured trusted proxies, and
// then takes the rightmost address that is not itself a trusted proxy.
func (s *Server) realIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	remote = remote.Unmap()
	if !s.isTrusted(remote) {
		return remote.String()
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			if a, err := netip.ParseAddr(xr); err == nil {
				return a.Unmap().String()
			}
		}
		return remote.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.isTrusted(a) {
			return a.String()
		}
		remote = a
	}
	return remote.String()
}

func (s *Server) isTrusted(a netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), keyIP, s.realIP(r))
		if c, err := r.Cookie(auth.CookieName); err == nil && !strings.HasPrefix(r.URL.Path, s.base+"/static/") {
			if sess, acc, err := s.Sessions.Lookup(ctx, c.Value); err == nil {
				caps := perm.Effective(acc.Role, perm.Cap(acc.ExtraCaps))
				ctx = context.WithValue(ctx, keyIdentity, &identity{
					Session: sess, Account: acc, Caps: caps, Scope: perm.ScopeFor(caps, acc.HSUser),
				})
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name: auth.CookieName, Value: tok, Path: "/", HttpOnly: true,
		Secure: s.Cfg.Server.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(auth.SessionAbsolute.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.Cfg.Server.CookieSecure, MaxAge: -1, SameSite: http.SameSiteLaxMode})
}

const preCSRFCookie = "mp_csrf"

// maxBody bounds request bodies (forms, policies, logo uploads).
const maxBody = 4 << 20

// csrfToken returns the token forms must echo: the session's, or a
// double-submit cookie for signed-out forms.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if id := who(r); id != nil {
		return id.Session.CSRF
	}
	if c, err := r.Cookie(preCSRFCookie); err == nil && len(c.Value) >= 20 {
		return c.Value
	}
	tok := auth.RandomToken(24)
	http.SetCookie(w, &http.Cookie{Name: preCSRFCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.Cfg.Server.CookieSecure, SameSite: http.SameSiteStrictMode})
	// Make it visible to this same request's render.
	r.AddCookie(&http.Cookie{Name: preCSRFCookie, Value: tok})
	return tok
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// csrf rejects state-changing requests without the matching token, and any
// request whose Origin is another site.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && o != "null" && !s.sameOrigin(r, o) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		var want string
		if id := who(r); id != nil {
			want = id.Session.CSRF
		} else if c, err := r.Cookie(preCSRFCookie); err == nil {
			want = c.Value
		}
		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			got = r.PostFormValue("_csrf")
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			s.renderError(w, r, http.StatusForbidden, "This form expired", "Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sameOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" && s.isTrusted(remoteAddr(r)) && strings.EqualFold(u.Host, fh) {
		return true
	}
	if pu, err := url.Parse(s.Cfg.Server.PublicURL); err == nil && pu.Host != "" && strings.EqualFold(u.Host, pu.Host) {
		return true
	}
	return false
}

func remoteAddr(r *http.Request) netip.Addr {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// authed requires a full (2FA-verified) session with dashboard access.
func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := who(r)
		if id == nil || !id.Session.MFAOK {
			if r.Header.Get("HX-Request") != "" || strings.HasSuffix(r.URL.Path, "/ws") || strings.Contains(r.Header.Get("Accept"), "application/json") {
				w.Header().Set("HX-Redirect", s.base+"/login")
				http.Error(w, "sign in required", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, s.base+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if !id.Account.TOTPEnabled {
			http.Redirect(w, r, s.base+"/2fa/enroll", http.StatusFound)
			return
		}
		if !id.Caps.Has(perm.UIAccess) {
			s.renderError(w, r, http.StatusForbidden, "No dashboard access", "Your role does not include the dashboard. You can still add your devices from the Tailscale app.")
			return
		}
		h(w, r)
	})
}

// need reports whether the caller has cap, rendering a 403 if not.
func (s *Server) need(w http.ResponseWriter, r *http.Request, c perm.Cap) bool {
	if who(r).Caps.Has(c) {
		return true
	}
	s.renderError(w, r, http.StatusForbidden, "Not allowed", "Your role doesn't include this. Ask an admin if you need it.")
	return false
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, s.base+"/static/") {
			h.Set("Cache-Control", "no-store")
		}
		if s.Cfg.Server.CookieSecure {
			// cookie_secure means the panel is served over HTTPS.
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !safeMethod(r.Method) {
			if r.ContentLength > maxBody {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				slog.Error("panic serving request", "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
