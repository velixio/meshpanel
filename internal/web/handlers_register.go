package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/registration"
)

// registerView drives templates/pages/register.html.
type registerView struct {
	State   string // invalid | confirm | waiting | ssh-decide | approved | denied | expired | cancelled | failed
	Kind    string
	AuthID  string
	Path    string // /register/<id> or /auth/<id>
	Pending *db.Pending
	Device  string
	IP      string
	Users   []hs.User // offered when the person may pick whose device it is
	SelfOK  bool      // confirming adds the device right away
	CanSSH  bool      // may approve SSH checks
	Error   string
	AtLimit bool // the person's user reached the device limit
	Count   int
	Limit   int
}

func kindPath(kind, id string) string {
	if kind == registration.KindSSH {
		return "/auth/" + id
	}
	return "/register/" + id
}

func kindTitle(kind string) string {
	if kind == registration.KindSSH {
		return "Approve SSH access"
	}
	return "Add this device"
}

// requireFull sends people who aren't fully signed in through login (and
// 2FA setup) and back. It reports whether to continue.
func (s *Server) requireFull(w http.ResponseWriter, r *http.Request, back string) bool {
	id := who(r)
	if id.Full() {
		return true
	}
	next := url.QueryEscape(back)
	if id != nil && !id.Account.TOTPEnabled {
		http.Redirect(w, r, s.base+"/2fa/enroll?next="+next, http.StatusFound)
		return false
	}
	http.Redirect(w, r, s.base+"/login?next="+next, http.StatusFound)
	return false
}

// registerPage only displays. Creating or approving a request takes a POST
// with the CSRF token: otherwise a link sent to a signed-in admin could add
// the sender's device to the admin's account.
func (s *Server) registerPage(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authID := r.PathValue("id")
		v := &registerView{Kind: kind, AuthID: authID, Path: kindPath(kind, authID), Device: r.UserAgent(), IP: clientIP(r)}
		if !hs.ValidAuthID(authID) {
			v.State = "invalid"
			w.WriteHeader(http.StatusNotFound)
			s.render(w, r, "register", s.page(w, r, "", kindTitle(kind), v))
			return
		}
		if !s.requireFull(w, r, v.Path) {
			return
		}
		id := who(r)
		v.CanSSH = id.Caps.Has(perm.ApproveSSH)
		p, err := s.DB.LatestPending(r.Context(), authID, id.Account.ID)
		switch {
		case errors.Is(err, db.ErrNotFound):
			v.State = "confirm"
			if kind == registration.KindRegister {
				v.AtLimit, v.Count, v.Limit = s.atLimit(r.Context(), id.Account.HSUser)
				v.SelfOK = !v.AtLimit && id.Account.HSUser != "" && perm.CanApprove(id.Caps, id.Account.HSUser, id.Account.HSUser)
				if id.Caps.Has(perm.ApproveDevices) {
					v.Users = s.Poller.Users()
				}
			}
		case err != nil:
			v.State, v.Error = "failed", friendly(err)
		default:
			v.Pending = p
			v.State = p.Status
			switch {
			case p.Open() && kind == registration.KindSSH && v.CanSSH:
				v.State = "ssh-decide"
			case p.Open(), p.Status == db.StatusApproving:
				v.State = "waiting"
			}
			v.Error = p.Error
		}
		s.render(w, r, "register", s.page(w, r, "", kindTitle(kind), v))
	}
}

func isDecision(d string) bool { return d == "approve" || d == "deny" }

// registerConfirm creates the request and, when the person may approve it
// themselves, decides it in the same step.
func (s *Server) registerConfirm(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authID := r.PathValue("id")
		back := kindPath(kind, authID)
		if !hs.ValidAuthID(authID) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !s.requireFull(w, r, back) {
			return
		}
		id := who(r)
		if _, err := s.DB.LatestPending(ctx, authID, id.Account.ID); err == nil {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		p, err := s.Reg.Create(ctx, kind, authID, id.Account, clientIP(r), r.UserAgent())
		if err != nil {
			s.done(w, r, back, "danger", friendly(err))
			return
		}
		s.audit(r, kind+".request", authID, nil, map[string]string{"device": registration.DescribeUA(r.UserAgent()), "ip": clientIP(r)})

		asUser := strings.TrimSpace(r.PostFormValue("as_user"))
		decision := r.PostFormValue("decision")
		// Over the device limit, only approve_devices holders add directly
		// (they're the ones the limit asks); everyone else goes to the queue.
		limited, _, _ := s.atLimit(ctx, id.Account.HSUser)
		if limited && !id.Caps.Has(perm.ApproveDevices) {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		switch {
		case kind == registration.KindSSH && isDecision(decision) && id.Caps.Has(perm.ApproveSSH):
			_, err = s.Reg.Decide(ctx, p.ID, decision == "approve", id.Account, "web", "")
			s.audit(r, "ssh.decide", authID, nil, map[string]any{"approve": decision == "approve", "error": friendly(err)})
		case kind == registration.KindRegister && asUser != "" && perm.CanApproveAs(id.Caps, id.Account.HSUser, id.Account.HSUser, asUser):
			_, err = s.Reg.Decide(ctx, p.ID, true, id.Account, "web", asUser)
			s.audit(r, "register.self_approve", authID, nil, map[string]any{"as_user": asUser, "error": friendly(err)})
		case kind == registration.KindRegister && id.Account.HSUser != "" && perm.CanApprove(id.Caps, id.Account.HSUser, id.Account.HSUser):
			_, err = s.Reg.Decide(ctx, p.ID, true, id.Account, "web", "")
			s.audit(r, "register.self_approve", authID, nil, map[string]any{"error": friendly(err)})
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

func (s *Server) pendingFor(r *http.Request) (*identity, *db.Pending, string, bool) {
	id := who(r)
	authID := r.PathValue("id")
	if !id.Full() || !hs.ValidAuthID(authID) {
		return nil, nil, "", false
	}
	p, err := s.DB.LatestPending(r.Context(), authID, id.Account.ID)
	if err != nil {
		return nil, nil, "", false
	}
	return id, p, kindPath(p.Kind, authID), true
}

// registerSelfDecide handles the buttons on the phone page: an approver
// deciding their own SSH check, or an admin picking a user for their device.
func (s *Server) registerSelfDecide(w http.ResponseWriter, r *http.Request) {
	id, p, back, ok := s.pendingFor(r)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	approve := r.PostFormValue("decision") == "approve"
	asUser := strings.TrimSpace(r.PostFormValue("as_user"))
	allowed := false
	if p.Kind == registration.KindSSH {
		allowed = id.Caps.Has(perm.ApproveSSH)
	} else {
		allowed = perm.CanApproveAs(id.Caps, id.Account.HSUser, p.HSUser, asUser)
	}
	if !allowed {
		s.renderError(w, r, http.StatusForbidden, "Not allowed", "You don't have permission to approve this. An approver has been notified.")
		return
	}
	_, err := s.Reg.Decide(r.Context(), p.ID, approve, id.Account, "web", asUser)
	s.audit(r, p.Kind+".decide", p.AuthID, nil, map[string]any{"approve": approve, "as_user": asUser, "error": friendly(err)})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) registerCancel(w http.ResponseWriter, r *http.Request) {
	id, p, back, ok := s.pendingFor(r)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if p.Open() {
		_, _ = s.Reg.Cancel(r.Context(), p.ID, id.Account)
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) registerStatus(w http.ResponseWriter, r *http.Request) {
	_, p, _, ok := s.pendingFor(r)
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"status":"unknown"}`))
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": p.Status})
}
