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
	State   string // invalid | waiting | choose | ssh-decide | approved | denied | expired | cancelled | failed
	Kind    string
	AuthID  string
	Path    string // /register/<id> or /auth/<id>
	Pending *db.Pending
	Device  string
	IP      string
	Users   []hs.User
	Error   string
}

func kindPath(kind, id string) string {
	if kind == registration.KindSSH {
		return "/auth/" + id
	}
	return "/register/" + id
}

func (s *Server) registerPage(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authID := r.PathValue("id")
		v := &registerView{Kind: kind, AuthID: authID, Path: kindPath(kind, authID), Device: r.UserAgent(), IP: clientIP(r)}
		title := "Add this device"
		if kind == registration.KindSSH {
			title = "Approve SSH access"
		}
		if !hs.ValidAuthID(authID) {
			v.State = "invalid"
			w.WriteHeader(http.StatusNotFound)
			s.render(w, r, "register", s.page(w, r, "", title, v))
			return
		}
		id := who(r)
		if !id.Full() {
			next := url.QueryEscape(v.Path)
			if id != nil && !id.Account.TOTPEnabled {
				http.Redirect(w, r, s.base+"/2fa/enroll?next="+next, http.StatusFound)
				return
			}
			http.Redirect(w, r, s.base+"/login?next="+next, http.StatusFound)
			return
		}
		p, err := s.DB.LatestPending(ctx, authID, id.Account.ID)
		if errors.Is(err, db.ErrNotFound) {
			p, err = s.Reg.Create(ctx, kind, authID, id.Account, clientIP(r), r.UserAgent())
			if err == nil {
				s.audit(r, kind+".request", authID, nil, map[string]string{"device": registration.DescribeUA(r.UserAgent()), "ip": clientIP(r)})
			}
		}
		if err != nil {
			v.State, v.Error = "failed", friendly(err)
			s.render(w, r, "register", s.page(w, r, "", title, v))
			return
		}
		v.Pending = p
		if p.Open() {
			switch {
			case kind == registration.KindSSH && id.Caps.Has(perm.ApproveSSH):
				v.State = "ssh-decide"
			case kind == registration.KindRegister && id.Account.HSUser != "" && perm.CanApprove(id.Caps, id.Account.HSUser, id.Account.HSUser):
				// People who may approve their own devices skip the wait.
				decided, derr := s.Reg.Decide(ctx, p.ID, true, id.Account, "web", "")
				if decided != nil {
					v.Pending = decided
				}
				if derr != nil {
					v.Error = friendly(derr)
				}
				s.audit(r, "register.self_approve", authID, nil, v.Pending.Status)
			case kind == registration.KindRegister && id.Caps.Has(perm.ApproveDevices):
				v.State = "choose"
				v.Users = s.Poller.Users()
			default:
				v.State = "waiting"
			}
		}
		if v.State == "" {
			v.State = v.Pending.Status
			if v.State == db.StatusApproving || v.State == db.StatusPending {
				v.State = "waiting"
			}
			if v.Error == "" {
				v.Error = v.Pending.Error
			}
		}
		s.render(w, r, "register", s.page(w, r, "", title, v))
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
