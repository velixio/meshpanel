package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/registration"
)

type pendingView struct {
	Pending       *db.Pending
	RequesterName string
	Users         []hs.User
	Count, Limit  int // the requester's devices, and the per-user limit (0 = none)
}

// openPendingFor lists open requests the caller may decide.
func (s *Server) openPendingFor(ctx context.Context, id *identity) []pendingView {
	ps, err := s.DB.ListPending(ctx, true, 100)
	if err != nil {
		return nil
	}
	users := s.Poller.Users()
	var out []pendingView
	for _, p := range ps {
		if p.RequesterID == id.Account.ID || !canDecide(id, p) {
			continue
		}
		name := "unknown"
		if a, err := s.DB.GetAccount(ctx, p.RequesterID); err == nil {
			name = a.Name()
		}
		_, count, limit := s.atLimit(ctx, p.HSUser)
		out = append(out, pendingView{Pending: p, RequesterName: name, Users: users, Count: count, Limit: limit})
	}
	return out
}

type overviewData struct {
	Online, Offline, Total int
	Expiring               []hs.Node
	RoutesPending          []hs.Node
	Pending                []pendingView
	Feed                   []*db.Notification
	Recent                 []*db.AuditEntry
	Mine                   []hs.Node
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	nodes := id.Scope.Nodes(s.Poller.Snapshot())
	d := overviewData{Total: len(nodes)}
	now := time.Now()
	for _, n := range nodes {
		if n.Online {
			d.Online++
		} else {
			d.Offline++
		}
		if n.Expiry != nil && !n.Expiry.IsZero() && n.Expiry.Sub(now) < 7*24*time.Hour {
			d.Expiring = append(d.Expiring, n)
		}
		if len(n.PendingRoutes()) > 0 {
			d.RoutesPending = append(d.RoutesPending, n)
		}
		if n.UserName() != "" && n.UserName() == id.Account.HSUser {
			d.Mine = append(d.Mine, n)
		}
	}
	sort.Slice(d.Expiring, func(i, j int) bool { return d.Expiring[i].Expiry.Before(*d.Expiring[j].Expiry) })
	d.Pending = s.openPendingFor(ctx, id)
	d.Feed, _ = s.DB.ListNotifications(ctx, id.Account.ID, 12)
	if id.Caps.Has(perm.ReadAudit) {
		d.Recent, _ = s.DB.ListAudit(ctx, db.AuditFilter{Limit: 8})
	}
	s.render(w, r, "overview", s.page(w, r, "overview", "Overview", d))
}

type approvalsData struct {
	Open   []pendingView
	Recent []*db.Pending
	Names  map[int64]string
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	d := approvalsData{Open: s.openPendingFor(ctx, id), Names: map[int64]string{}}
	all, _ := s.DB.ListPending(ctx, false, 60)
	for _, p := range all {
		if p.Open() || (!canDecide(id, p) && p.RequesterID != id.Account.ID) {
			continue
		}
		d.Recent = append(d.Recent, p)
		if _, ok := d.Names[p.RequesterID]; !ok {
			if a, err := s.DB.GetAccount(ctx, p.RequesterID); err == nil {
				d.Names[p.RequesterID] = a.Name()
			}
		}
	}
	s.render(w, r, "approvals", s.page(w, r, "overview", "Approvals", d))
}

func (s *Server) approvalDecide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	pid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := s.DB.GetPending(ctx, pid)
	if err != nil {
		s.failed(w, r, "", errors.New("that request no longer exists"))
		return
	}
	approve := r.PostFormValue("decision") == "approve"
	asUser := strings.TrimSpace(r.PostFormValue("as_user"))
	allowed := canDecide(id, p)
	if p.Kind == registration.KindRegister && asUser != "" {
		allowed = perm.CanApproveAs(id.Caps, id.Account.HSUser, p.HSUser, asUser)
	}
	if !allowed {
		s.renderError(w, r, http.StatusForbidden, "Not allowed", "You can't decide this request.")
		return
	}
	got, err := s.Reg.Decide(ctx, p.ID, approve, id.Account, "web", asUser)
	s.audit(r, p.Kind+".decide", p.AuthID, nil, map[string]any{"approve": approve, "as_user": asUser, "requester": p.RequesterID, "error": friendly(err)})
	var already *registration.AlreadyDecidedError
	switch {
	case errors.As(err, &already):
		s.done(w, r, "", "danger", "Already "+already.Status+" by "+already.By+".")
	case err != nil:
		s.failed(w, r, "", err)
	case approve && got.NodeName != "":
		s.ok(w, r, "", "Approved: "+got.NodeName+" joined the network.")
	case approve:
		s.ok(w, r, "", "Approved.")
	default:
		s.ok(w, r, "", "Denied.")
	}
}

// ---------- search (command palette) ----------

type searchResult struct {
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	URL   string `json:"url"`
	Icon  string `json:"icon,omitempty"`
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var out []searchResult
	match := func(parts ...string) bool {
		if q == "" {
			return true
		}
		for _, p := range parts {
			if strings.Contains(strings.ToLower(p), q) {
				return true
			}
		}
		return false
	}
	pages := []struct {
		label, path, icon string
		cap               perm.Cap
	}{
		{"Overview", "/", "home", perm.UIAccess},
		{"Machines", "/machines", "monitor", perm.UIAccess},
		{"Users", "/users", "users", perm.ReadUsers},
		{"Pre-auth keys", "/keys", "key", perm.GenerateOwnAuthkeys},
		{"Access policy", "/access", "shield", perm.ReadPolicy},
		{"DNS", "/dns", "globe", perm.ReadNetwork},
		{"People", "/people", "badge", perm.ConfigureIAM},
		{"Alerts & Telegram", "/alerts", "bell", perm.UIAccess},
		{"Audit log", "/audit", "scroll", perm.ReadAudit},
		{"Settings", "/settings", "sliders", perm.ConfigureIAM},
		{"My account", "/account", "user", perm.UIAccess},
		{"Approvals", "/approvals", "check", perm.UIAccess},
	}
	for _, p := range pages {
		if (id.Caps.Has(p.cap) || (p.cap == perm.GenerateOwnAuthkeys && id.Caps.Has(perm.GenerateAuthkeys))) && match(p.label) {
			out = append(out, searchResult{Label: p.label, Sub: "Page", URL: s.base + p.path, Icon: p.icon})
		}
	}
	nodes := id.Scope.Nodes(s.Poller.Snapshot())
	for _, n := range nodes {
		ip := ""
		if len(n.IPAddresses) > 0 {
			ip = n.IPAddresses[0]
		}
		if match(n.DisplayName(), n.Name, n.UserName(), ip, strings.Join(n.Tags, " ")) {
			sub := n.UserName()
			if n.IsTagged() {
				sub = strings.Join(n.Tags, ", ")
			}
			out = append(out, searchResult{Label: n.DisplayName(), Sub: sub + " · " + ip, URL: s.base + "/machines/" + n.ID, Icon: "monitor"})
		}
	}
	if id.Caps.Has(perm.ReadUsers) {
		for _, u := range s.Poller.Users() {
			if match(u.Name, u.DisplayName, u.Email) {
				out = append(out, searchResult{Label: u.Name, Sub: "headscale user", URL: s.base + "/users#u-" + u.ID, Icon: "user"})
			}
		}
	}
	if len(out) > 40 {
		out = out[:40]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// ---------- live updates ----------

// visibleTo decides whether an event kind is pushed to a viewer. Only the
// kind travels, never details, but members still only get their own.
func visibleTo(id *identity, ev events.Event) bool {
	switch ev.Kind {
	case events.Changed, events.HeadscaleDown, events.HeadscaleUp:
		return true
	case events.Security:
		return id.Caps.Has(perm.ConfigureIAM)
	case events.RegistrationPending, events.RegistrationDecided:
		return id.Caps.Has(perm.ApproveDevices) || id.Caps.Has(perm.ApproveSSH) || ev.HSUser == id.Account.HSUser
	}
	return id.Scope.All || (ev.HSUser != "" && ev.HSUser == id.Scope.HSUser)
}

func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.originPatterns(r)})
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := c.CloseRead(r.Context())
	ch, cancel := s.Bus.Subscribe(64)
	defer cancel()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	send := func(v any) error {
		b, _ := json.Marshal(v)
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return c.Write(wctx, websocket.MessageText, b)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		case ev := <-ch:
			if !visibleTo(id, ev) {
				continue
			}
			var err error
			switch ev.Kind {
			case events.HeadscaleDown, events.HeadscaleUp:
				err = send(map[string]any{"kind": "health", "ok": ev.Kind == events.HeadscaleUp})
			default:
				err = send(map[string]any{"kind": string(ev.Kind)})
			}
			if err != nil {
				return
			}
		}
	}
}

// originPatterns allows the request's own host and the public URL's host.
func (s *Server) originPatterns(r *http.Request) []string {
	out := []string{r.Host}
	if s.Cfg.Server.PublicURL != "" {
		if i := strings.Index(s.Cfg.Server.PublicURL, "://"); i >= 0 {
			out = append(out, strings.SplitN(s.Cfg.Server.PublicURL[i+3:], "/", 2)[0])
		}
	}
	return out
}
