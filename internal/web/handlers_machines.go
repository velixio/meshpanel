package web

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/tailnet"
)

type machineRow struct {
	hs.Node
	Search  string
	State   string
	Owner   string // panel account display name, if linked
	OS      string // from the tailnet agent, when enabled
	Session bool   // a meshpanel browser-SSH node
}

type machinesData struct {
	Rows   []machineRow
	Counts map[string]int
	Users  []hs.User
}

func nodeState(n hs.Node, now time.Time) string {
	var st []string
	if n.Online {
		st = append(st, "online")
	} else {
		st = append(st, "offline")
	}
	if n.IsExitNodeAdvertised() || n.IsExitNodeApproved() {
		st = append(st, "exit")
	}
	if len(n.PendingRoutes()) > 0 {
		st = append(st, "routes")
	}
	if n.Expiry != nil && !n.Expiry.IsZero() {
		if n.Expiry.Before(now) {
			st = append(st, "expired")
		} else if n.Expiry.Sub(now) < 7*24*time.Hour {
			st = append(st, "expiring")
		}
	}
	if n.IsTagged() {
		st = append(st, "tagged")
	}
	return strings.Join(st, " ")
}

func (s *Server) machines(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	nodes := id.Scope.Nodes(s.Poller.Snapshot())
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Online != nodes[j].Online {
			return nodes[i].Online
		}
		return strings.ToLower(nodes[i].DisplayName()) < strings.ToLower(nodes[j].DisplayName())
	})
	owners, _ := s.DB.AccountsByHSUser(r.Context())
	now := time.Now()
	d := machinesData{Counts: map[string]int{"all": len(nodes)}, Users: s.Poller.Users()}
	for _, n := range nodes {
		st := nodeState(n, now)
		for _, k := range strings.Fields(st) {
			d.Counts[k]++
		}
		row := machineRow{Node: n, State: st}
		row.Session = s.SessionNodes != nil && s.SessionNodes.Owns(n)
		if a, ok := owners[n.UserName()]; ok && a.Name() != n.UserName() {
			row.Owner = a.Name()
		}
		if s.Agent != nil {
			if hi, ok := s.Agent.Info(n.NodeKey); ok {
				row.OS = strings.TrimSpace(hi.OS + " " + hi.OSVersion)
			}
		}
		row.Search = strings.ToLower(strings.Join(append([]string{n.DisplayName(), n.Name, n.UserName(), row.Owner, strings.Join(n.Tags, " ")}, n.IPAddresses...), " "))
		d.Rows = append(d.Rows, row)
	}
	s.render(w, r, "machines", s.page(w, r, "machines", "Machines", d))
}

type machineData struct {
	Node       hs.Node
	Owner      *db.Account
	CanManage  bool
	CanTags    bool
	CanRoutes  bool
	Watching   bool
	State      string
	LoginCmd   string
	Users      []hs.User
	PendingSet map[string]bool
	Host       *tailnet.HostInfo
	CanSSH     bool
}

func (s *Server) findNode(r *http.Request) (hs.Node, bool) {
	n, ok := s.Poller.Node(r.PathValue("id"))
	if !ok || !who(r).Scope.Node(n) {
		return hs.Node{}, false
	}
	return n, true
}

func (s *Server) machine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	n, ok := s.findNode(r)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Machine not found", "It may have been deleted, or it belongs to someone else.")
		return
	}
	d := machineData{
		Node: n, CanManage: perm.CanManageNode(id.Caps, id.Account.HSUser, n),
		CanTags:   id.Caps.Has(perm.UseTags) && id.Caps.Has(perm.WriteMachines),
		CanRoutes: id.Caps.Has(perm.WriteNetwork) || id.Caps.Has(perm.WriteMachines),
		State:     nodeState(n, time.Now()), Users: s.Poller.Users(), PendingSet: map[string]bool{},
	}
	for _, rt := range n.PendingRoutes() {
		d.PendingSet[rt] = true
	}
	if s.Agent != nil {
		if hi, ok := s.Agent.Info(n.NodeKey); ok {
			d.Host = &hi
		}
	}
	d.CanSSH = s.SSH != nil && id.Caps.Has(perm.WebSSH) && id.Account.HSUser != "" && len(n.IPAddresses) > 0
	if owners, err := s.DB.AccountsByHSUser(ctx); err == nil {
		d.Owner = owners[n.UserName()]
	}
	if rules, err := s.DB.ListWatches(ctx, id.Account.ID); err == nil {
		for _, rule := range rules {
			if rule.SubjectType == "node" && rule.Subject == n.ID {
				d.Watching = true
			}
		}
	}
	if s.Cfg.Server.PublicURL != "" {
		d.LoginCmd = "tailscale up --login-server=" + s.Cfg.Server.PublicURL + " --force-reauth"
	}
	s.render(w, r, "machine", s.page(w, r, "machines", n.DisplayName(), d))
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var tagRe = regexp.MustCompile(`^tag:[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func parseTags(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, t := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if !strings.HasPrefix(t, "tag:") {
			t = "tag:" + t
		}
		if !tagRe.MatchString(t) {
			return nil, fmt.Errorf("%q is not a valid tag (use tag:name with letters, digits, - or _)", t)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *Server) machineAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	n, ok := s.findNode(r)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Machine not found", "It may have been deleted, or it belongs to someone else.")
		return
	}
	here := s.base + "/machines/" + n.ID
	manage := perm.CanManageNode(id.Caps, id.Account.HSUser, n)
	action := r.PathValue("action")
	deny := func() { s.renderError(w, r, http.StatusForbidden, "Not allowed", "You can't change this machine.") }
	switch action {
	case "rename":
		if !manage {
			deny()
			return
		}
		name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
		if !hostnameRe.MatchString(name) {
			s.failed(w, r, here, errors.New("names are 1–63 lowercase letters, digits or dashes, not starting or ending with a dash"))
			return
		}
		if _, err := s.HS.RenameNode(ctx, n.ID, name); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "machine.rename", n.DisplayName(), n.DisplayName(), name)
		s.ok(w, r, here, "Renamed to "+name+".")
	case "tags":
		if !(id.Caps.Has(perm.UseTags) && id.Caps.Has(perm.WriteMachines)) {
			deny()
			return
		}
		tags, err := parseTags(r.PostFormValue("tags"))
		if err != nil {
			s.failed(w, r, here, err)
			return
		}
		if len(tags) == 0 {
			s.failed(w, r, here, errors.New("a tagged machine must keep at least one tag; to give it back to a user, re-register it"))
			return
		}
		if _, err := s.HS.SetTags(ctx, n.ID, tags); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "machine.tags", n.DisplayName(), n.Tags, tags)
		s.ok(w, r, here, "Tags updated.")
	case "routes":
		if !(id.Caps.Has(perm.WriteNetwork) || id.Caps.Has(perm.WriteMachines)) {
			deny()
			return
		}
		r.ParseForm()
		routes := r.PostForm["route"]
		allowed := map[string]bool{}
		for _, rt := range n.AvailableRoutes {
			allowed[rt] = true
		}
		var keep []string
		for _, rt := range routes {
			if allowed[rt] {
				keep = append(keep, rt)
			}
		}
		if _, err := s.HS.ApproveRoutes(ctx, n.ID, keep); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "machine.routes", n.DisplayName(), n.ApprovedRoutes, keep)
		s.ok(w, r, here, "Routes updated.")
	case "expiry":
		if !manage {
			deny()
			return
		}
		disable := r.PostFormValue("expiry") == "off"
		if _, err := s.HS.SetKeyExpiryDisabled(ctx, n.ID, disable); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "machine.key_expiry", n.DisplayName(), nil, map[string]bool{"disabled": disable})
		if disable {
			s.ok(w, r, here, "Key expiry turned off. This machine stays signed in.")
		} else {
			s.ok(w, r, here, "Key expiry turned on (180 days).")
		}
	case "expire":
		if !manage {
			deny()
			return
		}
		if _, err := s.HS.ExpireNode(ctx, n.ID); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "machine.expire", n.DisplayName(), nil, nil)
		s.ok(w, r, here, "Key expired. The device must sign in again.")
	case "delete":
		if !manage {
			deny()
			return
		}
		if err := s.HS.DeleteNode(ctx, n.ID); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "machine.delete", n.DisplayName(), n, nil)
		s.ok(w, r, s.base+"/machines", n.DisplayName()+" deleted.")
	case "watch":
		if r.PostFormValue("off") == "1" {
			rules, _ := s.DB.ListWatches(ctx, id.Account.ID)
			for _, rule := range rules {
				if rule.SubjectType == "node" && rule.Subject == n.ID {
					_ = s.DB.DeleteWatch(ctx, rule.ID, id.Account.ID)
				}
			}
			s.ok(w, r, here, "Stopped watching "+n.DisplayName()+".")
			return
		}
		_, err := s.DB.CreateWatch(ctx, db.WatchRule{
			AccountID: id.Account.ID, SubjectType: "node", Subject: n.ID, OfflineDebounce: 2 * time.Minute,
			Events: []string{string(events.NodeOnline), string(events.NodeOffline), string(events.KeyExpiring), string(events.KeyExpired), string(events.RouteAdvertised)},
		})
		if err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.ok(w, r, here, "Watching "+n.DisplayName()+". Alerts go to your Telegram.")
	default:
		http.NotFound(w, r)
	}
}

var authIDInText = regexp.MustCompile(`hskey-authreq-[0-9a-f]{24}`)

// machineRegisterByID completes a registration from a pasted link or ID.
func (s *Server) machineRegisterByID(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if !id.Caps.Has(perm.ApproveDevices) {
		s.renderError(w, r, http.StatusForbidden, "Not allowed", "Adding devices for others needs the approve_devices permission.")
		return
	}
	authID := authIDInText.FindString(r.PostFormValue("auth_id"))
	user := strings.TrimSpace(r.PostFormValue("user"))
	if authID == "" {
		s.failed(w, r, "", errors.New("paste the link the device shows (it contains hskey-authreq- followed by 24 characters)"))
		return
	}
	if user == "" {
		s.failed(w, r, "", errors.New("choose the user this device belongs to"))
		return
	}
	n, err := s.HS.AuthRegister(r.Context(), user, authID)
	s.audit(r, "machine.register_by_id", authID, nil, map[string]string{"user": user, "node": n.DisplayName(), "error": friendly(err)})
	if err != nil {
		if hs.IsNotFound(err) {
			err = errors.New("headscale doesn't know this request; it may have expired (they last about 15 minutes)")
		}
		s.failed(w, r, "", err)
		return
	}
	s.ok(w, r, s.base+"/machines/"+n.ID, n.DisplayName()+" added for "+user+".")
}
