package web

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

type userRow struct {
	hs.User
	Nodes   int
	Online  int
	Account *db.Account
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ReadUsers) {
		return
	}
	users, err := s.HS.ListUsers(r.Context())
	if err != nil {
		users = s.Poller.Users()
	}
	owners, _ := s.DB.AccountsByHSUser(r.Context())
	counts := map[string][2]int{}
	for _, n := range s.Poller.Snapshot() {
		c := counts[n.UserName()]
		c[0]++
		if n.Online {
			c[1]++
		}
		counts[n.UserName()] = c
	}
	var rows []userRow
	for _, u := range users {
		if u.ID == hs.TaggedDevicesUserID {
			continue
		}
		c := counts[u.Name]
		rows = append(rows, userRow{User: u, Nodes: c[0], Online: c[1], Account: owners[u.Name]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	s.render(w, r, "users", s.page(w, r, "users", "Users", rows))
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.WriteUsers) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	if !usernameRe.MatchString(name) {
		s.failed(w, r, "", errors.New("user names are 2–32 lowercase letters, digits, dot, dash or underscore"))
		return
	}
	u, err := s.HS.CreateUser(r.Context(), name, strings.TrimSpace(r.PostFormValue("display_name")), strings.TrimSpace(r.PostFormValue("email")))
	if err != nil {
		s.failed(w, r, "", err)
		return
	}
	s.audit(r, "user.create", u.Name, nil, u)
	s.ok(w, r, "", "Created headscale user "+u.Name+".")
}

func (s *Server) userAction(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.WriteUsers) {
		return
	}
	ctx := r.Context()
	uid := r.PathValue("id")
	var user *hs.User
	for _, u := range s.Poller.Users() {
		if u.ID == uid {
			user = &u
			break
		}
	}
	if user == nil {
		s.failed(w, r, "", errors.New("that user no longer exists"))
		return
	}
	switch r.PathValue("action") {
	case "rename":
		name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
		if !usernameRe.MatchString(name) {
			s.failed(w, r, "", errors.New("user names are 2–32 lowercase letters, digits, dot, dash or underscore"))
			return
		}
		if _, err := s.HS.RenameUser(ctx, uid, name); err != nil {
			s.failed(w, r, "", err)
			return
		}
		// Keep panel accounts linked to the renamed user.
		if accs, err := s.DB.ListAccounts(ctx); err == nil {
			for _, a := range accs {
				if a.HSUser == user.Name {
					a.HSUser = name
					_ = s.DB.UpdateAccount(ctx, a)
				}
			}
		}
		s.audit(r, "user.rename", user.Name, user.Name, name)
		s.ok(w, r, "", "Renamed "+user.Name+" to "+name+".")
	case "delete":
		for _, n := range s.Poller.Snapshot() {
			if n.UserName() == user.Name {
				s.failed(w, r, "", errors.New(user.Name+" still has machines; delete or move them first"))
				return
			}
		}
		if err := s.HS.DeleteUser(ctx, uid); err != nil {
			s.failed(w, r, "", err)
			return
		}
		s.audit(r, "user.delete", user.Name, user, nil)
		s.ok(w, r, "", "Deleted "+user.Name+".")
	default:
		http.NotFound(w, r)
	}
}

// ---------- people (panel accounts) ----------

type personRow struct {
	*db.Account
	Telegram bool
}

type peopleData struct {
	People    []personRow
	Invites   []*db.Invite
	Roles     []string
	HSUsers   []hs.User
	NewInvite string
}

func (s *Server) peopleData(r *http.Request) peopleData {
	ctx := r.Context()
	accs, _ := s.DB.ListAccounts(ctx)
	links, _ := s.DB.ListLinks(ctx)
	linked := map[int64]bool{}
	for _, l := range links {
		linked[l.AccountID] = true
	}
	d := peopleData{Roles: s.assignableRoles(who(r)), HSUsers: s.Poller.Users()}
	for _, a := range accs {
		d.People = append(d.People, personRow{Account: a, Telegram: linked[a.ID]})
	}
	d.Invites, _ = s.DB.ListInvites(ctx)
	return d
}

// assignableRoles: only owners hand out the owner role.
func (s *Server) assignableRoles(id *identity) []string {
	var out []string
	for _, r := range perm.RoleOrder {
		if !perm.Within(perm.Roles[r], id.Caps) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *Server) people(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ConfigureIAM) {
		return
	}
	s.render(w, r, "people", s.page(w, r, "people", "People", s.peopleData(r)))
}

func (s *Server) inviteURL(tok string) string {
	base := s.Cfg.Server.PublicURL
	return base + s.base + "/invite/" + tok
}

func (s *Server) inviteCreate(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ConfigureIAM) {
		return
	}
	ctx := r.Context()
	id := who(r)
	username := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	role := r.PostFormValue("role")
	hsUser := strings.TrimSpace(r.PostFormValue("hs_user"))
	if !usernameRe.MatchString(username) {
		s.failed(w, r, "", errors.New("usernames are 2–32 lowercase letters, digits, dot, dash or underscore"))
		return
	}
	if !perm.ValidRole(role) || !perm.Within(perm.Roles[role], id.Caps) {
		s.failed(w, r, "", errors.New("you can't give a role with more permissions than your own"))
		return
	}
	if _, err := s.DB.GetAccountByUsername(ctx, username); err == nil {
		s.failed(w, r, "", errors.New("someone already has the username "+username))
		return
	}
	if hsUser == "_new" {
		hsUser = ""
	}
	if err := s.hsUserTaken(ctx, id, hsUser, 0); err != nil {
		s.failed(w, r, "", err)
		return
	}
	tok := auth.RandomToken(24)
	err := s.DB.CreateInvite(ctx, db.Invite{
		TokenHash: auth.HashToken(tok), Username: username, Role: role, HSUser: hsUser,
		CreatedBy: id.Account.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(72 * time.Hour),
	})
	if err != nil {
		s.failed(w, r, "", err)
		return
	}
	s.audit(r, "invite.create", username, nil, map[string]string{"role": role, "hs_user": hsUser})
	d := s.peopleData(r)
	d.NewInvite = s.inviteURL(tok)
	s.render(w, r, "people", s.page(w, r, "people", "People", d))
}

func (s *Server) inviteRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ConfigureIAM) {
		return
	}
	h := r.PathValue("hash")
	_ = s.DB.DeleteInvite(r.Context(), h)
	s.audit(r, "invite.revoke", h[:min(8, len(h))], nil, nil)
	s.ok(w, r, s.base+"/people", "Invite revoked.")
}

type personData struct {
	Person   *db.Account
	Caps     perm.Cap
	Extra    perm.Cap
	AllCaps  []perm.Named
	Roles    []string
	HSUsers  []hs.User
	Sessions []*db.Session
	Telegram *db.TelegramLink
	IsMe     bool
	Codes    int
}

func (s *Server) loadPerson(w http.ResponseWriter, r *http.Request) (*db.Account, bool) {
	if !s.need(w, r, perm.ConfigureIAM) {
		return nil, false
	}
	pid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	acc, err := s.DB.GetAccount(r.Context(), pid)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "Person not found", "")
		return nil, false
	}
	// Nobody manages an account more powerful than their own.
	id := who(r)
	if acc.ID != id.Account.ID && !perm.Within(perm.Effective(acc.Role, perm.Cap(acc.ExtraCaps)), id.Caps) {
		s.renderError(w, r, http.StatusForbidden, "Not allowed", "This person has permissions you don't, so only someone with at least their access can change their account.")
		return nil, false
	}
	return acc, true
}

func (s *Server) person(w http.ResponseWriter, r *http.Request) {
	acc, ok := s.loadPerson(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	d := personData{
		Person: acc, Extra: perm.Cap(acc.ExtraCaps), Caps: perm.Effective(acc.Role, perm.Cap(acc.ExtraCaps)),
		AllCaps: perm.All, Roles: s.assignableRoles(who(r)), HSUsers: s.Poller.Users(), IsMe: acc.ID == who(r).Account.ID,
		Codes: s.DB.RemainingBackupCodes(ctx, acc.ID),
	}
	d.Sessions, _ = s.DB.ListSessions(ctx, acc.ID)
	d.Telegram, _ = s.DB.LinkForAccount(ctx, acc.ID)
	s.render(w, r, "person", s.page(w, r, "people", acc.Name(), d))
}

func (s *Server) personAction(w http.ResponseWriter, r *http.Request) {
	acc, ok := s.loadPerson(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id := who(r)
	here := s.base + "/people/" + strconv.FormatInt(acc.ID, 10)
	switch r.PathValue("action") {
	case "role":
		role := r.PostFormValue("role")
		if !perm.ValidRole(role) || !perm.Within(perm.Roles[role], id.Caps) {
			s.failed(w, r, here, errors.New("you can't give a role with more permissions than your own"))
			return
		}
		if err := s.DB.SetRole(ctx, acc.ID, role); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "person.role", acc.Username, acc.Role, role)
		s.ok(w, r, here, "Role changed to "+role+".")
	case "caps":
		r.ParseForm()
		extra := perm.Parse(r.PostForm["cap"])
		if extra.Has(perm.Owner) && !id.Caps.Has(perm.Owner) {
			extra &^= perm.Owner
		}
		// Nobody grants a permission they don't hold themselves.
		extra &= id.Caps
		before := perm.Cap(acc.ExtraCaps).Names()
		acc.ExtraCaps = uint64(extra)
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "person.extra_caps", acc.Username, before, extra.Names())
		s.ok(w, r, here, "Extra permissions saved.")
	case "hsuser":
		hsUser := strings.TrimSpace(r.PostFormValue("hs_user"))
		if hsUser == "_new" {
			hsUser = acc.Username
			if err := s.ensureHSUser(ctx, hsUser, acc.DisplayName); err != nil {
				s.failed(w, r, here, err)
				return
			}
		} else if hsUser != "" && !hsUserExists(s.Poller.Users(), hsUser) {
			s.failed(w, r, here, errors.New("no headscale user named "+hsUser))
			return
		}
		if err := s.hsUserTaken(ctx, id, hsUser, acc.ID); err != nil {
			s.failed(w, r, here, err)
			return
		}
		before := acc.HSUser
		acc.HSUser = hsUser
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "person.hs_user", acc.Username, before, hsUser)
		s.ok(w, r, here, "Linked headscale user updated.")
	case "disable", "enable":
		disable := r.PathValue("action") == "disable"
		if disable && acc.ID == id.Account.ID {
			s.failed(w, r, here, errors.New("you can't disable yourself"))
			return
		}
		if err := s.DB.SetDisabled(ctx, acc.ID, disable); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "person."+r.PathValue("action"), acc.Username, nil, nil)
		s.ok(w, r, here, acc.Username+" "+r.PathValue("action")+"d.")
	case "reset2fa":
		acc.TOTPEnabled, acc.TOTPSecret = false, ""
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		_ = s.DB.ReplaceBackupCodes(ctx, acc.ID, nil)
		_ = s.DB.DeleteSessionsFor(ctx, acc.ID, "")
		s.audit(r, "person.reset_2fa", acc.Username, nil, nil)
		s.securityAlert(id.Account.Username + " reset two-factor for " + acc.Username)
		s.ok(w, r, here, "Two-factor reset. "+acc.Username+" sets it up again at next sign-in.")
	case "sessions":
		except := ""
		if acc.ID == id.Account.ID {
			except = id.Session.ID
		}
		_ = s.DB.DeleteSessionsFor(ctx, acc.ID, except)
		s.audit(r, "person.revoke_sessions", acc.Username, nil, nil)
		s.ok(w, r, here, "Signed out everywhere.")
	case "password":
		pw := r.PostFormValue("password")
		hash, err := auth.HashPassword(pw)
		if err != nil {
			s.failed(w, r, here, err)
			return
		}
		acc.PasswordHash = hash
		if err := s.DB.UpdateAccount(ctx, acc); err != nil {
			s.failed(w, r, here, err)
			return
		}
		_ = s.DB.DeleteSessionsFor(ctx, acc.ID, "")
		s.audit(r, "person.set_password", acc.Username, nil, nil)
		s.ok(w, r, here, "Password set. Share it with "+acc.Username+" privately.")
	case "delete":
		if acc.ID == id.Account.ID {
			s.failed(w, r, here, errors.New("you can't delete yourself"))
			return
		}
		if err := s.DB.DeleteAccount(ctx, acc.ID); err != nil {
			s.failed(w, r, here, err)
			return
		}
		s.audit(r, "person.delete", acc.Username, acc.Username, nil)
		s.ok(w, r, s.base+"/people", acc.Username+" deleted.")
	default:
		http.NotFound(w, r)
	}
}

// hsUserTaken refuses linking to a headscale user another account already
// acts as: that would let the linker act as that person on the tailnet.
// Only an Owner may share one.
func (s *Server) hsUserTaken(ctx context.Context, id *identity, hsUser string, accID int64) error {
	if hsUser == "" || id.Caps.Has(perm.Owner) {
		return nil
	}
	accs, err := s.DB.ListAccounts(ctx)
	if err != nil {
		return err
	}
	for _, a := range accs {
		if a.ID != accID && a.HSUser == hsUser {
			return errors.New("headscale user " + hsUser + " is already linked to " + a.Name() + "; only an owner can share it")
		}
	}
	return nil
}
