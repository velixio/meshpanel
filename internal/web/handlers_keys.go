package web

import (
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

type keysData struct {
	Keys     []hs.PreAuthKey
	Users    []hs.User
	OwnOnly  bool
	CanTags  bool
	NewKey   *hs.PreAuthKey
	Command  string
	QR       template.URL
	LoginURL string
}

func (s *Server) canKeys(id *identity) bool {
	return id.Caps.Has(perm.GenerateAuthkeys) || id.Caps.Has(perm.GenerateOwnAuthkeys)
}

func (s *Server) keysData(r *http.Request) (keysData, error) {
	id := who(r)
	d := keysData{OwnOnly: !id.Caps.Has(perm.GenerateAuthkeys), CanTags: id.Caps.Has(perm.UseTags), LoginURL: s.Cfg.Server.PublicURL}
	keys, err := s.HS.ListPreAuthKeys(r.Context())
	if err != nil {
		return d, err
	}
	for _, k := range keys {
		if d.OwnOnly && (k.User == nil || k.User.Name != id.Account.HSUser) {
			continue
		}
		d.Keys = append(d.Keys, k)
	}
	sort.Slice(d.Keys, func(i, j int) bool { return d.Keys[i].CreatedAt.After(d.Keys[j].CreatedAt) })
	for _, u := range s.Poller.Users() {
		if u.ID == hs.TaggedDevicesUserID || (d.OwnOnly && u.Name != id.Account.HSUser) {
			continue
		}
		d.Users = append(d.Users, u)
	}
	return d, nil
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if !s.canKeys(id) {
		s.need(w, r, perm.GenerateAuthkeys)
		return
	}
	d, err := s.keysData(r)
	p := s.page(w, r, "keys", "Pre-auth keys", d)
	if err != nil {
		p.Flash = &flash{Kind: "danger", Msg: friendly(err)}
	}
	s.render(w, r, "keys", p)
}

func (s *Server) keyCreate(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if !s.canKeys(id) {
		s.need(w, r, perm.GenerateAuthkeys)
		return
	}
	ctx := r.Context()
	d, err := s.keysData(r)
	if err != nil {
		s.failed(w, r, "", err)
		return
	}
	req := hs.CreateKeyReq{Reusable: r.PostFormValue("reusable") == "on", Ephemeral: r.PostFormValue("ephemeral") == "on"}
	hours, _ := strconv.Atoi(r.PostFormValue("expiry_hours"))
	if hours <= 0 || hours > 24*365 {
		hours = 24
	}
	exp := time.Now().Add(time.Duration(hours) * time.Hour).UTC()
	req.Expiration = &exp
	if raw := strings.TrimSpace(r.PostFormValue("tags")); raw != "" {
		if !id.Caps.Has(perm.UseTags) {
			s.failed(w, r, "", errors.New("you can't create tagged keys"))
			return
		}
		tags, err := parseTags(raw)
		if err != nil {
			s.failed(w, r, "", err)
			return
		}
		req.ACLTags = tags
	}
	userName := r.PostFormValue("user")
	if d.OwnOnly {
		userName = id.Account.HSUser
	}
	if len(req.ACLTags) == 0 || userName != "" {
		for _, u := range d.Users {
			if u.Name == userName {
				req.User = u.ID
			}
		}
		if req.User == "" && len(req.ACLTags) == 0 {
			s.failed(w, r, "", errors.New("choose a user (or tags) for this key"))
			return
		}
	}
	if err := s.checkKeyLimit(ctx, id, userName, req); err != nil {
		s.failed(w, r, "", err)
		return
	}
	key, err := s.HS.CreatePreAuthKey(ctx, req)
	if err != nil {
		s.failed(w, r, "", err)
		return
	}
	s.audit(r, "key.create", userName+strings.Join(req.ACLTags, ","), nil, map[string]any{"reusable": req.Reusable, "ephemeral": req.Ephemeral, "expires": exp, "tags": req.ACLTags, "id": key.ID})
	d, _ = s.keysData(r)
	d.NewKey = &key
	server := s.Cfg.Server.PublicURL
	if server == "" {
		server = "https://your-headscale-url"
	}
	d.Command = "tailscale up --login-server=" + server + " --authkey=" + key.Key
	d.QR = qrDataURI(d.Command)
	s.render(w, r, "keys", s.page(w, r, "keys", "Pre-auth keys", d))
}

func (s *Server) keyAction(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if !s.canKeys(id) {
		s.need(w, r, perm.GenerateAuthkeys)
		return
	}
	d, err := s.keysData(r)
	if err != nil {
		s.failed(w, r, "", err)
		return
	}
	kid := r.PathValue("id")
	found := false
	for _, k := range d.Keys {
		if k.ID == kid {
			found = true
		}
	}
	if !found {
		s.failed(w, r, "", errors.New("key not found"))
		return
	}
	switch r.PathValue("action") {
	case "expire":
		err = s.HS.ExpirePreAuthKey(r.Context(), kid)
	case "delete":
		err = s.HS.DeletePreAuthKey(r.Context(), kid)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.failed(w, r, s.base+"/keys", err)
		return
	}
	s.audit(r, "key."+r.PathValue("action"), kid, nil, nil)
	s.ok(w, r, s.base+"/keys", "Key "+r.PathValue("action")+"d.")
}
