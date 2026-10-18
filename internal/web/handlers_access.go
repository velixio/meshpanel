package web

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/meshpanel/meshpanel/internal/perm"
)

type accessData struct {
	Tab       string
	Mode      string // database | file | unknown
	Writable  bool
	WhyNot    string
	Policy    string
	View      policyView
	ParseErr  string
	Review    bool
	Proposed  string
	Diff      []diffLine
	CheckErr  string
	NoChanges bool
}

// policyMode reads policy.mode/path from headscale's config when available.
func (s *Server) policyMode(updatedAtZero bool) (mode, path string) {
	path = s.Cfg.Headscale.PolicyPath
	if s.HSConfig != nil {
		var c struct {
			Policy struct {
				Mode string `yaml:"mode"`
				Path string `yaml:"path"`
			} `yaml:"policy"`
		}
		if err := s.HSConfig.Decode(&c); err == nil {
			mode = c.Policy.Mode
			if path == "" && c.Policy.Path != "" {
				path = c.Policy.Path
				if !filepath.IsAbs(path) {
					path = filepath.Join(filepath.Dir(s.HSConfig.Path), path)
				}
			}
		}
	}
	if mode == "" {
		mode = "file"
		if !updatedAtZero {
			mode = "database"
		}
	}
	return mode, path
}

func (s *Server) accessBase(r *http.Request) (*accessData, error) {
	id := who(r)
	pol, err := s.HS.GetPolicy(r.Context())
	d := &accessData{Tab: r.URL.Query().Get("tab"), Policy: pol.Policy}
	if d.Tab == "" {
		d.Tab = "visual"
	}
	if err != nil {
		return d, err
	}
	var path string
	d.Mode, path = s.policyMode(pol.UpdatedAt.IsZero())
	switch {
	case !id.Caps.Has(perm.WritePolicy):
		d.WhyNot = "Your role can view the policy but not change it."
	case d.Mode == "database":
		d.Writable = true
	case path == "":
		d.WhyNot = "headscale reads the policy from a file. Set headscale.policy_path (or headscale.config_path) so meshpanel can edit it."
	case s.Applier == nil:
		d.WhyNot = "Applying a policy file needs headscale.reload_command in meshpanel's config."
	default:
		d.Writable = true
	}
	if doc, perr := parsePolicy(pol.Policy); perr != nil {
		d.ParseErr = perr.Error()
	} else {
		d.View = doc.view()
	}
	return d, nil
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ReadPolicy) {
		return
	}
	d, err := s.accessBase(r)
	p := s.page(w, r, "access", "Access policy", d)
	if err != nil {
		p.Flash = &flash{Kind: "danger", Msg: "Could not read the policy: " + friendly(err)}
	}
	s.render(w, r, "access", p)
}

func (s *Server) accessPost(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.WritePolicy) {
		return
	}
	ctx := r.Context()
	d, err := s.accessBase(r)
	if err != nil {
		s.failed(w, r, s.base+"/access", err)
		return
	}
	if !d.Writable {
		s.failed(w, r, s.base+"/access", errors.New(d.WhyNot))
		return
	}
	op := r.PostFormValue("op")
	proposed := r.PostFormValue("policy")
	switch {
	case op == "review" || op == "apply":
	case strings.HasPrefix(op, "v:"):
		doc, err := parsePolicy(d.Policy)
		if err != nil {
			s.failed(w, r, s.base+"/access", err)
			return
		}
		if err := doc.applyOp(strings.TrimPrefix(op, "v:"), r.PostFormValue); err != nil {
			s.failed(w, r, s.base+"/access", err)
			return
		}
		proposed = doc.String()
	default:
		http.NotFound(w, r)
		return
	}
	d.Review, d.Proposed, d.Tab = true, proposed, "editor"
	d.Diff = lineDiff(d.Policy, proposed)
	d.NoChanges = strings.TrimSpace(d.Policy) == strings.TrimSpace(proposed)
	if err := s.HS.CheckPolicy(ctx, proposed); err != nil {
		d.CheckErr = friendly(err)
	}
	if op != "apply" || d.CheckErr != "" || d.NoChanges {
		s.render(w, r, "access", s.page(w, r, "access", "Review policy", d))
		return
	}
	if d.Mode == "database" {
		_, err = s.HS.SetPolicy(ctx, proposed)
	} else {
		_, path := s.policyMode(false)
		err = s.Applier.ApplyPolicyFile(ctx, path, proposed)
	}
	if err != nil {
		d.CheckErr = friendly(err)
		s.render(w, r, "access", s.page(w, r, "access", "Review policy", d))
		return
	}
	s.audit(r, "policy.apply", d.Mode, d.Policy, proposed)
	s.ok(w, r, s.base+"/access", "Policy applied.")
}
