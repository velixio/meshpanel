package web

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/meshpanel/meshpanel/internal/hsconfig"
	"github.com/meshpanel/meshpanel/internal/perm"
)

type dnsData struct {
	DNS      *hsconfig.DNS
	Writable bool
	WhyNot   string
	Global   string
	Split    string
	Search   string
	Extra    string
	Error    string
}

func joinLines(s []string) string { return strings.Join(s, "\n") }

func (s *Server) dnsBase(r *http.Request) (*dnsData, error) {
	d := &dnsData{}
	if s.HSConfig == nil {
		d.WhyNot = "Set headscale.config_path in meshpanel's config to view and edit DNS."
		return d, nil
	}
	dns, err := s.HSConfig.ReadDNS()
	if err != nil {
		return d, err
	}
	d.DNS = dns
	d.Global, d.Search = joinLines(dns.Global), joinLines(dns.Search)
	var split []string
	for dom, ns := range dns.Split {
		split = append(split, dom+": "+strings.Join(ns, ", "))
	}
	sort.Strings(split)
	d.Split = joinLines(split)
	var extra []string
	for _, rec := range dns.Extra {
		extra = append(extra, rec.Name+" "+rec.Type+" "+rec.Value)
	}
	d.Extra = joinLines(extra)
	switch {
	case !who(r).Caps.Has(perm.WriteNetwork):
		d.WhyNot = "Your role can view DNS settings but not change them."
	case s.Applier == nil:
		d.WhyNot = "Applying DNS changes needs headscale.restart_command in meshpanel's config."
	case !s.HSConfig.Writable():
		d.WhyNot = fmt.Sprintf("meshpanel can't write %s. Give its user group write access (see the install guide).", s.HSConfig.Path)
	default:
		d.Writable = true
	}
	return d, nil
}

func (s *Server) dns(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.ReadNetwork) {
		return
	}
	d, err := s.dnsBase(r)
	p := s.page(w, r, "dns", "DNS", d)
	if err != nil {
		p.Flash = &flash{Kind: "danger", Msg: "Could not read headscale's config: " + friendly(err)}
	}
	s.render(w, r, "dns", p)
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func parseDNSForm(r *http.Request, cur *hsconfig.DNS) (*hsconfig.DNS, error) {
	d := &hsconfig.DNS{
		MagicDNS: r.PostFormValue("magic_dns") == "on", OverrideLocal: r.PostFormValue("override_local") == "on",
		BaseDomain: strings.TrimSpace(r.PostFormValue("base_domain")), Global: lines(r.PostFormValue("global")),
		Search: lines(r.PostFormValue("search")), Split: map[string][]string{}, ExtraPath: cur.ExtraPath,
	}
	for _, l := range lines(r.PostFormValue("split")) {
		dom, ns, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("split DNS line %q should look like: corp.example: 10.0.0.53", l)
		}
		d.Split[strings.TrimSpace(dom)] = splitList(ns)
	}
	for _, l := range lines(r.PostFormValue("extra")) {
		f := strings.Fields(l)
		if len(f) != 3 {
			return nil, fmt.Errorf("record line %q should look like: git.example.net A 100.64.0.5", l)
		}
		d.Extra = append(d.Extra, hsconfig.Record{Name: f[0], Type: strings.ToUpper(f[1]), Value: f[2]})
	}
	return d, d.Validate()
}

func (s *Server) dnsPost(w http.ResponseWriter, r *http.Request) {
	if !s.need(w, r, perm.WriteNetwork) {
		return
	}
	d, err := s.dnsBase(r)
	if err != nil {
		s.failed(w, r, s.base+"/dns", err)
		return
	}
	if !d.Writable {
		s.failed(w, r, s.base+"/dns", errors.New(d.WhyNot))
		return
	}
	next, err := parseDNSForm(r, d.DNS)
	if err != nil {
		d.Error = err.Error()
		d.Global, d.Split, d.Search, d.Extra = r.PostFormValue("global"), r.PostFormValue("split"), r.PostFormValue("search"), r.PostFormValue("extra")
		d.DNS.MagicDNS, d.DNS.OverrideLocal, d.DNS.BaseDomain = r.PostFormValue("magic_dns") == "on", r.PostFormValue("override_local") == "on", r.PostFormValue("base_domain")
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "dns", s.page(w, r, "dns", "DNS", d))
		return
	}
	if err := next.WriteExtraFile(); err != nil {
		s.failed(w, r, s.base+"/dns", err)
		return
	}
	if err := s.Applier.ApplyConfig(r.Context(), s.HSConfig, next.Changes()); err != nil {
		s.audit(r, "dns.apply_failed", "dns", d.DNS, friendly(err))
		s.failed(w, r, s.base+"/dns", err)
		return
	}
	s.audit(r, "dns.apply", "dns", d.DNS, next)
	s.ok(w, r, s.base+"/dns", "DNS saved. headscale restarted and devices pick it up within a minute.")
}
