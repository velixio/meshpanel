package hsconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Record struct {
	Name  string `yaml:"name" json:"name"`
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}

// DNS is the editable view of headscale's dns section.
type DNS struct {
	MagicDNS      bool
	BaseDomain    string
	OverrideLocal bool
	Global        []string
	Split         map[string][]string
	Search        []string
	Extra         []Record
	ExtraPath     string // when set, extra records live in this JSON file
}

type dnsFile struct {
	DNS struct {
		MagicDNS         bool     `yaml:"magic_dns"`
		BaseDomain       string   `yaml:"base_domain"`
		OverrideLocalDNS bool     `yaml:"override_local_dns"`
		SearchDomains    []string `yaml:"search_domains"`
		ExtraRecords     []Record `yaml:"extra_records"`
		ExtraRecordsPath string   `yaml:"extra_records_path"`
		Nameservers      struct {
			Global []string            `yaml:"global"`
			Split  map[string][]string `yaml:"split"`
		} `yaml:"nameservers"`
	} `yaml:"dns"`
}

func (e *Editor) ReadDNS() (*DNS, error) {
	var f dnsFile
	if err := e.Decode(&f); err != nil {
		return nil, err
	}
	d := &DNS{
		MagicDNS: f.DNS.MagicDNS, BaseDomain: f.DNS.BaseDomain, OverrideLocal: f.DNS.OverrideLocalDNS,
		Global: f.DNS.Nameservers.Global, Split: f.DNS.Nameservers.Split, Search: f.DNS.SearchDomains,
		Extra: f.DNS.ExtraRecords, ExtraPath: f.DNS.ExtraRecordsPath,
	}
	if d.ExtraPath != "" {
		b, err := os.ReadFile(d.ExtraPath)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			if err := json.Unmarshal(b, &d.Extra); err != nil {
				return nil, fmt.Errorf("reading %s: %w", d.ExtraPath, err)
			}
		}
	}
	if d.Split == nil {
		d.Split = map[string][]string{}
	}
	return d, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Changes are the config.yaml edits for d. Extra records in a separate
// file are written by WriteExtraFile instead.
func (d *DNS) Changes() []Change {
	split := d.Split
	if split == nil {
		split = map[string][]string{}
	}
	cs := []Change{
		{"dns.magic_dns", d.MagicDNS},
		{"dns.base_domain", d.BaseDomain},
		{"dns.override_local_dns", d.OverrideLocal},
		{"dns.nameservers.global", nonNil(d.Global)},
		{"dns.nameservers.split", split},
		{"dns.search_domains", nonNil(d.Search)},
	}
	if d.ExtraPath == "" {
		extra := d.Extra
		if extra == nil {
			extra = []Record{}
		}
		cs = append(cs, Change{"dns.extra_records", extra})
	}
	return cs
}

// WriteExtraFile writes extra records to ExtraPath (headscale watches it and
// reloads without a restart).
func (d *DNS) WriteExtraFile() error {
	if d.ExtraPath == "" {
		return nil
	}
	extra := d.Extra
	if extra == nil {
		extra = []Record{}
	}
	b, err := json.MarshalIndent(extra, "", "  ")
	if err != nil {
		return err
	}
	if _, err := backupFile(d.ExtraPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFile(d.ExtraPath, append(b, '\n'), 0o640)
}

var domainRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

func validNameserver(s string) bool {
	if strings.HasPrefix(s, "https://") {
		return len(s) > len("https://")
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// Validate catches mistakes before they reach headscale.
func (d *DNS) Validate() error {
	var errs []error
	if d.MagicDNS && d.BaseDomain == "" {
		errs = append(errs, errors.New("MagicDNS needs a base domain"))
	}
	if d.BaseDomain != "" && !domainRe.MatchString(d.BaseDomain) {
		errs = append(errs, fmt.Errorf("base domain %q is not a valid domain name", d.BaseDomain))
	}
	for _, ns := range d.Global {
		if !validNameserver(ns) {
			errs = append(errs, fmt.Errorf("nameserver %q must be an IP address or an https:// DoH URL", ns))
		}
	}
	for dom, nss := range d.Split {
		if !domainRe.MatchString(dom) {
			errs = append(errs, fmt.Errorf("split domain %q is not a valid domain name", dom))
		}
		for _, ns := range nss {
			if !validNameserver(ns) {
				errs = append(errs, fmt.Errorf("nameserver %q for %s must be an IP address", ns, dom))
			}
		}
	}
	for _, s := range d.Search {
		if !domainRe.MatchString(s) {
			errs = append(errs, fmt.Errorf("search domain %q is not a valid domain name", s))
		}
	}
	for _, r := range d.Extra {
		ip, err := netip.ParseAddr(r.Value)
		switch {
		case !domainRe.MatchString(r.Name):
			errs = append(errs, fmt.Errorf("record name %q is not a valid name", r.Name))
		case r.Type != "A" && r.Type != "AAAA":
			errs = append(errs, fmt.Errorf("record %s: type must be A or AAAA", r.Name))
		case err != nil:
			errs = append(errs, fmt.Errorf("record %s: %q is not an IP address", r.Name, r.Value))
		case r.Type == "A" && !ip.Is4(), r.Type == "AAAA" && !ip.Is6():
			errs = append(errs, fmt.Errorf("record %s: %s does not match type %s", r.Name, r.Value, r.Type))
		}
	}
	return errors.Join(errs...)
}
