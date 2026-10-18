package hsconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `# headscale config
server_url: https://hs.example.com # public
listen_addr: 127.0.0.1:8080

dns:
  # MagicDNS gives nodes names
  magic_dns: true
  base_domain: example.net
  override_local_dns: true
  nameservers:
    global:
      - 1.1.1.1
    split: {}
  search_domains: []
  extra_records: []
`

func write(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte(sample), 0o640)
	return p
}

func TestPatchKeepsComments(t *testing.T) {
	p := write(t)
	ed := &Editor{Path: p}
	if err := ed.Patch([]Change{{"dns.base_domain", "corp.example"}, {"dns.nameservers.global", []string{"9.9.9.9", "1.1.1.1"}}, {"dns.new_key", true}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, want := range []string{"# headscale config", "# public", "# MagicDNS gives nodes names", "base_domain: corp.example", "- 9.9.9.9", "new_key: true"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	backups, _ := filepath.Glob(p + ".meshpanel-*.bak")
	if len(backups) != 1 {
		t.Fatalf("backups %v", backups)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", st.Mode().Perm())
	}
}

func TestDNSRoundTrip(t *testing.T) {
	p := write(t)
	ed := &Editor{Path: p}
	d, err := ed.ReadDNS()
	if err != nil {
		t.Fatal(err)
	}
	if !d.MagicDNS || d.BaseDomain != "example.net" || len(d.Global) != 1 {
		t.Fatalf("%+v", d)
	}
	d.Split = map[string][]string{"corp.internal": {"10.0.0.53"}}
	d.Search = []string{"corp.internal"}
	d.Extra = []Record{{Name: "git.example.net", Type: "A", Value: "100.64.0.5"}}
	d.MagicDNS = false
	if err := ed.Patch(d.Changes()); err != nil {
		t.Fatal(err)
	}
	got, _ := ed.ReadDNS()
	if got.MagicDNS || got.Split["corp.internal"][0] != "10.0.0.53" || got.Extra[0].Value != "100.64.0.5" || got.Search[0] != "corp.internal" {
		t.Fatalf("%+v", got)
	}
}

func TestValidateDNS(t *testing.T) {
	d := DNS{BaseDomain: "bad domain", Global: []string{"not-an-ip"}}
	if err := d.Validate(); err == nil {
		t.Fatal("invalid dns accepted")
	}
	d = DNS{BaseDomain: "ts.example.net", Global: []string{"1.1.1.1", "https://dns.nextdns.io/abc"}, Extra: []Record{{Name: "a.ts.example.net", Type: "A", Value: "100.64.0.1"}}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRollsBackOnFailure(t *testing.T) {
	p := write(t)
	ed := &Editor{Path: p}
	var ran []string
	a := &Applier{
		Run: func(ctx context.Context, cmd string) error {
			ran = append(ran, cmd)
			return nil
		},
		RestartCmd: "restart",
		Health:     func(context.Context) error { return errors.New("down") },
		Timeout:    50e6,
	}
	err := a.ApplyConfig(context.Background(), ed, []Change{{"dns.base_domain", "broken.example"}})
	if err == nil {
		t.Fatal("expected failure")
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "base_domain: example.net") {
		t.Fatalf("not rolled back:\n%s", b)
	}
	if len(ran) != 2 {
		t.Fatalf("restart should run twice (apply + rollback), ran %v", ran)
	}
}

func TestApplySucceeds(t *testing.T) {
	p := write(t)
	ed := &Editor{Path: p}
	a := &Applier{
		Run:        func(context.Context, string) error { return nil },
		RestartCmd: "restart",
		Health:     func(context.Context) error { return nil },
		Timeout:    50e6,
	}
	if err := a.ApplyConfig(context.Background(), ed, []Change{{"dns.base_domain", "ok.example"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "base_domain: ok.example") {
		t.Fatal("not applied")
	}
}

func TestPolicyFileRollback(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.hujson")
	os.WriteFile(p, []byte(`{"acls":[]}`), 0o640)
	a := &Applier{
		Run:       func(context.Context, string) error { return nil },
		ReloadCmd: "reload",
		Health:    func(context.Context) error { return errors.New("bad policy") },
		Timeout:   50e6,
	}
	if err := a.ApplyPolicyFile(context.Background(), p, `{"acls":[{"action":"accept"}]}`); err == nil {
		t.Fatal("expected failure")
	}
	b, _ := os.ReadFile(p)
	if string(b) != `{"acls":[]}` {
		t.Fatalf("policy not restored: %s", b)
	}
}
