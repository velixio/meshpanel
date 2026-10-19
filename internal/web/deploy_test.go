package web

import (
	"strings"
	"testing"
)

func TestBuildCommands(t *testing.T) {
	o := deployOpts{
		Server: "https://hs.example.com", AuthKey: "hskey-auth-abc", Hostname: "web-01", SSH: true,
		ExitNode: true, Routes: []string{"10.0.0.0/24"}, AcceptRoutes: true, NoDNS: true, Tags: []string{"tag:server"},
	}
	c := buildCommands(o)
	want := "tailscale up --login-server=https://hs.example.com --authkey=hskey-auth-abc --hostname=web-01 --ssh --advertise-exit-node --advertise-routes=10.0.0.0/24 --accept-routes --accept-dns=false --advertise-tags=tag:server"
	if !strings.HasSuffix(c.Linux, "sudo "+want) || !strings.HasPrefix(c.Linux, "curl -fsSL https://tailscale.com/install.sh | sh") {
		t.Fatalf("linux:\n%s", c.Linux)
	}
	if c.MacOS != want || c.Windows != strings.Replace(want, "tailscale up", "tailscale.exe up", 1) {
		t.Fatalf("mac/win:\n%s\n%s", c.MacOS, c.Windows)
	}
	for _, s := range []string{"TS_AUTHKEY=hskey-auth-abc", "TS_HOSTNAME=web-01", "--login-server=https://hs.example.com", "--advertise-exit-node", "tailscale/tailscale"} {
		if !strings.Contains(c.Docker, s) {
			t.Fatalf("docker lacks %q:\n%s", s, c.Docker)
		}
	}
	interactive := buildCommands(deployOpts{Server: "https://hs.example.com"})
	if interactive.MacOS != "tailscale up --login-server=https://hs.example.com" {
		t.Fatalf("interactive: %s", interactive.MacOS)
	}
}

func TestParseDeployOptsRejectsBadInput(t *testing.T) {
	for _, form := range []map[string]string{
		{"hostname": "Bad Name"},
		{"routes": "10.0.0.0/33"},
		{"tags": "server prod!"},
	} {
		if _, err := parseDeployForm(func(k string) string { return form[k] }); err == nil {
			t.Errorf("accepted %v", form)
		}
	}
	o, err := parseDeployForm(func(k string) string {
		return map[string]string{"hostname": "nas", "routes": "192.168.1.0/24, 10.1.0.0/16", "tags": "server", "ssh": "on"}[k]
	})
	if err != nil || len(o.Routes) != 2 || o.Tags[0] != "tag:server" || !o.SSH || o.Hostname != "nas" {
		t.Fatalf("%+v %v", o, err)
	}
}
