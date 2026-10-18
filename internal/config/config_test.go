package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":8030" || c.Server.BasePath != "/admin" {
		t.Fatalf("server defaults: %+v", c.Server)
	}
	if c.Headscale.Socket != "/var/run/headscale/headscale.sock" || c.Headscale.HTTPURL != "http://127.0.0.1:8080" {
		t.Fatalf("headscale defaults: %+v", c.Headscale)
	}
	if c.Headscale.PollInterval != 5*time.Second {
		t.Fatalf("poll interval = %v", c.Headscale.PollInterval)
	}
	if c.Headscale.RestartCommand != "sudo systemctl restart headscale" || c.Headscale.ReloadCommand != "sudo systemctl reload headscale" {
		t.Fatalf("commands: %+v", c.Headscale)
	}
	if c.DB.Path != "/var/lib/meshpanel/meshpanel.db" || !c.Server.CookieSecure {
		t.Fatalf("db/cookie defaults: %+v %+v", c.DB, c.Server)
	}
}

func TestLoadFile(t *testing.T) {
	p := writeFile(t, "c.yaml", "server:\n  listen: \":7000\"\nheadscale:\n  poll_interval: 10s\ntelegram:\n  token: abc\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":7000" || c.Headscale.PollInterval != 10*time.Second || c.Telegram.Token != "abc" {
		t.Fatalf("got %+v", c)
	}
	if c.Server.BasePath != "/admin" {
		t.Fatal("defaults must survive partial file")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("MESHPANEL_SERVER_LISTEN", ":9000")
	t.Setenv("MESHPANEL_SERVER_COOKIE_SECURE", "false")
	t.Setenv("MESHPANEL_HEADSCALE_POLL_INTERVAL", "3s")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":9000" || c.Server.CookieSecure || c.Headscale.PollInterval != 3*time.Second {
		t.Fatalf("got %+v %+v", c.Server, c.Headscale)
	}
}

func TestSecretPath(t *testing.T) {
	sp := writeFile(t, "secret", "  0123456789abcdef0123456789abcdef\n")
	p := writeFile(t, "c.yaml", "server:\n  session_secret_path: "+sp+"\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.SessionSecret != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("secret = %q", c.Server.SessionSecret)
	}
}

func TestValidateWeakSecret(t *testing.T) {
	c, _ := Load("")
	c.Server.SessionSecret = "short"
	if c.Validate() == nil {
		t.Fatal("short secret accepted")
	}
	c.Server.SessionSecret = ExampleSecret
	if c.Validate() == nil {
		t.Fatal("example secret accepted")
	}
	c.Server.SessionSecret = "0123456789abcdef0123456789abcdef"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
