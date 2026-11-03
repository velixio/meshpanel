package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/meshpanel/meshpanel/internal/update"
)

func TestHeadscaleUpdatesOwnerOnlyAndConfirmed(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.29.7", "html_url": "https://github.com/juanfont/headscale/releases/tag/v0.29.7"})
	}))
	defer srv.Close()
	u := update.NewHeadscale("0.29.3")
	u.API = srv.URL
	u.AllowURL = func(p *url.URL) bool { return p.Host == srv.Listener.Addr().String() }
	h.s.HeadscaleUpdater = u
	h.s.HSVersion = func() string { return "0.29.3" }
	var installs atomic.Int32
	h.s.InstallHeadscale = func(ctx context.Context, tag string) (string, error) {
		if tag != "v0.29.7" {
			t.Error("wrong version")
		}
		installs.Add(1)
		return "Headscale installed and healthy", nil
	}
	_, ownerSecret := h.account("boss", "owner", "")
	_, adminSecret := h.account("adm", "admin", "")
	a := h.client()
	a.login("adm", adminSecret)
	if _, body, _ := a.get("/admin/settings"); strings.Contains(body, "Headscale updates") {
		t.Fatal("admin sees updates")
	}
	for _, action := range []string{"check", "install"} {
		if code, _, _ := a.post("/admin/settings", "/admin/settings/headscale_update_"+action, url.Values{"tag": {"v0.29.7"}}); code != http.StatusForbidden {
			t.Fatalf("admin %s: %d", action, code)
		}
	}
	o := h.client()
	o.login("boss", ownerSecret)
	o.post("/admin/settings", "/admin/settings/headscale_update_check", nil)
	_, body, _ := o.get("/admin/settings")
	if !strings.Contains(body, "Install Headscale v0.29.7") || !strings.Contains(body, "hx-confirm") {
		t.Fatal("owner install missing")
	}
	o.post("/admin/settings", "/admin/settings/headscale_update_install", url.Values{"tag": {"v0.29.6"}})
	if installs.Load() != 0 {
		t.Fatal("installed stale confirmation")
	}
	o.post("/admin/settings", "/admin/settings/headscale_update_install", url.Values{"tag": {"v0.29.7"}})
	if installs.Load() != 1 {
		t.Fatal("did not install")
	}
	h.s.HSVersion = func() string { return "0.28.9" }
	o.post("/admin/settings", "/admin/settings/headscale_update_install", url.Values{"tag": {"v0.29.7"}})
	if installs.Load() != 1 {
		t.Fatal("installed minor upgrade")
	}
	h.s.InstallHeadscale = nil
	_, body, _ = o.get("/admin/settings")
	if strings.Contains(body, ">Install Headscale") {
		t.Fatal("offered disabled install")
	}
}
