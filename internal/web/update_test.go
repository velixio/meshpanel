package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/update"
)

// fakeRelease serves a GitHub release signed with priv (for pub, the key the
// updater trusts).
func fakeRelease(t *testing.T, tag string, priv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	asset := "meshpanel_linux_" + runtime.GOARCH
	if runtime.GOARCH == "arm" {
		asset = "meshpanel_linux_armv7"
	}
	bin := []byte("#!/bin/sh\necho updated\n")
	sum := sha256.Sum256(bin)
	sums := hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	sig := ed25519.Sign(priv, []byte(sums))
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL + "/dl/"
		json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "html_url": "https://github.com/o/r/releases/tag/" + tag, "body": "notes", "assets": []map[string]string{
			{"name": asset, "browser_download_url": base + asset},
			{"name": "checksums.txt", "browser_download_url": base + "checksums.txt"},
			{"name": "checksums.txt.sig", "browser_download_url": base + "checksums.txt.sig"},
		}})
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, sums) })
	mux.HandleFunc("/dl/checksums.txt.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(sig) })
	mux.HandleFunc("/dl/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newUpdater(t *testing.T, h *harness, srv *httptest.Server, pub ed25519.PublicKey) (*update.Updater, *atomic.Int32, string) {
	t.Helper()
	dir := t.TempDir()
	u := update.New("o/r", dir, "0.1.1")
	u.API, u.Key = srv.URL, pub
	u.AllowURL = func(p *url.URL) bool { return p.Hostname() == "127.0.0.1" }
	restarts := &atomic.Int32{}
	u.Restart = func() { restarts.Add(1) }
	h.s.Updater = u
	return u, restarts, dir
}

func TestUpdateIsOwnerOnlyAndConfirmed(t *testing.T) {
	h := newHarness(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeRelease(t, "v0.2.0", priv)
	_, restarts, dir := newUpdater(t, h, srv, pub)
	_, ownerSecret := h.account("boss", "owner", "")
	adm, admSecret := h.account("adm", "admin", "")
	_ = adm

	// An admin (everything but Owner) can neither see nor use it.
	a := h.client()
	a.login("adm", admSecret)
	if _, body, _ := a.get("/admin/settings"); strings.Contains(body, "Install 0.2.0") || strings.Contains(body, "Check for updates") {
		t.Fatal("admin sees the Updates card")
	}
	if code, _, _ := a.post("/admin/settings", "/admin/settings/update_install", url.Values{"tag": {"v0.2.0"}}); code != http.StatusForbidden {
		t.Fatalf("admin install: %d", code)
	}

	o := h.client()
	o.login("boss", ownerSecret)
	_, body, _ := o.get("/admin/settings")
	if !strings.Contains(body, "Check for updates") {
		t.Fatal("owner doesn't see the Updates card")
	}
	o.post("/admin/settings", "/admin/settings/update_check", nil)
	_, body, _ = o.get("/admin/settings")
	if !strings.Contains(body, "0.2.0") || !strings.Contains(body, "Install 0.2.0") || !strings.Contains(body, "checks its signature") {
		t.Fatalf("owner is not offered 0.2.0 with a confirmation: %.300s", body)
	}

	// The version in the form is the one that must be installed.
	o.post("/admin/settings", "/admin/settings/update_install", url.Values{"tag": {"v0.1.9"}})
	if restarts.Load() != 0 {
		t.Fatal("installed a version the owner didn't confirm")
	}
	if _, err := os.Stat(filepath.Join(dir, "update", "VERSION")); err == nil {
		t.Fatal("staged the wrong version")
	}

	o.post("/admin/settings", "/admin/settings/update_install", url.Values{"tag": {"v0.2.0"}})
	if b, _ := os.ReadFile(filepath.Join(dir, "update", "VERSION")); strings.TrimSpace(string(b)) != "v0.2.0" {
		t.Fatalf("not staged: %q", b)
	}
	deadline := 60
	for restarts.Load() == 0 && deadline > 0 {
		deadline--
		sleepMs(50)
	}
	if restarts.Load() != 1 {
		t.Fatalf("restart requested %d times", restarts.Load())
	}
	ents, _ := h.d.ListAudit(context.Background(), db.AuditFilter{Limit: 50})
	found := false
	for _, e := range ents {
		found = found || e.Action == "update.install"
	}
	if !found {
		t.Fatal("install not in the audit log")
	}
}

func TestUpdateWithWrongSignatureInstallsNothing(t *testing.T) {
	h := newHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader) // the key meshpanel trusts…
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeRelease(t, "v0.2.0", attacker) // …but the release is signed by someone else
	_, restarts, dir := newUpdater(t, h, srv, pub)
	_, secret := h.account("boss", "owner", "")
	o := h.client()
	o.login("boss", secret)
	o.post("/admin/settings", "/admin/settings/update_install", url.Values{"tag": {"v0.2.0"}})
	_, body, _ := o.get("/admin/settings")
	if !strings.Contains(body, "signature") {
		t.Fatalf("no signature error shown: %.300s", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "update", "meshpanel")); err == nil {
		t.Fatal("a binary was staged from an unverified release")
	}
	sleepMs(300)
	if restarts.Load() != 0 {
		t.Fatal("restarted after a failed install")
	}
}

func sleepMs(n int) { time.Sleep(time.Duration(n) * time.Millisecond) }
