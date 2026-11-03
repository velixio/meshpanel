package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestReadOnlyDatabaseGuidance exercises invitation failure and administrator recovery guidance without losing accounts.
func TestReadOnlyDatabaseGuidance(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("boss", "owner", "ravi")
	c := h.client()
	c.login("boss", secret)
	if _, err := h.d.SQL.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	code, _, hdr := c.post("/admin/users", "/admin/people/invite", url.Values{"username": {"newperson"}, "role": {"member"}, "hs_user": {"ravi"}})
	if code != http.StatusSeeOther {
		t.Fatalf("invite: %d", code)
	}
	_, body, _ := c.get(hdr.Get("Location"))
	if !strings.Contains(body, "Meshpanel cannot write to its database") {
		t.Fatal("missing actionable invitation error")
	}
	code, body, _ = c.get("/admin/settings")
	if code != 200 || !strings.Contains(body, "write access failed") || !strings.Contains(body, h.d.Path()) {
		t.Fatalf("missing admin diagnostics: %d", code)
	}
	if n, err := h.d.CountAccounts(context.Background()); err != nil || n != 1 {
		t.Fatalf("accounts changed: %d %v", n, err)
	}
	var invites int
	if err := h.d.SQL.QueryRow(`SELECT count(*) FROM invites`).Scan(&invites); err != nil || invites != 0 {
		t.Fatalf("invites changed: %d %v", invites, err)
	}
}

// TestReadOnlyLoginHidesPaths verifies session failures explain the problem without exposing filesystem details.
func TestReadOnlyLoginHidesPaths(t *testing.T) {
	h := newHarness(t)
	h.account("boss", "owner", "ravi")
	if _, err := h.d.SQL.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	_, body, _ := c.post("/admin/login", "/admin/login", url.Values{"username": {"boss"}, "password": {testPassword}})
	if !strings.Contains(body, "Meshpanel cannot write to its database") {
		t.Fatal("missing session failure guidance")
	}
	if strings.Contains(body, h.d.Path()) || strings.Contains(body, "sudo chown") {
		t.Fatal("private recovery details leaked")
	}
}
