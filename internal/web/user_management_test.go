package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/hs"
)

// RenameUser records a Headscale rename while retaining its stable identity.
func (f *fakeHS) RenameUser(_ context.Context, id, name string) (hs.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.users {
		if f.users[i].ID == id {
			f.users[i].Name = name
			return f.users[i], nil
		}
	}
	return hs.User{}, nil
}

// TestUsersEditAndLinkedAccount verifies labels, stable editing, and role-aware account access.
func TestUsersEditAndLinkedAccount(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.hs.users = []hs.User{{ID: "99", Name: "team", DisplayName: "Team Devices"}, {ID: "100", Name: "owners"}}
	member, _ := h.account("memberlogin", "member", "team")
	member.DisplayName = "Member Display"
	if err := h.d.UpdateAccount(ctx, member); err != nil {
		t.Fatal(err)
	}
	owner, _ := h.account("boss", "owner", "owners")
	_, secret := h.account("adm", "admin", "")
	c := h.client()
	c.login("adm", secret)
	code, body, _ := c.get("/admin/users")
	if code != 200 || !strings.Contains(body, "Display name: Team Devices") || !strings.Contains(body, `href="/admin/users/99"`) || strings.Contains(body, "data-menu") {
		t.Fatal("Users labels or edit navigation missing")
	}
	if !strings.Contains(body, "/people/"+itoa(member.ID)+"#security") || strings.Contains(body, "/people/"+itoa(owner.ID)+"#security") {
		t.Fatal("incorrect account management links")
	}
	code, body, _ = c.get("/admin/users/99")
	if code != 200 || !strings.Contains(body, "Sign-in username") || !strings.Contains(body, "memberlogin") || !strings.Contains(body, "Manage password and two-factor") {
		t.Fatal("edit page missing account controls")
	}
	code, _, hdr := c.post("/admin/users/99", "/admin/users/99/rename", url.Values{"name": {"renamed"}})
	if code != http.StatusSeeOther || hdr.Get("Location") != "/admin/users/99" {
		t.Fatalf("rename: %d %v", code, hdr)
	}
	acc, _ := h.d.GetAccount(ctx, member.ID)
	if acc.HSUser != "renamed" || acc.Username != "memberlogin" || acc.PasswordHash != member.PasswordHash {
		t.Fatal("rename changed wrong account fields")
	}
	_, body, _ = c.get("/admin/users/99")
	if !strings.Contains(body, `value="renamed"`) {
		t.Fatal("edit page still shows old username")
	}
	_, itSecret := h.account("itadmin", "it_admin", "")
	it := h.client()
	it.login("itadmin", itSecret)
	_, body, _ = it.get("/admin/users/99")
	if strings.Contains(body, "Manage password and two-factor") {
		t.Fatal("IT admin can manage panel credentials")
	}
	for _, action := range []string{"password", "reset2fa"} {
		if code, _, _ := it.post("/admin/account", "/admin/people/"+itoa(member.ID)+"/"+action, url.Values{"password": {"not authorized password"}}); code != http.StatusForbidden {
			t.Fatalf("IT admin can %s", action)
		}
	}
	_, viewerSecret := h.account("viewer", "viewer", "")
	viewer := h.client()
	viewer.login("viewer", viewerSecret)
	if code, _, _ := viewer.get("/admin/users/99"); code != 403 {
		t.Fatal("viewer can edit user")
	}
}

// TestAdminResetsOtherAccountCredentials verifies reset effects and owner protection through HTTP.
func TestAdminResetsOtherAccountCredentials(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	member, _ := h.account("member", "member", "")
	owner, _ := h.account("boss", "owner", "")
	_, secret := h.account("adm", "admin", "")
	admin := h.client()
	admin.login("adm", secret)
	token, err := h.s.Sessions.Create(ctx, member.ID, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	path := "/admin/people/" + itoa(member.ID)
	if code, body, _ := admin.get(path); code != 200 || !strings.Contains(body, "New password") || !strings.Contains(body, "Reset two-factor") {
		t.Fatal("admin security controls unavailable")
	}
	admin.post(path, path+"/password", url.Values{"password": {"short"}})
	if _, _, err := h.s.Sessions.Lookup(ctx, token); err != nil {
		t.Fatal("invalid password revoked session")
	}
	newPassword := "new secure password 123"
	admin.post(path, path+"/password", url.Values{"password": {newPassword}})
	updated, _ := h.d.GetAccount(ctx, member.ID)
	if !auth.VerifyPassword(updated.PasswordHash, newPassword) || !updated.TOTPEnabled {
		t.Fatal("password reset failed or changed 2FA")
	}
	if _, _, err := h.s.Sessions.Lookup(ctx, token); err == nil {
		t.Fatal("password reset left active session")
	}
	if _, err := auth.NewBackupCodes(ctx, h.d, member.ID); err != nil {
		t.Fatal(err)
	}
	token, err = h.s.Sessions.Create(ctx, member.ID, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	admin.post(path, path+"/reset2fa", nil)
	updated, _ = h.d.GetAccount(ctx, member.ID)
	if updated.TOTPEnabled || updated.TOTPSecret != "" || h.d.RemainingBackupCodes(ctx, member.ID) != 0 {
		t.Fatal("2FA reset left credentials")
	}
	if _, _, err := h.s.Sessions.Lookup(ctx, token); err == nil {
		t.Fatal("2FA reset left active session")
	}
	login := h.client()
	code, _, hdr := login.post("/admin/login", "/admin/login", url.Values{"username": {"member"}, "password": {newPassword}})
	if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "/2fa/enroll") {
		t.Fatal("reset did not require enrollment")
	}
	for _, action := range []string{"password", "reset2fa"} {
		target := "/admin/people/" + itoa(owner.ID) + "/" + action
		if code, _, _ := admin.post("/admin/people", target, url.Values{"password": {newPassword}}); code != 403 {
			t.Fatalf("admin can %s for owner", action)
		}
	}
	currentOwner, _ := h.d.GetAccount(ctx, owner.ID)
	if currentOwner.PasswordHash != owner.PasswordHash || !currentOwner.TOTPEnabled {
		t.Fatal("owner credentials changed")
	}
}
