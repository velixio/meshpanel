package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/meshpanel/meshpanel/internal/perm"
)

func TestRequesterCannotDecideOwnQueuedRequest(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.d.SetSetting(ctx, "devices.max_per_user", "1")
	ravi, secret := h.account("ravi", "member", "ravi") // already owns node 1
	ravi.ExtraCaps = uint64(perm.ApproveDevicesOwn)
	h.d.UpdateAccount(ctx, ravi)
	c := h.client()
	c.login("ravi", secret)
	reg := "/register/hskey-authreq-0123456789abcdef01234567"
	c.post(reg, reg, nil)
	c.post(reg, reg+"/decide", url.Values{"decision": {"approve"}})
	ps, _ := h.d.ListPending(ctx, true, 10)
	if len(ps) != 1 {
		t.Fatalf("pending: %d", len(ps))
	}
	c.post("/admin/", "/admin/approvals/"+itoa(ps[0].ID), url.Values{"decision": {"approve"}})
	if len(h.hs.registered) != 0 {
		t.Fatal("requester approved their own over-limit request")
	}
}

func TestKeysCountTowardDeviceLimit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.hs.users = h.s.Poller.Users()
	_, secret := h.account("ravi", "member", "ravi") // 1 device + 1 unused key
	c := h.client()
	c.login("ravi", secret)
	key := func(reusable string) bool {
		_, body, _ := c.post("/admin/keys", "/admin/keys", url.Values{"user": {"ravi"}, "reusable": {reusable}, "expiry_hours": {"1"}})
		return strings.Contains(body, "newkey0123456789")
	}
	h.d.SetSetting(ctx, "devices.max_per_user", "3")
	if key("on") {
		t.Fatal("reusable key allowed under a device limit")
	}
	if !key("") {
		t.Fatal("single-use key refused while under the limit")
	}
	h.d.SetSetting(ctx, "devices.max_per_user", "2")
	if key("") {
		t.Fatal("key allowed with devices plus unused keys at the limit")
	}
}

func TestSetupNeedsToken(t *testing.T) {
	h := newHarness(t)
	code, _, _ := h.client().post("/admin/setup", "/admin/setup", url.Values{"setup_token": {"wrong"}, "username": {"boss"}, "password": {testPassword}, "confirm": {testPassword}})
	if n, _ := h.d.CountAccounts(context.Background()); code != http.StatusBadRequest || n != 0 {
		t.Fatalf("setup without the right token: %d, %d accounts", code, n)
	}
}

func TestIAMCannotLinkToSomeoneElsesHSUser(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.account("anna", "owner", "anna")
	mgr, secret := h.account("mgr", "network_admin", "")
	mgr.ExtraCaps = uint64(perm.ConfigureIAM)
	h.d.UpdateAccount(ctx, mgr)
	c := h.client()
	c.login("mgr", secret)
	c.post("/admin/people", "/admin/people/"+itoa(mgr.ID)+"/hsuser", url.Values{"hs_user": {"anna"}})
	if a, _ := h.d.GetAccount(ctx, mgr.ID); a.HSUser != "" {
		t.Fatal("linked to the owner's headscale user")
	}
	c.post("/admin/people", "/admin/people/"+itoa(mgr.ID)+"/hsuser", url.Values{"hs_user": {"ravi"}})
	if a, _ := h.d.GetAccount(ctx, mgr.ID); a.HSUser != "ravi" {
		t.Fatal("couldn't link to an unused headscale user")
	}
}

func TestEnrollRefusedWhenAlreadyEnrolled(t *testing.T) {
	h := newHarness(t)
	_, _ = h.account("ravi", "member", "ravi")
	c := h.client()
	c.post("/admin/login", "/admin/login", url.Values{"username": {"ravi"}, "password": {testPassword}})
	code, _, hdr := c.post("/admin/login/2fa", "/admin/2fa/enroll", url.Values{"code": {"000000"}})
	if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "/login/2fa") {
		t.Fatalf("enroll with a half-session on an enrolled account: %d %s", code, hdr.Get("Location"))
	}
}
