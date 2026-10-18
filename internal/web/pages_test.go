package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

func (f *fakeHS) GetPolicy(context.Context) (hs.Policy, error) {
	return hs.Policy{Policy: `{
  // comment
  "groups": {"group:eng": ["ravi@"]},
  "tagOwners": {"tag:server": ["group:eng"]},
  "hosts": {"office": "192.168.1.0/24"},
  "acls": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:server:22"]}],
  "ssh": [{"action": "check", "src": ["group:eng"], "dst": ["tag:server"], "users": ["root"]}],
}`, UpdatedAt: time.Now()}, nil
}
func (f *fakeHS) CheckPolicy(context.Context, string) error { return nil }
func (f *fakeHS) SetPolicy(_ context.Context, p string) (hs.Policy, error) {
	return hs.Policy{Policy: p}, nil
}
func (f *fakeHS) ListPreAuthKeys(context.Context) ([]hs.PreAuthKey, error) {
	return []hs.PreAuthKey{{ID: "1", Key: "abcdef0123456789abcdef", User: &hs.User{ID: "1", Name: "ravi"}, Expiration: time.Now().Add(time.Hour)}}, nil
}
func (f *fakeHS) CreatePreAuthKey(_ context.Context, r hs.CreateKeyReq) (hs.PreAuthKey, error) {
	return hs.PreAuthKey{ID: "2", Key: "newkey0123456789", Expiration: time.Now().Add(time.Hour)}, nil
}

func TestEveryPageRendersForEveryRole(t *testing.T) {
	h := newHarness(t)
	h.hs.users = []hs.User{{ID: "1", Name: "ravi"}, {ID: "2", Name: "anna"}}
	ctx := context.Background()
	reqer, _ := h.account("req", "member", "ravi")
	p, _ := h.s.Reg.Create(ctx, "register", "hskey-authreq-0123456789abcdef01234567", reqer, "1.2.3.4", "iPhone")
	_ = p
	h.d.CreateWatch(ctx, db.WatchRule{AccountID: reqer.ID, SubjectType: "node", Subject: "1", Events: []string{"node_offline"}})
	h.d.AddNotification(ctx, reqer.ID, "node_offline", "🔴 ravi-phone went offline")
	h.d.InsertAudit(ctx, db.AuditEntry{Actor: "x", Channel: "web", Action: "test", Target: "y"})
	pages := []string{"/admin/", "/admin/machines", "/admin/machines/1", "/admin/users", "/admin/people", "/admin/people/1",
		"/admin/keys", "/admin/access", "/admin/access?tab=editor", "/admin/dns", "/admin/alerts", "/admin/audit",
		"/admin/settings", "/admin/account", "/admin/approvals", "/admin/search?q=ra", "/admin/audit.csv"}
	for _, role := range []string{"owner", "admin", "network_admin", "it_admin", "auditor", "viewer", "member"} {
		_, secret := h.account("u-"+strings.ReplaceAll(role, "_", "-"), role, "ravi")
		c := h.client()
		c.login("u-"+strings.ReplaceAll(role, "_", "-"), secret)
		for _, pg := range pages {
			code, body, _ := c.get(pg)
			if code >= 500 || strings.Contains(body, "render error") {
				t.Errorf("%s %s: %d %s", role, pg, code, body[:min(300, len(body))])
			}
			if code != 200 && code != 403 && code != 404 {
				t.Errorf("%s %s: unexpected %d", role, pg, code)
			}
		}
	}
}

func TestMemberCannotOpenOthersNode(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("ravi", "member", "ravi")
	c := h.client()
	c.login("ravi", secret)
	if code, _, _ := c.get("/admin/machines/1"); code != 200 {
		t.Fatalf("own node: %d", code)
	}
	if code, _, _ := c.get("/admin/machines/2"); code != http.StatusNotFound {
		t.Fatalf("other's node: %d", code)
	}
	_, body, _ := c.get("/admin/machines")
	if strings.Contains(body, "anna-laptop") || !strings.Contains(body, "ravi-phone") {
		t.Fatal("machine list not scoped")
	}
	_, body, _ = c.get("/admin/search?q=anna")
	if strings.Contains(body, "anna-laptop") {
		t.Fatal("search leaks other users' machines")
	}
	c.post("/admin/machines/1", "/admin/machines/2/rename", url.Values{"name": {"pwned"}})
	if h.hs.renamed["2"] != "" {
		t.Fatal("member renamed someone else's machine")
	}
}

func TestRegisterPageInvalidID(t *testing.T) {
	h := newHarness(t)
	code, body, _ := h.client().get("/register/not-a-real-id")
	if code != http.StatusNotFound || !strings.Contains(body, "link doesn") {
		t.Fatalf("%d", code)
	}
}

func TestRegisterRequiresSignIn(t *testing.T) {
	h := newHarness(t)
	code, _, hdr := h.client().get("/register/hskey-authreq-0123456789abcdef01234567")
	if code != http.StatusFound || !strings.Contains(hdr.Get("Location"), "/admin/login?next=%2Fregister%2F") {
		t.Fatalf("%d %s", code, hdr.Get("Location"))
	}
}

func TestRegisterSelfApprove(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("anna", "admin", "anna")
	c := h.client()
	c.login("anna", secret)
	code, body, _ := c.get("/register/hskey-authreq-0123456789abcdef01234567")
	if code != 200 || !strings.Contains(body, "connected") {
		t.Fatalf("%d", code)
	}
	if len(h.hs.registered) != 1 || h.hs.registered[0] != "anna/hskey-authreq-0123456789abcdef01234567" {
		t.Fatalf("registered %v", h.hs.registered)
	}
}

func TestRegisterMemberWaitsThenApproved(t *testing.T) {
	h := newHarness(t)
	_, rs := h.account("ravi", "member", "ravi")
	_, as := h.account("anna", "admin", "anna")
	phone := h.client()
	phone.login("ravi", rs)
	_, body, _ := phone.get("/register/hskey-authreq-0123456789abcdef01234567")
	if !strings.Contains(body, "Waiting for approval") || len(h.hs.registered) != 0 {
		t.Fatal("member was not put in the queue")
	}
	admin := h.client()
	admin.login("anna", as)
	_, ov, _ := admin.get("/admin/")
	if !strings.Contains(ov, "ravi") || !strings.Contains(ov, "wants to add a device") {
		t.Fatal("pending request not on overview")
	}
	ps, _ := h.d.ListPending(context.Background(), true, 10)
	code, _, _ := admin.post("/admin/", "/admin/approvals/"+itoa(ps[0].ID), url.Values{"decision": {"approve"}})
	if code != http.StatusSeeOther || len(h.hs.registered) != 1 || h.hs.registered[0] != "ravi/hskey-authreq-0123456789abcdef01234567" {
		t.Fatalf("approve: %d %v", code, h.hs.registered)
	}
	_, body, _ = phone.get("/register/hskey-authreq-0123456789abcdef01234567")
	if !strings.Contains(body, "connected") || !strings.Contains(body, "anna") {
		t.Fatal("phone page not updated")
	}
}

func TestOwnApproverCannotApproveAsOtherUserOnWeb(t *testing.T) {
	h := newHarness(t)
	_, rs := h.account("ravi", "member", "ravi")
	c := h.client()
	c.login("ravi", rs)
	c.get("/register/hskey-authreq-0123456789abcdef01234567")
	c.post("/admin/", "/register/hskey-authreq-0123456789abcdef01234567/decide", url.Values{"decision": {"approve"}, "as_user": {"anna"}})
	if len(h.hs.registered) != 0 {
		t.Fatal("member approved their own device as another user")
	}
}

func TestAuditOnRename(t *testing.T) {
	h := newHarness(t)
	_, secret := h.account("anna", "admin", "anna")
	c := h.client()
	c.login("anna", secret)
	code, _, _ := c.post("/admin/machines/1", "/admin/machines/1/rename", url.Values{"name": {"ravi-iphone"}})
	if code != http.StatusSeeOther || h.hs.renamed["1"] != "ravi-iphone" {
		t.Fatalf("rename: %d", code)
	}
	es, _ := h.d.ListAudit(context.Background(), db.AuditFilter{Query: "machine.rename"})
	if len(es) != 1 || es[0].Actor != "anna" || es[0].After != "ravi-iphone" || es[0].Channel != "web" {
		t.Fatalf("audit %+v", es)
	}
}

func TestPolicyVisualEditAndDiff(t *testing.T) {
	doc, err := parsePolicy(`{"groups":{"group:eng":["ravi@"]}, // c
	"acls":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.applyOp("group_set", func(k string) string { return map[string]string{"name": "ops", "members": "anna@, bob@"}[k] }); err != nil {
		t.Fatal(err)
	}
	if err := doc.applyOp("acl_add", func(k string) string { return map[string]string{"src": "group:ops", "dst": "*:*"}[k] }); err != nil {
		t.Fatal(err)
	}
	out := doc.String()
	if !strings.Contains(out, `"group:ops"`) || !strings.Contains(out, `"anna@"`) || !strings.Contains(out, `"*:*"`) {
		t.Fatal(out)
	}
	d := lineDiff("a\nb\nc\n", "a\nB\nc\n")
	var kinds []string
	for _, l := range d {
		kinds = append(kinds, l.Kind+":"+l.Text)
	}
	if strings.Join(kinds, ",") != "ctx:a,del:b,add:B,ctx:c" {
		t.Fatal(kinds)
	}
}

func itoa(n int64) string { return strconvFormat(n) }

func strconvFormat(n int64) string { return strconv.FormatInt(n, 10) }

func TestIAMCannotEscalate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.account("boss", "owner", "")
	mgr, secret := h.account("mgr", "viewer", "")
	mgr.ExtraCaps = uint64(perm.ConfigureIAM)
	h.d.UpdateAccount(ctx, mgr)
	adm, _ := h.account("adm", "admin", "")
	c := h.client()
	c.login("mgr", secret)
	c.post("/admin/people", "/admin/people/"+itoa(mgr.ID)+"/role", url.Values{"role": {"admin"}})
	if a, _ := h.d.GetAccount(ctx, mgr.ID); a.Role != "viewer" {
		t.Fatal("viewer+configure_iam promoted themselves to admin")
	}
	c.post("/admin/people", "/admin/people/invite", url.Values{"username": {"sock"}, "role": {"admin"}})
	if ins, _ := h.d.ListInvites(ctx); len(ins) != 0 {
		t.Fatal("invited someone with more power than the inviter")
	}
	c.post("/admin/people", "/admin/people/"+itoa(adm.ID)+"/password", url.Values{"password": {"attacker-chosen-pw"}})
	if a, _ := h.d.GetAccount(ctx, adm.ID); auth.VerifyPassword(a.PasswordHash, "attacker-chosen-pw") {
		t.Fatal("reset the password of a more powerful account")
	}
}
