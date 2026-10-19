//go:build integration

package hs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Runs the client against a real headscale 0.29.x REST gateway:
//
//	HS_URL=http://127.0.0.1:8080 HS_API_KEY=hskey-api-… go test -tags integration ./internal/hs
func TestRealHeadscaleLegacy(t *testing.T) {
	url, key := os.Getenv("HS_URL"), os.Getenv("HS_API_KEY")
	if url == "" || key == "" {
		t.Skip("set HS_URL and HS_API_KEY")
	}
	c := New("/nonexistent.sock", url).UseAPIKey(key)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal("version:", err)
	}
	t.Log("version", v)
	if err := c.Health(ctx); err != nil {
		t.Fatal("health:", err)
	}
	u, err := c.CreateUser(ctx, "itest", "Integration Test", "")
	if err != nil {
		t.Fatal("create user:", err)
	}
	defer c.DeleteUser(ctx, u.ID)
	users, err := c.ListUsers(ctx)
	if err != nil || len(users) == 0 {
		t.Fatalf("list users: %v %v", users, err)
	}
	if u, err = c.RenameUser(ctx, u.ID, "itest2"); err != nil || u.Name != "itest2" {
		t.Fatalf("rename user: %+v %v", u, err)
	}
	exp := time.Now().Add(time.Hour).UTC()
	k, err := c.CreatePreAuthKey(ctx, CreateKeyReq{User: u.ID, Reusable: true, Expiration: &exp, ACLTags: nil})
	if err != nil || !strings.HasPrefix(k.Key, "hskey-auth-") && k.Key == "" {
		t.Fatalf("create key: %+v %v", k, err)
	}
	keys, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal("list keys:", err)
	}
	found := false
	for _, x := range keys {
		found = found || (x.ID == k.ID && x.User != nil && x.User.Name == "itest2" && x.Reusable)
	}
	if !found {
		t.Fatalf("created key %s not in list %+v", k.ID, keys)
	}
	if err := c.ExpirePreAuthKey(ctx, k.ID); err != nil {
		t.Fatal("expire key:", err)
	}
	if err := c.DeletePreAuthKey(ctx, k.ID); err != nil {
		t.Fatal("delete key:", err)
	}
	if _, err := c.ListNodes(ctx); err != nil {
		t.Fatal("list nodes:", err)
	}
	if _, err := c.GetPolicy(ctx); err != nil && !IsNotFound(err) {
		t.Log("get policy:", err) // empty policy is fine
	}
	if _, err := c.GetNode(ctx, "9999"); !IsNotFound(err) {
		t.Fatalf("missing node should be 404, got %v", err)
	}
	bad := New("/nonexistent.sock", url).UseAPIKey("hskey-api-wrong")
	if _, err := bad.ListUsers(ctx); err == nil || !strings.Contains(err.Error(), "apikeys create") {
		t.Fatalf("bad key: %v", err)
	}
}

// Needs the nodes from the docker e2e: alice-laptop (user alice) and
// bob-router (user bob, advertising 10.9.0.0/24).
func TestRealHeadscaleNodes(t *testing.T) {
	url, key := os.Getenv("HS_URL"), os.Getenv("HS_API_KEY")
	if url == "" || key == "" {
		t.Skip("set HS_URL and HS_API_KEY")
	}
	c := New("/nonexistent.sock", url).UseAPIKey(key)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	find := func(name string) Node {
		t.Helper()
		ns, err := c.ListNodes(ctx)
		if err != nil {
			t.Fatal("list nodes:", err)
		}
		for _, n := range ns {
			if n.GivenName == name || n.Name == name {
				return n
			}
		}
		t.Fatalf("node %q not in %d nodes", name, len(ns))
		return Node{}
	}

	alice, bob := find("alice-laptop"), find("bob-router")
	if alice.UserName() != "alice" || len(alice.IPAddresses) == 0 || alice.NodeKey == "" || alice.PreAuthKey == nil || alice.CreatedAt.IsZero() {
		t.Fatalf("alice decoded wrong: %+v", alice)
	}
	if !alice.Online {
		t.Error("alice-laptop should be online")
	}
	got, err := c.GetNode(ctx, alice.ID)
	if err != nil || got.ID != alice.ID || got.DisplayName() != "alice-laptop" {
		t.Fatalf("get node: %+v %v", got, err)
	}

	// Routes: advertised by the client, pending until approved.
	if len(bob.AvailableRoutes) != 1 || bob.AvailableRoutes[0] != "10.9.0.0/24" || len(bob.PendingRoutes()) != 1 {
		t.Fatalf("bob routes: avail=%v approved=%v", bob.AvailableRoutes, bob.ApprovedRoutes)
	}
	if n, err := c.ApproveRoutes(ctx, bob.ID, []string{"10.9.0.0/24"}); err != nil || len(n.ApprovedRoutes) != 1 || len(n.PendingRoutes()) != 0 {
		t.Fatalf("approve routes: %+v %v", n.ApprovedRoutes, err)
	}
	if n, err := c.ApproveRoutes(ctx, bob.ID, nil); err != nil || len(n.ApprovedRoutes) != 0 {
		t.Fatalf("unapprove routes: %+v %v", n.ApprovedRoutes, err)
	}

	// Rename and back.
	if n, err := c.RenameNode(ctx, alice.ID, "alice-renamed"); err != nil || n.GivenName != "alice-renamed" {
		t.Fatalf("rename: %+v %v", n.GivenName, err)
	}
	if n, err := c.RenameNode(ctx, alice.ID, "alice-laptop"); err != nil || n.GivenName != "alice-laptop" {
		t.Fatalf("rename back: %+v %v", n.GivenName, err)
	}

	// Key expiry: disable, enable (needs a date), then expire now.
	if _, err := c.SetKeyExpiryDisabled(ctx, alice.ID, true); err != nil {
		t.Fatalf("disable expiry: %v", err)
	}
	if n, err := c.SetKeyExpiryDisabled(ctx, alice.ID, false); err != nil || n.Expiry == nil || n.Expiry.Before(time.Now().AddDate(0, 5, 0)) {
		t.Fatalf("enable expiry: %+v %v", n.Expiry, err)
	}

	// Policy: validate, save, read back, then tag a node under it.
	pol := `{"tagOwners":{"tag:test":["bob@"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
	if err := c.CheckPolicy(ctx, pol); err != nil {
		t.Fatal("check policy:", err)
	}
	if err := c.CheckPolicy(ctx, `{"acls":[{"action":"nope"}]}`); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if _, err := c.SetPolicy(ctx, pol); err != nil {
		t.Fatal("set policy:", err)
	}
	if p, err := c.GetPolicy(ctx); err != nil || !strings.Contains(p.Policy, "tag:test") {
		t.Fatalf("get policy: %+v %v", p, err)
	}
	if n, err := c.SetTags(ctx, bob.ID, []string{"tag:test"}); err != nil || !n.IsTagged() || len(n.Tags) != 1 {
		t.Fatalf("set tags: %+v %v", n.Tags, err)
	}

	// Expire alice's key: she must log in again.
	if n, err := c.ExpireNode(ctx, alice.ID); err != nil || !n.KeyExpired(time.Now().Add(time.Second)) {
		t.Fatalf("expire: %+v %v", n.Expiry, err)
	}

	// Delete both; they are gone afterwards.
	for _, n := range []Node{alice, bob} {
		if err := c.DeleteNode(ctx, n.ID); err != nil {
			t.Fatal("delete node:", err)
		}
		if _, err := c.GetNode(ctx, n.ID); !IsNotFound(err) {
			t.Fatalf("deleted node still there: %v", err)
		}
	}
}
