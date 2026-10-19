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
