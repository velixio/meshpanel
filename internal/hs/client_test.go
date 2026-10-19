package hs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSocket serves h on a temporary unix socket and returns a Client for it.
func fakeSocket(t *testing.T, h http.Handler) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return New(sock, "http://127.0.0.1:1")
}

func TestListNodesDecodes(t *testing.T) {
	body, _ := os.ReadFile("testdata/nodes.json")
	c := fakeSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/node" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("socket requests must not send an API key")
		}
		w.Write(body)
	}))
	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes", len(nodes))
	}
	n := nodes[0]
	if n.ID != "1" || n.GivenName != "ravi-iphone-15" || !n.Online || n.User.Name != "ravi" || n.LastSeen == nil || n.Expiry != nil {
		t.Fatalf("node 0: %+v", n)
	}
	if !n.IsExitNodeAdvertised() || n.IsTagged() {
		t.Fatal("exit/tag detection")
	}
	if !nodes[1].IsTagged() || nodes[1].Expiry == nil || nodes[1].DisplayName() != "build-01" {
		t.Fatalf("node 1: %+v", nodes[1])
	}
}

func TestAuthRegisterBody(t *testing.T) {
	var got map[string]string
	c := fakeSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/auth/register" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"node":{"id":"9","givenName":"ravi-iphone","ipAddresses":["100.64.0.9"],"user":{"id":"3","name":"ravi"}}}`)
	}))
	n, err := c.AuthRegister(context.Background(), "ravi", "hskey-authreq-0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	if got["user"] != "ravi" || got["authId"] != "hskey-authreq-0123456789abcdef01234567" || len(got) != 2 {
		t.Fatalf("body %v", got)
	}
	if n.ID != "9" || n.IPAddresses[0] != "100.64.0.9" {
		t.Fatalf("node %+v", n)
	}
}

func TestProblemJSONError(t *testing.T) {
	c := fakeSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(404)
		io.WriteString(w, `{"title":"Not Found","status":404,"detail":"node not found"}`)
	}))
	_, err := c.GetNode(context.Background(), "77")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 || ae.Detail != "node not found" {
		t.Fatalf("err = %#v", err)
	}
	if !IsNotFound(err) {
		t.Fatal("IsNotFound")
	}
}

func TestExpireNodeBodies(t *testing.T) {
	var bodies []string
	c := fakeSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.URL.Path+" "+string(b))
		io.WriteString(w, `{"node":{"id":"1"}}`)
	}))
	ctx := context.Background()
	c.ExpireNode(ctx, "1")
	c.SetKeyExpiryDisabled(ctx, "1", true)
	if bodies[0] != "/api/v1/node/1/expire " || bodies[1] != `/api/v1/node/1/expire {"disableExpiry":true}` {
		t.Fatalf("bodies %q", bodies)
	}
}

func TestRenamePathEscaped(t *testing.T) {
	var path string
	c := fakeSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		io.WriteString(w, `{"node":{"id":"1"}}`)
	}))
	c.RenameNode(context.Background(), "1", "a/b c")
	if path != "/api/v1/node/1/rename/a%2Fb%20c" {
		t.Fatalf("path %q", path)
	}
}

func TestSocketMissing(t *testing.T) {
	c := New("/nonexistent/headscale.sock", "")
	_, err := c.ListNodes(context.Background())
	if err == nil || !errors.Is(err, ErrSocket) {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckSupported(t *testing.T) {
	for v, ok := range map[string]bool{
		"0.30.0": true, "v0.30.1": true, "0.30.0-beta.1": true, "dev": true, "main": true,
		"0.29.5": false, "v0.28.0": false, "0.31.0": true, "1.0.0": true, "": false,
	} {
		if err := CheckSupported(v); (err == nil) != ok {
			t.Errorf("%q: err=%v want ok=%v", v, err, ok)
		}
	}
}

func TestValidAuthID(t *testing.T) {
	if !ValidAuthID("hskey-authreq-0123456789abcdef01234567") {
		t.Fatal("valid rejected")
	}
	for _, s := range []string{"", "hskey-authreq-0123", "hskey-authreq-0123456789ABCDEF01234567", "hskey-authreq-0123456789abcdef01234567x", "../etc"} {
		if ValidAuthID(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestVersionNotHeadscale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "42") }))
	defer srv.Close()
	_, err := New("/nonexistent", srv.URL).Version(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not answer like headscale") {
		t.Fatalf("err = %v", err)
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"version":"0.30.0","commit":"x"}`) }))
	defer ok.Close()
	if v, err := New("/nonexistent", ok.URL).Version(context.Background()); err != nil || v != "0.30.0" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestNodePreAuthKeyDecodes(t *testing.T) {
	c := fakeSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"nodes":[{"id":"5","name":"meshpanel-ssh-ravi","preAuthKey":{"id":"77","key":"","reusable":false,"ephemeral":true,"used":true,"aclTags":[]},"tags":[]}]}`)
	}))
	nodes, err := c.ListNodes(context.Background())
	if err != nil || nodes[0].PreAuthKey == nil || nodes[0].PreAuthKey.ID != "77" {
		t.Fatalf("%+v %v", nodes, err)
	}
}
