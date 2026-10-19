package update

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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGitHub serves one release whose files the test can corrupt.
type fakeGitHub struct {
	srv      *httptest.Server
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	tag      string
	binary   []byte
	sums     string
	sig      []byte
	noSig    bool
	redirect string // serve the binary from here instead
}

func newFake(t *testing.T, tag string) *fakeGitHub {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeGitHub{pub: pub, priv: priv, tag: tag, binary: []byte("#!/bin/sh\necho new meshpanel\n")}
	f.resign()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		base := f.srv.URL + "/dl/"
		assets := []map[string]string{
			{"name": assetName(), "browser_download_url": base + assetName()},
			{"name": "checksums.txt", "browser_download_url": base + "checksums.txt"},
		}
		if !f.noSig {
			assets = append(assets, map[string]string{"name": "checksums.txt.sig", "browser_download_url": base + "checksums.txt.sig"})
		}
		json.NewEncoder(w).Encode(map[string]any{"tag_name": f.tag, "html_url": "https://github.com/o/r/releases/tag/" + f.tag, "body": "notes", "assets": assets})
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, f.sums) })
	mux.HandleFunc("/dl/checksums.txt.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(f.sig) })
	mux.HandleFunc("/dl/"+assetName(), func(w http.ResponseWriter, r *http.Request) {
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		w.Write(f.binary)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) resign() {
	sum := sha256.Sum256(f.binary)
	f.sums = hex.EncodeToString(sum[:]) + "  " + assetName() + "\n" + strings.Repeat("0", 64) + "  other_file\n"
	f.sig = ed25519.Sign(f.priv, []byte(f.sums))
}

func (f *fakeGitHub) updater(t *testing.T, current string) *Updater {
	u := New("o/r", t.TempDir(), current)
	u.API, u.Key = f.srv.URL, f.pub
	u.AllowURL = func(p *url.URL) bool { return p.Hostname() == "127.0.0.1" }
	return u
}

func TestInstallStagesAVerifiedUpdate(t *testing.T) {
	f := newFake(t, "v0.2.0")
	u := f.updater(t, "0.1.1")
	rel, err := u.Latest(context.Background(), true)
	if err != nil || rel.Version != "0.2.0" || rel.Notes != "notes" {
		t.Fatalf("latest: %+v %v", rel, err)
	}
	if err := u.Install(context.Background(), rel); err != nil {
		t.Fatal(err)
	}
	if tag, ok := u.Staged(); !ok || tag != "v0.2.0" {
		t.Fatalf("staged: %q %v", tag, ok)
	}
	b, _ := os.ReadFile(filepath.Join(u.Dir, "update", "meshpanel"))
	if string(b) != string(f.binary) {
		t.Fatal("staged binary differs")
	}
	if fi, _ := os.Stat(filepath.Join(u.Dir, "update", "meshpanel")); fi.Mode().Perm()&0o100 == 0 {
		t.Fatal("staged binary is not executable")
	}
}

func TestInstallRefusals(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(f *fakeGitHub){
		"signed by another key": func(f *fakeGitHub) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.sig = ed25519.Sign(other, []byte(f.sums))
		},
		"checksums edited after signing": func(f *fakeGitHub) { f.sums = strings.Replace(f.sums, "0", "1", 1) },
		"binary swapped":                 func(f *fakeGitHub) { f.binary = []byte("evil") },
		"unsigned release":               func(f *fakeGitHub) { f.noSig = true },
		"truncated signature":            func(f *fakeGitHub) { f.sig = f.sig[:10] },
		"redirect off GitHub":            func(f *fakeGitHub) { f.redirect = "http://evil.example/meshpanel" },
	}
	for name, corrupt := range cases {
		f := newFake(t, "v0.2.0")
		corrupt(f)
		u := f.updater(t, "0.1.1")
		rel, err := u.Latest(ctx, true)
		if err != nil {
			t.Fatalf("%s: latest: %v", name, err)
		}
		if err := u.Install(ctx, rel); err == nil {
			t.Errorf("%s: installed", name)
		}
		if _, ok := u.Staged(); ok {
			t.Errorf("%s: something was staged", name)
		}
		if _, err := os.Stat(filepath.Join(u.Dir, "update", "meshpanel")); err == nil {
			t.Errorf("%s: a binary was left behind", name)
		}
	}
}

func TestNoDowngradeNoDevBuild(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, "v0.1.1")
	for _, cur := range []string{"0.1.1", "0.2.0"} {
		u := f.updater(t, cur)
		rel, _ := u.Latest(ctx, true)
		if err := u.Install(ctx, rel); err != ErrNotNewer {
			t.Errorf("current %s: %v", cur, err)
		}
	}
	f = newFake(t, "v0.2.0")
	for _, cur := range []string{"dev", "0.1.1-3-g62a4f3b-dirty", ""} {
		u := f.updater(t, cur)
		rel, _ := u.Latest(ctx, true)
		if err := u.Install(ctx, rel); err != ErrDevBuild {
			t.Errorf("dev build %q: %v", cur, err)
		}
	}
}

func TestStagedIsReverifiedAtStartup(t *testing.T) {
	f := newFake(t, "v0.2.0")
	u := f.updater(t, "0.1.1")
	rel, _ := u.Latest(context.Background(), true)
	if err := u.Install(context.Background(), rel); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(u.Dir, "update", "meshpanel")
	if _, _, err := staged(u.Dir, "0.1.1", f.pub); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(bin, []byte("tampered"), 0o755)
	if _, _, err := staged(u.Dir, "0.1.1", f.pub); err == nil {
		t.Fatal("a tampered staged binary verified")
	}
	// A different release key (or an edited signature) fails too.
	f2 := newFake(t, "v0.2.0")
	_ = f2
	u.Install(context.Background(), rel)
	if _, _, err := staged(u.Dir, "0.1.1", f2.pub); err == nil {
		t.Fatal("staged update verified under the wrong key")
	}
	// Once the installed version catches up, the stage is not newer.
	if _, _, err := staged(u.Dir, "0.2.0", f.pub); err != ErrNotNewer {
		t.Fatalf("caught-up: %v", err)
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"v0.1.2", "0.1.1", true}, {"0.1.1", "0.1.1", false}, {"0.10.0", "0.9.9", true}, {"1.0.0", "0.99.99", true}, {"0.1.0", "0.1.1", false}, {"v0.2.0-rc1", "0.1.0", false}, {"0.2.0", "dev", false}} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

func TestEmbeddedKey(t *testing.T) {
	if k := PublicKey(); len(k) != ed25519.PublicKeySize {
		t.Fatalf("embedded release key is %d bytes", len(k))
	}
}

func TestGithubOnly(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://github.com/o/r/releases/download/v1/x":                    true,
		"https://api.github.com/repos/o/r/releases/latest":                 true,
		"https://release-assets.githubusercontent.com/github-production/x": true,
		"http://github.com/x":                 false,
		"https://github.com.evil.example/x":   false,
		"https://evilgithubusercontent.com/x": false,
		"https://example.com/x":               false,
	} {
		p, _ := url.Parse(raw)
		if got := githubOnly(p); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
}

// execStaged replaces the process, so run it in a child: the test binary
// itself, told by the environment to do nothing but switch to the stage.
func TestExecStagedSwitchesToVerifiedBinary(t *testing.T) {
	if dir := os.Getenv("UPDATE_EXEC_DIR"); dir != "" {
		pub, _ := hex.DecodeString(os.Getenv("UPDATE_EXEC_PUB"))
		execStaged(dir, "0.1.1", ed25519.PublicKey(pub))
		os.Exit(3) // reaching here means the exec did not happen
	}
	for _, tamper := range []bool{false, true} {
		f := newFake(t, "v0.2.0")
		marker := filepath.Join(t.TempDir(), "ran")
		f.binary = []byte("#!/bin/sh\necho \"switched $*\" > " + marker + "\n")
		f.resign()
		u := f.updater(t, "0.1.1")
		rel, _ := u.Latest(context.Background(), true)
		if err := u.Install(context.Background(), rel); err != nil {
			t.Fatal(err)
		}
		if tamper {
			os.WriteFile(filepath.Join(u.Dir, "update", "meshpanel"), []byte("#!/bin/sh\necho evil > "+marker+"\n"), 0o755)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestExecStagedSwitchesToVerifiedBinary$", "serve", "-c", "x.yaml")
		cmd.Env = append(os.Environ(), "UPDATE_EXEC_DIR="+u.Dir, "UPDATE_EXEC_PUB="+hex.EncodeToString(f.pub))
		err := cmd.Run()
		got, _ := os.ReadFile(marker)
		if !tamper && (err != nil || !strings.HasPrefix(string(got), "switched") || !strings.Contains(string(got), "serve -c x.yaml")) {
			t.Fatalf("verified update did not take over (err=%v marker=%q)", err, got)
		}
		if tamper && len(got) != 0 {
			t.Fatalf("a tampered staged binary was executed: %q", got)
		}
	}
}

// Once the staged version is running it must stay staged: the next restart
// starts the installed binary, which has to switch to it again. Only a newer
// installed package makes the stage obsolete.
func TestStageSurvivesUntilThePackageCatchesUp(t *testing.T) {
	f := newFake(t, "v0.2.0")
	u := f.updater(t, "0.1.1")
	rel, _ := u.Latest(context.Background(), true)
	if err := u.Install(context.Background(), rel); err != nil {
		t.Fatal(err)
	}
	version := filepath.Join(u.Dir, "update", "VERSION")
	for _, running := range []string{"0.2.0", "v0.2.0"} { // running the staged copy itself
		execStaged(u.Dir, running, f.pub)
		if _, err := os.Stat(version); err != nil {
			t.Fatalf("stage deleted while running %s: %v", running, err)
		}
	}
	execStaged(u.Dir, "0.2.1", f.pub) // the package was upgraded past it
	if _, err := os.Stat(version); err == nil {
		t.Fatal("obsolete stage kept")
	}
}
