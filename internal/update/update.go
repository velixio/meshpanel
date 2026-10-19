// Package update installs newer meshpanel releases from GitHub, but only
// ones signed with the release key built into this binary. A release's
// checksums.txt carries an ed25519 signature (checksums.txt.sig); the binary
// is trusted only if its sha256 appears in that signed file. The download is
// staged beside the database and the next start switches to it, so the
// service needs no write access to its own executable.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed signing.pub
var embeddedKey string

// DefaultRepo is where releases come from unless update.repo says otherwise.
const DefaultRepo = "velixio/meshpanel"

const (
	maxBinary = 150 << 20
	maxSmall  = 1 << 20
	cacheFor  = 15 * time.Minute
)

var (
	ErrBadSignature = errors.New("the release's signature does not match meshpanel's release key; refusing to install")
	ErrNotNewer     = errors.New("that release is not newer than the running version")
	ErrDevBuild     = errors.New("this is a development build; updates are for released versions")
	ErrNoAsset      = errors.New("the release has no binary for this machine")
)

// Release is the latest published release.
type Release struct {
	Tag       string
	Version   string // Tag without the leading v
	URL       string
	Notes     string
	Published time.Time
	assets    map[string]string // name → download URL
}

// Updater checks for and stages updates.
type Updater struct {
	Repo    string
	Dir     string // staging lives in Dir/update
	Current string
	Key     ed25519.PublicKey
	API     string
	HTTP    *http.Client
	// Restart asks the running server to shut down and start again. It is
	// called after a successful Install.
	Restart func()

	// AllowURL decides which download locations are acceptable (GitHub over
	// https). Only tests change it.
	AllowURL func(*url.URL) bool

	mu       sync.Mutex
	cached   *Release
	cachedAt time.Time
	lastErr  error
}

// PublicKey returns the key built into the binary.
func PublicKey() ed25519.PublicKey {
	b, err := hex.DecodeString(strings.TrimSpace(embeddedKey))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}

func New(repo, dir, current string) *Updater {
	if repo == "" {
		repo = DefaultRepo
	}
	u := &Updater{Repo: repo, Dir: dir, Current: current, Key: PublicKey(), API: "https://api.github.com", AllowURL: githubOnly}
	u.HTTP = &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || !u.AllowURL(req.URL) {
				return fmt.Errorf("refusing to follow a redirect to %s", req.URL.Host)
			}
			return nil
		},
	}
	return u
}

// githubOnly accepts https URLs on GitHub's own hosts.
func githubOnly(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	return u.Scheme == "https" && (h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".githubusercontent.com"))
}

// ---------- versions ----------

var verRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// ParseVersion reads a plain release version (0.1.2 or v0.1.2). Development
// builds (0.1.1-3-g62a4f3b-dirty, dev) don't parse.
func ParseVersion(s string) ([3]int, bool) {
	m := verRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// Newer reports whether a is a higher release version than b.
func Newer(a, b string) bool {
	x, ok1 := ParseVersion(a)
	y, ok2 := ParseVersion(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}

// Updatable says whether this binary can be updated in place.
func (u *Updater) Updatable() error {
	if runtime.GOOS != "linux" {
		return errors.New("in-app updates are only available on Linux")
	}
	if _, ok := ParseVersion(u.Current); !ok {
		return ErrDevBuild
	}
	if len(u.Key) != ed25519.PublicKeySize {
		return errors.New("this build has no release key")
	}
	return nil
}

// assetName is the bare binary published for this machine.
func assetName() string {
	switch runtime.GOARCH {
	case "arm":
		return "meshpanel_linux_armv7"
	default:
		return "meshpanel_linux_" + runtime.GOARCH
	}
}

// ---------- checking ----------

// Cached returns the last check without touching the network.
func (u *Updater) Cached() (*Release, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.cached, u.lastErr
}

// Latest asks GitHub for the newest release (at most every 15 minutes unless force).
func (u *Updater) Latest(ctx context.Context, force bool) (*Release, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !force && u.cached != nil && time.Since(u.cachedAt) < cacheFor {
		return u.cached, nil
	}
	rel, err := u.fetchLatest(ctx)
	u.lastErr = err
	if err != nil {
		return u.cached, err
	}
	u.cached, u.cachedAt = rel, time.Now()
	return rel, nil
}

func (u *Updater) fetchLatest(ctx context.Context) (*Release, error) {
	body, err := u.get(ctx, u.API+"/repos/"+u.Repo+"/releases/latest", maxSmall, "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	var j struct {
		Tag       string    `json:"tag_name"`
		URL       string    `json:"html_url"`
		Body      string    `json:"body"`
		Published time.Time `json:"published_at"`
		Draft     bool      `json:"draft"`
		Pre       bool      `json:"prerelease"`
		Assets    []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &j); err != nil {
		return nil, fmt.Errorf("reading the release: %w", err)
	}
	if j.Draft || j.Pre {
		return nil, errors.New("the latest release is not a final release")
	}
	if _, ok := ParseVersion(j.Tag); !ok {
		return nil, fmt.Errorf("unexpected release tag %q", j.Tag)
	}
	rel := &Release{Tag: j.Tag, Version: strings.TrimPrefix(j.Tag, "v"), URL: j.URL, Notes: j.Body, Published: j.Published, assets: map[string]string{}}
	for _, a := range j.Assets {
		rel.assets[a.Name] = a.URL
	}
	return rel, nil
}

// get fetches a small body from an allowed location.
func (u *Updater) get(ctx context.Context, rawurl string, max int64, accept string) ([]byte, error) {
	resp, err := u.do(ctx, rawurl, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("response is larger than expected")
	}
	return b, nil
}

func (u *Updater) do(ctx context.Context, rawurl, accept string) (*http.Response, error) {
	pu, err := url.Parse(rawurl)
	if err != nil || !u.AllowURL(pu) {
		return nil, fmt.Errorf("refusing to download from %q", rawurl)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "meshpanel/"+u.Current)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := u.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, pu.Host)
	}
	return resp, nil
}

// ---------- verifying ----------

func verifySignature(key ed25519.PublicKey, sums, sig []byte) error {
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, sums, sig) {
		return ErrBadSignature
	}
	return nil
}

// checksumFor finds name's sha256 in a checksums.txt ("<hex>  <name>").
func checksumFor(sums []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// ---------- installing ----------

func (u *Updater) stageDir() string { return filepath.Join(u.Dir, "update") }

// Install downloads rel, verifies it and stages it for the next start. It
// installs nothing unless the signature and the checksum both check out.
func (u *Updater) Install(ctx context.Context, rel *Release) error {
	if err := u.Updatable(); err != nil {
		return err
	}
	if !Newer(rel.Tag, u.Current) {
		return ErrNotNewer
	}
	name := assetName()
	binURL, ok := rel.assets[name]
	sumsURL, ok2 := rel.assets["checksums.txt"]
	sigURL, ok3 := rel.assets["checksums.txt.sig"]
	if !ok || !ok2 || !ok3 {
		if !ok {
			return ErrNoAsset
		}
		return errors.New("the release is not signed (no checksums.txt.sig); refusing to install")
	}
	sums, err := u.get(ctx, sumsURL, maxSmall, "")
	if err != nil {
		return fmt.Errorf("downloading checksums: %w", err)
	}
	sig, err := u.get(ctx, sigURL, 1024, "")
	if err != nil {
		return fmt.Errorf("downloading signature: %w", err)
	}
	if err := verifySignature(u.Key, sums, sig); err != nil {
		return err
	}
	want, ok := checksumFor(sums, name)
	if !ok {
		return fmt.Errorf("%s is not listed in the signed checksums", name)
	}

	dir := u.stageDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("preparing %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	resp, err := u.do(ctx, binURL, "")
	if err != nil {
		tmp.Close()
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinary+1))
	resp.Body.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	if n > maxBinary {
		return errors.New("the binary is larger than expected")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("the downloaded binary does not match the signed checksum (got %.12s…, want %.12s…); refusing to install", got, want)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	// Commit: binary first, the version marker last, so a half-written stage
	// is never picked up.
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), sums, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt.sig"), sig, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, "meshpanel")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(rel.Tag+"\n"), 0o640); err != nil {
		return err
	}
	slog.Info("update staged", "version", rel.Tag, "dir", dir)
	return nil
}

// Staged describes an update waiting for the next start.
func (u *Updater) Staged() (string, bool) {
	_, tag, err := staged(u.Dir, u.Current, u.Key)
	return tag, err == nil
}

// staged re-verifies everything on disk: the signature, then the binary's
// hash against the signed list. Nothing in the state directory is trusted.
func staged(dir, current string, key ed25519.PublicKey) (bin, tag string, err error) {
	d := filepath.Join(dir, "update")
	vb, err := os.ReadFile(filepath.Join(d, "VERSION"))
	if err != nil {
		return "", "", err
	}
	tag = strings.TrimSpace(string(vb))
	if !Newer(tag, current) {
		return "", "", ErrNotNewer
	}
	sums, err := os.ReadFile(filepath.Join(d, "checksums.txt"))
	if err != nil {
		return "", "", err
	}
	sig, err := os.ReadFile(filepath.Join(d, "checksums.txt.sig"))
	if err != nil {
		return "", "", err
	}
	if err := verifySignature(key, sums, sig); err != nil {
		return "", "", err
	}
	want, ok := checksumFor(sums, assetName())
	if !ok {
		return "", "", ErrNoAsset
	}
	bin = filepath.Join(d, "meshpanel")
	f, err := os.Open(bin)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return "", "", errors.New("the staged binary does not match the signed checksum")
	}
	return bin, tag, nil
}

// ExecStaged switches to a staged update, if there is a valid newer one. It
// returns only when there is nothing to switch to or the switch failed.
func ExecStaged(dir, current string) { execStaged(dir, current, PublicKey()) }

func execStaged(dir, current string, key ed25519.PublicKey) {
	if _, ok := ParseVersion(current); !ok {
		return
	}
	if vb, err := os.ReadFile(filepath.Join(dir, "update", "VERSION")); err == nil {
		tag := strings.TrimSpace(string(vb))
		if tag == "v"+strings.TrimPrefix(current, "v") {
			return // this process is the staged update: keep it for the next restart
		}
		if Newer(current, tag) {
			os.RemoveAll(filepath.Join(dir, "update")) // the installed package caught up
			return
		}
	}
	bin, tag, err := staged(dir, current, key)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("ignoring a staged update that does not verify", "err", err)
		}
		return
	}
	slog.Info("starting the staged update", "from", current, "to", tag)
	args := append([]string{bin}, os.Args[1:]...)
	if err := syscall.Exec(bin, args, os.Environ()); err != nil {
		slog.Error("could not start the staged update; continuing with the current version", "err", err)
	}
}
