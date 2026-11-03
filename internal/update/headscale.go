package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// NewHeadscale checks upstream Headscale releases. Its downloads use upstream
// checksums over HTTPS, not Meshpanel's release signing key.
func NewHeadscale(current string) *Updater { return New("juanfont/headscale", "", current) }

// HeadscaleUpgradeReason limits automatic installs to patch updates. Minor
// upgrades can require configuration changes and must be performed manually.
func HeadscaleUpgradeReason(current, target string) string {
	a, ok := ParseVersion(current)
	b, valid := ParseVersion(target)
	if !ok || !valid {
		return "The current and target versions must be stable releases."
	}
	if !Newer(target, current) {
		return "No newer release is available."
	}
	if a[0] != b[0] || a[1] != b[1] {
		return "This release changes the major or minor version. Follow Headscale's manual upgrade instructions."
	}
	return ""
}

// DownloadHeadscale downloads and verifies the exact release into a private
// temporary directory. Callers must remove that directory after use.
func (u *Updater) DownloadHeadscale(ctx context.Context, rel *Release, dir string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("Headscale binary updates require Linux")
	}
	if reason := HeadscaleUpgradeReason(u.Current, rel.Tag); reason != "" {
		return "", errors.New(reason)
	}
	name := fmt.Sprintf("headscale_%s_linux_%s", rel.Version, runtime.GOARCH)
	binURL, ok := rel.assets[name]
	sumsURL, sumsOK := rel.assets["checksums.txt"]
	if !ok || !sumsOK {
		return "", errors.New("the release has no binary/checksum for this architecture")
	}
	sums, err := u.get(ctx, sumsURL, maxSmall, "")
	if err != nil {
		return "", err
	}
	want, ok := checksumFor(sums, name)
	if !ok {
		return "", errors.New("Headscale binary is missing from checksums.txt")
	}
	resp, err := u.do(ctx, binURL, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	path := filepath.Join(dir, "headscale")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinary+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if n > maxBinary || hex.EncodeToString(h.Sum(nil)) != want {
		return "", errors.New("Headscale download failed checksum verification")
	}
	return path, nil
}
