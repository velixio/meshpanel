package update

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"testing"
)

func TestHeadscalePatchPolicy(t *testing.T) {
	for _, tt := range []struct {
		from, to string
		allowed  bool
	}{{"v0.29.3", "v0.29.7", true}, {"0.29.7", "v0.29.7", false}, {"0.29.7", "v0.29.3", false}, {"0.29.3", "v0.30.0", false}, {"dev", "v0.29.7", false}, {"0.29.3", "v0.29.8-rc1", false}} {
		if got := HeadscaleUpgradeReason(tt.from, tt.to) == ""; got != tt.allowed {
			t.Errorf("%s -> %s allowed=%v", tt.from, tt.to, got)
		}
	}
}

func TestHeadscaleDownloadVerification(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux binaries")
	}
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			payload := []byte("upstream binary")
			sum := sha256.Sum256(payload)
			name := fmt.Sprintf("headscale_0.29.7_linux_%s", runtime.GOARCH)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sums" {
					fmt.Fprintf(w, "%x  %s\n", sum, name)
				} else {
					if bad {
						w.Write([]byte("tampered"))
					} else {
						w.Write(payload)
					}
				}
			}))
			defer srv.Close()
			u := NewHeadscale("0.29.3")
			u.AllowURL = func(p *url.URL) bool { return p.Host == srv.Listener.Addr().String() }
			rel := &Release{Tag: "v0.29.7", Version: "0.29.7", assets: map[string]string{name: srv.URL + "/binary", "checksums.txt": srv.URL + "/sums"}}
			path, err := u.DownloadHeadscale(context.Background(), rel, t.TempDir())
			if bad {
				if err == nil {
					t.Fatal("accepted tampered binary")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(path)
			if string(b) != string(payload) {
				t.Fatal("wrong binary")
			}
		})
	}
}
