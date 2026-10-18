package registration

import "testing"

func TestDescribeUA(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15": "iPhone · iOS 18.0",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36":                 "Android 14 · Pixel 8",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15":        "Mac · macOS",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)":                                   "Windows",
		"Mozilla/5.0 (X11; Linux x86_64)":                                             "Linux",
		"":                                                                            "Unknown device",
	} {
		if got := DescribeUA(ua); got != want {
			t.Errorf("%q → %q, want %q", ua, got, want)
		}
	}
}
