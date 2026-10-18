package registration

import (
	"regexp"
	"strings"
)

var (
	iosRe     = regexp.MustCompile(`(iPhone|iPad); CPU (?:iPhone )?OS (\d+)_(\d+)`)
	androidRe = regexp.MustCompile(`Android (\d+(?:\.\d+)?)(?:; ([^;)]+))?`)
)

// DescribeUA turns the registering browser's user agent into a short device
// description for approval cards. headscale does not expose the pending
// node's hostname, so this is the best context available before approval.
func DescribeUA(ua string) string {
	switch {
	case ua == "":
		return "Unknown device"
	case iosRe.MatchString(ua):
		m := iosRe.FindStringSubmatch(ua)
		return m[1] + " · iOS " + m[2] + "." + m[3]
	case androidRe.MatchString(ua):
		m := androidRe.FindStringSubmatch(ua)
		s := "Android " + m[1]
		if model := strings.TrimSpace(m[2]); model != "" && model != "K" {
			s += " · " + model
		}
		return s
	case strings.Contains(ua, "Macintosh"):
		return "Mac · macOS"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "CrOS"):
		return "ChromeOS"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	return "Unknown device"
}
