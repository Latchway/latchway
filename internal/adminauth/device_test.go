package adminauth

import (
	"strings"
	"testing"
)

func TestDeviceSummaryFromUserAgent(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36":                   "Chrome on macOS",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0":           "Edge on Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1": "Safari on iOS",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36":                   "Chrome on Android",
		"curl/8.7.1":              "curl",
		"Mozilla/5.0 (Macintosh)": "Browser on macOS",
		"":                        "",
		"some-agent/1.0":          "",
	}
	for userAgent, want := range cases {
		got := DeviceSummaryFromUserAgent(userAgent)
		if got != want {
			t.Errorf("DeviceSummaryFromUserAgent(%q) = %q, want %q", userAgent, got, want)
		}
		if got != "" && !deviceSummaryPattern.MatchString(got) {
			t.Errorf("summary %q does not satisfy the stored pattern", got)
		}
	}
	if got := DeviceSummaryFromUserAgent(strings.Repeat("x", 5000) + " Firefox/1"); got != "" {
		t.Errorf("oversized header summary = %q, want the tail ignored", got)
	}
}
