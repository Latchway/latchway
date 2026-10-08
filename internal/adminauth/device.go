package adminauth

import "strings"

// DeviceSummaryFromUserAgent reduces a browser User-Agent to a coarse
// "Browser on OS" phrase for session lists. Versions, device models and the raw
// header are discarded. It returns "" when neither part is recognized.
func DeviceSummaryFromUserAgent(userAgent string) string {
	if len(userAgent) > 1024 {
		userAgent = userAgent[:1024]
	}
	browser := userAgentBrowser(userAgent)
	system := userAgentSystem(userAgent)
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return "Browser on " + system
	default:
		return ""
	}
}

func userAgentBrowser(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "Edg/") || strings.Contains(userAgent, "EdgA/") || strings.Contains(userAgent, "EdgiOS/"):
		return "Edge"
	case strings.Contains(userAgent, "OPR/") || strings.Contains(userAgent, "OPiOS/"):
		return "Opera"
	case strings.Contains(userAgent, "Firefox/") || strings.Contains(userAgent, "FxiOS/"):
		return "Firefox"
	case strings.Contains(userAgent, "CriOS/") || strings.Contains(userAgent, "Chrome/") || strings.Contains(userAgent, "Chromium/"):
		return "Chrome"
	case strings.Contains(userAgent, "Safari/") && strings.Contains(userAgent, "Version/"):
		return "Safari"
	case strings.HasPrefix(userAgent, "curl/"):
		return "curl"
	default:
		return ""
	}
}

func userAgentSystem(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad") || strings.Contains(userAgent, "iPod"):
		return "iOS"
	case strings.Contains(userAgent, "Android"):
		return "Android"
	case strings.Contains(userAgent, "CrOS"):
		return "ChromeOS"
	case strings.Contains(userAgent, "Windows"):
		return "Windows"
	case strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS X"):
		return "macOS"
	case strings.Contains(userAgent, "Linux") || strings.Contains(userAgent, "X11"):
		return "Linux"
	default:
		return ""
	}
}
