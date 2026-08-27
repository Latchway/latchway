package upstream

import (
	"errors"
	"net/http"
	"strings"
)

const maximumForwardedHeaderBytes = 32 << 10

var forbiddenHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Transfer-Encoding":   {},
	"Te":                  {},
	"Trailer":             {},
	"Upgrade":             {},
	"X-Api-Key":           {},
	"Api-Key":             {},
	"Openai-Api-Key":      {},
	"Openai-Organization": {},
	"Anthropic-Api-Key":   {},
	"Cookie":              {},
	"Forwarded":           {},
	"Set-Cookie":          {},
	"X-Forwarded-For":     {},
	"X-Forwarded-Host":    {},
	"X-Forwarded-Proto":   {},
	"X-Goog-Api-Key":      {},
}

// ForwardHeaders constructs a new outbound header map from an explicit
// allowlist. Incoming credentials and Latchway control headers are never copied.
func ForwardHeaders(incoming http.Header, allowlist []string) (http.Header, error) {
	allowed := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" {
			return nil, errors.New("header allowlist contains an empty name")
		}
		if isForbiddenHeader(canonical) {
			return nil, errors.New("header allowlist contains a forbidden name")
		}
		allowed[canonical] = struct{}{}
	}
	connectionTokens := make(map[string]struct{})
	for _, value := range incoming.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			connectionTokens[http.CanonicalHeaderKey(strings.TrimSpace(token))] = struct{}{}
		}
	}
	outbound := make(http.Header)
	totalBytes := 0
	for name, values := range incoming {
		canonical := http.CanonicalHeaderKey(name)
		if _, ok := allowed[canonical]; !ok || isForbiddenHeader(canonical) {
			continue
		}
		if _, hopByHop := connectionTokens[canonical]; hopByHop {
			continue
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return nil, errors.New("header value contains a line break")
			}
			totalBytes += len(canonical) + len(value)
			if totalBytes > maximumForwardedHeaderBytes {
				return nil, errors.New("forwarded headers exceed size limit")
			}
			outbound.Add(canonical, value)
		}
	}
	return outbound, nil
}

// ApplyBearerCredential injects a server-held bearer secret after all incoming
// authorization values have been discarded.
func ApplyBearerCredential(headers http.Header, credential []byte) error {
	if len(credential) == 0 || strings.ContainsAny(string(credential), "\r\n") {
		return errors.New("invalid bearer credential")
	}
	headers.Del("Authorization")
	headers.Set("Authorization", "Bearer "+string(credential))
	return nil
}

func isForbiddenHeader(name string) bool {
	if strings.HasPrefix(strings.ToLower(name), "x-latchway-") {
		return true
	}
	_, forbidden := forbiddenHeaders[http.CanonicalHeaderKey(name)]
	return forbidden
}
