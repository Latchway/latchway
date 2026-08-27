package upstream

import (
	"errors"
	"net/http"
	"strings"
)

const maximumForwardedHeaderBytes = 32 << 10

var singletonRequestHeaders = [...]string{
	"Accept",
	"Authorization",
	"Content-Encoding",
	"Content-Type",
	"Dpop",
	"Dpop-Nonce",
	"Expect",
}

var forbiddenHeaders = map[string]struct{}{
	"Accept-Encoding":     {},
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Dpop":                {},
	"Dpop-Nonce":          {},
	"Connection":          {},
	"Content-Encoding":    {},
	"Content-Length":      {},
	"Expect":              {},
	"Host":                {},
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
	"X-Auth-Token":        {},
}

// ForwardHeaders constructs a new outbound header map from an explicit
// allowlist. Incoming credentials and Latchway control headers are never copied.
func ForwardHeaders(incoming http.Header, allowlist []string) (http.Header, error) {
	if err := validateSingletonRequestHeaders(incoming); err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if strings.TrimSpace(name) != name || !validHeaderName(name) {
			return nil, errors.New("header allowlist contains an empty name")
		}
		if isForbiddenHeader(canonical) {
			return nil, errors.New("header allowlist contains a forbidden name")
		}
		allowed[canonical] = struct{}{}
	}
	connectionTokens := make(map[string]struct{})
	for _, value := range headerValues(incoming, "Connection") {
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
			if !validHeaderValue(value) {
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

// ApplyStaticHeaders applies administrator-owned values only after untrusted
// request headers have been reconstructed. Static values may override an
// explicitly forwarded application header, but never a transport control,
// credential, or Latchway control header.
func ApplyStaticHeaders(headers http.Header, values map[string]string) error {
	if headers == nil || len(values) > 32 {
		return errors.New("invalid static headers")
	}
	totalBytes := 0
	seen := make(map[string]struct{}, len(values))
	for name, value := range values {
		canonical := http.CanonicalHeaderKey(name)
		totalBytes += len(canonical) + len(value)
		if strings.TrimSpace(name) != name || !validHeaderName(name) || isForbiddenStaticHeader(canonical) || !validStaticHeaderValue(value) || totalBytes > maximumForwardedHeaderBytes {
			return errors.New("invalid static headers")
		}
		if _, duplicate := seen[canonical]; duplicate {
			return errors.New("invalid static headers")
		}
		seen[canonical] = struct{}{}
	}
	for name, value := range values {
		canonical := http.CanonicalHeaderKey(name)
		headers.Del(canonical)
		headers.Set(canonical, value)
	}
	return nil
}

func validateSingletonRequestHeaders(headers http.Header) error {
	for _, name := range singletonRequestHeaders {
		if len(headerValues(headers, name)) > 1 {
			return errors.New("request contains a duplicate singleton header")
		}
	}
	return nil
}

func headerValues(headers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range headers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func validBearerCredential(credential []byte) bool {
	if len(credential) == 0 || len(credential) > maximumForwardedHeaderBytes {
		return false
	}
	padding := false
	for _, character := range credential {
		if character == '=' {
			padding = true
			continue
		}
		if padding || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._~+/", rune(character))) {
			return false
		}
	}
	return true
}

func validHeaderCredential(credential []byte) bool {
	if len(credential) == 0 || len(credential) > maximumForwardedHeaderBytes {
		return false
	}
	for _, character := range credential {
		if (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}
	return true
}

func validStaticHeaderValue(value string) bool {
	return len(value) <= 2048 && validHeaderValue(value)
}

func validHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		if (value[index] < 0x20 && value[index] != '\t') || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func isForbiddenHeader(name string) bool {
	if strings.HasPrefix(strings.ToLower(name), "x-latchway-") {
		return true
	}
	_, forbidden := forbiddenHeaders[http.CanonicalHeaderKey(name)]
	return forbidden
}

func isForbiddenStaticHeader(name string) bool {
	if isForbiddenHeader(name) {
		return true
	}
	switch http.CanonicalHeaderKey(name) {
	case "Accept", "Content-Type":
		return true
	default:
		return false
	}
}

func isForbiddenCredentialHeader(name string) bool {
	if strings.HasPrefix(strings.ToLower(name), "x-latchway-") {
		return true
	}
	switch http.CanonicalHeaderKey(name) {
	case "Accept", "Accept-Encoding", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
		"Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return true
	default:
		return false
	}
}
