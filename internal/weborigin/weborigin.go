// Package weborigin owns strict browser Origin and CORS header parsing shared
// by the public session and data-plane transports. CORS is only a browser
// delivery permission; durable authorization still performs an exact
// configured-origin check after resolving the session scope.
package weborigin

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maximumOriginBytes          = 2048
	maximumRequestedHeaderBytes = 4096
	maximumRequestedHeaders     = 64
)

var ErrInvalid = errors.New("browser origin headers are invalid")

// Read returns an exact canonical HTTPS browser origin. Absence is valid and
// represented by an empty string; duplicates, comma lists, null origins, and
// non-canonical aliases fail closed.
func Read(header http.Header) (string, error) {
	if header == nil {
		return "", nil
	}
	values := header.Values("Origin")
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || !Canonical(values[0]) {
		return "", ErrInvalid
	}
	return values[0], nil
}

// Canonical reports whether value is an exact browser HTTPS origin
// serialization suitable for byte-for-byte allow-list membership.
func Canonical(value string) bool {
	if value == "" || len(value) > maximumOriginBytes || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\r\n\x00,") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= ' ' || value[index] >= 0x7f {
			return false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.String() != value ||
		parsed.Host != strings.ToLower(parsed.Host) || strings.Contains(parsed.Host, "%") ||
		strings.HasSuffix(parsed.Hostname(), ".") {
		return false
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || parsedPort == 0 || parsedPort == 443 ||
			strconv.FormatUint(parsedPort, 10) != port {
			return false
		}
	} else if strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	hostname := parsed.Hostname()
	if address := net.ParseIP(hostname); address != nil {
		return address.String() == hostname
	}
	if strings.IndexFunc(hostname, func(character rune) bool {
		return (character < '0' || character > '9') && character != '.'
	}) == -1 {
		// A numeric-looking host that is not a canonical IP address would be
		// normalized differently by browsers and cannot be an exact Origin.
		return false
	}
	if len(hostname) > 253 || strings.Contains(hostname, "..") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || !asciiAlphaNumeric(label[0]) ||
			!asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index+1 < len(label); index++ {
			if !asciiAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// SetResponseHeaders exposes only the headers needed by the SDK. It never
// enables cookie credentials and reflects only a value already accepted by
// Read.
func SetResponseHeaders(header http.Header, origin string) {
	if header == nil || !Canonical(origin) {
		return
	}
	header.Set("Access-Control-Allow-Origin", origin)
	header.Set("Access-Control-Expose-Headers", "DPoP-Nonce, Retry-After, X-Latchway-Request-ID")
	AppendVary(header, "Origin")
}

// RequestedMethod parses the one method declared by a CORS preflight.
func RequestedMethod(header http.Header) (string, error) {
	values := header.Values("Access-Control-Request-Method")
	if len(values) != 1 || !canonicalMethod(values[0]) {
		return "", ErrInvalid
	}
	return values[0], nil
}

// RequestedHeaders parses a bounded, unique, lowercase-normalized CORS header
// list. Header policy remains the caller's responsibility.
func RequestedHeaders(header http.Header) ([]string, error) {
	values := header.Values("Access-Control-Request-Headers")
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 || len(values[0]) > maximumRequestedHeaderBytes || values[0] == "" ||
		strings.ContainsAny(values[0], "\r\n\x00") {
		return nil, ErrInvalid
	}
	parts := strings.Split(values[0], ",")
	if len(parts) == 0 || len(parts) > maximumRequestedHeaders {
		return nil, ErrInvalid
	}
	seen := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		if !headerToken(name) {
			return nil, ErrInvalid
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, ErrInvalid
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result, nil
}

func canonicalMethod(method string) bool {
	if method == "" || len(method) > 16 {
		return false
	}
	for index := 0; index < len(method); index++ {
		if method[index] < 'A' || method[index] > 'Z' {
			return false
		}
	}
	return true
}

func headerToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

// AppendVary adds a case-insensitive Vary member without erasing middleware
// or handler values that were already present.
func AppendVary(header http.Header, name string) {
	if header == nil || name == "" {
		return
	}
	for _, value := range header.Values("Vary") {
		for _, member := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(member), name) {
				return
			}
		}
	}
	header.Add("Vary", name)
}
