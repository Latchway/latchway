package dataplane

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/session"
)

const (
	chatCompletionsPath = "/v1/chat/completions"
	providerChatPath    = "/chat/completions"
	protocolVersion     = "1"

	maximumAccessTokenBytes = 16 << 10
	maximumDPoPProofBytes   = 16 << 10
)

var (
	identifierPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	requestHintPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

type declaration struct {
	sdk             string
	sdkVersion      string
	feature         string
	clientRequestID string
	accessToken     session.AccessToken
	dpopProof       session.DPoPProof
}

type violation struct {
	code       string
	detail     string
	fields     []problem.FieldError
	supported  []int
	allowValue string
}

func requestViolation(path, message string) *violation {
	return &violation{
		code:   "request_invalid",
		detail: "The request does not match the Latchway client protocol.",
		fields: []problem.FieldError{{Path: path, Message: message}},
	}
}

func validateEndpoint(request *http.Request) *violation {
	if request == nil || request.URL == nil {
		return requestViolation("request", "A valid HTTP request is required.")
	}
	if request.Method != http.MethodPost {
		result := requestViolation("method", "POST is required by this endpoint.")
		result.allowValue = http.MethodPost
		return result
	}
	if request.URL.Opaque != "" || request.URL.User != nil || request.URL.Fragment != "" ||
		request.URL.RawFragment != "" || request.URL.Path != chatCompletionsPath ||
		request.URL.RawPath != "" || request.URL.EscapedPath() != chatCompletionsPath {
		return requestViolation("path", "The canonical /v1/chat/completions path is required.")
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		return requestViolation("query", "Query parameters are not supported by this endpoint.")
	}
	return nil
}

func parseDeclaration(request *http.Request) (declaration, *violation) {
	version, ok := exactlyOneHeader(request.Header, "X-Latchway-Protocol-Version")
	if !ok || version != protocolVersion {
		return declaration{}, &violation{
			code:      "protocol_version_unsupported",
			detail:    "This gateway supports Latchway protocol version 1.",
			supported: []int{1},
		}
	}
	sdk, ok := exactlyOneHeader(request.Header, "X-Latchway-SDK")
	if !ok || !validSDK(sdk) {
		return declaration{}, requestViolation("header.X-Latchway-SDK", "A supported SDK identifier is required.")
	}
	sdkVersion, ok := exactlyOneHeader(request.Header, "X-Latchway-SDK-Version")
	if !ok || !validSemVer(sdkVersion) {
		return declaration{}, requestViolation("header.X-Latchway-SDK-Version", "A semantic SDK version is required.")
	}
	feature, ok := exactlyOneHeader(request.Header, "X-Latchway-Feature")
	if !ok || !identifierPattern.MatchString(feature) {
		return declaration{}, requestViolation("header.X-Latchway-Feature", "A canonical feature identifier is required.")
	}

	rawAuthorization, ok := exactlyOneHeader(request.Header, "Authorization")
	if !ok {
		return declaration{}, requestViolation("header.Authorization", "Exactly one DPoP access token is required.")
	}
	scheme, rawToken, found := strings.Cut(rawAuthorization, " ")
	if !found || !strings.EqualFold(scheme, "DPoP") || !validCredential(rawToken, 64, maximumAccessTokenBytes) {
		return declaration{}, requestViolation("header.Authorization", "Authorization must use exactly one bounded DPoP access token.")
	}
	accessToken, err := session.NewAccessToken(rawToken)
	if err != nil {
		return declaration{}, requestViolation("header.Authorization", "Authorization must use exactly one bounded DPoP access token.")
	}

	rawProof, proofValues := oneRawHeader(request.Header, "DPoP")
	if proofValues == 0 {
		return declaration{}, &violation{code: "dpop_missing", detail: "Exactly one DPoP proof is required."}
	}
	if proofValues != 1 || !validCompactProof(rawProof) {
		return declaration{}, &violation{code: "dpop_invalid", detail: "The DPoP proof header is invalid."}
	}
	dpopProof, err := session.NewDPoPProof(rawProof)
	if err != nil {
		return declaration{}, &violation{code: "dpop_invalid", detail: "The DPoP proof header is invalid."}
	}

	return declaration{
		sdk: sdk, sdkVersion: sdkVersion, feature: feature,
		clientRequestID: validClientRequestHint(request.Header),
		accessToken:     accessToken,
		dpopProof:       dpopProof,
	}, nil
}

func validSemVer(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	version, build, hasBuild := strings.Cut(value, "+")
	if hasBuild && !validSemVerIdentifiers(build, false) {
		return false
	}
	core, prerelease, hasPrerelease := strings.Cut(version, "-")
	if hasPrerelease && !validSemVerIdentifiers(prerelease, true) {
		return false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !validSemVerNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validSemVerIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for index := 0; index < len(identifier); index++ {
			character := identifier[index]
			if character >= '0' && character <= '9' {
				continue
			}
			numeric = false
			if !((character >= 'A' && character <= 'Z') ||
				(character >= 'a' && character <= 'z') || character == '-') {
				return false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func validSemVerNumericIdentifier(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func exactlyOneHeader(header http.Header, name string) (string, bool) {
	value, count := oneRawHeader(header, name)
	if count != 1 || value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00,") {
		return "", false
	}
	return value, true
}

func oneRawHeader(header http.Header, name string) (string, int) {
	var value string
	count := 0
	for candidate, values := range header {
		if !strings.EqualFold(candidate, name) {
			continue
		}
		for _, item := range values {
			value = item
			count++
		}
	}
	return value, count
}

func validCredential(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= ' ' || value[index] >= 0x7f || value[index] == ',' {
			return false
		}
	}
	return true
}

func validCompactProof(value string) bool {
	if !validCredential(value, 64, maximumDPoPProofBytes) || strings.Count(value, ".") != 2 {
		return false
	}
	segments := strings.Split(value, ".")
	return len(segments) == 3 && segments[0] != "" && segments[1] != "" && segments[2] != ""
}

func validSDK(value string) bool {
	switch value {
	case "ios", "android", "javascript", "react-native":
		return true
	default:
		return false
	}
}

func sdkMatchesPlatform(sdk, platform string) bool {
	switch sdk {
	case "ios":
		return platform == "ios"
	case "android":
		return platform == "android"
	case "javascript":
		return platform == "web" || platform == "node"
	case "react-native":
		return platform == "react_native_ios" || platform == "react_native_android"
	default:
		return false
	}
}

func validClientRequestHint(header http.Header) string {
	value, ok := exactlyOneHeader(header, "X-Latchway-Request-ID")
	if !ok || len(value) < 8 || len(value) > 128 || !requestHintPattern.MatchString(value) {
		return ""
	}
	return value
}

func canonicalPublicOrigin(value string) (url.URL, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return url.URL{}, errInvalidConfiguration
	}
	origin, err := url.Parse(value)
	if err != nil || origin.Opaque != "" || origin.User != nil || origin.Scheme == "" || origin.Host == "" ||
		origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") {
		return url.URL{}, errInvalidConfiguration
	}
	origin.Scheme = strings.ToLower(origin.Scheme)
	origin.Host = strings.ToLower(origin.Host)
	if origin.Scheme != "https" && !(origin.Scheme == "http" && isLoopback(origin.Hostname())) {
		return url.URL{}, errInvalidConfiguration
	}
	return url.URL{Scheme: origin.Scheme, Host: origin.Host}, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
