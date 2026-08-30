package clientapi

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/weborigin"
)

const (
	maximumChallengeBodyBytes = 128 << 10
	maximumExchangeBodyBytes  = 96 << 10
	maximumRefreshBodyBytes   = 4 << 10
	maximumEvidenceBytes      = 64 << 10
	maximumEvidenceMembers    = 64
	maximumDPoPBytes          = 16 << 10
	maximumAccessTokenBytes   = 16 << 10
	minimumAccessTokenBytes   = 64
)

var (
	identifierPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	sdkVersionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	challengeIDPattern  = regexp.MustCompile(`^chl_[A-Za-z0-9_-]{16,128}$`)
	requestIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	base64URLPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	installationPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{16,128}$`)
)

type requestViolation struct {
	code                      string
	detail                    string
	fields                    []problem.FieldError
	supportedProtocolVersions []int
}

func invalidAt(path, message string) *requestViolation {
	return &requestViolation{
		code:   "request_invalid",
		detail: "The request does not match the Latchway client protocol.",
		fields: []problem.FieldError{{Path: path, Message: message}},
	}
}

type clientDeclaration struct {
	sdk        string
	sdkVersion string
}

func parseClientDeclaration(r *http.Request) (clientDeclaration, *requestViolation) {
	protocolVersion, ok := exactlyOneHeader(r.Header, "X-Latchway-Protocol-Version")
	if !ok || protocolVersion != "1" {
		return clientDeclaration{}, &requestViolation{
			code:                      "protocol_version_unsupported",
			detail:                    "This gateway supports Latchway protocol version 1.",
			supportedProtocolVersions: []int{1},
		}
	}
	sdk, ok := exactlyOneHeader(r.Header, "X-Latchway-SDK")
	if !ok || !validSDK(sdk) {
		return clientDeclaration{}, invalidAt("header.X-Latchway-SDK", "A supported SDK identifier is required.")
	}
	sdkVersion, ok := exactlyOneHeader(r.Header, "X-Latchway-SDK-Version")
	if !ok || len(sdkVersion) > 128 || !sdkVersionPattern.MatchString(sdkVersion) {
		return clientDeclaration{}, invalidAt("header.X-Latchway-SDK-Version", "A semantic SDK version is required.")
	}
	return clientDeclaration{sdk: sdk, sdkVersion: sdkVersion}, nil
}

func parseDPoPHeader(r *http.Request) (SensitiveString, *requestViolation) {
	values := r.Header.Values("DPoP")
	if len(values) == 0 {
		return SensitiveString{}, &requestViolation{code: "dpop_missing", detail: "Exactly one DPoP proof is required."}
	}
	if len(values) != 1 {
		return SensitiveString{}, &requestViolation{code: "dpop_invalid", detail: "The DPoP proof header is invalid."}
	}
	proof := values[0]
	if proof == "" || len(proof) > maximumDPoPBytes || strings.TrimSpace(proof) != proof || strings.ContainsAny(proof, " \t\r\n\x00,") || strings.Count(proof, ".") != 2 {
		return SensitiveString{}, &requestViolation{code: "dpop_invalid", detail: "The DPoP proof header is invalid."}
	}
	segments := strings.Split(proof, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return SensitiveString{}, &requestViolation{code: "dpop_invalid", detail: "The DPoP proof header is invalid."}
	}
	return NewSensitiveString(proof), nil
}

func parseDPoPAuthorization(r *http.Request) (SensitiveString, *requestViolation) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return SensitiveString{}, invalidAt("header.Authorization", "Exactly one DPoP access token is required.")
	}
	value := values[0]
	scheme, token, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "DPoP") || len(token) < minimumAccessTokenBytes || len(token) > maximumAccessTokenBytes || strings.TrimSpace(value) != value || !validAuthorizationCredential(token) {
		return SensitiveString{}, invalidAt("header.Authorization", "Authorization must use exactly one bounded DPoP access token.")
	}
	return NewSensitiveString(token), nil
}

func validAuthorizationCredential(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] <= ' ' || value[index] >= 0x7f || value[index] == ',' {
			return false
		}
	}
	return true
}

func exactlyOneHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	if value == "" || strings.ContainsAny(value, "\r\n\x00,") {
		return "", false
	}
	return value, true
}

func validateJSONMediaType(r *http.Request) *requestViolation {
	mediaType, ok := exactlyOneHeader(r.Header, "Content-Type")
	if !ok || !strings.EqualFold(mediaType, "application/json") {
		return invalidAt("header.Content-Type", "Content-Type must be application/json without parameters.")
	}
	if len(r.Header.Values("Content-Encoding")) != 0 {
		return invalidAt("header.Content-Encoding", "Encoded request bodies are not supported.")
	}
	return nil
}

func decodeRequestObject(r *http.Request, maximumBytes int64) (map[string]any, *requestViolation) {
	if violation := validateJSONMediaType(r); violation != nil {
		return nil, violation
	}
	if r.Body == nil || r.ContentLength > maximumBytes {
		return nil, invalidAt("body", "A bounded JSON object is required.")
	}
	value, err := jsonsafe.DecodeReader(r.Body, maximumBytes)
	if err != nil {
		return nil, invalidAt("body", "The body must contain exactly one unambiguous JSON object within the endpoint size limit.")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalidAt("body", "The body must be a JSON object.")
	}
	return object, nil
}

func parseChallengeRequest(r *http.Request, declaration clientDeclaration) (ChallengeInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumChallengeBodyBytes)
	if violation != nil {
		return ChallengeInput{}, violation
	}
	if !hasExactFields(object, []string{"application_id", "environment", "identity_provider", "identity_token", "platform", "sdk_version"}, nil) {
		return ChallengeInput{}, invalidAt("body", "The challenge object has missing or unsupported fields.")
	}
	applicationID, ok := boundedString(object["application_id"], 1, 128)
	if !ok {
		return ChallengeInput{}, invalidAt("body.application_id", "application_id must contain between 1 and 128 characters.")
	}
	environment, ok := stringMatching(object["environment"], identifierPattern, 63)
	if !ok {
		return ChallengeInput{}, invalidAt("body.environment", "environment must be a canonical identifier.")
	}
	identityProvider, ok := stringMatching(object["identity_provider"], identifierPattern, 63)
	if !ok {
		return ChallengeInput{}, invalidAt("body.identity_provider", "identity_provider must be a canonical identifier.")
	}
	identityToken, ok := boundedString(object["identity_token"], 16, 65536)
	if !ok {
		return ChallengeInput{}, invalidAt("body.identity_token", "identity_token must satisfy the protocol length limits.")
	}
	platform, ok := object["platform"].(string)
	if !ok || !validPlatform(platform) {
		return ChallengeInput{}, invalidAt("body.platform", "platform must be a supported Latchway platform.")
	}
	sdkVersion, ok := boundedString(object["sdk_version"], 1, 128)
	if !ok || !sdkVersionPattern.MatchString(sdkVersion) {
		return ChallengeInput{}, invalidAt("body.sdk_version", "sdk_version must be semantic version syntax.")
	}
	if sdkVersion != declaration.sdkVersion {
		return ChallengeInput{}, invalidAt("body.sdk_version", "sdk_version must match X-Latchway-SDK-Version.")
	}
	if !platformCompatible(declaration.sdk, platform) {
		return ChallengeInput{}, invalidAt("body.platform", "platform is incompatible with X-Latchway-SDK.")
	}
	origin, originErr := weborigin.Read(r.Header)
	if originErr != nil || (platform == "web" && origin == "") || (platform != "web" && origin != "") {
		return ChallengeInput{}, invalidAt("header.Origin", "Web challenges require exactly one canonical HTTPS Origin and non-web challenges must omit it.")
	}
	return ChallengeInput{
		ApplicationID: applicationID, Environment: environment,
		IdentityProvider: identityProvider, IdentityToken: NewSensitiveString(identityToken),
		Platform: platform,
	}, nil
}

func parseExchangeRequest(r *http.Request) (ExchangeInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumExchangeBodyBytes)
	if violation != nil {
		return ExchangeInput{}, violation
	}
	if !hasExactFields(object, []string{"challenge_id", "attestation", "installation"}, nil) {
		return ExchangeInput{}, invalidAt("body", "The session exchange object has missing or unsupported fields.")
	}
	challengeID, ok := object["challenge_id"].(string)
	if !ok || !challengeIDPattern.MatchString(challengeID) {
		return ExchangeInput{}, invalidAt("body.challenge_id", "challenge_id is invalid.")
	}
	attestationValue, ok := object["attestation"].(map[string]any)
	if !ok {
		return ExchangeInput{}, invalidAt("body.attestation", "attestation must be an object.")
	}
	attestation, violation := parseAttestation(attestationValue, "body.attestation")
	if violation != nil {
		return ExchangeInput{}, violation
	}
	installationValue, ok := object["installation"].(map[string]any)
	if !ok || !hasExactFields(installationValue, []string{"app_version"}, []string{"os_version", "device_model"}) {
		return ExchangeInput{}, invalidAt("body.installation", "installation has missing or unsupported fields.")
	}
	appVersion, ok := boundedString(installationValue["app_version"], 1, 128)
	if !ok {
		return ExchangeInput{}, invalidAt("body.installation.app_version", "app_version must contain between 1 and 128 characters.")
	}
	osVersion, violation := optionalBoundedString(installationValue, "os_version", "body.installation.os_version", 1, 128)
	if violation != nil {
		return ExchangeInput{}, violation
	}
	deviceModel, violation := optionalBoundedString(installationValue, "device_model", "body.installation.device_model", 1, 128)
	if violation != nil {
		return ExchangeInput{}, violation
	}
	return ExchangeInput{
		ChallengeID: challengeID, Attestation: attestation,
		Installation: InstallationMetadata{AppVersion: appVersion, OSVersion: osVersion, DeviceModel: deviceModel},
	}, nil
}

func parseRefreshRequest(r *http.Request) (RefreshInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumRefreshBodyBytes)
	if violation != nil {
		return RefreshInput{}, violation
	}
	if !hasExactFields(object, []string{"refresh_token"}, nil) {
		return RefreshInput{}, invalidAt("body", "The session refresh object has missing or unsupported fields.")
	}
	refreshToken, ok := boundedString(object["refresh_token"], 32, 2048)
	if !ok {
		return RefreshInput{}, invalidAt("body.refresh_token", "refresh_token must satisfy the protocol length limits.")
	}
	return RefreshInput{RefreshToken: NewSensitiveString(refreshToken)}, nil
}

func parseAttestation(object map[string]any, path string) (AttestationEvidence, *requestViolation) {
	if !hasExactFields(object, []string{"provider", "evidence"}, nil) {
		return AttestationEvidence{}, invalidAt(path, "attestation has missing or unsupported fields.")
	}
	provider, ok := object["provider"].(string)
	if !ok || !validAttestationProvider(provider) {
		return AttestationEvidence{}, invalidAt(path+".provider", "provider is not supported by the wire protocol.")
	}
	evidenceObject, ok := object["evidence"].(map[string]any)
	if !ok {
		return AttestationEvidence{}, invalidAt(path+".evidence", "evidence must be an object.")
	}
	payload, err := newEvidencePayload(evidenceObject)
	if err != nil {
		return AttestationEvidence{}, invalidAt(path+".evidence", "evidence exceeds the provider payload limits.")
	}
	return AttestationEvidence{Provider: provider, Payload: payload}, nil
}

func optionalBoundedString(object map[string]any, key, path string, minimum, maximum int) (string, *requestViolation) {
	value, exists := object[key]
	if !exists {
		return "", nil
	}
	text, ok := boundedString(value, minimum, maximum)
	if !ok {
		return "", invalidAt(path, "The value does not satisfy the protocol length limits.")
	}
	return text, nil
}

func hasExactFields(object map[string]any, required, optional []string) bool {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, exists := object[key]; !exists {
			return false
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, exists := allowed[key]; !exists {
			return false
		}
	}
	return true
}

func boundedString(value any, minimum, maximum int) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	length := utf8.RuneCountInString(text)
	return text, length >= minimum && length <= maximum
}

func stringMatching(value any, pattern *regexp.Regexp, maximum int) (string, bool) {
	text, ok := boundedString(value, 1, maximum)
	return text, ok && pattern.MatchString(text)
}

func validSDK(value string) bool {
	switch value {
	case "ios", "android", "javascript", "react-native":
		return true
	default:
		return false
	}
}

func validPlatform(value string) bool {
	switch value {
	case "ios", "android", "web", "react_native_ios", "react_native_android", "node":
		return true
	default:
		return false
	}
}

func platformCompatible(sdk, platform string) bool {
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

func validAttestationProvider(value string) bool {
	switch value {
	case "app_attest", "play_integrity", "firebase_app_check", "turnstile", "debug":
		return true
	default:
		return false
	}
}

func ensureBodyless(r *http.Request) *requestViolation {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return invalidAt("body", "This endpoint does not accept a request body.")
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	var one [1]byte
	if _, err := r.Body.Read(one[:]); err == io.EOF {
		return nil
	}
	return invalidAt("body", "This endpoint does not accept a request body.")
}
