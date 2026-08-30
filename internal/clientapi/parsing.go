package clientapi

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/frameworkcompat"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/weborigin"
)

const (
	maximumChallengeBodyBytes = 128 << 10
	maximumExchangeBodyBytes  = 96 << 10
	maximumRefreshBodyBytes   = 4 << 10
	maximumComponentBodyBytes = 32 << 10
	maximumEvidenceBytes      = 64 << 10
	maximumEvidenceMembers    = 64
	maximumDPoPBytes          = 16 << 10
	maximumAccessTokenBytes   = 16 << 10
	minimumAccessTokenBytes   = 64
)

var (
	identifierPattern          = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	sdkVersionPattern          = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	challengeIDPattern         = regexp.MustCompile(`^chl_[A-Za-z0-9_-]{16,128}$`)
	requestIDPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	base64URLPattern           = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	installationPattern        = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{16,128}$`)
	installationFamilyPattern  = regexp.MustCompile(`^fam_[A-Za-z0-9_-]{16,128}$`)
	clientComponentPattern     = regexp.MustCompile(`^cmp_[A-Za-z0-9_-]{16,128}$`)
	componentDelegationPattern = regexp.MustCompile(`^dlg_[A-Za-z0-9_-]{16,128}$`)
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
	protocolVersion  string
	sdk              string
	sdkVersion       string
	framework        string
	frameworkVersion string
}

func parseClientDeclaration(r *http.Request) (clientDeclaration, *requestViolation) {
	protocolVersion, ok := exactlyOneHeader(r.Header, "X-Latchway-Protocol-Version")
	if !ok || !buildinfo.SupportsProtocolVersion(protocolVersion) {
		return clientDeclaration{}, &requestViolation{
			code:                      "protocol_version_unsupported",
			detail:                    "This gateway supports Latchway protocol versions 1 and 2.",
			supportedProtocolVersions: buildinfo.SupportedProtocolVersions(),
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
	framework, frameworkCount := oneRawClientHeader(r.Header, "X-Latchway-Framework")
	frameworkVersion, frameworkVersionCount := oneRawClientHeader(r.Header, "X-Latchway-Framework-Version")
	if frameworkCount == 0 && frameworkVersionCount == 0 {
		return clientDeclaration{protocolVersion: protocolVersion, sdk: sdk, sdkVersion: sdkVersion}, nil
	}
	if frameworkCount != 1 || frameworkVersionCount != 1 || framework == "" || frameworkVersion == "" ||
		strings.TrimSpace(framework) != framework || strings.TrimSpace(frameworkVersion) != frameworkVersion ||
		strings.ContainsAny(framework, "\r\n\x00,") || strings.ContainsAny(frameworkVersion, "\r\n\x00,") {
		return clientDeclaration{}, invalidAt("header.X-Latchway-Framework", "Framework and framework version must be declared together exactly once.")
	}
	if !frameworkcompat.Compatible(sdk, framework) {
		return clientDeclaration{}, &requestViolation{code: "framework_integration_unsupported", detail: "The declared framework integration is not supported by this SDK."}
	}
	if !frameworkcompat.ValidVersion(frameworkVersion) {
		return clientDeclaration{}, &requestViolation{code: "framework_version_unsupported", detail: "The declared framework version is not supported."}
	}
	return clientDeclaration{
		protocolVersion: protocolVersion, sdk: sdk, sdkVersion: sdkVersion, framework: framework,
		frameworkVersion: frameworkVersion,
	}, nil
}

func requireCurrentProtocol(declaration clientDeclaration) *requestViolation {
	if declaration.protocolVersion == buildinfo.ProtocolVersion {
		return nil
	}
	return &requestViolation{
		code:                      "protocol_version_unsupported",
		detail:                    "This operation requires Latchway protocol version 2.",
		supportedProtocolVersions: []int{buildinfo.CurrentProtocolVersion},
	}
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
	value, count := oneRawClientHeader(header, name)
	if count != 1 {
		return "", false
	}
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00,") {
		return "", false
	}
	return value, true
}

func oneRawClientHeader(header http.Header, name string) (string, int) {
	var value string
	count := 0
	for candidate, values := range header {
		if !strings.EqualFold(candidate, name) {
			continue
		}
		for _, raw := range values {
			count++
			if count == 1 {
				value = raw
			}
		}
	}
	return value, count
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
	if !ok || !validInitialSessionPlatform(platform) {
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

func parseComponentAttestationExchangeRequest(r *http.Request) (ExchangeComponentAttestationInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumExchangeBodyBytes)
	if violation != nil {
		return ExchangeComponentAttestationInput{}, violation
	}
	if !hasExactFields(object, []string{"challenge_id", "attestation"}, nil) {
		return ExchangeComponentAttestationInput{}, invalidAt("body", "The component attestation exchange object has missing or unsupported fields.")
	}
	challengeID, ok := object["challenge_id"].(string)
	if !ok || !challengeIDPattern.MatchString(challengeID) {
		return ExchangeComponentAttestationInput{}, invalidAt("body.challenge_id", "challenge_id is invalid.")
	}
	attestationValue, ok := object["attestation"].(map[string]any)
	if !ok {
		return ExchangeComponentAttestationInput{}, invalidAt("body.attestation", "attestation must be an object.")
	}
	attestation, violation := parseAttestation(attestationValue, "body.attestation")
	if violation != nil {
		return ExchangeComponentAttestationInput{}, violation
	}
	return ExchangeComponentAttestationInput{ChallengeID: challengeID, Attestation: attestation}, nil
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

func parseProvisionComponentRequest(r *http.Request, declaration clientDeclaration) (ProvisionComponentInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumComponentBodyBytes)
	if violation != nil {
		return ProvisionComponentInput{}, violation
	}
	if !hasExactFields(object, []string{"component_definition_id", "public_jwk", "requested_features", "client_metadata"}, nil) {
		return ProvisionComponentInput{}, invalidAt("body", "The component provisioning object has missing or unsupported fields.")
	}
	definitionID, ok := stringMatching(object["component_definition_id"], identifierPattern, 63)
	if !ok {
		return ProvisionComponentInput{}, invalidAt("body.component_definition_id", "component_definition_id must be a canonical identifier.")
	}
	jwkObject, ok := object["public_jwk"].(map[string]any)
	if !ok || !hasExactFields(jwkObject, []string{"kty", "crv", "x", "y"}, nil) {
		return ProvisionComponentInput{}, invalidAt("body.public_jwk", "public_jwk must be an exact public P-256 JWK.")
	}
	kty, ktyOK := jwkObject["kty"].(string)
	crv, crvOK := jwkObject["crv"].(string)
	x, xOK := jwkObject["x"].(string)
	y, yOK := jwkObject["y"].(string)
	if !ktyOK || !crvOK || !xOK || !yOK || kty != "EC" || crv != "P-256" ||
		!validCanonicalBase64URL(x, 32) || !validCanonicalBase64URL(y, 32) {
		return ProvisionComponentInput{}, invalidAt("body.public_jwk", "public_jwk must be an exact public P-256 JWK.")
	}
	featuresValue, ok := object["requested_features"].([]any)
	if !ok || len(featuresValue) == 0 || len(featuresValue) > 256 {
		return ProvisionComponentInput{}, invalidAt("body.requested_features", "requested_features must be a nonempty bounded identifier list.")
	}
	features := make([]string, len(featuresValue))
	seen := make(map[string]struct{}, len(featuresValue))
	for index, value := range featuresValue {
		feature, ok := stringMatching(value, identifierPattern, 63)
		if !ok {
			return ProvisionComponentInput{}, invalidAt("body.requested_features", "requested_features must contain canonical identifiers.")
		}
		if _, duplicate := seen[feature]; duplicate {
			return ProvisionComponentInput{}, invalidAt("body.requested_features", "requested_features must not contain duplicates.")
		}
		seen[feature] = struct{}{}
		features[index] = feature
	}
	metadataObject, ok := object["client_metadata"].(map[string]any)
	if !ok || !hasExactFields(metadataObject, []string{"app_version", "sdk_version"}, nil) {
		return ProvisionComponentInput{}, invalidAt("body.client_metadata", "client_metadata has missing or unsupported fields.")
	}
	appVersion, ok := boundedString(metadataObject["app_version"], 1, 128)
	if !ok || strings.TrimSpace(appVersion) != appVersion || strings.ContainsAny(appVersion, "\r\n\x00") {
		return ProvisionComponentInput{}, invalidAt("body.client_metadata.app_version", "app_version must satisfy the protocol length limits.")
	}
	sdkVersion, ok := boundedString(metadataObject["sdk_version"], 1, 128)
	if !ok || sdkVersion != declaration.sdkVersion {
		return ProvisionComponentInput{}, invalidAt("body.client_metadata.sdk_version", "sdk_version must match X-Latchway-SDK-Version.")
	}
	return ProvisionComponentInput{
		DefinitionID:      definitionID,
		PublicJWK:         ComponentPublicJWK{Kty: kty, Crv: crv, X: x, Y: y},
		RequestedFeatures: features,
		ClientMetadata:    ComponentClientMetadata{AppVersion: appVersion, SDKVersion: sdkVersion},
	}, nil
}

func parseComponentSessionRequest(r *http.Request) (CreateComponentSessionInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumRefreshBodyBytes)
	if violation != nil {
		return CreateComponentSessionInput{}, violation
	}
	if !hasExactFields(object, []string{"component_id", "refresh_grant"}, nil) {
		return CreateComponentSessionInput{}, invalidAt("body", "The component session object has missing or unsupported fields.")
	}
	componentID, ok := object["component_id"].(string)
	if !ok || !clientComponentPattern.MatchString(componentID) {
		return CreateComponentSessionInput{}, invalidAt("body.component_id", "component_id is invalid.")
	}
	refreshGrant, ok := boundedString(object["refresh_grant"], 32, 2048)
	if !ok || strings.TrimSpace(refreshGrant) != refreshGrant || strings.ContainsAny(refreshGrant, "\r\n\x00") {
		return CreateComponentSessionInput{}, invalidAt("body.refresh_grant", "refresh_grant must satisfy the protocol length limits.")
	}
	return CreateComponentSessionInput{
		ComponentID: componentID, RefreshGrant: NewSensitiveString(refreshGrant),
	}, nil
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
	case "ios", "android", "web", "react_native_ios", "react_native_android", "watchos", "node":
		return true
	default:
		return false
	}
}

// validInitialSessionPlatform is narrower than the component/output
// vocabulary. A watchOS extension joins an existing installation family and
// can step up directly, but it cannot create a version-1 root installation.
func validInitialSessionPlatform(value string) bool {
	return value != "watchos" && validPlatform(value)
}

func platformCompatible(sdk, platform string) bool {
	switch sdk {
	case "ios":
		return platform == "ios" || platform == "watchos"
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
