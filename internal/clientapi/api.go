package clientapi

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/problem"
)

const (
	challengePath = "/client/v1/session-challenges"
	exchangePath  = "/client/v1/sessions"
	refreshPath   = "/client/v1/sessions/refresh"
	revokePath    = "/client/v1/installations/current"
	jwksPath      = "/.well-known/jwks.json"
	discoveryPath = "/.well-known/latchway"
)

type Config struct {
	Coordinator  Coordinator
	JWKS         JWKSProvider
	PublicOrigin string
}

type API struct {
	coordinator Coordinator
	jwks        JWKSProvider
	targets     map[string]url.URL
}

func New(config Config) (*API, error) {
	if nilDependency(config.Coordinator) || nilDependency(config.JWKS) {
		return nil, errors.New("client API dependency is nil")
	}
	origin, err := canonicalPublicOrigin(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	targets := make(map[string]url.URL, 4)
	for _, path := range []string{challengePath, exchangePath, refreshPath, revokePath} {
		targets[path] = url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: path}
	}
	return &API{coordinator: config.Coordinator, jwks: config.JWKS, targets: targets}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func canonicalPublicOrigin(value string) (url.URL, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return url.URL{}, errors.New("client API public origin is invalid")
	}
	origin, err := url.Parse(value)
	if err != nil || origin.Opaque != "" || origin.User != nil || origin.Scheme == "" || origin.Host == "" || origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return url.URL{}, errors.New("client API public origin must be an absolute origin")
	}
	origin.Scheme = strings.ToLower(origin.Scheme)
	origin.Host = strings.ToLower(origin.Host)
	if origin.Scheme != "https" && !(origin.Scheme == "http" && isLoopback(origin.Hostname())) {
		return url.URL{}, errors.New("client API public origin must use HTTPS except on loopback")
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

func (api *API) Handler() http.Handler { return api }

func (api *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := selectRequestID(r)
	w.Header().Set("X-Latchway-Request-ID", requestID)

	path := r.URL.EscapedPath()
	if path != r.URL.Path {
		api.writeProblem(w, requestID, problem.Error{Code: "resource_not_found", Detail: "The client endpoint was not found."})
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		api.writeViolation(w, requestID, invalidAt("query", "Query parameters are not supported by this endpoint."))
		return
	}

	switch path {
	case challengePath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, requestID)
			return
		}
		api.createChallenge(w, r, requestID)
	case exchangePath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, requestID)
			return
		}
		api.exchangeSession(w, r, requestID)
	case refreshPath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, requestID)
			return
		}
		api.refreshSession(w, r, requestID)
	case revokePath:
		if r.Method != http.MethodDelete {
			api.methodNotAllowed(w, requestID)
			return
		}
		api.revokeCurrentInstallation(w, r, requestID)
	case jwksPath:
		if r.Method != http.MethodGet {
			api.methodNotAllowed(w, requestID)
			return
		}
		api.publicJWKS(w, r, requestID)
	case discoveryPath:
		if r.Method != http.MethodGet {
			api.methodNotAllowed(w, requestID)
			return
		}
		api.publicDiscovery(w, r, requestID)
	default:
		api.writeProblem(w, requestID, problem.Error{Code: "resource_not_found", Detail: "The client endpoint was not found."})
	}
}

func (api *API) createChallenge(w http.ResponseWriter, r *http.Request, requestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	proof, violation := parseDPoPHeader(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input, violation := parseChallengeRequest(r, declaration)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input.Metadata = api.metadata(requestID, declaration, http.MethodPost, challengePath, proof)
	result, err := api.coordinator.CreateChallenge(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := challengeDocumentFor(result)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusCreated, "no-store", document)
}

func (api *API) exchangeSession(w http.ResponseWriter, r *http.Request, requestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	proof, violation := parseDPoPHeader(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input, violation := parseExchangeRequest(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input.Metadata = api.metadata(requestID, declaration, http.MethodPost, exchangePath, proof)
	result, err := api.coordinator.ExchangeSession(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := grantDocumentFor(result, declaration.sdk)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusCreated, "no-store", document)
}

func (api *API) refreshSession(w http.ResponseWriter, r *http.Request, requestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	proof, violation := parseDPoPHeader(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input, violation := parseRefreshRequest(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input.Metadata = api.metadata(requestID, declaration, http.MethodPost, refreshPath, proof)
	result, err := api.coordinator.RefreshSession(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := grantDocumentFor(result, declaration.sdk)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusOK, "no-store", document)
}

func (api *API) revokeCurrentInstallation(w http.ResponseWriter, r *http.Request, requestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	accessToken, violation := parseDPoPAuthorization(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	proof, violation := parseDPoPHeader(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	if violation := ensureBodyless(r); violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input := RevokeInstallationInput{
		Metadata:    api.metadata(requestID, declaration, http.MethodDelete, revokePath, proof),
		AccessToken: accessToken,
	}
	if err := api.coordinator.RevokeCurrentInstallation(r.Context(), input); err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) publicJWKS(w http.ResponseWriter, r *http.Request, requestID string) {
	if violation := ensureBodyless(r); violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	keys, err := api.jwks.PublicJWKS(r.Context())
	if err != nil {
		api.writeProblem(w, requestID, problem.Error{Code: "server_not_ready", Detail: "Public session-signing keys are temporarily unavailable."})
		return
	}
	if err := validateJWKS(keys); err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusOK, "public, max-age=300", keys)
}

func (api *API) publicDiscovery(w http.ResponseWriter, r *http.Request, requestID string) {
	if violation := ensureBodyless(r); violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	api.writeSuccess(w, requestID, http.StatusOK, "public, max-age=300", discoveryDocument{
		ServerVersion:             buildinfo.Version,
		ContractVersion:           buildinfo.ContractVersion,
		SupportedProtocolVersions: []int{1},
		SessionEndpoint:           exchangePath,
		DPoPAlgorithms:            []string{"ES256"},
		MaximumClockSkewSeconds:   300,
	})
}

func (api *API) metadata(requestID string, declaration clientDeclaration, method, path string, proof SensitiveString) RequestMetadata {
	target := api.targets[path]
	return RequestMetadata{
		RequestID: requestID, SDK: declaration.sdk, SDKVersion: declaration.sdkVersion,
		HTTPMethod: method, TargetURL: target, DPoPProof: proof,
	}
}

func (api *API) methodNotAllowed(w http.ResponseWriter, requestID string) {
	api.writeProblem(w, requestID, problem.Error{Code: "request_invalid", Detail: "The HTTP method is not supported by this client endpoint."})
}

func (api *API) writeViolation(w http.ResponseWriter, requestID string, violation *requestViolation) {
	if violation == nil {
		api.internal(w, requestID)
		return
	}
	api.writeProblem(w, requestID, problem.Error{
		Code: violation.code, Detail: violation.detail, Fields: violation.fields,
		SupportedProtocolVersions: violation.supportedProtocolVersions,
	})
}

func (api *API) writeDependencyFailure(w http.ResponseWriter, requestID string, err error) {
	var failure *DependencyError
	if !errors.As(err, &failure) || failure == nil || !allowedDependencyCode(failure.Code) || failure.RetryAfterSeconds < 0 || failure.RetryAfterSeconds > 86400 {
		api.internal(w, requestID)
		return
	}
	definition := problem.Registry[failure.Code]
	if failure.RetryAfterSeconds > 0 && !definition.Retryable {
		api.internal(w, requestID)
		return
	}
	if failure.Code == "dpop_nonce_required" {
		if len(failure.DPoPNonce) < 16 || len(failure.DPoPNonce) > 512 || strings.ContainsAny(failure.DPoPNonce, "\r\n\x00") {
			api.internal(w, requestID)
			return
		}
		w.Header().Set("DPoP-Nonce", failure.DPoPNonce)
	} else if failure.DPoPNonce != "" {
		api.internal(w, requestID)
		return
	}
	value := problem.Error{
		Code: failure.Code, Detail: safeFailureDetail(failure.Code),
		RetryAfterSeconds: failure.RetryAfterSeconds,
	}
	if failure.Code == "protocol_version_unsupported" {
		value.SupportedProtocolVersions = []int{1}
	}
	api.writeProblem(w, requestID, value)
}

func allowedDependencyCode(code string) bool {
	switch code {
	case "request_invalid",
		"identity_token_missing", "identity_token_invalid", "identity_token_expired", "identity_reauthentication_required",
		"attestation_required", "attestation_unsupported", "attestation_invalid", "attestation_stale", "attestation_step_up_required",
		"dpop_missing", "dpop_invalid", "dpop_replayed", "dpop_nonce_required",
		"session_expired", "session_revoked", "refresh_token_reused", "installation_revoked",
		"server_not_ready", "protocol_version_unsupported", "conflict", "internal_error":
		return true
	default:
		return false
	}
}

func safeFailureDetail(code string) string {
	switch code {
	case "request_invalid":
		return "The request cannot be processed by the configured client protocol."
	case "identity_token_missing":
		return "A current application identity token is required."
	case "identity_token_invalid":
		return "The application identity token could not be verified."
	case "identity_token_expired":
		return "The application identity token is expired."
	case "identity_reauthentication_required":
		return "The application identity provider requires reauthentication."
	case "attestation_required":
		return "Application attestation is required for this session."
	case "attestation_unsupported":
		return "The selected platform attestation flow is not supported."
	case "attestation_invalid":
		return "The application attestation evidence could not be verified."
	case "attestation_stale":
		return "Fresh application attestation is required."
	case "attestation_step_up_required":
		return "A stronger application attestation flow is required."
	case "dpop_missing":
		return "Exactly one DPoP proof is required."
	case "dpop_invalid":
		return "The DPoP proof could not be verified for this request."
	case "dpop_replayed":
		return "The DPoP proof has already been used."
	case "dpop_nonce_required":
		return "A new DPoP proof using the response nonce is required."
	case "session_expired":
		return "The Latchway session is expired."
	case "session_revoked":
		return "The Latchway session is no longer active."
	case "refresh_token_reused":
		return "Refresh-token reuse was detected and the token family is no longer active."
	case "installation_revoked":
		return "The installation is no longer active."
	case "server_not_ready":
		return "The gateway is not ready to complete this session operation."
	case "protocol_version_unsupported":
		return "This gateway supports Latchway protocol version 1."
	case "conflict":
		return "The one-time session state has already changed."
	default:
		return "The client operation could not be completed."
	}
}

func (api *API) internal(w http.ResponseWriter, requestID string) {
	api.writeProblem(w, requestID, problem.Error{Code: "internal_error", Detail: "The client operation could not be completed."})
}

func (api *API) writeProblem(w http.ResponseWriter, requestID string, value problem.Error) {
	problem.Write(w, requestID, value)
}

func (api *API) writeSuccess(w http.ResponseWriter, requestID string, status int, cacheControl string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	w.Header().Set("Cache-Control", cacheControl)
	if err := writeEncodedJSON(w, status, encoded); err != nil {
		// The response is already committed. A second problem response would
		// corrupt the wire body and could retain success cache headers.
		return
	}
}

func selectRequestID(r *http.Request) string {
	if current := middleware.GetReqID(r.Context()); validRequestID(current) {
		return current
	}
	if candidate, ok := exactlyOneHeader(r.Header, "X-Latchway-Request-ID"); ok && validRequestID(candidate) {
		return candidate
	}
	generated, err := id.New(id.LogicalRequest)
	if err != nil {
		return "request_unknown"
	}
	return generated
}

func validRequestID(value string) bool {
	return len(value) >= 8 && len(value) <= 128 && requestIDPattern.MatchString(value)
}

type challengeDocument struct {
	ChallengeID    string                       `json:"challenge_id"`
	ChallengeNonce string                       `json:"challenge_nonce"`
	BindingVersion int                          `json:"binding_version"`
	IssuedAt       int64                        `json:"issued_at"`
	ExpiresAt      time.Time                    `json:"expires_at"`
	Attestation    challengeAttestationDocument `json:"attestation"`
}

type discoveryDocument struct {
	ServerVersion             string   `json:"server_version"`
	ContractVersion           string   `json:"contract_version"`
	SupportedProtocolVersions []int    `json:"supported_protocol_versions"`
	SessionEndpoint           string   `json:"session_endpoint"`
	DPoPAlgorithms            []string `json:"dpop_algorithms"`
	MaximumClockSkewSeconds   int      `json:"maximum_clock_skew_seconds"`
}

type challengeAttestationDocument struct {
	Provider        string         `json:"provider"`
	Mode            string         `json:"mode"`
	ClientDataHash  string         `json:"client_data_hash"`
	ProviderOptions map[string]any `json:"provider_options,omitempty"`
}

func challengeDocumentFor(result ChallengeResult) (challengeDocument, error) {
	if !challengeIDPattern.MatchString(result.ChallengeID) || len(result.ChallengeNonce) > 512 || !validCanonicalBase64URL(result.ChallengeNonce, -1) || result.BindingVersion != 1 || result.IssuedAt < 0 || result.IssuedAt > 253402300799 || result.ExpiresAt.IsZero() || !result.ExpiresAt.After(time.Unix(result.IssuedAt, 0)) {
		return challengeDocument{}, errors.New("invalid challenge result")
	}
	attestation := result.Attestation
	if !validAttestationProvider(attestation.Provider) || (attestation.Mode != "required" && attestation.Mode != "preferred") || !validCanonicalBase64URL(attestation.ClientDataHash, 32) {
		return challengeDocument{}, errors.New("invalid challenge attestation result")
	}
	if attestation.ProviderOptions != nil {
		if len(attestation.ProviderOptions) > 32 {
			return challengeDocument{}, errors.New("invalid attestation provider options")
		}
		encoded, err := json.Marshal(attestation.ProviderOptions)
		if err != nil || len(encoded) > 16<<10 {
			return challengeDocument{}, errors.New("invalid attestation provider options")
		}
		decoded, err := jsonsafe.Decode(encoded)
		if err != nil {
			return challengeDocument{}, errors.New("invalid attestation provider options")
		}
		optionsCopy, ok := decoded.(map[string]any)
		if !ok {
			return challengeDocument{}, errors.New("invalid attestation provider options")
		}
		attestation.ProviderOptions = optionsCopy
	}
	return challengeDocument{
		ChallengeID: result.ChallengeID, ChallengeNonce: result.ChallengeNonce,
		BindingVersion: result.BindingVersion, IssuedAt: result.IssuedAt, ExpiresAt: result.ExpiresAt.UTC(),
		Attestation: challengeAttestationDocument{
			Provider: attestation.Provider, Mode: attestation.Mode,
			ClientDataHash: attestation.ClientDataHash, ProviderOptions: attestation.ProviderOptions,
		},
	}, nil
}

type grantDocument struct {
	AccessToken      string              `json:"access_token"`
	TokenType        string              `json:"token_type"`
	ExpiresIn        int                 `json:"expires_in"`
	RefreshToken     string              `json:"refresh_token"`
	RefreshExpiresIn int                 `json:"refresh_expires_in"`
	Installation     InstallationSummary `json:"installation"`
	Trust            TrustSummary        `json:"trust"`
}

func grantDocumentFor(result GrantResult, sdk string) (grantDocument, error) {
	accessToken := result.AccessToken.Reveal()
	refreshToken := result.RefreshToken.Reveal()
	if !validCredential(accessToken, 64, 16384) || !validCredential(refreshToken, 32, 2048) || result.ExpiresIn < 60 || result.ExpiresIn > 3600 || result.RefreshExpiresIn < 300 || result.RefreshExpiresIn > 31536000 {
		return grantDocument{}, errors.New("invalid session credential result")
	}
	installation := result.Installation
	if !installationPattern.MatchString(installation.ID) || !validPlatform(installation.Platform) || !platformCompatible(sdk, installation.Platform) || !validCanonicalBase64URL(installation.DPoPJKT, 32) || (installation.Status != "active" && installation.Status != "revoked") {
		return grantDocument{}, errors.New("invalid installation result")
	}
	trust := result.Trust
	if !validAttestationProvider(trust.Provider) || !validTrustLevel(trust.Level) || trust.VerifiedAt.IsZero() || trust.ExpiresAt.IsZero() || !trust.ExpiresAt.After(trust.VerifiedAt) {
		return grantDocument{}, errors.New("invalid trust result")
	}
	return grantDocument{
		AccessToken: accessToken, TokenType: "DPoP", ExpiresIn: result.ExpiresIn,
		RefreshToken: refreshToken, RefreshExpiresIn: result.RefreshExpiresIn,
		Installation: installation, Trust: TrustSummary{
			Provider: trust.Provider, Level: trust.Level,
			VerifiedAt: trust.VerifiedAt.UTC(), ExpiresAt: trust.ExpiresAt.UTC(),
		},
	}, nil
}

func validCredential(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validTrustLevel(value string) bool {
	switch value {
	case "none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug":
		return true
	default:
		return false
	}
}

func validCanonicalBase64URL(value string, decodedLength int) bool {
	if value == "" || !base64URLPattern.MatchString(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return false
	}
	return decodedLength < 0 || len(decoded) == decodedLength
}

func validateJWKS(keys JWKS) error {
	if len(keys.Keys) == 0 || len(keys.Keys) > 16 {
		return errors.New("invalid public JWKS size")
	}
	seen := make(map[string]struct{}, len(keys.Keys))
	for _, key := range keys.Keys {
		if key.Kty != "EC" || key.Crv != "P-256" || key.Use != "sig" || key.Alg != "ES256" || len(key.Kid) < 8 || len(key.Kid) > 128 || strings.ContainsAny(key.Kid, "\r\n\x00") || !validCanonicalBase64URL(key.X, 32) || !validCanonicalBase64URL(key.Y, 32) {
			return errors.New("invalid public JWK")
		}
		xBytes, _ := base64.RawURLEncoding.Strict().DecodeString(key.X)
		yBytes, _ := base64.RawURLEncoding.Strict().DecodeString(key.Y)
		if !elliptic.P256().IsOnCurve(new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)) {
			return errors.New("public JWK point is not on P-256")
		}
		if _, exists := seen[key.Kid]; exists {
			return errors.New("duplicate public JWK key ID")
		}
		seen[key.Kid] = struct{}{}
	}
	return nil
}

func writeEncodedJSON(w http.ResponseWriter, status int, encoded []byte) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	w.WriteHeader(status)
	written, err := w.Write(encoded)
	if err == nil && written != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}
