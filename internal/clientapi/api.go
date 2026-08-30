package clientapi

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/weborigin"
)

const (
	challengePath             = "/client/v1/session-challenges"
	exchangePath              = "/client/v1/sessions"
	refreshPath               = "/client/v1/sessions/refresh"
	revokePath                = "/client/v1/installations/current"
	provisionComponentPath    = "/client/v1/installation-families/current/components"
	componentSessionPath      = "/client/v1/component-sessions"
	revokeFamilyPath          = "/client/v1/installation-families/current"
	revokeComponentPrefix     = "/client/v1/installation-families/current/components/"
	diagnosticsPath           = "/client/v1/diagnostics"
	featureQuotaPrefix        = "/client/v1/features/"
	featureQuotaSuffix        = "/quota"
	jwksPath                  = "/.well-known/jwks.json"
	discoveryPath             = "/.well-known/latchway"
	maximumFeatureQuotaLimits = 128
	maximumSafeJSONInteger    = int64(1<<53 - 1)
)

type Config struct {
	Coordinator   Coordinator
	FeatureQuotas FeatureQuotaProvider
	JWKS          JWKSProvider
	PublicOrigin  string
}

type API struct {
	coordinator   Coordinator
	featureQuotas FeatureQuotaProvider
	jwks          JWKSProvider
	origin        url.URL
	targets       map[string]url.URL
}

func New(config Config) (*API, error) {
	if nilDependency(config.Coordinator) || nilDependency(config.FeatureQuotas) || nilDependency(config.JWKS) {
		return nil, errors.New("client API dependency is nil")
	}
	origin, err := canonicalPublicOrigin(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	targets := make(map[string]url.URL, 9)
	for _, path := range []string{
		challengePath, exchangePath, refreshPath, revokePath, diagnosticsPath,
		provisionComponentPath, componentSessionPath, revokeFamilyPath,
	} {
		targets[path] = url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: path}
	}
	return &API{
		coordinator: config.Coordinator, featureQuotas: config.FeatureQuotas,
		jwks: config.JWKS, origin: origin, targets: targets,
	}, nil
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
	if origin.Scheme != "https" && (origin.Scheme != "http" || !isLoopback(origin.Hostname())) {
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
	correlationID := selectCorrelationID(r)
	w.Header().Set("X-Latchway-Request-ID", correlationID)
	browserOrigin, originErr := weborigin.Read(r.Header)
	if originErr != nil {
		api.writeViolation(w, correlationID, invalidAt("header.Origin", "Origin must be exactly one canonical HTTPS browser origin."))
		return
	}
	if browserOrigin != "" {
		weborigin.SetResponseHeaders(w.Header(), browserOrigin)
	}
	if r.Method == http.MethodOptions {
		api.preflight(w, r, correlationID, browserOrigin)
		return
	}
	logicalID, ok := requestidentity.FromContext(r.Context())
	if !ok {
		api.writeProblem(w, correlationID, problem.Error{
			Code: "server_not_ready", Detail: "The server could not initialize request processing.",
		})
		return
	}

	path := r.URL.EscapedPath()
	if path != r.URL.Path {
		api.writeProblem(w, correlationID, problem.Error{Code: "resource_not_found", Detail: "The client endpoint was not found."})
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		api.writeViolation(w, correlationID, invalidAt("query", "Query parameters are not supported by this endpoint."))
		return
	}
	if feature, ok := featureFromQuotaPath(path); ok {
		if r.Method != http.MethodGet {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.getFeatureQuota(w, r, correlationID, logicalID, feature)
		return
	}
	if componentID, ok := componentFromRevokePath(path); ok {
		if r.Method != http.MethodDelete {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.revokeComponent(w, r, correlationID, logicalID.String(), componentID, path)
		return
	}

	switch path {
	case challengePath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.createChallenge(w, r, correlationID, logicalID.String())
	case exchangePath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.exchangeSession(w, r, correlationID, logicalID.String())
	case refreshPath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.refreshSession(w, r, correlationID, logicalID.String())
	case provisionComponentPath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.provisionComponent(w, r, correlationID, logicalID.String())
	case componentSessionPath:
		if r.Method != http.MethodPost {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.createComponentSession(w, r, correlationID, logicalID.String())
	case revokeFamilyPath:
		if r.Method != http.MethodDelete {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.revokeCurrentFamily(w, r, correlationID, logicalID.String())
	case revokePath:
		if r.Method != http.MethodDelete {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.revokeCurrentInstallation(w, r, correlationID, logicalID.String())
	case diagnosticsPath:
		if r.Method != http.MethodGet {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.getDiagnostics(w, r, correlationID, logicalID.String())
	case jwksPath:
		if r.Method != http.MethodGet {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.publicJWKS(w, r, correlationID)
	case discoveryPath:
		if r.Method != http.MethodGet {
			api.methodNotAllowed(w, correlationID)
			return
		}
		api.publicDiscovery(w, r, correlationID)
	default:
		api.writeProblem(w, correlationID, problem.Error{Code: "resource_not_found", Detail: "The client endpoint was not found."})
	}
}

func componentFromRevokePath(path string) (string, bool) {
	if !strings.HasPrefix(path, revokeComponentPrefix) {
		return "", false
	}
	componentID := strings.TrimPrefix(path, revokeComponentPrefix)
	if strings.Contains(componentID, "/") || !clientComponentPattern.MatchString(componentID) {
		return "", false
	}
	return componentID, true
}

func featureFromQuotaPath(path string) (string, bool) {
	if !strings.HasPrefix(path, featureQuotaPrefix) || !strings.HasSuffix(path, featureQuotaSuffix) {
		return "", false
	}
	feature := strings.TrimSuffix(strings.TrimPrefix(path, featureQuotaPrefix), featureQuotaSuffix)
	if !identifierPattern.MatchString(feature) {
		return "", false
	}
	return feature, true
}

func (api *API) createChallenge(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
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
	input.Metadata = api.metadata(r, logicalRequestID, declaration, http.MethodPost, challengePath, proof)
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

func (api *API) exchangeSession(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
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
	input.Metadata = api.metadata(r, logicalRequestID, declaration, http.MethodPost, exchangePath, proof)
	result, err := api.coordinator.ExchangeSession(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := grantDocumentFor(result, declaration.sdk, declaration.protocolVersion == buildinfo.ProtocolVersion)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusCreated, "no-store", document)
}

func (api *API) refreshSession(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
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
	input.Metadata = api.metadata(r, logicalRequestID, declaration, http.MethodPost, refreshPath, proof)
	result, err := api.coordinator.RefreshSession(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := grantDocumentFor(result, declaration.sdk, declaration.protocolVersion == buildinfo.ProtocolVersion)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusOK, "no-store", document)
}

func (api *API) provisionComponent(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	if violation := requireCurrentProtocol(declaration); violation != nil {
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
	input, violation := parseProvisionComponentRequest(r, declaration)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input.AccessToken = accessToken
	input.Metadata = api.metadata(r, logicalRequestID, declaration, http.MethodPost, provisionComponentPath, proof)
	result, err := api.coordinator.ProvisionComponent(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := provisionComponentDocumentFor(result)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusCreated, "no-store", document)
}

func (api *API) createComponentSession(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	if violation := requireCurrentProtocol(declaration); violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	proof, violation := parseDPoPHeader(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input, violation := parseComponentSessionRequest(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input.Metadata = api.metadata(r, logicalRequestID, declaration, http.MethodPost, componentSessionPath, proof)
	result, err := api.coordinator.CreateComponentSession(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := componentSessionDocumentFor(result, declaration.sdk)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusCreated, "no-store", document)
}

func (api *API) revokeComponent(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID, componentID, path string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	if violation := requireCurrentProtocol(declaration); violation != nil {
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
	metadata := api.metadataForPath(r, logicalRequestID, declaration, http.MethodDelete, path, proof)
	if err := api.coordinator.RevokeComponent(r.Context(), RevokeComponentInput{
		Metadata: metadata, AccessToken: accessToken, ComponentID: componentID,
	}); err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) revokeCurrentFamily(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	if violation := requireCurrentProtocol(declaration); violation != nil {
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
	if err := api.coordinator.RevokeCurrentFamily(r.Context(), RevokeFamilyInput{
		Metadata:    api.metadata(r, logicalRequestID, declaration, http.MethodDelete, revokeFamilyPath, proof),
		AccessToken: accessToken,
	}); err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) revokeCurrentInstallation(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
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
		Metadata:    api.metadata(r, logicalRequestID, declaration, http.MethodDelete, revokePath, proof),
		AccessToken: accessToken,
	}
	if err := api.coordinator.RevokeCurrentInstallation(r.Context(), input); err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) getDiagnostics(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
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
	result, err := api.coordinator.Diagnostics(r.Context(), DiagnosticsInput{
		Metadata:    api.metadata(r, logicalRequestID, declaration, http.MethodGet, diagnosticsPath, proof),
		AccessToken: accessToken,
	})
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	document, err := diagnosticsDocumentFor(result, declaration.sdk, requestID)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusOK, "no-store", document)
}

func (api *API) getFeatureQuota(w http.ResponseWriter, r *http.Request, requestID string, logicalRequestID requestidentity.LogicalID, feature string) {
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
	path := featureQuotaPrefix + feature + featureQuotaSuffix
	target := url.URL{Scheme: api.origin.Scheme, Host: api.origin.Host, Path: path}
	input := FeatureQuotaInput{
		Metadata: RequestMetadata{
			RequestID: logicalRequestID.String(), SDK: declaration.sdk, SDKVersion: declaration.sdkVersion,
			Framework: declaration.framework, FrameworkVersion: declaration.frameworkVersion,
			HTTPMethod: http.MethodGet, TargetURL: target, Origin: mustBrowserOrigin(r), DPoPProof: proof,
		},
		LogicalRequestID: logicalRequestID,
		AccessToken:      accessToken,
		Feature:          feature,
	}
	result, err := api.featureQuotas.FeatureQuota(r.Context(), input)
	if err != nil {
		api.writeFeatureDependencyFailure(w, requestID, feature, err)
		return
	}
	document, err := featureQuotaDocumentFor(result, feature)
	if err != nil {
		api.internal(w, requestID)
		return
	}
	api.writeSuccess(w, requestID, http.StatusOK, "no-store", document)
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
		CurrentProtocolVersion:    buildinfo.CurrentProtocolVersion,
		SupportedProtocolVersions: buildinfo.SupportedProtocolVersions(),
		SessionEndpoint:           exchangePath,
		DPoPAlgorithms:            []string{"ES256"},
		MaximumClockSkewSeconds:   300,
	})
}

func (api *API) metadata(r *http.Request, requestID string, declaration clientDeclaration, method, path string, proof SensitiveString) RequestMetadata {
	target := api.targets[path]
	return api.metadataForTarget(r, requestID, declaration, method, target, proof)
}

func (api *API) metadataForPath(r *http.Request, requestID string, declaration clientDeclaration, method, path string, proof SensitiveString) RequestMetadata {
	target := url.URL{Scheme: api.origin.Scheme, Host: api.origin.Host, Path: path}
	return api.metadataForTarget(r, requestID, declaration, method, target, proof)
}

func (api *API) metadataForTarget(r *http.Request, requestID string, declaration clientDeclaration, method string, target url.URL, proof SensitiveString) RequestMetadata {
	return RequestMetadata{
		RequestID: requestID, SDK: declaration.sdk, SDKVersion: declaration.sdkVersion,
		Framework: declaration.framework, FrameworkVersion: declaration.frameworkVersion,
		HTTPMethod: method, TargetURL: target, Origin: mustBrowserOrigin(r), DPoPProof: proof,
	}
}

func mustBrowserOrigin(r *http.Request) string {
	if r == nil {
		return ""
	}
	origin, err := weborigin.Read(r.Header)
	if err != nil {
		return ""
	}
	return origin
}

func (api *API) preflight(w http.ResponseWriter, r *http.Request, requestID, origin string) {
	if origin == "" || r.URL == nil || r.URL.EscapedPath() != r.URL.Path ||
		r.URL.RawQuery != "" || r.URL.ForceQuery || !bodylessPreflight(r) {
		api.writeViolation(w, requestID, invalidAt("header.Origin", "A canonical Origin is required for a CORS preflight."))
		return
	}
	expectedMethod := ""
	path := r.URL.Path
	switch path {
	case challengePath, exchangePath, refreshPath, provisionComponentPath, componentSessionPath:
		expectedMethod = http.MethodPost
	case revokePath, revokeFamilyPath:
		expectedMethod = http.MethodDelete
	case diagnosticsPath, jwksPath, discoveryPath:
		expectedMethod = http.MethodGet
	default:
		if _, ok := componentFromRevokePath(path); ok {
			expectedMethod = http.MethodDelete
		} else if _, ok := featureFromQuotaPath(path); ok {
			expectedMethod = http.MethodGet
		}
	}
	requestedMethod, err := weborigin.RequestedMethod(r.Header)
	if err != nil || expectedMethod == "" || requestedMethod != expectedMethod {
		api.writeViolation(w, requestID, invalidAt("header.Access-Control-Request-Method", "The preflight method is not supported by this client endpoint."))
		return
	}
	requestedHeaders, err := weborigin.RequestedHeaders(r.Header)
	if err != nil || !allowedClientPreflightHeaders(requestedHeaders) {
		api.writeViolation(w, requestID, invalidAt("header.Access-Control-Request-Headers", "The preflight requested unsupported client headers."))
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", expectedMethod)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP, Idempotency-Key, X-Latchway-Framework, X-Latchway-Framework-Version, X-Latchway-Protocol-Version, X-Latchway-Request-ID, X-Latchway-SDK, X-Latchway-SDK-Version")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.Header().Set("Cache-Control", "no-store")
	weborigin.AppendVary(w.Header(), "Access-Control-Request-Method")
	weborigin.AppendVary(w.Header(), "Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent)
}

func bodylessPreflight(r *http.Request) bool {
	return r != nil && r.ContentLength == 0 && len(r.TransferEncoding) == 0
}

func allowedClientPreflightHeaders(headers []string) bool {
	allowed := map[string]struct{}{
		"authorization": {}, "content-type": {}, "dpop": {}, "idempotency-key": {},
		"x-latchway-protocol-version": {}, "x-latchway-request-id": {},
		"x-latchway-framework": {}, "x-latchway-framework-version": {},
		"x-latchway-sdk": {}, "x-latchway-sdk-version": {},
	}
	for _, header := range headers {
		if _, ok := allowed[header]; !ok {
			return false
		}
	}
	return true
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
	api.writeDependencyFailureForFeature(w, requestID, "", err)
}

func (api *API) writeFeatureDependencyFailure(w http.ResponseWriter, requestID, feature string, err error) {
	api.writeDependencyFailureForFeature(w, requestID, feature, err)
}

func (api *API) writeDependencyFailureForFeature(w http.ResponseWriter, requestID, feature string, err error) {
	var failure *DependencyError
	if !errors.As(err, &failure) || failure == nil || !allowedDependencyCodeForOperation(failure.Code, feature != "") || failure.RetryAfterSeconds < 0 || failure.RetryAfterSeconds > 86400 {
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
	if problemIncludesFeature(failure.Code) {
		value.Feature = feature
	}
	if failure.Code == "protocol_version_unsupported" {
		value.SupportedProtocolVersions = buildinfo.SupportedProtocolVersions()
	}
	api.writeProblem(w, requestID, value)
}

func allowedDependencyCodeForOperation(code string, featureOperation bool) bool {
	if allowedDependencyCode(code) {
		return true
	}
	switch code {
	case "feature_not_found", "feature_not_allowed", "route_not_found", "configuration_invalid":
		return featureOperation
	default:
		return false
	}
}

func allowedDependencyCode(code string) bool {
	switch code {
	case "request_invalid",
		"identity_token_missing", "identity_token_invalid", "identity_token_expired", "identity_reauthentication_required",
		"attestation_required", "attestation_unsupported", "attestation_invalid", "attestation_stale", "attestation_step_up_required",
		"dpop_missing", "dpop_invalid", "dpop_replayed", "dpop_nonce_required",
		"session_expired", "session_revoked", "refresh_token_reused", "installation_revoked",
		"installation_family_revoked", "installation_family_not_found",
		"component_definition_not_found", "component_not_configured", "component_not_provisioned",
		"component_revoked", "component_key_invalid", "component_key_replaced",
		"component_delegation_expired", "component_feature_not_granted",
		"component_parent_trust_expired", "component_direct_attestation_required",
		"containing_app_setup_required", "framework_integration_unsupported",
		"framework_version_unsupported", "transport_destination_not_allowed",
		"transport_request_not_replayable",
		"server_not_ready", "protocol_version_unsupported", "conflict", "internal_error":
		return true
	default:
		return false
	}
}

func problemIncludesFeature(code string) bool {
	switch code {
	case "feature_not_found", "feature_not_allowed", "route_not_found":
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
		return "A fresh server DPoP nonce is required."
	case "session_expired":
		return "The Latchway session is expired."
	case "session_revoked":
		return "The Latchway session is no longer active."
	case "refresh_token_reused":
		return "Refresh-token reuse was detected and the token family is no longer active."
	case "installation_revoked":
		return "The installation is no longer active."
	case "installation_family_revoked":
		return "The installation family and all component sessions are no longer active."
	case "installation_family_not_found":
		return "The authenticated installation family could not be found."
	case "component_definition_not_found":
		return "The requested component definition is not configured."
	case "component_not_configured":
		return "The requested component is not permitted by the active configuration."
	case "component_not_provisioned":
		return "The component does not have a current provisioning grant."
	case "component_revoked":
		return "The component is no longer active."
	case "component_key_invalid":
		return "The component public key or proof is invalid."
	case "component_key_replaced":
		return "The component key has been replaced."
	case "component_delegation_expired":
		return "The component delegation is expired or already consumed."
	case "component_feature_not_granted":
		return "The requested feature set is outside the component delegation."
	case "component_parent_trust_expired":
		return "The parent component trust must be renewed before this operation."
	case "component_direct_attestation_required":
		return "The component must complete its configured direct attestation step."
	case "containing_app_setup_required":
		return "The trusted containing application must provision this component first."
	case "framework_integration_unsupported":
		return "The declared framework integration is not supported."
	case "framework_version_unsupported":
		return "The declared framework version is not supported."
	case "transport_destination_not_allowed":
		return "The authenticated transport destination is not allowed."
	case "transport_request_not_replayable":
		return "The consumed request body cannot be replayed safely."
	case "feature_not_found":
		return "The requested application feature is not configured."
	case "feature_not_allowed":
		return "The current principal is not allowed to use this feature."
	case "route_not_found":
		return "No configured upstream route is available."
	case "configuration_invalid":
		return "The active data-plane configuration cannot be enforced."
	case "server_not_ready":
		return "The gateway is not ready to complete this session operation."
	case "protocol_version_unsupported":
		return "This gateway supports Latchway protocol versions 1 and 2."
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

// selectCorrelationID preserves the bounded client-facing request hint. It is
// never an authoritative logical request identifier.
func selectCorrelationID(r *http.Request) string {
	if current := middleware.GetReqID(r.Context()); validRequestID(current) {
		return current
	}
	if candidate, ok := exactlyOneHeader(r.Header, "X-Latchway-Request-ID"); ok && validRequestID(candidate) {
		return candidate
	}
	if logicalID, ok := requestidentity.FromContext(r.Context()); ok {
		return logicalID.String()
	}
	return "request_unknown"
}

func validRequestID(value string) bool {
	return len(value) >= 8 && len(value) <= 128 && requestIDPattern.MatchString(value)
}

type featureQuotaDocument struct {
	Feature    string                      `json:"feature"`
	ObservedAt time.Time                   `json:"observed_at"`
	Limits     []featureQuotaLimitDocument `json:"limits"`
}

type featureQuotaLimitDocument struct {
	Metric    string     `json:"metric"`
	Maximum   *int64     `json:"maximum,omitempty"`
	Used      *int64     `json:"used,omitempty"`
	Reserved  *int64     `json:"reserved,omitempty"`
	Remaining *int64     `json:"remaining,omitempty"`
	ResetsAt  *time.Time `json:"resets_at,omitempty"`
	Hard      bool       `json:"hard"`
}

func featureQuotaDocumentFor(result FeatureQuotaResult, expectedFeature string) (featureQuotaDocument, error) {
	if !identifierPattern.MatchString(expectedFeature) || result.Feature != expectedFeature ||
		result.ObservedAt.IsZero() || result.ObservedAt.Location() != time.UTC ||
		len(result.Limits) > maximumFeatureQuotaLimits {
		return featureQuotaDocument{}, errors.New("invalid feature quota result")
	}

	limits := make([]featureQuotaLimitDocument, len(result.Limits))
	for index, limit := range result.Limits {
		if !supportedFeatureQuotaMetric(limit.Metric) || !limit.Hard {
			return featureQuotaDocument{}, errors.New("invalid feature quota limit")
		}
		maximum, err := safeJSONInteger(limit.Maximum)
		if err != nil {
			return featureQuotaDocument{}, err
		}
		used, err := safeJSONInteger(limit.Used)
		if err != nil {
			return featureQuotaDocument{}, err
		}
		reserved, err := safeJSONInteger(limit.Reserved)
		if err != nil {
			return featureQuotaDocument{}, err
		}
		remaining, err := safeJSONInteger(limit.Remaining)
		if err != nil {
			return featureQuotaDocument{}, err
		}
		var resetsAt *time.Time
		if limit.ResetsAt != nil {
			if limit.ResetsAt.IsZero() || limit.ResetsAt.Location() != time.UTC || !limit.ResetsAt.After(result.ObservedAt) {
				return featureQuotaDocument{}, errors.New("invalid feature quota reset time")
			}
			resetCopy := *limit.ResetsAt
			resetsAt = &resetCopy
		}
		limits[index] = featureQuotaLimitDocument{
			Metric: limit.Metric, Maximum: maximum, Used: used, Reserved: reserved,
			Remaining: remaining, ResetsAt: resetsAt, Hard: true,
		}
	}
	return featureQuotaDocument{
		Feature: result.Feature, ObservedAt: result.ObservedAt, Limits: limits,
	}, nil
}

func supportedFeatureQuotaMetric(metric string) bool {
	switch metric {
	case "logical_requests", "input_tokens", "output_tokens", "total_tokens",
		"concurrent_requests", "concurrent_streams", "cost_nano_usd":
		return true
	default:
		return false
	}
}

func safeJSONInteger(value *int64) (*int64, error) {
	if value == nil {
		return nil, nil
	}
	if *value < 0 {
		return nil, errors.New("negative feature quota counter")
	}
	if *value > maximumSafeJSONInteger {
		return nil, nil
	}
	copy := *value
	return &copy, nil
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
	CurrentProtocolVersion    int      `json:"current_protocol_version"`
	SupportedProtocolVersions []int    `json:"supported_protocol_versions"`
	SessionEndpoint           string   `json:"session_endpoint"`
	DPoPAlgorithms            []string `json:"dpop_algorithms"`
	MaximumClockSkewSeconds   int      `json:"maximum_clock_skew_seconds"`
}

type diagnosticsDocument struct {
	RequestID       string                     `json:"request_id"`
	ServerVersion   string                     `json:"server_version"`
	ContractVersion string                     `json:"contract_version"`
	ProtocolVersion int                        `json:"protocol_version"`
	Installation    InstallationSummary        `json:"installation"`
	Session         diagnosticsSessionDocument `json:"session"`
	Trust           TrustSummary               `json:"trust"`
}

type diagnosticsSessionDocument struct {
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshAvailable bool      `json:"refresh_available"`
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
		Attestation: challengeAttestationDocument(attestation),
	}, nil
}

func diagnosticsDocumentFor(result DiagnosticsResult, sdk, requestID string) (diagnosticsDocument, error) {
	installation := result.Installation
	trust := result.Trust
	if !validRequestID(requestID) || len(buildinfo.Version) < 1 || len(buildinfo.Version) > 128 ||
		strings.ContainsAny(buildinfo.Version, "\r\n\x00") ||
		!installationPattern.MatchString(installation.ID) || !validPlatform(installation.Platform) ||
		!platformCompatible(sdk, installation.Platform) || !validCanonicalBase64URL(installation.DPoPJKT, 32) ||
		installation.Status != "active" || result.SessionExpiresAt.IsZero() ||
		result.SessionExpiresAt.Location() != time.UTC || !validAttestationProvider(trust.Provider) ||
		!validTrustLevel(trust.Level) || trust.VerifiedAt.IsZero() || trust.VerifiedAt.Location() != time.UTC ||
		trust.ExpiresAt.IsZero() || trust.ExpiresAt.Location() != time.UTC ||
		!trust.ExpiresAt.After(trust.VerifiedAt) {
		return diagnosticsDocument{}, errors.New("invalid client diagnostics result")
	}
	return diagnosticsDocument{
		RequestID: requestID, ServerVersion: buildinfo.Version,
		ContractVersion: buildinfo.ContractVersion, ProtocolVersion: buildinfo.CurrentProtocolVersion,
		Installation: installation,
		Session: diagnosticsSessionDocument{
			ExpiresAt: result.SessionExpiresAt, RefreshAvailable: result.RefreshAvailable,
		},
		Trust: trust,
	}, nil
}

type grantDocument struct {
	AccessToken        string                     `json:"access_token"`
	TokenType          string                     `json:"token_type"`
	ExpiresIn          int                        `json:"expires_in"`
	RefreshToken       string                     `json:"refresh_token"`
	RefreshExpiresIn   int                        `json:"refresh_expires_in"`
	Installation       InstallationSummary        `json:"installation"`
	InstallationFamily *InstallationFamilySummary `json:"installation_family,omitempty"`
	Component          *ClientComponentSummary    `json:"component,omitempty"`
	Trust              TrustSummary               `json:"trust"`
}

type provisionComponentDocument struct {
	ComponentID           string                          `json:"component_id"`
	InstallationFamilyID  string                          `json:"installation_family_id"`
	Trust                 provisionComponentTrustDocument `json:"trust"`
	GrantedFeatures       []string                        `json:"granted_features"`
	RefreshGrant          string                          `json:"refresh_grant"`
	RefreshGrantExpiresAt time.Time                       `json:"refresh_grant_expires_at"`
}

type provisionComponentTrustDocument struct {
	Source    string    `json:"source"`
	ExpiresAt time.Time `json:"expires_at"`
}

func provisionComponentDocumentFor(result ProvisionComponentResult) (provisionComponentDocument, error) {
	grant := result.RefreshGrant.Reveal()
	if !clientComponentPattern.MatchString(result.ComponentID) ||
		!installationFamilyPattern.MatchString(result.InstallationFamilyID) ||
		(result.TrustSource != "delegated_from_attested_root" && result.TrustSource != "delegated_identity_only") ||
		result.TrustExpiresAt.IsZero() || result.RefreshGrantExpiresAt.IsZero() ||
		!result.RefreshGrantExpiresAt.Equal(result.TrustExpiresAt) ||
		!validCredential(grant, 32, 2048) || len(result.GrantedFeatures) == 0 ||
		len(result.GrantedFeatures) > 256 {
		return provisionComponentDocument{}, errors.New("invalid component provisioning result")
	}
	features := append([]string(nil), result.GrantedFeatures...)
	seen := make(map[string]struct{}, len(features))
	for _, feature := range features {
		if !identifierPattern.MatchString(feature) {
			return provisionComponentDocument{}, errors.New("invalid component provisioning features")
		}
		if _, duplicate := seen[feature]; duplicate {
			return provisionComponentDocument{}, errors.New("duplicate component provisioning feature")
		}
		seen[feature] = struct{}{}
	}
	return provisionComponentDocument{
		ComponentID: result.ComponentID, InstallationFamilyID: result.InstallationFamilyID,
		Trust:           provisionComponentTrustDocument{Source: result.TrustSource, ExpiresAt: result.TrustExpiresAt.UTC()},
		GrantedFeatures: features, RefreshGrant: grant,
		RefreshGrantExpiresAt: result.RefreshGrantExpiresAt.UTC(),
	}, nil
}

type componentSessionDocument struct {
	AccessToken      string    `json:"access_token"`
	ExpiresIn        int       `json:"expires_in"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func componentSessionDocumentFor(result GrantResult, sdk string) (componentSessionDocument, error) {
	document, err := grantDocumentFor(result, sdk, true)
	if err != nil || result.Component == nil || result.Component.IsRoot ||
		result.RefreshExpiresAt.IsZero() || result.RefreshExpiresAt.Location() != time.UTC {
		return componentSessionDocument{}, errors.New("invalid component session result")
	}
	return componentSessionDocument{
		AccessToken: document.AccessToken, ExpiresIn: document.ExpiresIn,
		RefreshToken: document.RefreshToken, RefreshExpiresAt: result.RefreshExpiresAt,
	}, nil
}

func grantDocumentFor(result GrantResult, sdk string, includeComponentMetadata bool) (grantDocument, error) {
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
	if (result.InstallationFamily == nil) != (result.Component == nil) ||
		(includeComponentMetadata && result.Component == nil) {
		return grantDocument{}, errors.New("incomplete component session result")
	}
	if result.Component != nil && !validComponentGrant(
		*result.InstallationFamily, *result.Component, trust, installation,
	) {
		return grantDocument{}, errors.New("invalid component session result")
	}
	document := grantDocument{
		AccessToken: accessToken, TokenType: "DPoP", ExpiresIn: result.ExpiresIn,
		RefreshToken: refreshToken, RefreshExpiresIn: result.RefreshExpiresIn,
		Installation: installation,
		Trust: TrustSummary{
			Provider: trust.Provider, Level: trust.Level,
			VerifiedAt: trust.VerifiedAt.UTC(), ExpiresAt: trust.ExpiresAt.UTC(),
		},
	}
	if includeComponentMetadata {
		document.InstallationFamily = result.InstallationFamily
		document.Component = result.Component
		document.Trust.Source = trust.Source
		document.Trust.ParentComponentID = trust.ParentComponentID
		document.Trust.ParentAttestationProvider = trust.ParentAttestationProvider
		document.Trust.DelegationID = trust.DelegationID
	}
	return document, nil
}

func validComponentGrant(
	family InstallationFamilySummary,
	component ClientComponentSummary,
	trust TrustSummary,
	installation InstallationSummary,
) bool {
	if !installationFamilyPattern.MatchString(family.ID) || family.Status != "active" ||
		!clientComponentPattern.MatchString(component.ID) ||
		!identifierPattern.MatchString(component.DefinitionID) ||
		!validComponentKind(component.Kind) || !validPlatform(component.Platform) ||
		component.Platform != installation.Platform || component.Status != "active" ||
		component.DPoPJKT != installation.DPoPJKT || len(component.GrantedFeatures) == 0 ||
		len(component.GrantedFeatures) > 256 || !validTrustSource(trust.Source) {
		return false
	}
	seen := make(map[string]struct{}, len(component.GrantedFeatures))
	for _, feature := range component.GrantedFeatures {
		if !identifierPattern.MatchString(feature) {
			return false
		}
		if _, exists := seen[feature]; exists {
			return false
		}
		seen[feature] = struct{}{}
	}
	if component.IsRoot {
		return trust.ParentComponentID == "" &&
			trust.ParentAttestationProvider == "" && trust.DelegationID == ""
	}
	return clientComponentPattern.MatchString(trust.ParentComponentID) &&
		componentDelegationPattern.MatchString(trust.DelegationID)
}

func validComponentKind(value string) bool {
	switch value {
	case "main_app", "widget", "share_extension", "app_intent_extension",
		"notification_service_extension", "action_extension", "sso_extension",
		"watch_extension", "android_app", "wear_app", "browser", "node_process":
		return true
	default:
		return false
	}
}

func validTrustSource(value string) bool {
	switch value {
	case "direct_attested", "delegated_from_attested_root", "delegated_identity_only",
		"identity_only", "web_risk_verified", "debug":
		return true
	default:
		return false
	}
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
		encodedPoint := make([]byte, 1+len(xBytes)+len(yBytes))
		encodedPoint[0] = 4
		copy(encodedPoint[1:], xBytes)
		copy(encodedPoint[1+len(xBytes):], yBytes)
		if _, err := ecdh.P256().NewPublicKey(encodedPoint); err != nil {
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
