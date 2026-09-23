package clientapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/latchway/latchway/internal/clientruntime"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/requestidentity"
)

// clientFailureResponseWriter connects the exact RFC 9457 problem selected by
// the Client API with the outer request log. It deliberately keeps only closed
// categories and bounded correlation IDs: raw paths, headers, credentials,
// proofs, bodies, provider errors, user identities and installation IDs never
// cross this boundary.
type clientFailureResponseWriter struct {
	http.ResponseWriter
	ctx       context.Context
	logger    *slog.Logger
	requestID string
	endpoint  string
	method    string
	sdk       string
	caller    string
	logged    bool
}

func newClientFailureResponseWriter(
	w http.ResponseWriter, r *http.Request, logger *slog.Logger, requestID string,
) http.ResponseWriter {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	sdk, caller := safeClientRuntimeDeclaration(r)
	return &clientFailureResponseWriter{
		ResponseWriter: w, ctx: r.Context(), logger: logger, requestID: requestID,
		endpoint: clientEndpointCategory(r.URL.Path), method: safeClientMethod(r.Method),
		sdk: sdk, caller: caller,
	}
}

func (writer *clientFailureResponseWriter) observeClientProblem(value problem.Error, stage string) {
	if writer == nil || writer.logged {
		return
	}
	writer.logged = true
	definition, ok := problem.Registry[value.Code]
	if !ok {
		value.Code = "internal_error"
		definition = problem.Registry[value.Code]
	}
	stage = safeClientFailureStage(stage)
	attributes := []slog.Attr{
		slog.String("request_id", writer.requestID),
		slog.String("endpoint", writer.endpoint),
		slog.String("method", writer.method),
		slog.String("sdk", writer.sdk),
		slog.String("caller", writer.caller),
		slog.String("failure_stage", stage),
		slog.String("error_code", value.Code),
		slog.Int("status", definition.Status),
		slog.Bool("retryable", definition.Retryable),
	}
	if logicalID, ok := requestidentity.FromContext(writer.ctx); ok {
		attributes = append(attributes, slog.String("logical_request_id", logicalID.String()))
	}
	level := slog.LevelInfo
	if definition.Status >= http.StatusInternalServerError {
		level = slog.LevelError
	} else if definition.Status == http.StatusUnauthorized || definition.Status == http.StatusForbidden {
		level = slog.LevelWarn
	}
	writer.logger.LogAttrs(writer.ctx, level, "Client API problem", attributes...)
}

func safeClientRuntimeDeclaration(r *http.Request) (string, string) {
	if r == nil {
		return "unknown", "unknown"
	}
	protocol, protocolOK := exactlyOneHeader(r.Header, "X-Latchway-Protocol-Version")
	sdk, sdkOK := exactlyOneHeader(r.Header, "X-Latchway-SDK")
	caller, callerCount := oneRawClientHeader(r.Header, clientruntime.CallerHeader)
	if !protocolOK || !sdkOK || callerCount > 1 || clientruntime.Validate(protocol, sdk, caller) != nil {
		return "unknown", "unknown"
	}
	if caller == "" {
		caller = "standalone"
	}
	return sdk, caller
}

func safeClientMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func clientEndpointCategory(path string) string {
	switch path {
	case challengePath:
		return "session_challenge"
	case exchangePath:
		return "session_exchange"
	case refreshPath:
		return "session_refresh"
	case verifyIdentityPath:
		return "identity_verification"
	case revokePath:
		return "installation_revoke"
	case provisionComponentPath:
		return "component_provision"
	case componentSessionPath:
		return "component_session"
	case revokeFamilyPath:
		return "installation_family_revoke"
	case diagnosticsPath:
		return "diagnostics"
	case jwksPath:
		return "jwks"
	case discoveryPath:
		return "discovery"
	}
	if _, operation, ok := componentAttestationOperationFromPath(path); ok {
		if operation == componentChallengeSuffix {
			return "component_attestation_challenge"
		}
		return "component_attestation_exchange"
	}
	if _, ok := componentFromRevokePath(path); ok {
		return "component_revoke"
	}
	if _, ok := featureFromQuotaPath(path); ok {
		return "feature_quota"
	}
	return "unknown"
}

func safeClientFailureStage(stage string) string {
	switch stage {
	case "routing", "request_context", "request_validation", "transport_contract",
		"dependency", "dependency_contract", "response_validation", "response_encoding", "handler":
		return stage
	default:
		return "handler"
	}
}
