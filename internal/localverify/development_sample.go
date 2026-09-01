package localverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/weborigin"
)

type developmentSampleResult struct {
	RequestID string `json:"request_id"`
	Feature   string `json:"feature"`
	Protocol  string `json:"protocol"`
	Status    string `json:"status"`
	Model     string `json:"model"`
}

const developmentSampleTimeout = 30 * time.Second

// developmentSampleRequest is deliberately available only on the isolated
// loopback development server. It runs one synthetic client through the same
// OIDC, challenge-bound debug attestation, DPoP, policy, quota, routing,
// upstream, settlement, and durable request paths used by a real SDK. The
// browser receives only redaction-safe request metadata.
func (f *fixture) developmentSampleRequest(writer http.ResponseWriter, request *http.Request) {
	if !f.developmentConsoleRequestAllowed(writer, request) {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 128)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input map[string]json.RawMessage
	if err := decoder.Decode(&input); err != nil || input == nil || len(input) != 0 || decoder.Decode(&struct{}{}) != io.EOF {
		writeDevelopmentProblem(writer, http.StatusBadRequest, "development_sample_request_invalid")
		return
	}

	release, acquired := f.tryAcquireDevelopmentSample()
	if !acquired {
		writeDevelopmentProblem(writer, http.StatusConflict, "development_sample_busy")
		return
	}
	defer release()
	operationContext, cancel := context.WithTimeout(request.Context(), developmentSampleTimeout)
	defer cancel()
	result, err := f.runDevelopmentSample(operationContext)
	if err != nil {
		writeDevelopmentProblem(writer, http.StatusBadGateway, "development_sample_failed")
		return
	}
	writeDevelopmentJSON(writer, http.StatusCreated, result)
}

func (f *fixture) tryAcquireDevelopmentSample() (func(), bool) {
	if f == nil {
		return nil, false
	}
	f.developmentSampleGateOnce.Do(func() {
		f.developmentSampleGate = make(chan struct{}, 1)
	})
	select {
	case f.developmentSampleGate <- struct{}{}:
		return func() { <-f.developmentSampleGate }, true
	default:
		return nil, false
	}
}

func (f *fixture) developmentConsoleRequestAllowed(writer http.ResponseWriter, request *http.Request) bool {
	writer.Header().Set("Cache-Control", "no-store")
	origin, originErr := weborigin.Read(request.Header)
	if originErr != nil || (origin != f.origin() && origin != f.browserOrigin) {
		writeDevelopmentProblem(writer, http.StatusForbidden, "development_origin_not_allowed")
		return false
	}
	weborigin.SetResponseHeaders(writer.Header(), origin)
	if request.Method == http.MethodOptions {
		requestedMethod, methodErr := weborigin.RequestedMethod(request.Header)
		requestedHeaders, headersErr := weborigin.RequestedHeaders(request.Header)
		if methodErr != nil || requestedMethod != http.MethodPost || headersErr != nil ||
			len(requestedHeaders) != 1 || requestedHeaders[0] != "content-type" {
			writeDevelopmentProblem(writer, http.StatusBadRequest, "development_preflight_invalid")
			return false
		}
		weborigin.AppendVary(writer.Header(), "Access-Control-Request-Method")
		weborigin.AppendVary(writer.Header(), "Access-Control-Request-Headers")
		writer.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
		writer.Header().Set("Access-Control-Allow-Headers", "content-type")
		writer.WriteHeader(http.StatusNoContent)
		return false
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost+", "+http.MethodOptions)
		writeDevelopmentProblem(writer, http.StatusMethodNotAllowed, "development_method_not_allowed")
		return false
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !strings.EqualFold(contentTypes[0], "application/json") {
		writeDevelopmentProblem(writer, http.StatusBadRequest, "development_sample_request_invalid")
		return false
	}
	return true
}

func (f *fixture) runDevelopmentSample(ctx context.Context) (developmentSampleResult, error) {
	if f == nil || f.clientHandler == nil || f.dataHandler == nil || f.pool == nil {
		return developmentSampleResult{}, errors.New("development sample runtime is unavailable")
	}
	if f.accessToken == "" || !f.accessExpiresAt.After(f.clock().Add(30*time.Second)) {
		if err := f.exchangeSession(ctx); err != nil {
			return developmentSampleResult{}, err
		}
	}
	clientRequestID, err := id.New(id.LogicalRequest)
	if err != nil {
		return developmentSampleResult{}, err
	}
	target, err := parseURL(f.origin() + protocol.OpenAIResponsesPublicPath)
	if err != nil {
		return developmentSampleResult{}, err
	}
	proof, err := signDPoP(
		f.dpopKey, http.MethodPost, target, f.clock(), "development-console-"+clientRequestID, f.accessToken,
	)
	if err != nil {
		return developmentSampleResult{}, err
	}
	response, err := postFeaturePath(
		ctx, f.dataHandler, protocol.OpenAIResponsesPublicPath, f.accessToken, proof,
		developmentFeature, clientRequestID,
		map[string]any{
			"model":             "client-model-is-server-rewritten",
			"input":             "Verify the Latchway development path.",
			"max_output_tokens": int64(9_999),
		},
	)
	if err != nil {
		return developmentSampleResult{}, err
	}
	if err := requireStatus(response.ResponseRecorder, http.StatusOK); err != nil {
		return developmentSampleResult{}, err
	}

	result := developmentSampleResult{Feature: developmentFeature, Protocol: protocol.OpenAIResponsesID}
	var attemptStatus string
	err = f.pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, attempt.status, attempt.physical_model
		FROM logical_requests AS request
		JOIN upstream_attempts AS attempt
		  ON attempt.organization_id = request.organization_id
		 AND attempt.application_id = request.application_id
		 AND attempt.environment_id = request.environment_id
		 AND attempt.logical_request_id = request.logical_request_id
		WHERE request.environment_id = $1
		  AND request.client_request_id = $2
		ORDER BY attempt.attempt_number DESC
		LIMIT 1
	`, f.tenant.environmentID, clientRequestID).Scan(
		&result.RequestID, &result.Status, &attemptStatus, &result.Model,
	)
	if err != nil {
		return developmentSampleResult{}, err
	}
	if id.Validate(result.RequestID, id.LogicalRequest) != nil || result.Status != "succeeded" ||
		attemptStatus != "succeeded" || result.Model != providerModel {
		return developmentSampleResult{}, errors.New("development sample did not settle durably")
	}
	return result, nil
}

func postFeaturePath(
	ctx context.Context,
	handler http.Handler,
	path string,
	accessToken string,
	proof string,
	feature string,
	clientRequestID string,
	body any,
) (*deadlineRecorder, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request = request.WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	protectedHeaders(request, proof)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	request.Header.Set("X-Latchway-Feature", feature)
	request.Header.Set("X-Latchway-Request-ID", clientRequestID)
	response := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(response, request)
	return response, nil
}
