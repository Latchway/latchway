package dataplane

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/upstream"
)

// Diagnostics use only established Problem members. Older SDKs reject new
// members and pin the status/retryability associated with each existing code.
func mappedProblem(code, feature string, retryAfter int, err error) problem.Error {
	value := problem.Error{Code: code, Detail: safeProblemDetail(code), RetryAfterSeconds: retryAfter}
	if problemIncludesFeature(code) {
		value.Feature = feature
	}
	var protocolError *protocol.Error
	if errors.As(err, &protocolError) && protocolError.Code == "request_invalid" &&
		len(protocolError.Detail) > 0 && len(protocolError.Detail) <= 1024 &&
		strings.IndexFunc(protocolError.Detail, unicode.IsControl) == -1 {
		// protocol.Error is authored by our adapters, never by the provider.
		value.Detail = protocolError.Detail
		value.Fields = []problem.FieldError{{Path: "body", Message: protocolError.Detail}}
	}
	var denial *quota.ExceededError
	if errors.As(err, &denial) {
		metric := safeQuotaMetric(denial.Metric())
		if denial.RequestBound() {
			value.Detail = "This request exceeds a fixed quota limit. Reduce the request size or requested output; retrying it unchanged cannot succeed."
		} else {
			value.Detail = "The configured " + metric + " quota has been reached."
		}
		value.Fields = []problem.FieldError{{Path: "quota." + metric, Message: fmt.Sprintf("Configured maximum: %d. %s", denial.Maximum(), value.Detail)}}
	}
	return value
}

func safeQuotaMetric(metric string) string {
	switch metric {
	case quota.LogicalRequestsMetric, quota.InputTokensMetric, quota.OutputTokensMetric,
		quota.TotalTokensMetric, quota.CostNanoUSDMetric, quota.RequestBytesMetric,
		quota.ImageUnitsMetric, quota.ToolCallsMetric, quota.UpstreamAttemptsMetric:
		return metric
	default:
		return "usage"
	}
}

func (handler *Handler) writeExecutionError(writer http.ResponseWriter, requestID, feature string, result executionResult) {
	if !errors.Is(result.err, upstream.ErrUpstreamNonSuccess) {
		handler.writeMappedError(writer, requestID, feature, result.err)
		return
	}
	// Classification is not evidence of zero usage. Reservation settlement has
	// already applied the separate, stricter provider-rejection accounting rule.
	code, detail := "upstream_unavailable", "The upstream service could not complete the request."
	switch result.relay.StatusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		code, detail = "request_invalid", "The upstream service rejected the request format or size. Check the request and reduce its size before retrying."
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusPaymentRequired:
		code, detail = "configuration_invalid", "The configured upstream credentials, account, or endpoint cannot serve this request. Ask the gateway administrator to check the upstream configuration."
	case http.StatusRequestTimeout:
		code, detail = "upstream_timeout", safeProblemDetail("upstream_timeout")
	case http.StatusTooManyRequests:
		detail = "The upstream service is rate limiting requests. Try again later."
	}
	value := mappedProblem(code, feature, 0, nil)
	value.Detail = detail
	if code == "upstream_unavailable" {
		value.RetryAfterSeconds = result.relay.RetryAfterSeconds
	}
	diagnostics := result.relay.ProviderError
	if code == "request_invalid" && diagnostics.Validate() == nil && diagnostics.Parameter != "" {
		value.Fields = []problem.FieldError{{Path: "body." + diagnostics.Parameter, Message: "The upstream service rejected this parameter. Check its type, structure, and supported values."}}
	}
	problem.Write(writer, requestID, value)
}
