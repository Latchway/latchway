package dataplane

import (
	"net/http"
	"strings"

	"github.com/latchway/latchway/internal/weborigin"
)

// servePreflight validates a syntactically safe browser delivery request
// without treating CORS as authorization. The eventual request still needs a
// DPoP-bound session whose active configuration contains the exact Origin.
func (handler *Handler) servePreflight(writer http.ResponseWriter, request *http.Request, requestID, origin string) {
	if handler == nil || request == nil || request.URL == nil || origin == "" ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		handler.writeViolation(writer, requestID, requestViolation("header.Origin", "A canonical Origin is required for a CORS preflight."))
		return
	}
	method, err := weborigin.RequestedMethod(request.Header)
	if err != nil {
		handler.writeViolation(writer, requestID, requestViolation("header.Access-Control-Request-Method", "The CORS preflight method is invalid."))
		return
	}
	probe := request.Clone(request.Context())
	probe.Method = method
	if _, violation := handler.endpoints.match(probe); violation != nil {
		handler.writeViolation(writer, requestID, violation)
		return
	}
	headers, err := weborigin.RequestedHeaders(request.Header)
	if err != nil || !safeDataPlanePreflightHeaders(headers) {
		handler.writeViolation(writer, requestID, requestViolation("header.Access-Control-Request-Headers", "The CORS preflight requested unsafe headers."))
		return
	}
	writer.Header().Set("Access-Control-Allow-Methods", method)
	if len(headers) != 0 {
		writer.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
	}
	writer.Header().Set("Access-Control-Max-Age", "600")
	writer.Header().Set("Cache-Control", "no-store")
	weborigin.AppendVary(writer.Header(), "Access-Control-Request-Method")
	weborigin.AppendVary(writer.Header(), "Access-Control-Request-Headers")
	writer.WriteHeader(http.StatusNoContent)
}

func safeDataPlanePreflightHeaders(headers []string) bool {
	for _, header := range headers {
		switch header {
		case "cookie", "set-cookie", "host", "origin", "content-length", "transfer-encoding",
			"connection", "keep-alive", "te", "trailer", "upgrade", "via", "forwarded":
			return false
		}
		if strings.HasPrefix(header, "proxy-") || strings.HasPrefix(header, "sec-") ||
			strings.HasPrefix(header, "x-forwarded-") {
			return false
		}
	}
	return true
}
