package clientapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAttestationDiagnosticsUseExistingProblemFieldsAndRejectRawReasons(t *testing.T) {
	api := &API{}
	for _, reason := range []string{"apple_environment_rejected", "android_testing_response_rejected", "SECRET-provider-token"} {
		recorder := httptest.NewRecorder()
		api.writeDependencyFailure(recorder, "request_attestation_test", &DependencyError{Code: "attestation_invalid", AttestationReason: reason})
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(recorder.Body.String(), "SECRET") {
			t.Fatal("unsafe diagnostic escaped")
		}
		if reason == "SECRET-provider-token" {
			if body["code"] != "internal_error" {
				t.Fatal(body)
			}
		} else if body["code"] != "attestation_invalid" || body["errors"] == nil || body["reason"] != nil {
			t.Fatalf("unexpected wire shape: %v", body)
		}
	}
}
