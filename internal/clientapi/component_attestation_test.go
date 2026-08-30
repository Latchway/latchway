package clientapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	validComponentID = "cmp_01K3NQ7M8P9RSTVWXYZABCDE12"
	validFamilyID    = "fam_01K3NQ7M8P9RSTVWXYZABCDE12"
	validDelegation  = "dlg_01K3NQ7M8P9RSTVWXYZABCDE12"
)

func TestComponentAttestationChallengeUsesExactAuthorizedPathScope(t *testing.T) {
	coordinator := &fakeCoordinator{componentChallengeResult: validComponentAttestationChallengeResult()}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://Gateway.Example.Test/")
	path := revokeComponentPrefix + validComponentID + componentChallengeSuffix
	request := validClientRequest(http.MethodPost, path, "", "ios", "1.2.3")
	request.Header.Set("X-Latchway-Protocol-Version", "2")
	request.Header.Set("Authorization", "DPoP "+validAccessToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || len(coordinator.componentChallengeInputs) != 1 {
		t.Fatalf("status = %d, inputs = %d, body = %s", response.Code, len(coordinator.componentChallengeInputs), response.Body.String())
	}
	input := coordinator.componentChallengeInputs[0]
	if input.ComponentID != validComponentID || input.AccessToken.Reveal() != validAccessToken ||
		input.Metadata.TargetURL.String() != "https://gateway.example.test"+path ||
		input.Metadata.HTTPMethod != http.MethodPost || input.Metadata.RequestID == validRequestIDText {
		t.Fatalf("component challenge input = %#v", input)
	}
	assertOpaqueFormatting(t, validAccessToken, input)
	assertSuccessHeaders(t, response, "no-store")
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	if document["binding_version"] != float64(2) {
		t.Fatalf("challenge document = %#v", document)
	}
}

func TestComponentAttestationExchangeReturnsRotatedComponentGrant(t *testing.T) {
	coordinator := &fakeCoordinator{componentExchangeResult: validDirectComponentGrantResult()}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	path := revokeComponentPrefix + validComponentID + componentExchangeSuffix
	request := validClientRequest(http.MethodPost, path,
		`{"challenge_id":"`+validChallengeID+`","attestation":{"provider":"app_attest","evidence":{}}}`,
		"ios", "1.2.3")
	request.Header.Set("X-Latchway-Protocol-Version", "2")
	request.Header.Set("Authorization", "DPoP "+validAccessToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || len(coordinator.componentExchangeInputs) != 1 {
		t.Fatalf("status = %d, inputs = %d, body = %s", response.Code, len(coordinator.componentExchangeInputs), response.Body.String())
	}
	input := coordinator.componentExchangeInputs[0]
	if input.ComponentID != validComponentID || input.ChallengeID != validChallengeID ||
		input.Attestation.Provider != "app_attest" || input.AccessToken.Reveal() != validAccessToken ||
		input.Metadata.TargetURL.String() != "https://gateway.example.test"+path {
		t.Fatalf("component exchange input = %#v", input)
	}
	assertOpaqueFormatting(t, validAccessToken, input)
	assertSuccessHeaders(t, response, "no-store")
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document, "access_token", "token_type", "expires_in", "refresh_token", "refresh_expires_in", "installation", "installation_family", "component", "trust")
	trust := document["trust"].(map[string]any)
	if trust["source"] != "delegated_direct_attested" || trust["delegation_id"] != validDelegation {
		t.Fatalf("direct component trust = %#v", trust)
	}
}

func TestComponentAttestationExchangeAcceptsWatchOSGrantForIOSSDK(t *testing.T) {
	t.Parallel()

	grant := validDirectComponentGrantResult()
	grant.Installation.Platform = "watchos"
	grant.Component.Platform = "watchos"
	grant.Component.DefinitionID = "watch-extension"
	grant.Component.Kind = "watch_extension"
	coordinator := &fakeCoordinator{componentExchangeResult: grant}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	path := revokeComponentPrefix + validComponentID + componentExchangeSuffix
	request := validClientRequest(http.MethodPost, path,
		`{"challenge_id":"`+validChallengeID+`","attestation":{"provider":"app_attest","evidence":{}}}`,
		"ios", "1.2.3")
	request.Header.Set("X-Latchway-Protocol-Version", "2")
	request.Header.Set("Authorization", "DPoP "+validAccessToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("watchOS component grant status = %d, body = %s", response.Code, response.Body.String())
	}
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	installation := document["installation"].(map[string]any)
	component := document["component"].(map[string]any)
	if installation["platform"] != "watchos" || component["platform"] != "watchos" {
		t.Fatalf("watchOS grant document = %#v", document)
	}
}

func TestComponentAttestationRoutesRejectAmbiguousOrLegacyRequests(t *testing.T) {
	validPath := revokeComponentPrefix + validComponentID + componentChallengeSuffix
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mutate func(*http.Request)
		code   string
		status int
	}{
		{name: "legacy protocol", method: http.MethodPost, path: validPath, code: "protocol_version_unsupported", status: http.StatusUpgradeRequired,
			mutate: func(request *http.Request) { request.Header.Set("X-Latchway-Protocol-Version", "1") }},
		{name: "challenge body", method: http.MethodPost, path: validPath, body: `{}`, code: "request_invalid", status: http.StatusBadRequest},
		{name: "wrong method", method: http.MethodDelete, path: validPath, code: "request_invalid", status: http.StatusBadRequest},
		{name: "nested component", method: http.MethodPost, path: revokeComponentPrefix + validComponentID + componentChallengeSuffix + "/extra", code: "resource_not_found", status: http.StatusNotFound},
		{name: "unknown operation", method: http.MethodPost, path: revokeComponentPrefix + validComponentID + "/attest", code: "resource_not_found", status: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := &fakeCoordinator{componentChallengeResult: validComponentAttestationChallengeResult()}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			request := validClientRequest(test.method, test.path, test.body, "ios", "1.2.3")
			request.Header.Set("X-Latchway-Protocol-Version", "2")
			request.Header.Set("Authorization", "DPoP "+validAccessToken)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.code, test.status)
			if len(coordinator.componentChallengeInputs) != 0 || len(coordinator.componentExchangeInputs) != 0 {
				t.Fatal("rejected request reached coordinator")
			}
		})
	}
}

func validComponentAttestationChallengeResult() ChallengeResult {
	result := validChallengeResult()
	result.BindingVersion = 2
	result.Attestation.Provider = "app_attest"
	result.Attestation.ProviderOptions = map[string]any{
		"app_id_prefix": "ABCDE12345", "bundle_id": "com.example.extension",
	}
	return result
}

func validDirectComponentGrantResult() GrantResult {
	result := validGrantResult("ios")
	result.RefreshExpiresAt = testInstant.Add(24 * time.Hour)
	result.InstallationFamily = &InstallationFamilySummary{ID: validFamilyID, Status: "active"}
	result.Component = &ClientComponentSummary{
		ID: validComponentID, DefinitionID: "action", Kind: "action_extension",
		Platform: "ios", IsRoot: false, Status: "active", DPoPJKT: result.Installation.DPoPJKT,
		GrantedFeatures: []string{"assistant"},
	}
	result.Trust = TrustSummary{
		Provider: "app_attest", Level: "app_verified", Source: "delegated_direct_attested",
		ParentComponentID:         "cmp_01K3NQ7M8P9RSTVWXYZABCDE13",
		ParentAttestationProvider: "app_attest", DelegationID: validDelegation,
		VerifiedAt: testInstant, ExpiresAt: testInstant.Add(time.Hour),
	}
	return result
}

func TestComponentAttestationEvidenceFormattingIsRedacted(t *testing.T) {
	payload, err := NewEvidencePayload(map[string]any{"assertion": strings.Repeat("secret", 8)})
	if err != nil {
		t.Fatal(err)
	}
	input := ExchangeComponentAttestationInput{
		AccessToken: NewSensitiveString(validAccessToken),
		Attestation: AttestationEvidence{Provider: "app_attest", Payload: payload},
	}
	assertOpaqueFormatting(t, validAccessToken, input)
}
