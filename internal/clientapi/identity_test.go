package clientapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type identityCoordinatorFake struct {
	fakeCoordinator
	input  VerifyIdentityInput
	result VerifyIdentityResult
	err    error
	calls  int
}

func (fake *identityCoordinatorFake) VerifySessionIdentity(_ context.Context, input VerifyIdentityInput) (VerifyIdentityResult, error) {
	fake.input = input
	fake.calls++
	return fake.result, fake.err
}

func identityRequest(body string) *http.Request {
	r := validClientRequest(http.MethodPost, verifyIdentityPath, body, "native", "1.2.0")
	r.Header.Set("X-Latchway-Protocol-Version", "3")
	r.Header.Set("X-Latchway-Caller", "react-native")
	return r
}

const identityVerificationBody = `{"refresh_token":"abcdefghijklmnopqrstuvwxyz0123456789","identity":{"provider":"firebase","token":"private-id-token"}}`

func TestSuppliedIdentityWireAndDiscovery(t *testing.T) {
	fake := &identityCoordinatorFake{result: VerifyIdentityResult{InstallationID: validInstallation,
		Identity: VerifiedIdentity{Provider: "firebase", Issuer: "https://identity.example.test", Subject: "current-user",
			Audience: []string{"project"}, VerifiedAt: testInstant, ExpiresAt: testInstant.Add(time.Hour)}}}
	handler := newTestHandler(t, fake, &fakeJWKSProvider{}, "https://gateway.example.test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, identityRequest(identityVerificationBody))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("identity status=%d body=%s", w.Code, w.Body.String())
	}
	if fake.input.Metadata.TargetURL.String() != "https://gateway.example.test"+verifyIdentityPath || fake.input.Metadata.Caller != "react-native" || fake.input.RefreshToken.Reveal() != "abcdefghijklmnopqrstuvwxyz0123456789" || fake.input.IdentityToken.Reveal() != "private-id-token" {
		t.Fatal("identity request boundary changed")
	}
	if strings.Contains(fmt.Sprintf("%+v", fake.input), "private-id-token") {
		t.Fatal("identity credential escaped redaction")
	}
	var result VerifyIdentityResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.InstallationID != validInstallation || !result.Identity.ExpiresAt.Equal(testInstant.Add(time.Hour)) {
		t.Fatalf("identity result: %v", err)
	}
	if strings.Contains(w.Body.String(), "private-id-token") || strings.Contains(w.Body.String(), "refresh_token") {
		t.Fatal("identity response leaked credentials")
	}
	discovery := httptest.NewRecorder()
	handler.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, discoveryPath, nil))
	if !strings.Contains(discovery.Body.String(), `"supplied_identity_v1"`) || !strings.Contains(discovery.Body.String(), `"identity_verification_endpoint":"/client/v1/sessions/identity"`) {
		t.Fatal("capability not negotiated")
	}
	old := httptest.NewRecorder()
	newTestHandler(t, &fakeCoordinator{}, &fakeJWKSProvider{}, "https://gateway.example.test").ServeHTTP(old, httptest.NewRequest(http.MethodGet, discoveryPath, nil))
	if strings.Contains(old.Body.String(), "supplied_identity_v1") {
		t.Fatal("unsupported coordinator advertised identity verification")
	}
}

func TestSuppliedIdentityRejectsMalformedAndUntrustedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"extra principal":  strings.Replace(identityVerificationBody, `"token":"private-id-token"`, `"token":"private-id-token","subject":"other"`, 1),
		"duplicate token":  strings.Replace(identityVerificationBody, `"token":"private-id-token"`, `"token":"a","token":"b"`, 1),
		"missing identity": `{"refresh_token":"abcdefghijklmnopqrstuvwxyz0123456789"}`,
		"invalid provider": strings.Replace(identityVerificationBody, "firebase", "../firebase", 1),
		"empty token":      strings.Replace(identityVerificationBody, "private-id-token", "", 1),
		"oversize token":   strings.Replace(identityVerificationBody, "private-id-token", strings.Repeat("x", 65537), 1),
	} {
		t.Run(name, func(t *testing.T) {
			fake := &identityCoordinatorFake{}
			w := httptest.NewRecorder()
			newTestHandler(t, fake, &fakeJWKSProvider{}, "https://gateway.example.test").ServeHTTP(w, identityRequest(body))
			if w.Code != http.StatusBadRequest || fake.calls != 0 {
				t.Fatalf("invalid input accepted: %d", w.Code)
			}
		})
	}
	fake := &identityCoordinatorFake{}
	handler := newTestHandler(t, fake, &fakeJWKSProvider{}, "https://gateway.example.test")
	r := identityRequest(identityVerificationBody)
	r.Header.Set("X-Latchway-Protocol-Version", "2")
	r.Header.Set("X-Latchway-SDK", "ios")
	r.Header.Del("X-Latchway-Caller")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUpgradeRequired || fake.calls != 0 {
		t.Fatal("legacy protocol reached identity verification")
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, identityRequest(identityVerificationBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatal("invalid trusted dependency response published")
	}
}
