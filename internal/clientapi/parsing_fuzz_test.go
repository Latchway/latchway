package clientapi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzProtectedCredentialHeaders(f *testing.F) {
	minimumToken := strings.Repeat("a", minimumAccessTokenBytes)
	validProof := "header.payload.signature"
	for _, seed := range []struct {
		authorization     string
		proof             string
		authorizationMode uint8
		proofMode         uint8
	}{
		{authorization: "DPoP " + minimumToken, proof: validProof, authorizationMode: 1, proofMode: 1},
		{authorization: "dpop " + minimumToken, proof: validProof, authorizationMode: 1, proofMode: 1},
		{authorization: "Bearer " + minimumToken, proof: validProof, authorizationMode: 1, proofMode: 1},
		{authorization: "DPoP " + minimumToken, proof: validProof, authorizationMode: 2, proofMode: 2},
		{authorization: "DPoP " + minimumToken + ",DPoP " + minimumToken, proof: validProof + "," + validProof, authorizationMode: 1, proofMode: 1},
		{authorization: "DPoP " + strings.Repeat("a", maximumAccessTokenBytes), proof: "a." + strings.Repeat("b", maximumDPoPBytes-4) + ".c", authorizationMode: 1, proofMode: 1},
		{authorization: "DPoP " + strings.Repeat("a", maximumAccessTokenBytes+1), proof: "a." + strings.Repeat("b", maximumDPoPBytes-3) + ".c", authorizationMode: 1, proofMode: 1},
		{authorization: "DPoP\t" + minimumToken, proof: "header.\n.signature", authorizationMode: 1, proofMode: 1},
		{authorization: "", proof: "", authorizationMode: 0, proofMode: 0},
	} {
		f.Add(seed.authorization, seed.proof, seed.authorizationMode, seed.proofMode)
	}

	f.Fuzz(func(t *testing.T, authorization, proof string, authorizationMode, proofMode uint8) {
		// Bound the direct-header harness just beyond the production limits so
		// oversized rejection paths remain covered without unbounded allocations.
		if len(authorization) > maximumAccessTokenBytes+256 || len(proof) > maximumDPoPBytes+256 {
			return
		}
		request := &http.Request{Header: make(http.Header)}
		addFuzzHeader(request.Header, "Authorization", authorization, authorizationMode)
		addFuzzHeader(request.Header, "DPoP", proof, proofMode)

		accessToken, authorizationViolation := parseDPoPAuthorization(request)
		if authorizationViolation != nil {
			if accessToken.Reveal() != "" {
				t.Fatal("rejected Authorization header returned credential material")
			}
			assertAuthorizationFuzzViolation(t, authorizationViolation, len(request.Header.Values("Authorization")) != 1)
		} else {
			values := request.Header.Values("Authorization")
			if len(values) != 1 {
				t.Fatalf("Authorization parser accepted %d field values", len(values))
			}
			scheme, token, found := strings.Cut(values[0], " ")
			if !found || !strings.EqualFold(scheme, "DPoP") || len(token) < minimumAccessTokenBytes || len(token) > maximumAccessTokenBytes || strings.TrimSpace(values[0]) != values[0] || !validAuthorizationCredential(token) {
				t.Fatalf("Authorization parser accepted an unsafe credential shape: scheme=%q bytes=%d", scheme, len(token))
			}
			if accessToken.Reveal() != token {
				t.Fatal("Authorization parser did not preserve the exact credential bytes")
			}
			assertSensitiveStringRedacted(t, accessToken, token)
		}

		dpopProof, dpopViolation := parseDPoPHeader(request)
		if dpopViolation != nil {
			if dpopProof.Reveal() != "" {
				t.Fatal("rejected DPoP header returned proof material")
			}
			assertDPoPFuzzViolation(t, dpopViolation, len(request.Header.Values("DPoP")) == 0)
		} else {
			values := request.Header.Values("DPoP")
			if len(values) != 1 {
				t.Fatalf("DPoP parser accepted %d field values", len(values))
			}
			segments := strings.Split(values[0], ".")
			if len(values[0]) == 0 || len(values[0]) > maximumDPoPBytes || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], " \t\r\n\x00,") || len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
				t.Fatalf("DPoP parser accepted an unsafe compact proof shape: bytes=%d segments=%d", len(values[0]), len(segments))
			}
			if dpopProof.Reveal() != values[0] {
				t.Fatal("DPoP parser did not preserve the exact proof bytes")
			}
			assertSensitiveStringRedacted(t, dpopProof, values[0])
		}

		if authorizationViolation == nil && dpopViolation == nil {
			input := RevokeInstallationInput{
				AccessToken: accessToken,
				Metadata: RequestMetadata{
					HTTPMethod: http.MethodDelete,
					TargetURL:  url.URL{Scheme: "https", Host: "gateway.example.test", Path: revokePath},
					DPoPProof:  dpopProof,
				},
			}
			formatted := fmt.Sprintf("%#v", input)
			if strings.Contains(formatted, accessToken.Reveal()) || strings.Contains(formatted, dpopProof.Reveal()) {
				t.Fatal("protected request formatting exposed a credential")
			}
		}
	})
}

func addFuzzHeader(header http.Header, name, value string, mode uint8) {
	switch mode % 3 {
	case 1:
		header.Set(name, value)
	case 2:
		header.Add(name, value)
		header.Add(name, value)
	}
}

func assertAuthorizationFuzzViolation(t *testing.T, violation *requestViolation, wrongValueCount bool) {
	t.Helper()
	wantMessage := "Authorization must use exactly one bounded DPoP access token."
	if wrongValueCount {
		wantMessage = "Exactly one DPoP access token is required."
	}
	if violation.code != "request_invalid" || violation.detail != "The request does not match the Latchway client protocol." || len(violation.fields) != 1 || violation.fields[0].Path != "header.Authorization" || violation.fields[0].Message != wantMessage || len(violation.supportedProtocolVersions) != 0 {
		t.Fatalf("Authorization parser returned a noncanonical or reflective violation: %#v", violation)
	}
}

func assertDPoPFuzzViolation(t *testing.T, violation *requestViolation, missing bool) {
	t.Helper()
	wantCode := "dpop_invalid"
	if missing {
		wantCode = "dpop_missing"
	}
	wantDetail := "The DPoP proof header is invalid."
	if missing {
		wantDetail = "Exactly one DPoP proof is required."
	}
	if violation.code != wantCode || violation.detail != wantDetail || len(violation.fields) != 0 || len(violation.supportedProtocolVersions) != 0 {
		t.Fatalf("DPoP parser returned a noncanonical or reflective violation: %#v", violation)
	}
}

func assertSensitiveStringRedacted(t *testing.T, credential SensitiveString, secret string) {
	t.Helper()
	for _, format := range []string{"%#v", "%+v", "%v", "%s", "%q", "%x"} {
		formatted := fmt.Sprintf(format, credential)
		if formatted != "[REDACTED]" || strings.Contains(formatted, secret) {
			t.Fatalf("SensitiveString format %q exposed credential material: %q", format, formatted)
		}
	}
}
