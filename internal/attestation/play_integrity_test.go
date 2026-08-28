package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var playIntegrityTestNow = time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)

type fakePlayIntegrityDecoder struct {
	project     int64
	response    []byte
	err         error
	calls       int
	packageName string
	token       string
}

func (decoder *fakePlayIntegrityDecoder) CloudProjectNumber() int64 { return decoder.project }

func (decoder *fakePlayIntegrityDecoder) DecodeIntegrityToken(
	_ context.Context,
	packageName string,
	token string,
) ([]byte, error) {
	decoder.calls++
	decoder.packageName = packageName
	decoder.token = token
	return append([]byte(nil), decoder.response...), decoder.err
}

func TestPlayIntegrityVerifierAcceptsBoundPhysicalDeviceVerdict(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(1)
	decoder := &fakePlayIntegrityDecoder{
		project: 123456789, response: playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, nil),
	}
	verifier := mustPlayIntegrityVerifier(t, playIntegrityConfig(decoder, certificate))
	evidence := playIntegrityEvidence(t, "valid.standard_integrity-token_01")

	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("verify Play Integrity evidence: %v", err)
	}
	if result.Provider != playIntegrityProvider || result.TrustLevel != "device_verified" ||
		!result.VerifiedAt.Equal(playIntegrityTestNow) ||
		!result.ExpiresAt.Equal(playIntegrityTestNow.Add(defaultPlayIntegrityResultLifetime)) ||
		result.NormalizedSignals["verified_app_id"] != "com.latchway.fixture" ||
		result.NormalizedSignals["verified_version"] != "42" ||
		result.NormalizedSignals["licensed"] != true || decoder.calls != 1 ||
		decoder.packageName != "com.latchway.fixture" || decoder.token != "valid.standard_integrity-token_01" {
		t.Fatalf("unexpected result or decoder call: result=%#v calls=%d package=%q",
			result, decoder.calls, decoder.packageName)
	}
	bindingHash, hashErr := binding.Hash()
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	if _, err := result.ValidatedSnapshot(bindingHash, playIntegrityTestNow); err != nil {
		t.Fatalf("validate sealed result: %v", err)
	}
	if strings.Contains(fmt.Sprint(evidence), "standard_integrity") ||
		strings.Contains(fmt.Sprintf("%#v", evidence), "standard_integrity") {
		t.Fatal("Play Integrity evidence formatting exposed the token")
	}
}

func TestPlayIntegrityVerifierAcceptsReactNativeAndStrongDevice(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("react_native_android")
	certificate := playIntegrityTestCertificate(2)
	overrides := map[string]any{
		"deviceRecognitionVerdict": []any{"MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"},
	}
	decoder := &fakePlayIntegrityDecoder{
		project: 123456789, response: playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, overrides),
	}
	config := playIntegrityConfig(decoder, certificate)
	config.MinimumDeviceIntegrity = playIntegrityStrongDevice
	verifier := mustPlayIntegrityVerifier(t, config)

	result, err := verifier.Verify(
		context.Background(), playIntegrityEvidence(t, "strong.standard_integrity-token_01"), binding,
	)
	if err != nil {
		t.Fatalf("verify strong React Native verdict: %v", err)
	}
	if result.TrustLevel != "strong_device_verified" {
		t.Fatalf("strong verdict trust = %q", result.TrustLevel)
	}
}

func TestPlayIntegrityTestingResponseIsExplicitAndTrustCapped(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(3)
	response := playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, map[string]any{
		"testingResponse": true,
	})
	decoder := &fakePlayIntegrityDecoder{project: 123456789, response: response}
	config := playIntegrityConfig(decoder, certificate)
	verifier := mustPlayIntegrityVerifier(t, config)
	evidence := playIntegrityEvidence(t, "testing.standard_integrity-token_01")
	if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("default verifier accepted testing response: %v", err)
	}

	config.AllowTestingResponses = true
	verifier = mustPlayIntegrityVerifier(t, config)
	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("explicit testing response: %v", err)
	}
	if result.TrustLevel != "debug" || result.NormalizedSignals["testing_response"] != true {
		t.Fatalf("testing response was not trust-capped: %#v", result)
	}
}

func TestPlayIntegrityVerifierRejectsMismatchedAndWeakVerdicts(t *testing.T) {
	t.Parallel()
	certificate := playIntegrityTestCertificate(4)
	otherCertificate := playIntegrityTestCertificate(5)
	tests := []struct {
		name       string
		platform   string
		overrides  map[string]any
		configEdit func(*PlayIntegrityConfig)
	}{
		{name: "wrong request hash", platform: "android", overrides: map[string]any{
			"requestHash": base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)),
		}},
		{name: "request package", platform: "android", overrides: map[string]any{"requestPackageName": "com.attacker.app"}},
		{name: "app package", platform: "android", overrides: map[string]any{"appPackageName": "com.attacker.app"}},
		{name: "unrecognized app", platform: "android", overrides: map[string]any{"appVerdict": "UNRECOGNIZED_VERSION"}},
		{name: "wrong certificate", platform: "android", overrides: map[string]any{
			"certificates": []any{base64.RawURLEncoding.EncodeToString(otherCertificate[:])},
		}},
		{name: "old version", platform: "android", overrides: map[string]any{"versionCode": "40"}},
		{name: "new version", platform: "android", overrides: map[string]any{"versionCode": "44"}},
		{name: "zero version", platform: "android", overrides: map[string]any{"versionCode": "0"}},
		{name: "basic only", platform: "android", overrides: map[string]any{
			"deviceRecognitionVerdict": []any{"MEETS_BASIC_INTEGRITY"},
		}},
		{name: "virtual only", platform: "android", overrides: map[string]any{
			"deviceRecognitionVerdict": []any{"MEETS_VIRTUAL_INTEGRITY"},
		}},
		{name: "unknown with physical", platform: "android", overrides: map[string]any{
			"deviceRecognitionVerdict": []any{"MEETS_DEVICE_INTEGRITY", "UNKNOWN"},
		}},
		{name: "virtual with physical", platform: "android", overrides: map[string]any{
			"deviceRecognitionVerdict": []any{"MEETS_DEVICE_INTEGRITY", "MEETS_VIRTUAL_INTEGRITY"},
		}},
		{name: "unknown device label", platform: "android", overrides: map[string]any{
			"deviceRecognitionVerdict": []any{"TRUST_ME"},
		}},
		{name: "duplicate device label", platform: "android", overrides: map[string]any{
			"deviceRecognitionVerdict": []any{"MEETS_DEVICE_INTEGRITY", "MEETS_DEVICE_INTEGRITY"},
		}},
		{name: "unlicensed", platform: "android", overrides: map[string]any{"licensingVerdict": "UNLICENSED"}},
		{name: "future request", platform: "android", overrides: map[string]any{
			"timestampMillis": strconvFormatMillis(playIntegrityTestNow.Add(2 * time.Minute)),
		}},
		{name: "stale request", platform: "android", overrides: map[string]any{
			"timestampMillis": strconvFormatMillis(playIntegrityTestNow.Add(-5 * time.Minute)),
		}},
		{name: "request before challenge", platform: "android", overrides: map[string]any{
			"timestampMillis": strconvFormatMillis(playIntegrityTestNow.Add(-90 * time.Second)),
		}, configEdit: func(config *PlayIntegrityConfig) { config.MaximumAge = 10 * time.Minute }},
		{name: "iOS binding", platform: "ios"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding := playIntegrityBinding(test.platform)
			decoder := &fakePlayIntegrityDecoder{
				project:  123456789,
				response: playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, test.overrides),
			}
			config := playIntegrityConfig(decoder, certificate)
			if test.configEdit != nil {
				test.configEdit(&config)
			}
			verifier := mustPlayIntegrityVerifier(t, config)
			_, err := verifier.Verify(
				context.Background(), playIntegrityEvidence(t, "invalid.standard_integrity-token_01"), binding,
			)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("rejected verdict error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestPlayIntegrityVerifierRejectsUnsafeEvidenceAndDecoderResponses(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(6)
	validResponse := playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, nil)
	tests := []struct {
		name     string
		payload  map[string]any
		response []byte
	}{
		{name: "extra evidence field", payload: map[string]any{
			"integrity_token": "valid.standard_integrity-token_01", "trusted": true,
		}, response: validResponse},
		{name: "token whitespace", payload: map[string]any{"integrity_token": "invalid token with spaces"}, response: validResponse},
		{name: "duplicate response member", payload: playIntegrityPayloadMap(), response: []byte(
			`{"tokenPayloadExternal":{},"tokenPayloadExternal":{}}`,
		)},
		{name: "trailing response", payload: playIntegrityPayloadMap(), response: append(validResponse, []byte(` {}`)...)},
		{name: "missing envelope", payload: playIntegrityPayloadMap(), response: []byte(`{}`)},
		{name: "oversized response", payload: playIntegrityPayloadMap(), response: make([]byte, maxPlayIntegrityDecodedBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decoder := &fakePlayIntegrityDecoder{project: 123456789, response: test.response}
			verifier := mustPlayIntegrityVerifier(t, playIntegrityConfig(decoder, certificate))
			evidence, err := NewEvidence(playIntegrityProvider, test.payload)
			if err != nil {
				if errors.Is(err, ErrInvalid) {
					return
				}
				t.Fatal(err)
			}
			if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe input error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestPlayIntegrityVerifierSanitizesDecoderFailureAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(7)
	decoder := &fakePlayIntegrityDecoder{
		project: 123456789, err: errors.New("provider payload with integrity token secret-token-value"),
	}
	verifier := mustPlayIntegrityVerifier(t, playIntegrityConfig(decoder, certificate))
	evidence := playIntegrityEvidence(t, "valid.standard_integrity-token_01")
	_, err := verifier.Verify(context.Background(), evidence, binding)
	if !errors.Is(err, ErrPlayIntegrityService) || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("decoder error was not sanitized: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := decoder.calls
	if _, err := verifier.Verify(ctx, evidence, binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled verification error = %v", err)
	}
	if decoder.calls != before {
		t.Fatal("pre-canceled verification called decoder")
	}
}

func TestPlayIntegrityVerifierConfigurationIsFailClosed(t *testing.T) {
	t.Parallel()
	certificate := playIntegrityTestCertificate(8)
	baseDecoder := &fakePlayIntegrityDecoder{project: 123456789}
	var typedNilDecoder *fakePlayIntegrityDecoder
	tests := []struct {
		name string
		edit func(*PlayIntegrityConfig)
	}{
		{name: "application", edit: func(config *PlayIntegrityConfig) { config.ApplicationID = "" }},
		{name: "environment", edit: func(config *PlayIntegrityConfig) { config.EnvironmentID = "Production" }},
		{name: "package", edit: func(config *PlayIntegrityConfig) { config.PackageName = "not-a-package" }},
		{name: "project", edit: func(config *PlayIntegrityConfig) { config.CloudProjectNumber = 0 }},
		{name: "nil decoder", edit: func(config *PlayIntegrityConfig) { config.Decoder = nil }},
		{name: "typed nil decoder", edit: func(config *PlayIntegrityConfig) {
			config.Decoder = typedNilDecoder
		}},
		{name: "decoder project", edit: func(config *PlayIntegrityConfig) {
			config.Decoder = &fakePlayIntegrityDecoder{project: 7}
		}},
		{name: "certificate", edit: func(config *PlayIntegrityConfig) {
			config.CertificateSHA256Digests = []string{"not-a-digest"}
		}},
		{name: "duplicate certificate", edit: func(config *PlayIntegrityConfig) {
			config.CertificateSHA256Digests = append(config.CertificateSHA256Digests, config.CertificateSHA256Digests[0])
		}},
		{name: "zero certificate", edit: func(config *PlayIntegrityConfig) {
			config.CertificateSHA256Digests = []string{
				base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)),
			}
		}},
		{name: "basic device", edit: func(config *PlayIntegrityConfig) { config.MinimumDeviceIntegrity = "basic" }},
		{name: "version range", edit: func(config *PlayIntegrityConfig) {
			config.MinimumVersionCode, config.MaximumVersionCode = 43, 42
		}},
		{name: "age", edit: func(config *PlayIntegrityConfig) { config.MaximumAge = time.Hour }},
		{name: "skew", edit: func(config *PlayIntegrityConfig) { config.ClockSkew = time.Hour }},
		{name: "lifetime", edit: func(config *PlayIntegrityConfig) { config.ResultLifetime = time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := playIntegrityConfig(baseDecoder, certificate)
			test.edit(&config)
			if _, err := NewPlayIntegrityVerifier(config); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("configuration error = %v, want ErrConfiguration", err)
			}
		})
	}

	padded := base64.URLEncoding.EncodeToString(certificate[:])
	config := playIntegrityConfig(baseDecoder, certificate)
	config.CertificateSHA256Digests = []string{padded}
	if _, err := NewPlayIntegrityVerifier(config); err != nil {
		t.Fatalf("canonical padded web-safe digest should be accepted: %v", err)
	}

	evidence := playIntegrityEvidence(t, "valid.standard_integrity-token_01")
	binding := playIntegrityBinding("android")
	var zero PlayIntegrityVerifier
	if _, err := zero.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("zero-value verifier error = %v", err)
	}
	if _, err := (*PlayIntegrityVerifier)(nil).Verify(context.Background(), evidence, binding); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil verifier error = %v", err)
	}
}

func playIntegrityConfig(
	decoder PlayIntegrityTokenDecoder,
	certificate [sha256.Size]byte,
) PlayIntegrityConfig {
	return PlayIntegrityConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		PackageName: "com.latchway.fixture", CloudProjectNumber: 123456789,
		CertificateSHA256Digests: []string{base64.RawURLEncoding.EncodeToString(certificate[:])},
		MinimumDeviceIntegrity:   playIntegrityDevice, RequireLicensed: true,
		MinimumVersionCode: 41, MaximumVersionCode: 43, Decoder: decoder,
		Now: func() time.Time { return playIntegrityTestNow },
	}
}

func mustPlayIntegrityVerifier(t *testing.T, config PlayIntegrityConfig) *PlayIntegrityVerifier {
	t.Helper()
	verifier, err := NewPlayIntegrityVerifier(config)
	if err != nil {
		t.Fatalf("construct Play Integrity verifier: %v", err)
	}
	return verifier
}

func playIntegrityBinding(platform string) Binding {
	binding := testBinding()
	binding.Platform = platform
	binding.IssuedAt = playIntegrityTestNow.Add(-30 * time.Second).Unix()
	return binding
}

func playIntegrityEvidence(t *testing.T, token string) Evidence {
	t.Helper()
	evidence, err := NewEvidence(playIntegrityProvider, map[string]any{"integrity_token": token})
	if err != nil {
		t.Fatalf("construct Play Integrity evidence: %v", err)
	}
	return evidence
}

func playIntegrityPayloadMap() map[string]any {
	return map[string]any{"integrity_token": "valid.standard_integrity-token_01"}
}

func playIntegrityResponse(
	t *testing.T,
	binding Binding,
	now time.Time,
	certificate [sha256.Size]byte,
	overrides map[string]any,
) []byte {
	t.Helper()
	requestHash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"requestPackageName": "com.latchway.fixture",
		"requestHash":        requestHash,
		"timestampMillis":    strconvFormatMillis(now.Add(-10 * time.Second)),
	}
	app := map[string]any{
		"appRecognitionVerdict":   "PLAY_RECOGNIZED",
		"packageName":             "com.latchway.fixture",
		"certificateSha256Digest": []any{base64.RawURLEncoding.EncodeToString(certificate[:])},
		"versionCode":             "42",
	}
	device := map[string]any{
		"deviceRecognitionVerdict": []any{"MEETS_DEVICE_INTEGRITY"},
	}
	account := map[string]any{"appLicensingVerdict": "LICENSED"}
	testingResponse := false
	for key, value := range overrides {
		switch key {
		case "requestPackageName", "requestHash", "timestampMillis":
			request[key] = value
		case "appPackageName":
			app["packageName"] = value
		case "appVerdict":
			app["appRecognitionVerdict"] = value
		case "certificates":
			app["certificateSha256Digest"] = value
		case "versionCode":
			app["versionCode"] = value
		case "deviceRecognitionVerdict":
			device["deviceRecognitionVerdict"] = value
		case "licensingVerdict":
			account["appLicensingVerdict"] = value
		case "testingResponse":
			testingResponse, _ = value.(bool)
		default:
			t.Fatalf("unknown Play Integrity fixture override %q", key)
		}
	}
	payload := map[string]any{
		"requestDetails":  request,
		"appIntegrity":    app,
		"deviceIntegrity": device,
		"accountDetails":  account,
		"environmentDetails": map[string]any{
			"playProtectVerdict": "NO_ISSUES",
		},
	}
	if testingResponse {
		payload["testingDetails"] = map[string]any{"isTestingResponse": true}
	}
	encoded, err := json.Marshal(map[string]any{"tokenPayloadExternal": payload})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func playIntegrityTestCertificate(seed byte) [sha256.Size]byte {
	var certificate [sha256.Size]byte
	for index := range certificate {
		certificate[index] = seed + byte(index)
	}
	return certificate
}

func strconvFormatMillis(value time.Time) string {
	return fmt.Sprintf("%d", value.UnixMilli())
}
