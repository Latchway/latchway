package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFailureDiagnosticUsesOnlyTypedClosedReasons(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want FailureDiagnostic
	}{
		{"nil", nil, FailureDiagnostic{}},
		{"unknown", errors.New("play integrity application certificate SECRET"), FailureDiagnostic{Reason: "verification_failed"}},
		{"invalid sentinel", fmt.Errorf("SECRET: %w", ErrInvalid), FailureDiagnostic{Reason: "evidence_invalid"}},
		{"malicious reason", invalid("SECRET\nplay integrity app package"), FailureDiagnostic{Reason: "evidence_invalid"}},
		{"wrapped known", fmt.Errorf("Bearer SECRET: %w", invalid("play integrity app package")), FailureDiagnostic{Reason: "play_integrity_app_package_invalid"}},
		{"stale", ErrStale, FailureDiagnostic{Reason: "evidence_stale"}},
		{"configuration", ErrConfiguration, FailureDiagnostic{Reason: "configuration_invalid"}},
		{"service", fmt.Errorf("credential SECRET: %w", ErrPlayIntegrityService), FailureDiagnostic{Reason: "service_unavailable"}},
		{"key store", ErrAppAttestKeyStore, FailureDiagnostic{Reason: "app_attest_key_store_unavailable"}},
		{"unsupported", ErrUnsupported, FailureDiagnostic{Reason: "provider_unsupported"}},
		{"canceled", context.Canceled, FailureDiagnostic{Reason: "operation_canceled"}},
		{"timeout", context.DeadlineExceeded, FailureDiagnostic{Reason: "operation_timed_out"}},
		{"token rejected", ErrPlayIntegrityTokenRejected, FailureDiagnostic{Reason: "play_integrity_token_rejected"}},
		{"apple phase", appAttestFailure(AppAttestFailurePhaseAttestationObject, invalid("app attest attestation CBOR")), FailureDiagnostic{Reason: "app_attest_attestation_cbor_invalid", Phase: "attestation_object"}},
		{"unknown apple phase", appAttestFailure(AppAttestFailurePhase("SECRET"), invalid("app attest assertion key")), FailureDiagnostic{Reason: "app_attest_assertion_key_invalid"}},
		{"unknown recognition", &playIntegrityAppRecognitionFailure{category: "SECRET", cause: invalid("play integrity app package")}, FailureDiagnostic{Reason: "play_integrity_app_package_invalid"}},
		{"unbounded HTTP", &playIntegrityHTTPFailure{status: 999999, cause: ErrPlayIntegrityService}, FailureDiagnostic{Reason: "service_unavailable"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := FailureDiagnosticOf(test.err); got != test.want {
				t.Fatalf("diagnostic = %#v, want %#v", got, test.want)
			}
			encoded, err := json.Marshal(FailureDiagnosticOf(test.err))
			if err != nil || strings.Contains(string(encoded), "SECRET") {
				t.Fatal("diagnostic exposed private error text")
			}
		})
	}
}

// Error() deliberately panics so a regression that inspects arbitrary provider
// error strings is caught even when its rendered value would happen to be safe.
type diagnosticOpaqueWrapper struct{ cause error }

func (diagnosticOpaqueWrapper) Error() string         { panic("must not inspect error text") }
func (wrapper diagnosticOpaqueWrapper) Unwrap() error { return wrapper.cause }

func TestFailureDiagnosticDoesNotInspectErrorStrings(t *testing.T) {
	t.Parallel()
	got := FailureDiagnosticOf(diagnosticOpaqueWrapper{cause: invalid("play integrity app certificate")})
	if got.Reason != "play_integrity_app_certificate_invalid" {
		t.Fatalf("unexpected diagnostic %#v", got)
	}
}

func TestFailureDiagnosticCoversEveryAuthoredMobileAndBindingReason(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	machineReason := regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
			!(strings.HasPrefix(name, "app_attest") || strings.HasPrefix(name, "play_integrity") || name == "binding.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Clean(name), nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			function, ok := call.Fun.(*ast.Ident)
			if !ok || function.Name != "invalid" || len(call.Args) != 1 {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Errorf("%s has an unreviewed dynamic invalid reason", name)
				return true
			}
			reason, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				t.Fatal(unquoteErr)
			}
			seen[reason] = true
			diagnostic := FailureDiagnosticOf(invalid(reason))
			if diagnostic.Reason == "evidence_invalid" || !machineReason.MatchString(diagnostic.Reason) {
				t.Errorf("%s reason %q has no reviewed machine diagnostic", name, reason)
			}
			return true
		})
	}
	if len(seen) < 60 {
		t.Fatalf("source coverage unexpectedly scanned only %d reasons", len(seen))
	}
}

func TestPlayIntegrityHTTPDiagnosticsSurviveDecoderAndVerifierWithoutChangingClassification(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		status int
		reason string
	}{
		{400, "play_integrity_token_rejected"},
		{401, "play_integrity_decode_unauthenticated"},
		{403, "play_integrity_decode_permission_denied"},
		{429, "play_integrity_decode_rate_limited"},
		{500, "play_integrity_decode_service_unavailable"},
		{503, "play_integrity_decode_service_unavailable"},
		{599, "play_integrity_decode_service_unavailable"},
		{307, "play_integrity_decode_http_error"},
		{404, "play_integrity_decode_http_error"},
	} {
		t.Run(strconv.Itoa(test.status), func(t *testing.T) {
			t.Parallel()
			decoder := mustGooglePlayIntegrityDecoder(t, GooglePlayIntegrityDecoderConfig{
				CloudProjectNumber: 123456789,
				TokenSource: &fakePlayIntegrityAccessTokenSource{token: PlayIntegrityAccessToken{
					Value: "ya29.SECRET-CREDENTIAL", ExpiresAt: playIntegrityTestNow.Add(time.Hour),
				}},
				Transport: playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
					return googleDecodeResponse(test.status, "application/json", []byte(`{"error":"SECRET-PAYLOAD"}`)), nil
				}),
				Now: func() time.Time { return playIntegrityTestNow },
			})
			_, decodeErr := decoder.DecodeIntegrityToken(context.Background(), "com.latchway.fixture", "SECRET-EVIDENCE-OPAQUE-TOKEN")
			decodeWant, verifyWant := ErrPlayIntegrityService, ErrPlayIntegrityService
			if test.status == 400 {
				decodeWant, verifyWant = ErrPlayIntegrityTokenRejected, ErrInvalid
			}
			if !errors.Is(decodeErr, decodeWant) {
				t.Fatal("decoder changed existing sentinel classification")
			}
			certificate := playIntegrityTestCertificate(81)
			verifier := mustPlayIntegrityVerifier(t, playIntegrityConfig(decoder, certificate))
			_, verifyErr := verifier.Verify(context.Background(), playIntegrityEvidence(t, "SECRET-EVIDENCE-OPAQUE-TOKEN"), playIntegrityBinding("android"))
			if !errors.Is(verifyErr, verifyWant) || (test.status == 400 && errors.Is(verifyErr, ErrPlayIntegrityService)) {
				t.Fatal("verifier changed existing client-facing classification")
			}
			want := FailureDiagnostic{Reason: test.reason, Phase: "google_decode", HTTPStatus: test.status}
			for _, failure := range []error{decodeErr, verifyErr, fmt.Errorf("SECRET-WRAPPER: %w", verifyErr)} {
				if got := FailureDiagnosticOf(failure); got != want {
					t.Fatalf("diagnostic = %#v, want %#v", got, want)
				}
				if ClientFailureReason(failure) != "" {
					t.Fatal("operator-only HTTP diagnostic changed client error detail")
				}
			}
			if strings.Contains(decodeErr.Error(), "SECRET") || strings.Contains(verifyErr.Error(), "SECRET") {
				t.Fatal("typed HTTP error retained provider evidence or credentials")
			}
		})
	}
}

func TestPlayIntegrityAppRecognitionDiagnosticsPreserveMissingFieldRejection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		verdict string
		reason  string
	}{
		{"UNRECOGNIZED_VERSION", "play_integrity_app_unrecognized"},
		{"UNEVALUATED", "play_integrity_app_unevaluated"},
		{"SECRET-UNKNOWN-VERDICT", "play_integrity_app_package_invalid"},
		{"PLAY_RECOGNIZED", "play_integrity_app_package_invalid"},
	} {
		t.Run(test.verdict, func(t *testing.T) {
			t.Parallel()
			binding := playIntegrityBinding("android")
			certificate := playIntegrityTestCertificate(82)
			encoded := playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, nil)
			var response map[string]any
			if err := json.Unmarshal(encoded, &response); err != nil {
				t.Fatal(err)
			}
			// Real negative verdicts can omit the identity fields entirely.
			response["tokenPayloadExternal"].(map[string]any)["appIntegrity"] = map[string]any{
				"appRecognitionVerdict": test.verdict,
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			decoder := &fakePlayIntegrityDecoder{project: 123456789, response: encoded}
			config := playIntegrityConfig(decoder, certificate)
			config.AllowTestingResponses = true
			verifier := mustPlayIntegrityVerifier(t, config)
			_, failure := verifier.Verify(context.Background(), playIntegrityEvidence(t, "SECRET-EVIDENCE-OPAQUE-TOKEN"), binding)
			if !errors.Is(failure, ErrInvalid) || ClientFailureReason(failure) != "" {
				t.Fatal("recognition diagnostic changed existing rejection/client detail")
			}
			var invalidFailure *invalidEvidenceError
			if !errors.As(failure, &invalidFailure) || invalidFailure.reason != "play integrity app package" {
				t.Fatal("original missing-field validation was changed")
			}
			if got := FailureDiagnosticOf(failure); got != (FailureDiagnostic{Reason: test.reason}) {
				t.Fatalf("diagnostic = %#v, want %s", got, test.reason)
			}
			if strings.Contains(failure.Error(), "SECRET") {
				t.Fatal("recognition diagnostic retained unreviewed verdict/evidence")
			}
		})
	}
}

func TestPlayIntegrityRecognitionAnnotationPreservesExistingClientBindingReason(t *testing.T) {
	t.Parallel()
	for _, verdict := range []string{"UNRECOGNIZED_VERSION", "UNEVALUATED", "UNREVIEWED-SECRET"} {
		failure := playIntegrityAppRecognitionDiagnostic(invalid("play integrity request or app binding"), verdict)
		if !errors.Is(failure, ErrInvalid) || ClientFailureReason(failure) != "android_app_binding_rejected" {
			t.Fatal("recognition annotation changed existing client binding error")
		}
	}
}
