package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/secrets"
)

func TestCoordinatorBuildsProductionMobileVerifierAndProviderOptions(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := &recordingAppAttestKeyStore{}
	coordinator := &clientCoordinator{
		now: nowClock(now), appAttestKeys: store,
		attestationCache: make(map[string]*preparedAttestationVerifier),
	}
	environment := clientEnvironment{
		OrganizationID: "org_00000000000000000000000000",
		ApplicationID:  "app_00000000000000000000000000",
		EnvironmentID:  "env_00000000000000000000000000",
		Slug:           "production", Kind: "production",
	}
	policy := configuration.AttestationPolicy{ID: "native", MaxAge: 10 * time.Minute}
	selection := validAppAttestSelection()
	verifier, err := coordinator.mobileAttestationVerifier(
		environment, configuration.ActiveSnapshot{RevisionID: "rev_00000000000000000000000000"},
		policy, selection, "react_native_ios",
	)
	if err != nil || verifier == nil || verifier.ID() != "app_attest" {
		t.Fatalf("App Attest verifier = %#v, err = %v", verifier, err)
	}
	again, err := coordinator.mobileAttestationVerifier(
		environment, configuration.ActiveSnapshot{RevisionID: "rev_00000000000000000000000000"},
		policy, selection, "react_native_ios",
	)
	if err != nil || again != verifier || len(coordinator.attestationCache) != 1 {
		t.Fatalf("immutable revision verifier was not cached: again=%p first=%p err=%v cache=%d", again, verifier, err, len(coordinator.attestationCache))
	}

	play := validPlayIntegritySelection("metadata")
	options := attestationProviderOptions(play)
	if len(options) != 1 || options["cloud_project_number"] != "123456789" {
		t.Fatalf("Play provider options = %#v", options)
	}
	if options := attestationProviderOptions(selection); options != nil {
		t.Fatalf("App Attest provider options = %#v", options)
	}
}

func TestCoordinatorMobileVerifierFailsClosedOnMismatchAndProductionRisk(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	environment := clientEnvironment{
		OrganizationID: "org_00000000000000000000000000",
		ApplicationID:  "app_00000000000000000000000000",
		EnvironmentID:  "env_00000000000000000000000000",
		Slug:           "production", Kind: "production",
	}
	policy := configuration.AttestationPolicy{ID: "native", MaxAge: 10 * time.Minute}
	typedNilStore := (*recordingAppAttestKeyStore)(nil)
	tests := []struct {
		name        string
		coordinator *clientCoordinator
		selection   configuration.PlatformAttestation
		platform    string
	}{
		{
			name: "typed nil App Attest store",
			coordinator: &clientCoordinator{now: nowClock(now), appAttestKeys: typedNilStore,
				attestationCache: make(map[string]*preparedAttestationVerifier)},
			selection: validAppAttestSelection(), platform: "ios",
		},
		{
			name: "App Attest Android mismatch",
			coordinator: &clientCoordinator{now: nowClock(now), appAttestKeys: &recordingAppAttestKeyStore{},
				attestationCache: make(map[string]*preparedAttestationVerifier)},
			selection: validAppAttestSelection(), platform: "android",
		},
		{
			name: "development Apple trust in production",
			coordinator: &clientCoordinator{now: nowClock(now), appAttestKeys: &recordingAppAttestKeyStore{},
				attestationCache: make(map[string]*preparedAttestationVerifier)},
			selection: func() configuration.PlatformAttestation {
				selection := validAppAttestSelection()
				selection.AppAttest.Environment = "development"
				return selection
			}(), platform: "ios",
		},
		{
			name: "Play testing response in production",
			coordinator: &clientCoordinator{now: nowClock(now),
				attestationCache: make(map[string]*preparedAttestationVerifier)},
			selection: func() configuration.PlatformAttestation {
				selection := validPlayIntegritySelection("metadata")
				selection.PlayIntegrity.AllowTestingResponses = true
				return selection
			}(), platform: "android",
		},
		{
			name: "Play iOS mismatch",
			coordinator: &clientCoordinator{now: nowClock(now),
				attestationCache: make(map[string]*preparedAttestationVerifier)},
			selection: validPlayIntegritySelection("metadata"), platform: "ios",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.coordinator.mobileAttestationVerifier(
				environment, configuration.ActiveSnapshot{RevisionID: "rev_00000000000000000000000000"},
				policy, test.selection, test.platform,
			)
			if err == nil {
				t.Fatal("invalid production verifier configuration was accepted")
			}
		})
	}
}

func TestCoordinatorVerifiesPlayIntegrityWithFixedGoogleClients(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	selection := validPlayIntegritySelection("metadata")
	binding := attestation.Binding{
		Version: 1, ChallengeID: "chl_01J00000000000000000000000",
		ChallengeNonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		ApplicationID:  "app_00000000000000000000000000", Environment: "development",
		PrincipalID: "usr_01J00000000000000000000000",
		DPoPJKT:     "bX0yCl562RPdpf8cJHVLBeUXu6PWExYJ0w-Bydre3q8",
		Platform:    "react_native_android", IssuedAt: now.Unix(),
	}
	bindingHash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	certificate := selection.PlayIntegrity.CertificateSHA256Digests[0]
	var metadataRequests, decodeRequests atomic.Int64
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "metadata.google.internal":
			metadataRequests.Add(1)
			if request.Method != http.MethodGet || request.Header.Get("Metadata-Flavor") != "Google" {
				t.Fatalf("metadata request = %s headers=%#v", request.Method, request.Header)
			}
			response := jsonHTTPResponse(http.StatusOK, `{"access_token":"metadata-access-token","expires_in":3600,"token_type":"Bearer"}`)
			response.Header.Set("Metadata-Flavor", "Google")
			return response, nil
		case "playintegrity.googleapis.com":
			decodeRequests.Add(1)
			if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer metadata-access-token" ||
				request.URL.Path != "/v1/com.example.habits:decodeIntegrityToken" {
				t.Fatalf("decode request = %s %s headers=%#v", request.Method, request.URL, request.Header)
			}
			payload, marshalErr := json.Marshal(map[string]any{
				"tokenPayloadExternal": map[string]any{
					"requestDetails": map[string]any{
						"requestPackageName": "com.example.habits", "requestHash": bindingHash,
						"timestampMillis": fmt.Sprintf("%d", now.UnixMilli()),
					},
					"appIntegrity": map[string]any{
						"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": "com.example.habits",
						"certificateSha256Digest": []any{certificate}, "versionCode": "1",
					},
					"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": []any{"MEETS_DEVICE_INTEGRITY"}},
					"accountDetails":  map[string]any{"appLicensingVerdict": "LICENSED"},
					"testingDetails":  map[string]any{"isTestingResponse": false},
				},
			})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			return jsonHTTPResponse(http.StatusOK, string(payload)), nil
		default:
			t.Fatalf("unexpected fixed Google destination %q", request.URL.Host)
			return nil, errors.New("unexpected destination")
		}
	})
	coordinator := &clientCoordinator{
		now: nowClock(now), attestationTransport: transport,
		attestationCache: make(map[string]*preparedAttestationVerifier),
	}
	evidence, err := attestation.NewEvidence("play_integrity", map[string]any{
		"integrity_token": "opaque-integrity-token-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.verifyAttestationEvidence(
		context.Background(),
		clientEnvironment{
			OrganizationID: "org_00000000000000000000000000",
			ApplicationID:  binding.ApplicationID, EnvironmentID: "env_00000000000000000000000000",
			Slug: binding.Environment, Kind: "development",
		},
		configuration.ActiveSnapshot{RevisionID: "rev_00000000000000000000000000"},
		configuration.AttestationPolicy{ID: "native", MaxAge: 10 * time.Minute},
		selection, evidence, binding,
	)
	if err != nil {
		t.Fatalf("verify Play Integrity through coordinator: %v", err)
	}
	if result.Provider != "play_integrity" || result.TrustLevel != "device_verified" ||
		metadataRequests.Load() != 1 || decodeRequests.Load() != 1 {
		t.Fatalf("Play result=%#v metadata=%d decode=%d", result, metadataRequests.Load(), decodeRequests.Load())
	}
}

func TestSecretServiceAccountTokenSourceDoesNotRetainCredentialAndSingleFlights(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	credentials := generatedServiceAccountCredentials(t)
	store := &ephemeralSecretStore{material: credentials}
	var requests atomic.Int64
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if request.Method != http.MethodPost || request.URL.String() != "https://oauth2.googleapis.com/token" {
			t.Fatalf("OAuth request = %s %s", request.Method, request.URL)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte("grant_type=")) || !bytes.Contains(body, []byte("assertion=")) {
			t.Fatalf("OAuth body shape = %q", body)
		}
		return jsonHTTPResponse(http.StatusOK, `{"access_token":"short-lived-access-token","expires_in":3600,"token_type":"Bearer"}`), nil
	})
	source, err := newSecretServiceAccountTokenSource(secretServiceAccountTokenSourceConfig{
		Store: store,
		Scope: secrets.Scope{
			OrganizationID: "org_00000000000000000000000000",
			ApplicationID:  "app_00000000000000000000000000",
			EnvironmentID:  "env_00000000000000000000000000",
		},
		SecretRef: "secret/play-integrity", Transport: transport, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 24
	results := make(chan attestation.PlayIntegrityAccessToken, callers)
	errorsChannel := make(chan error, callers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			token, tokenErr := source.AccessToken(context.Background())
			results <- token
			errorsChannel <- tokenErr
		}()
	}
	concurrentLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for range 100 {
				_ = fmt.Sprintf("%#v", source)
				_ = fmt.Sprintf("%+x", *source)
				concurrentLogger.Info("token source", "pointer", source, "value", *source)
			}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsChannel)
	for tokenErr := range errorsChannel {
		if tokenErr != nil {
			t.Fatalf("concurrent token error = %v", tokenErr)
		}
	}
	for token := range results {
		if token.Value != "short-lived-access-token" || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("token = %#v", token)
		}
	}
	if store.calls.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("secret uses=%d OAuth requests=%d", store.calls.Load(), requests.Load())
	}
	if !store.lastCallbackBufferCleared() {
		t.Fatal("temporary secret callback buffer was not cleared")
	}
	for _, candidate := range []any{source, *source} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%+x", "%d"} {
			formatted := fmt.Sprintf(format, candidate)
			if strings.Contains(formatted, "private_key") || strings.Contains(formatted, "service.test") ||
				strings.Contains(formatted, "short-lived-access-token") || !strings.Contains(formatted, "REDACTED") {
				t.Fatalf("token source formatting %s leaked material: %s", format, formatted)
			}
		}
	}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	logger.Info("token source", "pointer", source, "value", *source)
	logged := logOutput.String()
	if strings.Contains(logged, "private_key") || strings.Contains(logged, "service.test") ||
		strings.Contains(logged, "short-lived-access-token") || strings.Count(logged, "REDACTED") != 2 {
		t.Fatalf("structured logging leaked token source: %s", logged)
	}
}

func TestSecretServiceAccountTokenSourcePreflightAndTypedNilFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	bad := &ephemeralSecretStore{material: []byte(`{"type":"service_account"}`)}
	source, err := newSecretServiceAccountTokenSource(secretServiceAccountTokenSourceConfig{
		Store: bad, Scope: secrets.Scope{}, SecretRef: "secret/play", Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Preflight(context.Background()); err == nil {
		t.Fatal("malformed service-account secret passed preflight")
	}
	if _, err := source.AccessToken(context.Background()); err == nil ||
		strings.Contains(err.Error(), "service_account") {
		t.Fatalf("malformed credential error = %v", err)
	}
	var typedNil *ephemeralSecretStore
	if _, err := newSecretServiceAccountTokenSource(secretServiceAccountTokenSourceConfig{
		Store: typedNil, SecretRef: "secret/play", Now: nowClock(now),
	}); err == nil {
		t.Fatal("typed nil secret store was accepted")
	}
	var zero secretServiceAccountTokenSource
	if _, err := zero.AccessToken(context.Background()); err == nil {
		t.Fatal("zero-value token source was accepted")
	}
}

type recordingAppAttestKeyStore struct{}

func (*recordingAppAttestKeyStore) TransactAppAttestKey(
	context.Context,
	[sha256.Size]byte,
	attestation.AppAttestKeyTransaction,
) error {
	return nil
}

type ephemeralSecretStore struct {
	material []byte
	calls    atomic.Int64
	mu       sync.Mutex
	last     []byte
}

func (store *ephemeralSecretStore) Use(
	ctx context.Context,
	_ secrets.Scope,
	_ string,
	consume func([]byte) error,
) error {
	if store == nil || ctx == nil || consume == nil {
		return secrets.ErrInvalid
	}
	store.calls.Add(1)
	temporary := append([]byte(nil), store.material...)
	err := consume(temporary)
	clear(temporary)
	store.mu.Lock()
	store.last = temporary
	store.mu.Unlock()
	return err
}

func (store *ephemeralSecretStore) lastCallbackBufferCleared() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, value := range store.last {
		if value != 0 {
			return false
		}
	}
	return len(store.last) != 0
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func generatedServiceAccountCredentials(t *testing.T) []byte {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(map[string]any{
		"type":           "service_account",
		"client_email":   "latchway@service.test.gserviceaccount.com",
		"private_key_id": "0123456789abcdef0123456789abcdef",
		"private_key": string(pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: encoded,
		})),
		"token_uri": "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func validAppAttestSelection() configuration.PlatformAttestation {
	return configuration.PlatformAttestation{
		Provider: "app_attest", Mode: "required", MinimumTrustLevel: "app_verified",
		AppAttest: &configuration.AppAttestConfiguration{
			AppIDPrefix: "TEAM1234", BundleID: "com.example.habits", Environment: "production",
			AllowedValidationCategories: []uint32{1}, AllowedBundleVersions: []string{"1.0"},
		},
	}
}

func validPlayIntegritySelection(source string) configuration.PlatformAttestation {
	return configuration.PlatformAttestation{
		Provider: "play_integrity", Mode: "required", MinimumTrustLevel: "device_verified",
		PlayIntegrity: &configuration.PlayIntegrityConfiguration{
			PackageName: "com.example.habits", CloudProjectNumber: 123456789,
			CertificateSHA256Digests: []string{base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size))},
			MinimumDeviceIntegrity:   "device", RequireLicensed: true,
			MinimumVersionCode: 1, CredentialSource: source,
		},
	}
}

func nowClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}
