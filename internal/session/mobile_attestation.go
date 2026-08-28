package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

const maximumCachedAttestationVerifiers = 256

type preparedAttestationVerifier struct {
	attestation.Verifier
	preflight func(context.Context) error
}

func (verifier *preparedAttestationVerifier) Preflight(ctx context.Context) error {
	if verifier == nil || nilCoordinatorDependency(verifier.Verifier) || verifier.preflight == nil {
		return attestation.ErrConfiguration
	}
	return verifier.preflight(ctx)
}

func (coordinator *clientCoordinator) preflightAttestationVerifier(
	ctx context.Context,
	environment clientEnvironment,
	snapshot configuration.ActiveSnapshot,
	policy configuration.AttestationPolicy,
	selection configuration.PlatformAttestation,
	platform string,
) error {
	if selection.Provider == "debug" {
		return coordinator.preflightDebugVerifier(ctx, environment, snapshot, policy, selection)
	}
	verifier, err := coordinator.mobileAttestationVerifier(environment, snapshot, policy, selection, platform)
	if err != nil {
		return err
	}
	return verifier.Preflight(ctx)
}

func (coordinator *clientCoordinator) verifyAttestationEvidence(
	ctx context.Context,
	environment clientEnvironment,
	snapshot configuration.ActiveSnapshot,
	policy configuration.AttestationPolicy,
	selection configuration.PlatformAttestation,
	evidence attestation.Evidence,
	binding attestation.Binding,
) (attestation.Result, error) {
	if selection.Provider == "debug" {
		return coordinator.verifyDebugEvidence(ctx, environment, snapshot, policy, selection, evidence, binding)
	}
	verifier, err := coordinator.mobileAttestationVerifier(
		environment, snapshot, policy, selection, binding.Platform,
	)
	if err != nil {
		return attestation.Result{}, err
	}
	return verifier.Verify(ctx, evidence, binding)
}

func (coordinator *clientCoordinator) mobileAttestationVerifier(
	environment clientEnvironment,
	snapshot configuration.ActiveSnapshot,
	policy configuration.AttestationPolicy,
	selection configuration.PlatformAttestation,
	platform string,
) (*preparedAttestationVerifier, error) {
	if coordinator == nil || coordinator.now == nil || policy.ID == "" || policy.MaxAge <= 0 ||
		selection.Mode != "required" || selection.Provider == "" || platform == "" ||
		coordinator.attestationCache == nil || id.Validate(snapshot.RevisionID, id.ConfigRevision) != nil {
		return nil, attestation.ErrConfiguration
	}
	cacheKey := snapshot.RevisionID + "\x00" + policy.ID + "\x00" + platform + "\x00" + selection.Provider
	coordinator.attestationMu.Lock()
	defer coordinator.attestationMu.Unlock()
	if verifier := coordinator.attestationCache[cacheKey]; verifier != nil {
		return verifier, nil
	}
	verifier, err := coordinator.buildMobileAttestationVerifier(environment, snapshot, policy, selection, platform)
	if err != nil {
		return nil, err
	}
	if len(coordinator.attestationCache) >= maximumCachedAttestationVerifiers {
		for existing := range coordinator.attestationCache {
			delete(coordinator.attestationCache, existing)
			break
		}
	}
	coordinator.attestationCache[cacheKey] = verifier
	return verifier, nil
}

func (coordinator *clientCoordinator) buildMobileAttestationVerifier(
	environment clientEnvironment,
	snapshot configuration.ActiveSnapshot,
	policy configuration.AttestationPolicy,
	selection configuration.PlatformAttestation,
	platform string,
) (*preparedAttestationVerifier, error) {
	if environment.ApplicationID == "" || environment.EnvironmentID == "" || environment.Slug == "" ||
		id.Validate(environment.OrganizationID, id.Organization) != nil ||
		id.Validate(environment.ApplicationID, id.Application) != nil ||
		id.Validate(environment.EnvironmentID, id.Environment) != nil ||
		(environment.Kind != "development" && environment.Kind != "staging" && environment.Kind != "production") {
		return nil, attestation.ErrConfiguration
	}
	switch selection.Provider {
	case "app_attest":
		configuration := selection.AppAttest
		if configuration == nil || selection.PlayIntegrity != nil || selection.SecretRef != "" ||
			(platform != "ios" && platform != "react_native_ios") ||
			selection.MinimumTrustLevel != "app_verified" ||
			nilCoordinatorDependency(coordinator.appAttestKeys) ||
			(environment.Kind == "production" && configuration.Environment != "production") {
			return nil, attestation.ErrConfiguration
		}
		verifier, err := attestation.NewAppAttestVerifier(attestation.AppAttestConfig{
			ApplicationID: environment.ApplicationID, EnvironmentID: environment.Slug,
			AppIDPrefix: configuration.AppIDPrefix, BundleID: configuration.BundleID,
			AttestationEnvironment:      attestation.AppAttestEnvironment(configuration.Environment),
			AllowedValidationCategories: append([]uint32(nil), configuration.AllowedValidationCategories...),
			AllowedBundleVersions:       append([]string(nil), configuration.AllowedBundleVersions...),
			Store:                       coordinator.appAttestKeys, Now: coordinator.now, ResultLifetime: policy.MaxAge,
		})
		if err != nil {
			return nil, attestation.ErrConfiguration
		}
		return &preparedAttestationVerifier{
			Verifier: verifier,
			preflight: func(context.Context) error {
				return nil
			},
		}, nil
	case "play_integrity":
		configuration := selection.PlayIntegrity
		if configuration == nil || selection.AppAttest != nil ||
			(platform != "android" && platform != "react_native_android") ||
			(environment.Kind == "production" && configuration.AllowTestingResponses &&
				!selection.DangerousAllowInProduction) {
			return nil, attestation.ErrConfiguration
		}
		if (configuration.MinimumDeviceIntegrity == "device" && selection.MinimumTrustLevel != "device_verified") ||
			(configuration.MinimumDeviceIntegrity == "strong" && selection.MinimumTrustLevel != "strong_device_verified") {
			return nil, attestation.ErrConfiguration
		}
		var tokenSource attestation.PlayIntegrityAccessTokenSource
		preflight := func(context.Context) error { return nil }
		switch configuration.CredentialSource {
		case "metadata":
			if selection.SecretRef != "" {
				return nil, attestation.ErrConfiguration
			}
			metadata, err := attestation.NewGoogleMetadataTokenSource(attestation.GoogleMetadataTokenSourceOptions{
				Transport: coordinator.attestationTransport, Now: coordinator.now,
			})
			if err != nil {
				return nil, attestation.ErrConfiguration
			}
			tokenSource = metadata
		case "service_account":
			if selection.SecretRef == "" || nilCoordinatorDependency(coordinator.secrets) {
				return nil, attestation.ErrConfiguration
			}
			secretSource, err := newSecretServiceAccountTokenSource(secretServiceAccountTokenSourceConfig{
				Store: coordinator.secrets, Scope: secretScope(environment), SecretRef: selection.SecretRef,
				Transport: coordinator.attestationTransport, Now: coordinator.now,
			})
			if err != nil {
				return nil, attestation.ErrConfiguration
			}
			tokenSource = secretSource
			preflight = secretSource.Preflight
		default:
			return nil, attestation.ErrConfiguration
		}
		decoder, err := attestation.NewGooglePlayIntegrityDecoder(attestation.GooglePlayIntegrityDecoderConfig{
			CloudProjectNumber: configuration.CloudProjectNumber,
			TokenSource:        tokenSource, Transport: coordinator.attestationTransport, Now: coordinator.now,
		})
		if err != nil {
			return nil, attestation.ErrConfiguration
		}
		resultLifetime := policy.MaxAge
		if resultLifetime > 24*time.Hour {
			resultLifetime = 24 * time.Hour
		}
		verifier, err := attestation.NewPlayIntegrityVerifier(attestation.PlayIntegrityConfig{
			ApplicationID: environment.ApplicationID, EnvironmentID: environment.Slug,
			PackageName: configuration.PackageName, CloudProjectNumber: configuration.CloudProjectNumber,
			CertificateSHA256Digests: append([]string(nil), configuration.CertificateSHA256Digests...),
			MinimumDeviceIntegrity:   configuration.MinimumDeviceIntegrity,
			RequireLicensed:          configuration.RequireLicensed, AllowTestingResponses: configuration.AllowTestingResponses,
			MinimumVersionCode: configuration.MinimumVersionCode, MaximumVersionCode: configuration.MaximumVersionCode,
			Decoder: decoder, Now: coordinator.now, MaximumAge: 2 * time.Minute,
			ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
			ResultLifetime: resultLifetime,
		})
		if err != nil {
			return nil, attestation.ErrConfiguration
		}
		return &preparedAttestationVerifier{Verifier: verifier, preflight: preflight}, nil
	case "firebase_app_check":
		configuration := selection.FirebaseAppCheck
		if configuration == nil || selection.AppAttest != nil || selection.PlayIntegrity != nil ||
			selection.Turnstile != nil || selection.SecretRef != "" ||
			(platform != "ios" && platform != "android" && platform != "web" &&
				platform != "react_native_ios" && platform != "react_native_android") {
			return nil, attestation.ErrConfiguration
		}
		expectedTrust := "app_verified"
		if platform == "web" {
			expectedTrust = "web_risk_verified"
		}
		if selection.MinimumTrustLevel != expectedTrust {
			return nil, attestation.ErrConfiguration
		}
		resultLifetime := policy.MaxAge
		if resultLifetime > 24*time.Hour {
			resultLifetime = 24 * time.Hour
		}
		verifier, err := attestation.NewFirebaseAppCheckVerifier(attestation.FirebaseAppCheckConfig{
			ApplicationID: environment.ApplicationID, EnvironmentID: environment.Slug,
			ProjectNumber: configuration.ProjectNumber,
			AllowedAppIDs: append([]string(nil), configuration.AllowedAppIDs...),
			Transport:     coordinator.attestationTransport, Now: coordinator.now,
			ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
			ResultLifetime: resultLifetime,
		})
		if err != nil {
			return nil, attestation.ErrConfiguration
		}
		return &preparedAttestationVerifier{
			Verifier: verifier,
			preflight: func(context.Context) error {
				return nil
			},
		}, nil
	case "turnstile":
		configuration := selection.Turnstile
		if configuration == nil || selection.AppAttest != nil || selection.PlayIntegrity != nil ||
			selection.FirebaseAppCheck != nil || selection.SecretRef == "" || platform != "web" ||
			selection.MinimumTrustLevel != "web_risk_verified" ||
			nilCoordinatorDependency(coordinator.secrets) {
			return nil, attestation.ErrConfiguration
		}
		secret, err := newSecretTurnstileCapability(secretTurnstileCapabilityConfig{
			Store: coordinator.secrets, Scope: secretScope(environment), SecretRef: selection.SecretRef,
		})
		if err != nil {
			return nil, attestation.ErrConfiguration
		}
		maximumAge := policy.MaxAge
		if maximumAge > 10*time.Minute {
			maximumAge = 10 * time.Minute
		}
		resultLifetime := policy.MaxAge
		if resultLifetime > time.Hour {
			resultLifetime = time.Hour
		}
		verifier, err := attestation.NewTurnstileVerifier(attestation.TurnstileConfig{
			ApplicationID: environment.ApplicationID, EnvironmentID: environment.Slug,
			AllowedHostnames: append([]string(nil), configuration.AllowedHostnames...),
			ExpectedAction:   configuration.ExpectedAction, Secret: secret,
			Transport: coordinator.attestationTransport, Now: coordinator.now,
			MaximumAge: maximumAge,
			ClockSkew:  snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
			ResultLifetime: resultLifetime,
		})
		if err != nil {
			return nil, attestation.ErrConfiguration
		}
		return &preparedAttestationVerifier{Verifier: verifier, preflight: secret.Preflight}, nil
	default:
		return nil, attestation.ErrUnsupported
	}
}

func attestationProviderOptions(selection configuration.PlatformAttestation) map[string]any {
	switch selection.Provider {
	case "play_integrity":
		if selection.PlayIntegrity == nil || selection.PlayIntegrity.CloudProjectNumber <= 0 {
			return nil
		}
		return map[string]any{
			"cloud_project_number": strconv.FormatInt(selection.PlayIntegrity.CloudProjectNumber, 10),
		}
	case "turnstile":
		if selection.Turnstile == nil || selection.Turnstile.ExpectedAction == "" {
			return nil
		}
		return map[string]any{"action": selection.Turnstile.ExpectedAction}
	default:
		return nil
	}
}

type secretTurnstileCapabilityConfig struct {
	Store     clientSecretStore
	Scope     secrets.Scope
	SecretRef string
}

// secretTurnstileCapability passes the provider secret directly from the
// encrypted store into one synchronous Siteverify request. It never retains a
// plaintext or derived copy and all formatting is explicitly redacted.
type secretTurnstileCapability struct {
	store     clientSecretStore
	scope     secrets.Scope
	secretRef string
}

func newSecretTurnstileCapability(config secretTurnstileCapabilityConfig) (*secretTurnstileCapability, error) {
	if nilCoordinatorDependency(config.Store) || config.SecretRef == "" {
		return nil, attestation.ErrConfiguration
	}
	return &secretTurnstileCapability{
		store: config.Store, scope: config.Scope, secretRef: config.SecretRef,
	}, nil
}

func (capability *secretTurnstileCapability) Preflight(ctx context.Context) error {
	if capability == nil || ctx == nil {
		return attestation.ErrConfiguration
	}
	if err := capability.use(ctx, func([]byte) error { return nil }); err != nil {
		return attestation.ErrConfiguration
	}
	return nil
}

func (capability *secretTurnstileCapability) Use(ctx context.Context, consume func([]byte) error) error {
	if err := capability.use(ctx, consume); err != nil {
		if ctx != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
		}
		return attestation.ErrTurnstileService
	}
	return nil
}

func (capability *secretTurnstileCapability) use(ctx context.Context, consume func([]byte) error) error {
	if capability == nil || ctx == nil || consume == nil ||
		nilCoordinatorDependency(capability.store) || capability.secretRef == "" {
		return attestation.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	uses := 0
	var operationErr error
	storeErr := capability.store.Use(ctx, capability.scope, capability.secretRef, func(material []byte) error {
		uses++
		if uses != 1 || !validTurnstileSecretMaterial(material) {
			operationErr = attestation.ErrConfiguration
			return nil
		}
		operationErr = consume(material)
		return nil
	})
	if storeErr != nil || uses != 1 || operationErr != nil {
		if operationErr != nil {
			return operationErr
		}
		return attestation.ErrConfiguration
	}
	return nil
}

func validTurnstileSecretMaterial(material []byte) bool {
	if len(material) < 1 || len(material) > 4096 {
		return false
	}
	for _, value := range material {
		if value <= ' ' || value > '~' {
			return false
		}
	}
	return true
}

func (secretTurnstileCapability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func (secretTurnstileCapability) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

var _ attestation.TurnstileSecretCapability = (*secretTurnstileCapability)(nil)

type secretServiceAccountTokenSourceConfig struct {
	Store     clientSecretStore
	Scope     secrets.Scope
	SecretRef string
	Transport http.RoundTripper
	Now       func() time.Time
}

// secretServiceAccountTokenSource retains only Google's short-lived OAuth
// access token. Every private key parse and signature happens wholly inside a
// secrets.Store.Use callback, so neither plaintext nor a derived RSA key can
// survive the callback boundary.
type secretServiceAccountTokenSource struct {
	store     clientSecretStore
	scope     secrets.Scope
	secretRef string
	transport http.RoundTripper
	now       func() time.Time
	state     *secretServiceAccountTokenSourceState
}

// secretServiceAccountTokenSourceState contains all mutable state behind a
// pointer. That keeps the token source's value-receiver redaction methods safe
// to call concurrently: formatting copies only immutable handles and never
// reads the cached token while AccessToken refreshes it.
type secretServiceAccountTokenSourceState struct {
	gate   chan struct{}
	cached attestation.PlayIntegrityAccessToken
}

func newSecretServiceAccountTokenSource(config secretServiceAccountTokenSourceConfig) (*secretServiceAccountTokenSource, error) {
	if nilCoordinatorDependency(config.Store) || config.SecretRef == "" || config.Now == nil ||
		(config.Transport != nil && nilCoordinatorDependency(config.Transport)) {
		return nil, attestation.ErrConfiguration
	}
	return &secretServiceAccountTokenSource{
		store: config.Store, scope: config.Scope, secretRef: config.SecretRef,
		transport: config.Transport, now: config.Now,
		state: &secretServiceAccountTokenSourceState{gate: make(chan struct{}, 1)},
	}, nil
}

func (source *secretServiceAccountTokenSource) Preflight(ctx context.Context) error {
	if source == nil || ctx == nil || nilCoordinatorDependency(source.store) || source.now == nil ||
		source.state == nil || source.state.gate == nil {
		return attestation.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case source.state.gate <- struct{}{}:
		defer func() { <-source.state.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	var operationErr error
	err := source.store.Use(ctx, source.scope, source.secretRef, func(material []byte) error {
		transient, buildErr := attestation.NewGoogleServiceAccountTokenSource(
			material,
			attestation.GoogleServiceAccountTokenSourceOptions{Transport: source.transport, Now: source.now},
		)
		operationErr = buildErr
		if transient == nil && operationErr == nil {
			operationErr = attestation.ErrConfiguration
		}
		transient = nil
		return nil
	})
	if err != nil || operationErr != nil {
		return attestation.ErrConfiguration
	}
	return nil
}

func (source *secretServiceAccountTokenSource) AccessToken(ctx context.Context) (attestation.PlayIntegrityAccessToken, error) {
	if source == nil || ctx == nil || nilCoordinatorDependency(source.store) || source.now == nil ||
		source.state == nil || source.state.gate == nil {
		return attestation.PlayIntegrityAccessToken{}, attestation.ErrPlayIntegrityService
	}
	if err := ctx.Err(); err != nil {
		return attestation.PlayIntegrityAccessToken{}, err
	}
	select {
	case source.state.gate <- struct{}{}:
		defer func() { <-source.state.gate }()
	case <-ctx.Done():
		return attestation.PlayIntegrityAccessToken{}, ctx.Err()
	}
	now := source.now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return attestation.PlayIntegrityAccessToken{}, attestation.ErrPlayIntegrityService
	}
	if validCachedPlayIntegrityToken(source.state.cached, now.Add(time.Minute)) {
		return source.state.cached, nil
	}
	var token attestation.PlayIntegrityAccessToken
	var operationErr error
	err := source.store.Use(ctx, source.scope, source.secretRef, func(material []byte) error {
		var transient *attestation.GoogleServiceAccountTokenSource
		transient, operationErr = attestation.NewGoogleServiceAccountTokenSource(
			material,
			attestation.GoogleServiceAccountTokenSourceOptions{Transport: source.transport, Now: source.now},
		)
		if operationErr == nil {
			token, operationErr = transient.AccessToken(ctx)
		}
		transient = nil
		return nil
	})
	if err != nil {
		return attestation.PlayIntegrityAccessToken{}, attestation.ErrPlayIntegrityService
	}
	if operationErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(operationErr, ctxErr) {
			return attestation.PlayIntegrityAccessToken{}, ctxErr
		}
		return attestation.PlayIntegrityAccessToken{}, attestation.ErrPlayIntegrityService
	}
	if !validCachedPlayIntegrityToken(token, now) {
		return attestation.PlayIntegrityAccessToken{}, attestation.ErrPlayIntegrityService
	}
	source.state.cached = token
	return token, nil
}

func validCachedPlayIntegrityToken(token attestation.PlayIntegrityAccessToken, now time.Time) bool {
	if now.IsZero() || len(token.Value) < 16 || len(token.Value) > 16<<10 ||
		token.ExpiresAt.IsZero() || !token.ExpiresAt.After(now.Add(5*time.Second)) {
		return false
	}
	for _, character := range token.Value {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func (secretServiceAccountTokenSource) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func (secretServiceAccountTokenSource) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

func nilCoordinatorDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ attestation.PlayIntegrityAccessTokenSource = (*secretServiceAccountTokenSource)(nil)
