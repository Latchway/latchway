package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/secrets"
)

const maximumCachedIdentityVerifiers = 256

type clientSecretStore interface {
	Use(context.Context, secrets.Scope, string, func([]byte) error) error
}

// ClientCoordinatorConfig supplies the trusted runtime dependencies behind
// the public client transport. The concrete coordinator remains private so a
// caller cannot bypass identity, DPoP, policy, or attestation verification and
// write directly to the package-private challenge store.
type ClientCoordinatorConfig struct {
	Pool               *pgxpool.Pool
	Configuration      *configuration.Store
	Users              *identity.UserStore
	Sessions           *Store
	Secrets            clientSecretStore
	IdentityHTTPClient *http.Client
	Now                func() time.Time
}

type clientCoordinator struct {
	pool          *pgxpool.Pool
	configuration *configuration.Store
	users         *identity.UserStore
	sessions      *Store
	challenges    *ChallengeStore
	secrets       clientSecretStore
	identityHTTP  *http.Client
	now           func() time.Time

	identityMu    sync.Mutex
	identityCache map[string]identity.IdentityVerifier
}

// NewClientCoordinator constructs the fail-closed implementation used by the
// client HTTP API.
func NewClientCoordinator(config ClientCoordinatorConfig) (clientapi.Coordinator, error) {
	if config.Pool == nil || config.Configuration == nil || config.Users == nil || config.Sessions == nil || config.Secrets == nil {
		return nil, errors.New("client coordinator dependency is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	challenges, err := newChallengeStore(ChallengeStoreConfig{
		Pool: config.Pool, Configuration: config.Configuration, Now: config.Now,
	})
	if err != nil {
		return nil, err
	}
	return &clientCoordinator{
		pool: config.Pool, configuration: config.Configuration, users: config.Users,
		sessions: config.Sessions, challenges: challenges, secrets: config.Secrets,
		identityHTTP: config.IdentityHTTPClient, now: config.Now,
		identityCache: make(map[string]identity.IdentityVerifier),
	}, nil
}

type clientEnvironment struct {
	OrganizationID string
	ApplicationID  string
	EnvironmentID  string
	Slug           string
	Kind           string
}

func (coordinator *clientCoordinator) CreateChallenge(ctx context.Context, input clientapi.ChallengeInput) (clientapi.ChallengeResult, error) {
	// Browser sessions need a separate configured Origin/CORS authority check in
	// addition to the trusted DPoP target. Fail closed until that boundary is
	// implemented; native and server-side SDKs do not use browser authority.
	if input.Platform == "web" {
		return clientapi.ChallengeResult{}, clientFailure("attestation_unsupported")
	}
	environment, err := coordinator.resolveEnvironment(ctx, input.ApplicationID, input.Environment)
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapChallengeScopeError(err))
	}
	snapshot, err := coordinator.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: environment.OrganizationID,
		ApplicationID:  environment.ApplicationID,
		EnvironmentID:  environment.EnvironmentID,
	})
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure("server_not_ready")
	}
	proof, err := dpop.Validate(input.Metadata.DPoPProof.Reveal(), dpop.Options{
		Method:       input.Metadata.HTTPMethod,
		URI:          &input.Metadata.TargetURL,
		Now:          coordinator.now().UTC(),
		ClockSkew:    snapshot.SessionPolicy().MaximumClockSkew,
		ClockSkewSet: true,
	})
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapDPoPError(err))
	}
	credential, err := identity.NewRawIdentityCredential(input.IdentityToken.Reveal())
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure("identity_token_invalid")
	}
	provider, ok := snapshot.IdentityProvider(input.IdentityProvider)
	if !ok || provider.ID != input.IdentityProvider {
		return clientapi.ChallengeResult{}, clientFailure("identity_token_invalid")
	}
	verifier, err := coordinator.identityVerifier(environment, snapshot, provider)
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure("server_not_ready")
	}
	principal, err := verifier.Verify(ctx, credential)
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapIdentityError(err))
	}
	if principal.ProviderID != provider.ID {
		return clientapi.ChallengeResult{}, clientFailure("identity_token_invalid")
	}
	policy, selection, ok := snapshot.RequiredAttestationForPlatform(input.Platform)
	if !ok || policy.ID == "" || selection.Mode != "required" {
		return clientapi.ChallengeResult{}, clientFailure("attestation_unsupported")
	}
	if selection.Provider != "debug" {
		return clientapi.ChallengeResult{}, clientFailure("attestation_unsupported")
	}
	if err := coordinator.preflightDebugVerifier(ctx, environment, snapshot, policy, selection); err != nil {
		return clientapi.ChallengeResult{}, clientFailure("server_not_ready")
	}
	// Resolve can persist a newly observed upstream subject. Prove that the
	// selected attestation policy and its server-side verification material are
	// usable first so an unsupported or corrupt policy cannot create a user as a
	// side effect of a request that can never yield a challenge.
	user, err := coordinator.users.Resolve(ctx, identity.UserScope{
		OrganizationID: environment.OrganizationID,
		ApplicationID:  environment.ApplicationID,
	}, principal)
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapUserResolutionError(err))
	}
	challenge, err := coordinator.challenges.Create(ctx, ChallengeInput{
		OrganizationID: environment.OrganizationID, ApplicationID: environment.ApplicationID,
		EnvironmentID: environment.EnvironmentID, ConfigurationRevisionID: snapshot.RevisionID,
		EnvironmentSlug:   environment.Slug,
		ApplicationUserID: user.ID, IdentityProvider: principal.ProviderID,
		IdentityVerifiedAt: principal.AuthenticatedAt,
		IdentityExpiresAt:  principal.ExpiresAt, Platform: input.Platform,
		DPoPJKT: proof.JKT, DPoPPublicJWK: proof.JWK, DPoPProofJTI: proof.JTI,
		DPoPHTTPMethod: input.Metadata.HTTPMethod, DPoPRequestURI: &input.Metadata.TargetURL,
	})
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapChallengeError(err))
	}
	clientDataHash, err := challenge.Binding.HashBase64URL()
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure("internal_error")
	}
	return clientapi.ChallengeResult{
		ChallengeID: challenge.ID, ChallengeNonce: challenge.Nonce,
		BindingVersion: challenge.Binding.Version, IssuedAt: challenge.Binding.IssuedAt,
		ExpiresAt: challenge.ExpiresAt,
		Attestation: clientapi.AttestationRequirement{
			Provider: challenge.Attestation.Provider, Mode: challenge.Attestation.Mode,
			ClientDataHash: clientDataHash,
		},
	}, nil
}

func (coordinator *clientCoordinator) ExchangeSession(ctx context.Context, input clientapi.ExchangeInput) (clientapi.GrantResult, error) {
	challenge, err := coordinator.challenges.Get(ctx, input.ChallengeID)
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapExchangeChallengeError(err))
	}
	if input.Attestation.Provider != challenge.Attestation.Provider || challenge.Attestation.Provider != "debug" {
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	environment, err := coordinator.resolveEnvironment(ctx, challenge.Binding.ApplicationID, challenge.Binding.Environment)
	if err != nil || environment.OrganizationID != challenge.OrganizationID || environment.EnvironmentID != challenge.EnvironmentID {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	snapshot, err := coordinator.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: environment.OrganizationID,
		ApplicationID:  environment.ApplicationID,
		EnvironmentID:  environment.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != challenge.ConfigurationRevisionID {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	proof, err := prevalidateExchangeDPoP(input, challenge.Binding.DPoPJKT, coordinator.now().UTC(), snapshot.SessionPolicy().MaximumClockSkew)
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapDPoPError(err))
	}
	policy, ok := snapshot.AttestationPolicy(challenge.Attestation.ID)
	if !ok || policy.ID != challenge.Attestation.ID {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	selection, ok := snapshot.SelectAttestation(policy.ID, challenge.Binding.Platform)
	if !ok || selection.Provider != challenge.Attestation.Provider || selection.Mode != "required" {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	payload, err := input.Attestation.Payload.Object()
	if err != nil {
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	evidence, err := attestation.NewEvidence(input.Attestation.Provider, payload)
	if err != nil {
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	verified, err := coordinator.verifyDebugEvidence(ctx, environment, snapshot, policy, selection, evidence, challenge.Binding)
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapAttestationError(err))
	}
	issued, err := coordinator.sessions.Exchange(ctx, ExchangeInput{
		ChallengeID: input.ChallengeID, Attestation: verified, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		KeyStorage: "unknown", AppVersion: input.Installation.AppVersion,
	})
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapSessionError(err))
	}
	return clientGrant(issued)
}

func (coordinator *clientCoordinator) RefreshSession(ctx context.Context, input clientapi.RefreshInput) (clientapi.GrantResult, error) {
	if input.HasIdentityToken || input.Attestation != nil {
		return clientapi.GrantResult{}, clientFailure("request_invalid")
	}
	refresh, err := NewRefreshToken(input.RefreshToken.Reveal())
	if err != nil {
		return clientapi.GrantResult{}, clientFailure("session_expired")
	}
	proof, err := NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return clientapi.GrantResult{}, clientFailure("dpop_invalid")
	}
	issued, err := coordinator.sessions.Rotate(ctx, RotateInput{
		RefreshToken: refresh, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
	})
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapSessionError(err))
	}
	return clientGrant(issued)
}

func (coordinator *clientCoordinator) resolveEnvironment(ctx context.Context, applicationID, environmentSlug string) (clientEnvironment, error) {
	if id.Validate(applicationID, id.Application) != nil || !sessionIdentifierPattern.MatchString(environmentSlug) {
		return clientEnvironment{}, ErrSessionScope
	}
	var result clientEnvironment
	err := coordinator.pool.QueryRow(ctx, `
		SELECT organization.organization_id,
		       application.application_id,
		       environment.environment_id,
		       environment.slug,
		       environment.kind
		FROM applications AS application
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		JOIN environments AS environment
		  ON environment.organization_id = application.organization_id
		 AND environment.application_id = application.application_id
		WHERE application.application_id = $1
		  AND environment.slug = $2
		  AND organization.status = 'active'
		  AND application.status = 'active'
		  AND environment.status = 'active'
		  AND organization.disabled_at IS NULL
		  AND application.disabled_at IS NULL
		  AND environment.disabled_at IS NULL
	`, applicationID, environmentSlug).Scan(
		&result.OrganizationID, &result.ApplicationID, &result.EnvironmentID,
		&result.Slug, &result.Kind,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return clientEnvironment{}, ErrSessionScope
	}
	if err != nil {
		return clientEnvironment{}, fmt.Errorf("resolve client environment: %w", err)
	}
	if id.Validate(result.OrganizationID, id.Organization) != nil ||
		id.Validate(result.ApplicationID, id.Application) != nil ||
		id.Validate(result.EnvironmentID, id.Environment) != nil ||
		result.ApplicationID != applicationID || result.Slug != environmentSlug ||
		(result.Kind != "development" && result.Kind != "staging" && result.Kind != "production") {
		return clientEnvironment{}, ErrSessionScope
	}
	return result, nil
}

func (coordinator *clientCoordinator) identityVerifier(environment clientEnvironment, snapshot configuration.ActiveSnapshot, provider configuration.IdentityProvider) (identity.IdentityVerifier, error) {
	if err := validateIdentityKeySources(provider); err != nil {
		return nil, identity.ErrConfiguration
	}
	cacheKey := snapshot.RevisionID + "\x00" + provider.ID
	coordinator.identityMu.Lock()
	defer coordinator.identityMu.Unlock()
	if verifier := coordinator.identityCache[cacheKey]; verifier != nil {
		return verifier, nil
	}
	mapper, err := identity.NewCELClaimMapper(provider.ClaimMappings)
	if err != nil {
		return nil, err
	}
	var verifier identity.IdentityVerifier
	if provider.StaticPublicKeySecretRef != "" || provider.SymmetricSecretRef != "" {
		verifier = &secretIdentityVerifier{
			coordinator: coordinator, environment: environment, provider: provider, mapper: mapper,
		}
	} else {
		verifier, err = coordinator.buildRemoteIdentityVerifier(provider, mapper)
		if err != nil {
			return nil, err
		}
	}
	if len(coordinator.identityCache) >= maximumCachedIdentityVerifiers {
		for existing := range coordinator.identityCache {
			delete(coordinator.identityCache, existing)
			break
		}
	}
	coordinator.identityCache[cacheKey] = verifier
	return verifier, nil
}

// validateIdentityKeySources reasserts the compiled configuration's exact
// verification-key-source matrix at the runtime trust boundary. Active
// snapshots can outlive newer schema validation, and a corrupt or legacy row
// must never make source precedence (for example JWKS versus a static secret)
// an implicit security decision.
func validateIdentityKeySources(provider configuration.IdentityProvider) error {
	sourceCount := populatedIdentitySourceCount(
		provider.JWKSURL,
		provider.StaticPublicKeySecretRef,
		provider.SymmetricSecretRef,
	)
	switch provider.Type {
	case "firebase", "supabase":
		if sourceCount != 0 {
			return identity.ErrConfiguration
		}
	case "clerk":
		// An empty source selects Clerk's issuer-derived JWKS endpoint.
		if sourceCount > 1 || provider.SymmetricSecretRef != "" {
			return identity.ErrConfiguration
		}
	case "generic_oidc":
		if sourceCount != 1 || provider.SymmetricSecretRef != "" {
			return identity.ErrConfiguration
		}
	case "custom_jwt":
		if sourceCount != 1 {
			return identity.ErrConfiguration
		}
	default:
		return identity.ErrConfiguration
	}
	return nil
}

func populatedIdentitySourceCount(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

// prevalidateExchangeDPoP rejects an invalid proof against the trusted target,
// challenge key binding, and current active clock-skew policy before any
// attestation secret is opened. Store.Exchange intentionally validates the
// proof again immediately before replay and durable session writes.
func prevalidateExchangeDPoP(input clientapi.ExchangeInput, expectedJKT string, now time.Time, clockSkew time.Duration) (DPoPProof, error) {
	proof, err := NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return DPoPProof{}, err
	}
	if _, err := dpop.Validate(proof.value, dpop.Options{
		Method: input.Metadata.HTTPMethod, URI: &input.Metadata.TargetURL,
		ExpectedJKT: expectedJKT, Now: now,
		ClockSkew: clockSkew, ClockSkewSet: true,
	}); err != nil {
		return DPoPProof{}, err
	}
	return proof, nil
}

func (coordinator *clientCoordinator) buildRemoteIdentityVerifier(provider configuration.IdentityProvider, mapper identity.ClaimMapper) (identity.IdentityVerifier, error) {
	common := identity.PresetCommon{
		ProviderID: provider.ID, Mapper: mapper,
		SubjectClaim: provider.SubjectClaim, RequiredClaims: provider.RequiredClaims,
		AuthorizedParties: provider.AuthorizedParties,
		Client:            coordinator.identityHTTP, Now: coordinator.now,
		ClockSkew: time.Duration(provider.ClockSkewSeconds) * time.Second, ClockSkewSet: true,
	}
	switch provider.Type {
	case "firebase":
		expectedIssuer := "https://securetoken.google.com/" + provider.ProjectID
		if !emptyOrOnlyAlgorithm(provider.AllowedAlgorithms, "RS256") ||
			(provider.Issuer != "" && provider.Issuer != expectedIssuer) ||
			(len(provider.Audiences) != 0 && (len(provider.Audiences) != 1 || provider.Audiences[0] != provider.ProjectID)) ||
			provider.JWKSURL != "" {
			return nil, identity.ErrConfiguration
		}
		return identity.NewFirebaseVerifier(identity.FirebasePreset{PresetCommon: common, ProjectID: provider.ProjectID})
	case "supabase":
		if provider.JWKSURL != "" {
			return nil, identity.ErrConfiguration
		}
		return identity.NewSupabaseVerifier(identity.SupabasePreset{
			PresetCommon: common, ProjectURL: provider.ProjectURL, Issuer: provider.Issuer,
			Audiences: provider.Audiences, AllowedAlgorithms: provider.AllowedAlgorithms,
		})
	case "clerk":
		if !emptyOrOnlyAlgorithm(provider.AllowedAlgorithms, "RS256") {
			return nil, identity.ErrConfiguration
		}
		return identity.NewClerkVerifier(identity.ClerkPreset{
			PresetCommon: common, Issuer: provider.Issuer, Audiences: provider.Audiences,
			AuthorizedParties: provider.AuthorizedParties, JWKSURL: provider.JWKSURL,
		})
	case "generic_oidc", "custom_jwt":
		if provider.JWKSURL == "" {
			return nil, identity.ErrConfiguration
		}
		keys, err := identity.NewRemoteKeySource(identity.RemoteKeySourceConfig{
			URL: provider.JWKSURL, Format: identity.RemoteKeyFormatJWKS,
			Client: coordinator.identityHTTP, Now: coordinator.now,
		})
		if err != nil {
			return nil, err
		}
		config := verifierConfig(provider, mapper)
		config.Keys = keys
		config.Now = coordinator.now
		return identity.NewJWTVerifier(config)
	default:
		return nil, identity.ErrConfiguration
	}
}

type secretIdentityVerifier struct {
	coordinator *clientCoordinator
	environment clientEnvironment
	provider    configuration.IdentityProvider
	mapper      identity.ClaimMapper
}

func (verifier *secretIdentityVerifier) ID() string {
	if verifier == nil {
		return ""
	}
	return verifier.provider.ID
}

func (verifier *secretIdentityVerifier) Verify(ctx context.Context, credential identity.RawIdentityCredential) (identity.VerifiedPrincipal, error) {
	if verifier == nil || verifier.coordinator == nil {
		return identity.VerifiedPrincipal{}, identity.ErrKeyUnavailable
	}
	reference := verifier.provider.StaticPublicKeySecretRef
	if reference == "" {
		reference = verifier.provider.SymmetricSecretRef
	}
	var principal identity.VerifiedPrincipal
	var operationErr error
	err := verifier.coordinator.secrets.Use(ctx, secretScope(verifier.environment), reference, func(material []byte) error {
		var configured identity.IdentityVerifier
		configured, operationErr = verifier.coordinator.buildSecretIdentityVerifierWithMapper(verifier.provider, verifier.mapper, material)
		if operationErr == nil {
			principal, operationErr = configured.Verify(ctx, credential)
		}
		return nil
	})
	if err != nil {
		return identity.VerifiedPrincipal{}, identity.ErrKeyUnavailable
	}
	if operationErr != nil {
		return identity.VerifiedPrincipal{}, operationErr
	}
	return principal, nil
}

func (coordinator *clientCoordinator) buildSecretIdentityVerifier(provider configuration.IdentityProvider, material []byte) (identity.IdentityVerifier, error) {
	mapper, err := identity.NewCELClaimMapper(provider.ClaimMappings)
	if err != nil {
		return nil, err
	}
	return coordinator.buildSecretIdentityVerifierWithMapper(provider, mapper, material)
}

func (coordinator *clientCoordinator) buildSecretIdentityVerifierWithMapper(provider configuration.IdentityProvider, mapper identity.ClaimMapper, material []byte) (identity.IdentityVerifier, error) {
	if mapper == nil {
		return nil, identity.ErrConfiguration
	}
	config := verifierConfig(provider, mapper)
	config.Now = coordinator.now
	if provider.StaticPublicKeySecretRef != "" {
		if provider.Type != "generic_oidc" && provider.Type != "custom_jwt" && provider.Type != "clerk" {
			return nil, identity.ErrConfiguration
		}
		publicKey, err := identity.ParsePublicKeyPEM(material)
		if err != nil {
			return nil, err
		}
		if provider.Type == "clerk" {
			if !emptyOrOnlyAlgorithm(provider.AllowedAlgorithms, "RS256") {
				return nil, identity.ErrConfiguration
			}
			return identity.NewClerkVerifier(identity.ClerkPreset{
				PresetCommon: identity.PresetCommon{
					ProviderID: provider.ID, Mapper: mapper,
					SubjectClaim: provider.SubjectClaim, RequiredClaims: provider.RequiredClaims,
					Now: coordinator.now, ClockSkew: config.ClockSkew, ClockSkewSet: true,
				},
				Issuer: provider.Issuer, Audiences: provider.Audiences,
				AuthorizedParties: provider.AuthorizedParties,
				StaticPublicKey:   publicKey,
			})
		}
		return identity.NewStaticPublicKeyVerifier(config, "", publicKey)
	}
	if provider.SymmetricSecretRef == "" || provider.Type != "custom_jwt" ||
		len(provider.AllowedAlgorithms) != 1 || provider.AllowedAlgorithms[0] != "HS256" ||
		!provider.AcknowledgeSymmetricRisk || len(material) < 32 || len(material) > 4096 {
		return nil, identity.ErrConfiguration
	}
	config.Keys = transientSymmetricKey{value: material}
	return identity.NewJWTVerifier(config)
}

type transientSymmetricKey struct {
	value []byte
}

func (key transientSymmetricKey) Key(_ context.Context, kid, algorithm string) (any, error) {
	if algorithm != "HS256" || kid != "" || len(key.value) < 32 {
		return nil, identity.ErrKeyUnavailable
	}
	return key.value, nil
}

func (transientSymmetricKey) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[REDACTED]"))
}

func verifierConfig(provider configuration.IdentityProvider, mapper identity.ClaimMapper) identity.VerifierConfig {
	return identity.VerifierConfig{
		ProviderID: provider.ID, Issuer: provider.Issuer,
		Audiences:         append([]string(nil), provider.Audiences...),
		AllowedAlgorithms: append([]string(nil), provider.AllowedAlgorithms...),
		AuthorizedParties: append([]string(nil), provider.AuthorizedParties...),
		SubjectClaim:      provider.SubjectClaim,
		ClockSkew:         time.Duration(provider.ClockSkewSeconds) * time.Second, ClockSkewSet: true,
		RequiredClaims: append([]string(nil), provider.RequiredClaims...),
		Mapper:         mapper,
	}
}

func emptyOrOnlyAlgorithm(values []string, expected string) bool {
	return len(values) == 0 || (len(values) == 1 && values[0] == expected)
}

func (coordinator *clientCoordinator) preflightDebugVerifier(ctx context.Context, environment clientEnvironment, snapshot configuration.ActiveSnapshot, policy configuration.AttestationPolicy, selection configuration.PlatformAttestation) error {
	return coordinator.useDebugVerifier(ctx, environment, snapshot, policy, selection, func(*attestation.DebugVerifier) error { return nil })
}

func (coordinator *clientCoordinator) verifyDebugEvidence(ctx context.Context, environment clientEnvironment, snapshot configuration.ActiveSnapshot, policy configuration.AttestationPolicy, selection configuration.PlatformAttestation, evidence attestation.Evidence, binding attestation.Binding) (attestation.Result, error) {
	var result attestation.Result
	var verifyErr error
	err := coordinator.useDebugVerifier(ctx, environment, snapshot, policy, selection, func(verifier *attestation.DebugVerifier) error {
		result, verifyErr = verifier.Verify(ctx, evidence, binding)
		return nil
	})
	if err != nil {
		return attestation.Result{}, err
	}
	return result, verifyErr
}

func (coordinator *clientCoordinator) useDebugVerifier(ctx context.Context, environment clientEnvironment, snapshot configuration.ActiveSnapshot, policy configuration.AttestationPolicy, selection configuration.PlatformAttestation, consume func(*attestation.DebugVerifier) error) error {
	if selection.Provider != "debug" || selection.Mode != "required" || selection.SecretRef == "" || consume == nil {
		return attestation.ErrConfiguration
	}
	maximumLifetime := policy.MaxAge
	if maximumLifetime > time.Hour {
		maximumLifetime = time.Hour
	}
	var operationErr error
	err := coordinator.secrets.Use(ctx, secretScope(environment), selection.SecretRef, func(material []byte) error {
		keys, parseErr := attestation.ParseDebugPublicKeys(material)
		if parseErr != nil {
			operationErr = parseErr
			return nil
		}
		verifier, buildErr := attestation.NewDebugVerifier(attestation.DebugConfig{
			Enabled: true, EnvironmentKind: environment.Kind,
			DangerousAllowInProduction: selection.DangerousAllowInProduction,
			PublicKeys:                 keys, Now: coordinator.now, MaximumEvidenceLifetime: maximumLifetime,
			ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
		})
		if buildErr != nil {
			operationErr = buildErr
			return nil
		}
		operationErr = consume(verifier)
		return nil
	})
	if err != nil {
		return attestation.ErrConfiguration
	}
	return operationErr
}

func secretScope(environment clientEnvironment) secrets.Scope {
	return secrets.Scope{
		OrganizationID: environment.OrganizationID,
		ApplicationID:  environment.ApplicationID,
		EnvironmentID:  environment.EnvironmentID,
	}
}

func clientGrant(issued IssuedSession) (clientapi.GrantResult, error) {
	accessSeconds, ok := exactPositiveSeconds(issued.Access.ExpiresAt.Sub(issued.Access.IssuedAt))
	if !ok {
		return clientapi.GrantResult{}, clientFailure("internal_error")
	}
	refreshSeconds, ok := exactPositiveSeconds(issued.RefreshExpiresAt.Sub(issued.Access.IssuedAt))
	if !ok {
		return clientapi.GrantResult{}, clientFailure("internal_error")
	}
	return clientapi.GrantResult{
		AccessToken:      clientapi.NewSensitiveString(issued.Access.Token.Reveal()),
		ExpiresIn:        accessSeconds,
		RefreshToken:     clientapi.NewSensitiveString(issued.Refresh.Reveal()),
		RefreshExpiresIn: refreshSeconds,
		Installation: clientapi.InstallationSummary{
			ID: issued.Installation.ID, Platform: issued.Installation.Platform,
			DPoPJKT: issued.Installation.DPoPJKT, Status: issued.Installation.Status,
		},
		Trust: clientapi.TrustSummary{
			Provider: issued.Trust.Provider, Level: issued.Trust.Level,
			VerifiedAt: issued.Trust.VerifiedAt, ExpiresAt: issued.Trust.ExpiresAt,
		},
	}, nil
}

func exactPositiveSeconds(duration time.Duration) (int, bool) {
	if duration <= 0 || duration%time.Second != 0 {
		return 0, false
	}
	seconds := duration / time.Second
	if seconds > time.Duration(^uint(0)>>1) {
		return 0, false
	}
	return int(seconds), true
}

func clientFailure(code string) error {
	return &clientapi.DependencyError{Code: code}
}

func mapChallengeScopeError(err error) string {
	if errors.Is(err, ErrSessionScope) {
		return "identity_token_invalid"
	}
	return "server_not_ready"
}

func mapDPoPError(err error) string {
	switch {
	case dpop.IsCode(err, "dpop_replayed"):
		return "dpop_replayed"
	case dpop.IsCode(err, "dpop_nonce_required"):
		return "dpop_nonce_required"
	default:
		return "dpop_invalid"
	}
}

func mapIdentityError(err error) string {
	switch {
	case errors.Is(err, identity.ErrCredentialExpired):
		return "identity_token_expired"
	case errors.Is(err, identity.ErrKeyUnavailable), errors.Is(err, identity.ErrConfiguration):
		return "server_not_ready"
	default:
		return "identity_token_invalid"
	}
}

func mapUserResolutionError(err error) string {
	switch {
	case errors.Is(err, identity.ErrCredentialInvalid),
		errors.Is(err, identity.ErrCredentialExpired),
		errors.Is(err, identity.ErrUserBlocked),
		errors.Is(err, identity.ErrUserNotFound),
		errors.Is(err, identity.ErrIdentityScope):
		return "identity_token_invalid"
	case errors.Is(err, identity.ErrConfiguration):
		return "server_not_ready"
	default:
		// User resolution performs PostgreSQL writes after verification. Unknown
		// transaction/query failures are availability failures, not evidence that
		// the already-verified credential was invalid.
		return "server_not_ready"
	}
}

func mapChallengeError(err error) string {
	switch {
	case errors.Is(err, ErrDPoPReplayed):
		return "dpop_replayed"
	case errors.Is(err, ErrSessionScope):
		return "conflict"
	case errors.Is(err, ErrChallengeInvalid):
		return "request_invalid"
	default:
		return "internal_error"
	}
}

func mapExchangeChallengeError(err error) string {
	switch {
	case errors.Is(err, ErrChallengeConsumed):
		return "conflict"
	case errors.Is(err, ErrChallengeExpired):
		return "attestation_stale"
	case errors.Is(err, ErrSessionScope):
		return "conflict"
	case errors.Is(err, ErrChallengeInvalid):
		return "attestation_invalid"
	default:
		return "internal_error"
	}
}

func mapAttestationError(err error) string {
	switch {
	case errors.Is(err, attestation.ErrUnsupported):
		return "attestation_unsupported"
	case errors.Is(err, attestation.ErrConfiguration):
		return "server_not_ready"
	default:
		return "attestation_invalid"
	}
}

func mapSessionError(err error) string {
	if dpop.IsCode(err, "dpop_nonce_required") {
		return "dpop_nonce_required"
	}
	if dpop.IsCode(err, "dpop_invalid") {
		return "dpop_invalid"
	}
	switch {
	case errors.Is(err, ErrDPoPReplayed):
		return "dpop_replayed"
	case errors.Is(err, ErrChallengeConsumed):
		return "conflict"
	case errors.Is(err, ErrChallengeExpired):
		return "attestation_stale"
	case errors.Is(err, ErrInstallationRevoked):
		return "installation_revoked"
	case errors.Is(err, ErrRefreshReused):
		return "refresh_token_reused"
	case errors.Is(err, ErrIdentityRefreshRequired):
		return "identity_reauthentication_required"
	case errors.Is(err, ErrAttestationStepUpRequired):
		return "attestation_step_up_required"
	case errors.Is(err, ErrAttestationRefreshNeeded):
		return "attestation_stale"
	case errors.Is(err, ErrRefreshInvalid):
		return "session_expired"
	case errors.Is(err, ErrSessionRevoked):
		return "session_revoked"
	case errors.Is(err, ErrSessionScope):
		return "session_revoked"
	case errors.Is(err, ErrSessionInvalid):
		return "attestation_invalid"
	case errors.Is(err, ErrSigningKeyUnavailable):
		return "server_not_ready"
	default:
		return "internal_error"
	}
}
