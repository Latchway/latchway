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
	"github.com/latchway/latchway/internal/telemetry"
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
	Pool                 *pgxpool.Pool
	Configuration        *configuration.Store
	Users                *identity.UserStore
	Sessions             *Store
	AccessTokens         *AccessTokenVerifier
	Secrets              clientSecretStore
	IdentityHTTPClient   *http.Client
	IdentityKeyCache     identity.RemoteKeyDocumentCache
	AttestationTransport http.RoundTripper
	AppAttestKeys        attestation.AppAttestKeyStore
	Telemetry            *telemetry.Registry
	Now                  func() time.Time
}

type clientCoordinator struct {
	pool                 *pgxpool.Pool
	configuration        *configuration.Store
	users                *identity.UserStore
	sessions             *Store
	accessTokens         *AccessTokenVerifier
	challenges           *ChallengeStore
	secrets              clientSecretStore
	identityHTTP         *http.Client
	identityKeyCache     identity.RemoteKeyDocumentCache
	attestationTransport http.RoundTripper
	appAttestKeys        attestation.AppAttestKeyStore
	telemetry            *telemetry.Registry
	now                  func() time.Time

	identityMu       sync.Mutex
	identityCache    map[string]identity.IdentityVerifier
	attestationMu    sync.Mutex
	attestationCache map[attestationVerifierCacheKey]*preparedAttestationVerifier
}

// NewClientCoordinator constructs the fail-closed implementation used by the
// client HTTP API.
func NewClientCoordinator(config ClientCoordinatorConfig) (clientapi.Coordinator, error) {
	if config.Pool == nil || config.Configuration == nil || config.Users == nil || config.Sessions == nil || config.AccessTokens == nil || nilCoordinatorDependency(config.Secrets) {
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
		sessions: config.Sessions, accessTokens: config.AccessTokens,
		challenges: challenges, secrets: config.Secrets,
		identityHTTP: config.IdentityHTTPClient, identityKeyCache: config.IdentityKeyCache,
		attestationTransport: config.AttestationTransport,
		appAttestKeys:        config.AppAttestKeys, telemetry: config.Telemetry, now: config.Now,
		identityCache:    make(map[string]identity.IdentityVerifier),
		attestationCache: make(map[attestationVerifierCacheKey]*preparedAttestationVerifier),
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
	policy, selection, ok := snapshot.RequiredAttestationForPlatform(input.Platform)
	if !ok || policy.ID == "" || selection.Mode != "required" {
		return clientapi.ChallengeResult{}, clientFailure("attestation_unsupported")
	}
	if !platformOriginAllowed(selection, input.Platform, input.Metadata.Origin) {
		return clientapi.ChallengeResult{}, clientFailure("attestation_invalid")
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
	if err := coordinator.preflightAttestationVerifier(ctx, environment, snapshot, policy, selection, input.Platform); err != nil {
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
		Origin:  input.Metadata.Origin,
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
			ClientDataHash:  clientDataHash,
			ProviderOptions: attestationProviderOptions(selection),
		},
	}, nil
}

func (coordinator *clientCoordinator) ExchangeSession(ctx context.Context, input clientapi.ExchangeInput) (clientapi.GrantResult, error) {
	challenge, err := coordinator.challenges.Get(ctx, input.ChallengeID)
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapExchangeChallengeError(err))
	}
	if input.Attestation.Provider != challenge.Attestation.Provider {
		coordinator.recordAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
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
	if !platformOriginAllowed(selection, challenge.Binding.Platform, input.Metadata.Origin) {
		coordinator.recordAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	if input.Metadata.Origin != challenge.Origin {
		coordinator.recordAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	payload, err := input.Attestation.Payload.Object()
	if err != nil {
		coordinator.recordAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	evidence, err := attestation.NewEvidence(input.Attestation.Provider, payload)
	if err != nil {
		coordinator.recordAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	verified, err := coordinator.verifyAttestationEvidence(ctx, environment, snapshot, policy, selection, evidence, challenge.Binding)
	if err != nil {
		coordinator.recordAttestationResult(ctx, challenge, attestationTelemetryOutcome(err), "none")
		return clientapi.GrantResult{}, clientFailure(mapAttestationError(err))
	}
	coordinator.recordAttestationResult(ctx, challenge, telemetry.AttestationOutcomeSucceeded, verified.TrustLevel)
	issued, err := coordinator.sessions.Exchange(ctx, ExchangeInput{
		ChallengeID: input.ChallengeID, Attestation: verified, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		Origin:     input.Metadata.Origin,
		KeyStorage: "unknown", AppVersion: input.Installation.AppVersion,
	})
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapSessionError(err))
	}
	return clientGrant(issued)
}

func (coordinator *clientCoordinator) recordAttestationResult(
	ctx context.Context,
	challenge Challenge,
	outcome string,
	level string,
) {
	if coordinator == nil || coordinator.telemetry == nil {
		return
	}
	coordinator.telemetry.RecordAttestationResult(ctx, telemetry.Labels{
		Application: challenge.Binding.ApplicationID,
		Environment: challenge.EnvironmentID,
		Platform:    challenge.Binding.Platform, AttestationLevel: level,
		Outcome: outcome,
	})
}

func (coordinator *clientCoordinator) recordComponentAttestationResult(
	ctx context.Context,
	challenge ComponentAttestationChallenge,
	outcome string,
	level string,
) {
	if coordinator == nil || coordinator.telemetry == nil {
		return
	}
	coordinator.telemetry.RecordAttestationResult(ctx, telemetry.Labels{
		Application: challenge.Binding.ApplicationID,
		Environment: challenge.EnvironmentID,
		Platform:    challenge.Binding.Platform, AttestationLevel: level,
		Outcome: outcome,
	})
}

func attestationTelemetryOutcome(err error) string {
	switch {
	case errors.Is(err, attestation.ErrConfiguration),
		errors.Is(err, attestation.ErrPlayIntegrityService),
		errors.Is(err, attestation.ErrAppAttestKeyStore),
		errors.Is(err, attestation.ErrFirebaseAppCheckService),
		errors.Is(err, attestation.ErrTurnstileService):
		return telemetry.AttestationOutcomeUnavailable
	default:
		return telemetry.AttestationOutcomeRejected
	}
}

func (coordinator *clientCoordinator) RefreshSession(ctx context.Context, input clientapi.RefreshInput) (clientapi.GrantResult, error) {
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
		Origin: input.Metadata.Origin,
	})
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapSessionError(err))
	}
	return clientGrant(issued)
}

func (coordinator *clientCoordinator) ProvisionComponent(ctx context.Context, input clientapi.ProvisionComponentInput) (clientapi.ProvisionComponentResult, error) {
	access, principal, proof, err := coordinator.verifiedAccessRequest(ctx, input.AccessToken, input.Metadata)
	if err != nil {
		return clientapi.ProvisionComponentResult{}, err
	}
	provisioned, err := coordinator.sessions.ProvisionComponent(ctx, ComponentProvisionInput{
		Access: AccessRequestInput{
			AccessToken: access, Principal: principal, DPoPProof: proof,
			HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
			Origin: input.Metadata.Origin,
		},
		DefinitionID: input.DefinitionID,
		PublicJWK: dpop.PublicJWK{
			Kty: input.PublicJWK.Kty, Crv: input.PublicJWK.Crv,
			X: input.PublicJWK.X, Y: input.PublicJWK.Y,
		},
		RequestedFeatures: append([]string(nil), input.RequestedFeatures...),
		AppVersion:        input.ClientMetadata.AppVersion,
		SDKVersion:        input.ClientMetadata.SDKVersion,
	})
	if err != nil {
		return clientapi.ProvisionComponentResult{}, clientFailure(mapSessionError(err))
	}
	return clientapi.ProvisionComponentResult{
		ComponentID:           provisioned.Component.ID,
		InstallationFamilyID:  provisioned.Family.ID,
		TrustSource:           provisioned.Component.TrustSource,
		TrustExpiresAt:        provisioned.TrustExpiresAt,
		GrantedFeatures:       append([]string(nil), provisioned.Component.GrantedFeatures...),
		RefreshGrant:          clientapi.NewSensitiveString(provisioned.RefreshGrant.Reveal()),
		RefreshGrantExpiresAt: provisioned.RefreshExpiresAt,
	}, nil
}

func (coordinator *clientCoordinator) CreateComponentSession(ctx context.Context, input clientapi.CreateComponentSessionInput) (clientapi.GrantResult, error) {
	refresh, err := NewRefreshToken(input.RefreshGrant.Reveal())
	if err != nil {
		return clientapi.GrantResult{}, clientFailure("component_not_provisioned")
	}
	proof, err := NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return clientapi.GrantResult{}, clientFailure("dpop_invalid")
	}
	issued, err := coordinator.sessions.CreateComponentSession(ctx, ComponentSessionInput{
		ComponentID: input.ComponentID, RefreshGrant: refresh, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		Origin: input.Metadata.Origin,
	})
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapSessionError(err))
	}
	return clientGrant(issued)
}

func (coordinator *clientCoordinator) CreateComponentAttestationChallenge(
	ctx context.Context,
	input clientapi.CreateComponentAttestationChallengeInput,
) (clientapi.ChallengeResult, error) {
	access, principal, proof, err := coordinator.verifiedAccessRequest(ctx, input.AccessToken, input.Metadata)
	if err != nil {
		return clientapi.ChallengeResult{}, err
	}
	if principal.ComponentIsRoot || principal.ComponentID != input.ComponentID {
		return clientapi.ChallengeResult{}, clientFailure("component_not_provisioned")
	}
	environment, err := coordinator.resolveEnvironmentByID(
		ctx, principal.OrganizationID, principal.ApplicationID, principal.EnvironmentID,
	)
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure("session_revoked")
	}
	snapshot, err := coordinator.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: environment.OrganizationID, ApplicationID: environment.ApplicationID,
		EnvironmentID: environment.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != principal.PolicyRevisionID {
		return clientapi.ChallengeResult{}, clientFailure("component_not_configured")
	}
	definition, policy, selection, err := componentStepUpSelection(snapshot, principal.ComponentDefinitionID)
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapSessionError(err))
	}
	if err := coordinator.preflightAttestationVerifier(
		ctx, environment, snapshot, policy, selection, definition.Platform,
	); err != nil {
		return clientapi.ChallengeResult{}, clientFailure("server_not_ready")
	}
	challenge, err := coordinator.sessions.CreateComponentAttestationChallenge(ctx, ComponentAttestationChallengeInput{
		Access: AccessRequestInput{
			AccessToken: access, Principal: principal, DPoPProof: proof,
			HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
			Origin: input.Metadata.Origin,
		},
		ComponentID: input.ComponentID,
	})
	if err != nil {
		return clientapi.ChallengeResult{}, clientFailure(mapSessionError(err))
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
			ClientDataHash: clientDataHash, ProviderOptions: attestationProviderOptions(selection),
		},
	}, nil
}

func (coordinator *clientCoordinator) ExchangeComponentAttestation(
	ctx context.Context,
	input clientapi.ExchangeComponentAttestationInput,
) (clientapi.GrantResult, error) {
	access, principal, proof, err := coordinator.verifiedAccessRequest(ctx, input.AccessToken, input.Metadata)
	if err != nil {
		return clientapi.GrantResult{}, err
	}
	if principal.ComponentIsRoot || principal.ComponentID != input.ComponentID {
		return clientapi.GrantResult{}, clientFailure("component_not_provisioned")
	}
	challenge, err := coordinator.sessions.GetComponentAttestationChallenge(ctx, input.ChallengeID)
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapExchangeChallengeError(err))
	}
	if challenge.Binding.ClientComponentID != principal.ComponentID ||
		challenge.Binding.ComponentDefinitionID != principal.ComponentDefinitionID ||
		challenge.Binding.InstallationFamilyID != principal.InstallationFamilyID ||
		challenge.Binding.DPoPJKT != principal.DPoPJKT ||
		challenge.Binding.PrincipalID != principal.ApplicationUserID ||
		challenge.Binding.ApplicationID != principal.ApplicationID ||
		challenge.OrganizationID != principal.OrganizationID ||
		challenge.EnvironmentID != principal.EnvironmentID {
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	if input.Attestation.Provider != challenge.Attestation.Provider {
		coordinator.recordComponentAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	environment, err := coordinator.resolveEnvironmentByID(
		ctx, principal.OrganizationID, principal.ApplicationID, principal.EnvironmentID,
	)
	if err != nil || environment.Slug != challenge.Binding.Environment {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	snapshot, err := coordinator.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: environment.OrganizationID, ApplicationID: environment.ApplicationID,
		EnvironmentID: environment.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != challenge.ConfigurationRevisionID ||
		snapshot.RevisionID != principal.PolicyRevisionID {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	_, policy, selection, err := componentStepUpSelection(snapshot, principal.ComponentDefinitionID)
	if err != nil || policy.ID != challenge.Attestation.ID ||
		selection.Provider != challenge.Attestation.Provider {
		return clientapi.GrantResult{}, clientFailure("conflict")
	}
	if _, err := prevalidateAccessDPoPMetadata(
		input.Metadata, challenge.Binding.DPoPJKT, access.value, coordinator.now().UTC(),
		snapshot.SessionPolicy().MaximumClockSkew,
	); err != nil {
		return clientapi.GrantResult{}, clientFailure(mapDPoPError(err))
	}
	if !platformOriginAllowed(selection, challenge.Binding.Platform, input.Metadata.Origin) {
		coordinator.recordComponentAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	payload, err := input.Attestation.Payload.Object()
	if err != nil {
		coordinator.recordComponentAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	evidence, err := attestation.NewEvidence(input.Attestation.Provider, payload)
	if err != nil {
		coordinator.recordComponentAttestationResult(ctx, challenge, telemetry.AttestationOutcomeRejected, "none")
		return clientapi.GrantResult{}, clientFailure("attestation_invalid")
	}
	verified, err := coordinator.verifyAttestationEvidence(
		ctx, environment, snapshot, policy, selection, evidence, challenge.Binding,
	)
	if err != nil {
		coordinator.recordComponentAttestationResult(ctx, challenge, attestationTelemetryOutcome(err), "none")
		return clientapi.GrantResult{}, clientFailure(mapAttestationError(err))
	}
	coordinator.recordComponentAttestationResult(ctx, challenge, telemetry.AttestationOutcomeSucceeded, verified.TrustLevel)
	issued, err := coordinator.sessions.ExchangeComponentAttestation(ctx, ComponentAttestationExchangeInput{
		Access: AccessRequestInput{
			AccessToken: access, Principal: principal, DPoPProof: proof,
			HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
			Origin: input.Metadata.Origin,
		},
		ComponentID: input.ComponentID, Challenge: challenge, Attestation: verified,
	})
	if err != nil {
		return clientapi.GrantResult{}, clientFailure(mapSessionError(err))
	}
	return clientGrant(issued)
}

func (coordinator *clientCoordinator) verifiedAccessRequest(ctx context.Context, raw clientapi.SensitiveString, metadata clientapi.RequestMetadata) (AccessToken, AccessPrincipal, DPoPProof, error) {
	access, err := NewAccessToken(raw.Reveal())
	if err != nil {
		return AccessToken{}, AccessPrincipal{}, DPoPProof{}, clientFailure("session_expired")
	}
	principal, err := coordinator.accessTokens.Verify(ctx, access)
	if err != nil {
		return AccessToken{}, AccessPrincipal{}, DPoPProof{}, clientFailure(mapAccessRequestError(err))
	}
	proof, err := NewDPoPProof(metadata.DPoPProof.Reveal())
	if err != nil {
		return AccessToken{}, AccessPrincipal{}, DPoPProof{}, clientFailure("dpop_invalid")
	}
	return access, principal, proof, nil
}

func (coordinator *clientCoordinator) Diagnostics(ctx context.Context, input clientapi.DiagnosticsInput) (clientapi.DiagnosticsResult, error) {
	accessToken, err := NewAccessToken(input.AccessToken.Reveal())
	if err != nil {
		return clientapi.DiagnosticsResult{}, clientFailure("session_expired")
	}
	principal, err := coordinator.accessTokens.Verify(ctx, accessToken)
	if err != nil {
		return clientapi.DiagnosticsResult{}, clientFailure(mapAccessRequestError(err))
	}
	proof, err := NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return clientapi.DiagnosticsResult{}, clientFailure("dpop_invalid")
	}
	authorization, refreshAvailable, err := coordinator.sessions.authorizeClientDiagnostics(ctx, AccessRequestInput{
		AccessToken: accessToken, Principal: principal, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		Origin: input.Metadata.Origin,
	})
	if err != nil {
		return clientapi.DiagnosticsResult{}, clientFailure(mapAccessRequestError(err))
	}
	if !clientSDKMatchesInstallation(input.Metadata.SDK, authorization.InstallationPlatform) {
		return clientapi.DiagnosticsResult{}, clientFailure("request_invalid")
	}
	return clientapi.DiagnosticsResult{
		Installation: clientapi.InstallationSummary{
			ID: authorization.InstallationID, Platform: authorization.InstallationPlatform,
			DPoPJKT: authorization.DPoPJKT, Status: "active",
		},
		SessionExpiresAt: authorization.AccessExpiresAt,
		RefreshAvailable: refreshAvailable,
		Trust: clientapi.TrustSummary{
			Provider: authorization.AttestationProvider, Level: authorization.TrustLevel,
			Source:                    authorization.TrustSource,
			ParentComponentID:         authorization.ParentComponentID,
			ParentAttestationProvider: authorization.ParentAttestationProvider,
			DelegationID:              authorization.DelegationID,
			VerifiedAt:                authorization.AttestedAt, ExpiresAt: authorization.AttestationExpiresAt,
		},
	}, nil
}

func clientSDKMatchesInstallation(sdk, platform string) bool {
	switch sdk {
	case "ios":
		return platform == "ios" || platform == "watchos"
	case "android":
		return platform == "android"
	case "javascript":
		return platform == "web" || platform == "node"
	case "react-native":
		return platform == "react_native_ios" || platform == "react_native_android"
	default:
		return false
	}
}

func (coordinator *clientCoordinator) RevokeCurrentInstallation(ctx context.Context, input clientapi.RevokeInstallationInput) error {
	accessToken, err := NewAccessToken(input.AccessToken.Reveal())
	if err != nil {
		return clientFailure("session_expired")
	}
	principal, err := coordinator.accessTokens.Verify(ctx, accessToken)
	if err != nil {
		return clientFailure(mapAccessRequestError(err))
	}
	proof, err := NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return clientFailure("dpop_invalid")
	}
	err = coordinator.sessions.RevokeCurrentInstallation(ctx, AccessRequestInput{
		AccessToken: accessToken, Principal: principal, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		Origin: input.Metadata.Origin,
	})
	if err != nil {
		return clientFailure(mapAccessRequestError(err))
	}
	return nil
}

func (coordinator *clientCoordinator) RevokeComponent(ctx context.Context, input clientapi.RevokeComponentInput) error {
	access, principal, proof, err := coordinator.verifiedAccessRequest(ctx, input.AccessToken, input.Metadata)
	if err != nil {
		return err
	}
	err = coordinator.sessions.RevokeComponent(ctx, AccessRequestInput{
		AccessToken: access, Principal: principal, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		Origin: input.Metadata.Origin,
	}, input.ComponentID)
	if err != nil {
		return clientFailure(mapAccessRequestError(err))
	}
	return nil
}

func (coordinator *clientCoordinator) RevokeCurrentFamily(ctx context.Context, input clientapi.RevokeFamilyInput) error {
	access, principal, proof, err := coordinator.verifiedAccessRequest(ctx, input.AccessToken, input.Metadata)
	if err != nil {
		return err
	}
	err = coordinator.sessions.RevokeCurrentFamily(ctx, AccessRequestInput{
		AccessToken: access, Principal: principal, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL,
		Origin: input.Metadata.Origin,
	})
	if err != nil {
		return clientFailure(mapAccessRequestError(err))
	}
	return nil
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

func (coordinator *clientCoordinator) resolveEnvironmentByID(
	ctx context.Context,
	organizationID string,
	applicationID string,
	environmentID string,
) (clientEnvironment, error) {
	if id.Validate(organizationID, id.Organization) != nil ||
		id.Validate(applicationID, id.Application) != nil ||
		id.Validate(environmentID, id.Environment) != nil {
		return clientEnvironment{}, ErrSessionScope
	}
	var result clientEnvironment
	err := coordinator.pool.QueryRow(ctx, `
		SELECT organization.organization_id,
		       application.application_id,
		       environment.environment_id,
		       environment.slug,
		       environment.kind
		FROM organizations AS organization
		JOIN applications AS application
		  ON application.organization_id = organization.organization_id
		JOIN environments AS environment
		  ON environment.organization_id = application.organization_id
		 AND environment.application_id = application.application_id
		WHERE organization.organization_id = $1
		  AND application.application_id = $2
		  AND environment.environment_id = $3
		  AND organization.status = 'active'
		  AND application.status = 'active'
		  AND environment.status = 'active'
		  AND organization.disabled_at IS NULL
		  AND application.disabled_at IS NULL
		  AND environment.disabled_at IS NULL
	`, organizationID, applicationID, environmentID).Scan(
		&result.OrganizationID, &result.ApplicationID, &result.EnvironmentID,
		&result.Slug, &result.Kind,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return clientEnvironment{}, ErrSessionScope
	}
	if err != nil {
		return clientEnvironment{}, fmt.Errorf("resolve client environment by ID: %w", err)
	}
	if result.OrganizationID != organizationID || result.ApplicationID != applicationID ||
		result.EnvironmentID != environmentID || !sessionIdentifierPattern.MatchString(result.Slug) ||
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
	return prevalidateDPoPMetadata(input.Metadata, expectedJKT, now, clockSkew)
}

func prevalidateAccessDPoPMetadata(
	metadata clientapi.RequestMetadata,
	expectedJKT string,
	accessToken string,
	now time.Time,
	clockSkew time.Duration,
) (DPoPProof, error) {
	proof, err := NewDPoPProof(metadata.DPoPProof.Reveal())
	if err != nil {
		return DPoPProof{}, err
	}
	if _, err := dpop.Validate(proof.value, dpop.Options{
		Method: metadata.HTTPMethod, URI: &metadata.TargetURL,
		AccessToken: accessToken, ExpectedJKT: expectedJKT, Now: now,
		ClockSkew: clockSkew, ClockSkewSet: true, RequireAccessHash: true,
	}); err != nil {
		return DPoPProof{}, err
	}
	return proof, nil
}

func prevalidateDPoPMetadata(metadata clientapi.RequestMetadata, expectedJKT string, now time.Time, clockSkew time.Duration) (DPoPProof, error) {
	proof, err := NewDPoPProof(metadata.DPoPProof.Reveal())
	if err != nil {
		return DPoPProof{}, err
	}
	if _, err := dpop.Validate(proof.value, dpop.Options{
		Method: metadata.HTTPMethod, URI: &metadata.TargetURL,
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
		Client:            coordinator.identityHTTP, SharedCache: coordinator.identityKeyCache, Now: coordinator.now,
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
			URL: provider.JWKSURL, Issuer: provider.Issuer, Format: identity.RemoteKeyFormatJWKS,
			Client: coordinator.identityHTTP, SharedCache: coordinator.identityKeyCache, Now: coordinator.now,
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
	result := clientapi.GrantResult{
		AccessToken:      clientapi.NewSensitiveString(issued.Access.Token.Reveal()),
		ExpiresIn:        accessSeconds,
		RefreshToken:     clientapi.NewSensitiveString(issued.Refresh.Reveal()),
		RefreshExpiresIn: refreshSeconds,
		RefreshExpiresAt: issued.RefreshExpiresAt,
		Installation: clientapi.InstallationSummary{
			ID: issued.Installation.ID, Platform: issued.Installation.Platform,
			DPoPJKT: issued.Installation.DPoPJKT, Status: issued.Installation.Status,
		},
		Trust: clientapi.TrustSummary{
			Provider: issued.Trust.Provider, Level: issued.Trust.Level,
			Source:                    issued.Component.TrustSource,
			ParentComponentID:         issued.Component.ParentComponentID,
			ParentAttestationProvider: issued.Component.ParentAttestationProvider,
			DelegationID:              issued.Component.DelegationID,
			VerifiedAt:                issued.Trust.VerifiedAt, ExpiresAt: issued.Trust.ExpiresAt,
		},
	}
	if issued.Family.ID != "" && issued.Component.ID != "" {
		result.InstallationFamily = &clientapi.InstallationFamilySummary{
			ID: issued.Family.ID, Status: issued.Family.Status,
		}
		result.Component = &clientapi.ClientComponentSummary{
			ID: issued.Component.ID, DefinitionID: issued.Component.DefinitionID,
			Kind: issued.Component.Kind, Platform: issued.Component.Platform,
			IsRoot: issued.Component.IsRoot, Status: issued.Component.Status,
			DPoPJKT:         issued.Component.DPoPJKT,
			GrantedFeatures: append([]string(nil), issued.Component.GrantedFeatures...),
		}
	}
	return result, nil
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
	case errors.Is(err, ErrReplayInvalid):
		return "dpop_invalid"
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
	case errors.Is(err, attestation.ErrConfiguration),
		errors.Is(err, attestation.ErrPlayIntegrityService),
		errors.Is(err, attestation.ErrAppAttestKeyStore),
		errors.Is(err, attestation.ErrFirebaseAppCheckService),
		errors.Is(err, attestation.ErrTurnstileService):
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
	case errors.Is(err, ErrInstallationFamilyRevoked):
		return "installation_family_revoked"
	case errors.Is(err, ErrInstallationFamilyNotFound):
		return "installation_family_not_found"
	case errors.Is(err, ErrComponentDefinitionNotFound):
		return "component_definition_not_found"
	case errors.Is(err, ErrComponentRevoked):
		return "component_revoked"
	case errors.Is(err, ErrComponentNotConfigured):
		return "component_not_configured"
	case errors.Is(err, ErrComponentNotProvisioned):
		return "component_not_provisioned"
	case errors.Is(err, ErrComponentKeyInvalid):
		return "component_key_invalid"
	case errors.Is(err, ErrComponentKeyReplaced):
		return "component_key_replaced"
	case errors.Is(err, ErrComponentDelegationExpired):
		return "component_delegation_expired"
	case errors.Is(err, ErrComponentFeatureNotGranted):
		return "component_feature_not_granted"
	case errors.Is(err, ErrComponentParentTrustExpired):
		return "component_parent_trust_expired"
	case errors.Is(err, ErrComponentDirectAttestationRequired):
		return "component_direct_attestation_required"
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

func mapAccessRequestError(err error) string {
	if dpop.IsCode(err, "dpop_nonce_required") {
		return "dpop_nonce_required"
	}
	if dpop.IsCode(err, "dpop_invalid") {
		return "dpop_invalid"
	}
	switch {
	case errors.Is(err, ErrDPoPReplayed):
		return "dpop_replayed"
	case errors.Is(err, ErrReplayInvalid):
		return "dpop_invalid"
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenExpired):
		return "session_expired"
	case errors.Is(err, ErrInstallationRevoked):
		return "installation_revoked"
	case errors.Is(err, ErrInstallationFamilyRevoked):
		return "installation_family_revoked"
	case errors.Is(err, ErrInstallationFamilyNotFound):
		return "installation_family_not_found"
	case errors.Is(err, ErrComponentDefinitionNotFound):
		return "component_definition_not_found"
	case errors.Is(err, ErrComponentRevoked):
		return "component_revoked"
	case errors.Is(err, ErrComponentNotConfigured):
		return "component_not_configured"
	case errors.Is(err, ErrComponentNotProvisioned):
		return "component_not_provisioned"
	case errors.Is(err, ErrComponentKeyInvalid):
		return "component_key_invalid"
	case errors.Is(err, ErrComponentKeyReplaced):
		return "component_key_replaced"
	case errors.Is(err, ErrComponentDelegationExpired):
		return "component_delegation_expired"
	case errors.Is(err, ErrComponentFeatureNotGranted):
		return "component_feature_not_granted"
	case errors.Is(err, ErrComponentParentTrustExpired):
		return "component_parent_trust_expired"
	case errors.Is(err, ErrComponentDirectAttestationRequired):
		return "component_direct_attestation_required"
	case errors.Is(err, ErrAttestationRefreshNeeded):
		return "attestation_stale"
	case errors.Is(err, ErrSessionRevoked), errors.Is(err, ErrSessionScope), errors.Is(err, ErrSessionInvalid):
		return "session_revoked"
	case errors.Is(err, ErrSigningKeyUnavailable):
		return "server_not_ready"
	default:
		return "internal_error"
	}
}
