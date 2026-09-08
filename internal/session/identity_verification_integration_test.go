package session

import (
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/identity"
)

func TestIdentityVerificationFencesRetirementAndRotatedPossessionPostgreSQL(t *testing.T) {
	for _, components := range []bool{false, true} {
		for _, scenario := range []string{"revoked", "rotated", "expired"} {
			t.Run(scenario+map[bool]string{false: "-legacy", true: "-component"}[components], func(t *testing.T) {
				f := newAccessRevocationFixtureWithComponents(t, components)
				binding, err := f.store.InspectRefresh(f.ctx, f.issued.Refresh)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := f.store.configuration.ActiveSnapshot(f.ctx, configuration.TenantScope{
					OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID, EnvironmentID: binding.EnvironmentID})
				if err != nil {
					t.Fatal(err)
				}
				target := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions/identity")
				input := RotateInput{RefreshToken: f.issued.Refresh, DPoPProof: signedSessionDPoP(t, f.key, "POST", target, f.now, "late-identity-verification"), HTTPMethod: "POST", RequestURI: target}
				// Simulate identity verification finishing after a competing durable
				// state transition. The transaction must re-read, never trust preflight.
				switch scenario {
				case "revoked":
					err = f.store.RevokeCurrentInstallation(f.ctx, AccessRequestInput{AccessToken: f.issued.Access.Token, Principal: f.principal,
						DPoPProof: signedSessionAccessDPoP(t, f.key, "DELETE", f.revokeURI, f.now, f.issued.Access.Token.Reveal(), "identity-race-revoke"), HTTPMethod: "DELETE", RequestURI: f.revokeURI})
				case "rotated":
					_, err = f.store.Rotate(f.ctx, RotateInput{RefreshToken: f.issued.Refresh, DPoPProof: signedSessionDPoP(t, f.key, "POST", f.refreshURI, f.now, "identity-race-rotate"), HTTPMethod: "POST", RequestURI: f.refreshURI})
				case "expired":
					f.store.now = func() time.Time { return binding.ExpiresAt.Add(time.Second) }
				}
				if err != nil {
					t.Fatal(err)
				}
				verified := identity.VerifiedPrincipal{ProviderID: binding.IdentityProvider, ExpiresAt: binding.ExpiresAt.Add(time.Hour)}
				_, err = f.store.commitVerifiedIdentity(f.ctx, input, binding, snapshot, verified, nil)
				if err == nil || !(errors.Is(err, ErrSessionRevoked) || errors.Is(err, ErrInstallationFamilyRevoked) || errors.Is(err, ErrRefreshInvalid) || errors.Is(err, ErrInstallationRevoked) || errors.Is(err, ErrComponentRevoked)) {
					t.Fatalf("late identity verification not fenced: %v", err)
				}
			})
		}
	}
}
