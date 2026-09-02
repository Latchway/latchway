package session

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAuthorizationValidatedSnapshotProvenanceAndDeepCopy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	claims := map[string]any{
		"plan":  "premium",
		"roles": []any{"member", "tester"},
		"score": json.Number("42"),
	}
	authorization := testAuthorization(now, claims)
	authorization.UserOverrideID = "uov_00000000000000000000000000"
	authorization.LimitPlanOverride = "premium_override"
	sealed, err := sealAuthorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	// Sealing must detach the durable snapshot from the source map.
	claims["plan"] = "forged"
	claims["roles"].([]any)[0] = "owner"

	first, err := sealed.ValidatedSnapshot(now)
	if err != nil {
		t.Fatal(err)
	}
	if first.NormalizedClaims["plan"] != "premium" || first.InstallationPlatform != "ios" ||
		first.UserOverrideID != authorization.UserOverrideID ||
		first.LimitPlanOverride != authorization.LimitPlanOverride ||
		first.EnvironmentKind != "production" || !first.AttestedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("unexpected validated authorization: %#v", first)
	}
	roles, ok := first.NormalizedClaims["roles"].([]any)
	if !ok || roles[0] != "member" {
		t.Fatalf("unexpected validated roles: %#v", first.NormalizedClaims["roles"])
	}
	first.NormalizedClaims["plan"] = "mutated"
	roles[0] = "mutated"

	second, err := sealed.ValidatedSnapshot(now)
	if err != nil {
		t.Fatal(err)
	}
	secondRoles := second.NormalizedClaims["roles"].([]any)
	if second.NormalizedClaims["plan"] != "premium" || secondRoles[0] != "member" {
		t.Fatal("validated snapshot retained a caller mutation")
	}

	sealed.NormalizedClaims["plan"] = "tampered"
	if _, err := sealed.ValidatedSnapshot(now); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("tampered authorization error = %v, want session invalid", err)
	}

	sealed, err = sealAuthorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	sealed.LimitPlanOverride = "free"
	if _, err := sealed.ValidatedSnapshot(now); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("tampered limit-plan override error = %v, want session invalid", err)
	}
}

func TestAuthorizationValidatedSnapshotFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Authorization)
		want   error
	}{
		{name: "platform", mutate: func(value *Authorization) { value.InstallationPlatform = "desktop" }, want: ErrSessionInvalid},
		{name: "environment", mutate: func(value *Authorization) { value.EnvironmentKind = "preview" }, want: ErrSessionInvalid},
		{name: "attested at", mutate: func(value *Authorization) { value.AttestedAt = time.Time{} }, want: ErrSessionInvalid},
		{name: "claims", mutate: func(value *Authorization) { value.NormalizedClaims["plan"] = map[string]any{"raw": true} }, want: ErrSessionInvalid},
		{name: "override ID only", mutate: func(value *Authorization) { value.UserOverrideID = "uov_00000000000000000000000000" }, want: ErrSessionInvalid},
		{name: "override plan only", mutate: func(value *Authorization) { value.LimitPlanOverride = "premium" }, want: ErrSessionInvalid},
		{name: "invalid override plan", mutate: func(value *Authorization) {
			value.UserOverrideID = "uov_00000000000000000000000000"
			value.LimitPlanOverride = "Premium"
		}, want: ErrSessionInvalid},
		{name: "access expired", mutate: func(value *Authorization) { value.AccessExpiresAt = now }, want: ErrTokenExpired},
		{name: "identity expired", mutate: func(value *Authorization) { value.IdentityExpiresAt = now }, want: ErrTokenExpired},
		{name: "attested in future", mutate: func(value *Authorization) { value.AttestedAt = now.Add(time.Minute) }, want: ErrSessionInvalid},
		{name: "attestation expired", mutate: func(value *Authorization) { value.AttestationExpiresAt = now }, want: ErrAttestationRefreshNeeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := testAuthorization(now, map[string]any{"plan": "premium"})
			test.mutate(&candidate)
			sealed, sealErr := sealAuthorization(candidate)
			if test.want == ErrSessionInvalid && test.name != "attested in future" {
				if !errors.Is(sealErr, test.want) {
					t.Fatalf("sealAuthorization() error = %v, want %v", sealErr, test.want)
				}
				return
			}
			if sealErr != nil {
				t.Fatal(sealErr)
			}
			if _, validateErr := sealed.ValidatedSnapshot(now); !errors.Is(validateErr, test.want) {
				t.Fatalf("ValidatedSnapshot() error = %v, want %v", validateErr, test.want)
			}
		})
	}
}

func TestAuthorizationStateAllowsIndependentNonRootComponentTrust(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	state := activeAuthorizationState(now)
	state.ComponentID = "cmp_00000000000000000000000000"
	state.ComponentIsRoot = false
	state.TrustLevel = "app_verified"
	state.installationTrust = "debug"
	state.familyStatus = "active"
	state.componentStatus = "active"
	state.componentKeyStatus = "active"
	state.componentSessionStatus = "active"
	if err := authorizationStateError(state, now, false); err != nil {
		t.Fatalf("independent component trust error = %v", err)
	}

	state.ComponentIsRoot = true
	if err := authorizationStateError(state, now, false); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("root trust mismatch error = %v, want session revoked", err)
	}
	state.ComponentID = ""
	state.ComponentIsRoot = false
	if err := authorizationStateError(state, now, false); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("legacy trust mismatch error = %v, want session revoked", err)
	}
}

func TestComponentAuthorizationSurvivesTrustExpiryUntilAccessExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	authorization := testAuthorization(now, map[string]any{"plan": "premium"})
	authorization.InstallationFamilyID = "fam_00000000000000000000000000"
	authorization.InstallationFamilyStatus = "active"
	authorization.ComponentID = "cmp_00000000000000000000000000"
	authorization.ComponentDefinitionID = "ios-main-app"
	authorization.ComponentKind = "main_app"
	authorization.ComponentIsRoot = true
	authorization.ComponentSessionFamilyID = "csf_00000000000000000000000000"
	authorization.ComponentKeyID = "cky_00000000000000000000000000"
	authorization.TrustSource = "direct_attested"
	authorization.GrantedFeatures = []string{"assistant"}
	authorization.AttestationExpiresAt = now

	state := activeAuthorizationState(now)
	state.Authorization = authorization
	state.familyStatus = "active"
	state.componentStatus = "active"
	state.componentKeyStatus = "active"
	state.componentSessionStatus = "active"
	if err := authorizationStateError(state, now, false); err != nil {
		t.Fatalf("component access rejected at trust expiry: %v", err)
	}

	sealed, err := sealAuthorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.ValidatedSnapshot(now); err != nil {
		t.Fatalf("component snapshot rejected at trust expiry: %v", err)
	}
	if _, err := sealed.ValidatedSnapshot(authorization.AccessExpiresAt); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("component snapshot at access expiry error = %v, want token expired", err)
	}
}

func TestAuthorizationMatchesPrincipalBindsAttestationProvider(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	authorization := testAuthorization(now, map[string]any{"plan": "premium"})
	authorization.ComponentID = "cmp_00000000000000000000000000"
	principal := AccessPrincipal{
		InstallationFamilyID:      authorization.InstallationFamilyID,
		ComponentID:               authorization.ComponentID,
		ComponentDefinitionID:     authorization.ComponentDefinitionID,
		ComponentKind:             authorization.ComponentKind,
		ComponentIsRoot:           authorization.ComponentIsRoot,
		TrustSource:               authorization.TrustSource,
		AttestationProvider:       authorization.AttestationProvider,
		ParentComponentID:         authorization.ParentComponentID,
		ParentAttestationProvider: authorization.ParentAttestationProvider,
		DelegationID:              authorization.DelegationID,
		Features:                  append([]string(nil), authorization.GrantedFeatures...),
	}
	if !authorizationMatchesPrincipal(authorization, principal) {
		t.Fatal("matching attestation provider was rejected")
	}
	principal.AttestationProvider = "play_integrity"
	if authorizationMatchesPrincipal(authorization, principal) {
		t.Fatal("mismatched attestation provider was accepted")
	}
}

func activeAuthorizationState(now time.Time) authorizationState {
	return authorizationState{
		Authorization:      testAuthorization(now, map[string]any{"plan": "premium"}),
		installationStatus: "active", installationTrust: "device_verified",
		userStatus: "active", applicationStatus: "active", environmentStatus: "active",
		organizationStatus: "active",
	}
}

func testAuthorization(now time.Time, claims map[string]any) Authorization {
	return Authorization{
		OrganizationID: "org_00000000000000000000000000", ApplicationID: "app_00000000000000000000000000",
		EnvironmentID: "env_00000000000000000000000000", EnvironmentKind: "production",
		ApplicationUserID: "usr_00000000000000000000000000", InstallationID: "ins_00000000000000000000000000",
		InstallationPlatform: "ios", SessionGrantID: "sgr_00000000000000000000000000",
		PolicyRevisionID: "rev_00000000000000000000000000", IdentityProvider: "firebase",
		DPoPJKT: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TrustLevel: "device_verified",
		AttestationProvider: "app_attest", NormalizedClaims: claims,
		IdentityVerifiedAt: now.Add(-2 * time.Minute), IdentityExpiresAt: now.Add(time.Hour),
		AttestedAt:           now.Add(-time.Minute),
		AttestationExpiresAt: now.Add(time.Hour), AccessExpiresAt: now.Add(10 * time.Minute),
	}
}
