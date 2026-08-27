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
	sealed, err := sealAuthorization(testAuthorization(now, claims))
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

func testAuthorization(now time.Time, claims map[string]any) Authorization {
	return Authorization{
		OrganizationID: "org_00000000000000000000000000", ApplicationID: "app_00000000000000000000000000",
		EnvironmentID: "env_00000000000000000000000000", EnvironmentKind: "production",
		ApplicationUserID: "usr_00000000000000000000000000", InstallationID: "ins_00000000000000000000000000",
		InstallationPlatform: "ios", SessionGrantID: "sgr_00000000000000000000000000",
		PolicyRevisionID: "rev_00000000000000000000000000", IdentityProvider: "firebase",
		DPoPJKT: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TrustLevel: "device_verified",
		AttestationProvider: "app_attest", NormalizedClaims: claims,
		IdentityExpiresAt: now.Add(time.Hour), AttestedAt: now.Add(-time.Minute),
		AttestationExpiresAt: now.Add(time.Hour), AccessExpiresAt: now.Add(10 * time.Minute),
	}
}
