package attestation

import (
	"context"
	"errors"
	"testing"
)

func TestAppAttestEnvironmentAcceptanceAndAssertions(t *testing.T) {
	for _, policy := range []AppAttestEnvironment{AppAttestDevelopment, AppAttestProduction, AppAttestAny} {
		for _, actual := range []AppAttestEnvironment{AppAttestDevelopment, AppAttestProduction} {
			t.Run(string(policy)+"/"+string(actual), func(t *testing.T) {
				binding := appAttestTestBinding(1)
				fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: actual})
				store := newMemoryAppAttestKeyStore()
				verifier := mustTestAppAttestVerifier(t, store, fixture.root, policy)
				evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
				result, err := verifier.Verify(context.Background(), evidence, binding)
				if !policy.Allows(actual) {
					if !errors.Is(err, ErrInvalid) {
						t.Fatalf("disallowed attestation error = %v", err)
					}
					if _, exists := store.snapshot(fixture.keyID); exists {
						t.Fatal("disallowed attestation registered a key")
					}
					return
				}
				if err != nil || result.TrustLevel != "app_verified" ||
					result.NormalizedSignals["app_attest_environment"] != string(actual) {
					t.Fatalf("attestation did not preserve actual Apple environment: result=%#v err=%v", result, err)
				}
				stored, exists := store.snapshot(fixture.keyID)
				if !exists || stored.AttestationEnvironment != actual {
					t.Fatal("key did not persist its actual Apple environment")
				}
				assertionBinding := appAttestTestBinding(2)
				assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{})
				assertionEvidence := mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding)
				result, err = verifier.Verify(context.Background(), assertionEvidence, assertionBinding)
				if err != nil || result.TrustLevel != "app_verified" ||
					result.NormalizedSignals["app_attest_environment"] != string(actual) {
					t.Fatalf("assertion did not preserve actual Apple environment: result=%#v err=%v", result, err)
				}
			})
		}
	}
}

func TestAppAttestAnyPolicyNarrowingRechecksExistingKey(t *testing.T) {
	for _, actual := range []AppAttestEnvironment{AppAttestDevelopment, AppAttestProduction} {
		t.Run(string(actual), func(t *testing.T) {
			binding := appAttestTestBinding(1)
			fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: actual})
			store := newMemoryAppAttestKeyStore()
			anyEnvironment := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestAny)
			evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
			if _, err := anyEnvironment.Verify(context.Background(), evidence, binding); err != nil {
				t.Fatal(err)
			}
			assertionBinding := appAttestTestBinding(2)
			assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{})
			assertionEvidence := mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding)
			opposite := AppAttestProduction
			if actual == AppAttestProduction {
				opposite = AppAttestDevelopment
			}
			disallowed := mustTestAppAttestVerifier(t, store, fixture.root, opposite)
			if _, err := disallowed.Verify(context.Background(), assertionEvidence, assertionBinding); !errors.Is(err, ErrInvalid) {
				t.Fatalf("narrowed policy accepted old key: %v", err)
			}
			stored, _ := store.snapshot(fixture.keyID)
			if stored.Counter != 0 || stored.AttestationEnvironment != actual {
				t.Fatal("rejected assertion changed durable key state")
			}
			allowed := mustTestAppAttestVerifier(t, store, fixture.root, actual)
			if _, err := allowed.Verify(context.Background(), assertionEvidence, assertionBinding); err != nil {
				t.Fatalf("narrowing to the actual key environment rejected assertion: %v", err)
			}
		})
	}
}

func TestAppAttestAnyRejectsUnknownAAGUIDAndStoredPolicyValue(t *testing.T) {
	binding := appAttestTestBinding(1)
	unknown := [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'b', 'o', 't', 'h'}
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{aaguid: &unknown})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestAny)
	evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
	if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("any policy accepted unknown AAGUID: %v", err)
	}
	if _, exists := store.snapshot(fixture.keyID); exists {
		t.Fatal("unknown AAGUID persisted a key")
	}
	for _, invalidActual := range []AppAttestEnvironment{"", "unknown", "both", AppAttestAny} {
		if AppAttestAny.Allows(invalidActual) || AppAttestEnvironment("unknown").Allows(AppAttestProduction) ||
			AppAttestEnvironment("both").Allows(AppAttestProduction) {
			t.Fatal("unknown Apple environment accepted")
		}
	}

	fixture = mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	verifier = mustTestAppAttestVerifier(t, store, fixture.root, AppAttestAny)
	evidence = mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
	if _, err := verifier.Verify(context.Background(), evidence, binding); err != nil {
		t.Fatal(err)
	}
	stored, _ := store.snapshot(fixture.keyID)
	stored.AttestationEnvironment = AppAttestAny
	if err := validateAppAttestStoredKey(fixture.keyID, stored); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stored policy value accepted as actual environment: %v", err)
	}
}
