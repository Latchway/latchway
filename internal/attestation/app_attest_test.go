package attestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	appAttestTestAppIDPrefix = "ABCDE12345"
	appAttestTestBundleID    = "com.latchway.fixture"

	// Apple publishes this leaf/intermediate pair in its current App Attest
	// Attestation Object Validation Guide. Keeping the DER as Base64 makes the
	// compatibility gate deterministic without storing private evidence.
	appAttestOfficialLeafCertificateBase64         = "MIIEHTCCA6OgAwIBAgIGAZ2xPwtOMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MDQyMDE4MTMxMloXDTI2MDQyMzE4MTMxMlowgZExSTBHBgNVBAMMQGNlMDQ5OGY1ODQ4M2ZiYjRkYTBkN2IyYzYzYTVhNTM4ZjU1MmQ0YWRjYjlhNGZhOTE2MTk1YzQ5NjEzZTY1NWQxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQzJUSs8yPbd0RDyq8zn1bn6VxyT6wsFCWfNl4kRWULK1+yhbz1Sby2BZRBLnaCokJ+6tqftS3+0LGrF+0J+pvaOCAiYwggIiMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDB6BgkqhkiG92NkCAUEbTBrpAMCAQq/iTADAgEAv4kxAwIBAL+JMgMCAQC/iTMDAgEAv4k0HgQcMTIzNDU2Nzg5MC5jb20uZXhhbXBsZS5teWFwcL+JNgMCAQS/iTcDAgEAv4k5AwIBAL+JOgMCAQC/iTsDAgEAqgMCAQAwgeAGCSqGSIb3Y2QIBwSB0jCBz7+KeAYEBDI3LjC/iFADAgECv4p5CQQHMS4wLjIxNr+KewkEBzI0QTMyNWK/inwGBAQyNy4wv4p9BgQEMjcuML+KfgMCAQC/in8DAgEAv4sAAwIBAL+LAQMCAQC/iwIDAgEAv4sDAwIBAL+LBAMCAQG/iwUDAgEAv4sKEAQOMjQuMS4zMjUuMC4yLDC/iwsQBA4yNC4xLjMyNS4wLjIsML+LDBAEDjI0LjEuMzI1LjAuMiwwv4gCCgQIaXBob25lb3O/iAUKBAhJbnRlcm5hbDAzBgkqhkiG92NkCAIEJjAkoSIEIIe30G2TpClORvAR5mtsxADwurIHKZdsYZWAtCrmC/9uMFgGCSqGSIb3Y2QIBgRLMEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/MAoGCCqGSM49BAMCA2gAMGUCMCG8x2j20SnJtrGuCbw1sk1+NMs/VNm8sRcU4aPhyDNB3mMBdxy8gNza6r91g8v1HQIxAKTqMS+83kFdMob2rD3t9fnNWWLhA8RFOqw64XhXFTEWXqb1ddPoRcYCFlTEqULtPQ=="
	appAttestOfficialIntermediateCertificateBase64 = "MIICQzCCAcigAwIBAgIQCbrF4bxAGtnUU5W8OBoIVDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM5NTVaFw0zMDAzMTMwMDAwMDBaME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAErls3oHdNebI1j0Dn0fImJvHCX+8XgC3qs4JqWYdP+NKtFSV4mqJmBBkSSLY8uWcGnpjTY71eNw+/oI4ynoBzqYXndG6jWaL2bynbMq9FXiEWWNVnr54mfrJhTcIaZs6Zo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFKyREFMzvb5oQf+nDKnl+url5YqhMB0GA1UdDgQWBBQ+410cBBmpybQx+IR01uHhV3LjmzAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaQAwZgIxALu+iI1zjQUCz7z9Zm0JV1A1vNaHLD+EMEkmKe3R+RToeZkcmui1rvjTqFQz97YNBgIxAKs47dDMge0ApFLDukT5k2NlU/7MKX8utN+fXr5aSsq2mVxLgg35BDhveAe7WJQ5tw=="
	appAttestOfficialAttestationObjectBase64       = "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"
)

var appAttestTestNow = time.Date(2026, 8, 28, 6, 30, 0, 0, time.UTC)

type memoryAppAttestKeyStore struct {
	mu    sync.Mutex
	keys  map[[sha256.Size]byte]AppAttestStoredKey
	calls int
}

func newMemoryAppAttestKeyStore() *memoryAppAttestKeyStore {
	return &memoryAppAttestKeyStore{keys: make(map[[sha256.Size]byte]AppAttestStoredKey)}
}

func (store *memoryAppAttestKeyStore) TransactAppAttestKey(
	ctx context.Context,
	keyID [sha256.Size]byte,
	transact AppAttestKeyTransaction,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	current, exists := store.keys[keyID]
	next, err := transact(cloneAppAttestStoredKey(current), exists)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.keys[keyID] = cloneAppAttestStoredKey(next)
	return nil
}

func (store *memoryAppAttestKeyStore) snapshot(keyID [sha256.Size]byte) (AppAttestStoredKey, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key, exists := store.keys[keyID]
	return cloneAppAttestStoredKey(key), exists
}

func (store *memoryAppAttestKeyStore) replace(keyID [sha256.Size]byte, key AppAttestStoredKey) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.keys[keyID] = cloneAppAttestStoredKey(key)
}

func (store *memoryAppAttestKeyStore) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

type appAttestFixture struct {
	keyID           [sha256.Size]byte
	privateKey      *ecdsa.PrivateKey
	publicKeyX963   []byte
	attestation     []byte
	root            *x509.Certificate
	rootDER         []byte
	intermediateDER []byte
}

type appAttestFixtureOptions struct {
	environment        AppAttestEnvironment
	aaguid             *[16]byte
	rpIDHash           *[sha256.Size]byte
	counter            uint32
	credentialID       *[sha256.Size]byte
	coseKeyScalar      int64
	nonceOverride      *[sha256.Size]byte
	validationCategory uint32
	bundleVersion      string
	omitExtensions     bool
	flags              byte
	flagsSet           bool
	rootScalar         int64
	leafNotBefore      time.Time
	leafNotAfter       time.Time
}

type appAttestAssertionOptions struct {
	rpIDHash           *[sha256.Size]byte
	validationCategory uint32
	bundleVersion      string
	omitExtensions     bool
	flags              byte
	signingKey         *ecdsa.PrivateKey
}

func TestAppAttestVerifierRegistersKeyAndConsumesBoundAssertion(t *testing.T) {
	attestationBinding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)

	attestationEvidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding)
	attestationResult, err := verifier.Verify(context.Background(), attestationEvidence, attestationBinding)
	if err != nil {
		t.Fatalf("verify attestation: %v", err)
	}
	attestationHash, err := attestationBinding.Hash()
	if err != nil {
		t.Fatalf("hash attestation binding: %v", err)
	}
	if attestationResult.Provider != appAttestProvider || attestationResult.TrustLevel != "app_verified" ||
		!attestationResult.VerifiedAt.Equal(appAttestTestNow) ||
		!attestationResult.ExpiresAt.Equal(appAttestTestNow.Add(defaultAppAttestResultLifetime)) ||
		attestationResult.NormalizedSignals["evidence_type"] != "attestation" ||
		attestationResult.NormalizedSignals["app_attest_environment"] != "production" ||
		attestationResult.NormalizedSignals["app_attest_extensions_present"] != true ||
		attestationResult.NormalizedSignals["validation_category"] != int64(4) ||
		attestationResult.NormalizedSignals["bundle_version"] != "1.0" ||
		attestationResult.NormalizedSignals["assertion_counter"] != int64(0) {
		t.Fatalf("unexpected attestation result: %#v", attestationResult)
	}
	resultKeyID, ok := attestationResult.AppAttestKeyID()
	if !ok || resultKeyID != fixture.keyID {
		t.Fatalf("sealed App Attest key ID = %x valid=%v", resultKeyID, ok)
	}
	if _, public := attestationResult.NormalizedSignals["app_attest_key_id"]; public {
		t.Fatal("App Attest credential identifier escaped into normalized signals")
	}
	if formatted := fmt.Sprintf("%#v", attestationResult); formatted != "attestation.Result{[REDACTED]}" {
		t.Fatalf("App Attest result formatter = %q", formatted)
	}
	if attestationResult.EvidenceHash != appAttestEvidenceHash("attestation", fixture.keyID, fixture.attestation) {
		t.Fatal("attestation evidence hash did not bind the decoded object")
	}
	snapshot, err := attestationResult.ValidatedSnapshot(attestationHash, appAttestTestNow)
	if err != nil {
		t.Fatalf("validate sealed attestation result: %v", err)
	}
	if snapshotKeyID, valid := snapshot.AppAttestKeyID(); !valid || snapshotKeyID != fixture.keyID {
		t.Fatalf("snapshot App Attest key ID = %x valid=%v", snapshotKeyID, valid)
	}
	tamperedResult := attestationResult
	tamperedResult.appAttestKeyID[0] ^= 0xff
	if _, ok := tamperedResult.AppAttestKeyID(); ok {
		t.Fatal("tampered result exposed an App Attest key ID")
	}

	stored, exists := store.snapshot(fixture.keyID)
	if !exists || stored.Counter != 0 || !stored.ExtensionsPresent || !bytes.Equal(stored.PublicKeyX963, fixture.publicKeyX963) ||
		stored.ApplicationID != attestationBinding.ApplicationID || stored.EnvironmentID != attestationBinding.Environment ||
		stored.Platform != attestationBinding.Platform || stored.PrincipalID != attestationBinding.PrincipalID ||
		stored.DPoPJKT != attestationBinding.DPoPJKT {
		t.Fatalf("unexpected registered key: %#v exists=%v", stored, exists)
	}

	assertionBinding := appAttestTestBinding(2)
	assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 7, appAttestAssertionOptions{})
	assertionEvidence := mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding)
	assertionResult, err := verifier.Verify(context.Background(), assertionEvidence, assertionBinding)
	if err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	assertionHash, err := assertionBinding.Hash()
	if err != nil {
		t.Fatalf("hash assertion binding: %v", err)
	}
	if assertionResult.NormalizedSignals["evidence_type"] != "assertion" ||
		assertionResult.NormalizedSignals["assertion_counter"] != int64(7) ||
		assertionResult.EvidenceHash != appAttestEvidenceHash("assertion", fixture.keyID, assertion) {
		t.Fatalf("unexpected assertion result: %#v", assertionResult)
	}
	if _, err := assertionResult.ValidatedSnapshot(assertionHash, appAttestTestNow); err != nil {
		t.Fatalf("validate sealed assertion result: %v", err)
	}
	stored, exists = store.snapshot(fixture.keyID)
	wantRetryHash := appAttestAssertionReplayHash(fixture.keyID, assertion, assertionHash)
	if !exists || stored.Counter != 7 || stored.LastAssertionHash != wantRetryHash {
		t.Fatalf("assertion counter was not atomically stored: %#v exists=%v", stored, exists)
	}

	retriedResult, err := verifier.Verify(context.Background(), assertionEvidence, assertionBinding)
	if err != nil || retriedResult.EvidenceHash != assertionResult.EvidenceHash ||
		retriedResult.NormalizedSignals["assertion_counter"] != int64(7) {
		t.Fatalf("exact assertion retry result=%#v err=%v", retriedResult, err)
	}
	stored, _ = store.snapshot(fixture.keyID)
	if stored.Counter != 7 || stored.LastAssertionHash != wantRetryHash {
		t.Fatalf("exact retry changed durable state: %#v", stored)
	}

	// The retry exception is byte- and binding-exact. A newly signed assertion
	// with the same counter but a different challenge remains a replay.
	equalBinding := appAttestTestBinding(4)
	equalAssertion := mustAppAttestAssertion(t, fixture, equalBinding, 7, appAttestAssertionOptions{})
	if bytes.Equal(equalAssertion, assertion) {
		t.Fatal("different challenge produced identical assertion evidence")
	}
	if _, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "assertion_object", equalAssertion, equalBinding),
		equalBinding,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("different equal-counter assertion error = %v, want ErrInvalid", err)
	}
	lowerBinding := appAttestTestBinding(3)
	lowerAssertion := mustAppAttestAssertion(t, fixture, lowerBinding, 6, appAttestAssertionOptions{})
	if _, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "assertion_object", lowerAssertion, lowerBinding),
		lowerBinding,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("lower assertion counter error = %v, want ErrInvalid", err)
	}
	stored, _ = store.snapshot(fixture.keyID)
	if stored.Counter != 7 {
		t.Fatalf("lower assertion changed counter to %d", stored.Counter)
	}
}

func TestAppAttestVerifierAcceptsLegacyAuthenticatorDataWithoutExtensions(t *testing.T) {
	attestationBinding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{
		environment: AppAttestProduction, omitExtensions: true,
	})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	attestationResult, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding),
		attestationBinding,
	)
	if err != nil {
		t.Fatalf("verify legacy attestation: %v", err)
	}
	if attestationResult.NormalizedSignals["app_attest_extensions_present"] != false {
		t.Fatalf("legacy attestation did not record absent extensions: %#v", attestationResult.NormalizedSignals)
	}
	if _, exists := attestationResult.NormalizedSignals["validation_category"]; exists {
		t.Fatal("legacy attestation synthesized a validation category")
	}
	if _, exists := attestationResult.NormalizedSignals["bundle_version"]; exists {
		t.Fatal("legacy attestation synthesized a bundle version")
	}
	stored, exists := store.snapshot(fixture.keyID)
	if !exists || stored.ExtensionsPresent || stored.ValidationCategory != 0 || stored.BundleVersion != "" {
		t.Fatalf("legacy registration state = %#v exists=%v", stored, exists)
	}

	assertionBinding := appAttestTestBinding(2)
	assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{omitExtensions: true})
	assertionResult, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding),
		assertionBinding,
	)
	if err != nil {
		t.Fatalf("verify legacy assertion: %v", err)
	}
	if assertionResult.NormalizedSignals["app_attest_extensions_present"] != false {
		t.Fatalf("legacy assertion did not record absent extensions: %#v", assertionResult.NormalizedSignals)
	}
	stored, exists = store.snapshot(fixture.keyID)
	if !exists || stored.Counter != 1 || stored.ExtensionsPresent || stored.ValidationCategory != 0 || stored.BundleVersion != "" {
		t.Fatalf("legacy assertion state = %#v exists=%v", stored, exists)
	}
}

func TestAppAttestLegacyAssertionDoesNotReuseStoredExtensionSignals(t *testing.T) {
	attestationBinding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	if _, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding),
		attestationBinding,
	); err != nil {
		t.Fatalf("register current fixture: %v", err)
	}
	assertionBinding := appAttestTestBinding(2)
	assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{omitExtensions: true})
	result, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding),
		assertionBinding,
	)
	if err != nil {
		t.Fatalf("verify legacy assertion after current attestation: %v", err)
	}
	if result.NormalizedSignals["app_attest_extensions_present"] != false {
		t.Fatalf("legacy assertion reused stored extension presence: %#v", result.NormalizedSignals)
	}
	if _, exists := result.NormalizedSignals["validation_category"]; exists {
		t.Fatal("legacy assertion reused stored validation category")
	}
	stored, _ := store.snapshot(fixture.keyID)
	if stored.ExtensionsPresent || stored.ValidationCategory != 0 || stored.BundleVersion != "" {
		t.Fatalf("legacy assertion retained stale extension state: %#v", stored)
	}
}

func TestAppAttestGeneratedFixturesAreDeterministic(t *testing.T) {
	binding := appAttestTestBinding(1)
	first := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	second := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	if first.keyID != second.keyID || !bytes.Equal(first.publicKeyX963, second.publicKeyX963) ||
		!bytes.Equal(first.attestation, second.attestation) || !bytes.Equal(first.rootDER, second.rootDER) ||
		!bytes.Equal(first.intermediateDER, second.intermediateDER) {
		t.Fatal("generated attestation fixtures are not byte deterministic")
	}
	assertionBinding := appAttestTestBinding(2)
	firstAssertion := mustAppAttestAssertion(t, first, assertionBinding, 1, appAttestAssertionOptions{})
	secondAssertion := mustAppAttestAssertion(t, second, assertionBinding, 1, appAttestAssertionOptions{})
	if !bytes.Equal(firstAssertion, secondAssertion) {
		t.Fatal("generated assertion fixtures are not byte deterministic")
	}
}

func TestAppAttestVerifierRejectsWrongBindingScopeBeforeStorage(t *testing.T) {
	binding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "application", mutate: func(binding *Binding) { binding.ApplicationID = "app_other" }},
		{name: "environment", mutate: func(binding *Binding) { binding.Environment = "staging" }},
		{name: "platform", mutate: func(binding *Binding) { binding.Platform = "android" }},
		{name: "invalid canonical binding", mutate: func(binding *Binding) { binding.ChallengeNonce = "not-base64url" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newMemoryAppAttestKeyStore()
			verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
			wrong := binding
			test.mutate(&wrong)
			if _, err := verifier.Verify(context.Background(), evidence, wrong); !errors.Is(err, ErrInvalid) {
				t.Fatalf("scope error = %v, want ErrInvalid", err)
			}
			if store.callCount() != 0 {
				t.Fatal("binding scope failure reached the key store")
			}
		})
	}
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	var nilContext context.Context
	if _, err := verifier.Verify(nilContext, evidence, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil context error = %v, want ErrInvalid", err)
	}
	debugEvidence, err := NewEvidence("debug", map[string]any{"opaque": true})
	if err != nil {
		t.Fatalf("construct provider-mismatch evidence: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), debugEvidence, binding); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("provider mismatch error = %v, want ErrUnsupported", err)
	}
}

func TestAppAttestVerifierRejectsAttestationTampering(t *testing.T) {
	tests := []struct {
		name    string
		options appAttestFixtureOptions
		mutate  func(*testing.T, *appAttestFixture)
	}{
		{name: "wrong RP ID", options: appAttestFixtureOptions{rpIDHash: pointerToHash(sha256.Sum256([]byte("wrong-app-id")))}},
		{name: "nonzero counter", options: appAttestFixtureOptions{counter: 1}},
		{name: "wrong credential ID", options: appAttestFixtureOptions{credentialID: pointerToHash(sha256.Sum256([]byte("wrong-credential")))}},
		{name: "COSE key differs from certificate", options: appAttestFixtureOptions{coseKeyScalar: 91}},
		{name: "key identifier differs from public key", mutate: func(_ *testing.T, fixture *appAttestFixture) {
			fixture.keyID = sha256.Sum256([]byte("wrong-client-key-id"))
		}},
		{name: "wrong AAGUID", options: appAttestFixtureOptions{aaguid: pointerToAAGUID([16]byte{'n', 'o', 't', '-', 'a', 'p', 'p', '-', 'a', 't', 't', 'e', 's', 't'})}},
		{name: "disallowed validation category", options: appAttestFixtureOptions{validationCategory: 3}},
		{name: "disallowed bundle version", options: appAttestFixtureOptions{bundleVersion: "2.0"}},
		{name: "user-presence flag", options: appAttestFixtureOptions{flags: 0x41}},
		{name: "extension-data flag", options: appAttestFixtureOptions{flags: 0xc0}},
		{name: "reserved flag", options: appAttestFixtureOptions{flags: 0x42}},
		{name: "backup flag", options: appAttestFixtureOptions{flags: 0x50}},
		{name: "missing attested-data flag", options: appAttestFixtureOptions{flagsSet: true}},
		{name: "nonce mismatch", options: appAttestFixtureOptions{nonceOverride: pointerToHash(sha256.Sum256([]byte("wrong-nonce")))}},
		{name: "expired leaf", options: appAttestFixtureOptions{leafNotBefore: appAttestTestNow.Add(-2 * time.Hour), leafNotAfter: appAttestTestNow.Add(-time.Hour)}},
		{name: "format", mutate: func(t *testing.T, fixture *appAttestFixture) {
			fixture.attestation = rewriteAppAttestation(t, fixture.attestation, func(wire *appAttestationObjectWire) { wire.Format = "packed" })
		}},
		{name: "empty receipt", mutate: func(t *testing.T, fixture *appAttestFixture) {
			fixture.attestation = rewriteAppAttestation(t, fixture.attestation, func(wire *appAttestationObjectWire) { wire.Statement.Receipt = nil })
		}},
		{name: "duplicate certificate", mutate: func(t *testing.T, fixture *appAttestFixture) {
			fixture.attestation = rewriteAppAttestation(t, fixture.attestation, func(wire *appAttestationObjectWire) {
				wire.Statement.Certificates = append(wire.Statement.Certificates, append([]byte(nil), wire.Statement.Certificates[1]...))
			})
		}},
		{name: "reversed certificate order", mutate: func(t *testing.T, fixture *appAttestFixture) {
			fixture.attestation = rewriteAppAttestation(t, fixture.attestation, func(wire *appAttestationObjectWire) {
				wire.Statement.Certificates[0], wire.Statement.Certificates[1] = wire.Statement.Certificates[1], wire.Statement.Certificates[0]
			})
		}},
		{name: "client supplied root", mutate: func(t *testing.T, fixture *appAttestFixture) {
			fixture.attestation = rewriteAppAttestation(t, fixture.attestation, func(wire *appAttestationObjectWire) {
				wire.Statement.Certificates = append(wire.Statement.Certificates, append([]byte(nil), fixture.rootDER...))
			})
		}},
		{name: "certificate corruption", mutate: func(t *testing.T, fixture *appAttestFixture) {
			fixture.attestation = rewriteAppAttestation(t, fixture.attestation, func(wire *appAttestationObjectWire) {
				wire.Statement.Certificates[0][len(wire.Statement.Certificates[0])-1] ^= 0x01
			})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := appAttestTestBinding(1)
			options := test.options
			options.environment = AppAttestProduction
			fixture := mustAppAttestFixture(t, binding, options)
			if test.mutate != nil {
				test.mutate(t, &fixture)
			}
			store := newMemoryAppAttestKeyStore()
			verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
			evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
			if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
				t.Fatalf("tampered attestation error = %v, want ErrInvalid", err)
			}
			if _, exists := store.snapshot(fixture.keyID); exists {
				t.Fatal("invalid attestation registered a key")
			}
		})
	}
}

func TestAppAttestVerifierRejectsAssertionTamperingAndScopeChanges(t *testing.T) {
	tests := []struct {
		name                 string
		counter              uint32
		options              appAttestAssertionOptions
		buildBinding         func() Binding
		verificationBind     func(Binding) Binding
		mutate               func([]byte) []byte
		unknownKey           bool
		corruptStore         bool
		corruptPlatform      bool
		registrationPlatform string
		wantStoreError       bool
	}{
		{name: "zero counter", counter: 0},
		{name: "equal counter", counter: 0},
		{name: "wrong RP ID", counter: 1, options: appAttestAssertionOptions{rpIDHash: pointerToHash(sha256.Sum256([]byte("wrong-rp")))}},
		{name: "disallowed category", counter: 1, options: appAttestAssertionOptions{validationCategory: 3}},
		{name: "disallowed bundle", counter: 1, options: appAttestAssertionOptions{bundleVersion: "2.0"}},
		{name: "reserved flag", counter: 1, options: appAttestAssertionOptions{flags: 0x02}},
		{name: "backup flag", counter: 1, options: appAttestAssertionOptions{flags: 0x10}},
		{name: "attested-data flag", counter: 1, options: appAttestAssertionOptions{flags: 0x40}},
		{name: "extension-data flag", counter: 1, options: appAttestAssertionOptions{flags: 0x80}},
		{name: "user-presence flag", counter: 1, options: appAttestAssertionOptions{flags: 0x01}},
		{name: "bad signature", counter: 1, mutate: func(encoded []byte) []byte {
			return rewriteAppAssertion(t, encoded, func(wire *appAttestAssertionWire) { wire.Signature[len(wire.Signature)-1] ^= 0x01 })
		}},
		{name: "wrong authoritative binding", counter: 1, verificationBind: func(binding Binding) Binding {
			binding.ChallengeNonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xf1}, sha256.Size))
			return binding
		}},
		{name: "principal association", counter: 1, buildBinding: func() Binding {
			binding := appAttestTestBinding(2)
			binding.PrincipalID = "usr_01J00000000000000000000001"
			return binding
		}},
		{name: "DPoP association", counter: 1, buildBinding: func() Binding {
			binding := appAttestTestBinding(2)
			binding.DPoPJKT = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa7}, sha256.Size))
			return binding
		}},
		{name: "native to React Native association", counter: 1, buildBinding: func() Binding {
			binding := appAttestTestBinding(2)
			binding.Platform = "react_native_ios"
			return binding
		}},
		{name: "React Native to native association", counter: 1, registrationPlatform: "react_native_ios"},
		{name: "unregistered key", counter: 1, unknownKey: true},
		{name: "corrupt stored public key", counter: 1, corruptStore: true, wantStoreError: true},
		{name: "corrupt stored platform", counter: 1, corruptPlatform: true, wantStoreError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attestationBinding := appAttestTestBinding(1)
			if test.registrationPlatform != "" {
				attestationBinding.Platform = test.registrationPlatform
			}
			fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
			store := newMemoryAppAttestKeyStore()
			verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
			registerEvidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding)
			if _, err := verifier.Verify(context.Background(), registerEvidence, attestationBinding); err != nil {
				t.Fatalf("register fixture key: %v", err)
			}

			assertionBinding := appAttestTestBinding(2)
			if test.buildBinding != nil {
				assertionBinding = test.buildBinding()
			}
			assertion := mustAppAttestAssertion(t, fixture, assertionBinding, test.counter, test.options)
			if test.mutate != nil {
				assertion = test.mutate(assertion)
			}
			verificationBinding := assertionBinding
			if test.verificationBind != nil {
				verificationBinding = test.verificationBind(verificationBinding)
			}
			keyID := fixture.keyID
			if test.unknownKey {
				keyID = sha256.Sum256([]byte("unregistered-app-attest-key"))
			}
			if test.corruptStore {
				stored, _ := store.snapshot(fixture.keyID)
				stored.PublicKeyX963[1] ^= 0xff
				store.replace(fixture.keyID, stored)
			}
			if test.corruptPlatform {
				stored, _ := store.snapshot(fixture.keyID)
				stored.Platform = "android"
				store.replace(fixture.keyID, stored)
			}
			evidence := mustAppAttestEvidence(t, keyID, "assertion_object", assertion, verificationBinding)
			_, err := verifier.Verify(context.Background(), evidence, verificationBinding)
			if test.wantStoreError {
				if !errors.Is(err, ErrAppAttestKeyStore) {
					t.Fatalf("assertion error = %v, want ErrAppAttestKeyStore", err)
				}
			} else if !errors.Is(err, ErrInvalid) {
				t.Fatalf("assertion error = %v, want ErrInvalid", err)
			}
			stored, _ := store.snapshot(fixture.keyID)
			if stored.Counter != 0 {
				t.Fatalf("invalid assertion changed counter to %d", stored.Counter)
			}
		})
	}
}

func TestAppAttestVerifierDevelopmentAndProductionEnvironmentsAreIsolated(t *testing.T) {
	developmentAAGUIDs := [][16]byte{
		{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'},
		{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 's', 'a', 'n', 'd', 'b', 'o', 'x'},
	}
	for _, aaguid := range developmentAAGUIDs {
		name := strings.TrimRight(string(aaguid[:]), "\x00")
		t.Run(name, func(t *testing.T) {
			binding := appAttestTestBinding(1)
			fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{
				environment: AppAttestDevelopment, aaguid: &aaguid, validationCategory: 3,
			})
			store := newMemoryAppAttestKeyStore()
			verifier := mustTestAppAttestVerifierWithPolicy(t, store, fixture.root, AppAttestDevelopment, []uint32{3}, []string{"1.0"})
			evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
			if _, err := verifier.Verify(context.Background(), evidence, binding); err != nil {
				t.Fatalf("development AAGUID %q rejected: %v", name, err)
			}
		})
	}

	for _, test := range []struct {
		name                string
		fixtureEnvironment  AppAttestEnvironment
		verifierEnvironment AppAttestEnvironment
	}{
		{name: "development key in production", fixtureEnvironment: AppAttestDevelopment, verifierEnvironment: AppAttestProduction},
		{name: "production key in development", fixtureEnvironment: AppAttestProduction, verifierEnvironment: AppAttestDevelopment},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := appAttestTestBinding(1)
			fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: test.fixtureEnvironment})
			store := newMemoryAppAttestKeyStore()
			verifier := mustTestAppAttestVerifier(t, store, fixture.root, test.verifierEnvironment)
			evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
			if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
				t.Fatalf("cross-environment attestation error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAppAttestCertificateChecksAcceptOfficialAppleValidationFixture(t *testing.T) {
	leafDER, err := base64.StdEncoding.DecodeString(appAttestOfficialLeafCertificateBase64)
	if err != nil {
		t.Fatalf("decode official Apple leaf: %v", err)
	}
	intermediateDER, err := base64.StdEncoding.DecodeString(appAttestOfficialIntermediateCertificateBase64)
	if err != nil {
		t.Fatalf("decode official Apple intermediate: %v", err)
	}
	roots, err := appleAppAttestationRoots()
	if err != nil {
		t.Fatalf("construct Apple App Attestation roots: %v", err)
	}
	leaf, err := verifyAppAttestCertificateChain(
		[][]byte{leafDER, intermediateDER}, roots,
		time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("official Apple leaf/intermediate path rejected: %v", err)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!bytes.Equal(leaf.Raw, leafDER) {
		t.Fatalf("unexpected official Apple credential certificate properties: constraints=%v isCA=%v usage=%#x", leaf.BasicConstraintsValid, leaf.IsCA, leaf.KeyUsage)
	}
}

func TestAppAttestParserMatchesOfficialAppleAttestationObject(t *testing.T) {
	encoded, err := base64.StdEncoding.DecodeString(appAttestOfficialAttestationObjectBase64)
	if err != nil {
		t.Fatalf("decode official Apple attestation object: %v", err)
	}
	parsed, err := parseAppAttestationObject(encoded)
	if err != nil {
		t.Fatalf("parse official Apple attestation object: %v", err)
	}
	if len(parsed.certificates) != 2 {
		t.Fatalf("official x5c length = %d, want leaf plus intermediate", len(parsed.certificates))
	}
	expectedRPIDHash := sha256.Sum256([]byte("1234567890.com.example.myapp"))
	if parsed.authenticator.rpIDHash != expectedRPIDHash {
		t.Fatalf("official RP ID hash = %x, want %x", parsed.authenticator.rpIDHash, expectedRPIDHash)
	}
	if parsed.authenticatorData[32] != appAttestFlagAttestedData || parsed.authenticator.counter != 0 ||
		!appAttestAAGUIDMatches(parsed.authenticator.aaguid, AppAttestProduction) {
		t.Fatalf("official authenticator flags=%#x counter=%d aaguid=%x", parsed.authenticatorData[32], parsed.authenticator.counter, parsed.authenticator.aaguid)
	}
	expectedKeyIDBytes, err := base64.StdEncoding.DecodeString("zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=")
	if err != nil || len(expectedKeyIDBytes) != sha256.Size {
		t.Fatalf("decode official key ID: bytes=%d err=%v", len(expectedKeyIDBytes), err)
	}
	var expectedKeyID [sha256.Size]byte
	copy(expectedKeyID[:], expectedKeyIDBytes)
	if parsed.authenticator.credentialID != expectedKeyID ||
		sha256.Sum256(parsed.authenticator.publicKeyX963) != expectedKeyID {
		t.Fatalf("official credential/public key did not match key ID")
	}
	// Apple's object encodes CFBundleVersion as "1" even though the prose below
	// the vector currently describes the expected value as "1.0". Assert the
	// signed CBOR bytes rather than silently rewriting the provider evidence.
	if !parsed.authenticator.extensions.present || parsed.authenticator.extensions.validationCategory != 1 ||
		parsed.authenticator.extensions.bundleVersion != "1" {
		t.Fatalf("official extensions = %#v", parsed.authenticator.extensions)
	}

	authenticatorData := parsed.authenticatorData
	offset := appAttestAuthenticatorHeaderBytes + 16
	credentialLength := int(binary.BigEndian.Uint16(authenticatorData[offset : offset+2]))
	offset += 2 + credentialLength
	var cose appAttestCOSEKeyWire
	extensionBytes, err := appAttestCBORMode.UnmarshalFirst(authenticatorData[offset:], &cose)
	if err != nil {
		t.Fatalf("locate official extension dictionary: %v", err)
	}
	var extensionWire appAttestExtensionsWire
	if err := appAttestCBORMode.Unmarshal(extensionBytes, &extensionWire); err != nil ||
		extensionWire.ValidationCategory == nil ||
		!bytes.Equal(*extensionWire.ValidationCategory, []byte{0x01, 0x00, 0x00, 0x00}) {
		t.Fatalf("official validation category is not a four-byte little-endian CBOR byte string: value=%v err=%v", extensionWire.ValidationCategory, err)
	}

	leaf, err := x509.ParseCertificate(parsed.certificates[0])
	if err != nil {
		t.Fatalf("parse official credential certificate: %v", err)
	}
	leafPublicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("official credential certificate key type = %T", leaf.PublicKey)
	}
	leafPublicKeyX963, err := leafPublicKey.Bytes()
	if err != nil || len(leafPublicKeyX963) != 65 || leafPublicKeyX963[0] != 4 {
		t.Fatalf("encode official credential certificate key: bytes=%d err=%v", len(leafPublicKeyX963), err)
	}
	if !bytes.Equal(leafPublicKeyX963, parsed.authenticator.publicKeyX963) ||
		sha256.Sum256(leafPublicKeyX963) != expectedKeyID {
		t.Fatal("official leaf and COSE public keys did not hash to the key ID")
	}
	nonceInput := append(append([]byte(nil), parsed.authenticatorData...), []byte("example_server_challenge")...)
	expectedNonce := sha256.Sum256(nonceInput)
	publishedNonce, err := base64.StdEncoding.DecodeString("h7fQbZOkKU5G8BHma2zEAPC6sgcpl2xhlYC0KuYL/24=")
	if err != nil || !bytes.Equal(expectedNonce[:], publishedNonce) {
		t.Fatalf("official guide nonce input mismatch: nonce=%x published=%x err=%v", expectedNonce, publishedNonce, err)
	}
	certificateNonce, err := appAttestCertificateNonce(leaf)
	if err != nil || !bytes.Equal(certificateNonce, expectedNonce[:]) {
		t.Fatalf("official certificate nonce=%x expected=%x err=%v", certificateNonce, expectedNonce, err)
	}
}

func TestAppAttestCertificateTrustIsPinnedAndRejectsClientRoots(t *testing.T) {
	block, rest := pem.Decode([]byte(appleAppAttestationRootCAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("embedded Apple App Attestation root is not one canonical PEM block")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse embedded Apple root: %v", err)
	}
	if root.Subject.CommonName != "Apple App Attestation Root CA" || !root.IsCA ||
		!root.NotBefore.Equal(time.Date(2020, 3, 18, 18, 32, 53, 0, time.UTC)) ||
		!root.NotAfter.Equal(time.Date(2045, 3, 15, 0, 0, 0, 0, time.UTC)) || root.CheckSignatureFrom(root) != nil {
		t.Fatalf("unexpected embedded Apple root: subject=%q notBefore=%s notAfter=%s", root.Subject.CommonName, root.NotBefore, root.NotAfter)
	}

	binding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	config := appAttestTestConfig(store, AppAttestProduction, []uint32{4}, []string{"1.0"})
	verifier, err := NewAppAttestVerifier(config)
	if err != nil {
		t.Fatalf("construct verifier with pinned Apple root: %v", err)
	}
	evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
	if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("locally rooted chain error = %v, want ErrInvalid", err)
	}
	if _, exists := store.snapshot(fixture.keyID); exists {
		t.Fatal("client-controlled trust root registered a key")
	}
}

func TestAppAttestEvidenceMatchesSwiftSDKEncoding(t *testing.T) {
	bindingHash, err := appAttestTestBinding(1).Hash()
	if err != nil {
		t.Fatalf("hash authoritative binding: %v", err)
	}
	var keyID [sha256.Size]byte
	copy(keyID[:], bytes.Repeat([]byte{0xfb}, sha256.Size))
	object := []byte{0xfb, 0xff, 0xef, 0x00}
	keyIDText := base64.StdEncoding.EncodeToString(keyID[:])
	objectText := base64.RawURLEncoding.EncodeToString(object)
	clientDataHashText := base64.RawURLEncoding.EncodeToString(bindingHash[:])
	if !strings.ContainsAny(keyIDText, "+/") || strings.ContainsAny(objectText, "+/=") {
		t.Fatal("test vector does not distinguish Apple key ID from SDK binary encoding")
	}
	decodedKeyID, decodedObject, kind, err := decodeAppAttestEvidence(map[string]any{
		"key_id": keyIDText, "client_data_hash": clientDataHashText, "assertion_object": objectText,
	}, bindingHash)
	if err != nil || decodedKeyID != keyID || !bytes.Equal(decodedObject, object) || kind != "assertion" {
		t.Fatalf("decode Swift SDK evidence: key=%x object=%x kind=%q err=%v", decodedKeyID, decodedObject, kind, err)
	}
}

func TestAppAttestVerifierRejectsAmbiguousCBORAndEvidenceLimits(t *testing.T) {
	binding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})

	duplicateFormat := []byte{0xa2}
	duplicateFormat = append(duplicateFormat, mustTestCBOR(t, "fmt")...)
	duplicateFormat = append(duplicateFormat, mustTestCBOR(t, "apple-appattest")...)
	duplicateFormat = append(duplicateFormat, mustTestCBOR(t, "fmt")...)
	duplicateFormat = append(duplicateFormat, mustTestCBOR(t, "apple-appattest")...)

	unknownTop := map[string]any{
		"fmt": "apple-appattest", "attStmt": map[string]any{"x5c": [][]byte{{1}, {2}}, "receipt": []byte{1}},
		"authData": []byte{1}, "unexpected": true,
	}
	attestationCases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "malformed", data: []byte{0xff}},
		{name: "indefinite map", data: []byte{0xbf, 0xff}},
		{name: "duplicate map key", data: duplicateFormat},
		{name: "unknown field", data: mustTestCBOR(t, unknownTop)},
		{name: "trailing item", data: append(append([]byte(nil), fixture.attestation...), 0x00)},
		{name: "oversize", data: make([]byte, maxAppAttestAttestationBytes+1)},
	}
	for _, test := range attestationCases {
		t.Run("attestation "+test.name, func(t *testing.T) {
			if _, err := parseAppAttestationObject(test.data); !errors.Is(err, ErrInvalid) {
				t.Fatalf("parse error = %v, want ErrInvalid", err)
			}
		})
	}

	assertion := mustAppAttestAssertion(t, fixture, appAttestTestBinding(2), 1, appAttestAssertionOptions{})
	duplicateSignature := []byte{0xa2}
	duplicateSignature = append(duplicateSignature, mustTestCBOR(t, "signature")...)
	duplicateSignature = append(duplicateSignature, mustTestCBOR(t, []byte{1})...)
	duplicateSignature = append(duplicateSignature, mustTestCBOR(t, "signature")...)
	duplicateSignature = append(duplicateSignature, mustTestCBOR(t, []byte{2})...)
	assertionCases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "malformed", data: []byte{0xff}},
		{name: "indefinite map", data: []byte{0xbf, 0xff}},
		{name: "duplicate map key", data: duplicateSignature},
		{name: "unknown field", data: mustTestCBOR(t, map[string]any{
			"signature": []byte{1, 2, 3, 4, 5, 6, 7, 8}, "authenticatorData": bytes.Repeat([]byte{1}, 38), "extra": true,
		})},
		{name: "trailing item", data: append(append([]byte(nil), assertion...), 0x00)},
		{name: "oversize", data: make([]byte, maxAppAttestAssertionBytes+1)},
	}
	for _, test := range assertionCases {
		t.Run("assertion "+test.name, func(t *testing.T) {
			if _, err := parseAppAttestAssertionObject(test.data); !errors.Is(err, ErrInvalid) {
				t.Fatalf("parse error = %v, want ErrInvalid", err)
			}
		})
	}

	duplicateExtension := []byte{0xa3}
	duplicateExtension = append(duplicateExtension, mustTestCBOR(t, "apple_validation_category_01")...)
	duplicateExtension = append(duplicateExtension, mustTestCBOR(t, appAttestTestCategory(4))...)
	duplicateExtension = append(duplicateExtension, mustTestCBOR(t, "apple_validation_category_01")...)
	duplicateExtension = append(duplicateExtension, mustTestCBOR(t, appAttestTestCategory(4))...)
	duplicateExtension = append(duplicateExtension, mustTestCBOR(t, "apple_bundle_version_01")...)
	duplicateExtension = append(duplicateExtension, mustTestCBOR(t, "1.0")...)
	if _, err := decodeAppAttestExtensions(duplicateExtension); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate extension error = %v, want ErrInvalid", err)
	}
	extensionCases := []map[string]any{
		{"apple_validation_category_01": appAttestTestCategory(4)},
		{"apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": uint32(4), "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": []byte{}, "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": []byte{4, 0, 0}, "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": []byte{4, 0, 0, 0, 0}, "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": []byte{0, 0, 0, 4}, "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": appAttestTestCategory(0), "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": appAttestTestCategory(7), "apple_bundle_version_01": "1.0"},
		{"apple_validation_category_01": appAttestTestCategory(4), "apple_bundle_version_01": "../1"},
		{"apple_validation_category_01": appAttestTestCategory(4), "apple_bundle_version_01": "1.0", "unknown": true},
	}
	for index, extension := range extensionCases {
		if _, err := decodeAppAttestExtensions(mustTestCBOR(t, extension)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("extension case %d error = %v, want ErrInvalid", index, err)
		}
	}

	validKeyID := base64.StdEncoding.EncodeToString(fixture.keyID[:])
	expectedClientDataHash, err := binding.Hash()
	if err != nil {
		t.Fatalf("hash evidence binding: %v", err)
	}
	validClientDataHash := base64.RawURLEncoding.EncodeToString(expectedClientDataHash[:])
	validObject := base64.RawURLEncoding.EncodeToString([]byte{0})
	evidenceCases := []map[string]any{
		nil,
		{"key_id": validKeyID},
		{"key_id": true, "client_data_hash": validClientDataHash, "attestation_object": validObject},
		{"key_id": validKeyID, "client_data_hash": true, "attestation_object": validObject},
		{"key_id": validKeyID, "client_data_hash": validClientDataHash, "attestation_object": true},
		{"key_id": validKeyID, "client_data_hash": validClientDataHash, "attestation_object": validObject, "extra": true},
		{"key_id": validKeyID, "client_data_hash": validClientDataHash, "attestation_object": validObject, "assertion_object": validObject},
		{"key_id": base64.RawStdEncoding.EncodeToString(fixture.keyID[:]), "client_data_hash": validClientDataHash, "attestation_object": validObject},
		{"key_id": base64.RawURLEncoding.EncodeToString(fixture.keyID[:]), "client_data_hash": validClientDataHash, "attestation_object": validObject},
		{"key_id": validKeyID, "attestation_object": validObject, "client_data_hash": base64.StdEncoding.EncodeToString(expectedClientDataHash[:])},
		{"key_id": validKeyID, "attestation_object": validObject, "client_data_hash": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, sha256.Size))},
		{"key_id": validKeyID, "attestation_object": base64.StdEncoding.EncodeToString([]byte{0}), "client_data_hash": validClientDataHash},
		{"key_id": validKeyID, "attestation_object": strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maxAppAttestAttestationBytes)+4), "client_data_hash": validClientDataHash},
	}
	for index, payload := range evidenceCases {
		if _, _, _, err := decodeAppAttestEvidence(payload, expectedClientDataHash); !errors.Is(err, ErrInvalid) {
			t.Fatalf("evidence case %d error = %v, want ErrInvalid", index, err)
		}
	}
}

func TestAppAttestNonceExtensionRequiresOneExactDEROctetString(t *testing.T) {
	expected := sha256.Sum256([]byte("exact-certificate-nonce"))
	valid := appAttestTestNonceExtension(expected)
	certificate := &x509.Certificate{Extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: valid}}}
	nonce, err := appAttestCertificateNonce(certificate)
	if err != nil || !bytes.Equal(nonce, expected[:]) {
		t.Fatalf("parse valid nonce extension: nonce=%x err=%v", nonce, err)
	}

	tests := []struct {
		name       string
		extensions []pkix.Extension
	}{
		{name: "missing"},
		{name: "duplicate", extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: valid}, {Id: appAttestNonceOID, Value: valid}}},
		{name: "wrong outer tag", extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: append([]byte{0x31}, valid[1:]...)}}},
		{name: "wrong explicit tag", extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: append([]byte{0x30, 0x24, 0xa2}, valid[3:]...)}}},
		{name: "trailing DER", extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: append(append([]byte(nil), valid...), 0x00)}}},
		{name: "short nonce", extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: []byte{0x30, 0x05, 0xa1, 0x03, 0x04, 0x01, 0x01}}}},
		{name: "oversize", extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: make([]byte, 129)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := appAttestCertificateNonce(&x509.Certificate{Extensions: test.extensions}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("nonce error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAppAttestKeyRegistrationExactRetryIsIdempotentAndStoreErrorsAreRedacted(t *testing.T) {
	binding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
	if _, err := verifier.Verify(context.Background(), evidence, binding); err != nil {
		t.Fatalf("register key: %v", err)
	}
	first, exists := store.snapshot(fixture.keyID)
	if !exists {
		t.Fatal("first registration did not persist")
	}
	verifier.now = func() time.Time { return appAttestTestNow.Add(time.Minute) }
	retried, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("retry exact registration: %v", err)
	}
	second, exists := store.snapshot(fixture.keyID)
	if !exists || !second.AttestedAt.Equal(first.AttestedAt) || second.Counter != 0 ||
		retried.NormalizedSignals["assertion_counter"] != int64(0) {
		t.Fatalf("idempotent registration changed state: first=%#v second=%#v result=%#v",
			first, second, retried)
	}
	if store.callCount() != 2 {
		t.Fatalf("transaction calls = %d, want 2", store.callCount())
	}

	// An existing key with any different valid scope is not an idempotent
	// registration and must remain unusable for this challenge.
	otherScope := cloneAppAttestStoredKey(second)
	otherJKT := sha256.Sum256([]byte("different valid DPoP binding"))
	otherScope.DPoPJKT = base64.RawURLEncoding.EncodeToString(otherJKT[:])
	store.replace(fixture.keyID, otherScope)
	if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("different-scope registration error = %v, want ErrInvalid", err)
	}

	secret := "postgres://operator:password@private/key-row"
	failing := appAttestFailingStore{err: errors.New(secret)}
	verifier = mustTestAppAttestVerifier(t, failing, fixture.root, AppAttestProduction)
	_, err = verifier.Verify(context.Background(), evidence, binding)
	if !errors.Is(err, ErrAppAttestKeyStore) || strings.Contains(err.Error(), secret) {
		t.Fatalf("store error was not normalized safely: %v", err)
	}
	stored := AppAttestStoredKey{PublicKeyX963: bytes.Repeat([]byte{0xab}, 65), PrincipalID: "usr_secret"}
	for _, value := range []any{stored, &stored} {
		for _, formatted := range []string{
			fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value),
			fmt.Sprintf("%s", value), fmt.Sprintf("%q", value), fmt.Sprintf("%+x", value), fmt.Sprintf("%d", value),
		} {
			if formatted != "[REDACTED]" {
				t.Fatalf("stored key formatter = %q", formatted)
			}
		}
	}
	var structured bytes.Buffer
	slog.New(slog.NewJSONHandler(&structured, nil)).Info(
		"App Attest state", "value", stored, "pointer", &stored,
	)
	if !strings.Contains(structured.String(), "[REDACTED]") ||
		strings.Contains(structured.String(), "usr_secret") || strings.Contains(structured.String(), "PublicKeyX963") {
		t.Fatalf("structured log exposed stored key state: %s", structured.String())
	}
	if strings.Contains(fmt.Sprint(evidence), "attestation_object") || strings.Contains(fmt.Sprintf("%#v", evidence), validObjectPrefix(fixture.attestation)) {
		t.Fatal("evidence formatting exposed provider data")
	}
}

func TestAppAttestAssertionCounterTransactionAcceptsOnlyExactConcurrentRetry(t *testing.T) {
	attestationBinding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	if _, err := verifier.Verify(context.Background(), mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding), attestationBinding); err != nil {
		t.Fatalf("register key: %v", err)
	}
	assertionBinding := appAttestTestBinding(2)
	assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{})
	evidence := mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding)

	const workers = 32
	start := make(chan struct{})
	var successes atomic.Int32
	var invalids atomic.Int32
	var unexpected atomic.Int32
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := verifier.Verify(context.Background(), evidence, assertionBinding)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrInvalid):
				invalids.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != workers || invalids.Load() != 0 || unexpected.Load() != 0 {
		t.Fatalf("success=%d invalid=%d unexpected=%d", successes.Load(), invalids.Load(), unexpected.Load())
	}
	stored, _ := store.snapshot(fixture.keyID)
	if stored.Counter != 1 {
		t.Fatalf("concurrent replay stored counter = %d, want 1", stored.Counter)
	}
}

func TestAppAttestVerifierCancellationDoesNotAdvanceCounter(t *testing.T) {
	attestationBinding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	if _, err := verifier.Verify(context.Background(), mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding), attestationBinding); err != nil {
		t.Fatalf("register key: %v", err)
	}
	assertionBinding := appAttestTestBinding(2)
	assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{})
	evidence := mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := store.callCount()
	if _, err := verifier.Verify(ctx, evidence, assertionBinding); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled verification error = %v, want context.Canceled", err)
	}
	if store.callCount() != before {
		t.Fatal("pre-canceled verification reached the key store")
	}

	ctx, cancel = context.WithCancel(context.Background())
	verifier.store = &appAttestCancelAfterCallbackStore{base: store, cancel: cancel}
	if _, err := verifier.Verify(ctx, evidence, assertionBinding); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-callback cancellation error = %v, want context.Canceled", err)
	}
	stored, _ := store.snapshot(fixture.keyID)
	if stored.Counter != 0 {
		t.Fatalf("canceled transaction advanced counter to %d", stored.Counter)
	}
}

func TestAppAttestVerifierCancellationBeforeRegistrationCommitRollsBack(t *testing.T) {
	binding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	base := newMemoryAppAttestKeyStore()
	ctx, cancel := context.WithCancel(context.Background())
	verifier := mustTestAppAttestVerifier(
		t, &appAttestCancelAfterCallbackStore{base: base, cancel: cancel}, fixture.root, AppAttestProduction,
	)
	_, err := verifier.Verify(
		ctx,
		mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding),
		binding,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("precommit registration cancellation error = %v, want context.Canceled", err)
	}
	if _, exists := base.snapshot(fixture.keyID); exists {
		t.Fatal("precommit registration cancellation persisted the key")
	}
}

func TestAppAttestVerifierReturnsSealedSuccessAfterStoreCommitDespiteCancellation(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		binding := appAttestTestBinding(1)
		fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
		base := newMemoryAppAttestKeyStore()
		ctx, cancel := context.WithCancel(context.Background())
		verifier := mustTestAppAttestVerifier(
			t, &appAttestCommitThenCancelStore{base: base, cancel: cancel}, fixture.root, AppAttestProduction,
		)
		result, err := verifier.Verify(
			ctx,
			mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding),
			binding,
		)
		if err != nil {
			t.Fatalf("committed registration returned error: %v", err)
		}
		bindingHash, err := binding.Hash()
		if err != nil {
			t.Fatalf("hash binding: %v", err)
		}
		if _, err := result.ValidatedSnapshot(bindingHash, appAttestTestNow); err != nil {
			t.Fatalf("committed registration result is not sealed: %v", err)
		}
		if _, exists := base.snapshot(fixture.keyID); !exists {
			t.Fatal("successful registration did not remain committed")
		}
	})

	t.Run("assertion", func(t *testing.T) {
		attestationBinding := appAttestTestBinding(1)
		fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
		base := newMemoryAppAttestKeyStore()
		verifier := mustTestAppAttestVerifier(t, base, fixture.root, AppAttestProduction)
		if _, err := verifier.Verify(
			context.Background(),
			mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding),
			attestationBinding,
		); err != nil {
			t.Fatalf("register assertion key: %v", err)
		}
		binding := appAttestTestBinding(2)
		assertion := mustAppAttestAssertion(t, fixture, binding, 1, appAttestAssertionOptions{})
		ctx, cancel := context.WithCancel(context.Background())
		verifier.store = &appAttestCommitThenCancelStore{base: base, cancel: cancel}
		result, err := verifier.Verify(
			ctx,
			mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, binding),
			binding,
		)
		if err != nil {
			t.Fatalf("committed assertion returned error: %v", err)
		}
		bindingHash, err := binding.Hash()
		if err != nil {
			t.Fatalf("hash binding: %v", err)
		}
		if _, err := result.ValidatedSnapshot(bindingHash, appAttestTestNow); err != nil {
			t.Fatalf("committed assertion result is not sealed: %v", err)
		}
		stored, exists := base.snapshot(fixture.keyID)
		if !exists || stored.Counter != 1 {
			t.Fatalf("committed assertion counter = %d exists=%v", stored.Counter, exists)
		}
	})
}

func TestAppAttestStoreFailureAfterSuccessfulCallbackRollsBackCounter(t *testing.T) {
	attestationBinding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, attestationBinding, appAttestFixtureOptions{environment: AppAttestProduction})
	store := newMemoryAppAttestKeyStore()
	verifier := mustTestAppAttestVerifier(t, store, fixture.root, AppAttestProduction)
	if _, err := verifier.Verify(context.Background(), mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, attestationBinding), attestationBinding); err != nil {
		t.Fatalf("register key: %v", err)
	}
	assertionBinding := appAttestTestBinding(2)
	assertion := mustAppAttestAssertion(t, fixture, assertionBinding, 1, appAttestAssertionOptions{})
	secret := "database host and row details must be redacted"
	verifier.store = &appAttestErrorAfterCallbackStore{base: store, err: errors.New(secret)}
	_, err := verifier.Verify(
		context.Background(),
		mustAppAttestEvidence(t, fixture.keyID, "assertion_object", assertion, assertionBinding),
		assertionBinding,
	)
	if !errors.Is(err, ErrAppAttestKeyStore) || strings.Contains(err.Error(), secret) {
		t.Fatalf("post-callback store error was not normalized: %v", err)
	}
	stored, _ := store.snapshot(fixture.keyID)
	if stored.Counter != 0 {
		t.Fatalf("failed store commit advanced counter to %d", stored.Counter)
	}
}

func TestAppAttestKeyStoreContractViolationsFailClosed(t *testing.T) {
	binding := appAttestTestBinding(1)
	fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{environment: AppAttestProduction})
	evidence := mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding)
	for _, test := range []struct {
		name  string
		store AppAttestKeyStore
	}{
		{name: "callback omitted", store: appAttestNoCallbackStore{}},
		{name: "callback repeated", store: appAttestDoubleCallbackStore{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := mustTestAppAttestVerifier(t, test.store, fixture.root, AppAttestProduction)
			if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrAppAttestKeyStore) {
				t.Fatalf("contract violation error = %v, want ErrAppAttestKeyStore", err)
			}
		})
	}
}

func TestNewAppAttestVerifierRejectsUnsafeConfiguration(t *testing.T) {
	valid := appAttestTestConfig(newMemoryAppAttestKeyStore(), AppAttestProduction, []uint32{4}, []string{"1.0"})
	tests := []struct {
		name   string
		mutate func(*AppAttestConfig)
	}{
		{name: "application", mutate: func(config *AppAttestConfig) { config.ApplicationID = "client-app" }},
		{name: "binding environment", mutate: func(config *AppAttestConfig) { config.EnvironmentID = "Production" }},
		{name: "App ID prefix", mutate: func(config *AppAttestConfig) { config.AppIDPrefix = "abcde12345" }},
		{name: "bundle ID", mutate: func(config *AppAttestConfig) { config.BundleID = "com..unsafe" }},
		{name: "attestation environment", mutate: func(config *AppAttestConfig) { config.AttestationEnvironment = "staging" }},
		{name: "store", mutate: func(config *AppAttestConfig) { config.Store = nil }},
		{name: "typed nil store", mutate: func(config *AppAttestConfig) { config.Store = (*memoryAppAttestKeyStore)(nil) }},
		{name: "empty categories", mutate: func(config *AppAttestConfig) { config.AllowedValidationCategories = nil }},
		{name: "invalid category", mutate: func(config *AppAttestConfig) { config.AllowedValidationCategories = []uint32{7} }},
		{name: "duplicate category", mutate: func(config *AppAttestConfig) { config.AllowedValidationCategories = []uint32{4, 4} }},
		{name: "empty versions", mutate: func(config *AppAttestConfig) { config.AllowedBundleVersions = nil }},
		{name: "unsafe version", mutate: func(config *AppAttestConfig) { config.AllowedBundleVersions = []string{"1/../../2"} }},
		{name: "duplicate version", mutate: func(config *AppAttestConfig) { config.AllowedBundleVersions = []string{"1.0", "1.0"} }},
		{name: "short lifetime", mutate: func(config *AppAttestConfig) { config.ResultLifetime = time.Second }},
		{name: "long lifetime", mutate: func(config *AppAttestConfig) { config.ResultLifetime = maximumAppAttestResultLifetime + time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			config.AllowedValidationCategories = append([]uint32(nil), valid.AllowedValidationCategories...)
			config.AllowedBundleVersions = append([]string(nil), valid.AllowedBundleVersions...)
			test.mutate(&config)
			if _, err := NewAppAttestVerifier(config); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("constructor error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestAppAttestPlatformVocabularyIncludesWatchOS(t *testing.T) {
	t.Parallel()

	for _, platform := range []string{"ios", "react_native_ios", "watchos"} {
		if !validAppAttestPlatform(platform) {
			t.Errorf("App Attest platform %q was rejected", platform)
		}
	}
	for _, platform := range []string{"", "android", "react_native_android", "web", "node"} {
		if validAppAttestPlatform(platform) {
			t.Errorf("non-App-Attest platform %q was accepted", platform)
		}
	}
}

type appAttestFailingStore struct{ err error }

func (store appAttestFailingStore) TransactAppAttestKey(
	context.Context,
	[sha256.Size]byte,
	AppAttestKeyTransaction,
) error {
	return store.err
}

type appAttestNoCallbackStore struct{}

func (appAttestNoCallbackStore) TransactAppAttestKey(
	context.Context,
	[sha256.Size]byte,
	AppAttestKeyTransaction,
) error {
	return nil
}

type appAttestDoubleCallbackStore struct{}

func (appAttestDoubleCallbackStore) TransactAppAttestKey(
	_ context.Context,
	_ [sha256.Size]byte,
	transact AppAttestKeyTransaction,
) error {
	if _, err := transact(AppAttestStoredKey{}, false); err != nil {
		return err
	}
	_, err := transact(AppAttestStoredKey{}, false)
	return err
}

type appAttestCancelAfterCallbackStore struct {
	base   *memoryAppAttestKeyStore
	cancel context.CancelFunc
}

type appAttestCommitThenCancelStore struct {
	base   *memoryAppAttestKeyStore
	cancel context.CancelFunc
}

type appAttestErrorAfterCallbackStore struct {
	base *memoryAppAttestKeyStore
	err  error
}

func (store *appAttestErrorAfterCallbackStore) TransactAppAttestKey(
	ctx context.Context,
	keyID [sha256.Size]byte,
	transact AppAttestKeyTransaction,
) error {
	store.base.mu.Lock()
	defer store.base.mu.Unlock()
	store.base.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	current, exists := store.base.keys[keyID]
	if _, err := transact(cloneAppAttestStoredKey(current), exists); err != nil {
		return err
	}
	return store.err
}

func (store *appAttestCancelAfterCallbackStore) TransactAppAttestKey(
	ctx context.Context,
	keyID [sha256.Size]byte,
	transact AppAttestKeyTransaction,
) error {
	store.base.mu.Lock()
	defer store.base.mu.Unlock()
	store.base.calls++
	current, exists := store.base.keys[keyID]
	if _, err := transact(cloneAppAttestStoredKey(current), exists); err != nil {
		return err
	}
	store.cancel()
	return ctx.Err()
}

func (store *appAttestCommitThenCancelStore) TransactAppAttestKey(
	ctx context.Context,
	keyID [sha256.Size]byte,
	transact AppAttestKeyTransaction,
) error {
	if err := store.base.TransactAppAttestKey(ctx, keyID, transact); err != nil {
		return err
	}
	store.cancel()
	return nil
}

type appAttestRepeatingReader byte

func (reader appAttestRepeatingReader) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = byte(reader)
	}
	return len(destination), nil
}

type appAttestDeterministicSigner struct{ key *ecdsa.PrivateKey }

func (signer appAttestDeterministicSigner) Public() crypto.PublicKey { return &signer.key.PublicKey }

func (signer appAttestDeterministicSigner) Sign(
	_ io.Reader,
	digest []byte,
	options crypto.SignerOpts,
) ([]byte, error) {
	return signer.key.Sign(nil, digest, options)
}

func mustAppAttestFixture(t *testing.T, binding Binding, options appAttestFixtureOptions) appAttestFixture {
	t.Helper()
	fixture, err := newAppAttestFixture(binding, options)
	if err != nil {
		t.Fatalf("build deterministic App Attest fixture: %v", err)
	}
	return fixture
}

func newAppAttestFixture(binding Binding, options appAttestFixtureOptions) (appAttestFixture, error) {
	if err := binding.Validate(); err != nil {
		return appAttestFixture{}, err
	}
	if options.environment == "" {
		options.environment = AppAttestProduction
	}
	if options.validationCategory == 0 {
		options.validationCategory = 4
	}
	if options.bundleVersion == "" {
		options.bundleVersion = "1.0"
	}
	if !options.flagsSet && options.flags == 0 {
		options.flags = 0x40
	}
	if options.rootScalar == 0 {
		options.rootScalar = 11
	}
	if options.leafNotBefore.IsZero() {
		options.leafNotBefore = appAttestTestNow.Add(-time.Hour)
	}
	if options.leafNotAfter.IsZero() {
		options.leafNotAfter = appAttestTestNow.Add(24 * time.Hour)
	}

	privateKey := appAttestTestPrivateKey(31)
	publicKeyX963, err := privateKey.PublicKey.Bytes()
	if err != nil || len(publicKeyX963) != 65 || publicKeyX963[0] != 4 {
		return appAttestFixture{}, errors.New("fixture public key is invalid")
	}
	keyID := sha256.Sum256(publicKeyX963)
	rpIDHash := sha256.Sum256([]byte(appAttestTestAppIDPrefix + "." + appAttestTestBundleID))
	if options.rpIDHash != nil {
		rpIDHash = *options.rpIDHash
	}
	credentialID := keyID
	if options.credentialID != nil {
		credentialID = *options.credentialID
	}
	aaguid := appAttestTestAAGUID(options.environment)
	if options.aaguid != nil {
		aaguid = *options.aaguid
	}
	coseKey := privateKey
	if options.coseKeyScalar != 0 {
		coseKey = appAttestTestPrivateKey(options.coseKeyScalar)
	}
	authenticatorData, err := appAttestTestAttestationAuthenticator(
		rpIDHash, options.flags, options.counter, aaguid, credentialID, &coseKey.PublicKey,
		options.validationCategory, options.bundleVersion, options.omitExtensions,
	)
	if err != nil {
		return appAttestFixture{}, err
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		return appAttestFixture{}, err
	}
	nonceInput := make([]byte, 0, len(authenticatorData)+sha256.Size)
	nonceInput = append(nonceInput, authenticatorData...)
	nonceInput = append(nonceInput, bindingHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	if options.nonceOverride != nil {
		nonce = *options.nonceOverride
	}

	rootKey := appAttestTestPrivateKey(options.rootScalar)
	intermediateKey := appAttestTestPrivateKey(options.rootScalar + 1)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(options.rootScalar),
		Subject:      pkix.Name{CommonName: "Latchway deterministic App Attest root"},
		NotBefore:    appAttestTestNow.Add(-24 * time.Hour),
		NotAfter:     appAttestTestNow.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:         true, BasicConstraintsValid: true,
		SubjectKeyId: []byte{byte(options.rootScalar), 1},
	}
	rootDER, err := x509.CreateCertificate(
		appAttestRepeatingReader(0x41), rootTemplate, rootTemplate, &rootKey.PublicKey,
		appAttestDeterministicSigner{key: rootKey},
	)
	if err != nil {
		return appAttestFixture{}, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return appAttestFixture{}, err
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(options.rootScalar + 100),
		Subject:      pkix.Name{CommonName: "Latchway deterministic App Attest intermediate"},
		NotBefore:    appAttestTestNow.Add(-12 * time.Hour),
		NotAfter:     appAttestTestNow.Add(180 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:         true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		SubjectKeyId: []byte{byte(options.rootScalar), 2},
	}
	intermediateDER, err := x509.CreateCertificate(
		appAttestRepeatingReader(0x42), intermediateTemplate, root, &intermediateKey.PublicKey,
		appAttestDeterministicSigner{key: rootKey},
	)
	if err != nil {
		return appAttestFixture{}, err
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		return appAttestFixture{}, err
	}
	nonceExtension := appAttestTestNonceExtension(nonce)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(options.rootScalar + 200),
		Subject:               pkix.Name{CommonName: "Latchway deterministic App Attest credential"},
		NotBefore:             options.leafNotBefore,
		NotAfter:              options.leafNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          append([]byte(nil), keyID[:]...),
		ExtraExtensions: []pkix.Extension{{
			Id: appAttestNonceOID, Value: nonceExtension,
		}},
	}
	leafDER, err := x509.CreateCertificate(
		appAttestRepeatingReader(0x43), leafTemplate, intermediate, &privateKey.PublicKey,
		appAttestDeterministicSigner{key: intermediateKey},
	)
	if err != nil {
		return appAttestFixture{}, err
	}
	attestation, err := testAppAttestEncMode.Marshal(appAttestationObjectWire{
		Format: "apple-appattest",
		Statement: appAttestationStatementWire{
			Certificates: [][]byte{leafDER, intermediateDER},
			Receipt:      []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		},
		AuthenticatorData: authenticatorData,
	})
	if err != nil {
		return appAttestFixture{}, err
	}
	return appAttestFixture{
		keyID: keyID, privateKey: privateKey, publicKeyX963: publicKeyX963,
		attestation: attestation, root: root, rootDER: rootDER, intermediateDER: intermediateDER,
	}, nil
}

func appAttestTestAttestationAuthenticator(
	rpIDHash [sha256.Size]byte,
	flags byte,
	counter uint32,
	aaguid [16]byte,
	credentialID [sha256.Size]byte,
	publicKey *ecdsa.PublicKey,
	validationCategory uint32,
	bundleVersion string,
	omitExtensions bool,
) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("fixture public key is invalid")
	}
	encodedPublicKey, err := publicKey.Bytes()
	if err != nil || len(encodedPublicKey) != 65 || encodedPublicKey[0] != 4 {
		return nil, errors.New("fixture public key is invalid")
	}
	x := encodedPublicKey[1:33]
	y := encodedPublicKey[33:]
	cose, err := testAppAttestEncMode.Marshal(map[int64]any{
		1: int64(2), 3: int64(-7), -1: int64(1), -2: x, -3: y,
	})
	if err != nil {
		return nil, err
	}
	var extensions []byte
	if !omitExtensions {
		extensions, err = testAppAttestEncMode.Marshal(map[string]any{
			"apple_validation_category_01": appAttestTestCategory(validationCategory),
			"apple_bundle_version_01":      bundleVersion,
		})
		if err != nil {
			return nil, err
		}
	}
	result := make([]byte, 0, appAttestAuthenticatorHeaderBytes+16+2+sha256.Size+len(cose)+len(extensions))
	result = append(result, rpIDHash[:]...)
	result = append(result, flags)
	var encodedCounter [4]byte
	binary.BigEndian.PutUint32(encodedCounter[:], counter)
	result = append(result, encodedCounter[:]...)
	result = append(result, aaguid[:]...)
	var credentialLength [2]byte
	binary.BigEndian.PutUint16(credentialLength[:], sha256.Size)
	result = append(result, credentialLength[:]...)
	result = append(result, credentialID[:]...)
	result = append(result, cose...)
	result = append(result, extensions...)
	return result, nil
}

func mustAppAttestAssertion(
	t *testing.T,
	fixture appAttestFixture,
	binding Binding,
	counter uint32,
	options appAttestAssertionOptions,
) []byte {
	t.Helper()
	if options.validationCategory == 0 {
		options.validationCategory = 4
	}
	if options.bundleVersion == "" {
		options.bundleVersion = "1.0"
	}
	rpIDHash := sha256.Sum256([]byte(appAttestTestAppIDPrefix + "." + appAttestTestBundleID))
	if options.rpIDHash != nil {
		rpIDHash = *options.rpIDHash
	}
	var extensions []byte
	if !options.omitExtensions {
		extensions = mustTestCBOR(t, map[string]any{
			"apple_validation_category_01": appAttestTestCategory(options.validationCategory),
			"apple_bundle_version_01":      options.bundleVersion,
		})
	}
	authenticatorData := make([]byte, 0, appAttestAuthenticatorHeaderBytes+len(extensions))
	authenticatorData = append(authenticatorData, rpIDHash[:]...)
	authenticatorData = append(authenticatorData, options.flags)
	var encodedCounter [4]byte
	binary.BigEndian.PutUint32(encodedCounter[:], counter)
	authenticatorData = append(authenticatorData, encodedCounter[:]...)
	authenticatorData = append(authenticatorData, extensions...)
	bindingHash, err := binding.Hash()
	if err != nil {
		t.Fatalf("hash assertion binding: %v", err)
	}
	nonceInput := make([]byte, 0, len(authenticatorData)+sha256.Size)
	nonceInput = append(nonceInput, authenticatorData...)
	nonceInput = append(nonceInput, bindingHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	signingKey := fixture.privateKey
	if options.signingKey != nil {
		signingKey = options.signingKey
	}
	signature, err := signingKey.Sign(nil, nonce[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign deterministic assertion: %v", err)
	}
	encoded, err := testAppAttestEncMode.Marshal(appAttestAssertionWire{
		Signature: signature, AuthenticatorData: authenticatorData,
	})
	if err != nil {
		t.Fatalf("encode assertion fixture: %v", err)
	}
	return encoded
}

func appAttestTestCategory(category uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], category)
	return encoded[:]
}

func appAttestTestNonceExtension(nonce [sha256.Size]byte) []byte {
	result := make([]byte, 0, 38)
	result = append(result, 0x30, 0x24, 0xa1, 0x22, 0x04, 0x20)
	result = append(result, nonce[:]...)
	return result
}

func appAttestTestPrivateKey(scalar int64) *ecdsa.PrivateKey {
	encodedScalar := big.NewInt(scalar).FillBytes(make([]byte, 32))
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), encodedScalar)
	if err != nil {
		panic("invalid deterministic App Attest fixture scalar")
	}
	return privateKey
}

func appAttestTestAAGUID(environment AppAttestEnvironment) [16]byte {
	if environment == AppAttestDevelopment {
		return [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'}
	}
	return [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't'}
}

func appAttestTestBinding(sequence byte) Binding {
	binding := testBinding()
	binding.ChallengeID = fmt.Sprintf("chl_01J000000000000000000000%02d", sequence)
	binding.ChallengeNonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{sequence}, sha256.Size))
	binding.IssuedAt += int64(sequence)
	return binding
}

func appAttestTestConfig(
	store AppAttestKeyStore,
	environment AppAttestEnvironment,
	categories []uint32,
	versions []string,
) AppAttestConfig {
	return AppAttestConfig{
		ApplicationID: testBinding().ApplicationID, EnvironmentID: testBinding().Environment,
		AppIDPrefix: appAttestTestAppIDPrefix, BundleID: appAttestTestBundleID,
		AttestationEnvironment:      environment,
		AllowedValidationCategories: append([]uint32(nil), categories...),
		AllowedBundleVersions:       append([]string(nil), versions...), Store: store,
		Now: func() time.Time { return appAttestTestNow },
	}
}

func mustTestAppAttestVerifier(
	t *testing.T,
	store AppAttestKeyStore,
	root *x509.Certificate,
	environment AppAttestEnvironment,
) *AppAttestVerifier {
	t.Helper()
	return mustTestAppAttestVerifierWithPolicy(t, store, root, environment, []uint32{4}, []string{"1.0"})
}

func mustTestAppAttestVerifierWithPolicy(
	t *testing.T,
	store AppAttestKeyStore,
	root *x509.Certificate,
	environment AppAttestEnvironment,
	categories []uint32,
	versions []string,
) *AppAttestVerifier {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifier, err := newAppAttestVerifier(appAttestTestConfig(store, environment, categories, versions), roots)
	if err != nil {
		t.Fatalf("construct test App Attest verifier: %v", err)
	}
	return verifier
}

func mustAppAttestEvidence(
	t *testing.T,
	keyID [sha256.Size]byte,
	objectField string,
	object []byte,
	binding Binding,
) Evidence {
	t.Helper()
	clientDataHash, err := binding.Hash()
	if err != nil {
		t.Fatalf("hash App Attest evidence binding: %v", err)
	}
	evidence, err := NewEvidence(appAttestProvider, map[string]any{
		"key_id":           base64.StdEncoding.EncodeToString(keyID[:]),
		"client_data_hash": base64.RawURLEncoding.EncodeToString(clientDataHash[:]),
		objectField:        base64.RawURLEncoding.EncodeToString(object),
	})
	if err != nil {
		t.Fatalf("construct App Attest evidence: %v", err)
	}
	return evidence
}

func rewriteAppAttestation(
	t *testing.T,
	encoded []byte,
	mutate func(*appAttestationObjectWire),
) []byte {
	t.Helper()
	var wire appAttestationObjectWire
	if err := appAttestCBORMode.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode attestation for mutation: %v", err)
	}
	mutate(&wire)
	return mustTestCBOR(t, wire)
}

func rewriteAppAssertion(
	t *testing.T,
	encoded []byte,
	mutate func(*appAttestAssertionWire),
) []byte {
	t.Helper()
	var wire appAttestAssertionWire
	if err := appAttestCBORMode.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode assertion for mutation: %v", err)
	}
	mutate(&wire)
	return mustTestCBOR(t, wire)
}

var testAppAttestEncMode = func() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("construct deterministic test CBOR encoder")
	}
	return mode
}()

func mustTestCBOR(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := testAppAttestEncMode.Marshal(value)
	if err != nil {
		t.Fatalf("encode deterministic CBOR fixture: %v", err)
	}
	return encoded
}

func pointerToHash(value [sha256.Size]byte) *[sha256.Size]byte { return &value }
func pointerToAAGUID(value [16]byte) *[16]byte                 { return &value }

func validObjectPrefix(encoded []byte) string {
	text := base64.StdEncoding.EncodeToString(encoded)
	if len(text) > 12 {
		return text[:12]
	}
	return text
}
