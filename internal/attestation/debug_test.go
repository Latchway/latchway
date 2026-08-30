package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var debugTestNow = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func TestDebugVerifierAcceptsBoundSignedEvidence(t *testing.T) {
	publicKey, privateKey := deterministicDebugKey()
	verifier := mustDebugVerifier(t, DebugConfig{
		Enabled: true, EnvironmentKind: "development",
		PublicKeys: map[string]ed25519.PublicKey{"fixture-key-01": publicKey},
		Now:        func() time.Time { return debugTestNow },
	})
	binding := testBinding()
	evidence := signedDebugEvidence(t, binding, privateKey, "fixture-key-01", debugTestNow.Add(5*time.Minute))

	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("verify debug evidence: %v", err)
	}
	if result.Provider != "debug" || result.TrustLevel != "debug" || !result.VerifiedAt.Equal(debugTestNow) || !result.ExpiresAt.Equal(debugTestNow.Add(5*time.Minute)) || result.NormalizedSignals["deterministic_test_evidence"] != true {
		t.Fatalf("unexpected debug result: %#v", result)
	}
	if result.EvidenceHash == ([sha256.Size]byte{}) {
		t.Fatal("debug evidence hash was not recorded")
	}
	if strings.Contains(fmt.Sprint(evidence), "signature") || strings.Contains(fmt.Sprintf("%#v", evidence), "fixture-key") {
		t.Fatal("debug evidence formatting was not redacted")
	}
}

func TestVerifiedResultSealRejectsMutationAndWrongBinding(t *testing.T) {
	publicKey, privateKey := deterministicDebugKey()
	binding := testBinding()
	bindingHash, err := binding.Hash()
	if err != nil {
		t.Fatalf("hash binding: %v", err)
	}
	newVerifiedResult := func(t *testing.T) Result {
		t.Helper()
		verifier := mustDebugVerifier(t, DebugConfig{
			Enabled: true, EnvironmentKind: "development",
			PublicKeys: map[string]ed25519.PublicKey{"fixture-key-01": publicKey},
			Now:        func() time.Time { return debugTestNow },
		})
		evidence := signedDebugEvidence(t, binding, privateKey, "fixture-key-01", debugTestNow.Add(5*time.Minute))
		result, verifyErr := verifier.Verify(context.Background(), evidence, binding)
		if verifyErr != nil {
			t.Fatalf("verify debug evidence: %v", verifyErr)
		}
		return result
	}

	result := newVerifiedResult(t)
	snapshot, err := result.ValidatedSnapshot(bindingHash, debugTestNow)
	if err != nil {
		t.Fatalf("validate sealed result: %v", err)
	}
	if snapshot.Provider != result.Provider || snapshot.NormalizedSignals["deterministic_test_evidence"] != true {
		t.Fatalf("unexpected validated snapshot: %#v", snapshot)
	}
	snapshot.NormalizedSignals["deterministic_test_evidence"] = false
	if _, err := snapshot.ValidatedSnapshot(bindingHash, debugTestNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mutated snapshot should fail its seal: %v", err)
	}
	if _, err := result.ValidatedSnapshot(bindingHash, debugTestNow); err != nil {
		t.Fatalf("mutating defensive snapshot changed original result: %v", err)
	}
	wrongBindingHash := sha256.Sum256([]byte("different-authoritative-binding"))
	if _, err := result.ValidatedSnapshot(wrongBindingHash, debugTestNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("result accepted for a different binding: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "provider", mutate: func(result *Result) { result.Provider = "play_integrity" }},
		{name: "trust level", mutate: func(result *Result) { result.TrustLevel = "device_verified" }},
		{name: "verified time", mutate: func(result *Result) { result.VerifiedAt = result.VerifiedAt.Add(time.Second) }},
		{name: "expiry", mutate: func(result *Result) { result.ExpiresAt = result.ExpiresAt.Add(time.Second) }},
		{name: "signals", mutate: func(result *Result) { result.NormalizedSignals["deterministic_test_evidence"] = false }},
		{name: "evidence hash", mutate: func(result *Result) { result.EvidenceHash[0] ^= 0xff }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := newVerifiedResult(t)
			mutation.mutate(&mutated)
			if _, err := mutated.ValidatedSnapshot(bindingHash, debugTestNow); !errors.Is(err, ErrInvalid) {
				t.Fatalf("mutated result passed seal validation: %v", err)
			}
		})
	}

	unsealed := Result{
		Provider: "debug", TrustLevel: "debug", VerifiedAt: debugTestNow,
		ExpiresAt:         debugTestNow.Add(5 * time.Minute),
		NormalizedSignals: map[string]any{"deterministic_test_evidence": true},
		EvidenceHash:      sha256.Sum256([]byte("caller-created-result")),
	}
	if _, err := unsealed.ValidatedSnapshot(bindingHash, debugTestNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("caller-created unsealed result was accepted: %v", err)
	}
}

func TestDebugVerifierRejectsTamperingExpiryAndUnknownShape(t *testing.T) {
	publicKey, privateKey := deterministicDebugKey()
	verifier := mustDebugVerifier(t, DebugConfig{
		Enabled: true, EnvironmentKind: "staging",
		PublicKeys: map[string]ed25519.PublicKey{"fixture-key-01": publicKey},
		Now:        func() time.Time { return debugTestNow }, MaximumEvidenceLifetime: 10 * time.Minute,
	})
	binding := testBinding()
	valid := debugPayload(t, binding, privateKey, "fixture-key-01", debugTestNow.Add(5*time.Minute))

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong binding", mutate: func(value map[string]any) {
			value["binding_hash"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}},
		{name: "wrong signature", mutate: func(value map[string]any) {
			value["signature"] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}},
		{name: "unknown key", mutate: func(value map[string]any) { value["key_id"] = "unknown-key-01" }},
		{name: "expired", mutate: func(value map[string]any) { value["expires_at"] = debugTestNow.Add(-time.Minute).Unix() }},
		{name: "excessive lifetime", mutate: func(value map[string]any) { value["expires_at"] = debugTestNow.Add(time.Hour).Unix() }},
		{name: "fractional expiry", mutate: func(value map[string]any) { value["expires_at"] = 1234.5 }},
		{name: "extra member", mutate: func(value map[string]any) { value["trusted"] = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := cloneMap(valid)
			test.mutate(payload)
			evidence, err := NewEvidence("debug", payload)
			if err != nil {
				if errors.Is(err, ErrInvalid) {
					return
				}
				t.Fatalf("construct evidence: %v", err)
			}
			if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected invalid evidence, got %v", err)
			}
		})
	}

	wrongProvider, err := NewEvidence("turnstile", valid)
	if err != nil {
		t.Fatalf("construct other provider: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), wrongProvider, binding); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("wrong provider should be unsupported: %v", err)
	}
}

func TestDebugVerifierRequiresExplicitEnvironmentPermission(t *testing.T) {
	publicKey, _ := deterministicDebugKey()
	base := DebugConfig{Enabled: true, EnvironmentKind: "production", PublicKeys: map[string]ed25519.PublicKey{"fixture-key-01": publicKey}}
	if _, err := NewDebugVerifier(base); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("production debug verifier should fail without override: %v", err)
	}
	base.DangerousAllowInProduction = true
	if _, err := NewDebugVerifier(base); err != nil {
		t.Fatalf("explicit production override should construct verifier: %v", err)
	}
	base.Enabled = false
	if _, err := NewDebugVerifier(base); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("disabled debug verifier should not construct: %v", err)
	}
}

func TestDebugVerifierPreservesExplicitZeroClockSkew(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier := mustDebugVerifier(t, DebugConfig{
		Enabled: true, EnvironmentKind: "development",
		PublicKeys: map[string]ed25519.PublicKey{"fixture-key-01": publicKey},
		Now:        func() time.Time { return debugTestNow }, ClockSkewSet: true,
	})
	binding := testBinding()
	evidence := signedDebugEvidence(t, binding, privateKey, "fixture-key-01", debugTestNow.Add(time.Second))
	if _, err := verifier.Verify(context.Background(), evidence, binding); err != nil {
		t.Fatalf("unexpired evidence should be valid: %v", err)
	}
	evidence = signedDebugEvidence(t, binding, privateKey, "fixture-key-01", debugTestNow)
	if _, err := verifier.Verify(context.Background(), evidence, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("explicit zero skew accepted evidence at its expiry boundary: %v", err)
	}
}

func deterministicDebugKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func mustDebugVerifier(t *testing.T, config DebugConfig) *DebugVerifier {
	t.Helper()
	verifier, err := NewDebugVerifier(config)
	if err != nil {
		t.Fatalf("construct debug verifier: %v", err)
	}
	return verifier
}

func signedDebugEvidence(t *testing.T, binding Binding, privateKey ed25519.PrivateKey, keyID string, expiresAt time.Time) Evidence {
	t.Helper()
	payload := debugPayload(t, binding, privateKey, keyID, expiresAt)
	evidence, err := NewEvidence("debug", payload)
	if err != nil {
		t.Fatalf("construct signed debug evidence: %v", err)
	}
	return evidence
}

func debugPayload(t *testing.T, binding Binding, privateKey ed25519.PrivateKey, keyID string, expiresAt time.Time) map[string]any {
	t.Helper()
	hash, err := binding.Hash()
	if err != nil {
		t.Fatalf("hash binding: %v", err)
	}
	expiry := expiresAt.Unix()
	signature := ed25519.Sign(privateKey, DebugSigningMessage(hash, expiry))
	return map[string]any{
		"key_id": keyID, "binding_hash": base64.RawURLEncoding.EncodeToString(hash[:]),
		"expires_at": expiry, "signature": base64.RawURLEncoding.EncodeToString(signature),
	}
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
