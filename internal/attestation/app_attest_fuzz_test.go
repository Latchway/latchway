package attestation

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"testing"
)

func FuzzParseAppAttestationObject(f *testing.F) {
	fixture, err := newAppAttestFixture(appAttestTestBinding(1), appAttestFixtureOptions{environment: AppAttestProduction})
	if err != nil {
		f.Fatalf("build attestation seed: %v", err)
	}
	legacyFixture, err := newAppAttestFixture(appAttestTestBinding(1), appAttestFixtureOptions{
		environment: AppAttestProduction, omitExtensions: true,
	})
	if err != nil {
		f.Fatalf("build legacy attestation seed: %v", err)
	}
	officialFixture, err := base64.StdEncoding.DecodeString(appAttestOfficialAttestationObjectBase64)
	if err != nil {
		f.Fatalf("decode official Apple attestation seed: %v", err)
	}
	f.Add(fixture.attestation)
	f.Add(legacyFixture.attestation)
	f.Add(officialFixture)
	f.Add([]byte{0xbf, 0xff})
	f.Add([]byte{0xa2, 0x63, 'f', 'm', 't', 0x61, 'a', 0x63, 'f', 'm', 't', 0x61, 'b'})
	f.Add(append(append([]byte(nil), fixture.attestation...), 0x00))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		parsed, err := parseAppAttestationObject(encoded)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected parser error: %v", err)
			}
			return
		}
		if len(parsed.certificates) < 2 || len(parsed.certificates) > maxAppAttestCertificates ||
			len(parsed.authenticatorData) == 0 || len(parsed.authenticatorData) > maxAppAttestAuthenticatorBytes ||
			len(parsed.authenticator.publicKeyX963) != 65 || !validParsedAppAttestExtensions(parsed.authenticator.extensions) {
			t.Fatalf("successful parse violated invariants: %#v", parsed)
		}
		if len(encoded) != 0 {
			before := append([]byte(nil), parsed.authenticatorData...)
			encoded[0] ^= 0xff
			if !bytes.Equal(before, parsed.authenticatorData) {
				t.Fatal("parser retained caller-owned authenticator bytes")
			}
		}
	})
}

func FuzzParseAppAttestAssertionObject(f *testing.F) {
	extensions, err := testAppAttestEncMode.Marshal(map[string]any{
		"apple_validation_category_01": appAttestTestCategory(4),
		"apple_bundle_version_01":      "1.0",
	})
	if err != nil {
		f.Fatalf("encode assertion extension seed: %v", err)
	}
	authenticator := make([]byte, appAttestAuthenticatorHeaderBytes, appAttestAuthenticatorHeaderBytes+len(extensions))
	authenticator[32] = 0
	authenticator[36] = 1
	authenticator = append(authenticator, extensions...)
	validShape, err := testAppAttestEncMode.Marshal(appAttestAssertionWire{
		Signature: bytes.Repeat([]byte{0x01}, 64), AuthenticatorData: authenticator,
	})
	if err != nil {
		f.Fatalf("encode assertion seed: %v", err)
	}
	legacyShape, err := testAppAttestEncMode.Marshal(appAttestAssertionWire{
		Signature: bytes.Repeat([]byte{0x01}, 64), AuthenticatorData: authenticator[:appAttestAuthenticatorHeaderBytes],
	})
	if err != nil {
		f.Fatalf("encode legacy assertion seed: %v", err)
	}
	f.Add(validShape)
	f.Add(legacyShape)
	f.Add([]byte{0xbf, 0xff})
	f.Add([]byte{0xa2, 0x69, 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', 0x41, 0x01, 0x69, 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', 0x41, 0x02})
	f.Add(append(append([]byte(nil), validShape...), 0x00))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		parsed, err := parseAppAttestAssertionObject(encoded)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected parser error: %v", err)
			}
			return
		}
		if len(parsed.signature) < 8 || len(parsed.signature) > maxAppAttestSignatureBytes ||
			len(parsed.authenticatorData) < appAttestAuthenticatorHeaderBytes ||
			!validParsedAppAttestExtensions(parsed.extensions) {
			t.Fatalf("successful parse violated invariants: %#v", parsed)
		}
		if len(encoded) != 0 {
			before := append([]byte(nil), parsed.signature...)
			encoded[0] ^= 0xff
			if !bytes.Equal(before, parsed.signature) {
				t.Fatal("parser retained caller-owned signature bytes")
			}
		}
	})
}

func FuzzDecodeAppAttestEvidence(f *testing.F) {
	keyID := sha256.Sum256([]byte("fuzz-app-attest-key"))
	expectedClientDataHash := sha256.Sum256([]byte("fuzz-authoritative-binding"))
	validClientDataHash := base64.RawURLEncoding.EncodeToString(expectedClientDataHash[:])
	f.Add(base64.StdEncoding.EncodeToString(keyID[:]), base64.RawURLEncoding.EncodeToString([]byte{0xa0}), validClientDataHash, true)
	f.Add("not-base64", "%%%", "wrong-hash", false)
	f.Fuzz(func(t *testing.T, keyIDText, objectText, clientDataHashText string, attestation bool) {
		if len(keyIDText) > 1024 || len(objectText) > 128<<10 || len(clientDataHashText) > 1024 {
			return
		}
		field := "assertion_object"
		maximum := maxAppAttestAssertionBytes
		if attestation {
			field = "attestation_object"
			maximum = maxAppAttestAttestationBytes
		}
		decodedKeyID, object, kind, err := decodeAppAttestEvidence(map[string]any{
			"key_id": keyIDText, "client_data_hash": clientDataHashText, field: objectText,
		}, expectedClientDataHash)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected evidence error: %v", err)
			}
			return
		}
		if decodedKeyID == ([sha256.Size]byte{}) || len(object) == 0 || len(object) > maximum ||
			(attestation && kind != "attestation") || (!attestation && kind != "assertion") ||
			base64.StdEncoding.EncodeToString(decodedKeyID[:]) != keyIDText ||
			base64.RawURLEncoding.EncodeToString(object) != objectText || clientDataHashText != validClientDataHash {
			t.Fatalf("successful evidence decode violated invariants")
		}
	})
}

func validParsedAppAttestExtensions(extensions appAttestExtensions) bool {
	if !extensions.present {
		return extensions.validationCategory == 0 && extensions.bundleVersion == ""
	}
	return validAppAttestValidationCategory(extensions.validationCategory) &&
		validAppAttestBundleVersion(extensions.bundleVersion)
}

func FuzzAppAttestCertificateNonce(f *testing.F) {
	valid := appAttestTestNonceExtension(sha256.Sum256([]byte("nonce-seed")))
	f.Add(valid)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x24, 0xa1, 0x22, 0x04, 0x20})
	f.Fuzz(func(t *testing.T, value []byte) {
		certificate := &x509.Certificate{Extensions: []pkix.Extension{{Id: appAttestNonceOID, Value: value}}}
		nonce, err := appAttestCertificateNonce(certificate)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected nonce parser error: %v", err)
			}
			return
		}
		if len(nonce) != sha256.Size {
			t.Fatalf("nonce length = %d, want %d", len(nonce), sha256.Size)
		}
	})
}
