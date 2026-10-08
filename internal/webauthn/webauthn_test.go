package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/latchway/latchway/internal/webauthn/webauthntest"
)

var testRP = RelyingParty{ID: "console.example.test", Origin: "https://console.example.test"}

func newChallenge(t *testing.T) []byte {
	t.Helper()
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func TestRegistrationAndAssertion(t *testing.T) {
	t.Parallel()
	authenticator, err := webauthntest.New(testRP.ID, testRP.Origin)
	if err != nil {
		t.Fatal(err)
	}
	challenge := newChallenge(t)
	clientData, attestation := authenticator.Register(challenge)
	credential, err := VerifyRegistration(testRP, challenge, clientData, attestation)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	if !bytes.Equal(credential.ID, authenticator.CredentialID) || !credential.BackupEligible || !credential.BackupState {
		t.Fatalf("credential = %+v", credential)
	}
	x, y, err := Coordinates(credential.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := PublicKeyFromCoordinates(x, y)
	if err != nil {
		t.Fatal(err)
	}

	assertChallenge := newChallenge(t)
	assertClientData, authData, signature := authenticator.Assert(assertChallenge)
	assertion, err := VerifyAssertion(testRP, assertChallenge, assertClientData, authData, signature, stored)
	if err != nil || assertion.SignCount != 1 {
		t.Fatalf("assertion = %+v, %v", assertion, err)
	}

	cases := map[string]func() error{
		"wrong challenge": func() error {
			_, err := VerifyAssertion(testRP, newChallenge(t), assertClientData, authData, signature, stored)
			return err
		},
		"wrong origin": func() error {
			_, err := VerifyAssertion(RelyingParty{ID: testRP.ID, Origin: "https://evil.example.test"}, assertChallenge, assertClientData, authData, signature, stored)
			return err
		},
		"wrong rp id": func() error {
			_, err := VerifyAssertion(RelyingParty{ID: "other.example.test", Origin: testRP.Origin}, assertChallenge, assertClientData, authData, signature, stored)
			return err
		},
		"registration replayed as assertion": func() error {
			_, err := VerifyAssertion(testRP, challenge, clientData, authData, signature, stored)
			return err
		},
		"tampered authenticator data": func() error {
			tampered := append([]byte(nil), authData...)
			tampered[36] ^= 0x01
			_, err := VerifyAssertion(testRP, assertChallenge, assertClientData, tampered, signature, stored)
			return err
		},
		"cross-origin client data": func() error {
			var data map[string]any
			_ = json.Unmarshal(assertClientData, &data)
			data["crossOrigin"] = true
			encoded, _ := json.Marshal(data)
			_, err := VerifyAssertion(testRP, assertChallenge, encoded, authData, signature, stored)
			return err
		},
	}
	for name, check := range cases {
		if err := check(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestRegistrationRequiresUserVerification(t *testing.T) {
	t.Parallel()
	authenticator, err := webauthntest.New(testRP.ID, testRP.Origin)
	if err != nil {
		t.Fatal(err)
	}
	authenticator.Flags = 0x01 | 0x40 // present but not verified
	challenge := newChallenge(t)
	clientData, attestation := authenticator.Register(challenge)
	if _, err := VerifyRegistration(testRP, challenge, clientData, attestation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unverified registration err = %v", err)
	}
	if _, err := VerifyRegistration(testRP, challenge, clientData, []byte{0xff}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("garbage attestation err = %v", err)
	}
	if _, _, err := ParseClientData([]byte(`{"type":"webauthn.create","challenge":"short"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short challenge err = %v", err)
	}
}

func TestPublicKeyFromCoordinatesRejectsOffCurvePoints(t *testing.T) {
	t.Parallel()
	if _, err := PublicKeyFromCoordinates(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("off-curve point err = %v", err)
	}
}
