package identity

import (
	"bytes"
	"errors"
	"testing"

	"github.com/latchway/latchway/internal/id"
)

func TestSubjectProtectorIsDeterministicAndScopeSeparated(t *testing.T) {
	protector, err := NewSubjectProtector(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("construct subject protector: %v", err)
	}
	application1 := mustPrivacyID(t, id.Application)
	application2 := mustPrivacyID(t, id.Application)
	first, err := protector.Pseudonymize(application1, "firebase", "https://issuer.example", "external-user-123")
	if err != nil {
		t.Fatalf("pseudonymize subject: %v", err)
	}
	repeated, err := protector.Pseudonymize(application1, "firebase", "https://issuer.example", "external-user-123")
	if err != nil {
		t.Fatalf("repeat pseudonymize subject: %v", err)
	}
	if first != repeated {
		t.Fatal("same external identity did not produce the same pseudonym")
	}
	if first.IssuerHash == first.SubjectHMAC {
		t.Fatal("issuer digest and keyed subject value unexpectedly match")
	}

	variants := []struct {
		applicationID string
		providerID    string
		issuer        string
		subject       string
	}{
		{application2, "firebase", "https://issuer.example", "external-user-123"},
		{application1, "clerk", "https://issuer.example", "external-user-123"},
		{application1, "firebase", "https://other-issuer.example", "external-user-123"},
		{application1, "firebase", "https://issuer.example", "external-user-456"},
	}
	for _, variant := range variants {
		other, err := protector.Pseudonymize(variant.applicationID, variant.providerID, variant.issuer, variant.subject)
		if err != nil {
			t.Fatalf("pseudonymize variant: %v", err)
		}
		if other.SubjectHMAC == first.SubjectHMAC {
			t.Fatalf("scope variant correlated to first subject: %+v", variant)
		}
	}

	// Length-prefixing prevents concatenation ambiguity.
	ambiguous1, _ := protector.Pseudonymize(application1, "firebase", "https://issuer.example/a", "bc")
	ambiguous2, _ := protector.Pseudonymize(application1, "firebase", "https://issuer.example/ab", "c")
	if ambiguous1.SubjectHMAC == ambiguous2.SubjectHMAC {
		t.Fatal("length-ambiguous issuer/subject pairs collided")
	}
}

func TestSubjectProtectorRejectsWeakKeysAndInvalidScope(t *testing.T) {
	if _, err := NewSubjectProtector([]byte("short")); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("weak HMAC key should fail: %v", err)
	}
	protector, err := NewSubjectProtector(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatalf("construct protector: %v", err)
	}
	if _, err := protector.Pseudonymize("app_invalid", "firebase", "https://issuer.example", "subject"); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("invalid application ID should fail: %v", err)
	}
}

func mustPrivacyID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
