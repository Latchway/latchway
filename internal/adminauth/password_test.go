package adminauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestPasswordHashFormattingIsRedacted(t *testing.T) {
	t.Parallel()

	hash := PasswordHash{encoded: "$argon2id$v=19$sensitive"}
	for _, formatted := range []string{fmt.Sprint(hash), fmt.Sprintf("%+v", hash), fmt.Sprintf("%#v", hash)} {
		if strings.Contains(formatted, "sensitive") {
			t.Fatalf("formatted password hash disclosed encoded value: %q", formatted)
		}
	}
}

func testPasswordParameters() PasswordParameters {
	return PasswordParameters{
		MemoryKiB:   8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestPasswordHashAndVerify(t *testing.T) {
	t.Parallel()

	parameters := testPasswordParameters()
	hasher, err := NewPasswordHasher(parameters, bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)))
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}
	hash, err := hasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(hash.Encoded(), "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("Hash() = %q", hash.Encoded())
	}

	parsed, err := ParsePasswordHash(hash.Encoded())
	if err != nil {
		t.Fatalf("ParsePasswordHash() error = %v", err)
	}
	verification, err := hasher.Verify([]byte("correct horse battery staple"), parsed)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verification.Match || verification.NeedsRehash {
		t.Fatalf("Verify() = %+v", verification)
	}
	wrong, err := hasher.Verify([]byte("wrong password"), parsed)
	if err != nil {
		t.Fatalf("Verify(wrong) error = %v", err)
	}
	if wrong.Match || wrong.NeedsRehash {
		t.Fatalf("Verify(wrong) = %+v", wrong)
	}
}

func TestPasswordNeedsRehash(t *testing.T) {
	t.Parallel()

	oldParameters := testPasswordParameters()
	oldHasher, err := NewPasswordHasher(oldParameters, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatalf("NewPasswordHasher(old) error = %v", err)
	}
	hash, err := oldHasher.Hash([]byte("password"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	newParameters := oldParameters
	newParameters.Iterations = 2
	newHasher, err := NewPasswordHasher(newParameters, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatalf("NewPasswordHasher(new) error = %v", err)
	}
	verification, err := newHasher.Verify([]byte("password"), hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verification.Match || !verification.NeedsRehash {
		t.Fatalf("Verify() = %+v", verification)
	}
}

func TestPasswordParameterBounds(t *testing.T) {
	t.Parallel()

	tests := []PasswordParameters{
		{},
		{MemoryKiB: 8191, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{MemoryKiB: 262145, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{MemoryKiB: 8192, Iterations: 11, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{MemoryKiB: 8192, Iterations: 1, Parallelism: 9, SaltLength: 16, KeyLength: 32},
		{MemoryKiB: 8192, Iterations: 1, Parallelism: 1, SaltLength: 15, KeyLength: 32},
		{MemoryKiB: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 31},
	}
	for _, parameters := range tests {
		if err := parameters.Validate(); !errors.Is(err, ErrInvalidPasswordParameters) {
			t.Errorf("Validate(%+v) error = %v", parameters, err)
		}
	}
}

func TestParsePasswordHashRejectsMaliciousParameters(t *testing.T) {
	t.Parallel()

	encodedSalt := "MDEyMzQ1Njc4OWFiY2RlZg"
	encodedDigest := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
	tests := []string{
		"",
		"$argon2i$v=19$m=8192,t=1,p=1$" + encodedSalt + "$" + encodedDigest,
		"$argon2id$v=16$m=8192,t=1,p=1$" + encodedSalt + "$" + encodedDigest,
		"$argon2id$v=19$m=999999999,t=1,p=1$" + encodedSalt + "$" + encodedDigest,
		"$argon2id$v=19$m=08192,t=1,p=1$" + encodedSalt + "$" + encodedDigest,
		"$argon2id$v=19$m=8192,t=0,p=1$" + encodedSalt + "$" + encodedDigest,
		"$argon2id$v=19$m=8192,t=1,p=1$bad*$" + encodedDigest,
		strings.Repeat("x", maxEncodedHashBytes+1),
	}
	for _, encoded := range tests {
		if _, err := ParsePasswordHash(encoded); !errors.Is(err, ErrInvalidPasswordHash) {
			t.Errorf("ParsePasswordHash(%q) error = %v", encoded, err)
		}
	}
}

func TestPasswordHasherBoundsInputAndEntropy(t *testing.T) {
	t.Parallel()

	hasher, err := NewPasswordHasher(testPasswordParameters(), failingReader{})
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}
	if _, err := hasher.Hash(nil); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("Hash(nil) error = %v", err)
	}
	if _, err := hasher.Hash(bytes.Repeat([]byte{'a'}, maxPasswordBytes+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Hash(long) error = %v", err)
	}
	if _, err := hasher.Hash([]byte("valid")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Hash(entropy failure) error = %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
