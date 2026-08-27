package adminauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestTokenIssuerCreatesCanonicalRedactedTokens(t *testing.T) {
	t.Parallel()

	issuer, err := NewTokenIssuer(bytes.NewReader(bytes.Repeat([]byte{0x7f}, tokenEntropyBytes)))
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}
	issued, err := issuer.Issue(AdminAPITokenKind)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	plaintext := issued.Secret.Reveal()
	if !strings.HasPrefix(plaintext, "lwa_") {
		t.Fatalf("token prefix = %q", plaintext)
	}
	if got := fmt.Sprintf("%s", issued.Secret); got != "[REDACTED]" {
		t.Fatalf("formatted token = %q", got)
	}
	if got := fmt.Sprintf("%#v", issued.Secret); strings.Contains(got, plaintext) {
		t.Fatalf("GoString disclosed token: %q", got)
	}
	if len(issued.Secret.Hint()) != 6 || !strings.HasSuffix(plaintext, issued.Secret.Hint()) {
		t.Fatalf("Hint() = %q", issued.Secret.Hint())
	}

	recomputed, err := HashToken(AdminAPITokenKind, plaintext)
	if err != nil {
		t.Fatalf("HashToken() error = %v", err)
	}
	if !recomputed.Equal(issued.Hash) {
		t.Fatal("recomputed token hash differs")
	}
	if _, err := HashToken(AdminSessionKind, plaintext); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("HashToken(wrong kind) error = %v", err)
	}
}

func TestTokenKindsHaveSeparateHashDomains(t *testing.T) {
	t.Parallel()

	apiPlaintext := "lwa_" + strings.Repeat("A", base64TokenLength())
	sessionPlaintext := "lws_" + strings.Repeat("A", base64TokenLength())
	apiHash, err := HashToken(AdminAPITokenKind, apiPlaintext)
	if err != nil {
		t.Fatalf("HashToken(api) error = %v", err)
	}
	sessionHash, err := HashToken(AdminSessionKind, sessionPlaintext)
	if err != nil {
		t.Fatalf("HashToken(session) error = %v", err)
	}
	if apiHash.Equal(sessionHash) {
		t.Fatal("different token kinds produced equal hashes")
	}
}

func TestTokenHashDefensiveCopies(t *testing.T) {
	t.Parallel()

	source := bytes.Repeat([]byte{0x11}, tokenHashBytes)
	hash, err := ParseTokenHash(source)
	if err != nil {
		t.Fatalf("ParseTokenHash() error = %v", err)
	}
	source[0] = 0
	first := hash.Bytes()
	if first[0] != 0x11 {
		t.Fatal("ParseTokenHash retained source slice")
	}
	first[0] = 0
	if hash.Bytes()[0] != 0x11 {
		t.Fatal("Bytes returned internal storage")
	}
	if _, err := ParseTokenHash(make([]byte, tokenHashBytes-1)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseTokenHash(short) error = %v", err)
	}
}

func TestBootstrapTokenHashing(t *testing.T) {
	t.Parallel()

	plaintext := strings.Repeat("b", minBootstrapTokenBytes)
	hash, err := HashBootstrapToken(plaintext)
	if err != nil {
		t.Fatalf("HashBootstrapToken() error = %v", err)
	}
	if !VerifyBootstrapToken(plaintext, hash) {
		t.Fatal("VerifyBootstrapToken() rejected correct token")
	}
	if VerifyBootstrapToken(strings.Repeat("c", minBootstrapTokenBytes), hash) {
		t.Fatal("VerifyBootstrapToken() accepted wrong token")
	}
	if _, err := HashBootstrapToken("short"); !errors.Is(err, ErrBootstrapTokenLength) {
		t.Fatalf("HashBootstrapToken(short) error = %v", err)
	}
	if _, err := HashBootstrapToken(strings.Repeat("x", maxBootstrapTokenBytes+1)); !errors.Is(err, ErrBootstrapTokenLength) {
		t.Fatalf("HashBootstrapToken(long) error = %v", err)
	}
}

func TestTokenIssuerPropagatesEntropyFailure(t *testing.T) {
	t.Parallel()

	issuer, err := NewTokenIssuer(failingTokenReader{})
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}
	if _, err := issuer.Issue(AdminSessionKind); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Issue() error = %v", err)
	}
}

func base64TokenLength() int {
	return 43
}

type failingTokenReader struct{}

func (failingTokenReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
