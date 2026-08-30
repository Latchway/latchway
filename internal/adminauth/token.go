package adminauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	tokenEntropyBytes      = 32
	minBootstrapTokenBytes = 32
	maxBootstrapTokenBytes = 4096
	tokenHashBytes         = sha256.Size
)

var (
	// ErrInvalidToken indicates a malformed or wrong-kind opaque token.
	ErrInvalidToken = errors.New("invalid token")
	// ErrBootstrapTokenLength prevents weak or unbounded bootstrap secrets.
	ErrBootstrapTokenLength = errors.New("bootstrap token must be between 32 and 4096 bytes")
)

// TokenKind separates token namespaces and hash domains.
type TokenKind string

const (
	AdminAPITokenKind TokenKind = "admin_api"
	AdminSessionKind  TokenKind = "admin_session"
	CSRFTokenKind     TokenKind = "csrf"
)

func (kind TokenKind) prefix() (string, error) {
	switch kind {
	case AdminAPITokenKind:
		return "lwa_", nil
	case AdminSessionKind:
		return "lws_", nil
	case CSRFTokenKind:
		return "lwc_", nil
	default:
		return "", fmt.Errorf("%w: unsupported kind", ErrInvalidToken)
	}
}

// TokenHash is a domain-separated SHA-256 digest suitable for persistence.
// Bytes returns a defensive copy.
type TokenHash struct {
	value [tokenHashBytes]byte
}

// ParseTokenHash validates a persisted hash.
func ParseTokenHash(value []byte) (TokenHash, error) {
	if len(value) != tokenHashBytes {
		return TokenHash{}, ErrInvalidToken
	}
	var hash TokenHash
	copy(hash.value[:], value)
	return hash, nil
}

// Bytes returns a copy suitable for a database parameter.
func (hash TokenHash) Bytes() []byte {
	value := make([]byte, len(hash.value))
	copy(value, hash.value[:])
	return value
}

// Equal compares token hashes without leaking an early mismatch.
func (hash TokenHash) Equal(other TokenHash) bool {
	return subtle.ConstantTimeCompare(hash.value[:], other.value[:]) == 1
}

// SecretToken is an opaque credential. Reveal is deliberately explicit.
type SecretToken struct {
	kind  TokenKind
	value string
}

// Reveal returns the credential for its one-time handoff or cookie value.
func (token SecretToken) Reveal() string {
	return token.value
}

// Kind identifies the credential namespace.
func (token SecretToken) Kind() TokenKind {
	return token.kind
}

// String prevents accidental token disclosure through formatted logging.
func (SecretToken) String() string {
	return "[REDACTED]"
}

// GoString prevents disclosure through %#v formatting.
func (SecretToken) GoString() string {
	return "adminauth.SecretToken{[REDACTED]}"
}

// Hint returns a non-authenticating suffix suitable for an admin listing.
func (token SecretToken) Hint() string {
	if len(token.value) < 6 {
		return ""
	}
	return token.value[len(token.value)-6:]
}

// IssuedToken holds a one-time plaintext credential and its persisted digest.
type IssuedToken struct {
	Secret SecretToken
	Hash   TokenHash
}

// TokenIssuer creates opaque 256-bit credentials.
type TokenIssuer struct {
	random io.Reader
}

// NewTokenIssuer constructs an issuer using random as its entropy source.
func NewTokenIssuer(random io.Reader) (*TokenIssuer, error) {
	if random == nil {
		return nil, errors.New("token entropy source is nil")
	}
	return &TokenIssuer{random: random}, nil
}

// NewDefaultTokenIssuer constructs a cryptographically secure issuer.
func NewDefaultTokenIssuer() *TokenIssuer {
	issuer, err := NewTokenIssuer(rand.Reader)
	if err != nil {
		panic(err)
	}
	return issuer
}

// Issue creates a high-entropy token and its domain-separated digest.
func (issuer *TokenIssuer) Issue(kind TokenKind) (IssuedToken, error) {
	prefix, err := kind.prefix()
	if err != nil {
		return IssuedToken{}, err
	}
	entropy := make([]byte, tokenEntropyBytes)
	if _, err := io.ReadFull(issuer.random, entropy); err != nil {
		return IssuedToken{}, fmt.Errorf("read token entropy: %w", err)
	}
	plaintext := prefix + base64.RawURLEncoding.EncodeToString(entropy)
	hash, err := HashToken(kind, plaintext)
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{
		Secret: SecretToken{kind: kind, value: plaintext},
		Hash:   hash,
	}, nil
}

// HashToken validates and hashes an issued API, session, or CSRF token.
func HashToken(kind TokenKind, plaintext string) (TokenHash, error) {
	prefix, err := kind.prefix()
	if err != nil {
		return TokenHash{}, err
	}
	if !strings.HasPrefix(plaintext, prefix) {
		return TokenHash{}, ErrInvalidToken
	}
	encoded := strings.TrimPrefix(plaintext, prefix)
	if len(encoded) != base64.RawURLEncoding.EncodedLen(tokenEntropyBytes) {
		return TokenHash{}, ErrInvalidToken
	}
	entropy, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(entropy) != tokenEntropyBytes ||
		base64.RawURLEncoding.EncodeToString(entropy) != encoded {
		return TokenHash{}, ErrInvalidToken
	}
	return digest("latchway.adminauth."+string(kind), plaintext), nil
}

// HashBootstrapToken hashes the one-time environment-provided bootstrap
// secret. The minimum length is enforced before storage.
func HashBootstrapToken(plaintext string) (TokenHash, error) {
	if len(plaintext) < minBootstrapTokenBytes || len(plaintext) > maxBootstrapTokenBytes {
		return TokenHash{}, ErrBootstrapTokenLength
	}
	return digest("latchway.adminauth.bootstrap", plaintext), nil
}

// VerifyBootstrapToken checks a presented bootstrap token in constant time.
func VerifyBootstrapToken(plaintext string, expected TokenHash) bool {
	actual, err := HashBootstrapToken(plaintext)
	if err != nil {
		return false
	}
	return actual.Equal(expected)
}

func digest(domain, plaintext string) TokenHash {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(plaintext))
	var hash TokenHash
	copy(hash.value[:], digest.Sum(nil))
	return hash
}
