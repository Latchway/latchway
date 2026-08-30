package adminauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Version       = 19
	maxPasswordBytes    = 1024
	maxEncodedHashBytes = 256
)

var (
	// ErrInvalidPasswordParameters indicates unsafe or unsupported Argon2id
	// resource bounds.
	ErrInvalidPasswordParameters = errors.New("invalid Argon2id parameters")
	// ErrInvalidPasswordHash indicates malformed or unsupported encoded input.
	ErrInvalidPasswordHash = errors.New("invalid Argon2id password hash")
	// ErrPasswordRequired indicates that an empty password reached the hasher.
	ErrPasswordRequired = errors.New("password is required")
	// ErrPasswordTooLong bounds attacker-controlled password processing.
	ErrPasswordTooLong = errors.New("password exceeds maximum length")
)

// PasswordParameters bounds Argon2id work and encoded salt/key sizes. MemoryKiB
// is measured in kibibytes.
type PasswordParameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultPasswordParameters returns the production password profile.
func DefaultPasswordParameters() PasswordParameters {
	return PasswordParameters{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Validate rejects weak parameters and bounds attacker-controlled hashes before
// Argon2 allocates memory.
func (parameters PasswordParameters) Validate() error {
	if parameters.MemoryKiB < 8*1024 || parameters.MemoryKiB > 256*1024 {
		return fmt.Errorf("%w: memory must be between 8192 and 262144 KiB", ErrInvalidPasswordParameters)
	}
	if parameters.Iterations < 1 || parameters.Iterations > 10 {
		return fmt.Errorf("%w: iterations must be between 1 and 10", ErrInvalidPasswordParameters)
	}
	if parameters.Parallelism < 1 || parameters.Parallelism > 8 {
		return fmt.Errorf("%w: parallelism must be between 1 and 8", ErrInvalidPasswordParameters)
	}
	if parameters.SaltLength < 16 || parameters.SaltLength > 64 {
		return fmt.Errorf("%w: salt length must be between 16 and 64 bytes", ErrInvalidPasswordParameters)
	}
	if parameters.KeyLength < 32 || parameters.KeyLength > 64 {
		return fmt.Errorf("%w: key length must be between 32 and 64 bytes", ErrInvalidPasswordParameters)
	}
	return nil
}

// PasswordHash is a validated Argon2id PHC string. Encoded must be called
// explicitly so accidental structured logging does not reveal it.
type PasswordHash struct {
	encoded    string
	parameters PasswordParameters
	salt       []byte
	digest     []byte
}

// String prevents accidental PHC-string disclosure through formatted logs.
func (PasswordHash) String() string {
	return "[REDACTED]"
}

// GoString prevents disclosure through %#v formatting.
func (PasswordHash) GoString() string {
	return "adminauth.PasswordHash{[REDACTED]}"
}

// Encoded returns the PHC string for persistence.
func (hash PasswordHash) Encoded() string {
	return hash.encoded
}

// Parameters returns the resource profile encoded in the hash.
func (hash PasswordHash) Parameters() PasswordParameters {
	return hash.parameters
}

// ParsePasswordHash validates an encoded Argon2id PHC string without running
// the expensive derivation.
func ParsePasswordHash(encoded string) (PasswordHash, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedHashBytes {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	if parts[2] != "v="+strconv.Itoa(argon2Version) {
		return PasswordHash{}, ErrInvalidPasswordHash
	}

	parameters, err := parseArgon2Parameters(parts[3])
	if err != nil {
		return PasswordHash{}, err
	}
	if len(parts[4]) > base64.RawStdEncoding.EncodedLen(64) ||
		len(parts[5]) > base64.RawStdEncoding.EncodedLen(64) {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || base64.RawStdEncoding.EncodeToString(salt) != parts[4] {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || base64.RawStdEncoding.EncodeToString(digest) != parts[5] {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	parameters.SaltLength = uint32(len(salt))
	parameters.KeyLength = uint32(len(digest))
	if err := parameters.Validate(); err != nil {
		return PasswordHash{}, fmt.Errorf("%w: %v", ErrInvalidPasswordHash, err)
	}

	return PasswordHash{
		encoded:    encoded,
		parameters: parameters,
		salt:       salt,
		digest:     digest,
	}, nil
}

func parseArgon2Parameters(encoded string) (PasswordParameters, error) {
	parts := strings.Split(encoded, ",")
	if len(parts) != 3 {
		return PasswordParameters{}, ErrInvalidPasswordHash
	}
	memory, err := parseParameter(parts[0], "m")
	if err != nil || memory > uint64(^uint32(0)) {
		return PasswordParameters{}, ErrInvalidPasswordHash
	}
	iterations, err := parseParameter(parts[1], "t")
	if err != nil || iterations > uint64(^uint32(0)) {
		return PasswordParameters{}, ErrInvalidPasswordHash
	}
	parallelism, err := parseParameter(parts[2], "p")
	if err != nil || parallelism > uint64(^uint8(0)) {
		return PasswordParameters{}, ErrInvalidPasswordHash
	}
	return PasswordParameters{
		MemoryKiB:   uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
	}, nil
}

func parseParameter(part, name string) (uint64, error) {
	prefix := name + "="
	if !strings.HasPrefix(part, prefix) || len(part) == len(prefix) {
		return 0, ErrInvalidPasswordHash
	}
	valueText := strings.TrimPrefix(part, prefix)
	if valueText[0] == '0' && len(valueText) > 1 {
		return 0, ErrInvalidPasswordHash
	}
	value, err := strconv.ParseUint(valueText, 10, 64)
	if err != nil {
		return 0, ErrInvalidPasswordHash
	}
	return value, nil
}

// PasswordHasher creates and verifies bounded Argon2id hashes.
type PasswordHasher struct {
	parameters PasswordParameters
	random     io.Reader
}

// NewPasswordHasher constructs a hasher with explicit parameters and entropy.
func NewPasswordHasher(parameters PasswordParameters, random io.Reader) (*PasswordHasher, error) {
	if err := parameters.Validate(); err != nil {
		return nil, err
	}
	if random == nil {
		return nil, errors.New("password salt source is nil")
	}
	return &PasswordHasher{parameters: parameters, random: random}, nil
}

// NewDefaultPasswordHasher constructs the production Argon2id profile.
func NewDefaultPasswordHasher() *PasswordHasher {
	hasher, err := NewPasswordHasher(DefaultPasswordParameters(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return hasher
}

// Hash derives a new salted password hash.
func (hasher *PasswordHasher) Hash(password []byte) (PasswordHash, error) {
	if err := validatePassword(password); err != nil {
		return PasswordHash{}, err
	}
	salt := make([]byte, hasher.parameters.SaltLength)
	if _, err := io.ReadFull(hasher.random, salt); err != nil {
		return PasswordHash{}, fmt.Errorf("read password salt: %w", err)
	}
	digest := argon2.IDKey(
		password,
		salt,
		hasher.parameters.Iterations,
		hasher.parameters.MemoryKiB,
		hasher.parameters.Parallelism,
		hasher.parameters.KeyLength,
	)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		hasher.parameters.MemoryKiB,
		hasher.parameters.Iterations,
		hasher.parameters.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
	return PasswordHash{
		encoded:    encoded,
		parameters: hasher.parameters,
		salt:       salt,
		digest:     digest,
	}, nil
}

// PasswordVerification reports whether a password matched and whether a
// successful match should be rehashed with the configured profile.
type PasswordVerification struct {
	Match       bool
	NeedsRehash bool
}

// Verify compares password with a validated hash in constant time.
func (hasher *PasswordHasher) Verify(password []byte, hash PasswordHash) (PasswordVerification, error) {
	if err := validatePassword(password); err != nil {
		return PasswordVerification{}, err
	}
	if hash.encoded == "" || len(hash.salt) == 0 || len(hash.digest) == 0 {
		return PasswordVerification{}, ErrInvalidPasswordHash
	}
	if err := hash.parameters.Validate(); err != nil {
		return PasswordVerification{}, fmt.Errorf("%w: %v", ErrInvalidPasswordHash, err)
	}
	actual := argon2.IDKey(
		password,
		hash.salt,
		hash.parameters.Iterations,
		hash.parameters.MemoryKiB,
		hash.parameters.Parallelism,
		hash.parameters.KeyLength,
	)
	match := subtle.ConstantTimeCompare(actual, hash.digest) == 1
	return PasswordVerification{
		Match:       match,
		NeedsRehash: match && hash.parameters != hasher.parameters,
	}, nil
}

func validatePassword(password []byte) error {
	if len(password) == 0 {
		return ErrPasswordRequired
	}
	if len(password) > maxPasswordBytes {
		return ErrPasswordTooLong
	}
	return nil
}
