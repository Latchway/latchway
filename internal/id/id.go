// Package id generates opaque, prefixed, time-sortable identifiers.
package id

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	payloadLength = 26
	maxTimestamp  = uint64(1<<48 - 1)
)

var (
	// ErrInvalidPrefix indicates that an identifier prefix is not canonical.
	ErrInvalidPrefix = errors.New("invalid identifier prefix")
	// ErrInvalidID indicates that an identifier is malformed or non-canonical.
	ErrInvalidID = errors.New("invalid identifier")
	// ErrTimestampOutOfRange indicates that the clock cannot fit in the ID.
	ErrTimestampOutOfRange = errors.New("identifier timestamp out of range")
	// ErrEntropyExhausted indicates that all 80-bit values in one millisecond
	// were consumed.
	ErrEntropyExhausted = errors.New("identifier entropy exhausted")
)

// Prefix names a resource family. Prefixes are lowercase and intentionally
// short so IDs remain readable in logs and support tools.
type Prefix string

const (
	Organization        Prefix = "org"
	Application         Prefix = "app"
	Environment         Prefix = "env"
	AdminUser           Prefix = "adm"
	AdminMembership     Prefix = "amb"
	AdminSession        Prefix = "asn"
	AdminAPIToken       Prefix = "tok"
	AdminBootstrapToken Prefix = "abt"
	AdminRequest        Prefix = "arq"
	ConfigRevision      Prefix = "rev"
	SecretRecord        Prefix = "sec"
	GatewaySigningKey   Prefix = "gsk"
	IdentityProvider    Prefix = "idp"
	ApplicationUser     Prefix = "usr"
	ExternalIdentity    Prefix = "xid"
	UserOverride        Prefix = "uov"
	Installation        Prefix = "ins"
	AttestationKey      Prefix = "aky"
	AttestationEvent    Prefix = "aev"
	SessionChallenge    Prefix = "chl"
	SessionGrant        Prefix = "sgr"
	RefreshToken        Prefix = "rft"
	RefreshTokenFamily  Prefix = "rff"
	DPoPReplay          Prefix = "drp"
	QuotaBucket         Prefix = "qbk"
	QuotaReservation    Prefix = "qrs"
	QuotaEntry          Prefix = "qre"
	ConcurrencyLease    Prefix = "cls"
	LogicalRequest      Prefix = "req"
	UpstreamAttempt     Prefix = "atm"
	UsageRecord         Prefix = "usg"
	Job                 Prefix = "job"
	AuditEvent          Prefix = "aud"
	SelfTest            Prefix = "tst"
	SelfTestSchedule    Prefix = "sts"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Generator creates monotonically ordered identifiers. It is safe for
// concurrent use. A clock regression retains the last observed millisecond.
type Generator struct {
	mu          sync.Mutex
	random      io.Reader
	now         func() time.Time
	initialized bool
	lastMillis  uint64
	entropy     [10]byte
}

// NewGenerator constructs a generator from explicit entropy and clock
// sources. Production callers normally use New.
func NewGenerator(random io.Reader, now func() time.Time) (*Generator, error) {
	if random == nil {
		return nil, errors.New("identifier entropy source is nil")
	}
	if now == nil {
		return nil, errors.New("identifier clock is nil")
	}
	return &Generator{random: random, now: now}, nil
}

var defaultGenerator = func() *Generator {
	generator, err := NewGenerator(rand.Reader, time.Now)
	if err != nil {
		panic(err)
	}
	return generator
}()

// New generates a prefixed, ULID-shaped identifier from cryptographic entropy.
func New(prefix Prefix) (string, error) {
	return defaultGenerator.New(prefix)
}

// Must generates an identifier or panics. It is intended for process-internal
// construction paths where entropy failure is unrecoverable.
func Must(prefix Prefix) string {
	value, err := New(prefix)
	if err != nil {
		panic(fmt.Sprintf("generate %s identifier: %v", prefix, err))
	}
	return value
}

// New generates an identifier using this generator.
func (g *Generator) New(prefix Prefix) (string, error) {
	if err := validatePrefix(prefix); err != nil {
		return "", err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	millis := g.now().UTC().UnixMilli()
	if millis < 0 || uint64(millis) > maxTimestamp {
		return "", ErrTimestampOutOfRange
	}
	observed := uint64(millis)

	if !g.initialized || observed > g.lastMillis {
		if _, err := io.ReadFull(g.random, g.entropy[:]); err != nil {
			return "", fmt.Errorf("read identifier entropy: %w", err)
		}
		g.lastMillis = observed
		g.initialized = true
	} else if !increment(g.entropy[:]) {
		return "", ErrEntropyExhausted
	}

	var raw [16]byte
	raw[0] = byte(g.lastMillis >> 40)
	raw[1] = byte(g.lastMillis >> 32)
	raw[2] = byte(g.lastMillis >> 24)
	raw[3] = byte(g.lastMillis >> 16)
	raw[4] = byte(g.lastMillis >> 8)
	raw[5] = byte(g.lastMillis)
	copy(raw[6:], g.entropy[:])

	return string(prefix) + "_" + encodePayload(raw), nil
}

func increment(value []byte) bool {
	for i := len(value) - 1; i >= 0; i-- {
		value[i]++
		if value[i] != 0 {
			return true
		}
	}
	return false
}

// Parsed is the validated decomposition of an identifier.
type Parsed struct {
	Prefix    Prefix
	Timestamp time.Time
}

// Parse validates a canonical ID and returns its prefix and embedded time.
func Parse(value string) (Parsed, error) {
	prefixText, payload, ok := strings.Cut(value, "_")
	if !ok || strings.Contains(payload, "_") {
		return Parsed{}, ErrInvalidID
	}
	prefix := Prefix(prefixText)
	if err := validatePrefix(prefix); err != nil {
		return Parsed{}, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if len(payload) != payloadLength {
		return Parsed{}, ErrInvalidID
	}
	for i := range payload {
		if !isCrockford(payload[i]) {
			return Parsed{}, ErrInvalidID
		}
	}

	raw, err := decodePayload(payload)
	if err != nil || encodePayload(raw) != payload {
		return Parsed{}, ErrInvalidID
	}
	millis := uint64(raw[0])<<40 |
		uint64(raw[1])<<32 |
		uint64(raw[2])<<24 |
		uint64(raw[3])<<16 |
		uint64(raw[4])<<8 |
		uint64(raw[5])

	return Parsed{
		Prefix:    prefix,
		Timestamp: time.UnixMilli(int64(millis)).UTC(),
	}, nil
}

// encodePayload uses the canonical ULID bit layout: two leading zero bits
// followed by the 128 payload bits. encoding/base32 instead pads on the right,
// which is not ULID-compatible and can violate the database's leading 0-7
// invariant at the upper end of the 48-bit timestamp range.
func encodePayload(raw [16]byte) string {
	encoded := [payloadLength]byte{}
	for encodedIndex := range encoded {
		var digit byte
		for bitIndex := range 5 {
			conceptualBit := encodedIndex*5 + bitIndex
			if conceptualBit < 2 {
				continue
			}
			rawBit := conceptualBit - 2
			bit := (raw[rawBit/8] >> (7 - rawBit%8)) & 1
			digit |= bit << (4 - bitIndex)
		}
		encoded[encodedIndex] = crockfordAlphabet[digit]
	}
	return string(encoded[:])
}

func decodePayload(encoded string) ([16]byte, error) {
	var raw [16]byte
	if len(encoded) != payloadLength {
		return raw, ErrInvalidID
	}
	for encodedIndex := range encoded {
		digit, ok := crockfordValue(encoded[encodedIndex])
		if !ok || (encodedIndex == 0 && digit > 7) {
			return raw, ErrInvalidID
		}
		for bitIndex := range 5 {
			conceptualBit := encodedIndex*5 + bitIndex
			if conceptualBit < 2 {
				continue
			}
			rawBit := conceptualBit - 2
			bit := (digit >> (4 - bitIndex)) & 1
			raw[rawBit/8] |= bit << (7 - rawBit%8)
		}
	}
	return raw, nil
}

// Validate confirms that value is canonical and has the expected prefix.
func Validate(value string, expected Prefix) error {
	if err := validatePrefix(expected); err != nil {
		return err
	}
	parsed, err := Parse(value)
	if err != nil {
		return err
	}
	if parsed.Prefix != expected {
		return fmt.Errorf("%w: expected prefix %q", ErrInvalidID, expected)
	}
	return nil
}

func validatePrefix(prefix Prefix) error {
	value := string(prefix)
	if len(value) < 2 || len(value) > 16 {
		return ErrInvalidPrefix
	}
	for i := range value {
		character := value[i]
		if (character < 'a' || character > 'z') && (i == 0 || character < '0' || character > '9') {
			return ErrInvalidPrefix
		}
	}
	return nil
}

func isCrockford(character byte) bool {
	_, ok := crockfordValue(character)
	return ok
}

func crockfordValue(character byte) (byte, bool) {
	for index := range crockfordAlphabet {
		if crockfordAlphabet[index] == character {
			return byte(index), true
		}
	}
	return 0, false
}
