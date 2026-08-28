// Package attestation binds provider evidence to a verified identity, one-time
// challenge, and installation DPoP key without treating attestation as identity.
package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const maxEvidenceBytes = 64 << 10

var (
	ErrInvalid       = errors.New("attestation evidence is invalid")
	ErrUnsupported   = errors.New("attestation provider is unsupported")
	ErrConfiguration = errors.New("attestation verifier configuration is invalid")
)

var providerPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

// Evidence is deliberately redacted when formatted. The bounded payload is a
// defensive deep copy and is available only inside this package.
type Evidence struct {
	provider string
	payload  map[string]any
}

func NewEvidence(provider string, payload map[string]any) (Evidence, error) {
	if !providerPattern.MatchString(provider) || payload == nil || len(payload) > 64 {
		return Evidence{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > maxEvidenceBytes {
		return Evidence{}, ErrInvalid
	}
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return Evidence{}, ErrInvalid
	}
	copyOfPayload, ok := value.(map[string]any)
	if !ok {
		return Evidence{}, ErrInvalid
	}
	return Evidence{provider: provider, payload: copyOfPayload}, nil
}

func (Evidence) String() string   { return "[REDACTED]" }
func (Evidence) GoString() string { return "attestation.Evidence{[REDACTED]}" }

func (evidence Evidence) Provider() string { return evidence.provider }

type Result struct {
	Provider          string
	TrustLevel        string
	VerifiedAt        time.Time
	ExpiresAt         time.Time
	NormalizedSignals map[string]any
	EvidenceHash      [sha256.Size]byte

	bindingHash    [sha256.Size]byte
	appAttestKeyID [sha256.Size]byte
	seal           [sha256.Size]byte
}

func (result Result) validate() error {
	if !providerPattern.MatchString(result.Provider) || !trustLevelPattern.MatchString(result.TrustLevel) || result.VerifiedAt.IsZero() || !result.ExpiresAt.After(result.VerifiedAt) || result.NormalizedSignals == nil || result.EvidenceHash == ([sha256.Size]byte{}) || result.bindingHash == ([sha256.Size]byte{}) {
		return ErrInvalid
	}
	if (result.Provider == appAttestProvider) != (result.appAttestKeyID != ([sha256.Size]byte{})) {
		return ErrInvalid
	}
	encoded, err := json.Marshal(result.NormalizedSignals)
	if err != nil || len(encoded) > 16<<10 {
		return ErrInvalid
	}
	expectedSeal, err := resultSeal(result)
	if err != nil || subtle.ConstantTimeCompare(result.seal[:], expectedSeal[:]) != 1 {
		return ErrInvalid
	}
	return nil
}

func newResult(provider, trustLevel string, verifiedAt, expiresAt time.Time, signals map[string]any, evidenceHash, bindingHash [sha256.Size]byte) (Result, error) {
	return newResultWithAppAttestKeyID(
		provider, trustLevel, verifiedAt, expiresAt, signals, evidenceHash, bindingHash,
		[sha256.Size]byte{},
	)
}

func newResultWithAppAttestKeyID(
	provider, trustLevel string,
	verifiedAt, expiresAt time.Time,
	signals map[string]any,
	evidenceHash, bindingHash, appAttestKeyID [sha256.Size]byte,
) (Result, error) {
	result := Result{
		Provider: provider, TrustLevel: trustLevel, VerifiedAt: verifiedAt.UTC(), ExpiresAt: expiresAt.UTC(),
		NormalizedSignals: signals, EvidenceHash: evidenceHash, bindingHash: bindingHash,
		appAttestKeyID: appAttestKeyID,
	}
	seal, err := resultSeal(result)
	if err != nil {
		return Result{}, ErrInvalid
	}
	result.seal = seal
	if err := result.validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// ValidatedSnapshot verifies that this result was created by an attestation
// verifier for the exact authoritative binding, then returns a deep copy that
// cannot be changed through a caller-owned signals map.
func (result Result) ValidatedSnapshot(expectedBindingHash [sha256.Size]byte, now time.Time) (Result, error) {
	if err := result.validate(); err != nil || now.IsZero() || result.VerifiedAt.After(now.Add(time.Minute)) || !result.ExpiresAt.After(now) || subtle.ConstantTimeCompare(result.bindingHash[:], expectedBindingHash[:]) != 1 {
		return Result{}, ErrInvalid
	}
	encoded, err := json.Marshal(result.NormalizedSignals)
	if err != nil {
		return Result{}, ErrInvalid
	}
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return Result{}, ErrInvalid
	}
	signals, ok := value.(map[string]any)
	if !ok {
		return Result{}, ErrInvalid
	}
	return newResultWithAppAttestKeyID(
		result.Provider, result.TrustLevel, result.VerifiedAt, result.ExpiresAt,
		signals, result.EvidenceHash, result.bindingHash, result.appAttestKeyID,
	)
}

func resultSeal(result Result) ([sha256.Size]byte, error) {
	encodedSignals, err := json.Marshal(result.NormalizedSignals)
	if err != nil || len(encodedSignals) > 16<<10 {
		return [sha256.Size]byte{}, ErrInvalid
	}
	var payload bytes.Buffer
	for _, value := range []string{result.Provider, result.TrustLevel, result.VerifiedAt.UTC().Format(time.RFC3339Nano), result.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		payload.WriteString(value)
		payload.WriteByte(0)
	}
	payload.Write(encodedSignals)
	payload.WriteByte(0)
	payload.Write(result.EvidenceHash[:])
	payload.Write(result.bindingHash[:])
	payload.Write(result.appAttestKeyID[:])
	return sha256.Sum256(payload.Bytes()), nil
}

// Format and LogValue prevent private verifier state and provider evidence
// metadata from being traversed by diagnostic or structured loggers.
func (Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "attestation.Result{[REDACTED]}")
}

func (Result) LogValue() slog.Value {
	return slog.StringValue("attestation.Result{[REDACTED]}")
}

var trustLevelPattern = regexp.MustCompile(`^(none|identity_only|web_risk_verified|app_verified|device_verified|strong_device_verified|debug)$`)

// Verifier authenticates provider evidence against the exact canonical binding.
type Verifier interface {
	ID() string
	Verify(context.Context, Evidence, Binding) (Result, error)
}

func invalid(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return ErrInvalid
	}
	return fmt.Errorf("%w: %s", ErrInvalid, reason)
}
