// Package attestation binds provider evidence to a verified identity, one-time
// challenge, and installation DPoP key without treating attestation as identity.
package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
}

func (result Result) validate() error {
	if !providerPattern.MatchString(result.Provider) || !trustLevelPattern.MatchString(result.TrustLevel) || result.VerifiedAt.IsZero() || !result.ExpiresAt.After(result.VerifiedAt) || result.NormalizedSignals == nil {
		return ErrInvalid
	}
	encoded, err := json.Marshal(result.NormalizedSignals)
	if err != nil || len(encoded) > 16<<10 {
		return ErrInvalid
	}
	return nil
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
