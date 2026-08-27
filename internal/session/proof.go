package session

import (
	"errors"
	"strings"
)

const maximumDPoPProofBytes = 16 << 10

// DPoPProof is a redacted compact proof credential. Only session trust
// boundaries can reveal it to the RFC 9449 verifier.
type DPoPProof struct {
	value string
}

func NewDPoPProof(value string) (DPoPProof, error) {
	if len(value) < 64 || len(value) > maximumDPoPProofBytes || strings.ContainsAny(value, "\r\n\x00") {
		return DPoPProof{}, errors.New("DPoP proof is invalid")
	}
	return DPoPProof{value: value}, nil
}

func (DPoPProof) String() string   { return "[REDACTED]" }
func (DPoPProof) GoString() string { return "session.DPoPProof{[REDACTED]}" }
