package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/latchway/latchway/internal/id"
)

const subjectHMACDomain = "latchway/external-subject/v1"

// SubjectProtector creates application- and provider-scoped deterministic
// lookup values without retaining external subjects. The master key should be
// resolved from the configured secret source, never from client input.
type SubjectProtector struct {
	master []byte
}

type SubjectPseudonym struct {
	IssuerHash  [sha256.Size]byte
	SubjectHMAC [sha256.Size]byte
}

func NewSubjectProtector(master []byte) (*SubjectProtector, error) {
	if len(master) < 32 || len(master) > 4096 {
		return nil, fmt.Errorf("%w: external-subject HMAC key", ErrConfiguration)
	}
	copyOfMaster := append([]byte(nil), master...)
	return &SubjectProtector{master: copyOfMaster}, nil
}

// Pseudonymize returns an issuer digest and a keyed subject lookup value. The
// provider-specific HMAC key prevents correlation across applications and
// provider configurations even when both see the same issuer and subject.
func (protector *SubjectProtector) Pseudonymize(applicationID, providerID, issuer, subject string) (SubjectPseudonym, error) {
	if protector == nil || id.Validate(applicationID, id.Application) != nil || !providerIDPattern.MatchString(providerID) || issuer == "" || len(issuer) > 2048 || subject == "" || len(subject) > 2048 || strings.ContainsAny(issuer+subject, "\x00\r\n") {
		return SubjectPseudonym{}, ErrCredentialInvalid
	}
	deriver := hmac.New(sha256.New, protector.master)
	writeLengthPrefixed(deriver, subjectHMACDomain)
	writeLengthPrefixed(deriver, applicationID)
	writeLengthPrefixed(deriver, providerID)
	derivedKey := deriver.Sum(nil)

	subjectMAC := hmac.New(sha256.New, derivedKey)
	writeLengthPrefixed(subjectMAC, issuer)
	writeLengthPrefixed(subjectMAC, subject)
	var result SubjectPseudonym
	result.IssuerHash = sha256.Sum256([]byte(issuer))
	copy(result.SubjectHMAC[:], subjectMAC.Sum(nil))
	return result, nil
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeLengthPrefixed(writer hashWriter, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func advisoryLockKey(pseudonym SubjectPseudonym) int64 {
	return int64(binary.BigEndian.Uint64(pseudonym.SubjectHMAC[:8]))
}
