package adminauth

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA-1, which authenticator apps require.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	totpSecretBytes = 20
	totpPeriod      = 30
	totpDigits      = 6
	// totpSkew accepts one period either side for clock drift.
	totpSkew = 1
	// recoveryCodeCount is how many single-use recovery codes an enrollment issues.
	recoveryCodeCount = 10
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// TOTPSecret is a new authenticator key. It is shown once during enrollment.
type TOTPSecret struct {
	raw []byte
}

// NewTOTPSecret draws a 160-bit authenticator key.
func NewTOTPSecret(random io.Reader) (TOTPSecret, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return TOTPSecret{}, fmt.Errorf("generate authenticator key: %w", err)
	}
	return TOTPSecret{raw: raw}, nil
}

// TOTPSecretFromBytes wraps a stored key.
func TOTPSecretFromBytes(raw []byte) TOTPSecret {
	return TOTPSecret{raw: raw}
}

// Bytes returns the raw key for sealing.
func (secret TOTPSecret) Bytes() []byte {
	return secret.raw
}

// Base32 is the key as authenticator apps accept it for manual entry.
func (secret TOTPSecret) Base32() string {
	return base32NoPadding.EncodeToString(secret.raw)
}

// URI is the otpauth:// enrollment link an authenticator app reads.
func (secret TOTPSecret) URI(issuer, account string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	query := url.Values{
		"secret": {secret.Base32()}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(totpDigits)}, "period": {fmt.Sprint(totpPeriod)},
	}
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// Format keeps the key out of logs and error strings.
func (TOTPSecret) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func totpCode(raw []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// MatchTOTP returns the time step a code belongs to when it is valid now within
// the allowed skew. Callers must reject a step at or before the last one used.
func MatchTOTP(secret TOTPSecret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpPeriod
	var matched int64
	found := 0
	for offset := int64(-totpSkew); offset <= totpSkew; offset++ {
		step := current + offset
		if subtle.ConstantTimeCompare([]byte(totpCode(secret.raw, step)), []byte(code)) == 1 {
			matched = step
			found = 1
		}
	}
	return matched, found == 1
}

const recoveryCodeAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes draws single-use recovery codes like "k7m2-9qpx-3hfa", each
// with about 59 bits of entropy.
func NewRecoveryCodes(random io.Reader) ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		raw := make([]byte, 12)
		if _, err := io.ReadFull(random, raw); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		var builder strings.Builder
		for index, value := range raw {
			if index > 0 && index%4 == 0 {
				builder.WriteByte('-')
			}
			builder.WriteByte(recoveryCodeAlphabet[int(value)%len(recoveryCodeAlphabet)])
		}
		codes = append(codes, builder.String())
	}
	return codes, nil
}

// HashRecoveryCode normalizes and hashes a recovery code for storage and
// lookup. Codes are high-entropy, so a fast domain-separated hash suffices.
func HashRecoveryCode(code string) [sha256.Size]byte {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	return sha256.Sum256([]byte("latchway/admin/recovery-code/v1\x00" + normalized))
}
