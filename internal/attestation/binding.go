package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
)

var (
	challengeIDPattern = regexp.MustCompile(`^chl_[A-Za-z0-9_-]{16,128}$`)
	applicationPattern = regexp.MustCompile(`^app_[A-Za-z0-9_-]{1,128}$`)
	principalPattern   = regexp.MustCompile(`^usr_[A-Za-z0-9_-]{16,128}$`)
	environmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	platformPattern    = regexp.MustCompile(`^(ios|android|web|react_native_ios|react_native_android|node)$`)
)

// Binding is the version-1 canonical attestation input. The server reconstructs
// every member from authoritative challenge state.
type Binding struct {
	Version        int    `json:"version"`
	ChallengeID    string `json:"challenge_id"`
	ChallengeNonce string `json:"challenge_nonce"`
	ApplicationID  string `json:"application_id"`
	Environment    string `json:"environment"`
	PrincipalID    string `json:"principal_id"`
	DPoPJKT        string `json:"dpop_jkt"`
	Platform       string `json:"platform"`
	IssuedAt       int64  `json:"issued_at"`
}

func (binding Binding) Validate() error {
	if binding.Version != 1 || !challengeIDPattern.MatchString(binding.ChallengeID) || !applicationPattern.MatchString(binding.ApplicationID) || !environmentPattern.MatchString(binding.Environment) || !principalPattern.MatchString(binding.PrincipalID) || !platformPattern.MatchString(binding.Platform) || binding.IssuedAt < 0 || binding.IssuedAt > 253402300799 {
		return invalid("binding fields")
	}
	if err := validateBase64URL(binding.ChallengeNonce, 32, 64); err != nil {
		return invalid("challenge nonce")
	}
	if err := validateBase64URL(binding.DPoPJKT, sha256.Size, sha256.Size); err != nil {
		return invalid("DPoP thumbprint")
	}
	return nil
}

// CanonicalJSON returns the exact RFC 8785/JCS representation. Version-1
// values are ASCII-restricted by schema, so lexical member ordering and the
// integer representation fully determine the canonical bytes.
func (binding Binding) CanonicalJSON() ([]byte, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Grow(512)
	output.WriteString(`{"application_id":"`)
	output.WriteString(binding.ApplicationID)
	output.WriteString(`","challenge_id":"`)
	output.WriteString(binding.ChallengeID)
	output.WriteString(`","challenge_nonce":"`)
	output.WriteString(binding.ChallengeNonce)
	output.WriteString(`","dpop_jkt":"`)
	output.WriteString(binding.DPoPJKT)
	output.WriteString(`","environment":"`)
	output.WriteString(binding.Environment)
	output.WriteString(`","issued_at":`)
	output.WriteString(strconv.FormatInt(binding.IssuedAt, 10))
	output.WriteString(`,"platform":"`)
	output.WriteString(binding.Platform)
	output.WriteString(`","principal_id":"`)
	output.WriteString(binding.PrincipalID)
	output.WriteString(`","version":1}`)
	return output.Bytes(), nil
}

func (binding Binding) Hash() ([sha256.Size]byte, error) {
	canonical, err := binding.CanonicalJSON()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func (binding Binding) HashBase64URL() (string, error) {
	hash, err := binding.Hash()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func validateBase64URL(value string, minimumBytes, maximumBytes int) error {
	if value == "" || bytes.ContainsRune([]byte(value), '=') || len(value) > base64.RawURLEncoding.EncodedLen(maximumBytes) {
		return errors.New("invalid base64url")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < minimumBytes || len(decoded) > maximumBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("invalid base64url")
	}
	return nil
}
