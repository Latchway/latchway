// Package webauthn verifies the two WebAuthn ceremonies Latchway uses for
// administrator passkeys: registering a credential and asserting with it. It
// supports exactly ES256 (P-256 ECDSA with SHA-256), requires user presence
// and user verification, and does not evaluate attestation statements, so
// registration trusts the authenticator data's public key the way the
// "none" attestation conveyance the server requests intends.
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// AlgorithmES256 is the COSE algorithm identifier the server offers.
const AlgorithmES256 = -7

const (
	flagUserPresent       = 0x01
	flagUserVerified      = 0x04
	flagBackupEligible    = 0x08
	flagBackupState       = 0x10
	flagAttestedData      = 0x40
	flagExtensionData     = 0x80
	authenticatorDataBase = 37
	maxCredentialIDBytes  = 1023
	maxClientDataBytes    = 4096
	maxAttestationBytes   = 16 << 10
)

// ErrInvalid covers every malformed or unacceptable ceremony response; callers
// report it generically.
var ErrInvalid = errors.New("webauthn response is invalid")

// RelyingParty is this server as WebAuthn sees it.
type RelyingParty struct {
	// ID is the effective domain, e.g. "console.example.com".
	ID string
	// Origin is the exact web origin the console is served from.
	Origin string
}

// ClientData is the part of clientDataJSON the server checks.
type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	// CrossOrigin is true when the ceremony ran in a cross-origin iframe.
	CrossOrigin bool `json:"crossOrigin"`
}

// ParseClientData decodes clientDataJSON and returns the challenge bytes it
// carries so the caller can look up the stored challenge.
func ParseClientData(clientDataJSON []byte) (ClientData, []byte, error) {
	if len(clientDataJSON) == 0 || len(clientDataJSON) > maxClientDataBytes {
		return ClientData{}, nil, ErrInvalid
	}
	var data ClientData
	if err := json.Unmarshal(clientDataJSON, &data); err != nil {
		return ClientData{}, nil, ErrInvalid
	}
	challenge, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil || len(challenge) < 16 || len(challenge) > 64 {
		return ClientData{}, nil, ErrInvalid
	}
	return data, challenge, nil
}

func checkClientData(rp RelyingParty, data ClientData, wantType string, challenge []byte) error {
	presented, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil || data.Type != wantType || data.Origin != rp.Origin || data.CrossOrigin ||
		subtle.ConstantTimeCompare(presented, challenge) != 1 {
		return ErrInvalid
	}
	return nil
}

// Credential is a verified newly registered passkey.
type Credential struct {
	ID             []byte
	PublicKey      *ecdsa.PublicKey
	SignCount      uint32
	AAGUID         [16]byte
	BackupEligible bool
	BackupState    bool
}

type attestationObjectWire struct {
	Format            string          `cbor:"fmt"`
	Statement         cbor.RawMessage `cbor:"attStmt"`
	AuthenticatorData []byte          `cbor:"authData"`
}

type coseKeyWire struct {
	KeyType   int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Curve     int64  `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

var decodeMode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  8,
		MaxArrayElements: 64,
		MaxMapPairs:      32,
		IndefLength:      cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// VerifyRegistration checks a navigator.credentials.create() response against
// the challenge the server issued and returns the new credential.
func VerifyRegistration(rp RelyingParty, challenge, clientDataJSON, attestationObject []byte) (Credential, error) {
	data, _, err := ParseClientData(clientDataJSON)
	if err != nil {
		return Credential{}, err
	}
	if err := checkClientData(rp, data, "webauthn.create", challenge); err != nil {
		return Credential{}, err
	}
	if len(attestationObject) == 0 || len(attestationObject) > maxAttestationBytes {
		return Credential{}, ErrInvalid
	}
	var object attestationObjectWire
	if err := decodeMode.Unmarshal(attestationObject, &object); err != nil || object.Format == "" || len(object.Format) > 32 {
		return Credential{}, ErrInvalid
	}
	flags, signCount, rest, err := parseAuthenticatorData(rp, object.AuthenticatorData)
	if err != nil {
		return Credential{}, err
	}
	if flags&flagAttestedData == 0 || len(rest) < 18 {
		return Credential{}, ErrInvalid
	}
	credential := Credential{SignCount: signCount, BackupEligible: flags&flagBackupEligible != 0, BackupState: flags&flagBackupState != 0}
	copy(credential.AAGUID[:], rest[:16])
	idLength := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if idLength == 0 || idLength > maxCredentialIDBytes || len(rest) < idLength {
		return Credential{}, ErrInvalid
	}
	credential.ID = append([]byte(nil), rest[:idLength]...)
	rest = rest[idLength:]
	reader := bytes.NewReader(rest)
	var key coseKeyWire
	if err := decodeMode.NewDecoder(reader).Decode(&key); err != nil {
		return Credential{}, ErrInvalid
	}
	if reader.Len() > 0 && flags&flagExtensionData == 0 {
		return Credential{}, ErrInvalid
	}
	publicKey, err := es256PublicKey(key)
	if err != nil {
		return Credential{}, err
	}
	credential.PublicKey = publicKey
	return credential, nil
}

// Assertion is what a verified navigator.credentials.get() response proves.
type Assertion struct {
	SignCount   uint32
	BackupState bool
}

// VerifyAssertion checks a navigator.credentials.get() response for a stored
// credential and the challenge the server issued.
func VerifyAssertion(rp RelyingParty, challenge, clientDataJSON, authenticatorData, signature []byte, publicKey *ecdsa.PublicKey) (Assertion, error) {
	if publicKey == nil || len(signature) == 0 || len(signature) > 80 {
		return Assertion{}, ErrInvalid
	}
	data, _, err := ParseClientData(clientDataJSON)
	if err != nil {
		return Assertion{}, err
	}
	if err := checkClientData(rp, data, "webauthn.get", challenge); err != nil {
		return Assertion{}, err
	}
	flags, signCount, rest, err := parseAuthenticatorData(rp, authenticatorData)
	if err != nil {
		return Assertion{}, err
	}
	if flags&flagAttestedData != 0 || (len(rest) > 0 && flags&flagExtensionData == 0) {
		return Assertion{}, ErrInvalid
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	signed = append(signed, authenticatorData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return Assertion{}, ErrInvalid
	}
	return Assertion{SignCount: signCount, BackupState: flags&flagBackupState != 0}, nil
}

// parseAuthenticatorData checks the RP ID hash and that the user was present
// and verified, and returns the flags, counter and the bytes after them.
func parseAuthenticatorData(rp RelyingParty, authenticatorData []byte) (byte, uint32, []byte, error) {
	if len(authenticatorData) < authenticatorDataBase || len(authenticatorData) > maxAttestationBytes {
		return 0, 0, nil, ErrInvalid
	}
	rpIDHash := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(authenticatorData[:32], rpIDHash[:]) != 1 {
		return 0, 0, nil, ErrInvalid
	}
	flags := authenticatorData[32]
	if flags&flagUserPresent == 0 || flags&flagUserVerified == 0 {
		return 0, 0, nil, ErrInvalid
	}
	if flags&flagBackupState != 0 && flags&flagBackupEligible == 0 {
		return 0, 0, nil, ErrInvalid
	}
	return flags, binary.BigEndian.Uint32(authenticatorData[33:37]), authenticatorData[37:], nil
}

func es256PublicKey(key coseKeyWire) (*ecdsa.PublicKey, error) {
	if key.KeyType != 2 || key.Algorithm != AlgorithmES256 || key.Curve != 1 || len(key.X) != 32 || len(key.Y) != 32 {
		return nil, ErrInvalid
	}
	return PublicKeyFromCoordinates(key.X, key.Y)
}

// PublicKeyFromCoordinates rebuilds a stored P-256 public key and rejects
// points off the curve.
func PublicKeyFromCoordinates(x, y []byte) (*ecdsa.PublicKey, error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, ErrInvalid
	}
	uncompressed := make([]byte, 0, 65)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, x...)
	uncompressed = append(uncompressed, y...)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, ErrInvalid
	}
	return key, nil
}

// Coordinates returns a P-256 key's fixed-width X and Y for storage.
func Coordinates(key *ecdsa.PublicKey) ([]byte, []byte, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, nil, fmt.Errorf("%w: not a P-256 key", ErrInvalid)
	}
	encoded, err := key.Bytes()
	if err != nil || len(encoded) != 65 {
		return nil, nil, ErrInvalid
	}
	return encoded[1:33], encoded[33:65], nil
}
