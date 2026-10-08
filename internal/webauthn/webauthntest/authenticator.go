// Package webauthntest is a software passkey authenticator for tests. It
// produces genuine ES256 registration and assertion responses.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator holds one passkey.
type Authenticator struct {
	RPID         string
	Origin       string
	CredentialID []byte
	UserHandle   []byte
	Key          *ecdsa.PrivateKey
	Counter      uint32
	// Flags overrides the authenticator-data flags when non-zero.
	Flags byte
}

// New creates a passkey for an RP and origin.
func New(rpID, origin string) (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &Authenticator{RPID: rpID, Origin: origin, CredentialID: id, Key: key}, nil
}

// ClientData encodes clientDataJSON for a ceremony.
func (a *Authenticator) ClientData(kind string, challenge []byte) []byte {
	encoded, _ := json.Marshal(map[string]any{
		"type": kind, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": a.Origin, "crossOrigin": false,
	})
	return encoded
}

func (a *Authenticator) authenticatorData(flags byte, attested []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(a.RPID))
	if a.Flags != 0 {
		flags = a.Flags
	}
	data := append([]byte(nil), rpIDHash[:]...)
	data = append(data, flags)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], a.Counter)
	data = append(data, counter[:]...)
	return append(data, attested...)
}

// Register answers navigator.credentials.create() for the challenge.
func (a *Authenticator) Register(challenge []byte) (clientDataJSON, attestationObject []byte) {
	encodedKey, _ := a.Key.PublicKey.Bytes()
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: encodedKey[1:33], -3: encodedKey[33:65]})
	attested := make([]byte, 16)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(a.CredentialID)))
	attested = append(attested, length[:]...)
	attested = append(attested, a.CredentialID...)
	attested = append(attested, cose...)
	authData := a.authenticatorData(0x01|0x04|0x08|0x10|0x40, attested)
	object, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	return a.ClientData("webauthn.create", challenge), object
}

// Assert answers navigator.credentials.get() for the challenge.
func (a *Authenticator) Assert(challenge []byte) (clientDataJSON, authenticatorData, signature []byte) {
	a.Counter++
	clientDataJSON = a.ClientData("webauthn.get", challenge)
	authenticatorData = a.authenticatorData(0x01|0x04|0x08|0x10, nil)
	clientDataHash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(append([]byte(nil), authenticatorData...), clientDataHash[:]...))
	signature, _ = ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	return clientDataJSON, authenticatorData, signature
}
