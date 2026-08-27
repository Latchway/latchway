package attestation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const maxDebugPublicKeySetBytes = 64 << 10

// ParseDebugPublicKeys decodes the strict, versioned public-key document held
// by a debug attestation secret. Only Ed25519 public keys are accepted; private
// keys, ambiguous JSON, duplicate IDs, and unknown members fail closed.
//
// The version-1 document is:
//
//	{"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"<base64url>"}]}
func ParseDebugPublicKeys(input []byte) (map[string]ed25519.PublicKey, error) {
	if len(input) == 0 || len(input) > maxDebugPublicKeySetBytes {
		return nil, ErrConfiguration
	}
	value, err := jsonsafe.Decode(input)
	if err != nil {
		return nil, ErrConfiguration
	}
	document, ok := value.(map[string]any)
	if !ok || len(document) != 2 || document["version"] != json.Number("1") {
		return nil, ErrConfiguration
	}
	entries, ok := document["keys"].([]any)
	if !ok || len(entries) == 0 || len(entries) > 16 {
		return nil, ErrConfiguration
	}
	keys := make(map[string]ed25519.PublicKey, len(entries))
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]any)
		if !ok || len(entry) != 2 {
			return nil, ErrConfiguration
		}
		keyID, idOK := entry["key_id"].(string)
		encoded, keyOK := entry["public_key"].(string)
		if !idOK || !debugKeyIDPattern.MatchString(keyID) || !keyOK {
			return nil, ErrConfiguration
		}
		publicKey, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != encoded {
			return nil, ErrConfiguration
		}
		if _, duplicate := keys[keyID]; duplicate {
			return nil, ErrConfiguration
		}
		keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return keys, nil
}
