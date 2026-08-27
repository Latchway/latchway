package dpop

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func FuzzParsePublicJWK(f *testing.F) {
	curve := elliptic.P256()
	valid := PublicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(curve.Params().Gx.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(curve.Params().Gy.FillBytes(make([]byte, 32))),
	}
	validJSON, err := json.Marshal(valid)
	if err != nil {
		f.Fatalf("marshal valid JWK seed: %v", err)
	}
	f.Add(string(validJSON))
	f.Add(`{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"first","x":"second","y":"value"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"value","y":"value","d":"private"}`)
	f.Add(`{"kty":"RSA","crv":"P-256","x":"value","y":"value"}`)
	f.Add(`null`)
	f.Add(`not-json`)

	f.Fuzz(func(t *testing.T, raw string) {
		// The production proof envelope is capped at maxProofBytes. Keeping this
		// direct parser target under the same cap makes each fuzz iteration
		// representative and bounded.
		if len(raw) > maxProofBytes {
			return
		}
		decoded, err := jsonsafe.Decode([]byte(raw))
		if err != nil {
			return
		}
		values, ok := decoded.(map[string]any)
		if !ok {
			return
		}
		jwk, err := parsePublicJWK(values)
		if err != nil {
			return
		}

		if len(values) != 4 || jwk.Kty != "EC" || jwk.Crv != "P-256" {
			t.Fatalf("JWK parser accepted members outside the public P-256 profile: %#v", values)
		}
		for _, coordinate := range []string{jwk.X, jwk.Y} {
			decodedCoordinate, decodeErr := base64.RawURLEncoding.Strict().DecodeString(coordinate)
			if decodeErr != nil || len(decodedCoordinate) != 32 || base64.RawURLEncoding.EncodeToString(decodedCoordinate) != coordinate {
				t.Fatalf("JWK parser accepted a non-canonical coordinate %q", coordinate)
			}
		}
		publicKey, err := jwk.PublicKey()
		if err != nil || publicKey == nil {
			t.Fatalf("accepted JWK did not produce a public key: key=%#v err=%v", publicKey, err)
		}
		if publicKey.Curve.Params().Name != curve.Params().Name || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
			t.Fatalf("accepted JWK did not produce a P-256 public key: key=%#v err=%v", publicKey, err)
		}
		thumbprint, err := jwk.Thumbprint()
		if err != nil {
			t.Fatalf("accepted JWK did not produce a thumbprint: %v", err)
		}
		thumbprintBytes, err := base64.RawURLEncoding.Strict().DecodeString(thumbprint)
		if err != nil || len(thumbprintBytes) != 32 || base64.RawURLEncoding.EncodeToString(thumbprintBytes) != thumbprint {
			t.Fatalf("accepted JWK produced a non-canonical thumbprint %q", thumbprint)
		}
		thumbprintAgain, err := jwk.Thumbprint()
		if err != nil || thumbprintAgain != thumbprint {
			t.Fatalf("JWK thumbprint is not deterministic: %q, %v", thumbprintAgain, err)
		}

		withPrivateMember := cloneJWKMembers(values)
		withPrivateMember["d"] = "private-key-material"
		if _, err := parsePublicJWK(withPrivateMember); err == nil {
			t.Fatal("JWK parser accepted a private key member")
		}
		withRemoteMetadata := cloneJWKMembers(values)
		withRemoteMetadata["jku"] = "https://attacker.invalid/jwks"
		if _, err := parsePublicJWK(withRemoteMetadata); err == nil {
			t.Fatal("JWK parser accepted remote key metadata")
		}
	})
}

func FuzzNormalizeHTU(f *testing.F) {
	for _, seed := range []string{
		"https://gateway.example.test/client/v1/sessions",
		"HTTPS://Example.COM:443/a/./b/../c/%7euser?q=ignored#fragment",
		"http://LOCALHOST:80",
		"http://127.0.0.1:8080/a/%2f/b",
		"https://[2001:db8::1]:443/a/../b",
		"https://[fe80::1%25en0]/",
		"https://user@example.test/private",
		"https://example.test:0/",
		"https://example.test/%zz",
		"https://éxample.test/",
		"ftp://example.test/resource",
		"relative/path",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxProofBytes {
			return
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return
		}
		normalized, err := NormalizeHTU(parsed)
		if err != nil {
			return
		}
		if normalized == "" {
			t.Fatal("HTU normalization returned an empty successful result")
		}

		canonical, err := url.Parse(normalized)
		if err != nil || canonical.String() != normalized {
			t.Fatalf("HTU normalization produced an unparsable or non-canonical URI %q: %v", normalized, err)
		}
		if canonical.User != nil || canonical.RawQuery != "" || canonical.ForceQuery || canonical.Fragment != "" || canonical.Scheme == "" || canonical.Host == "" {
			t.Fatalf("HTU normalization retained a forbidden URI component: %#v", canonical)
		}
		if canonical.Scheme != strings.ToLower(canonical.Scheme) || (canonical.Scheme != "http" && canonical.Scheme != "https") || !isASCII(canonical.Hostname()) {
			t.Fatalf("HTU normalization produced an unsafe scheme or hostname: %q", normalized)
		}
		if (canonical.Scheme == "http" && canonical.Port() == "80") || (canonical.Scheme == "https" && canonical.Port() == "443") {
			t.Fatalf("HTU normalization retained a default port: %q", normalized)
		}
		normalizedAgain, err := NormalizeHTU(canonical)
		if err != nil || normalizedAgain != normalized {
			t.Fatalf("HTU normalization is not idempotent: first=%q second=%q err=%v", normalized, normalizedAgain, err)
		}

		withIgnoredComponents := *parsed
		withIgnoredComponents.RawQuery = "ignored=true"
		withIgnoredComponents.ForceQuery = true
		withIgnoredComponents.Fragment = "ignored"
		withoutQueryOrFragment, err := NormalizeHTU(&withIgnoredComponents)
		if err != nil || withoutQueryOrFragment != normalized {
			t.Fatalf("HTU query/fragment removal is unstable: first=%q second=%q err=%v", normalized, withoutQueryOrFragment, err)
		}
	})
}

func cloneJWKMembers(values map[string]any) map[string]any {
	cloned := make(map[string]any, len(values)+1)
	for name, value := range values {
		cloned[name] = value
	}
	return cloned
}
