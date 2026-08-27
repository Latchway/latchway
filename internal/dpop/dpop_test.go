package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_787_820_000, 0)
	target, _ := url.Parse("https://API.Example.com:443/v1/../v1/responses?ignored=yes")
	proof := signProof(t, privateKey, map[string]any{
		"jti": "72f4a1d4-975d-42e3-8f3e-98cf9065681a",
		"htm": "POST",
		"htu": "https://api.example.com/v1/responses",
		"iat": now.Unix(),
		"ath": AccessTokenHash("access-token"),
	})

	result, err := Validate(proof, Options{
		Method:      "POST",
		URI:         target,
		AccessToken: "access-token",
		Now:         now,
	})
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if result.JTI == "" || result.JKT == "" {
		t.Fatalf("incomplete result: %+v", result)
	}
}

func TestValidateRejectsBindingsAndPrivateJWK(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_787_820_000, 0)
	target, _ := url.Parse("https://api.example.com/v1/responses")
	claims := map[string]any{
		"jti": "b337fbda-271f-432d-898d-c223b91e427d",
		"htm": "POST",
		"htu": target.String(),
		"iat": now.Unix(),
		"ath": AccessTokenHash("access-token"),
	}

	t.Run("method", func(t *testing.T) {
		proof := signProof(t, privateKey, claims)
		_, err := Validate(proof, Options{Method: "GET", URI: target, AccessToken: "access-token", Now: now})
		if !IsCode(err, "dpop_invalid") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("access token", func(t *testing.T) {
		proof := signProof(t, privateKey, claims)
		_, err := Validate(proof, Options{Method: "POST", URI: target, AccessToken: "another-token", Now: now})
		if !IsCode(err, "dpop_invalid") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("private jwk", func(t *testing.T) {
		proof := signProofWithJWK(t, privateKey, claims, true)
		_, err := Validate(proof, Options{Method: "POST", URI: target, AccessToken: "access-token", Now: now})
		if !IsCode(err, "dpop_jwk_private") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestNormalizeHTU(t *testing.T) {
	t.Parallel()

	input, _ := url.Parse("HTTPS://Example.COM:443/a/./b/../c/%7euser?q=1#fragment")
	got, err := NormalizeHTU(input)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://example.com/a/c/~user"; got != want {
		t.Fatalf("NormalizeHTU() = %q, want %q", got, want)
	}
}

func TestDecodeUniqueJSONRejectsDuplicates(t *testing.T) {
	t.Parallel()

	if _, err := jsonsafe.Decode([]byte(`{"alg":"ES256","alg":"none"}`)); err == nil {
		t.Fatal("duplicate JSON member accepted")
	}
}

func signProof(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signProofWithJWK(t, key, claims, false)
}

func signProofWithJWK(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any, includePrivate bool) string {
	t.Helper()
	x := key.PublicKey.X.FillBytes(make([]byte, 32))
	y := key.PublicKey.Y.FillBytes(make([]byte, 32))
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
	if includePrivate {
		jwk["d"] = base64.RawURLEncoding.EncodeToString(key.D.FillBytes(make([]byte, 32)))
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	headerSegment := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsSegment := base64.RawURLEncoding.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimsSegment))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + claimsSegment + "." + base64.RawURLEncoding.EncodeToString(signature)
}
