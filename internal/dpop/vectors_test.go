package dpop

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormativeDPoPVectors(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "api", "test-vectors", "dpop", "v1.json"))
	if err != nil {
		t.Fatalf("read DPoP vectors: %v", err)
	}
	var fixture struct {
		ReferenceTime      int64     `json:"reference_time"`
		FixtureAccessToken string    `json:"fixture_access_token"`
		Thumbprint         string    `json:"jwk_thumbprint_sha256_base64url"`
		PublicJWK          PublicJWK `json:"public_jwk"`
		Vectors            []struct {
			ID      string `json:"id"`
			Proof   string `json:"proof"`
			Request struct {
				Method                string `json:"method"`
				URI                   string `json:"uri"`
				UseFixtureAccessToken bool   `json:"use_fixture_access_token"`
				RequiredNonce         string `json:"required_nonce"`
				ProofJTIAlreadySeen   bool   `json:"proof_jti_already_seen"`
			} `json:"request"`
			Expected struct {
				Valid     bool   `json:"valid"`
				ErrorCode string `json:"error_code"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatalf("decode DPoP vectors: %v", err)
	}
	thumbprint, err := fixture.PublicJWK.Thumbprint()
	if err != nil || thumbprint != fixture.Thumbprint {
		t.Fatalf("fixture thumbprint mismatch: %q, %v", thumbprint, err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			requestURI, err := url.Parse(vector.Request.URI)
			if err != nil {
				t.Fatalf("parse vector URI: %v", err)
			}
			accessToken := ""
			if vector.Request.UseFixtureAccessToken {
				accessToken = fixture.FixtureAccessToken
			}
			result, err := Validate(vector.Proof, Options{
				Method: vector.Request.Method, URI: requestURI, AccessToken: accessToken,
				ExpectedNonce: vector.Request.RequiredNonce, Now: time.Unix(fixture.ReferenceTime, 0),
			})
			if vector.Request.ProofJTIAlreadySeen {
				// Replay insertion is a database operation layered after proof
				// validation; this vector still must be cryptographically valid.
				if err != nil || result.JTI == "" {
					t.Fatalf("replay fixture proof did not validate before replay storage: %v", err)
				}
				return
			}
			if vector.Expected.Valid {
				if err != nil || result.JKT != fixture.Thumbprint {
					t.Fatalf("valid vector rejected: result=%+v err=%v", result, err)
				}
				return
			}
			if err == nil || !IsCode(err, vector.Expected.ErrorCode) {
				t.Fatalf("invalid vector error=%v, want code %q", err, vector.Expected.ErrorCode)
			}
		})
	}
}

func FuzzValidate(f *testing.F) {
	target, _ := url.Parse("https://gateway.example.test/client/v1/session-challenges")
	contents, err := os.ReadFile(filepath.Join("..", "..", "api", "test-vectors", "dpop", "v1.json"))
	if err != nil {
		f.Fatalf("read DPoP fuzz seeds: %v", err)
	}
	var fixture struct {
		Vectors []struct {
			ID    string `json:"id"`
			Proof string `json:"proof"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		f.Fatalf("decode DPoP fuzz seeds: %v", err)
	}
	for _, vector := range fixture.Vectors {
		if vector.ID == "valid_session_challenge" {
			f.Add(vector.Proof)
		}
	}
	f.Add(signProof(f, fixedDPoPFuzzKey(f), map[string]any{
		"jti": "escaped\ncontrol",
		"htm": "POST",
		"htu": target.String(),
		"iat": int64(1700000000),
	}))
	f.Add("not-a-proof")
	f.Add("e30.e30.AA")
	f.Fuzz(func(t *testing.T, proof string) {
		options := Options{Method: "POST", URI: target, Now: time.Unix(1700000030, 0)}
		result, err := Validate(proof, options)
		if err != nil {
			if !IsCode(err, "dpop_invalid") {
				t.Fatalf("proof parser returned an unsafe error for untrusted input: %v", err)
			}
			return
		}
		if !validJTI(result.JTI) || result.JKT == "" {
			t.Fatalf("validated proof returned incomplete bounded identifiers: %+v", result)
		}
		if result.IssuedAt.After(options.Now.Add(defaultSkew)) || result.IssuedAt.Before(options.Now.Add(-defaultMaxAge-defaultSkew)) {
			t.Fatalf("validated proof escaped its acceptance window: %s", result.IssuedAt)
		}
		if len(result.Nonce) > 512 || strings.ContainsAny(result.Nonce, "\r\n\x00") {
			t.Fatalf("validated proof returned an unsafe nonce: %q", result.Nonce)
		}
		thumbprint, err := result.JWK.Thumbprint()
		if err != nil || thumbprint != result.JKT {
			t.Fatalf("validated proof JWK/thumbprint mismatch: thumbprint=%q result=%+v err=%v", thumbprint, result, err)
		}
		resultAgain, err := Validate(proof, options)
		if err != nil || resultAgain != result {
			t.Fatalf("proof validation is not deterministic: result=%+v err=%v", resultAgain, err)
		}
		if _, err := Validate(proof+"=", options); !IsCode(err, "dpop_invalid") {
			t.Fatalf("proof parser accepted a padded mutation: %v", err)
		}
	})
}
