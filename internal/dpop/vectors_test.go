package dpop

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
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
	f.Add("not-a-proof")
	f.Add("e30.e30.AA")
	f.Fuzz(func(t *testing.T, proof string) {
		_, _ = Validate(proof, Options{Method: "POST", URI: target, Now: time.Unix(1700000030, 0)})
	})
}
