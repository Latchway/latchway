package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBindingMatchesNormativeVectors(t *testing.T) {
	files := []string{
		filepath.Join("attestation-binding", "v1.json"),
		filepath.Join("component-attestation-binding", "v2.json"),
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			testBindingVectorFile(t, file)
		})
	}
}

func testBindingVectorFile(t *testing.T, file string) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "api", "test-vectors", file))
	if err != nil {
		t.Fatalf("read attestation-binding vectors: %v", err)
	}
	var vectors struct {
		Vectors []struct {
			ID            string  `json:"id"`
			Input         Binding `json:"input"`
			CanonicalJSON string  `json:"canonical_json"`
			SHA256Hex     string  `json:"sha256_hex"`
			SHA256Base64  string  `json:"sha256_base64url"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatalf("decode attestation-binding vectors: %v", err)
	}
	if len(vectors.Vectors) == 0 {
		t.Fatal("attestation-binding vector set is empty")
	}
	for _, vector := range vectors.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			canonical, err := vector.Input.CanonicalJSON()
			if err != nil {
				t.Fatalf("canonicalize binding: %v", err)
			}
			if string(canonical) != vector.CanonicalJSON {
				t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", canonical, vector.CanonicalJSON)
			}
			hash, err := vector.Input.Hash()
			if err != nil {
				t.Fatalf("hash binding: %v", err)
			}
			if hex.EncodeToString(hash[:]) != vector.SHA256Hex {
				t.Fatalf("SHA-256 mismatch: %x != %s", hash, vector.SHA256Hex)
			}
			encoded, err := vector.Input.HashBase64URL()
			if err != nil || encoded != vector.SHA256Base64 {
				t.Fatalf("base64url hash mismatch: %q, %v", encoded, err)
			}
		})
	}
}

func TestBindingRejectsNonCanonicalOrOutOfRangeFields(t *testing.T) {
	valid := testBinding()
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "version", mutate: func(value *Binding) { value.Version = 3 }},
		{name: "challenge ID", mutate: func(value *Binding) { value.ChallengeID = "chl_short" }},
		{name: "padded nonce", mutate: func(value *Binding) { value.ChallengeNonce += "=" }},
		{name: "short nonce", mutate: func(value *Binding) { value.ChallengeNonce = "AA" }},
		{name: "application", mutate: func(value *Binding) { value.ApplicationID = `app_bad"value` }},
		{name: "environment", mutate: func(value *Binding) { value.Environment = "Production" }},
		{name: "principal", mutate: func(value *Binding) { value.PrincipalID = "usr_short" }},
		{name: "thumbprint", mutate: func(value *Binding) { value.DPoPJKT = "not-a-thumbprint" }},
		{name: "platform", mutate: func(value *Binding) { value.Platform = "desktop" }},
		{name: "issued at", mutate: func(value *Binding) { value.IssuedAt = 253402300800 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := valid
			test.mutate(&binding)
			if _, err := binding.CanonicalJSON(); err == nil {
				t.Fatal("invalid binding was canonicalized")
			}
		})
	}
}

func TestComponentBindingRejectsMissingOrCrossScopedMembers(t *testing.T) {
	valid := testComponentBinding()
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "purpose", mutate: func(value *Binding) { value.Purpose = "root_session" }},
		{name: "family", mutate: func(value *Binding) { value.InstallationFamilyID = "" }},
		{name: "component", mutate: func(value *Binding) { value.ClientComponentID = "cmp_short" }},
		{name: "definition", mutate: func(value *Binding) { value.ComponentDefinitionID = "Action" }},
		{name: "component key", mutate: func(value *Binding) { value.ComponentKeyID = "cky_short" }},
		{name: "unsupported platform", mutate: func(value *Binding) { value.Platform = "android" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := valid
			test.mutate(&binding)
			if _, err := binding.CanonicalJSON(); err == nil {
				t.Fatal("invalid component binding was canonicalized")
			}
		})
	}
}

func FuzzBindingCanonicalJSON(f *testing.F) {
	seed := testBinding()
	f.Add(seed.ChallengeNonce, seed.Environment, seed.IssuedAt)
	f.Fuzz(func(t *testing.T, nonce, environment string, issuedAt int64) {
		binding := seed
		binding.ChallengeNonce = nonce
		binding.Environment = environment
		binding.IssuedAt = issuedAt
		canonical, err := binding.CanonicalJSON()
		if err != nil {
			return
		}
		if len(canonical) > 1024 || sha256.Sum256(canonical) == ([sha256.Size]byte{}) {
			t.Fatal("valid canonical binding has invalid output")
		}
	})
}

func testBinding() Binding {
	return Binding{
		Version: 1, ChallengeID: "chl_01J00000000000000000000000",
		ChallengeNonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		ApplicationID:  "app_habitify", Environment: "production",
		PrincipalID: "usr_01J00000000000000000000000",
		DPoPJKT:     "bX0yCl562RPdpf8cJHVLBeUXu6PWExYJ0w-Bydre3q8",
		Platform:    "ios", IssuedAt: 1787820000,
	}
}

func testComponentBinding() Binding {
	return Binding{
		Version: 2, Purpose: "component_attestation_step_up",
		ChallengeID:    "chl_01J00000000000000000000003",
		ChallengeNonce: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
		ApplicationID:  "app_habitify", Environment: "production",
		PrincipalID:           "usr_01J00000000000000000000000",
		InstallationFamilyID:  "fam_01J00000000000000000000000",
		ClientComponentID:     "cmp_01J00000000000000000000003",
		ComponentDefinitionID: "action_extension",
		ComponentKeyID:        "cky_01J00000000000000000000003",
		DPoPJKT:               "bX0yCl562RPdpf8cJHVLBeUXu6PWExYJ0w-Bydre3q8",
		Platform:              "ios", IssuedAt: 1787820003,
	}
}
