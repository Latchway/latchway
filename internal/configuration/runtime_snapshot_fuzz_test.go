package configuration

import (
	"bytes"
	"testing"
	"time"
)

func FuzzActiveSnapshotCompilation(f *testing.F) {
	validator, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	source := []byte(`{
		"apiVersion":"latchway.dev/v1alpha1",
		"kind":"EnvironmentConfig",
		"metadata":{"organization":"example","application":"habits","environment":"production"},
		"spec":{
			"identityProviders":[{"id":"firebase","type":"firebase","projectId":"habits-production"}],
			"attestationPolicies":[{"id":"native","platforms":{"ios":{"provider":"app_attest","mode":"required"}}}],
			"upstreams":[{"id":"primary","type":"openai_compatible","baseUrl":"https://api.example.test/v1","authentication":{"type":"none"}}],
			"models":[{"id":"fast","upstream":"primary","upstreamModel":"physical-fast"}],
			"limitPlans":[{"id":"free","limits":[{"metric":"logical_requests","scope":["user","feature"],"window":"1d","maximum":5}]}],
			"features":[{"id":"assistant","protocol":"openai_chat","attestationPolicy":"native","access":{"expression":"principal.authenticated"},"limitPlan":{"expression":"'free'"},"output":{"defaultMaximumTokens":100,"absoluteMaximumTokens":200},"routes":[{"id":"primary","when":"true","model":"fast","priority":1}]}]
		}
	}`)
	report, compiled := validator.Validate(source, testEnvironment(), time.Unix(0, 0).UTC())
	if !report.Valid {
		f.Fatalf("seed configuration rejected: %+v", report.Issues)
	}
	f.Add([]byte(compiled))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"spec":{"features":[]}}`))

	f.Fuzz(func(t *testing.T, candidate []byte) {
		if len(candidate) > 1<<20 {
			t.Skip()
		}
		snapshot, snapshotErr := newActiveSnapshot(
			"rev_00000000000000000000000000",
			"env_00000000000000000000000000",
			source,
			candidate,
		)
		if snapshotErr != nil {
			return
		}
		first := snapshot.CompiledJSON()
		if len(first) == 0 {
			t.Fatal("accepted snapshot has empty compiled document")
		}
		first[0] ^= 0xff
		if bytes.Equal(first, snapshot.CompiledJSON()) {
			t.Fatal("compiled snapshot aliases returned bytes")
		}
	})
}
