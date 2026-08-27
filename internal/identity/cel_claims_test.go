package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCELClaimMapperEvaluatesNormalizedProjection(t *testing.T) {
	t.Parallel()

	mapper, err := NewCELClaimMapper(map[string]string{
		"active": "claims.enabled && claims.score >= 2",
		"label":  "claims.profile.plan + '-member'",
		"plan":   "claims.profile.plan",
		"roles":  "claims.roles.filter(role, role != 'blocked')",
		"score":  "claims.score + 1",
	})
	if err != nil {
		t.Fatalf("NewCELClaimMapper() error = %v", err)
	}
	claims := map[string]any{
		"enabled": true,
		"profile": map[string]any{"plan": "pro", "unmapped": "private"},
		"roles":   []any{"reader", "blocked", "writer"},
		"score":   json.Number("2"),
	}
	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("Map() error = %v", err)
	}
	if result["active"] != true || result["label"] != "pro-member" || result["plan"] != "pro" || result["score"] != json.Number("3") {
		t.Fatalf("normalized projection = %#v", result)
	}
	roles, ok := result["roles"].([]any)
	if !ok || len(roles) != 2 || roles[0] != "reader" || roles[1] != "writer" {
		t.Fatalf("normalized roles = %#v", result["roles"])
	}
	if _, leaked := result["unmapped"]; leaked {
		t.Fatal("unmapped claim entered the normalized projection")
	}
	roles[0] = "changed"
	if claims["roles"].([]any)[0] != "reader" {
		t.Fatal("mapped result aliases the credential claims")
	}
}

func TestCELClaimMapperRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mappings map[string]string
	}{
		{name: "invalid normalized name", mappings: map[string]string{"Plan": "claims.plan"}},
		{name: "invalid expression", mappings: map[string]string{"plan": "claims.["}},
		{name: "oversized expression", mappings: map[string]string{"plan": strings.Repeat(" ", 4097) + "claims.plan"}},
		{name: "known object result", mappings: map[string]string{"plan": "{'value': claims.plan}"}},
		{name: "known timestamp result", mappings: map[string]string{"plan": "timestamp('2026-08-27T00:00:00Z')"}},
	}
	tooMany := make(map[string]string, maximumCELClaimMappings+1)
	for index := 0; index <= maximumCELClaimMappings; index++ {
		tooMany["claim_"+string(rune('a'+index))] = "true"
	}
	tests = append(tests, struct {
		name     string
		mappings map[string]string
	}{name: "too many mappings", mappings: tooMany})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCELClaimMapper(test.mappings); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if mapper, err := NewCELClaimMapper(nil); err != nil || mapper == nil {
		t.Fatalf("empty mapper = %#v, %v", mapper, err)
	}
}

func TestCELClaimMapperRejectsUnsafeEvaluationResults(t *testing.T) {
	t.Parallel()

	largeValues := make([]any, 65)
	for index := range largeValues {
		largeValues[index] = index
	}
	tests := []struct {
		name       string
		expression string
		claims     map[string]any
	}{
		{name: "missing claim", expression: "claims.missing", claims: map[string]any{}},
		{name: "object result", expression: "claims.profile", claims: map[string]any{"profile": map[string]any{"plan": "pro"}}},
		{name: "nested list", expression: "claims.values", claims: map[string]any{"values": []any{[]any{"nested"}}}},
		{name: "oversized string", expression: "claims.value", claims: map[string]any{"value": strings.Repeat("x", 2049)}},
		{name: "oversized list", expression: "claims.values", claims: map[string]any{"values": largeValues}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapper, err := NewCELClaimMapper(map[string]string{"value": test.expression})
			if err != nil {
				t.Fatalf("construct mapper: %v", err)
			}
			if _, err := mapper.Map(test.claims); !errors.Is(err, ErrCredentialInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCELClaimMapperEnforcesRuntimeCostLimit(t *testing.T) {
	t.Parallel()

	mapper, err := NewCELClaimMapper(map[string]string{
		"found": "claims.values.exists(x, claims.values.exists(y, x + y == -1))",
	})
	if err != nil {
		t.Fatalf("construct mapper: %v", err)
	}
	values := make([]any, 128)
	for index := range values {
		values[index] = index
	}
	if _, err := mapper.Map(map[string]any{"values": values}); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("runtime-cost overflow error = %v", err)
	}
}

func TestCELClaimMapperIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	mapper, err := NewCELClaimMapper(map[string]string{"plan": "claims.plan"})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, mapErr := mapper.Map(map[string]any{"plan": "pro"})
			if mapErr != nil {
				errorsSeen <- mapErr
				return
			}
			if result["plan"] != "pro" {
				errorsSeen <- ErrCredentialInvalid
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent Map() error = %v", err)
	}
}
