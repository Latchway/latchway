package dataplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
)

func TestChatSchemaPreflightPassesGatewayValidation(t *testing.T) {
	t.Parallel()
	profile := protocol.TrustedInputProfile{
		ID: "chat_profile", Protocol: protocol.OpenAIChatID,
		Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel: "physical", MaximumFramingTokensPerRequest: 1024,
		MaximumFramingTokensPerMessage: 128, MaximumContextTokens: 100000,
	}
	decision := policy.Decision{Feature: configuration.Feature{Protocol: profile.Protocol}, Model: configuration.Model{UpstreamModel: profile.PhysicalModel}}
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(`{"model":"physical","max_tokens":1024,"messages":[{"role":"user","content":"Weather?"}],"tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]}`))
	request.Header.Set("Content-Type", "application/json")
	preflight, err := (openaichat.Adapter{}).PreflightInput(context.Background(), request, profile)
	if err != nil {
		t.Fatal(err)
	}
	if preflight.ExpandedSchemaBytes <= 0 {
		t.Fatal("schema overhead not reserved")
	}
	if err := validateTrustedInputPreflight(profile, decision, 1024, preflight); err != nil {
		t.Fatal(err)
	}
	if err := verifyAndRebindPreflightBody(request, preflight); err != nil {
		t.Fatal(err)
	}
	rules := []quota.Rule{{Metric: quota.InputTokensMetric, Algorithm: quota.CalendarAlgorithm}, {Metric: quota.TotalTokensMetric, Algorithm: quota.CalendarAlgorithm}}
	if _, err := assignDecisionReservationUnits(rules, configuredPricing{}, 1024, &preflight); err != nil {
		t.Fatal(err)
	}
	if rules[0].ReservedUnits != preflight.InputTokenBound || rules[1].ReservedUnits != preflight.TotalTokenBound {
		t.Fatal("tool schema missing from quota reservation")
	}
	for _, value := range []int64{-1, 0, preflight.ExpandedSchemaBytes + 1, 4*1024*1024 + 1} {
		invalid := preflight
		invalid.ExpandedSchemaBytes = value
		if err := validateTrustedInputPreflight(profile, decision, 1024, invalid); !errors.Is(err, policy.ErrConfiguration) {
			t.Fatalf("altered schema proof %d accepted", value)
		}
	}
	other := profile
	other.Protocol = protocol.OpenAIResponsesID
	if _, ok := trustedInputBoundFromProfile(other, preflight); ok {
		t.Fatal("Chat proof accepted for another protocol")
	}
}
