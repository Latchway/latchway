package adminapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/upstream"
)

func TestProductionCredentialSelfTestsOpenRouter(t *testing.T) {
	t.Parallel()
	scope := configuration.TenantScope{
		OrganizationID: id.Must(id.Organization),
		ApplicationID:  id.Must(id.Application),
		EnvironmentID:  id.Must(id.Environment),
	}
	snapshot := credentialSelfTestSnapshotFixture{
		revision: id.Must(id.ConfigRevision),
		upstream: configuration.Upstream{
			ID: "openrouter", Type: "openai_compatible", BaseURL: "https://openrouter.ai/api/v1",
			Authentication: configuration.UpstreamAuthentication{Type: "bearer", SecretRef: "secret/openrouter"},
		},
		model: configuration.Model{
			ID: "canary", UpstreamID: "openrouter", UpstreamModel: "provider/canary",
			PricingRef: "canary_prices", InputAccountingRef: "canary_input",
			Capabilities: []string{protocol.OpenAIChatID},
		},
		profile: configuration.InputAccountingProfile{
			ID: "canary_input", Protocol: protocol.OpenAIChatID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "provider/canary", MaximumFramingTokensPerRequest: 2,
			MaximumFramingTokensPerMessage: 2, MaximumContextTokens: 4096,
		},
		catalog: configuration.PricingCatalog{
			ID: "canary_prices", Currency: "USD",
			Entries: []configuration.PricingEntry{{
				ModelID: "canary", InputNanoUSDPerMillion: 1_000_000,
				OutputNanoUSDPerMillion: 2_000_000, RequestNanoUSD: 3,
			}},
		},
	}
	secretStore := &credentialSelfTestSecretFixture{
		scope: scope, reference: "secret/openrouter", value: []byte("test-only-provider-key"),
	}
	targets := &credentialSelfTestTargetFixture{responses: []credentialSelfTestResponseFixture{
		{path: "/key", status: http.StatusOK, contentType: "application/json", body: `{"data":{"is_free_tier":false,"limit":10,"limit_remaining":1}}`},
		{path: "/chat/completions", status: http.StatusOK, contentType: "application/json", body: `{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`},
		{path: "/chat/completions", status: http.StatusOK, contentType: "text/event-stream", body: "data: {\"choices\":[]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":6,\"completion_tokens\":1,\"total_tokens\":7}}\n\ndata: [DONE]\n\n"},
		{path: "/chat/completions", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":{"message":"must never enter the result"}}`},
	}}
	runner, err := newProductionCredentialSelfTests(
		credentialSelfTestSnapshotLoaderFixture{snapshot: snapshot}, secretStore, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC) }
	result := runner.Run(context.Background(), credentialSelfTestInput{
		Scope: scope, Kind: "openrouter", UpstreamID: "openrouter", ModelID: "canary",
		MaxCostNano: 10_000_000,
	})
	if result.State != "passed" || !validCredentialSelfTestResultForTest(result) {
		t.Fatalf("Run() = %+v", result)
	}
	if secretStore.uses != 4 {
		t.Fatalf("secret uses = %d, want one fresh use per dispatch", secretStore.uses)
	}
	if targets.acquisitions != 4 || targets.remaining() != 0 {
		t.Fatalf("target acquisitions=%d remaining=%d", targets.acquisitions, targets.remaining())
	}
	encoded := strings.Builder{}
	for _, check := range result.Checks {
		encoded.WriteString(check.SafeDetail)
	}
	if strings.Contains(encoded.String(), "provider-key") || strings.Contains(encoded.String(), "must never") {
		t.Fatal("credential or provider error body entered the safe result")
	}
}

func TestProductionCredentialSelfTestsOpenAIResponses(t *testing.T) {
	t.Parallel()
	scope := configuration.TenantScope{
		OrganizationID: id.Must(id.Organization),
		ApplicationID:  id.Must(id.Application),
		EnvironmentID:  id.Must(id.Environment),
	}
	snapshot := credentialSelfTestSnapshotFixture{
		revision: id.Must(id.ConfigRevision),
		upstream: configuration.Upstream{
			ID: "primary", Type: "openai_compatible", BaseURL: "https://api.openai.com/v1",
			Authentication: configuration.UpstreamAuthentication{Type: "none"},
		},
		model: configuration.Model{
			ID: "assistant_default", UpstreamID: "primary", UpstreamModel: "operator-model",
			PricingRef: "operator_prices", InputAccountingRef: "responses_input",
			Capabilities: []string{protocol.OpenAIChatID, protocol.OpenAIResponsesID},
		},
		profile: configuration.InputAccountingProfile{
			ID: "responses_input", Protocol: protocol.OpenAIResponsesID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "operator-model", MaximumFramingTokensPerRequest: 2,
			MaximumFramingTokensPerMessage: 2, MaximumContextTokens: 4096,
		},
		catalog: configuration.PricingCatalog{
			ID: "operator_prices", Currency: "USD",
			Entries: []configuration.PricingEntry{{
				ModelID: "assistant_default", InputNanoUSDPerMillion: 1_000_000,
				OutputNanoUSDPerMillion: 2_000_000, RequestNanoUSD: 3,
			}},
		},
	}
	targets := &credentialSelfTestTargetFixture{responses: []credentialSelfTestResponseFixture{
		{path: "/responses", status: http.StatusOK, contentType: "application/json", body: `{"id":"resp_1","usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}}`},
		{path: "/responses", status: http.StatusOK, contentType: "text/event-stream", body: "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":6,\"output_tokens\":1,\"total_tokens\":7}}}\n\n"},
		{path: "/responses", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":{"message":"must never enter the result"}}`},
	}}
	runner, err := newProductionCredentialSelfTests(
		credentialSelfTestSnapshotLoaderFixture{snapshot: snapshot},
		&credentialSelfTestSecretFixture{}, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC) }
	result := runner.Run(context.Background(), credentialSelfTestInput{
		Scope: scope, Kind: "upstream", UpstreamID: "primary", ModelID: "assistant_default",
		MaxCostNano: 10_000_000,
	})
	if result.State != "passed" || len(result.Checks) != 8 {
		t.Fatalf("Run() = %+v", result)
	}
	for _, check := range result.Checks {
		if check.State != "passed" || check.SafeDetail == "" || strings.Contains(check.SafeDetail, "must never") {
			t.Fatalf("unsafe or failed check: %+v", check)
		}
	}
	if targets.acquisitions != 3 || targets.remaining() != 0 {
		t.Fatalf("target acquisitions=%d remaining=%d", targets.acquisitions, targets.remaining())
	}
}

func TestProductionCredentialSelfTestsOpenAIEmbeddings(t *testing.T) {
	t.Parallel()
	scope := configuration.TenantScope{
		OrganizationID: id.Must(id.Organization),
		ApplicationID:  id.Must(id.Application),
		EnvironmentID:  id.Must(id.Environment),
	}
	snapshot := credentialSelfTestSnapshotFixture{
		revision: id.Must(id.ConfigRevision),
		upstream: configuration.Upstream{
			ID: "embeddings", Type: "openai_compatible", BaseURL: "https://api.openai.com/v1",
			Authentication: configuration.UpstreamAuthentication{Type: "none"},
		},
		model: configuration.Model{
			ID: "search_vectors", UpstreamID: "embeddings", UpstreamModel: "text-embedding-3-small",
			PricingRef: "embedding_prices", InputAccountingRef: "embedding_input",
			Capabilities: []string{protocol.OpenAIEmbeddingsID},
		},
		profile: configuration.InputAccountingProfile{
			ID: "embedding_input", Protocol: protocol.OpenAIEmbeddingsID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "text-embedding-3-small", MaximumFramingTokensPerRequest: 2,
			MaximumFramingTokensPerMessage: 2, MaximumContextTokens: 8192,
		},
		catalog: configuration.PricingCatalog{
			ID: "embedding_prices", Currency: "USD",
			Entries: []configuration.PricingEntry{{
				ModelID: "search_vectors", InputNanoUSDPerMillion: 20_000,
				OutputNanoUSDPerMillion: 0, RequestNanoUSD: 5_000_000,
			}},
		},
	}
	targets := &credentialSelfTestTargetFixture{responses: []credentialSelfTestResponseFixture{
		{path: "/embeddings", status: http.StatusOK, contentType: "application/json", body: `{"object":"list","data":[{"object":"embedding","embedding":[0.125,-0.25],"index":0}],"model":"text-embedding-3-small","usage":{"prompt_tokens":7,"total_tokens":7}}`},
		{path: "/embeddings", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":{"message":"must never enter the result"}}`},
	}}
	runner, err := newProductionCredentialSelfTests(
		credentialSelfTestSnapshotLoaderFixture{snapshot: snapshot},
		&credentialSelfTestSecretFixture{}, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC) }
	result := runner.Run(context.Background(), credentialSelfTestInput{
		Scope: scope, Kind: "upstream", UpstreamID: "embeddings", ModelID: "search_vectors",
		// One Embeddings request fits; an incorrectly doubled request charge would not.
		MaxCostNano: 6_000_000,
	})
	if result.State != "passed" || len(result.Checks) != 8 {
		t.Fatalf("Run() = %+v", result)
	}
	states := make(map[string]string, len(result.Checks))
	for _, check := range result.Checks {
		states[check.Name] = check.State
		if check.SafeDetail == "" || strings.Contains(check.SafeDetail, "must never") {
			t.Fatalf("unsafe or empty check: %+v", check)
		}
	}
	if states["streaming"] != "skipped" || states["output_clamp"] != "skipped" ||
		states["non_streaming"] != "passed" || states["usage"] != "passed" {
		t.Fatalf("protocol-specific check states = %v", states)
	}
	if targets.acquisitions != 2 || targets.remaining() != 0 {
		t.Fatalf("target acquisitions=%d remaining=%d", targets.acquisitions, targets.remaining())
	}
	if len(targets.requestBodies) != 2 || strings.Contains(targets.requestBodies[0], `"stream"`) ||
		strings.Contains(targets.requestBodies[0], "max_tokens") ||
		!strings.Contains(targets.requestBodies[0], `"input":"Latchway credential diagnostic."`) {
		t.Fatalf("Embeddings diagnostic requests = %q", targets.requestBodies)
	}
}

func TestProductionCredentialSelfTestsAnthropicMessages(t *testing.T) {
	t.Parallel()
	scope := configuration.TenantScope{
		OrganizationID: id.Must(id.Organization),
		ApplicationID:  id.Must(id.Application),
		EnvironmentID:  id.Must(id.Environment),
	}
	snapshot := credentialSelfTestSnapshotFixture{
		revision: id.Must(id.ConfigRevision),
		upstream: configuration.Upstream{
			ID: "anthropic", Type: "anthropic", BaseURL: "https://api.anthropic.com/v1",
			Authentication: configuration.UpstreamAuthentication{
				Type: "header", HeaderName: "X-Api-Key", SecretRef: "secret/anthropic",
			},
		},
		model: configuration.Model{
			ID: "assistant", UpstreamID: "anthropic", UpstreamModel: "claude-sonnet-4-20250514",
			PricingRef: "anthropic_prices", InputAccountingRef: "anthropic_input",
			Capabilities: []string{protocol.AnthropicMessagesID},
		},
		profile: configuration.InputAccountingProfile{
			ID: "anthropic_input", Protocol: protocol.AnthropicMessagesID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "claude-sonnet-4-20250514", MaximumFramingTokensPerRequest: 2,
			MaximumFramingTokensPerMessage: 2, MaximumContextTokens: 4096,
		},
		catalog: configuration.PricingCatalog{
			ID: "anthropic_prices", Currency: "USD",
			Entries: []configuration.PricingEntry{{
				ModelID: "assistant", InputNanoUSDPerMillion: 3_000_000,
				OutputNanoUSDPerMillion: 15_000_000, RequestNanoUSD: 3,
			}},
		},
	}
	secretStore := &credentialSelfTestSecretFixture{
		scope: scope, reference: "secret/anthropic", value: []byte("test-only-anthropic-key"),
	}
	targets := &credentialSelfTestTargetFixture{responses: []credentialSelfTestResponseFixture{
		{path: "/messages", status: http.StatusOK, contentType: "application/json", body: `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":7,"output_tokens":1}}`},
		{path: "/messages", status: http.StatusOK, contentType: "text/event-stream", body: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":8,\"output_tokens\":0}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"OK\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"},
		{path: "/messages", status: http.StatusBadRequest, contentType: "application/json", body: `{"type":"error","error":{"message":"must never enter the result"}}`},
	}}
	runner, err := newProductionCredentialSelfTests(
		credentialSelfTestSnapshotLoaderFixture{snapshot: snapshot}, secretStore, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC) }
	result := runner.Run(context.Background(), credentialSelfTestInput{
		Scope: scope, Kind: "upstream", UpstreamID: "anthropic", ModelID: "assistant",
		MaxCostNano: 10_000_000,
	})
	if result.State != "passed" || len(result.Checks) != 8 {
		t.Fatalf("Run() = %+v", result)
	}
	for _, check := range result.Checks {
		if check.State != "passed" || check.SafeDetail == "" || strings.Contains(check.SafeDetail, "must never") {
			t.Fatalf("unsafe or failed check: %+v", check)
		}
	}
	if secretStore.uses != 3 || targets.acquisitions != 3 || targets.remaining() != 0 {
		t.Fatalf("secret uses/acquisitions/remaining=%d/%d/%d", secretStore.uses, targets.acquisitions, targets.remaining())
	}
	if len(targets.requestHeaders) != 3 || len(targets.forwardedHeaders) != 3 {
		t.Fatalf("captured Anthropic requests=%d/%d", len(targets.requestHeaders), len(targets.forwardedHeaders))
	}
	for index := range targets.requestHeaders {
		if targets.requestHeaders[index].Get("Anthropic-Version") != "2023-06-01" ||
			!slices.Equal(targets.forwardedHeaders[index], []string{"Content-Type", "Anthropic-Version"}) {
			t.Fatalf("Anthropic request %d headers=%v forwarded=%v", index, targets.requestHeaders[index], targets.forwardedHeaders[index])
		}
	}
	if !strings.Contains(targets.requestBodies[0], `"stream":false`) ||
		!strings.Contains(targets.requestBodies[1], `"stream":true`) ||
		!strings.Contains(targets.requestBodies[0], `"max_tokens":1`) {
		t.Fatalf("Anthropic diagnostic request bodies = %q", targets.requestBodies)
	}
}

func TestProductionCredentialSelfTestsFailBeforeDispatch(t *testing.T) {
	t.Parallel()
	snapshot := credentialSelfTestSnapshotFixture{
		revision: id.Must(id.ConfigRevision),
		upstream: configuration.Upstream{
			ID: "openrouter", Type: "openai_compatible", BaseURL: "https://openrouter.ai/api/v1",
			Authentication: configuration.UpstreamAuthentication{Type: "bearer", SecretRef: "secret/openrouter"},
		},
		model: configuration.Model{
			ID: "canary", UpstreamID: "openrouter", UpstreamModel: "provider/canary",
			PricingRef: "canary_prices", InputAccountingRef: "canary_input",
			Capabilities: []string{protocol.OpenAIChatID},
		},
		profile: configuration.InputAccountingProfile{
			ID: "canary_input", Protocol: protocol.OpenAIChatID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "provider/canary", MaximumContextTokens: 4096,
		},
		catalog: configuration.PricingCatalog{
			ID: "canary_prices", Currency: "USD",
			Entries: []configuration.PricingEntry{{
				ModelID: "canary", RequestNanoUSD: 100,
			}},
		},
	}
	targets := &credentialSelfTestTargetFixture{}
	runner, err := newProductionCredentialSelfTests(
		credentialSelfTestSnapshotLoaderFixture{snapshot: snapshot},
		&credentialSelfTestSecretFixture{}, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Run(context.Background(), credentialSelfTestInput{
		Scope: configuration.TenantScope{}, Kind: "openrouter",
		UpstreamID: "openrouter", ModelID: "canary", MaxCostNano: 1,
	})
	if result.State != "failed" || len(result.Checks) != 3 || result.Checks[2].Name != "budget" {
		t.Fatalf("Run() = %+v, want pre-dispatch budget failure", result)
	}
	if targets.acquisitions != 0 {
		t.Fatalf("budget failure acquired %d targets", targets.acquisitions)
	}
}

func TestCredentialSelfTestKeyAndStoredResultValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		body string
		cost int64
		ok   bool
	}{
		{name: "free", body: `{"data":{"is_free_tier":true,"limit":0,"limit_remaining":0}}`, cost: 1, ok: true},
		{name: "unlimited", body: `{"data":{"is_free_tier":false,"limit":null,"limit_remaining":null}}`, cost: 1, ok: true},
		{name: "decimal", body: `{"data":{"is_free_tier":false,"limit":1,"limit_remaining":1e-2}}`, cost: 10_000_000, ok: true},
		{name: "insufficient", body: `{"data":{"is_free_tier":false,"limit":1,"limit_remaining":0.009}}`, cost: 10_000_000, ok: false},
		{name: "missing", body: `{"data":{"is_free_tier":false,"limit":1}}`, cost: 1, ok: false},
		{name: "missing data", body: `{"status":"ok"}`, cost: 1, ok: false},
		{name: "duplicate credit", body: `{"data":{"is_free_tier":false,"limit":1,"limit_remaining":1,"limit_remaining":0}}`, cost: 1, ok: false},
		{name: "trailing", body: `{"data":{"is_free_tier":true}} {}`, cost: 1, ok: false},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateOpenRouterKeyInformation([]byte(test.body), test.cost)
			if (err == nil) != test.ok {
				t.Fatalf("validateOpenRouterKeyInformation() error=%v, want ok=%t", err, test.ok)
			}
		})
	}
	for value, want := range map[string]int64{"0": 0, "0.01": 10_000_000, "1e-3": 1_000_000} {
		got, ok := decimalUSDToNanoUSD(value)
		if !ok || got != want {
			t.Fatalf("decimalUSDToNanoUSD(%q)=(%d,%t), want (%d,true)", value, got, ok, want)
		}
	}
	if _, ok := decimalUSDToNanoUSD("-1"); ok {
		t.Fatal("negative credit accepted")
	}
	if _, ok := decimalUSDToNanoUSD("0.0000000001"); ok {
		t.Fatal("sub-nano credit accepted instead of being rounded down")
	}
	now := time.Now().UTC()
	completed := now.Add(time.Second)
	valid := selfTestDocument{
		ID: id.Must(id.Prefix("tst")), Kind: "openrouter", State: "passed",
		CreatedAt: now, CompletedAt: &completed,
		Checks: []selfTestCheck{{Name: "usage", State: "passed", SafeDetail: "safe"}},
	}
	if !validStoredSelfTest(valid) {
		t.Fatal("valid stored self-test rejected")
	}
	valid.Checks[0].SafeDetail = strings.Repeat("x", 2049)
	if validStoredSelfTest(valid) {
		t.Fatal("oversized safe detail accepted")
	}
}

func TestCredentialSelfTestDispatchSupportsBasicAndMultipleHeaders(t *testing.T) {
	scope := configuration.TenantScope{
		OrganizationID: id.Must(id.Organization),
		ApplicationID:  id.Must(id.Application),
		EnvironmentID:  id.Must(id.Environment),
	}
	secretStore := &credentialSelfTestSecretFixture{
		scope: scope,
		values: map[string][]byte{
			"secret/provider_password":     []byte("password"),
			"secret/provider_key":          []byte("key"),
			"secret/provider_organization": []byte("organization"),
		},
	}
	targets := &credentialSelfTestTargetFixture{responses: []credentialSelfTestResponseFixture{
		{path: "/probe", status: http.StatusOK, contentType: "application/json", body: `{}`},
		{path: "/probe", status: http.StatusOK, contentType: "application/json", body: `{}`},
	}}
	runner, err := newProductionCredentialSelfTests(
		credentialSelfTestSnapshotLoaderFixture{}, secretStore, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, authentication := range []configuration.UpstreamAuthentication{
		{Type: "basic", Username: "provider-user", SecretRef: "secret/provider_password"},
		{Type: "headers", Headers: []configuration.UpstreamAuthenticationHeader{
			{HeaderName: "X-Provider-Key", SecretRef: "secret/provider_key"},
			{HeaderName: "X-Provider-Organization", SecretRef: "secret/provider_organization"},
		}},
	} {
		request, requestErr := http.NewRequestWithContext(
			context.Background(), http.MethodGet, "https://latchway.invalid/probe", nil,
		)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		dispatchErr := runner.dispatch(
			request.Context(), scope,
			configuration.Upstream{Authentication: authentication},
			request, "/probe", []string{"Content-Type"},
			func(response *upstream.DispatchedResponse) error { return response.Close() },
		)
		if dispatchErr != nil {
			t.Fatalf("dispatch %q: %v", authentication.Type, dispatchErr)
		}
	}
	if secretStore.uses != 3 || !slices.Equal(secretStore.references, []string{
		"secret/provider_password", "secret/provider_key", "secret/provider_organization",
	}) {
		t.Fatalf("secret uses/references = %d/%v", secretStore.uses, secretStore.references)
	}
	if !slices.Equal(targets.authentications, []string{"basic", "headers"}) ||
		!slices.Equal(targets.usernames, []string{"provider-user", ""}) ||
		len(targets.headerNames) != 2 ||
		!slices.Equal(targets.headerNames[1], []string{"X-Provider-Key", "X-Provider-Organization"}) {
		t.Fatalf("self-test authentication dispatch = %v/%v/%v",
			targets.authentications, targets.usernames, targets.headerNames)
	}
}

type credentialSelfTestSnapshotLoaderFixture struct {
	snapshot credentialSelfTestSnapshot
	err      error
}

func (loader credentialSelfTestSnapshotLoaderFixture) CredentialSelfTestSnapshot(
	context.Context,
	configuration.TenantScope,
) (credentialSelfTestSnapshot, error) {
	return loader.snapshot, loader.err
}

type credentialSelfTestSnapshotFixture struct {
	revision string
	upstream configuration.Upstream
	model    configuration.Model
	profile  configuration.InputAccountingProfile
	catalog  configuration.PricingCatalog
}

func (snapshot credentialSelfTestSnapshotFixture) Upstream(value string) (configuration.Upstream, bool) {
	return snapshot.upstream, value == snapshot.upstream.ID
}

func (snapshot credentialSelfTestSnapshotFixture) Model(value string) (configuration.Model, bool) {
	return snapshot.model, value == snapshot.model.ID
}

func (snapshot credentialSelfTestSnapshotFixture) InputAccountingProfile(value string) (configuration.InputAccountingProfile, bool) {
	return snapshot.profile, value == snapshot.profile.ID
}

func (snapshot credentialSelfTestSnapshotFixture) PricingCatalog(value string) (configuration.PricingCatalog, bool) {
	return snapshot.catalog, value == snapshot.catalog.ID
}

func (snapshot credentialSelfTestSnapshotFixture) PricingEntry(catalogID, modelID string) (configuration.PricingEntry, bool) {
	if catalogID != snapshot.catalog.ID {
		return configuration.PricingEntry{}, false
	}
	return snapshot.catalog.Entry(modelID)
}

func (snapshot credentialSelfTestSnapshotFixture) PolicyRevision() string { return snapshot.revision }

type credentialSelfTestSecretFixture struct {
	mu         sync.Mutex
	scope      configuration.TenantScope
	reference  string
	value      []byte
	values     map[string][]byte
	references []string
	uses       int
}

func (store *credentialSelfTestSecretFixture) Use(
	ctx context.Context,
	scope secrets.Scope,
	reference string,
	consume func([]byte) error,
) error {
	if ctx == nil || consume == nil {
		return secrets.ErrInvalid
	}
	store.mu.Lock()
	store.uses++
	store.references = append(store.references, reference)
	expectedScope := store.scope
	expectedReference := store.reference
	selected := store.value
	if mapped, ok := store.values[reference]; ok {
		selected = mapped
	} else if store.values != nil {
		store.mu.Unlock()
		return secrets.ErrUnavailable
	}
	value := append([]byte(nil), selected...)
	store.mu.Unlock()
	defer clear(value)
	if expectedReference != "" && (scope.OrganizationID != expectedScope.OrganizationID ||
		scope.ApplicationID != expectedScope.ApplicationID || scope.EnvironmentID != expectedScope.EnvironmentID ||
		reference != expectedReference) {
		return secrets.ErrUnavailable
	}
	return consume(value)
}

type credentialSelfTestResponseFixture struct {
	path        string
	status      int
	contentType string
	body        string
}

type credentialSelfTestTargetFixture struct {
	mu               sync.Mutex
	responses        []credentialSelfTestResponseFixture
	acquisitions     int
	authentications  []string
	usernames        []string
	headerNames      [][]string
	requestHeaders   []http.Header
	requestBodies    []string
	forwardedHeaders [][]string
}

func (factory *credentialSelfTestTargetFixture) Acquire(configuration.Upstream) (dataplane.TargetLease, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if len(factory.responses) == 0 {
		return nil, errors.New("unexpected target acquisition")
	}
	response := factory.responses[0]
	factory.responses = factory.responses[1:]
	factory.acquisitions++
	return &credentialSelfTestLeaseFixture{response: response, factory: factory}, nil
}

func (factory *credentialSelfTestTargetFixture) remaining() int {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return len(factory.responses)
}

type credentialSelfTestLeaseFixture struct {
	response credentialSelfTestResponseFixture
	request  *http.Request
	released bool
	factory  *credentialSelfTestTargetFixture
}

func (lease *credentialSelfTestLeaseFixture) recordAuthentication(kind, username string, names []string) {
	if lease.factory == nil {
		return
	}
	lease.factory.mu.Lock()
	defer lease.factory.mu.Unlock()
	lease.factory.authentications = append(lease.factory.authentications, kind)
	lease.factory.usernames = append(lease.factory.usernames, username)
	lease.factory.headerNames = append(lease.factory.headerNames, append([]string(nil), names...))
}

func (lease *credentialSelfTestLeaseFixture) Prepare(
	incoming *http.Request,
	path string,
	forwardedHeaders []string,
	_ map[string]string,
) (dataplane.ProviderRequest, error) {
	if incoming == nil || path != lease.response.path || incoming.Header.Get("Authorization") != "" {
		return dataplane.ProviderRequest{}, errors.New("unexpected prepared request")
	}
	requestBody := ""
	if incoming.Body != nil {
		body, err := io.ReadAll(incoming.Body)
		if err != nil {
			return dataplane.ProviderRequest{}, err
		}
		incoming.Body = io.NopCloser(bytes.NewReader(body))
		requestBody = string(body)
	}
	lease.factory.mu.Lock()
	lease.factory.requestHeaders = append(lease.factory.requestHeaders, incoming.Header.Clone())
	lease.factory.requestBodies = append(lease.factory.requestBodies, requestBody)
	lease.factory.forwardedHeaders = append(
		lease.factory.forwardedHeaders, append([]string(nil), forwardedHeaders...),
	)
	lease.factory.mu.Unlock()
	lease.request = incoming
	return dataplane.ProviderRequest{}, nil
}

func (lease *credentialSelfTestLeaseFixture) DispatchWithBeforeRoundTrip(
	_ context.Context,
	_ dataplane.ProviderRequest,
	before func() error,
) (*upstream.DispatchedResponse, error) {
	lease.recordAuthentication("none", "", nil)
	if err := before(); err != nil {
		return nil, err
	}
	return lease.dispatched(), nil
}

func (lease *credentialSelfTestLeaseFixture) WithBearerDispatchWithBeforeRoundTrip(
	_ context.Context,
	_ dataplane.ProviderRequest,
	credential []byte,
	before func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if len(credential) == 0 || before == nil || consume == nil {
		return errors.New("invalid bearer dispatch")
	}
	if err := before(); err != nil {
		return err
	}
	lease.recordAuthentication("bearer", "", nil)
	return consume(lease.dispatched())
}

func (lease *credentialSelfTestLeaseFixture) WithHeaderDispatchWithBeforeRoundTrip(
	_ context.Context,
	_ dataplane.ProviderRequest,
	name string,
	credential []byte,
	before func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if name == "" || len(credential) == 0 || before == nil || consume == nil {
		return errors.New("invalid header dispatch")
	}
	if err := before(); err != nil {
		return err
	}
	lease.recordAuthentication("header", "", []string{name})
	return consume(lease.dispatched())
}

func (lease *credentialSelfTestLeaseFixture) WithBasicDispatchWithBeforeRoundTrip(
	_ context.Context,
	_ dataplane.ProviderRequest,
	username string,
	credential []byte,
	before func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if username == "" || len(credential) == 0 || before == nil || consume == nil {
		return errors.New("invalid basic dispatch")
	}
	if err := before(); err != nil {
		return err
	}
	lease.recordAuthentication("basic", username, nil)
	return consume(lease.dispatched())
}

func (lease *credentialSelfTestLeaseFixture) WithHeadersDispatchWithBeforeRoundTrip(
	_ context.Context,
	_ dataplane.ProviderRequest,
	credentials []upstream.HeaderCredential,
	before func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if len(credentials) == 0 || before == nil || consume == nil {
		return errors.New("invalid multi-header dispatch")
	}
	names := make([]string, len(credentials))
	for index, credential := range credentials {
		if credential.Name == "" || len(credential.Value) == 0 {
			return errors.New("invalid multi-header dispatch")
		}
		names[index] = credential.Name
	}
	if err := before(); err != nil {
		return err
	}
	lease.recordAuthentication("headers", "", names)
	return consume(lease.dispatched())
}

func (lease *credentialSelfTestLeaseFixture) Release() { lease.released = true }

func (lease *credentialSelfTestLeaseFixture) dispatched() *upstream.DispatchedResponse {
	header := make(http.Header)
	if lease.response.contentType != "" {
		header.Set("Content-Type", lease.response.contentType)
	}
	return &upstream.DispatchedResponse{Response: &http.Response{
		StatusCode: lease.response.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(lease.response.body)),
		Request:    lease.request,
	}}
}

func validCredentialSelfTestResultForTest(result credentialSelfTestResult) bool {
	if result.State != "passed" || len(result.Checks) != 9 {
		return false
	}
	for _, check := range result.Checks {
		if check.State != "passed" || check.SafeDetail == "" {
			return false
		}
	}
	return true
}
