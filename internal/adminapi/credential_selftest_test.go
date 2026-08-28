package adminapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
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
	mu        sync.Mutex
	scope     configuration.TenantScope
	reference string
	value     []byte
	uses      int
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
	expectedScope := store.scope
	expectedReference := store.reference
	value := append([]byte(nil), store.value...)
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
	mu           sync.Mutex
	responses    []credentialSelfTestResponseFixture
	acquisitions int
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
	return &credentialSelfTestLeaseFixture{response: response}, nil
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
}

func (lease *credentialSelfTestLeaseFixture) Prepare(
	incoming *http.Request,
	path string,
	_ []string,
	_ map[string]string,
) (dataplane.ProviderRequest, error) {
	if incoming == nil || path != lease.response.path || incoming.Header.Get("Authorization") != "" {
		return dataplane.ProviderRequest{}, errors.New("unexpected prepared request")
	}
	if incoming.Body != nil {
		body, err := io.ReadAll(incoming.Body)
		if err != nil {
			return dataplane.ProviderRequest{}, err
		}
		incoming.Body = io.NopCloser(bytes.NewReader(body))
	}
	lease.request = incoming
	return dataplane.ProviderRequest{}, nil
}

func (lease *credentialSelfTestLeaseFixture) DispatchWithBeforeRoundTrip(
	_ context.Context,
	_ dataplane.ProviderRequest,
	before func() error,
) (*upstream.DispatchedResponse, error) {
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
	return consume(lease.dispatched())
}

func (lease *credentialSelfTestLeaseFixture) WithHeaderDispatchWithBeforeRoundTrip(
	context.Context,
	dataplane.ProviderRequest,
	string,
	[]byte,
	func() error,
	func(*upstream.DispatchedResponse) error,
) error {
	return errors.New("unexpected header dispatch")
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
