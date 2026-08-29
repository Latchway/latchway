package providerverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/upstream"
)

const testCredential = "sk-or-v1-secret-never-report-this"

type fakeStep func(*http.Request, string, []byte) (*http.Response, error)

type fakeTarget struct {
	t      *testing.T
	steps  []fakeStep
	index  int
	closed bool
	secret []byte
}

func (f *fakeTarget) Do(ctx context.Context, request *http.Request, path string, credential []byte, consume func(*http.Response) error) error {
	f.t.Helper()
	if f.index >= len(f.steps) {
		return errors.New("unexpected dispatch")
	}
	if !bytes.Equal(credential, f.secret) {
		return errors.New("credential mismatch")
	}
	response, err := f.steps[f.index](request, path, credential)
	f.index++
	if err != nil {
		return err
	}
	if response.Request == nil {
		response.Request = request
	}
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	if response.Body == nil {
		response.Body = io.NopCloser(strings.NewReader(""))
	}
	defer response.Body.Close()
	return consume(response)
}

func (f *fakeTarget) Close() { f.closed = true }

func verifierWithTarget(fake *fakeTarget) *Verifier {
	return &Verifier{
		newTarget:    func(string, upstream.Timeouts, upstream.Resolver) (target, error) { return fake, nil },
		totalTimeout: time.Second,
		now:          func() time.Time { return time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC) },
	}
}

func credentialSource(secret string) CredentialSource {
	return func(ctx context.Context, consume func([]byte) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		material := []byte(secret)
		defer func() {
			for index := range material {
				material[index] = 0
			}
		}()
		return consume(material)
	}
}

func TestGenericSuccessIsBoundedAndCostUnverified(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		completionStep(t, false, 8, 1, 9, ""),
		completionStep(t, true, 7, 1, 8, ""),
		errorStep(http.StatusBadRequest, `{"error":{"message":"private provider detail"}}`),
	}}
	report, err := verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenAIChat, BaseURL: "https://provider.example/v1", Model: "physical-model",
		Credential: credentialSource(testCredential),
	})
	if err != nil || !report.Passed || report.CostVerification != CostUnverified || report.MaximumCostNanoUSD != 0 {
		t.Fatalf("Verify() report=%+v error=%v", report, err)
	}
	if fake.index != 3 || !fake.closed || report.NonStreaming.OutputTokens != 1 || report.Streaming.TotalTokens != 8 {
		t.Fatalf("unexpected execution/report: index=%d closed=%v report=%+v", fake.index, fake.closed, report)
	}
	assertNoSecret(t, report, err)
}

func TestOpenRouterSuccessProvesAndReconcilesCost(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		modelStep(validModelBody()),
		keyStep(`{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":1,"expires_at":"2027-01-01T00:00:00Z"}}`),
		completionStep(t, false, 8, 1, 9, "0.000000010"),
		completionStep(t, true, 7, 1, 8, "0.000000009"),
		errorStep(http.StatusUnprocessableEntity, `{"error":{"message":"no echo"}}`),
	}}
	report, err := verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenRouter, Model: "openai/test-model", MaxCostNanoUSD: 1_000_000,
		Credential: credentialSource(testCredential),
	})
	if err != nil || !report.Passed || report.CostVerification != CostVerified ||
		report.MaximumCostNanoUSD <= 0 || report.CalculatedCostNanoUSD != 19 || report.ReportedCostNanoUSD != 19 {
		t.Fatalf("Verify() report=%+v error=%v", report, err)
	}
	if fake.index != 5 || !fake.closed {
		t.Fatalf("execution index=%d closed=%v", fake.index, fake.closed)
	}
	assertNoSecret(t, report, err)
}

func TestFailuresNeverExposeCredentialOrProviderBody(t *testing.T) {
	tests := []struct {
		name string
		step fakeStep
		code string
	}{
		{name: "transport", step: func(*http.Request, string, []byte) (*http.Response, error) {
			return nil, fmt.Errorf("transport leaked %s", testCredential)
		}, code: "non_streaming"},
		{name: "redirect", step: errorStep(http.StatusFound, testCredential), code: "non_streaming"},
		{name: "body", step: errorStep(http.StatusOK, strings.Repeat("x", int(maximumResponseBytes+1))), code: "non_streaming"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{test.step}}
			report, err := verifierWithTarget(fake).Verify(context.Background(), Request{
				Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
				Credential: credentialSource(testCredential),
			})
			assertErrorCode(t, err, test.code)
			assertNoSecret(t, report, err)
		})
	}
}

func TestCredentialSourceErrorsAndConcurrentCallbacksAreSafe(t *testing.T) {
	t.Run("no callback", func(t *testing.T) {
		fake := &fakeTarget{t: t, secret: []byte(testCredential)}
		_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
			Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
			Credential: func(context.Context, func([]byte) error) error { return nil },
		})
		assertErrorCode(t, err, "credential_unavailable")
	})

	t.Run("empty callback", func(t *testing.T) {
		fake := &fakeTarget{t: t, secret: []byte(testCredential)}
		_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
			Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
			Credential: func(_ context.Context, consume func([]byte) error) error { return consume(nil) },
		})
		assertErrorCode(t, err, "credential_unavailable")
	})

	t.Run("source error", func(t *testing.T) {
		_, err := New().Verify(context.Background(), Request{
			Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
			Credential: func(context.Context, func([]byte) error) error {
				return fmt.Errorf("source leaked %s", testCredential)
			},
		})
		assertErrorCode(t, err, "credential_unavailable")
		assertNoSecret(t, Report{}, err)
	})

	t.Run("source error after callback", func(t *testing.T) {
		fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
			completionStep(t, false, 5, 1, 6, ""), completionStep(t, true, 5, 1, 6, ""), errorStep(400, `{}`),
		}}
		_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
			Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
			Credential: func(ctx context.Context, consume func([]byte) error) error {
				_ = consume([]byte(testCredential))
				return fmt.Errorf("source leaked %s", testCredential)
			},
		})
		assertErrorCode(t, err, "credential_unavailable")
		assertNoSecret(t, Report{}, err)
	})

	t.Run("concurrent callbacks", func(t *testing.T) {
		fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
			completionStep(t, false, 5, 1, 6, ""), completionStep(t, true, 5, 1, 6, ""), errorStep(400, `{}`),
		}}
		_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
			Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
			Credential: func(_ context.Context, consume func([]byte) error) error {
				var wait sync.WaitGroup
				wait.Add(2)
				for range 2 {
					go func() {
						defer wait.Done()
						_ = consume([]byte(testCredential))
					}()
				}
				wait.Wait()
				return nil
			},
		})
		assertErrorCode(t, err, "credential_unavailable")
		assertNoSecret(t, Report{}, err)
	})
}

func TestTimeoutIsBoundedAndSafe(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		func(request *http.Request, _ string, _ []byte) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		},
	}}
	verifier := verifierWithTarget(fake)
	verifier.totalTimeout = 5 * time.Millisecond
	started := time.Now()
	_, err := verifier.Verify(context.Background(), Request{
		Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
		Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "non_streaming")
	if time.Since(started) > time.Second {
		t.Fatal("verification timeout was not bounded")
	}
	assertNoSecret(t, Report{}, err)
}

func TestInputAndDestinationValidation(t *testing.T) {
	requests := []Request{
		{Mode: ModeOpenAIChat, BaseURL: "http://provider.example", Model: "model", Credential: credentialSource(testCredential)},
		{Mode: ModeOpenAIChat, BaseURL: "https://127.0.0.1", Model: "model", Credential: credentialSource(testCredential)},
		{Mode: ModeOpenAIChat, BaseURL: "https://[::1]", Model: "model", Credential: credentialSource(testCredential)},
		{Mode: ModeOpenAIChat, BaseURL: "https://169.254.169.254", Model: "model", Credential: credentialSource(testCredential)},
		{Mode: ModeOpenAIChat, BaseURL: "https://provider.example?target=x", Model: "model", Credential: credentialSource(testCredential)},
		{Mode: ModeOpenRouter, BaseURL: "https://mirror.example/api/v1", Model: "openai/model", MaxCostNanoUSD: 100, Credential: credentialSource(testCredential)},
		{Mode: ModeOpenRouter, Model: "alias-without-author", MaxCostNanoUSD: 100, Credential: credentialSource(testCredential)},
	}
	for index, request := range requests {
		_, err := New().Verify(context.Background(), request)
		assertErrorCode(t, err, "invalid_request")
		if strings.Contains(err.Error(), testCredential) {
			t.Fatalf("case %d leaked credential", index)
		}
	}
}

type fixedResolver struct{ addresses []netip.Addr }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), nil
}

func TestProtectedTargetRejectsDNSRebindingAnswer(t *testing.T) {
	verifier := New()
	verifier.resolver = fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	_, err := verifier.Verify(context.Background(), Request{
		Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model",
		Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "non_streaming")
	assertNoSecret(t, Report{}, err)
}

func TestMalformedUsageStreamAndCostFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		steps []fakeStep
		code  string
	}{
		{name: "inconsistent usage", steps: []fakeStep{completionRaw(false, `{"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":99}}`)}, code: "non_streaming"},
		{name: "missing final stream usage", steps: []fakeStep{completionStep(t, false, 5, 1, 6, ""), completionRaw(true, "data: {}\n\ndata: [DONE]\n\n")}, code: "usage"},
		{name: "incomplete SSE", steps: []fakeStep{completionStep(t, false, 5, 1, 6, ""), completionRaw(true, "data: {}\n\n")}, code: "streaming"},
		{name: "oversized SSE event", steps: []fakeStep{completionStep(t, false, 5, 1, 6, ""), completionRaw(true, "data: "+strings.Repeat("x", (1<<20)+1)+"\n\n")}, code: "streaming"},
		{name: "output exceeds clamp", steps: []fakeStep{completionStep(t, false, 5, 2, 7, ""), completionStep(t, true, 5, 1, 6, "")}, code: "usage"},
		{name: "malformed generic cost", steps: []fakeStep{completionRaw(false, `{"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6,"cost":"secret"}}`), completionStep(t, true, 5, 1, 6, ""), errorStep(400, `{}`)}, code: "usage"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: test.steps}
			_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
				Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model", Credential: credentialSource(testCredential),
			})
			assertErrorCode(t, err, test.code)
			assertNoSecret(t, Report{}, err)
		})
	}
}

func TestOpenRouterMalformedMetadataAndCostFailClosed(t *testing.T) {
	pricingCases := []string{
		`null`,
		`{"prompt":"bad","completion":"0.000000002","request":"0"}`,
		`{"prompt":"0.000000001","completion":"0.000000002"}`,
		`{"prompt":"0.000000001","completion":"0.000000002","request":"0","internal_reasoning":"0.1"}`,
		`{"prompt":"0.000000001","completion":"0.000000002","request":"0","future_charge":"0"}`,
		`{"prompt":"0.000000001","completion":"0.000000002","request":"0","overrides":[{"new_condition":true,"prompt":"0.1"}]}`,
		`{"prompt":"0.000000001","completion":"0.000000002","request":"0","overrides":[{"utc_start":2460,"utc_end":0,"prompt":"0.1"}]}`,
		`{"prompt":"0.000000001","completion":"0.000000002","request":"0","overrides":[{"utc_days":["monday","monday"],"prompt":"0.1"}]}`,
	}
	for index, pricing := range pricingCases {
		if _, err := parseOpenRouterModel([]byte(fmt.Sprintf(`{"data":{"id":"openai/test-model","context_length":4096,"supported_parameters":["max_tokens"],"architecture":{"input_modalities":["text"],"output_modalities":["text"],"tokenizer":"GPT"},"pricing":%s}}`, pricing)), "openai/test-model"); err == nil {
			t.Fatalf("pricing case %d accepted", index)
		}
	}

	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		modelStep(validModelBody()),
		keyStep(`{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":1}}`),
		completionStep(t, false, 8, 1, 9, "not-a-number"),
		completionStep(t, true, 7, 1, 8, "0.000000009"),
	}}
	_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenRouter, Model: "openai/test-model", MaxCostNanoUSD: 1_000_000, Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "cost_reconciliation")
	assertNoSecret(t, Report{}, err)
}

func TestOpenRouterKeyInformationIsStrictAndExact(t *testing.T) {
	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{name: "bounded", body: `{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":0.1}}`, ok: true},
		{name: "unlimited", body: `{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":null,"limit_remaining":null}}`, ok: true},
		{name: "management", body: `{"data":{"is_free_tier":false,"is_management_key":true,"is_provisioning_key":false,"limit":1,"limit_remaining":1}}`},
		{name: "provisioning", body: `{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":true,"limit":1,"limit_remaining":1}}`},
		{name: "missing remaining", body: `{"data":{"is_free_tier":true,"is_management_key":false,"is_provisioning_key":false,"limit":1}}`},
		{name: "malformed remaining", body: `{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":"1"}}`},
		{name: "insufficient", body: `{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":0.000000001}}`},
		{name: "expired", body: `{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":1,"expires_at":"2026-01-01T00:00:00Z"}}`},
		{name: "duplicate", body: `{"data":{"is_free_tier":false,"is_free_tier":true,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":1}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := parseOpenRouterKey([]byte(test.body), 10, now)
			if (err == nil) != test.ok {
				t.Fatalf("parseOpenRouterKey() error=%v, want ok=%v", err, test.ok)
			}
		})
	}
}

func TestOpenRouterPerTokenPriceScalingIsExact(t *testing.T) {
	tests := []struct {
		value string
		want  int64
		ok    bool
	}{
		{value: "0", want: 0, ok: true},
		{value: "0.000000001", want: 1_000_000, ok: true},
		{value: "0.0000000005", want: 500_000, ok: true},
		{value: "5e-10", want: 500_000, ok: true},
		{value: "0.000000000000001", want: 1, ok: true},
		{value: "0.0000000000000001", ok: false},
		{value: "1e100", ok: false},
		{value: "-0.1", ok: false},
		{value: "01", ok: false},
	}
	for _, test := range tests {
		got, err := parseUSDPerTokenNanoPerMillion(test.value)
		if (err == nil) != test.ok || (err == nil && got != test.want) {
			t.Errorf("parseUSDPerTokenNanoPerMillion(%q)=(%d,%v), want (%d, ok=%v)", test.value, got, err, test.want, test.ok)
		}
	}
}

func TestOpenRouterPricingUsesWorstConditionalRate(t *testing.T) {
	rates, err := parseOpenRouterPricing(map[string]any{
		"prompt": "0.000000001", "completion": "0.000000002", "request": "0",
		"overrides": []any{
			map[string]any{"min_prompt_tokens": json.Number("100"), "prompt": "0.0000000005"},
			map[string]any{"utc_start": json.Number("0"), "utc_end": json.Number("1200"), "completion": "0.000000003", "request": "0.01"},
		},
	})
	if err != nil || rates.InputNanoUSDPerMillion != 1_000_000 || rates.OutputNanoUSDPerMillion != 3_000_000 || rates.RequestNanoUSD != 10_000_000 {
		t.Fatalf("parseOpenRouterPricing() rates=%+v error=%v", rates, err)
	}
}

func TestOpenRouterReportedCostCannotExceedCalculatedBound(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		modelStep(validModelBody()),
		keyStep(`{"data":{"is_free_tier":false,"is_management_key":false,"is_provisioning_key":false,"limit":1,"limit_remaining":1}}`),
		completionStep(t, false, 8, 1, 9, "0.000001"),
		completionStep(t, true, 7, 1, 8, "0.000000009"),
	}}
	_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenRouter, Model: "openai/test-model", MaxCostNanoUSD: 1_000_000,
		Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "cost_reconciliation")
	assertNoSecret(t, Report{}, err)
}

func TestOpenRouterBudgetStopsBeforeInference(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{modelStep(validModelBody())}}
	_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenRouter, Model: "openai/test-model", MaxCostNanoUSD: 1, Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "cost_ceiling")
	if fake.index != 1 {
		t.Fatalf("dispatched %d requests, want metadata only", fake.index)
	}
}

func TestMetadataHeaderAndErrorBodyLimits(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		func(request *http.Request, path string, _ []byte) (*http.Response, error) {
			return response(http.StatusOK, "text/plain", validModelBody()), nil
		},
	}}
	_, err := verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenRouter, Model: "openai/test-model", MaxCostNanoUSD: 1_000_000, Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "model_pricing")

	fake = &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		completionStep(t, false, 5, 1, 6, ""), completionStep(t, true, 5, 1, 6, ""),
		errorStep(400, strings.Repeat("x", int(maximumMetadataBytes+1))),
	}}
	_, err = verifierWithTarget(fake).Verify(context.Background(), Request{
		Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model", Credential: credentialSource(testCredential),
	})
	assertErrorCode(t, err, "error_normalization")
}

func TestErrorNormalizationBodyBoundary(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
		code string
	}{
		{name: "exact limit", size: int(maximumMetadataBytes)},
		{name: "one over", size: int(maximumMetadataBytes + 1), code: "error_normalization"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
				completionStep(t, false, 5, 1, 6, ""), completionStep(t, true, 5, 1, 6, ""),
				errorUnknownLengthStep(400, strings.Repeat("x", test.size)),
			}}
			report, err := verifierWithTarget(fake).Verify(context.Background(), Request{
				Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model", Credential: credentialSource(testCredential),
			})
			if test.code == "" {
				if err != nil || !report.Passed {
					t.Fatalf("Verify() report=%+v error=%v", report, err)
				}
				return
			}
			assertErrorCode(t, err, test.code)
		})
	}
}

func TestTransportTimeoutConfigurationIsBounded(t *testing.T) {
	fake := &fakeTarget{t: t, secret: []byte(testCredential), steps: []fakeStep{
		completionStep(t, false, 5, 1, 6, ""), completionStep(t, true, 5, 1, 6, ""), errorStep(400, `{}`),
	}}
	var captured upstream.Timeouts
	verifier := verifierWithTarget(fake)
	verifier.newTarget = func(_ string, timeouts upstream.Timeouts, _ upstream.Resolver) (target, error) {
		captured = timeouts
		return fake, nil
	}
	_, err := verifier.Verify(context.Background(), Request{
		Mode: ModeOpenAIChat, BaseURL: "https://provider.example", Model: "model", Credential: credentialSource(testCredential),
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.Connect != 5*time.Second || captured.TLSHandshake != 5*time.Second || captured.ResponseHeader != 10*time.Second || captured.IdleConnection != 30*time.Second {
		t.Fatalf("unexpected transport bounds: %+v", captured)
	}
}

func completionStep(t *testing.T, stream bool, input, output, total int64, cost string) fakeStep {
	t.Helper()
	return func(request *http.Request, path string, _ []byte) (*http.Response, error) {
		if path != protocol.OpenAIChatProviderPath {
			return nil, errors.New("wrong path")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil || object["model"] == "" || object["max_tokens"] != float64(1) || object["stream"] != stream {
			return nil, errors.New("unbounded request")
		}
		if strings.Contains(string(body), "provider") {
			providerObject, ok := object["provider"].(map[string]any)
			maxPrice, priceOK := providerObject["max_price"].(map[string]any)
			if !ok || providerObject["sort"] != "price" || providerObject["allow_fallbacks"] != false ||
				providerObject["require_parameters"] != true || !priceOK || maxPrice["prompt"] != float64(0.001) ||
				maxPrice["completion"] != float64(0.002) || maxPrice["request"] != float64(0) {
				return nil, errors.New("missing provider boundary")
			}
		}
		usage := fmt.Sprintf(`"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d`, input, output, total)
		if cost != "" {
			if cost == "not-a-number" {
				usage += `,"cost":"not-a-number"`
			} else {
				usage += `,"cost":` + cost
			}
		}
		if stream {
			return response(200, "text/event-stream", "data: {\"choices\":[],\"usage\":{"+usage+"}}\n\ndata: [DONE]\n\n"), nil
		}
		return response(200, "application/json", `{"usage":{`+usage+`}}`), nil
	}
}

func completionRaw(stream bool, body string) fakeStep {
	return func(*http.Request, string, []byte) (*http.Response, error) {
		contentType := "application/json"
		if stream {
			contentType = "text/event-stream"
		}
		return response(200, contentType, body), nil
	}
}

func modelStep(body string) fakeStep {
	return func(_ *http.Request, path string, _ []byte) (*http.Response, error) {
		if path != "/model/openai/test-model" {
			return nil, errors.New("wrong model path")
		}
		return response(200, "application/json", body), nil
	}
}

func keyStep(body string) fakeStep {
	return func(_ *http.Request, path string, _ []byte) (*http.Response, error) {
		if path != "/key" {
			return nil, errors.New("wrong key path")
		}
		return response(200, "application/json", body), nil
	}
}

func errorStep(status int, body string) fakeStep {
	return func(*http.Request, string, []byte) (*http.Response, error) {
		return response(status, "application/json", body), nil
	}
}

func errorUnknownLengthStep(status int, body string) fakeStep {
	return func(*http.Request, string, []byte) (*http.Response, error) {
		result := response(status, "application/json", body)
		result.ContentLength = -1
		return result, nil
	}
}

func response(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
	}
}

func validModelBody() string {
	return `{"data":{"id":"openai/test-model","context_length":8192,"supported_parameters":["max_tokens"],"architecture":{"input_modalities":["text"],"output_modalities":["text"],"tokenizer":"GPT"},"pricing":{"prompt":"0.000000001","completion":"0.000000002","request":"0","image":"0","web_search":"0","internal_reasoning":"0","input_cache_read":"0","input_cache_write":"0","overrides":[]}}}`
}

func assertErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != code {
		t.Fatalf("error=%v, want safe code %s", err, code)
	}
}

func assertNoSecret(t *testing.T, report Report, err error) {
	t.Helper()
	encoded, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(testCredential)) || (err != nil && strings.Contains(err.Error(), testCredential)) {
		t.Fatalf("credential leaked: report=%s error=%v", encoded, err)
	}
}
