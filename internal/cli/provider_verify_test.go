package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/providerverify"
)

const providerCLITestSecret = "sk-or-v1-cli-secret-never-print"

type providerVerifierFunc func(context.Context, providerverify.Request) (providerverify.Report, error)

func (function providerVerifierFunc) Verify(ctx context.Context, request providerverify.Request) (providerverify.Report, error) {
	return function(ctx, request)
}

func TestVerifyOpenRouterEphemeralEnvironmentContract(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", providerCLITestSecret)
	var credentialReference []byte
	verifier := providerVerifierFunc(func(ctx context.Context, request providerverify.Request) (providerverify.Report, error) {
		if request.Mode != providerverify.ModeOpenRouter || request.BaseURL != "" || request.Model != "openai/test-model" || request.MaxCostNanoUSD != 10_000_000 {
			t.Fatalf("request = %+v", request)
		}
		if err := request.Credential(ctx, func(value []byte) error {
			credentialReference = value
			if !bytes.Equal(value, []byte(providerCLITestSecret)) {
				t.Fatal("credential mismatch")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return successfulProviderReport(providerverify.ModeOpenRouter), nil
	})
	var stdout, stderr bytes.Buffer
	opts := &options{
		output: "json", stdout: &stdout, stderr: &stderr, providerVerifier: verifier,
		adminHTTPClient: &http.Client{Transport: secretRoundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("ephemeral verification sent a request to the Admin API")
			return nil, errors.New("unreachable")
		})},
	}
	err := executeWithOptions(context.Background(), []string{
		"--output", "json", "verify", "openrouter", "--api-key-env", "OPENROUTER_API_KEY",
		"--model", "openai/test-model", "--max-cost-usd", "0.01",
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentialReference) == 0 || !allZero(credentialReference) {
		t.Fatal("CLI credential buffer was not cleared")
	}
	if strings.Contains(stdout.String(), providerCLITestSecret) || strings.Contains(stderr.String(), providerCLITestSecret) ||
		!strings.Contains(stdout.String(), `"cost_verification": "verified"`) {
		t.Fatalf("unsafe or incomplete output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	var report providerverify.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || !report.Passed {
		t.Fatalf("JSON report=%+v error=%v", report, err)
	}
}

func TestVerifyUpstreamEphemeralStdinContract(t *testing.T) {
	var credentialReference []byte
	verifier := providerVerifierFunc(func(ctx context.Context, request providerverify.Request) (providerverify.Report, error) {
		if request.Mode != providerverify.ModeOpenAIChat || request.BaseURL != "https://api.example.test/v1" ||
			request.Model != "physical-model" || request.MaxCostNanoUSD != 0 {
			t.Fatalf("request = %+v", request)
		}
		if err := request.Credential(ctx, func(value []byte) error {
			credentialReference = value
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return successfulProviderReport(providerverify.ModeOpenAIChat), nil
	})
	var stdout, stderr bytes.Buffer
	opts := &options{
		output: "table", stdin: strings.NewReader(providerCLITestSecret), stdout: &stdout, stderr: &stderr,
		providerVerifier: verifier,
	}
	err := executeWithOptions(context.Background(), []string{
		"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat",
		"--api-key-stdin", "--model", "physical-model",
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentialReference) == 0 || !allZero(credentialReference) {
		t.Fatal("stdin credential buffer was not cleared")
	}
	if strings.Contains(stdout.String(), providerCLITestSecret) || strings.Contains(stderr.String(), providerCLITestSecret) ||
		!strings.Contains(stdout.String(), "cost: unverified") || !strings.Contains(stdout.String(), "verification: passed") {
		t.Fatalf("unsafe or incomplete output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestProviderCredentialInputsAreExclusiveAndBounded(t *testing.T) {
	t.Setenv("GOOD_PROVIDER_KEY", providerCLITestSecret)
	t.Setenv("EMPTY_PROVIDER_KEY", "")
	t.Setenv("MULTILINE_PROVIDER_KEY", "secret\nvalue")
	t.Setenv("OVERSIZED_PROVIDER_KEY", strings.Repeat("a", maximumProviderCredentialBytes+1))
	tests := []struct {
		name  string
		args  []string
		stdin string
	}{
		{name: "missing source", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model"}},
		{name: "both sources", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "GOOD_PROVIDER_KEY", "--api-key-stdin"}, stdin: providerCLITestSecret},
		{name: "invalid env name", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "BAD-NAME"}},
		{name: "empty env", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "EMPTY_PROVIDER_KEY"}},
		{name: "multiline env", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "MULTILINE_PROVIDER_KEY"}},
		{name: "oversized env", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "OVERSIZED_PROVIDER_KEY"}},
		{name: "newline stdin", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-stdin"}, stdin: providerCLITestSecret + "\n"},
		{name: "control stdin", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-stdin"}, stdin: "abc\x00def"},
		{name: "padding-only stdin", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-stdin"}, stdin: "==="},
		{name: "oversized stdin", args: []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-stdin"}, stdin: strings.Repeat("a", maximumProviderCredentialBytes+1)},
		{name: "plaintext argv unavailable", args: []string{"verify", "upstream", "--api-key", providerCLITestSecret}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			opts := &options{output: "json", stdin: strings.NewReader(test.stdin), stdout: &stdout, stderr: &stderr,
				providerVerifier: providerVerifierFunc(func(context.Context, providerverify.Request) (providerverify.Report, error) {
					t.Fatal("verifier called for invalid credential input")
					return providerverify.Report{}, nil
				})}
			err := executeWithOptions(context.Background(), test.args, opts)
			if err == nil {
				t.Fatal("invalid input accepted")
			}
			combined := stdout.String() + stderr.String() + err.Error()
			if strings.Contains(combined, providerCLITestSecret) || strings.Contains(combined, "abc\x00def") {
				t.Fatalf("credential leaked in %q", combined)
			}
		})
	}
}

func TestProviderCredentialExactBoundsAndCommonValueAreAccepted(t *testing.T) {
	maximumName := "A" + strings.Repeat("A", 127)
	tooLongName := maximumName + "A"
	t.Setenv(maximumName, strings.Repeat("a", maximumProviderCredentialBytes))
	t.Setenv("COMMON_PROVIDER_KEY", "target")
	if !providerCredentialEnvironmentPattern.MatchString(maximumName) || providerCredentialEnvironmentPattern.MatchString(tooLongName) {
		t.Fatal("environment name boundary is incorrect")
	}

	for _, environment := range []string{maximumName, "COMMON_PROVIDER_KEY"} {
		t.Run(environment, func(t *testing.T) {
			var credentialReference []byte
			verifier := providerVerifierFunc(func(ctx context.Context, request providerverify.Request) (providerverify.Report, error) {
				if err := request.Credential(ctx, func(value []byte) error {
					credentialReference = value
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return successfulProviderReport(providerverify.ModeOpenAIChat), nil
			})
			err := executeWithOptions(context.Background(), []string{
				"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat",
				"--model", "model", "--api-key-env", environment,
			}, &options{output: "json", stdout: io.Discard, stderr: io.Discard, providerVerifier: verifier})
			if err != nil {
				t.Fatal(err)
			}
			if len(credentialReference) == 0 || !allZero(credentialReference) {
				t.Fatal("credential buffer was not cleared")
			}
		})
	}

	err := executeWithOptions(context.Background(), []string{
		"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat",
		"--model", "model", "--api-key-env", tooLongName,
	}, &options{output: "json", stdout: io.Discard, stderr: io.Discard})
	if err == nil {
		t.Fatal("overlong environment name accepted")
	}
}

func TestProviderVerificationRejectsHybridFlagSets(t *testing.T) {
	t.Setenv("GOOD_PROVIDER_KEY", providerCLITestSecret)
	tests := [][]string{
		{"verify", "openrouter", "--server-owned", "--environment", controlTestEnvironment, "--upstream", "openrouter", "--model", "canary", "--api-key-env", "GOOD_PROVIDER_KEY"},
		{"verify", "openrouter", "--environment", controlTestEnvironment, "--model", "openai/model", "--api-key-env", "GOOD_PROVIDER_KEY", "--max-cost-usd", "0.01"},
		{"verify", "upstream", "--server-owned", "--environment", controlTestEnvironment, "--upstream", "primary", "--model", "canary", "--base-url", "https://api.example.test/v1"},
		{"verify", "upstream", "--api-token-env", "TOKEN", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "GOOD_PROVIDER_KEY"},
	}
	for _, args := range tests {
		err := executeWithOptions(context.Background(), args, &options{output: "json", stdout: io.Discard, stderr: io.Discard})
		if err == nil {
			t.Fatalf("hybrid flags accepted: %v", args)
		}
	}
}

func TestProviderMaxCostUSDParsingIsExact(t *testing.T) {
	tests := []struct {
		value string
		want  int64
		ok    bool
	}{
		{value: "0.01", want: 10_000_000, ok: true},
		{value: "0.000000001", want: 1, ok: true},
		{value: "1.000000000", want: 1_000_000_000, ok: true},
		{value: "0.0000000001"},
		{value: "1.000000001"},
		{value: "0"},
		{value: "-0.01"},
		{value: "NaN"},
		{value: "9223372036854775808"},
	}
	for _, test := range tests {
		got, err := parseProviderMaxCostUSD(test.value)
		if (err == nil) != test.ok || (err == nil && got != test.want) {
			t.Errorf("parseProviderMaxCostUSD(%q)=(%d,%v), want (%d,ok=%v)", test.value, got, err, test.want, test.ok)
		}
	}
}

func TestProviderVerificationCancellationAndUnsafeDependenciesDoNotLeak(t *testing.T) {
	t.Setenv("GOOD_PROVIDER_KEY", providerCLITestSecret)
	baseArgs := []string{"verify", "upstream", "--base-url", "https://api.example.test/v1", "--protocol", "openai_chat", "--model", "model", "--api-key-env", "GOOD_PROVIDER_KEY"}
	tests := []struct {
		name     string
		verifier providerVerifierCLI
		cancel   bool
	}{
		{name: "canceled", cancel: true, verifier: providerVerifierFunc(func(ctx context.Context, _ providerverify.Request) (providerverify.Report, error) {
			return providerverify.Report{}, ctx.Err()
		})},
		{name: "unsafe error", verifier: providerVerifierFunc(func(context.Context, providerverify.Request) (providerverify.Report, error) {
			return providerverify.Report{}, errors.New("dependency leaked " + providerCLITestSecret)
		})},
		{name: "unsafe report", verifier: providerVerifierFunc(func(context.Context, providerverify.Request) (providerverify.Report, error) {
			report := successfulProviderReport(providerverify.ModeOpenAIChat)
			report.Checks[0].Detail = providerCLITestSecret
			return report, nil
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var stdout, stderr bytes.Buffer
			err := executeWithOptions(ctx, baseArgs, &options{output: "json", stdout: &stdout, stderr: &stderr, providerVerifier: test.verifier})
			if err == nil {
				t.Fatal("failure accepted")
			}
			combined := stdout.String() + stderr.String() + err.Error()
			if strings.Contains(combined, providerCLITestSecret) {
				t.Fatalf("credential leaked in %q", combined)
			}
		})
	}
}

func TestProviderVerifyHelpDocumentsOnlySafeCredentialInputs(t *testing.T) {
	for _, command := range [][]string{{"verify", "openrouter", "--help"}, {"verify", "upstream", "--help"}} {
		var stdout bytes.Buffer
		err := executeWithOptions(context.Background(), command, &options{output: "table", stdout: &stdout, stderr: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		help := stdout.String()
		if !strings.Contains(help, "--api-key-env") || !strings.Contains(help, "--api-key-stdin") || strings.Contains(help, "--api-key string") {
			t.Fatalf("unsafe or incomplete help: %s", help)
		}
	}
}

func successfulProviderReport(mode string) providerverify.Report {
	report := providerverify.Report{
		Passed: true, Mode: mode, CostVerification: providerverify.CostUnverified,
		NonStreaming: providerverify.Usage{InputTokens: 5, OutputTokens: 1, TotalTokens: 6},
		Streaming:    providerverify.Usage{InputTokens: 5, OutputTokens: 1, TotalTokens: 6},
	}
	for name, detail := range expectedProviderVerifyChecks(mode) {
		report.Checks = append(report.Checks, providerverify.Check{Name: name, Passed: true, Detail: detail})
	}
	if mode == providerverify.ModeOpenRouter {
		report.CostVerification = providerverify.CostVerified
		report.MaximumCostNanoUSD = 100
		report.CalculatedCostNanoUSD = 20
		report.ReportedCostNanoUSD = 20
		report.NonStreaming.ReportedCostNanoUSD = 10
		report.Streaming.ReportedCostNanoUSD = 10
	}
	return report
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
