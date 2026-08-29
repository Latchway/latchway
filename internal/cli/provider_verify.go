package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/providerverify"
	"github.com/latchway/latchway/internal/upstream"
	"github.com/spf13/cobra"
)

const (
	maximumProviderCredentialBytes = 32 << 10
	providerVerifyTotalTimeout     = 45 * time.Second
)

var providerCredentialEnvironmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var providerVerifyCheckPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

var providerVerifyCommonCheckDetails = map[string]string{
	"input_preflight":     "Both exact request bodies passed model-bound conservative input accounting and a one-token output clamp.",
	"non_streaming":       "A bounded non-streaming response supplied consistent final usage.",
	"streaming":           "A bounded SSE stream terminated with consistent final-frame usage.",
	"error_normalization": "A malformed request produced a bounded body-free provider rejection class.",
}

type providerVerifierCLI interface {
	Verify(context.Context, providerverify.Request) (providerverify.Report, error)
}

type providerVerifyCLIOptions struct {
	serverOwned       bool
	environmentID     string
	upstream          string
	model             string
	serverMaxCostNano int64
	baseURL           string
	protocol          string
	credentialEnv     string
	credentialStdin   bool
	privateCIDRs      []string
	maxCostUSD        string
}

func newProviderVerifyCommand(opts *options, control *controlCommandOptions, kind string) *cobra.Command {
	values := providerVerifyCLIOptions{serverMaxCostNano: 10_000_000}
	command := &cobra.Command{
		Use: kind, Short: verifyShort(kind), Args: safeProviderVerifyNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderVerify(cmd, opts, control, kind, values)
		},
	}
	command.SetFlagErrorFunc(func(*cobra.Command, error) error {
		return errors.New("provider verification command-line arguments are invalid")
	})
	command.Flags().BoolVar(&values.serverOwned, "server-owned", false, "verify an active server-owned upstream and credential through the Admin API")
	command.Flags().StringVar(&values.environmentID, "environment", "", "server-owned target environment ID (requires --server-owned)")
	command.Flags().StringVar(&values.upstream, "upstream", "", "server-owned upstream identifier (requires --server-owned)")
	command.Flags().StringVar(&values.model, "model", "", "ephemeral physical model identifier or server-owned logical model key")
	command.Flags().Int64Var(&values.serverMaxCostNano, "max-cost-nano-usd", values.serverMaxCostNano, "server-owned hard cost ceiling (requires --server-owned)")
	command.Flags().StringVar(&values.credentialEnv, "api-key-env", "", "read the ephemeral provider API key from this environment variable")
	command.Flags().BoolVar(&values.credentialStdin, "api-key-stdin", false, "read the ephemeral provider API key from standard input without a trailing newline")
	if kind == providerverify.ModeOpenRouter {
		command.Flags().StringVar(&values.maxCostUSD, "max-cost-usd", "", "exact two-request cost ceiling in USD (for example 0.01)")
	} else {
		command.Flags().StringVar(&values.baseURL, "base-url", "", "canonical production HTTPS OpenAI-compatible API base URL")
		command.Flags().StringVar(&values.protocol, "protocol", "", "provider protocol (openai_chat)")
		command.Flags().StringArrayVar(&values.privateCIDRs, "allow-private-cidr", nil, "explicit RFC 1918 or IPv6 ULA CIDR allowed for an internal proxy (repeatable; maximum 32)")
	}
	return command
}

func runProviderVerify(cmd *cobra.Command, opts *options, control *controlCommandOptions, kind string, values providerVerifyCLIOptions) error {
	if values.serverOwned {
		if providerLocalFlagsChanged(cmd, kind) {
			return errors.New("server-owned and ephemeral provider verification flags cannot be combined")
		}
		return runServerOwnedProviderVerify(cmd, opts, control, kind, values)
	}
	if providerServerFlagsChanged(cmd) {
		return errors.New("server-owned verification flags require --server-owned")
	}
	if values.model == "" || (!values.credentialStdin && values.credentialEnv == "") ||
		(values.credentialStdin && values.credentialEnv != "") {
		return errors.New("select exactly one of --api-key-env or --api-key-stdin and provide --model")
	}

	request := providerverify.Request{Model: values.model}
	switch kind {
	case providerverify.ModeOpenRouter:
		maximum, err := parseProviderMaxCostUSD(values.maxCostUSD)
		if err != nil {
			return err
		}
		request.Mode = providerverify.ModeOpenRouter
		request.MaxCostNanoUSD = maximum
	case "upstream":
		if values.protocol != providerverify.ModeOpenAIChat || values.baseURL == "" {
			return errors.New("ephemeral upstream verification requires --base-url and --protocol openai_chat")
		}
		request.Mode = providerverify.ModeOpenAIChat
		request.BaseURL = values.baseURL
		policy, err := parseProviderDestinationPolicy(values.privateCIDRs)
		if err != nil {
			return err
		}
		request.DestinationPolicy = policy
	default:
		return errors.New("provider verification mode is invalid")
	}

	verifyCtx, cancel := context.WithTimeout(cmd.Context(), providerVerifyTotalTimeout)
	defer cancel()
	credential, err := readProviderCredential(verifyCtx, cmd, values)
	if err != nil {
		return err
	}
	defer clearProviderCredential(credential)
	request.Credential = func(ctx context.Context, consume func([]byte) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return consume(credential)
	}
	verifier := opts.providerVerifier
	if verifier == nil {
		verifier = providerverify.New()
	}
	report, verifyErr := verifier.Verify(verifyCtx, request)
	// Do not retain the credential while rendering potentially blocking output.
	// The deferred clear remains as the early-return safety net.
	clearProviderCredential(credential)
	if verifyErr != nil {
		return safeProviderVerifyCLIError(verifyErr)
	}
	if !validProviderVerifyReport(report, request.Mode, request.MaxCostNanoUSD) {
		return errors.New("ephemeral provider verification returned an unsafe report")
	}
	return printProviderVerifyReport(opts, report)
}

func providerLocalFlagsChanged(command *cobra.Command, kind string) bool {
	for _, name := range []string{"api-key-env", "api-key-stdin"} {
		if command.Flags().Changed(name) {
			return true
		}
	}
	if kind == providerverify.ModeOpenRouter {
		return command.Flags().Changed("max-cost-usd")
	}
	return command.Flags().Changed("base-url") || command.Flags().Changed("protocol") || command.Flags().Changed("allow-private-cidr")
}

func providerServerFlagsChanged(command *cobra.Command) bool {
	for _, name := range []string{"environment", "upstream", "max-cost-nano-usd", "api-token-env"} {
		if command.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func runServerOwnedProviderVerify(cmd *cobra.Command, opts *options, control *controlCommandOptions, kind string, values providerVerifyCLIOptions) error {
	if id.Validate(values.environmentID, id.Environment) != nil ||
		!secretNamePattern.MatchString(values.upstream) || !secretNamePattern.MatchString(values.model) ||
		values.serverMaxCostNano < 1 || values.serverMaxCostNano > 1_000_000_000 {
		return errors.New("server-owned verification environment, selection, or cost bound is invalid")
	}
	request := map[string]any{
		"kind": kind, "environment_id": values.environmentID, "upstream": values.upstream,
		"model": values.model, "max_cost_nano_usd": values.serverMaxCostNano,
	}
	client, err := newControlAPIClient(opts, control.tokenEnvironment)
	if err != nil {
		return err
	}
	var run selfTestRunCLI
	if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/self-tests", nil, request, http.StatusAccepted, &run); err != nil {
		return err
	}
	return printSelfTest(opts, run)
}

func parseProviderMaxCostUSD(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("ephemeral OpenRouter verification requires --max-cost-usd")
	}
	result, err := pricing.ParseUSDDecimalNanoUSD(value)
	if err != nil || result < 0 || result > 1_000_000_000 {
		return 0, errors.New("--max-cost-usd must be an exact non-negative USD decimal no greater than 1")
	}
	return result, nil
}

func readProviderCredential(ctx context.Context, command *cobra.Command, values providerVerifyCLIOptions) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("provider API key input is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var material []byte
	if values.credentialEnv != "" {
		if !providerCredentialEnvironmentPattern.MatchString(values.credentialEnv) {
			return nil, errors.New("provider API key environment variable name is invalid")
		}
		value, present := os.LookupEnv(values.credentialEnv)
		if !present || len(value) == 0 || len(value) > maximumProviderCredentialBytes {
			return nil, errors.New("provider API key environment variable is missing or invalid")
		}
		material = []byte(value)
	} else {
		value, err := readProviderCredentialStdin(ctx, command.InOrStdin())
		if err != nil || len(value) == 0 || len(value) > maximumProviderCredentialBytes {
			clearProviderCredential(value)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, errors.New("provider API key stdin value is missing or invalid")
		}
		material = value
	}
	if !validProviderCredential(material) {
		clearProviderCredential(material)
		return nil, errors.New("provider API key contains invalid bytes")
	}
	return material, nil
}

type providerCredentialReadDeadliner interface {
	SetReadDeadline(time.Time) error
}

func readProviderCredentialStdin(ctx context.Context, source io.Reader) ([]byte, error) {
	if source == nil {
		return nil, errors.New("stdin unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	var stop func()
	if deadlines, ok := source.(providerCredentialReadDeadliner); ok {
		deadline, hasDeadline := ctx.Deadline()
		if hasDeadline && deadlines.SetReadDeadline(deadline) == nil {
			go func() {
				select {
				case <-ctx.Done():
					_ = deadlines.SetReadDeadline(time.Now())
				case <-done:
				}
			}()
			stop = func() {
				close(done)
				_ = deadlines.SetReadDeadline(time.Time{})
			}
		}
	}
	if stop == nil {
		if closer, ok := source.(io.ReadCloser); ok {
			go func() {
				select {
				case <-ctx.Done():
					_ = closer.Close()
				case <-done:
				}
			}()
			stop = func() { close(done) }
		}
	}
	if stop != nil {
		defer stop()
	}

	value, err := io.ReadAll(io.LimitReader(source, maximumProviderCredentialBytes+1))
	if ctx.Err() != nil {
		clearProviderCredential(value)
		return nil, ctx.Err()
	}
	if err != nil {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			clearProviderCredential(value)
			return nil, context.DeadlineExceeded
		}
	}
	return value, err
}

func safeProviderVerifyNoArgs(_ *cobra.Command, args []string) error {
	if len(args) != 0 {
		return errors.New("provider verification command-line arguments are invalid")
	}
	return nil
}

func parseProviderDestinationPolicy(values []string) (upstream.DestinationPolicy, error) {
	if len(values) == 0 {
		return upstream.DestinationPolicy{}, nil
	}
	if len(values) > 32 {
		return upstream.DestinationPolicy{}, errors.New("--allow-private-cidr accepts at most 32 explicit CIDRs")
	}
	policy := upstream.DestinationPolicy{AllowPrivate: true, AllowedCIDRs: make([]netip.Prefix, 0, len(values))}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value {
			return upstream.DestinationPolicy{}, errors.New("--allow-private-cidr values must be canonical RFC 1918 or IPv6 ULA CIDRs")
		}
		policy.AllowedCIDRs = append(policy.AllowedCIDRs, prefix)
	}
	if err := upstream.ValidateDestinationPolicy(policy); err != nil {
		return upstream.DestinationPolicy{}, errors.New("--allow-private-cidr values must be canonical, non-overlapping RFC 1918 or IPv6 ULA CIDRs")
	}
	return policy, nil
}

func validProviderCredential(value []byte) bool {
	if len(value) == 0 || len(value) > maximumProviderCredentialBytes || value[0] == '=' {
		return false
	}
	padding := false
	for _, character := range value {
		if character == '=' {
			padding = true
			continue
		}
		if padding || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._~+/", rune(character))) {
			return false
		}
	}
	return true
}

func clearProviderCredential(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func safeProviderVerifyCLIError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var safe *providerverify.Error
	if errors.As(err, &safe) && providerVerifyCheckPattern.MatchString(safe.Code) {
		return fmt.Errorf("ephemeral provider verification failed (%s)", safe.Code)
	}
	return errors.New("ephemeral provider verification failed")
}

func validProviderVerifyReport(report providerverify.Report, mode string, maximum int64) bool {
	expectedChecks := expectedProviderVerifyChecks(mode)
	if !report.Passed || report.Mode != mode || len(report.Checks) != len(expectedChecks) {
		return false
	}
	if mode == providerverify.ModeOpenRouter {
		if report.CostVerification != providerverify.CostVerified || report.MaximumCostNanoUSD < 0 ||
			report.MaximumCostNanoUSD > maximum || report.CalculatedCostNanoUSD < 0 ||
			report.ReportedCostNanoUSD < 0 || report.CalculatedCostNanoUSD > report.MaximumCostNanoUSD ||
			report.ReportedCostNanoUSD > report.CalculatedCostNanoUSD {
			return false
		}
	} else if report.CostVerification != providerverify.CostUnverified || report.MaximumCostNanoUSD != 0 ||
		report.CalculatedCostNanoUSD != 0 || report.ReportedCostNanoUSD != 0 {
		return false
	}
	for _, usage := range []providerverify.Usage{report.NonStreaming, report.Streaming} {
		if usage.InputTokens <= 0 || usage.OutputTokens <= 0 || usage.OutputTokens > 1 ||
			usage.TotalTokens != usage.InputTokens+usage.OutputTokens || usage.ReportedCostNanoUSD < 0 {
			return false
		}
	}
	seenChecks := make(map[string]struct{}, len(report.Checks))
	for _, check := range report.Checks {
		if !check.Passed || !providerVerifyCheckPattern.MatchString(check.Name) || len(check.Detail) > 512 ||
			!utf8.ValidString(check.Detail) || strings.ContainsAny(check.Detail, "\x00\r\n") {
			return false
		}
		expectedDetail, known := expectedChecks[check.Name]
		if _, duplicate := seenChecks[check.Name]; duplicate || !known || expectedDetail != check.Detail {
			return false
		}
		seenChecks[check.Name] = struct{}{}
	}
	if len(seenChecks) != len(expectedChecks) {
		return false
	}
	if mode == providerverify.ModeOpenRouter {
		if report.NonStreaming.ReportedCostNanoUSD > int64(^uint64(0)>>1)-report.Streaming.ReportedCostNanoUSD ||
			report.NonStreaming.ReportedCostNanoUSD+report.Streaming.ReportedCostNanoUSD != report.ReportedCostNanoUSD {
			return false
		}
	}
	return true
}

func expectedProviderVerifyChecks(mode string) map[string]string {
	expected := make(map[string]string, 9)
	for name, detail := range providerVerifyCommonCheckDetails {
		expected[name] = detail
	}
	if mode == providerverify.ModeOpenRouter {
		expected["target"] = "The canonical OpenRouter HTTPS target passed protected destination validation."
		expected["model_pricing"] = "Exact selected-model pricing and context metadata were validated."
		expected["key_information"] = "The key is inference-capable, current, and has sufficient declared credit or free access."
		expected["cost_preflight"] = "The complete live-probe worst-case cost was proved below the operator ceiling before dispatch."
		expected["cost_reconciliation"] = "Provider-reported cost was exact and did not exceed the trusted calculated bound."
	} else if mode == providerverify.ModeOpenAIChat {
		expected["target"] = "The generic HTTPS target passed protected destination validation."
		expected["cost_preflight"] = "No trusted generic price source was supplied; monetary cost remains explicitly unverified."
	}
	return expected
}

func printProviderVerifyReport(opts *options, report providerverify.Report) error {
	if opts.output == "json" {
		return printControlJSON(opts, report)
	}
	if _, err := fmt.Fprintf(opts.stdout, "verification: passed\nmode: %s\ncost: %s\n", report.Mode, report.CostVerification); err != nil {
		return err
	}
	if report.CostVerification == providerverify.CostVerified {
		if _, err := fmt.Fprintf(opts.stdout, "maximum cost (nano-USD): %d\ncalculated cost (nano-USD): %d\nreported cost (nano-USD): %d\n",
			report.MaximumCostNanoUSD, report.CalculatedCostNanoUSD, report.ReportedCostNanoUSD); err != nil {
			return err
		}
	}
	rows := make([][]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		rows = append(rows, []string{check.Name, "passed", check.Detail})
	}
	return printControlTable(opts, []string{"CHECK", "STATE", "DETAIL"}, rows)
}
