package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/conformance/mockupstream"
	"github.com/spf13/cobra"
)

const defaultTestUpstreamListen = "127.0.0.1:19090"

type testUpstreamServeOptions struct {
	listen              string
	scenario            string
	allowScenarioHeader bool
	firstByteDelay      time.Duration
	cancellationWait    time.Duration
	maxRequestBodyBytes int64
	maxOutputBytes      int
	oversizedEventBytes int
	inputTokens         int
	outputTokens        int
	costNanoUSD         int64
	shutdownTimeout     time.Duration
}

func newTestUpstreamCommand(opts *options) *cobra.Command {
	command := &cobra.Command{
		Use:   "test-upstream",
		Short: "Run deterministic loopback-only upstream fixtures",
	}
	command.AddCommand(newTestUpstreamServeCommand(opts))
	return command
}

func newTestUpstreamServeCommand(opts *options) *cobra.Command {
	defaults := mockupstream.DefaultConfig()
	scenarios := make([]string, 0, len(mockupstream.SupportedScenarios()))
	for _, scenario := range mockupstream.SupportedScenarios() {
		scenarios = append(scenarios, string(scenario))
	}
	values := testUpstreamServeOptions{
		listen: defaultTestUpstreamListen, scenario: string(defaults.Scenario),
		firstByteDelay: defaults.FirstByteDelay, cancellationWait: defaults.CancellationWait,
		maxRequestBodyBytes: defaults.MaxRequestBodyBytes, maxOutputBytes: defaults.MaxOutputBytes,
		oversizedEventBytes: defaults.OversizedEventBytes,
		inputTokens:         defaults.FixedUsage.InputTokens, outputTokens: defaults.FixedUsage.OutputTokens,
		costNanoUSD: defaults.FixedCostNanoUSD, shutdownTimeout: 10 * time.Second,
	}
	command := &cobra.Command{
		Use:   "serve",
		Short: "Serve the bounded deterministic mock upstream on loopback",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateTestUpstreamListenAddress(values.listen); err != nil {
				return err
			}
			if values.shutdownTimeout < time.Second || values.shutdownTimeout > 30*time.Second {
				return errors.New("test upstream shutdown timeout must be between 1s and 30s")
			}
			handler, err := mockupstream.New(mockupstream.Config{
				Scenario:            mockupstream.Scenario(values.scenario),
				AllowScenarioHeader: values.allowScenarioHeader,
				FirstByteDelay:      values.firstByteDelay, CancellationWait: values.cancellationWait,
				MaxRequestBodyBytes: values.maxRequestBodyBytes, MaxOutputBytes: values.maxOutputBytes,
				OversizedEventBytes: values.oversizedEventBytes,
				FixedUsage:          mockupstream.Usage{InputTokens: values.inputTokens, OutputTokens: values.outputTokens},
				FixedCostNanoUSD:    values.costNanoUSD,
			})
			if err != nil {
				return err
			}
			listener, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", values.listen)
			if err != nil {
				return fmt.Errorf("listen for test upstream: %w", err)
			}
			defer func() { _ = listener.Close() }()
			if err := opts.print(map[string]any{
				"listen": listener.Addr().String(), "scenario": values.scenario,
				"scenario_header": values.allowScenarioHeader, "status": "ready",
			}); err != nil {
				return err
			}
			return serveTestUpstream(cmd.Context(), listener, handler, values.shutdownTimeout)
		},
	}
	command.Flags().StringVar(&values.listen, "listen", values.listen, "explicit loopback host and port")
	command.Flags().StringVar(&values.scenario, "scenario", values.scenario,
		"deterministic default response scenario: "+strings.Join(scenarios, ", "))
	command.Flags().BoolVar(&values.allowScenarioHeader, "allow-scenario-header", false, "allow the bounded per-request test scenario header")
	command.Flags().DurationVar(&values.firstByteDelay, "first-byte-delay", values.firstByteDelay, "delay used by delayed-first-byte responses")
	command.Flags().DurationVar(&values.cancellationWait, "cancellation-wait", values.cancellationWait, "maximum cancellation-observation wait")
	command.Flags().Int64Var(&values.maxRequestBodyBytes, "max-request-body-bytes", values.maxRequestBodyBytes, "maximum accepted mock request body")
	command.Flags().IntVar(&values.maxOutputBytes, "max-output-bytes", values.maxOutputBytes, "maximum emitted mock response body")
	command.Flags().IntVar(&values.oversizedEventBytes, "oversized-event-bytes", values.oversizedEventBytes, "payload size used by the oversized-event scenario")
	command.Flags().IntVar(&values.inputTokens, "input-tokens", values.inputTokens, "fixed successful-response input-token usage")
	command.Flags().IntVar(&values.outputTokens, "output-tokens", values.outputTokens, "fixed successful-response output-token usage")
	command.Flags().Int64Var(&values.costNanoUSD, "cost-nano-usd", values.costNanoUSD, "fixed successful-response cost in nano-USD")
	command.Flags().DurationVar(&values.shutdownTimeout, "shutdown-timeout", values.shutdownTimeout, "graceful shutdown deadline")
	_ = command.RegisterFlagCompletionFunc("scenario", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return scenarios, cobra.ShellCompDirectiveNoFileComp
	})
	command.ValidArgsFunction = cobra.NoFileCompletions
	return command
}

func validateTestUpstreamListenAddress(raw string) error {
	host, rawPort, err := net.SplitHostPort(raw)
	if err != nil || host == "" || rawPort == "" {
		return errors.New("test upstream listen address must contain one explicit loopback host and port")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("test upstream listen port must be between 0 and 65535")
	}
	if host == "localhost" {
		return nil
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return errors.New("test upstream listen host must be localhost or one explicit loopback IP")
	}
	return nil
}

func serveTestUpstream(
	ctx context.Context,
	listener net.Listener,
	handler http.Handler,
	shutdownTimeout time.Duration,
) error {
	if ctx == nil || listener == nil || handler == nil || shutdownTimeout <= 0 {
		return errors.New("test upstream server configuration is invalid")
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve test upstream: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownContext)
		if shutdownErr != nil {
			_ = server.Close()
		}
		serveErr := <-serveErrors
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}
}
