package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func runPreflight(ctx context.Context, cfg config, client *protectedClient) gateResult {
	gate := newGate("preflight")
	readyURL := client.target(cfg.Gateway.ReadyPath)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, readyURL.String(), nil)
	if err == nil {
		var response *http.Response
		response, err = client.http.Do(request)
		if err == nil {
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			if response.StatusCode != http.StatusOK {
				err = fmt.Errorf("readiness status %d, want 200", response.StatusCode)
			}
		}
	}
	if err == nil {
		result := client.execute(ctx, withRequestID(cfg.NonStream, 0))
		if requestErr := validateExpectedJSON(result, cfg.NonStream.ExpectedStatus); requestErr != nil {
			err = fmt.Errorf("warm protected request: %w", requestErr)
		}
	}
	gate.Metrics = map[string]any{"ready_url": redactedURL(readyURL)}
	gate.finish(err)
	return gate
}

func runIdleGate(ctx context.Context, cfg config, pid int) gateResult {
	gate := newGate("idle_memory")
	select {
	case <-ctx.Done():
		gate.finish(ctx.Err())
		return gate
	case <-time.After(time.Duration(cfg.Targets.IdleWarmupSeconds) * time.Second):
	}
	samples := make([]float64, 0, 5)
	var err error
	for range 5 {
		var rss float64
		rss, err = processRSSMiB(pid)
		if err != nil {
			break
		}
		samples = append(samples, rss)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		if err != nil {
			break
		}
	}
	maximum := 0.0
	for _, sample := range samples {
		maximum = math.Max(maximum, sample)
	}
	gate.Metrics = map[string]any{
		"pid": pid, "rss_samples_mib": samples, "maximum_rss_mib": maximum,
		"target_mib": cfg.Targets.IdleMemoryMiB,
	}
	if err == nil && maximum >= cfg.Targets.IdleMemoryMiB {
		err = fmt.Errorf("idle RSS %.2f MiB is not below %.2f MiB", maximum, cfg.Targets.IdleMemoryMiB)
	}
	gate.finish(err)
	return gate
}

func runOverheadGate(ctx context.Context, cfg config, client *protectedClient) gateResult {
	gate := newGate("gateway_overhead")
	baselineClient := &http.Client{Timeout: cfg.timeout()}
	var err error
	for index := range cfg.Targets.OverheadWarmup {
		result := executeBaseline(ctx, baselineClient, cfg)
		if requestErr := validateExpectedJSON(result, cfg.Baseline.ExpectedStatus); requestErr != nil {
			err = fmt.Errorf("baseline warmup %d failed: %v", index, requestErr)
			break
		}
		result = client.execute(ctx, withRequestID(cfg.NonStream, -index-1))
		if requestErr := validateExpectedJSON(result, cfg.NonStream.ExpectedStatus); requestErr != nil {
			err = fmt.Errorf("gateway warmup %d failed: %v", index, requestErr)
			break
		}
	}
	overheads := make([]time.Duration, 0, cfg.Targets.OverheadSamples)
	gatewaySamples := make([]time.Duration, 0, cfg.Targets.OverheadSamples)
	baselineSamples := make([]time.Duration, 0, cfg.Targets.OverheadSamples)
	for index := 0; err == nil && index < cfg.Targets.OverheadSamples; index++ {
		var gateway, baseline requestResult
		if index%2 == 0 {
			baseline = executeBaseline(ctx, baselineClient, cfg)
			gateway = client.execute(ctx, withRequestID(cfg.NonStream, index))
		} else {
			gateway = client.execute(ctx, withRequestID(cfg.NonStream, index))
			baseline = executeBaseline(ctx, baselineClient, cfg)
		}
		gatewayErr := validateExpectedJSON(gateway, cfg.NonStream.ExpectedStatus)
		baselineErr := validateExpectedJSON(baseline, cfg.Baseline.ExpectedStatus)
		if gatewayErr != nil || baselineErr != nil {
			err = fmt.Errorf("paired sample %d failed: gateway=%v baseline=%v", index, gatewayErr, baselineErr)
			break
		}
		overhead := gateway.Latency - baseline.Latency
		if overhead < 0 {
			overhead = 0
		}
		overheads = append(overheads, overhead)
		gatewaySamples = append(gatewaySamples, gateway.Latency)
		baselineSamples = append(baselineSamples, baseline.Latency)
	}
	p50 := percentile(overheads, 0.50)
	p95 := percentile(overheads, 0.95)
	p99 := percentile(overheads, 0.99)
	gate.Metrics = map[string]any{
		"method":          "paired client-observed gateway minus direct fixture latency, floored at zero",
		"samples":         len(overheads),
		"p50_overhead_ms": milliseconds(p50), "p95_overhead_ms": milliseconds(p95), "p99_overhead_ms": milliseconds(p99),
		"p50_gateway_e2e_ms": milliseconds(percentile(gatewaySamples, .50)), "p95_gateway_e2e_ms": milliseconds(percentile(gatewaySamples, .95)), "p99_gateway_e2e_ms": milliseconds(percentile(gatewaySamples, .99)),
		"p50_direct_upstream_ms": milliseconds(percentile(baselineSamples, .50)), "p95_direct_upstream_ms": milliseconds(percentile(baselineSamples, .95)), "p99_direct_upstream_ms": milliseconds(percentile(baselineSamples, .99)),
		"targets_ms": map[string]float64{"p50": cfg.Targets.P50Milliseconds, "p95": cfg.Targets.P95Milliseconds, "p99": cfg.Targets.P99Milliseconds},
	}
	if err == nil && (milliseconds(p50) >= cfg.Targets.P50Milliseconds || milliseconds(p95) >= cfg.Targets.P95Milliseconds || milliseconds(p99) >= cfg.Targets.P99Milliseconds) {
		err = fmt.Errorf("gateway overhead thresholds failed: p50=%.3f p95=%.3f p99=%.3f ms", milliseconds(p50), milliseconds(p95), milliseconds(p99))
	}
	gate.finish(err)
	return gate
}

func runNonStreamGate(ctx context.Context, cfg config, client *protectedClient) gateResult {
	gate := newGate("non_stream_100_rps")
	total := cfg.Targets.NonStreamRPS * cfg.Targets.NonStreamDurationSeconds
	type scheduledResult struct {
		requestResult
		startLag time.Duration
	}
	results := make(chan scheduledResult, total)
	started := time.Now()
	maximumSchedulerLag := time.Duration(0)
	maximumStartLag := time.Duration(0)
	for index := range total {
		target := started.Add(time.Duration(index) * time.Second / time.Duration(cfg.Targets.NonStreamRPS))
		if wait := time.Until(target); wait > 0 {
			select {
			case <-ctx.Done():
				gate.finish(ctx.Err())
				return gate
			case <-time.After(wait):
			}
		}
		lag := time.Since(target)
		maximumSchedulerLag = max(maximumSchedulerLag, lag)
		specification := withRequestID(cfg.NonStream, 10_000+index)
		go func() {
			actualStartLag := time.Since(target)
			requestCtx, cancel := context.WithTimeout(ctx, cfg.timeout())
			defer cancel()
			results <- scheduledResult{requestResult: client.execute(requestCtx, specification), startLag: actualStartLag}
		}()
	}
	statuses := make(map[int]int)
	successful := 0
	failed := 0
	latencies := make([]time.Duration, 0, total)
	for range total {
		result := <-results
		maximumStartLag = max(maximumStartLag, result.startLag)
		statuses[result.Status]++
		latencies = append(latencies, result.Latency)
		if validateExpectedJSON(result.requestResult, cfg.NonStream.ExpectedStatus) == nil {
			successful++
		} else {
			failed++
		}
	}
	completionElapsed := time.Since(started)
	snapshot, snapshotErr := client.quotaSnapshot(ctx, cfg.Quota.NonStreamSnapshotPath, cfg.NonStream)
	quotaErr := validateSettledHardLimits(snapshot)
	if snapshotErr != nil {
		quotaErr = snapshotErr
	}
	gate.Metrics = map[string]any{
		"target_rps": cfg.Targets.NonStreamRPS, "duration_seconds": cfg.Targets.NonStreamDurationSeconds,
		"scheduled": total, "successful": successful, "failed": failed, "statuses": statuses,
		"maximum_scheduler_lag_ms": milliseconds(maximumSchedulerLag), "maximum_request_start_lag_ms": milliseconds(maximumStartLag), "schedule_lag_target_ms": cfg.Targets.MaximumScheduleLagMilliseconds,
		"completion_elapsed_seconds": completionElapsed.Seconds(),
		"p50_e2e_ms":                 milliseconds(percentile(latencies, .50)), "p95_e2e_ms": milliseconds(percentile(latencies, .95)), "p99_e2e_ms": milliseconds(percentile(latencies, .99)),
		"quota_snapshot": snapshot,
	}
	var err error
	if failed != 0 || successful != total {
		err = fmt.Errorf("%d/%d scheduled requests did not complete with expected status", failed, total)
	} else if maximumStartLag >= time.Duration(cfg.Targets.MaximumScheduleLagMilliseconds)*time.Millisecond {
		err = fmt.Errorf("maximum request start lag %s reached %dms bound", maximumStartLag, cfg.Targets.MaximumScheduleLagMilliseconds)
	} else if quotaErr != nil {
		err = quotaErr
	}
	gate.finish(err)
	return gate
}

func runContentionGate(ctx context.Context, cfg config, client *protectedClient) gateResult {
	gate := newGate("quota_contention_zero_overspend")
	before, err := client.quotaSnapshot(ctx, cfg.Quota.ContentionSnapshotPath, cfg.Quota.ContentionRequest)
	if err != nil {
		gate.finish(err)
		return gate
	}
	limit, err := uniqueLimit(before, cfg.Quota.ContentionMetric)
	if err != nil {
		gate.finish(err)
		return gate
	}
	if limit.Maximum == nil || limit.Used == nil || limit.Reserved == nil || limit.Remaining == nil || limit.ResetsAt == nil || !limit.Hard {
		gate.finish(errors.New("contention oracle requires one hard calendar-style limit with maximum, used, reserved, and remaining"))
		return gate
	}
	if int64(cfg.Quota.ContentionAttempts) <= *limit.Remaining {
		gate.finish(fmt.Errorf("contention_attempts=%d must exceed the selected limit remaining=%d", cfg.Quota.ContentionAttempts, *limit.Remaining))
		return gate
	}
	start := make(chan struct{})
	results := make(chan requestResult, cfg.Quota.ContentionAttempts)
	for index := range cfg.Quota.ContentionAttempts {
		specification := withRequestID(cfg.Quota.ContentionRequest, 100_000+index)
		go func() {
			<-start
			requestCtx, cancel := context.WithTimeout(ctx, cfg.timeout())
			defer cancel()
			results <- client.execute(requestCtx, specification)
		}()
	}
	close(start)
	accepted := int64(0)
	denied := 0
	unexpected := 0
	statuses := make(map[int]int)
	for range cfg.Quota.ContentionAttempts {
		result := <-results
		statuses[result.Status]++
		switch {
		case validateExpectedJSON(result, cfg.Quota.ContentionRequest.ExpectedStatus) == nil:
			accepted++
		case result.Err == nil && result.Status == cfg.Quota.DenialStatus:
			denied++
		default:
			unexpected++
		}
	}
	after, afterErr := waitForSettledSnapshot(ctx, cfg, client, cfg.Quota.ContentionSnapshotPath, cfg.Quota.ContentionRequest)
	if afterErr != nil {
		err = afterErr
	}
	afterLimit, limitErr := uniqueLimit(after, cfg.Quota.ContentionMetric)
	if err == nil && limitErr != nil {
		err = limitErr
	}
	expectedAccepted := *limit.Remaining
	if expectedAccepted < 0 {
		expectedAccepted = 0
	}
	if expectedAccepted > int64(cfg.Quota.ContentionAttempts) {
		expectedAccepted = int64(cfg.Quota.ContentionAttempts)
	}
	gate.Metrics = map[string]any{
		"metric": cfg.Quota.ContentionMetric, "attempts": cfg.Quota.ContentionAttempts,
		"accepted": accepted, "expected_accepted": expectedAccepted, "denied": denied, "unexpected": unexpected,
		"statuses": statuses, "before": before, "after": after,
	}
	if err == nil && unexpected != 0 {
		err = fmt.Errorf("contention returned %d unexpected results", unexpected)
	}
	if err == nil && accepted != expectedAccepted {
		err = fmt.Errorf("contention accepted %d requests, want exact remaining capacity %d", accepted, expectedAccepted)
	}
	if err == nil && (afterLimit.Maximum == nil || afterLimit.Used == nil || afterLimit.Reserved == nil || *afterLimit.Used+*afterLimit.Reserved > *afterLimit.Maximum || *afterLimit.Reserved != 0) {
		err = errors.New("post-contention quota state overspent its maximum or retained reservations")
	}
	gate.finish(err)
	return gate
}

func runSSEGate(ctx context.Context, cfg config, client *protectedClient, pid int) gateResult {
	gate := newGate("sse_500_concurrent_memory")
	baselineRSS, err := processRSSMiB(pid)
	if err != nil {
		gate.finish(err)
		return gate
	}
	streamCtx, cancelStreams := context.WithCancel(ctx)
	defer cancelStreams()
	established := make(chan requestResult, cfg.Targets.SSEConcurrency)
	completed := make(chan requestResult, cfg.Targets.SSEConcurrency)
	for index := range cfg.Targets.SSEConcurrency {
		specification := withRequestID(cfg.Stream, 200_000+index)
		go openStream(streamCtx, client, specification, established, completed)
	}
	establishedCount := 0
	completedObserved := 0
	establishmentDeadline := time.NewTimer(cfg.timeout())
	defer establishmentDeadline.Stop()
	for establishedCount < cfg.Targets.SSEConcurrency && err == nil {
		select {
		case result := <-established:
			if result.Err != nil || result.Status != cfg.Stream.ExpectedStatus {
				err = fmt.Errorf("stream establishment failed: status=%d error=%v", result.Status, result.Err)
				break
			}
			establishedCount++
		case result := <-completed:
			completedObserved++
			err = fmt.Errorf("stream completed before all peers established: status=%d error=%v", result.Status, result.Err)
		case <-establishmentDeadline.C:
			err = fmt.Errorf("only %d/%d streams established within %s", establishedCount, cfg.Targets.SSEConcurrency, cfg.timeout())
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	samples := []memorySample{{At: time.Now(), MiB: baselineRSS}}
	premature := 0
	if err == nil {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		hold := time.NewTimer(time.Duration(cfg.Targets.SSEHoldSeconds) * time.Second)
		defer hold.Stop()
	holdLoop:
		for {
			select {
			case result := <-completed:
				premature++
				completedObserved++
				if result.Err != nil {
					err = fmt.Errorf("stream ended during hold: %v", result.Err)
				} else {
					err = errors.New("stream ended during required hold period")
				}
				break holdLoop
			case sampledAt := <-ticker.C:
				rss, rssErr := processRSSMiB(pid)
				if rssErr != nil {
					err = rssErr
					break holdLoop
				}
				samples = append(samples, memorySample{At: sampledAt, MiB: rss})
			case <-hold.C:
				break holdLoop
			case <-ctx.Done():
				err = ctx.Err()
				break holdLoop
			}
		}
	}
	cancelStreams()
	cleanupDeadline := time.NewTimer(cfg.timeout())
	defer cleanupDeadline.Stop()
	for completedCount := completedObserved; completedCount < cfg.Targets.SSEConcurrency; completedCount++ {
		select {
		case <-completed:
		case <-cleanupDeadline.C:
			if err == nil {
				err = errors.New("stream clients did not stop within cleanup timeout")
			}
			completedCount = cfg.Targets.SSEConcurrency
		}
	}
	peak := baselineRSS
	for _, sample := range samples {
		peak = math.Max(peak, sample.MiB)
	}
	plateau := samples
	if len(plateau) > 4 {
		plateau = plateau[len(plateau)/2:]
	}
	slope := memorySlopeMiBPerMinute(plateau)
	growth := peak - baselineRSS
	gate.Metrics = map[string]any{
		"established": establishedCount, "target_concurrency": cfg.Targets.SSEConcurrency,
		"hold_seconds": cfg.Targets.SSEHoldSeconds, "premature_completions": premature,
		"baseline_rss_mib": baselineRSS, "peak_rss_mib": peak, "growth_mib": growth,
		"growth_target_mib":            cfg.Targets.MaximumStreamGrowthMiB,
		"plateau_slope_mib_per_minute": slope, "slope_target_mib_per_minute": cfg.Targets.MaximumStreamSlopeMiBPerMinute,
		"rss_samples": samples,
	}
	if err == nil && establishedCount != cfg.Targets.SSEConcurrency {
		err = fmt.Errorf("established %d streams, want %d", establishedCount, cfg.Targets.SSEConcurrency)
	} else if err == nil && growth >= cfg.Targets.MaximumStreamGrowthMiB {
		err = fmt.Errorf("stream RSS growth %.2f MiB reached %.2f MiB bound", growth, cfg.Targets.MaximumStreamGrowthMiB)
	} else if err == nil && slope >= cfg.Targets.MaximumStreamSlopeMiBPerMinute {
		err = fmt.Errorf("stream RSS slope %.2f MiB/min reached %.2f bound", slope, cfg.Targets.MaximumStreamSlopeMiBPerMinute)
	}
	if err == nil {
		_, settleErr := waitForSettledSnapshot(ctx, cfg, client, cfg.Quota.StreamSnapshotPath, cfg.Stream)
		if settleErr != nil {
			err = settleErr
		}
	}
	gate.finish(err)
	return gate
}

func openStream(ctx context.Context, client *protectedClient, specification requestConfig, established, completed chan<- requestResult) {
	started := time.Now()
	request, err := client.request(ctx, specification)
	if err != nil {
		result := requestResult{Latency: time.Since(started), Err: err}
		established <- result
		completed <- result
		return
	}
	response, err := client.http.Do(request)
	if err != nil {
		result := requestResult{Latency: time.Since(started), Err: err}
		established <- result
		completed <- result
		return
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "text/event-stream" {
		result := requestResult{Status: response.StatusCode, Latency: time.Since(started), Err: errors.New("stream response is not text/event-stream")}
		established <- result
		completed <- result
		return
	}
	reader := bufio.NewReaderSize(response.Body, 4096)
	readErr := readFirstSSEEvent(reader)
	firstByteAt := time.Now()
	result := requestResult{Status: response.StatusCode, Latency: firstByteAt.Sub(started), FirstByteAt: firstByteAt, Err: readErr}
	established <- result
	if readErr == nil {
		_, readErr = io.Copy(io.Discard, reader)
	}
	completed <- requestResult{Status: response.StatusCode, Latency: time.Since(started), FirstByteAt: firstByteAt, Err: readErr}
}

func readFirstSSEEvent(reader *bufio.Reader) error {
	const maximumFirstEventBytes = 64 << 10
	total := 0
	hasData := false
	for total <= maximumFirstEventBytes {
		line, err := reader.ReadString('\n')
		total += len(line)
		trimmed := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(trimmed, "data:") {
			hasData = true
		}
		if trimmed == "" {
			if !hasData {
				return errors.New("first SSE event contains no data field")
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
	return errors.New("first SSE event exceeds 64 KiB")
}

func withRequestID(input requestConfig, index int) requestConfig {
	result := input
	result.Headers = make(map[string]string, len(input.Headers)+1)
	for key, value := range input.Headers {
		result.Headers[key] = value
	}
	result.Headers["X-Latchway-Request-ID"] = requestID(index)
	return result
}

func waitForSettledSnapshot(ctx context.Context, cfg config, client *protectedClient, path string, headers requestConfig) (quotaSnapshot, error) {
	deadline := time.NewTimer(cfg.timeout())
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last quotaSnapshot
	for {
		var err error
		last, err = client.quotaSnapshot(ctx, path, headers)
		if err == nil && validateSettledHardLimits(last) == nil {
			return last, nil
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			if err != nil {
				return last, err
			}
			return last, validateSettledHardLimits(last)
		case <-ctx.Done():
			return last, ctx.Err()
		}
	}
}

func validateSettledHardLimits(snapshot quotaSnapshot) error {
	for _, limit := range snapshot.Limits {
		if !limit.Hard {
			continue
		}
		if limit.Maximum != nil && limit.Used != nil && limit.Reserved != nil && *limit.Used+*limit.Reserved > *limit.Maximum {
			return fmt.Errorf("hard %s limit overspent: used=%d reserved=%d maximum=%d", limit.Metric, *limit.Used, *limit.Reserved, *limit.Maximum)
		}
		if limit.Reserved != nil && *limit.Reserved != 0 {
			return fmt.Errorf("hard %s limit retained %d reserved units", limit.Metric, *limit.Reserved)
		}
	}
	return nil
}

func uniqueLimit(snapshot quotaSnapshot, metric string) (quotaLimit, error) {
	matches := make([]quotaLimit, 0, 1)
	for _, limit := range snapshot.Limits {
		if limit.Metric == metric {
			matches = append(matches, limit)
		}
	}
	if len(matches) != 1 {
		return quotaLimit{}, fmt.Errorf("quota snapshot has %d %q limits; contention oracle requires exactly one", len(matches), metric)
	}
	return matches[0], nil
}

func redactedURL(value *url.URL) string {
	copy := *value
	copy.User = nil
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}

func milliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}
