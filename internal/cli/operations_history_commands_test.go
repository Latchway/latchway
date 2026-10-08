package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOperationsHistoryCommands(t *testing.T) {
	t.Setenv("TEST_LATCHWAY_HISTORY_TOKEN", strings.Repeat("history-control-token-", 2))
	const runID = "tst_00000000000000000000000000"
	var queries []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
		}
		queries = append(queries, request.URL.Path+"?"+request.URL.RawQuery)
		switch request.URL.Path {
		case "/admin/v1/system/health-history":
			return controlHTTPResponse(request, http.StatusOK, `{"start":"2026-10-07T00:00:00Z","end":"2026-10-08T00:00:00Z","interval_seconds":300,"samples":[`+
				`{"sampled_at":"2026-10-07T00:00:00Z","overall_state":"healthy","failed_checks":[],"warning_checks":[]},`+
				`{"sampled_at":"2026-10-07T00:05:00Z","overall_state":"unhealthy","failed_checks":["worker_heartbeat"],"warning_checks":["external_jwks_reachability"]}]}`, nil), nil
		case "/admin/v1/usage/connections":
			environment := request.URL.Query().Get("environment_id")
			return controlHTTPResponse(request, http.StatusOK, `{"environment_id":"`+environment+`","start":"2026-10-07T00:00:00Z","end":"2026-10-08T00:00:00Z","interval":"day","connections":[`+
				`{"upstream":"openai","attempts":20,"succeeded":18,"failed":2,"canceled":0,"rate_limited":2,"server_errors":0,"fell_back":2,`+
				`"failures":[{"code":"upstream_rejected","count":2}],"first_byte":{"samples":18,"p50_ms":300,"p95_ms":800,"p99_ms":900},`+
				`"duration":{"samples":18,"p50_ms":900,"p95_ms":2400,"p99_ms":2600},"usage":{"logical_requests":18,"input_tokens":10,"output_tokens":5,"total_tokens":15,"cost_nano_usd":1250000000}}],`+
				`"truncated":false,"series":[{"upstream":"openai","timestamp":"2026-10-07T00:00:00Z","attempts":20,"failed":2}]}`, nil), nil
		case "/admin/v1/self-tests":
			environment := request.URL.Query().Get("environment_id")
			return controlHTTPResponse(request, http.StatusOK, `{"items":[{"id":"`+runID+`","environment_id":"`+environment+`","schedule_id":"sts_00000000000000000000000000","config_revision_id":"rev_00000000000000000000000000","kind":"upstream","state":"failed","created_at":"2026-10-07T00:00:00Z","completed_at":"2026-10-07T00:00:05Z","checks":[]}],"page":{"has_more":true,"next_cursor":"next-page"}}`, nil), nil
		}
		t.Fatalf("unexpected path %s", request.URL.Path)
		return nil, nil
	})}
	run := func(args ...string) (string, error) {
		var output bytes.Buffer
		opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
		err := executeWithOptions(context.Background(), append([]string{"--server", "http://127.0.0.1:8080"}, append(args, "--api-token-env", "TEST_LATCHWAY_HISTORY_TOKEN")...), opts)
		return output.String(), err
	}

	output, err := run("status", "history")
	if err != nil || !strings.Contains(output, "healthy samples: 1 of 2") || !strings.Contains(output, "worker_heartbeat") || !strings.Contains(output, "external_jwks_reachability") {
		t.Fatalf("status history output=%q err=%v", output, err)
	}
	if _, err := run("status", "history", "--start", "2026-09-01T00:00:00Z", "--end", "2026-10-01T00:00:00Z"); err == nil {
		t.Fatal("status history accepted a range longer than 7 days")
	}

	output, err = run("usage", "connections", "--environment", controlTestEnvironment, "--interval", "day")
	if err != nil || !strings.Contains(output, "openai") || !strings.Contains(output, "upstream_rejected=2") || !strings.Contains(output, "1250000000") || !strings.Contains(output, "300/800/900") {
		t.Fatalf("usage connections output=%q err=%v", output, err)
	}
	if !strings.Contains(queries[len(queries)-1], "interval=day") {
		t.Fatalf("usage connections query = %s", queries[len(queries)-1])
	}
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	if _, err := run("usage", "connections", "--environment", controlTestEnvironment, "--interval", "hour",
		"--start", end.Add(-15*24*time.Hour).Format(time.RFC3339), "--end", end.Format(time.RFC3339)); err == nil {
		t.Fatal("usage connections accepted an hourly series longer than 14 days")
	}

	output, err = run("verify", "runs", "--environment", controlTestEnvironment, "--state", "failed")
	if err != nil || !strings.Contains(output, runID) || !strings.Contains(output, "next cursor: next-page") {
		t.Fatalf("verify runs output=%q err=%v", output, err)
	}
	if !strings.Contains(queries[len(queries)-1], "state=failed") {
		t.Fatalf("verify runs query = %s", queries[len(queries)-1])
	}
	if _, err := run("verify", "runs", "--environment", controlTestEnvironment, "--state", "exploded"); err == nil {
		t.Fatal("verify runs accepted an unknown state")
	}
}
