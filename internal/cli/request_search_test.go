package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const requestSearchFixture = `{
	"id":"req_00000000000000000000000000",
	"environment_id":"env_00000000000000000000000000",
	"user_id":"usr_00000000000000000000000000",
	"installation_id":"ins_00000000000000000000000000",
	"platform":"ios","client_request_id":"checkout:2026-10-08.a1",
	"config_revision_id":"rev_00000000000000000000000000","selected_limit_plan":"paid",
	"feature":"assistant","protocol":"openai_chat",
	"started_at":"2026-10-08T00:00:00Z","completed_at":"2026-10-08T00:00:01Z","status":"succeeded",
	"decision_stages":[],"attempts":[]
}`

func TestRequestsListSendsFiltersAndPrintsTotal(t *testing.T) {
	token := strings.Repeat("request-search-token-", 2)
	t.Setenv("TEST_LATCHWAY_REQUEST_SEARCH_TOKEN", token)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		want := url.Values{
			"environment_id": {controlTestEnvironment}, "page_size": {"25"},
			"status": {"succeeded"}, "feature": {"assistant"}, "user_id": {controlTestUser},
			"platform": {"ios"}, "upstream": {"openai"}, "model": {"openai/gpt-5 mini"},
			"error_code": {"timeout"}, "client_request_id": {"checkout:2026-10-08.a1"},
			"start": {"2026-10-07T00:00:00Z"}, "end": {"2026-10-08T00:00:00Z"},
			"sort": {"started_at_asc"}, "tokens_min": {"0"}, "cost_max_nano_usd": {"500"},
			"include_total": {"true"},
		}
		if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/requests" ||
			request.URL.Query().Encode() != want.Encode() {
			t.Fatalf("requests list call = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		return controlHTTPResponse(request, http.StatusOK,
			`{"items":[`+requestSearchFixture+`],"page":{"has_more":false},"total":{"count":1,"capped":false}}`, nil), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "requests", "list",
		"--environment", controlTestEnvironment, "--page-size", "25",
		"--status", "succeeded", "--feature", "assistant", "--user", controlTestUser,
		"--platform", "ios", "--upstream", "openai", "--model", "openai/gpt-5 mini",
		"--error-code", "timeout", "--client-request-id", "checkout:2026-10-08.a1",
		"--start", "2026-10-07T00:00:00Z", "--end", "2026-10-08T00:00:00Z",
		"--sort", "started_at_asc", "--tokens-min", "0", "--cost-max-nano-usd", "500", "--total",
		"--api-token-env", "TEST_LATCHWAY_REQUEST_SEARCH_TOKEN",
	}, opts); err != nil {
		t.Fatalf("requests list error = %v", err)
	}
	if !strings.Contains(output.String(), "PLATFORM") || !strings.Contains(output.String(), "ios") ||
		!strings.Contains(output.String(), "matching requests: 1\n") {
		t.Fatalf("requests list output = %q", output.String())
	}
}

func TestRequestsListRejectsInvalidFiltersBeforeRequest(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		return nil, nil
	})}
	for name, flags := range map[string][]string{
		"status":         {"--status", "pending"},
		"platform":       {"--platform", "windows"},
		"feature":        {"--feature", "Assistant"},
		"user":           {"--user", "user-1"},
		"client request": {"--client-request-id", "short"},
		"negative":       {"--latency-min-ms", "-1"},
		"start":          {"--start", "yesterday"},
		"sort":           {"--sort", "cost"},
		"model":          {"--model", "a\nb"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TEST_LATCHWAY_REQUEST_SEARCH_TOKEN", strings.Repeat("request-search-token-", 2))
			opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
			args := append([]string{
				"--server", "http://127.0.0.1:8080", "requests", "list", "--environment", controlTestEnvironment,
				"--api-token-env", "TEST_LATCHWAY_REQUEST_SEARCH_TOKEN",
			}, flags...)
			if err := executeWithOptions(context.Background(), args, opts); err == nil {
				t.Fatalf("requests list accepted %v", flags)
			}
		})
	}
}

func TestRequestsListRejectsUnrequestedOrInvalidTotal(t *testing.T) {
	for name, body := range map[string]string{
		"unrequested": `{"items":[],"page":{"has_more":false},"total":{"count":0,"capped":false}}`,
		"over cap":    `{"items":[],"page":{"has_more":false},"total":{"count":100001,"capped":false}}`,
		"unknown":     `{"items":[],"page":{"has_more":false},"totals":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TEST_LATCHWAY_REQUEST_SEARCH_TOKEN", strings.Repeat("request-search-token-", 2))
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return controlHTTPResponse(request, http.StatusOK, body, nil), nil
			})}
			args := []string{
				"--server", "http://127.0.0.1:8080", "requests", "list", "--environment", controlTestEnvironment,
				"--api-token-env", "TEST_LATCHWAY_REQUEST_SEARCH_TOKEN",
			}
			if name == "over cap" {
				args = append(args, "--total")
			}
			opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
			if err := executeWithOptions(context.Background(), args, opts); err == nil {
				t.Fatalf("requests list accepted %s", body)
			}
		})
	}
}

func TestRequestsFacetsValidatesAndPrints(t *testing.T) {
	t.Setenv("TEST_LATCHWAY_REQUEST_SEARCH_TOKEN", strings.Repeat("request-search-token-", 2))
	facets := `{"environment_id":"env_00000000000000000000000000","start":"2026-10-07T00:00:00Z","end":"2026-10-08T00:00:00Z","requests":3,"facets":{` +
		`"status":{"values":[{"value":"succeeded","count":2},{"value":"failed","count":1}],"truncated":false},` +
		`"feature":{"values":[{"value":"assistant","count":3}],"truncated":false},` +
		`"error_code":{"values":[{"value":"timeout","count":1}],"truncated":false},` +
		`"upstream":{"values":[{"value":"openai","count":3}],"truncated":true},` +
		`"model":{"values":[],"truncated":false},"route":{"values":[],"truncated":false},` +
		`"platform":{"values":[{"value":"ios","count":3}],"truncated":false},` +
		`"component_kind":{"values":[],"truncated":false},"trust_source":{"values":[],"truncated":false}}}`
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		query := request.URL.Query()
		if request.URL.Path != "/admin/v1/requests/facets" || query.Get("environment_id") != controlTestEnvironment ||
			query.Get("start") != "2026-10-07T00:00:00Z" || query.Get("end") != "2026-10-08T00:00:00Z" || query.Get("limit") != "5" {
			t.Fatalf("facets call = %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		return controlHTTPResponse(request, http.StatusOK, facets, nil), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "requests", "facets", "--environment", controlTestEnvironment,
		"--start", "2026-10-07T00:00:00Z", "--end", "2026-10-08T00:00:00Z", "--limit", "5",
		"--api-token-env", "TEST_LATCHWAY_REQUEST_SEARCH_TOKEN",
	}, opts); err != nil {
		t.Fatalf("requests facets error = %v", err)
	}
	for _, want := range []string{"FACET", "succeeded", "timeout", "(more values)", "ios"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("facets output missing %q: %q", want, output.String())
		}
	}

	corrupt := strings.Replace(facets, `{"value":"openai","count":3}`, `{"value":"openai","count":9}`, 1)
	client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return controlHTTPResponse(request, http.StatusOK, corrupt, nil), nil
	})}
	opts = &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "requests", "facets", "--environment", controlTestEnvironment,
		"--start", "2026-10-07T00:00:00Z", "--end", "2026-10-08T00:00:00Z", "--limit", "5",
		"--api-token-env", "TEST_LATCHWAY_REQUEST_SEARCH_TOKEN",
	}, opts); err == nil {
		t.Fatal("requests facets accepted a count above the request total")
	}
}
