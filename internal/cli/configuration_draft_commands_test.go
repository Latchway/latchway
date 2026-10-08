package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestConfigApplySendsPublishNote(t *testing.T) {
	t.Setenv("TEST_LATCHWAY_NOTE_TOKEN", strings.Repeat("note-control-token-", 2))
	var note string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/admin/v1/environments/" + controlTestEnvironment + "/config-revisions":
			return controlHTTPResponse(request, http.StatusCreated, revisionJSON("draft"), http.Header{"ETag": []string{`"revision-etag"`}}), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/validate":
			return controlHTTPResponse(request, http.StatusOK, `{"valid":true,"checked_at":"2026-08-29T00:00:00Z","issues":[]}`, nil), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/plan":
			return controlHTTPResponse(request, http.StatusNotFound, problemJSONForControl("resource_not_found", http.StatusNotFound), nil), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/activate":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("activation body: %v", err)
			}
			note = body["note"]
			return controlHTTPResponse(request, http.StatusOK, strings.TrimSuffix(revisionJSON("active"), "}")+`,"activation_note":"Raise the free plan."}`, nil), nil
		}
		t.Fatalf("unexpected path %s", request.URL.Path)
		return nil, nil
	})}
	opts := &options{output: "json", stdin: strings.NewReader(`{"apiVersion":"latchway.dev/v1alpha1"}`), stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "config", "apply", "--environment", controlTestEnvironment,
		"--from-stdin", "--note", "  Raise the free plan.  ", "--api-token-env", "TEST_LATCHWAY_NOTE_TOKEN",
	}, opts); err != nil {
		t.Fatalf("config apply error = %v", err)
	}
	if note != "Raise the free plan." {
		t.Fatalf("activation note = %q", note)
	}
	opts = &options{output: "json", stdin: strings.NewReader(`{}`), stdout: io.Discard, stderr: io.Discard, adminHTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request %s", request.URL.Path)
		return nil, nil
	})}}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "config", "apply", "--environment", controlTestEnvironment,
		"--from-stdin", "--note", "bell\a", "--api-token-env", "TEST_LATCHWAY_NOTE_TOKEN",
	}, opts); err == nil {
		t.Fatal("config apply accepted a note with a control character")
	}
}

func TestConfigHistoryDiscardAndPromote(t *testing.T) {
	t.Setenv("TEST_LATCHWAY_DRAFT_TOKEN", strings.Repeat("draft-control-token-", 2))
	const target = "env_11111111111111111111111111"
	calls := make([]string, 0, 4)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.Method+" "+request.URL.Path)
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/config-revisions/"+controlTestRevision+"/edits":
			return controlHTTPResponse(request, http.StatusOK, `{"revision_id":"`+controlTestRevision+`","truncated":false,"items":[
				{"version":2,"kind":"edited","edited_at":"2026-10-08T00:00:01Z","edited_by":"adm_00000000000000000000000000","change_count":2,
				 "changes":[{"operation":"replace","path":"/spec/limitPlans/free","summary":"Configuration structure changed."}]},
				{"version":1,"kind":"created","edited_at":"2026-10-08T00:00:00Z","edited_by":"adm_00000000000000000000000000","change_count":0,"changes":[]}]}`, nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/config-revisions/"+controlTestRevision:
			return controlHTTPResponse(request, http.StatusOK, revisionJSON("valid"), http.Header{"ETag": []string{`"draft-etag"`}}), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/config-revisions/"+controlTestRevision+"/discard":
			if request.Header.Get("If-Match") != `"draft-etag"` {
				t.Fatalf("discard If-Match = %q", request.Header.Get("If-Match"))
			}
			return controlHTTPResponse(request, http.StatusOK, strings.TrimSuffix(revisionJSON("discarded"), "}")+`,"discarded_at":"2026-10-08T00:00:02Z","discarded_by":"adm_00000000000000000000000000"}`, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/environments/"+target+"/config-revisions/promote":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["source_environment_id"] != controlTestEnvironment {
				t.Fatalf("promotion body = %v err=%v", body, err)
			}
			revision := strings.Replace(revisionJSON("draft"), controlTestEnvironment, target, 1)
			return controlHTTPResponse(request, http.StatusCreated, `{"revision":`+revision+`,"promotion":{"source_environment_id":"`+controlTestEnvironment+`","source_revision_id":"rev_22222222222222222222222222","copied":["/spec/features"],"kept":["/metadata"],"review":["/spec/upstreams/openai"]}}`, nil), nil
		}
		t.Fatalf("unexpected call %s %s", request.Method, request.URL.Path)
		return nil, nil
	})}
	run := func(args ...string) string {
		t.Helper()
		var output bytes.Buffer
		opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
		if err := executeWithOptions(context.Background(), append([]string{"--server", "http://127.0.0.1:8080"}, append(args, "--api-token-env", "TEST_LATCHWAY_DRAFT_TOKEN")...), opts); err != nil {
			t.Fatalf("%v error = %v", args, err)
		}
		return output.String()
	}
	if history := run("config", "history", controlTestRevision); !strings.Contains(history, "replace /spec/limitPlans/free") || !strings.Contains(history, "and 1 more") || !strings.Contains(history, "created") {
		t.Fatalf("history output = %q", history)
	}
	if discarded := run("config", "discard", controlTestRevision); !strings.Contains(discarded, "discarded") {
		t.Fatalf("discard output = %q", discarded)
	}
	if promoted := run("config", "promote", "--environment", target, "--from", controlTestEnvironment); !strings.Contains(promoted, "review: /spec/upstreams/openai") || !strings.Contains(promoted, "Review copied entries") {
		t.Fatalf("promote output = %q", promoted)
	}
	if len(calls) != 4 {
		t.Fatalf("calls = %v", calls)
	}
}
