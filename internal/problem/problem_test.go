package problem

import (
	"bufio"
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegistryMatchesCanonicalYAML(t *testing.T) {
	file, err := os.Open("../../api/error-codes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	codeLine := regexp.MustCompile(`^  ([a-z][a-z0-9_]*):$`)
	fieldLine := regexp.MustCompile(`^    (status|title|retryable): (.+)$`)
	parsed := map[string]Definition{}
	current := ""
	definition := Definition{}
	flush := func() {
		if current != "" {
			parsed[current] = definition
		}
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if match := codeLine.FindStringSubmatch(line); match != nil {
			flush()
			current, definition = match[1], Definition{}
			continue
		}
		if current == "" {
			continue
		}
		match := fieldLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		switch match[1] {
		case "status":
			definition.Status, err = strconv.Atoi(match[2])
			if err != nil {
				t.Fatalf("invalid status for %s: %v", current, err)
			}
		case "title":
			definition.Title = strings.Trim(match[2], `"'`)
		case "retryable":
			definition.Retryable = match[2] == "true"
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(Registry) {
		t.Fatalf("registry count drift: canonical=%d runtime=%d", len(parsed), len(Registry))
	}
	for code, expected := range parsed {
		if actual, ok := Registry[code]; !ok || actual != expected {
			t.Errorf("registry drift for %s: canonical=%+v runtime=%+v present=%t", code, expected, actual, ok)
		}
	}
}

func TestWriteRegisteredProblem(t *testing.T) {
	recorder := httptest.NewRecorder()
	Write(recorder, "req_test", Error{Code: "rate_limited", Detail: "Try later.", RetryAfterSeconds: 3})
	if recorder.Code != 429 || recorder.Header().Get("Content-Type") != "application/problem+json" || recorder.Header().Get("Retry-After") != "3" {
		t.Fatalf("unexpected response: status=%d headers=%v", recorder.Code, recorder.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "rate_limited" || body["request_id"] != "req_test" || body["retryable"] != true {
		t.Fatalf("unexpected body: %#v", body)
	}
	retryAfter, ok := body["retry_after"].(string)
	if !ok {
		t.Fatalf("retry_after is not a date-time string: %#v", body["retry_after"])
	}
	if _, err := time.Parse(time.RFC3339, retryAfter); err != nil {
		t.Fatalf("retry_after is not RFC 3339: %v", err)
	}
}

func TestWriteUnknownProblemFailsClosed(t *testing.T) {
	recorder := httptest.NewRecorder()
	Write(recorder, "req_test", Error{Code: "not_registered", Detail: "database secret"})
	if recorder.Code != 500 || recorder.Body.String() == "" {
		t.Fatalf("unexpected response: %d %q", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	if body["code"] != "internal_error" || body["detail"] == "database secret" {
		t.Fatalf("unknown error did not fail closed: %#v", body)
	}
}

func TestWriteUsesDistinctClientAndAdminErrorShapes(t *testing.T) {
	tests := []struct {
		name      string
		value     Error
		wantKeys  []string
		rejectKey string
	}{
		{
			name:     "client field error",
			value:    Error{Code: "request_invalid", Fields: []FieldError{{Path: "/platform", Message: "The platform is invalid."}}},
			wantKeys: []string{"path", "message"}, rejectKey: "code",
		},
		{
			name:     "admin validation issue",
			value:    Error{Code: "configuration_invalid", ValidationIssues: []ValidationIssue{{Severity: "error", Code: "invalid_platform", Path: "/spec", Message: "The platform is invalid."}}},
			wantKeys: []string{"severity", "code", "path", "message"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			Write(recorder, "req_error_shape", test.value)
			var body struct {
				Errors []map[string]any `json:"errors"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if len(body.Errors) != 1 {
				t.Fatalf("errors=%#v", body.Errors)
			}
			for _, key := range test.wantKeys {
				if _, ok := body.Errors[0][key]; !ok {
					t.Errorf("missing error member %q: %#v", key, body.Errors[0])
				}
			}
			if test.rejectKey != "" {
				if _, ok := body.Errors[0][test.rejectKey]; ok {
					t.Errorf("unexpected error member %q: %#v", test.rejectKey, body.Errors[0])
				}
			}
		})
	}
}
