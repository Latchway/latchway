package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

const readyReadinessDocument = `{
  "status": "ready",
  "checks": {
    "database": "ok",
    "schema": "ok",
    "active_configuration": "ok",
    "quota_completion_pool": "ok",
    "master_key": "ok",
    "signing_key": "ok",
    "worker_heartbeat": "ok"
  }
}`

func TestReadinessCommandUsesUnauthenticatedBoundedCanonicalProbe(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	origin, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	jar.SetCookies(origin, []*http.Cookie{{Name: "administrative_session", Value: "cookie-secret"}})
	originalRedirectErr := errors.New("original redirect policy")
	client := &http.Client{
		Jar:     jar,
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return originalRedirectErr
		},
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1:8080/readyz" {
				t.Fatalf("request = %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("Accept") != "application/json" || request.Header.Get("Authorization") != "" ||
				request.Header.Get("Cookie") != "" || request.Header.Get("Origin") != "" {
				t.Fatalf("unexpected readiness headers = %#v", request.Header)
			}
			return readinessTestResponse(request, http.StatusOK, "application/json; charset=utf-8", readyReadinessDocument), nil
		}),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{stdout: &stdout, stderr: &stderr, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "readiness",
	}, opts); err != nil {
		t.Fatalf("executeWithOptions() error = %v, stderr = %q", err, stderr.String())
	}
	expectedOrder := []string{
		"CHECK", "status", "database", "schema", "active_configuration", "quota_completion_pool",
		"master_key", "signing_key", "worker_heartbeat",
	}
	position := -1
	for _, expected := range expectedOrder {
		next := strings.Index(stdout.String()[position+1:], expected)
		if next < 0 {
			t.Fatalf("table output %q does not contain %q after prior row", stdout.String(), expected)
		}
		position += next + 1
	}
	if strings.Contains(stdout.String(), "127.0.0.1") || stderr.Len() != 0 {
		t.Fatalf("readiness output disclosed the endpoint or wrote stderr: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !errors.Is(client.CheckRedirect(nil, nil), originalRedirectErr) {
		t.Fatal("readiness command mutated the injected client's redirect policy")
	}
}

func TestReadinessCommandEmitsExactSafeJSON(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return readinessTestResponse(request, http.StatusOK, "application/json", readyReadinessDocument), nil
	})}
	var stdout bytes.Buffer
	opts := &options{stdout: &stdout, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "https://gateway.example.test", "--output", "json", "readiness",
	}, opts); err != nil {
		t.Fatalf("executeWithOptions() error = %v", err)
	}
	var result readinessCLIResult
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if result.Status != "ready" || len(result.Checks) != len(readinessCLICheckNames) {
		t.Fatalf("result = %#v", result)
	}
	for _, name := range readinessCLICheckNames {
		if result.Checks[name] != "ok" {
			t.Fatalf("result.Checks[%q] = %q", name, result.Checks[name])
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("readiness command emitted trailing output %q", stdout.String())
	}
}

func TestReadinessRejectsNoncanonicalServerOriginsBeforeTransport(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"", " https://gateway.example.test", "https://gateway.example.test/",
		"https://Gateway.example.test", "https://gateway.example.test:443",
		"https://gateway.example.test/path", "https://gateway.example.test?query=1",
		"https://gateway.example.test#fragment", "https://user@gateway.example.test",
		"http://gateway.example.test", "//gateway.example.test", "https://gateway.example.test.",
		"https://127.000.000.001",
	}
	for _, rawServer := range invalid {
		rawServer := rawServer
		t.Run(rawServer, func(t *testing.T) {
			t.Parallel()
			called := false
			opts := &options{server: rawServer, adminHTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				called = true
				return nil, errors.New("transport must not run")
			})}}
			if _, err := probeReadiness(context.Background(), opts); err == nil {
				t.Fatalf("probeReadiness() accepted %q", rawServer)
			}
			if called {
				t.Fatalf("transport ran for noncanonical origin %q", rawServer)
			}
		})
	}
}

func TestReadinessAcceptsCanonicalSecureAndLoopbackOrigins(t *testing.T) {
	t.Parallel()
	for _, rawServer := range []string{
		"https://gateway.example.test", "https://gateway.example.test:8443",
		"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
	} {
		rawServer := rawServer
		t.Run(rawServer, func(t *testing.T) {
			t.Parallel()
			opts := &options{server: rawServer, adminHTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return readinessTestResponse(request, http.StatusOK, "application/json", readyReadinessDocument), nil
			})}}
			if result, err := probeReadiness(context.Background(), opts); err != nil || result.Status != "ready" {
				t.Fatalf("probeReadiness(%q) = %#v, %v", rawServer, result, err)
			}
		})
	}
}

func TestReadinessRejectsRedirectWithoutFollowingIt(t *testing.T) {
	calls := 0
	originalRedirectCalls := 0
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			originalRedirectCalls++
			return nil
		},
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if calls > 1 {
				t.Fatal("readiness probe followed a redirect")
			}
			response := readinessTestResponse(request, http.StatusFound, "application/json", readyReadinessDocument)
			response.Header.Set("Location", "https://other.example.test/readyz")
			return response, nil
		}),
	}
	opts := &options{server: "https://gateway.example.test", adminHTTPClient: client}
	if _, err := probeReadiness(context.Background(), opts); err == nil || err.Error() != "readiness endpoint returned HTTP status 302" {
		t.Fatalf("probeReadiness() error = %v", err)
	}
	if calls != 1 || originalRedirectCalls != 0 {
		t.Fatalf("transport calls = %d, injected redirect calls = %d", calls, originalRedirectCalls)
	}
}

func TestReadinessRejectsInvalidOrUnsafeResponses(t *testing.T) {
	missingCheck := strings.Replace(readyReadinessDocument, `    "worker_heartbeat": "ok"`, `    "other": "ok"`, 1)
	cases := []struct {
		name                 string
		status               int
		contentType          string
		body                 string
		contentLength        int64
		duplicateContentType bool
	}{
		{name: "service unavailable", status: http.StatusServiceUnavailable, contentType: "application/json", body: readyReadinessDocument},
		{name: "missing content type", status: http.StatusOK, body: readyReadinessDocument},
		{name: "non JSON", status: http.StatusOK, contentType: "text/plain", body: readyReadinessDocument},
		{name: "duplicate content type", status: http.StatusOK, contentType: "application/json", body: readyReadinessDocument, duplicateContentType: true},
		{name: "malformed", status: http.StatusOK, contentType: "application/json", body: `{"status":`},
		{name: "multiple values", status: http.StatusOK, contentType: "application/json", body: readyReadinessDocument + ` {}`},
		{name: "duplicate member", status: http.StatusOK, contentType: "application/json", body: strings.Replace(readyReadinessDocument, `"status": "ready"`, `"status": "ready", "status": "ready"`, 1)},
		{name: "unknown top level member", status: http.StatusOK, contentType: "application/json", body: strings.Replace(readyReadinessDocument, `"status": "ready",`, `"status": "ready", "sensitive": "TOP_SECRET",`, 1)},
		{name: "not ready", status: http.StatusOK, contentType: "application/json", body: strings.Replace(readyReadinessDocument, `"status": "ready"`, `"status": "not_ready"`, 1)},
		{name: "missing exact check", status: http.StatusOK, contentType: "application/json", body: missingCheck},
		{name: "failed check", status: http.StatusOK, contentType: "application/json", body: strings.Replace(readyReadinessDocument, `"database": "ok"`, `"database": "unavailable"`, 1)},
		{name: "null checks", status: http.StatusOK, contentType: "application/json", body: `{"status":"ready","checks":null}`},
		{name: "wrong check type", status: http.StatusOK, contentType: "application/json", body: strings.Replace(readyReadinessDocument, `"database": "ok"`, `"database": true`, 1)},
		{name: "top level array", status: http.StatusOK, contentType: "application/json", body: `[]`},
		{name: "invalid UTF-8", status: http.StatusOK, contentType: "application/json", body: string([]byte{'{', 0xff, '}'})},
		{name: "declared oversized", status: http.StatusOK, contentType: "application/json", body: readyReadinessDocument, contentLength: maxReadinessCLIResponse + 1},
		{name: "streamed oversized", status: http.StatusOK, contentType: "application/json", body: strings.Repeat("TOP_SECRET", maxReadinessCLIResponse)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := &readinessTrackingBody{Reader: strings.NewReader(testCase.body)}
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				response := &http.Response{
					StatusCode: testCase.status,
					Header:     make(http.Header),
					Body:       body,
					Request:    request,
				}
				if testCase.contentType != "" {
					response.Header.Set("Content-Type", testCase.contentType)
				}
				if testCase.duplicateContentType {
					response.Header.Add("Content-Type", "text/plain")
				}
				if testCase.contentLength != 0 {
					response.ContentLength = testCase.contentLength
				} else {
					response.ContentLength = -1
				}
				return response, nil
			})}
			opts := &options{server: "https://gateway.example.test", adminHTTPClient: client}
			if _, err := probeReadiness(context.Background(), opts); err == nil {
				t.Fatal("probeReadiness() accepted invalid response")
			} else if strings.Contains(err.Error(), "TOP_SECRET") {
				t.Fatalf("probeReadiness() disclosed response content: %v", err)
			}
			if !body.closed {
				t.Fatal("readiness response body was not closed")
			}
			if body.bytesRead > maxReadinessCLIResponse+1 {
				t.Fatalf("readiness probe read %d bytes", body.bytesRead)
			}
		})
	}
}

func TestReadinessRejectsNilUnreadableAndUncloseableBodies(t *testing.T) {
	tests := []struct {
		name string
		body io.ReadCloser
	}{
		{name: "nil body"},
		{name: "unreadable", body: &readinessTrackingBody{Reader: readinessErrorReader{}}},
		{name: "uncloseable", body: &readinessTrackingBody{Reader: strings.NewReader(readyReadinessDocument), closeErr: errors.New("TOP_SECRET close error")}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       testCase.body,
					Request:    request,
				}, nil
			})}
			opts := &options{server: "https://gateway.example.test", adminHTTPClient: client}
			if _, err := probeReadiness(context.Background(), opts); err == nil {
				t.Fatal("probeReadiness() accepted unusable response body")
			} else if strings.Contains(err.Error(), "TOP_SECRET") {
				t.Fatalf("probeReadiness() disclosed body error: %v", err)
			}
		})
	}
}

func TestReadinessTransportFailureIsBoundedAndRedacted(t *testing.T) {
	client := &http.Client{
		Timeout: 10 * time.Millisecond,
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, errors.New("TOP_SECRET transport failure")
		}),
	}
	started := time.Now()
	opts := &options{server: "https://gateway.example.test", adminHTTPClient: client}
	_, err := probeReadiness(context.Background(), opts)
	if err == nil || err.Error() != "readiness probe failed" {
		t.Fatalf("probeReadiness() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("readiness timeout was not bounded: %s", elapsed)
	}
}

func TestBoundedReadinessHTTPClientDoesNotMutateBase(t *testing.T) {
	originalRedirectErr := errors.New("original redirect")
	transport := &http.Transport{MaxResponseHeaderBytes: 1 << 20}
	base := &http.Client{
		Transport: transport,
		Timeout:   time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return originalRedirectErr
		},
	}
	bounded := boundedReadinessHTTPClient(base)
	boundedTransport, ok := bounded.Transport.(*http.Transport)
	if !ok || boundedTransport == transport {
		t.Fatal("bounded readiness client did not clone the HTTP transport")
	}
	if readinessCLITimeout != 4*time.Second || bounded.Timeout != 4*time.Second || boundedTransport.MaxResponseHeaderBytes != maxReadinessCLIResponseHeader {
		t.Fatalf("bounded client timeout/header cap = %s/%d", bounded.Timeout, boundedTransport.MaxResponseHeaderBytes)
	}
	if base.Timeout != time.Minute || transport.MaxResponseHeaderBytes != 1<<20 || !errors.Is(base.CheckRedirect(nil, nil), originalRedirectErr) {
		t.Fatal("bounded readiness client mutated its base client")
	}
	if !errors.Is(bounded.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("bounded readiness client does not reject redirects")
	}
}

func TestReadinessCommandIsRegisteredAndRejectsArguments(t *testing.T) {
	opts := &options{stdout: io.Discard, stderr: io.Discard}
	root := newRootCommand(opts)
	command, remaining, err := root.Find([]string{"readiness"})
	if err != nil || command == nil || command.Name() != "readiness" || len(remaining) != 0 {
		t.Fatalf("Find(readiness) = %v, %v, %v", command, remaining, err)
	}
	if err := executeWithOptions(context.Background(), []string{"readiness", "unexpected"}, opts); err == nil {
		t.Fatal("readiness command accepted a positional argument")
	}
}

func readinessTestResponse(request *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

type readinessTrackingBody struct {
	io.Reader
	bytesRead int
	closed    bool
	closeErr  error
}

func (body *readinessTrackingBody) Read(target []byte) (int, error) {
	read, err := body.Reader.Read(target)
	body.bytesRead += read
	return read, err
}

func (body *readinessTrackingBody) Close() error {
	body.closed = true
	return body.closeErr
}

type readinessErrorReader struct{}

func (readinessErrorReader) Read(target []byte) (int, error) {
	read := copy(target, "TOP_SECRET")
	return read, errors.New("TOP_SECRET read failure")
}
