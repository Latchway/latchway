package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/conformance/mockupstream"
)

func TestTestUpstreamServeCommandIsDiscoverable(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := Execute(context.Background(), []string{"test-upstream", "serve", "--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("help error = %v, stderr = %q", err, stderr.String())
	}
	for _, expected := range []string{
		"Serve the bounded deterministic mock upstream on loopback",
		"--scenario", "--allow-scenario-header", "--first-byte-delay",
		"--max-request-body-bytes", "--oversized-event-bytes",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("test-upstream help omitted %q:\n%s", expected, stdout.String())
		}
	}
	for _, scenario := range mockupstream.SupportedScenarios() {
		if !strings.Contains(stdout.String(), string(scenario)) {
			t.Fatalf("test-upstream help omitted scenario %q", scenario)
		}
	}

	stdout.Reset()
	err := Execute(context.Background(), []string{
		"test-upstream", "serve", "--listen", "127.0.0.1:0", "--scenario", "not-a-scenario",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "unsupported mock upstream scenario") {
		t.Fatalf("invalid scenario error = %v", err)
	}
}

func TestValidateTestUpstreamListenAddressIsLoopbackOnly(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{"127.0.0.1:19090", "localhost:0", "[::1]:443"} {
		if err := validateTestUpstreamListenAddress(valid); err != nil {
			t.Errorf("valid address %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", ":19090", "0.0.0.0:19090", "192.0.2.1:19090", "fixture.example:19090", "127.0.0.1"} {
		if err := validateTestUpstreamListenAddress(invalid); err == nil {
			t.Errorf("unsafe address %q accepted", invalid)
		}
	}
}

func TestServeTestUpstreamExposesMockAndShutsDown(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := mockupstream.New(mockupstream.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- serveTestUpstream(ctx, listener, handler, time.Second) }()

	request, err := http.NewRequest(http.MethodPost,
		"http://"+listener.Addr().String()+"/v1/chat/completions",
		strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		cancel()
		t.Fatalf("read/close mock response: %v/%v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusOK ||
		!bytes.Contains(body, []byte(`"prompt_tokens":11`)) ||
		!bytes.Contains(body, []byte(`"completion_tokens":7`)) {
		cancel()
		t.Fatalf("mock response status/body = %d/%s", response.StatusCode, body)
	}

	cancel()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server shutdown error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not shut down")
	}
}
