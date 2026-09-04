package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/weborigin"
	"github.com/spf13/cobra"
)

const (
	maxReadinessCLIResponse       = 8 << 10
	maxReadinessCLIResponseHeader = 16 << 10
	readinessCLITimeout           = 4 * time.Second
)

var readinessCLICheckNames = [...]string{
	"database",
	"schema",
	"active_configuration",
	"quota_completion_pool",
	"master_key",
	"signing_key",
	"worker_heartbeat",
}

type readinessCLIResult struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func newReadinessCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "readiness",
		Short: "Probe unauthenticated server readiness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := probeReadiness(cmd.Context(), opts)
			if err != nil {
				return err
			}
			if opts.output == "json" {
				return printControlJSON(opts, result)
			}
			rows := make([][]string, 0, len(readinessCLICheckNames)+1)
			rows = append(rows, []string{"status", result.Status})
			for _, name := range readinessCLICheckNames {
				rows = append(rows, []string{name, result.Checks[name]})
			}
			return printControlTable(opts, []string{"CHECK", "STATE"}, rows)
		},
	}
}

func probeReadiness(ctx context.Context, opts *options) (readinessCLIResult, error) {
	endpoint, err := readinessEndpoint(opts.server)
	if err != nil {
		return readinessCLIResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return readinessCLIResult{}, errors.New("construct readiness request")
	}
	request.Header.Set("Accept", "application/json")

	client := boundedReadinessHTTPClient(opts.adminHTTPClient)
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return readinessCLIResult{}, errors.New("readiness probe failed")
	}
	if response == nil || response.Body == nil {
		return readinessCLIResult{}, errors.New("readiness endpoint returned an invalid response")
	}
	if response.ContentLength > maxReadinessCLIResponse {
		_ = response.Body.Close()
		return readinessCLIResult{}, errors.New("readiness response exceeds the safety limit")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, maxReadinessCLIResponse+1))
	closeErr := response.Body.Close()
	if len(encoded) > maxReadinessCLIResponse {
		clear(encoded)
		return readinessCLIResult{}, errors.New("readiness response exceeds the safety limit")
	}
	if readErr != nil || closeErr != nil {
		clear(encoded)
		return readinessCLIResult{}, errors.New("readiness endpoint returned an unreadable response")
	}
	defer clear(encoded)

	if response.StatusCode != http.StatusOK {
		return readinessCLIResult{}, fmt.Errorf("readiness endpoint returned HTTP status %d", response.StatusCode)
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !secretJSONContentType(contentTypes[0]) {
		return readinessCLIResult{}, errors.New("readiness endpoint returned a non-JSON response")
	}
	return decodeReadinessCLIResult(encoded)
}

func readinessEndpoint(rawServer string) (string, error) {
	if !weborigin.Canonical(rawServer) {
		return "", errors.New("--server must be an exact canonical HTTPS origin or loopback HTTP origin")
	}
	return rawServer + "/readyz", nil
}

func boundedReadinessHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = newAdminHTTPClient()
	}
	client := *base
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if client.Timeout <= 0 || client.Timeout > readinessCLITimeout {
		client.Timeout = readinessCLITimeout
	}
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport = transport.Clone()
		if transport.MaxResponseHeaderBytes <= 0 || transport.MaxResponseHeaderBytes > maxReadinessCLIResponseHeader {
			transport.MaxResponseHeaderBytes = maxReadinessCLIResponseHeader
		}
		client.Transport = transport
	}
	return &client
}

func decodeReadinessCLIResult(encoded []byte) (readinessCLIResult, error) {
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		return readinessCLIResult{}, errors.New("readiness endpoint returned malformed JSON")
	}
	document, ok := decoded.(map[string]any)
	if !ok || len(document) != 2 {
		return readinessCLIResult{}, errors.New("readiness endpoint returned an invalid readiness document")
	}
	status, statusOK := document["status"].(string)
	checks, checksOK := document["checks"].(map[string]any)
	if !statusOK || status != "ready" || !checksOK || len(checks) != len(readinessCLICheckNames) {
		return readinessCLIResult{}, errors.New("readiness endpoint returned an invalid readiness document")
	}

	result := readinessCLIResult{Status: "ready", Checks: make(map[string]string, len(readinessCLICheckNames))}
	for _, name := range readinessCLICheckNames {
		state, present := checks[name].(string)
		if !present || state != "ok" {
			return readinessCLIResult{}, errors.New("readiness endpoint returned an invalid readiness document")
		}
		result.Checks[name] = "ok"
	}
	return result, nil
}
