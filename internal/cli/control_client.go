package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	defaultAdminTokenEnvironment = "LATCHWAY_ADMIN_API_TOKEN"
	maxControlCLIRequest         = 2 << 20
	maxControlCLIResponse        = 2 << 20
	cliAdminSourceHeader         = "X-Latchway-Admin-Source"
	cliAuditReasonHeader         = "X-Latchway-Audit-Reason"
	cliAuditSource               = "cli"
	cliReasonProvided            = "operator_reason_provided"
)

type controlAPIClient struct {
	server         string
	token          string
	tokenSensitive []string
	http           *http.Client
}

type controlResponse struct {
	Header http.Header
}

type controlProblemError struct {
	Code             string
	Detail           string
	RequestID        string
	DocumentationURL string
	Retryable        bool
	StatusCode       int
	ValidationIssues []validationIssueCLI
}

func (problem controlProblemError) Error() string {
	message := fmt.Sprintf(
		"Admin API failed (%s): %s [request_id=%s retryable=%t docs=%s]",
		problem.Code, problem.Detail, problem.RequestID, problem.Retryable, problem.DocumentationURL,
	)
	for _, issue := range problem.ValidationIssues {
		message += fmt.Sprintf("\n- %s %s: %s", issue.Code, issue.Path, issue.Message)
	}
	return message
}

func newControlAPIClient(opts *options, tokenEnvironment string) (*controlAPIClient, error) {
	if !environmentNamePattern.MatchString(tokenEnvironment) {
		return nil, errors.New("API token environment variable name is invalid")
	}
	token, present := os.LookupEnv(tokenEnvironment)
	if !present || !validSecretAPIToken(token) {
		return nil, fmt.Errorf("API token environment variable %s is empty or invalid", tokenEnvironment)
	}
	if _, err := adminEndpoint(opts.server, "/admin/v1/system"); err != nil {
		return nil, err
	}
	base := opts.adminHTTPClient
	if base == nil {
		base = newAdminHTTPClient()
	}
	copy := *base
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if copy.Timeout <= 0 || copy.Timeout > 30*time.Second {
		copy.Timeout = 30 * time.Second
	}
	return &controlAPIClient{
		server: opts.server, token: token, tokenSensitive: secretSensitiveVariants(token), http: &copy,
	}, nil
}

func (client *controlAPIClient) do(
	ctx context.Context,
	method string,
	path string,
	query url.Values,
	requestDocument any,
	expectedStatus int,
	responseDocument any,
) (controlResponse, error) {
	return client.doWithHeaders(
		ctx, method, path, query, requestDocument, nil, expectedStatus, responseDocument,
	)
}

func (client *controlAPIClient) doWithHeaders(
	ctx context.Context,
	method string,
	path string,
	query url.Values,
	requestDocument any,
	requestHeaders http.Header,
	expectedStatus int,
	responseDocument any,
) (controlResponse, error) {
	var body []byte
	var err error
	if requestDocument != nil {
		body, err = json.Marshal(requestDocument)
		if err != nil {
			return controlResponse{}, errors.New("encode Admin API request")
		}
		defer clear(body)
		if len(body) > maxControlCLIRequest {
			return controlResponse{}, errors.New("admin API request exceeds the safety limit")
		}
	}
	endpoint, err := adminEndpoint(client.server, path)
	if err != nil {
		return controlResponse{}, err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return controlResponse{}, errors.New("construct Admin API endpoint")
	}
	if len(query) != 0 {
		parsed.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return controlResponse{}, errors.New("construct Admin API request")
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set(cliAdminSourceHeader, cliAuditSource)
	if auditReasonWasProvided(requestDocument) {
		request.Header.Set(cliAuditReasonHeader, cliReasonProvided)
	}
	for name, values := range requestHeaders {
		if !strings.EqualFold(name, "If-Match") || len(values) != 1 || !validStrongETag(values[0]) {
			return controlResponse{}, errors.New("unsupported or invalid Admin API request header")
		}
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if requestDocument != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return controlResponse{}, fmt.Errorf("call Admin API: %s", client.safeText(err.Error()))
	}
	if response.Body == nil {
		return controlResponse{}, errors.New("admin API returned an empty response")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxControlCLIResponse+1))
	closeErr := response.Body.Close()
	if err != nil {
		return controlResponse{}, fmt.Errorf("read Admin API response: %s", client.safeText(err.Error()))
	}
	if closeErr != nil {
		return controlResponse{}, errors.New("close admin API response")
	}
	defer clear(responseBody)
	if len(responseBody) > maxControlCLIResponse {
		return controlResponse{}, errors.New("admin API response exceeds the safety limit")
	}
	if client.containsToken(responseBody) {
		return controlResponse{}, errors.New("admin API returned unsafe credential material")
	}
	if response.StatusCode != expectedStatus {
		return controlResponse{}, client.problem(response.StatusCode, response.Header, responseBody)
	}
	if expectedStatus == http.StatusNoContent {
		if len(responseBody) != 0 {
			return controlResponse{}, errors.New("admin API returned an invalid no-content response")
		}
		return controlResponse{Header: response.Header.Clone()}, nil
	}
	if responseDocument == nil || len(responseBody) == 0 || !secretJSONContentType(response.Header.Get("Content-Type")) {
		return controlResponse{}, errors.New("admin API returned an invalid success document")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(responseDocument); err != nil {
		return controlResponse{}, errors.New("admin API returned malformed or non-conforming JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return controlResponse{}, errors.New("admin API returned multiple JSON values")
	}
	return controlResponse{Header: response.Header.Clone()}, nil
}

func auditReasonWasProvided(document any) bool {
	switch typed := document.(type) {
	case map[string]string:
		return strings.TrimSpace(typed["reason"]) != ""
	case map[string]any:
		reason, _ := typed["reason"].(string)
		return strings.TrimSpace(reason) != ""
	case confirmedUserOperationCLI:
		return strings.TrimSpace(typed.Reason) != ""
	default:
		return false
	}
}

func (client *controlAPIClient) problem(status int, header http.Header, body []byte) error {
	document, _, valid := decodeSecretProblem(status, header, body)
	if !valid {
		return fmt.Errorf("admin API failed with HTTP status %d", status)
	}
	detail := client.safeText(document.Detail)
	if detail == "" {
		detail = "The administrative request failed."
	}
	issues := make([]validationIssueCLI, 0)
	if document.Errors != nil {
		issues = make([]validationIssueCLI, 0, len(*document.Errors))
		for _, issue := range *document.Errors {
			issues = append(issues, validationIssueCLI{
				Severity: client.safeText(*issue.Severity),
				Code:     client.safeText(*issue.Code),
				Path:     client.safeText(*issue.Path),
				Message:  client.safeText(*issue.Message),
			})
		}
	}
	return controlProblemError{
		Code: document.Code, Detail: detail, RequestID: document.RequestID,
		DocumentationURL: document.DocumentationURL, Retryable: document.Retryable,
		StatusCode: status, ValidationIssues: issues,
	}
}

func (client *controlAPIClient) containsToken(body []byte) bool {
	for _, sensitive := range client.tokenSensitive {
		if sensitive != "" && bytes.Contains(body, []byte(sensitive)) {
			return true
		}
	}
	return false
}

func (client *controlAPIClient) safeText(value string) string {
	for _, sensitive := range client.tokenSensitive {
		if sensitive != "" {
			value = strings.ReplaceAll(value, sensitive, "[redacted]")
		}
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(value)
}

func printControlTable(opts *options, headers []string, rows [][]string) error {
	writer := tabwriter.NewWriter(opts.stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, strings.Join(headers, "\t")); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(writer, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func printControlJSON(opts *options, value any) error {
	encoder := json.NewEncoder(opts.stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func formatControlTime(value string) string {
	if value == "" {
		return "-"
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.UTC().Format("2006-01-02 15:04:05Z")
}

func boolLabel(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
