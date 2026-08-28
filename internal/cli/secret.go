package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	problemcontract "github.com/latchway/latchway/internal/problem"
	"github.com/spf13/cobra"
)

const (
	defaultSecretTokenEnvironment = "LATCHWAY_ADMIN_API_TOKEN"
	maxSecretValueBytes           = 1 << 20
	maxSecretCLIRequest           = (6 * maxSecretValueBytes) + (16 << 10)
	maxSecretCLIResponse          = 1 << 20
	maxSecretProblemDetail        = 4096
)

var (
	secretNamePattern             = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	secretAlgorithmPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	secretMasterKeyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	secretProblemRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$`)
	secretProblemIssueCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
)

type secretRootCLIOptions struct {
	tokenEnvironment string
}

type secretListCLIOptions struct {
	environmentID string
	cursor        string
	pageSize      int
}

type secretValueCLIOptions struct {
	fromStdin        bool
	valueEnvironment string
	valueFile        string
	valueFD          int
}

type secretWriteCLIOptions struct {
	environmentID string
	value         secretValueCLIOptions
}

type secretMetadataCLI struct {
	ID            string  `json:"id"`
	EnvironmentID string  `json:"environment_id"`
	Name          string  `json:"name"`
	Version       int64   `json:"version"`
	Algorithm     string  `json:"algorithm"`
	MasterKeyID   string  `json:"master_key_id"`
	CreatedAt     string  `json:"created_at"`
	RotatedAt     *string `json:"rotated_at,omitempty"`
}

type secretPageInfoCLI struct {
	HasMore    *bool  `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type secretPageCLI struct {
	Items []secretMetadataCLI `json:"items"`
	Page  *secretPageInfoCLI  `json:"page"`
}

type secretProblemCLI struct {
	Type                      string                             `json:"type"`
	Title                     string                             `json:"title"`
	Status                    int                                `json:"status"`
	Detail                    string                             `json:"detail"`
	Code                      string                             `json:"code"`
	RequestID                 string                             `json:"request_id"`
	Retryable                 bool                               `json:"retryable"`
	OperationID               *string                            `json:"operation_id,omitempty"`
	Instance                  *string                            `json:"instance,omitempty"`
	RetryAfter                *string                            `json:"retry_after,omitempty"`
	Feature                   *string                            `json:"feature,omitempty"`
	SupportedProtocolVersions *[]int                             `json:"supported_protocol_versions,omitempty"`
	Errors                    *[]secretProblemValidationIssueCLI `json:"errors,omitempty"`
}

type secretProblemValidationIssueCLI struct {
	Severity *string `json:"severity"`
	Code     *string `json:"code"`
	Path     *string `json:"path"`
	Message  *string `json:"message"`
}

type secretAPIClient struct {
	server         string
	token          string
	http           *http.Client
	tokenSensitive []string
	valueSensitive []string
}

func newSecretCommand(opts *options) *cobra.Command {
	rootValues := secretRootCLIOptions{tokenEnvironment: defaultSecretTokenEnvironment}
	command := &cobra.Command{
		Use:   "secret",
		Short: "Manage write-only encrypted secrets through the canonical Admin API",
		Args:  cobra.NoArgs,
	}
	command.PersistentFlags().StringVar(&rootValues.tokenEnvironment, "api-token-env", rootValues.tokenEnvironment, "environment variable containing a scoped Admin API token")
	command.AddCommand(
		newSecretListCommand(opts, &rootValues),
		newSecretSetCommand(opts, &rootValues),
		newSecretRotateCommand(opts, &rootValues),
		newSecretDeleteCommand(opts, &rootValues),
	)
	return command
}

func newSecretListCommand(opts *options, rootValues *secretRootCLIOptions) *cobra.Command {
	values := secretListCLIOptions{pageSize: 50}
	command := &cobra.Command{
		Use:   "list",
		Short: "List secret metadata without retrieving plaintext",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSecretList(cmd, opts, *rootValues, values)
		},
	}
	command.Flags().StringVar(&values.environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&values.cursor, "cursor", "", "opaque continuation cursor")
	command.Flags().IntVar(&values.pageSize, "page-size", values.pageSize, "page size (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newSecretSetCommand(opts *options, rootValues *secretRootCLIOptions) *cobra.Command {
	values := secretWriteCLIOptions{value: secretValueCLIOptions{valueFD: -1}}
	command := &cobra.Command{
		Use:     "set NAME",
		Aliases: []string{"create"},
		Short:   "Create a named write-only secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretSet(cmd, opts, *rootValues, args[0], values)
		},
	}
	command.Flags().StringVar(&values.environmentID, "environment", "", "target environment ID")
	addSecretValueFlags(command, &values.value)
	_ = command.MarkFlagRequired("environment")
	return command
}

func newSecretRotateCommand(opts *options, rootValues *secretRootCLIOptions) *cobra.Command {
	values := secretValueCLIOptions{valueFD: -1}
	command := &cobra.Command{
		Use:   "rotate SECRET_ID",
		Short: "Store a new encrypted version of a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretRotate(cmd, opts, *rootValues, args[0], values)
		},
	}
	addSecretValueFlags(command, &values)
	return command
}

func newSecretDeleteCommand(opts *options, rootValues *secretRootCLIOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "delete SECRET_ID",
		Short: "Delete or tombstone an unreferenced secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretDelete(cmd, opts, *rootValues, args[0])
		},
	}
}

func addSecretValueFlags(command *cobra.Command, values *secretValueCLIOptions) {
	command.Flags().BoolVar(&values.fromStdin, "from-stdin", false, "read the secret value from standard input")
	command.Flags().StringVar(&values.valueEnvironment, "value-env", "", "read the secret value from this environment variable")
	command.Flags().StringVar(&values.valueFile, "value-file", "", "read the secret value from this regular file")
	command.Flags().IntVar(&values.valueFD, "value-fd", values.valueFD, "read the secret value from this open file descriptor")
}

func runSecretList(cmd *cobra.Command, opts *options, rootValues secretRootCLIOptions, values secretListCLIOptions) error {
	if id.Validate(values.environmentID, id.Environment) != nil {
		return errors.New("environment ID is invalid")
	}
	if values.pageSize < 1 || values.pageSize > 200 {
		return errors.New("--page-size must be between 1 and 200")
	}
	if values.cursor != "" && !validSecretCursor(values.cursor) {
		return errors.New("--cursor is invalid")
	}
	client, err := newSecretAPIClient(opts, rootValues.tokenEnvironment, nil)
	if err != nil {
		return err
	}
	query := url.Values{
		"environment_id": []string{values.environmentID},
		"page_size":      []string{fmt.Sprintf("%d", values.pageSize)},
	}
	if values.cursor != "" {
		query.Set("cursor", values.cursor)
	}
	var document secretPageCLI
	if err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/secrets", query, nil, http.StatusOK, &document); err != nil {
		return err
	}
	if err := validateSecretPage(document, values.environmentID, values.pageSize); err != nil {
		return err
	}
	if client.pageContainsToken(document) {
		return errors.New("secret API returned unsafe metadata")
	}
	return printSecretPage(opts, document)
}

func runSecretSet(cmd *cobra.Command, opts *options, rootValues secretRootCLIOptions, name string, values secretWriteCLIOptions) error {
	if id.Validate(values.environmentID, id.Environment) != nil {
		return errors.New("environment ID is invalid")
	}
	if !secretNamePattern.MatchString(name) {
		return errors.New("secret name must match ^[a-z][a-z0-9_-]{0,62}$")
	}
	plaintext, err := readSecretValue(cmd, values.value)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	client, err := newSecretAPIClient(opts, rootValues.tokenEnvironment, plaintext)
	if err != nil {
		return err
	}
	body, err := marshalBoundedSecretRequest(struct {
		EnvironmentID string `json:"environment_id"`
		Name          string `json:"name"`
		Value         string `json:"value"`
	}{EnvironmentID: values.environmentID, Name: name, Value: string(plaintext)})
	if err != nil {
		return err
	}
	defer clear(body)
	var document secretMetadataCLI
	if err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/secrets", nil, body, http.StatusCreated, &document); err != nil {
		return err
	}
	if err := validateSecretMetadata(document, "", values.environmentID, name); err != nil {
		return err
	}
	if client.metadataContainsToken(document) {
		return errors.New("secret API returned unsafe metadata")
	}
	return printSecretMetadata(opts, document)
}

func runSecretRotate(cmd *cobra.Command, opts *options, rootValues secretRootCLIOptions, secretID string, values secretValueCLIOptions) error {
	if id.Validate(secretID, id.SecretRecord) != nil {
		return errors.New("secret ID is invalid")
	}
	plaintext, err := readSecretValue(cmd, values)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	client, err := newSecretAPIClient(opts, rootValues.tokenEnvironment, plaintext)
	if err != nil {
		return err
	}
	body, err := marshalBoundedSecretRequest(struct {
		Value string `json:"value"`
	}{Value: string(plaintext)})
	if err != nil {
		return err
	}
	defer clear(body)
	var document secretMetadataCLI
	path := "/admin/v1/secrets/" + secretID + "/rotate"
	if err := client.do(cmd.Context(), http.MethodPost, path, nil, body, http.StatusOK, &document); err != nil {
		return err
	}
	if err := validateSecretMetadata(document, "", "", ""); err != nil {
		return err
	}
	if document.ID == secretID {
		return errors.New("secret API returned mismatched rotation metadata")
	}
	if client.metadataContainsToken(document) {
		return errors.New("secret API returned unsafe metadata")
	}
	return printSecretMetadata(opts, document)
}

func runSecretDelete(cmd *cobra.Command, opts *options, rootValues secretRootCLIOptions, secretID string) error {
	if id.Validate(secretID, id.SecretRecord) != nil {
		return errors.New("secret ID is invalid")
	}
	client, err := newSecretAPIClient(opts, rootValues.tokenEnvironment, nil)
	if err != nil {
		return err
	}
	path := "/admin/v1/secrets/" + secretID
	if err := client.do(cmd.Context(), http.MethodDelete, path, nil, nil, http.StatusNoContent, nil); err != nil {
		return err
	}
	return printSecretDelete(opts, secretID)
}

func readSecretValue(command *cobra.Command, values secretValueCLIOptions) ([]byte, error) {
	selected := 0
	for _, flag := range []string{"from-stdin", "value-env", "value-file", "value-fd"} {
		if command.Flags().Changed(flag) {
			selected++
		}
	}
	if selected != 1 {
		return nil, errors.New("select exactly one secret value source: --from-stdin, --value-env, --value-file, or --value-fd")
	}

	var reader io.Reader
	source := "selected source"
	switch {
	case command.Flags().Changed("from-stdin"):
		if !values.fromStdin {
			return nil, errors.New("--from-stdin must be true when selected")
		}
		reader = command.InOrStdin()
		source = "standard input"
	case command.Flags().Changed("value-env"):
		if !environmentNamePattern.MatchString(values.valueEnvironment) {
			return nil, errors.New("secret value environment variable name is invalid")
		}
		value, present := os.LookupEnv(values.valueEnvironment)
		if !present || value == "" {
			return nil, fmt.Errorf("secret value environment variable %s is empty", values.valueEnvironment)
		}
		return validateSecretValue([]byte(value))
	case command.Flags().Changed("value-file"):
		if values.valueFile == "" {
			return nil, errors.New("--value-file must name a regular file")
		}
		file, err := os.Open(values.valueFile)
		if err != nil {
			return nil, errors.New("open secret value file")
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("--value-file must name a regular file")
		}
		if info.Size() > maxSecretValueBytes {
			return nil, errors.New("secret value exceeds the 1048576-byte safety limit")
		}
		reader = file
		source = "file"
	case command.Flags().Changed("value-fd"):
		if values.valueFD < 0 || values.valueFD > 1<<20 {
			return nil, errors.New("--value-fd is invalid")
		}
		file := os.NewFile(uintptr(values.valueFD), fmt.Sprintf("secret-value-fd-%d", values.valueFD))
		if file == nil {
			return nil, errors.New("--value-fd is invalid")
		}
		reader = file
		source = "file descriptor"
	}
	if reader == nil {
		return nil, errors.New("secret value source is unavailable")
	}
	value, err := io.ReadAll(io.LimitReader(reader, maxSecretValueBytes+1))
	if err != nil {
		clear(value)
		return nil, fmt.Errorf("read secret value from %s", source)
	}
	return validateSecretValue(value)
}

func validateSecretValue(value []byte) ([]byte, error) {
	if len(value) == 0 {
		clear(value)
		return nil, errors.New("secret value must not be empty")
	}
	if len(value) > maxSecretValueBytes {
		clear(value)
		return nil, errors.New("secret value exceeds the 1048576-byte safety limit")
	}
	if !utf8.Valid(value) {
		clear(value)
		return nil, errors.New("secret value must be valid UTF-8")
	}
	return value, nil
}

func marshalBoundedSecretRequest(document any) ([]byte, error) {
	body, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("encode secret request")
	}
	if len(body) > maxSecretCLIRequest {
		clear(body)
		return nil, errors.New("encoded secret request exceeds the safety limit")
	}
	return body, nil
}

func newSecretAPIClient(opts *options, tokenEnvironment string, secretValue []byte) (*secretAPIClient, error) {
	if !environmentNamePattern.MatchString(tokenEnvironment) {
		return nil, errors.New("API token environment variable name is invalid")
	}
	token, present := os.LookupEnv(tokenEnvironment)
	if !present || !validSecretAPIToken(token) {
		return nil, fmt.Errorf("API token environment variable %s is empty or invalid", tokenEnvironment)
	}
	if _, err := adminEndpoint(opts.server, "/admin/v1/secrets"); err != nil {
		return nil, err
	}

	baseClient := opts.adminHTTPClient
	if baseClient == nil {
		baseClient = newAdminHTTPClient()
	}
	clientCopy := *baseClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > 30*time.Second {
		clientCopy.Timeout = 30 * time.Second
	}
	tokenSensitive := secretSensitiveVariants(token)
	var valueSensitive []string
	if len(secretValue) != 0 {
		valueSensitive = secretSensitiveVariants(string(secretValue))
	}
	return &secretAPIClient{
		server: opts.server, token: token, http: &clientCopy,
		tokenSensitive: tokenSensitive, valueSensitive: valueSensitive,
	}, nil
}

func secretSensitiveVariants(value string) []string {
	if value == "" {
		return nil
	}
	variants := []string{value}
	encoded, err := json.Marshal(value)
	if err == nil && len(encoded) >= 2 {
		escaped := string(encoded[1 : len(encoded)-1])
		if escaped != value {
			variants = append(variants, escaped)
		}
	}
	sort.SliceStable(variants, func(left, right int) bool {
		return len(variants[left]) > len(variants[right])
	})
	return variants
}

func validSecretAPIToken(token string) bool {
	if len(token) < 32 || len(token) > 2048 || !utf8.ValidString(token) {
		return false
	}
	for index := range token {
		if token[index] < 0x21 || token[index] > 0x7e {
			return false
		}
	}
	return true
}

func (client *secretAPIClient) do(ctx context.Context, method, path string, query url.Values, requestBody []byte, expectedStatus int, output any) error {
	if len(requestBody) > maxSecretCLIRequest {
		return errors.New("encoded secret request exceeds the safety limit")
	}
	endpoint, err := adminEndpoint(client.server, path)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return errors.New("construct secret API endpoint")
	}
	if len(query) != 0 {
		parsed.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(requestBody))
	if err != nil {
		return errors.New("construct secret API request")
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("call secret API: %s", client.safeUntrustedText(err.Error()))
	}
	if response.Body == nil {
		return errors.New("secret API returned an invalid empty response")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxSecretCLIResponse+1))
	if err != nil {
		clear(responseBody)
		return fmt.Errorf("read secret API response: %s", client.safeUntrustedText(err.Error()))
	}
	defer clear(responseBody)
	if len(responseBody) > maxSecretCLIResponse {
		return errors.New("secret API response exceeds the safety limit")
	}
	if response.StatusCode != expectedStatus {
		return client.problem(response.StatusCode, response.Header, responseBody)
	}
	if expectedStatus == http.StatusNoContent {
		if len(responseBody) != 0 {
			return errors.New("secret API returned an invalid no-content response")
		}
		return nil
	}
	if output == nil || len(responseBody) == 0 || !secretJSONContentType(response.Header.Get("Content-Type")) {
		return errors.New("secret API returned an invalid success document")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("secret API returned malformed JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("secret API returned malformed JSON")
	}
	return nil
}

func secretJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func (client *secretAPIClient) problem(httpStatus int, header http.Header, body []byte) error {
	document, retryAfterSeconds, ok := decodeSecretProblem(httpStatus, header, body)
	if !ok {
		return client.problemStatusOnly(httpStatus)
	}

	detail := client.safeUntrustedText(document.Detail)
	requestID := client.safeUntrustedText(document.RequestID)
	var diagnostic strings.Builder
	_, _ = fmt.Fprintf(&diagnostic, "secret API failed: HTTP %d %s (%s): %s [request_id=%s retryable=%t",
		httpStatus, client.safeTokenField(document.Title), client.safeTokenField(document.Code), detail, requestID, document.Retryable)
	if document.RetryAfter != nil {
		_, _ = fmt.Fprintf(&diagnostic, " retry_after=%s", client.safeUntrustedText(*document.RetryAfter))
	}
	if retryAfterSeconds != nil {
		_, _ = fmt.Fprintf(&diagnostic, " retry_after_seconds=%d", *retryAfterSeconds)
	}
	if document.OperationID != nil {
		_, _ = fmt.Fprintf(&diagnostic, " operation_id=%s", client.safeTokenField(*document.OperationID))
	}
	diagnostic.WriteByte(']')
	return errors.New(safeSecretProblemDetail(diagnostic.String()))
}

func (client *secretAPIClient) problemStatusOnly(httpStatus int) error {
	return fmt.Errorf("secret API failed with HTTP status %d", httpStatus)
}

func decodeSecretProblem(httpStatus int, header http.Header, body []byte) (secretProblemCLI, *int64, bool) {
	if !secretProblemContentType(header.Get("Content-Type")) {
		return secretProblemCLI{}, nil, false
	}
	decoded, err := jsonsafe.Decode(body)
	if err != nil {
		return secretProblemCLI{}, nil, false
	}
	object, ok := decoded.(map[string]any)
	if !ok || !secretProblemFieldPresenceValid(object) {
		return secretProblemCLI{}, nil, false
	}

	var document secretProblemCLI
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return secretProblemCLI{}, nil, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validateSecretProblem(httpStatus, document) {
		return secretProblemCLI{}, nil, false
	}
	retryAfterSeconds, ok := secretProblemRetryAfterSeconds(header)
	if !ok {
		return secretProblemCLI{}, nil, false
	}
	return document, retryAfterSeconds, true
}

func secretProblemContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/problem+json"
}

func secretProblemFieldPresenceValid(object map[string]any) bool {
	for _, field := range []string{"type", "title", "status", "detail", "code", "request_id", "retryable"} {
		value, present := object[field]
		if !present || value == nil {
			return false
		}
	}
	for _, field := range []string{"operation_id", "instance", "retry_after", "feature", "supported_protocol_versions", "errors"} {
		if value, present := object[field]; present && value == nil {
			return false
		}
	}
	return true
}

func validateSecretProblem(httpStatus int, document secretProblemCLI) bool {
	definition, registered := problemcontract.Registry[document.Code]
	if !registered || httpStatus < 400 || httpStatus > 599 || document.Status != httpStatus || definition.Status != httpStatus ||
		document.Type != "https://latchway.dev/problems/"+document.Code || document.Title != definition.Title ||
		document.Retryable != definition.Retryable || !boundedSecretProblemString(document.Detail, 1, 2048) ||
		safeSecretProblemDetail(document.Detail) == "" || !secretProblemRequestIDPattern.MatchString(document.RequestID) {
		return false
	}
	if document.Instance != nil {
		if !boundedSecretProblemString(*document.Instance, 0, 2048) || containsSecretProblemControl(*document.Instance) {
			return false
		}
		if _, err := url.Parse(*document.Instance); err != nil {
			return false
		}
	}
	if (document.Code == "operation_indeterminate") != (document.OperationID != nil) {
		return false
	}
	if document.OperationID != nil && id.Validate(*document.OperationID, id.AdminRequest) != nil {
		return false
	}
	if document.RetryAfter != nil {
		if !boundedSecretProblemString(*document.RetryAfter, 1, 64) {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, *document.RetryAfter); err != nil {
			return false
		}
	}
	if document.Feature != nil && !secretNamePattern.MatchString(*document.Feature) {
		return false
	}
	if document.SupportedProtocolVersions != nil && !validSecretProblemProtocolVersions(*document.SupportedProtocolVersions) {
		return false
	}
	if document.Errors != nil && !validSecretProblemIssues(*document.Errors) {
		return false
	}
	return true
}

func boundedSecretProblemString(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value)
}

func containsSecretProblemControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validSecretProblemProtocolVersions(versions []int) bool {
	if len(versions) > 32 {
		return false
	}
	seen := make(map[int]struct{}, len(versions))
	for _, version := range versions {
		if version < 1 || version > 1<<31-1 {
			return false
		}
		if _, duplicate := seen[version]; duplicate {
			return false
		}
		seen[version] = struct{}{}
	}
	return true
}

func validSecretProblemIssues(issues []secretProblemValidationIssueCLI) bool {
	if len(issues) > 100 {
		return false
	}
	for _, issue := range issues {
		if issue.Severity == nil || issue.Code == nil || issue.Path == nil || issue.Message == nil ||
			(*issue.Severity != "error" && *issue.Severity != "warning") || !secretProblemIssueCodePattern.MatchString(*issue.Code) ||
			!boundedSecretProblemString(*issue.Path, 0, 1024) || !boundedSecretProblemString(*issue.Message, 0, 2048) {
			return false
		}
	}
	return true
}

func secretProblemRetryAfterSeconds(header http.Header) (*int64, bool) {
	values := header.Values("Retry-After")
	if len(values) == 0 {
		return nil, true
	}
	if len(values) != 1 {
		return nil, false
	}
	value := values[0]
	if len(value) < 1 || len(value) > 10 || (len(value) > 1 && value[0] == '0') {
		return nil, false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return nil, false
		}
	}
	seconds, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return nil, false
	}
	return &seconds, true
}

func (client *secretAPIClient) safeUntrustedText(value string) string {
	if containsSecretSensitiveVariant(value, client.tokenSensitive) || containsSecretSensitiveVariant(value, client.valueSensitive) {
		return "[redacted]"
	}
	value = safeSecretProblemDetail(value)
	if value == "" {
		return "[redacted]"
	}
	return value
}

func (client *secretAPIClient) safeTokenField(value string) string {
	if containsSecretSensitiveVariant(value, client.tokenSensitive) || matchesSecretSensitiveVariant(value, client.valueSensitive) {
		return "[redacted]"
	}
	return value
}

func containsSecretSensitiveVariant(value string, variants []string) bool {
	for _, sensitive := range variants {
		if sensitive != "" && strings.Contains(value, sensitive) {
			return true
		}
	}
	return false
}

func matchesSecretSensitiveVariant(value string, variants []string) bool {
	for _, sensitive := range variants {
		if sensitive != "" && value == sensitive {
			return true
		}
	}
	return false
}

func safeSecretProblemDetail(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= maxSecretProblemDetail {
		return value
	}
	cutoff := maxSecretProblemDetail
	for cutoff > 0 && !utf8.RuneStart(value[cutoff]) {
		cutoff--
	}
	return value[:cutoff]
}

func validSecretCursor(value string) bool {
	if len(value) < 1 || len(value) > 2048 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validateSecretMetadata(document secretMetadataCLI, expectedID, expectedEnvironmentID, expectedName string) error {
	if id.Validate(document.ID, id.SecretRecord) != nil || id.Validate(document.EnvironmentID, id.Environment) != nil ||
		!secretNamePattern.MatchString(document.Name) || document.Version < 1 ||
		!secretAlgorithmPattern.MatchString(document.Algorithm) || !secretMasterKeyIDPattern.MatchString(document.MasterKeyID) {
		return errors.New("secret API returned an invalid metadata document")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, document.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return errors.New("secret API returned an invalid metadata document")
	}
	if document.RotatedAt != nil {
		rotatedAt, err := time.Parse(time.RFC3339Nano, *document.RotatedAt)
		if err != nil || rotatedAt.Before(createdAt) {
			return errors.New("secret API returned an invalid metadata document")
		}
	}
	if (expectedID != "" && document.ID != expectedID) ||
		(expectedEnvironmentID != "" && document.EnvironmentID != expectedEnvironmentID) ||
		(expectedName != "" && document.Name != expectedName) {
		return errors.New("secret API returned mismatched metadata")
	}
	return nil
}

func validateSecretPage(document secretPageCLI, environmentID string, pageSize int) error {
	if document.Items == nil || document.Page == nil || document.Page.HasMore == nil ||
		len(document.Items) > pageSize || len(document.Items) > 200 ||
		(*document.Page.HasMore && !validSecretCursor(document.Page.NextCursor)) ||
		(!*document.Page.HasMore && document.Page.NextCursor != "") {
		return errors.New("secret API returned an invalid metadata page")
	}
	seen := make(map[string]struct{}, len(document.Items))
	for _, item := range document.Items {
		if err := validateSecretMetadata(item, "", environmentID, ""); err != nil {
			return errors.New("secret API returned an invalid metadata page")
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return errors.New("secret API returned an invalid metadata page")
		}
		seen[item.ID] = struct{}{}
	}
	return nil
}

func (client *secretAPIClient) metadataContainsToken(document secretMetadataCLI) bool {
	for _, value := range []string{
		document.ID, document.EnvironmentID, document.Name, document.Algorithm,
		document.MasterKeyID, document.CreatedAt,
	} {
		if containsSecretSensitiveVariant(value, client.tokenSensitive) || matchesSecretSensitiveVariant(value, client.valueSensitive) {
			return true
		}
	}
	return document.RotatedAt != nil &&
		(containsSecretSensitiveVariant(*document.RotatedAt, client.tokenSensitive) || matchesSecretSensitiveVariant(*document.RotatedAt, client.valueSensitive))
}

func (client *secretAPIClient) pageContainsToken(document secretPageCLI) bool {
	for _, item := range document.Items {
		if client.metadataContainsToken(item) {
			return true
		}
	}
	return containsSecretSensitiveVariant(document.Page.NextCursor, client.tokenSensitive)
}

func printSecretMetadata(opts *options, document secretMetadataCLI) error {
	if opts.output == "json" {
		return printSecretJSON(opts.stdout, document)
	}
	writer := tabwriter.NewWriter(opts.stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tENVIRONMENT\tNAME\tVERSION\tALGORITHM\tMASTER KEY\tCREATED\tROTATED"); err != nil {
		return err
	}
	if err := writeSecretMetadataRow(writer, document); err != nil {
		return err
	}
	return writer.Flush()
}

func printSecretPage(opts *options, document secretPageCLI) error {
	if opts.output == "json" {
		return printSecretJSON(opts.stdout, document)
	}
	writer := tabwriter.NewWriter(opts.stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tENVIRONMENT\tNAME\tVERSION\tALGORITHM\tMASTER KEY\tCREATED\tROTATED"); err != nil {
		return err
	}
	for _, item := range document.Items {
		if err := writeSecretMetadataRow(writer, item); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer, "\nHAS MORE\tNEXT CURSOR"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%t\t%s\n", *document.Page.HasMore, tableSecretValue(document.Page.NextCursor)); err != nil {
		return err
	}
	return writer.Flush()
}

func writeSecretMetadataRow(writer io.Writer, document secretMetadataCLI) error {
	rotatedAt := "-"
	if document.RotatedAt != nil {
		rotatedAt = *document.RotatedAt
	}
	_, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
		document.ID, document.EnvironmentID, document.Name, document.Version,
		document.Algorithm, document.MasterKeyID, document.CreatedAt, rotatedAt)
	return err
}

func printSecretDelete(opts *options, secretID string) error {
	if opts.output == "json" {
		return printSecretJSON(opts.stdout, map[string]string{"status": "deleted", "secret_id": secretID})
	}
	writer := tabwriter.NewWriter(opts.stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "STATUS\tSECRET ID"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "deleted\t%s\n", secretID); err != nil {
		return err
	}
	return writer.Flush()
}

func tableSecretValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func printSecretJSON(writer io.Writer, document any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}
