package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/useroverride"
	"github.com/spf13/cobra"
)

const maxAdminCLIResponse = 1 << 20

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type bootstrapCLIOptions struct {
	organizationSlug string
	organizationName string
	email            string
	displayName      string
	tokenEnvironment string
	passwordEnv      string
}

type bootstrapCLIRequest struct {
	BootstrapToken   string `json:"bootstrap_token"`
	OrganizationSlug string `json:"organization_slug"`
	OrganizationName string `json:"organization_name"`
	Email            string `json:"email"`
	DisplayName      string `json:"display_name"`
	Password         string `json:"password"`
}

type bootstrapCLIResponse struct {
	Administrator struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"administrator"`
	OrganizationID string `json:"organization_id"`
}

type adminProblem struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func newAdminCommand(opts *options) *cobra.Command {
	command := &cobra.Command{Use: "admin", Short: "Perform administrative operations through the canonical API"}
	command.AddCommand(
		newAdminBootstrapCommand(opts), newAdminAccountsCommand(opts),
		newAdminAPITokensCommand(opts), newAdminUsersCommand(opts),
	)
	return command
}

type userOverrideCLIOptions struct {
	environmentID    string
	limitPlan        string
	reason           string
	expiresAt        string
	tokenEnvironment string
}

type userOverrideCLIResponse struct {
	ID                string `json:"id"`
	EnvironmentID     string `json:"environment_id"`
	LimitPlanOverride *struct {
		ID        string     `json:"id"`
		LimitPlan string     `json:"limit_plan"`
		Reason    string     `json:"reason"`
		CreatedAt time.Time  `json:"created_at"`
		ExpiresAt *time.Time `json:"expires_at"`
	} `json:"limit_plan_override"`
}

func newAdminUsersCommand(opts *options) *cobra.Command {
	users := &cobra.Command{Use: "users", Short: "Manage pseudonymous application users"}
	override := &cobra.Command{Use: "limit-override", Short: "Manage environment-specific user limit-plan overrides"}
	override.AddCommand(newAdminUserOverrideSetCommand(opts), newAdminUserOverrideClearCommand(opts))
	users.AddCommand(override)
	return users
}

func newAdminUserOverrideSetCommand(opts *options) *cobra.Command {
	values := userOverrideCLIOptions{tokenEnvironment: "LATCHWAY_ADMIN_API_TOKEN"}
	command := &cobra.Command{
		Use:   "set USER_ID",
		Short: "Replace an explicit limit-plan override",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdminUserOverrideSet(cmd, opts, args[0], values)
		},
	}
	command.Flags().StringVar(&values.environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&values.limitPlan, "limit-plan", "", "server-owned limit-plan identifier")
	command.Flags().StringVar(&values.reason, "reason", "", "administrative reason (1-500 characters)")
	command.Flags().StringVar(&values.expiresAt, "expires-at", "", "optional RFC 3339 expiration instant")
	command.Flags().StringVar(&values.tokenEnvironment, "api-token-env", values.tokenEnvironment, "environment variable containing a scoped Admin API token")
	_ = command.MarkFlagRequired("environment")
	_ = command.MarkFlagRequired("limit-plan")
	_ = command.MarkFlagRequired("reason")
	return command
}

func newAdminUserOverrideClearCommand(opts *options) *cobra.Command {
	values := userOverrideCLIOptions{tokenEnvironment: "LATCHWAY_ADMIN_API_TOKEN"}
	command := &cobra.Command{
		Use:   "clear USER_ID",
		Short: "Clear the explicit limit-plan override",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdminUserOverrideClear(cmd, opts, args[0], values)
		},
	}
	command.Flags().StringVar(&values.environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&values.tokenEnvironment, "api-token-env", values.tokenEnvironment, "environment variable containing a scoped Admin API token")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newAdminBootstrapCommand(opts *options) *cobra.Command {
	values := bootstrapCLIOptions{
		tokenEnvironment: "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN",
		passwordEnv:      "LATCHWAY_ADMIN_PASSWORD",
	}
	command := &cobra.Command{
		Use:   "bootstrap",
		Short: "Consume the one-time token and create the first owner",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAdminBootstrap(cmd, opts, values)
		},
	}
	command.Flags().StringVar(&values.organizationSlug, "organization-slug", "", "initial organization slug")
	command.Flags().StringVar(&values.organizationName, "organization-name", "", "initial organization display name")
	command.Flags().StringVar(&values.email, "email", "", "first owner email")
	command.Flags().StringVar(&values.displayName, "display-name", "", "first owner display name")
	command.Flags().StringVar(&values.tokenEnvironment, "bootstrap-token-env", values.tokenEnvironment, "environment variable containing the one-time bootstrap token")
	command.Flags().StringVar(&values.passwordEnv, "password-env", values.passwordEnv, "environment variable containing the first owner password")
	_ = command.MarkFlagRequired("organization-slug")
	_ = command.MarkFlagRequired("organization-name")
	_ = command.MarkFlagRequired("email")
	_ = command.MarkFlagRequired("display-name")
	return command
}

func runAdminBootstrap(cmd *cobra.Command, opts *options, values bootstrapCLIOptions) error {
	if !environmentNamePattern.MatchString(values.tokenEnvironment) || !environmentNamePattern.MatchString(values.passwordEnv) {
		return errors.New("secret environment variable names are invalid")
	}
	bootstrapToken := os.Getenv(values.tokenEnvironment)
	if bootstrapToken == "" {
		return fmt.Errorf("bootstrap token environment variable %s is empty", values.tokenEnvironment)
	}
	password := os.Getenv(values.passwordEnv)
	if password == "" {
		return fmt.Errorf("password environment variable %s is empty", values.passwordEnv)
	}
	endpoint, err := adminEndpoint(opts.server, "/admin/v1/auth/bootstrap")
	if err != nil {
		return err
	}
	body, err := json.Marshal(bootstrapCLIRequest{
		BootstrapToken: bootstrapToken, OrganizationSlug: values.organizationSlug,
		OrganizationName: values.organizationName, Email: values.email,
		DisplayName: values.displayName, Password: password,
	})
	if err != nil {
		return fmt.Errorf("encode bootstrap request: %w", err)
	}
	request, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		clear(body)
		return fmt.Errorf("construct bootstrap request: %w", err)
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Content-Type", "application/json")
	client := opts.adminHTTPClient
	if client == nil {
		client = newAdminHTTPClient()
	}
	response, err := client.Do(request)
	clear(body)
	if err != nil {
		return fmt.Errorf("call administrative bootstrap API: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxAdminCLIResponse+1))
	if err != nil {
		return fmt.Errorf("read administrative bootstrap response: %w", err)
	}
	if len(responseBody) > maxAdminCLIResponse {
		return errors.New("administrative bootstrap response exceeds the safety limit")
	}
	if response.StatusCode != http.StatusCreated {
		var problem adminProblem
		if json.Unmarshal(responseBody, &problem) == nil && problem.Code != "" {
			return fmt.Errorf("administrative bootstrap failed (%s): %s", problem.Code, strings.TrimSpace(problem.Detail))
		}
		return fmt.Errorf("administrative bootstrap failed with HTTP status %d", response.StatusCode)
	}
	var document bootstrapCLIResponse
	if err := json.Unmarshal(responseBody, &document); err != nil || document.Administrator.ID == "" || document.OrganizationID == "" {
		return errors.New("administrative bootstrap returned an invalid success document")
	}
	return opts.print(map[string]any{
		"administrator_id": document.Administrator.ID,
		"email":            document.Administrator.Email,
		"organization_id":  document.OrganizationID,
		"status":           "created",
	})
}

func runAdminUserOverrideSet(cmd *cobra.Command, opts *options, userID string, values userOverrideCLIOptions) error {
	if id.Validate(userID, id.ApplicationUser) != nil || id.Validate(values.environmentID, id.Environment) != nil {
		return errors.New("user or environment ID is invalid")
	}
	if _, err := useroverride.Encode(useroverride.Document{LimitPlan: values.limitPlan}); err != nil {
		return errors.New("limit-plan identifier is invalid")
	}
	reason := strings.TrimSpace(values.reason)
	if !utf8.ValidString(reason) || strings.ContainsRune(reason, '\x00') || utf8.RuneCountInString(reason) < 1 || utf8.RuneCountInString(reason) > 500 {
		return errors.New("reason must contain 1 to 500 characters")
	}
	var expiresAt *time.Time
	if values.expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, values.expiresAt)
		if err != nil {
			return errors.New("--expires-at must be an RFC 3339 instant")
		}
		parsed = parsed.UTC()
		expiresAt = &parsed
	}
	requestDocument := map[string]any{"limit_plan": values.limitPlan, "reason": reason}
	if expiresAt != nil {
		requestDocument["expires_at"] = expiresAt
	}
	body, err := json.Marshal(requestDocument)
	if err != nil {
		return fmt.Errorf("encode user limit override request: %w", err)
	}
	document, err := callAdminUserOverride(cmd, opts, http.MethodPut, userID, values.environmentID, values.tokenEnvironment, body)
	clear(body)
	if err != nil {
		return err
	}
	if document.ID != userID || document.EnvironmentID != values.environmentID || document.LimitPlanOverride == nil ||
		document.LimitPlanOverride.ID == "" || document.LimitPlanOverride.LimitPlan != values.limitPlan {
		return errors.New("administrative user override returned an invalid success document")
	}
	return opts.print(map[string]any{
		"status": "set", "user_id": document.ID, "environment_id": document.EnvironmentID,
		"override_id": document.LimitPlanOverride.ID, "limit_plan": document.LimitPlanOverride.LimitPlan,
		"expires_at": document.LimitPlanOverride.ExpiresAt,
	})
}

func runAdminUserOverrideClear(cmd *cobra.Command, opts *options, userID string, values userOverrideCLIOptions) error {
	if id.Validate(userID, id.ApplicationUser) != nil || id.Validate(values.environmentID, id.Environment) != nil {
		return errors.New("user or environment ID is invalid")
	}
	document, err := callAdminUserOverride(cmd, opts, http.MethodDelete, userID, values.environmentID, values.tokenEnvironment, nil)
	if err != nil {
		return err
	}
	if document.ID != userID || document.EnvironmentID != values.environmentID || document.LimitPlanOverride != nil {
		return errors.New("administrative user override clear returned an invalid success document")
	}
	return opts.print(map[string]any{
		"status": "cleared", "user_id": document.ID, "environment_id": document.EnvironmentID,
	})
}

func callAdminUserOverride(cmd *cobra.Command, opts *options, method, userID, environmentID, tokenEnvironment string, body []byte) (userOverrideCLIResponse, error) {
	if !environmentNamePattern.MatchString(tokenEnvironment) {
		return userOverrideCLIResponse{}, errors.New("API token environment variable name is invalid")
	}
	token := os.Getenv(tokenEnvironment)
	if len(token) < 32 || len(token) > 2048 || strings.ContainsAny(token, "\r\n\x00") {
		return userOverrideCLIResponse{}, fmt.Errorf("API token environment variable %s is empty or invalid", tokenEnvironment)
	}
	endpoint, err := adminUserOverrideEndpoint(opts.server, userID, environmentID)
	if err != nil {
		return userOverrideCLIResponse{}, err
	}
	request, err := http.NewRequestWithContext(cmd.Context(), method, endpoint, bytes.NewReader(body))
	if err != nil {
		return userOverrideCLIResponse{}, fmt.Errorf("construct administrative user override request: %w", err)
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := opts.adminHTTPClient
	if client == nil {
		client = newAdminHTTPClient()
	}
	response, err := client.Do(request)
	if err != nil {
		return userOverrideCLIResponse{}, fmt.Errorf("call administrative user override API: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxAdminCLIResponse+1))
	if err != nil {
		return userOverrideCLIResponse{}, fmt.Errorf("read administrative user override response: %w", err)
	}
	defer clear(responseBody)
	if len(responseBody) > maxAdminCLIResponse {
		return userOverrideCLIResponse{}, errors.New("administrative user override response exceeds the safety limit")
	}
	if method == http.MethodDelete && response.StatusCode == http.StatusNoContent && len(responseBody) == 0 {
		return userOverrideCLIResponse{ID: userID, EnvironmentID: environmentID}, nil
	}
	if response.StatusCode != http.StatusOK {
		var problem adminProblem
		if json.Unmarshal(responseBody, &problem) == nil && problem.Code != "" {
			detail := strings.TrimSpace(problem.Detail)
			if token != "" {
				detail = strings.ReplaceAll(detail, token, "[redacted]")
			}
			return userOverrideCLIResponse{}, fmt.Errorf("administrative user override failed (%s): %s", problem.Code, detail)
		}
		return userOverrideCLIResponse{}, fmt.Errorf("administrative user override failed with HTTP status %d", response.StatusCode)
	}
	var document userOverrideCLIResponse
	if err := json.Unmarshal(responseBody, &document); err != nil {
		return userOverrideCLIResponse{}, errors.New("administrative user override returned malformed JSON")
	}
	return document, nil
}

func adminUserOverrideEndpoint(rawServer, userID, environmentID string) (string, error) {
	endpoint, err := adminEndpoint(rawServer, "/admin/v1/users/"+userID+"/limit-override")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("construct administrative user override endpoint")
	}
	query := parsed.Query()
	query.Set("environment_id", environmentID)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func newAdminHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func adminEndpoint(rawServer, path string) (string, error) {
	server, err := url.Parse(strings.TrimSpace(rawServer))
	if err != nil || server.Scheme == "" || server.Host == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" || (server.Path != "" && server.Path != "/") {
		return "", errors.New("--server must be an absolute origin without credentials, path, query, or fragment")
	}
	if server.Scheme != "https" && (server.Scheme != "http" || !cliLoopbackHost(server.Hostname())) {
		return "", errors.New("--server must use HTTPS except on localhost or a loopback address")
	}
	server.Path = path
	server.RawPath = ""
	return server.String(), nil
}

func cliLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
