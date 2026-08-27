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
	command := &cobra.Command{Use: "admin", Short: "Perform administrative bootstrap operations through the canonical API"}
	command.AddCommand(newAdminBootstrapCommand(opts))
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
	if server.Scheme != "https" && !(server.Scheme == "http" && cliLoopbackHost(server.Hostname())) {
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
