package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

var administratorCapabilities = []string{
	"activate_configuration",
	"inspect_users",
	"manage_owners",
	"manage_secrets",
	"revoke_installations",
	"run_self_tests",
	"view_prompt_bodies",
}

type tokenModeMembershipCLI struct {
	OrganizationID string `json:"organization_id"`
	Role           string `json:"role"`
}

type tokenModeSessionCLI struct {
	Administrator struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Enabled bool   `json:"enabled"`
	} `json:"administrator"`
	OrganizationID string                   `json:"organization_id"`
	Memberships    []tokenModeMembershipCLI `json:"memberships"`
	Capabilities   []string                 `json:"capabilities"`
	ExpiresAt      *string                  `json:"expires_at"`
}

type apiTokenMetadataCLI struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	Revoked   bool     `json:"revoked"`
}

type apiTokenPageCLI struct {
	Items []apiTokenMetadataCLI `json:"items"`
}

type createdAPITokenCLI struct {
	Token    string              `json:"token"`
	Metadata apiTokenMetadataCLI `json:"metadata"`
}

func newTokenModeLoginCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "login", Short: "Validate scoped API-token access without persisting credentials", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newControlAPIClient(opts, values.tokenEnvironment)
			if err != nil {
				return err
			}
			var session tokenModeSessionCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/auth/session", nil, nil, http.StatusOK, &session); err != nil {
				return err
			}
			if err := validateTokenModeSession(session); err != nil {
				return err
			}
			return printTokenModeSession(opts, session)
		},
	}
	addControlTokenFlag(command, values)
	return command
}

func newTokenModeLogoutCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "logout", Short: "Revoke the current environment-supplied API token", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newControlAPIClient(opts, values.tokenEnvironment)
			if err != nil {
				return err
			}
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/auth/logout", nil, nil, http.StatusNoContent, nil); err != nil {
				return err
			}
			return opts.print(map[string]any{"authentication_mode": "api_token", "status": "revoked"})
		},
	}
	addControlTokenFlag(command, values)
	return command
}

func newAdminAPITokensCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "api-tokens", Aliases: []string{"tokens"},
		Short: "Manage scoped API tokens through the canonical Admin API",
	}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newAdminAPITokensListCommand(opts, values),
		newAdminAPITokenCreateCommand(opts, values),
		newAdminAPITokenRevokeCommand(opts, values),
	)
	return command
}

func newAdminAPITokensListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List metadata for the current administrator's API tokens", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page apiTokenPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/api-tokens", nil, nil, http.StatusOK, &page); err != nil {
				return err
			}
			for _, item := range page.Items {
				if err := validateAPITokenMetadata(item); err != nil {
					return err
				}
			}
			return printAPITokens(opts, page.Items)
		},
	}
}

func newAdminAPITokenCreateCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var name, expiresAt, outputFile string
	var scopes []string
	command := &cobra.Command{
		Use: "create", Short: "Create a scoped token and write it once to a new mode-0600 file", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request, err := apiTokenCreateRequest(name, scopes, expiresAt)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			metadata, err := createAPITokenFile(cmd, client, outputFile, request)
			if err != nil {
				return err
			}
			return printAPIToken(opts, metadata)
		},
	}
	command.Flags().StringVar(&name, "name", "", "non-secret token name")
	command.Flags().StringSliceVar(&scopes, "scope", nil, "capability scope (repeat or comma-separate)")
	command.Flags().StringVar(&expiresAt, "expires-at", "", "optional RFC 3339 expiration instant")
	command.Flags().StringVar(&outputFile, "token-output-file", "", "new file that receives the token exactly once with mode 0600")
	_ = command.MarkFlagRequired("name")
	_ = command.MarkFlagRequired("scope")
	_ = command.MarkFlagRequired("token-output-file")
	return command
}

func newAdminAPITokenRevokeCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "revoke TOKEN_ID", Short: "Revoke one API token owned by the current administrator", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.AdminAPIToken) != nil {
				return errors.New("API token ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			if _, err := client.do(cmd.Context(), http.MethodDelete, "/admin/v1/api-tokens/"+args[0], nil, nil, http.StatusNoContent, nil); err != nil {
				return err
			}
			return opts.print(map[string]any{"status": "revoked", "token_id": args[0]})
		},
	}
}

func apiTokenCreateRequest(name string, scopes []string, expiresAt string) (map[string]any, error) {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\r\n\x00") {
		return nil, errors.New("API token name is invalid")
	}
	if len(scopes) == 0 || len(scopes) > len(administratorCapabilities) {
		return nil, errors.New("API token scope is invalid")
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(administratorCapabilities, scope) {
			return nil, fmt.Errorf("API token scope %q is invalid", scope)
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, fmt.Errorf("API token scope %q is duplicated", scope)
		}
		seen[scope] = struct{}{}
	}
	scopes = slices.Clone(scopes)
	slices.Sort(scopes)
	request := map[string]any{"name": name, "scopes": scopes}
	if expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil || !parsed.After(time.Now()) {
			return nil, errors.New("--expires-at must be a future RFC 3339 instant")
		}
		request["expires_at"] = parsed.UTC()
	}
	return request, nil
}

func createAPITokenFile(command *cobra.Command, client *controlAPIClient, path string, request map[string]any) (apiTokenMetadataCLI, error) {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return apiTokenMetadataCLI{}, errors.New("token output file is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return apiTokenMetadataCLI{}, errors.New("create exclusive token output file")
	}
	keepFile := false
	defer func() {
		_ = file.Close()
		if !keepFile {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return apiTokenMetadataCLI{}, errors.New("secure token output file permissions")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return apiTokenMetadataCLI{}, errors.New("token output file is not a mode-0600 regular file")
	}

	var issued createdAPITokenCLI
	if _, err := client.do(command.Context(), http.MethodPost, "/admin/v1/api-tokens", nil, request, http.StatusCreated, &issued); err != nil {
		return apiTokenMetadataCLI{}, err
	}
	if !validSecretAPIToken(issued.Token) || validateAPITokenMetadata(issued.Metadata) != nil || issued.Metadata.Revoked {
		if id.Validate(issued.Metadata.ID, id.AdminAPIToken) == nil {
			_, _ = client.do(command.Context(), http.MethodDelete, "/admin/v1/api-tokens/"+issued.Metadata.ID, nil, nil, http.StatusNoContent, nil)
		}
		return apiTokenMetadataCLI{}, errors.New("Admin API returned an invalid token creation document")
	}
	plaintext := []byte(issued.Token)
	issued.Token = ""
	defer clear(plaintext)
	if err := writeExclusiveToken(file, plaintext); err != nil {
		revocationErr := revokeCreatedAPIToken(command, client, issued.Metadata.ID)
		if revocationErr != nil {
			return apiTokenMetadataCLI{}, fmt.Errorf("write token output file; revocation of created token %s could not be confirmed", issued.Metadata.ID)
		}
		return apiTokenMetadataCLI{}, errors.New("write token output file; the created token was revoked")
	}
	keepFile = true
	return issued.Metadata, nil
}

func writeExclusiveToken(file *os.File, plaintext []byte) error {
	written, err := file.Write(plaintext)
	if err != nil || written != len(plaintext) {
		return errors.New("write credential")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync credential")
	}
	if err := file.Close(); err != nil {
		return errors.New("close credential")
	}
	return nil
}

func revokeCreatedAPIToken(command *cobra.Command, client *controlAPIClient, tokenID string) error {
	if id.Validate(tokenID, id.AdminAPIToken) != nil {
		return errors.New("created token ID is invalid")
	}
	_, err := client.do(command.Context(), http.MethodDelete, "/admin/v1/api-tokens/"+tokenID, nil, nil, http.StatusNoContent, nil)
	return err
}

func validateAPITokenMetadata(metadata apiTokenMetadataCLI) error {
	if id.Validate(metadata.ID, id.AdminAPIToken) != nil || len(strings.TrimSpace(metadata.Name)) == 0 ||
		len(metadata.Name) > 256 || len(metadata.Scopes) == 0 || len(metadata.Scopes) > len(administratorCapabilities) {
		return errors.New("Admin API returned invalid API token metadata")
	}
	seen := make(map[string]struct{}, len(metadata.Scopes))
	for _, scope := range metadata.Scopes {
		if !slices.Contains(administratorCapabilities, scope) {
			return errors.New("Admin API returned an unknown API token scope")
		}
		if _, duplicate := seen[scope]; duplicate {
			return errors.New("Admin API returned duplicate API token scopes")
		}
		seen[scope] = struct{}{}
	}
	if _, err := time.Parse(time.RFC3339Nano, metadata.CreatedAt); err != nil {
		return errors.New("Admin API returned an invalid API token creation time")
	}
	if metadata.ExpiresAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *metadata.ExpiresAt); err != nil {
			return errors.New("Admin API returned an invalid API token expiration time")
		}
	}
	return nil
}

func validateTokenModeSession(session tokenModeSessionCLI) error {
	if id.Validate(session.Administrator.ID, id.AdminUser) != nil ||
		id.Validate(session.OrganizationID, id.Organization) != nil ||
		!session.Administrator.Enabled || len(session.Administrator.Email) < 3 || len(session.Administrator.Email) > 320 ||
		strings.ContainsAny(session.Administrator.Email, "\r\n\x00") {
		return errors.New("Admin API returned an invalid token-mode session")
	}
	for _, membership := range session.Memberships {
		if id.Validate(membership.OrganizationID, id.Organization) != nil || !validAdministratorRole(membership.Role) {
			return errors.New("Admin API returned an invalid token-mode membership")
		}
	}
	seen := make(map[string]struct{}, len(session.Capabilities))
	for _, capability := range session.Capabilities {
		if !slices.Contains(administratorCapabilities, capability) {
			return errors.New("Admin API returned an invalid token-mode capability")
		}
		if _, duplicate := seen[capability]; duplicate {
			return errors.New("Admin API returned duplicate token-mode capabilities")
		}
		seen[capability] = struct{}{}
	}
	if session.ExpiresAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *session.ExpiresAt); err != nil {
			return errors.New("Admin API returned an invalid token-mode expiration")
		}
	}
	return nil
}

func printTokenModeSession(opts *options, session tokenModeSessionCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, session)
	}
	expiresAt := "never"
	if session.ExpiresAt != nil {
		expiresAt = formatControlTime(*session.ExpiresAt)
	}
	return printControlTable(opts, []string{"ADMINISTRATOR", "EMAIL", "ORGANIZATION", "CAPABILITIES", "EXPIRES"}, [][]string{{
		session.Administrator.ID, session.Administrator.Email, session.OrganizationID,
		strings.Join(session.Capabilities, ","), expiresAt,
	}})
}

func printAPITokens(opts *options, items []apiTokenMetadataCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, apiTokenPageCLI{Items: items})
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		expiresAt := "never"
		if item.ExpiresAt != nil {
			expiresAt = formatControlTime(*item.ExpiresAt)
		}
		rows = append(rows, []string{item.ID, item.Name, strings.Join(item.Scopes, ","), boolLabel(item.Revoked), expiresAt})
	}
	return printControlTable(opts, []string{"TOKEN", "NAME", "SCOPES", "REVOKED", "EXPIRES"}, rows)
}

func printAPIToken(opts *options, metadata apiTokenMetadataCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, metadata)
	}
	return printAPITokens(opts, []apiTokenMetadataCLI{metadata})
}
