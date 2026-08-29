package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

type administratorCLI struct {
	ID                    string  `json:"id"`
	MembershipID          string  `json:"membership_id"`
	OrganizationID        string  `json:"organization_id"`
	Email                 string  `json:"email"`
	DisplayName           string  `json:"display_name"`
	Role                  string  `json:"role"`
	Status                string  `json:"status"`
	PasswordResetRequired bool    `json:"password_reset_required"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
	DisabledAt            *string `json:"disabled_at,omitempty"`
}

type administratorPageCLI struct {
	Items []administratorCLI `json:"items"`
	Page  pageInfoCLI        `json:"page"`
}

type administratorCreateCLIOptions struct {
	email       string
	displayName string
	role        string
	password    secretValueCLIOptions
}

func newAdminAccountsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "accounts", Aliases: []string{"account", "administrators"},
		Short: "Manage local administrator accounts and organization roles",
	}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newAdminAccountsListCommand(opts, values),
		newAdminAccountCreateCommand(opts, values),
		newAdminAccountRoleCommand(opts, values),
		newAdminAccountStatusCommand(opts, values, false),
		newAdminAccountStatusCommand(opts, values, true),
		newAdminAccountResetCommand(opts, values),
	)
	return command
}

func newAdminAccountsListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List redaction-safe administrator membership metadata", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if pageSize < 1 || pageSize > 200 || len(cursor) > 2048 || strings.ContainsAny(cursor, "\r\n\x00") {
				return errors.New("page size or cursor is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			query := url.Values{"page_size": []string{strconv.Itoa(pageSize)}}
			if cursor != "" {
				query.Set("cursor", cursor)
			}
			var page administratorPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/administrators", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			return printAdministrators(opts, page)
		},
	}
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of administrators to return (1-200)")
	return command
}

func newAdminAccountCreateCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	values := administratorCreateCLIOptions{role: "viewer", password: secretValueCLIOptions{valueFD: -1}}
	command := &cobra.Command{
		Use: "create", Short: "Create a local administrator and first organization membership", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !validAdministratorRole(values.role) || strings.TrimSpace(values.email) == "" || strings.TrimSpace(values.displayName) == "" {
				return errors.New("administrator email, display name, or role is invalid")
			}
			password, err := readAdministratorPassword(cmd, values.password)
			if err != nil {
				return err
			}
			defer clear(password)
			client, err := newSensitiveControlAPIClient(opts, root.tokenEnvironment, password)
			if err != nil {
				return err
			}
			var administrator administratorCLI
			request := map[string]any{
				"email": strings.TrimSpace(values.email), "display_name": strings.TrimSpace(values.displayName),
				"role": values.role, "password": string(password),
			}
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/administrators", nil, request, http.StatusCreated, &administrator); err != nil {
				return err
			}
			return printAdministrator(opts, administrator)
		},
	}
	command.Flags().StringVar(&values.email, "email", "", "administrator email address")
	command.Flags().StringVar(&values.displayName, "display-name", "", "administrator display name")
	command.Flags().StringVar(&values.role, "role", values.role, "owner, admin, operator, or viewer")
	addSecretValueFlags(command, &values.password)
	_ = command.MarkFlagRequired("email")
	_ = command.MarkFlagRequired("display-name")
	return command
}

func newAdminAccountRoleCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var role string
	command := &cobra.Command{
		Use: "role ADMIN_USER_ID", Short: "Change an administrator's organization role", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.AdminUser) != nil || !validAdministratorRole(role) {
				return errors.New("administrator ID or role is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var administrator administratorCLI
			if _, err := client.do(cmd.Context(), http.MethodPut, "/admin/v1/administrators/"+args[0]+"/role", nil, map[string]string{"role": role}, http.StatusOK, &administrator); err != nil {
				return err
			}
			return printAdministrator(opts, administrator)
		},
	}
	command.Flags().StringVar(&role, "role", "", "owner, admin, operator, or viewer")
	_ = command.MarkFlagRequired("role")
	return command
}

func newAdminAccountStatusCommand(opts *options, root *controlCommandOptions, enabled bool) *cobra.Command {
	action := "disable"
	short := "Disable an administrator membership and revoke its active credentials"
	if enabled {
		action = "enable"
		short = "Re-enable a disabled administrator membership"
	}
	return &cobra.Command{
		Use: action + " ADMIN_USER_ID", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.AdminUser) != nil {
				return errors.New("administrator ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var administrator administratorCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/administrators/"+args[0]+"/"+action, nil, nil, http.StatusOK, &administrator); err != nil {
				return err
			}
			return printAdministrator(opts, administrator)
		},
	}
}

func newAdminAccountResetCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	values := secretValueCLIOptions{valueFD: -1}
	command := &cobra.Command{
		Use: "reset-password ADMIN_USER_ID", Aliases: []string{"reset"},
		Short: "Replace a local administrator password and revoke active credentials", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.AdminUser) != nil {
				return errors.New("administrator ID is invalid")
			}
			password, err := readAdministratorPassword(cmd, values)
			if err != nil {
				return err
			}
			defer clear(password)
			client, err := newSensitiveControlAPIClient(opts, root.tokenEnvironment, password)
			if err != nil {
				return err
			}
			var administrator administratorCLI
			if _, err := client.do(
				cmd.Context(), http.MethodPost, "/admin/v1/administrators/"+args[0]+"/reset-password",
				nil, map[string]string{"password": string(password)}, http.StatusOK, &administrator,
			); err != nil {
				return err
			}
			return printAdministrator(opts, administrator)
		},
	}
	addSecretValueFlags(command, &values)
	return command
}

func readAdministratorPassword(command *cobra.Command, values secretValueCLIOptions) ([]byte, error) {
	password, err := readSecretValue(command, values)
	if err != nil {
		return nil, err
	}
	if len(password) < 12 || len(password) > 1024 {
		clear(password)
		return nil, errors.New("administrator password must contain 12 to 1024 UTF-8 bytes")
	}
	return password, nil
}

func newSensitiveControlAPIClient(opts *options, tokenEnvironment string, secret []byte) (*controlAPIClient, error) {
	client, err := newControlAPIClient(opts, tokenEnvironment)
	if err != nil {
		return nil, err
	}
	client.tokenSensitive = append(client.tokenSensitive, secretSensitiveVariants(string(secret))...)
	return client, nil
}

func validAdministratorRole(value string) bool {
	switch value {
	case "owner", "admin", "operator", "viewer":
		return true
	default:
		return false
	}
}

func printAdministrators(opts *options, page administratorPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, administrator := range page.Items {
		rows = append(rows, []string{
			administrator.ID, administrator.Email, administrator.DisplayName,
			administrator.Role, administrator.Status, formatControlTime(administrator.UpdatedAt),
		})
	}
	if err := printControlTable(opts, []string{"ADMINISTRATOR", "EMAIL", "NAME", "ROLE", "STATUS", "UPDATED"}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printAdministrator(opts *options, administrator administratorCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, administrator)
	}
	disabledAt := "-"
	if administrator.DisabledAt != nil {
		disabledAt = formatControlTime(*administrator.DisabledAt)
	}
	return printControlTable(opts, []string{"ADMINISTRATOR", "EMAIL", "NAME", "ROLE", "STATUS", "DISABLED"}, [][]string{{
		administrator.ID, administrator.Email, administrator.DisplayName,
		administrator.Role, administrator.Status, disabledAt,
	}})
}
