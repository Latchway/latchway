package cli

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

type applicationLifecycleCLI struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Slug           string  `json:"slug"`
	DisplayName    string  `json:"display_name"`
	Status         string  `json:"status"`
	DisabledAt     *string `json:"disabled_at,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

type environmentLifecycleCLI struct {
	ID            string  `json:"id"`
	ApplicationID string  `json:"application_id"`
	Slug          string  `json:"slug"`
	DisplayName   string  `json:"display_name"`
	Kind          string  `json:"kind"`
	Status        string  `json:"status"`
	DisabledAt    *string `json:"disabled_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

func newApplicationsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "applications", Aliases: []string{"application", "apps"}, Short: "Manage application lifecycle status"}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newApplicationLifecycleCommand(opts, values, false),
		newApplicationLifecycleCommand(opts, values, true),
	)
	return command
}

func newEnvironmentsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "environments", Aliases: []string{"environment", "envs"}, Short: "Manage environment lifecycle status"}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newEnvironmentLifecycleCommand(opts, values, false),
		newEnvironmentLifecycleCommand(opts, values, true),
	)
	return command
}

func newApplicationLifecycleCommand(opts *options, root *controlCommandOptions, enabled bool) *cobra.Command {
	action := "disable"
	short := "Disable an application and transactionally revoke scoped client credentials"
	if enabled {
		action = "enable"
		short = "Re-enable an application without reviving revoked credentials"
	}
	var reason string
	command := &cobra.Command{
		Use: action + " APPLICATION_ID", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.Application) != nil {
				return errors.New("application ID is invalid")
			}
			var request any
			if !enabled {
				validated, err := validLifecycleReasonCLI(reason)
				if err != nil {
					return err
				}
				request = map[string]string{"reason": validated}
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var application applicationLifecycleCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/applications/"+args[0]+"/"+action, nil, request, http.StatusOK, &application); err != nil {
				return err
			}
			if !validApplicationLifecycleCLI(application, enabled) {
				return errors.New("admin API returned a non-conforming application lifecycle document")
			}
			return printApplicationLifecycle(opts, application)
		},
	}
	if !enabled {
		command.Flags().StringVar(&reason, "reason", "", "operator reason (1-500 characters; value is not persisted in audit data)")
		_ = command.MarkFlagRequired("reason")
	}
	return command
}

func newEnvironmentLifecycleCommand(opts *options, root *controlCommandOptions, enabled bool) *cobra.Command {
	action := "disable"
	short := "Disable an environment and transactionally revoke scoped client credentials"
	if enabled {
		action = "enable"
		short = "Re-enable an environment without reviving revoked credentials"
	}
	var reason string
	command := &cobra.Command{
		Use: action + " ENVIRONMENT_ID", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.Environment) != nil {
				return errors.New("environment ID is invalid")
			}
			var request any
			if !enabled {
				validated, err := validLifecycleReasonCLI(reason)
				if err != nil {
					return err
				}
				request = map[string]string{"reason": validated}
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var environment environmentLifecycleCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/environments/"+args[0]+"/"+action, nil, request, http.StatusOK, &environment); err != nil {
				return err
			}
			if !validEnvironmentLifecycleCLI(environment, enabled) {
				return errors.New("admin API returned a non-conforming environment lifecycle document")
			}
			return printEnvironmentLifecycle(opts, environment)
		},
	}
	if !enabled {
		command.Flags().StringVar(&reason, "reason", "", "operator reason (1-500 characters; value is not persisted in audit data)")
		_ = command.MarkFlagRequired("reason")
	}
	return command
}

func validLifecycleReasonCLI(value string) (string, error) {
	if value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 ||
		utf8.RuneCountInString(value) > 500 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("disable reason must contain 1 to 500 safe characters without surrounding whitespace")
	}
	return value, nil
}

func validApplicationLifecycleCLI(item applicationLifecycleCLI, enabled bool) bool {
	if id.Validate(item.ID, id.Application) != nil || id.Validate(item.OrganizationID, id.Organization) != nil ||
		!operationalIdentifierPattern.MatchString(item.Slug) || strings.TrimSpace(item.DisplayName) == "" || !validControlTimestamp(item.CreatedAt) {
		return false
	}
	return validLifecycleStatus(item.Status, item.DisabledAt, enabled)
}

func validEnvironmentLifecycleCLI(item environmentLifecycleCLI, enabled bool) bool {
	if id.Validate(item.ID, id.Environment) != nil || id.Validate(item.ApplicationID, id.Application) != nil ||
		!operationalIdentifierPattern.MatchString(item.Slug) || strings.TrimSpace(item.DisplayName) == "" || !validControlTimestamp(item.CreatedAt) {
		return false
	}
	switch item.Kind {
	case "development", "staging", "production":
	default:
		return false
	}
	return validLifecycleStatus(item.Status, item.DisabledAt, enabled)
}

func validLifecycleStatus(status string, disabledAt *string, enabled bool) bool {
	if enabled {
		return status == "active" && disabledAt == nil
	}
	return status == "disabled" && disabledAt != nil && validControlTimestamp(*disabledAt)
}

func validControlTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero()
}

func printApplicationLifecycle(opts *options, item applicationLifecycleCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, item)
	}
	disabledAt := "-"
	if item.DisabledAt != nil {
		disabledAt = formatControlTime(*item.DisabledAt)
	}
	return printControlTable(opts, []string{"APPLICATION", "NAME", "STATUS", "DISABLED"}, [][]string{{item.ID, item.DisplayName, item.Status, disabledAt}})
}

func printEnvironmentLifecycle(opts *options, item environmentLifecycleCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, item)
	}
	disabledAt := "-"
	if item.DisabledAt != nil {
		disabledAt = formatControlTime(*item.DisabledAt)
	}
	return printControlTable(opts, []string{"ENVIRONMENT", "NAME", "KIND", "STATUS", "DISABLED"}, [][]string{{item.ID, item.DisplayName, item.Kind, item.Status, disabledAt}})
}
