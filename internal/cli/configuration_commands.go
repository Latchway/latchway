package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/spf13/cobra"
)

const maxConfigurationCLIBytes = 1 << 20

type configurationRevisionCLI struct {
	ID            string          `json:"id"`
	EnvironmentID string          `json:"environment_id"`
	State         string          `json:"state"`
	Version       int64           `json:"version"`
	Document      json.RawMessage `json:"document"`
	Validation    *validationCLI  `json:"validation,omitempty"`
	CreatedAt     string          `json:"created_at"`
	CreatedBy     string          `json:"created_by"`
	ActivatedAt   string          `json:"activated_at,omitempty"`
}

type validationIssueCLI struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type validationCLI struct {
	Valid     bool                 `json:"valid"`
	CheckedAt string               `json:"checked_at"`
	Issues    []validationIssueCLI `json:"issues"`
}

type planChangeCLI struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
	Summary   string `json:"summary,omitempty"`
}

type configurationPlanCLI struct {
	FromRevisionID string               `json:"from_revision_id"`
	ToRevisionID   string               `json:"to_revision_id"`
	Changes        []planChangeCLI      `json:"changes"`
	Warnings       []validationIssueCLI `json:"warnings"`
}

type configurationApplyResultCLI struct {
	Revision   configurationRevisionCLI `json:"revision"`
	Validation validationCLI            `json:"validation"`
	Plan       *configurationPlanCLI    `json:"plan,omitempty"`
	Activated  bool                     `json:"activated"`
	DryRun     bool                     `json:"dry_run"`
	Warnings   []string                 `json:"warnings,omitempty"`
}

type configurationInputOptions struct {
	file      string
	fromStdin bool
}

func newConfigCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "config", Short: "Manage immutable configuration revisions through the Admin API"}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newConfigPullCommand(opts, values),
		newConfigValidateCommand(opts, values),
		newConfigPlanCommand(opts, values, "plan"),
		newConfigPlanCommand(opts, values, "diff"),
		newConfigApplyCommand(opts, values),
		newConfigRollbackCommand(opts, values),
	)
	return command
}

func newConfigPullCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID string
	command := &cobra.Command{
		Use: "pull", Short: "Pull the active redaction-safe configuration", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil {
				return errors.New("environment ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var revision configurationRevisionCLI
			response, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/environments/"+environmentID+"/config", nil, nil, http.StatusOK, &revision)
			if err != nil {
				return err
			}
			if opts.output == "json" {
				var document any
				if err := json.Unmarshal(revision.Document, &document); err != nil {
					return errors.New("admin API returned a malformed configuration document")
				}
				return printControlJSON(opts, document)
			}
			return printControlTable(opts, []string{"REVISION", "STATE", "VERSION", "ETAG", "ACTIVATED"}, [][]string{{
				revision.ID, revision.State, fmt.Sprint(revision.Version), response.Header.Get("ETag"), formatControlTime(revision.ActivatedAt),
			}})
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newConfigValidateCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "validate REVISION_ID", Short: "Run authoritative schema, reference, CEL, secret, and pricing validation", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ConfigRevision) != nil {
				return errors.New("revision ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var report validationCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+args[0]+"/validate", nil, nil, http.StatusOK, &report); err != nil {
				return err
			}
			if err := printValidation(opts, report); err != nil {
				return err
			}
			if !report.Valid {
				return errors.New("configuration validation failed")
			}
			return nil
		},
	}
}

func newConfigPlanCommand(opts *options, root *controlCommandOptions, name string) *cobra.Command {
	return &cobra.Command{
		Use: name + " REVISION_ID", Short: "Show a value-redacted structural diff against the active revision", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ConfigRevision) != nil {
				return errors.New("revision ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var plan configurationPlanCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+args[0]+"/plan", nil, nil, http.StatusOK, &plan); err != nil {
				return err
			}
			return printConfigurationPlan(opts, plan)
		},
	}
}

func newConfigApplyCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, baseRevisionID, description string
	var dryRun bool
	input := &configurationInputOptions{}
	command := &cobra.Command{
		Use: "apply", Short: "Create, validate, plan, and atomically activate a configuration", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil || (baseRevisionID != "" && id.Validate(baseRevisionID, id.ConfigRevision) != nil) {
				return errors.New("environment or base revision ID is invalid")
			}
			document, err := readConfigurationInput(cmd, input)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			request := map[string]any{}
			if baseRevisionID == "" {
				request["document"] = document
			} else {
				request["base_revision_id"] = baseRevisionID
			}
			if description = strings.TrimSpace(description); description != "" {
				request["description"] = description
			}
			var draft configurationRevisionCLI
			created, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/environments/"+environmentID+"/config-revisions", nil, request, http.StatusCreated, &draft)
			if err != nil {
				return err
			}
			etag := created.Header.Get("ETag")
			if !validStrongETag(etag) {
				return errors.New("admin API omitted the strong ETag required for safe activation")
			}
			if baseRevisionID != "" {
				headers := http.Header{"If-Match": []string{etag}}
				var replaced configurationRevisionCLI
				replacement, replaceErr := client.doWithHeaders(
					cmd.Context(), http.MethodPatch, "/admin/v1/config-revisions/"+draft.ID,
					nil, document, headers, http.StatusOK, &replaced,
				)
				if replaceErr != nil {
					return replaceErr
				}
				draft = replaced
				etag = replacement.Header.Get("ETag")
				if !validStrongETag(etag) {
					return errors.New("admin API omitted the strong ETag required for safe activation")
				}
			}
			var report validationCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+draft.ID+"/validate", nil, nil, http.StatusOK, &report); err != nil {
				return err
			}
			result := configurationApplyResultCLI{Revision: draft, Validation: report, DryRun: dryRun}
			if !report.Valid {
				if err := printConfigurationApply(opts, result); err != nil {
					return err
				}
				return errors.New("configuration validation failed; the invalid immutable draft was not activated")
			}
			var plan configurationPlanCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+draft.ID+"/plan", nil, nil, http.StatusOK, &plan); err != nil {
				var problem controlProblemError
				if !errors.As(err, &problem) || problem.Code != "resource_not_found" {
					return err
				}
				result.Warnings = append(result.Warnings, "No active revision exists; this is the first activation and has no diff base.")
			} else {
				result.Plan = &plan
			}
			if dryRun {
				result.Revision.State = "valid"
				return printConfigurationApply(opts, result)
			}
			headers := http.Header{"If-Match": []string{etag}}
			var activated configurationRevisionCLI
			if _, err := client.doWithHeaders(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+draft.ID+"/activate", nil, nil, headers, http.StatusOK, &activated); err != nil {
				return err
			}
			result.Revision = activated
			result.Activated = true
			return printConfigurationApply(opts, result)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&baseRevisionID, "base-revision", "", "active revision this draft must replace")
	command.Flags().StringVar(&description, "description", "", "redaction-safe revision description")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "create and validate a draft without activation")
	addConfigurationInputFlags(command, input)
	_ = command.MarkFlagRequired("environment")
	return command
}

func newConfigRollbackCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID string
	command := &cobra.Command{
		Use: "rollback REVISION_ID", Short: "Atomically reactivate a prior valid revision", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(environmentID, id.Environment) != nil || id.Validate(args[0], id.ConfigRevision) != nil {
				return errors.New("environment or revision ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var active configurationRevisionCLI
			current, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/environments/"+environmentID+"/config", nil, nil, http.StatusOK, &active)
			if err != nil {
				return err
			}
			etag := current.Header.Get("ETag")
			if !validStrongETag(etag) {
				return errors.New("admin API omitted the strong ETag required for safe rollback")
			}
			var rolledBack configurationRevisionCLI
			headers := http.Header{"If-Match": []string{etag}}
			if _, err := client.doWithHeaders(cmd.Context(), http.MethodPost, "/admin/v1/environments/"+environmentID+"/rollback", nil, map[string]string{"revision_id": args[0]}, headers, http.StatusOK, &rolledBack); err != nil {
				return err
			}
			return printConfigurationRevision(opts, rolledBack)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	_ = command.MarkFlagRequired("environment")
	return command
}

func addConfigurationInputFlags(command *cobra.Command, input *configurationInputOptions) {
	command.Flags().StringVar(&input.file, "file", "", "configuration JSON file (regular file, maximum 1 MiB)")
	command.Flags().BoolVar(&input.fromStdin, "from-stdin", false, "read configuration JSON from standard input")
}

func readConfigurationInput(command *cobra.Command, input *configurationInputOptions) (any, error) {
	if (input.file == "") == !input.fromStdin {
		return nil, errors.New("exactly one of --file or --from-stdin is required")
	}
	var reader io.Reader
	var closeFile *os.File
	if input.file != "" {
		info, err := os.Lstat(input.file)
		if err != nil {
			return nil, fmt.Errorf("inspect configuration file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() > maxConfigurationCLIBytes {
			return nil, errors.New("configuration input must be a regular file no larger than 1 MiB")
		}
		closeFile, err = os.Open(input.file)
		if err != nil {
			return nil, fmt.Errorf("open configuration file: %w", err)
		}
		reader = closeFile
	} else {
		reader = command.InOrStdin()
	}
	value, err := jsonsafe.DecodeReader(reader, maxConfigurationCLIBytes)
	if closeFile != nil {
		if closeErr := closeFile.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close configuration file: %w", closeErr)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read configuration JSON: %w", err)
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("configuration JSON must be an object")
	}
	return value, nil
}

func validStrongETag(value string) bool {
	return len(value) >= 3 && len(value) <= 256 && value[0] == '"' && value[len(value)-1] == '"' &&
		!strings.HasPrefix(value, "W/") && !strings.ContainsAny(value, "\r\n,")
}

func printValidation(opts *options, report validationCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, report)
	}
	if _, err := fmt.Fprintf(opts.stdout, "valid: %s\nchecked: %s\n", boolLabel(report.Valid), formatControlTime(report.CheckedAt)); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Issues))
	for _, issue := range report.Issues {
		rows = append(rows, []string{issue.Severity, issue.Code, issue.Path, issue.Message})
	}
	return printControlTable(opts, []string{"SEVERITY", "CODE", "PATH", "MESSAGE"}, rows)
}

func printConfigurationPlan(opts *options, plan configurationPlanCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, plan)
	}
	if _, err := fmt.Fprintf(opts.stdout, "from: %s\nto: %s\n", plan.FromRevisionID, plan.ToRevisionID); err != nil {
		return err
	}
	rows := make([][]string, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		rows = append(rows, []string{change.Operation, change.Path, change.Summary})
	}
	return printControlTable(opts, []string{"OPERATION", "PATH", "SUMMARY"}, rows)
}

func printConfigurationApply(opts *options, result configurationApplyResultCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, result)
	}
	if err := printConfigurationRevision(opts, result.Revision); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(opts.stdout, "dry run: %s\nactivated: %s\nvalid: %s\n", boolLabel(result.DryRun), boolLabel(result.Activated), boolLabel(result.Validation.Valid)); err != nil {
		return err
	}
	if result.Plan != nil {
		if err := printConfigurationPlan(opts, *result.Plan); err != nil {
			return err
		}
	}
	if len(result.Warnings) != 0 {
		_, err := fmt.Fprintf(opts.stdout, "warnings: %s\n", strings.Join(result.Warnings, " "))
		return err
	}
	return nil
}

func printConfigurationRevision(opts *options, revision configurationRevisionCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, revision)
	}
	return printControlTable(opts, []string{"REVISION", "ENVIRONMENT", "STATE", "VERSION", "CREATED"}, [][]string{{
		revision.ID, revision.EnvironmentID, revision.State, fmt.Sprint(revision.Version), formatControlTime(revision.CreatedAt),
	}})
}
