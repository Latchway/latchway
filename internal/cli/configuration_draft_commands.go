package cli

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

type revisionEditCLI struct {
	Version     int64           `json:"version"`
	Kind        string          `json:"kind"`
	EditedAt    string          `json:"edited_at"`
	EditedBy    string          `json:"edited_by"`
	ChangeCount int             `json:"change_count"`
	Changes     []planChangeCLI `json:"changes"`
}

type revisionEditsCLI struct {
	RevisionID string            `json:"revision_id"`
	Items      []revisionEditCLI `json:"items"`
	Truncated  bool              `json:"truncated"`
}

type promotionReportCLI struct {
	SourceEnvironmentID string   `json:"source_environment_id"`
	SourceRevisionID    string   `json:"source_revision_id"`
	Copied              []string `json:"copied"`
	Kept                []string `json:"kept"`
	Review              []string `json:"review"`
}

type configurationPromotionCLI struct {
	Revision  configurationRevisionCLI `json:"revision"`
	Promotion promotionReportCLI       `json:"promotion"`
}

func validActivationNoteCLI(note string) bool {
	if note == "" || !utf8.ValidString(note) || utf8.RuneCountInString(note) > 500 {
		return false
	}
	for _, character := range note {
		if character != '\n' && unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func newConfigHistoryCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "history REVISION_ID", Short: "Show who changed a revision, when, and which paths", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ConfigRevision) != nil {
				return errors.New("revision ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var edits revisionEditsCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/config-revisions/"+args[0]+"/edits", nil, nil, http.StatusOK, &edits); err != nil {
				return err
			}
			if edits.RevisionID != args[0] || len(edits.Items) > 200 {
				return errors.New("admin API returned a non-conforming edit history")
			}
			for _, edit := range edits.Items {
				if edit.Version < 1 || edit.ChangeCount < len(edit.Changes) || len(edit.Changes) > 100 ||
					(edit.Kind != "created" && edit.Kind != "edited" && edit.Kind != "rebased" && edit.Kind != "promoted") {
					return errors.New("admin API returned a non-conforming edit history")
				}
			}
			if opts.output == "json" {
				return printControlJSON(opts, edits)
			}
			rows := make([][]string, 0, len(edits.Items))
			for _, edit := range edits.Items {
				paths := make([]string, 0, len(edit.Changes))
				for _, change := range edit.Changes {
					paths = append(paths, change.Operation+" "+change.Path)
				}
				if edit.ChangeCount > len(edit.Changes) {
					paths = append(paths, fmt.Sprintf("and %d more", edit.ChangeCount-len(edit.Changes)))
				}
				rows = append(rows, []string{
					strconv.FormatInt(edit.Version, 10), edit.Kind, formatControlTime(edit.EditedAt), edit.EditedBy, strings.Join(paths, ", "),
				})
			}
			if err := printControlTable(opts, []string{"EDIT", "KIND", "WHEN", "BY", "CHANGES"}, rows); err != nil {
				return err
			}
			if edits.Truncated {
				_, err := fmt.Fprintln(opts.stdout, "older edits are not shown")
				return err
			}
			return nil
		},
	}
}

func newConfigDiscardCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "discard REVISION_ID", Short: "Discard a never-activated draft; it stays in history", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ConfigRevision) != nil {
				return errors.New("revision ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var current configurationRevisionCLI
			response, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/config-revisions/"+args[0], nil, nil, http.StatusOK, &current)
			if err != nil {
				return err
			}
			etag := response.Header.Get("ETag")
			if !validStrongETag(etag) || current.ID != args[0] {
				return errors.New("admin API omitted the strong ETag required for a safe discard")
			}
			var discarded configurationRevisionCLI
			if _, err := client.doWithHeaders(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+args[0]+"/discard",
				nil, nil, http.Header{"If-Match": []string{etag}}, http.StatusOK, &discarded); err != nil {
				return err
			}
			if discarded.ID != args[0] || discarded.State != "discarded" {
				return errors.New("admin API returned a non-conforming discarded revision")
			}
			return printConfigurationRevision(opts, discarded)
		},
	}
}

func newConfigPromoteCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, sourceEnvironmentID, description string
	command := &cobra.Command{
		Use: "promote", Short: "Start a draft from another environment's live configuration", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil || id.Validate(sourceEnvironmentID, id.Environment) != nil ||
				environmentID == sourceEnvironmentID {
				return errors.New("target and source environment IDs must be valid and different")
			}
			description = strings.TrimSpace(description)
			if len(description) > 512 || strings.ContainsRune(description, '\x00') {
				return errors.New("--description is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			request := map[string]string{"source_environment_id": sourceEnvironmentID}
			if description != "" {
				request["description"] = description
			}
			var promotion configurationPromotionCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/environments/"+environmentID+"/config-revisions/promote",
				nil, request, http.StatusCreated, &promotion); err != nil {
				return err
			}
			if promotion.Revision.EnvironmentID != environmentID || promotion.Promotion.SourceEnvironmentID != sourceEnvironmentID ||
				id.Validate(promotion.Revision.ID, id.ConfigRevision) != nil || id.Validate(promotion.Promotion.SourceRevisionID, id.ConfigRevision) != nil {
				return errors.New("admin API returned a non-conforming promotion")
			}
			if opts.output == "json" {
				return printControlJSON(opts, promotion)
			}
			if err := printConfigurationRevision(opts, promotion.Revision); err != nil {
				return err
			}
			for _, line := range []struct {
				label string
				paths []string
			}{{"copied", promotion.Promotion.Copied}, {"kept", promotion.Promotion.Kept}, {"review", promotion.Promotion.Review}} {
				if len(line.paths) == 0 {
					continue
				}
				if _, err := fmt.Fprintf(opts.stdout, "%s: %s\n", line.label, strings.Join(line.paths, ", ")); err != nil {
					return err
				}
			}
			if len(promotion.Promotion.Review) != 0 {
				_, err := fmt.Fprintln(opts.stdout, "Review copied entries: they may point at the source environment's projects, identifiers, URLs or secrets.")
				return err
			}
			return nil
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "environment that receives the draft")
	command.Flags().StringVar(&sourceEnvironmentID, "from", "", "environment whose live configuration is copied")
	command.Flags().StringVar(&description, "description", "", "redaction-safe revision description")
	_ = command.MarkFlagRequired("environment")
	_ = command.MarkFlagRequired("from")
	return command
}
