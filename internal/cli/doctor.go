package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/diagnostics"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/spf13/cobra"
)

func doctorCommand(opts *options) *cobra.Command {
	var supportBundlePath string
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Run the canonical redaction-safe deployment diagnostics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := database.Open(cmd.Context(), cfg.DatabaseURL, cfg.DBMaxConnections)
			if err != nil {
				return err
			}
			defer pool.Close()
			envelope, envelopeErr := secrets.NewEnvironmentMasterKeyFromEnv()
			masterKeyCheck := func(context.Context) error { return envelopeErr }
			if envelopeErr == nil {
				masterKeyCheck = func(checkCtx context.Context) error {
					return secrets.CheckMasterKeyConsistency(checkCtx, pool, envelope)
				}
			}
			report := diagnostics.Run(cmd.Context(), pool, string(cfg.Role), diagnostics.Dependencies{MasterKey: masterKeyCheck})
			if err := diagnostics.Validate(report); err != nil {
				return err
			}
			if supportBundlePath != "" {
				if err := writeSupportBundle(supportBundlePath, diagnostics.Bundle(report, "local_cli")); err != nil {
					return err
				}
			}
			if err := printDoctorReport(opts, report); err != nil {
				return err
			}
			if report.OverallState == diagnostics.OverallUnhealthy {
				return errors.New("deployment doctor found one or more failed operational checks")
			}
			return nil
		},
	}
	command.Flags().StringVar(&supportBundlePath, "support-bundle", "", "write a new redacted JSON support bundle with mode 0600")
	return command
}

func writeSupportBundle(path string, bundle diagnostics.SupportBundle) error {
	if path == "" || path == "-" {
		return errors.New("support-bundle path must name a new file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create support bundle: %w", err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(bundle)
	closeErr := file.Close()
	if encodeErr != nil {
		return errors.New("encode support bundle")
	}
	if closeErr != nil {
		return errors.New("close support bundle")
	}
	completed = true
	return nil
}

func printDoctorReport(opts *options, report diagnostics.Report) error {
	if opts.output == "json" {
		return printControlJSON(opts, report)
	}
	if _, err := fmt.Fprintf(opts.stdout, "status: %s\noverall: %s\ndatabase: %s\nschema: %d/%d\nrole: %s\n", report.Status, report.OverallState, report.Database, report.Facts.Database.SchemaCurrent, report.Facts.Database.SchemaAvailable, report.Role); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		rows = append(rows, []string{check.ID, string(check.State), check.Summary, check.Remediation})
	}
	if err := printControlTable(opts, []string{"CHECK", "STATE", "SUMMARY", "REMEDIATION"}, rows); err != nil {
		return err
	}
	return printControlTable(opts, []string{"FACT", "VALUE"}, [][]string{
		{"gateway API", string(report.OverallState) + " · " + report.Facts.Runtime.Role},
		{"PostgreSQL", diagnosticCheckState(report, "database_connectivity") + " · " + strconv.FormatInt(report.Facts.Database.LatencyMS, 10) + " ms"},
		{"background workers", diagnosticCheckState(report, "worker_heartbeat") + " · " + strconv.FormatInt(report.Facts.Replicas.FreshWorkers, 10) + " fresh"},
		{"configuration", strconv.FormatInt(report.Facts.Configuration.ActiveConfigurations, 10) + " active · rev " + strconv.FormatInt(report.Facts.Configuration.HighestRevisionNumber, 10)},
		{"configuration cache", diagnosticCheckState(report, "configuration_cache_state")},
		{"session signing keys", diagnosticCheckState(report, "signing_key_rotation")},
		{"JWKS refresh", diagnosticCheckState(report, "external_jwks_reachability")},
		{"Apple verification", diagnosticCheckState(report, "apple_verification_dependencies")},
		{"Google verification", diagnosticCheckState(report, "google_verification_dependencies")},
		{"usage settlement backlog", strconv.FormatInt(report.Facts.Jobs.UsageSettlementBacklog, 10)},
		{"storage retention", diagnosticCheckState(report, "storage_retention")},
		{"current version", report.Facts.Runtime.ServerVersion},
		{"latest compatible version", report.Facts.Runtime.LatestCompatibleVersion + " · embedded"},
		{"pending jobs", strconv.FormatInt(countDiagnosticJobs(report, "pending"), 10)},
		{"expired quota reservations", strconv.FormatInt(report.Facts.ExpiredQuotaReservations, 10)},
	})
}

func diagnosticCheckState(report diagnostics.Report, id string) string {
	for _, check := range report.Checks {
		if check.ID == id {
			return string(check.State)
		}
	}
	return "unavailable"
}

func countDiagnosticJobs(report diagnostics.Report, status string) int64 {
	for _, item := range report.Facts.Jobs.ByStatus {
		if item.Status == status {
			return item.Count
		}
	}
	return 0
}
