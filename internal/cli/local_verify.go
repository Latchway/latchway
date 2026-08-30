package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/localverify"
	"github.com/spf13/cobra"
)

var environmentVariableName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func newVerifyLocalCommand(opts *options) *cobra.Command {
	var databaseURLEnvironment, junitPath string
	var timeout time.Duration
	command := &cobra.Command{
		Use: "local", Short: "Run the isolated PostgreSQL, session, proxy, quota, routing, and recovery vertical",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !environmentVariableName.MatchString(databaseURLEnvironment) {
				return errors.New("--database-url-env must name an uppercase environment variable")
			}
			databaseURL := strings.TrimSpace(os.Getenv(databaseURLEnvironment))
			if databaseURL == "" && databaseURLEnvironment == "LATCHWAY_DATABASE_URL" && !cmd.Flags().Changed("database-url-env") {
				databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
			}
			if databaseURL == "" {
				return fmt.Errorf("database URL environment variable %s is empty", databaseURLEnvironment)
			}
			report := localverify.Run(cmd.Context(), localverify.Config{
				DatabaseURL: databaseURL, Timeout: timeout,
			})
			if err := printLocalVerification(opts, report); err != nil {
				return err
			}
			if junitPath != "" {
				if err := writeLocalVerificationJUnit(junitPath, report); err != nil {
					return err
				}
			}
			return report.Error()
		},
	}
	command.Flags().StringVar(
		&databaseURLEnvironment, "database-url-env", "LATCHWAY_DATABASE_URL",
		"environment variable containing the PostgreSQL URL (DATABASE_URL is the default fallback)",
	)
	command.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "total verification timeout (10s-5m)")
	command.Flags().StringVar(&junitPath, "junit", "", "optional JUnit XML evidence output path")
	return command
}

func printLocalVerification(opts *options, report localverify.Report) error {
	if opts.output == "json" {
		encoder := json.NewEncoder(opts.stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	rows := make([][]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		rows = append(rows, []string{check.Name, check.State, check.Detail})
	}
	if _, err := fmt.Fprintf(opts.stdout, "kind: %s\nstate: %s\n", report.Kind, report.State); err != nil {
		return err
	}
	return printControlTable(opts, []string{"CHECK", "STATE", "DETAIL"}, rows)
}

func writeLocalVerificationJUnit(path string, report localverify.Report) error {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, '\x00') {
		return errors.New("JUnit output path is invalid")
	}
	payload, err := report.MarshalJUnit()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return errors.New("JUnit output path must name a file")
	}
	temporary, err := os.CreateTemp(directory, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create JUnit output: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect JUnit output: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write JUnit output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync JUnit output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close JUnit output: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace JUnit output: %w", err)
	}
	committed = true
	return nil
}
