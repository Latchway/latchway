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
	"github.com/latchway/latchway/internal/telemetry"
	"github.com/spf13/cobra"
)

var environmentVariableName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func newDevelopCommand(opts *options) *cobra.Command {
	var databaseURLEnvironment, listenAddress, browserOrigin string
	command := &cobra.Command{
		Use:     "develop",
		Aliases: []string{"dev"},
		Short:   "Run an isolated local gateway, mock services, helpers, and Console for client quickstarts",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			databaseURL, err := localDatabaseURL(cmd, databaseURLEnvironment)
			if err != nil {
				return err
			}
			logger := telemetry.NewLogger(opts.stderr, "info")
			return localverify.RunDevelopment(cmd.Context(), localverify.DevelopmentConfig{
				DatabaseURL: databaseURL, ListenAddress: listenAddress,
				BrowserOrigin: browserOrigin, Logger: logger,
				OnReady: func(info localverify.DevelopmentInfo) error {
					return opts.print(map[string]any{
						"state": "ready", "gateway_url": info.GatewayURL,
						"application_id": info.ApplicationID, "environment": info.Environment,
						"feature": info.Feature, "model": info.Model, "browser_origin": info.BrowserOrigin,
						"identity_token_url":       info.IdentityTokenURL,
						"attestation_evidence_url": info.AttestationEvidenceURL,
						"console_url":              info.ConsoleURL, "console_email": info.ConsoleEmail,
						"console_password":               info.ConsolePassword,
						"ios_bundle_identifier":          info.IOSBundleIdentifier,
						"android_package_name":           info.AndroidPackageName,
						"react_native_bundle_identifier": info.ReactNativeBundleID,
						"react_native_package_name":      info.ReactNativePackageName,
						"cleanup":                        "automatic_on_exit",
					})
				},
			})
		},
	}
	command.Flags().StringVar(
		&databaseURLEnvironment, "database-url-env", "LATCHWAY_DATABASE_URL",
		"environment variable containing the PostgreSQL URL (DATABASE_URL is the default fallback)",
	)
	command.Flags().StringVar(&listenAddress, "listen", "127.0.0.1:8080", "exact loopback IP and port for the development gateway")
	command.Flags().StringVar(&browserOrigin, "browser-origin", "http://localhost:5173", "exact loopback HTTP browser Origin allowed by the development configuration")
	return command
}

func newVerifyLocalCommand(opts *options) *cobra.Command {
	var databaseURLEnvironment, junitPath string
	var timeout time.Duration
	command := &cobra.Command{
		Use: "local", Short: "Run the isolated PostgreSQL, session, proxy, quota, routing, and recovery vertical",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			databaseURL, err := localDatabaseURL(cmd, databaseURLEnvironment)
			if err != nil {
				return err
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

func localDatabaseURL(command *cobra.Command, environmentName string) (string, error) {
	if command == nil || !environmentVariableName.MatchString(environmentName) {
		return "", errors.New("--database-url-env must name an uppercase environment variable")
	}
	databaseURL := strings.TrimSpace(os.Getenv(environmentName))
	if databaseURL == "" && environmentName == "LATCHWAY_DATABASE_URL" && !command.Flags().Changed("database-url-env") {
		databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	if databaseURL == "" {
		return "", fmt.Errorf("database URL environment variable %s is empty", environmentName)
	}
	return databaseURL, nil
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
