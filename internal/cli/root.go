// Package cli implements the latchway command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/app"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/telemetry"
	"github.com/spf13/cobra"
)

type options struct {
	output          string
	server          string
	stdin           io.Reader
	stdout          io.Writer
	stderr          io.Writer
	adminHTTPClient *http.Client
}

// Execute runs the CLI with explicit process dependencies.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	opts := &options{output: "table", stdout: stdout, stderr: stderr}
	return executeWithOptions(ctx, args, opts)
}

func executeWithOptions(ctx context.Context, args []string, opts *options) error {
	root := newRootCommand(opts)
	root.SetArgs(args)
	if opts.stdin != nil {
		root.SetIn(opts.stdin)
	}
	root.SetOut(opts.stdout)
	root.SetErr(opts.stderr)
	root.SilenceUsage = true
	root.SilenceErrors = true
	return root.ExecuteContext(ctx)
}

func newRootCommand(opts *options) *cobra.Command {
	defaultServer := os.Getenv("LATCHWAY_SERVER")
	if defaultServer == "" {
		defaultServer = "http://127.0.0.1:8080"
	}
	root := &cobra.Command{
		Use:           "latchway",
		Short:         "Self-hosted access gateway for untrusted AI clients",
		Version:       buildinfo.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&opts.output, "output", "table", "output format: table or json")
	root.PersistentFlags().StringVar(&opts.server, "server", defaultServer, "canonical Latchway server origin")
	root.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		if opts.output != "table" && opts.output != "json" {
			return fmt.Errorf("unsupported output format %q", opts.output)
		}
		return nil
	}
	root.AddCommand(
		newServeCommand(opts), newMigrateCommand(opts), newDoctorCommand(opts), newVersionCommand(opts),
		newTokenModeLoginCommand(opts), newTokenModeLogoutCommand(opts),
		newAdminCommand(opts), newSecretCommand(opts), newStatusCommand(opts), newConfigCommand(opts),
		newUsersCommand(opts), newInstallationsCommand(opts), newRequestsCommand(opts),
		newRoutesCommand(opts), newUsageCommand(opts), newAuditCommand(opts), newVerifyCommand(opts),
	)
	root.InitDefaultCompletionCmd()
	return root
}

func newServeCommand(opts *options) *cobra.Command {
	var role string
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the API, worker, or combined process",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("role") {
				cfg.Role = config.Role(role)
				if err := cfg.Validate(); err != nil {
					return err
				}
			}
			logger := telemetry.NewLogger(opts.stderr, cfg.LogLevel)
			return app.Run(cmd.Context(), cfg, logger)
		},
	}
	command.Flags().StringVar(&role, "role", string(config.RoleAll), "process role: all, api, or worker")
	return command
}

func newMigrateCommand(opts *options) *cobra.Command {
	command := &cobra.Command{Use: "migrate", Short: "Manage embedded database migrations"}
	command.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Apply every pending forward migration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pool, migrator, err := migrationDependencies(cmd.Context())
			if err != nil {
				return err
			}
			defer pool.Close()
			if err := migrator.Up(cmd.Context()); err != nil {
				return err
			}
			return opts.print(map[string]any{"status": "ok", "message": "database schema is current"})
		},
	})
	command.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show current and available schema versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pool, migrator, err := migrationDependencies(cmd.Context())
			if err != nil {
				return err
			}
			defer pool.Close()
			current, available, err := migrator.Status(cmd.Context())
			if err != nil {
				return err
			}
			return opts.print(map[string]any{"current": current, "available": available, "up_to_date": current == available})
		},
	})
	return command
}

func newDoctorCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Validate bootstrap configuration, database access, and schema state",
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
			current, available, err := database.NewMigrator(pool).Status(cmd.Context())
			if err != nil {
				return err
			}
			if current != available {
				return fmt.Errorf("database schema is behind: current %d, available %d", current, available)
			}
			return opts.print(map[string]any{"status": "ok", "database": "reachable", "schema_version": current, "role": cfg.Role})
		},
	}
}

func newVersionCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build and protocol versions",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return opts.print(buildinfo.Current())
		},
	}
}

func migrationDependencies(ctx context.Context) (*pgxpool.Pool, *database.Migrator, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	pool, err := database.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConnections)
	if err != nil {
		return nil, nil, err
	}
	return pool, database.NewMigrator(pool), nil
}

func (o *options) print(value any) error {
	if o.output == "json" {
		encoder := json.NewEncoder(o.stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	switch typed := value.(type) {
	case buildinfo.Info:
		_, err := fmt.Fprintf(o.stdout, "Latchway %s\ncommit: %s\nbuilt: %s\ncontract: %s\nprotocol: %s\n", typed.Version, typed.Commit, typed.BuildDate, typed.ContractVersion, typed.ProtocolVersion)
		return err
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item := typed[key]
			if _, err := fmt.Fprintf(o.stdout, "%s: %v\n", key, item); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unsupported human-readable output value")
	}
}
