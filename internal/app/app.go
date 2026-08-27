// Package app composes process dependencies.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/latchway/latchway/internal/adminapi"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/server"
)

// Run starts the configured Latchway process.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	pool, err := database.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConnections)
	if err != nil {
		return err
	}
	defer pool.Close()

	migrator := database.NewMigrator(pool)
	if cfg.MigrateOnStart {
		if err := migrator.Up(ctx); err != nil {
			return fmt.Errorf("automatic migration: %w", err)
		}
	}

	adminAPI, err := adminapi.New(pool, cfg.PublicOrigin, cfg.AdminSessionLifetime, logger)
	if err != nil {
		return fmt.Errorf("construct administrative API: %w", err)
	}
	if err := adminAPI.InitializeBootstrap(ctx, cfg.AdminBootstrapToken); err != nil {
		return err
	}

	httpServer, err := server.New(cfg, pool, logger, adminAPI.Handler())
	if err != nil {
		return err
	}
	logger.Info("Latchway process starting", "role", cfg.Role)
	return httpServer.Run(ctx, cfg.ShutdownTimeout)
}
