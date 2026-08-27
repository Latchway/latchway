// Package app composes process dependencies.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/latchway/latchway/internal/adminapi"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/server"
	"github.com/latchway/latchway/internal/session"
)

const clientAccessTokenAudience = "latchway-data-plane"

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

	envelope, err := secrets.NewEnvironmentMasterKeyFromEnv()
	if err != nil {
		return fmt.Errorf("load runtime master key: %w", err)
	}
	if err := secrets.CheckMasterKeyConsistency(ctx, pool, envelope); err != nil {
		return fmt.Errorf("verify runtime master key: %w", err)
	}
	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
	if err != nil {
		return fmt.Errorf("construct secret store: %w", err)
	}
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		return fmt.Errorf("construct configuration store: %w", err)
	}
	keyManager, err := session.NewSigningKeyManager(session.SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope,
	})
	if err != nil {
		return fmt.Errorf("construct client signing-key manager: %w", err)
	}
	if _, err := keyManager.Active(ctx); err != nil {
		return fmt.Errorf("initialize client signing key: %w", err)
	}
	var subjectProtector *identity.SubjectProtector
	if err := envelope.UseIdentitySubjectHMACKey(func(key []byte) error {
		var constructErr error
		subjectProtector, constructErr = identity.NewSubjectProtector(key)
		return constructErr
	}); err != nil {
		return fmt.Errorf("construct identity subject protector: %w", err)
	}
	userStore, err := identity.NewUserStore(pool, subjectProtector)
	if err != nil {
		return fmt.Errorf("construct identity user store: %w", err)
	}
	if err := adminAPI.InitializeBootstrap(ctx, cfg.AdminBootstrapToken); err != nil {
		return err
	}
	accessIssuer, err := session.NewAccessTokenIssuer(session.AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: cfg.PublicOrigin, Audience: clientAccessTokenAudience,
	})
	if err != nil {
		return fmt.Errorf("construct client access-token issuer: %w", err)
	}
	sessionStore, err := session.NewStore(session.StoreConfig{
		Pool: pool, AccessTokens: accessIssuer, Configuration: configurationStore,
	})
	if err != nil {
		return fmt.Errorf("construct client session store: %w", err)
	}
	coordinator, err := session.NewClientCoordinator(session.ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore,
		Sessions: sessionStore, Secrets: secretStore,
	})
	if err != nil {
		return fmt.Errorf("construct client session coordinator: %w", err)
	}
	jwks, err := session.NewClientJWKSProvider(keyManager)
	if err != nil {
		return fmt.Errorf("construct client JWKS provider: %w", err)
	}
	clientAPI, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, JWKS: jwks, PublicOrigin: cfg.PublicOrigin,
	})
	if err != nil {
		return fmt.Errorf("construct client API: %w", err)
	}

	httpServer, err := server.New(cfg, pool, logger, server.Handlers{
		AdminAPI: adminAPI.Handler(), ClientAPI: clientAPI.Handler(),
	})
	if err != nil {
		return err
	}
	logger.Info("Latchway process starting", "role", cfg.Role)
	return httpServer.Run(ctx, cfg.ShutdownTimeout)
}
