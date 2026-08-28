// Package app composes process dependencies.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminapi"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/server"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/worker"
)

const clientAccessTokenAudience = "latchway-data-plane"

// Run starts only the responsibilities selected by cfg.Role. The worker role
// never constructs HTTP, administrative, client-session, policy, upstream, or
// secret dependencies.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	selection, err := selectRole(cfg.Role)
	if err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}

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

	// Both the data plane and maintenance runtime use this same store in the
	// all role. Its methods remain transactionally safe across split replicas.
	quotaStore, err := quota.NewStore(quota.StoreConfig{Pool: pool})
	if err != nil {
		return fmt.Errorf("construct quota store: %w", err)
	}

	var api apiRuntime
	if selection.api {
		var targetCache *dataplane.TargetCache
		api, targetCache, err = newAPIRuntime(ctx, cfg, logger, pool, quotaStore)
		if err != nil {
			return err
		}
		// The HTTP runtime drains in-flight requests before runRole returns. Only
		// then may pooled upstream transports be retired.
		defer targetCache.Close()
	}

	var jobs workerRuntime
	if selection.worker {
		jobs, err = newWorkerRuntime(pool, quotaStore, logger)
		if err != nil {
			return err
		}
	}

	logger.Info("Latchway process starting", "role", cfg.Role)
	return runRole(ctx, cfg.Role, cfg.ShutdownTimeout, api, jobs)
}

func newAPIRuntime(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	pool *pgxpool.Pool,
	quotaStore *quota.Store,
) (*server.Server, *dataplane.TargetCache, error) {
	adminAPI, err := adminapi.New(pool, cfg.PublicOrigin, cfg.AdminSessionLifetime, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("construct administrative API: %w", err)
	}

	envelope, err := secrets.NewEnvironmentMasterKeyFromEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("load runtime master key: %w", err)
	}
	if err := secrets.CheckMasterKeyConsistency(ctx, pool, envelope); err != nil {
		return nil, nil, fmt.Errorf("verify runtime master key: %w", err)
	}
	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
	if err != nil {
		return nil, nil, fmt.Errorf("construct secret store: %w", err)
	}
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		return nil, nil, fmt.Errorf("construct configuration store: %w", err)
	}
	keyManager, err := session.NewSigningKeyManager(session.SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client signing-key manager: %w", err)
	}
	if _, err := keyManager.Active(ctx); err != nil {
		return nil, nil, fmt.Errorf("initialize client signing key: %w", err)
	}
	var subjectProtector *identity.SubjectProtector
	if err := envelope.UseIdentitySubjectHMACKey(func(key []byte) error {
		var constructErr error
		subjectProtector, constructErr = identity.NewSubjectProtector(key)
		return constructErr
	}); err != nil {
		return nil, nil, fmt.Errorf("construct identity subject protector: %w", err)
	}
	userStore, err := identity.NewUserStore(pool, subjectProtector)
	if err != nil {
		return nil, nil, fmt.Errorf("construct identity user store: %w", err)
	}
	if err := adminAPI.InitializeBootstrap(ctx, cfg.AdminBootstrapToken); err != nil {
		return nil, nil, err
	}
	accessIssuer, err := session.NewAccessTokenIssuer(session.AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: cfg.PublicOrigin, Audience: clientAccessTokenAudience,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client access-token issuer: %w", err)
	}
	accessVerifier, err := session.NewAccessTokenVerifier(session.AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: cfg.PublicOrigin, Audience: clientAccessTokenAudience,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client access-token verifier: %w", err)
	}
	sessionStore, err := session.NewStore(session.StoreConfig{
		Pool: pool, AccessTokens: accessIssuer, Configuration: configurationStore,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client session store: %w", err)
	}
	coordinator, err := session.NewClientCoordinator(session.ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore,
		Sessions: sessionStore, AccessTokens: accessVerifier, Secrets: secretStore,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client session coordinator: %w", err)
	}
	jwks, err := session.NewClientJWKSProvider(keyManager)
	if err != nil {
		return nil, nil, fmt.Errorf("construct client JWKS provider: %w", err)
	}
	policyResolver, err := policy.NewResolver()
	if err != nil {
		return nil, nil, fmt.Errorf("construct data-plane policy resolver: %w", err)
	}
	policyEngine, err := dataplane.NewPolicyEngine(policyResolver)
	if err != nil {
		return nil, nil, fmt.Errorf("construct data-plane policy engine: %w", err)
	}
	featureQuotas, err := dataplane.NewFeatureQuotaProvider(dataplane.FeatureQuotaConfig{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: configurationStore, Policies: policyResolver,
		Quotas: quotaStore, PublicOrigin: cfg.PublicOrigin,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct feature quota provider: %w", err)
	}
	clientAPI, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, FeatureQuotas: featureQuotas,
		JWKS: jwks, PublicOrigin: cfg.PublicOrigin,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client API: %w", err)
	}
	targetCache := dataplane.NewTargetCache()
	dataPlane, err := dataplane.New(dataplane.Config{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: configurationStore, Policies: policyEngine,
		Quotas: quotaStore, Secrets: secretStore, Targets: targetCache,
		PublicOrigin: cfg.PublicOrigin,
	})
	if err != nil {
		_ = targetCache.Close()
		return nil, nil, fmt.Errorf("construct data-plane handler: %w", err)
	}

	httpServer, err := server.New(cfg, pool, logger, server.Handlers{
		AdminAPI: adminAPI.Handler(), ClientAPI: clientAPI.Handler(), DataPlane: dataPlane.Handler(),
	})
	if err != nil {
		_ = targetCache.Close()
		return nil, nil, err
	}
	return httpServer, targetCache, nil
}

func newWorkerRuntime(pool *pgxpool.Pool, quotaStore *quota.Store, logger *slog.Logger) (*worker.Runtime, error) {
	replayStore, err := session.NewReplayStore(session.ReplayStoreConfig{Pool: pool})
	if err != nil {
		return nil, fmt.Errorf("construct worker replay cleaner: %w", err)
	}
	runtime, err := worker.New(worker.Config{
		Quotas: quotaStore, Replays: replayStore, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("construct worker runtime: %w", err)
	}
	return runtime, nil
}

type roleSelection struct {
	api    bool
	worker bool
}

func selectRole(role config.Role) (roleSelection, error) {
	switch role {
	case config.RoleAPI:
		return roleSelection{api: true}, nil
	case config.RoleWorker:
		return roleSelection{worker: true}, nil
	case config.RoleAll:
		return roleSelection{api: true, worker: true}, nil
	default:
		return roleSelection{}, fmt.Errorf("unsupported process role %q", role)
	}
}

type apiRuntime interface {
	Run(context.Context, time.Duration) error
}

type workerRuntime interface {
	Run(context.Context) error
}

// runRole is the process-lifecycle boundary. Ordinary maintenance job errors
// are retried inside worker.Runtime. If either co-located component exits or
// fails unexpectedly, the shared context is canceled and the peer is fully
// drained before the error is returned.
func runRole(
	ctx context.Context,
	role config.Role,
	shutdownTimeout time.Duration,
	api apiRuntime,
	jobs workerRuntime,
) error {
	if ctx == nil {
		return errors.New("process context is nil")
	}
	switch role {
	case config.RoleAPI:
		if api == nil || jobs != nil {
			return errors.New("API role dependencies are invalid")
		}
		result := componentResult{name: "HTTP runtime", err: api.Run(ctx, shutdownTimeout)}
		return componentExitError(result, ctx.Err() != nil, false)
	case config.RoleWorker:
		if api != nil || jobs == nil {
			return errors.New("worker role dependencies are invalid")
		}
		result := componentResult{name: "worker runtime", err: jobs.Run(ctx)}
		return componentExitError(result, ctx.Err() != nil, false)
	case config.RoleAll:
		if api == nil || jobs == nil {
			return errors.New("all role dependencies are invalid")
		}
		return runAll(ctx, shutdownTimeout, api, jobs)
	default:
		return fmt.Errorf("unsupported process role %q", role)
	}
}

type componentResult struct {
	name string
	err  error
}

func runAll(ctx context.Context, shutdownTimeout time.Duration, api apiRuntime, jobs workerRuntime) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan componentResult, 2)
	go func() {
		results <- componentResult{name: "HTTP runtime", err: api.Run(runCtx, shutdownTimeout)}
	}()
	go func() {
		results <- componentResult{name: "worker runtime", err: jobs.Run(runCtx)}
	}()

	first := <-results
	cancel()
	second := <-results

	cancellationExpected := ctx.Err() != nil
	return errors.Join(
		componentExitError(first, cancellationExpected, false),
		componentExitError(second, true, cancellationExpected),
	)
}

func componentExitError(result componentResult, cancellationExpected, peerStoppedFirst bool) error {
	if result.err != nil {
		return fmt.Errorf("%s: %w", result.name, result.err)
	}
	if cancellationExpected || peerStoppedFirst {
		return nil
	}
	return fmt.Errorf("%s stopped unexpectedly", result.name)
}
