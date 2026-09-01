// Package app composes process dependencies.
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminapi"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/diagnostics"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/server"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/telemetry"
	"github.com/latchway/latchway/internal/worker"
)

const clientAccessTokenAudience = "latchway-data-plane"

// Run starts only the responsibilities selected by cfg.Role. Worker-only
// replicas construct the gateway signing-key envelope required for rotation,
// but never construct HTTP, administrative, identity, policy, or upstream
// dependencies.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) (runErr error) {
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

	observability, err := telemetry.NewRegistryFromEnvironment(ctx)
	if err != nil {
		return fmt.Errorf("construct process telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = observability.Shutdown(shutdownCtx)
	}()

	envelope, err := secrets.NewEnvironmentMasterKeyFromEnv()
	if err != nil {
		return fmt.Errorf("load runtime master key: %w", err)
	}
	if err := secrets.CheckMasterKeyConsistency(ctx, pool, envelope); err != nil {
		return fmt.Errorf("verify runtime master key: %w", err)
	}
	identityKeyCache, err := identity.NewPostgreSQLRemoteKeyCache(pool)
	if err != nil {
		return fmt.Errorf("construct shared identity-key cache: %w", err)
	}

	// Both the data plane and maintenance runtime use this same store in the
	// all role. Its methods remain transactionally safe across split replicas.
	quotaStore, err := quota.NewStore(quota.StoreConfig{
		Pool: pool,
		OnDenial: func(observationCtx context.Context, observation quota.DenialObservation) {
			observability.RecordQuotaDenial(observationCtx, telemetry.Labels{
				Application: observation.ApplicationID, Environment: observation.EnvironmentID,
				Feature: observation.Feature, Plan: observation.LimitPlan, Outcome: "denied",
			}, observation.Concurrency)
		},
	})
	if err != nil {
		return fmt.Errorf("construct quota store: %w", err)
	}

	var api apiRuntime
	if selection.api {
		var targetCache *dataplane.TargetCache
		api, targetCache, err = newAPIRuntime(ctx, cfg, logger, pool, quotaStore, envelope, identityKeyCache, observability)
		if err != nil {
			return err
		}
		// The HTTP runtime drains in-flight requests before runRole returns. Only
		// then may pooled upstream transports be retired.
		defer func() {
			runErr = errors.Join(runErr, targetCache.Close())
		}()
	}

	var jobs workerRuntime
	if selection.worker {
		jobs, err = newWorkerRuntime(cfg.Role, pool, quotaStore, envelope, identityKeyCache, observability, logger)
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
	envelope *secrets.EnvironmentMasterKey,
	identityKeyCache identity.RemoteKeyDocumentCache,
	observability *telemetry.Registry,
) (*server.Server, *dataplane.TargetCache, error) {
	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
	if err != nil {
		return nil, nil, fmt.Errorf("construct secret store: %w", err)
	}
	secretManager, err := secrets.NewManager(secrets.ManagerConfig{Pool: pool, Provider: envelope})
	if err != nil {
		return nil, nil, fmt.Errorf("construct secret manager: %w", err)
	}
	configurationStore, err := configuration.NewStore(pool, configuration.WithActivationObserver(
		func(observationCtx context.Context, observation configuration.ActivationObservation) {
			observability.RecordConfigurationActivation(observationCtx, telemetry.Labels{
				Application: observation.ApplicationID, Environment: observation.EnvironmentID,
				Outcome: string(observation.Operation),
			})
		},
	))
	if err != nil {
		return nil, nil, fmt.Errorf("construct configuration store: %w", err)
	}
	targetCache := dataplane.NewTargetCache()
	keepTargetCache := false
	defer func() {
		if !keepTargetCache {
			_ = targetCache.Close()
		}
	}()
	adminAPI, err := adminapi.New(
		pool, cfg.PublicOrigin, cfg.AdminSessionLifetime, logger, secretManager,
		adminapi.WithRole(string(cfg.Role)),
		adminapi.WithConfigurationStore(configurationStore),
		adminapi.WithCredentialSelfTests(secretStore, targetCache),
		adminapi.WithDiagnosticDependencies(diagnostics.Dependencies{
			MasterKey: func(checkCtx context.Context) error {
				return secrets.CheckMasterKeyConsistency(checkCtx, pool, envelope)
			},
			ConfigurationCache: configurationStore.ActiveSnapshotCacheStatus,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("construct administrative API: %w", err)
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
		RotationProtector: envelope,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("construct client session store: %w", err)
	}
	appAttestKeys, err := attestation.NewPostgreSQLAppAttestKeyStore(pool)
	if err != nil {
		return nil, nil, fmt.Errorf("construct App Attest key store: %w", err)
	}
	coordinator, err := session.NewClientCoordinator(session.ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore,
		Sessions: sessionStore, AccessTokens: accessVerifier, Secrets: secretStore,
		IdentityKeyCache: identityKeyCache, AppAttestKeys: appAttestKeys,
		Telemetry: observability,
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
	dataPlane, err := dataplane.New(dataplane.Config{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: configurationStore, Policies: policyEngine,
		Quotas: quotaStore, Secrets: secretStore, Targets: targetCache,
		Telemetry: observability, PublicOrigin: cfg.PublicOrigin,
	})
	if err != nil {
		_ = targetCache.Close()
		return nil, nil, fmt.Errorf("construct data-plane handler: %w", err)
	}

	httpServer, err := server.New(cfg, pool, logger, server.Handlers{
		AdminAPI: adminAPI.Handler(), ClientAPI: clientAPI.Handler(), DataPlane: dataPlane.Handler(),
		Metrics: observability,
		Readiness: server.ReadinessChecks{
			MasterKey: func(checkCtx context.Context) error {
				return secrets.CheckMasterKeyConsistency(checkCtx, pool, envelope)
			},
			SigningKey: func(checkCtx context.Context) error {
				_, checkErr := keyManager.PublicJWKS(checkCtx)
				return checkErr
			},
			WorkerHeartbeat: func(checkCtx context.Context) error {
				return worker.CheckRecentHeartbeat(checkCtx, pool, 90*time.Second)
			},
		},
	})
	if err != nil {
		_ = targetCache.Close()
		return nil, nil, err
	}
	keepTargetCache = true
	return httpServer, targetCache, nil
}

func newWorkerRuntime(
	role config.Role,
	pool *pgxpool.Pool,
	quotaStore *quota.Store,
	envelope *secrets.EnvironmentMasterKey,
	identityKeyCache identity.RemoteKeyDocumentCache,
	observability *telemetry.Registry,
	logger *slog.Logger,
) (workerRuntime, error) {
	replayStore, err := session.NewReplayStore(session.ReplayStoreConfig{Pool: pool})
	if err != nil {
		return nil, fmt.Errorf("construct worker replay cleaner: %w", err)
	}
	appAttestKeys, err := attestation.NewPostgreSQLAppAttestKeyStore(pool)
	if err != nil {
		return nil, fmt.Errorf("construct worker App Attest cleaner: %w", err)
	}
	challengeMaintenance, err := session.NewChallengeMaintenance(pool)
	if err != nil {
		return nil, fmt.Errorf("construct worker challenge cleaner: %w", err)
	}
	keyManager, err := session.NewSigningKeyManager(session.SigningKeyManagerConfig{Pool: pool, Envelope: envelope})
	if err != nil {
		return nil, fmt.Errorf("construct worker signing-key manager: %w", err)
	}
	operations, err := worker.NewPostgreSQLOperations(pool)
	if err != nil {
		return nil, fmt.Errorf("construct worker operational jobs: %w", err)
	}
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		return nil, fmt.Errorf("construct worker configuration store: %w", err)
	}
	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
	if err != nil {
		return nil, fmt.Errorf("construct worker secret store: %w", err)
	}
	targetCache := dataplane.NewTargetCache()
	keepTargetCache := false
	defer func() {
		if !keepTargetCache {
			_ = targetCache.Close()
		}
	}()
	selfTests, err := adminapi.NewScheduledSelfTestExecutor(
		pool, configurationStore, secretStore, targetCache, observability,
	)
	if err != nil {
		return nil, fmt.Errorf("construct scheduled self-test executor: %w", err)
	}
	identityKeys, err := session.NewIdentityKeyMaintenance(session.IdentityKeyMaintenanceConfig{
		Pool: pool, Configuration: configurationStore, SharedCache: identityKeyCache,
	})
	if err != nil {
		return nil, fmt.Errorf("construct worker identity-key maintenance: %w", err)
	}
	instanceID, err := newRuntimeInstanceID()
	if err != nil {
		return nil, err
	}
	queue, err := worker.NewQueue(pool, instanceID, string(role))
	if err != nil {
		return nil, fmt.Errorf("construct worker job queue: %w", err)
	}
	runtime, err := worker.New(worker.Config{
		Quotas: quotaStore, Replays: replayStore, Attestations: appAttestKeys,
		Challenges: challengeMaintenance, SigningKeys: keyManager, IdentityKeys: identityKeys, Operations: operations,
		SelfTests: selfTests,
		Queue:     queue, Telemetry: observability, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("construct worker runtime: %w", err)
	}
	keepTargetCache = true
	return &ownedWorkerRuntime{runtime: runtime, targets: targetCache}, nil
}

type ownedWorkerRuntime struct {
	runtime *worker.Runtime
	targets *dataplane.TargetCache
}

func (runtime *ownedWorkerRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.runtime == nil || runtime.targets == nil {
		return errors.New("owned worker runtime is invalid")
	}
	err := runtime.runtime.Run(ctx)
	closeErr := runtime.targets.Close()
	return errors.Join(err, closeErr)
}

func newRuntimeInstanceID() (string, error) {
	var entropy [18]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", errors.New("generate runtime instance identifier")
	}
	return "runtime-" + base64.RawURLEncoding.EncodeToString(entropy[:]), nil
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
