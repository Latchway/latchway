package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/identity"
)

const maximumIdentityKeyMaintenanceSources = 4096

// IdentityKeyMaintenanceConfig supplies only public configuration and the
// public-key cache. It never resolves identity tokens or secret-backed keys.
type IdentityKeyMaintenanceConfig struct {
	Pool          *pgxpool.Pool
	Configuration *configuration.Store
	SharedCache   identity.RemoteKeyDocumentCache
	HTTPClient    *http.Client
	Now           func() time.Time
}

// IdentityKeyMaintenance refreshes fixed HTTPS verification-key endpoints
// selected by active compiled configuration. PostgreSQL cache leases make the
// operation safe when several worker replicas claim adjacent retry windows.
type IdentityKeyMaintenance struct {
	pool          *pgxpool.Pool
	configuration *configuration.Store
	sharedCache   identity.RemoteKeyDocumentCache
	httpClient    *http.Client
	now           func() time.Time
}

func NewIdentityKeyMaintenance(config IdentityKeyMaintenanceConfig) (*IdentityKeyMaintenance, error) {
	if config.Pool == nil || config.Configuration == nil || config.SharedCache == nil {
		return nil, errors.New("identity key maintenance dependency is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &IdentityKeyMaintenance{
		pool: config.Pool, configuration: config.Configuration,
		sharedCache: config.SharedCache, httpClient: config.HTTPClient, now: config.Now,
	}, nil
}

// MaintainIdentityKeys checks every remote key source referenced by an active
// snapshot. Fresh shared documents avoid network I/O; expired documents use
// conditional HTTPS and a short database lease.
func (maintenance *IdentityKeyMaintenance) MaintainIdentityKeys(ctx context.Context) (int64, error) {
	if maintenance == nil || ctx == nil {
		return 0, errors.New("identity key maintenance is unavailable")
	}
	rows, err := maintenance.pool.Query(ctx, `
		SELECT organization_id, application_id, environment_id
		FROM active_config_revisions
		ORDER BY organization_id, application_id, environment_id
		LIMIT $1
	`, maximumIdentityKeyMaintenanceSources+1)
	if err != nil {
		return 0, errors.New("list active identity-key scopes")
	}
	type activeScope struct{ organizationID, applicationID, environmentID string }
	scopes := make([]activeScope, 0)
	for rows.Next() {
		var scope activeScope
		if err := rows.Scan(&scope.organizationID, &scope.applicationID, &scope.environmentID); err != nil {
			rows.Close()
			return 0, errors.New("scan active identity-key scope")
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, errors.New("iterate active identity-key scopes")
	}
	rows.Close()
	if len(scopes) > maximumIdentityKeyMaintenanceSources {
		return 0, errors.New("active identity-key scope limit exceeded")
	}

	providers := make([]configuration.IdentityProvider, 0)
	for _, scope := range scopes {
		snapshot, err := maintenance.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
			OrganizationID: scope.organizationID, ApplicationID: scope.applicationID, EnvironmentID: scope.environmentID,
		})
		if err != nil {
			return 0, errors.New("load active identity-key configuration")
		}
		for _, provider := range snapshot.IdentityProviders() {
			if provider.StaticPublicKeySecretRef != "" || provider.SymmetricSecretRef != "" {
				continue
			}
			providers = append(providers, provider)
			if len(providers) > maximumIdentityKeyMaintenanceSources {
				return 0, errors.New("active identity-key source limit exceeded")
			}
		}
	}

	coordinator := &clientCoordinator{
		identityHTTP: maintenance.httpClient, identityKeyCache: maintenance.sharedCache, now: maintenance.now,
	}
	var processed int64
	for _, provider := range providers {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		if err := validateIdentityKeySources(provider); err != nil {
			return processed, errors.New("active identity-key source is invalid")
		}
		mapper, err := identity.NewCELClaimMapper(provider.ClaimMappings)
		if err != nil {
			return processed, errors.New("active identity claim mapping is invalid")
		}
		verifier, err := coordinator.buildRemoteIdentityVerifier(provider, mapper)
		if err != nil {
			return processed, errors.New("construct active identity-key verifier")
		}
		refresher, ok := verifier.(interface{ RefreshKeys(context.Context) error })
		if !ok {
			return processed, errors.New("active identity-key verifier is not refreshable")
		}
		if err := refresher.RefreshKeys(ctx); err != nil {
			return processed, errors.New("refresh active identity keys")
		}
		processed++
	}
	return processed, nil
}
