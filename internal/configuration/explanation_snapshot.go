package configuration

import (
	"context"

	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

// ExplanationSnapshot loads the exact validated compiled revision used by an
// administrative explanation. Unlike SimulationSnapshot, it is read-only,
// permits the inspect-users capability, and accepts superseded revisions so a
// durable request can be explained against its historical configuration.
// The returned typed snapshot must never be serialized wholesale because its
// compiled representation can contain server-side secret references.
func (store *Store) ExplanationSnapshot(
	ctx context.Context,
	principal adminauth.Principal,
	revisionID string,
) (SimulationSnapshot, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		id.Validate(revisionID, id.ConfigRevision) != nil {
		return SimulationSnapshot{}, ErrInvalid
	}
	if !principal.Allows(adminauth.InspectUsers, adminauth.AuthorizationContext{}) {
		return SimulationSnapshot{}, ErrForbidden
	}
	revision, err := store.revision(ctx, store.pool, principal.OrganizationID, revisionID, false)
	if err != nil {
		return SimulationSnapshot{}, err
	}
	if revision.State != StateValid && revision.State != StateActive && revision.State != StateSuperseded {
		return SimulationSnapshot{}, ErrConfigurationInvalid
	}
	if len(revision.compiled) == 0 || revision.Validation == nil || !revision.Validation.Valid {
		return SimulationSnapshot{}, ErrConfigurationInvalid
	}
	environment, _, err := store.environment(
		ctx, store.pool, principal.OrganizationID, revision.EnvironmentID, false,
	)
	if err != nil {
		return SimulationSnapshot{}, err
	}
	if environment.ApplicationID != revision.applicationID || environment.OrganizationID != revision.organizationID {
		return SimulationSnapshot{}, ErrConfigurationInvalid
	}
	snapshot, err := newActiveSnapshot(
		revision.ID, revision.EnvironmentID, revision.Document, revision.compiled,
	)
	if err != nil {
		return SimulationSnapshot{}, ErrConfigurationInvalid
	}
	return SimulationSnapshot{
		Snapshot: snapshot,
		Scope: TenantScope{
			OrganizationID: environment.OrganizationID,
			ApplicationID:  environment.ApplicationID,
			EnvironmentID:  environment.EnvironmentID,
		},
		EnvironmentKind: environment.EnvironmentKind,
	}, nil
}
