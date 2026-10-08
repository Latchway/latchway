package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

// validDisplayName applies the same rule as creation: 1 to 200 characters,
// one line. Slugs never change: configuration metadata, URLs and CLI flags
// name resources by slug.
func validDisplayName(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	return trimmed, trimmed != "" && len(trimmed) <= 200 && !strings.ContainsAny(trimmed, "\r\n\x00")
}

// RenameOrganization changes the organization's display name. Owners only.
func (store *Store) RenameOrganization(ctx context.Context, principal adminauth.Principal, organizationID, displayName string) (Organization, error) {
	name, ok := validDisplayName(displayName)
	if !ok || id.Validate(organizationID, id.Organization) != nil {
		return Organization{}, ErrInvalid
	}
	if principal.OrganizationID != organizationID || !principal.Allows(adminauth.ManageOwners, adminauth.AuthorizationContext{}) {
		return Organization{}, ErrForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Organization{}, fmt.Errorf("begin organization rename: %w", err)
	}
	defer rollback(tx)
	var item Organization
	var createdAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		UPDATE organizations SET display_name = $2, updated_at = $3
		WHERE organization_id = $1 AND status = 'active'
		RETURNING organization_id, slug, display_name, created_at
	`, organizationID, name, store.now().UTC()).Scan(&item.ID, &item.Slug, &item.DisplayName, &createdAt); errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	} else if err != nil {
		return Organization{}, mapWriteError("rename organization", err)
	}
	item.CreatedAt = createdAt.Time.UTC()
	if err := store.audit(ctx, tx, principal, organizationID, "admin.organization_rename", "organization", organizationID, "", []string{"display_name"}); err != nil {
		return Organization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Organization{}, fmt.Errorf("commit organization rename: %w", err)
	}
	return item, nil
}

// RenameApplication changes an application's display name.
func (store *Store) RenameApplication(ctx context.Context, principal adminauth.Principal, applicationID, displayName string) (Application, error) {
	name, ok := validDisplayName(displayName)
	if !ok || id.Validate(applicationID, id.Application) != nil {
		return Application{}, ErrInvalid
	}
	if !principal.AllowsIn(adminauth.ActivateConfiguration, applicationID, adminauth.AuthorizationContext{}) {
		return Application{}, ErrForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Application{}, fmt.Errorf("begin application rename: %w", err)
	}
	defer rollback(tx)
	var item Application
	var disabledAt, createdAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		UPDATE applications SET display_name = $3, updated_at = $4
		WHERE organization_id = $1 AND application_id = $2
		RETURNING application_id, organization_id, slug, display_name, status, disabled_at, created_at
	`, principal.OrganizationID, applicationID, name, store.now().UTC()).Scan(
		&item.ID, &item.OrganizationID, &item.Slug, &item.DisplayName, &item.Status, &disabledAt, &createdAt,
	); errors.Is(err, pgx.ErrNoRows) {
		return Application{}, ErrNotFound
	} else if err != nil {
		return Application{}, mapWriteError("rename application", err)
	}
	if err := store.audit(ctx, tx, principal, principal.OrganizationID, "admin.application_rename", "application", applicationID, "", []string{"display_name"}); err != nil {
		return Application{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("commit application rename: %w", err)
	}
	return applicationFromRow(item.ID, item.OrganizationID, item.Slug, item.DisplayName, item.Status, disabledAt, createdAt), nil
}

// RenameEnvironment changes an environment's display name.
func (store *Store) RenameEnvironment(ctx context.Context, principal adminauth.Principal, environmentID, displayName string) (Environment, error) {
	name, ok := validDisplayName(displayName)
	if !ok || id.Validate(environmentID, id.Environment) != nil {
		return Environment{}, ErrInvalid
	}
	if !principal.AllowsSomewhere(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return Environment{}, ErrForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Environment{}, fmt.Errorf("begin environment rename: %w", err)
	}
	defer rollback(tx)
	var applicationID string
	if err := tx.QueryRow(ctx, `
		SELECT application_id FROM environments
		WHERE organization_id = $1 AND environment_id = $2
		FOR UPDATE
	`, principal.OrganizationID, environmentID).Scan(&applicationID); errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	} else if err != nil {
		return Environment{}, fmt.Errorf("lock environment for rename: %w", err)
	}
	if !principal.AllowsIn(adminauth.ActivateConfiguration, applicationID, adminauth.AuthorizationContext{}) {
		return Environment{}, ErrForbidden
	}
	var item Environment
	var disabledAt, createdAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		UPDATE environments SET display_name = $3, updated_at = $4
		WHERE organization_id = $1 AND environment_id = $2
		RETURNING environment_id, application_id, slug, display_name, kind, status, disabled_at, created_at
	`, principal.OrganizationID, environmentID, name, store.now().UTC()).Scan(
		&item.ID, &item.ApplicationID, &item.Slug, &item.DisplayName, &item.Kind, &item.Status, &disabledAt, &createdAt,
	); err != nil {
		return Environment{}, mapWriteError("rename environment", err)
	}
	if err := store.audit(ctx, tx, principal, principal.OrganizationID, "admin.environment_rename", "environment", environmentID, environmentID, []string{"display_name"}); err != nil {
		return Environment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Environment{}, fmt.Errorf("commit environment rename: %w", err)
	}
	return environmentFromRow(item.ID, item.ApplicationID, item.Slug, item.DisplayName, item.Kind, item.Status, disabledAt, createdAt), nil
}
