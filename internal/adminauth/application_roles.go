package adminauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

// ErrRoleNotRaised means an application role wouldn't raise the member's
// organization role, including every role for owners.
var ErrRoleNotRaised = errors.New("the application role doesn't raise the organization role")

// ApplicationRoleGrant is one member's raised role in one application.
type ApplicationRoleGrant struct {
	AdminUserID   string    `json:"admin_user_id"`
	ApplicationID string    `json:"application_id"`
	Role          Role      `json:"role"`
	GrantedBy     string    `json:"granted_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type rowQuerier interface {
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
}

// loadApplicationRoles reads the roles that raise an administrator's
// organization role, per application.
func loadApplicationRoles(ctx context.Context, query rowQuerier, organizationID, adminUserID string) (map[string]Role, error) {
	rows, err := query.Query(ctx, `
		SELECT application_id, role FROM admin_application_roles WHERE organization_id = $1 AND admin_user_id = $2
	`, organizationID, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("read application roles: %w", err)
	}
	defer rows.Close()
	roles := map[string]Role{}
	for rows.Next() {
		var applicationID, role string
		if err := rows.Scan(&applicationID, &role); err != nil {
			return nil, fmt.Errorf("scan application role: %w", err)
		}
		roles[applicationID] = Role(role)
	}
	return roles, rows.Err()
}

// ListApplicationRoles returns every application role in the owner's organization.
func (store *Store) ListApplicationRoles(ctx context.Context, principal Principal) ([]ApplicationRoleGrant, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT g.admin_user_id, g.application_id, g.role, granter.display_name, g.created_at, g.updated_at
		FROM admin_application_roles AS g JOIN admin_users AS granter ON granter.admin_user_id = g.granted_by_admin_user_id
		WHERE g.organization_id = $1
		ORDER BY g.application_id, g.admin_user_id
		LIMIT 2000
	`, principal.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("list application roles: %w", err)
	}
	defer rows.Close()
	items := make([]ApplicationRoleGrant, 0)
	for rows.Next() {
		var item ApplicationRoleGrant
		if err := rows.Scan(&item.AdminUserID, &item.ApplicationID, &item.Role, &item.GrantedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan application role: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// SetApplicationRole gives a member a role in one application that is higher
// than their organization role.
func (store *Store) SetApplicationRole(ctx context.Context, principal Principal, adminUserID, applicationID string, role Role, requestID string) (ApplicationRoleGrant, error) {
	if err := validateLifecycleInput(principal, adminUserID, requestID); err != nil {
		return ApplicationRoleGrant{}, err
	}
	if id.Validate(applicationID, id.Application) != nil || (role != RoleAdmin && role != RoleOperator) {
		return ApplicationRoleGrant{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ApplicationRoleGrant{}, fmt.Errorf("begin application role change: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return ApplicationRoleGrant{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return ApplicationRoleGrant{}, ErrAdminAuthentication
	}
	member, ok := locked[adminUserID]
	if !ok {
		return ApplicationRoleGrant{}, ErrAdminNotFound
	}
	if role.rank() <= member.administrator.Role.rank() {
		return ApplicationRoleGrant{}, ErrRoleNotRaised
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND application_id = $2)`, principal.OrganizationID, applicationID).Scan(&exists); err != nil {
		return ApplicationRoleGrant{}, fmt.Errorf("check application: %w", err)
	}
	if !exists {
		return ApplicationRoleGrant{}, ErrAdminNotFound
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_application_roles (organization_id, admin_user_id, application_id, role, granted_by_admin_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		ON CONFLICT (admin_user_id, application_id) DO UPDATE SET role = EXCLUDED.role, granted_by_admin_user_id = EXCLUDED.granted_by_admin_user_id, updated_at = EXCLUDED.updated_at
	`, principal.OrganizationID, adminUserID, applicationID, string(role), principal.AdminUserID, now); err != nil {
		return ApplicationRoleGrant{}, fmt.Errorf("set application role: %w", err)
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.application_role_set", adminUserID, requestID, now,
		[]AuditChange{mustPublicAuditChange("application_role", AuditSet)}); err != nil {
		return ApplicationRoleGrant{}, err
	}
	var grant ApplicationRoleGrant
	if err := tx.QueryRow(ctx, `
		SELECT g.admin_user_id, g.application_id, g.role, granter.display_name, g.created_at, g.updated_at
		FROM admin_application_roles AS g JOIN admin_users AS granter ON granter.admin_user_id = g.granted_by_admin_user_id
		WHERE g.admin_user_id = $1 AND g.application_id = $2
	`, adminUserID, applicationID).Scan(&grant.AdminUserID, &grant.ApplicationID, &grant.Role, &grant.GrantedBy, &grant.CreatedAt, &grant.UpdatedAt); err != nil {
		return ApplicationRoleGrant{}, fmt.Errorf("read application role: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplicationRoleGrant{}, fmt.Errorf("commit application role change: %w", err)
	}
	return grant, nil
}

// RemoveApplicationRole returns a member to their organization role in one application.
func (store *Store) RemoveApplicationRole(ctx context.Context, principal Principal, adminUserID, applicationID, requestID string) error {
	if err := validateLifecycleInput(principal, adminUserID, requestID); err != nil {
		return err
	}
	if id.Validate(applicationID, id.Application) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin application role removal: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return err
	}
	if !lockedOwnerAllows(locked, principal) {
		return ErrAdminAuthentication
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM admin_application_roles WHERE organization_id = $1 AND admin_user_id = $2 AND application_id = $3
	`, principal.OrganizationID, adminUserID, applicationID)
	if err != nil {
		return fmt.Errorf("remove application role: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAdminNotFound
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.application_role_remove", adminUserID, requestID, now,
		[]AuditChange{mustPublicAuditChange("application_role", AuditRemove)}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit application role removal: %w", err)
	}
	return nil
}

// ApplicationRolesFor reads an administrator's application roles in one organization.
func (store *Store) ApplicationRolesFor(ctx context.Context, organizationID, adminUserID string) (map[string]Role, error) {
	return loadApplicationRoles(ctx, store.pool, organizationID, adminUserID)
}
