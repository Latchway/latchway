package adminauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

// AdministratorPageRequest is a bounded keyset page over administrator
// membership creation time and administrator ID.
type AdministratorPageRequest struct {
	After   time.Time
	AfterID string
	Size    int32
}

func (page AdministratorPageRequest) validate() error {
	if page.Size < 1 || page.Size > 200 {
		return ErrInvalidAdminInput
	}
	if page.After.IsZero() != (page.AfterID == "") {
		return ErrInvalidAdminInput
	}
	if page.AfterID != "" && id.Validate(page.AfterID, id.AdminUser) != nil {
		return ErrInvalidAdminInput
	}
	return nil
}

// Administrator is the value-safe organization membership view. Password
// hashes, session material, and API-token metadata are deliberately absent.
type Administrator struct {
	ID                    string     `json:"id"`
	MembershipID          string     `json:"membership_id"`
	OrganizationID        string     `json:"organization_id"`
	Email                 string     `json:"email"`
	DisplayName           string     `json:"display_name"`
	Role                  Role       `json:"role"`
	Status                string     `json:"status"`
	PasswordResetRequired bool       `json:"password_reset_required"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	DisabledAt            *time.Time `json:"disabled_at,omitempty"`
}

// CreateAdministratorInput atomically creates one local account and its first
// organization membership. Existing global accounts are rejected so an owner
// cannot silently change credentials used by another tenant.
type CreateAdministratorInput struct {
	Email        string
	DisplayName  string
	PasswordHash PasswordHash
	Role         Role
	RequestID    string
}

func (input CreateAdministratorInput) validate() error {
	if _, err := NormalizeEmail(input.Email); err != nil {
		return err
	}
	if err := validateDisplayName(input.DisplayName); err != nil {
		return fmt.Errorf("%w: display name", ErrInvalidAdminInput)
	}
	if input.Role.Validate() != nil {
		return fmt.Errorf("%w: role", ErrInvalidAdminInput)
	}
	if input.PasswordHash.encoded == "" {
		return fmt.Errorf("%w: password hash", ErrInvalidAdminInput)
	}
	if _, err := ParsePasswordHash(input.PasswordHash.Encoded()); err != nil {
		return fmt.Errorf("%w: password hash", ErrInvalidAdminInput)
	}
	if validateRequestID(input.RequestID) != nil {
		return fmt.Errorf("%w: request ID", ErrInvalidAdminInput)
	}
	return nil
}

type lockedAdministrator struct {
	administrator Administrator
	accountStatus string
}

// ListAdministrators returns only administrators belonging to the active
// principal's organization. Owner capability is required even for listing.
func (store *Store) ListAdministrators(
	ctx context.Context,
	principal Principal,
	page AdministratorPageRequest,
) ([]Administrator, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return nil, err
	}
	if err := page.validate(); err != nil {
		return nil, err
	}
	var after any
	if !page.After.IsZero() {
		after = page.After.UTC()
	}
	rows, err := store.pool.Query(ctx, `
		SELECT u.admin_user_id,
		       m.admin_membership_id,
		       m.organization_id,
		       u.email,
		       u.display_name,
		       m.role,
		       m.status,
		       u.password_reset_required,
		       m.created_at,
		       m.updated_at,
		       m.disabled_at
		FROM admin_memberships AS m
		JOIN admin_users AS u ON u.admin_user_id = m.admin_user_id
		WHERE m.organization_id = $1
		  AND ($2::timestamptz IS NULL OR (m.created_at, u.admin_user_id) > ($2, $3))
		ORDER BY m.created_at, u.admin_user_id
		LIMIT $4
	`, principal.OrganizationID, after, page.AfterID, page.Size+1)
	if err != nil {
		return nil, fmt.Errorf("list administrators: %w", err)
	}
	defer rows.Close()
	items := make([]Administrator, 0)
	for rows.Next() {
		var item Administrator
		if err := rows.Scan(
			&item.ID, &item.MembershipID, &item.OrganizationID, &item.Email,
			&item.DisplayName, &item.Role, &item.Status, &item.PasswordResetRequired,
			&item.CreatedAt, &item.UpdatedAt, &item.DisabledAt,
		); err != nil {
			return nil, fmt.Errorf("scan administrator: %w", err)
		}
		if item.Role.Validate() != nil || !validMembershipStatus(item.Status) {
			return nil, errors.New("stored administrator membership is invalid")
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate administrators: %w", err)
	}
	return items, nil
}

// CreateAdministrator creates one local administrator and first membership in
// the principal's organization. The password hash never appears in audit data.
func (store *Store) CreateAdministrator(
	ctx context.Context,
	principal Principal,
	input CreateAdministratorInput,
) (Administrator, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return Administrator{}, err
	}
	if err := input.validate(); err != nil {
		return Administrator{}, err
	}
	emailNormalized, _ := NormalizeEmail(input.Email)
	adminUserID, err := store.newID(id.AdminUser)
	if err != nil {
		return Administrator{}, fmt.Errorf("generate administrator ID: %w", err)
	}
	membershipID, err := store.newID(id.AdminMembership)
	if err != nil {
		return Administrator{}, fmt.Errorf("generate administrator membership ID: %w", err)
	}
	now := store.now().UTC()

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Administrator{}, fmt.Errorf("begin administrator creation: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Administrator{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Administrator{}, ErrAdminAuthentication
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name, status,
			created_at, updated_at, password_reset_required
		) VALUES ($1, $2, $3, $4, 'active', $5, $5, false)
	`, adminUserID, strings.TrimSpace(input.Email), emailNormalized, strings.TrimSpace(input.DisplayName), now); err != nil {
		if isUniqueViolation(err) {
			return Administrator{}, ErrAdminConflict
		}
		return Administrator{}, fmt.Errorf("create administrator: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_password_credentials (
			admin_user_id, password_hash, created_at, changed_at, reset_by_admin_user_id
		) VALUES ($1, $2, $3, $3, $4)
	`, adminUserID, input.PasswordHash.Encoded(), now, principal.AdminUserID); err != nil {
		return Administrator{}, fmt.Errorf("create administrator password: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, status,
			created_by_admin_user_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)
	`, membershipID, principal.OrganizationID, adminUserID, input.Role, principal.AdminUserID, now); err != nil {
		if isUniqueViolation(err) {
			return Administrator{}, ErrAdminConflict
		}
		return Administrator{}, fmt.Errorf("create administrator membership: %w", err)
	}
	changes := []AuditChange{
		mustSensitiveAuditChange("email", AuditSet),
		mustSensitiveAuditChange("password_hash", AuditSet),
		mustPublicAuditChange("display_name", AuditSet),
		mustPublicAuditChange("role", AuditSet),
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.administrator_create", adminUserID, input.RequestID, now, changes); err != nil {
		return Administrator{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Administrator{}, fmt.Errorf("commit administrator creation: %w", err)
	}
	return Administrator{
		ID: adminUserID, MembershipID: membershipID, OrganizationID: principal.OrganizationID,
		Email: strings.TrimSpace(input.Email), DisplayName: strings.TrimSpace(input.DisplayName),
		Role: input.Role, Status: "active", CreatedAt: now, UpdatedAt: now,
	}, nil
}

// ChangeAdministratorRole atomically changes one organization membership and
// refuses to demote its final active owner.
func (store *Store) ChangeAdministratorRole(
	ctx context.Context,
	principal Principal,
	targetAdminUserID string,
	role Role,
	requestID string,
) (Administrator, error) {
	if err := validateLifecycleInput(principal, targetAdminUserID, requestID); err != nil || role.Validate() != nil {
		return Administrator{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Administrator{}, fmt.Errorf("begin administrator role change: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Administrator{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Administrator{}, ErrAdminAuthentication
	}
	target, ok := locked[targetAdminUserID]
	if !ok {
		return Administrator{}, ErrAdminNotFound
	}
	if target.administrator.Status == "active" && target.accountStatus == "active" && target.administrator.Role == RoleOwner && role != RoleOwner && activeOwnerCount(locked, targetAdminUserID) == 0 {
		return Administrator{}, ErrLastActiveOwner
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_memberships
		SET role = $3, updated_at = $4
		WHERE organization_id = $1 AND admin_user_id = $2
	`, principal.OrganizationID, targetAdminUserID, role, now); err != nil {
		return Administrator{}, fmt.Errorf("change administrator role: %w", err)
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.administrator_role_change", targetAdminUserID, requestID, now, []AuditChange{mustPublicAuditChange("role", AuditSet)}); err != nil {
		return Administrator{}, err
	}
	updated, err := readAdministratorTx(ctx, tx, principal.OrganizationID, targetAdminUserID)
	if err != nil {
		return Administrator{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Administrator{}, fmt.Errorf("commit administrator role change: %w", err)
	}
	return updated, nil
}

// SetAdministratorEnabled changes the organization membership status. Disable
// revokes every session and API token scoped to that membership in the same
// transaction and protects the final active owner.
func (store *Store) SetAdministratorEnabled(
	ctx context.Context,
	principal Principal,
	targetAdminUserID string,
	enabled bool,
	requestID string,
) (Administrator, error) {
	if err := validateLifecycleInput(principal, targetAdminUserID, requestID); err != nil {
		return Administrator{}, err
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Administrator{}, fmt.Errorf("begin administrator status change: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Administrator{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Administrator{}, ErrAdminAuthentication
	}
	target, ok := locked[targetAdminUserID]
	if !ok {
		return Administrator{}, ErrAdminNotFound
	}
	desiredStatus := "disabled"
	var disabledAt any = now
	operation := AuditSet
	action := "admin.administrator_disable"
	if enabled {
		desiredStatus = "active"
		disabledAt = nil
		operation = AuditClear
		action = "admin.administrator_enable"
	}
	if !enabled && target.administrator.Status == "active" && target.accountStatus == "active" && target.administrator.Role == RoleOwner && activeOwnerCount(locked, targetAdminUserID) == 0 {
		return Administrator{}, ErrLastActiveOwner
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_memberships
		SET status = $3, disabled_at = $4, updated_at = $5
		WHERE organization_id = $1 AND admin_user_id = $2
	`, principal.OrganizationID, targetAdminUserID, desiredStatus, disabledAt, now); err != nil {
		return Administrator{}, fmt.Errorf("change administrator status: %w", err)
	}
	changes := []AuditChange{mustPublicAuditChange("membership_status", operation)}
	if !enabled {
		if err := revokeAdministratorCredentials(ctx, tx, principal.OrganizationID, targetAdminUserID, now, "administrator_disabled"); err != nil {
			return Administrator{}, err
		}
		changes = append(changes,
			mustSensitiveAuditChange("session_tokens", AuditRevoke),
			mustSensitiveAuditChange("api_tokens", AuditRevoke),
		)
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, action, targetAdminUserID, requestID, now, changes); err != nil {
		return Administrator{}, err
	}
	updated, err := readAdministratorTx(ctx, tx, principal.OrganizationID, targetAdminUserID)
	if err != nil {
		return Administrator{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Administrator{}, fmt.Errorf("commit administrator status change: %w", err)
	}
	return updated, nil
}

// ResetAdministratorPassword replaces the global local credential only when
// the target belongs exclusively to the principal's organization. This avoids
// letting one tenant's owner change credentials used by another tenant.
func (store *Store) ResetAdministratorPassword(
	ctx context.Context,
	principal Principal,
	targetAdminUserID string,
	passwordHash PasswordHash,
	requestID string,
) (Administrator, error) {
	if err := validateLifecycleInput(principal, targetAdminUserID, requestID); err != nil {
		return Administrator{}, err
	}
	if _, err := ParsePasswordHash(passwordHash.Encoded()); err != nil {
		return Administrator{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Administrator{}, fmt.Errorf("begin administrator password reset: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Administrator{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Administrator{}, ErrAdminAuthentication
	}
	if _, ok := locked[targetAdminUserID]; !ok {
		return Administrator{}, ErrAdminNotFound
	}
	var otherMemberships int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM admin_memberships
		WHERE admin_user_id = $1 AND organization_id <> $2
	`, targetAdminUserID, principal.OrganizationID).Scan(&otherMemberships); err != nil {
		return Administrator{}, fmt.Errorf("check cross-organization administrator memberships: %w", err)
	}
	if otherMemberships != 0 {
		return Administrator{}, ErrAdminConflict
	}
	tag, err := tx.Exec(ctx, `
		UPDATE admin_password_credentials
		SET password_hash = $2, changed_at = $3, reset_by_admin_user_id = $4
		WHERE admin_user_id = $1
	`, targetAdminUserID, passwordHash.Encoded(), now, principal.AdminUserID)
	if err != nil {
		return Administrator{}, fmt.Errorf("reset administrator password: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Administrator{}, ErrAdminNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_users
		SET password_reset_required = false, updated_at = $2
		WHERE admin_user_id = $1
	`, targetAdminUserID, now); err != nil {
		return Administrator{}, fmt.Errorf("update administrator password state: %w", err)
	}
	if err := revokeAdministratorCredentials(ctx, tx, principal.OrganizationID, targetAdminUserID, now, "password_reset"); err != nil {
		return Administrator{}, err
	}
	changes := []AuditChange{
		mustSensitiveAuditChange("password_hash", AuditRotate),
		mustSensitiveAuditChange("session_tokens", AuditRevoke),
		mustSensitiveAuditChange("api_tokens", AuditRevoke),
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.administrator_password_reset", targetAdminUserID, requestID, now, changes); err != nil {
		return Administrator{}, err
	}
	updated, err := readAdministratorTx(ctx, tx, principal.OrganizationID, targetAdminUserID)
	if err != nil {
		return Administrator{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Administrator{}, fmt.Errorf("commit administrator password reset: %w", err)
	}
	return updated, nil
}

func validateOwnerPrincipal(principal Principal) error {
	if id.Validate(principal.OrganizationID, id.Organization) != nil ||
		id.Validate(principal.AdminUserID, id.AdminUser) != nil {
		return ErrInvalidAdminInput
	}
	if !principal.Allows(ManageOwners, AuthorizationContext{}) {
		return ErrAdminAuthentication
	}
	return nil
}

func validateLifecycleInput(principal Principal, targetAdminUserID, requestID string) error {
	if err := validateOwnerPrincipal(principal); err != nil {
		return err
	}
	if id.Validate(targetAdminUserID, id.AdminUser) != nil || validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	return nil
}

func lockOrganizationAdministrators(
	ctx context.Context,
	tx pgx.Tx,
	organizationID string,
) (map[string]lockedAdministrator, error) {
	rows, err := tx.Query(ctx, `
		SELECT u.admin_user_id,
		       m.admin_membership_id,
		       m.organization_id,
		       u.email,
		       u.display_name,
		       m.role,
		       m.status,
		       u.password_reset_required,
		       m.created_at,
		       m.updated_at,
		       m.disabled_at,
		       u.status
		FROM admin_memberships AS m
		JOIN admin_users AS u ON u.admin_user_id = m.admin_user_id
		WHERE m.organization_id = $1
		ORDER BY m.admin_user_id
		FOR UPDATE OF m
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("lock administrator memberships: %w", err)
	}
	defer rows.Close()
	items := make(map[string]lockedAdministrator)
	for rows.Next() {
		var item lockedAdministrator
		if err := rows.Scan(
			&item.administrator.ID, &item.administrator.MembershipID,
			&item.administrator.OrganizationID, &item.administrator.Email,
			&item.administrator.DisplayName, &item.administrator.Role,
			&item.administrator.Status, &item.administrator.PasswordResetRequired,
			&item.administrator.CreatedAt, &item.administrator.UpdatedAt,
			&item.administrator.DisabledAt, &item.accountStatus,
		); err != nil {
			return nil, fmt.Errorf("scan locked administrator membership: %w", err)
		}
		items[item.administrator.ID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locked administrator memberships: %w", err)
	}
	return items, nil
}

func lockedOwnerAllows(items map[string]lockedAdministrator, principal Principal) bool {
	actor, ok := items[principal.AdminUserID]
	return ok && actor.accountStatus == "active" && actor.administrator.Status == "active" &&
		actor.administrator.Role == RoleOwner
}

func activeOwnerCount(items map[string]lockedAdministrator, excluding string) int {
	count := 0
	for adminUserID, item := range items {
		if adminUserID != excluding && item.accountStatus == "active" &&
			item.administrator.Status == "active" && item.administrator.Role == RoleOwner {
			count++
		}
	}
	return count
}

func validMembershipStatus(value string) bool {
	return value == "active" || value == "disabled"
}

func readAdministratorTx(ctx context.Context, tx pgx.Tx, organizationID, adminUserID string) (Administrator, error) {
	var item Administrator
	err := tx.QueryRow(ctx, `
		SELECT u.admin_user_id,
		       m.admin_membership_id,
		       m.organization_id,
		       u.email,
		       u.display_name,
		       m.role,
		       m.status,
		       u.password_reset_required,
		       m.created_at,
		       m.updated_at,
		       m.disabled_at
		FROM admin_memberships AS m
		JOIN admin_users AS u ON u.admin_user_id = m.admin_user_id
		WHERE m.organization_id = $1 AND m.admin_user_id = $2
	`, organizationID, adminUserID).Scan(
		&item.ID, &item.MembershipID, &item.OrganizationID, &item.Email,
		&item.DisplayName, &item.Role, &item.Status, &item.PasswordResetRequired,
		&item.CreatedAt, &item.UpdatedAt, &item.DisabledAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Administrator{}, ErrAdminNotFound
	}
	if err != nil {
		return Administrator{}, fmt.Errorf("read administrator: %w", err)
	}
	return item, nil
}

func revokeAdministratorCredentials(
	ctx context.Context,
	tx pgx.Tx,
	organizationID string,
	adminUserID string,
	now time.Time,
	reason string,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE admin_sessions
		SET revoked_at = $3, revoke_reason = $4
		WHERE organization_id = $1 AND admin_user_id = $2 AND revoked_at IS NULL
	`, organizationID, adminUserID, now, reason); err != nil {
		return fmt.Errorf("revoke administrator sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_api_tokens
		SET revoked_at = $3, revoke_reason = $4
		WHERE organization_id = $1 AND admin_user_id = $2 AND revoked_at IS NULL
	`, organizationID, adminUserID, now, reason); err != nil {
		return fmt.Errorf("revoke administrator API tokens: %w", err)
	}
	return nil
}

func (store *Store) insertAdministratorAudit(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	action string,
	targetAdminUserID string,
	requestID string,
	now time.Time,
	changes []AuditChange,
) error {
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate administrator audit event ID: %w", err)
	}
	actor, err := auditActorForPrincipal(principal)
	if err != nil {
		return err
	}
	mutation, err := NewAuditMutation(
		eventID, principal.OrganizationID, "", actor, action, "admin_user",
		targetAdminUserID, AuditSucceeded, requestID, now, changes,
	)
	if err != nil {
		return err
	}
	return insertAuditMutation(ctx, tx, mutation)
}

func auditActorForPrincipal(principal Principal) (AuditActor, error) {
	if principal.Method == AuthenticationAPIToken {
		return NewAPITokenActor(principal.CredentialID)
	}
	return NewAdminUserActor(principal.AdminUserID)
}

func mustPublicAuditChange(field string, operation AuditOperation) AuditChange {
	change, _ := NewPublicAuditChange(field, operation)
	return change
}

func mustSensitiveAuditChange(field string, operation AuditOperation) AuditChange {
	change, _ := NewSensitiveAuditChange(field, operation)
	return change
}
