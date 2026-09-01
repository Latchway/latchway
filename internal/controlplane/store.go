// Package controlplane owns tenant-scoped administrative resource mutations.
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/database/dbsql"
	"github.com/latchway/latchway/internal/id"
)

var (
	ErrInvalid   = errors.New("invalid control-plane input")
	ErrForbidden = errors.New("control-plane operation forbidden")
	ErrConflict  = errors.New("control-plane resource conflict")
	ErrNotFound  = errors.New("control-plane resource not found")
)

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("control-plane database pool is nil")
	}
	return &Store{pool: pool, now: time.Now}, nil
}

type NamedInput struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type ApplicationInput struct {
	OrganizationID string
	NamedInput
}

type EnvironmentInput struct {
	ApplicationID string
	Kind          string
	NamedInput
}

// PageRequest is a validated keyset page over (created_at, resource_id).
type PageRequest struct {
	After   time.Time
	AfterID string
	Size    int32
}

type Organization struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
}

type Application struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Slug           string     `json:"slug"`
	DisplayName    string     `json:"display_name"`
	Status         string     `json:"status"`
	DisabledAt     *time.Time `json:"disabled_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type Environment struct {
	ID            string     `json:"id"`
	ApplicationID string     `json:"application_id"`
	Slug          string     `json:"slug"`
	DisplayName   string     `json:"display_name"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	DisabledAt    *time.Time `json:"disabled_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Membership struct {
	OrganizationID string         `json:"organization_id"`
	Role           adminauth.Role `json:"role"`
}

type AdminView struct {
	ID          string
	Email       string
	DisplayName string
	Memberships []Membership
}

func (store *Store) AdminView(ctx context.Context, adminUserID string) (AdminView, error) {
	if err := id.Validate(adminUserID, id.AdminUser); err != nil {
		return AdminView{}, ErrInvalid
	}
	rows, err := dbsql.New(store.pool).AdminSessionView(ctx, adminUserID)
	if err != nil {
		return AdminView{}, fmt.Errorf("read administrator view: %w", err)
	}
	if len(rows) == 0 {
		return AdminView{}, ErrNotFound
	}
	view := AdminView{ID: rows[0].AdminUserID, Email: rows[0].Email, DisplayName: rows[0].DisplayName}
	for _, row := range rows {
		role := adminauth.Role(row.Role)
		if role.Validate() != nil {
			return AdminView{}, errors.New("stored administrator role is invalid")
		}
		view.Memberships = append(view.Memberships, Membership{OrganizationID: row.OrganizationID, Role: role})
	}
	return view, nil
}

func (store *Store) ListOrganizations(ctx context.Context, principal adminauth.Principal, page PageRequest) ([]Organization, error) {
	after, afterID, err := page.parameters(id.Organization)
	if err != nil {
		return nil, err
	}
	rows, err := dbsql.New(store.pool).ListOrganizationsForAdmin(ctx, principal.AdminUserID, after, afterID, page.Size+1)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	items := make([]Organization, 0, len(rows))
	for _, row := range rows {
		items = append(items, Organization{ID: row.OrganizationID, Slug: row.Slug, DisplayName: row.DisplayName, CreatedAt: row.CreatedAt.Time})
	}
	return items, nil
}

func (store *Store) ListApplications(ctx context.Context, principal adminauth.Principal, organizationID string, page PageRequest) ([]Application, error) {
	if id.Validate(organizationID, id.Organization) != nil {
		return nil, ErrInvalid
	}
	if principal.OrganizationID != organizationID {
		return nil, ErrForbidden
	}
	after, afterID, err := page.parameters(id.Application)
	if err != nil {
		return nil, err
	}
	rows, err := dbsql.New(store.pool).ListApplications(ctx, organizationID, after, afterID, page.Size+1)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	items := make([]Application, 0, len(rows))
	for _, row := range rows {
		items = append(items, applicationFromRow(row.ApplicationID, row.OrganizationID, row.Slug, row.DisplayName, row.Status, row.DisabledAt, row.CreatedAt))
	}
	return items, nil
}

func (store *Store) ListEnvironments(ctx context.Context, principal adminauth.Principal, applicationID string) ([]Environment, error) {
	if id.Validate(applicationID, id.Application) != nil {
		return nil, ErrInvalid
	}
	rows, err := dbsql.New(store.pool).ListEnvironments(ctx, principal.OrganizationID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	items := make([]Environment, 0, len(rows))
	for _, row := range rows {
		items = append(items, environmentFromRow(row.EnvironmentID, row.ApplicationID, row.Slug, row.DisplayName, row.Kind, row.Status, row.DisabledAt, row.CreatedAt))
	}
	return items, nil
}

func (store *Store) CreateOrganization(ctx context.Context, principal adminauth.Principal, input NamedInput) (Organization, error) {
	if !principal.Allows(adminauth.ManageOwners, adminauth.AuthorizationContext{}) {
		return Organization{}, ErrForbidden
	}
	if validateNamed(input) != nil {
		return Organization{}, ErrInvalid
	}
	organizationID, err := id.New(id.Organization)
	if err != nil {
		return Organization{}, err
	}
	membershipID, err := id.New(id.AdminMembership)
	if err != nil {
		return Organization{}, err
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Organization{}, fmt.Errorf("begin organization creation: %w", err)
	}
	defer rollback(tx)
	row, err := dbsql.New(tx).CreateOrganization(ctx, organizationID, input.Slug, strings.TrimSpace(input.DisplayName), timestamp(now))
	if err != nil {
		return Organization{}, mapWriteError("create organization", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, status,
			created_by_admin_user_id, created_at, updated_at
		) VALUES ($1, $2, $3, 'owner', 'active', $3, $4, $4)
	`, membershipID, organizationID, principal.AdminUserID, now); err != nil {
		return Organization{}, mapWriteError("create owner membership", err)
	}
	if err := store.audit(ctx, tx, principal, organizationID, "admin.organization_create", "organization", organizationID, "", []string{"slug", "display_name"}); err != nil {
		return Organization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Organization{}, fmt.Errorf("commit organization creation: %w", err)
	}
	return Organization{ID: row.OrganizationID, Slug: row.Slug, DisplayName: row.DisplayName, CreatedAt: row.CreatedAt.Time}, nil
}

func (store *Store) CreateApplication(ctx context.Context, principal adminauth.Principal, input ApplicationInput) (Application, error) {
	if principal.OrganizationID != input.OrganizationID || !principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return Application{}, ErrForbidden
	}
	if id.Validate(input.OrganizationID, id.Organization) != nil || validateNamed(input.NamedInput) != nil {
		return Application{}, ErrInvalid
	}
	applicationID, err := id.New(id.Application)
	if err != nil {
		return Application{}, err
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Application{}, fmt.Errorf("begin application creation: %w", err)
	}
	defer rollback(tx)
	row, err := dbsql.New(tx).CreateApplication(ctx, dbsql.CreateApplicationParams{
		ApplicationID: applicationID, OrganizationID: input.OrganizationID,
		Slug: input.Slug, DisplayName: strings.TrimSpace(input.DisplayName), CreatedAt: timestamp(now),
	})
	if err != nil {
		return Application{}, mapWriteError("create application", err)
	}
	if err := store.audit(ctx, tx, principal, input.OrganizationID, "admin.application_create", "application", applicationID, "", []string{"slug", "display_name"}); err != nil {
		return Application{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("commit application creation: %w", err)
	}
	return applicationFromRow(row.ApplicationID, row.OrganizationID, row.Slug, row.DisplayName, row.Status, row.DisabledAt, row.CreatedAt), nil
}

func (store *Store) CreateEnvironment(ctx context.Context, principal adminauth.Principal, input EnvironmentInput) (Environment, error) {
	if !principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return Environment{}, ErrForbidden
	}
	if id.Validate(input.ApplicationID, id.Application) != nil || validateNamed(input.NamedInput) != nil {
		return Environment{}, ErrInvalid
	}
	if input.Kind != "development" && input.Kind != "staging" && input.Kind != "production" {
		return Environment{}, ErrInvalid
	}
	environmentID, err := id.New(id.Environment)
	if err != nil {
		return Environment{}, err
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Environment{}, fmt.Errorf("begin environment creation: %w", err)
	}
	defer rollback(tx)
	var applicationStatus string
	if err := tx.QueryRow(ctx, `
		SELECT application.status
		FROM applications AS application
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE application.organization_id = $1 AND application.application_id = $2
		  AND organization.status = 'active'
		FOR SHARE OF application
	`, principal.OrganizationID, input.ApplicationID).Scan(&applicationStatus); errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	} else if err != nil {
		return Environment{}, fmt.Errorf("lock parent application: %w", err)
	} else if applicationStatus != "active" {
		return Environment{}, ErrNotFound
	}
	row, err := dbsql.New(tx).CreateEnvironment(ctx, dbsql.CreateEnvironmentParams{
		EnvironmentID: environmentID, OrganizationID: principal.OrganizationID,
		ApplicationID: input.ApplicationID, Slug: input.Slug,
		DisplayName: strings.TrimSpace(input.DisplayName), Kind: input.Kind, CreatedAt: timestamp(now),
	})
	if err != nil {
		return Environment{}, mapWriteError("create environment", err)
	}
	if err := store.audit(ctx, tx, principal, principal.OrganizationID, "admin.environment_create", "environment", environmentID, environmentID, []string{"slug", "display_name", "kind"}); err != nil {
		return Environment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Environment{}, fmt.Errorf("commit environment creation: %w", err)
	}
	return environmentFromRow(row.EnvironmentID, row.ApplicationID, row.Slug, row.DisplayName, row.Kind, row.Status, row.DisabledAt, row.CreatedAt), nil
}

// DisableApplication atomically disables an application and revokes every
// active session and refresh credential in its scope. Child environment
// lifecycle states are intentionally preserved.
func (store *Store) DisableApplication(ctx context.Context, principal adminauth.Principal, applicationID, reason string) (Application, error) {
	if validateLifecycleReason(reason) != nil {
		return Application{}, ErrInvalid
	}
	return store.setApplicationStatus(ctx, principal, applicationID, "disabled", true)
}

// EnableApplication restores future eligibility without reviving credentials.
func (store *Store) EnableApplication(ctx context.Context, principal adminauth.Principal, applicationID string) (Application, error) {
	return store.setApplicationStatus(ctx, principal, applicationID, "active", false)
}

func (store *Store) setApplicationStatus(ctx context.Context, principal adminauth.Principal, applicationID, status string, reasonProvided bool) (Application, error) {
	if !principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return Application{}, ErrForbidden
	}
	if id.Validate(applicationID, id.Application) != nil || (status != "active" && status != "disabled") {
		return Application{}, ErrInvalid
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Application{}, fmt.Errorf("begin application status change: %w", err)
	}
	defer rollback(tx)
	var item Application
	var disabledAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		/* controlplane_lock_application_lifecycle */
		SELECT application.application_id, application.organization_id, application.slug,
		       application.display_name, application.status, application.disabled_at,
		       application.created_at
		FROM applications AS application
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE application.organization_id = $1 AND application.application_id = $2
		  AND organization.status = 'active'
		FOR UPDATE OF application
	`, principal.OrganizationID, applicationID).Scan(
		&item.ID, &item.OrganizationID, &item.Slug, &item.DisplayName,
		&item.Status, &disabledAt, &item.CreatedAt,
	); errors.Is(err, pgx.ErrNoRows) {
		return Application{}, ErrNotFound
	} else if err != nil {
		return Application{}, fmt.Errorf("lock application status: %w", err)
	}
	if status == "disabled" {
		if err := revokeScopedCredentials(ctx, tx, principal.OrganizationID, applicationID, "", now, "application_disabled"); err != nil {
			return Application{}, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE applications
			SET status = 'disabled', disabled_at = COALESCE(disabled_at, $3), updated_at = $3
			WHERE organization_id = $1 AND application_id = $2
		`, principal.OrganizationID, applicationID, now); err != nil {
			return Application{}, mapWriteError("disable application", err)
		}
		disabled := now
		if disabledAt.Valid {
			disabled = disabledAt.Time.UTC()
		}
		item.Status, item.DisabledAt = "disabled", &disabled
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE applications
			SET status = 'active', disabled_at = NULL, updated_at = $3
			WHERE organization_id = $1 AND application_id = $2
		`, principal.OrganizationID, applicationID, now); err != nil {
			return Application{}, mapWriteError("enable application", err)
		}
		item.Status, item.DisabledAt = "active", nil
	}
	changes, err := lifecycleAuditChanges(status, reasonProvided)
	if err != nil {
		return Application{}, err
	}
	action := "admin.application_enable"
	if status == "disabled" {
		action = "admin.application_disable"
	}
	if err := store.auditExact(ctx, tx, principal, principal.OrganizationID, action, "application", applicationID, "", changes); err != nil {
		return Application{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("commit application status change: %w", err)
	}
	return item, nil
}

// DisableEnvironment atomically disables one environment and revokes only its
// active session and refresh credentials.
func (store *Store) DisableEnvironment(ctx context.Context, principal adminauth.Principal, environmentID, reason string) (Environment, error) {
	if validateLifecycleReason(reason) != nil {
		return Environment{}, ErrInvalid
	}
	return store.setEnvironmentStatus(ctx, principal, environmentID, "disabled", true)
}

// EnableEnvironment restores future eligibility without reviving credentials.
func (store *Store) EnableEnvironment(ctx context.Context, principal adminauth.Principal, environmentID string) (Environment, error) {
	return store.setEnvironmentStatus(ctx, principal, environmentID, "active", false)
}

func (store *Store) setEnvironmentStatus(ctx context.Context, principal adminauth.Principal, environmentID, status string, reasonProvided bool) (Environment, error) {
	if !principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return Environment{}, ErrForbidden
	}
	if id.Validate(environmentID, id.Environment) != nil || (status != "active" && status != "disabled") {
		return Environment{}, ErrInvalid
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Environment{}, fmt.Errorf("begin environment status change: %w", err)
	}
	defer rollback(tx)
	var applicationID string
	if err := tx.QueryRow(ctx, `
		SELECT application.application_id
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE environment.organization_id = $1 AND environment.environment_id = $2
		  AND organization.status = 'active'
		FOR SHARE OF application
	`, principal.OrganizationID, environmentID).Scan(&applicationID); errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	} else if err != nil {
		return Environment{}, fmt.Errorf("lock environment application: %w", err)
	}
	var item Environment
	var disabledAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		/* controlplane_lock_environment_lifecycle */
		SELECT environment.environment_id, environment.application_id, environment.slug,
		       environment.display_name, environment.kind, environment.status,
		       environment.disabled_at, environment.created_at
		FROM environments AS environment
		WHERE environment.organization_id = $1 AND environment.application_id = $2
		  AND environment.environment_id = $3
		FOR UPDATE
	`, principal.OrganizationID, applicationID, environmentID).Scan(
		&item.ID, &item.ApplicationID, &item.Slug, &item.DisplayName, &item.Kind,
		&item.Status, &disabledAt, &item.CreatedAt,
	); errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	} else if err != nil {
		return Environment{}, fmt.Errorf("lock environment status: %w", err)
	}
	if status == "disabled" {
		if err := revokeScopedCredentials(ctx, tx, principal.OrganizationID, applicationID, environmentID, now, "environment_disabled"); err != nil {
			return Environment{}, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE environments
			SET status = 'disabled', disabled_at = COALESCE(disabled_at, $3), updated_at = $3
			WHERE organization_id = $1 AND environment_id = $2
		`, principal.OrganizationID, environmentID, now); err != nil {
			return Environment{}, mapWriteError("disable environment", err)
		}
		disabled := now
		if disabledAt.Valid {
			disabled = disabledAt.Time.UTC()
		}
		item.Status, item.DisabledAt = "disabled", &disabled
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE environments
			SET status = 'active', disabled_at = NULL, updated_at = $3
			WHERE organization_id = $1 AND environment_id = $2
		`, principal.OrganizationID, environmentID, now); err != nil {
			return Environment{}, mapWriteError("enable environment", err)
		}
		item.Status, item.DisabledAt = "active", nil
	}
	changes, err := lifecycleAuditChanges(status, reasonProvided)
	if err != nil {
		return Environment{}, err
	}
	action := "admin.environment_enable"
	if status == "disabled" {
		action = "admin.environment_disable"
	}
	if err := store.auditExact(ctx, tx, principal, principal.OrganizationID, action, "environment", environmentID, environmentID, changes); err != nil {
		return Environment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Environment{}, fmt.Errorf("commit environment status change: %w", err)
	}
	return item, nil
}

func revokeScopedCredentials(ctx context.Context, tx pgx.Tx, organizationID, applicationID, environmentID string, now time.Time, reason string) error {
	scope := "organization_id = $1 AND application_id = $2"
	arguments := []any{organizationID, applicationID, now, reason}
	if environmentID != "" {
		scope += " AND environment_id = $5"
		arguments = append(arguments, environmentID)
	}
	challengeScope := "challenge.organization_id = $1 AND challenge.application_id = $2"
	if environmentID != "" {
		challengeScope += " AND challenge.environment_id = $5"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO session_challenge_consumptions (
			organization_id, application_id, environment_id,
			session_challenge_id, consumed_at
		)
		SELECT challenge.organization_id, challenge.application_id,
		       challenge.environment_id, challenge.session_challenge_id,
		       GREATEST(challenge.created_at, $3)
		FROM session_challenges AS challenge
		WHERE $4::text <> '' AND `+challengeScope+`
		ON CONFLICT (session_challenge_id) DO NOTHING`, arguments...); err != nil {
		return fmt.Errorf("invalidate scoped session challenges: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE component_attestation_challenges AS challenge
		SET consumed_at = COALESCE(challenge.consumed_at, GREATEST(challenge.created_at, $3))
		WHERE $4::text <> '' AND `+challengeScope+` AND challenge.consumed_at IS NULL`, arguments...); err != nil {
		return fmt.Errorf("invalidate scoped component attestation challenges: %w", err)
	}
	delegationScope := "delegation.organization_id = $1 AND delegation.application_id = $2"
	if environmentID != "" {
		delegationScope += " AND delegation.environment_id = $5"
	}
	if _, err := tx.Exec(ctx, `UPDATE component_delegations AS delegation
		SET revoked_at = COALESCE(delegation.revoked_at, GREATEST(delegation.created_at, $3))
		WHERE $4::text <> '' AND `+delegationScope+` AND delegation.revoked_at IS NULL`, arguments...); err != nil {
		return fmt.Errorf("invalidate scoped component delegations: %w", err)
	}
	attestationKeyScope := "attestation_key.organization_id = $1 AND attestation_key.application_id = $2"
	if environmentID != "" {
		attestationKeyScope += " AND attestation_key.environment_id = $5"
	}
	if _, err := tx.Exec(ctx, `UPDATE attestation_keys AS attestation_key
		SET status = 'revoked',
		    revoked_at = COALESCE(attestation_key.revoked_at, GREATEST(attestation_key.created_at, $3)),
		    updated_at = GREATEST(attestation_key.updated_at, attestation_key.created_at, $3)
		WHERE $4::text <> '' AND `+attestationKeyScope+`
		  AND attestation_key.status = 'active' AND attestation_key.linked_at IS NULL`, arguments...); err != nil {
		return fmt.Errorf("revoke scoped pending attestation keys: %w", err)
	}
	if _, err := tx.Exec(ctx, `/* controlplane_revoke_scoped_session_grants */
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $3)),
		    revoke_reason = COALESCE(revoke_reason, $4)
		WHERE `+scope+` AND revoked_at IS NULL`, arguments...); err != nil {
		return fmt.Errorf("revoke scoped session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $3))
		WHERE $4::text <> '' AND `+scope+` AND status IN ('staged', 'active')`, arguments...); err != nil {
		return fmt.Errorf("revoke scoped refresh tokens: %w", err)
	}
	familyScope := "family.organization_id = $1 AND family.application_id = $2"
	if environmentID != "" {
		familyScope += " AND family.environment_id = $5"
	}
	if _, err := tx.Exec(ctx, `UPDATE component_refresh_tokens AS refresh
		SET status = 'revoked', revoked_at = COALESCE(refresh.revoked_at, GREATEST(refresh.issued_at, $3))
		FROM component_session_families AS family
		WHERE family.component_session_family_id = refresh.component_session_family_id
		  AND $4::text <> '' AND `+familyScope+`
		  AND refresh.status IN ('staged', 'active')`, arguments...); err != nil {
		return fmt.Errorf("revoke scoped component refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE component_session_families AS family
		SET status = 'revoked', updated_at = GREATEST(family.updated_at, $3),
		    revoked_at = COALESCE(family.revoked_at, GREATEST(family.created_at, $3)),
		    revocation_reason = COALESCE(family.revocation_reason, $4)
		WHERE `+familyScope+` AND family.status = 'active'`, arguments...); err != nil {
		return fmt.Errorf("revoke scoped component session families: %w", err)
	}
	componentScope := "component.organization_id = $1 AND component.application_id = $2"
	if environmentID != "" {
		componentScope += " AND component.environment_id = $5"
	}
	if _, err := tx.Exec(ctx, `DELETE FROM refresh_rotation_results AS result
		USING client_components AS component
		WHERE component.client_component_id = result.client_component_id
		  AND $3::timestamptz IS NOT NULL AND $4::text <> ''
		  AND `+componentScope, arguments...); err != nil {
		return fmt.Errorf("remove scoped refresh rotation results: %w", err)
	}
	return nil
}

func lifecycleAuditChanges(status string, reasonProvided bool) ([]adminauth.AuditChange, error) {
	operation := adminauth.AuditSet
	if status == "active" {
		operation = adminauth.AuditClear
	}
	statusChange, err := adminauth.NewPublicAuditChange("status", operation)
	if err != nil {
		return nil, err
	}
	changes := []adminauth.AuditChange{statusChange}
	if reasonProvided {
		reasonChange, err := adminauth.NewPublicAuditChange("reason_provided", adminauth.AuditSet)
		if err != nil {
			return nil, err
		}
		credentialChange, err := adminauth.NewSensitiveAuditChange("session_credentials", adminauth.AuditRevoke)
		if err != nil {
			return nil, err
		}
		changes = append(changes, reasonChange, credentialChange)
	}
	return changes, nil
}

func validateLifecycleReason(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed != value || !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 500 || strings.ContainsAny(value, "\r\n\x00") {
		return ErrInvalid
	}
	return nil
}

func applicationFromRow(applicationID, organizationID, slug, displayName, status string, disabledAt pgtype.Timestamptz, createdAt pgtype.Timestamptz) Application {
	item := Application{ID: applicationID, OrganizationID: organizationID, Slug: slug, DisplayName: displayName, Status: status, CreatedAt: createdAt.Time}
	if disabledAt.Valid {
		disabled := disabledAt.Time.UTC()
		item.DisabledAt = &disabled
	}
	return item
}

func environmentFromRow(environmentID, applicationID, slug, displayName, kind, status string, disabledAt pgtype.Timestamptz, createdAt pgtype.Timestamptz) Environment {
	item := Environment{ID: environmentID, ApplicationID: applicationID, Slug: slug, DisplayName: displayName, Kind: kind, Status: status, CreatedAt: createdAt.Time}
	if disabledAt.Valid {
		disabled := disabledAt.Time.UTC()
		item.DisabledAt = &disabled
	}
	return item
}

func (store *Store) audit(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, organizationID, action, resourceType, resourceID, environmentID string, fields []string) error {
	eventID, err := id.New(id.AuditEvent)
	if err != nil {
		return err
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		return err
	}
	var actor adminauth.AuditActor
	if principal.Method == adminauth.AuthenticationAPIToken {
		actor, err = adminauth.NewAPITokenActor(principal.CredentialID)
	} else {
		actor, err = adminauth.NewAdminUserActor(principal.AdminUserID)
	}
	if err != nil {
		return err
	}
	changes := make([]adminauth.AuditChange, 0, len(fields))
	for _, field := range fields {
		change, changeErr := adminauth.NewPublicAuditChange(field, adminauth.AuditSet)
		if changeErr != nil {
			return changeErr
		}
		changes = append(changes, change)
	}
	return store.auditExactWithIdentity(ctx, tx, principal, organizationID, action, resourceType, resourceID, environmentID, eventID, requestID, actor, changes)

}

func (store *Store) auditExact(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, organizationID, action, resourceType, resourceID, environmentID string, changes []adminauth.AuditChange) error {
	eventID, err := id.New(id.AuditEvent)
	if err != nil {
		return err
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		return err
	}
	var actor adminauth.AuditActor
	if principal.Method == adminauth.AuthenticationAPIToken {
		actor, err = adminauth.NewAPITokenActor(principal.CredentialID)
	} else {
		actor, err = adminauth.NewAdminUserActor(principal.AdminUserID)
	}
	if err != nil {
		return err
	}
	return store.auditExactWithIdentity(ctx, tx, principal, organizationID, action, resourceType, resourceID, environmentID, eventID, requestID, actor, changes)
}

func (store *Store) auditExactWithIdentity(ctx context.Context, tx pgx.Tx, _ adminauth.Principal, organizationID, action, resourceType, resourceID, environmentID, eventID, requestID string, actor adminauth.AuditActor, changes []adminauth.AuditChange) error {
	mutation, err := adminauth.NewAuditMutation(eventID, organizationID, environmentID, actor, action, resourceType, resourceID, adminauth.AuditSucceeded, requestID, store.now().UTC(), changes)
	if err != nil {
		return err
	}
	return adminauth.InsertAuditMutation(ctx, tx, mutation)
}

func validateNamed(input NamedInput) error {
	name := strings.TrimSpace(input.DisplayName)
	if !slugPattern.MatchString(input.Slug) || len(name) == 0 || len(name) > 200 || strings.ContainsAny(name, "\r\n\x00") {
		return ErrInvalid
	}
	return nil
}

func timestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func (page PageRequest) parameters(prefix id.Prefix) (pgtype.Timestamptz, *string, error) {
	if page.Size < 1 || page.Size > 200 {
		return pgtype.Timestamptz{}, nil, ErrInvalid
	}
	if page.After.IsZero() != (page.AfterID == "") {
		return pgtype.Timestamptz{}, nil, ErrInvalid
	}
	if page.After.IsZero() {
		return pgtype.Timestamptz{}, nil, nil
	}
	if id.Validate(page.AfterID, prefix) != nil {
		return pgtype.Timestamptz{}, nil, ErrInvalid
	}
	afterID := page.AfterID
	return timestamp(page.After.UTC()), &afterID, nil
}

func mapWriteError(operation string, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505":
			return ErrConflict
		case "23503":
			return ErrNotFound
		case "23514", "22001":
			return ErrInvalid
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func rollback(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}
