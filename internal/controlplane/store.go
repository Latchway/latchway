// Package controlplane owns tenant-scoped administrative resource mutations.
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

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
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Slug           string    `json:"slug"`
	DisplayName    string    `json:"display_name"`
	CreatedAt      time.Time `json:"created_at"`
}

type Environment struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	Slug          string    `json:"slug"`
	DisplayName   string    `json:"display_name"`
	Kind          string    `json:"kind"`
	CreatedAt     time.Time `json:"created_at"`
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
		items = append(items, Application{ID: row.ApplicationID, OrganizationID: row.OrganizationID, Slug: row.Slug, DisplayName: row.DisplayName, CreatedAt: row.CreatedAt.Time})
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
		items = append(items, Environment{ID: row.EnvironmentID, ApplicationID: row.ApplicationID, Slug: row.Slug, DisplayName: row.DisplayName, Kind: row.Kind, CreatedAt: row.CreatedAt.Time})
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
	return Application{ID: row.ApplicationID, OrganizationID: row.OrganizationID, Slug: row.Slug, DisplayName: row.DisplayName, CreatedAt: row.CreatedAt.Time}, nil
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
	return Environment{ID: row.EnvironmentID, ApplicationID: row.ApplicationID, Slug: row.Slug, DisplayName: row.DisplayName, Kind: row.Kind, CreatedAt: row.CreatedAt.Time}, nil
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
