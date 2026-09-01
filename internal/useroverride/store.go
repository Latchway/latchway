package useroverride

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/identity"
)

var (
	ErrForbidden     = errors.New("user override operation is forbidden")
	ErrNotFound      = errors.New("user override target not found")
	ErrConfiguration = errors.New("user override plan is unavailable")
)

type identifierSource func(id.Prefix) (string, error)

// AdminScope identifies the application user and environment selected by the
// canonical Admin API. The application is derived from the environment under
// the administrator's organization rather than accepted from the request.
type AdminScope struct {
	OrganizationID    string
	EnvironmentID     string
	ApplicationUserID string
}

func (scope AdminScope) validate() error {
	if id.Validate(scope.OrganizationID, id.Organization) != nil ||
		id.Validate(scope.EnvironmentID, id.Environment) != nil ||
		id.Validate(scope.ApplicationUserID, id.ApplicationUser) != nil {
		return ErrInvalid
	}
	return nil
}

type ReplaceInput struct {
	Scope     AdminScope
	LimitPlan string
	Reason    string
	ExpiresAt *time.Time
	RequestID string
}

// LimitPlanOverride is the redaction-safe Admin API representation of one
// effective durable override.
type LimitPlanOverride struct {
	ID        string     `json:"id"`
	LimitPlan string     `json:"limit_plan"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ApplicationUser is an environment-contextual administrative view. External
// subjects and identity credentials never enter this representation.
type ApplicationUser struct {
	ID                string             `json:"id"`
	EnvironmentID     string             `json:"environment_id"`
	Status            string             `json:"status"`
	IdentityProviders []string           `json:"identity_providers"`
	NormalizedClaims  map[string]any     `json:"normalized_claims"`
	LimitPlanOverride *LimitPlanOverride `json:"limit_plan_override,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	LastSeenAt        *time.Time         `json:"last_seen_at,omitempty"`
}

type Store struct {
	pool  *pgxpool.Pool
	newID identifierSource
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	return newStore(pool, id.New)
}

func newStore(pool *pgxpool.Pool, newID identifierSource) (*Store, error) {
	if pool == nil || newID == nil {
		return nil, errors.New("user override store dependency is nil")
	}
	return &Store{pool: pool, newID: newID}, nil
}

// Replace atomically replaces the unrevoked row, including an expired row
// retained by schema version 9's partial unique index. The active revision and
// target plan are checked while the environment pointer is locked.
func (store *Store) Replace(ctx context.Context, principal adminauth.Principal, input ReplaceInput) (ApplicationUser, error) {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil {
		return ApplicationUser{}, ErrInvalid
	}
	if err := input.Scope.validate(); err != nil || id.Validate(input.RequestID, id.AdminRequest) != nil ||
		id.Validate(principal.AdminUserID, id.AdminUser) != nil {
		return ApplicationUser{}, ErrInvalid
	}
	if input.Scope.OrganizationID != principal.OrganizationID ||
		!principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return ApplicationUser{}, ErrForbidden
	}
	document, err := Encode(Document{LimitPlan: input.LimitPlan})
	if err != nil {
		return ApplicationUser{}, ErrInvalid
	}
	reason := strings.TrimSpace(input.Reason)
	if !utf8.ValidString(reason) || strings.ContainsRune(reason, '\x00') ||
		utf8.RuneCountInString(reason) < 1 || utf8.RuneCountInString(reason) > 500 {
		return ApplicationUser{}, ErrInvalid
	}
	expiresAt := canonicalOptionalTime(input.ExpiresAt)

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ApplicationUser{}, fmt.Errorf("begin user override replacement: %w", err)
	}
	defer rollback(tx)
	applicationID, err := findEnvironmentApplication(ctx, tx, input.Scope)
	if err != nil {
		return ApplicationUser{}, err
	}
	user, err := lockApplicationUser(ctx, tx, input.Scope, applicationID)
	if err != nil {
		return ApplicationUser{}, err
	}
	lockedApplicationID, planExists, err := lockActiveEnvironment(ctx, tx, input.Scope, input.LimitPlan)
	if err != nil {
		return ApplicationUser{}, err
	}
	if lockedApplicationID != applicationID {
		return ApplicationUser{}, ErrNotFound
	}
	if !planExists {
		return ApplicationUser{}, ErrConfiguration
	}

	current, found, err := lockUnrevoked(ctx, tx, input.Scope, applicationID)
	if err != nil {
		return ApplicationUser{}, err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return ApplicationUser{}, err
	}
	if expiresAt != nil && !expiresAt.After(now) {
		return ApplicationUser{}, ErrInvalid
	}
	if found && current.effectiveAt(now) && current.matches(document, reason, expiresAt) {
		if err := store.auditReplace(
			ctx, tx, principal, input.Scope, input.RequestID, now,
			current.ID, false, expiresAt != nil,
		); err != nil {
			return ApplicationUser{}, err
		}
		view, viewErr := applicationUserView(ctx, tx, input.Scope, applicationID, user, current.public())
		if viewErr != nil {
			return ApplicationUser{}, viewErr
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplicationUser{}, fmt.Errorf("commit unchanged user override: %w", err)
		}
		return view, nil
	}
	if found {
		if _, err := tx.Exec(ctx, `
			UPDATE user_overrides
			SET revoked_at = GREATEST(created_at, $2::timestamptz)
			WHERE user_override_id = $1 AND revoked_at IS NULL
		`, current.ID, now); err != nil {
			return ApplicationUser{}, fmt.Errorf("revoke previous user override: %w", err)
		}
	}
	overrideID, err := store.newID(id.UserOverride)
	if err != nil {
		return ApplicationUser{}, fmt.Errorf("generate user override ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_overrides (
			user_override_id, organization_id, application_id, environment_id,
			application_user_id, override_document, reason,
			created_by_admin_user_id, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, overrideID, input.Scope.OrganizationID, applicationID, input.Scope.EnvironmentID,
		input.Scope.ApplicationUserID, document, reason, principal.AdminUserID, now, expiresAt); err != nil {
		return ApplicationUser{}, fmt.Errorf("insert user override: %w", err)
	}
	created := LimitPlanOverride{
		ID: overrideID, LimitPlan: input.LimitPlan, Reason: reason, CreatedAt: now, ExpiresAt: cloneTime(expiresAt),
	}
	if err := store.auditReplace(ctx, tx, principal, input.Scope, input.RequestID, now, created.ID, found, expiresAt != nil); err != nil {
		return ApplicationUser{}, err
	}
	view, err := applicationUserView(ctx, tx, input.Scope, applicationID, user, &created)
	if err != nil {
		return ApplicationUser{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplicationUser{}, fmt.Errorf("commit user override replacement: %w", err)
	}
	return view, nil
}

// Clear idempotently removes the currently unrevoked override. Expired rows
// are revoked as well so a future replacement cannot be blocked by the partial
// unique index.
func (store *Store) Clear(ctx context.Context, principal adminauth.Principal, scope AdminScope, requestID string) error {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil {
		return ErrInvalid
	}
	if err := scope.validate(); err != nil || id.Validate(requestID, id.AdminRequest) != nil ||
		id.Validate(principal.AdminUserID, id.AdminUser) != nil {
		return ErrInvalid
	}
	if scope.OrganizationID != principal.OrganizationID ||
		!principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return ErrForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin user override clear: %w", err)
	}
	defer rollback(tx)
	applicationID, err := findEnvironmentApplication(ctx, tx, scope)
	if err != nil {
		return err
	}
	if _, err := lockApplicationUser(ctx, tx, scope, applicationID); err != nil {
		return err
	}
	lockedApplicationID, err := lockEnvironment(ctx, tx, scope)
	if err != nil {
		return err
	}
	if lockedApplicationID != applicationID {
		return ErrNotFound
	}
	current, found, err := lockUnrevoked(ctx, tx, scope, applicationID)
	if err != nil {
		return err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	if found {
		if _, err := tx.Exec(ctx, `
			UPDATE user_overrides
			SET revoked_at = GREATEST(created_at, $2::timestamptz)
			WHERE user_override_id = $1 AND revoked_at IS NULL
		`, current.ID, now); err != nil {
			return fmt.Errorf("clear user override: %w", err)
		}
	}
	if err := store.auditClear(ctx, tx, principal, scope, requestID, now, current.ID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit user override clear: %w", err)
	}
	return nil
}

type lockedUser struct {
	status     string
	claims     []byte
	createdAt  time.Time
	lastSeenAt *time.Time
}

func lockApplicationUser(ctx context.Context, tx pgx.Tx, scope AdminScope, applicationID string) (lockedUser, error) {
	var result lockedUser
	err := tx.QueryRow(ctx, `
		SELECT status, normalized_claims, created_at, last_seen_at
		FROM application_users
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND status <> 'deleted'
		FOR UPDATE
	`, scope.OrganizationID, applicationID, scope.ApplicationUserID).Scan(
		&result.status, &result.claims, &result.createdAt, &result.lastSeenAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedUser{}, ErrNotFound
	}
	if err != nil {
		return lockedUser{}, fmt.Errorf("lock application user: %w", err)
	}
	return result, nil
}

func findEnvironmentApplication(ctx context.Context, tx pgx.Tx, scope AdminScope) (string, error) {
	var applicationID string
	err := tx.QueryRow(ctx, `
		SELECT e.application_id
		FROM environments e
		JOIN applications a ON a.organization_id = e.organization_id AND a.application_id = e.application_id
		JOIN organizations o ON o.organization_id = e.organization_id
		WHERE e.organization_id = $1 AND e.environment_id = $2
		  AND e.status = 'active' AND a.status = 'active' AND o.status = 'active'
	`, scope.OrganizationID, scope.EnvironmentID).Scan(&applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("resolve user override environment: %w", err)
	}
	return applicationID, nil
}

func lockEnvironment(ctx context.Context, tx pgx.Tx, scope AdminScope) (string, error) {
	var applicationID string
	err := tx.QueryRow(ctx, `
		SELECT e.application_id
		FROM environments e
		JOIN applications a ON a.organization_id = e.organization_id AND a.application_id = e.application_id
		JOIN organizations o ON o.organization_id = e.organization_id
		WHERE e.organization_id = $1 AND e.environment_id = $2
		  AND e.status = 'active' AND a.status = 'active' AND o.status = 'active'
		FOR UPDATE OF e FOR SHARE OF a
	`, scope.OrganizationID, scope.EnvironmentID).Scan(&applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("lock user override environment: %w", err)
	}
	return applicationID, nil
}

func lockActiveEnvironment(ctx context.Context, tx pgx.Tx, scope AdminScope, limitPlan string) (string, bool, error) {
	var applicationID string
	var planExists bool
	err := tx.QueryRow(ctx, `
		SELECT e.application_id,
		       EXISTS (
		           SELECT 1
		           FROM jsonb_array_elements(r.compiled_document->'spec'->'limitPlans') AS plan
		           WHERE plan->>'id' = $3
		       )
		FROM environments e
		JOIN applications a ON a.organization_id = e.organization_id AND a.application_id = e.application_id
		JOIN organizations o ON o.organization_id = e.organization_id
		JOIN active_config_revisions active
		  ON active.organization_id = e.organization_id
		 AND active.application_id = e.application_id
		 AND active.environment_id = e.environment_id
		JOIN config_revisions r
		  ON r.organization_id = active.organization_id
		 AND r.application_id = active.application_id
		 AND r.environment_id = active.environment_id
		 AND r.config_revision_id = active.config_revision_id
		WHERE e.organization_id = $1 AND e.environment_id = $2
		  AND e.status = 'active' AND a.status = 'active' AND o.status = 'active'
		  AND r.status = 'valid' AND active.revision_status = 'valid'
		  AND r.compiled_document IS NOT NULL
		FOR UPDATE OF e, active FOR SHARE OF a
	`, scope.OrganizationID, scope.EnvironmentID, limitPlan).Scan(&applicationID, &planExists)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("lock active user override configuration: %w", err)
	}
	return applicationID, planExists, nil
}

type storedOverride struct {
	ID        string
	document  []byte
	reason    string
	createdAt time.Time
	expiresAt *time.Time
}

func lockUnrevoked(ctx context.Context, tx pgx.Tx, scope AdminScope, applicationID string) (storedOverride, bool, error) {
	var result storedOverride
	err := tx.QueryRow(ctx, `
		SELECT user_override_id, override_document, reason, created_at, expires_at
		FROM user_overrides
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND revoked_at IS NULL
		FOR UPDATE
	`, scope.OrganizationID, applicationID, scope.EnvironmentID, scope.ApplicationUserID).Scan(
		&result.ID, &result.document, &result.reason, &result.createdAt, &result.expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedOverride{}, false, nil
	}
	if err != nil {
		return storedOverride{}, false, fmt.Errorf("lock current user override: %w", err)
	}
	return result, true, nil
}

func (stored storedOverride) effectiveAt(now time.Time) bool {
	return stored.expiresAt == nil || stored.expiresAt.After(now)
}

func (stored storedOverride) matches(document []byte, reason string, expiresAt *time.Time) bool {
	decoded, err := Decode(stored.document)
	if err != nil {
		return false
	}
	want, err := Decode(document)
	return err == nil && decoded == want && stored.reason == reason && timesEqual(stored.expiresAt, expiresAt)
}

func (stored storedOverride) public() *LimitPlanOverride {
	document, err := Decode(stored.document)
	if err != nil {
		return nil
	}
	return &LimitPlanOverride{
		ID: stored.ID, LimitPlan: document.LimitPlan, Reason: stored.reason,
		CreatedAt: stored.createdAt.UTC(), ExpiresAt: canonicalOptionalTime(stored.expiresAt),
	}
}

func applicationUserView(ctx context.Context, tx pgx.Tx, scope AdminScope, applicationID string, user lockedUser, override *LimitPlanOverride) (ApplicationUser, error) {
	claims, err := identity.DecodeNormalizedClaims(user.claims)
	if err != nil {
		return ApplicationUser{}, fmt.Errorf("decode application user claims: %w", err)
	}
	var providers []string
	if err := tx.QueryRow(ctx, `
		SELECT ARRAY(
			SELECT DISTINCT provider_key
			FROM external_identities
			WHERE organization_id = $1 AND application_id = $2 AND application_user_id = $3
			ORDER BY provider_key
		)
	`, scope.OrganizationID, applicationID, scope.ApplicationUserID).Scan(&providers); err != nil {
		return ApplicationUser{}, fmt.Errorf("list application user identity providers: %w", err)
	}
	if providers == nil {
		providers = []string{}
	}
	if len(providers) == 0 {
		return ApplicationUser{}, errors.New("application user has no external identity provider")
	}
	for _, provider := range providers {
		if !identifierPattern.MatchString(provider) {
			return ApplicationUser{}, errors.New("application user has an invalid identity provider")
		}
	}
	return ApplicationUser{
		ID: scope.ApplicationUserID, EnvironmentID: scope.EnvironmentID, Status: user.status,
		IdentityProviders: providers, NormalizedClaims: claims, LimitPlanOverride: override,
		CreatedAt: user.createdAt.UTC(), LastSeenAt: canonicalOptionalTime(user.lastSeenAt),
	}, nil
}

func (store *Store) auditReplace(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, scope AdminScope, requestID string, now time.Time, overrideID string, replaced, hasExpiry bool) error {
	fields := make([]adminauth.AuditChange, 0, 4)
	limitPlan, _ := adminauth.NewPublicAuditChange("limit_plan", adminauth.AuditSet)
	reason, _ := adminauth.NewSensitiveAuditChange("reason", adminauth.AuditSet)
	fields = append(fields, limitPlan, reason)
	operation := adminauth.AuditClear
	if hasExpiry {
		operation = adminauth.AuditSet
	}
	expiry, _ := adminauth.NewPublicAuditChange("expires_at", operation)
	fields = append(fields, expiry)
	if replaced {
		previous, _ := adminauth.NewPublicAuditChange("previous_override", adminauth.AuditRevoke)
		fields = append(fields, previous)
	}
	return store.audit(ctx, tx, principal, scope, requestID, now, "admin.user_limit_override_replace", overrideID, fields)
}

func (store *Store) auditClear(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, scope AdminScope, requestID string, now time.Time, overrideID string) error {
	change, _ := adminauth.NewPublicAuditChange("limit_plan", adminauth.AuditClear)
	resourceType, resourceID := "user_override", overrideID
	if resourceID == "" {
		resourceType, resourceID = "application_user", scope.ApplicationUserID
	}
	return store.auditResource(
		ctx, tx, principal, scope, requestID, now,
		"admin.user_limit_override_clear", resourceType, resourceID,
		[]adminauth.AuditChange{change},
	)
}

func (store *Store) audit(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, scope AdminScope, requestID string, now time.Time, action, overrideID string, changes []adminauth.AuditChange) error {
	return store.auditResource(ctx, tx, principal, scope, requestID, now, action, "user_override", overrideID, changes)
}

func (store *Store) auditResource(
	ctx context.Context,
	tx pgx.Tx,
	principal adminauth.Principal,
	scope AdminScope,
	requestID string,
	now time.Time,
	action string,
	resourceType string,
	resourceID string,
	changes []adminauth.AuditChange,
) error {
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate user override audit ID: %w", err)
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
	mutation, err := adminauth.NewAuditMutation(
		eventID, scope.OrganizationID, scope.EnvironmentID, actor, action,
		resourceType, resourceID, adminauth.AuditSucceeded, requestID, now, changes,
	)
	if err != nil {
		return err
	}
	return adminauth.InsertAuditMutation(ctx, tx, mutation)
}

func databaseTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("read user override database time: %w", err)
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

func canonicalOptionalTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	instant := value.UTC().Truncate(time.Microsecond)
	return &instant
}

func cloneTime(value *time.Time) *time.Time {
	return canonicalOptionalTime(value)
}

func timesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.UTC().Truncate(time.Microsecond).Equal(right.UTC().Truncate(time.Microsecond))
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
