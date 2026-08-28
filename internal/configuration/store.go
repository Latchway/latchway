package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/useroverride"
)

// Store persists immutable configuration snapshots and the active pointer.
type Store struct {
	pool      *pgxpool.Pool
	validator *Validator
	now       func() time.Time
}

// NewStore constructs the configuration store and compiles the canonical
// validation assets before accepting traffic.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("configuration database pool is nil")
	}
	validator, err := NewValidator()
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, validator: validator, now: time.Now}, nil
}

// CreateRevision creates a mutable draft from an explicit document or the
// current active revision.
func (store *Store) CreateRevision(ctx context.Context, principal adminauth.Principal, input CreateInput) (Revision, error) {
	if !canWrite(principal) {
		return Revision{}, ErrForbidden
	}
	if id.Validate(input.EnvironmentID, id.Environment) != nil ||
		(input.BaseRevisionID == "") == (len(input.Document) == 0) ||
		len(input.Description) > 512 || strings.ContainsRune(input.Description, '\x00') {
		return Revision{}, ErrInvalid
	}
	if input.BaseRevisionID != "" && id.Validate(input.BaseRevisionID, id.ConfigRevision) != nil {
		return Revision{}, ErrInvalid
	}
	var document json.RawMessage
	if len(input.Document) != 0 {
		var err error
		document, err = canonicalDocument(input.Document)
		if err != nil {
			return Revision{}, err
		}
		if issues := store.validator.SchemaIssues(document); len(issues) != 0 {
			return Revision{}, &ValidationFailure{Issues: issues}
		}
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, fmt.Errorf("begin configuration draft creation: %w", err)
	}
	defer rollback(tx)
	environment, activeRevisionID, err := store.environment(ctx, tx, principal.OrganizationID, input.EnvironmentID, true)
	if err != nil {
		return Revision{}, err
	}
	baseRevisionID := activeRevisionID
	if input.BaseRevisionID != "" {
		if activeRevisionID == "" || input.BaseRevisionID != activeRevisionID {
			return Revision{}, ErrConflict
		}
		base, getErr := store.revision(ctx, tx, principal.OrganizationID, input.BaseRevisionID, false)
		if getErr != nil {
			return Revision{}, getErr
		}
		if base.State != StateActive || base.EnvironmentID != input.EnvironmentID {
			return Revision{}, ErrConflict
		}
		document = append(json.RawMessage(nil), base.Document...)
	}
	revisionID, err := id.New(id.ConfigRevision)
	if err != nil {
		return Revision{}, err
	}
	var version int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(revision_number), 0) + 1
		FROM config_revisions
		WHERE environment_id = $1
	`, input.EnvironmentID).Scan(&version); err != nil {
		return Revision{}, fmt.Errorf("allocate configuration revision number: %w", err)
	}
	editVersion := int64(1)
	etag := revisionETag(revisionID, editVersion, document)
	now := store.now().UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, created_by_admin_user_id,
			created_at, base_config_revision_id, description, edit_version
		) VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, NULLIF($10, ''), NULLIF($11, ''), $12)
	`, revisionID, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID,
		version, etag, document, principal.AdminUserID, now, baseRevisionID,
		strings.TrimSpace(input.Description), editVersion); err != nil {
		return Revision{}, mapDatabaseError("insert configuration draft", err)
	}
	if err := store.audit(ctx, tx, principal, environment.OrganizationID, environment.EnvironmentID,
		"admin.configuration_revision_create", revisionID,
		[]auditField{{name: "document", sensitive: true}, {name: "base_revision_id"}}); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, mapDatabaseError("commit configuration draft creation", err)
	}
	return Revision{
		ID: revisionID, EnvironmentID: input.EnvironmentID, State: StateDraft,
		Version: version, Document: append(json.RawMessage(nil), document...), CreatedAt: now,
		CreatedBy: principal.AdminUserID, ETag: etag, organizationID: environment.OrganizationID,
		applicationID: environment.ApplicationID, baseRevisionID: baseRevisionID,
		storedState: StateDraft, editVersion: editVersion,
	}, nil
}

// ReplaceDraft replaces the entire document of a mutable draft using a strong
// ETag. Invalid revisions remain editable and return to draft state.
func (store *Store) ReplaceDraft(ctx context.Context, principal adminauth.Principal, revisionID, ifMatch string, document json.RawMessage) (Revision, error) {
	if !canWrite(principal) {
		return Revision{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return Revision{}, ErrInvalid
	}
	canonical, err := canonicalDocument(document)
	if err != nil {
		return Revision{}, err
	}
	if issues := store.validator.SchemaIssues(canonical); len(issues) != 0 {
		return Revision{}, &ValidationFailure{Issues: issues}
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, fmt.Errorf("begin configuration draft replacement: %w", err)
	}
	defer rollback(tx)
	revision, err := store.revision(ctx, tx, principal.OrganizationID, revisionID, true)
	if err != nil {
		return Revision{}, err
	}
	if revision.storedState != StateDraft && revision.storedState != StateInvalid {
		return Revision{}, ErrConflict
	}
	if revision.ETag != ifMatch {
		return Revision{}, ErrETagMismatch
	}
	editVersion := revision.editVersion + 1
	etag := revisionETag(revisionID, editVersion, canonical)
	if _, err := tx.Exec(ctx, `
		UPDATE config_revisions
		SET document = $2, etag = $3, edit_version = $4, status = 'draft',
			compiled_document = NULL, validation_errors = NULL,
			validation_report = NULL, validated_at = NULL
		WHERE config_revision_id = $1
	`, revisionID, canonical, etag, editVersion); err != nil {
		return Revision{}, mapDatabaseError("replace configuration draft", err)
	}
	if err := store.audit(ctx, tx, principal, revision.organizationID, revision.EnvironmentID,
		"admin.configuration_revision_update", revisionID,
		[]auditField{{name: "document", sensitive: true}}); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, mapDatabaseError("commit configuration draft replacement", err)
	}
	revision.State = StateDraft
	revision.storedState = StateDraft
	revision.Document = append(json.RawMessage(nil), canonical...)
	revision.Validation = nil
	revision.compiled = nil
	revision.ETag = etag
	revision.editVersion = editVersion
	return revision, nil
}

// ValidateRevision compiles a mutable revision and freezes it when valid.
func (store *Store) ValidateRevision(ctx context.Context, principal adminauth.Principal, revisionID string) (ValidationReport, error) {
	if !canWrite(principal) {
		return ValidationReport{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return ValidationReport{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ValidationReport{}, fmt.Errorf("begin configuration validation: %w", err)
	}
	defer rollback(tx)
	revision, err := store.revision(ctx, tx, principal.OrganizationID, revisionID, true)
	if err != nil {
		return ValidationReport{}, err
	}
	if revision.storedState == StateValid {
		if revision.Validation == nil {
			return ValidationReport{}, errors.New("validated configuration revision has no report")
		}
		return *revision.Validation, nil
	}
	if revision.storedState != StateDraft && revision.storedState != StateInvalid {
		return ValidationReport{}, ErrConflict
	}
	// Validation is the transition that makes a document capable of retaining
	// a secret reference indefinitely. Serialize it with secret lifecycle
	// writes on the shared environment row so destruction cannot race a draft
	// into the valid state after the reference check.
	environment, _, err := store.environment(ctx, tx, principal.OrganizationID, revision.EnvironmentID, true)
	if err != nil {
		return ValidationReport{}, err
	}
	report, compiled := store.validator.Validate(revision.Document, environment, store.now().UTC())
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return ValidationReport{}, fmt.Errorf("encode configuration validation report: %w", err)
	}
	errorJSON, err := json.Marshal(errorIssues(report.Issues))
	if err != nil {
		return ValidationReport{}, fmt.Errorf("encode configuration validation errors: %w", err)
	}
	state := StateInvalid
	if report.Valid {
		state = StateValid
	}
	if _, err := tx.Exec(ctx, `
		UPDATE config_revisions
		SET status = $2, compiled_document = $3, validation_errors = $4,
			validation_report = $5, validated_at = $6
		WHERE config_revision_id = $1
	`, revisionID, state, nullableJSON(compiled), errorJSON, reportJSON, report.CheckedAt); err != nil {
		return ValidationReport{}, mapDatabaseError("persist configuration validation", err)
	}
	if err := store.audit(ctx, tx, principal, revision.organizationID, revision.EnvironmentID,
		"admin.configuration_revision_validate", revisionID,
		[]auditField{{name: "validation_status"}}); err != nil {
		return ValidationReport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ValidationReport{}, mapDatabaseError("commit configuration validation", err)
	}
	return report, nil
}

// PlanRevision returns a value-free structural diff against the current
// active revision.
func (store *Store) PlanRevision(ctx context.Context, principal adminauth.Principal, revisionID string) (Plan, error) {
	if !canWrite(principal) {
		return Plan{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return Plan{}, ErrInvalid
	}
	target, err := store.revision(ctx, store.pool, principal.OrganizationID, revisionID, false)
	if err != nil {
		return Plan{}, err
	}
	if target.State != StateValid || target.Validation == nil || !target.Validation.Valid {
		return Plan{}, ErrConfigurationInvalid
	}
	active, err := store.activeRevision(ctx, store.pool, principal.OrganizationID, target.EnvironmentID)
	if err != nil {
		return Plan{}, err
	}
	changes, err := structuralDiff(active.Document, target.Document)
	if err != nil {
		return Plan{}, err
	}
	warnings := make([]Issue, 0)
	for _, issue := range target.Validation.Issues {
		if issue.Severity == "warning" {
			warnings = append(warnings, issue)
		}
	}
	return Plan{FromRevisionID: active.ID, ToRevisionID: target.ID, Changes: changes, Warnings: warnings}, nil
}

// ActivateRevision atomically checks the immutable compiled snapshot, base
// pointer, ETag, active pointer, notification, and audit evidence.
func (store *Store) ActivateRevision(ctx context.Context, principal adminauth.Principal, revisionID, ifMatch string) (Revision, error) {
	if !canWrite(principal) {
		return Revision{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return Revision{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, fmt.Errorf("begin configuration activation: %w", err)
	}
	defer rollback(tx)
	revision, err := store.revision(ctx, tx, principal.OrganizationID, revisionID, true)
	if err != nil {
		return Revision{}, err
	}
	environment, activeRevisionID, err := store.environment(ctx, tx, principal.OrganizationID, revision.EnvironmentID, true)
	if err != nil {
		return Revision{}, err
	}
	if revision.ETag != ifMatch {
		return Revision{}, ErrETagMismatch
	}
	if revision.storedState != StateValid || revision.Validation == nil || !revision.Validation.Valid || len(revision.compiled) == 0 {
		return Revision{}, ErrConfigurationInvalid
	}
	// Recheck the persisted compiled artifact at activation time. This protects
	// upgrades that add stricter runtime invariants from activating a revision
	// whose older validation report can no longer be loaded safely.
	candidate, err := newActiveSnapshot(revision.ID, environment.EnvironmentID, revision.Document, revision.compiled)
	if err != nil {
		return Revision{}, ErrConfigurationInvalid
	}
	if revision.ActivatedAt != nil || revision.baseRevisionID != activeRevisionID || activeRevisionID == revision.ID {
		return Revision{}, ErrConflict
	}
	if err := validateActiveUserOverrides(ctx, tx, environment, candidate); err != nil {
		return Revision{}, err
	}
	now := store.now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE config_revisions
		SET activated_at = $2
		WHERE config_revision_id = $1 AND activated_at IS NULL
	`, revisionID, now); err != nil {
		return Revision{}, mapDatabaseError("record configuration activation", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO active_config_revisions (
			organization_id, application_id, environment_id, config_revision_id,
			revision_status, activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, 'valid', $5, $6)
		ON CONFLICT (environment_id) DO UPDATE
		SET organization_id = EXCLUDED.organization_id,
			application_id = EXCLUDED.application_id,
			config_revision_id = EXCLUDED.config_revision_id,
			revision_status = 'valid',
			activated_by_admin_user_id = EXCLUDED.activated_by_admin_user_id,
			activated_at = EXCLUDED.activated_at
	`, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID,
		revisionID, principal.AdminUserID, now); err != nil {
		return Revision{}, mapDatabaseError("move active configuration pointer", err)
	}
	if err := store.audit(ctx, tx, principal, environment.OrganizationID, environment.EnvironmentID,
		"admin.configuration_activate", revisionID,
		[]auditField{{name: "active_revision_id"}}); err != nil {
		return Revision{}, err
	}
	if err := notifyConfigurationChanged(ctx, tx, environment, revisionID); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, mapDatabaseError("commit configuration activation", err)
	}
	revision.State = StateActive
	revision.ActivatedAt = &now
	return revision, nil
}

// Rollback atomically points an environment at an exact previously activated
// compiled snapshot. It never updates the target revision row.
func (store *Store) Rollback(ctx context.Context, principal adminauth.Principal, environmentID, targetRevisionID, ifMatch string) (Revision, error) {
	if !canWrite(principal) {
		return Revision{}, ErrForbidden
	}
	if id.Validate(environmentID, id.Environment) != nil || id.Validate(targetRevisionID, id.ConfigRevision) != nil {
		return Revision{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, fmt.Errorf("begin configuration rollback: %w", err)
	}
	defer rollback(tx)
	environment, activeRevisionID, err := store.environment(ctx, tx, principal.OrganizationID, environmentID, true)
	if err != nil {
		return Revision{}, err
	}
	if activeRevisionID == "" {
		return Revision{}, ErrNotFound
	}
	active, err := store.revision(ctx, tx, principal.OrganizationID, activeRevisionID, false)
	if err != nil {
		return Revision{}, err
	}
	if active.ETag != ifMatch {
		return Revision{}, ErrETagMismatch
	}
	if activeRevisionID == targetRevisionID {
		return Revision{}, ErrConflict
	}
	target, err := store.revision(ctx, tx, principal.OrganizationID, targetRevisionID, false)
	if err != nil {
		return Revision{}, err
	}
	if target.EnvironmentID != environmentID || target.storedState != StateValid || target.ActivatedAt == nil ||
		target.Validation == nil || !target.Validation.Valid || len(target.compiled) == 0 {
		return Revision{}, ErrConfigurationInvalid
	}
	targetSnapshot, err := newActiveSnapshot(target.ID, environment.EnvironmentID, target.Document, target.compiled)
	if err != nil {
		return Revision{}, ErrConfigurationInvalid
	}
	if err := validateActiveUserOverrides(ctx, tx, environment, targetSnapshot); err != nil {
		return Revision{}, err
	}
	now := store.now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE active_config_revisions
		SET config_revision_id = $2, revision_status = 'valid',
			activated_by_admin_user_id = $3, activated_at = $4
		WHERE environment_id = $1
	`, environmentID, targetRevisionID, principal.AdminUserID, now); err != nil {
		return Revision{}, mapDatabaseError("move active configuration pointer for rollback", err)
	}
	if err := store.audit(ctx, tx, principal, environment.OrganizationID, environment.EnvironmentID,
		"admin.configuration_rollback", targetRevisionID,
		[]auditField{{name: "active_revision_id"}}); err != nil {
		return Revision{}, err
	}
	if err := notifyConfigurationChanged(ctx, tx, environment, targetRevisionID); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, mapDatabaseError("commit configuration rollback", err)
	}
	target.State = StateActive
	return target, nil
}

// GetRevision returns one tenant-scoped revision.
func (store *Store) GetRevision(ctx context.Context, principal adminauth.Principal, revisionID string) (Revision, error) {
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return Revision{}, ErrInvalid
	}
	return store.revision(ctx, store.pool, principal.OrganizationID, revisionID, false)
}

// GetActiveRevision returns the Admin API representation selected by the
// environment's active pointer.
func (store *Store) GetActiveRevision(ctx context.Context, principal adminauth.Principal, environmentID string) (Revision, error) {
	if id.Validate(environmentID, id.Environment) != nil {
		return Revision{}, ErrInvalid
	}
	return store.activeRevision(ctx, store.pool, principal.OrganizationID, environmentID)
}

// ListRevisions returns a descending, tenant-scoped keyset page plus one item
// so the HTTP layer can determine has_more without a count query.
func (store *Store) ListRevisions(ctx context.Context, principal adminauth.Principal, environmentID string, page PageRequest) ([]Revision, error) {
	if id.Validate(environmentID, id.Environment) != nil || page.Size < 1 || page.Size > 200 ||
		page.Before.IsZero() != (page.BeforeID == "") {
		return nil, ErrInvalid
	}
	if page.BeforeID != "" && id.Validate(page.BeforeID, id.ConfigRevision) != nil {
		return nil, ErrInvalid
	}
	var before any
	var beforeID any
	if !page.Before.IsZero() {
		before = page.Before.UTC()
		beforeID = page.BeforeID
	}
	rows, err := store.pool.Query(ctx, revisionSelect+`
		WHERE revision.organization_id = $1
		  AND revision.environment_id = $2
		  AND ($3::timestamptz IS NULL OR (revision.created_at, revision.config_revision_id) < ($3, $4::text))
		ORDER BY revision.created_at DESC, revision.config_revision_id DESC
		LIMIT $5
	`, principal.OrganizationID, environmentID, before, beforeID, page.Size+1)
	if err != nil {
		return nil, fmt.Errorf("list configuration revisions: %w", err)
	}
	defer rows.Close()
	items := make([]Revision, 0, page.Size+1)
	for rows.Next() {
		revision, scanErr := scanRevision(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, revision)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate configuration revisions: %w", err)
	}
	return items, nil
}

// ActiveSnapshot resolves the exact compiled snapshot for internal data-plane
// consumers. All returned JSON and lookup values are defensive copies.
func (store *Store) ActiveSnapshot(ctx context.Context, scope TenantScope) (ActiveSnapshot, error) {
	if id.Validate(scope.OrganizationID, id.Organization) != nil || id.Validate(scope.ApplicationID, id.Application) != nil || id.Validate(scope.EnvironmentID, id.Environment) != nil {
		return ActiveSnapshot{}, ErrInvalid
	}
	var revisionID string
	var document, compiled []byte
	if err := store.pool.QueryRow(ctx, `
		SELECT revision.config_revision_id, revision.document, revision.compiled_document
		FROM active_config_revisions AS active_revision
		JOIN config_revisions AS revision
		  ON revision.organization_id = active_revision.organization_id
		 AND revision.application_id = active_revision.application_id
		 AND revision.environment_id = active_revision.environment_id
		 AND revision.config_revision_id = active_revision.config_revision_id
		 AND revision.status = 'valid'
		WHERE active_revision.organization_id = $1
		  AND active_revision.application_id = $2
		  AND active_revision.environment_id = $3
	`, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID).Scan(&revisionID, &document, &compiled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ActiveSnapshot{}, ErrNotFound
		}
		return ActiveSnapshot{}, fmt.Errorf("resolve active compiled configuration: %w", err)
	}
	if len(compiled) == 0 {
		return ActiveSnapshot{}, errors.New("active configuration has no compiled snapshot")
	}
	return newActiveSnapshot(revisionID, scope.EnvironmentID, document, compiled)
}

// SimulationSnapshot returns the exact compiled policy for a tenant-scoped
// valid draft or the currently active revision. Superseded and invalid
// revisions are deliberately excluded so the simulator cannot imply that an
// obsolete or non-executable document represents deployable behavior.
func (store *Store) SimulationSnapshot(
	ctx context.Context,
	principal adminauth.Principal,
	revisionID string,
) (SimulationSnapshot, error) {
	if !canWrite(principal) {
		return SimulationSnapshot{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return SimulationSnapshot{}, ErrInvalid
	}
	revision, err := store.revision(ctx, store.pool, principal.OrganizationID, revisionID, false)
	if err != nil {
		return SimulationSnapshot{}, err
	}
	if revision.State != StateValid && revision.State != StateActive {
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

const revisionSelect = `
	SELECT
		revision.config_revision_id,
		revision.organization_id,
		revision.application_id,
		revision.environment_id,
		revision.revision_number,
		revision.etag,
		revision.status,
		revision.document,
		revision.compiled_document,
		revision.validation_report,
		revision.created_by_admin_user_id,
		revision.created_at,
		revision.activated_at,
		revision.base_config_revision_id,
		revision.edit_version,
		CASE
			WHEN active_revision.config_revision_id = revision.config_revision_id THEN 'active'
			WHEN revision.activated_at IS NOT NULL THEN 'superseded'
			ELSE revision.status
		END AS derived_state
	FROM config_revisions AS revision
	LEFT JOIN active_config_revisions AS active_revision
	  ON active_revision.environment_id = revision.environment_id
`

type databaseQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (store *Store) revision(ctx context.Context, query databaseQuery, organizationID, revisionID string, forUpdate bool) (Revision, error) {
	statement := revisionSelect + `
		WHERE revision.organization_id = $1
		  AND revision.config_revision_id = $2
	`
	if forUpdate {
		statement += " FOR UPDATE OF revision"
	}
	revision, err := scanRevision(query.QueryRow(ctx, statement, organizationID, revisionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Revision{}, ErrNotFound
	}
	return revision, err
}

func (store *Store) activeRevision(ctx context.Context, query databaseQuery, organizationID, environmentID string) (Revision, error) {
	revision, err := scanRevision(query.QueryRow(ctx, revisionSelect+`
		WHERE revision.organization_id = $1
		  AND revision.environment_id = $2
		  AND active_revision.config_revision_id = revision.config_revision_id
	`, organizationID, environmentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Revision{}, ErrNotFound
	}
	return revision, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanRevision(row rowScanner) (Revision, error) {
	var revision Revision
	var document, compiled, validation []byte
	var activatedAt *time.Time
	var baseRevisionID *string
	var derivedState string
	if err := row.Scan(
		&revision.ID, &revision.organizationID, &revision.applicationID, &revision.EnvironmentID,
		&revision.Version, &revision.ETag, &revision.storedState, &document, &compiled,
		&validation, &revision.CreatedBy, &revision.CreatedAt, &activatedAt,
		&baseRevisionID, &revision.editVersion, &derivedState,
	); err != nil {
		return Revision{}, err
	}
	revision.State = derivedState
	revision.Document = append(json.RawMessage(nil), document...)
	revision.compiled = append(json.RawMessage(nil), compiled...)
	if activatedAt != nil {
		instant := activatedAt.UTC()
		revision.ActivatedAt = &instant
	}
	if baseRevisionID != nil {
		revision.baseRevisionID = *baseRevisionID
	}
	if len(validation) != 0 {
		var report ValidationReport
		if err := json.Unmarshal(validation, &report); err != nil {
			return Revision{}, fmt.Errorf("decode stored configuration validation report: %w", err)
		}
		revision.Validation = &report
	}
	return revision, nil
}

func (store *Store) environment(ctx context.Context, query databaseQuery, organizationID, environmentID string, forUpdate bool) (EnvironmentDescriptor, string, error) {
	statement := `
		SELECT organization.organization_id, application.application_id, environment.environment_id,
			organization.slug, application.slug, environment.slug, environment.kind
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE environment.organization_id = $1
		  AND environment.environment_id = $2
		  AND environment.status = 'active'
		  AND application.status = 'active'
		  AND organization.status = 'active'
	`
	if forUpdate {
		statement += " FOR UPDATE OF environment"
	}
	var descriptor EnvironmentDescriptor
	if err := query.QueryRow(ctx, statement, organizationID, environmentID).Scan(
		&descriptor.OrganizationID, &descriptor.ApplicationID, &descriptor.EnvironmentID,
		&descriptor.OrganizationSlug, &descriptor.ApplicationSlug, &descriptor.EnvironmentSlug,
		&descriptor.EnvironmentKind,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EnvironmentDescriptor{}, "", ErrNotFound
		}
		return EnvironmentDescriptor{}, "", fmt.Errorf("read configuration environment: %w", err)
	}
	pointerStatement := `
		SELECT config_revision_id
		FROM active_config_revisions
		WHERE organization_id = $1 AND environment_id = $2
	`
	if forUpdate {
		pointerStatement += " FOR UPDATE"
	}
	var activeRevisionID string
	if err := query.QueryRow(ctx, pointerStatement, organizationID, environmentID).Scan(&activeRevisionID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return EnvironmentDescriptor{}, "", fmt.Errorf("read active configuration pointer: %w", err)
	}
	descriptor.SecretNames = make(map[string]struct{})
	rows, err := query.Query(ctx, `
		SELECT name
		FROM secret_records
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND rotated_at IS NULL AND destroyed_at IS NULL
		ORDER BY name
	`, descriptor.OrganizationID, descriptor.ApplicationID, descriptor.EnvironmentID)
	if err != nil {
		return EnvironmentDescriptor{}, "", fmt.Errorf("list configuration secret references: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return EnvironmentDescriptor{}, "", fmt.Errorf("scan configuration secret reference: %w", err)
		}
		descriptor.SecretNames[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return EnvironmentDescriptor{}, "", fmt.Errorf("iterate configuration secret references: %w", err)
	}
	return descriptor, activeRevisionID, nil
}

func canonicalDocument(document json.RawMessage) (json.RawMessage, error) {
	value, err := jsonsafe.Decode(document)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	return canonical, nil
}

func revisionETag(revisionID string, editVersion int64, document json.RawMessage) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(revisionID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(strconv.FormatInt(editVersion, 10)))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(document)
	return `"cfg-` + base64.RawURLEncoding.EncodeToString(digest.Sum(nil)) + `"`
}

func errorIssues(issues []Issue) []Issue {
	result := make([]Issue, 0)
	for _, issue := range issues {
		if issue.Severity == "error" {
			result = append(result, issue)
		}
	}
	return result
}

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func canWrite(principal adminauth.Principal) bool {
	return principal.Allows(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{})
}

// validateActiveUserOverrides rejects a candidate snapshot that would strand
// an active user limit-plan override. Callers already hold the environment
// lock. This query deliberately takes no user or override row locks, preserving
// the application-user-before-environment mutation lock order.
func validateActiveUserOverrides(ctx context.Context, query databaseQuery, environment EnvironmentDescriptor, snapshot ActiveSnapshot) error {
	rows, err := query.Query(ctx, `
		SELECT override_document
		FROM user_overrides
		WHERE organization_id = $1
		  AND application_id = $2
		  AND environment_id = $3
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > statement_timestamp())
		ORDER BY user_override_id
	`, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID)
	if err != nil {
		return fmt.Errorf("list active user overrides for configuration: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return fmt.Errorf("scan active user override for configuration: %w", err)
		}
		document, err := useroverride.Decode(encoded)
		if err != nil {
			return ErrConfigurationInvalid
		}
		if _, ok := snapshot.LimitPlan(document.LimitPlan); !ok {
			return ErrConfigurationInvalid
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate active user overrides for configuration: %w", err)
	}
	return nil
}

type auditField struct {
	name      string
	sensitive bool
}

func (store *Store) audit(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, organizationID, environmentID, action, revisionID string, fields []auditField) error {
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
		var change adminauth.AuditChange
		if field.sensitive {
			change, err = adminauth.NewSensitiveAuditChange(field.name, adminauth.AuditSet)
		} else {
			change, err = adminauth.NewPublicAuditChange(field.name, adminauth.AuditSet)
		}
		if err != nil {
			return err
		}
		changes = append(changes, change)
	}
	mutation, err := adminauth.NewAuditMutation(
		eventID, organizationID, environmentID, actor, action,
		"configuration_revision", revisionID, adminauth.AuditSucceeded,
		requestID, store.now().UTC(), changes,
	)
	if err != nil {
		return err
	}
	return adminauth.InsertAuditMutation(ctx, tx, mutation)
}

func notifyConfigurationChanged(ctx context.Context, tx pgx.Tx, environment EnvironmentDescriptor, revisionID string) error {
	payload, err := json.Marshal(map[string]string{
		"organization_id": environment.OrganizationID,
		"application_id":  environment.ApplicationID,
		"environment_id":  environment.EnvironmentID,
		"revision_id":     revisionID,
	})
	if err != nil {
		return fmt.Errorf("encode configuration notification: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify('latchway_config_changed', $1)", string(payload)); err != nil {
		return fmt.Errorf("queue configuration notification: %w", err)
	}
	return nil
}

func mapDatabaseError(operation string, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505", "40001", "40P01", "55000":
			return ErrConflict
		case "23503":
			return ErrNotFound
		case "23514", "22001", "22P02":
			return ErrInvalid
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func rollback(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}
