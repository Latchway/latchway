package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

const (
	// MaxValueBytes is the largest plaintext accepted by the write-only secret
	// lifecycle. HTTP and CLI callers should reject larger values before they
	// allocate or decode them.
	MaxValueBytes = 1 << 20
)

var (
	// ErrForbidden means the principal lacks the secret-management capability.
	ErrForbidden = errors.New("secret operation forbidden")
	// ErrNotFound intentionally covers absent and cross-tenant resources.
	ErrNotFound = errors.New("secret resource not found")
	// ErrConflict means the requested lifecycle transition is stale or collides
	// with an existing logical secret.
	ErrConflict = errors.New("secret resource conflict")
	// ErrReferenced means an immutable usable configuration still names the
	// logical secret, so destroying it would strand that revision.
	ErrReferenced = errors.New("secret is referenced by configuration")
	// ErrIndeterminate means PostgreSQL may have committed the mutation but the
	// acknowledgement was lost. Callers must not report a definitive failure.
	ErrIndeterminate = errors.New("secret operation outcome is indeterminate")
)

var errEncryptionFailed = errors.New("secret encryption failed")

// ManagerConfig contains the production dependencies for secret lifecycle
// management.
type ManagerConfig struct {
	Pool     *pgxpool.Pool
	Provider Provider
}

// Manager owns tenant-scoped secret metadata and encrypted lifecycle writes.
// It never returns plaintext.
type Manager struct {
	*managerMaterial
}

type managerMaterial struct {
	pool          *pgxpool.Pool
	provider      Provider
	providerKeyID string
}

// NewManager constructs a PostgreSQL-backed secret lifecycle manager.
func NewManager(config ManagerConfig) (*Manager, error) {
	if config.Pool == nil || config.Provider == nil {
		return nil, ErrInvalid
	}
	providerKeyID := config.Provider.KeyID()
	if !masterKeyIdentifierPattern.MatchString(providerKeyID) {
		return nil, ErrInvalid
	}
	return &Manager{managerMaterial: &managerMaterial{
		pool:          config.Pool,
		provider:      config.Provider,
		providerKeyID: providerKeyID,
	}}, nil
}

// Format prevents diagnostic formatting from traversing the encryption
// provider and its key material.
func (Manager) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

// PageRequest is a descending keyset page over (created_at, secret_record_id).
type PageRequest struct {
	Before   time.Time
	BeforeID string
	Size     int32
}

// Metadata is the complete redaction-safe representation of one active secret
// version. Ciphertext and nonce are deliberately absent.
type Metadata struct {
	ID            string     `json:"id"`
	EnvironmentID string     `json:"environment_id"`
	Name          string     `json:"name"`
	Version       int64      `json:"version"`
	Algorithm     string     `json:"algorithm"`
	MasterKeyID   string     `json:"master_key_id"`
	CreatedAt     time.Time  `json:"created_at"`
	RotatedAt     *time.Time `json:"rotated_at,omitempty"`
}

// CreateInput creates the first version of a logical secret name. Value is
// consumed and cleared before Create returns, including on failure.
type CreateInput struct {
	EnvironmentID string
	Name          string
	Value         []byte `json:"-"`
	RequestID     string
}

// Format prevents accidental plaintext disclosure from diagnostic logging.
func (CreateInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

// RotateInput creates the next encrypted version of the logical secret
// identified by its current record ID. A historical ID is rejected as stale.
// Value is consumed and cleared before Rotate returns, including on failure.
type RotateInput struct {
	SecretID  string
	Value     []byte `json:"-"`
	RequestID string
}

// Format prevents accidental plaintext disclosure from diagnostic logging.
func (RotateInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

// DestroyInput tombstones every version of one logical secret. Only the
// current record ID may initiate destruction. Repeating the operation through
// that exact tombstoned ID is a safe success; historical IDs are stale.
type DestroyInput struct {
	SecretID  string
	RequestID string
}

// List returns only current, usable secret metadata. It includes one extra
// item so a transport can calculate has_more without a count query.
func (manager *Manager) List(ctx context.Context, principal adminauth.Principal, environmentID string, page PageRequest) ([]Metadata, error) {
	if !manager.authorized(ctx, principal) {
		return nil, ErrForbidden
	}
	if id.Validate(environmentID, id.Environment) != nil || page.validate() != nil {
		return nil, ErrInvalid
	}

	tx, err := manager.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin secret metadata list: %w", err)
	}
	defer rollbackManager(tx)
	if _, err := resolveSecretEnvironment(ctx, tx, principal.OrganizationID, environmentID, false); err != nil {
		return nil, err
	}

	var before any
	var beforeID any
	if !page.Before.IsZero() {
		before = page.Before.UTC()
		beforeID = page.BeforeID
	}
	rows, err := tx.Query(ctx, `
		SELECT secret_record_id, environment_id, name, version, algorithm,
		       master_key_identifier, created_at, rotated_at
		FROM secret_records
		WHERE organization_id = $1
		  AND environment_id = $2
		  AND rotated_at IS NULL
		  AND destroyed_at IS NULL
		  AND ($3::timestamptz IS NULL OR (created_at, secret_record_id) < ($3, $4::text))
		ORDER BY created_at DESC, secret_record_id DESC
		LIMIT $5
	`, principal.OrganizationID, environmentID, before, beforeID, page.Size+1)
	if err != nil {
		return nil, fmt.Errorf("list active secret metadata: %w", err)
	}
	defer rows.Close()
	items := make([]Metadata, 0, page.Size+1)
	for rows.Next() {
		metadata, scanErr := scanMetadata(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, metadata)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active secret metadata: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit secret metadata list: %w", err)
	}
	return items, nil
}

// Create encrypts and persists version one of a previously unused logical
// secret name.
func (manager *Manager) Create(ctx context.Context, principal adminauth.Principal, input CreateInput) (Metadata, error) {
	defer clear(input.Value)
	if !manager.authorized(ctx, principal) {
		return Metadata{}, ErrForbidden
	}
	if id.Validate(input.EnvironmentID, id.Environment) != nil ||
		!validSecretName(input.Name) || validateMutationRequestID(input.RequestID) != nil ||
		!validSecretValue(input.Value) {
		return Metadata{}, ErrInvalid
	}
	plaintext := append([]byte(nil), input.Value...)
	clear(input.Value)
	defer clear(plaintext)

	tx, err := manager.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Metadata{}, fmt.Errorf("begin secret creation: %w", err)
	}
	defer rollbackManager(tx)
	environment, err := resolveSecretEnvironment(ctx, tx, principal.OrganizationID, input.EnvironmentID, true)
	if err != nil {
		return Metadata{}, err
	}
	now, err := secretDatabaseTime(ctx, tx)
	if err != nil {
		return Metadata{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM secret_records
			WHERE organization_id = $1 AND application_id = $2
			  AND environment_id = $3 AND name = $4
		)
	`, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID, input.Name).Scan(&exists); err != nil {
		return Metadata{}, fmt.Errorf("check existing logical secret: %w", err)
	}
	if exists {
		return Metadata{}, ErrConflict
	}

	recordID, err := id.New(id.SecretRecord)
	if err != nil {
		return Metadata{}, fmt.Errorf("generate secret record ID: %w", err)
	}
	metadata, envelope, err := manager.encryptMetadata(environment, recordID, input.Name, 1, plaintext, now)
	if err != nil {
		return Metadata{}, err
	}
	defer clearEnvelope(envelope)
	if err := insertSecretRecord(ctx, tx, principal.AdminUserID, environment, metadata, envelope); err != nil {
		return Metadata{}, err
	}
	if err := manager.audit(ctx, tx, principal, environment, input.RequestID, now,
		"admin.secret_create", recordID, adminauth.AuditSet); err != nil {
		return Metadata{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Metadata{}, mapManagerCommitError("commit secret creation", err)
	}
	return metadata, nil
}

// Rotate serializes on the environment row, verifies the caller still holds
// the current record ID, retires it, and inserts exactly one successor.
func (manager *Manager) Rotate(ctx context.Context, principal adminauth.Principal, input RotateInput) (Metadata, error) {
	defer clear(input.Value)
	if !manager.authorized(ctx, principal) {
		return Metadata{}, ErrForbidden
	}
	if id.Validate(input.SecretID, id.SecretRecord) != nil ||
		validateMutationRequestID(input.RequestID) != nil ||
		!validSecretValue(input.Value) {
		return Metadata{}, ErrInvalid
	}
	plaintext := append([]byte(nil), input.Value...)
	clear(input.Value)
	defer clear(plaintext)

	tx, err := manager.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Metadata{}, fmt.Errorf("begin secret rotation: %w", err)
	}
	defer rollbackManager(tx)
	environment, name, err := lockSecretEnvironment(ctx, tx, principal.OrganizationID, input.SecretID)
	if err != nil {
		return Metadata{}, err
	}
	current, err := currentSecretMetadata(ctx, tx, environment, name, true)
	if err != nil {
		return Metadata{}, err
	}
	if current.ID != input.SecretID {
		return Metadata{}, ErrConflict
	}
	now, err := secretLifecycleTime(ctx, tx, environment, name)
	if err != nil {
		return Metadata{}, err
	}
	if current.Version == math.MaxInt64 {
		return Metadata{}, ErrConflict
	}
	newRecordID, err := id.New(id.SecretRecord)
	if err != nil {
		return Metadata{}, fmt.Errorf("generate rotated secret record ID: %w", err)
	}
	metadata, envelope, err := manager.encryptMetadata(environment, newRecordID, name, current.Version+1, plaintext, now)
	if err != nil {
		return Metadata{}, err
	}
	defer clearEnvelope(envelope)
	command, err := tx.Exec(ctx, `
		UPDATE secret_records
		SET rotated_at = $2
		WHERE secret_record_id = $1
		  AND rotated_at IS NULL
		  AND destroyed_at IS NULL
	`, current.ID, now)
	if err != nil {
		return Metadata{}, mapManagerDatabaseError("retire current secret version", err)
	}
	if command.RowsAffected() != 1 {
		return Metadata{}, ErrConflict
	}
	if err := insertSecretRecord(ctx, tx, principal.AdminUserID, environment, metadata, envelope); err != nil {
		return Metadata{}, err
	}
	if err := manager.audit(ctx, tx, principal, environment, input.RequestID, now,
		"admin.secret_rotate", newRecordID, adminauth.AuditRotate); err != nil {
		return Metadata{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Metadata{}, mapManagerCommitError("commit secret rotation", err)
	}
	return metadata, nil
}

// Destroy marks every retained version unavailable after proving that no
// usable immutable configuration document references the logical secret.
func (manager *Manager) Destroy(ctx context.Context, principal adminauth.Principal, input DestroyInput) error {
	if !manager.authorized(ctx, principal) {
		return ErrForbidden
	}
	if id.Validate(input.SecretID, id.SecretRecord) != nil || validateMutationRequestID(input.RequestID) != nil {
		return ErrInvalid
	}
	tx, err := manager.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin secret destruction: %w", err)
	}
	defer rollbackManager(tx)
	environment, name, err := lockSecretEnvironment(ctx, tx, principal.OrganizationID, input.SecretID)
	if err != nil {
		return err
	}
	current, currentErr := currentSecretMetadata(ctx, tx, environment, name, true)
	if currentErr != nil && !errors.Is(currentErr, ErrNotFound) {
		return currentErr
	}
	now, err := secretLifecycleTime(ctx, tx, environment, name)
	if err != nil {
		return err
	}
	if currentErr == nil {
		if current.ID != input.SecretID {
			return ErrConflict
		}
		referenced, referenceErr := secretReferencedByUsableConfiguration(ctx, tx, environment, name)
		if referenceErr != nil {
			return referenceErr
		}
		if referenced {
			return ErrReferenced
		}
		command, updateErr := tx.Exec(ctx, `
			UPDATE secret_records
			SET destroyed_at = $4
			WHERE organization_id = $1 AND application_id = $2
			  AND environment_id = $3 AND name = $5
			  AND destroyed_at IS NULL
		`, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID, now, name)
		if updateErr != nil {
			return mapManagerDatabaseError("tombstone secret versions", updateErr)
		}
		if command.RowsAffected() < 1 {
			return ErrConflict
		}
	} else {
		requestedRotated, requestedDestroyed, stateErr := secretRecordLifecycleState(ctx, tx, principal.OrganizationID, input.SecretID)
		if stateErr != nil {
			return stateErr
		}
		if requestedRotated || !requestedDestroyed {
			// The only valid idempotent replay is the record that was current when
			// destruction tombstoned the logical secret. Superseded versions retain
			// rotated_at and therefore cannot act as mutable aliases.
			return ErrConflict
		}
	}
	if err := manager.audit(ctx, tx, principal, environment, input.RequestID, now,
		"admin.secret_delete", input.SecretID, adminauth.AuditClear); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapManagerCommitError("commit secret destruction", err)
	}
	return nil
}

func (manager *Manager) authorized(ctx context.Context, principal adminauth.Principal) bool {
	return manager != nil && manager.managerMaterial != nil && manager.pool != nil && manager.provider != nil &&
		ctx != nil && id.Validate(principal.OrganizationID, id.Organization) == nil &&
		id.Validate(principal.AdminUserID, id.AdminUser) == nil &&
		principal.Allows(adminauth.ManageSecrets, adminauth.AuthorizationContext{})
}

func (page PageRequest) validate() error {
	if page.Size < 1 || page.Size > 200 || page.Before.IsZero() != (page.BeforeID == "") {
		return ErrInvalid
	}
	if page.BeforeID != "" && id.Validate(page.BeforeID, id.SecretRecord) != nil {
		return ErrInvalid
	}
	return nil
}

func validSecretName(name string) bool {
	return !strings.HasPrefix(name, "secret/") && secretReferencePattern.MatchString("secret/"+name)
}

func validSecretValue(value []byte) bool {
	return len(value) >= 1 && len(value) <= MaxValueBytes && utf8.Valid(value)
}

func validateMutationRequestID(requestID string) error {
	if requestID == "" {
		return nil
	}
	return id.Validate(requestID, id.AdminRequest)
}

type secretEnvironment struct {
	OrganizationID string
	ApplicationID  string
	EnvironmentID  string
}

type managerQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func resolveSecretEnvironment(ctx context.Context, query managerQuery, organizationID, environmentID string, forUpdate bool) (secretEnvironment, error) {
	statement := `
		SELECT organization.organization_id, application.application_id, environment.environment_id
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE environment.organization_id = $1
		  AND environment.environment_id = $2
		  AND environment.status = 'active' AND environment.disabled_at IS NULL
		  AND application.status = 'active' AND application.disabled_at IS NULL
		  AND organization.status = 'active' AND organization.disabled_at IS NULL
	`
	if forUpdate {
		statement += " FOR UPDATE OF environment"
	}
	var environment secretEnvironment
	err := query.QueryRow(ctx, statement, organizationID, environmentID).Scan(
		&environment.OrganizationID, &environment.ApplicationID, &environment.EnvironmentID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return secretEnvironment{}, ErrNotFound
	}
	if err != nil {
		return secretEnvironment{}, fmt.Errorf("resolve secret environment: %w", err)
	}
	return environment, nil
}

// lockSecretEnvironment locates a record without locking it, then locks only
// the environment row. Every secret writer therefore acquires locks in the
// same environment-before-secret order, while cross-tenant IDs remain
// indistinguishable from absent IDs.
func lockSecretEnvironment(ctx context.Context, tx pgx.Tx, organizationID, secretID string) (secretEnvironment, string, error) {
	var environment secretEnvironment
	var name string
	err := tx.QueryRow(ctx, `
		SELECT organization.organization_id, application.application_id,
		       environment.environment_id, secret.name
		FROM secret_records AS secret
		JOIN environments AS environment
		  ON environment.organization_id = secret.organization_id
		 AND environment.application_id = secret.application_id
		 AND environment.environment_id = secret.environment_id
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE secret.organization_id = $1
		  AND secret.secret_record_id = $2
		  AND environment.status = 'active' AND environment.disabled_at IS NULL
		  AND application.status = 'active' AND application.disabled_at IS NULL
		  AND organization.status = 'active' AND organization.disabled_at IS NULL
		FOR UPDATE OF environment
	`, organizationID, secretID).Scan(
		&environment.OrganizationID, &environment.ApplicationID, &environment.EnvironmentID, &name,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return secretEnvironment{}, "", ErrNotFound
	}
	if err != nil {
		return secretEnvironment{}, "", fmt.Errorf("lock secret environment: %w", err)
	}
	if !validSecretName(name) {
		return secretEnvironment{}, "", errors.New("stored secret name is invalid")
	}
	return environment, name, nil
}

// secretRecordLifecycleState runs in a fresh READ COMMITTED statement after
// the environment lock has been acquired. A concurrent deletion that was
// already in flight therefore observes the committed tombstone and remains
// idempotent rather than retaining pre-wait state from the locking query.
func secretRecordLifecycleState(ctx context.Context, tx pgx.Tx, organizationID, secretID string) (bool, bool, error) {
	var rotated, destroyed bool
	err := tx.QueryRow(ctx, `
		SELECT rotated_at IS NOT NULL, destroyed_at IS NOT NULL
		FROM secret_records
		WHERE organization_id = $1 AND secret_record_id = $2
	`, organizationID, secretID).Scan(&rotated, &destroyed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, ErrNotFound
	}
	if err != nil {
		return false, false, fmt.Errorf("read secret record lifecycle state: %w", err)
	}
	return rotated, destroyed, nil
}

func secretDatabaseTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("read secret database time: %w", err)
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

// secretLifecycleTime floors wall-clock time at the latest persisted version
// timestamp. This preserves lifecycle constraints and ordering if the database
// clock steps backward while the environment writer lock is held.
func secretLifecycleTime(ctx context.Context, tx pgx.Tx, environment secretEnvironment, name string) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `
		SELECT GREATEST(clock_timestamp(), COALESCE(max(created_at), '-infinity'::timestamptz))
		FROM secret_records
		WHERE organization_id = $1 AND application_id = $2
		  AND environment_id = $3 AND name = $4
	`, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID, name).Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("read monotonic secret lifecycle time: %w", err)
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

func (manager *Manager) encryptMetadata(environment secretEnvironment, recordID, name string, version int64, plaintext []byte, now time.Time) (Metadata, Envelope, error) {
	envelope, err := manager.provider.Encrypt(plaintext, AssociatedData{
		OrganizationID: environment.OrganizationID,
		EnvironmentID:  environment.EnvironmentID,
		SecretID:       recordID,
		SecretVersion:  version,
		FormatVersion:  formatVersion,
	})
	if err != nil {
		clearEnvelope(envelope)
		return Metadata{}, Envelope{}, errEncryptionFailed
	}
	if envelope.FormatVersion != formatVersion || envelope.Algorithm != algorithm ||
		envelope.KeyID != manager.providerKeyID || !masterKeyIdentifierPattern.MatchString(envelope.KeyID) ||
		len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 17 {
		clearEnvelope(envelope)
		return Metadata{}, Envelope{}, errEncryptionFailed
	}
	return Metadata{
		ID: recordID, EnvironmentID: environment.EnvironmentID, Name: name,
		Version: version, Algorithm: storedEnvelopeAlgorithm,
		MasterKeyID: envelope.KeyID, CreatedAt: now,
	}, envelope, nil
}

func insertSecretRecord(ctx context.Context, tx pgx.Tx, adminUserID string, environment secretEnvironment, metadata Metadata, envelope Envelope) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO secret_records (
			secret_record_id, organization_id, application_id, environment_id,
			name, version, encryption_format_version, algorithm,
			master_key_identifier, ciphertext, nonce,
			created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'aes-256-gcm', $8, $9, $10, $11, $12)
	`, metadata.ID, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID,
		metadata.Name, metadata.Version, int16(envelope.FormatVersion), envelope.KeyID,
		envelope.Ciphertext, envelope.Nonce, adminUserID, metadata.CreatedAt)
	if err != nil {
		return mapManagerDatabaseError("insert encrypted secret record", err)
	}
	return nil
}

func currentSecretMetadata(ctx context.Context, tx pgx.Tx, environment secretEnvironment, name string, forUpdate bool) (Metadata, error) {
	statement := `
		SELECT secret_record_id, environment_id, name, version, algorithm,
		       master_key_identifier, created_at, rotated_at
		FROM secret_records
		WHERE organization_id = $1 AND application_id = $2
		  AND environment_id = $3 AND name = $4
		  AND rotated_at IS NULL AND destroyed_at IS NULL
	`
	if forUpdate {
		statement += " FOR UPDATE"
	}
	metadata, err := scanMetadata(tx.QueryRow(ctx, statement,
		environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	return metadata, err
}

type metadataScanner interface {
	Scan(...any) error
}

func scanMetadata(scanner metadataScanner) (Metadata, error) {
	var metadata Metadata
	if err := scanner.Scan(
		&metadata.ID, &metadata.EnvironmentID, &metadata.Name, &metadata.Version,
		&metadata.Algorithm, &metadata.MasterKeyID, &metadata.CreatedAt, &metadata.RotatedAt,
	); err != nil {
		return Metadata{}, err
	}
	metadata.CreatedAt = metadata.CreatedAt.UTC()
	if metadata.RotatedAt != nil {
		instant := metadata.RotatedAt.UTC()
		metadata.RotatedAt = &instant
	}
	if id.Validate(metadata.ID, id.SecretRecord) != nil || id.Validate(metadata.EnvironmentID, id.Environment) != nil ||
		!validSecretName(metadata.Name) || metadata.Version < 1 ||
		metadata.Algorithm != storedEnvelopeAlgorithm || !masterKeyIdentifierPattern.MatchString(metadata.MasterKeyID) ||
		metadata.CreatedAt.IsZero() {
		return Metadata{}, errors.New("stored secret metadata is invalid")
	}
	return metadata, nil
}

// PostgreSQL stores valid, active, and superseded documents uniformly as
// status='valid'; activated_at and the active pointer distinguish their public
// states. All three therefore block destruction.
func secretReferencedByUsableConfiguration(ctx context.Context, tx pgx.Tx, environment secretEnvironment, name string) (bool, error) {
	var referenced bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM config_revisions AS revision
			WHERE revision.organization_id = $1
			  AND revision.application_id = $2
			  AND revision.environment_id = $3
			  AND revision.status = 'valid'
			  AND (
				jsonb_path_exists(revision.document, '$.spec.identityProviders[*].staticPublicKeySecretRef ? (@ == $reference)'::jsonpath,
					jsonb_build_object('reference', to_jsonb($4::text)))
				OR jsonb_path_exists(revision.document, '$.spec.identityProviders[*].symmetricSecretRef ? (@ == $reference)'::jsonpath,
					jsonb_build_object('reference', to_jsonb($4::text)))
				OR jsonb_path_exists(revision.document, '$.spec.attestationPolicies[*].platforms.*.secretRef ? (@ == $reference)'::jsonpath,
					jsonb_build_object('reference', to_jsonb($4::text)))
				OR jsonb_path_exists(revision.document, '$.spec.upstreams[*].authentication.secretRef ? (@ == $reference)'::jsonpath,
					jsonb_build_object('reference', to_jsonb($4::text)))
			  )
		)
	`, environment.OrganizationID, environment.ApplicationID, environment.EnvironmentID, "secret/"+name).Scan(&referenced)
	if err != nil {
		return false, fmt.Errorf("check configuration secret references: %w", err)
	}
	return referenced, nil
}

func (manager *Manager) audit(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, environment secretEnvironment, requestID string, now time.Time, action, recordID string, operation adminauth.AuditOperation) error {
	eventID, err := id.New(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate secret audit event ID: %w", err)
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
	change, err := adminauth.NewSensitiveAuditChange("value", operation)
	if err != nil {
		return err
	}
	mutation, err := adminauth.NewAuditMutation(
		eventID, environment.OrganizationID, environment.EnvironmentID, actor,
		action, "secret_record", recordID, adminauth.AuditSucceeded,
		requestID, now, []adminauth.AuditChange{change},
	)
	if err != nil {
		return err
	}
	return adminauth.InsertAuditMutation(ctx, tx, mutation)
}

func clearEnvelope(envelope Envelope) {
	clear(envelope.Nonce)
	clear(envelope.Ciphertext)
}

func mapManagerDatabaseError(operation string, err error) error {
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

func mapManagerCommitError(operation string, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return mapManagerDatabaseError(operation, err)
	}
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return fmt.Errorf("%s: %w", operation, err)
	}
	// A transport/context error while COMMIT is in flight cannot distinguish a
	// rollback from a committed transaction whose acknowledgement was lost.
	// Do not wrap the transport error because it may contain endpoint details.
	return fmt.Errorf("%w: %s", ErrIndeterminate, operation)
}

func rollbackManager(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}
