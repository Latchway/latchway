package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrInvalid is returned for malformed requests or stored envelope
	// metadata. It deliberately carries no record contents.
	ErrInvalid = errors.New("secret request or record is invalid")
	// ErrUnavailable covers absent, inactive, inaccessible, and
	// unauthenticatable secrets without revealing which condition occurred.
	ErrUnavailable = errors.New("secret is unavailable")
)

var (
	secretReferencePattern     = regexp.MustCompile(`^secret/[a-z][a-z0-9_-]{0,62}$`)
	masterKeyIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const storedEnvelopeAlgorithm = "aes-256-gcm"

// Scope selects one exact organization application environment. Every field
// is required even though environment identifiers are globally unique.
type Scope struct {
	OrganizationID string
	ApplicationID  string
	EnvironmentID  string
}

// StoreConfig contains the runtime dependencies for encrypted secret reads.
type StoreConfig struct {
	Pool     *pgxpool.Pool
	Provider Provider
}

// Store resolves active configuration secret references. It intentionally has
// no method that returns plaintext.
type Store struct {
	*storeMaterial
}

// Binding is redaction-safe metadata for one exact active secret version.
// It contains no key identifier, ciphertext, nonce, hash or plaintext.
type Binding struct {
	RecordID string
	Version  int64
}

type storeMaterial struct {
	loader        secretRecordLoader
	provider      Provider
	providerKeyID string
}

// NewStore constructs a PostgreSQL-backed encrypted secret reader.
func NewStore(config StoreConfig) (*Store, error) {
	if config.Pool == nil || config.Provider == nil {
		return nil, ErrInvalid
	}
	providerKeyID := config.Provider.KeyID()
	if !masterKeyIdentifierPattern.MatchString(providerKeyID) {
		return nil, ErrInvalid
	}
	return newStore(postgresSecretRecordLoader{pool: config.Pool}, config.Provider, providerKeyID)
}

func newStore(loader secretRecordLoader, provider Provider, providerKeyID string) (*Store, error) {
	if loader == nil || provider == nil || !masterKeyIdentifierPattern.MatchString(providerKeyID) {
		return nil, ErrInvalid
	}
	return &Store{storeMaterial: &storeMaterial{loader: loader, provider: provider, providerKeyID: providerKeyID}}, nil
}

// Use resolves reference at its current active version, authenticates and
// decrypts it, and supplies one temporary plaintext buffer to consume. The
// buffer is cleared as soon as consume returns or panics. consume must not
// copy the value or retain a derived representation after returning.
//
// Callback errors collapse to ErrInvalid so a callback cannot accidentally
// return a plaintext-bearing error through this boundary.
func (store *Store) Use(ctx context.Context, scope Scope, reference string, consume func([]byte) error) error {
	if store == nil || store.storeMaterial == nil || ctx == nil || consume == nil || validateScope(scope) != nil || !secretReferencePattern.MatchString(reference) {
		return ErrInvalid
	}
	name := strings.TrimPrefix(reference, "secret/")
	record, err := store.loader.load(ctx, scope, name)
	if err != nil {
		return ErrUnavailable
	}
	if err := record.validate(scope, name, store.providerKeyID); err != nil {
		return err
	}

	plaintext, err := store.provider.Decrypt(Envelope{
		FormatVersion: int(record.formatVersion),
		Algorithm:     algorithm,
		KeyID:         record.masterKeyID,
		Nonce:         record.nonce,
		Ciphertext:    record.ciphertext,
	}, AssociatedData{
		OrganizationID: record.organizationID,
		EnvironmentID:  record.environmentID,
		SecretID:       record.id,
		SecretVersion:  record.version,
		FormatVersion:  int(record.formatVersion),
	})
	if err != nil {
		clear(plaintext)
		return ErrUnavailable
	}
	defer clear(plaintext)
	if len(plaintext) == 0 {
		return ErrInvalid
	}
	if err := consume(plaintext); err != nil {
		return ErrInvalid
	}
	return nil
}

// ActiveBinding resolves only the opaque identifier and version of the
// current active record. Automated operations persist this metadata to reject
// later credential substitution without persisting secret material.
func (store *Store) ActiveBinding(ctx context.Context, scope Scope, reference string) (Binding, error) {
	if store == nil || store.storeMaterial == nil || ctx == nil || validateScope(scope) != nil ||
		!secretReferencePattern.MatchString(reference) {
		return Binding{}, ErrInvalid
	}
	name := strings.TrimPrefix(reference, "secret/")
	record, err := store.loader.load(ctx, scope, name)
	if err != nil {
		return Binding{}, ErrUnavailable
	}
	if err := record.validate(scope, name, store.providerKeyID); err != nil {
		return Binding{}, err
	}
	return Binding{RecordID: record.id, Version: record.version}, nil
}

// UseBound decrypts only when the currently active record is the exact opaque
// record and version reviewed when the operation was created. Rotation fails
// closed instead of silently rebinding an unattended operation.
func (store *Store) UseBound(
	ctx context.Context,
	scope Scope,
	reference string,
	binding Binding,
	consume func([]byte) error,
) error {
	if store == nil || store.storeMaterial == nil || ctx == nil || consume == nil ||
		validateScope(scope) != nil || !secretReferencePattern.MatchString(reference) ||
		id.Validate(binding.RecordID, id.SecretRecord) != nil || binding.Version < 1 {
		return ErrInvalid
	}
	name := strings.TrimPrefix(reference, "secret/")
	record, err := store.loader.load(ctx, scope, name)
	if err != nil {
		return ErrUnavailable
	}
	if record.id != binding.RecordID || record.version != binding.Version {
		return ErrUnavailable
	}
	if err := record.validate(scope, name, store.providerKeyID); err != nil {
		return err
	}

	plaintext, err := store.provider.Decrypt(Envelope{
		FormatVersion: int(record.formatVersion),
		Algorithm:     algorithm,
		KeyID:         record.masterKeyID,
		Nonce:         record.nonce,
		Ciphertext:    record.ciphertext,
	}, AssociatedData{
		OrganizationID: record.organizationID,
		EnvironmentID:  record.environmentID,
		SecretID:       record.id,
		SecretVersion:  record.version,
		FormatVersion:  int(record.formatVersion),
	})
	if err != nil {
		clear(plaintext)
		return ErrUnavailable
	}
	defer clear(plaintext)
	if len(plaintext) == 0 {
		return ErrInvalid
	}
	if err := consume(plaintext); err != nil {
		return ErrInvalid
	}
	return nil
}

// Format prevents the provider and its key material from being traversed by
// diagnostic formatting.
func (Store) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func validateScope(scope Scope) error {
	if id.Validate(scope.OrganizationID, id.Organization) != nil ||
		id.Validate(scope.ApplicationID, id.Application) != nil ||
		id.Validate(scope.EnvironmentID, id.Environment) != nil {
		return ErrInvalid
	}
	return nil
}

type secretRecord struct {
	*secretRecordMaterial
}

type secretRecordMaterial struct {
	id                 string
	organizationID     string
	applicationID      string
	environmentID      string
	name               string
	version            int64
	formatVersion      int16
	storedAlgorithm    string
	masterKeyID        string
	ciphertext         []byte
	nonce              []byte
	createdAt          time.Time
	rotatedAt          *time.Time
	destroyedAt        *time.Time
	organizationStatus string
	applicationStatus  string
	environmentStatus  string
}

func (record secretRecord) validate(scope Scope, name, providerKeyID string) error {
	if record.secretRecordMaterial == nil ||
		id.Validate(record.id, id.SecretRecord) != nil ||
		id.Validate(record.organizationID, id.Organization) != nil ||
		id.Validate(record.applicationID, id.Application) != nil ||
		id.Validate(record.environmentID, id.Environment) != nil ||
		record.organizationID != scope.OrganizationID ||
		record.applicationID != scope.ApplicationID ||
		record.environmentID != scope.EnvironmentID ||
		record.name != name ||
		record.version <= 0 ||
		record.formatVersion != int16(formatVersion) ||
		record.storedAlgorithm != storedEnvelopeAlgorithm ||
		!masterKeyIdentifierPattern.MatchString(record.masterKeyID) ||
		len(record.nonce) != 12 ||
		len(record.ciphertext) < 17 ||
		record.createdAt.IsZero() {
		return ErrInvalid
	}
	if record.organizationStatus != "active" || record.applicationStatus != "active" || record.environmentStatus != "active" ||
		record.rotatedAt != nil || record.destroyedAt != nil || record.masterKeyID != providerKeyID {
		return ErrUnavailable
	}
	return nil
}

// Format ensures test diagnostics and future logging cannot render encrypted
// record fields or key identifiers.
func (secretRecord) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

type secretRecordLoader interface {
	load(context.Context, Scope, string) (secretRecord, error)
}

type postgresSecretRecordLoader struct {
	pool *pgxpool.Pool
}

func (loader postgresSecretRecordLoader) load(ctx context.Context, scope Scope, name string) (secretRecord, error) {
	record := secretRecord{secretRecordMaterial: &secretRecordMaterial{}}
	err := loader.pool.QueryRow(ctx, `
		SELECT secret.secret_record_id,
		       secret.organization_id,
		       secret.application_id,
		       secret.environment_id,
		       secret.name,
		       secret.version,
		       secret.encryption_format_version,
		       secret.algorithm,
		       secret.master_key_identifier,
		       secret.ciphertext,
		       secret.nonce,
		       secret.created_at,
		       secret.rotated_at,
		       secret.destroyed_at,
		       organization.status,
		       application.status,
		       environment.status
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
		  AND secret.application_id = $2
		  AND secret.environment_id = $3
		  AND secret.name = $4
		  AND secret.rotated_at IS NULL
		  AND secret.destroyed_at IS NULL
		  AND organization.status = 'active'
		  AND application.status = 'active'
		  AND environment.status = 'active'
		  AND organization.disabled_at IS NULL
		  AND application.disabled_at IS NULL
		  AND environment.disabled_at IS NULL
	`, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID, name).Scan(
		&record.id,
		&record.organizationID,
		&record.applicationID,
		&record.environmentID,
		&record.name,
		&record.version,
		&record.formatVersion,
		&record.storedAlgorithm,
		&record.masterKeyID,
		&record.ciphertext,
		&record.nonce,
		&record.createdAt,
		&record.rotatedAt,
		&record.destroyedAt,
		&record.organizationStatus,
		&record.applicationStatus,
		&record.environmentStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return secretRecord{}, ErrUnavailable
	}
	if err != nil {
		return secretRecord{}, ErrUnavailable
	}
	return record, nil
}
