package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
)

const (
	defaultReplayLifetime = 15 * time.Minute
	minimumReplayLifetime = defaultReplayLifetime
	maximumReplayLifetime = time.Hour
	maximumReplayJTIBytes = 128
	maximumReplayURIBytes = 8 << 10
	maximumCleanupBatch   = 10_000
)

var (
	// ErrDPoPReplayed is returned when a session grant has already used a proof
	// identifier. Its text is the stable public problem code and contains no
	// proof material.
	ErrDPoPReplayed = errors.New("dpop_replayed")
	// ErrReplayInvalid identifies malformed replay-store inputs without
	// reflecting any proof identifier or URI into logs or responses.
	ErrReplayInvalid = errors.New("DPoP replay input is invalid")

	replayMethodPattern = regexp.MustCompile(`^[A-Z]{3,10}$`)
)

// ReplayStoreConfig configures PostgreSQL-backed DPoP replay protection.
type ReplayStoreConfig struct {
	Pool     *pgxpool.Pool
	Now      func() time.Time
	Lifetime time.Duration
}

// ReplayStore atomically accepts each DPoP proof identifier at most once per
// stable installation. It persists only SHA-256 digests of proof identifiers
// and normalized request URIs.
type ReplayStore struct {
	pool     *pgxpool.Pool
	now      func() time.Time
	lifetime time.Duration
}

// NewReplayStore constructs a replay store with a retention window that
// safely exceeds the default DPoP proof acceptance window.
func NewReplayStore(config ReplayStoreConfig) (*ReplayStore, error) {
	if config.Pool == nil {
		return nil, errors.New("DPoP replay store database pool is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Lifetime == 0 {
		config.Lifetime = defaultReplayLifetime
	}
	if config.Lifetime < minimumReplayLifetime || config.Lifetime > maximumReplayLifetime {
		return nil, errors.New("DPoP replay lifetime is outside the safe range")
	}
	return &ReplayStore{pool: config.Pool, now: config.Now, lifetime: config.Lifetime}, nil
}

// ReplayInput contains the already-validated request binding to record. The
// URI must be the exact canonical value returned by dpop.NormalizeHTU.
type ReplayInput struct {
	OrganizationID string
	ApplicationID  string
	EnvironmentID  string
	InstallationID string
	SessionGrantID string
	ProofJTI       string
	HTTPMethod     string
	NormalizedURI  string
}

func (input ReplayInput) validate() error {
	if id.Validate(input.OrganizationID, id.Organization) != nil ||
		id.Validate(input.ApplicationID, id.Application) != nil ||
		id.Validate(input.EnvironmentID, id.Environment) != nil ||
		id.Validate(input.InstallationID, id.Installation) != nil ||
		id.Validate(input.SessionGrantID, id.SessionGrant) != nil ||
		!validReplayJTI(input.ProofJTI) ||
		!replayMethodPattern.MatchString(input.HTTPMethod) ||
		!validNormalizedReplayURI(input.NormalizedURI) {
		return ErrReplayInvalid
	}
	return nil
}

func validReplayJTI(value string) bool {
	return len(value) >= 1 && len(value) <= maximumReplayJTIBytes &&
		utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) == -1
}

func validNormalizedReplayURI(value string) bool {
	if len(value) == 0 || len(value) > maximumReplayURIBytes || !utf8.ValidString(value) ||
		strings.IndexFunc(value, unicode.IsControl) != -1 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	normalized, err := dpop.NormalizeHTU(parsed)
	return err == nil && normalized == value
}

// Accept records a proof atomically. Concurrent calls for the same
// installation and proof identifier have exactly one success; all others return
// ErrDPoPReplayed. Raw proof identifiers and URIs never reach PostgreSQL.
func (store *ReplayStore) Accept(ctx context.Context, input ReplayInput) error {
	return store.accept(ctx, store.pool, input)
}

type replayInserter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// accept records a validated proof through the supplied transaction or pool.
// Session mutations use the transaction form so proof acceptance and the
// protected mutation either commit together or both roll back.
func (store *ReplayStore) accept(ctx context.Context, inserter replayInserter, input ReplayInput) error {
	if err := input.validate(); err != nil {
		return err
	}
	entryID, err := id.New(id.DPoPReplay)
	if err != nil {
		return errors.New("generate DPoP replay entry ID")
	}
	observedAt := store.now().UTC()
	if observedAt.IsZero() {
		return errors.New("DPoP replay store clock is invalid")
	}
	expiresAt := observedAt.Add(store.lifetime)
	if !expiresAt.After(observedAt) {
		return errors.New("DPoP replay expiry is invalid")
	}
	proofJTIHash := sha256.Sum256([]byte(input.ProofJTI))
	httpURIHash := sha256.Sum256([]byte(input.NormalizedURI))
	command, err := inserter.Exec(ctx, `
		INSERT INTO dpop_replay_entries (
			dpop_replay_entry_id, organization_id, application_id, environment_id,
			installation_id, session_grant_id, proof_jti_hash, http_method,
			http_uri_hash, observed_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (installation_id, proof_jti_hash) DO NOTHING
	`, entryID, input.OrganizationID, input.ApplicationID, input.EnvironmentID,
		input.InstallationID, input.SessionGrantID, proofJTIHash[:], input.HTTPMethod,
		httpURIHash[:], observedAt, expiresAt)
	if err != nil {
		if replayForeignKeyViolation(err) {
			return ErrSessionScope
		}
		return fmt.Errorf("store DPoP replay digest: %w", err)
	}
	if command.RowsAffected() == 0 {
		return ErrDPoPReplayed
	}
	if command.RowsAffected() != 1 {
		return errors.New("store DPoP replay digest affected an invalid row count")
	}
	return nil
}

// DeleteExpired removes at most limit expired entries. SKIP LOCKED lets
// multiple cleanup workers safely make progress without selecting the same
// rows or blocking the request path.
func (store *ReplayStore) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	cleanupNow := store.now().UTC()
	if cleanupNow.IsZero() || before.IsZero() || before.UTC().After(cleanupNow) ||
		limit < 1 || limit > maximumCleanupBatch {
		return 0, errors.New("DPoP replay cleanup input is invalid")
	}
	command, err := store.pool.Exec(ctx, `
		WITH expired AS (
			SELECT dpop_replay_entry_id
			FROM dpop_replay_entries
			WHERE expires_at <= $1
			ORDER BY expires_at, dpop_replay_entry_id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM dpop_replay_entries AS replay
		USING expired
		WHERE replay.dpop_replay_entry_id = expired.dpop_replay_entry_id
	`, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired DPoP replay digests: %w", err)
	}
	return command.RowsAffected(), nil
}

func replayForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
