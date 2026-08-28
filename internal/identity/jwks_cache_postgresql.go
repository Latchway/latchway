package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const sharedKeyRefreshLease = 30 * time.Second

type remoteKeyIdentity struct {
	issuer [sha256.Size]byte
	source [sha256.Size]byte
	format RemoteKeyFormat
}

func newRemoteKeyIdentity(issuer, endpoint string, format RemoteKeyFormat) remoteKeyIdentity {
	return remoteKeyIdentity{
		issuer: sha256.Sum256([]byte("latchway-identity-issuer-v1\x00" + issuer)),
		source: sha256.Sum256([]byte("latchway-identity-key-source-v1\x00" + string(format) + "\x00" + endpoint)),
		format: format,
	}
}

type cachedRemoteKeyDocument struct {
	document     []byte
	documentHash [sha256.Size]byte
	etag         string
	lastModified *time.Time
	fetchedAt    time.Time
	freshUntil   time.Time
	staleUntil   time.Time
}

type remoteKeyRefreshLease struct {
	identity remoteKeyIdentity
	token    [sha256.Size]byte
}

// RemoteKeyDocumentCache is intentionally sealed to this package. Production
// composition can pass the PostgreSQL implementation, while arbitrary callers
// cannot persist unvalidated key documents through the interface.
type RemoteKeyDocumentCache interface {
	load(context.Context, remoteKeyIdentity) (cachedRemoteKeyDocument, bool, error)
	acquire(context.Context, remoteKeyIdentity) (remoteKeyRefreshLease, cachedRemoteKeyDocument, bool, bool, error)
	complete(context.Context, remoteKeyRefreshLease, cachedRemoteKeyDocument, bool) error
	release(context.Context, remoteKeyRefreshLease) error
}

// PostgreSQLRemoteKeyCache shares validated public identity-key documents
// between API and worker replicas without persisting endpoint URLs, issuers,
// credentials, or identity tokens.
type PostgreSQLRemoteKeyCache struct {
	pool *pgxpool.Pool
}

func NewPostgreSQLRemoteKeyCache(pool *pgxpool.Pool) (*PostgreSQLRemoteKeyCache, error) {
	if pool == nil {
		return nil, errors.New("identity key cache database is nil")
	}
	return &PostgreSQLRemoteKeyCache{pool: pool}, nil
}

func (cache *PostgreSQLRemoteKeyCache) load(ctx context.Context, identity remoteKeyIdentity) (cachedRemoteKeyDocument, bool, error) {
	if cache == nil || cache.pool == nil || ctx == nil {
		return cachedRemoteKeyDocument{}, false, errors.New("identity key cache is unavailable")
	}
	var record cachedRemoteKeyDocument
	var document, documentHash []byte
	var etag *string
	var lastModified, fetchedAt, freshUntil, staleUntil *time.Time
	err := cache.pool.QueryRow(ctx, `
		SELECT document, document_sha256, etag, last_modified,
		       fetched_at, fresh_until, stale_until
		FROM identity_jwks_cache
		WHERE issuer_sha256 = $1 AND source_sha256 = $2 AND source_format = $3
	`, identity.issuer[:], identity.source[:], string(identity.format)).Scan(
		&document, &documentHash, &etag, &lastModified,
		&fetchedAt, &freshUntil, &staleUntil,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return cachedRemoteKeyDocument{}, false, nil
	}
	if err != nil {
		return cachedRemoteKeyDocument{}, false, errors.New("read shared identity key cache")
	}
	// A row with only a refresh lease is a valid first-refresh placeholder.
	if document == nil && documentHash == nil && etag == nil && lastModified == nil &&
		fetchedAt == nil && freshUntil == nil && staleUntil == nil {
		return cachedRemoteKeyDocument{}, false, nil
	}
	if len(document) < 2 || len(document) > maxRemoteKeyDocumentBytes ||
		len(documentHash) != sha256.Size || fetchedAt == nil || freshUntil == nil || staleUntil == nil ||
		fetchedAt.IsZero() || freshUntil.Before(*fetchedAt) || staleUntil.Before(*freshUntil) ||
		freshUntil.Sub(*fetchedAt) > 24*time.Hour || staleUntil.Sub(*freshUntil) > 24*time.Hour {
		return cachedRemoteKeyDocument{}, false, errors.New("shared identity key cache is invalid")
	}
	record.document = append([]byte(nil), document...)
	if etag != nil {
		record.etag = *etag
	}
	if boundedETag(record.etag) != record.etag {
		return cachedRemoteKeyDocument{}, false, errors.New("shared identity key cache is invalid")
	}
	record.lastModified = lastModified
	record.fetchedAt = fetchedAt.UTC()
	record.freshUntil = freshUntil.UTC()
	record.staleUntil = staleUntil.UTC()
	copy(record.documentHash[:], documentHash)
	calculated := sha256.Sum256(record.document)
	if !bytes.Equal(calculated[:], record.documentHash[:]) {
		return cachedRemoteKeyDocument{}, false, errors.New("shared identity key cache is invalid")
	}
	return record, true, nil
}

func (cache *PostgreSQLRemoteKeyCache) acquire(
	ctx context.Context,
	identity remoteKeyIdentity,
) (remoteKeyRefreshLease, cachedRemoteKeyDocument, bool, bool, error) {
	if cache == nil || cache.pool == nil || ctx == nil {
		return remoteKeyRefreshLease{}, cachedRemoteKeyDocument{}, false, false, errors.New("identity key cache is unavailable")
	}
	lease := remoteKeyRefreshLease{identity: identity}
	if _, err := rand.Read(lease.token[:]); err != nil || bytes.Equal(lease.token[:], make([]byte, sha256.Size)) {
		return remoteKeyRefreshLease{}, cachedRemoteKeyDocument{}, false, false, errors.New("generate identity key refresh lease")
	}
	result, err := cache.pool.Exec(ctx, `
		INSERT INTO identity_jwks_cache (
			issuer_sha256, source_sha256, source_format,
			refresh_lease_token, refresh_lease_until, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			statement_timestamp() + make_interval(secs => $5),
			statement_timestamp(), statement_timestamp()
		)
		ON CONFLICT (issuer_sha256, source_sha256) DO UPDATE
		SET refresh_lease_token = EXCLUDED.refresh_lease_token,
		    refresh_lease_until = EXCLUDED.refresh_lease_until,
		    updated_at = statement_timestamp()
		WHERE identity_jwks_cache.source_format = EXCLUDED.source_format
		  AND (identity_jwks_cache.refresh_lease_until IS NULL
		       OR identity_jwks_cache.refresh_lease_until <= statement_timestamp())
	`, identity.issuer[:], identity.source[:], string(identity.format), lease.token[:], int64(sharedKeyRefreshLease/time.Second))
	if err != nil {
		return remoteKeyRefreshLease{}, cachedRemoteKeyDocument{}, false, false, errors.New("acquire identity key refresh lease")
	}
	record, found, loadErr := cache.load(ctx, identity)
	if loadErr != nil {
		if result.RowsAffected() == 1 {
			// The lease owner may repair a structurally valid row whose
			// document/hash pair was corrupted. Completion still requires a
			// freshly validated public-only document and the exact lease token.
			return lease, cachedRemoteKeyDocument{}, false, true, loadErr
		}
		return remoteKeyRefreshLease{}, cachedRemoteKeyDocument{}, false, false, loadErr
	}
	if result.RowsAffected() != 1 {
		return remoteKeyRefreshLease{}, record, found, false, nil
	}
	return lease, record, found, true, nil
}

func (cache *PostgreSQLRemoteKeyCache) complete(
	ctx context.Context,
	lease remoteKeyRefreshLease,
	record cachedRemoteKeyDocument,
	noStore bool,
) error {
	if cache == nil || cache.pool == nil || ctx == nil || bytes.Equal(lease.token[:], make([]byte, sha256.Size)) {
		return errors.New("identity key refresh completion is invalid")
	}
	if noStore {
		command, err := cache.pool.Exec(ctx, `
			UPDATE identity_jwks_cache
			SET document = NULL, document_sha256 = NULL, etag = NULL, last_modified = NULL,
			    fetched_at = NULL, fresh_until = NULL, stale_until = NULL,
			    refresh_lease_token = NULL, refresh_lease_until = NULL,
			    updated_at = statement_timestamp()
			WHERE issuer_sha256 = $1 AND source_sha256 = $2
			  AND source_format = $3 AND refresh_lease_token = $4
		`, lease.identity.issuer[:], lease.identity.source[:], string(lease.identity.format), lease.token[:])
		if err != nil || command.RowsAffected() != 1 {
			return errors.New("complete no-store identity key refresh")
		}
		return nil
	}
	if len(record.document) < 2 || len(record.document) > maxRemoteKeyDocumentBytes ||
		record.fetchedAt.IsZero() || record.freshUntil.Before(record.fetchedAt) ||
		record.freshUntil.Sub(record.fetchedAt) > 24*time.Hour || record.staleUntil.Before(record.freshUntil) ||
		record.staleUntil.Sub(record.freshUntil) > 24*time.Hour ||
		sha256.Sum256(record.document) != record.documentHash || boundedETag(record.etag) != record.etag {
		return errors.New("identity key refresh document is invalid")
	}
	command, err := cache.pool.Exec(ctx, `
		UPDATE identity_jwks_cache
		SET document = $5, document_sha256 = $6, etag = NULLIF($7, ''),
		    last_modified = $8, fetched_at = $9, fresh_until = $10, stale_until = $11,
		    refresh_lease_token = NULL, refresh_lease_until = NULL,
		    updated_at = statement_timestamp()
		WHERE issuer_sha256 = $1 AND source_sha256 = $2
		  AND source_format = $3 AND refresh_lease_token = $4
	`, lease.identity.issuer[:], lease.identity.source[:], string(lease.identity.format), lease.token[:],
		record.document, record.documentHash[:], record.etag, record.lastModified,
		record.fetchedAt, record.freshUntil, record.staleUntil)
	if err != nil || command.RowsAffected() != 1 {
		return errors.New("complete identity key refresh")
	}
	return nil
}

func (cache *PostgreSQLRemoteKeyCache) release(ctx context.Context, lease remoteKeyRefreshLease) error {
	if cache == nil || cache.pool == nil || ctx == nil || bytes.Equal(lease.token[:], make([]byte, sha256.Size)) {
		return errors.New("identity key refresh release is invalid")
	}
	_, err := cache.pool.Exec(ctx, `
		UPDATE identity_jwks_cache
		SET refresh_lease_token = NULL, refresh_lease_until = NULL,
		    updated_at = statement_timestamp()
		WHERE issuer_sha256 = $1 AND source_sha256 = $2
		  AND source_format = $3 AND refresh_lease_token = $4
	`, lease.identity.issuer[:], lease.identity.source[:], string(lease.identity.format), lease.token[:])
	if err != nil {
		return errors.New("release identity key refresh lease")
	}
	return nil
}
