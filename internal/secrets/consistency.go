package secrets

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrMasterKeyMismatch means persisted encrypted secrets were sealed under a
	// different runtime master key. It deliberately omits both key identifiers.
	ErrMasterKeyMismatch = errors.New("runtime master key does not match encrypted secrets")
	// ErrMasterKeyCheckUnavailable means the persisted master-key state could
	// not be checked. Startup must fail closed rather than risk changing the
	// identity-subject derivation key.
	ErrMasterKeyCheckUnavailable = errors.New("runtime master-key consistency check is unavailable")
)

// CheckMasterKeyConsistency verifies that every persisted secret record uses
// the current provider. Gateway signing-key records are checked separately by
// SigningKeyManager.Active while holding its rotation advisory lock, which also
// closes the concurrent empty-database initialization race.
func CheckMasterKeyConsistency(ctx context.Context, pool *pgxpool.Pool, provider Provider) error {
	if ctx == nil || pool == nil || provider == nil {
		return ErrMasterKeyCheckUnavailable
	}
	keyID := provider.KeyID()
	if !masterKeyIdentifierPattern.MatchString(keyID) {
		return ErrMasterKeyCheckUnavailable
	}
	return checkMasterKeyConsistency(ctx, postgresMasterKeyRecordInspector{pool: pool}, keyID)
}

type masterKeyRecordInspector interface {
	hasMismatchedSecretKey(context.Context, string) (bool, error)
}

type postgresMasterKeyRecordInspector struct {
	pool *pgxpool.Pool
}

func (inspector postgresMasterKeyRecordInspector) hasMismatchedSecretKey(ctx context.Context, keyID string) (bool, error) {
	var mismatch bool
	err := inspector.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM secret_records
			WHERE master_key_identifier <> $1
		)
	`, keyID).Scan(&mismatch)
	return mismatch, err
}

func checkMasterKeyConsistency(ctx context.Context, inspector masterKeyRecordInspector, keyID string) error {
	if ctx == nil || inspector == nil || !masterKeyIdentifierPattern.MatchString(keyID) {
		return ErrMasterKeyCheckUnavailable
	}
	mismatch, err := inspector.hasMismatchedSecretKey(ctx, keyID)
	if err != nil {
		return ErrMasterKeyCheckUnavailable
	}
	if mismatch {
		return ErrMasterKeyMismatch
	}
	return nil
}
