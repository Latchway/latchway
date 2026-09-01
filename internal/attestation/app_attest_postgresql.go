package attestation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

const (
	appAttestKeyLockNamespace      int64 = 0x4150504154544553
	appAttestCommitResolveTimeout        = 5 * time.Second
	appAttestReceiptCleanupTimeout       = 2 * time.Second
	appAttestAbandonedKeyRetention       = 24 * time.Hour
	maximumAppAttestCleanupBatch         = 10_000
)

type appAttestCommitFunc func(context.Context, pgx.Tx) error

// PostgreSQLAppAttestKeyStore persists Apple assertion keys before an
// installation exists. A transaction-scoped advisory lock serializes both an
// existing row and the otherwise-unlocked absence of a credential ID across
// every gateway replica.
type PostgreSQLAppAttestKeyStore struct {
	pool   *pgxpool.Pool
	newID  func(id.Prefix) (string, error)
	random io.Reader
	commit appAttestCommitFunc
}

// NewPostgreSQLAppAttestKeyStore constructs the production App Attest key
// store. The database must have migration 000013 applied.
func NewPostgreSQLAppAttestKeyStore(pool *pgxpool.Pool) (*PostgreSQLAppAttestKeyStore, error) {
	if pool == nil {
		return nil, ErrAppAttestKeyStore
	}
	return &PostgreSQLAppAttestKeyStore{
		pool:   pool,
		newID:  id.New,
		random: rand.Reader,
		commit: func(ctx context.Context, tx pgx.Tx) error {
			return tx.Commit(ctx)
		},
	}, nil
}

// TransactAppAttestKey implements AppAttestKeyStore. Callback errors and
// caller cancellation remain distinguishable to the verifier; all persistence
// and corruption failures collapse to the redaction-safe store sentinel.
func (store *PostgreSQLAppAttestKeyStore) TransactAppAttestKey(
	ctx context.Context,
	keyID [sha256.Size]byte,
	transact AppAttestKeyTransaction,
) error {
	if store == nil || store.pool == nil || store.newID == nil || store.random == nil || store.commit == nil ||
		ctx == nil || keyID == ([sha256.Size]byte{}) || transact == nil {
		return ErrAppAttestKeyStore
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var commitToken [sha256.Size]byte
	if _, err := io.ReadFull(store.random, commitToken[:]); err != nil || commitToken == ([sha256.Size]byte{}) {
		return ErrAppAttestKeyStore
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return appAttestPersistenceError(ctx, err)
	}
	defer rollbackAppAttestKeyTransaction(tx)

	// FOR UPDATE cannot lock an absent row. Lock a deterministic 64-bit slice
	// of the cryptographic credential ID first so concurrent registrations also
	// serialize. A lock collision only reduces concurrency; row identity still
	// uses all 256 bits.
	lockID := appAttestAdvisoryLockID(keyID)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockID); err != nil {
		return appAttestPersistenceError(ctx, err)
	}

	loaded, err := loadPostgreSQLAppAttestKey(ctx, tx, keyID)
	if err != nil {
		return appAttestPersistenceError(ctx, err)
	}
	callbackCurrent := cloneAppAttestStoredKey(loaded.state)
	next, callbackErr := transact(callbackCurrent, loaded.exists)
	if callbackErr != nil {
		return callbackErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	next = cloneAppAttestStoredKey(next)
	if !loaded.usable && loaded.exists {
		return ErrAppAttestKeyStore
	}
	if validateAppAttestStoredKey(keyID, next) != nil ||
		next.AttestedAt.Year() < 1 || next.AttestedAt.Year() > 9998 {
		return ErrAppAttestKeyStore
	}

	if loaded.exists {
		if !sameAppAttestImmutableState(loaded.state, next) || next.Counter < loaded.state.Counter {
			return ErrAppAttestKeyStore
		}
		if next.Counter == loaded.state.Counter {
			if !sameAppAttestMutableState(loaded.state, next) {
				return ErrAppAttestKeyStore
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			// An exact registration replay can happen after the key commit but
			// before session exchange commits. It is already durable, so release
			// the read transaction without an UPDATE or commit receipt.
			return nil
		}
		if err := updatePostgreSQLAppAttestKey(ctx, tx, keyID, loaded, next); err != nil {
			return appAttestPersistenceError(ctx, err)
		}
	} else {
		if next.Counter != 0 {
			return ErrAppAttestKeyStore
		}
		attestationKeyID, err := store.newID(id.AttestationKey)
		if err != nil {
			return ErrAppAttestKeyStore
		}
		if err := insertPostgreSQLAppAttestKey(ctx, tx, attestationKeyID, keyID, next); err != nil {
			return appAttestPersistenceError(ctx, err)
		}
	}
	if err := recordPostgreSQLAppAttestCommitReceipt(ctx, tx, keyID, commitToken, next.Counter); err != nil {
		return appAttestPersistenceError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Keep COMMIT caller-cancelable so cancellation immediately before the
	// server receives it cannot persist a key. If the acknowledgement is lost,
	// the receipt written in this same transaction distinguishes a durable
	// commit from rollback without invoking the verifier callback again.
	commitCtx, cancelCommit := context.WithTimeout(ctx, appAttestCommitResolveTimeout)
	commitErr := store.commit(commitCtx, tx)
	cancelCommit()
	if commitErr == nil {
		store.deleteAppAttestCommitReceipt(ctx, commitToken)
		return nil
	}
	// A test hook or driver error may leave the transaction open. Rollback is a
	// no-op after a completed COMMIT, but otherwise releases its connection and
	// makes a missing receipt conclusive before the independent resolution read.
	rollbackAppAttestKeyTransaction(tx)
	committed, resolveErr := store.hasAppAttestCommitReceipt(ctx, keyID, commitToken)
	if resolveErr == nil && committed {
		store.deleteAppAttestCommitReceipt(ctx, commitToken)
		return nil
	}
	if resolveErr == nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
	}
	return ErrAppAttestKeyStore
}

type postgreSQLAppAttestKey struct {
	attestationKeyID string
	providerKeyID    string
	state            AppAttestStoredKey
	exists           bool
	usable           bool
}

func loadPostgreSQLAppAttestKey(
	ctx context.Context,
	tx pgx.Tx,
	keyID [sha256.Size]byte,
) (postgreSQLAppAttestKey, error) {
	var loaded postgreSQLAppAttestKey
	var publicKey, appIDHash, lastAssertionHash []byte
	var attestationEnvironment, status string
	var counter int64
	var extensionsPresent *bool
	var validationCategory *int64
	var bundleVersion *string
	var attestedSeconds *int64
	var attestedNanosecond *int32
	err := tx.QueryRow(ctx, `
		SELECT attestation_key_id, provider_key_id, public_key, app_id_hash,
		       environment, application_id, binding_environment, platform,
		       application_user_id, dpop_jkt, sign_count, last_assertion_hash, status,
		       extensions_present, validation_category, bundle_version,
		       attested_at_unix_seconds, attested_at_nanosecond
		FROM attestation_keys
		WHERE provider = 'app_attest' AND provider_key_hash = $1
		FOR UPDATE
	`, keyID[:]).Scan(
		&loaded.attestationKeyID, &loaded.providerKeyID, &publicKey, &appIDHash,
		&attestationEnvironment, &loaded.state.ApplicationID, &loaded.state.EnvironmentID,
		&loaded.state.Platform, &loaded.state.PrincipalID, &loaded.state.DPoPJKT,
		&counter, &lastAssertionHash, &status, &extensionsPresent, &validationCategory, &bundleVersion,
		&attestedSeconds, &attestedNanosecond,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return postgreSQLAppAttestKey{}, nil
	}
	if err != nil {
		return postgreSQLAppAttestKey{}, err
	}
	loaded.exists = true
	loaded.state.PublicKeyX963 = append([]byte(nil), publicKey...)
	if len(appIDHash) == sha256.Size {
		copy(loaded.state.AppIDHash[:], appIDHash)
	}
	loaded.state.AttestationEnvironment = AppAttestEnvironment(attestationEnvironment)
	if counter >= 0 && counter <= math.MaxUint32 {
		loaded.state.Counter = uint32(counter)
	}
	if len(lastAssertionHash) == sha256.Size {
		copy(loaded.state.LastAssertionHash[:], lastAssertionHash)
	}
	if extensionsPresent != nil {
		loaded.state.ExtensionsPresent = *extensionsPresent
	}
	if validationCategory != nil && *validationCategory >= 0 && *validationCategory <= math.MaxUint32 {
		loaded.state.ValidationCategory = uint32(*validationCategory)
	}
	if bundleVersion != nil {
		loaded.state.BundleVersion = *bundleVersion
	}
	if attestedSeconds != nil && attestedNanosecond != nil &&
		*attestedNanosecond >= 0 && *attestedNanosecond < int32(time.Second) {
		loaded.state.AttestedAt = time.Unix(*attestedSeconds, int64(*attestedNanosecond)).UTC()
	}

	wantProviderKeyID := base64.StdEncoding.EncodeToString(keyID[:])
	extensionColumnsValid := extensionsPresent != nil &&
		((!*extensionsPresent && validationCategory == nil && bundleVersion == nil) ||
			(*extensionsPresent && validationCategory != nil && bundleVersion != nil))
	assertionHashColumnValid := (counter == 0 && lastAssertionHash == nil) ||
		(counter > 0 && counter <= math.MaxUint32 && len(lastAssertionHash) == sha256.Size &&
			!bytes.Equal(lastAssertionHash, make([]byte, sha256.Size)))
	loaded.usable = status == "active" && loaded.providerKeyID == wantProviderKeyID &&
		id.Validate(loaded.attestationKeyID, id.AttestationKey) == nil &&
		counter >= 0 && counter <= math.MaxUint32 &&
		assertionHashColumnValid && extensionColumnsValid && attestedSeconds != nil && attestedNanosecond != nil &&
		validateAppAttestStoredKey(keyID, loaded.state) == nil &&
		loaded.state.AttestedAt.Year() >= 1 && loaded.state.AttestedAt.Year() <= 9998
	return loaded, nil
}

func insertPostgreSQLAppAttestKey(
	ctx context.Context,
	tx pgx.Tx,
	attestationKeyID string,
	keyID [sha256.Size]byte,
	state AppAttestStoredKey,
) error {
	// Application/environment disable takes these locks in the same order and
	// then revokes every unlinked key it can see. Keep the scope locked through
	// insertion so a newly registered key cannot commit after that scan and
	// survive a later re-enable.
	var marker int
	if err := tx.QueryRow(ctx, `
		/* app_attest_active_application_lock */
		SELECT 1
		FROM applications AS application
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE application.application_id = $1
		  AND application.status = 'active' AND application.disabled_at IS NULL
		  AND organization.status = 'active' AND organization.disabled_at IS NULL
		FOR SHARE OF application
	`, state.ApplicationID).Scan(&marker); err != nil {
		return ErrAppAttestKeyStore
	}
	if err := tx.QueryRow(ctx, `
		/* app_attest_active_environment_lock */
		SELECT 1
		FROM environments
		WHERE application_id = $1 AND slug = $2
		  AND status = 'active' AND disabled_at IS NULL
		FOR SHARE
	`, state.ApplicationID, state.EnvironmentID).Scan(&marker); err != nil {
		return ErrAppAttestKeyStore
	}
	category, version := appAttestExtensionColumns(state)
	command, err := tx.Exec(ctx, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, provider, provider_key_id,
			provider_key_hash, public_key, app_id_hash, environment,
			binding_environment, platform, dpop_jkt, sign_count, last_assertion_hash, status,
			extensions_present, validation_category, bundle_version,
			attested_at_unix_seconds, attested_at_nanosecond,
			created_at, updated_at, linked_at
		)
		SELECT $1, environment.organization_id, environment.application_id,
		       environment.environment_id, application_user.application_user_id,
		       NULL, 'app_attest', $2, $3, $4, $5, $6, environment.slug,
		       $7, $8, $9, $10, 'active', $11, $12, $13, $14, $15,
		       transaction_timestamp(), transaction_timestamp(), NULL
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		JOIN application_users AS application_user
		  ON application_user.organization_id = environment.organization_id
		 AND application_user.application_id = environment.application_id
		WHERE environment.application_id = $16
		  AND environment.slug = $17
		  AND application_user.application_user_id = $18
		  AND organization.status = 'active'
		  AND application.status = 'active'
		  AND environment.status = 'active'
		  AND application_user.status = 'active'
	`, attestationKeyID, base64.StdEncoding.EncodeToString(keyID[:]), keyID[:],
		append([]byte(nil), state.PublicKeyX963...), state.AppIDHash[:], string(state.AttestationEnvironment),
		state.Platform, state.DPoPJKT, int64(state.Counter), appAttestAssertionHashColumn(state),
		state.ExtensionsPresent, category, version, state.AttestedAt.Unix(), int32(state.AttestedAt.Nanosecond()),
		state.ApplicationID, state.EnvironmentID, state.PrincipalID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAppAttestKeyStore
	}
	return nil
}

func updatePostgreSQLAppAttestKey(
	ctx context.Context,
	tx pgx.Tx,
	keyID [sha256.Size]byte,
	loaded postgreSQLAppAttestKey,
	state AppAttestStoredKey,
) error {
	category, version := appAttestExtensionColumns(state)
	command, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET sign_count = $3,
		    last_assertion_hash = $4,
		    extensions_present = $5,
		    validation_category = $6,
		    bundle_version = $7,
		    updated_at = GREATEST(updated_at, transaction_timestamp())
		WHERE attestation_key_id = $1
		  AND provider = 'app_attest'
		  AND provider_key_hash = $2
		  AND status = 'active'
		  AND sign_count = $8
	`, loaded.attestationKeyID, keyID[:], int64(state.Counter), appAttestAssertionHashColumn(state),
		state.ExtensionsPresent, category, version, int64(loaded.state.Counter))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAppAttestKeyStore
	}
	return nil
}

func recordPostgreSQLAppAttestCommitReceipt(
	ctx context.Context,
	tx pgx.Tx,
	keyID [sha256.Size]byte,
	commitToken [sha256.Size]byte,
	counter uint32,
) error {
	command, err := tx.Exec(ctx, `
		INSERT INTO app_attest_key_commit_receipts (
			commit_token, organization_id, application_id, environment_id,
			attestation_key_id, sign_count
		)
		SELECT $1, organization_id, application_id, environment_id,
		       attestation_key_id, sign_count
		FROM attestation_keys
		WHERE provider = 'app_attest'
		  AND provider_key_hash = $2
		  AND status = 'active'
		  AND sign_count = $3
	`, commitToken[:], keyID[:], int64(counter))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAppAttestKeyStore
	}
	return nil
}

func (store *PostgreSQLAppAttestKeyStore) hasAppAttestCommitReceipt(
	ctx context.Context,
	keyID [sha256.Size]byte,
	commitToken [sha256.Size]byte,
) (bool, error) {
	resolveCtx, cancelResolve := context.WithTimeout(context.WithoutCancel(ctx), appAttestCommitResolveTimeout)
	defer cancelResolve()
	resolveTx, err := store.pool.BeginTx(resolveCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer rollbackAppAttestKeyTransaction(resolveTx)
	// PostgreSQL can still be finishing a COMMIT after its acknowledgement is
	// lost. Wait for the original transaction's key-scoped lock before reading
	// the receipt, so an absent row is not observed while that COMMIT is in
	// flight on another connection.
	if _, err := resolveTx.Exec(
		resolveCtx, "SELECT pg_advisory_xact_lock($1)", appAttestAdvisoryLockID(keyID),
	); err != nil {
		return false, err
	}
	var committed bool
	err = resolveTx.QueryRow(resolveCtx, `
		SELECT EXISTS (
			SELECT 1
			FROM app_attest_key_commit_receipts
			WHERE commit_token = $1 AND expires_at > clock_timestamp()
		)
	`, commitToken[:]).Scan(&committed)
	return committed, err
}

func appAttestAdvisoryLockID(keyID [sha256.Size]byte) int64 {
	return int64(binary.BigEndian.Uint64(keyID[:8])) ^ appAttestKeyLockNamespace
}

func (store *PostgreSQLAppAttestKeyStore) deleteAppAttestCommitReceipt(
	ctx context.Context,
	commitToken [sha256.Size]byte,
) {
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), appAttestReceiptCleanupTimeout)
	defer cancelCleanup()
	_, _ = store.pool.Exec(cleanupCtx, `
		DELETE FROM app_attest_key_commit_receipts WHERE commit_token = $1
	`, commitToken[:])
}

// DeleteExpired removes at most limit expired commit receipts and abandoned
// active pre-session keys. A key is retained for a full day and is never
// deleted while any commit-resolution receipt still refers to it. SKIP LOCKED
// lets multiple worker replicas make progress without blocking registration,
// assertion, or session-link transactions.
func (store *PostgreSQLAppAttestKeyStore) DeleteExpired(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	if store == nil || store.pool == nil || ctx == nil || before.IsZero() ||
		limit < 1 || limit > maximumAppAttestCleanupBatch {
		return 0, ErrAppAttestKeyStore
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	before = before.UTC()
	if before.Year() < 1 || before.Year() > 9998 {
		return 0, ErrAppAttestKeyStore
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, appAttestPersistenceError(ctx, err)
	}
	defer rollbackAppAttestKeyTransaction(tx)
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseNow); err != nil {
		return 0, appAttestPersistenceError(ctx, err)
	}
	databaseNow = databaseNow.UTC()
	if databaseNow.IsZero() || databaseNow.Year() < 1 || databaseNow.Year() > 9998 ||
		before.After(databaseNow) {
		return 0, ErrAppAttestKeyStore
	}

	receipts, err := tx.Exec(ctx, `
		WITH expired AS (
			SELECT commit_token
			FROM app_attest_key_commit_receipts
			WHERE expires_at <= $1
			ORDER BY expires_at, commit_token
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM app_attest_key_commit_receipts AS receipt
		USING expired
		WHERE receipt.commit_token = expired.commit_token
	`, before, limit)
	if err != nil {
		return 0, appAttestPersistenceError(ctx, err)
	}
	processed := receipts.RowsAffected()
	if processed < 0 || processed > int64(limit) {
		return 0, ErrAppAttestKeyStore
	}
	remaining := limit - int(processed)
	if remaining > 0 {
		keys, err := tx.Exec(ctx, `
			WITH abandoned AS (
				SELECT key.organization_id, key.application_id,
				       key.environment_id, key.attestation_key_id
				FROM attestation_keys AS key
				WHERE key.provider = 'app_attest'
				  AND key.status = 'active'
				  AND key.installation_id IS NULL
				  AND key.linked_at IS NULL
				  AND key.created_at <= $1
				  AND NOT EXISTS (
				      SELECT 1
				      FROM app_attest_key_commit_receipts AS receipt
				      WHERE receipt.organization_id = key.organization_id
				        AND receipt.application_id = key.application_id
				        AND receipt.environment_id = key.environment_id
				        AND receipt.attestation_key_id = key.attestation_key_id
				  )
				ORDER BY key.created_at, key.attestation_key_id
				LIMIT $2
				FOR UPDATE OF key SKIP LOCKED
			)
			DELETE FROM attestation_keys AS key
			USING abandoned
			WHERE key.organization_id = abandoned.organization_id
			  AND key.application_id = abandoned.application_id
			  AND key.environment_id = abandoned.environment_id
			  AND key.attestation_key_id = abandoned.attestation_key_id
		`, before.Add(-appAttestAbandonedKeyRetention), remaining)
		if err != nil {
			return 0, appAttestPersistenceError(ctx, err)
		}
		if keys.RowsAffected() < 0 || keys.RowsAffected() > int64(remaining) {
			return 0, ErrAppAttestKeyStore
		}
		processed += keys.RowsAffected()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, appAttestPersistenceError(ctx, err)
	}
	return processed, nil
}

func appAttestExtensionColumns(state AppAttestStoredKey) (any, any) {
	if !state.ExtensionsPresent {
		return nil, nil
	}
	return int64(state.ValidationCategory), state.BundleVersion
}

func appAttestAssertionHashColumn(state AppAttestStoredKey) any {
	if state.LastAssertionHash == ([sha256.Size]byte{}) {
		return nil
	}
	return append([]byte(nil), state.LastAssertionHash[:]...)
}

func sameAppAttestImmutableState(left, right AppAttestStoredKey) bool {
	return bytes.Equal(left.PublicKeyX963, right.PublicKeyX963) &&
		bytes.Equal(left.AppIDHash[:], right.AppIDHash[:]) &&
		left.AttestationEnvironment == right.AttestationEnvironment &&
		left.ApplicationID == right.ApplicationID &&
		left.EnvironmentID == right.EnvironmentID &&
		left.Platform == right.Platform &&
		left.PrincipalID == right.PrincipalID &&
		left.DPoPJKT == right.DPoPJKT &&
		left.AttestedAt.Equal(right.AttestedAt)
}

func sameAppAttestMutableState(left, right AppAttestStoredKey) bool {
	return left.Counter == right.Counter &&
		left.LastAssertionHash == right.LastAssertionHash &&
		left.ExtensionsPresent == right.ExtensionsPresent &&
		left.ValidationCategory == right.ValidationCategory &&
		left.BundleVersion == right.BundleVersion
}

func appAttestPersistenceError(ctx context.Context, _ error) error {
	if ctx != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
	}
	return ErrAppAttestKeyStore
}

func rollbackAppAttestKeyTransaction(tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

var _ AppAttestKeyStore = (*PostgreSQLAppAttestKeyStore)(nil)
