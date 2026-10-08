package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrPasskeyCounter means an assertion's signature counter didn't advance,
	// which can indicate a cloned authenticator.
	ErrPasskeyCounter = errors.New("passkey signature counter did not advance")
	// ErrWebAuthnChallengeInvalid covers unknown, expired, used and mismatched
	// WebAuthn challenges alike.
	ErrWebAuthnChallengeInvalid = errors.New("webauthn challenge is invalid")
	// ErrWebAuthnBusy means too many passwordless sign-ins are pending.
	ErrWebAuthnBusy = errors.New("too many pending passkey sign-ins")
)

// maxPendingPasskeySignIns bounds the challenges anyone can request without
// credentials, so the table can't be grown without limit.
const maxPendingPasskeySignIns = 1000

// WebAuthn challenge purposes.
const (
	WebAuthnRegister     = "register"
	WebAuthnSignIn       = "sign_in"
	WebAuthnSecondFactor = "second_factor"
)

// Passkey is an administrator's registered credential as they see it.
type Passkey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Synced is true when the authenticator reports the credential is backed
	// up, as platform passkeys synced across devices are.
	Synced bool `json:"synced"`
}

// StoredPasskey is what verifying an assertion needs.
type StoredPasskey struct {
	ID          string
	AdminUserID string
	X, Y        []byte
	SignCount   uint32
}

// NewPasskey is a verified registration to store.
type NewPasskey struct {
	CredentialID   []byte
	X, Y           []byte
	SignCount      uint32
	AAGUID         [16]byte
	BackupEligible bool
	BackupState    bool
	Name           string
}

func signInChallengeHash(plaintext string) [sha256.Size]byte {
	return sha256.Sum256([]byte(plaintext))
}

// WebAuthnUserHandle returns the administrator's opaque WebAuthn user ID,
// creating it on first use. It carries no account data.
func (store *Store) WebAuthnUserHandle(ctx context.Context, adminUserID string) ([]byte, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil {
		return nil, ErrInvalidAdminInput
	}
	candidate := make([]byte, 32)
	if _, err := rand.Read(candidate); err != nil {
		return nil, fmt.Errorf("generate webauthn user handle: %w", err)
	}
	var handle []byte
	err := store.pool.QueryRow(ctx, `
		UPDATE admin_users SET webauthn_user_handle = COALESCE(webauthn_user_handle, $2)
		WHERE admin_user_id = $1
		RETURNING webauthn_user_handle
	`, adminUserID, candidate).Scan(&handle)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAdminNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read webauthn user handle: %w", err)
	}
	return handle, nil
}

// CreateWebAuthnChallenge issues and stores a WebAuthn challenge. A
// second-factor challenge is tied to the password sign-in it completes.
func (store *Store) CreateWebAuthnChallenge(ctx context.Context, purpose, adminUserID, signInChallenge string, lifetime time.Duration) ([]byte, error) {
	switch {
	case purpose == WebAuthnSignIn && adminUserID == "" && signInChallenge == "":
	case purpose == WebAuthnRegister && id.Validate(adminUserID, id.AdminUser) == nil && signInChallenge == "":
	case purpose == WebAuthnSecondFactor && id.Validate(adminUserID, id.AdminUser) == nil && signInChallenge != "":
	default:
		return nil, ErrInvalidAdminInput
	}
	if lifetime < time.Minute || lifetime > 10*time.Minute {
		return nil, ErrInvalidAdminInput
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate webauthn challenge: %w", err)
	}
	hash := sha256.Sum256(challenge)
	now := store.now().UTC()
	if _, err := store.pool.Exec(ctx, `DELETE FROM admin_webauthn_challenges WHERE expires_at < $1`, now.Add(-time.Hour)); err != nil {
		return nil, fmt.Errorf("prune webauthn challenges: %w", err)
	}
	if purpose == WebAuthnSignIn {
		var pending int
		if err := store.pool.QueryRow(ctx, `
			SELECT count(*) FROM admin_webauthn_challenges WHERE purpose = 'sign_in' AND consumed_at IS NULL AND expires_at > $1
		`, now).Scan(&pending); err != nil {
			return nil, fmt.Errorf("count pending passkey sign-ins: %w", err)
		}
		if pending >= maxPendingPasskeySignIns {
			return nil, ErrWebAuthnBusy
		}
	}
	var signInHash any
	if signInChallenge != "" {
		linked := signInChallengeHash(signInChallenge)
		signInHash = linked[:]
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO admin_webauthn_challenges (challenge_hash, purpose, admin_user_id, sign_in_challenge_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, hash[:], purpose, nullableString(adminUserID), signInHash, now, now.Add(lifetime)); err != nil {
		return nil, fmt.Errorf("store webauthn challenge: %w", err)
	}
	return challenge, nil
}

// ConsumeWebAuthnChallenge spends a challenge exactly once and returns the
// administrator it was issued for ("" for passwordless sign-in). For a second
// factor, signInChallenge must be the sign-in the challenge was tied to.
func (store *Store) ConsumeWebAuthnChallenge(ctx context.Context, challenge []byte, purpose, signInChallenge string) (string, error) {
	hash := sha256.Sum256(challenge)
	var linked any
	if purpose == WebAuthnSecondFactor {
		if signInChallenge == "" {
			return "", ErrWebAuthnChallengeInvalid
		}
		value := signInChallengeHash(signInChallenge)
		linked = value[:]
	}
	var adminUserID *string
	err := store.pool.QueryRow(ctx, `
		UPDATE admin_webauthn_challenges SET consumed_at = $3
		WHERE challenge_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > $3
		  AND sign_in_challenge_hash IS NOT DISTINCT FROM $4
		RETURNING admin_user_id
	`, hash[:], purpose, store.now().UTC(), linked).Scan(&adminUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrWebAuthnChallengeInvalid
	}
	if err != nil {
		return "", fmt.Errorf("consume webauthn challenge: %w", err)
	}
	if adminUserID == nil {
		return "", nil
	}
	return *adminUserID, nil
}

// ListPasskeys returns an administrator's passkeys, oldest first.
func (store *Store) ListPasskeys(ctx context.Context, adminUserID string) ([]Passkey, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil {
		return nil, ErrInvalidAdminInput
	}
	rows, err := store.pool.Query(ctx, `
		SELECT admin_passkey_id, name, created_at, last_used_at, backup_state
		FROM admin_passkeys WHERE admin_user_id = $1 ORDER BY created_at, admin_passkey_id
	`, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	defer rows.Close()
	items := make([]Passkey, 0)
	for rows.Next() {
		var item Passkey
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedAt, &item.LastUsedAt, &item.Synced); err != nil {
			return nil, fmt.Errorf("scan passkey: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate passkeys: %w", err)
	}
	return items, nil
}

// PasskeyCredentialIDs lists an administrator's credential IDs for
// excludeCredentials and allowCredentials.
func (store *Store) PasskeyCredentialIDs(ctx context.Context, adminUserID string) ([][]byte, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil {
		return nil, ErrInvalidAdminInput
	}
	rows, err := store.pool.Query(ctx, `SELECT credential_id FROM admin_passkeys WHERE admin_user_id = $1 ORDER BY created_at`, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("list passkey credentials: %w", err)
	}
	defer rows.Close()
	ids := make([][]byte, 0)
	for rows.Next() {
		var credentialID []byte
		if err := rows.Scan(&credentialID); err != nil {
			return nil, fmt.Errorf("scan passkey credential: %w", err)
		}
		ids = append(ids, credentialID)
	}
	return ids, rows.Err()
}

// AddPasskey stores a verified registration. When the administrator has no
// unused recovery codes yet, recoveryHashes are stored too and issued is true.
func (store *Store) AddPasskey(ctx context.Context, principal Principal, passkey NewPasskey, recoveryHashes [][sha256.Size]byte, requestID string) (Passkey, bool, error) {
	name := strings.TrimSpace(passkey.Name)
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil || validateRequestID(requestID) != nil ||
		len(passkey.CredentialID) == 0 || len(passkey.CredentialID) > 1023 || len(passkey.X) != 32 || len(passkey.Y) != 32 ||
		name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\x00") {
		return Passkey{}, false, ErrInvalidAdminInput
	}
	passkeyID, err := store.newID(id.AdminPasskey)
	if err != nil {
		return Passkey{}, false, fmt.Errorf("generate passkey ID: %w", err)
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Passkey{}, false, fmt.Errorf("begin passkey registration: %w", err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_passkeys (admin_passkey_id, admin_user_id, credential_id, public_key_x, public_key_y,
			sign_count, aaguid, backup_eligible, backup_state, name, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, passkeyID, principal.AdminUserID, passkey.CredentialID, passkey.X, passkey.Y, int64(passkey.SignCount),
		passkey.AAGUID[:], passkey.BackupEligible, passkey.BackupState, name, now); err != nil {
		if isUniqueViolation(err) {
			return Passkey{}, false, ErrAdminConflict
		}
		return Passkey{}, false, fmt.Errorf("store passkey: %w", err)
	}
	var remaining int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admin_recovery_codes WHERE admin_user_id = $1 AND used_at IS NULL`, principal.AdminUserID).Scan(&remaining); err != nil {
		return Passkey{}, false, fmt.Errorf("count recovery codes: %w", err)
	}
	issued := remaining == 0 && len(recoveryHashes) > 0
	changes := []AuditChange{mustSensitiveAuditChange("passkey", AuditAdd)}
	if issued {
		if err := replaceRecoveryCodesTx(ctx, tx, principal.AdminUserID, recoveryHashes, now); err != nil {
			return Passkey{}, false, err
		}
		changes = append(changes, mustSensitiveAuditChange("recovery_codes", AuditSet))
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.passkey_add", principal.AdminUserID, requestID, now, changes); err != nil {
		return Passkey{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Passkey{}, false, fmt.Errorf("commit passkey registration: %w", err)
	}
	return Passkey{ID: passkeyID, Name: name, CreatedAt: now, Synced: passkey.BackupState}, issued, nil
}

// PasskeyByCredentialID finds a stored credential.
func (store *Store) PasskeyByCredentialID(ctx context.Context, credentialID []byte) (StoredPasskey, error) {
	if len(credentialID) == 0 || len(credentialID) > 1023 {
		return StoredPasskey{}, ErrAdminNotFound
	}
	var passkey StoredPasskey
	var signCount int64
	err := store.pool.QueryRow(ctx, `
		SELECT p.admin_passkey_id, p.admin_user_id, p.public_key_x, p.public_key_y, p.sign_count
		FROM admin_passkeys AS p JOIN admin_users AS u ON u.admin_user_id = p.admin_user_id
		WHERE p.credential_id = $1 AND u.status = 'active'
	`, credentialID).Scan(&passkey.ID, &passkey.AdminUserID, &passkey.X, &passkey.Y, &signCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredPasskey{}, ErrAdminNotFound
	}
	if err != nil {
		return StoredPasskey{}, fmt.Errorf("read passkey: %w", err)
	}
	passkey.SignCount = uint32(signCount)
	return passkey, nil
}

// RecordPasskeyUse stores an assertion's counter. Authenticators that report
// a counter must advance it; a counter of zero means the authenticator
// doesn't keep one, which synced passkeys commonly do.
func (store *Store) RecordPasskeyUse(ctx context.Context, passkeyID string, signCount uint32, backupState bool) error {
	tag, err := store.pool.Exec(ctx, `
		UPDATE admin_passkeys SET sign_count = $2, backup_state = $3, last_used_at = $4
		WHERE admin_passkey_id = $1 AND (sign_count < $2 OR ($2 = 0 AND sign_count = 0))
	`, passkeyID, int64(signCount), backupState, store.now().UTC())
	if err != nil {
		return fmt.Errorf("record passkey use: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrPasskeyCounter
	}
	return nil
}

// RemovePasskey deletes one of the administrator's own passkeys. It refuses
// to remove the last second factor while an organization requires one, and
// deletes the recovery codes when no second factor remains.
func (store *Store) RemovePasskey(ctx context.Context, principal Principal, passkeyID, requestID string) error {
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil || id.Validate(passkeyID, id.AdminPasskey) != nil || validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin passkey removal: %w", err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `DELETE FROM admin_passkeys WHERE admin_passkey_id = $1 AND admin_user_id = $2`, passkeyID, principal.AdminUserID)
	if err != nil {
		return fmt.Errorf("remove passkey: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAdminNotFound
	}
	if err := enforceRemainingFactorTx(ctx, tx, principal.AdminUserID); err != nil {
		return err
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.passkey_remove", principal.AdminUserID, requestID, now,
		[]AuditChange{mustSensitiveAuditChange("passkey", AuditRemove)}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit passkey removal: %w", err)
	}
	return nil
}

// enforceRemainingFactorTx runs after a factor was removed in tx: with none
// left it refuses when an organization requires one, and otherwise drops the
// now-unneeded recovery codes.
func enforceRemainingFactorTx(ctx context.Context, tx pgx.Tx, adminUserID string) error {
	var remaining, required bool
	if err := tx.QueryRow(ctx, `
		SELECT `+hasSecondFactorSQL("$1")+`,
		       EXISTS (
		           SELECT 1 FROM admin_memberships AS m JOIN organizations AS o ON o.organization_id = m.organization_id
		           WHERE m.admin_user_id = $1 AND m.status = 'active' AND o.require_two_factor
		       )
	`, adminUserID).Scan(&remaining, &required); err != nil {
		return fmt.Errorf("check remaining second factors: %w", err)
	}
	if remaining {
		return nil
	}
	if required {
		return ErrTwoFactorRequired
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_recovery_codes WHERE admin_user_id = $1`, adminUserID); err != nil {
		return fmt.Errorf("remove recovery codes: %w", err)
	}
	return nil
}
