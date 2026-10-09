package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrTwoFactorRequired means an organization the administrator belongs to
	// requires a second factor, so it can't be turned off.
	ErrTwoFactorRequired = errors.New("an organization requires two-factor sign-in")
	// ErrSignInChallengeInvalid covers unknown, expired, used and exhausted
	// second-factor sign-in attempts alike.
	ErrSignInChallengeInvalid = errors.New("sign-in challenge is invalid")
)

// hasSecondFactorSQL is true when the administrator named by the SQL
// expression adminUserID has a confirmed authenticator app or a passkey.
func hasSecondFactorSQL(adminUserID string) string {
	return `(EXISTS (SELECT 1 FROM admin_totp_factors AS f WHERE f.admin_user_id = ` + adminUserID + ` AND f.confirmed_at IS NOT NULL)` +
		` OR EXISTS (SELECT 1 FROM admin_passkeys AS p WHERE p.admin_user_id = ` + adminUserID + `))`
}

// confirmedSecondFactorSQL is true when the session's administrator (`s`) has a
// second factor.
var confirmedSecondFactorSQL = hasSecondFactorSQL("s.admin_user_id")

const (
	signInChallengeAttempts = 5
	revokeReasonTwoFactor   = "two_factor_reset"
)

// SealedFactor is an authenticator key sealed by the master key for one
// administrator. Only the API layer can open it.
type SealedFactor struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

// TwoFactorStatus is an administrator's second-factor state.
type TwoFactorStatus struct {
	// Enabled is true when any second factor is set up.
	Enabled                bool       `json:"enabled"`
	TOTPConfirmed          bool       `json:"totp_enabled"`
	TOTPConfirmedAt        *time.Time `json:"totp_enabled_at,omitempty"`
	Passkeys               int        `json:"passkeys"`
	RecoveryCodesRemaining int        `json:"recovery_codes_remaining"`
	// RequiredByOrganization is filled for the organization of the session.
	RequiredByOrganization bool `json:"required_by_organization"`
}

// TwoFactorStatus reads an administrator's second factor and, when an
// organization is given, whether it requires one.
func (store *Store) TwoFactorStatus(ctx context.Context, adminUserID, organizationID string) (TwoFactorStatus, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil || (organizationID != "" && id.Validate(organizationID, id.Organization) != nil) {
		return TwoFactorStatus{}, ErrInvalidAdminInput
	}
	var status TwoFactorStatus
	err := store.pool.QueryRow(ctx, `
		SELECT (SELECT confirmed_at FROM admin_totp_factors WHERE admin_user_id = $1),
		       (SELECT count(*) FROM admin_passkeys WHERE admin_user_id = $1),
		       (SELECT count(*) FROM admin_recovery_codes WHERE admin_user_id = $1 AND used_at IS NULL),
		       COALESCE((SELECT require_two_factor FROM organizations WHERE organization_id = NULLIF($2, '')), false)
	`, adminUserID, organizationID).Scan(&status.TOTPConfirmedAt, &status.Passkeys, &status.RecoveryCodesRemaining, &status.RequiredByOrganization)
	if err != nil {
		return TwoFactorStatus{}, fmt.Errorf("read two-factor status: %w", err)
	}
	status.TOTPConfirmed = status.TOTPConfirmedAt != nil
	status.Enabled = status.TOTPConfirmed || status.Passkeys > 0
	return status, nil
}

// SaveTOTPEnrollment stores a new, unconfirmed authenticator key, replacing
// any earlier unconfirmed one. A confirmed key must be turned off first.
func (store *Store) SaveTOTPEnrollment(ctx context.Context, adminUserID string, sealed SealedFactor) error {
	if id.Validate(adminUserID, id.AdminUser) != nil || sealed.KeyID == "" || len(sealed.Nonce) != 12 || len(sealed.Ciphertext) < 17 {
		return ErrInvalidAdminInput
	}
	tag, err := store.pool.Exec(ctx, `
		INSERT INTO admin_totp_factors (admin_user_id, key_id, nonce, ciphertext, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (admin_user_id) DO UPDATE
		SET key_id = EXCLUDED.key_id, nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext,
		    created_at = EXCLUDED.created_at, last_used_step = NULL
		WHERE admin_totp_factors.confirmed_at IS NULL
	`, adminUserID, sealed.KeyID, sealed.Nonce, sealed.Ciphertext, store.now().UTC())
	if err != nil {
		return fmt.Errorf("save authenticator enrollment: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAdminConflict
	}
	return nil
}

// TOTPFactor returns the sealed authenticator key and whether it is confirmed.
func (store *Store) TOTPFactor(ctx context.Context, adminUserID string) (SealedFactor, bool, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil {
		return SealedFactor{}, false, ErrInvalidAdminInput
	}
	var sealed SealedFactor
	var confirmedAt *time.Time
	err := store.pool.QueryRow(ctx, `
		SELECT key_id, nonce, ciphertext, confirmed_at FROM admin_totp_factors WHERE admin_user_id = $1
	`, adminUserID).Scan(&sealed.KeyID, &sealed.Nonce, &sealed.Ciphertext, &confirmedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SealedFactor{}, false, ErrAdminNotFound
	}
	if err != nil {
		return SealedFactor{}, false, fmt.Errorf("read authenticator key: %w", err)
	}
	return sealed, confirmedAt != nil, nil
}

// ConfirmTOTP confirms a pending authenticator key with the time step of a
// valid code and replaces the recovery codes, all in one transaction.
func (store *Store) ConfirmTOTP(ctx context.Context, principal Principal, step int64, recoveryHashes [][sha256.Size]byte, requestID string) error {
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil || step <= 0 || len(recoveryHashes) == 0 || validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin authenticator confirmation: %w", err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `
		UPDATE admin_totp_factors SET confirmed_at = $2, last_used_step = $3
		WHERE admin_user_id = $1 AND confirmed_at IS NULL
	`, principal.AdminUserID, now, step)
	if err != nil {
		return fmt.Errorf("confirm authenticator key: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAdminConflict
	}
	if err := replaceRecoveryCodesTx(ctx, tx, principal.AdminUserID, recoveryHashes, now); err != nil {
		return err
	}
	changes := []AuditChange{mustSensitiveAuditChange("totp_key", AuditSet), mustSensitiveAuditChange("recovery_codes", AuditSet)}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.two_factor_enable", principal.AdminUserID, requestID, now, changes); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit authenticator confirmation: %w", err)
	}
	return nil
}

// UseTOTPStep records a confirmed key's newest accepted time step. It returns
// false when the step was already used, so a code works at most once.
func (store *Store) UseTOTPStep(ctx context.Context, adminUserID string, step int64) (bool, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil || step <= 0 {
		return false, ErrInvalidAdminInput
	}
	tag, err := store.pool.Exec(ctx, `
		UPDATE admin_totp_factors SET last_used_step = $2
		WHERE admin_user_id = $1 AND confirmed_at IS NOT NULL
		  AND (last_used_step IS NULL OR last_used_step < $2)
	`, adminUserID, step)
	if err != nil {
		return false, fmt.Errorf("record authenticator use: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UseRecoveryCode spends one unused recovery code and audits it in the
// organization being signed in to. It returns false when the code is unknown
// or already used.
func (store *Store) UseRecoveryCode(ctx context.Context, adminUserID, organizationID string, hash [sha256.Size]byte, requestID string) (bool, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil || id.Validate(organizationID, id.Organization) != nil || validateRequestID(requestID) != nil {
		return false, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, fmt.Errorf("begin recovery code use: %w", err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `
		UPDATE admin_recovery_codes SET used_at = $3
		WHERE admin_user_id = $1 AND code_hash = $2 AND used_at IS NULL
	`, adminUserID, hash[:], now)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	actor, err := NewAdminUserActor(adminUserID)
	if err != nil {
		return false, err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return false, fmt.Errorf("generate audit event ID: %w", err)
	}
	mutation, err := NewAuditMutation(eventID, organizationID, "", actor, "admin.recovery_code_use", "admin_user", adminUserID,
		AuditSucceeded, requestID, now, []AuditChange{mustSensitiveAuditChange("recovery_codes", AuditConsume)})
	if err != nil {
		return false, err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit recovery code use: %w", err)
	}
	return true, nil
}

// ReplaceRecoveryCodes issues a fresh set of recovery codes for an
// administrator with a second factor.
func (store *Store) ReplaceRecoveryCodes(ctx context.Context, principal Principal, recoveryHashes [][sha256.Size]byte, requestID string) error {
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil || len(recoveryHashes) == 0 || validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin recovery code replacement: %w", err)
	}
	defer rollback(tx)
	var confirmed bool
	if err := tx.QueryRow(ctx, `SELECT `+hasSecondFactorSQL("$1"), principal.AdminUserID).Scan(&confirmed); err != nil {
		return fmt.Errorf("check second factor: %w", err)
	}
	if !confirmed {
		return ErrAdminConflict
	}
	if err := replaceRecoveryCodesTx(ctx, tx, principal.AdminUserID, recoveryHashes, now); err != nil {
		return err
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.recovery_codes_replace", principal.AdminUserID, requestID, now,
		[]AuditChange{mustSensitiveAuditChange("recovery_codes", AuditRotate)}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit recovery code replacement: %w", err)
	}
	return nil
}

func replaceRecoveryCodesTx(ctx context.Context, tx pgx.Tx, adminUserID string, hashes [][sha256.Size]byte, now time.Time) error {
	if _, err := tx.Exec(ctx, `DELETE FROM admin_recovery_codes WHERE admin_user_id = $1`, adminUserID); err != nil {
		return fmt.Errorf("remove recovery codes: %w", err)
	}
	for _, hash := range hashes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO admin_recovery_codes (admin_user_id, code_hash, created_at) VALUES ($1, $2, $3)
		`, adminUserID, hash[:], now); err != nil {
			return fmt.Errorf("store recovery code: %w", err)
		}
	}
	return nil
}

// DisableTwoFactor removes the administrator's own authenticator app. When no
// passkey remains it also removes the recovery codes, and it refuses then if
// any of their organizations requires a second factor.
func (store *Store) DisableTwoFactor(ctx context.Context, principal Principal, requestID string) error {
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil || validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin two-factor removal: %w", err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `DELETE FROM admin_totp_factors WHERE admin_user_id = $1 AND confirmed_at IS NOT NULL`, principal.AdminUserID)
	if err != nil {
		return fmt.Errorf("remove authenticator key: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAdminNotFound
	}
	var passkeys bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM admin_passkeys WHERE admin_user_id = $1)`, principal.AdminUserID).Scan(&passkeys); err != nil {
		return fmt.Errorf("check passkeys: %w", err)
	}
	if err := enforceRemainingFactorTx(ctx, tx, principal.AdminUserID); err != nil {
		return err
	}
	changes := []AuditChange{mustSensitiveAuditChange("totp_key", AuditRevoke)}
	if !passkeys {
		changes = append(changes, mustSensitiveAuditChange("recovery_codes", AuditRevoke))
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.two_factor_disable", principal.AdminUserID, requestID, now, changes); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit two-factor removal: %w", err)
	}
	return nil
}

// ResetAdministratorTwoFactor lets an owner remove another member's
// authenticator app, passkeys and recovery codes, ending that member's sessions in the
// organization. Like a password reset it refuses accounts that also belong to
// other organizations, because the factor is global to the account.
func (store *Store) ResetAdministratorTwoFactor(ctx context.Context, principal Principal, targetAdminUserID, requestID string) (Administrator, error) {
	if err := validateLifecycleInput(principal, targetAdminUserID, requestID); err != nil {
		return Administrator{}, err
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Administrator{}, fmt.Errorf("begin two-factor reset: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Administrator{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Administrator{}, ErrAdminAuthentication
	}
	if _, ok := locked[targetAdminUserID]; !ok {
		return Administrator{}, ErrAdminNotFound
	}
	var otherMemberships int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM admin_memberships WHERE admin_user_id = $1 AND organization_id <> $2
	`, targetAdminUserID, principal.OrganizationID).Scan(&otherMemberships); err != nil {
		return Administrator{}, fmt.Errorf("check cross-organization administrator memberships: %w", err)
	}
	if otherMemberships != 0 {
		return Administrator{}, ErrAdminConflict
	}
	totp, err := tx.Exec(ctx, `DELETE FROM admin_totp_factors WHERE admin_user_id = $1`, targetAdminUserID)
	if err != nil {
		return Administrator{}, fmt.Errorf("remove authenticator key: %w", err)
	}
	passkeys, err := tx.Exec(ctx, `DELETE FROM admin_passkeys WHERE admin_user_id = $1`, targetAdminUserID)
	if err != nil {
		return Administrator{}, fmt.Errorf("remove passkeys: %w", err)
	}
	if totp.RowsAffected() == 0 && passkeys.RowsAffected() == 0 {
		return Administrator{}, ErrAdminNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_recovery_codes WHERE admin_user_id = $1`, targetAdminUserID); err != nil {
		return Administrator{}, fmt.Errorf("remove recovery codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_sessions SET revoked_at = $3, revoke_reason = $4
		WHERE organization_id = $1 AND admin_user_id = $2 AND revoked_at IS NULL
	`, principal.OrganizationID, targetAdminUserID, now, revokeReasonTwoFactor); err != nil {
		return Administrator{}, fmt.Errorf("revoke administrator sessions: %w", err)
	}
	changes := make([]AuditChange, 0, 4)
	if totp.RowsAffected() != 0 {
		changes = append(changes, mustSensitiveAuditChange("totp_key", AuditRevoke))
	}
	if passkeys.RowsAffected() != 0 {
		changes = append(changes, mustSensitiveAuditChange("passkeys", AuditRevoke))
	}
	changes = append(changes,
		mustSensitiveAuditChange("recovery_codes", AuditRevoke),
		mustSensitiveAuditChange("session_tokens", AuditRevoke),
	)
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.two_factor_reset", targetAdminUserID, requestID, now, changes); err != nil {
		return Administrator{}, err
	}
	updated, err := readAdministratorTx(ctx, tx, principal.OrganizationID, targetAdminUserID)
	if err != nil {
		return Administrator{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Administrator{}, fmt.Errorf("commit two-factor reset: %w", err)
	}
	return updated, nil
}

// SetOrganizationTwoFactorRequirement turns the organization's two-factor
// requirement on or off. It requires an active owner.
func (store *Store) SetOrganizationTwoFactorRequirement(ctx context.Context, principal Principal, required bool, requestID string) error {
	if err := validateOwnerPrincipal(principal); err != nil {
		return err
	}
	if validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin organization security update: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return err
	}
	if !lockedOwnerAllows(locked, principal) {
		return ErrAdminAuthentication
	}
	if _, err := tx.Exec(ctx, `UPDATE organizations SET require_two_factor = $2 WHERE organization_id = $1`, principal.OrganizationID, required); err != nil {
		return fmt.Errorf("update organization two-factor requirement: %w", err)
	}
	actor, err := auditActorForPrincipal(principal)
	if err != nil {
		return err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate audit event ID: %w", err)
	}
	mutation, err := NewAuditMutation(eventID, principal.OrganizationID, "", actor, "admin.organization_security_update", "organization",
		principal.OrganizationID, AuditSucceeded, requestID, now, []AuditChange{mustPublicAuditChange("require_two_factor", AuditSet)})
	if err != nil {
		return err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit organization security update: %w", err)
	}
	return nil
}

// SignInChallenge is a pending second-factor sign-in.
type SignInChallenge struct {
	AdminUserID    string
	OrganizationID string
	DeviceSummary  string
}

// CreateSignInChallenge records that a password was correct and returns the
// opaque value that lets the second factor finish signing in.
func (store *Store) CreateSignInChallenge(ctx context.Context, challenge SignInChallenge, lifetime time.Duration) (string, time.Time, error) {
	if id.Validate(challenge.AdminUserID, id.AdminUser) != nil || id.Validate(challenge.OrganizationID, id.Organization) != nil ||
		lifetime < time.Minute || lifetime > 15*time.Minute ||
		(challenge.DeviceSummary != "" && !deviceSummaryPattern.MatchString(challenge.DeviceSummary)) {
		return "", time.Time{}, ErrInvalidAdminInput
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate sign-in challenge: %w", err)
	}
	plaintext := "lwsic_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plaintext))
	now := store.now().UTC()
	expiresAt := now.Add(lifetime)
	if _, err := store.pool.Exec(ctx, `
		DELETE FROM admin_sign_in_challenges WHERE expires_at < $1
	`, now.Add(-time.Hour)); err != nil {
		return "", time.Time{}, fmt.Errorf("prune sign-in challenges: %w", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO admin_sign_in_challenges (challenge_hash, admin_user_id, organization_id, device_summary, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, hash[:], challenge.AdminUserID, challenge.OrganizationID, nullableString(challenge.DeviceSummary), now, expiresAt); err != nil {
		return "", time.Time{}, fmt.Errorf("store sign-in challenge: %w", err)
	}
	return plaintext, expiresAt, nil
}

// PendingSignInChallenge reads a usable challenge without consuming it.
func (store *Store) PendingSignInChallenge(ctx context.Context, plaintext string) (SignInChallenge, error) {
	if len(plaintext) < 16 || len(plaintext) > 128 {
		return SignInChallenge{}, ErrSignInChallengeInvalid
	}
	hash := sha256.Sum256([]byte(plaintext))
	var challenge SignInChallenge
	var device *string
	err := store.pool.QueryRow(ctx, `
		SELECT admin_user_id, organization_id, device_summary FROM admin_sign_in_challenges
		WHERE challenge_hash = $1 AND consumed_at IS NULL AND expires_at > $2 AND failed_attempts < $3
	`, hash[:], store.now().UTC(), signInChallengeAttempts).Scan(&challenge.AdminUserID, &challenge.OrganizationID, &device)
	if errors.Is(err, pgx.ErrNoRows) {
		return SignInChallenge{}, ErrSignInChallengeInvalid
	}
	if err != nil {
		return SignInChallenge{}, fmt.Errorf("read sign-in challenge: %w", err)
	}
	if device != nil {
		challenge.DeviceSummary = *device
	}
	return challenge, nil
}

// FailSignInChallenge counts a wrong second factor; the fifth ends the challenge.
func (store *Store) FailSignInChallenge(ctx context.Context, plaintext string) error {
	hash := sha256.Sum256([]byte(plaintext))
	if _, err := store.pool.Exec(ctx, `
		UPDATE admin_sign_in_challenges SET failed_attempts = least(failed_attempts + 1, $2)
		WHERE challenge_hash = $1 AND consumed_at IS NULL
	`, hash[:], signInChallengeAttempts); err != nil {
		return fmt.Errorf("record failed second factor: %w", err)
	}
	return nil
}

// ConsumeSignInChallenge marks a challenge used exactly once.
func (store *Store) ConsumeSignInChallenge(ctx context.Context, plaintext string) error {
	hash := sha256.Sum256([]byte(plaintext))
	tag, err := store.pool.Exec(ctx, `
		UPDATE admin_sign_in_challenges SET consumed_at = $2
		WHERE challenge_hash = $1 AND consumed_at IS NULL AND expires_at > $2 AND failed_attempts < $3
	`, hash[:], store.now().UTC(), signInChallengeAttempts)
	if err != nil {
		return fmt.Errorf("consume sign-in challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrSignInChallengeInvalid
	}
	return nil
}
