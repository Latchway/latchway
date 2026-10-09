package adminauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

// Revocation reasons recorded by administrator self-service.
const (
	revokeReasonPasswordChanged     = "password_changed"
	revokeReasonOrganizationSwitch  = "organization_switch"
	revokeReasonSignedOutElsewhere  = "signed_out_elsewhere"
	revokeReasonAdministratorLogout = "logout"
)

// SessionEndReason is the stable reason a presented console session no longer
// authenticates. It is disclosed only to the holder of that session's cookie.
type SessionEndReason string

const (
	SessionEndExpired            SessionEndReason = "expired"
	SessionEndSignedOut          SessionEndReason = "signed_out"
	SessionEndSignedOutElsewhere SessionEndReason = "signed_out_elsewhere"
	SessionEndRevokedByOwner     SessionEndReason = "revoked_by_owner"
	SessionEndPasswordReset      SessionEndReason = "password_reset"
	SessionEndPasswordChanged    SessionEndReason = "password_changed"
	SessionEndOrganizationSwitch SessionEndReason = "organization_switch"
	SessionEndAccessDisabled     SessionEndReason = "access_disabled"
	SessionEndTwoFactorReset     SessionEndReason = "two_factor_reset"
	SessionEndSSOChanged         SessionEndReason = "sso_changed"
	SessionEndOther              SessionEndReason = "other"
)

func sessionEndFromRevokeReason(reason string) SessionEndReason {
	switch reason {
	case revokeReasonAdministratorLogout:
		return SessionEndSignedOut
	case revokeReasonSignedOutElsewhere:
		return SessionEndSignedOutElsewhere
	case managedSessionRevokeReason:
		return SessionEndRevokedByOwner
	case "password_reset":
		return SessionEndPasswordReset
	case revokeReasonPasswordChanged:
		return SessionEndPasswordChanged
	case revokeReasonOrganizationSwitch:
		return SessionEndOrganizationSwitch
	case "administrator_disabled":
		return SessionEndAccessDisabled
	case revokeReasonTwoFactor:
		return SessionEndTwoFactorReset
	case revokeReasonSSOChanged:
		return SessionEndSSOChanged
	default:
		return SessionEndOther
	}
}

// EndedSessionReason explains why a session token that failed authentication
// stopped working. It returns false when the token never belonged to a
// session, so unknown cookies keep the generic authentication failure.
func (store *Store) EndedSessionReason(ctx context.Context, plaintext string) (SessionEndReason, bool, error) {
	hash, err := HashToken(AdminSessionKind, plaintext)
	if err != nil {
		return "", false, nil
	}
	var expired bool
	var revokeReason *string
	var disabled bool
	err = store.pool.QueryRow(ctx, `
		SELECT s.expires_at <= $2,
		       s.revoke_reason,
		       u.status <> 'active' OR m.status <> 'active'
		FROM admin_sessions AS s
		JOIN admin_users AS u ON u.admin_user_id = s.admin_user_id
		JOIN admin_memberships AS m
		  ON m.organization_id = s.organization_id AND m.admin_user_id = s.admin_user_id
		WHERE s.token_hash = $1
	`, hash.Bytes(), store.now().UTC()).Scan(&expired, &revokeReason, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read ended administrator session: %w", err)
	}
	switch {
	case revokeReason != nil:
		return sessionEndFromRevokeReason(*revokeReason), true, nil
	case disabled:
		return SessionEndAccessDisabled, true, nil
	case expired:
		return SessionEndExpired, true, nil
	default:
		return SessionEndOther, true, nil
	}
}

// PasswordCredentialByAdminUserID returns the stored password hash for an
// active administrator, for verifying the current password before a change.
func (store *Store) PasswordCredentialByAdminUserID(ctx context.Context, adminUserID string) (PasswordHash, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil {
		return PasswordHash{}, ErrInvalidAdminInput
	}
	var encoded string
	err := store.pool.QueryRow(ctx, `
		SELECT credential.password_hash
		FROM admin_password_credentials AS credential
		JOIN admin_users AS u ON u.admin_user_id = credential.admin_user_id
		WHERE credential.admin_user_id = $1 AND u.status = 'active'
	`, adminUserID).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return PasswordHash{}, ErrAdminAuthentication
	}
	if err != nil {
		return PasswordHash{}, fmt.Errorf("read administrator password credential: %w", err)
	}
	hash, err := ParsePasswordHash(encoded)
	if err != nil {
		return PasswordHash{}, fmt.Errorf("parse administrator password credential: %w", err)
	}
	return hash, nil
}

// ChangeOwnPassword replaces the signed-in administrator's password after the
// caller verified the current one, clears a pending forced change and signs
// out every other console session of this administrator in every
// organization. API tokens are unaffected. It returns how many sessions ended.
func (store *Store) ChangeOwnPassword(
	ctx context.Context,
	principal Principal,
	passwordHash PasswordHash,
	requestID string,
) (int64, error) {
	if principal.Method != AuthenticationSession ||
		id.Validate(principal.OrganizationID, id.Organization) != nil ||
		id.Validate(principal.AdminUserID, id.AdminUser) != nil ||
		id.Validate(principal.CredentialID, id.AdminSession) != nil ||
		validateRequestID(requestID) != nil {
		return 0, ErrInvalidAdminInput
	}
	if _, err := ParsePasswordHash(passwordHash.Encoded()); err != nil {
		return 0, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin administrator password change: %w", err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `
		UPDATE admin_password_credentials AS credential
		SET password_hash = $2, changed_at = $3, reset_by_admin_user_id = $1
		FROM admin_users AS u
		WHERE credential.admin_user_id = $1
		  AND u.admin_user_id = credential.admin_user_id
		  AND u.status = 'active'
	`, principal.AdminUserID, passwordHash.Encoded(), now)
	if err != nil {
		return 0, fmt.Errorf("change administrator password: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return 0, ErrAdminAuthentication
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_users SET password_reset_required = false, updated_at = $2 WHERE admin_user_id = $1
	`, principal.AdminUserID, now); err != nil {
		return 0, fmt.Errorf("clear administrator password reset: %w", err)
	}
	revoked, err := tx.Exec(ctx, `
		UPDATE admin_sessions
		SET revoked_at = $3, revoke_reason = $4
		WHERE admin_user_id = $1 AND admin_session_id <> $2
		  AND revoked_at IS NULL AND expires_at > $3
	`, principal.AdminUserID, principal.CredentialID, now, revokeReasonPasswordChanged)
	if err != nil {
		return 0, fmt.Errorf("sign out other administrator sessions: %w", err)
	}
	changes := []AuditChange{mustSensitiveAuditChange("password_hash", AuditRotate)}
	if revoked.RowsAffected() > 0 {
		changes = append(changes, mustSensitiveAuditChange("session_tokens", AuditRevoke))
	}
	if err := store.insertAdministratorAudit(ctx, tx, principal, "admin.password_change", principal.AdminUserID, requestID, now, changes); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit administrator password change: %w", err)
	}
	return revoked.RowsAffected(), nil
}

// SwitchSessionOrganization replaces the signed-in console session with a new
// session for another organization the administrator belongs to. The old
// session is revoked in the same transaction, so exactly one stays usable.
func (store *Store) SwitchSessionOrganization(
	ctx context.Context,
	principal Principal,
	targetOrganizationID string,
	lifetime time.Duration,
	deviceSummary string,
	requestID string,
) (IssuedSession, error) {
	if principal.Method != AuthenticationSession ||
		id.Validate(principal.CredentialID, id.AdminSession) != nil ||
		principal.OrganizationID == targetOrganizationID {
		return IssuedSession{}, ErrInvalidAdminInput
	}
	if principal.SignInMethod == SignInSSO {
		return IssuedSession{}, ErrSSOSessionSwitch
	}
	input := CreateSessionInput{
		OrganizationID: targetOrganizationID, AdminUserID: principal.AdminUserID,
		Lifetime: lifetime, RequestID: requestID, DeviceSummary: deviceSummary,
		SignInMethod: principal.SignInMethod,
	}
	if err := input.validate(); err != nil {
		return IssuedSession{}, err
	}
	issued, created, err := store.prepareSession(input)
	if err != nil {
		return IssuedSession{}, err
	}
	now := created.CreatedAt()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin organization switch: %w", err)
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `
		UPDATE admin_sessions
		SET revoked_at = $3, revoke_reason = $4
		WHERE admin_session_id = $1 AND admin_user_id = $2
		  AND revoked_at IS NULL AND expires_at > $3
	`, principal.CredentialID, principal.AdminUserID, now, revokeReasonOrganizationSwitch)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("end switched administrator session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return IssuedSession{}, ErrAdminAuthentication
	}
	if err := store.insertPreparedSession(ctx, tx, input, issued, created); err != nil {
		return IssuedSession{}, err
	}
	actor, err := NewAdminUserActor(principal.AdminUserID)
	if err != nil {
		return IssuedSession{}, err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	ended, err := NewAuditMutation(
		eventID, principal.OrganizationID, "", actor, "admin.session_revoke", "admin_session",
		principal.CredentialID, AuditSucceeded, requestID, now,
		[]AuditChange{mustSensitiveAuditChange("session_token", AuditRevoke)},
	)
	if err != nil {
		return IssuedSession{}, err
	}
	if err := insertAuditMutation(ctx, tx, ended); err != nil {
		return IssuedSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit organization switch: %w", err)
	}
	return issued, nil
}

// OwnSessionMetadata is one of the signed-in administrator's own console
// sessions, in any organization. EndReason is set for ended sessions.
type OwnSessionMetadata struct {
	ID             string             `json:"id"`
	OrganizationID string             `json:"organization_id"`
	DeviceSummary  *string            `json:"device_summary,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	LastSeenAt     time.Time          `json:"last_seen_at"`
	ExpiresAt      time.Time          `json:"expires_at"`
	Status         AdminSessionStatus `json:"status"`
	EndReason      *SessionEndReason  `json:"end_reason,omitempty"`
	Current        bool               `json:"current"`
}

// ownSessionWindow bounds how far back ended sessions are listed.
const ownSessionWindow = 30 * 24 * time.Hour

// ListOwnSessions returns the administrator's own active sessions and those
// that ended within the last 30 days, newest activity first, at most 100.
func (store *Store) ListOwnSessions(ctx context.Context, principal Principal) ([]OwnSessionMetadata, error) {
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil {
		return nil, ErrInvalidAdminInput
	}
	currentSessionID, err := currentAdminSessionID(principal)
	if err != nil {
		return nil, err
	}
	now := store.now().UTC()
	rows, err := store.pool.Query(ctx, `
		SELECT admin_session_id, organization_id, device_summary, created_at, last_seen_at, expires_at,
		       CASE
		           WHEN revoked_at IS NOT NULL THEN 'revoked'
		           WHEN expires_at <= $2 THEN 'expired'
		           ELSE 'active'
		       END,
		       revoke_reason
		FROM admin_sessions
		WHERE admin_user_id = $1
		  AND COALESCE(revoked_at, expires_at) > $3
		ORDER BY last_seen_at DESC, admin_session_id
		LIMIT 100
	`, principal.AdminUserID, now, now.Add(-ownSessionWindow))
	if err != nil {
		return nil, fmt.Errorf("list own administrator sessions: %w", err)
	}
	defer rows.Close()
	items := make([]OwnSessionMetadata, 0)
	for rows.Next() {
		var item OwnSessionMetadata
		var revokeReason *string
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.DeviceSummary, &item.CreatedAt,
			&item.LastSeenAt, &item.ExpiresAt, &item.Status, &revokeReason); err != nil {
			return nil, fmt.Errorf("scan own administrator session: %w", err)
		}
		if !item.Status.valid() {
			return nil, errors.New("stored administrator session status is invalid")
		}
		switch {
		case revokeReason != nil:
			reason := sessionEndFromRevokeReason(*revokeReason)
			item.EndReason = &reason
		case item.Status == AdminSessionExpired:
			reason := SessionEndExpired
			item.EndReason = &reason
		}
		item.Current = currentSessionID != "" && item.ID == currentSessionID
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate own administrator sessions: %w", err)
	}
	return items, nil
}

// RevokeOwnSessions signs out the administrator's own active sessions: one
// session by ID, or (with sessionID empty) every session except the current
// one. Each organization that loses a session records an audit event. It
// returns how many sessions ended.
func (store *Store) RevokeOwnSessions(ctx context.Context, principal Principal, sessionID string, requestID string) (int64, error) {
	if id.Validate(principal.AdminUserID, id.AdminUser) != nil || validateRequestID(requestID) != nil {
		return 0, ErrInvalidAdminInput
	}
	if sessionID != "" && id.Validate(sessionID, id.AdminSession) != nil {
		return 0, ErrInvalidAdminInput
	}
	currentSessionID, err := currentAdminSessionID(principal)
	if err != nil {
		return 0, err
	}
	if sessionID == "" && currentSessionID == "" {
		return 0, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin own session revocation: %w", err)
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `
		UPDATE admin_sessions
		SET revoked_at = $4, revoke_reason = $5
		WHERE admin_user_id = $1
		  AND revoked_at IS NULL AND expires_at > $4
		  AND (($2 <> '' AND admin_session_id = $2) OR ($2 = '' AND admin_session_id <> $3))
		RETURNING admin_session_id, organization_id
	`, principal.AdminUserID, sessionID, currentSessionID, now, revokeReasonSignedOutElsewhere)
	if err != nil {
		return 0, fmt.Errorf("revoke own administrator sessions: %w", err)
	}
	type ended struct{ sessionID, organizationID string }
	endedSessions := make([]ended, 0)
	for rows.Next() {
		var item ended
		if err := rows.Scan(&item.sessionID, &item.organizationID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan revoked own session: %w", err)
		}
		endedSessions = append(endedSessions, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate revoked own sessions: %w", err)
	}
	if sessionID != "" && len(endedSessions) == 0 {
		return 0, ErrAdminNotFound
	}
	actor, err := auditActorForPrincipal(principal)
	if err != nil {
		return 0, err
	}
	for _, item := range endedSessions {
		eventID, err := store.newID(id.AuditEvent)
		if err != nil {
			return 0, fmt.Errorf("generate audit event ID: %w", err)
		}
		mutation, err := NewAuditMutation(
			eventID, item.organizationID, "", actor, "admin.session_revoke", "admin_session",
			item.sessionID, AuditSucceeded, requestID, now,
			[]AuditChange{mustSensitiveAuditChange("session_token", AuditRevoke)},
		)
		if err != nil {
			return 0, err
		}
		if err := insertAuditMutation(ctx, tx, mutation); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit own session revocation: %w", err)
	}
	return int64(len(endedSessions)), nil
}

// ListOrganizationAPITokens returns metadata for every administrator's API
// tokens in the principal's organization. It requires manage_owners.
func (store *Store) ListOrganizationAPITokens(ctx context.Context, principal Principal) ([]APITokenMetadata, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT token.admin_api_token_id, token.name, token.scopes, token.created_at, token.expires_at,
		       token.last_used_at, token.revoked_at IS NOT NULL, u.admin_user_id, u.email
		FROM admin_api_tokens AS token
		JOIN admin_users AS u ON u.admin_user_id = token.admin_user_id
		WHERE token.organization_id = $1
		ORDER BY token.created_at, token.admin_api_token_id
	`, principal.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("list organization API tokens: %w", err)
	}
	defer rows.Close()
	items := make([]APITokenMetadata, 0)
	for rows.Next() {
		var item APITokenMetadata
		var owner AdminSessionAdministrator
		if err := rows.Scan(&item.ID, &item.Name, &item.Scopes, &item.CreatedAt, &item.ExpiresAt,
			&item.LastUsedAt, &item.Revoked, &owner.ID, &owner.Email); err != nil {
			return nil, fmt.Errorf("scan organization API token: %w", err)
		}
		item.Administrator = &owner
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate organization API tokens: %w", err)
	}
	return items, nil
}

// SignInState is what a password sign-in needs beyond the credential check.
type SignInState struct {
	// LastOrganizationID is the organization of the most recent session, or "".
	LastOrganizationID string
	// PasswordResetRequired means an owner set the password and the
	// administrator must choose their own before doing anything else.
	PasswordResetRequired bool
}

// SignInState reads the administrator's last organization and forced-change flag.
func (store *Store) SignInState(ctx context.Context, adminUserID string) (SignInState, error) {
	if id.Validate(adminUserID, id.AdminUser) != nil {
		return SignInState{}, ErrInvalidAdminInput
	}
	var state SignInState
	var organizationID *string
	err := store.pool.QueryRow(ctx, `
		SELECT last_organization_id, password_reset_required FROM admin_users WHERE admin_user_id = $1
	`, adminUserID).Scan(&organizationID, &state.PasswordResetRequired)
	if errors.Is(err, pgx.ErrNoRows) {
		return SignInState{}, ErrAdminNotFound
	}
	if err != nil {
		return SignInState{}, fmt.Errorf("read administrator sign-in state: %w", err)
	}
	if organizationID != nil {
		state.LastOrganizationID = *organizationID
	}
	return state, nil
}

// BootstrapOpen reports whether first-owner setup can still be completed: a
// bootstrap token is installed and unconsumed and no owner exists yet.
func (store *Store) BootstrapOpen(ctx context.Context) (bool, error) {
	var open bool
	err := store.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM admin_bootstrap_tokens
			WHERE consumed_at IS NULL AND (expires_at IS NULL OR expires_at > $1)
		) AND NOT EXISTS (
			SELECT 1 FROM admin_memberships WHERE role = 'owner'
		)
	`, store.now().UTC()).Scan(&open)
	if err != nil {
		return false, fmt.Errorf("read bootstrap availability: %w", err)
	}
	return open, nil
}
