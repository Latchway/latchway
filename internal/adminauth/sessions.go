package adminauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

const managedSessionRevokeReason = "administrator_session_management"

// AdminSessionPageRequest is a bounded keyset page over session creation time
// and session ID.
type AdminSessionPageRequest struct {
	After   time.Time
	AfterID string
	Size    int32
}

func (page AdminSessionPageRequest) validate() error {
	if page.Size < 1 || page.Size > 200 {
		return ErrInvalidAdminInput
	}
	if page.After.IsZero() != (page.AfterID == "") {
		return ErrInvalidAdminInput
	}
	if page.AfterID != "" && id.Validate(page.AfterID, id.AdminSession) != nil {
		return ErrInvalidAdminInput
	}
	return nil
}

// AdminSessionStatus is the server-computed lifecycle state of an opaque
// administrator session.
type AdminSessionStatus string

const (
	AdminSessionActive  AdminSessionStatus = "active"
	AdminSessionExpired AdminSessionStatus = "expired"
	AdminSessionRevoked AdminSessionStatus = "revoked"
)

func (status AdminSessionStatus) valid() bool {
	switch status {
	case AdminSessionActive, AdminSessionExpired, AdminSessionRevoked:
		return true
	default:
		return false
	}
}

// AdminSessionAdministrator is the value-safe identity attached to a session.
// It intentionally excludes membership, password, and credential material.
type AdminSessionAdministrator struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// AdminSessionMetadata is the redaction-safe administrator-session view.
// Token hashes, token hints, CSRF material, network metadata, and revocation
// reasons are deliberately absent.
type AdminSessionMetadata struct {
	ID            string                    `json:"id"`
	Administrator AdminSessionAdministrator `json:"administrator"`
	CreatedAt     time.Time                 `json:"created_at"`
	LastSeenAt    time.Time                 `json:"last_seen_at"`
	ExpiresAt     time.Time                 `json:"expires_at"`
	Status        AdminSessionStatus        `json:"status"`
	Current       bool                      `json:"current"`
}

// ListAdminSessions returns a tenant-scoped page of redaction-safe session
// metadata. The manage_owners capability is required, including for API-token
// principals.
func (store *Store) ListAdminSessions(
	ctx context.Context,
	principal Principal,
	page AdminSessionPageRequest,
) ([]AdminSessionMetadata, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return nil, err
	}
	if err := page.validate(); err != nil {
		return nil, err
	}
	currentSessionID, err := currentAdminSessionID(principal)
	if err != nil {
		return nil, err
	}
	var after any
	if !page.After.IsZero() {
		after = page.After.UTC()
	}
	now := store.now().UTC()
	rows, err := store.pool.Query(ctx, `
		SELECT session.admin_session_id,
		       admin_user.admin_user_id,
		       admin_user.email,
		       session.created_at,
		       session.last_seen_at,
		       session.expires_at,
		       CASE
		           WHEN session.revoked_at IS NOT NULL THEN 'revoked'
		           WHEN session.expires_at <= $4 THEN 'expired'
		           ELSE 'active'
		       END
		FROM admin_sessions AS session
		JOIN admin_users AS admin_user
		  ON admin_user.admin_user_id = session.admin_user_id
		WHERE session.organization_id = $1
		  AND ($2::timestamptz IS NULL OR (session.created_at, session.admin_session_id) > ($2, $3))
		ORDER BY session.created_at, session.admin_session_id
		LIMIT $5
	`, principal.OrganizationID, after, page.AfterID, now, page.Size+1)
	if err != nil {
		return nil, fmt.Errorf("list administrator sessions: %w", err)
	}
	defer rows.Close()
	items := make([]AdminSessionMetadata, 0)
	for rows.Next() {
		var item AdminSessionMetadata
		if err := rows.Scan(
			&item.ID,
			&item.Administrator.ID,
			&item.Administrator.Email,
			&item.CreatedAt,
			&item.LastSeenAt,
			&item.ExpiresAt,
			&item.Status,
		); err != nil {
			return nil, fmt.Errorf("scan administrator session metadata: %w", err)
		}
		if !item.Status.valid() {
			return nil, errors.New("stored administrator session status is invalid")
		}
		item.Current = currentSessionID != "" && item.ID == currentSessionID
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate administrator session metadata: %w", err)
	}
	return items, nil
}

func currentAdminSessionID(principal Principal) (string, error) {
	switch principal.Method {
	case AuthenticationSession:
		if id.Validate(principal.CredentialID, id.AdminSession) != nil {
			return "", ErrInvalidAdminInput
		}
		return principal.CredentialID, nil
	case AuthenticationAPIToken:
		if id.Validate(principal.CredentialID, id.AdminAPIToken) != nil {
			return "", ErrInvalidAdminInput
		}
		return "", nil
	default:
		return "", ErrInvalidAdminInput
	}
}

// RevokeManagedAdminSession revokes one session in the principal's active
// organization. The stored reason is fixed by the server and retries after a
// successful revocation are idempotent.
func (store *Store) RevokeManagedAdminSession(
	ctx context.Context,
	principal Principal,
	sessionID string,
	requestID string,
) error {
	if err := validateOwnerPrincipal(principal); err != nil {
		return err
	}
	if _, err := currentAdminSessionID(principal); err != nil {
		return err
	}
	if id.Validate(sessionID, id.AdminSession) != nil || validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin managed administrator-session revocation: %w", err)
	}
	defer rollback(tx)

	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return err
	}
	if !lockedOwnerAllows(locked, principal) {
		return ErrAdminAuthentication
	}
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT revoked_at
		FROM admin_sessions
		WHERE organization_id = $1 AND admin_session_id = $2
		FOR UPDATE
	`, principal.OrganizationID, sessionID).Scan(&revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAdminNotFound
	}
	if err != nil {
		return fmt.Errorf("lock managed administrator session: %w", err)
	}
	if revokedAt != nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_sessions
		SET revoked_at = $3, revoke_reason = $4
		WHERE organization_id = $1 AND admin_session_id = $2
	`, principal.OrganizationID, sessionID, now, managedSessionRevokeReason); err != nil {
		return fmt.Errorf("revoke managed administrator session: %w", err)
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate administrator-session audit event ID: %w", err)
	}
	actor, err := auditActorForPrincipal(principal)
	if err != nil {
		return err
	}
	mutation, err := NewAuditMutation(
		eventID,
		principal.OrganizationID,
		"",
		actor,
		"admin.session_revoke",
		"admin_session",
		sessionID,
		AuditSucceeded,
		requestID,
		now,
		[]AuditChange{mustSensitiveAuditChange("session_token", AuditRevoke)},
	)
	if err != nil {
		return err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit managed administrator-session revocation: %w", err)
	}
	return nil
}
