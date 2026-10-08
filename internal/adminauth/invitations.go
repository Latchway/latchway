package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrInvitationInvalid covers unknown, expired, revoked and used invitations alike.
	ErrInvitationInvalid = errors.New("invitation is invalid")
	// ErrInvitationAccount means the invited address already has an account,
	// so the invitation must be claimed by signing in to it.
	ErrInvitationAccount = errors.New("the invited address already has an account")
	// ErrInvitationEmail means a signed-in administrator tried to claim an
	// invitation for a different address.
	ErrInvitationEmail = errors.New("the invitation is for another address")
	// ErrAlreadyMember means the address already belongs to the organization.
	ErrAlreadyMember = errors.New("the address already belongs to the organization")
)

// InvitationTokenPrefix starts every invitation token.
const InvitationTokenPrefix = "lwinv_"

// Invitation status values.
const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationRevoked  = "revoked"
	InvitationExpired  = "expired"
)

// Invitation is an invitation as owners see it.
type Invitation struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName *string    `json:"display_name,omitempty"`
	Role        Role       `json:"role"`
	Status      string     `json:"status"`
	InvitedBy   string     `json:"invited_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	EmailStatus string     `json:"email_status"`
	EmailSentAt *time.Time `json:"email_sent_at,omitempty"`
}

// InvitationPreview is what the person holding an invitation link may see.
type InvitationPreview struct {
	OrganizationID   string    `json:"organization_id"`
	OrganizationName string    `json:"organization_name"`
	Email            string    `json:"email"`
	DisplayName      *string   `json:"display_name,omitempty"`
	Role             Role      `json:"role"`
	InvitedBy        string    `json:"invited_by"`
	ExpiresAt        time.Time `json:"expires_at"`
	AccountExists    bool      `json:"account_exists"`
}

// NewInvitationToken returns a fresh token and its stored hash.
func NewInvitationToken() (string, [sha256.Size]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("generate invitation token: %w", err)
	}
	token := InvitationTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashInvitationToken(token), nil
}

// HashInvitationToken is how invitation tokens are stored and looked up.
func HashInvitationToken(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte("latchway/admin/invitation/v1\x00" + token))
}

// ValidInvitationToken checks a token's shape before any lookup.
func ValidInvitationToken(token string) bool {
	if !strings.HasPrefix(token, InvitationTokenPrefix) || len(token) != len(InvitationTokenPrefix)+43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, InvitationTokenPrefix))
	return err == nil
}

const invitationColumns = `i.admin_invitation_id, i.email, i.display_name, i.role,
	CASE WHEN i.accepted_at IS NOT NULL THEN 'accepted' WHEN i.revoked_at IS NOT NULL THEN 'revoked'
	     WHEN i.expires_at <= $1 THEN 'expired' ELSE 'pending' END,
	creator.display_name, i.created_at, i.expires_at, i.accepted_at, i.revoked_at, i.email_status, i.email_sent_at`

func scanInvitation(row pgx.Row) (Invitation, error) {
	var item Invitation
	err := row.Scan(&item.ID, &item.Email, &item.DisplayName, &item.Role, &item.Status, &item.InvitedBy,
		&item.CreatedAt, &item.ExpiresAt, &item.AcceptedAt, &item.RevokedAt, &item.EmailStatus, &item.EmailSentAt)
	return item, err
}

// CreateInvitationInput describes one invitation.
type CreateInvitationInput struct {
	Email       string
	DisplayName string
	Role        Role
	TokenHash   [sha256.Size]byte
	Lifetime    time.Duration
	RequestID   string
}

// CreateInvitation invites an address to the owner's organization, replacing
// any open invitation for the same address.
func (store *Store) CreateInvitation(ctx context.Context, principal Principal, input CreateInvitationInput) (Invitation, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return Invitation{}, err
	}
	normalized, err := NormalizeEmail(input.Email)
	if err != nil || input.Role.Validate() != nil || validateRequestID(input.RequestID) != nil ||
		input.Lifetime < time.Hour || input.Lifetime > 30*24*time.Hour ||
		(input.DisplayName != "" && validateDisplayName(input.DisplayName) != nil) {
		return Invitation{}, ErrInvalidAdminInput
	}
	invitationID, err := store.newID(id.AdminInvitation)
	if err != nil {
		return Invitation{}, fmt.Errorf("generate invitation ID: %w", err)
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Invitation{}, fmt.Errorf("begin invitation: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Invitation{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Invitation{}, ErrAdminAuthentication
	}
	for _, member := range locked {
		if strings.EqualFold(strings.TrimSpace(member.administrator.Email), normalized) {
			return Invitation{}, ErrAlreadyMember
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_invitations SET revoked_at = $3
		WHERE organization_id = $1 AND email_normalized = $2 AND accepted_at IS NULL AND revoked_at IS NULL
	`, principal.OrganizationID, normalized, now); err != nil {
		return Invitation{}, fmt.Errorf("replace earlier invitation: %w", err)
	}
	var displayName *string
	if name := strings.TrimSpace(input.DisplayName); name != "" {
		displayName = &name
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_invitations (admin_invitation_id, organization_id, email, email_normalized, display_name, role,
			token_hash, created_by_admin_user_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, invitationID, principal.OrganizationID, strings.TrimSpace(input.Email), normalized, displayName, string(input.Role),
		input.TokenHash[:], principal.AdminUserID, now, now.Add(input.Lifetime)); err != nil {
		return Invitation{}, fmt.Errorf("create invitation: %w", err)
	}
	if err := store.insertInvitationAudit(ctx, tx, principal, "admin.invitation_create", invitationID, input.RequestID, now, []AuditChange{
		mustSensitiveAuditChange("email", AuditSet), mustPublicAuditChange("role", AuditSet), mustSensitiveAuditChange("invitation_token", AuditSet),
	}); err != nil {
		return Invitation{}, err
	}
	created, err := readInvitationTx(ctx, tx, principal.OrganizationID, invitationID, now)
	if err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Invitation{}, fmt.Errorf("commit invitation: %w", err)
	}
	return created, nil
}

func readInvitationTx(ctx context.Context, tx pgx.Tx, organizationID, invitationID string, now time.Time) (Invitation, error) {
	item, err := scanInvitation(tx.QueryRow(ctx, `
		SELECT `+invitationColumns+`
		FROM admin_invitations AS i JOIN admin_users AS creator ON creator.admin_user_id = i.created_by_admin_user_id
		WHERE i.organization_id = $2 AND i.admin_invitation_id = $3
	`, now, organizationID, invitationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrAdminNotFound
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("read invitation: %w", err)
	}
	return item, nil
}

func (store *Store) insertInvitationAudit(ctx context.Context, tx pgx.Tx, principal Principal, action, invitationID, requestID string, now time.Time, changes []AuditChange) error {
	actor, err := auditActorForPrincipal(principal)
	if err != nil {
		return err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate audit event ID: %w", err)
	}
	mutation, err := NewAuditMutation(eventID, principal.OrganizationID, "", actor, action, "admin_invitation", invitationID,
		AuditSucceeded, requestID, now, changes)
	if err != nil {
		return err
	}
	return insertAuditMutation(ctx, tx, mutation)
}

// ListInvitations returns the organization's recent invitations, newest first.
func (store *Store) ListInvitations(ctx context.Context, principal Principal) ([]Invitation, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT `+invitationColumns+`
		FROM admin_invitations AS i JOIN admin_users AS creator ON creator.admin_user_id = i.created_by_admin_user_id
		WHERE i.organization_id = $2
		ORDER BY i.created_at DESC, i.admin_invitation_id DESC
		LIMIT 200
	`, store.now().UTC(), principal.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer rows.Close()
	items := make([]Invitation, 0)
	for rows.Next() {
		item, err := scanInvitation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invitations: %w", err)
	}
	return items, nil
}

// RevokeInvitation stops an open invitation from being used.
func (store *Store) RevokeInvitation(ctx context.Context, principal Principal, invitationID, requestID string) (Invitation, error) {
	return store.changeOpenInvitation(ctx, principal, invitationID, requestID, "admin.invitation_revoke",
		`UPDATE admin_invitations SET revoked_at = $3 WHERE organization_id = $1 AND admin_invitation_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
		[]AuditChange{mustSensitiveAuditChange("invitation_token", AuditRevoke)})
}

// RenewInvitation gives an open or expired invitation a new link and expiry;
// the earlier link stops working.
func (store *Store) RenewInvitation(ctx context.Context, principal Principal, invitationID string, tokenHash [sha256.Size]byte, lifetime time.Duration, requestID string) (Invitation, error) {
	if lifetime < time.Hour || lifetime > 30*24*time.Hour {
		return Invitation{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	return store.changeOpenInvitation(ctx, principal, invitationID, requestID, "admin.invitation_renew",
		`UPDATE admin_invitations SET token_hash = $4, expires_at = $5, email_status = 'not_requested', email_sent_at = NULL
		 WHERE organization_id = $1 AND admin_invitation_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL AND $3::timestamptz IS NOT NULL`,
		[]AuditChange{mustSensitiveAuditChange("invitation_token", AuditRotate)}, tokenHash[:], now.Add(lifetime))
}

func (store *Store) changeOpenInvitation(ctx context.Context, principal Principal, invitationID, requestID, action, statement string, changes []AuditChange, extra ...any) (Invitation, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return Invitation{}, err
	}
	if id.Validate(invitationID, id.AdminInvitation) != nil || validateRequestID(requestID) != nil {
		return Invitation{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Invitation{}, fmt.Errorf("begin invitation change: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return Invitation{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return Invitation{}, ErrAdminAuthentication
	}
	arguments := append([]any{principal.OrganizationID, invitationID, now}, extra...)
	tag, err := tx.Exec(ctx, statement, arguments...)
	if err != nil {
		return Invitation{}, fmt.Errorf("change invitation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		if _, err := readInvitationTx(ctx, tx, principal.OrganizationID, invitationID, now); err != nil {
			return Invitation{}, err
		}
		return Invitation{}, ErrInvitationInvalid
	}
	if err := store.insertInvitationAudit(ctx, tx, principal, action, invitationID, requestID, now, changes); err != nil {
		return Invitation{}, err
	}
	changed, err := readInvitationTx(ctx, tx, principal.OrganizationID, invitationID, now)
	if err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Invitation{}, fmt.Errorf("commit invitation change: %w", err)
	}
	return changed, nil
}

// RecordInvitationEmail notes whether the invitation email went out.
func (store *Store) RecordInvitationEmail(ctx context.Context, organizationID, invitationID string, sent bool) error {
	status := "failed"
	var sentAt any
	if sent {
		status = "sent"
		sentAt = store.now().UTC()
	}
	if _, err := store.pool.Exec(ctx, `
		UPDATE admin_invitations SET email_status = $3, email_sent_at = $4 WHERE organization_id = $1 AND admin_invitation_id = $2
	`, organizationID, invitationID, status, sentAt); err != nil {
		return fmt.Errorf("record invitation email: %w", err)
	}
	return nil
}

// PreviewInvitation reads an open invitation by its token.
func (store *Store) PreviewInvitation(ctx context.Context, token string) (InvitationPreview, error) {
	if !ValidInvitationToken(token) {
		return InvitationPreview{}, ErrInvitationInvalid
	}
	hash := HashInvitationToken(token)
	var preview InvitationPreview
	err := store.pool.QueryRow(ctx, `
		SELECT i.organization_id, o.display_name, i.email, i.display_name, i.role, creator.display_name, i.expires_at,
		       EXISTS (SELECT 1 FROM admin_users AS u WHERE u.email_normalized = i.email_normalized)
		FROM admin_invitations AS i
		JOIN organizations AS o ON o.organization_id = i.organization_id
		JOIN admin_users AS creator ON creator.admin_user_id = i.created_by_admin_user_id
		WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > $2
	`, hash[:], store.now().UTC()).Scan(&preview.OrganizationID, &preview.OrganizationName, &preview.Email, &preview.DisplayName,
		&preview.Role, &preview.InvitedBy, &preview.ExpiresAt, &preview.AccountExists)
	if errors.Is(err, pgx.ErrNoRows) {
		return InvitationPreview{}, ErrInvitationInvalid
	}
	if err != nil {
		return InvitationPreview{}, fmt.Errorf("read invitation: %w", err)
	}
	return preview, nil
}

type openInvitation struct {
	id             string
	organizationID string
	emailNormalize string
	email          string
	role           Role
}

func lockOpenInvitation(ctx context.Context, tx pgx.Tx, token string, now time.Time) (openInvitation, error) {
	if !ValidInvitationToken(token) {
		return openInvitation{}, ErrInvitationInvalid
	}
	hash := HashInvitationToken(token)
	var invitation openInvitation
	err := tx.QueryRow(ctx, `
		SELECT admin_invitation_id, organization_id, email_normalized, email, role FROM admin_invitations
		WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $2
		FOR UPDATE
	`, hash[:], now).Scan(&invitation.id, &invitation.organizationID, &invitation.emailNormalize, &invitation.email, &invitation.role)
	if errors.Is(err, pgx.ErrNoRows) {
		return openInvitation{}, ErrInvitationInvalid
	}
	if err != nil {
		return openInvitation{}, fmt.Errorf("lock invitation: %w", err)
	}
	return invitation, nil
}

// AcceptedInvitation names the administrator and organization an accepted
// invitation joined.
type AcceptedInvitation struct {
	AdminUserID    string
	OrganizationID string
	Role           Role
}

// AcceptInvitationWithNewAccount creates the invited account with a password
// its holder chose, and its membership.
func (store *Store) AcceptInvitationWithNewAccount(ctx context.Context, token, displayName string, passwordHash PasswordHash, requestID string) (AcceptedInvitation, error) {
	if validateDisplayName(displayName) != nil || validateRequestID(requestID) != nil {
		return AcceptedInvitation{}, ErrInvalidAdminInput
	}
	if _, err := ParsePasswordHash(passwordHash.Encoded()); err != nil {
		return AcceptedInvitation{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return AcceptedInvitation{}, fmt.Errorf("begin invitation acceptance: %w", err)
	}
	defer rollback(tx)
	invitation, err := lockOpenInvitation(ctx, tx, token, now)
	if err != nil {
		return AcceptedInvitation{}, err
	}
	adminUserID, err := store.newID(id.AdminUser)
	if err != nil {
		return AcceptedInvitation{}, fmt.Errorf("generate administrator ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name, status, created_at, updated_at, password_reset_required)
		VALUES ($1, $2, $3, $4, 'active', $5, $5, false)
	`, adminUserID, invitation.email, invitation.emailNormalize, strings.TrimSpace(displayName), now); err != nil {
		if isUniqueViolation(err) {
			return AcceptedInvitation{}, ErrInvitationAccount
		}
		return AcceptedInvitation{}, fmt.Errorf("create invited administrator: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_password_credentials (admin_user_id, password_hash, created_at, changed_at) VALUES ($1, $2, $3, $3)
	`, adminUserID, passwordHash.Encoded(), now); err != nil {
		return AcceptedInvitation{}, fmt.Errorf("create invited administrator password: %w", err)
	}
	return store.finishInvitation(ctx, tx, invitation, adminUserID, requestID, now, true)
}

// ClaimInvitation adds the signed-in administrator to the invitation's
// organization; the invitation must be for their address.
func (store *Store) ClaimInvitation(ctx context.Context, principal Principal, token, requestID string) (AcceptedInvitation, error) {
	if principal.Method != AuthenticationSession || id.Validate(principal.AdminUserID, id.AdminUser) != nil || validateRequestID(requestID) != nil {
		return AcceptedInvitation{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return AcceptedInvitation{}, fmt.Errorf("begin invitation claim: %w", err)
	}
	defer rollback(tx)
	invitation, err := lockOpenInvitation(ctx, tx, token, now)
	if err != nil {
		return AcceptedInvitation{}, err
	}
	var email string
	if err := tx.QueryRow(ctx, `SELECT email_normalized FROM admin_users WHERE admin_user_id = $1 AND status = 'active'`, principal.AdminUserID).Scan(&email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AcceptedInvitation{}, ErrAdminAuthentication
		}
		return AcceptedInvitation{}, fmt.Errorf("read administrator email: %w", err)
	}
	if email != invitation.emailNormalize {
		return AcceptedInvitation{}, ErrInvitationEmail
	}
	return store.finishInvitation(ctx, tx, invitation, principal.AdminUserID, requestID, now, false)
}

func (store *Store) finishInvitation(ctx context.Context, tx pgx.Tx, invitation openInvitation, adminUserID, requestID string, now time.Time, created bool) (AcceptedInvitation, error) {
	membershipID, err := store.newID(id.AdminMembership)
	if err != nil {
		return AcceptedInvitation{}, fmt.Errorf("generate administrator membership ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', $5, $5)
	`, membershipID, invitation.organizationID, adminUserID, string(invitation.role), now); err != nil {
		if isUniqueViolation(err) {
			return AcceptedInvitation{}, ErrAlreadyMember
		}
		return AcceptedInvitation{}, fmt.Errorf("create invited membership: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_invitations SET accepted_at = $2, accepted_admin_user_id = $3 WHERE admin_invitation_id = $1
	`, invitation.id, now, adminUserID); err != nil {
		return AcceptedInvitation{}, fmt.Errorf("accept invitation: %w", err)
	}
	actor, err := NewAdminUserActor(adminUserID)
	if err != nil {
		return AcceptedInvitation{}, err
	}
	changes := []AuditChange{mustSensitiveAuditChange("invitation_token", AuditConsume), mustPublicAuditChange("role", AuditSet)}
	if created {
		changes = append(changes, mustSensitiveAuditChange("password_hash", AuditSet))
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return AcceptedInvitation{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	mutation, err := NewAuditMutation(eventID, invitation.organizationID, "", actor, "admin.invitation_accept", "admin_invitation", invitation.id,
		AuditSucceeded, requestID, now, changes)
	if err != nil {
		return AcceptedInvitation{}, err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return AcceptedInvitation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AcceptedInvitation{}, fmt.Errorf("commit invitation acceptance: %w", err)
	}
	return AcceptedInvitation{AdminUserID: adminUserID, OrganizationID: invitation.organizationID, Role: invitation.role}, nil
}

// OrganizationName reads an organization's display name.
func (store *Store) OrganizationName(ctx context.Context, organizationID string) (string, error) {
	var name string
	if err := store.pool.QueryRow(ctx, `SELECT display_name FROM organizations WHERE organization_id = $1`, organizationID).Scan(&name); err != nil {
		return "", fmt.Errorf("read organization name: %w", err)
	}
	return name, nil
}
