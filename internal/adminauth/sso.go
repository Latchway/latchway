package adminauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrSSONotConfigured means the organization has no enabled identity provider.
	ErrSSONotConfigured = errors.New("single sign-on is not configured")
	// ErrSSOStateInvalid covers unknown, expired, used and browser-mismatched logins.
	ErrSSOStateInvalid = errors.New("single sign-on login is invalid")
	// ErrSSONoAccount means the verified identity matches no administrator and
	// the organization doesn't create accounts.
	ErrSSONoAccount = errors.New("no administrator matches the identity")
	// ErrSSOEmailUnverified means the provider didn't vouch for the email the
	// identity would be matched or provisioned by.
	ErrSSOEmailUnverified = errors.New("the identity provider didn't verify the email")
	// ErrSSODomain means the email's domain isn't one the organization allows.
	ErrSSODomain = errors.New("the email domain is not allowed")
	// ErrSSORequired means the organization requires single sign-on for this
	// administrator, so another sign-in method can't open a session there.
	ErrSSORequired = errors.New("the organization requires single sign-on")
	// ErrSSOSessionSwitch means a single sign-on session can't move to another
	// organization, whose own sign-in rules apply.
	ErrSSOSessionSwitch = errors.New("a single sign-on session can't switch organization")
	// ErrSSOBusy means too many single sign-on logins are pending for the organization.
	ErrSSOBusy = errors.New("too many pending single sign-on logins")
)

// revokeReasonSSOChanged ends sessions an owner's single sign-on change no
// longer allows.
const revokeReasonSSOChanged = "sso_changed"

// maxPendingSSOLogins bounds the logins anyone can start for one organization
// without credentials, so the table can't be grown without limit.
const maxPendingSSOLogins = 500

var emailDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// SSOProvider is an organization's identity provider as owners see it. The
// client secret is never returned.
type SSOProvider struct {
	Issuer                string    `json:"issuer"`
	ClientID              string    `json:"client_id"`
	AuthorizationEndpoint string    `json:"authorization_endpoint"`
	TokenEndpoint         string    `json:"token_endpoint"`
	JWKSURI               string    `json:"jwks_uri"`
	AllowedEmailDomains   []string  `json:"allowed_email_domains"`
	ProvisionRole         *Role     `json:"provision_role"`
	Enabled               bool      `json:"enabled"`
	RequireSSO            bool      `json:"require_sso"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// StoredSSOProvider adds what signing in needs.
type StoredSSOProvider struct {
	SSOProvider
	OrganizationID string
	Secret         SealedFactor
}

// SaveSSOProviderInput replaces the provider. A nil Secret keeps the stored one.
type SaveSSOProviderInput struct {
	Issuer                string
	ClientID              string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	Secret                *SealedFactor
	AllowedEmailDomains   []string
	ProvisionRole         *Role
	Enabled               bool
	RequireSSO            bool
}

// NormalizeEmailDomains lowercases, deduplicates and validates domains.
func NormalizeEmailDomains(values []string) ([]string, error) {
	if len(values) > 20 {
		return nil, ErrInvalidAdminInput
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "@")))
		if len(domain) > 253 || !emailDomainPattern.MatchString(domain) {
			return nil, ErrInvalidAdminInput
		}
		if !slices.Contains(normalized, domain) {
			normalized = append(normalized, domain)
		}
	}
	slices.Sort(normalized)
	return normalized, nil
}

func (input SaveSSOProviderInput) validate() error {
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" || len(clientID) > 512 || clientID != input.ClientID {
		return ErrInvalidAdminInput
	}
	for _, value := range []string{input.Issuer, input.AuthorizationEndpoint, input.TokenEndpoint, input.JWKSURI} {
		if !strings.HasPrefix(value, "https://") || len(value) > 2048 {
			return ErrInvalidAdminInput
		}
	}
	if input.Secret != nil && (input.Secret.KeyID == "" || len(input.Secret.Nonce) != 12 || len(input.Secret.Ciphertext) < 17 || len(input.Secret.Ciphertext) > 2048) {
		return ErrInvalidAdminInput
	}
	if input.ProvisionRole != nil && (*input.ProvisionRole == RoleOwner || input.ProvisionRole.Validate() != nil) {
		return ErrInvalidAdminInput
	}
	if input.RequireSSO && !input.Enabled {
		return ErrInvalidAdminInput
	}
	return nil
}

const ssoProviderColumns = `issuer, client_id, authorization_endpoint, token_endpoint, jwks_uri, allowed_email_domains,
	provision_role, enabled, require_sso, created_at, updated_at, organization_id, secret_key_id, secret_nonce, secret_ciphertext`

func scanSSOProvider(row pgx.Row) (StoredSSOProvider, error) {
	var provider StoredSSOProvider
	var role *string
	err := row.Scan(&provider.Issuer, &provider.ClientID, &provider.AuthorizationEndpoint, &provider.TokenEndpoint, &provider.JWKSURI,
		&provider.AllowedEmailDomains, &role, &provider.Enabled, &provider.RequireSSO, &provider.CreatedAt, &provider.UpdatedAt,
		&provider.OrganizationID, &provider.Secret.KeyID, &provider.Secret.Nonce, &provider.Secret.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredSSOProvider{}, ErrSSONotConfigured
	}
	if err != nil {
		return StoredSSOProvider{}, fmt.Errorf("read single sign-on provider: %w", err)
	}
	if role != nil {
		value := Role(*role)
		provider.ProvisionRole = &value
	}
	if provider.AllowedEmailDomains == nil {
		provider.AllowedEmailDomains = []string{}
	}
	return provider, nil
}

// OrganizationSSOProvider reads an organization's provider, enabled or not.
func (store *Store) OrganizationSSOProvider(ctx context.Context, organizationID string) (StoredSSOProvider, error) {
	if id.Validate(organizationID, id.Organization) != nil {
		return StoredSSOProvider{}, ErrInvalidAdminInput
	}
	return scanSSOProvider(store.pool.QueryRow(ctx, `SELECT `+ssoProviderColumns+` FROM organization_sso_providers WHERE organization_id = $1`, organizationID))
}

// EnabledSSOProviderBySlug finds the enabled provider of the organization with slug.
func (store *Store) EnabledSSOProviderBySlug(ctx context.Context, slug string) (StoredSSOProvider, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" || len(slug) > 128 {
		return StoredSSOProvider{}, ErrSSONotConfigured
	}
	return scanSSOProvider(store.pool.QueryRow(ctx, `
		SELECT `+ssoProviderColumns+` FROM organization_sso_providers
		WHERE enabled AND organization_id = (SELECT organization_id FROM organizations WHERE slug = $1)
	`, slug))
}

// AnySSOEnabled reports whether any organization offers single sign-on.
func (store *Store) AnySSOEnabled(ctx context.Context) (bool, error) {
	var enabled bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organization_sso_providers WHERE enabled)`).Scan(&enabled); err != nil {
		return false, fmt.Errorf("check single sign-on providers: %w", err)
	}
	return enabled, nil
}

// SaveSSOProvider creates or replaces the organization's provider. It requires
// an active owner, and a new provider must come with a client secret.
func (store *Store) SaveSSOProvider(ctx context.Context, principal Principal, input SaveSSOProviderInput, requestID string) (SSOProvider, error) {
	if err := validateOwnerPrincipal(principal); err != nil {
		return SSOProvider{}, err
	}
	domains, err := NormalizeEmailDomains(input.AllowedEmailDomains)
	if err != nil || input.validate() != nil || validateRequestID(requestID) != nil {
		return SSOProvider{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return SSOProvider{}, fmt.Errorf("begin single sign-on update: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return SSOProvider{}, err
	}
	if !lockedOwnerAllows(locked, principal) {
		return SSOProvider{}, ErrAdminAuthentication
	}
	var role *string
	if input.ProvisionRole != nil {
		value := string(*input.ProvisionRole)
		role = &value
	}
	changes := []AuditChange{
		mustPublicAuditChange("issuer", AuditSet), mustPublicAuditChange("client_id", AuditSet),
		mustPublicAuditChange("allowed_email_domains", AuditSet), mustPublicAuditChange("provision_role", AuditSet),
		mustPublicAuditChange("enabled", AuditSet), mustPublicAuditChange("require_sso", AuditSet),
	}
	var tag interface{ RowsAffected() int64 }
	if input.Secret != nil {
		changes = append(changes, mustSensitiveAuditChange("client_secret", AuditSet))
		tag, err = tx.Exec(ctx, `
			INSERT INTO organization_sso_providers (
				organization_id, issuer, authorization_endpoint, token_endpoint, jwks_uri, client_id,
				secret_key_id, secret_nonce, secret_ciphertext, allowed_email_domains, provision_role,
				enabled, require_sso, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
			ON CONFLICT (organization_id) DO UPDATE SET
				issuer = EXCLUDED.issuer, authorization_endpoint = EXCLUDED.authorization_endpoint,
				token_endpoint = EXCLUDED.token_endpoint, jwks_uri = EXCLUDED.jwks_uri, client_id = EXCLUDED.client_id,
				secret_key_id = EXCLUDED.secret_key_id, secret_nonce = EXCLUDED.secret_nonce,
				secret_ciphertext = EXCLUDED.secret_ciphertext, allowed_email_domains = EXCLUDED.allowed_email_domains,
				provision_role = EXCLUDED.provision_role, enabled = EXCLUDED.enabled, require_sso = EXCLUDED.require_sso,
				updated_at = EXCLUDED.updated_at
		`, principal.OrganizationID, input.Issuer, input.AuthorizationEndpoint, input.TokenEndpoint, input.JWKSURI, input.ClientID,
			input.Secret.KeyID, input.Secret.Nonce, input.Secret.Ciphertext, domains, role, input.Enabled, input.RequireSSO, now)
	} else {
		tag, err = tx.Exec(ctx, `
			UPDATE organization_sso_providers SET
				issuer = $2, authorization_endpoint = $3, token_endpoint = $4, jwks_uri = $5, client_id = $6,
				allowed_email_domains = $7, provision_role = $8, enabled = $9, require_sso = $10, updated_at = $11
			WHERE organization_id = $1
		`, principal.OrganizationID, input.Issuer, input.AuthorizationEndpoint, input.TokenEndpoint, input.JWKSURI, input.ClientID,
			domains, role, input.Enabled, input.RequireSSO, now)
	}
	if err != nil {
		return SSOProvider{}, fmt.Errorf("save single sign-on provider: %w", err)
	}
	if tag.RowsAffected() != 1 {
		// Without a stored provider there's no secret to keep.
		return SSOProvider{}, ErrSSONotConfigured
	}
	// Disabling ends single sign-on sessions; requiring it ends members' other sessions.
	ended := int64(0)
	if !input.Enabled {
		if ended, err = revokeSSOChangedSessions(ctx, tx, principal, now, `s.sign_in_method = 'sso'`); err != nil {
			return SSOProvider{}, err
		}
	} else if input.RequireSSO {
		if ended, err = revokeSSOChangedSessions(ctx, tx, principal, now, `s.sign_in_method <> 'sso' AND m.role <> 'owner'`); err != nil {
			return SSOProvider{}, err
		}
	}
	if ended > 0 {
		changes = append(changes, mustSensitiveAuditChange("session_tokens", AuditRevoke))
	}
	if err := store.insertOrganizationAudit(ctx, tx, principal, "admin.sso_configure", requestID, now, changes); err != nil {
		return SSOProvider{}, err
	}
	saved, err := scanSSOProvider(tx.QueryRow(ctx, `SELECT `+ssoProviderColumns+` FROM organization_sso_providers WHERE organization_id = $1`, principal.OrganizationID))
	if err != nil {
		return SSOProvider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SSOProvider{}, fmt.Errorf("commit single sign-on update: %w", err)
	}
	return saved.SSOProvider, nil
}

// RemoveSSOProvider deletes the organization's provider and every identity
// linked through it. Members keep their accounts and other sign-in methods.
func (store *Store) RemoveSSOProvider(ctx context.Context, principal Principal, requestID string) error {
	if err := validateOwnerPrincipal(principal); err != nil {
		return err
	}
	if validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin single sign-on removal: %w", err)
	}
	defer rollback(tx)
	locked, err := lockOrganizationAdministrators(ctx, tx, principal.OrganizationID)
	if err != nil {
		return err
	}
	if !lockedOwnerAllows(locked, principal) {
		return ErrAdminAuthentication
	}
	tag, err := tx.Exec(ctx, `DELETE FROM organization_sso_providers WHERE organization_id = $1`, principal.OrganizationID)
	if err != nil {
		return fmt.Errorf("remove single sign-on provider: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrSSONotConfigured
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_sso_identities WHERE organization_id = $1`, principal.OrganizationID); err != nil {
		return fmt.Errorf("remove single sign-on identities: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_sso_states WHERE organization_id = $1`, principal.OrganizationID); err != nil {
		return fmt.Errorf("remove pending single sign-on logins: %w", err)
	}
	changes := []AuditChange{mustSensitiveAuditChange("client_secret", AuditRemove), mustPublicAuditChange("enabled", AuditClear)}
	if ended, err := revokeSSOChangedSessions(ctx, tx, principal, now, `s.sign_in_method = 'sso'`); err != nil {
		return err
	} else if ended > 0 {
		changes = append(changes, mustSensitiveAuditChange("session_tokens", AuditRevoke))
	}
	if err := store.insertOrganizationAudit(ctx, tx, principal, "admin.sso_remove", requestID, now, changes); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit single sign-on removal: %w", err)
	}
	return nil
}

// revokeSSOChangedSessions ends the organization's active sessions matching
// condition (over sessions s and memberships m), except the acting session.
func revokeSSOChangedSessions(ctx context.Context, tx pgx.Tx, principal Principal, now time.Time, condition string) (int64, error) {
	acting := ""
	if principal.Method == AuthenticationSession {
		acting = principal.CredentialID
	}
	tag, err := tx.Exec(ctx, `
		UPDATE admin_sessions AS s SET revoked_at = $2, revoke_reason = $3
		FROM admin_memberships AS m
		WHERE s.organization_id = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND s.admin_session_id <> $4
		  AND m.organization_id = s.organization_id AND m.admin_user_id = s.admin_user_id AND `+condition, principal.OrganizationID, now, revokeReasonSSOChanged, acting)
	if err != nil {
		return 0, fmt.Errorf("end sessions after a single sign-on change: %w", err)
	}
	return tag.RowsAffected(), nil
}

// insertOrganizationAudit records an owner's change to the organization itself.
func (store *Store) insertOrganizationAudit(ctx context.Context, tx pgx.Tx, principal Principal, action, requestID string, now time.Time, changes []AuditChange) error {
	actor, err := auditActorForPrincipal(principal)
	if err != nil {
		return err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate audit event ID: %w", err)
	}
	mutation, err := NewAuditMutation(eventID, principal.OrganizationID, "", actor, action, "organization", principal.OrganizationID,
		AuditSucceeded, requestID, now, changes)
	if err != nil {
		return err
	}
	return insertAuditMutation(ctx, tx, mutation)
}

// SSOLoginState is a pending single sign-on login.
type SSOLoginState struct {
	OrganizationID string
	Nonce          string
	CodeVerifier   string
}

// CreateSSOState stores a login between the redirect and the callback. The
// state and the browser binding are stored only as hashes.
func (store *Store) CreateSSOState(ctx context.Context, state, browserBinding string, login SSOLoginState, lifetime time.Duration) error {
	if len(state) < 32 || len(browserBinding) < 32 || id.Validate(login.OrganizationID, id.Organization) != nil ||
		len(login.Nonce) < 32 || len(login.CodeVerifier) < 43 || lifetime < time.Minute || lifetime > 15*time.Minute {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	if _, err := store.pool.Exec(ctx, `DELETE FROM admin_sso_states WHERE expires_at < $1`, now.Add(-time.Hour)); err != nil {
		return fmt.Errorf("prune single sign-on logins: %w", err)
	}
	var pending int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*) FROM admin_sso_states WHERE organization_id = $1 AND consumed_at IS NULL AND expires_at > $2
	`, login.OrganizationID, now).Scan(&pending); err != nil {
		return fmt.Errorf("count pending single sign-on logins: %w", err)
	}
	if pending >= maxPendingSSOLogins {
		return ErrSSOBusy
	}
	stateHash := sha256.Sum256([]byte(state))
	browserHash := sha256.Sum256([]byte(browserBinding))
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO admin_sso_states (state_hash, browser_hash, organization_id, nonce, code_verifier, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, stateHash[:], browserHash[:], login.OrganizationID, login.Nonce, login.CodeVerifier, now, now.Add(lifetime)); err != nil {
		return fmt.Errorf("store single sign-on login: %w", err)
	}
	return nil
}

// ConsumeSSOState spends a login exactly once, only from the browser that
// started it.
func (store *Store) ConsumeSSOState(ctx context.Context, state, browserBinding string) (SSOLoginState, error) {
	if len(state) < 32 || len(state) > 128 || len(browserBinding) < 32 || len(browserBinding) > 128 {
		return SSOLoginState{}, ErrSSOStateInvalid
	}
	stateHash := sha256.Sum256([]byte(state))
	browserHash := sha256.Sum256([]byte(browserBinding))
	var login SSOLoginState
	err := store.pool.QueryRow(ctx, `
		UPDATE admin_sso_states SET consumed_at = $3
		WHERE state_hash = $1 AND browser_hash = $2 AND consumed_at IS NULL AND expires_at > $3
		RETURNING organization_id, nonce, code_verifier
	`, stateHash[:], browserHash[:], store.now().UTC()).Scan(&login.OrganizationID, &login.Nonce, &login.CodeVerifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return SSOLoginState{}, ErrSSOStateInvalid
	}
	if err != nil {
		return SSOLoginState{}, fmt.Errorf("consume single sign-on login: %w", err)
	}
	return login, nil
}

// SSOIdentity is what the identity provider verified.
type SSOIdentity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// SSOResolution is the administrator a verified identity signs in as.
type SSOResolution struct {
	AdminUserID string
	// Linked is true when this sign-in linked the identity to an existing
	// administrator; Provisioned when it created the account or membership.
	Linked      bool
	Provisioned bool
}

func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// ResolveSSOIdentity finds or creates the administrator a verified identity
// signs in as within one organization:
//   - an identity already linked signs in as its administrator;
//   - otherwise a verified email in an allowed domain links to the active
//     member with that email;
//   - otherwise, when the organization provisions accounts, it adds a
//     membership with the provisioning role, creating the account if needed.
//
// Accounts created this way have no password.
func (store *Store) ResolveSSOIdentity(ctx context.Context, provider StoredSSOProvider, identity SSOIdentity, requestID string) (SSOResolution, error) {
	if id.Validate(provider.OrganizationID, id.Organization) != nil || identity.Issuer != provider.Issuer ||
		identity.Subject == "" || len(identity.Subject) > 255 || validateRequestID(requestID) != nil {
		return SSOResolution{}, ErrInvalidAdminInput
	}
	now := store.now().UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return SSOResolution{}, fmt.Errorf("begin single sign-on resolution: %w", err)
	}
	defer rollback(tx)
	var linked string
	err = tx.QueryRow(ctx, `
		UPDATE admin_sso_identities SET last_used_at = $4
		WHERE organization_id = $1 AND issuer = $2 AND subject = $3
		RETURNING admin_user_id
	`, provider.OrganizationID, identity.Issuer, identity.Subject, now).Scan(&linked)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return SSOResolution{}, fmt.Errorf("commit single sign-on resolution: %w", err)
		}
		return SSOResolution{AdminUserID: linked}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return SSOResolution{}, fmt.Errorf("read single sign-on identity: %w", err)
	}

	// Matching by email needs the provider to vouch for it.
	normalized, emailErr := NormalizeEmail(identity.Email)
	if !identity.EmailVerified || emailErr != nil {
		return SSOResolution{}, ErrSSOEmailUnverified
	}
	if len(provider.AllowedEmailDomains) > 0 && !slices.Contains(provider.AllowedEmailDomains, emailDomain(normalized)) {
		return SSOResolution{}, ErrSSODomain
	}
	resolution := SSOResolution{}
	var memberStatus string
	err = tx.QueryRow(ctx, `
		SELECT u.admin_user_id, m.status
		FROM admin_users AS u JOIN admin_memberships AS m ON m.admin_user_id = u.admin_user_id AND m.organization_id = $1
		WHERE u.email_normalized = $2 AND u.status = 'active'
		FOR UPDATE OF m
	`, provider.OrganizationID, normalized).Scan(&resolution.AdminUserID, &memberStatus)
	switch {
	case err == nil:
		if memberStatus != "active" {
			return SSOResolution{}, ErrSSONoAccount
		}
		resolution.Linked = true
	case errors.Is(err, pgx.ErrNoRows):
		if provider.ProvisionRole == nil {
			return SSOResolution{}, ErrSSONoAccount
		}
		if resolution.AdminUserID, err = store.provisionSSOMember(ctx, tx, provider, identity, normalized, now); err != nil {
			return SSOResolution{}, err
		}
		resolution.Provisioned = true
	default:
		return SSOResolution{}, fmt.Errorf("match single sign-on email: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_sso_identities (organization_id, issuer, subject, admin_user_id, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $5)
	`, provider.OrganizationID, identity.Issuer, identity.Subject, resolution.AdminUserID, now); err != nil {
		if isUniqueViolation(err) {
			// The administrator is already linked to a different subject.
			return SSOResolution{}, ErrAdminConflict
		}
		return SSOResolution{}, fmt.Errorf("link single sign-on identity: %w", err)
	}
	actor, err := NewAdminUserActor(resolution.AdminUserID)
	if err != nil {
		return SSOResolution{}, err
	}
	action, changes := "admin.sso_link", []AuditChange{mustSensitiveAuditChange("sso_identity", AuditAdd)}
	if resolution.Provisioned {
		action = "admin.sso_provision"
		changes = append(changes, mustPublicAuditChange("role", AuditSet))
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return SSOResolution{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	mutation, err := NewAuditMutation(eventID, provider.OrganizationID, "", actor, action, "admin_user", resolution.AdminUserID,
		AuditSucceeded, requestID, now, changes)
	if err != nil {
		return SSOResolution{}, err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return SSOResolution{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SSOResolution{}, fmt.Errorf("commit single sign-on resolution: %w", err)
	}
	return resolution, nil
}

func (store *Store) provisionSSOMember(ctx context.Context, tx pgx.Tx, provider StoredSSOProvider, identity SSOIdentity, normalized string, now time.Time) (string, error) {
	var adminUserID, accountStatus string
	err := tx.QueryRow(ctx, `SELECT admin_user_id, status FROM admin_users WHERE email_normalized = $1 FOR UPDATE`, normalized).Scan(&adminUserID, &accountStatus)
	switch {
	case err == nil:
		if accountStatus != "active" {
			return "", ErrSSONoAccount
		}
	case errors.Is(err, pgx.ErrNoRows):
		if adminUserID, err = store.newID(id.AdminUser); err != nil {
			return "", fmt.Errorf("generate administrator ID: %w", err)
		}
		displayName := strings.TrimSpace(identity.Name)
		if validateDisplayName(displayName) != nil {
			displayName = strings.SplitN(normalized, "@", 2)[0]
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name, status, created_at, updated_at, password_reset_required)
			VALUES ($1, $2, $3, $4, 'active', $5, $5, false)
		`, adminUserID, strings.TrimSpace(identity.Email), normalized, displayName, now); err != nil {
			if isUniqueViolation(err) {
				return "", ErrAdminConflict
			}
			return "", fmt.Errorf("create single sign-on administrator: %w", err)
		}
	default:
		return "", fmt.Errorf("read administrator by email: %w", err)
	}
	membershipID, err := store.newID(id.AdminMembership)
	if err != nil {
		return "", fmt.Errorf("generate administrator membership ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', $5, $5)
	`, membershipID, provider.OrganizationID, adminUserID, string(*provider.ProvisionRole), now); err != nil {
		if isUniqueViolation(err) {
			// A disabled membership exists; an owner has to enable it.
			return "", ErrSSONoAccount
		}
		return "", fmt.Errorf("create single sign-on membership: %w", err)
	}
	return adminUserID, nil
}

// SSORequiredFor reports whether signing in to the organization with a
// password or passkey is refused for this administrator. Owners keep their
// other methods so a broken identity provider can't lock everyone out.
func (store *Store) SSORequiredFor(ctx context.Context, organizationID string, role Role) (bool, error) {
	if role == RoleOwner {
		return false, nil
	}
	var required bool
	err := store.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT require_sso FROM organization_sso_providers WHERE organization_id = $1), false)
	`, organizationID).Scan(&required)
	if err != nil {
		return false, fmt.Errorf("check single sign-on requirement: %w", err)
	}
	return required, nil
}
