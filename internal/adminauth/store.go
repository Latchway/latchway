package adminauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

type identifierSource func(id.Prefix) (string, error)

// Store persists administrative credentials and value-safe audit events.
type Store struct {
	pool   *pgxpool.Pool
	newID  identifierSource
	tokens *TokenIssuer
	now    func() time.Time
}

// NewStore constructs a production store.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("admin auth database pool is nil")
	}
	return &Store{
		pool:   pool,
		newID:  id.New,
		tokens: NewDefaultTokenIssuer(),
		now:    time.Now,
	}, nil
}

func newStore(
	pool *pgxpool.Pool,
	newID identifierSource,
	tokens *TokenIssuer,
	now func() time.Time,
) (*Store, error) {
	if pool == nil || newID == nil || tokens == nil || now == nil {
		return nil, errors.New("admin auth store dependency is nil")
	}
	return &Store{pool: pool, newID: newID, tokens: tokens, now: now}, nil
}

// InitializeBootstrapToken installs the environment-provided token hash. The
// same token is idempotent; a different live token is rejected.
func (store *Store) InitializeBootstrapToken(
	ctx context.Context,
	plaintext string,
	expiresAt *time.Time,
) error {
	hash, err := HashBootstrapToken(plaintext)
	if err != nil {
		return err
	}
	now := store.now().UTC()
	if expiresAt != nil && !expiresAt.After(now) {
		return ErrBootstrapTokenExpired
	}
	tokenID, err := store.newID(id.AdminBootstrapToken)
	if err != nil {
		return fmt.Errorf("generate bootstrap token ID: %w", err)
	}

	// The singleton bootstrap row is the serialization point. READ COMMITTED is
	// intentional: a waiter on FOR UPDATE must observe the committed consumed_at
	// value instead of failing the whole operation with SQLSTATE 40001.
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin bootstrap initialization: %w", err)
	}
	defer rollback(tx)

	var existingBytes []byte
	var consumedAt *time.Time
	var existingExpiresAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT token_hash, consumed_at, expires_at
		FROM admin_bootstrap_tokens
		WHERE generation = 1
		FOR UPDATE
	`).Scan(&existingBytes, &consumedAt, &existingExpiresAt)
	switch {
	case err == nil:
		if consumedAt != nil {
			return ErrBootstrapDisabled
		}
		owner, ownerErr := hasOwner(ctx, tx)
		if ownerErr != nil {
			return ownerErr
		}
		if owner {
			return ErrBootstrapDisabled
		}
		existing, parseErr := ParseTokenHash(existingBytes)
		if parseErr != nil {
			return fmt.Errorf("read bootstrap token hash: %w", parseErr)
		}
		if existingExpiresAt == nil || existingExpiresAt.After(now) {
			if existing.Equal(hash) {
				return nil
			}
			return ErrBootstrapAlreadyInitialized
		}
		if _, err := tx.Exec(ctx, `
			UPDATE admin_bootstrap_tokens
			SET admin_bootstrap_token_id = $1,
			    token_hash = $2,
			    created_at = $3,
			    expires_at = $4
			WHERE generation = 1 AND consumed_at IS NULL
		`, tokenID, hash.Bytes(), now, expiresAt); err != nil {
			return fmt.Errorf("replace expired bootstrap token: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit expired bootstrap replacement: %w", err)
		}
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		owner, ownerErr := hasOwner(ctx, tx)
		if ownerErr != nil {
			return ownerErr
		}
		if owner {
			return ErrBootstrapDisabled
		}
	default:
		return fmt.Errorf("lock bootstrap token: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_bootstrap_tokens (
			admin_bootstrap_token_id,
			generation,
			token_hash,
			created_at,
			expires_at
		) VALUES ($1, 1, $2, $3, $4)
	`, tokenID, hash.Bytes(), now, expiresAt); err != nil {
		if isUniqueViolation(err) {
			_ = tx.Rollback(ctx)
			return store.bootstrapInitializationOutcome(ctx, hash, now)
		}
		return fmt.Errorf("insert bootstrap token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		if isSerializationFailure(err) {
			return ErrBootstrapAlreadyInitialized
		}
		return fmt.Errorf("commit bootstrap initialization: %w", err)
	}
	return nil
}

func (store *Store) bootstrapInitializationOutcome(
	ctx context.Context,
	presented TokenHash,
	now time.Time,
) error {
	var storedBytes []byte
	var consumedAt *time.Time
	var expiresAt *time.Time
	var owner bool
	err := store.pool.QueryRow(ctx, `
		SELECT token_hash,
		       consumed_at,
		       expires_at,
		       EXISTS (SELECT 1 FROM admin_memberships WHERE role = 'owner')
		FROM admin_bootstrap_tokens
		WHERE generation = 1
	`).Scan(&storedBytes, &consumedAt, &expiresAt, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBootstrapAlreadyInitialized
	}
	if err != nil {
		return fmt.Errorf("read concurrent bootstrap initialization: %w", err)
	}
	if consumedAt != nil || owner {
		return ErrBootstrapDisabled
	}
	stored, err := ParseTokenHash(storedBytes)
	if err != nil {
		return fmt.Errorf("parse concurrent bootstrap token hash: %w", err)
	}
	if (expiresAt == nil || expiresAt.After(now)) && stored.Equal(presented) {
		return nil
	}
	return ErrBootstrapAlreadyInitialized
}

// BootstrapOwner atomically consumes the one-time token and creates the first
// organization, administrator, owner membership, password, and audit event.
func (store *Store) BootstrapOwner(
	ctx context.Context,
	plaintext string,
	input BootstrapOwnerInput,
) (BootstrapResult, error) {
	presentedHash, err := HashBootstrapToken(plaintext)
	if err != nil {
		return BootstrapResult{}, ErrBootstrapTokenInvalid
	}
	if err := input.validate(); err != nil {
		return BootstrapResult{}, err
	}
	emailNormalized, err := NormalizeEmail(input.Email)
	if err != nil {
		return BootstrapResult{}, err
	}

	result := BootstrapResult{}
	result.OrganizationID, err = store.newID(id.Organization)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("generate organization ID: %w", err)
	}
	result.AdminUserID, err = store.newID(id.AdminUser)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("generate admin user ID: %w", err)
	}
	result.AdminMembershipID, err = store.newID(id.AdminMembership)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("generate admin membership ID: %w", err)
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	bootstrapChange, _ := NewSensitiveAuditChange("bootstrap_token", AuditConsume)
	passwordChange, _ := NewSensitiveAuditChange("password_hash", AuditSet)
	roleChange, _ := NewPublicAuditChange("role", AuditSet)
	now := store.now().UTC()
	mutation, err := NewAuditMutation(
		eventID,
		result.OrganizationID,
		"",
		SystemActor(),
		"admin.bootstrap_owner",
		"admin_user",
		result.AdminUserID,
		AuditSucceeded,
		input.RequestID,
		now,
		[]AuditChange{bootstrapChange, passwordChange, roleChange},
	)
	if err != nil {
		return BootstrapResult{}, err
	}

	// Locking the singleton row is sufficient to serialize consumers. Under
	// READ COMMITTED, a concurrent waiter sees the winner's consumed_at value
	// after the lock is released and returns the stable disabled result.
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("begin owner bootstrap: %w", err)
	}
	defer rollback(tx)

	var storedHashBytes []byte
	var expiresAt *time.Time
	var consumedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT token_hash, expires_at, consumed_at
		FROM admin_bootstrap_tokens
		WHERE generation = 1
		FOR UPDATE
	`).Scan(&storedHashBytes, &expiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BootstrapResult{}, ErrBootstrapTokenInvalid
	}
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("lock bootstrap token: %w", err)
	}
	if consumedAt != nil {
		return BootstrapResult{}, ErrBootstrapDisabled
	}
	owner, err := hasOwner(ctx, tx)
	if err != nil {
		return BootstrapResult{}, err
	}
	if owner {
		return BootstrapResult{}, ErrBootstrapDisabled
	}
	storedHash, err := ParseTokenHash(storedHashBytes)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("read bootstrap token hash: %w", err)
	}
	if !storedHash.Equal(presentedHash) {
		return BootstrapResult{}, ErrBootstrapTokenInvalid
	}
	if expiresAt != nil && !expiresAt.After(now) {
		return BootstrapResult{}, ErrBootstrapTokenExpired
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (
			organization_id, slug, display_name, status, created_at, updated_at
		) VALUES ($1, $2, $3, 'active', $4, $4)
	`, result.OrganizationID, input.OrganizationSlug, strings.TrimSpace(input.OrganizationName), now); err != nil {
		return BootstrapResult{}, fmt.Errorf("create bootstrap organization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id,
			email,
			email_normalized,
			display_name,
			status,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, $4, 'active', $5, $5)
	`, result.AdminUserID, strings.TrimSpace(input.Email), emailNormalized, strings.TrimSpace(input.DisplayName), now); err != nil {
		return BootstrapResult{}, fmt.Errorf("create bootstrap admin user: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_password_credentials (
			admin_user_id, password_hash, created_at, changed_at
		) VALUES ($1, $2, $3, $3)
	`, result.AdminUserID, input.PasswordHash.Encoded(), now); err != nil {
		return BootstrapResult{}, fmt.Errorf("create bootstrap password: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id,
			organization_id,
			admin_user_id,
			role,
			status,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, 'owner', 'active', $4, $4)
	`, result.AdminMembershipID, result.OrganizationID, result.AdminUserID, now); err != nil {
		return BootstrapResult{}, fmt.Errorf("create bootstrap owner membership: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE admin_bootstrap_tokens
		SET consumed_at = $1, consumed_by_admin_user_id = $2
		WHERE generation = 1 AND consumed_at IS NULL
	`, now, result.AdminUserID)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("consume bootstrap token: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return BootstrapResult{}, ErrBootstrapDisabled
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return BootstrapResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if isSerializationFailure(err) {
			return BootstrapResult{}, ErrBootstrapDisabled
		}
		return BootstrapResult{}, fmt.Errorf("commit owner bootstrap: %w", err)
	}
	return result, nil
}

// PasswordCredentialByEmail returns a validated hash for a currently active
// local administrator. Callers should map every failure to one public login
// error.
func (store *Store) PasswordCredentialByEmail(
	ctx context.Context,
	email string,
) (string, PasswordHash, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return "", PasswordHash{}, ErrAdminAuthentication
	}
	var adminUserID string
	var encoded string
	err = store.pool.QueryRow(ctx, `
		SELECT u.admin_user_id, p.password_hash
		FROM admin_users AS u
		JOIN admin_password_credentials AS p
			ON p.admin_user_id = u.admin_user_id
		WHERE u.email_normalized = $1
		  AND u.status = 'active'
	`, normalized).Scan(&adminUserID, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", PasswordHash{}, ErrAdminAuthentication
	}
	if err != nil {
		return "", PasswordHash{}, fmt.Errorf("read password credential: %w", err)
	}
	hash, err := ParsePasswordHash(encoded)
	if err != nil {
		return "", PasswordHash{}, fmt.Errorf("parse stored password credential: %w", err)
	}
	return adminUserID, hash, nil
}

// CreateSession creates an organization-scoped opaque session and CSRF secret
// and returns both plaintext values once.
func (store *Store) CreateSession(
	ctx context.Context,
	input CreateSessionInput,
) (IssuedSession, error) {
	if err := input.validate(); err != nil {
		return IssuedSession{}, err
	}
	sessionID, err := store.newID(id.AdminSession)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate session ID: %w", err)
	}
	sessionToken, err := store.tokens.Issue(AdminSessionKind)
	if err != nil {
		return IssuedSession{}, err
	}
	csrfToken, err := store.tokens.Issue(CSRFTokenKind)
	if err != nil {
		return IssuedSession{}, err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	actor, err := NewAdminUserActor(input.AdminUserID)
	if err != nil {
		return IssuedSession{}, err
	}
	sessionChange, _ := NewSensitiveAuditChange("session_token", AuditSet)
	csrfChange, _ := NewSensitiveAuditChange("csrf_token", AuditSet)
	now := store.now().UTC()
	expiresAt := now.Add(input.Lifetime)
	mutation, err := NewAuditMutation(
		eventID,
		input.OrganizationID,
		"",
		actor,
		"admin.session_create",
		"admin_session",
		sessionID,
		AuditSucceeded,
		input.RequestID,
		now,
		[]AuditChange{sessionChange, csrfChange},
	)
	if err != nil {
		return IssuedSession{}, err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin session creation: %w", err)
	}
	defer rollback(tx)

	tag, err := tx.Exec(ctx, `
		INSERT INTO admin_sessions (
			admin_session_id,
			organization_id,
			admin_user_id,
			token_hash,
			token_hint,
			csrf_token_hash,
			created_at,
			expires_at,
			last_seen_at
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $7
		FROM admin_users AS u
		JOIN admin_memberships AS m
			ON m.admin_user_id = u.admin_user_id
		   AND m.organization_id = $2
		WHERE u.admin_user_id = $3
		  AND u.status = 'active'
		  AND m.status = 'active'
	`, sessionID, input.OrganizationID, input.AdminUserID, sessionToken.Hash.Bytes(),
		sessionToken.Secret.Hint(), csrfToken.Hash.Bytes(), now, expiresAt)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("insert admin session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return IssuedSession{}, ErrAdminAuthentication
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return IssuedSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit session creation: %w", err)
	}
	return IssuedSession{
		SessionID: sessionID,
		Token:     sessionToken.Secret,
		CSRFToken: csrfToken.Secret,
		ExpiresAt: expiresAt,
	}, nil
}

// AuthenticateSession validates and touches an active opaque session.
func (store *Store) AuthenticateSession(ctx context.Context, plaintext string) (Principal, error) {
	hash, err := HashToken(AdminSessionKind, plaintext)
	if err != nil {
		return Principal{}, ErrAdminAuthentication
	}
	now := store.now().UTC()
	var principal Principal
	var role string
	err = store.pool.QueryRow(ctx, `
		UPDATE admin_sessions AS s
		SET last_seen_at = $2
		FROM admin_users AS u, admin_memberships AS m
		WHERE s.token_hash = $1
		  AND s.revoked_at IS NULL
		  AND s.expires_at > $2
		  AND u.admin_user_id = s.admin_user_id
		  AND u.status = 'active'
		  AND m.organization_id = s.organization_id
		  AND m.admin_user_id = s.admin_user_id
		  AND m.status = 'active'
		RETURNING s.organization_id, s.admin_user_id, m.role, s.admin_session_id
	`, hash.Bytes(), now).Scan(
		&principal.OrganizationID,
		&principal.AdminUserID,
		&role,
		&principal.CredentialID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrAdminAuthentication
	}
	if err != nil {
		return Principal{}, fmt.Errorf("authenticate admin session: %w", err)
	}
	principal.Role = Role(role)
	if err := principal.Role.Validate(); err != nil {
		return Principal{}, fmt.Errorf("read admin session role: %w", err)
	}
	principal.Method = AuthenticationSession
	return principal, nil
}

// ValidateSessionCSRF verifies the double-submit/session-bound CSRF secret.
func (store *Store) ValidateSessionCSRF(
	ctx context.Context,
	sessionID string,
	plaintext string,
) error {
	if err := id.Validate(sessionID, id.AdminSession); err != nil {
		return ErrAdminAuthentication
	}
	hash, err := HashToken(CSRFTokenKind, plaintext)
	if err != nil {
		return ErrAdminAuthentication
	}
	var valid bool
	err = store.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM admin_sessions
			WHERE admin_session_id = $1
			  AND csrf_token_hash = $2
			  AND revoked_at IS NULL
			  AND expires_at > $3
		)
	`, sessionID, hash.Bytes(), store.now().UTC()).Scan(&valid)
	if err != nil {
		return fmt.Errorf("validate CSRF token: %w", err)
	}
	if !valid {
		return ErrAdminAuthentication
	}
	return nil
}

// RevokeSession revokes an active session and records the mutation.
func (store *Store) RevokeSession(
	ctx context.Context,
	sessionID string,
	actor AuditActor,
	requestID string,
	reason string,
) error {
	if err := id.Validate(sessionID, id.AdminSession); err != nil {
		return ErrInvalidAdminInput
	}
	if err := actor.validate(); err != nil {
		return ErrInvalidAdminInput
	}
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > 100 {
		return ErrInvalidAdminInput
	}
	if validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate audit event ID: %w", err)
	}
	change, _ := NewSensitiveAuditChange("session_token", AuditRevoke)

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin session revocation: %w", err)
	}
	defer rollback(tx)
	var organizationID string
	var targetAdminUserID string
	err = tx.QueryRow(ctx, `
		SELECT organization_id, admin_user_id
		FROM admin_sessions
		WHERE admin_session_id = $1 AND revoked_at IS NULL
		FOR UPDATE
	`, sessionID).Scan(&organizationID, &targetAdminUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAdminNotFound
	}
	if err != nil {
		return fmt.Errorf("lock admin session: %w", err)
	}
	if err := store.authorizeCredentialRevocation(
		ctx, tx, actor, organizationID, targetAdminUserID, now,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_sessions
		SET revoked_at = $2, revoke_reason = $3
		WHERE admin_session_id = $1
	`, sessionID, now, reason); err != nil {
		return fmt.Errorf("revoke admin session: %w", err)
	}
	mutation, err := NewAuditMutation(
		eventID,
		organizationID,
		"",
		actor,
		"admin.session_revoke",
		"admin_session",
		sessionID,
		AuditSucceeded,
		requestID,
		now,
		[]AuditChange{change},
	)
	if err != nil {
		return err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit session revocation: %w", err)
	}
	return nil
}

// CreateAPIToken creates a scoped credential and returns its plaintext once.
func (store *Store) CreateAPIToken(
	ctx context.Context,
	input CreateAPITokenInput,
) (IssuedAPIToken, error) {
	now := store.now().UTC()
	if err := input.validate(now); err != nil {
		return IssuedAPIToken{}, err
	}
	tokenID, err := store.newID(id.AdminAPIToken)
	if err != nil {
		return IssuedAPIToken{}, fmt.Errorf("generate API token ID: %w", err)
	}
	token, err := store.tokens.Issue(AdminAPITokenKind)
	if err != nil {
		return IssuedAPIToken{}, err
	}
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return IssuedAPIToken{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	actor, err := NewAdminUserActor(input.CreatedByAdminUserID)
	if err != nil {
		return IssuedAPIToken{}, err
	}
	tokenChange, _ := NewSensitiveAuditChange("api_token", AuditSet)
	scopeChange, _ := NewPublicAuditChange("scopes", AuditSet)
	mutation, err := NewAuditMutation(
		eventID,
		input.OrganizationID,
		"",
		actor,
		"admin.api_token_create",
		"admin_api_token",
		tokenID,
		AuditSucceeded,
		input.RequestID,
		now,
		[]AuditChange{tokenChange, scopeChange},
	)
	if err != nil {
		return IssuedAPIToken{}, err
	}

	values := input.Scope.Values()
	scopes := make([]string, len(values))
	for index, capability := range values {
		scopes[index] = string(capability)
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedAPIToken{}, fmt.Errorf("begin API token creation: %w", err)
	}
	defer rollback(tx)

	var targetRole string
	var creatorRole string
	err = tx.QueryRow(ctx, `
		SELECT target.role, creator.role
		FROM admin_memberships AS target
		JOIN admin_users AS target_user
			ON target_user.admin_user_id = target.admin_user_id
		JOIN admin_memberships AS creator
			ON creator.organization_id = target.organization_id
		   AND creator.admin_user_id = $3
		JOIN admin_users AS creator_user
			ON creator_user.admin_user_id = creator.admin_user_id
		WHERE target.organization_id = $1
		  AND target.admin_user_id = $2
		  AND target.status = 'active'
		  AND target_user.status = 'active'
		  AND creator.status = 'active'
		  AND creator_user.status = 'active'
	`, input.OrganizationID, input.AdminUserID, input.CreatedByAdminUserID).Scan(&targetRole, &creatorRole)
	if errors.Is(err, pgx.ErrNoRows) {
		return IssuedAPIToken{}, ErrAdminAuthentication
	}
	if err != nil {
		return IssuedAPIToken{}, fmt.Errorf("validate API token memberships: %w", err)
	}
	role := Role(targetRole)
	if err := role.Validate(); err != nil {
		return IssuedAPIToken{}, fmt.Errorf("read API token role: %w", err)
	}
	creator := Role(creatorRole)
	if err := creator.Validate(); err != nil {
		return IssuedAPIToken{}, fmt.Errorf("read API token creator role: %w", err)
	}
	if input.CreatedByAdminUserID != input.AdminUserID && creator != RoleOwner {
		return IssuedAPIToken{}, ErrAdminAuthentication
	}
	maximumContext := AuthorizationContext{
		PromptBodiesAllowedByPolicy: true,
		AdminPromptBodiesEnabled:    true,
	}
	for _, capability := range values {
		if !role.Allows(capability, maximumContext) || !creator.Allows(capability, maximumContext) {
			return IssuedAPIToken{}, fmt.Errorf("%w: scope %s exceeds role %s", ErrInvalidAdminInput, capability, role)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_api_tokens (
			admin_api_token_id,
			organization_id,
			admin_user_id,
			name,
			token_hash,
			token_hint,
			scopes,
			created_by_admin_user_id,
			created_at,
			expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, tokenID, input.OrganizationID, input.AdminUserID, strings.TrimSpace(input.Name),
		token.Hash.Bytes(), token.Secret.Hint(), scopes, input.CreatedByAdminUserID, now, input.ExpiresAt); err != nil {
		return IssuedAPIToken{}, fmt.Errorf("insert admin API token: %w", err)
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return IssuedAPIToken{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedAPIToken{}, fmt.Errorf("commit API token creation: %w", err)
	}
	return IssuedAPIToken{
		APITokenID: tokenID,
		Token:      token.Secret,
		ExpiresAt:  input.ExpiresAt,
	}, nil
}

// AuthenticateAPIToken validates and touches an active scoped token.
func (store *Store) AuthenticateAPIToken(ctx context.Context, plaintext string) (Principal, error) {
	hash, err := HashToken(AdminAPITokenKind, plaintext)
	if err != nil {
		return Principal{}, ErrAdminAuthentication
	}
	now := store.now().UTC()
	var principal Principal
	var role string
	var scopes []string
	err = store.pool.QueryRow(ctx, `
		UPDATE admin_api_tokens AS token
		SET last_used_at = $2
		FROM admin_users AS u, admin_memberships AS m
		WHERE token.token_hash = $1
		  AND token.revoked_at IS NULL
		  AND (token.expires_at IS NULL OR token.expires_at > $2)
		  AND u.admin_user_id = token.admin_user_id
		  AND u.status = 'active'
		  AND m.organization_id = token.organization_id
		  AND m.admin_user_id = token.admin_user_id
		  AND m.status = 'active'
		RETURNING token.organization_id, token.admin_user_id, m.role,
		          token.admin_api_token_id, token.scopes
	`, hash.Bytes(), now).Scan(
		&principal.OrganizationID,
		&principal.AdminUserID,
		&role,
		&principal.CredentialID,
		&scopes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrAdminAuthentication
	}
	if err != nil {
		return Principal{}, fmt.Errorf("authenticate admin API token: %w", err)
	}
	principal.Role = Role(role)
	if err := principal.Role.Validate(); err != nil {
		return Principal{}, fmt.Errorf("read API token role: %w", err)
	}
	scope, err := capabilitiesFromStrings(scopes)
	if err != nil {
		return Principal{}, fmt.Errorf("read API token scope: %w", err)
	}
	principal.Method = AuthenticationAPIToken
	principal.scope = &scope
	return principal, nil
}

// RevokeAPIToken revokes an active token and records the mutation.
func (store *Store) RevokeAPIToken(
	ctx context.Context,
	tokenID string,
	actor AuditActor,
	requestID string,
	reason string,
) error {
	if err := id.Validate(tokenID, id.AdminAPIToken); err != nil {
		return ErrInvalidAdminInput
	}
	if err := actor.validate(); err != nil {
		return ErrInvalidAdminInput
	}
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > 100 {
		return ErrInvalidAdminInput
	}
	if validateRequestID(requestID) != nil {
		return ErrInvalidAdminInput
	}
	now := store.now().UTC()
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate audit event ID: %w", err)
	}
	change, _ := NewSensitiveAuditChange("api_token", AuditRevoke)

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin API token revocation: %w", err)
	}
	defer rollback(tx)
	var organizationID string
	var targetAdminUserID string
	err = tx.QueryRow(ctx, `
		SELECT organization_id, admin_user_id
		FROM admin_api_tokens
		WHERE admin_api_token_id = $1 AND revoked_at IS NULL
		FOR UPDATE
	`, tokenID).Scan(&organizationID, &targetAdminUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAdminNotFound
	}
	if err != nil {
		return fmt.Errorf("lock admin API token: %w", err)
	}
	if err := store.authorizeCredentialRevocation(
		ctx, tx, actor, organizationID, targetAdminUserID, now,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE admin_api_tokens
		SET revoked_at = $2, revoke_reason = $3
		WHERE admin_api_token_id = $1
	`, tokenID, now, reason); err != nil {
		return fmt.Errorf("revoke admin API token: %w", err)
	}
	mutation, err := NewAuditMutation(
		eventID,
		organizationID,
		"",
		actor,
		"admin.api_token_revoke",
		"admin_api_token",
		tokenID,
		AuditSucceeded,
		requestID,
		now,
		[]AuditChange{change},
	)
	if err != nil {
		return err
	}
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit API token revocation: %w", err)
	}
	return nil
}

// RecordAuditMutation persists a value-safe event independently.
func (store *Store) RecordAuditMutation(ctx context.Context, mutation AuditMutation) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin audit mutation: %w", err)
	}
	defer rollback(tx)
	if err := insertAuditMutation(ctx, tx, mutation); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit mutation: %w", err)
	}
	return nil
}

func insertAuditMutation(ctx context.Context, tx pgx.Tx, mutation AuditMutation) error {
	if _, err := NewAuditMutation(
		mutation.EventID(),
		mutation.OrganizationID(),
		mutation.EnvironmentID(),
		mutation.Actor(),
		mutation.Action(),
		mutation.ResourceType(),
		mutation.ResourceID(),
		mutation.Outcome(),
		mutation.RequestID(),
		mutation.OccurredAt(),
		mutation.Changes(),
	); err != nil {
		return err
	}
	actor := mutation.Actor()
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			audit_event_id,
			organization_id,
			environment_id,
			actor_kind,
			actor_id,
			action,
			resource_type,
			resource_id,
			outcome,
			request_id,
			occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, mutation.EventID(), nullableString(mutation.OrganizationID()),
		nullableString(mutation.EnvironmentID()), actor.Kind(), nullableString(actor.ID()),
		mutation.Action(), mutation.ResourceType(), mutation.ResourceID(), mutation.Outcome(),
		nullableString(mutation.RequestID()), mutation.OccurredAt()); err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	for index, change := range mutation.Changes() {
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_event_changes (
				audit_event_id, ordinal, field_name, operation, classification
			) VALUES ($1, $2, $3, $4, $5)
		`, mutation.EventID(), index, change.Field(), change.Operation(), change.Classification()); err != nil {
			return fmt.Errorf("insert audit event change: %w", err)
		}
	}
	return nil
}

func hasOwner(ctx context.Context, tx pgx.Tx) (bool, error) {
	var owner bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM admin_memberships
			WHERE role = 'owner'
		)
	`).Scan(&owner); err != nil {
		return false, fmt.Errorf("check existing owner: %w", err)
	}
	return owner, nil
}

// authorizeCredentialRevocation binds an asserted audit actor to the target
// tenant. Users may revoke their own credentials; active owners may revoke
// another user's credentials. API-token actors are intentionally self-only.
func (store *Store) authorizeCredentialRevocation(
	ctx context.Context,
	tx pgx.Tx,
	actor AuditActor,
	organizationID string,
	targetAdminUserID string,
	now time.Time,
) error {
	switch actor.Kind() {
	case AuditActorSystem:
		return nil
	case AuditActorAdminUser:
		var roleText string
		err := tx.QueryRow(ctx, `
			SELECT membership.role
			FROM admin_memberships AS membership
			JOIN admin_users AS admin_user
				ON admin_user.admin_user_id = membership.admin_user_id
			WHERE membership.organization_id = $1
			  AND membership.admin_user_id = $2
			  AND membership.status = 'active'
			  AND admin_user.status = 'active'
		`, organizationID, actor.ID()).Scan(&roleText)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAdminAuthentication
		}
		if err != nil {
			return fmt.Errorf("authorize credential revocation: %w", err)
		}
		role := Role(roleText)
		if role.Validate() != nil || (actor.ID() != targetAdminUserID && role != RoleOwner) {
			return ErrAdminAuthentication
		}
		return nil
	case AuditActorAPIToken:
		var actorAdminUserID string
		err := tx.QueryRow(ctx, `
			SELECT token.admin_user_id
			FROM admin_api_tokens AS token
			JOIN admin_memberships AS membership
				ON membership.organization_id = token.organization_id
			   AND membership.admin_user_id = token.admin_user_id
			JOIN admin_users AS admin_user
				ON admin_user.admin_user_id = token.admin_user_id
			WHERE token.organization_id = $1
			  AND token.admin_api_token_id = $2
			  AND token.revoked_at IS NULL
			  AND (token.expires_at IS NULL OR token.expires_at > $3)
			  AND membership.status = 'active'
			  AND admin_user.status = 'active'
		`, organizationID, actor.ID(), now).Scan(&actorAdminUserID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAdminAuthentication
		}
		if err != nil {
			return fmt.Errorf("authorize API-token credential revocation: %w", err)
		}
		if actorAdminUserID != targetAdminUserID {
			return ErrAdminAuthentication
		}
		return nil
	default:
		return ErrAdminAuthentication
	}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
