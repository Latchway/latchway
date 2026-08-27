package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
)

type userIdentifierSource func(id.Prefix) (string, error)

type UserScope struct {
	OrganizationID string
	ApplicationID  string
}

func (scope UserScope) validate() error {
	if id.Validate(scope.OrganizationID, id.Organization) != nil || id.Validate(scope.ApplicationID, id.Application) != nil {
		return ErrIdentityScope
	}
	return nil
}

type ApplicationUser struct {
	ID             string
	OrganizationID string
	ApplicationID  string
	Status         string
	Claims         map[string]any
	CreatedAt      time.Time
	LastSeenAt     time.Time
}

// UserStore resolves verified principals to private internal application-user
// IDs. Its API cannot accept a raw identity credential.
type UserStore struct {
	pool      *pgxpool.Pool
	protector *SubjectProtector
	newID     userIdentifierSource
	now       func() time.Time
}

func NewUserStore(pool *pgxpool.Pool, protector *SubjectProtector) (*UserStore, error) {
	return newUserStore(pool, protector, id.New, time.Now)
}

func newUserStore(pool *pgxpool.Pool, protector *SubjectProtector, newID userIdentifierSource, now func() time.Time) (*UserStore, error) {
	if pool == nil || protector == nil || newID == nil || now == nil {
		return nil, errors.New("identity user store dependency is nil")
	}
	return &UserStore{pool: pool, protector: protector, newID: newID, now: now}, nil
}

// Resolve returns the stable internal user for a verified external principal,
// replacing the configured claim projection and refreshing last-seen time.
func (store *UserStore) Resolve(ctx context.Context, scope UserScope, principal VerifiedPrincipal) (ApplicationUser, error) {
	if err := scope.validate(); err != nil {
		return ApplicationUser{}, err
	}
	if err := principal.validate(); err != nil {
		return ApplicationUser{}, err
	}
	claims, err := validateNormalizedClaims(principal.Claims)
	if err != nil {
		return ApplicationUser{}, err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return ApplicationUser{}, ErrCredentialInvalid
	}
	pseudonym, err := store.protector.Pseudonymize(scope.ApplicationID, principal.ProviderID, principal.Issuer, principal.Subject)
	if err != nil {
		return ApplicationUser{}, err
	}
	now := store.now().UTC()

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ApplicationUser{}, fmt.Errorf("begin identity resolution: %w", err)
	}
	defer rollbackUserStore(tx)
	if err := verifyActiveScope(ctx, tx, scope); err != nil {
		return ApplicationUser{}, err
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockKey(pseudonym)); err != nil {
		return ApplicationUser{}, fmt.Errorf("lock external identity lookup: %w", err)
	}

	user, found, err := findExternalIdentity(ctx, tx, scope, principal, pseudonym)
	if err != nil {
		return ApplicationUser{}, err
	}
	if found {
		if user.Status != "active" {
			return ApplicationUser{}, ErrUserBlocked
		}
		if _, err := tx.Exec(ctx, `
			UPDATE external_identities
			SET selected_claims = $1,
			    last_verified_at = GREATEST(last_verified_at, $2)
			WHERE organization_id = $3
			  AND application_id = $4
			  AND external_identity_id = $5
		`, claimsJSON, now, scope.OrganizationID, scope.ApplicationID, user.externalIdentityID); err != nil {
			return ApplicationUser{}, fmt.Errorf("refresh external identity: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE application_users
			SET normalized_claims = $1,
			    updated_at = GREATEST(updated_at, $2),
			    last_seen_at = GREATEST(COALESCE(last_seen_at, created_at), $2)
			WHERE organization_id = $3
			  AND application_id = $4
			  AND application_user_id = $5
		`, claimsJSON, now, scope.OrganizationID, scope.ApplicationID, user.ID); err != nil {
			return ApplicationUser{}, fmt.Errorf("refresh application user: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplicationUser{}, fmt.Errorf("commit identity refresh: %w", err)
		}
		user.Claims = claims
		if now.After(user.LastSeenAt) {
			user.LastSeenAt = now
		}
		return user.ApplicationUser, nil
	}

	userID, err := store.newID(id.ApplicationUser)
	if err != nil {
		return ApplicationUser{}, fmt.Errorf("generate application-user ID: %w", err)
	}
	externalIdentityID, err := store.newID(id.ExternalIdentity)
	if err != nil {
		return ApplicationUser{}, fmt.Errorf("generate external-identity ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id, status,
			normalized_claims, created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, 'active', $4, $5, $5, $5)
	`, userID, scope.OrganizationID, scope.ApplicationID, claimsJSON, now); err != nil {
		return ApplicationUser{}, fmt.Errorf("create application user: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO external_identities (
			external_identity_id, organization_id, application_id, application_user_id,
			provider_key, issuer_hash, subject_hmac, selected_claims, created_at, last_verified_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
	`, externalIdentityID, scope.OrganizationID, scope.ApplicationID, userID, principal.ProviderID,
		pseudonym.IssuerHash[:], pseudonym.SubjectHMAC[:], claimsJSON, now); err != nil {
		return ApplicationUser{}, fmt.Errorf("create external identity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplicationUser{}, fmt.Errorf("commit identity creation: %w", err)
	}
	return ApplicationUser{
		ID: userID, OrganizationID: scope.OrganizationID, ApplicationID: scope.ApplicationID,
		Status: "active", Claims: claims, CreatedAt: now, LastSeenAt: now,
	}, nil
}

type storedUser struct {
	ApplicationUser
	externalIdentityID string
}

func findExternalIdentity(ctx context.Context, tx pgx.Tx, scope UserScope, principal VerifiedPrincipal, pseudonym SubjectPseudonym) (storedUser, bool, error) {
	var result storedUser
	var claimsJSON []byte
	var lastSeen *time.Time
	err := tx.QueryRow(ctx, `
		SELECT u.application_user_id,
		       u.status,
		       u.normalized_claims,
		       u.created_at,
		       u.last_seen_at,
		       e.external_identity_id
		FROM external_identities e
		JOIN application_users u
		  ON u.organization_id = e.organization_id
		 AND u.application_id = e.application_id
		 AND u.application_user_id = e.application_user_id
		WHERE e.organization_id = $1
		  AND e.application_id = $2
		  AND e.provider_key = $3
		  AND e.issuer_hash = $4
		  AND e.subject_hmac = $5
		FOR UPDATE OF e, u
	`, scope.OrganizationID, scope.ApplicationID, principal.ProviderID, pseudonym.IssuerHash[:], pseudonym.SubjectHMAC[:]).Scan(
		&result.ID, &result.Status, &claimsJSON, &result.CreatedAt, &lastSeen, &result.externalIdentityID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedUser{}, false, nil
	}
	if err != nil {
		return storedUser{}, false, fmt.Errorf("read external identity: %w", err)
	}
	claims, err := decodeNormalizedClaims(claimsJSON)
	if err != nil {
		return storedUser{}, false, fmt.Errorf("stored normalized claims are invalid: %w", err)
	}
	result.OrganizationID = scope.OrganizationID
	result.ApplicationID = scope.ApplicationID
	result.Claims = claims
	if lastSeen != nil {
		result.LastSeenAt = lastSeen.UTC()
	}
	return result, true, nil
}

func verifyActiveScope(ctx context.Context, tx pgx.Tx, scope UserScope) error {
	var organizationStatus, applicationStatus string
	err := tx.QueryRow(ctx, `
		SELECT o.status, a.status
		FROM organizations o
		JOIN applications a ON a.organization_id = o.organization_id
		WHERE o.organization_id = $1 AND a.application_id = $2
		FOR SHARE OF o, a
	`, scope.OrganizationID, scope.ApplicationID).Scan(&organizationStatus, &applicationStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIdentityScope
	}
	if err != nil {
		return fmt.Errorf("verify identity scope: %w", err)
	}
	if organizationStatus != "active" || applicationStatus != "active" {
		return ErrIdentityScope
	}
	return nil
}

// SetBlocked applies an administrator-authorized block or unblock. Deleted
// users are intentionally not resurrected.
func (store *UserStore) SetBlocked(ctx context.Context, scope UserScope, userID string, blocked bool) error {
	if err := scope.validate(); err != nil || id.Validate(userID, id.ApplicationUser) != nil {
		return ErrUserNotFound
	}
	now := store.now().UTC()
	status := "active"
	if blocked {
		status = "blocked"
	}
	command, err := store.pool.Exec(ctx, `
		UPDATE application_users
		SET status = $1,
		    blocked_at = CASE
		        WHEN $1 = 'blocked' THEN COALESCE(blocked_at, GREATEST(created_at, $2::timestamptz))
		        ELSE NULL
		    END,
		    updated_at = GREATEST(updated_at, $2::timestamptz)
		WHERE organization_id = $3
		  AND application_id = $4
		  AND application_user_id = $5
		  AND status <> 'deleted'
	`, status, now, scope.OrganizationID, scope.ApplicationID, userID)
	if err != nil {
		return fmt.Errorf("set application-user block: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrUserNotFound
	}
	return nil
}

func decodeNormalizedClaims(encoded []byte) (map[string]any, error) {
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return nil, err
	}
	claims, ok := value.(map[string]any)
	if !ok {
		return nil, ErrCredentialInvalid
	}
	return validateNormalizedClaims(claims)
}

func rollbackUserStore(tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}
