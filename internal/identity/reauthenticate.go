package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

// RefreshMatchingUserTx updates an existing verified identity in the caller's
// authorization transaction. It cannot create/link users or transfer a session
// to another principal. Only the trusted verifier may supply principal.
func (store *UserStore) RefreshMatchingUserTx(ctx context.Context, tx pgx.Tx, scope UserScope, userID string, principal VerifiedPrincipal, now time.Time) error {
	if err := scope.validate(); err != nil {
		return err
	}
	if err := principal.validate(); err != nil {
		return err
	}
	if id.Validate(userID, id.ApplicationUser) != nil || now.IsZero() || !principal.ExpiresAt.After(now) {
		return ErrCredentialInvalid
	}
	pseudonym, err := store.protector.Pseudonymize(scope.ApplicationID, principal.ProviderID, principal.Issuer, principal.Subject)
	if err != nil {
		return err
	}
	claims, err := validateNormalizedClaims(principal.Claims)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return ErrCredentialInvalid
	}
	// Share the same per-principal lock as initial Resolve, so claim refreshes
	// cannot deadlock or interleave their external/user projections.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockKey(pseudonym)); err != nil {
		return fmt.Errorf("lock matching external identity: %w", err)
	}
	// Matching is performed before any write. Reauthentication never calls
	// Resolve: that operation may create a different application user.
	var externalID string
	err = tx.QueryRow(ctx, `
		SELECT e.external_identity_id
		FROM external_identities e JOIN application_users u
		  ON u.application_user_id = e.application_user_id
		WHERE e.organization_id = $1 AND e.application_id = $2
		  AND e.application_user_id = $3 AND e.provider_key = $4
		  AND e.issuer_hash = $5 AND e.subject_hmac = $6 AND u.status = 'active'
		FOR UPDATE OF u, e
	`, scope.OrganizationID, scope.ApplicationID, userID, principal.ProviderID,
		pseudonym.IssuerHash[:], pseudonym.SubjectHMAC[:]).Scan(&externalID)
	if err == pgx.ErrNoRows {
		return ErrCredentialInvalid
	}
	if err != nil {
		return fmt.Errorf("match reauthenticated user: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE external_identities SET selected_claims = $2,
		last_verified_at = GREATEST(last_verified_at, $3) WHERE external_identity_id = $1`, externalID, encoded, now); err != nil {
		return fmt.Errorf("refresh matching identity claims: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE application_users SET normalized_claims = $2,
		updated_at = GREATEST(updated_at, $3), last_seen_at = GREATEST(COALESCE(last_seen_at, created_at), $3)
		WHERE application_user_id = $1`, userID, encoded, now); err != nil {
		return fmt.Errorf("refresh matching user claims: %w", err)
	}
	return nil
}
