package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// lockActiveCredentialScope linearizes every credential-minting or rotation
// transaction with application/environment disable. The lock order is always
// application then environment, matching the administrative lifecycle store.
func lockActiveCredentialScope(ctx context.Context, tx pgx.Tx, organizationID, applicationID, environmentID string) error {
	var marker int
	if err := tx.QueryRow(ctx, `
		/* active_credential_application_lock */
		SELECT 1
		FROM applications AS application
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE application.organization_id = $1 AND application.application_id = $2
		  AND application.status = 'active' AND application.disabled_at IS NULL
		  AND organization.status = 'active' AND organization.disabled_at IS NULL
		FOR SHARE OF application
	`, organizationID, applicationID).Scan(&marker); errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionScope
	} else if err != nil {
		return fmt.Errorf("lock active application credential scope: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		/* active_credential_environment_lock */
		SELECT 1
		FROM environments AS environment
		WHERE environment.organization_id = $1 AND environment.application_id = $2
		  AND environment.environment_id = $3
		  AND environment.status = 'active' AND environment.disabled_at IS NULL
		FOR SHARE
	`, organizationID, applicationID, environmentID).Scan(&marker); errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionScope
	} else if err != nil {
		return fmt.Errorf("lock active environment credential scope: %w", err)
	}
	return nil
}
