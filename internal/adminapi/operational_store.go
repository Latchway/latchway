package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/useroverride"
)

var (
	errOperationalInvalid       = errors.New("invalid operational Admin API input")
	errOperationalForbidden     = errors.New("operational Admin API operation forbidden")
	errOperationalNotFound      = errors.New("operational Admin API resource not found")
	errOperationalIndeterminate = errors.New("operational Admin API outcome indeterminate")
	errOperationalCorrupt       = errors.New("operational Admin API state is corrupt")
)

const (
	maximumNormalizedClaimsBytes = 64 << 10
	maximumIdentityProviders     = 64
	maximumUsagePoints           = 10_000
	maximumSummaryRange          = 366 * 24 * time.Hour
	maximumUpstreamAttempts      = 32
)

var operationalIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

type operationalStore struct {
	pool          *pgxpool.Pool
	newID         func(id.Prefix) (string, error)
	selfTests     credentialSelfTestRunner
	selfSchedules scheduledSelfTestService
}

func newOperationalStore(pool *pgxpool.Pool) *operationalStore {
	if pool == nil {
		return nil
	}
	return &operationalStore{pool: pool, newID: id.New}
}

type operationalPage struct {
	after   time.Time
	afterID string
	size    int32
}

func (page operationalPage) validate(prefix id.Prefix) error {
	if page.size < 1 || page.size > 200 || page.after.IsZero() != (page.afterID == "") {
		return errOperationalInvalid
	}
	if !page.after.IsZero() && id.Validate(page.afterID, prefix) != nil {
		return errOperationalInvalid
	}
	return nil
}

type installationDocument struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	EnvironmentID       string     `json:"environment_id"`
	Platform            string     `json:"platform"`
	DPoPJKT             string     `json:"dpop_jkt"`
	Status              string     `json:"status"`
	TrustLevel          string     `json:"trust_level"`
	AttestationProvider *string    `json:"attestation_provider,omitempty"`
	TrustExpiresAt      *time.Time `json:"trust_expires_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
}

type usageValues struct {
	LogicalRequests int64 `json:"logical_requests"`
	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	TotalTokens     int64 `json:"total_tokens"`
	CostNanoUSD     int64 `json:"cost_nano_usd"`
}

type upstreamAttemptDocument struct {
	ID              string       `json:"id"`
	AttemptNumber   int32        `json:"attempt_number"`
	Route           string       `json:"route"`
	Upstream        string       `json:"upstream"`
	Model           string       `json:"model"`
	StartedAt       time.Time    `json:"started_at"`
	FirstByteAt     *time.Time   `json:"first_byte_at,omitempty"`
	FirstTokenAt    *time.Time   `json:"first_token_at,omitempty"`
	CompletedAt     *time.Time   `json:"completed_at,omitempty"`
	Status          string       `json:"status"`
	HTTPStatus      *int32       `json:"http_status,omitempty"`
	FailureCode     *string      `json:"failure_code,omitempty"`
	Usage           *usageValues `json:"usage,omitempty"`
	UsageProvenance string       `json:"usage_provenance"`
	CostProvenance  string       `json:"cost_provenance"`
	CostSource      *string      `json:"cost_source,omitempty"`
}

type logicalRequestDocument struct {
	ID                    string                    `json:"id"`
	EnvironmentID         string                    `json:"environment_id"`
	UserID                string                    `json:"user_id"`
	InstallationID        string                    `json:"installation_id"`
	InstallationFamilyID  *string                   `json:"installation_family_id,omitempty"`
	ClientComponentID     *string                   `json:"client_component_id,omitempty"`
	ComponentDefinitionID *string                   `json:"component_definition_id,omitempty"`
	ComponentKind         *string                   `json:"component_kind,omitempty"`
	TrustSource           *string                   `json:"trust_source,omitempty"`
	Framework             *string                   `json:"framework,omitempty"`
	FrameworkVersion      *string                   `json:"framework_version,omitempty"`
	Feature               string                    `json:"feature"`
	Protocol              string                    `json:"protocol"`
	StartedAt             time.Time                 `json:"started_at"`
	CompletedAt           *time.Time                `json:"completed_at,omitempty"`
	Status                string                    `json:"status"`
	Usage                 *usageValues              `json:"usage,omitempty"`
	Attempts              []upstreamAttemptDocument `json:"attempts"`
}

type usageSummaryDocument struct {
	Start      time.Time              `json:"start"`
	End        time.Time              `json:"end"`
	Values     usageValues            `json:"values"`
	Provenance []string               `json:"provenance"`
	Analytics  usageAnalyticsDocument `json:"analytics"`
}

type usagePoint struct {
	Timestamp time.Time   `json:"timestamp"`
	Values    usageValues `json:"values"`
}

type usageTimeseriesDocument struct {
	Interval string       `json:"interval"`
	Points   []usagePoint `json:"points"`
}

type auditEventDocument struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Result    string         `json:"result"`
	RequestID string         `json:"request_id"`
	Summary   map[string]any `json:"summary"`
}

type selfTestCheck struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	SafeDetail string `json:"safe_detail,omitempty"`
}

type selfTestDocument struct {
	ID          string          `json:"id"`
	ScheduleID  string          `json:"schedule_id,omitempty"`
	Kind        string          `json:"kind"`
	State       string          `json:"state"`
	CreatedAt   time.Time       `json:"created_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Checks      []selfTestCheck `json:"checks"`
}

func (store *operationalStore) listUsers(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	page operationalPage,
) ([]useroverride.ApplicationUser, error) {
	if id.Validate(environmentID, id.Environment) != nil || page.validate(id.ApplicationUser) != nil {
		return nil, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, `
		SELECT u.application_user_id, e.environment_id, u.status,
		       u.normalized_claims, u.created_at, u.last_seen_at,
		       ARRAY(
		           SELECT DISTINCT identity.provider_key
		           FROM external_identities AS identity
		           WHERE identity.organization_id = u.organization_id
		             AND identity.application_id = u.application_id
		             AND identity.application_user_id = u.application_user_id
		           ORDER BY identity.provider_key
		           LIMIT 65
		       ) AS identity_providers,
		       CASE WHEN override.user_override_id IS NULL THEN NULL ELSE
		           jsonb_build_object(
		               'id', override.user_override_id,
		               'limit_plan', override.override_document->>'limit_plan',
		               'reason', override.reason,
		               'created_at', override.created_at,
		               'expires_at', override.expires_at
		           )
		       END AS limit_override
		FROM environments AS e
		JOIN applications AS application
		  ON application.organization_id = e.organization_id
		 AND application.application_id = e.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = e.organization_id
		JOIN application_users AS u
		  ON u.organization_id = e.organization_id
		 AND u.application_id = e.application_id
		LEFT JOIN LATERAL (
		    SELECT candidate.*
		    FROM user_overrides AS candidate
		    WHERE candidate.organization_id = e.organization_id
		      AND candidate.application_id = e.application_id
		      AND candidate.environment_id = e.environment_id
		      AND candidate.application_user_id = u.application_user_id
		      AND candidate.revoked_at IS NULL
		      AND (candidate.expires_at IS NULL OR candidate.expires_at > transaction_timestamp())
		    ORDER BY candidate.created_at DESC, candidate.user_override_id DESC
		    LIMIT 1
		) AS override ON true
		WHERE e.organization_id = $1 AND e.environment_id = $2
		  AND organization.status = 'active' AND application.status = 'active'
		  AND e.status = 'active' AND u.status <> 'deleted'
		  AND ($3::timestamptz IS NULL OR (u.created_at, u.application_user_id) > ($3, $4))
		ORDER BY u.created_at, u.application_user_id
		LIMIT $5
	`, principal.OrganizationID, environmentID, nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list application users: %w", err)
	}
	defer rows.Close()
	items := make([]useroverride.ApplicationUser, 0, page.size+1)
	for rows.Next() {
		item, scanErr := scanApplicationUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate application users: %w", err)
	}
	return items, nil
}

func (store *operationalStore) getUser(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	userID string,
) (useroverride.ApplicationUser, error) {
	if id.Validate(environmentID, id.Environment) != nil || id.Validate(userID, id.ApplicationUser) != nil {
		return useroverride.ApplicationUser{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return useroverride.ApplicationUser{}, errOperationalForbidden
	}
	return queryApplicationUser(ctx, store.pool, principal.OrganizationID, environmentID, userID)
}

type rowScanner interface {
	Scan(...any) error
}

type rowQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func queryApplicationUser(
	ctx context.Context,
	queryer rowQueryer,
	organizationID string,
	environmentID string,
	userID string,
) (useroverride.ApplicationUser, error) {
	row := queryer.QueryRow(ctx, `
		SELECT u.application_user_id, e.environment_id, u.status,
		       u.normalized_claims, u.created_at, u.last_seen_at,
		       ARRAY(
		           SELECT DISTINCT identity.provider_key
		           FROM external_identities AS identity
		           WHERE identity.organization_id = u.organization_id
		             AND identity.application_id = u.application_id
		             AND identity.application_user_id = u.application_user_id
		           ORDER BY identity.provider_key
		           LIMIT 65
		       ) AS identity_providers,
		       CASE WHEN override.user_override_id IS NULL THEN NULL ELSE
		           jsonb_build_object(
		               'id', override.user_override_id,
		               'limit_plan', override.override_document->>'limit_plan',
		               'reason', override.reason,
		               'created_at', override.created_at,
		               'expires_at', override.expires_at
		           )
		       END AS limit_override
		FROM environments AS e
		JOIN applications AS application
		  ON application.organization_id = e.organization_id
		 AND application.application_id = e.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = e.organization_id
		JOIN application_users AS u
		  ON u.organization_id = e.organization_id
		 AND u.application_id = e.application_id
		LEFT JOIN LATERAL (
		    SELECT candidate.*
		    FROM user_overrides AS candidate
		    WHERE candidate.organization_id = e.organization_id
		      AND candidate.application_id = e.application_id
		      AND candidate.environment_id = e.environment_id
		      AND candidate.application_user_id = u.application_user_id
		      AND candidate.revoked_at IS NULL
		      AND (candidate.expires_at IS NULL OR candidate.expires_at > transaction_timestamp())
		    ORDER BY candidate.created_at DESC, candidate.user_override_id DESC
		    LIMIT 1
		) AS override ON true
		WHERE e.organization_id = $1 AND e.environment_id = $2
		  AND u.application_user_id = $3 AND u.status <> 'deleted'
		  AND organization.status = 'active' AND application.status = 'active' AND e.status = 'active'
	`, organizationID, environmentID, userID)
	item, err := scanApplicationUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return useroverride.ApplicationUser{}, errOperationalNotFound
	}
	return item, err
}

func scanApplicationUser(row rowScanner) (useroverride.ApplicationUser, error) {
	var item useroverride.ApplicationUser
	var claims []byte
	var providers []string
	var overrideJSON []byte
	if err := row.Scan(
		&item.ID, &item.EnvironmentID, &item.Status, &claims, &item.CreatedAt,
		&item.LastSeenAt, &providers, &overrideJSON,
	); err != nil {
		return useroverride.ApplicationUser{}, err
	}
	if len(providers) == 0 || len(providers) > maximumIdentityProviders {
		return useroverride.ApplicationUser{}, errOperationalCorrupt
	}
	decodedClaims, err := decodeNormalizedClaims(claims)
	if err != nil {
		return useroverride.ApplicationUser{}, err
	}
	item.IdentityProviders = providers
	item.NormalizedClaims = decodedClaims
	if len(overrideJSON) > 0 {
		var override useroverride.LimitPlanOverride
		if len(overrideJSON) > 4096 || json.Unmarshal(overrideJSON, &override) != nil ||
			id.Validate(override.ID, id.UserOverride) != nil || override.LimitPlan == "" {
			return useroverride.ApplicationUser{}, errOperationalCorrupt
		}
		item.LimitPlanOverride = &override
	}
	return item, nil
}

func decodeNormalizedClaims(encoded []byte) (map[string]any, error) {
	if len(encoded) == 0 || len(encoded) > maximumNormalizedClaimsBytes {
		return nil, errOperationalCorrupt
	}
	var claims map[string]any
	if json.Unmarshal(encoded, &claims) != nil || claims == nil || len(claims) > 64 {
		return nil, errOperationalCorrupt
	}
	return claims, nil
}

func (store *operationalStore) setUserBlocked(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	userID string,
	blocked bool,
	requestID string,
) (useroverride.ApplicationUser, error) {
	if id.Validate(environmentID, id.Environment) != nil || id.Validate(userID, id.ApplicationUser) != nil ||
		id.Validate(requestID, id.AdminRequest) != nil {
		return useroverride.ApplicationUser{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return useroverride.ApplicationUser{}, errOperationalForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return useroverride.ApplicationUser{}, fmt.Errorf("begin application-user status mutation: %w", err)
	}
	defer rollbackOperational(tx)

	var applicationID string
	if err := tx.QueryRow(ctx, `
		SELECT e.application_id
		FROM environments AS e
		JOIN applications AS application
		  ON application.organization_id = e.organization_id
		 AND application.application_id = e.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = e.organization_id
		WHERE e.organization_id = $1 AND e.environment_id = $2
		  AND organization.status = 'active' AND application.status = 'active' AND e.status = 'active'
	`, principal.OrganizationID, environmentID).Scan(&applicationID); errors.Is(err, pgx.ErrNoRows) {
		return useroverride.ApplicationUser{}, errOperationalNotFound
	} else if err != nil {
		return useroverride.ApplicationUser{}, fmt.Errorf("resolve application-user environment: %w", err)
	}
	var storedStatus string
	if err := tx.QueryRow(ctx, `
		SELECT status
		FROM application_users
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND status <> 'deleted'
		FOR UPDATE
	`, principal.OrganizationID, applicationID, userID).Scan(&storedStatus); errors.Is(err, pgx.ErrNoRows) {
		return useroverride.ApplicationUser{}, errOperationalNotFound
	} else if err != nil {
		return useroverride.ApplicationUser{}, fmt.Errorf("lock application user: %w", err)
	}
	if storedStatus != "active" && storedStatus != "blocked" {
		return useroverride.ApplicationUser{}, errOperationalCorrupt
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return useroverride.ApplicationUser{}, fmt.Errorf("read application-user mutation time: %w", err)
	}
	status := "active"
	var blockedAt any
	action := "admin.user_unblock"
	if blocked {
		status = "blocked"
		blockedAt = now
		action = "admin.user_block"
	}
	if _, err := tx.Exec(ctx, `
		UPDATE application_users
		SET status = $4,
		    blocked_at = $5,
		    updated_at = GREATEST(updated_at, created_at, $6::timestamptz)
		WHERE organization_id = $1 AND application_id = $2 AND application_user_id = $3
	`, principal.OrganizationID, applicationID, userID, status, blockedAt, now); err != nil {
		return useroverride.ApplicationUser{}, fmt.Errorf("update application-user status: %w", err)
	}
	if blocked {
		if _, err := tx.Exec(ctx, `
			UPDATE session_grants
			SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4::timestamptz)),
			    revoke_reason = COALESCE(revoke_reason, 'admin_user_blocked')
			WHERE organization_id = $1 AND application_id = $2
			  AND application_user_id = $3 AND revoked_at IS NULL
		`, principal.OrganizationID, applicationID, userID, now); err != nil {
			return useroverride.ApplicationUser{}, fmt.Errorf("revoke blocked-user session grants: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens
			SET status = 'revoked',
			    revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4::timestamptz))
			WHERE organization_id = $1 AND application_id = $2
			  AND application_user_id = $3 AND status IN ('staged', 'active')
		`, principal.OrganizationID, applicationID, userID, now); err != nil {
			return useroverride.ApplicationUser{}, fmt.Errorf("revoke blocked-user refresh tokens: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE component_refresh_tokens
			SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4))
			WHERE client_component_id IN (
			    SELECT client_component_id FROM client_components
			    WHERE organization_id = $1 AND application_id = $2
			      AND application_user_id = $3
			) AND status IN ('staged', 'active')
		`, principal.OrganizationID, applicationID, userID, now); err != nil {
			return useroverride.ApplicationUser{}, fmt.Errorf("revoke blocked-user component refresh tokens: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM refresh_rotation_results
			WHERE client_component_id IN (
			    SELECT client_component_id FROM client_components
			    WHERE organization_id = $1 AND application_id = $2
			      AND application_user_id = $3
			)
		`, principal.OrganizationID, applicationID, userID); err != nil {
			return useroverride.ApplicationUser{}, fmt.Errorf("remove blocked-user component refresh results: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE component_session_families
			SET status = 'revoked', updated_at = GREATEST(updated_at, created_at, $4),
			    revoked_at = COALESCE(revoked_at, GREATEST(created_at, $4)),
			    revocation_reason = COALESCE(revocation_reason, 'admin_user_blocked')
			WHERE organization_id = $1 AND application_id = $2
			  AND application_user_id = $3 AND status = 'active'
		`, principal.OrganizationID, applicationID, userID, now); err != nil {
			return useroverride.ApplicationUser{}, fmt.Errorf("revoke blocked-user component session families: %w", err)
		}
	}
	changes, err := operationalUserChanges(blocked)
	if err != nil {
		return useroverride.ApplicationUser{}, err
	}
	if err := store.audit(ctx, tx, principal, environmentID, action, "application_user", userID, requestID, now, changes); err != nil {
		return useroverride.ApplicationUser{}, err
	}
	result, err := queryApplicationUser(ctx, tx, principal.OrganizationID, environmentID, userID)
	if err != nil {
		return useroverride.ApplicationUser{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return useroverride.ApplicationUser{}, mapOperationalCommit("commit application-user status mutation", err)
	}
	return result, nil
}

func operationalUserChanges(blocked bool) ([]adminauth.AuditChange, error) {
	status, err := adminauth.NewPublicAuditChange("status", adminauth.AuditSet)
	if err != nil {
		return nil, err
	}
	changes := []adminauth.AuditChange{status}
	if blocked {
		sessions, err := adminauth.NewSensitiveAuditChange("session_tokens", adminauth.AuditRevoke)
		if err != nil {
			return nil, err
		}
		changes = append(changes, sessions)
	}
	return changes, nil
}

func (store *operationalStore) listInstallations(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	page operationalPage,
) ([]installationDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || page.validate(id.Installation) != nil {
		return nil, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, `
		SELECT installation.installation_id, installation.application_user_id,
		       installation.environment_id, installation.platform, installation.dpop_jkt,
		       installation.status, installation.trust_level,
		       (
		           SELECT event.provider
		           FROM attestation_events AS event
		           WHERE event.organization_id = installation.organization_id
		             AND event.application_id = installation.application_id
		             AND event.environment_id = installation.environment_id
		             AND event.installation_id = installation.installation_id
		             AND event.outcome = 'accepted'
		           ORDER BY event.occurred_at DESC, event.attestation_event_id DESC
		           LIMIT 1
		       ) AS attestation_provider,
		       (
		           SELECT max(session_record.expires_at)
		           FROM session_grants AS session_record
		           WHERE session_record.organization_id = installation.organization_id
		             AND session_record.application_id = installation.application_id
		             AND session_record.environment_id = installation.environment_id
		             AND session_record.installation_id = installation.installation_id
		             AND session_record.attested_at IS NOT NULL AND session_record.revoked_at IS NULL
		       ) AS trust_expires_at,
		       installation.created_at, installation.last_seen_at, installation.revoked_at
		FROM installations AS installation
		JOIN environments AS environment
		  ON environment.organization_id = installation.organization_id
		 AND environment.application_id = installation.application_id
		 AND environment.environment_id = installation.environment_id
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE installation.organization_id = $1 AND installation.environment_id = $2
		  AND organization.status = 'active' AND application.status = 'active' AND environment.status = 'active'
		  AND ($3::timestamptz IS NULL OR (installation.created_at, installation.installation_id) > ($3, $4))
		ORDER BY installation.created_at, installation.installation_id
		LIMIT $5
	`, principal.OrganizationID, environmentID, nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list installations: %w", err)
	}
	defer rows.Close()
	items := make([]installationDocument, 0, page.size+1)
	for rows.Next() {
		item, scanErr := scanInstallation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate installations: %w", err)
	}
	return items, nil
}

func (store *operationalStore) getInstallation(
	ctx context.Context,
	principal adminauth.Principal,
	installationID string,
) (installationDocument, error) {
	if id.Validate(installationID, id.Installation) != nil {
		return installationDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return installationDocument{}, errOperationalForbidden
	}
	return queryInstallation(ctx, store.pool, principal.OrganizationID, installationID)
}

func queryInstallation(
	ctx context.Context,
	queryer rowQueryer,
	organizationID string,
	installationID string,
) (installationDocument, error) {
	row := queryer.QueryRow(ctx, `
		SELECT installation.installation_id, installation.application_user_id,
		       installation.environment_id, installation.platform, installation.dpop_jkt,
		       installation.status, installation.trust_level,
		       (
		           SELECT event.provider
		           FROM attestation_events AS event
		           WHERE event.organization_id = installation.organization_id
		             AND event.application_id = installation.application_id
		             AND event.environment_id = installation.environment_id
		             AND event.installation_id = installation.installation_id
		             AND event.outcome = 'accepted'
		           ORDER BY event.occurred_at DESC, event.attestation_event_id DESC
		           LIMIT 1
		       ),
		       (
		           SELECT max(session_record.expires_at)
		           FROM session_grants AS session_record
		           WHERE session_record.organization_id = installation.organization_id
		             AND session_record.application_id = installation.application_id
		             AND session_record.environment_id = installation.environment_id
		             AND session_record.installation_id = installation.installation_id
		             AND session_record.attested_at IS NOT NULL AND session_record.revoked_at IS NULL
		       ),
		       installation.created_at, installation.last_seen_at, installation.revoked_at
		FROM installations AS installation
		JOIN environments AS environment
		  ON environment.organization_id = installation.organization_id
		 AND environment.application_id = installation.application_id
		 AND environment.environment_id = installation.environment_id
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE installation.organization_id = $1 AND installation.installation_id = $2
		  AND organization.status = 'active' AND application.status = 'active' AND environment.status = 'active'
	`, organizationID, installationID)
	item, err := scanInstallation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return installationDocument{}, errOperationalNotFound
	}
	return item, err
}

func scanInstallation(row rowScanner) (installationDocument, error) {
	var item installationDocument
	if err := row.Scan(
		&item.ID, &item.UserID, &item.EnvironmentID, &item.Platform, &item.DPoPJKT,
		&item.Status, &item.TrustLevel, &item.AttestationProvider, &item.TrustExpiresAt,
		&item.CreatedAt, &item.LastSeenAt, &item.RevokedAt,
	); err != nil {
		return installationDocument{}, err
	}
	return item, nil
}

func (store *operationalStore) revokeInstallation(
	ctx context.Context,
	principal adminauth.Principal,
	installationID string,
	reason string,
	requestID string,
) (installationDocument, error) {
	if id.Validate(installationID, id.Installation) != nil || id.Validate(requestID, id.AdminRequest) != nil {
		return installationDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return installationDocument{}, errOperationalForbidden
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "admin_installation_revoked"
	}
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 100 ||
		strings.ContainsAny(reason, "\r\n\x00") {
		return installationDocument{}, errOperationalInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return installationDocument{}, fmt.Errorf("begin installation revocation: %w", err)
	}
	defer rollbackOperational(tx)
	var applicationID, environmentID, userID, status string
	if err := tx.QueryRow(ctx, `
		SELECT application_id, environment_id, application_user_id, status
		FROM installations
		WHERE organization_id = $1 AND installation_id = $2
		FOR UPDATE
	`, principal.OrganizationID, installationID).Scan(
		&applicationID, &environmentID, &userID, &status,
	); errors.Is(err, pgx.ErrNoRows) {
		return installationDocument{}, errOperationalNotFound
	} else if err != nil {
		return installationDocument{}, fmt.Errorf("lock installation: %w", err)
	}
	if status != "active" && status != "revoked" {
		return installationDocument{}, errOperationalCorrupt
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return installationDocument{}, fmt.Errorf("read installation revocation time: %w", err)
	}
	var installationFamilyID *string
	if err := tx.QueryRow(ctx, `
		SELECT installation_family_id
		FROM installation_families
		WHERE organization_id = $1 AND root_installation_id = $2
		FOR UPDATE
	`, principal.OrganizationID, installationID).Scan(&installationFamilyID); errors.Is(err, pgx.ErrNoRows) {
		installationFamilyID = nil
	} else if err != nil {
		return installationDocument{}, fmt.Errorf("lock installation family for legacy revocation: %w", err)
	}
	if installationFamilyID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE installation_families
			SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(created_at, $3)),
			    revocation_reason = COALESCE(revocation_reason, $4),
			    updated_at = GREATEST(updated_at, created_at, $3)
			WHERE organization_id = $1 AND installation_family_id = $2
		`, principal.OrganizationID, *installationFamilyID, now, reason); err != nil {
			return installationDocument{}, fmt.Errorf("revoke installation family through legacy endpoint: %w", err)
		}
		if err := revokeComponentCredentials(
			ctx, tx, principal.OrganizationID, *installationFamilyID, nil, now, reason,
		); err != nil {
			return installationDocument{}, err
		}
	}
	if status == "active" {
		if _, err := tx.Exec(ctx, `
			UPDATE installations
			SET status = 'revoked',
			    revoked_at = GREATEST(created_at, $3::timestamptz),
			    revoke_reason = $4,
			    updated_at = GREATEST(updated_at, created_at, $3::timestamptz)
			WHERE organization_id = $1 AND installation_id = $2 AND status = 'active'
		`, principal.OrganizationID, installationID, now, reason); err != nil {
			return installationDocument{}, fmt.Errorf("revoke installation: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $6::timestamptz)),
		    revoke_reason = COALESCE(revoke_reason, 'admin_installation_revoked')
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5 AND revoked_at IS NULL
	`, principal.OrganizationID, applicationID, environmentID, userID, installationID, now); err != nil {
		return installationDocument{}, fmt.Errorf("revoke installation session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $6::timestamptz))
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5
		  AND status IN ('staged', 'active')
	`, principal.OrganizationID, applicationID, environmentID, userID, installationID, now); err != nil {
		return installationDocument{}, fmt.Errorf("revoke installation refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET status = 'revoked', revoked_at = GREATEST(created_at, $5::timestamptz),
		    updated_at = GREATEST(updated_at, created_at, $5::timestamptz)
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND installation_id = $4 AND status <> 'revoked'
	`, principal.OrganizationID, applicationID, environmentID, installationID, now); err != nil {
		return installationDocument{}, fmt.Errorf("revoke installation attestation keys: %w", err)
	}
	statusChange, err := adminauth.NewPublicAuditChange("status", adminauth.AuditSet)
	if err != nil {
		return installationDocument{}, err
	}
	credentialChange, err := adminauth.NewSensitiveAuditChange("session_tokens", adminauth.AuditRevoke)
	if err != nil {
		return installationDocument{}, err
	}
	if err := store.audit(
		ctx, tx, principal, environmentID, "admin.installation_revoke", "installation",
		installationID, requestID, now, []adminauth.AuditChange{statusChange, credentialChange},
	); err != nil {
		return installationDocument{}, err
	}
	result, err := queryInstallation(ctx, tx, principal.OrganizationID, installationID)
	if err != nil {
		return installationDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return installationDocument{}, mapOperationalCommit("commit installation revocation", err)
	}
	return result, nil
}

func (store *operationalStore) listRequests(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	page operationalPage,
) ([]logicalRequestDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || page.validate(id.LogicalRequest) != nil {
		return nil, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, `
		SELECT logical_request_id, environment_id, application_user_id, installation_id,
		       installation_family_id, client_component_id, component_definition_id,
		       component_kind, trust_source, framework, framework_version,
		       feature_key, protocol, requested_at, completed_at, status
		FROM logical_requests
		WHERE organization_id = $1 AND environment_id = $2
		  AND ($3::timestamptz IS NULL OR (requested_at, logical_request_id) > ($3, $4))
		ORDER BY requested_at, logical_request_id
		LIMIT $5
	`, principal.OrganizationID, environmentID, nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list logical requests: %w", err)
	}
	defer rows.Close()
	items := make([]logicalRequestDocument, 0, page.size+1)
	for rows.Next() {
		item, scanErr := scanLogicalRequestSummary(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		item.Attempts = make([]upstreamAttemptDocument, 0)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate logical requests: %w", err)
	}
	if err := store.populateRequestDetails(ctx, principal.OrganizationID, items); err != nil {
		return nil, err
	}
	return items, nil
}

func (store *operationalStore) getRequest(
	ctx context.Context,
	principal adminauth.Principal,
	requestID string,
) (logicalRequestDocument, error) {
	if id.Validate(requestID, id.LogicalRequest) != nil {
		return logicalRequestDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return logicalRequestDocument{}, errOperationalForbidden
	}
	row := store.pool.QueryRow(ctx, `
		SELECT logical_request_id, environment_id, application_user_id, installation_id,
		       installation_family_id, client_component_id, component_definition_id,
		       component_kind, trust_source, framework, framework_version,
		       feature_key, protocol, requested_at, completed_at, status
		FROM logical_requests
		WHERE organization_id = $1 AND logical_request_id = $2
	`, principal.OrganizationID, requestID)
	item, err := scanLogicalRequestSummary(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return logicalRequestDocument{}, errOperationalNotFound
	}
	if err != nil {
		return logicalRequestDocument{}, fmt.Errorf("read logical request: %w", err)
	}
	item.Attempts = make([]upstreamAttemptDocument, 0)
	items := []logicalRequestDocument{item}
	if err := store.populateRequestDetails(ctx, principal.OrganizationID, items); err != nil {
		return logicalRequestDocument{}, err
	}
	return items[0], nil
}

func scanLogicalRequestSummary(row rowScanner) (logicalRequestDocument, error) {
	var item logicalRequestDocument
	var status string
	if err := row.Scan(
		&item.ID, &item.EnvironmentID, &item.UserID, &item.InstallationID,
		&item.InstallationFamilyID, &item.ClientComponentID,
		&item.ComponentDefinitionID, &item.ComponentKind, &item.TrustSource,
		&item.Framework, &item.FrameworkVersion,
		&item.Feature, &item.Protocol, &item.StartedAt, &item.CompletedAt, &status,
	); err != nil {
		return logicalRequestDocument{}, err
	}
	if !validRequestAttribution(item) {
		return logicalRequestDocument{}, errOperationalCorrupt
	}
	item.Status = publicLogicalRequestStatus(status)
	return item, nil
}

func validRequestAttribution(item logicalRequestDocument) bool {
	componentValues := []bool{
		item.InstallationFamilyID != nil,
		item.ClientComponentID != nil,
		item.ComponentDefinitionID != nil,
		item.ComponentKind != nil,
		item.TrustSource != nil,
	}
	for _, present := range componentValues[1:] {
		if present != componentValues[0] {
			return false
		}
	}
	if item.InstallationFamilyID != nil {
		if id.Validate(*item.InstallationFamilyID, id.InstallationFamily) != nil ||
			id.Validate(*item.ClientComponentID, id.ClientComponent) != nil ||
			!operationalIdentifierPattern.MatchString(*item.ComponentDefinitionID) ||
			!operationalIdentifierPattern.MatchString(*item.ComponentKind) ||
			!operationalIdentifierPattern.MatchString(*item.TrustSource) {
			return false
		}
	}
	if (item.Framework == nil) != (item.FrameworkVersion == nil) {
		return false
	}
	if item.Framework != nil {
		if !operationalIdentifierPattern.MatchString(*item.Framework) ||
			!validOperationalVersion(*item.FrameworkVersion) {
			return false
		}
	}
	return true
}

func validOperationalVersion(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func publicLogicalRequestStatus(status string) string {
	switch status {
	case "succeeded":
		return "succeeded"
	case "failed", "denied":
		return "failed"
	case "cancelled":
		return "canceled"
	case "reserved", "dispatched", "streaming":
		return "unknown"
	default:
		return "unknown"
	}
}

func publicAttemptStatus(status string) string {
	switch status {
	case "succeeded":
		return "succeeded"
	case "failed", "timed_out":
		return "failed"
	case "cancelled":
		return "canceled"
	case "started":
		return "unknown"
	default:
		return "unknown"
	}
}

// publicAttemptFailureCode is deliberately a many-to-one boundary. Durable
// failure codes are internal implementation details and may contain legacy or
// dependency-specific values. Only this closed, redaction-safe vocabulary is
// returned by the Admin API.
func publicAttemptFailureCode(code string) string {
	switch code {
	case "client_cancelled", "request_cancelled":
		return "canceled"
	case "pricing_unavailable", "quota_state_unavailable", "configuration_invalid":
		return "gateway_error"
	case "upstream_protocol_error":
		return "protocol_error"
	case "upstream_timeout", "upstream_timed_out":
		return "timeout"
	case "upstream_unavailable":
		return "unavailable"
	case "upstream_non_success":
		return "upstream_rejected"
	default:
		return "unknown"
	}
}

func validateUpstreamAttempt(
	attempt upstreamAttemptDocument,
	storedStatus string,
	storedFailureCode *string,
	expectedNumber int32,
) error {
	if attempt.AttemptNumber != expectedNumber || attempt.AttemptNumber < 1 ||
		attempt.AttemptNumber > maximumUpstreamAttempts ||
		id.Validate(attempt.ID, id.UpstreamAttempt) != nil ||
		!operationalIdentifierPattern.MatchString(attempt.Route) ||
		!operationalIdentifierPattern.MatchString(attempt.Upstream) ||
		attempt.StartedAt.IsZero() {
		return errOperationalCorrupt
	}
	if attempt.FirstByteAt != nil && attempt.FirstByteAt.Before(attempt.StartedAt) ||
		attempt.FirstTokenAt != nil && (attempt.FirstByteAt == nil || attempt.FirstTokenAt.Before(*attempt.FirstByteAt)) ||
		attempt.CompletedAt != nil && attempt.CompletedAt.Before(attempt.StartedAt) ||
		attempt.FirstByteAt != nil && attempt.CompletedAt != nil &&
			attempt.FirstByteAt.After(*attempt.CompletedAt) ||
		attempt.FirstTokenAt != nil && attempt.CompletedAt != nil &&
			attempt.FirstTokenAt.After(*attempt.CompletedAt) ||
		attempt.HTTPStatus != nil && (*attempt.HTTPStatus < 100 || *attempt.HTTPStatus > 599) {
		return errOperationalCorrupt
	}
	switch storedStatus {
	case "started":
		if attempt.CompletedAt != nil || attempt.HTTPStatus != nil || storedFailureCode != nil {
			return errOperationalCorrupt
		}
	case "succeeded":
		if attempt.CompletedAt == nil || storedFailureCode != nil || attempt.HTTPStatus == nil ||
			*attempt.HTTPStatus < 200 || *attempt.HTTPStatus > 299 {
			return errOperationalCorrupt
		}
	case "failed", "timed_out", "cancelled":
		if attempt.CompletedAt == nil || storedFailureCode == nil {
			return errOperationalCorrupt
		}
	default:
		return errOperationalCorrupt
	}
	return nil
}

func (store *operationalStore) populateRequestDetails(
	ctx context.Context,
	organizationID string,
	items []logicalRequestDocument,
) error {
	if len(items) == 0 {
		return nil
	}
	requestIDs := make([]string, len(items))
	requestIndexes := make(map[string]int, len(items))
	for index := range items {
		requestIDs[index] = items[index].ID
		requestIndexes[items[index].ID] = index
	}
	attemptRows, err := store.pool.Query(ctx, `
		SELECT logical_request_id, upstream_attempt_id, attempt_number, route_key,
		       upstream_key, COALESCE(physical_model, ''), started_at, first_byte_at, first_token_at,
		       completed_at, status, http_status, failure_code,
		       cost_confidence, pricing_source
		FROM upstream_attempts
		WHERE organization_id = $1 AND logical_request_id = ANY($2::text[])
		ORDER BY logical_request_id, attempt_number
	`, organizationID, requestIDs)
	if err != nil {
		return fmt.Errorf("list upstream attempts: %w", err)
	}
	attemptLocations := make(map[string][2]int)
	for attemptRows.Next() {
		var requestID, status string
		var failureCode, costConfidence, pricingSource *string
		var attempt upstreamAttemptDocument
		if err := attemptRows.Scan(
			&requestID, &attempt.ID, &attempt.AttemptNumber, &attempt.Route,
			&attempt.Upstream, &attempt.Model, &attempt.StartedAt, &attempt.FirstByteAt, &attempt.FirstTokenAt,
			&attempt.CompletedAt, &status, &attempt.HTTPStatus, &failureCode,
			&costConfidence, &pricingSource,
		); err != nil {
			attemptRows.Close()
			return fmt.Errorf("scan upstream attempt: %w", err)
		}
		requestIndex, ok := requestIndexes[requestID]
		if !ok || validateUpstreamAttempt(
			attempt, status, failureCode, int32(len(items[requestIndex].Attempts)+1),
		) != nil {
			attemptRows.Close()
			return errOperationalCorrupt
		}
		attempt.Status = publicAttemptStatus(status)
		if failureCode != nil {
			publicCode := publicAttemptFailureCode(*failureCode)
			attempt.FailureCode = &publicCode
		}
		attempt.UsageProvenance = "unknown"
		attempt.CostProvenance = "unknown"
		if costConfidence != nil {
			attempt.CostProvenance = publicUsageProvenance(*costConfidence)
			switch *costConfidence {
			case "reported":
				source := configuration.ProviderReportedCostSourceOpenRouterUsage
				attempt.CostSource = &source
			case "calculated", "estimated", "reconciled_later":
				attempt.CostSource = pricingSource
			}
		}
		attemptIndex := len(items[requestIndex].Attempts)
		items[requestIndex].Attempts = append(items[requestIndex].Attempts, attempt)
		attemptLocations[attempt.ID] = [2]int{requestIndex, attemptIndex}
	}
	if err := attemptRows.Err(); err != nil {
		attemptRows.Close()
		return fmt.Errorf("iterate upstream attempts: %w", err)
	}
	attemptRows.Close()

	usageRows, err := store.pool.Query(ctx, `
		SELECT logical_request_id, upstream_attempt_id,
		       GROUPING(upstream_attempt_id) = 1 AS request_total,
		       COALESCE(sum(units) FILTER (WHERE metric = 'logical_requests'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'input_tokens'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'output_tokens'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'total_tokens'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'cost_nano_usd'), 0)::bigint,
		       COALESCE(array_agg(DISTINCT confidence), ARRAY[]::text[])
		FROM usage_records
		WHERE organization_id = $1 AND logical_request_id = ANY($2::text[])
		GROUP BY GROUPING SETS (
		    (logical_request_id),
		    (logical_request_id, upstream_attempt_id)
		)
		ORDER BY logical_request_id, request_total DESC, upstream_attempt_id NULLS FIRST
	`, organizationID, requestIDs)
	if err != nil {
		return fmt.Errorf("list request usage: %w", err)
	}
	defer usageRows.Close()
	for usageRows.Next() {
		var requestID string
		var attemptID *string
		var requestTotal bool
		var values usageValues
		var confidences []string
		if err := usageRows.Scan(
			&requestID, &attemptID, &requestTotal,
			&values.LogicalRequests, &values.InputTokens, &values.OutputTokens,
			&values.TotalTokens, &values.CostNanoUSD, &confidences,
		); err != nil {
			return fmt.Errorf("scan request usage: %w", err)
		}
		requestIndex, requestFound := requestIndexes[requestID]
		if !requestFound || values.LogicalRequests < 0 || values.InputTokens < 0 ||
			values.OutputTokens < 0 || values.TotalTokens < 0 || values.CostNanoUSD < 0 {
			return errOperationalCorrupt
		}
		if requestTotal {
			if attemptID != nil {
				return errOperationalCorrupt
			}
			items[requestIndex].Usage = &values
			continue
		}
		// Usage can be attached only to the logical request. Its per-attempt
		// grouping is intentionally omitted while the request-total grouping
		// above still accounts for it.
		if attemptID == nil {
			continue
		}
		location, ok := attemptLocations[*attemptID]
		if !ok || location[0] != requestIndex {
			return errOperationalCorrupt
		}
		items[location[0]].Attempts[location[1]].Usage = &values
		items[location[0]].Attempts[location[1]].UsageProvenance = primaryUsageProvenance(confidences)
	}
	if err := usageRows.Err(); err != nil {
		return fmt.Errorf("iterate request usage: %w", err)
	}
	return nil
}

func publicUsageProvenance(confidence string) string {
	switch confidence {
	case "reported":
		return "upstream_reported"
	case "calculated":
		return "calculated"
	case "estimated", "reconciled_later":
		return "estimated"
	case "unknown":
		return "unknown"
	default:
		return "unknown"
	}
}

func primaryUsageProvenance(confidences []string) string {
	values := make(map[string]struct{}, len(confidences))
	for _, confidence := range confidences {
		values[publicUsageProvenance(confidence)] = struct{}{}
	}
	for _, candidate := range []string{"unknown", "estimated", "upstream_reported", "calculated", "configured"} {
		if _, ok := values[candidate]; ok {
			return candidate
		}
	}
	return "unknown"
}

func (store *operationalStore) usageSummary(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	start time.Time,
	end time.Time,
	breakdownLimit int,
) (usageSummaryDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || !validUsageRange(start, end, maximumSummaryRange) ||
		breakdownLimit < 1 || breakdownLimit > maximumUsageBreakdownLimit {
		return usageSummaryDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return usageSummaryDocument{}, errOperationalForbidden
	}
	if err := store.ensureEnvironment(ctx, principal.OrganizationID, environmentID); err != nil {
		return usageSummaryDocument{}, err
	}
	values, provenance, err := store.aggregateUsage(ctx, principal.OrganizationID, environmentID, start, end)
	if err != nil {
		return usageSummaryDocument{}, err
	}
	analytics, err := store.usageAnalytics(
		ctx, principal, environmentID, start, end, values, breakdownLimit,
	)
	if err != nil {
		return usageSummaryDocument{}, err
	}
	return usageSummaryDocument{
		Start: start.UTC(), End: end.UTC(), Values: values, Provenance: provenance, Analytics: analytics,
	}, nil
}

func (store *operationalStore) aggregateUsage(
	ctx context.Context,
	organizationID string,
	environmentID string,
	start time.Time,
	end time.Time,
) (usageValues, []string, error) {
	var values usageValues
	var confidences []string
	err := store.pool.QueryRow(ctx, `
		SELECT
		    COALESCE(sum(units) FILTER (WHERE metric = 'logical_requests'), 0)::bigint,
		    COALESCE(sum(units) FILTER (WHERE metric = 'input_tokens'), 0)::bigint,
		    COALESCE(sum(units) FILTER (WHERE metric = 'output_tokens'), 0)::bigint,
		    COALESCE(sum(units) FILTER (WHERE metric = 'total_tokens'), 0)::bigint,
		    COALESCE(sum(units) FILTER (WHERE metric = 'cost_nano_usd'), 0)::bigint,
		    COALESCE(array_agg(DISTINCT confidence) FILTER (WHERE confidence IS NOT NULL), ARRAY[]::text[])
		FROM usage_records
		WHERE organization_id = $1 AND environment_id = $2
		  AND recorded_at >= $3 AND recorded_at < $4
	`, organizationID, environmentID, start.UTC(), end.UTC()).Scan(
		&values.LogicalRequests, &values.InputTokens, &values.OutputTokens,
		&values.TotalTokens, &values.CostNanoUSD, &confidences,
	)
	if err != nil {
		return usageValues{}, nil, fmt.Errorf("aggregate usage summary: %w", err)
	}
	provenance := normalizeProvenance(confidences)
	return values, provenance, nil
}

func normalizeProvenance(confidences []string) []string {
	set := make(map[string]struct{}, len(confidences))
	for _, confidence := range confidences {
		set[publicUsageProvenance(confidence)] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (store *operationalStore) usageTimeseries(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	start time.Time,
	end time.Time,
	interval string,
) (usageTimeseriesDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || !validUsageRange(start, end, 0) ||
		(interval != "hour" && interval != "day") {
		return usageTimeseriesDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return usageTimeseriesDocument{}, errOperationalForbidden
	}
	if err := store.ensureEnvironment(ctx, principal.OrganizationID, environmentID); err != nil {
		return usageTimeseriesDocument{}, err
	}
	floor, step := usageBucket(interval, start.UTC())
	points := make([]usagePoint, 0)
	pointIndex := make(map[time.Time]int)
	for timestamp := floor; timestamp.Before(end.UTC()); timestamp = timestamp.Add(step) {
		if len(points) >= maximumUsagePoints {
			return usageTimeseriesDocument{}, errOperationalInvalid
		}
		pointIndex[timestamp] = len(points)
		points = append(points, usagePoint{Timestamp: timestamp})
	}
	truncation := "hour"
	if interval == "day" {
		truncation = "day"
	}
	query := fmt.Sprintf(`
		SELECT date_trunc('%s', recorded_at, 'UTC') AS bucket,
		       COALESCE(sum(units) FILTER (WHERE metric = 'logical_requests'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'input_tokens'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'output_tokens'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'total_tokens'), 0)::bigint,
		       COALESCE(sum(units) FILTER (WHERE metric = 'cost_nano_usd'), 0)::bigint
		FROM usage_records
		WHERE organization_id = $1 AND environment_id = $2
		  AND recorded_at >= $3 AND recorded_at < $4
		GROUP BY bucket
		ORDER BY bucket
	`, truncation)
	rows, err := store.pool.Query(ctx, query, principal.OrganizationID, environmentID, start.UTC(), end.UTC())
	if err != nil {
		return usageTimeseriesDocument{}, fmt.Errorf("read usage timeseries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var timestamp time.Time
		var values usageValues
		if err := rows.Scan(
			&timestamp, &values.LogicalRequests, &values.InputTokens, &values.OutputTokens,
			&values.TotalTokens, &values.CostNanoUSD,
		); err != nil {
			return usageTimeseriesDocument{}, fmt.Errorf("scan usage timeseries: %w", err)
		}
		index, ok := pointIndex[timestamp.UTC()]
		if !ok {
			return usageTimeseriesDocument{}, errOperationalCorrupt
		}
		points[index].Values = values
	}
	if err := rows.Err(); err != nil {
		return usageTimeseriesDocument{}, fmt.Errorf("iterate usage timeseries: %w", err)
	}
	return usageTimeseriesDocument{Interval: interval, Points: points}, nil
}

func usageBucket(interval string, instant time.Time) (time.Time, time.Duration) {
	instant = instant.UTC()
	if interval == "day" {
		return time.Date(instant.Year(), instant.Month(), instant.Day(), 0, 0, 0, 0, time.UTC), 24 * time.Hour
	}
	return instant.Truncate(time.Hour), time.Hour
}

func validUsageRange(start, end time.Time, maximum time.Duration) bool {
	if start.IsZero() || end.IsZero() || !start.Before(end) {
		return false
	}
	duration := end.Sub(start)
	return maximum <= 0 || duration <= maximum
}

func (store *operationalStore) ensureEnvironment(ctx context.Context, organizationID, environmentID string) error {
	var exists bool
	err := store.pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM environments AS environment
		    JOIN applications AS application
		      ON application.organization_id = environment.organization_id
		     AND application.application_id = environment.application_id
		    JOIN organizations AS organization
		      ON organization.organization_id = environment.organization_id
		    WHERE environment.organization_id = $1 AND environment.environment_id = $2
		      AND organization.status = 'active' AND application.status = 'active'
		      AND environment.status = 'active'
		)
	`, organizationID, environmentID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("verify usage environment: %w", err)
	}
	if !exists {
		return errOperationalNotFound
	}
	return nil
}

func (store *operationalStore) listAuditEvents(
	ctx context.Context,
	principal adminauth.Principal,
	organizationID string,
	page operationalPage,
) ([]auditEventDocument, error) {
	if organizationID == "" {
		organizationID = principal.OrganizationID
	}
	if id.Validate(organizationID, id.Organization) != nil || page.validate(id.AuditEvent) != nil {
		return nil, errOperationalInvalid
	}
	if organizationID != principal.OrganizationID || !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, `
		SELECT event.audit_event_id, event.occurred_at,
		       event.actor_kind, event.actor_id, event.action,
		       event.resource_type, event.resource_id, event.outcome,
		       event.request_id,
		       COALESCE((
		           SELECT jsonb_agg(
		               jsonb_build_object(
		                   'field', change.field_name,
		                   'operation', change.operation,
		                   'classification', change.classification
		               ) ORDER BY change.ordinal
		           )
		           FROM audit_event_changes AS change
		           WHERE change.audit_event_id = event.audit_event_id
		       ), '[]'::jsonb) AS changes
		FROM audit_events AS event
		WHERE event.organization_id = $1
		  AND ($2::timestamptz IS NULL OR (event.occurred_at, event.audit_event_id) < ($2, $3))
		ORDER BY event.occurred_at DESC, event.audit_event_id DESC
		LIMIT $4
	`, organizationID, nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	items := make([]auditEventDocument, 0, page.size+1)
	for rows.Next() {
		var item auditEventDocument
		var actorKind, resourceType string
		var actorID, requestID *string
		var changesJSON []byte
		if err := rows.Scan(
			&item.ID, &item.Timestamp, &actorKind, &actorID, &item.Action,
			&resourceType, &item.Target, &item.Result, &requestID, &changesJSON,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		resourceID := item.Target
		item.Target = resourceType + ":" + resourceID
		item.Actor = actorKind
		if actorID != nil {
			item.Actor += ":" + *actorID
		}
		if requestID != nil {
			item.RequestID = *requestID
		}
		var changes []map[string]any
		if len(changesJSON) > 64<<10 || json.Unmarshal(changesJSON, &changes) != nil || len(changes) > 100 {
			return nil, errOperationalCorrupt
		}
		item.Summary = map[string]any{"changes": changes}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return items, nil
}

type startSelfTestInput struct {
	Kind        string
	Environment string
	Upstream    string
	Model       string
	MaxCost     int64
	RequestID   string
}

func (store *operationalStore) startSelfTest(
	ctx context.Context,
	principal adminauth.Principal,
	input startSelfTestInput,
) (selfTestDocument, error) {
	if id.Validate(input.Environment, id.Environment) != nil ||
		id.Validate(input.RequestID, id.AdminRequest) != nil {
		return selfTestDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RunSelfTests, adminauth.AuthorizationContext{}) {
		return selfTestDocument{}, errOperationalForbidden
	}
	switch input.Kind {
	case "local":
		if input.Upstream != "" || input.Model != "" || input.MaxCost != 0 {
			return selfTestDocument{}, errOperationalInvalid
		}
	case "upstream", "openrouter":
		if store.selfTests == nil || !selfTestIdentifierPattern.MatchString(input.Upstream) ||
			!selfTestIdentifierPattern.MatchString(input.Model) || input.MaxCost < 1 ||
			input.MaxCost > maximumSelfTestCostNanoUSD {
			return selfTestDocument{}, errOperationalInvalid
		}
		return store.startCredentialSelfTest(ctx, principal, input)
	default:
		return selfTestDocument{}, errOperationalInvalid
	}
	currentSchema, availableSchema, err := database.NewMigrator(store.pool).Status(ctx)
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("read self-test schema status: %w", err)
	}
	selfTestID, err := store.newID(id.Prefix("tst"))
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("generate self-test ID: %w", err)
	}
	jobID, err := store.newID(id.Job)
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("generate self-test job ID: %w", err)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("begin local self-test: %w", err)
	}
	defer rollbackOperational(tx)
	var now time.Time
	var activeConfiguration bool
	err = tx.QueryRow(ctx, `
		SELECT transaction_timestamp(),
		       EXISTS (
		           SELECT 1
		           FROM active_config_revisions AS active
		           JOIN config_revisions AS revision
		             ON revision.organization_id = active.organization_id
		            AND revision.application_id = active.application_id
		            AND revision.environment_id = active.environment_id
		            AND revision.config_revision_id = active.config_revision_id
		           WHERE active.organization_id = environment.organization_id
		             AND active.application_id = environment.application_id
		             AND active.environment_id = environment.environment_id
			     AND active.revision_status = 'valid'
			     AND revision.status = 'valid'
		             AND revision.compiled_document IS NOT NULL
		       )
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE environment.organization_id = $1 AND environment.environment_id = $2
		  AND organization.status = 'active' AND application.status = 'active'
		  AND environment.status = 'active'
		FOR SHARE OF environment
	`, principal.OrganizationID, input.Environment).Scan(&now, &activeConfiguration)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestDocument{}, errOperationalNotFound
	}
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("inspect local self-test environment: %w", err)
	}
	checks := []selfTestCheck{
		{Name: "database", State: "passed", SafeDetail: "PostgreSQL transaction completed."},
		{Name: "schema", State: "passed", SafeDetail: "Database schema is current."},
		{Name: "active_configuration", State: "passed", SafeDetail: "An active compiled configuration is available."},
	}
	state := "passed"
	if currentSchema != availableSchema {
		checks[1] = selfTestCheck{Name: "schema", State: "failed", SafeDetail: "Database schema is not current."}
		state = "failed"
	}
	if !activeConfiguration {
		checks[2] = selfTestCheck{Name: "active_configuration", State: "failed", SafeDetail: "No active compiled configuration is available."}
		state = "failed"
	}
	completedAt := now.UTC()
	run := selfTestDocument{
		ID: selfTestID, Kind: "local", State: state, CreatedAt: now.UTC(),
		CompletedAt: &completedAt, Checks: checks,
	}
	payload, err := json.Marshal(run)
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("encode local self-test result: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO jobs (
		    job_id, organization_id, environment_id, job_type, idempotency_key,
		    payload, status, available_at, attempt_count, max_attempts,
		    created_at, updated_at, completed_at
		) VALUES (
		    $1, $2, $3, 'run_scheduled_self_test', $4,
		    $5, 'succeeded', $6, 1, 1, $6, $6, $6
		)
	`, jobID, principal.OrganizationID, input.Environment, "admin-self-test:"+selfTestID,
		payload, now); err != nil {
		return selfTestDocument{}, mapOperationalDatabase("persist local self-test", err)
	}
	stateChange, err := adminauth.NewPublicAuditChange("state", adminauth.AuditSet)
	if err != nil {
		return selfTestDocument{}, err
	}
	if err := store.audit(
		ctx, tx, principal, input.Environment, "admin.self_test_run", "self_test",
		selfTestID, input.RequestID, now, []adminauth.AuditChange{stateChange},
	); err != nil {
		return selfTestDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return selfTestDocument{}, mapOperationalCommit("commit local self-test", err)
	}
	return run, nil
}

func (store *operationalStore) getSelfTest(
	ctx context.Context,
	principal adminauth.Principal,
	selfTestID string,
) (selfTestDocument, error) {
	if id.Validate(selfTestID, id.Prefix("tst")) != nil {
		return selfTestDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RunSelfTests, adminauth.AuthorizationContext{}) {
		return selfTestDocument{}, errOperationalForbidden
	}
	var payload []byte
	err := store.pool.QueryRow(ctx, `
		SELECT payload
		FROM jobs
		WHERE organization_id = $1 AND job_type = 'run_scheduled_self_test'
		  AND payload->>'id' = $2
	`, principal.OrganizationID, selfTestID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestDocument{}, errOperationalNotFound
	}
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("read self-test: %w", err)
	}
	var run selfTestDocument
	if len(payload) == 0 || len(payload) > 64<<10 || json.Unmarshal(payload, &run) != nil ||
		run.ID != selfTestID || !validStoredSelfTest(run) {
		return selfTestDocument{}, errOperationalCorrupt
	}
	return run, nil
}

func (store *operationalStore) audit(
	ctx context.Context,
	tx pgx.Tx,
	principal adminauth.Principal,
	environmentID string,
	action string,
	resourceType string,
	resourceID string,
	requestID string,
	occurredAt time.Time,
	changes []adminauth.AuditChange,
) error {
	eventID, err := store.newID(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate operational audit ID: %w", err)
	}
	var actor adminauth.AuditActor
	if principal.Method == adminauth.AuthenticationAPIToken {
		actor, err = adminauth.NewAPITokenActor(principal.CredentialID)
	} else {
		actor, err = adminauth.NewAdminUserActor(principal.AdminUserID)
	}
	if err != nil {
		return err
	}
	mutation, err := adminauth.NewAuditMutation(
		eventID, principal.OrganizationID, environmentID, actor, action, resourceType,
		resourceID, adminauth.AuditSucceeded, requestID, occurredAt.UTC(), changes,
	)
	if err != nil {
		return err
	}
	if err := adminauth.InsertAuditMutation(ctx, tx, mutation); err != nil {
		return fmt.Errorf("insert operational audit event: %w", err)
	}
	return nil
}

func validOperationalRead(principal adminauth.Principal) bool {
	return principal.Allows(adminauth.InspectUsers, adminauth.AuthorizationContext{})
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func mapOperationalDatabase(operation string, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23503":
			return errOperationalNotFound
		case "23505":
			return fmt.Errorf("%w: %s", errOperationalInvalid, operation)
		case "23514", "22001", "22P02":
			return fmt.Errorf("%w: %s", errOperationalInvalid, operation)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func mapOperationalCommit(operation string, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) || errors.Is(err, pgx.ErrTxCommitRollback) {
		return mapOperationalDatabase(operation, err)
	}
	return fmt.Errorf("%w: %s", errOperationalIndeterminate, operation)
}

func rollbackOperational(tx pgx.Tx) {
	rollbackContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackContext)
}
