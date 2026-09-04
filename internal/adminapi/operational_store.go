package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
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
	maximumRequestDecisionStages = 256
)

var (
	operationalIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	operationalRuleKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	operationalFailurePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)
)

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

type requestListFilter struct {
	page operationalPage

	status        string
	feature       string
	userID        string
	platform      string
	componentKind string
	trustSource   string
	route         string
	upstream      string
	model         string
	errorCode     string
	requestID     string
	start         time.Time
	end           time.Time
	sort          string

	minimumLatencyMS *int64
	maximumLatencyMS *int64
	minimumTokens    *int64
	maximumTokens    *int64
	minimumCost      *int64
	maximumCost      *int64
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

func (filter requestListFilter) validate() error {
	if filter.page.validate(id.LogicalRequest) != nil ||
		!slices.Contains([]string{"", "succeeded", "failed", "denied", "canceled", "unknown"}, filter.status) ||
		!slices.Contains([]string{"started_at_asc", "started_at_desc"}, filter.sort) ||
		(filter.feature != "" && !operationalIdentifierPattern.MatchString(filter.feature)) ||
		(filter.userID != "" && id.Validate(filter.userID, id.ApplicationUser) != nil) ||
		(filter.platform != "" && !operationalIdentifierPattern.MatchString(filter.platform)) ||
		(filter.componentKind != "" && !operationalIdentifierPattern.MatchString(filter.componentKind)) ||
		(filter.trustSource != "" && !operationalIdentifierPattern.MatchString(filter.trustSource)) ||
		(filter.route != "" && !operationalIdentifierPattern.MatchString(filter.route)) ||
		(filter.upstream != "" && !operationalIdentifierPattern.MatchString(filter.upstream)) ||
		(filter.model != "" && !validOperationalText(filter.model, 512)) ||
		(filter.requestID != "" && id.Validate(filter.requestID, id.LogicalRequest) != nil) ||
		(!filter.start.IsZero() && !filter.end.IsZero() && !filter.start.Before(filter.end)) ||
		!validOptionalRange(filter.minimumLatencyMS, filter.maximumLatencyMS) ||
		!validOptionalRange(filter.minimumTokens, filter.maximumTokens) ||
		!validOptionalRange(filter.minimumCost, filter.maximumCost) {
		return errOperationalInvalid
	}
	if filter.errorCode != "" {
		if _, ok := problem.Registry[filter.errorCode]; !ok &&
			!slices.Contains([]string{
				"canceled", "gateway_error", "protocol_error", "timeout",
				"unavailable", "upstream_rejected", "unknown",
			}, filter.errorCode) {
			return errOperationalInvalid
		}
	}
	return nil
}

func validOptionalRange(minimum, maximum *int64) bool {
	if minimum != nil && *minimum < 0 || maximum != nil && *maximum < 0 {
		return false
	}
	return minimum == nil || maximum == nil || *minimum <= *maximum
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

type requestDecisionStageDocument struct {
	Number           int32     `json:"number"`
	Stage            string    `json:"stage"`
	Outcome          string    `json:"outcome"`
	FailureCode      *string   `json:"failure_code,omitempty"`
	ConfigRevisionID string    `json:"config_revision_id"`
	PolicyRuleKey    *string   `json:"policy_rule_key,omitempty"`
	LimitPlanKey     *string   `json:"limit_plan_key,omitempty"`
	LimitRuleKey     *string   `json:"limit_rule_key,omitempty"`
	LimitMetric      *string   `json:"limit_metric,omitempty"`
	LimitAlgorithm   *string   `json:"limit_algorithm,omitempty"`
	LimitMaximum     *int64    `json:"limit_maximum,omitempty"`
	Route            *string   `json:"route,omitempty"`
	Upstream         *string   `json:"upstream,omitempty"`
	Model            *string   `json:"model,omitempty"`
	PhysicalModel    *string   `json:"physical_model,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
	DurationMS       int64     `json:"duration_ms"`
}

type logicalRequestDocument struct {
	ID                    string                         `json:"id"`
	EnvironmentID         string                         `json:"environment_id"`
	UserID                string                         `json:"user_id"`
	InstallationID        string                         `json:"installation_id"`
	InstallationFamilyID  *string                        `json:"installation_family_id,omitempty"`
	ClientComponentID     *string                        `json:"client_component_id,omitempty"`
	ComponentDefinitionID *string                        `json:"component_definition_id,omitempty"`
	ComponentKind         *string                        `json:"component_kind,omitempty"`
	TrustSource           *string                        `json:"trust_source,omitempty"`
	Framework             *string                        `json:"framework,omitempty"`
	FrameworkVersion      *string                        `json:"framework_version,omitempty"`
	ConfigRevisionID      string                         `json:"config_revision_id"`
	SelectedLimitPlan     string                         `json:"selected_limit_plan"`
	SelectedRoute         *string                        `json:"selected_route,omitempty"`
	SelectedUpstream      *string                        `json:"selected_upstream,omitempty"`
	SelectedModel         *string                        `json:"selected_model,omitempty"`
	SelectedPhysicalModel *string                        `json:"selected_physical_model,omitempty"`
	Feature               string                         `json:"feature"`
	Protocol              string                         `json:"protocol"`
	StartedAt             time.Time                      `json:"started_at"`
	CompletedAt           *time.Time                     `json:"completed_at,omitempty"`
	Status                string                         `json:"status"`
	FailureCode           *string                        `json:"failure_code,omitempty"`
	Usage                 *usageValues                   `json:"usage,omitempty"`
	DecisionStages        []requestDecisionStageDocument `json:"decision_stages"`
	Attempts              []upstreamAttemptDocument      `json:"attempts"`
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

type auditChangeDocument struct {
	Field          string `json:"field"`
	Operation      string `json:"operation"`
	Classification string `json:"classification"`
	Redacted       bool   `json:"redacted"`
}

type auditEventDocument struct {
	ID            string                `json:"id"`
	Timestamp     time.Time             `json:"timestamp"`
	Actor         string                `json:"actor"`
	ActorKind     string                `json:"actor_kind"`
	ActorID       *string               `json:"actor_id,omitempty"`
	Action        string                `json:"action"`
	Target        string                `json:"target"`
	ResourceType  string                `json:"resource_type"`
	ResourceID    string                `json:"resource_id"`
	EnvironmentID *string               `json:"environment_id,omitempty"`
	Source        string                `json:"source"`
	Reason        *string               `json:"reason,omitempty"`
	Result        string                `json:"result"`
	RequestID     string                `json:"request_id"`
	Changes       []auditChangeDocument `json:"changes"`
	Summary       map[string]any        `json:"summary"`
}

type auditFilter struct {
	OrganizationID string
	EventID        string
	EnvironmentID  string
	ActorKind      string
	ActorID        string
	Action         string
	ResourceType   string
	ResourceID     string
	Source         string
	Reason         string
	Result         string
	Start          time.Time
	End            time.Time
}

type selfTestCheck struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	SafeDetail string `json:"safe_detail,omitempty"`
}

type selfTestDocument struct {
	ID               string          `json:"id"`
	EnvironmentID    string          `json:"environment_id"`
	ScheduleID       string          `json:"schedule_id,omitempty"`
	ConfigRevisionID string          `json:"config_revision_id,omitempty"`
	Kind             string          `json:"kind"`
	State            string          `json:"state"`
	CreatedAt        time.Time       `json:"created_at"`
	CompletedAt      *time.Time      `json:"completed_at,omitempty"`
	Checks           []selfTestCheck `json:"checks"`
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
		  AND organization.status = 'active' AND u.status <> 'deleted'
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

// lockActiveOperationalScope makes resource mutations linearizable with
// application/environment disable while preserving read-only forensic access.
func lockActiveOperationalScope(ctx context.Context, tx pgx.Tx, organizationID, applicationID, environmentID string) error {
	var marker int
	if err := tx.QueryRow(ctx, `
		/* active_operational_application_lock */
		SELECT 1
		FROM applications AS application
		JOIN organizations AS organization
		  ON organization.organization_id = application.organization_id
		WHERE application.organization_id = $1 AND application.application_id = $2
		  AND application.status = 'active' AND application.disabled_at IS NULL
		  AND organization.status = 'active' AND organization.disabled_at IS NULL
		FOR SHARE OF application
	`, organizationID, applicationID).Scan(&marker); errors.Is(err, pgx.ErrNoRows) {
		return errOperationalNotFound
	} else if err != nil {
		return fmt.Errorf("lock active operational application: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		/* active_operational_environment_lock */
		SELECT 1
		FROM environments AS environment
		WHERE environment.organization_id = $1 AND environment.application_id = $2
		  AND environment.environment_id = $3
		  AND environment.status = 'active' AND environment.disabled_at IS NULL
		FOR SHARE
	`, organizationID, applicationID, environmentID).Scan(&marker); errors.Is(err, pgx.ErrNoRows) {
		return errOperationalNotFound
	} else if err != nil {
		return fmt.Errorf("lock active operational environment: %w", err)
	}
	return nil
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
		  AND organization.status = 'active'
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
	confirmation confirmedUserOperationRequest,
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
		FOR SHARE OF application, e
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
	impactAction := userOperationUnblock
	if blocked {
		impactAction = userOperationBlock
	}
	counts, err := loadUserOperationCounts(
		ctx, tx, principal.OrganizationID, applicationID, userID,
	)
	if err != nil {
		return useroverride.ApplicationUser{}, err
	}
	impact := describeUserOperation(
		impactAction, storedStatus, counts,
		principal.OrganizationID, environmentID, userID,
	)
	if !impact.Applicable || impact.ImpactToken != confirmation.ImpactToken {
		return useroverride.ApplicationUser{}, errOperationalConflict
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
	reason, err := adminauth.NewPublicAuditChange("reason_provided", adminauth.AuditSet)
	if err != nil {
		return useroverride.ApplicationUser{}, err
	}
	changes = append(changes, reason)
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
		  AND organization.status = 'active'
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
		  AND organization.status = 'active'
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
	if err := lockActiveOperationalScope(ctx, tx, principal.OrganizationID, applicationID, environmentID); err != nil {
		return installationDocument{}, err
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
	filter requestListFilter,
) ([]logicalRequestDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || filter.validate() != nil {
		return nil, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	arguments := []any{principal.OrganizationID, environmentID}
	where := []string{
		"request.organization_id = $1",
		"request.environment_id = $2",
	}
	add := func(template string, value any) {
		arguments = append(arguments, value)
		where = append(where, strings.ReplaceAll(template, "%d", fmt.Sprint(len(arguments))))
	}
	if filter.status != "" {
		stored := filter.status
		switch stored {
		case "canceled":
			stored = "cancelled"
		case "unknown":
			where = append(where, "request.status IN ('authenticated', 'reserved', 'dispatched', 'streaming')")
			stored = ""
		}
		if stored != "" {
			add("request.status = $%d", stored)
		}
	}
	if filter.feature != "" {
		add("request.feature_key = $%d", filter.feature)
	}
	if filter.userID != "" {
		add("request.application_user_id = $%d", filter.userID)
	}
	if filter.platform != "" {
		add(`EXISTS (
			SELECT 1 FROM installations AS installation
			WHERE installation.organization_id = request.organization_id
			  AND installation.application_id = request.application_id
			  AND installation.environment_id = request.environment_id
			  AND installation.installation_id = request.installation_id
			  AND installation.platform = $%d
		)`, filter.platform)
	}
	if filter.componentKind != "" {
		add("request.component_kind = $%d", filter.componentKind)
	}
	if filter.trustSource != "" {
		add("request.trust_source = $%d", filter.trustSource)
	}
	if filter.route != "" {
		add(`(request.selected_route_key = $%d OR EXISTS (
			SELECT 1 FROM upstream_attempts AS attempt
			WHERE attempt.logical_request_id = request.logical_request_id
			  AND attempt.route_key = $%d
		))`, filter.route)
	}
	if filter.upstream != "" {
		add(`(request.selected_upstream_key = $%d OR EXISTS (
			SELECT 1 FROM upstream_attempts AS attempt
			WHERE attempt.logical_request_id = request.logical_request_id
			  AND attempt.upstream_key = $%d
		))`, filter.upstream)
	}
	if filter.model != "" {
		add(`(request.selected_model_key = $%d OR request.selected_physical_model = $%d
			OR EXISTS (
				SELECT 1 FROM upstream_attempts AS attempt
				WHERE attempt.logical_request_id = request.logical_request_id
				  AND (attempt.model_key = $%d OR attempt.physical_model = $%d)
			))`, filter.model)
	}
	if filter.errorCode != "" {
		knownCodes := registeredProblemCodes()
		arguments = append(arguments, filter.errorCode)
		codeArgument := len(arguments)
		arguments = append(arguments, knownCodes)
		knownArgument := len(arguments)
		where = append(where, fmt.Sprintf(`(
			CASE
				WHEN request.failure_code IS NULL THEN NULL
				WHEN request.failure_code IN ('client_cancelled', 'request_cancelled') THEN 'canceled'
				WHEN request.failure_code = ANY($%d::text[]) THEN request.failure_code
				ELSE 'unknown'
			END = $%d
			OR EXISTS (
				SELECT 1 FROM logical_request_decision_stages AS stage
				WHERE stage.logical_request_id = request.logical_request_id
				  AND CASE
				      WHEN stage.failure_code IS NULL THEN NULL
				      WHEN stage.failure_code IN ('client_cancelled', 'request_cancelled') THEN 'canceled'
				      WHEN stage.failure_code = ANY($%d::text[]) THEN stage.failure_code
				      ELSE 'unknown'
				  END = $%d
			)
			OR EXISTS (
				SELECT 1 FROM upstream_attempts AS attempt
				WHERE attempt.logical_request_id = request.logical_request_id
				  AND %s = $%d
			)
		)`, knownArgument, codeArgument, knownArgument, codeArgument,
			publicAttemptFailureSQL("attempt.failure_code"), codeArgument))
	}
	if filter.requestID != "" {
		add("request.logical_request_id = $%d", filter.requestID)
	}
	if !filter.start.IsZero() {
		add("request.requested_at >= $%d", filter.start)
	}
	if !filter.end.IsZero() {
		add("request.requested_at < $%d", filter.end)
	}
	if filter.minimumLatencyMS != nil {
		add("request.completed_at IS NOT NULL AND extract(epoch FROM (request.completed_at - request.requested_at)) * 1000 >= $%d", *filter.minimumLatencyMS)
	}
	if filter.maximumLatencyMS != nil {
		add("request.completed_at IS NOT NULL AND extract(epoch FROM (request.completed_at - request.requested_at)) * 1000 <= $%d", *filter.maximumLatencyMS)
	}
	if filter.minimumTokens != nil {
		add(`COALESCE((
			SELECT sum(usage.units) FROM usage_records AS usage
			WHERE usage.logical_request_id = request.logical_request_id
			  AND usage.metric = 'total_tokens'
		), 0) >= $%d`, *filter.minimumTokens)
	}
	if filter.maximumTokens != nil {
		add(`COALESCE((
			SELECT sum(usage.units) FROM usage_records AS usage
			WHERE usage.logical_request_id = request.logical_request_id
			  AND usage.metric = 'total_tokens'
		), 0) <= $%d`, *filter.maximumTokens)
	}
	if filter.minimumCost != nil {
		add(`COALESCE((
			SELECT sum(usage.units) FROM usage_records AS usage
			WHERE usage.logical_request_id = request.logical_request_id
			  AND usage.metric = 'cost_nano_usd'
		), 0) >= $%d`, *filter.minimumCost)
	}
	if filter.maximumCost != nil {
		add(`COALESCE((
			SELECT sum(usage.units) FROM usage_records AS usage
			WHERE usage.logical_request_id = request.logical_request_id
			  AND usage.metric = 'cost_nano_usd'
		), 0) <= $%d`, *filter.maximumCost)
	}
	descending := filter.sort == "started_at_desc"
	if !filter.page.after.IsZero() {
		arguments = append(arguments, filter.page.after, filter.page.afterID)
		operator := ">"
		if descending {
			operator = "<"
		}
		where = append(where, fmt.Sprintf(
			"(request.requested_at, request.logical_request_id) %s ($%d, $%d)",
			operator, len(arguments)-1, len(arguments),
		))
	}
	arguments = append(arguments, filter.page.size+1)
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	query := fmt.Sprintf(`
		SELECT logical_request_id, environment_id, application_user_id, installation_id,
		       installation_family_id, client_component_id, component_definition_id,
		       component_kind, trust_source, framework, framework_version,
		       config_revision_id, selected_limit_plan_key,
		       selected_route_key, selected_upstream_key, selected_model_key,
		       selected_physical_model, feature_key, protocol, requested_at,
		       completed_at, status, failure_code
		FROM logical_requests AS request
		WHERE %s
		ORDER BY request.requested_at %s, request.logical_request_id %s
		LIMIT $%d
	`, strings.Join(where, " AND "), direction, direction, len(arguments))
	rows, err := store.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list logical requests: %w", err)
	}
	defer rows.Close()
	items := make([]logicalRequestDocument, 0, filter.page.size+1)
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
		       config_revision_id, selected_limit_plan_key,
		       selected_route_key, selected_upstream_key, selected_model_key,
		       selected_physical_model, feature_key, protocol, requested_at,
		       completed_at, status, failure_code
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
	var failureCode *string
	if err := row.Scan(
		&item.ID, &item.EnvironmentID, &item.UserID, &item.InstallationID,
		&item.InstallationFamilyID, &item.ClientComponentID,
		&item.ComponentDefinitionID, &item.ComponentKind, &item.TrustSource,
		&item.Framework, &item.FrameworkVersion,
		&item.ConfigRevisionID, &item.SelectedLimitPlan,
		&item.SelectedRoute, &item.SelectedUpstream, &item.SelectedModel,
		&item.SelectedPhysicalModel,
		&item.Feature, &item.Protocol, &item.StartedAt, &item.CompletedAt, &status,
		&failureCode,
	); err != nil {
		return logicalRequestDocument{}, err
	}
	if !validRequestAttribution(item) {
		return logicalRequestDocument{}, errOperationalCorrupt
	}
	item.Status = publicLogicalRequestStatus(status)
	item.FailureCode = publicLogicalFailureCode(failureCode)
	item.DecisionStages = make([]requestDecisionStageDocument, 0)
	return item, nil
}

func validRequestAttribution(item logicalRequestDocument) bool {
	if id.Validate(item.ConfigRevisionID, id.ConfigRevision) != nil ||
		!operationalIdentifierPattern.MatchString(item.SelectedLimitPlan) {
		return false
	}
	selectedRouteValues := []bool{
		item.SelectedRoute != nil,
		item.SelectedUpstream != nil,
		item.SelectedModel != nil,
		item.SelectedPhysicalModel != nil,
	}
	for _, present := range selectedRouteValues[1:] {
		if present != selectedRouteValues[0] {
			return false
		}
	}
	if item.SelectedRoute != nil &&
		(!operationalIdentifierPattern.MatchString(*item.SelectedRoute) ||
			!operationalIdentifierPattern.MatchString(*item.SelectedUpstream) ||
			!operationalIdentifierPattern.MatchString(*item.SelectedModel) ||
			!validOperationalText(*item.SelectedPhysicalModel, 512)) {
		return false
	}
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
	return validOperationalText(value, 128)
}

func validOperationalText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) == -1
}

func publicLogicalRequestStatus(status string) string {
	switch status {
	case "succeeded":
		return "succeeded"
	case "failed":
		return "failed"
	case "denied":
		return "denied"
	case "cancelled":
		return "canceled"
	case "reserved", "dispatched", "streaming":
		return "unknown"
	default:
		return "unknown"
	}
}

func registeredProblemCodes() []string {
	result := make([]string, 0, len(problem.Registry))
	for code := range problem.Registry {
		result = append(result, code)
	}
	sort.Strings(result)
	return result
}

func publicLogicalFailureCode(code *string) *string {
	if code == nil {
		return nil
	}
	if *code == "client_cancelled" || *code == "request_cancelled" {
		value := "canceled"
		return &value
	}
	if _, ok := problem.Registry[*code]; ok {
		value := *code
		return &value
	}
	value := "unknown"
	return &value
}

func publicDecisionFailureCode(code *string) *string {
	return publicLogicalFailureCode(code)
}

func publicAttemptFailureSQL(column string) string {
	return `CASE
		WHEN ` + column + ` IS NULL THEN NULL
		WHEN ` + column + ` IN ('client_cancelled', 'request_cancelled') THEN 'canceled'
		WHEN ` + column + ` IN ('pricing_unavailable', 'quota_state_unavailable', 'configuration_invalid') THEN 'gateway_error'
		WHEN ` + column + ` = 'upstream_protocol_error' THEN 'protocol_error'
		WHEN ` + column + ` IN ('upstream_timeout', 'upstream_timed_out') THEN 'timeout'
		WHEN ` + column + ` = 'upstream_unavailable' THEN 'unavailable'
		WHEN ` + column + ` = 'upstream_non_success' THEN 'upstream_rejected'
		ELSE 'unknown'
	END`
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

func validateRequestDecisionStage(
	stage requestDecisionStageDocument,
	storedFailureCode *string,
	request logicalRequestDocument,
	expectedNumber int32,
) error {
	if stage.Number != expectedNumber || stage.Number < 1 || stage.Number > maximumRequestDecisionStages ||
		!slices.Contains([]string{
			"identity_verified", "client_trust_verified", "client_context_validated",
			"configuration_loaded", "request_inspected", "policy_evaluated",
			"route_selected", "quota_rule_evaluated", "quota_reserved",
			"lifecycle_recovered",
		}, stage.Stage) ||
		!slices.Contains([]string{"succeeded", "denied", "failed", "cancelled"}, stage.Outcome) ||
		stage.StartedAt.IsZero() || stage.CompletedAt.Before(stage.StartedAt) ||
		stage.ConfigRevisionID != request.ConfigRevisionID ||
		(stage.Outcome == "succeeded") != (storedFailureCode == nil) {
		return errOperationalCorrupt
	}
	if storedFailureCode != nil && !operationalFailurePattern.MatchString(*storedFailureCode) {
		return errOperationalCorrupt
	}
	if stage.PolicyRuleKey != nil &&
		!operationalIdentifierPattern.MatchString(*stage.PolicyRuleKey) &&
		!operationalRuleKeyPattern.MatchString(*stage.PolicyRuleKey) {
		return errOperationalCorrupt
	}
	if stage.PolicyRuleKey != nil && stage.Stage != "policy_evaluated" {
		return errOperationalCorrupt
	}
	if stage.LimitPlanKey != nil &&
		(!operationalIdentifierPattern.MatchString(*stage.LimitPlanKey) ||
			*stage.LimitPlanKey != request.SelectedLimitPlan ||
			!slices.Contains([]string{
				"policy_evaluated", "route_selected", "quota_rule_evaluated", "quota_reserved",
			}, stage.Stage)) {
		return errOperationalCorrupt
	}
	limitValues := []bool{
		stage.LimitRuleKey != nil, stage.LimitMetric != nil,
		stage.LimitAlgorithm != nil, stage.LimitMaximum != nil,
	}
	for _, present := range limitValues[1:] {
		if present != limitValues[0] {
			return errOperationalCorrupt
		}
	}
	if stage.LimitRuleKey != nil &&
		(!operationalRuleKeyPattern.MatchString(*stage.LimitRuleKey) ||
			!operationalFailurePattern.MatchString(*stage.LimitMetric) ||
			!slices.Contains([]string{"calendar", "token_bucket", "per_request", "concurrency"}, *stage.LimitAlgorithm) ||
			*stage.LimitMaximum < 0 || stage.Stage != "quota_rule_evaluated") {
		return errOperationalCorrupt
	}
	routeValues := []bool{
		stage.Route != nil, stage.Upstream != nil, stage.Model != nil, stage.PhysicalModel != nil,
	}
	for _, present := range routeValues[1:] {
		if present != routeValues[0] {
			return errOperationalCorrupt
		}
	}
	if stage.Route != nil &&
		(!operationalIdentifierPattern.MatchString(*stage.Route) ||
			!operationalIdentifierPattern.MatchString(*stage.Upstream) ||
			!operationalIdentifierPattern.MatchString(*stage.Model) ||
			!validOperationalText(*stage.PhysicalModel, 512) ||
			request.SelectedRoute == nil || *stage.Route != *request.SelectedRoute ||
			*stage.Upstream != *request.SelectedUpstream || *stage.Model != *request.SelectedModel ||
			*stage.PhysicalModel != *request.SelectedPhysicalModel ||
			!slices.Contains([]string{"route_selected", "quota_reserved"}, stage.Stage)) {
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
	stageRows, err := store.pool.Query(ctx, `
		SELECT logical_request_id, stage_number, stage, outcome, failure_code,
		       config_revision_id, policy_rule_key, limit_plan_key, limit_rule_key,
		       limit_metric, limit_algorithm, limit_maximum, route_key, upstream_key,
		       model_key, physical_model, started_at, completed_at
		FROM logical_request_decision_stages
		WHERE organization_id = $1 AND logical_request_id = ANY($2::text[])
		ORDER BY logical_request_id, stage_number
	`, organizationID, requestIDs)
	if err != nil {
		return fmt.Errorf("list request decision stages: %w", err)
	}
	terminalStages := make(map[string]bool, len(items))
	for stageRows.Next() {
		var requestID string
		var storedFailureCode *string
		var stage requestDecisionStageDocument
		if err := stageRows.Scan(
			&requestID, &stage.Number, &stage.Stage, &stage.Outcome, &storedFailureCode,
			&stage.ConfigRevisionID, &stage.PolicyRuleKey, &stage.LimitPlanKey,
			&stage.LimitRuleKey, &stage.LimitMetric, &stage.LimitAlgorithm,
			&stage.LimitMaximum, &stage.Route, &stage.Upstream, &stage.Model,
			&stage.PhysicalModel, &stage.StartedAt, &stage.CompletedAt,
		); err != nil {
			stageRows.Close()
			return fmt.Errorf("scan request decision stage: %w", err)
		}
		requestIndex, ok := requestIndexes[requestID]
		if !ok || terminalStages[requestID] || validateRequestDecisionStage(
			stage, storedFailureCode, items[requestIndex], int32(len(items[requestIndex].DecisionStages)+1),
		) != nil {
			stageRows.Close()
			return errOperationalCorrupt
		}
		stage.FailureCode = publicDecisionFailureCode(storedFailureCode)
		stage.DurationMS = stage.CompletedAt.Sub(stage.StartedAt).Milliseconds()
		items[requestIndex].DecisionStages = append(items[requestIndex].DecisionStages, stage)
		terminalStages[requestID] = stage.Outcome != "succeeded"
	}
	if err := stageRows.Err(); err != nil {
		stageRows.Close()
		return fmt.Errorf("iterate request decision stages: %w", err)
	}
	stageRows.Close()
	for index := range items {
		if len(items[index].DecisionStages) == 0 {
			continue
		}
		last := items[index].DecisionStages[len(items[index].DecisionStages)-1]
		if last.Outcome == "succeeded" {
			continue
		}
		expectedStatus := last.Outcome
		if expectedStatus == "cancelled" {
			expectedStatus = "canceled"
		}
		if items[index].Status != expectedStatus ||
			(items[index].FailureCode == nil) != (last.FailureCode == nil) ||
			(items[index].FailureCode != nil && *items[index].FailureCode != *last.FailureCode) {
			return errOperationalCorrupt
		}
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
		      AND organization.status = 'active'
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
	filter auditFilter,
	page operationalPage,
) ([]auditEventDocument, error) {
	if filter.OrganizationID == "" {
		filter.OrganizationID = principal.OrganizationID
	}
	if validateAuditFilter(filter) != nil || page.validate(id.AuditEvent) != nil {
		return nil, errOperationalInvalid
	}
	if filter.OrganizationID != principal.OrganizationID || !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, `
		SELECT event.audit_event_id, event.occurred_at,
		       event.actor_kind, event.actor_id, event.action,
		       event.resource_type, event.resource_id, event.environment_id,
		       event.source, event.reason, event.outcome, event.request_id,
		       COALESCE((
		           SELECT jsonb_agg(
		               jsonb_build_object(
		                   'field', change.field_name,
		                   'operation', change.operation,
		                   'classification', change.classification,
		                   'redacted', change.classification = 'sensitive'
		               ) ORDER BY change.ordinal
		           )
		           FROM audit_event_changes AS change
		           WHERE change.audit_event_id = event.audit_event_id
		       ), '[]'::jsonb) AS changes
		FROM audit_events AS event
		WHERE event.organization_id = $1
		  AND ($2::text IS NULL OR event.audit_event_id = $2)
		  AND ($3::text IS NULL OR event.environment_id = $3)
		  AND ($4::text IS NULL OR event.actor_kind = $4)
		  AND ($5::text IS NULL OR event.actor_id = $5)
		  AND ($6::text IS NULL OR event.action = $6)
		  AND ($7::text IS NULL OR event.resource_type = $7)
		  AND ($8::text IS NULL OR event.resource_id = $8)
		  AND ($9::text IS NULL OR event.source = $9)
		  AND ($10::text IS NULL OR event.reason = $10)
		  AND ($11::text IS NULL OR event.outcome = $11)
		  AND ($12::timestamptz IS NULL OR event.occurred_at >= $12)
		  AND ($13::timestamptz IS NULL OR event.occurred_at < $13)
		  AND ($14::timestamptz IS NULL OR (event.occurred_at, event.audit_event_id) < ($14, $15))
		ORDER BY event.occurred_at DESC, event.audit_event_id DESC
		LIMIT $16
	`, filter.OrganizationID, nullableString(filter.EventID), nullableString(filter.EnvironmentID), nullableString(filter.ActorKind),
		nullableString(filter.ActorID), nullableString(filter.Action), nullableString(filter.ResourceType),
		nullableString(filter.ResourceID), nullableString(filter.Source), nullableString(filter.Reason),
		nullableString(filter.Result), nullableTime(filter.Start), nullableTime(filter.End),
		nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	items := make([]auditEventDocument, 0, page.size+1)
	for rows.Next() {
		var item auditEventDocument
		var requestID *string
		var changesJSON []byte
		if err := rows.Scan(
			&item.ID, &item.Timestamp, &item.ActorKind, &item.ActorID, &item.Action,
			&item.ResourceType, &item.ResourceID, &item.EnvironmentID, &item.Source,
			&item.Reason, &item.Result, &requestID, &changesJSON,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		item.Target = item.ResourceType + ":" + item.ResourceID
		item.Actor = item.ActorKind
		if item.ActorID != nil {
			item.Actor += ":" + *item.ActorID
		}
		if requestID != nil {
			item.RequestID = *requestID
		}
		if len(changesJSON) > 64<<10 || json.Unmarshal(changesJSON, &item.Changes) != nil || len(item.Changes) > 100 || !validAuditEventDocument(item) {
			return nil, errOperationalCorrupt
		}
		item.Summary = map[string]any{"changes": item.Changes}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return items, nil
}

func (store *operationalStore) getAuditEvent(
	ctx context.Context,
	principal adminauth.Principal,
	auditEventID string,
) (auditEventDocument, error) {
	if id.Validate(auditEventID, id.AuditEvent) != nil {
		return auditEventDocument{}, errOperationalInvalid
	}
	items, err := store.listAuditEvents(ctx, principal, auditFilter{
		OrganizationID: principal.OrganizationID, EventID: auditEventID,
	}, operationalPage{size: 1})
	if err != nil {
		return auditEventDocument{}, err
	}
	if len(items) == 1 && items[0].ID == auditEventID {
		return items[0], nil
	}
	return auditEventDocument{}, errOperationalNotFound
}

func validateAuditFilter(filter auditFilter) error {
	if id.Validate(filter.OrganizationID, id.Organization) != nil {
		return errOperationalInvalid
	}
	if filter.EventID != "" && id.Validate(filter.EventID, id.AuditEvent) != nil {
		return errOperationalInvalid
	}
	if filter.EnvironmentID != "" && id.Validate(filter.EnvironmentID, id.Environment) != nil {
		return errOperationalInvalid
	}
	if filter.ActorID != "" {
		parsed, err := id.Parse(filter.ActorID)
		if err != nil || (parsed.Prefix != id.AdminUser && parsed.Prefix != id.AdminAPIToken) {
			return errOperationalInvalid
		}
	}
	switch filter.ActorKind {
	case "", "admin_user", "admin_api_token", "system":
	default:
		return errOperationalInvalid
	}
	if (filter.Action != "" && !operationalAuditName(filter.Action, 100)) ||
		(filter.ResourceType != "" && !operationalAuditName(filter.ResourceType, 64)) {
		return errOperationalInvalid
	}
	if filter.ResourceID != "" {
		parsed, err := id.Parse(filter.ResourceID)
		if err != nil || parsed.Prefix == "" {
			return errOperationalInvalid
		}
	}
	switch filter.Source {
	case "", "console", "cli", "api", "system":
	default:
		return errOperationalInvalid
	}
	if adminauth.ValidateAuditReason(filter.Reason) != nil {
		return errOperationalInvalid
	}
	switch filter.Result {
	case "", "succeeded", "denied", "failed", "indeterminate":
	default:
		return errOperationalInvalid
	}
	if !filter.Start.IsZero() && !filter.End.IsZero() && !filter.Start.Before(filter.End) {
		return errOperationalInvalid
	}
	return nil
}

func operationalAuditName(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '.' {
			return false
		}
		if index == 0 && character >= '0' && character <= '9' {
			return false
		}
	}
	return true
}

func validAuditEventDocument(item auditEventDocument) bool {
	if id.Validate(item.ID, id.AuditEvent) != nil || item.Timestamp.IsZero() ||
		!operationalAuditName(item.Action, 100) || !operationalAuditName(item.ResourceType, 64) {
		return false
	}
	if parsed, err := id.Parse(item.ResourceID); err != nil || parsed.Prefix == "" {
		return false
	}
	if item.EnvironmentID != nil && id.Validate(*item.EnvironmentID, id.Environment) != nil {
		return false
	}
	switch item.ActorKind {
	case "system":
		if item.ActorID != nil || item.Source != "system" {
			return false
		}
	case "admin_user":
		if item.ActorID == nil || id.Validate(*item.ActorID, id.AdminUser) != nil ||
			item.Source == "system" || item.Source == "cli" {
			return false
		}
	case "admin_api_token":
		if item.ActorID == nil || id.Validate(*item.ActorID, id.AdminAPIToken) != nil ||
			item.Source == "system" || item.Source == "console" {
			return false
		}
	default:
		return false
	}
	switch item.Source {
	case "console", "cli", "api", "system":
	default:
		return false
	}
	if item.Reason != nil && adminauth.ValidateAuditReason(*item.Reason) != nil {
		return false
	}
	switch item.Result {
	case "succeeded", "denied", "failed", "indeterminate":
	default:
		return false
	}
	if item.RequestID != "" && id.Validate(item.RequestID, id.AdminRequest) != nil {
		return false
	}
	for _, change := range item.Changes {
		if !operationalAuditName(change.Field, 64) ||
			(change.Classification != "public" && change.Classification != "sensitive") ||
			!validAuditChangeOperation(change.Operation) ||
			(change.Redacted != (change.Classification == "sensitive")) {
			return false
		}
	}
	return true
}

func validAuditChangeOperation(operation string) bool {
	switch operation {
	case "set", "clear", "add", "remove", "rotate", "consume", "revoke":
		return true
	default:
		return false
	}
}

type startSelfTestInput struct {
	Kind             string
	Environment      string
	ConfigRevisionID string
	Upstream         string
	Model            string
	MaxCost          int64
	RequestID        string
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
		if input.ConfigRevisionID != "" || input.Upstream != "" || input.Model != "" || input.MaxCost != 0 {
			return selfTestDocument{}, errOperationalInvalid
		}
	case "upstream", "openrouter":
		if store.selfTests == nil || id.Validate(input.ConfigRevisionID, id.ConfigRevision) != nil ||
			!selfTestIdentifierPattern.MatchString(input.Upstream) ||
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
		FOR SHARE OF environment, application
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
		ID: selfTestID, EnvironmentID: input.Environment,
		Kind: "local", State: state, CreatedAt: now.UTC(),
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
	environmentID string,
	selfTestID string,
) (selfTestDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || id.Validate(selfTestID, id.Prefix("tst")) != nil {
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
		  AND environment_id = $2 AND payload->>'id' = $3
	`, principal.OrganizationID, environmentID, selfTestID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestDocument{}, errOperationalNotFound
	}
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("read self-test: %w", err)
	}
	var run selfTestDocument
	if len(payload) == 0 || len(payload) > 64<<10 || json.Unmarshal(payload, &run) != nil ||
		run.ID != selfTestID || run.EnvironmentID != environmentID || !validStoredSelfTest(run) {
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
