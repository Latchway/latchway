package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/useroverride"
)

var errOperationalConflict = errors.New("operational Admin API state changed")

const (
	userOperationBlock                   = "block"
	userOperationUnblock                 = "unblock"
	userOperationRequireReauthentication = "require_reauthentication"
	userOperationRequireReverification   = "require_app_reverification"
)

type userOperationCounts struct {
	ActiveSessionGrants          int64 `json:"active_session_grants"`
	ActiveRefreshTokens          int64 `json:"active_refresh_tokens"`
	ActiveComponentSessions      int64 `json:"active_component_sessions"`
	ActiveComponentRefreshTokens int64 `json:"active_component_refresh_tokens"`
	ActiveInstallationFamilies   int64 `json:"active_installation_families"`
	ActiveClientComponents       int64 `json:"active_client_components"`
}

type userOperationImpact struct {
	Action        string              `json:"action"`
	Immediate     bool                `json:"immediate"`
	Reversible    bool                `json:"reversible"`
	Applicable    bool                `json:"applicable"`
	CurrentStatus string              `json:"current_status"`
	AccessEffect  string              `json:"access_effect"`
	Summary       string              `json:"summary"`
	Counts        userOperationCounts `json:"counts"`
	ImpactToken   string              `json:"impact_token"`
}

type confirmedUserOperationRequest struct {
	Reason                     string `json:"reason"`
	ImpactToken                string `json:"impact_token"`
	AcknowledgeImmediateEffect bool   `json:"acknowledge_immediate_effect"`
}

type userOperationResult struct {
	OperationID string                       `json:"operation_id"`
	Impact      userOperationImpact          `json:"impact"`
	User        useroverride.ApplicationUser `json:"user"`
}

func (api *API) userOperationImpact(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "action") {
		api.writeProblem(w, r, invalidRequest("The user-operation impact query is invalid."))
		return
	}
	environmentID, environmentOK := requiredQueryValue(r, "environment_id")
	action, actionOK := requiredQueryValue(r, "action")
	if !environmentOK || !actionOK || !validUserOperation(action) {
		api.writeProblem(w, r, invalidRequest("The user-operation impact query is invalid."))
		return
	}
	impact, err := api.operations.previewUserOperation(
		r.Context(), mustPrincipal(r.Context()), environmentID,
		chi.URLParam(r, "userID"), action,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, impact)
}

func (api *API) requireUserReauthentication(w http.ResponseWriter, r *http.Request) {
	api.confirmedUserOperation(w, r, userOperationRequireReauthentication)
}

func (api *API) requireUserAppReverification(w http.ResponseWriter, r *http.Request) {
	api.confirmedUserOperation(w, r, userOperationRequireReverification)
}

func (api *API) confirmedUserOperation(w http.ResponseWriter, r *http.Request, action string) {
	if !onlyQueryKeys(r, "environment_id") {
		api.writeProblem(w, r, invalidRequest("The user-operation query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	request, ok := decodeConfirmedUserOperation(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The confirmed user operation is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	result, err := api.operations.performConfirmedUserOperation(
		r.Context(), mustPrincipal(r.Context()), environmentID,
		chi.URLParam(r, "userID"), action, request, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeConfirmedUserOperation(r *http.Request) (confirmedUserOperationRequest, bool) {
	request, err := decodeJSON[confirmedUserOperationRequest](r)
	if err != nil {
		return confirmedUserOperationRequest{}, false
	}
	request.Reason = strings.TrimSpace(request.Reason)
	return request, request.AcknowledgeImmediateEffect &&
		utf8.ValidString(request.Reason) && !strings.ContainsRune(request.Reason, '\x00') &&
		utf8.RuneCountInString(request.Reason) >= 1 && utf8.RuneCountInString(request.Reason) <= 500 &&
		len(request.ImpactToken) == 43 && operationalTokenPattern(request.ImpactToken)
}

func operationalTokenPattern(value string) bool {
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validUserOperation(action string) bool {
	switch action {
	case userOperationBlock, userOperationUnblock,
		userOperationRequireReauthentication, userOperationRequireReverification:
		return true
	default:
		return false
	}
}

func (store *operationalStore) previewUserOperation(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	userID string,
	action string,
) (userOperationImpact, error) {
	if id.Validate(environmentID, id.Environment) != nil ||
		id.Validate(userID, id.ApplicationUser) != nil || !validUserOperation(action) {
		return userOperationImpact{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return userOperationImpact{}, errOperationalForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return userOperationImpact{}, fmt.Errorf("begin user-operation impact: %w", err)
	}
	defer rollbackOperational(tx)
	applicationID, status, err := userOperationTarget(ctx, tx, principal.OrganizationID, environmentID, userID, false)
	if err != nil {
		return userOperationImpact{}, err
	}
	counts, err := loadUserOperationCounts(ctx, tx, principal.OrganizationID, applicationID, userID)
	if err != nil {
		return userOperationImpact{}, err
	}
	impact := describeUserOperation(action, status, counts, principal.OrganizationID, environmentID, userID)
	if err := tx.Commit(ctx); err != nil {
		return userOperationImpact{}, fmt.Errorf("commit user-operation impact: %w", err)
	}
	return impact, nil
}

func (store *operationalStore) performConfirmedUserOperation(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	userID string,
	action string,
	request confirmedUserOperationRequest,
	operationID string,
) (userOperationResult, error) {
	if id.Validate(environmentID, id.Environment) != nil || id.Validate(userID, id.ApplicationUser) != nil ||
		id.Validate(operationID, id.AdminRequest) != nil || !validUserOperation(action) {
		return userOperationResult{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return userOperationResult{}, errOperationalForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return userOperationResult{}, fmt.Errorf("begin confirmed user operation: %w", err)
	}
	defer rollbackOperational(tx)
	applicationID, status, err := userOperationTarget(ctx, tx, principal.OrganizationID, environmentID, userID, true)
	if err != nil {
		return userOperationResult{}, err
	}
	counts, err := loadUserOperationCounts(ctx, tx, principal.OrganizationID, applicationID, userID)
	if err != nil {
		return userOperationResult{}, err
	}
	impact := describeUserOperation(action, status, counts, principal.OrganizationID, environmentID, userID)
	if !impact.Applicable || impact.ImpactToken != request.ImpactToken {
		return userOperationResult{}, errOperationalConflict
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return userOperationResult{}, fmt.Errorf("read confirmed user-operation time: %w", err)
	}
	changes, err := confirmedUserOperationChanges(action)
	if err != nil {
		return userOperationResult{}, err
	}
	switch action {
	case userOperationRequireReauthentication:
		if err := requireReauthentication(ctx, tx, principal.OrganizationID, applicationID, userID, now); err != nil {
			return userOperationResult{}, err
		}
	case userOperationRequireReverification:
		if err := requireAppReverification(ctx, tx, principal.OrganizationID, applicationID, userID, now); err != nil {
			return userOperationResult{}, err
		}
	default:
		return userOperationResult{}, errOperationalInvalid
	}
	if err := store.audit(
		ctx, tx, principal, environmentID, "admin.user_"+action,
		"application_user", userID, operationID, now, changes,
	); err != nil {
		return userOperationResult{}, err
	}
	user, err := queryApplicationUser(ctx, tx, principal.OrganizationID, environmentID, userID)
	if err != nil {
		return userOperationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return userOperationResult{}, mapOperationalCommit("commit confirmed user operation", err)
	}
	return userOperationResult{OperationID: operationID, Impact: impact, User: user}, nil
}

func userOperationTarget(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	organizationID, environmentID, userID string,
	forUpdate bool,
) (string, string, error) {
	lock := ""
	if forUpdate {
		lock = " FOR UPDATE OF users"
	}
	var applicationID, status string
	err := queryer.QueryRow(ctx, `
		SELECT environment.application_id, users.status
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		JOIN application_users AS users
		  ON users.organization_id = environment.organization_id
		 AND users.application_id = environment.application_id
		WHERE environment.organization_id = $1 AND environment.environment_id = $2
		  AND users.application_user_id = $3 AND users.status <> 'deleted'
		  AND environment.status = 'active' AND application.status = 'active'
		  AND organization.status = 'active'
	`+lock, organizationID, environmentID, userID).Scan(&applicationID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", errOperationalNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("load user-operation target: %w", err)
	}
	if status != "active" && status != "blocked" {
		return "", "", errOperationalCorrupt
	}
	return applicationID, status, nil
}

func loadUserOperationCounts(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	organizationID, applicationID, userID string,
) (userOperationCounts, error) {
	var result userOperationCounts
	err := queryer.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM session_grants
		   WHERE organization_id = $1 AND application_id = $2
		     AND application_user_id = $3 AND revoked_at IS NULL
		     AND expires_at > transaction_timestamp()),
		  (SELECT count(*) FROM refresh_tokens
		   WHERE organization_id = $1 AND application_id = $2
		     AND application_user_id = $3 AND status IN ('staged', 'active')
		     AND expires_at > transaction_timestamp()),
		  (SELECT count(*) FROM component_session_families
		   WHERE organization_id = $1 AND application_id = $2
		     AND application_user_id = $3 AND status = 'active'),
		  (SELECT count(*) FROM component_refresh_tokens AS token
		   JOIN client_components AS component ON component.client_component_id = token.client_component_id
		   WHERE component.organization_id = $1 AND component.application_id = $2
		     AND component.application_user_id = $3
		     AND token.status IN ('staged', 'active')
		     AND token.expires_at > transaction_timestamp()),
		  (SELECT count(*) FROM installation_families
		   WHERE organization_id = $1 AND application_id = $2
		     AND application_user_id = $3 AND status = 'active'),
		  (SELECT count(*) FROM client_components
		   WHERE organization_id = $1 AND application_id = $2
		     AND application_user_id = $3 AND status = 'active')
	`, organizationID, applicationID, userID).Scan(
		&result.ActiveSessionGrants, &result.ActiveRefreshTokens,
		&result.ActiveComponentSessions, &result.ActiveComponentRefreshTokens,
		&result.ActiveInstallationFamilies, &result.ActiveClientComponents,
	)
	if err != nil {
		return userOperationCounts{}, fmt.Errorf("load user-operation impact: %w", err)
	}
	return result, nil
}

func describeUserOperation(
	action, status string,
	counts userOperationCounts,
	organizationID, environmentID, userID string,
) userOperationImpact {
	impact := userOperationImpact{
		Action: action, Immediate: true, CurrentStatus: status, Counts: counts,
	}
	switch action {
	case userOperationBlock:
		impact.Applicable = status == "active"
		impact.AccessEffect = "existing_sessions_revoked_and_future_sessions_denied"
		impact.Summary = "Block the user across the application immediately and revoke every active user and component session credential. Unblocking will not restore revoked credentials."
	case userOperationUnblock:
		impact.Applicable = status == "blocked"
		impact.Reversible = true
		impact.AccessEffect = "future_sessions_eligible_existing_credentials_remain_revoked"
		impact.Summary = "Restore eligibility for future sessions without restoring any credential revoked by the block."
	case userOperationRequireReauthentication:
		impact.Applicable = status == "active"
		impact.AccessEffect = "existing_sessions_revoked_future_identity_exchange_required"
		impact.Summary = "Revoke current user and component sessions across the application immediately while leaving the user and installations eligible for a fresh identity exchange."
	case userOperationRequireReverification:
		impact.Applicable = status == "active"
		impact.AccessEffect = "refresh_credentials_revoked_current_access_expires_normally"
		impact.Summary = "Expire component trust and refresh credentials across the application immediately. Existing access grants live only until their normal expiry; the app must establish fresh platform trust before refresh."
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"latchway/admin-user-impact/v1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d",
		organizationID, environmentID, userID, action, status,
		counts.ActiveSessionGrants, counts.ActiveRefreshTokens,
		counts.ActiveComponentSessions, counts.ActiveComponentRefreshTokens,
		counts.ActiveInstallationFamilies, counts.ActiveClientComponents,
	)))
	impact.ImpactToken = base64.RawURLEncoding.EncodeToString(digest[:])
	return impact
}

func confirmedUserOperationChanges(action string) ([]adminauth.AuditChange, error) {
	reason, err := adminauth.NewPublicAuditChange("reason_provided", adminauth.AuditSet)
	if err != nil {
		return nil, err
	}
	var field string
	switch action {
	case userOperationRequireReauthentication:
		field = "session_credentials"
	case userOperationRequireReverification:
		field = "app_trust_and_refresh_credentials"
	default:
		return nil, errOperationalInvalid
	}
	credentials, err := adminauth.NewSensitiveAuditChange(field, adminauth.AuditRevoke)
	if err != nil {
		return nil, err
	}
	return []adminauth.AuditChange{reason, credentials}, nil
}

func requireReauthentication(
	ctx context.Context,
	tx pgx.Tx,
	organizationID, applicationID, userID string,
	now time.Time,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4)),
		    revoke_reason = COALESCE(revoke_reason, 'admin_user_reauthentication_required')
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND revoked_at IS NULL
	`, organizationID, applicationID, userID, now); err != nil {
		return fmt.Errorf("revoke user sessions for reauthentication: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4))
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND status IN ('staged', 'active')
	`, organizationID, applicationID, userID, now); err != nil {
		return fmt.Errorf("revoke user refresh tokens for reauthentication: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE component_refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4))
		WHERE client_component_id IN (
		  SELECT client_component_id FROM client_components
		  WHERE organization_id = $1 AND application_id = $2 AND application_user_id = $3
		) AND status IN ('staged', 'active')
	`, organizationID, applicationID, userID, now); err != nil {
		return fmt.Errorf("revoke component refresh tokens for reauthentication: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM refresh_rotation_results
		WHERE client_component_id IN (
		  SELECT client_component_id FROM client_components
		  WHERE organization_id = $1 AND application_id = $2 AND application_user_id = $3
		)
	`, organizationID, applicationID, userID); err != nil {
		return fmt.Errorf("remove component refresh results for reauthentication: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE component_session_families
		SET status = 'revoked', updated_at = GREATEST(updated_at, created_at, $4),
		    revoked_at = COALESCE(revoked_at, GREATEST(created_at, $4)),
		    revocation_reason = COALESCE(revocation_reason, 'admin_user_reauthentication_required')
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND status = 'active'
	`, organizationID, applicationID, userID, now); err != nil {
		return fmt.Errorf("revoke component sessions for reauthentication: %w", err)
	}
	return nil
}

func requireAppReverification(
	ctx context.Context,
	tx pgx.Tx,
	organizationID, applicationID, userID string,
	now time.Time,
) error {
	rows, err := tx.Query(ctx, `
		SELECT installation_family_id, root_installation_id, environment_id
		FROM installation_families
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND status = 'active'
		ORDER BY installation_family_id
		FOR UPDATE
	`, organizationID, applicationID, userID)
	if err != nil {
		return fmt.Errorf("lock user installation families for re-verification: %w", err)
	}
	type family struct{ id, installationID, environmentID string }
	var families []family
	for rows.Next() {
		var item family
		if err := rows.Scan(&item.id, &item.installationID, &item.environmentID); err != nil {
			rows.Close()
			return fmt.Errorf("scan user installation family for re-verification: %w", err)
		}
		families = append(families, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate user installation families for re-verification: %w", err)
	}
	rows.Close()
	for _, item := range families {
		if err := expireComponentTrustAndRefresh(ctx, tx, organizationID, item.id, nil, now); err != nil {
			return err
		}
		if err := revokeLegacyRefreshForRenewal(
			ctx, tx, organizationID, applicationID, item.environmentID, userID, item.installationID, now,
		); err != nil {
			return err
		}
	}
	// Legacy installations that have not yet been lifted into a family still
	// lose their refresh capability. Their next session exchange must perform
	// the configured platform verification again.
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4))
		WHERE organization_id = $1 AND application_id = $2
		  AND application_user_id = $3 AND status IN ('staged', 'active')
	`, organizationID, applicationID, userID, now); err != nil {
		return fmt.Errorf("revoke user refresh tokens for app re-verification: %w", err)
	}
	return nil
}
