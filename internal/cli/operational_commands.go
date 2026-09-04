package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/spf13/cobra"
)

type controlCommandOptions struct {
	tokenEnvironment string
}

var operationalIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var operationalFailurePatternCLI = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)
var operationalImpactTokenPatternCLI = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var operationalDecimalPatternCLI = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)

type pageInfoCLI struct {
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type applicationUserCLI struct {
	ID                string         `json:"id"`
	EnvironmentID     string         `json:"environment_id"`
	Status            string         `json:"status"`
	IdentityProviders []string       `json:"identity_providers"`
	NormalizedClaims  map[string]any `json:"normalized_claims"`
	LimitPlanOverride any            `json:"limit_plan_override,omitempty"`
	CreatedAt         string         `json:"created_at"`
	LastSeenAt        string         `json:"last_seen_at,omitempty"`
}

type applicationUserPageCLI struct {
	Items []applicationUserCLI `json:"items"`
	Page  pageInfoCLI          `json:"page"`
}

type userOperationCountsCLI struct {
	ActiveSessionGrants          int64 `json:"active_session_grants"`
	ActiveRefreshTokens          int64 `json:"active_refresh_tokens"`
	ActiveComponentSessions      int64 `json:"active_component_sessions"`
	ActiveComponentRefreshTokens int64 `json:"active_component_refresh_tokens"`
	ActiveInstallationFamilies   int64 `json:"active_installation_families"`
	ActiveClientComponents       int64 `json:"active_client_components"`
}

type userOperationImpactCLI struct {
	Action        string                 `json:"action"`
	Immediate     bool                   `json:"immediate"`
	Reversible    bool                   `json:"reversible"`
	Applicable    bool                   `json:"applicable"`
	CurrentStatus string                 `json:"current_status"`
	AccessEffect  string                 `json:"access_effect"`
	Summary       string                 `json:"summary"`
	Counts        userOperationCountsCLI `json:"counts"`
	ImpactToken   string                 `json:"impact_token"`
}

type confirmedUserOperationCLI struct {
	Reason                     string `json:"reason"`
	ImpactToken                string `json:"impact_token"`
	AcknowledgeImmediateEffect bool   `json:"acknowledge_immediate_effect"`
}

type userOperationResultCLI struct {
	OperationID string                 `json:"operation_id"`
	Impact      userOperationImpactCLI `json:"impact"`
	User        applicationUserCLI     `json:"user"`
}

type effectiveInputCLI struct {
	Fact         string            `json:"fact"`
	Source       string            `json:"source"`
	Availability string            `json:"availability"`
	Keys         []string          `json:"keys,omitempty"`
	Values       map[string]string `json:"values,omitempty"`
	Detail       string            `json:"detail"`
}

type effectiveLimitCLI struct {
	Index              int      `json:"index"`
	Metric             string   `json:"metric"`
	Algorithm          string   `json:"algorithm"`
	Scope              []string `json:"scope"`
	Window             string   `json:"window,omitempty"`
	Timezone           string   `json:"timezone,omitempty"`
	Maximum            int64    `json:"maximum,omitempty"`
	PerRequestMaximum  int64    `json:"per_request_maximum,omitempty"`
	Capacity           int64    `json:"capacity,omitempty"`
	RefillPerSecond    string   `json:"refill_per_second,omitempty"`
	CostRetryTreatment string   `json:"cost_retry_treatment,omitempty"`
	Hard               bool     `json:"hard"`
	Source             string   `json:"source"`
}

type effectiveRouteCLI struct {
	Order                int      `json:"order"`
	Route                string   `json:"route"`
	Upstream             string   `json:"upstream"`
	Model                string   `json:"model"`
	PhysicalModel        string   `json:"physical_model"`
	MatchExpression      string   `json:"match_expression"`
	ConfiguredPriority   int64    `json:"configured_priority"`
	ConfiguredWeight     int64    `json:"configured_weight"`
	StickyBy             string   `json:"sticky_by,omitempty"`
	FallbackOn           []string `json:"fallback_on"`
	RetryMaximumAttempts int64    `json:"retry_maximum_attempts"`
	RetryOn              []string `json:"retry_on"`
	Source               string   `json:"source"`
	Observed             bool     `json:"observed"`
}

type effectiveOutputCLI struct {
	ConfiguredDefaultMaximumTokens  int64  `json:"configured_default_maximum_tokens,omitempty"`
	ConfiguredAbsoluteMaximumTokens int64  `json:"configured_absolute_maximum_tokens,omitempty"`
	EffectiveDefaultMaximumTokens   int64  `json:"effective_default_maximum_tokens,omitempty"`
	EffectiveMaximumTokens          int64  `json:"effective_maximum_tokens,omitempty"`
	RequestedMaximumTokens          int64  `json:"requested_maximum_tokens,omitempty"`
	Source                          string `json:"source"`
}

type effectiveSubjectCLI struct {
	Kind           string `json:"kind"`
	ID             string `json:"id"`
	UserID         string `json:"user_id"`
	InstallationID string `json:"installation_id,omitempty"`
	ComponentID    string `json:"component_id,omitempty"`
}

type installationCLI struct {
	ID                  string `json:"id"`
	UserID              string `json:"user_id"`
	EnvironmentID       string `json:"environment_id"`
	Platform            string `json:"platform"`
	DPoPJKT             string `json:"dpop_jkt"`
	Status              string `json:"status"`
	TrustLevel          string `json:"trust_level"`
	AttestationProvider string `json:"attestation_provider,omitempty"`
	TrustExpiresAt      string `json:"trust_expires_at,omitempty"`
	CreatedAt           string `json:"created_at"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	RevokedAt           string `json:"revoked_at,omitempty"`
}

type installationPageCLI struct {
	Items []installationCLI `json:"items"`
	Page  pageInfoCLI       `json:"page"`
}

type usageValuesCLI struct {
	LogicalRequests json.Number `json:"logical_requests"`
	InputTokens     json.Number `json:"input_tokens"`
	OutputTokens    json.Number `json:"output_tokens"`
	TotalTokens     json.Number `json:"total_tokens"`
	CostNanoUSD     json.Number `json:"cost_nano_usd"`
}

type upstreamAttemptCLI struct {
	ID              string          `json:"id"`
	AttemptNumber   int32           `json:"attempt_number"`
	Route           string          `json:"route"`
	Upstream        string          `json:"upstream"`
	Model           string          `json:"model"`
	StartedAt       string          `json:"started_at"`
	FirstByteAt     string          `json:"first_byte_at,omitempty"`
	FirstTokenAt    string          `json:"first_token_at,omitempty"`
	CompletedAt     string          `json:"completed_at,omitempty"`
	Status          string          `json:"status"`
	HTTPStatus      int             `json:"http_status,omitempty"`
	FailureCode     string          `json:"failure_code,omitempty"`
	Usage           *usageValuesCLI `json:"usage,omitempty"`
	UsageProvenance string          `json:"usage_provenance"`
	CostProvenance  string          `json:"cost_provenance"`
	CostSource      string          `json:"cost_source,omitempty"`
}

type requestDecisionStageCLI struct {
	Number           int32  `json:"number"`
	Stage            string `json:"stage"`
	Outcome          string `json:"outcome"`
	FailureCode      string `json:"failure_code,omitempty"`
	ConfigRevisionID string `json:"config_revision_id"`
	PolicyRuleKey    string `json:"policy_rule_key,omitempty"`
	LimitPlanKey     string `json:"limit_plan_key,omitempty"`
	LimitRuleKey     string `json:"limit_rule_key,omitempty"`
	LimitMetric      string `json:"limit_metric,omitempty"`
	LimitAlgorithm   string `json:"limit_algorithm,omitempty"`
	LimitMaximum     *int64 `json:"limit_maximum,omitempty"`
	Route            string `json:"route,omitempty"`
	Upstream         string `json:"upstream,omitempty"`
	Model            string `json:"model,omitempty"`
	PhysicalModel    string `json:"physical_model,omitempty"`
	StartedAt        string `json:"started_at"`
	CompletedAt      string `json:"completed_at"`
	DurationMS       int64  `json:"duration_ms"`
}

type logicalRequestCLI struct {
	ID                    string                    `json:"id"`
	EnvironmentID         string                    `json:"environment_id"`
	UserID                string                    `json:"user_id"`
	InstallationID        string                    `json:"installation_id"`
	InstallationFamilyID  string                    `json:"installation_family_id,omitempty"`
	ClientComponentID     string                    `json:"client_component_id,omitempty"`
	ComponentDefinitionID string                    `json:"component_definition_id,omitempty"`
	ComponentKind         string                    `json:"component_kind,omitempty"`
	TrustSource           string                    `json:"trust_source,omitempty"`
	Framework             string                    `json:"framework,omitempty"`
	FrameworkVersion      string                    `json:"framework_version,omitempty"`
	ConfigRevisionID      string                    `json:"config_revision_id"`
	SelectedLimitPlan     string                    `json:"selected_limit_plan"`
	SelectedRoute         string                    `json:"selected_route,omitempty"`
	SelectedUpstream      string                    `json:"selected_upstream,omitempty"`
	SelectedModel         string                    `json:"selected_model,omitempty"`
	SelectedPhysicalModel string                    `json:"selected_physical_model,omitempty"`
	Feature               string                    `json:"feature"`
	Protocol              string                    `json:"protocol"`
	StartedAt             string                    `json:"started_at"`
	CompletedAt           string                    `json:"completed_at,omitempty"`
	Status                string                    `json:"status"`
	FailureCode           string                    `json:"failure_code,omitempty"`
	Usage                 *usageValuesCLI           `json:"usage,omitempty"`
	DecisionStages        []requestDecisionStageCLI `json:"decision_stages"`
	Attempts              []upstreamAttemptCLI      `json:"attempts"`
}

type effectiveConfigurationCLI struct {
	Subject                 effectiveSubjectCLI       `json:"subject"`
	EvaluationMode          string                    `json:"evaluation_mode"`
	EnvironmentID           string                    `json:"environment_id"`
	EnvironmentKind         string                    `json:"environment_kind"`
	RevisionID              string                    `json:"revision_id"`
	Feature                 string                    `json:"feature"`
	Protocol                string                    `json:"protocol,omitempty"`
	RequestStatus           string                    `json:"request_status,omitempty"`
	PolicyOutcome           string                    `json:"policy_outcome"`
	DenialReason            string                    `json:"denial_reason,omitempty"`
	MatchedAccessExpression string                    `json:"matched_access_expression,omitempty"`
	MatchedLimitExpression  string                    `json:"matched_limit_plan_expression,omitempty"`
	LimitPlan               string                    `json:"limit_plan,omitempty"`
	LimitPlanSource         string                    `json:"limit_plan_source,omitempty"`
	UserOverrideID          string                    `json:"user_override_id,omitempty"`
	ComponentDefinitionID   string                    `json:"component_definition_id,omitempty"`
	ComponentAllowed        *bool                     `json:"component_allowed,omitempty"`
	Inputs                  []effectiveInputCLI       `json:"inputs"`
	Output                  *effectiveOutputCLI       `json:"output,omitempty"`
	Limits                  []effectiveLimitCLI       `json:"limits"`
	SelectedRoute           *effectiveRouteCLI        `json:"selected_route,omitempty"`
	Routes                  []effectiveRouteCLI       `json:"routes"`
	DecisionStages          []requestDecisionStageCLI `json:"decision_stages"`
	Warnings                []string                  `json:"warnings"`
}

type logicalRequestPageCLI struct {
	Items []logicalRequestCLI `json:"items"`
	Page  pageInfoCLI         `json:"page"`
}

type usageSummaryCLI struct {
	Start      string            `json:"start"`
	End        string            `json:"end"`
	Values     usageValuesCLI    `json:"values"`
	Provenance []string          `json:"provenance"`
	Analytics  usageAnalyticsCLI `json:"analytics"`
}

type usageFractionCLI struct {
	Numerator   json.Number `json:"numerator"`
	Denominator json.Number `json:"denominator"`
}

type usageRateCLI struct {
	Numerator       json.Number `json:"numerator"`
	Denominator     json.Number `json:"denominator"`
	PartsPerMillion json.Number `json:"parts_per_million"`
}

type usageDistributionCLI struct {
	Samples json.Number `json:"samples"`
	P50MS   json.Number `json:"p50_ms"`
	P95MS   json.Number `json:"p95_ms"`
	P99MS   json.Number `json:"p99_ms"`
}

type usageBreakdownItemCLI struct {
	Key          string         `json:"key"`
	ActiveUsers  json.Number    `json:"active_users"`
	RequestCount json.Number    `json:"request_count"`
	Values       usageValuesCLI `json:"values"`
}

type usageBreakdownCLI struct {
	Items     []usageBreakdownItemCLI `json:"items"`
	Truncated bool                    `json:"truncated"`
	Limit     int                     `json:"limit"`
}

type usageProvenanceCLI struct {
	Provenance string         `json:"provenance"`
	CostSource string         `json:"cost_source,omitempty"`
	Values     usageValuesCLI `json:"values"`
}

type usageAnalyticsCLI struct {
	ActiveUsers              json.Number          `json:"active_users"`
	RequestCount             json.Number          `json:"request_count"`
	RequestsPerActiveUser    usageFractionCLI     `json:"requests_per_active_user"`
	CostPerActiveUserNanoUSD usageFractionCLI     `json:"cost_per_active_user_nano_usd"`
	ByFeature                usageBreakdownCLI    `json:"by_feature"`
	ByModel                  usageBreakdownCLI    `json:"by_model"`
	BySelectedPlan           usageBreakdownCLI    `json:"by_selected_plan"`
	RequestLatency           usageDistributionCLI `json:"request_latency"`
	TimeToFirstToken         usageDistributionCLI `json:"time_to_first_token"`
	FailureRate              usageRateCLI         `json:"failure_rate"`
	QuotaDenialRate          usageRateCLI         `json:"quota_denial_rate"`
	AttestationFailureRate   usageRateCLI         `json:"attestation_failure_rate"`
	FallbackRate             usageRateCLI         `json:"fallback_rate"`
	UsageByProvenance        []usageProvenanceCLI `json:"usage_by_provenance"`
}

type usagePointCLI struct {
	Timestamp string         `json:"timestamp"`
	Values    usageValuesCLI `json:"values"`
}

type usageTimeseriesCLI struct {
	Interval string          `json:"interval"`
	Points   []usagePointCLI `json:"points"`
}

type auditEventCLI struct {
	ID            string           `json:"id"`
	Timestamp     string           `json:"timestamp"`
	Actor         string           `json:"actor"`
	ActorKind     string           `json:"actor_kind"`
	ActorID       string           `json:"actor_id,omitempty"`
	Action        string           `json:"action"`
	Target        string           `json:"target"`
	ResourceType  string           `json:"resource_type"`
	ResourceID    string           `json:"resource_id"`
	EnvironmentID string           `json:"environment_id,omitempty"`
	Source        string           `json:"source"`
	Reason        string           `json:"reason,omitempty"`
	Result        string           `json:"result"`
	RequestID     string           `json:"request_id"`
	Changes       []auditChangeCLI `json:"changes"`
	Summary       map[string]any   `json:"summary"`
}

type auditChangeCLI struct {
	Field          string `json:"field"`
	Operation      string `json:"operation"`
	Classification string `json:"classification"`
	Redacted       bool   `json:"redacted"`
}

type auditPageCLI struct {
	Items []auditEventCLI `json:"items"`
	Page  pageInfoCLI     `json:"page"`
}

type selfTestCheckCLI struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	SafeDetail string `json:"safe_detail,omitempty"`
}

type selfTestRunCLI struct {
	ID               string             `json:"id"`
	EnvironmentID    string             `json:"environment_id"`
	ScheduleID       string             `json:"schedule_id,omitempty"`
	ConfigRevisionID string             `json:"config_revision_id,omitempty"`
	Kind             string             `json:"kind"`
	State            string             `json:"state"`
	CreatedAt        string             `json:"created_at"`
	CompletedAt      string             `json:"completed_at,omitempty"`
	Checks           []selfTestCheckCLI `json:"checks"`
}

type selfTestScheduleCLI struct {
	ID                        string `json:"id"`
	EnvironmentID             string `json:"environment_id"`
	ApplicationID             string `json:"application_id"`
	ConfigRevisionID          string `json:"config_revision_id"`
	AuthorizationCredentialID string `json:"authorization_credential_id"`
	Kind                      string `json:"kind"`
	Upstream                  string `json:"upstream"`
	Model                     string `json:"model"`
	MaxCostNanoUSD            int64  `json:"max_cost_nano_usd"`
	DailyCostLimitNanoUSD     int64  `json:"daily_cost_limit_nano_usd"`
	IntervalSeconds           int64  `json:"interval_seconds"`
	Status                    string `json:"status"`
	NextRunAt                 string `json:"next_run_at,omitempty"`
	LastEnqueuedAt            string `json:"last_enqueued_at,omitempty"`
	LastSelfTestID            string `json:"last_self_test_id,omitempty"`
	CreatedAt                 string `json:"created_at"`
	UpdatedAt                 string `json:"updated_at"`
	DisabledAt                string `json:"disabled_at,omitempty"`
	DisabledReasonCode        string `json:"disabled_reason_code,omitempty"`
}

type selfTestSchedulePageCLI struct {
	Items []selfTestScheduleCLI `json:"items"`
	Page  pageInfoCLI           `json:"page"`
}

type systemStatusCLI struct {
	ServerVersion         string   `json:"server_version"`
	ContractVersion       string   `json:"contract_version"`
	ProtocolVersions      []int    `json:"protocol_versions"`
	Role                  string   `json:"role"`
	DatabaseSchemaVersion string   `json:"database_schema_version"`
	MutationReady         bool     `json:"mutation_ready"`
	Ready                 bool     `json:"ready"`
	ServerCapabilities    []string `json:"server_capabilities"`
}

var requiredServerCapabilitiesCLI = []string{
	"app_attest",
	"play_integrity",
	"firebase_app_check",
	"turnstile",
	"component_delegation",
	"cost_limits",
	"openai_responses",
	"openai_chat",
	"openai_embeddings",
	"anthropic_messages",
	"opaque_http",
	"configuration_import_export",
	"admin_session_management",
	"admin_event_stream",
}

func validSystemStatusCLI(status systemStatusCLI) bool {
	return status.ServerVersion != "" && utf8.ValidString(status.ServerVersion) &&
		status.ContractVersion == buildinfo.ContractVersion &&
		slices.Equal(status.ProtocolVersions, buildinfo.SupportedProtocolVersions()) &&
		(status.Role == "all" || status.Role == "api" || status.Role == "worker") &&
		status.DatabaseSchemaVersion != "" && utf8.ValidString(status.DatabaseSchemaVersion) &&
		slices.Equal(status.ServerCapabilities, requiredServerCapabilitiesCLI)
}

func addControlTokenFlag(command *cobra.Command, values *controlCommandOptions) {
	values.tokenEnvironment = defaultAdminTokenEnvironment
	command.PersistentFlags().StringVar(
		&values.tokenEnvironment, "api-token-env", values.tokenEnvironment,
		"environment variable containing a scoped Admin API token",
	)
}

func newUsersCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "users", Short: "Inspect, explain, and safely operate on pseudonymous application users"}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newUsersListCommand(opts, values), newUsersInspectCommand(opts, values),
		newUsersEffectiveCommand(opts, values), newUsersImpactCommand(opts, values),
		newUsersMutationCommand(opts, values, "block", "block", false),
		newUsersMutationCommand(opts, values, "unblock", "unblock", false),
		newUsersMutationCommand(opts, values, "require-reauthentication", "require_reauthentication", true),
		newUsersMutationCommand(opts, values, "require-app-reverification", "require_app_reverification", true),
	)
	return command
}

func newUsersListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List users without external subjects or identity credentials", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil {
				return errors.New("environment ID is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page applicationUserPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/users", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			return printUsers(opts, page)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of users to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newUsersInspectCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID string
	command := &cobra.Command{
		Use: "inspect USER_ID", Short: "Inspect one user and safe normalized claims", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ApplicationUser) != nil || id.Validate(environmentID, id.Environment) != nil {
				return errors.New("user or environment ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var user applicationUserCLI
			query := url.Values{"environment_id": []string{environmentID}}
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/users/"+args[0], query, nil, http.StatusOK, &user); err != nil {
				return err
			}
			return printUser(opts, user)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newUsersEffectiveCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, feature, installationID, componentID string
	var streaming bool
	var estimatedInputTokens, maximumOutputTokens int64
	command := &cobra.Command{
		Use: "effective USER_ID", Short: "Explain a user's exact current policy, limits, and route projection", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ApplicationUser) != nil || id.Validate(environmentID, id.Environment) != nil ||
				!operationalIdentifierPattern.MatchString(feature) ||
				(installationID != "" && id.Validate(installationID, id.Installation) != nil) ||
				(componentID != "" && id.Validate(componentID, id.ClientComponent) != nil) ||
				(installationID != "" && componentID != "") ||
				estimatedInputTokens < 0 || estimatedInputTokens > protocol.MaximumPolicyRequestTokens ||
				maximumOutputTokens < 0 || maximumOutputTokens > protocol.MaximumPolicyRequestTokens {
				return errors.New("effective-configuration user, environment, feature, surface, or request facts are invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			query := url.Values{"environment_id": {environmentID}, "feature": {feature}}
			if installationID != "" {
				query.Set("installation_id", installationID)
			}
			if componentID != "" {
				query.Set("component_id", componentID)
			}
			if streaming {
				query.Set("streaming", "true")
			}
			if estimatedInputTokens != 0 {
				query.Set("estimated_input_tokens", strconv.FormatInt(estimatedInputTokens, 10))
			}
			if maximumOutputTokens != 0 {
				query.Set("maximum_output_tokens", strconv.FormatInt(maximumOutputTokens, 10))
			}
			var document effectiveConfigurationCLI
			if _, err := client.do(cmd.Context(), http.MethodGet,
				"/admin/v1/users/"+args[0]+"/effective-configuration", query, nil, http.StatusOK, &document); err != nil {
				return err
			}
			if !validEffectiveConfigurationCLI(document) || document.EvaluationMode != "current_user_projection" ||
				document.Subject.ID != args[0] || document.EnvironmentID != environmentID || document.Feature != feature {
				return errors.New("admin API returned a non-conforming effective-configuration document")
			}
			return printEffectiveConfiguration(opts, document)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&feature, "feature", "", "feature identifier to evaluate")
	command.Flags().StringVar(&installationID, "installation", "", "optional installation surface")
	command.Flags().StringVar(&componentID, "component", "", "optional component surface (exclusive with --installation)")
	command.Flags().BoolVar(&streaming, "streaming", false, "evaluate a streaming request")
	command.Flags().Int64Var(&estimatedInputTokens, "estimated-input-tokens", 0, "bounded untrusted input-token estimate assumed by policy")
	command.Flags().Int64Var(&maximumOutputTokens, "maximum-output-tokens", 0, "requested output-token maximum assumed by policy")
	_ = command.MarkFlagRequired("environment")
	_ = command.MarkFlagRequired("feature")
	return command
}

func newUsersImpactCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, action string
	command := &cobra.Command{
		Use: "impact USER_ID", Short: "Review application-wide credential impact before a sensitive user operation", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ApplicationUser) != nil || id.Validate(environmentID, id.Environment) != nil ||
				!validUserOperationCLI(action) {
				return errors.New("user, environment, or operation action is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			impact, err := loadUserOperationImpactCLI(cmd, client, args[0], environmentID, action)
			if err != nil {
				return err
			}
			return printUserOperationImpact(opts, impact)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "environment used to resolve the application-wide user")
	command.Flags().StringVar(&action, "action", "", "block, unblock, require_reauthentication, or require_app_reverification")
	_ = command.MarkFlagRequired("environment")
	_ = command.MarkFlagRequired("action")
	return command
}

func newUsersMutationCommand(
	opts *options,
	root *controlCommandOptions,
	commandName string,
	action string,
	returnsResult bool,
) *cobra.Command {
	var environmentID, reason, confirmation, reviewedImpactToken string
	command := &cobra.Command{
		Use: commandName + " USER_ID", Short: "Perform a reviewed " + strings.ReplaceAll(action, "_", " ") + " operation", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ApplicationUser) != nil || id.Validate(environmentID, id.Environment) != nil {
				return errors.New("user or environment ID is invalid")
			}
			reason = strings.TrimSpace(reason)
			if confirmation != args[0] || !operationalImpactTokenPatternCLI.MatchString(reviewedImpactToken) ||
				!utf8.ValidString(reason) || strings.ContainsRune(reason, '\x00') ||
				utf8.RuneCountInString(reason) < 1 || utf8.RuneCountInString(reason) > 500 {
				return errors.New("set --confirm to the exact user ID, provide the reviewed --impact-token, and provide a 1-500 character --reason")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			impact, err := loadUserOperationImpactCLI(cmd, client, args[0], environmentID, action)
			if err != nil {
				return err
			}
			if !impact.Applicable {
				return fmt.Errorf("operation %s is not applicable while the user is %s", action, impact.CurrentStatus)
			}
			if impact.ImpactToken != reviewedImpactToken {
				return errors.New("user-operation impact changed; run users impact again and review the new token")
			}
			query := url.Values{"environment_id": []string{environmentID}}
			body := confirmedUserOperationCLI{
				Reason: reason, ImpactToken: reviewedImpactToken, AcknowledgeImmediateEffect: true,
			}
			path := "/admin/v1/users/" + args[0] + "/" + commandName
			if returnsResult {
				var result userOperationResultCLI
				if _, err := client.do(cmd.Context(), http.MethodPost, path, query, body, http.StatusOK, &result); err != nil {
					return err
				}
				return printUserOperationResult(opts, result)
			}
			var user applicationUserCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, path, query, body, http.StatusOK, &user); err != nil {
				return err
			}
			return printUser(opts, user)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "environment used to resolve the application-wide user")
	command.Flags().StringVar(&reason, "reason", "", "operator justification (not copied into audit metadata)")
	command.Flags().StringVar(&confirmation, "confirm", "", "exact user ID acknowledging the reviewed immediate effect")
	command.Flags().StringVar(&reviewedImpactToken, "impact-token", "", "exact optimistic token printed by users impact")
	_ = command.MarkFlagRequired("environment")
	return command
}

func validUserOperationCLI(action string) bool {
	switch action {
	case "block", "unblock", "require_reauthentication", "require_app_reverification":
		return true
	default:
		return false
	}
}

func loadUserOperationImpactCLI(
	cmd *cobra.Command,
	client *controlAPIClient,
	userID, environmentID, action string,
) (userOperationImpactCLI, error) {
	var impact userOperationImpactCLI
	query := url.Values{"environment_id": {environmentID}, "action": {action}}
	if _, err := client.do(cmd.Context(), http.MethodGet,
		"/admin/v1/users/"+userID+"/operation-impact", query, nil, http.StatusOK, &impact); err != nil {
		return userOperationImpactCLI{}, err
	}
	if impact.Action != action || !operationalImpactTokenPatternCLI.MatchString(impact.ImpactToken) || impact.CurrentStatus == "" || impact.Summary == "" {
		return userOperationImpactCLI{}, errors.New("admin API returned a non-conforming user-operation impact")
	}
	return impact, nil
}

func newInstallationsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "installations", Short: "Inspect and revoke installations through the Admin API"}
	addControlTokenFlag(command, values)
	command.AddCommand(newInstallationsListCommand(opts, values), newInstallationsInspectCommand(opts, values), newInstallationsRevokeCommand(opts, values))
	return command
}

func newInstallationsListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List installations and normalized trust without evidence", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil {
				return errors.New("environment ID is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page installationPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/installations", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			return printInstallations(opts, page)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of installations to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newInstallationsInspectCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "inspect INSTALLATION_ID", Short: "Inspect one installation", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.Installation) != nil {
				return errors.New("installation ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var installation installationCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/installations/"+args[0], nil, nil, http.StatusOK, &installation); err != nil {
				return err
			}
			return printInstallation(opts, installation)
		},
	}
}

func newInstallationsRevokeCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var reason string
	command := &cobra.Command{
		Use: "revoke INSTALLATION_ID", Short: "Revoke an installation, grants, and refresh tokens", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.Installation) != nil {
				return errors.New("installation ID is invalid")
			}
			reason = strings.TrimSpace(reason)
			if len(reason) > 100 || strings.ContainsAny(reason, "\r\n\x00") {
				return errors.New("revocation reason must not exceed 100 safe characters")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var installation installationCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/installations/"+args[0]+"/revoke", nil, map[string]string{"reason": reason}, http.StatusOK, &installation); err != nil {
				return err
			}
			return printInstallation(opts, installation)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "redaction-safe administrative reason (maximum 100 characters)")
	return command
}

func newRequestsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "requests", Short: "Explore redaction-safe logical request metadata"}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newRequestsListCommand(opts, values), newRequestsInspectCommand(opts, values),
		newRequestsEffectiveCommand(opts, values),
	)
	return command
}

func newRequestsListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List logical requests without prompt or response bodies", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil {
				return errors.New("environment ID is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page logicalRequestPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/requests", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			for _, request := range page.Items {
				if !validLogicalRequestCLI(request) {
					return errors.New("admin API returned a non-conforming request document")
				}
			}
			return printRequests(opts, page)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of requests to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newRequestsInspectCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "inspect REQUEST_ID", Short: "Inspect one request, attempts, and usage provenance", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.LogicalRequest) != nil {
				return errors.New("request ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var request logicalRequestCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/requests/"+args[0], nil, nil, http.StatusOK, &request); err != nil {
				return err
			}
			if !validLogicalRequestCLI(request) {
				return errors.New("admin API returned a non-conforming request document")
			}
			return printRequest(opts, request)
		},
	}
}

func newRequestsEffectiveCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "effective REQUEST_ID", Short: "Explain a request from its immutable revision and durable decision stages", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.LogicalRequest) != nil {
				return errors.New("request ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var document effectiveConfigurationCLI
			if _, err := client.do(cmd.Context(), http.MethodGet,
				"/admin/v1/requests/"+args[0]+"/effective-configuration", nil, nil, http.StatusOK, &document); err != nil {
				return err
			}
			if !validEffectiveConfigurationCLI(document) || document.EvaluationMode != "recorded_request" || document.Subject.ID != args[0] {
				return errors.New("admin API returned a non-conforming effective-configuration document")
			}
			return printEffectiveConfiguration(opts, document)
		},
	}
}

func newUsageCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "usage", Short: "Inspect immutable usage ledger aggregates"}
	addControlTokenFlag(command, values)
	command.AddCommand(newUsageSummaryCommand(opts, values), newUsageTimeseriesCommand(opts, values))
	return command
}

func newUsageSummaryCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, start, end string
	var breakdownLimit int
	command := &cobra.Command{
		Use: "summary", Short: "Summarize requests, tokens, and nano-USD cost", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if breakdownLimit < 1 || breakdownLimit > 200 {
				return errors.New("usage breakdown limit must be between 1 and 200")
			}
			query, err := usageQuery(environmentID, start, end, "")
			if err != nil {
				return err
			}
			query.Set("breakdown_limit", strconv.Itoa(breakdownLimit))
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var summary usageSummaryCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/usage/summary", query, nil, http.StatusOK, &summary); err != nil {
				return err
			}
			return printUsageSummary(opts, summary)
		},
	}
	usageRangeFlags(command, &environmentID, &start, &end)
	command.Flags().IntVar(&breakdownLimit, "breakdown-limit", 50, "maximum feature, model, and selected-plan rows (1-200)")
	return command
}

func newUsageTimeseriesCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, start, end, interval string
	command := &cobra.Command{
		Use: "timeseries", Short: "Return bounded UTC hourly or daily usage buckets", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			query, err := usageQuery(environmentID, start, end, interval)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var series usageTimeseriesCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/usage/timeseries", query, nil, http.StatusOK, &series); err != nil {
				return err
			}
			return printUsageTimeseries(opts, series)
		},
	}
	usageRangeFlags(command, &environmentID, &start, &end)
	command.Flags().StringVar(&interval, "interval", "hour", "UTC bucket interval: hour or day")
	return command
}

func usageRangeFlags(command *cobra.Command, environmentID, start, end *string) {
	command.Flags().StringVar(environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(start, "start", "", "inclusive RFC 3339 start (defaults to 24 hours before end)")
	command.Flags().StringVar(end, "end", "", "exclusive RFC 3339 end (defaults to now)")
	_ = command.MarkFlagRequired("environment")
}

func newAuditCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	var organizationID, environmentID, actorKind, actorID, action, resourceType, resourceID, source, reason, result, start, end, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "audit", Short: "Inspect append-only redaction-safe administrative audit events", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(organizationID, id.Organization) != nil || pageSize < 1 || pageSize > 200 {
				return errors.New("organization ID or page size is invalid")
			}
			query := url.Values{"organization_id": []string{organizationID}, "page_size": []string{strconv.Itoa(pageSize)}}
			for name, value := range map[string]string{
				"environment_id": environmentID, "actor_kind": actorKind, "actor_id": actorID, "action": action,
				"resource_type": resourceType, "resource_id": resourceID, "source": source, "reason": reason, "result": result,
				"start": start, "end": end, "cursor": cursor,
			} {
				if value != "" {
					query.Set(name, value)
				}
			}
			client, err := newControlAPIClient(opts, values.tokenEnvironment)
			if err != nil {
				return err
			}
			var page auditPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/audit-events", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			return printAudit(opts, page)
		},
	}
	addControlTokenFlag(command, values)
	command.Flags().StringVar(&organizationID, "organization", "", "organization ID")
	command.Flags().StringVar(&environmentID, "environment", "", "filter by environment ID")
	command.Flags().StringVar(&actorKind, "actor-kind", "", "filter by actor kind: admin_user, admin_api_token, or system")
	command.Flags().StringVar(&actorID, "actor", "", "filter by administrator or API-token actor ID")
	command.Flags().StringVar(&action, "action", "", "filter by exact audit action")
	command.Flags().StringVar(&resourceType, "resource-type", "", "filter by exact resource type")
	command.Flags().StringVar(&resourceID, "resource", "", "filter by exact resource ID")
	command.Flags().StringVar(&source, "source", "", "filter by descriptive source: console, cli, api, or system")
	command.Flags().StringVar(&reason, "reason", "", "filter by stable redaction-safe reason code")
	command.Flags().StringVar(&result, "result", "", "filter by result: succeeded, denied, failed, or indeterminate")
	command.Flags().StringVar(&start, "start", "", "inclusive RFC 3339 start")
	command.Flags().StringVar(&end, "end", "", "exclusive RFC 3339 end")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of events to return (1-200)")
	_ = command.MarkFlagRequired("organization")
	command.AddCommand(newAuditInspectCommand(opts))
	return command
}

func newAuditInspectCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "inspect AUDIT_EVENT_ID", Short: "Inspect one redaction-safe audit event and its field-level changes", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.AuditEvent) != nil {
				return errors.New("audit event ID is invalid")
			}
			client, err := newControlAPIClient(opts, values.tokenEnvironment)
			if err != nil {
				return err
			}
			var event auditEventCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/audit-events/"+args[0], nil, nil, http.StatusOK, &event); err != nil {
				return err
			}
			return printAuditEvent(opts, event)
		},
	}
	addControlTokenFlag(command, values)
	return command
}

func newStatusCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "status", Short: "Show authenticated build, protocol, schema, role, and readiness status", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newControlAPIClient(opts, values.tokenEnvironment)
			if err != nil {
				return err
			}
			var status systemStatusCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/system", nil, nil, http.StatusOK, &status); err != nil {
				return err
			}
			if !validSystemStatusCLI(status) {
				return errors.New("admin API returned an incompatible system status document")
			}
			if opts.output == "json" {
				return printControlJSON(opts, status)
			}
			versions := make([]string, len(status.ProtocolVersions))
			for index, version := range status.ProtocolVersions {
				versions[index] = strconv.Itoa(version)
			}
			return printControlTable(opts, []string{"SERVER", "CONTRACT", "PROTOCOLS", "ROLE", "SCHEMA", "MUTATION READY", "TRAFFIC READY", "CAPABILITIES"}, [][]string{{
				status.ServerVersion, status.ContractVersion, strings.Join(versions, ","), status.Role,
				status.DatabaseSchemaVersion, boolLabel(status.MutationReady), boolLabel(status.Ready), strings.Join(status.ServerCapabilities, ","),
			}})
		},
	}
	addControlTokenFlag(command, values)
	return command
}

func newVerifyCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "verify", Short: "Run bounded local or server-side verification"}
	addControlTokenFlag(command, values)
	command.AddCommand(newVerifyLocalCommand(opts))
	command.AddCommand(newVerifyScheduleCommand(opts, values))
	for _, kind := range []string{"upstream", "openrouter"} {
		command.AddCommand(newProviderVerifyCommand(opts, values, kind))
	}
	return command
}

func newVerifyScheduleCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	command := &cobra.Command{Use: "schedule", Short: "Manage persistently authorized bounded self-test schedules"}
	command.AddCommand(
		newVerifyScheduleCreateCommand(opts, root),
		newVerifyScheduleListCommand(opts, root),
		newVerifyScheduleGetCommand(opts, root),
		newVerifyScheduleDisableCommand(opts, root),
	)
	return command
}

func newVerifyScheduleCreateCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, kind, upstream, model string
	var maxCost, dailyCost int64
	var intervalSeconds int64
	command := &cobra.Command{
		Use: "create", Short: "Create a schedule bound to the current durable Admin API token", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil ||
				(kind != "upstream" && kind != "openrouter") ||
				!operationalIdentifierPattern.MatchString(upstream) ||
				!operationalIdentifierPattern.MatchString(model) ||
				maxCost < 1 || maxCost > 1_000_000_000 ||
				dailyCost < maxCost || dailyCost > 10_000_000_000 ||
				intervalSeconds < 3600 || intervalSeconds > 2_592_000 {
				return errors.New("scheduled verification target, cadence, or budget is invalid")
			}
			runsPerDay := (86_400 + intervalSeconds - 1) / intervalSeconds
			if maxCost > dailyCost/runsPerDay {
				return errors.New("scheduled verification daily budget cannot cover the configured cadence")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			request := map[string]any{
				"environment_id": environmentID, "kind": kind, "upstream": upstream, "model": model,
				"max_cost_nano_usd": maxCost, "daily_cost_limit_nano_usd": dailyCost,
				"interval_seconds": intervalSeconds,
			}
			var schedule selfTestScheduleCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/self-test-schedules", nil, request, http.StatusCreated, &schedule); err != nil {
				return err
			}
			return printSelfTestSchedule(opts, schedule)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&kind, "kind", "upstream", "scheduled self-test kind: upstream or openrouter")
	command.Flags().StringVar(&upstream, "upstream", "", "server-owned upstream identifier")
	command.Flags().StringVar(&model, "model", "", "active configured model identifier")
	command.Flags().Int64Var(&maxCost, "max-cost-nano-usd", 10_000_000, "per-run hard cost ceiling")
	command.Flags().Int64Var(&dailyCost, "daily-cost-limit-nano-usd", 240_000_000, "UTC-day hard cost ceiling")
	command.Flags().Int64Var(&intervalSeconds, "interval-seconds", 3600, "cadence from 3600 through 2592000 seconds")
	_ = command.MarkFlagRequired("environment")
	_ = command.MarkFlagRequired("upstream")
	_ = command.MarkFlagRequired("model")
	return command
}

func newVerifyScheduleListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List redaction-safe schedule metadata", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil {
				return errors.New("scheduled verification environment is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page selfTestSchedulePageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/self-test-schedules", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			return printSelfTestSchedulePage(opts, page)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of schedules to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newVerifyScheduleGetCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "get SCHEDULE_ID", Short: "Inspect one schedule and its exact persisted bindings", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.SelfTestSchedule) != nil {
				return errors.New("self-test schedule ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var schedule selfTestScheduleCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/self-test-schedules/"+args[0], nil, nil, http.StatusOK, &schedule); err != nil {
				return err
			}
			return printSelfTestSchedule(opts, schedule)
		},
	}
}

func newVerifyScheduleDisableCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "disable SCHEDULE_ID", Short: "Permanently disable a self-test schedule", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.SelfTestSchedule) != nil {
				return errors.New("self-test schedule ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var schedule selfTestScheduleCLI
			if _, err := client.do(cmd.Context(), http.MethodDelete, "/admin/v1/self-test-schedules/"+args[0], nil, nil, http.StatusOK, &schedule); err != nil {
				return err
			}
			return printSelfTestSchedule(opts, schedule)
		},
	}
}

func verifyShort(kind string) string {
	switch kind {
	case "upstream":
		return "Run bounded ephemeral verification against an OpenAI-compatible upstream (or use --server-owned)"
	default:
		return "Run bounded OpenRouter key, usage, streaming, clamp, and error checks"
	}
}

func pageQuery(environmentID, cursor string, pageSize int) (url.Values, error) {
	if pageSize < 1 || pageSize > 200 || len(cursor) > 2048 || strings.ContainsAny(cursor, "\r\n\x00") {
		return nil, errors.New("page size or cursor is invalid")
	}
	query := url.Values{"environment_id": []string{environmentID}, "page_size": []string{strconv.Itoa(pageSize)}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	return query, nil
}

func usageQuery(environmentID, startRaw, endRaw, interval string) (url.Values, error) {
	if id.Validate(environmentID, id.Environment) != nil || (interval != "" && interval != "hour" && interval != "day") {
		return nil, errors.New("usage environment or interval is invalid")
	}
	end := time.Now().UTC()
	var err error
	if endRaw != "" {
		end, err = time.Parse(time.RFC3339Nano, endRaw)
		if err != nil {
			return nil, errors.New("--end must be an RFC 3339 instant")
		}
		end = end.UTC()
	}
	start := end.Add(-24 * time.Hour)
	if startRaw != "" {
		start, err = time.Parse(time.RFC3339Nano, startRaw)
		if err != nil {
			return nil, errors.New("--start must be an RFC 3339 instant")
		}
		start = start.UTC()
	}
	if !start.Before(end) || end.Sub(start) > 366*24*time.Hour {
		return nil, errors.New("usage range must be positive and no longer than 366 days")
	}
	query := url.Values{
		"environment_id": []string{environmentID},
		"start":          []string{start.Format(time.RFC3339Nano)},
		"end":            []string{end.Format(time.RFC3339Nano)},
	}
	if interval != "" {
		query.Set("interval", interval)
	}
	return query, nil
}

func printUsers(opts *options, page applicationUserPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items)+1)
	for _, user := range page.Items {
		rows = append(rows, []string{user.ID, user.Status, strings.Join(user.IdentityProviders, ","), formatControlTime(user.LastSeenAt)})
	}
	if err := printControlTable(opts, []string{"USER", "STATUS", "PROVIDERS", "LAST SEEN"}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printUser(opts *options, user applicationUserCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, user)
	}
	claims, _ := json.Marshal(user.NormalizedClaims)
	return printControlTable(opts, []string{"USER", "ENVIRONMENT", "STATUS", "PROVIDERS", "CLAIMS", "LAST SEEN"}, [][]string{{
		user.ID, user.EnvironmentID, user.Status, strings.Join(user.IdentityProviders, ","), string(claims), formatControlTime(user.LastSeenAt),
	}})
}

func printUserOperationImpact(opts *options, impact userOperationImpactCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, impact)
	}
	if err := printControlTable(opts,
		[]string{"ACTION", "STATUS", "APPLICABLE", "IMMEDIATE", "REVERSIBLE", "ACCESS EFFECT", "IMPACT TOKEN"},
		[][]string{{
			impact.Action, impact.CurrentStatus, boolLabel(impact.Applicable), boolLabel(impact.Immediate),
			boolLabel(impact.Reversible), impact.AccessEffect, impact.ImpactToken,
		}},
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(opts.stdout, impact.Summary); err != nil {
		return err
	}
	return printControlTable(opts,
		[]string{"SESSIONS", "REFRESH", "COMPONENT SESSIONS", "COMPONENT REFRESH", "FAMILIES", "COMPONENTS"},
		[][]string{{
			strconv.FormatInt(impact.Counts.ActiveSessionGrants, 10),
			strconv.FormatInt(impact.Counts.ActiveRefreshTokens, 10),
			strconv.FormatInt(impact.Counts.ActiveComponentSessions, 10),
			strconv.FormatInt(impact.Counts.ActiveComponentRefreshTokens, 10),
			strconv.FormatInt(impact.Counts.ActiveInstallationFamilies, 10),
			strconv.FormatInt(impact.Counts.ActiveClientComponents, 10),
		}},
	)
}

func printUserOperationResult(opts *options, result userOperationResultCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, result)
	}
	if err := printControlTable(opts, []string{"OPERATION", "ACTION", "USER", "STATUS"}, [][]string{{
		result.OperationID, result.Impact.Action, result.User.ID, result.User.Status,
	}}); err != nil {
		return err
	}
	return printUserOperationImpact(opts, result.Impact)
}

func printEffectiveConfiguration(opts *options, document effectiveConfigurationCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, document)
	}
	if err := printControlTable(opts,
		[]string{"SUBJECT", "MODE", "ENVIRONMENT", "REVISION", "FEATURE", "PROTOCOL", "POLICY", "PLAN", "PLAN SOURCE"},
		[][]string{{
			document.Subject.ID, document.EvaluationMode, document.EnvironmentID, document.RevisionID,
			document.Feature, document.Protocol, document.PolicyOutcome, document.LimitPlan, document.LimitPlanSource,
		}},
	); err != nil {
		return err
	}
	inputRows := make([][]string, 0, len(document.Inputs))
	for _, input := range document.Inputs {
		values, _ := json.Marshal(input.Values)
		inputRows = append(inputRows, []string{
			input.Fact, input.Availability, input.Source, strings.Join(input.Keys, ","), string(values), input.Detail,
		})
	}
	if err := printControlTable(opts, []string{"FACT", "AVAILABLE", "SOURCE", "KEYS", "VALUES", "DETAIL"}, inputRows); err != nil {
		return err
	}
	limitRows := make([][]string, 0, len(document.Limits))
	for _, limit := range document.Limits {
		limitRows = append(limitRows, []string{
			strconv.Itoa(limit.Index), limit.Metric, limit.Algorithm, effectiveLimitValueCLI(limit),
			strings.Join(limit.Scope, ","), limit.Source,
		})
	}
	if err := printControlTable(opts, []string{"#", "METRIC", "ALGORITHM", "EFFECTIVE LIMIT", "SCOPE", "SOURCE"}, limitRows); err != nil {
		return err
	}
	routeRows := make([][]string, 0, len(document.Routes))
	for _, route := range document.Routes {
		routeRows = append(routeRows, []string{
			strconv.Itoa(route.Order), route.Route, route.Upstream, route.Model, route.PhysicalModel,
			strconv.FormatInt(route.ConfiguredPriority, 10), strconv.FormatInt(route.ConfiguredWeight, 10),
			route.StickyBy, strconv.FormatInt(route.RetryMaximumAttempts, 10),
			strings.Join(route.FallbackOn, ","), boolLabel(route.Observed), route.Source,
		})
	}
	if err := printControlTable(opts, []string{
		"#", "ROUTE", "UPSTREAM", "MODEL", "PHYSICAL", "PRIORITY", "WEIGHT", "STICKY", "ATTEMPTS", "FALLBACK", "OBSERVED", "SOURCE",
	}, routeRows); err != nil {
		return err
	}
	stageRows := make([][]string, 0, len(document.DecisionStages))
	for _, stage := range document.DecisionStages {
		limitMaximum := ""
		if stage.LimitMaximum != nil {
			limitMaximum = strconv.FormatInt(*stage.LimitMaximum, 10)
		}
		stageRows = append(stageRows, []string{
			strconv.Itoa(int(stage.Number)), stage.Stage, stage.Outcome, stage.FailureCode,
			stage.LimitMetric, limitMaximum, stage.Route, strconv.FormatInt(stage.DurationMS, 10),
		})
	}
	if err := printControlTable(opts, []string{"#", "STAGE", "OUTCOME", "FAILURE", "LIMIT", "MAX", "ROUTE", "MS"}, stageRows); err != nil {
		return err
	}
	for _, warning := range document.Warnings {
		if _, err := fmt.Fprintf(opts.stdout, "warning: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func effectiveLimitValueCLI(limit effectiveLimitCLI) string {
	switch limit.Algorithm {
	case "calendar":
		return strconv.FormatInt(limit.Maximum, 10) + "/" + limit.Window + " " + limit.Timezone
	case "token_bucket":
		return "capacity=" + strconv.FormatInt(limit.Capacity, 10) + " refill=" + limit.RefillPerSecond + "/s"
	case "per_request":
		return strconv.FormatInt(limit.PerRequestMaximum, 10) + "/request"
	case "concurrency":
		return strconv.FormatInt(limit.Maximum, 10) + " concurrent"
	default:
		return "unknown"
	}
}

func printInstallations(opts *options, page installationPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, installation := range page.Items {
		rows = append(rows, []string{installation.ID, installation.UserID, installation.Platform, installation.Status, installation.TrustLevel, formatControlTime(installation.LastSeenAt)})
	}
	if err := printControlTable(opts, []string{"INSTALLATION", "USER", "PLATFORM", "STATUS", "TRUST", "LAST SEEN"}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printInstallation(opts *options, installation installationCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, installation)
	}
	return printControlTable(opts, []string{"INSTALLATION", "USER", "ENVIRONMENT", "PLATFORM", "STATUS", "TRUST", "PROVIDER", "REVOKED"}, [][]string{{
		installation.ID, installation.UserID, installation.EnvironmentID, installation.Platform,
		installation.Status, installation.TrustLevel, installation.AttestationProvider, formatControlTime(installation.RevokedAt),
	}})
}

func validPublicAttemptFailureCode(value string) bool {
	switch value {
	case "canceled", "gateway_error", "protocol_error", "timeout", "unavailable", "upstream_rejected", "unknown":
		return true
	default:
		return false
	}
}

func validEffectiveConfigurationCLI(document effectiveConfigurationCLI) bool {
	expectedSubjectPrefix := id.ApplicationUser
	expectedSubjectKind := "user"
	if document.EvaluationMode == "recorded_request" {
		expectedSubjectPrefix = id.LogicalRequest
		expectedSubjectKind = "request"
	} else if document.EvaluationMode != "current_user_projection" {
		return false
	}
	if document.Subject.Kind != expectedSubjectKind || id.Validate(document.Subject.ID, expectedSubjectPrefix) != nil ||
		id.Validate(document.Subject.UserID, id.ApplicationUser) != nil ||
		(document.Subject.InstallationID != "" && id.Validate(document.Subject.InstallationID, id.Installation) != nil) ||
		(document.Subject.ComponentID != "" && id.Validate(document.Subject.ComponentID, id.ClientComponent) != nil) ||
		id.Validate(document.EnvironmentID, id.Environment) != nil ||
		id.Validate(document.RevisionID, id.ConfigRevision) != nil ||
		!containsEffectiveValueCLI([]string{"development", "staging", "production"}, document.EnvironmentKind) ||
		!operationalIdentifierPattern.MatchString(document.Feature) || !validEffectiveProtocolCLI(document.Protocol) ||
		!containsEffectiveValueCLI([]string{"allowed", "denied", "unavailable"}, document.PolicyOutcome) ||
		(document.DenialReason != "" && !operationalFailurePatternCLI.MatchString(document.DenialReason)) ||
		(document.LimitPlan == "") != (document.LimitPlanSource == "") ||
		(document.LimitPlan != "" && !operationalIdentifierPattern.MatchString(document.LimitPlan)) ||
		!validEffectiveOptionalTextCLI(document.LimitPlanSource, 128) ||
		(document.UserOverrideID != "" && id.Validate(document.UserOverrideID, id.UserOverride) != nil) ||
		(document.ComponentDefinitionID != "" && !operationalIdentifierPattern.MatchString(document.ComponentDefinitionID)) ||
		!validEffectiveOptionalTextCLI(document.MatchedAccessExpression, 4096) ||
		!validEffectiveOptionalTextCLI(document.MatchedLimitExpression, 4096) ||
		len(document.Inputs) > 16 || len(document.Limits) > 64 || len(document.Routes) > 32 ||
		len(document.DecisionStages) > 256 || len(document.Warnings) > 16 {
		return false
	}
	if document.EvaluationMode == "recorded_request" {
		if !containsEffectiveValueCLI([]string{"succeeded", "failed", "denied", "canceled", "unknown"}, document.RequestStatus) {
			return false
		}
	} else if document.RequestStatus != "" || len(document.DecisionStages) != 0 {
		return false
	}
	for _, input := range document.Inputs {
		if !operationalIdentifierPattern.MatchString(input.Fact) ||
			!containsEffectiveValueCLI([]string{"available", "unavailable"}, input.Availability) ||
			!validEffectiveRequiredTextCLI(input.Source, 512) || !validEffectiveRequiredTextCLI(input.Detail, 2048) ||
			len(input.Keys) > 64 || len(input.Values) > 16 || !validEffectiveTextListCLI(input.Keys, 64, false) {
			return false
		}
		for key, value := range input.Values {
			if !validEffectiveRequiredTextCLI(key, 128) || !validEffectiveOptionalTextCLI(value, 512) {
				return false
			}
		}
	}
	for index, limit := range document.Limits {
		if !validEffectiveLimitCLI(limit, index) {
			return false
		}
	}
	selectedRoute := ""
	if document.SelectedRoute != nil {
		if !validEffectiveRouteCLI(*document.SelectedRoute, 0) || document.SelectedRoute.Observed {
			return false
		}
		selectedRoute = document.SelectedRoute.Route
	}
	for index, route := range document.Routes {
		if !validEffectiveRouteCLI(route, index+1) ||
			(document.EvaluationMode == "current_user_projection" && route.Observed) ||
			(document.EvaluationMode == "recorded_request" && !route.Observed) {
			return false
		}
	}
	if document.Output != nil {
		output := document.Output
		if !validEffectiveRequiredTextCLI(output.Source, 512) || output.ConfiguredDefaultMaximumTokens < 0 ||
			output.ConfiguredAbsoluteMaximumTokens < 0 || output.EffectiveDefaultMaximumTokens < 0 ||
			output.EffectiveMaximumTokens < 0 || output.RequestedMaximumTokens < 0 {
			return false
		}
	}
	terminalStage := false
	for index, stage := range document.DecisionStages {
		if terminalStage || !validRequestDecisionStageCLI(stage, int32(index+1), document.RevisionID, document.LimitPlan, selectedRoute) {
			return false
		}
		terminalStage = stage.Outcome != "succeeded"
	}
	for _, warning := range document.Warnings {
		if !validEffectiveRequiredTextCLI(warning, 2048) {
			return false
		}
	}
	return true
}

func validEffectiveProtocolCLI(value string) bool {
	return containsEffectiveValueCLI([]string{
		"openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages", "opaque_http",
	}, value)
}

func validEffectiveLimitCLI(limit effectiveLimitCLI, expectedIndex int) bool {
	if limit.Index != expectedIndex || !operationalIdentifierPattern.MatchString(limit.Metric) || !limit.Hard ||
		!validEffectiveIdentifierListCLI(limit.Scope, 1, 8) || !validEffectiveRequiredTextCLI(limit.Source, 512) {
		return false
	}
	if limit.Metric == "cost_nano_usd" {
		if limit.CostRetryTreatment != "actual_attempts" &&
			(limit.CostRetryTreatment != "initial_attempt_only" || !slices.Contains(limit.Scope, "user")) {
			return false
		}
	} else if limit.CostRetryTreatment != "" {
		return false
	}
	switch limit.Algorithm {
	case "calendar":
		return limit.Maximum > 0 && limit.PerRequestMaximum == 0 && limit.Capacity == 0 && limit.RefillPerSecond == "" &&
			validEffectiveRequiredTextCLI(limit.Window, 32) && len(limit.Window) >= 2 && validEffectiveRequiredTextCLI(limit.Timezone, 128)
	case "token_bucket":
		return limit.Maximum == 0 && limit.PerRequestMaximum == 0 && limit.Capacity > 0 &&
			operationalDecimalPatternCLI.MatchString(limit.RefillPerSecond) && limit.Window == "" && limit.Timezone == ""
	case "per_request":
		return limit.Maximum == 0 && limit.PerRequestMaximum > 0 && limit.Capacity == 0 &&
			limit.RefillPerSecond == "" && limit.Window == "" && limit.Timezone == ""
	case "concurrency":
		return limit.Maximum > 0 && limit.PerRequestMaximum == 0 && limit.Capacity == 0 &&
			limit.RefillPerSecond == "" && limit.Window == "" && limit.Timezone == ""
	default:
		return false
	}
}

func validEffectiveRouteCLI(route effectiveRouteCLI, expectedOrder int) bool {
	if route.Order < 1 || route.Order > 32 || expectedOrder > 0 && route.Order != expectedOrder ||
		!operationalIdentifierPattern.MatchString(route.Route) || !operationalIdentifierPattern.MatchString(route.Upstream) ||
		!operationalIdentifierPattern.MatchString(route.Model) || !validEffectiveRequiredTextCLI(route.PhysicalModel, 512) ||
		!validEffectiveRequiredTextCLI(route.MatchExpression, 4096) || route.ConfiguredPriority < 0 || route.ConfiguredWeight < 1 ||
		!validEffectiveOptionalTextCLI(route.StickyBy, 256) || !validEffectiveIdentifierListCLI(route.FallbackOn, 0, 32) ||
		route.RetryMaximumAttempts < 1 || route.RetryMaximumAttempts > 32 ||
		!validEffectiveIdentifierListCLI(route.RetryOn, 0, 32) || !validEffectiveRequiredTextCLI(route.Source, 512) {
		return false
	}
	return true
}

func validEffectiveIdentifierListCLI(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !operationalIdentifierPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validEffectiveTextListCLI(values []string, maximum int, identifiers bool) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if identifiers && !operationalIdentifierPattern.MatchString(value) ||
			!identifiers && !validEffectiveRequiredTextCLI(value, 128) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validEffectiveRequiredTextCLI(value string, maximum int) bool {
	return value != "" && validEffectiveOptionalTextCLI(value, maximum)
}

func validEffectiveOptionalTextCLI(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func containsEffectiveValueCLI(values []string, value string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func validLogicalRequestCLI(request logicalRequestCLI) bool {
	if id.Validate(request.ID, id.LogicalRequest) != nil ||
		id.Validate(request.EnvironmentID, id.Environment) != nil ||
		id.Validate(request.UserID, id.ApplicationUser) != nil ||
		id.Validate(request.InstallationID, id.Installation) != nil ||
		id.Validate(request.ConfigRevisionID, id.ConfigRevision) != nil ||
		!operationalIdentifierPattern.MatchString(request.SelectedLimitPlan) ||
		!operationalIdentifierPattern.MatchString(request.Feature) {
		return false
	}
	selectedRouteFields := []string{
		request.SelectedRoute, request.SelectedUpstream,
		request.SelectedModel, request.SelectedPhysicalModel,
	}
	selectedRoutePresent := selectedRouteFields[0] != ""
	for _, value := range selectedRouteFields[1:] {
		if (value != "") != selectedRoutePresent {
			return false
		}
	}
	if selectedRoutePresent && (!operationalIdentifierPattern.MatchString(request.SelectedRoute) ||
		!operationalIdentifierPattern.MatchString(request.SelectedUpstream) ||
		!operationalIdentifierPattern.MatchString(request.SelectedModel) ||
		len(request.SelectedPhysicalModel) > 512 || strings.ContainsAny(request.SelectedPhysicalModel, "\r\n\x00")) {
		return false
	}
	componentFields := []string{
		request.InstallationFamilyID, request.ClientComponentID,
		request.ComponentDefinitionID, request.ComponentKind, request.TrustSource,
	}
	componentAware := componentFields[0] != ""
	for _, value := range componentFields[1:] {
		if (value != "") != componentAware {
			return false
		}
	}
	if componentAware && (id.Validate(request.InstallationFamilyID, id.InstallationFamily) != nil ||
		id.Validate(request.ClientComponentID, id.ClientComponent) != nil ||
		!operationalIdentifierPattern.MatchString(request.ComponentDefinitionID) ||
		!operationalIdentifierPattern.MatchString(request.ComponentKind) ||
		!operationalIdentifierPattern.MatchString(request.TrustSource)) {
		return false
	}
	if (request.Framework == "") != (request.FrameworkVersion == "") ||
		request.Framework != "" && (!operationalIdentifierPattern.MatchString(request.Framework) ||
			len(request.FrameworkVersion) > 128 || strings.ContainsAny(request.FrameworkVersion, "\r\n\x00")) {
		return false
	}
	startedAt, err := time.Parse(time.RFC3339Nano, request.StartedAt)
	if err != nil || len(request.Attempts) > 32 || len(request.DecisionStages) > 256 {
		return false
	}
	var completedAt *time.Time
	if request.CompletedAt != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, request.CompletedAt)
		if parseErr != nil || value.Before(startedAt) {
			return false
		}
		completedAt = &value
	}
	switch request.Status {
	case "unknown":
		if completedAt != nil {
			return false
		}
	case "succeeded", "failed", "denied", "canceled":
		if completedAt == nil {
			return false
		}
	default:
		return false
	}
	terminalStage := false
	for index, stage := range request.DecisionStages {
		if terminalStage || !validRequestDecisionStageCLI(
			stage, int32(index+1), request.ConfigRevisionID,
			request.SelectedLimitPlan, request.SelectedRoute,
		) {
			return false
		}
		terminalStage = stage.Outcome != "succeeded"
	}
	for index, attempt := range request.Attempts {
		if !validUpstreamAttemptCLI(attempt, int32(index+1)) {
			return false
		}
	}
	return true
}

func validRequestDecisionStageCLI(
	stage requestDecisionStageCLI,
	expectedNumber int32,
	revisionID, selectedLimitPlan, selectedRoute string,
) bool {
	if stage.Number != expectedNumber || stage.Number < 1 || stage.Number > 256 ||
		stage.ConfigRevisionID != revisionID || stage.DurationMS < 0 {
		return false
	}
	switch stage.Stage {
	case "identity_verified", "client_trust_verified", "client_context_validated",
		"configuration_loaded", "request_inspected", "policy_evaluated",
		"route_selected", "quota_rule_evaluated", "quota_reserved", "lifecycle_recovered":
	default:
		return false
	}
	switch stage.Outcome {
	case "succeeded":
		if stage.FailureCode != "" {
			return false
		}
	case "denied", "failed", "cancelled":
		if stage.FailureCode == "" || !operationalFailurePatternCLI.MatchString(stage.FailureCode) {
			return false
		}
	default:
		return false
	}
	started, err := time.Parse(time.RFC3339Nano, stage.StartedAt)
	if err != nil {
		return false
	}
	completed, err := time.Parse(time.RFC3339Nano, stage.CompletedAt)
	if err != nil || completed.Before(started) || completed.Sub(started).Milliseconds() != stage.DurationMS {
		return false
	}
	if stage.LimitPlanKey != "" && stage.LimitPlanKey != selectedLimitPlan {
		return false
	}
	limitFields := []bool{
		stage.LimitRuleKey != "", stage.LimitMetric != "",
		stage.LimitAlgorithm != "", stage.LimitMaximum != nil,
	}
	for _, present := range limitFields[1:] {
		if present != limitFields[0] {
			return false
		}
	}
	routeFields := []string{stage.Route, stage.Upstream, stage.Model, stage.PhysicalModel}
	routePresent := routeFields[0] != ""
	for _, value := range routeFields[1:] {
		if (value != "") != routePresent {
			return false
		}
	}
	return !routePresent || selectedRoute != "" && stage.Route == selectedRoute
}

func validUpstreamAttemptCLI(attempt upstreamAttemptCLI, expectedNumber int32) bool {
	if attempt.AttemptNumber != expectedNumber || attempt.AttemptNumber < 1 || attempt.AttemptNumber > 32 ||
		id.Validate(attempt.ID, id.UpstreamAttempt) != nil ||
		!operationalIdentifierPattern.MatchString(attempt.Route) ||
		!operationalIdentifierPattern.MatchString(attempt.Upstream) ||
		(attempt.HTTPStatus != 0 && (attempt.HTTPStatus < 100 || attempt.HTTPStatus > 599)) {
		return false
	}
	startedAt, err := time.Parse(time.RFC3339Nano, attempt.StartedAt)
	if err != nil {
		return false
	}
	var firstByteAt, firstTokenAt, completedAt *time.Time
	if attempt.FirstByteAt != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, attempt.FirstByteAt)
		if parseErr != nil || value.Before(startedAt) {
			return false
		}
		firstByteAt = &value
	}
	if attempt.FirstTokenAt != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, attempt.FirstTokenAt)
		if parseErr != nil || firstByteAt == nil || value.Before(*firstByteAt) {
			return false
		}
		firstTokenAt = &value
	}
	if attempt.CompletedAt != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, attempt.CompletedAt)
		if parseErr != nil || value.Before(startedAt) || firstByteAt != nil && firstByteAt.After(value) ||
			firstTokenAt != nil && firstTokenAt.After(value) {
			return false
		}
		completedAt = &value
	}
	switch attempt.Status {
	case "unknown":
		return completedAt == nil && attempt.HTTPStatus == 0 && attempt.FailureCode == ""
	case "succeeded":
		return completedAt != nil && attempt.HTTPStatus >= 200 && attempt.HTTPStatus <= 299 && attempt.FailureCode == ""
	case "failed", "canceled":
		return completedAt != nil && validPublicAttemptFailureCode(attempt.FailureCode)
	default:
		return false
	}
}

func printRequests(opts *options, page logicalRequestPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, request := range page.Items {
		rows = append(rows, []string{
			request.ID, request.ClientComponentID, request.Framework, request.FrameworkVersion,
			request.Feature, request.Protocol, request.SelectedLimitPlan, request.SelectedRoute, request.Status,
			strconv.Itoa(len(request.Attempts)), formatControlTime(request.StartedAt),
		})
	}
	if err := printControlTable(opts, []string{
		"REQUEST", "COMPONENT", "FRAMEWORK", "VERSION", "FEATURE", "PROTOCOL", "PLAN", "ROUTE", "STATUS", "ATTEMPTS", "STARTED",
	}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printRequest(opts *options, request logicalRequestCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, request)
	}
	rows := [][]string{{
		request.ID, request.InstallationFamilyID, request.ClientComponentID,
		request.TrustSource, request.Framework, request.FrameworkVersion,
		request.ConfigRevisionID, request.Feature, request.SelectedLimitPlan, request.SelectedRoute,
		request.Status, strconv.Itoa(len(request.DecisionStages)), strconv.Itoa(len(request.Attempts)), formatControlTime(request.StartedAt),
	}}
	if err := printControlTable(opts, []string{
		"REQUEST", "FAMILY", "COMPONENT", "TRUST", "FRAMEWORK", "VERSION", "REVISION", "FEATURE", "PLAN", "ROUTE", "STATUS", "STAGES", "ATTEMPTS", "STARTED",
	}, rows); err != nil {
		return err
	}
	stageRows := make([][]string, 0, len(request.DecisionStages))
	for _, stage := range request.DecisionStages {
		limitMaximum := ""
		if stage.LimitMaximum != nil {
			limitMaximum = strconv.FormatInt(*stage.LimitMaximum, 10)
		}
		stageRows = append(stageRows, []string{
			strconv.Itoa(int(stage.Number)), stage.Stage, stage.Outcome, stage.FailureCode,
			stage.LimitMetric, limitMaximum, stage.Route, strconv.FormatInt(stage.DurationMS, 10),
		})
	}
	if err := printControlTable(opts, []string{"#", "STAGE", "OUTCOME", "FAILURE", "LIMIT", "MAX", "ROUTE", "MS"}, stageRows); err != nil {
		return err
	}
	if len(request.Attempts) == 0 {
		return nil
	}
	attempts := make([][]string, 0, len(request.Attempts))
	for _, attempt := range request.Attempts {
		httpStatus := "-"
		if attempt.HTTPStatus != 0 {
			httpStatus = strconv.Itoa(attempt.HTTPStatus)
		}
		failureCode := attempt.FailureCode
		if failureCode == "" {
			failureCode = "-"
		}
		attempts = append(attempts, []string{
			strconv.Itoa(int(attempt.AttemptNumber)), attempt.ID, attempt.Route,
			attempt.Upstream, attempt.Model, attempt.Status, formatControlTime(attempt.StartedAt),
			formatControlTime(attempt.FirstByteAt), formatControlTime(attempt.FirstTokenAt),
			formatControlTime(attempt.CompletedAt),
			httpStatus, failureCode,
			attempt.UsageProvenance, attempt.CostProvenance, attempt.CostSource,
		})
	}
	return printControlTable(opts, []string{
		"#", "ATTEMPT", "ROUTE", "UPSTREAM", "MODEL", "STATUS", "STARTED", "FIRST BYTE",
		"FIRST TOKEN", "COMPLETED", "HTTP", "FAILURE", "USAGE SOURCE", "COST PROVENANCE", "COST SOURCE",
	}, attempts)
}

func printUsageSummary(opts *options, summary usageSummaryCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, summary)
	}
	if err := printControlTable(opts, []string{"START", "END", "ACTIVE USERS", "REQUESTS", "REQUESTS/USER", "COST/USER NANO-USD", "INPUT", "OUTPUT", "TOTAL", "COST NANO-USD", "PROVENANCE"}, [][]string{{
		formatControlTime(summary.Start), formatControlTime(summary.End), summary.Analytics.ActiveUsers.String(),
		summary.Analytics.RequestCount.String(), usageFractionText(summary.Analytics.RequestsPerActiveUser),
		usageFractionText(summary.Analytics.CostPerActiveUserNanoUSD), summary.Values.InputTokens.String(),
		summary.Values.OutputTokens.String(), summary.Values.TotalTokens.String(),
		summary.Values.CostNanoUSD.String(), strings.Join(summary.Provenance, ","),
	}}); err != nil {
		return err
	}
	if err := printControlTable(opts, []string{"FAILURE PPM", "QUOTA DENIAL PPM", "ATTESTATION FAILURE PPM", "FALLBACK PPM", "LATENCY P50/P95/P99 MS", "TTFT P50/P95/P99 MS"}, [][]string{{
		summary.Analytics.FailureRate.PartsPerMillion.String(), summary.Analytics.QuotaDenialRate.PartsPerMillion.String(),
		summary.Analytics.AttestationFailureRate.PartsPerMillion.String(), summary.Analytics.FallbackRate.PartsPerMillion.String(),
		usageDistributionText(summary.Analytics.RequestLatency), usageDistributionText(summary.Analytics.TimeToFirstToken),
	}}); err != nil {
		return err
	}
	breakdowns := []struct {
		label string
		value usageBreakdownCLI
	}{
		{label: "FEATURE", value: summary.Analytics.ByFeature},
		{label: "MODEL", value: summary.Analytics.ByModel},
		{label: "SELECTED PLAN", value: summary.Analytics.BySelectedPlan},
	}
	for _, selected := range breakdowns {
		breakdown := selected.value
		rows := make([][]string, 0, len(breakdown.Items))
		for _, item := range breakdown.Items {
			rows = append(rows, []string{item.Key, item.ActiveUsers.String(), item.RequestCount.String(), item.Values.TotalTokens.String(), item.Values.CostNanoUSD.String()})
		}
		if err := printControlTable(opts, []string{selected.label, "ACTIVE USERS", "REQUESTS", "TOTAL TOKENS", "COST NANO-USD"}, rows); err != nil {
			return err
		}
	}
	provenanceRows := make([][]string, 0, len(summary.Analytics.UsageByProvenance))
	for _, item := range summary.Analytics.UsageByProvenance {
		provenanceRows = append(provenanceRows, []string{
			item.Provenance, item.CostSource, item.Values.InputTokens.String(),
			item.Values.OutputTokens.String(), item.Values.TotalTokens.String(),
			item.Values.CostNanoUSD.String(),
		})
	}
	return printControlTable(opts, []string{
		"USAGE PROVENANCE", "COST SOURCE", "INPUT", "OUTPUT", "TOTAL", "COST NANO-USD",
	}, provenanceRows)
}

func usageFractionText(value usageFractionCLI) string {
	return value.Numerator.String() + "/" + value.Denominator.String()
}

func usageDistributionText(value usageDistributionCLI) string {
	return value.P50MS.String() + "/" + value.P95MS.String() + "/" + value.P99MS.String()
}

func printUsageTimeseries(opts *options, series usageTimeseriesCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, series)
	}
	rows := make([][]string, 0, len(series.Points))
	for _, point := range series.Points {
		rows = append(rows, []string{formatControlTime(point.Timestamp), point.Values.LogicalRequests.String(), point.Values.TotalTokens.String(), point.Values.CostNanoUSD.String()})
	}
	return printControlTable(opts, []string{"TIMESTAMP", "REQUESTS", "TOTAL TOKENS", "COST NANO-USD"}, rows)
}

func printAudit(opts *options, page auditPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, event := range page.Items {
		rows = append(rows, []string{formatControlTime(event.Timestamp), event.Actor, event.Source, event.EnvironmentID, event.Action, event.Target, event.Result, event.Reason, event.RequestID})
	}
	if err := printControlTable(opts, []string{"TIME", "ACTOR", "SOURCE", "ENVIRONMENT", "ACTION", "TARGET", "RESULT", "REASON", "REQUEST"}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printAuditEvent(opts *options, event auditEventCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, event)
	}
	if _, err := fmt.Fprintf(opts.stdout,
		"event: %s\ntime: %s\nactor: %s\nsource: %s\nenvironment: %s\naction: %s\ntarget: %s\nresult: %s\nreason: %s\nrequest: %s\n",
		event.ID, formatControlTime(event.Timestamp), event.Actor, event.Source, event.EnvironmentID,
		event.Action, event.Target, event.Result, event.Reason, event.RequestID,
	); err != nil {
		return err
	}
	rows := make([][]string, 0, len(event.Changes))
	for _, change := range event.Changes {
		rows = append(rows, []string{change.Field, change.Operation, change.Classification, boolLabel(change.Redacted)})
	}
	return printControlTable(opts, []string{"FIELD", "OPERATION", "CLASSIFICATION", "REDACTED"}, rows)
}

func printSelfTest(opts *options, run selfTestRunCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, run)
	}
	rows := make([][]string, 0, len(run.Checks))
	for _, check := range run.Checks {
		rows = append(rows, []string{check.Name, check.State, check.SafeDetail})
	}
	if _, err := fmt.Fprintf(opts.stdout, "self-test: %s\nkind: %s\nstate: %s\n", run.ID, run.Kind, run.State); err != nil {
		return err
	}
	return printControlTable(opts, []string{"CHECK", "STATE", "DETAIL"}, rows)
}

func printSelfTestSchedule(opts *options, schedule selfTestScheduleCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, schedule)
	}
	return printControlTable(opts, []string{
		"SCHEDULE", "ENVIRONMENT", "CONFIG REVISION", "CREDENTIAL", "KIND", "TARGET",
		"INTERVAL", "MAX/RUN", "MAX/UTC DAY", "STATUS", "NEXT RUN", "LAST SELF-TEST",
	}, [][]string{{
		schedule.ID, schedule.EnvironmentID, schedule.ConfigRevisionID,
		schedule.AuthorizationCredentialID, schedule.Kind, schedule.Upstream + "/" + schedule.Model,
		strconv.FormatInt(schedule.IntervalSeconds, 10), strconv.FormatInt(schedule.MaxCostNanoUSD, 10),
		strconv.FormatInt(schedule.DailyCostLimitNanoUSD, 10), schedule.Status,
		formatControlTime(schedule.NextRunAt), schedule.LastSelfTestID,
	}})
}

func printSelfTestSchedulePage(opts *options, page selfTestSchedulePageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	for _, schedule := range page.Items {
		if err := printSelfTestSchedule(opts, schedule); err != nil {
			return err
		}
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}
