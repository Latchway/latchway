package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

type controlCommandOptions struct {
	tokenEnvironment string
}

var operationalIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

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
	CompletedAt     string          `json:"completed_at,omitempty"`
	Status          string          `json:"status"`
	HTTPStatus      int             `json:"http_status,omitempty"`
	FailureCode     string          `json:"failure_code,omitempty"`
	Usage           *usageValuesCLI `json:"usage,omitempty"`
	UsageProvenance string          `json:"usage_provenance"`
	CostProvenance  string          `json:"cost_provenance"`
	CostSource      string          `json:"cost_source,omitempty"`
}

type logicalRequestCLI struct {
	ID             string               `json:"id"`
	EnvironmentID  string               `json:"environment_id"`
	UserID         string               `json:"user_id"`
	InstallationID string               `json:"installation_id"`
	Feature        string               `json:"feature"`
	Protocol       string               `json:"protocol"`
	StartedAt      string               `json:"started_at"`
	CompletedAt    string               `json:"completed_at,omitempty"`
	Status         string               `json:"status"`
	Usage          *usageValuesCLI      `json:"usage,omitempty"`
	Attempts       []upstreamAttemptCLI `json:"attempts"`
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
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Result    string         `json:"result"`
	RequestID string         `json:"request_id"`
	Summary   map[string]any `json:"summary"`
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
	ID          string             `json:"id"`
	Kind        string             `json:"kind"`
	State       string             `json:"state"`
	CreatedAt   string             `json:"created_at"`
	CompletedAt string             `json:"completed_at,omitempty"`
	Checks      []selfTestCheckCLI `json:"checks"`
}

type systemStatusCLI struct {
	ServerVersion         string `json:"server_version"`
	ContractVersion       string `json:"contract_version"`
	ProtocolVersions      []int  `json:"protocol_versions"`
	Role                  string `json:"role"`
	DatabaseSchemaVersion string `json:"database_schema_version"`
	Ready                 bool   `json:"ready"`
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
	command := &cobra.Command{Use: "users", Short: "Inspect and block pseudonymous application users through the Admin API"}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newUsersListCommand(opts, values), newUsersInspectCommand(opts, values),
		newUsersMutationCommand(opts, values, "block"), newUsersMutationCommand(opts, values, "unblock"),
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

func newUsersMutationCommand(opts *options, root *controlCommandOptions, action string) *cobra.Command {
	var environmentID string
	command := &cobra.Command{
		Use: action + " USER_ID", Short: strings.ToUpper(action[:1]) + action[1:] + " a user through the canonical Admin API", Args: cobra.ExactArgs(1),
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
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/users/"+args[0]+"/"+action, query, nil, http.StatusOK, &user); err != nil {
				return err
			}
			return printUser(opts, user)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	_ = command.MarkFlagRequired("environment")
	return command
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
	command.AddCommand(newRequestsListCommand(opts, values), newRequestsInspectCommand(opts, values))
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
					return errors.New("Admin API returned a non-conforming request document")
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
				return errors.New("Admin API returned a non-conforming request document")
			}
			return printRequest(opts, request)
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
	var organizationID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "audit", Short: "Inspect append-only redaction-safe administrative audit events", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(organizationID, id.Organization) != nil || pageSize < 1 || pageSize > 200 {
				return errors.New("organization ID or page size is invalid")
			}
			query := url.Values{"organization_id": []string{organizationID}, "page_size": []string{strconv.Itoa(pageSize)}}
			if cursor != "" {
				query.Set("cursor", cursor)
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
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of events to return (1-200)")
	_ = command.MarkFlagRequired("organization")
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
			if opts.output == "json" {
				return printControlJSON(opts, status)
			}
			versions := make([]string, len(status.ProtocolVersions))
			for index, version := range status.ProtocolVersions {
				versions[index] = strconv.Itoa(version)
			}
			return printControlTable(opts, []string{"SERVER", "CONTRACT", "PROTOCOLS", "ROLE", "SCHEMA", "READY"}, [][]string{{
				status.ServerVersion, status.ContractVersion, strings.Join(versions, ","), status.Role,
				status.DatabaseSchemaVersion, boolLabel(status.Ready),
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
	for _, kind := range []string{"upstream", "openrouter"} {
		kind := kind
		var environmentID, upstream, model string
		var maxCost int64
		subcommand := &cobra.Command{
			Use: kind, Short: verifyShort(kind), Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				credentialInputValid := secretNamePattern.MatchString(upstream) &&
					secretNamePattern.MatchString(model) && maxCost >= 1 && maxCost <= 1_000_000_000
				if id.Validate(environmentID, id.Environment) != nil || !credentialInputValid {
					return errors.New("verification environment, configured selection, or cost bound is invalid")
				}
				request := map[string]any{"kind": kind, "environment_id": environmentID}
				if upstream != "" {
					request["upstream"] = upstream
				}
				if model != "" {
					request["model"] = model
				}
				if maxCost != 0 {
					request["max_cost_nano_usd"] = maxCost
				}
				client, err := newControlAPIClient(opts, values.tokenEnvironment)
				if err != nil {
					return err
				}
				var run selfTestRunCLI
				if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/self-tests", nil, request, http.StatusAccepted, &run); err != nil {
					return err
				}
				return printSelfTest(opts, run)
			},
		}
		subcommand.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
		subcommand.Flags().StringVar(&upstream, "upstream", "", "server-owned upstream identifier")
		subcommand.Flags().StringVar(&model, "model", "", "active configured model identifier")
		subcommand.Flags().Int64Var(&maxCost, "max-cost-nano-usd", 10_000_000, "hard two-request verification cost ceiling (10,000,000 is US$0.01)")
		_ = subcommand.MarkFlagRequired("environment")
		command.AddCommand(subcommand)
	}
	return command
}

func verifyShort(kind string) string {
	switch kind {
	case "upstream":
		return "Run bounded verification against an active server-owned upstream and model"
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

func validLogicalRequestCLI(request logicalRequestCLI) bool {
	startedAt, err := time.Parse(time.RFC3339Nano, request.StartedAt)
	if err != nil || len(request.Attempts) > 32 {
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
	case "succeeded", "failed", "canceled":
		if completedAt == nil {
			return false
		}
	default:
		return false
	}
	for index, attempt := range request.Attempts {
		if !validUpstreamAttemptCLI(attempt, int32(index+1)) {
			return false
		}
	}
	return true
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
	var firstByteAt, completedAt *time.Time
	if attempt.FirstByteAt != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, attempt.FirstByteAt)
		if parseErr != nil || value.Before(startedAt) {
			return false
		}
		firstByteAt = &value
	}
	if attempt.CompletedAt != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, attempt.CompletedAt)
		if parseErr != nil || value.Before(startedAt) || firstByteAt != nil && firstByteAt.After(value) {
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
		rows = append(rows, []string{request.ID, request.Feature, request.Protocol, request.Status, strconv.Itoa(len(request.Attempts)), formatControlTime(request.StartedAt)})
	}
	if err := printControlTable(opts, []string{"REQUEST", "FEATURE", "PROTOCOL", "STATUS", "ATTEMPTS", "STARTED"}, rows); err != nil {
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
	rows := [][]string{{request.ID, request.Feature, request.Status, strconv.Itoa(len(request.Attempts)), formatControlTime(request.StartedAt)}}
	if err := printControlTable(opts, []string{"REQUEST", "FEATURE", "STATUS", "ATTEMPTS", "STARTED"}, rows); err != nil {
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
			formatControlTime(attempt.FirstByteAt), formatControlTime(attempt.CompletedAt),
			httpStatus, failureCode,
			attempt.UsageProvenance, attempt.CostProvenance, attempt.CostSource,
		})
	}
	return printControlTable(opts, []string{
		"#", "ATTEMPT", "ROUTE", "UPSTREAM", "MODEL", "STATUS", "STARTED", "FIRST BYTE",
		"COMPLETED", "HTTP", "FAILURE", "USAGE SOURCE", "COST PROVENANCE", "COST SOURCE",
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
		rows = append(rows, []string{formatControlTime(event.Timestamp), event.Actor, event.Action, event.Target, event.Result, event.RequestID})
	}
	if err := printControlTable(opts, []string{"TIME", "ACTOR", "ACTION", "TARGET", "RESULT", "REQUEST"}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
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
