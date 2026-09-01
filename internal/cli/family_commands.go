package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

type componentDelegationCLI struct {
	ID                      string   `json:"id"`
	ParentComponentID       string   `json:"parent_component_id"`
	FeatureScopes           []string `json:"feature_scopes"`
	ConfigurationRevisionID string   `json:"configuration_revision_id"`
	TrustLevel              string   `json:"trust_level"`
	AttestationProvider     string   `json:"attestation_provider"`
	ExpiresAt               string   `json:"expires_at"`
	ConsumedAt              string   `json:"consumed_at,omitempty"`
	RevokedAt               string   `json:"revoked_at,omitempty"`
}

type clientComponentCLI struct {
	ID                       string                  `json:"id"`
	InstallationFamilyID     string                  `json:"installation_family_id"`
	UserID                   string                  `json:"user_id"`
	EnvironmentID            string                  `json:"environment_id"`
	DefinitionID             string                  `json:"definition_id"`
	Kind                     string                  `json:"kind"`
	Platform                 string                  `json:"platform"`
	IsRoot                   bool                    `json:"is_root"`
	Status                   string                  `json:"status"`
	ComponentKeyID           string                  `json:"component_key_id"`
	DPoPJKT                  string                  `json:"dpop_jkt"`
	KeyStorageClaim          string                  `json:"key_storage_claim"`
	TrustSource              string                  `json:"trust_source"`
	AttestationProvider      string                  `json:"attestation_provider,omitempty"`
	ParentComponentID        string                  `json:"parent_component_id,omitempty"`
	ParentAttestationEventID string                  `json:"parent_attestation_event_id,omitempty"`
	TrustVerifiedAt          string                  `json:"trust_verified_at,omitempty"`
	TrustExpiresAt           string                  `json:"trust_expires_at,omitempty"`
	GrantedFeatures          []string                `json:"granted_features"`
	AppVersion               string                  `json:"app_version,omitempty"`
	SDKVersion               string                  `json:"sdk_version,omitempty"`
	SessionFamilyID          string                  `json:"session_family_id,omitempty"`
	SessionStatus            string                  `json:"session_status,omitempty"`
	SessionExpiresAt         string                  `json:"session_expires_at,omitempty"`
	SessionFailureCount      json.Number             `json:"session_failure_count"`
	RefreshReuseCount        json.Number             `json:"refresh_reuse_count"`
	RequestCount             json.Number             `json:"request_count"`
	Usage                    usageValuesCLI          `json:"usage"`
	Delegation               *componentDelegationCLI `json:"delegation,omitempty"`
	CreatedAt                string                  `json:"created_at"`
	UpdatedAt                string                  `json:"updated_at"`
	LastSeenAt               string                  `json:"last_seen_at"`
	RevokedAt                string                  `json:"revoked_at,omitempty"`
	RevocationReason         string                  `json:"revocation_reason,omitempty"`
}

type installationFamilyCLI struct {
	ID                 string               `json:"id"`
	UserID             string               `json:"user_id"`
	EnvironmentID      string               `json:"environment_id"`
	Platform           string               `json:"platform"`
	Status             string               `json:"status"`
	RootComponentID    string               `json:"root_component_id"`
	RootTrustSource    string               `json:"root_trust_source"`
	RootTrustExpiresAt string               `json:"root_trust_expires_at,omitempty"`
	ComponentCount     json.Number          `json:"component_count"`
	RequestCount       json.Number          `json:"request_count"`
	Usage              usageValuesCLI       `json:"usage"`
	CreatedAt          string               `json:"created_at"`
	UpdatedAt          string               `json:"updated_at"`
	LastSeenAt         string               `json:"last_seen_at"`
	RevokedAt          string               `json:"revoked_at,omitempty"`
	RevocationReason   string               `json:"revocation_reason,omitempty"`
	Components         []clientComponentCLI `json:"components,omitempty"`
}

type installationFamilyPageCLI struct {
	Items []installationFamilyCLI `json:"items"`
	Page  pageInfoCLI             `json:"page"`
}

type clientComponentPageCLI struct {
	Items []clientComponentCLI `json:"items"`
	Page  pageInfoCLI          `json:"page"`
}

func newInstallationFamiliesCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "installation-families", Aliases: []string{"families"},
		Short: "Inspect and control Installation Families through the Admin API",
	}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newInstallationFamiliesListCommand(opts, values),
		newInstallationFamiliesInspectCommand(opts, values),
		newInstallationFamiliesRequireRenewalCommand(opts, values),
		newInstallationFamiliesRevokeCommand(opts, values),
	)
	return command
}

func newInstallationFamiliesListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, userID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List families with root trust and aggregate usage", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil ||
				(userID != "" && id.Validate(userID, id.ApplicationUser) != nil) {
				return errors.New("environment or application-user ID is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			if userID != "" {
				query.Set("user_id", userID)
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page installationFamilyPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/installation-families", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			for _, family := range page.Items {
				if !validInstallationFamilyCLI(family, false) {
					return errors.New("admin API returned a non-conforming installation-family document")
				}
			}
			return printInstallationFamilies(opts, page)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&userID, "user", "", "optional Application User ID")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of families to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newInstallationFamiliesRequireRenewalCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var reason string
	command := &cobra.Command{
		Use: "require-renewal FAMILY_ID", Short: "Expire family trust and refresh credentials without revoking current access grants", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.InstallationFamily) != nil {
				return errors.New("installation-family ID is invalid")
			}
			reason, err := validCLIRevocationReason(reason)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var family installationFamilyCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/installation-families/"+args[0]+"/require-renewal", nil, map[string]string{"reason": reason}, http.StatusOK, &family); err != nil {
				return err
			}
			if !validInstallationFamilyCLI(family, false) || family.Status != "active" || family.RootTrustExpiresAt == "" {
				return errors.New("admin API returned a non-conforming family renewal document")
			}
			return printInstallationFamily(opts, family)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "redaction-safe administrative reason (maximum 100 characters)")
	return command
}

func newInstallationFamiliesInspectCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "inspect FAMILY_ID", Short: "Inspect one family and its component trust graph", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.InstallationFamily) != nil {
				return errors.New("installation-family ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var family installationFamilyCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/installation-families/"+args[0], nil, nil, http.StatusOK, &family); err != nil {
				return err
			}
			if !validInstallationFamilyCLI(family, true) {
				return errors.New("admin API returned a non-conforming installation-family document")
			}
			return printInstallationFamily(opts, family)
		},
	}
}

func newInstallationFamiliesRevokeCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var reason string
	command := &cobra.Command{
		Use: "revoke FAMILY_ID", Short: "Revoke a family and every component credential", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.InstallationFamily) != nil {
				return errors.New("installation-family ID is invalid")
			}
			reason, err := validCLIRevocationReason(reason)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var family installationFamilyCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/installation-families/"+args[0]+"/revoke", nil, map[string]string{"reason": reason}, http.StatusOK, &family); err != nil {
				return err
			}
			if !validInstallationFamilyCLI(family, false) || family.Status != "revoked" {
				return errors.New("admin API returned a non-conforming family revocation document")
			}
			return printInstallationFamily(opts, family)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "redaction-safe administrative reason (maximum 100 characters)")
	return command
}

func newClientComponentsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "components", Short: "Inspect and control independently keyed client components",
	}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newClientComponentsListCommand(opts, values),
		newClientComponentsInspectCommand(opts, values),
		newClientComponentsRequireReattestationCommand(opts, values),
		newClientComponentsRevokeCommand(opts, values),
	)
	return command
}

func newClientComponentsRequireReattestationCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var reason string
	command := &cobra.Command{
		Use: "require-reattestation COMPONENT_ID", Short: "Expire component trust and refresh credentials without revoking current access grants", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ClientComponent) != nil {
				return errors.New("client-component ID is invalid")
			}
			reason, err := validCLIRevocationReason(reason)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var component clientComponentCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/client-components/"+args[0]+"/require-reattestation", nil, map[string]string{"reason": reason}, http.StatusOK, &component); err != nil {
				return err
			}
			if !validClientComponentCLI(component) || component.Status != "active" || component.TrustExpiresAt == "" {
				return errors.New("admin API returned a non-conforming component re-attestation document")
			}
			return printClientComponent(opts, component)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "redaction-safe administrative reason (maximum 100 characters)")
	return command
}

func newClientComponentsListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, familyID, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List component trust, sessions, feature grants, and usage", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil ||
				(familyID != "" && id.Validate(familyID, id.InstallationFamily) != nil) {
				return errors.New("environment or installation-family ID is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			if familyID != "" {
				query.Set("installation_family_id", familyID)
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page clientComponentPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/client-components", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			for _, component := range page.Items {
				if !validClientComponentCLI(component) {
					return errors.New("admin API returned a non-conforming client-component document")
				}
			}
			return printClientComponents(opts, page)
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&familyID, "family", "", "optional Installation Family ID")
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of components to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

func newClientComponentsInspectCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "inspect COMPONENT_ID", Short: "Inspect component trust provenance, session, and usage", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ClientComponent) != nil {
				return errors.New("client-component ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var component clientComponentCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/client-components/"+args[0], nil, nil, http.StatusOK, &component); err != nil {
				return err
			}
			if !validClientComponentCLI(component) {
				return errors.New("admin API returned a non-conforming client-component document")
			}
			return printClientComponent(opts, component)
		},
	}
}

func newClientComponentsRevokeCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var reason string
	command := &cobra.Command{
		Use: "revoke COMPONENT_ID", Short: "Revoke one component subtree without revoking siblings", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ClientComponent) != nil {
				return errors.New("client-component ID is invalid")
			}
			reason, err := validCLIRevocationReason(reason)
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var component clientComponentCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/client-components/"+args[0]+"/revoke", nil, map[string]string{"reason": reason}, http.StatusOK, &component); err != nil {
				return err
			}
			if !validClientComponentCLI(component) || component.Status != "revoked" {
				return errors.New("admin API returned a non-conforming component revocation document")
			}
			return printClientComponent(opts, component)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "redaction-safe administrative reason (maximum 100 characters)")
	return command
}

func validCLIRevocationReason(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 100 ||
		strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("revocation reason must not exceed 100 safe characters")
	}
	return value, nil
}

func validInstallationFamilyCLI(family installationFamilyCLI, detail bool) bool {
	componentCount, componentOK := nonNegativeJSONInteger(family.ComponentCount)
	_, requestsOK := nonNegativeJSONInteger(family.RequestCount)
	if id.Validate(family.ID, id.InstallationFamily) != nil ||
		id.Validate(family.RootComponentID, id.ClientComponent) != nil ||
		!operationalIdentifierPattern.MatchString(family.RootTrustSource) ||
		!componentOK || !requestsOK || componentCount < 1 || componentCount > 128 ||
		!validUsageValuesCLI(family.Usage) {
		return false
	}
	switch family.Status {
	case "active", "suspended", "revoked":
	default:
		return false
	}
	if detail && (int64(len(family.Components)) != componentCount || len(family.Components) > 128) {
		return false
	}
	for _, component := range family.Components {
		if component.InstallationFamilyID != family.ID || !validClientComponentCLI(component) {
			return false
		}
	}
	return true
}

func validClientComponentCLI(component clientComponentCLI) bool {
	_, failuresOK := nonNegativeJSONInteger(component.SessionFailureCount)
	_, reuseOK := nonNegativeJSONInteger(component.RefreshReuseCount)
	_, requestsOK := nonNegativeJSONInteger(component.RequestCount)
	if id.Validate(component.ID, id.ClientComponent) != nil ||
		id.Validate(component.InstallationFamilyID, id.InstallationFamily) != nil ||
		id.Validate(component.ComponentKeyID, id.ComponentKey) != nil ||
		!operationalIdentifierPattern.MatchString(component.DefinitionID) ||
		!operationalIdentifierPattern.MatchString(component.Kind) ||
		!operationalIdentifierPattern.MatchString(component.TrustSource) ||
		len(component.DPoPJKT) != 43 || !failuresOK || !reuseOK || !requestsOK ||
		!validUsageValuesCLI(component.Usage) || len(component.GrantedFeatures) > 256 {
		return false
	}
	if component.IsRoot != (component.ParentComponentID == "") {
		return false
	}
	if component.ParentComponentID != "" && id.Validate(component.ParentComponentID, id.ClientComponent) != nil {
		return false
	}
	switch component.Status {
	case "active", "suspended", "revoked", "replaced":
	default:
		return false
	}
	if (component.SessionFamilyID == "") != (component.SessionStatus == "") {
		return false
	}
	if component.SessionFamilyID != "" {
		if id.Validate(component.SessionFamilyID, id.ComponentSession) != nil {
			return false
		}
		switch component.SessionStatus {
		case "active", "revoked", "expired", "replaced":
		default:
			return false
		}
	}
	seen := make(map[string]struct{}, len(component.GrantedFeatures))
	for _, feature := range component.GrantedFeatures {
		if !operationalIdentifierPattern.MatchString(feature) {
			return false
		}
		if _, duplicate := seen[feature]; duplicate {
			return false
		}
		seen[feature] = struct{}{}
	}
	if component.Delegation != nil {
		if id.Validate(component.Delegation.ID, id.ComponentDelegation) != nil ||
			id.Validate(component.Delegation.ParentComponentID, id.ClientComponent) != nil ||
			id.Validate(component.Delegation.ConfigurationRevisionID, id.ConfigRevision) != nil {
			return false
		}
	}
	return true
}

func nonNegativeJSONInteger(value json.Number) (int64, bool) {
	parsed, err := strconv.ParseInt(value.String(), 10, 64)
	return parsed, err == nil && parsed >= 0
}

func validUsageValuesCLI(values usageValuesCLI) bool {
	for _, value := range []json.Number{
		values.LogicalRequests, values.InputTokens, values.OutputTokens,
		values.TotalTokens, values.CostNanoUSD,
	} {
		if _, ok := nonNegativeJSONInteger(value); !ok {
			return false
		}
	}
	return true
}

func printInstallationFamilies(opts *options, page installationFamilyPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, family := range page.Items {
		rows = append(rows, []string{
			family.ID, family.UserID, family.Platform, family.Status,
			family.RootTrustSource, family.ComponentCount.String(), family.RequestCount.String(),
			family.Usage.TotalTokens.String(), family.Usage.CostNanoUSD.String(),
			formatControlTime(family.LastSeenAt),
		})
	}
	if err := printControlTable(opts, []string{
		"FAMILY", "USER", "PLATFORM", "STATUS", "ROOT TRUST", "COMPONENTS",
		"REQUESTS", "TOTAL TOKENS", "COST NANO-USD", "LAST SEEN",
	}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printInstallationFamily(opts *options, family installationFamilyCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, family)
	}
	if err := printControlTable(opts, []string{
		"FAMILY", "USER", "ENVIRONMENT", "PLATFORM", "STATUS", "ROOT", "TRUST",
		"COMPONENTS", "REQUESTS", "TOTAL TOKENS", "COST NANO-USD", "LAST SEEN",
	}, [][]string{{
		family.ID, family.UserID, family.EnvironmentID, family.Platform, family.Status,
		family.RootComponentID, family.RootTrustSource, family.ComponentCount.String(),
		family.RequestCount.String(), family.Usage.TotalTokens.String(),
		family.Usage.CostNanoUSD.String(), formatControlTime(family.LastSeenAt),
	}}); err != nil {
		return err
	}
	if len(family.Components) == 0 {
		return nil
	}
	return printClientComponents(opts, clientComponentPageCLI{Items: family.Components})
}

func printClientComponents(opts *options, page clientComponentPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, component := range page.Items {
		parent := component.ParentComponentID
		if parent == "" {
			parent = "root"
		}
		rows = append(rows, []string{
			component.ID, component.InstallationFamilyID, component.DefinitionID,
			component.Kind, parent, component.Status, component.TrustSource,
			strings.Join(component.GrantedFeatures, ","), component.SessionStatus,
			component.SessionFailureCount.String(),
			component.RequestCount.String(), component.Usage.CostNanoUSD.String(),
		})
	}
	if err := printControlTable(opts, []string{
		"COMPONENT", "FAMILY", "DEFINITION", "KIND", "PARENT", "STATUS", "TRUST",
		"FEATURES", "SESSION", "CLOSED SESSIONS", "REQUESTS", "COST NANO-USD",
	}, rows); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printClientComponent(opts *options, component clientComponentCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, component)
	}
	if err := printControlTable(opts, []string{
		"COMPONENT", "FAMILY", "DEFINITION", "KIND", "STATUS", "TRUST", "PROVIDER",
		"PARENT", "KEY STORAGE", "FEATURES", "SESSION", "CLOSED SESSIONS", "REUSE", "REQUESTS",
		"TOTAL TOKENS", "COST NANO-USD",
	}, [][]string{{
		component.ID, component.InstallationFamilyID, component.DefinitionID,
		component.Kind, component.Status, component.TrustSource,
		component.AttestationProvider, component.ParentComponentID,
		component.KeyStorageClaim, strings.Join(component.GrantedFeatures, ","),
		component.SessionStatus, component.SessionFailureCount.String(),
		component.RefreshReuseCount.String(),
		component.RequestCount.String(), component.Usage.TotalTokens.String(),
		component.Usage.CostNanoUSD.String(),
	}}); err != nil {
		return err
	}
	if component.Delegation == nil {
		return nil
	}
	return printControlTable(opts, []string{
		"DELEGATION", "PARENT", "TRUST", "PROVIDER", "FEATURES", "CONFIG", "EXPIRES", "CONSUMED", "REVOKED",
	}, [][]string{{
		component.Delegation.ID, component.Delegation.ParentComponentID,
		component.Delegation.TrustLevel, component.Delegation.AttestationProvider,
		strings.Join(component.Delegation.FeatureScopes, ","),
		component.Delegation.ConfigurationRevisionID,
		formatControlTime(component.Delegation.ExpiresAt),
		formatControlTime(component.Delegation.ConsumedAt),
		formatControlTime(component.Delegation.RevokedAt),
	}})
}
