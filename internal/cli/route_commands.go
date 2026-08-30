package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/spf13/cobra"
)

const maxSimulationClaimsBytes = 64 << 10

type routeSimulationLimitCLI struct {
	Metric            string   `json:"metric"`
	Algorithm         string   `json:"algorithm"`
	Scope             []string `json:"scope"`
	Window            string   `json:"window,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`
	Maximum           int64    `json:"maximum,omitempty"`
	PerRequestMaximum int64    `json:"per_request_maximum,omitempty"`
	Capacity          int64    `json:"capacity,omitempty"`
	RefillPerSecond   string   `json:"refill_per_second,omitempty"`
	Hard              bool     `json:"hard"`
}

type routeSimulationFactUseCLI struct {
	Fact        string `json:"fact"`
	Role        string `json:"role"`
	AffectsCEL  bool   `json:"affects_cel"`
	Explanation string `json:"explanation"`
}

type routeSimulationAllocationCLI struct {
	Metric     string `json:"metric"`
	Algorithm  string `json:"algorithm"`
	Units      int64  `json:"units"`
	Applicable bool   `json:"applicable"`
	Durable    bool   `json:"durable"`
}

type routeSimulationReservationCLI struct {
	AppliedOutputMaximum int64                          `json:"applied_output_maximum"`
	TotalTokenBound      int64                          `json:"total_token_bound"`
	CostNanoUSDBound     int64                          `json:"cost_nano_usd_bound"`
	CostBoundKnown       bool                           `json:"cost_bound_known"`
	PricingCatalog       string                         `json:"pricing_catalog,omitempty"`
	InputAccounting      map[string]any                 `json:"input_accounting"`
	Allocations          []routeSimulationAllocationCLI `json:"allocations"`
}

type routeSimulationCandidateCLI struct {
	Route         string   `json:"route"`
	Upstream      string   `json:"upstream"`
	Model         string   `json:"model"`
	PhysicalModel string   `json:"physical_model"`
	FallbackOn    []string `json:"fallback_on"`
}

type routeSimulationResultCLI struct {
	Allowed                 bool                           `json:"allowed"`
	Feature                 string                         `json:"feature"`
	ApplicationID           string                         `json:"application_id"`
	EnvironmentID           string                         `json:"environment_id"`
	RevisionID              string                         `json:"revision_id"`
	EnvironmentKind         string                         `json:"environment_kind"`
	Facts                   map[string]any                 `json:"facts"`
	FactUsage               []routeSimulationFactUseCLI    `json:"fact_usage"`
	Protocol                string                         `json:"protocol,omitempty"`
	MatchedAccessExpression string                         `json:"matched_access_expression,omitempty"`
	LimitPlan               string                         `json:"limit_plan,omitempty"`
	Limits                  []routeSimulationLimitCLI      `json:"limits,omitempty"`
	Route                   string                         `json:"route,omitempty"`
	Upstream                string                         `json:"upstream,omitempty"`
	Model                   string                         `json:"model,omitempty"`
	PhysicalModel           string                         `json:"physical_model,omitempty"`
	FallbackSequence        []routeSimulationCandidateCLI  `json:"fallback_sequence,omitempty"`
	PricingConfidence       string                         `json:"pricing_confidence,omitempty"`
	Reservation             *routeSimulationReservationCLI `json:"reservation,omitempty"`
	Warnings                []string                       `json:"warnings,omitempty"`
	Explanation             []string                       `json:"explanation"`
}

func newRoutesCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{Use: "routes", Short: "Explain exact compiled route decisions without dispatch"}
	addControlTokenFlag(command, values)
	command.AddCommand(newRoutesSimulateCommand(opts, values))
	return command
}

func newRoutesSimulateCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var feature, platform, trustLevel, claimsFile, appVersion string
	var authenticated, streaming bool
	var requestedInput, requestedOutput, rewrittenRequestBytes, framingUnitCount int64
	var imageUnits, toolCalls int64
	command := &cobra.Command{
		Use: "simulate REVISION_ID", Short: "Run the exact production resolver against a valid or active revision", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.ConfigRevision) != nil || !secretNamePattern.MatchString(feature) || !validSimulationPlatform(platform) || !validSimulationTrust(trustLevel) {
				return errors.New("revision, feature, platform, or trust level is invalid")
			}
			if requestedInput < 0 || requestedOutput < 0 || requestedInput > 100_000_000 || requestedOutput > 100_000_000 ||
				rewrittenRequestBytes < 0 || rewrittenRequestBytes > 100<<20 || framingUnitCount < 0 || framingUnitCount > 4096 ||
				imageUnits < 0 || imageUnits > 1_000_000 || toolCalls < 0 || toolCalls > 1_000_000 ||
				len(appVersion) > 128 || strings.ContainsAny(appVersion, "\r\n\x00") {
				return errors.New("simulated request bounds are invalid")
			}
			claims, err := readSimulationClaims(claimsFile)
			if err != nil {
				return err
			}
			requestFacts := map[string]any{"streaming": streaming}
			if appVersion != "" {
				requestFacts["app_version"] = appVersion
			}
			if requestedInput != 0 {
				requestFacts["requested_input_tokens"] = requestedInput
			}
			if requestedOutput != 0 {
				requestFacts["requested_output_max"] = requestedOutput
			}
			if rewrittenRequestBytes != 0 {
				requestFacts["rewritten_request_bytes"] = rewrittenRequestBytes
			}
			if framingUnitCount != 0 {
				requestFacts["framing_unit_count"] = framingUnitCount
			}
			if imageUnits != 0 {
				requestFacts["image_units"] = imageUnits
			}
			if toolCalls != 0 {
				requestFacts["tool_calls"] = toolCalls
			}
			request := map[string]any{
				"feature": feature, "platform": platform, "trust_level": trustLevel,
				"principal": map[string]any{"authenticated": authenticated, "claims": claims},
				"request":   requestFacts,
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var result routeSimulationResultCLI
			if _, err := client.do(cmd.Context(), http.MethodPost, "/admin/v1/config-revisions/"+args[0]+"/simulate", nil, request, http.StatusOK, &result); err != nil {
				return err
			}
			return printRouteSimulation(opts, result)
		},
	}
	command.Flags().StringVar(&feature, "feature", "", "client-visible feature identifier")
	command.Flags().StringVar(&platform, "platform", "", "ios, android, web, react_native_ios, react_native_android, or node")
	command.Flags().StringVar(&trustLevel, "trust-level", "none", "normalized simulated attestation trust")
	command.Flags().StringVar(&claimsFile, "claims-file", "", "normalized claims JSON object from a regular file (maximum 64 KiB)")
	command.Flags().StringVar(&appVersion, "app-version", "", "simulated client app version (reported as currently non-decisional)")
	command.Flags().BoolVar(&authenticated, "authenticated", true, "simulate an authenticated principal")
	command.Flags().BoolVar(&streaming, "streaming", false, "simulate a streaming request")
	command.Flags().Int64Var(&requestedInput, "requested-input-tokens", 0, "requested input-token estimate (reported as currently non-decisional)")
	command.Flags().Int64Var(&requestedOutput, "requested-output-max", 0, "requested output-token maximum used by the production clamp and reservation projection")
	command.Flags().Int64Var(&rewrittenRequestBytes, "rewritten-request-bytes", 0, "hypothetical exact post-rewrite bytes required by trusted input projection")
	command.Flags().Int64Var(&framingUnitCount, "framing-unit-count", 0, "hypothetical exact message/item/input count required by trusted input projection")
	command.Flags().Int64Var(&imageUnits, "image-units", 0, "hypothetical exact structured image count used by per-request guards")
	command.Flags().Int64Var(&toolCalls, "tool-calls", 0, "hypothetical exact structured tool-call count used by per-request guards")
	_ = command.MarkFlagRequired("feature")
	_ = command.MarkFlagRequired("platform")
	return command
}

func readSimulationClaims(path string) (map[string]any, error) {
	if path == "" {
		return map[string]any{}, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect claims file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxSimulationClaimsBytes {
		return nil, errors.New("claims input must be a regular file no larger than 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open claims file: %w", err)
	}
	value, err := jsonsafe.DecodeReader(file, maxSimulationClaimsBytes)
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("close claims file: %w", closeErr)
	}
	if err != nil {
		return nil, fmt.Errorf("read normalized claims JSON: %w", err)
	}
	claims, ok := value.(map[string]any)
	if !ok || len(claims) > 64 {
		return nil, errors.New("normalized claims must be a JSON object with at most 64 properties")
	}
	return claims, nil
}

func validSimulationPlatform(value string) bool {
	switch value {
	case "ios", "android", "web", "react_native_ios", "react_native_android", "watchos", "node":
		return true
	default:
		return false
	}
}

func validSimulationTrust(value string) bool {
	switch value {
	case "none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug":
		return true
	default:
		return false
	}
}

func printRouteSimulation(opts *options, result routeSimulationResultCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, result)
	}
	if err := printControlTable(opts, []string{"ALLOWED", "APPLICATION", "ENVIRONMENT", "REVISION", "FEATURE", "PROTOCOL", "LIMIT PLAN", "ROUTE", "UPSTREAM", "MODEL", "PHYSICAL MODEL", "PRICING"}, [][]string{{
		boolLabel(result.Allowed), result.ApplicationID, result.EnvironmentID, result.RevisionID,
		result.Feature, result.Protocol, result.LimitPlan, result.Route,
		result.Upstream, result.Model, result.PhysicalModel, result.PricingConfidence,
	}}); err != nil {
		return err
	}
	if result.Reservation != nil {
		if err := printControlTable(opts, []string{"OUTPUT MAX", "TOTAL TOKEN BOUND", "COST NANO-USD BOUND", "COST KNOWN", "PRICING CATALOG"}, [][]string{{
			strconv.FormatInt(result.Reservation.AppliedOutputMaximum, 10),
			strconv.FormatInt(result.Reservation.TotalTokenBound, 10),
			strconv.FormatInt(result.Reservation.CostNanoUSDBound, 10), boolLabel(result.Reservation.CostBoundKnown),
			result.Reservation.PricingCatalog,
		}}); err != nil {
			return err
		}
		rows := make([][]string, 0, len(result.Reservation.Allocations))
		for _, allocation := range result.Reservation.Allocations {
			rows = append(rows, []string{allocation.Metric, allocation.Algorithm, strconv.FormatInt(allocation.Units, 10), boolLabel(allocation.Applicable), boolLabel(allocation.Durable)})
		}
		if err := printControlTable(opts, []string{"METRIC", "ALGORITHM", "UNITS", "APPLICABLE", "DURABLE"}, rows); err != nil {
			return err
		}
	}
	if result.MatchedAccessExpression != "" {
		if _, err := fmt.Fprintf(opts.stdout, "matched access: %s\n", result.MatchedAccessExpression); err != nil {
			return err
		}
	}
	if len(result.Limits) != 0 {
		rows := make([][]string, 0, len(result.Limits))
		for _, limit := range result.Limits {
			bound := strconv.FormatInt(limit.Maximum, 10)
			if limit.PerRequestMaximum != 0 {
				bound = strconv.FormatInt(limit.PerRequestMaximum, 10)
			} else if limit.Capacity != 0 {
				bound = strconv.FormatInt(limit.Capacity, 10)
			}
			rows = append(rows, []string{limit.Metric, limit.Algorithm, strings.Join(limit.Scope, ","), bound, boolLabel(limit.Hard)})
		}
		if err := printControlTable(opts, []string{"METRIC", "ALGORITHM", "SCOPE", "BOUND", "HARD"}, rows); err != nil {
			return err
		}
	}
	if len(result.FallbackSequence) != 0 {
		rows := make([][]string, 0, len(result.FallbackSequence))
		for _, candidate := range result.FallbackSequence {
			rows = append(rows, []string{candidate.Route, candidate.Upstream, candidate.Model, candidate.PhysicalModel, strings.Join(candidate.FallbackOn, ",")})
		}
		if err := printControlTable(opts, []string{"ROUTE", "UPSTREAM", "MODEL", "PHYSICAL MODEL", "FALLBACK ON"}, rows); err != nil {
			return err
		}
	}
	if len(result.Explanation) != 0 {
		if _, err := fmt.Fprintf(opts.stdout, "explanation: %s\n", strings.Join(result.Explanation, " ")); err != nil {
			return err
		}
	}
	if len(result.Warnings) != 0 {
		_, err := fmt.Fprintf(opts.stdout, "warnings: %s\n", strings.Join(result.Warnings, " "))
		return err
	}
	return nil
}
