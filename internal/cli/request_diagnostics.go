package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

// A denied rule belongs to an atomic quota-evaluation batch. The terminal
// event is its matching aggregate quota_reserved denial, not the first rule.
type requestDecisionSequenceCLI struct {
	terminal    bool
	quotaDenial string
}

func (sequence *requestDecisionSequenceCLI) append(stage requestDecisionStageCLI) bool {
	if sequence.terminal {
		return false
	}
	if sequence.quotaDenial != "" {
		switch stage.Stage {
		case "quota_rule_evaluated":
			return stage.Outcome == "succeeded" && stage.FailureCode == "" ||
				stage.Outcome == "denied" && stage.FailureCode == sequence.quotaDenial
		case "quota_reserved":
			if stage.Outcome == "denied" && stage.FailureCode == sequence.quotaDenial {
				sequence.quotaDenial = ""
				sequence.terminal = true
				return true
			}
		}
		return false
	}
	if stage.Stage == "quota_rule_evaluated" && stage.Outcome == "denied" && stage.FailureCode != "" {
		sequence.quotaDenial = stage.FailureCode
	} else if stage.Outcome != "succeeded" {
		sequence.terminal = true
	}
	return true
}

type usageMetricDetailsCLI struct {
	RecordedUnits *json.Number `json:"recorded_units"`
	ReportedUnits *json.Number `json:"reported_units"`
	UnknownUnits  *json.Number `json:"unknown_units"`
	Provenance    []string     `json:"provenance"`
}

type usageDetailsCLI struct {
	InputTokens  usageMetricDetailsCLI `json:"input_tokens"`
	OutputTokens usageMetricDetailsCLI `json:"output_tokens"`
	TotalTokens  usageMetricDetailsCLI `json:"total_tokens"`
	CostNanoUSD  usageMetricDetailsCLI `json:"cost_nano_usd"`
}

// Null is meaningful: an absent observation is not an observed zero. Require
// all nullable keys so a malformed or older shape cannot erase that distinction.
func (details *usageDetailsCLI) UnmarshalJSON(data []byte) error {
	if len(data) > 4096 {
		return errors.New("usage details exceed limit")
	}
	value, err := jsonsafe.Decode(data)
	object, ok := value.(map[string]any)
	if err != nil || !ok || len(object) != 4 {
		return errors.New("invalid usage details")
	}
	for _, key := range []string{"input_tokens", "output_tokens", "total_tokens", "cost_nano_usd"} {
		metric, ok := object[key].(map[string]any)
		if !ok || len(metric) != 4 {
			return errors.New("invalid usage metric details")
		}
		for _, units := range []string{"recorded_units", "reported_units", "unknown_units"} {
			value, present := metric[units]
			if !present {
				return errors.New("missing nullable usage units")
			}
			if value != nil {
				if _, ok := value.(json.Number); !ok {
					return errors.New("invalid usage units")
				}
			}
		}
		if _, ok := metric["provenance"].([]any); !ok {
			return errors.New("invalid usage provenance")
		}
	}
	type plain usageDetailsCLI
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("invalid usage details")
	}
	*details = usageDetailsCLI(decoded)
	return nil
}

func (details usageDetailsCLI) valid(values usageValuesCLI) bool {
	for _, item := range []struct {
		metric usageMetricDetailsCLI
		legacy json.Number
	}{
		{details.InputTokens, values.InputTokens}, {details.OutputTokens, values.OutputTokens},
		{details.TotalTokens, values.TotalTokens}, {details.CostNanoUSD, values.CostNanoUSD},
	} {
		legacy, ok := nonNegativeJSONInteger(item.legacy)
		if !ok {
			return false
		}
		metric := item.metric
		if metric.RecordedUnits == nil {
			if legacy != 0 || metric.ReportedUnits != nil || metric.UnknownUnits != nil || len(metric.Provenance) != 0 {
				return false
			}
			continue
		}
		recorded, ok := nonNegativeJSONInteger(*metric.RecordedUnits)
		if !ok || recorded != legacy || len(metric.Provenance) == 0 || len(metric.Provenance) > 4 {
			return false
		}
		seen := make(map[string]bool)
		for _, provenance := range metric.Provenance {
			if !slices.Contains([]string{"upstream_reported", "calculated", "estimated", "unknown"}, provenance) || seen[provenance] {
				return false
			}
			seen[provenance] = true
		}
		accounted := int64(0)
		for _, observation := range []struct {
			units      *json.Number
			provenance string
		}{
			{metric.ReportedUnits, "upstream_reported"}, {metric.UnknownUnits, "unknown"},
		} {
			if observation.units == nil {
				continue
			}
			units, ok := nonNegativeJSONInteger(*observation.units)
			if !ok || units > recorded-accounted || !seen[observation.provenance] {
				return false
			}
			accounted += units
		}
	}
	return true
}

type inputAccountingBreakdownCLI protocol.InputAccountingBreakdown

func (value inputAccountingBreakdownCLI) bound() (int64, bool) {
	if value.FramingUnitCount <= 0 || value.MaximumFramingTokensPerUnit < 0 || value.MaximumFramingTokensPerRequest < 0 ||
		value.ExpandedSchemaBytes < 0 || value.RewrittenRequestBytes <= 0 || value.MaximumFramingTokensPerUnit > math.MaxInt64/value.FramingUnitCount {
		return 0, false
	}
	bound := value.RewrittenRequestBytes
	for _, part := range []int64{value.MaximumFramingTokensPerRequest, value.FramingUnitCount * value.MaximumFramingTokensPerUnit, value.ExpandedSchemaBytes} {
		if bound > math.MaxInt64-part {
			return 0, false
		}
		bound += part
	}
	return bound, true
}

func (value inputAccountingBreakdownCLI) valid(protocolID string) bool {
	bound, ok := value.bound()
	return ok && protocol.InputAccountingBreakdown(value).Validate(bound, protocolID)
}

func (value *inputAccountingBreakdownCLI) UnmarshalJSON(data []byte) error {
	type plain inputAccountingBreakdownCLI
	var decoded plain
	if len(data) > 2048 || json.Unmarshal(data, &decoded) != nil {
		return errors.New("invalid input accounting breakdown")
	}
	bound, ok := inputAccountingBreakdownCLI(decoded).bound()
	if !ok {
		return errors.New("invalid input accounting breakdown bound")
	}
	// The owning request validates its actual protocol after decoding. Chat is
	// the permissive supported shape here; the strict decoder still checks all
	// six required integer members, uniqueness, bounds, and overflow.
	checked, err := protocol.DecodeInputAccountingBreakdown(data, bound, protocol.OpenAIChatID)
	if err != nil {
		return errors.New("invalid input accounting breakdown")
	}
	*value = inputAccountingBreakdownCLI(*checked)
	return nil
}

func validAttemptDiagnosticsCLI(attempt upstreamAttemptCLI) bool {
	if attempt.ProviderError != nil && attempt.ProviderError.Validate() != nil {
		return false
	}
	if attempt.InputAccountingBreakdown != nil && !attempt.InputAccountingBreakdown.valid(protocol.OpenAIChatID) {
		return false
	}
	switch attempt.AccountingPolicy {
	case "":
		return true
	case "reported_usage_v1":
		return attempt.Status != "unknown"
	case "provider_rejection_v1":
		return attempt.Status == "failed" && attempt.HTTPStatus == 400 && attempt.FailureCode == "upstream_rejected" &&
			attempt.FirstByteAt == "" && attempt.FirstTokenAt == "" && attempt.ProviderError != nil &&
			attempt.ProviderError.AllowsPreGenerationRejection(attempt.HTTPStatus)
	default:
		return false
	}
}

func printRequestDiagnosticsCLI(opts *options, request logicalRequestCLI) error {
	providerRows := make([][]string, 0)
	inputRows := make([][]string, 0)
	usageRows := make([][]string, 0)
	appendUsage := func(scope string, usage *usageValuesCLI) {
		if usage == nil || usage.Details == nil {
			return
		}
		for _, item := range []struct {
			name    string
			details usageMetricDetailsCLI
		}{
			{"input_tokens", usage.Details.InputTokens}, {"output_tokens", usage.Details.OutputTokens},
			{"total_tokens", usage.Details.TotalTokens}, {"cost_nano_usd", usage.Details.CostNanoUSD},
		} {
			usageRows = append(usageRows, []string{scope, item.name, nullableUsageTextCLI(item.details.RecordedUnits),
				nullableUsageTextCLI(item.details.ReportedUnits), nullableUsageTextCLI(item.details.UnknownUnits), strings.Join(item.details.Provenance, ",")})
		}
	}
	appendUsage("request", request.Usage)
	for _, attempt := range request.Attempts {
		name := strconv.Itoa(int(attempt.AttemptNumber))
		appendUsage("attempt "+name, attempt.Usage)
		if attempt.ProviderError != nil {
			diagnostic := attempt.ProviderError
			providerRows = append(providerRows, []string{name, attempt.AccountingPolicy, string(diagnostic.Category), diagnostic.Parameter, diagnostic.ProviderCode, diagnostic.GenerationID, diagnostic.RequestID})
		}
		if attempt.InputAccountingBreakdown != nil {
			value := attempt.InputAccountingBreakdown
			bound, _ := value.bound()
			inputRows = append(inputRows, []string{name, strconv.FormatInt(value.RewrittenRequestBytes, 10), strconv.FormatInt(value.FramingUnitCount, 10),
				strconv.FormatInt(value.MaximumFramingTokensPerRequest, 10), strconv.FormatInt(value.MaximumFramingTokensPerUnit, 10),
				strconv.FormatInt(value.ExpandedSchemaBytes, 10), strconv.FormatInt(bound, 10)})
		}
	}
	if len(providerRows) > 0 {
		if err := printControlTable(opts, []string{"ATTEMPT", "ACCOUNTING POLICY", "PROVIDER CATEGORY", "PARAMETER", "PROVIDER CODE", "GENERATION ID", "PROVIDER REQUEST ID"}, providerRows); err != nil {
			return err
		}
	}
	if len(inputRows) > 0 {
		if err := printControlTable(opts, []string{"ATTEMPT", "REQUEST BYTES", "FRAMING UNITS", "REQUEST ALLOWANCE", "UNIT ALLOWANCE", "EXPANDED SCHEMA BYTES", "INPUT BOUND"}, inputRows); err != nil {
			return err
		}
	}
	if len(usageRows) > 0 {
		return printControlTable(opts, []string{"SCOPE", "METRIC", "RECORDED", "REPORTED", "UNKNOWN CHARGE", "PROVENANCE"}, usageRows)
	}
	return nil
}

func nullableUsageTextCLI(value *json.Number) string {
	if value == nil {
		return "not recorded"
	}
	return value.String()
}
