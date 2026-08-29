package providerverify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/pricing"
)

type openRouterModel struct {
	Rates         pricing.Rates
	ContextTokens int64
}

var providerPricePattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

func fetchOpenRouterModel(ctx context.Context, transport target, credential []byte, model string) (openRouterModel, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://latchway.invalid/model", nil)
	if err != nil {
		return openRouterModel{}, err
	}
	var result openRouterModel
	err = transport.Do(ctx, request, "/model/"+model, credential, func(response *http.Response) error {
		body, err := boundedJSONResponse(response, maximumMetadataBytes)
		if err != nil {
			return err
		}
		result, err = parseOpenRouterModel(body, model)
		return err
	})
	return result, err
}

func parseOpenRouterModel(body []byte, selected string) (openRouterModel, error) {
	value, err := jsonsafe.Decode(body)
	root, ok := value.(map[string]any)
	if err != nil || !ok || len(root) != 1 {
		return openRouterModel{}, errors.New("model")
	}
	data, ok := root["data"].(map[string]any)
	if !ok || data["id"] != selected {
		return openRouterModel{}, errors.New("model")
	}
	contextTokens, ok := exactPositiveInteger(data["context_length"])
	if !ok || contextTokens < minimumContextTokens {
		return openRouterModel{}, errors.New("model")
	}
	if !containsString(data["supported_parameters"], "max_tokens") {
		return openRouterModel{}, errors.New("model")
	}
	architecture, ok := data["architecture"].(map[string]any)
	if !ok || !containsString(architecture["input_modalities"], "text") || !containsString(architecture["output_modalities"], "text") {
		return openRouterModel{}, errors.New("model")
	}
	if tokenizer, ok := architecture["tokenizer"].(string); !ok || tokenizer == "" || len(tokenizer) > 128 {
		return openRouterModel{}, errors.New("model")
	}
	rates, err := parseOpenRouterPricing(data["pricing"])
	if err != nil {
		return openRouterModel{}, err
	}
	return openRouterModel{Rates: rates, ContextTokens: contextTokens}, nil
}

func parseOpenRouterPricing(value any) (pricing.Rates, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return pricing.Rates{}, errors.New("pricing")
	}
	base, err := parsePriceSet(object, pricing.Rates{}, true)
	if err != nil {
		return pricing.Rates{}, err
	}
	for key, value := range object {
		switch key {
		case "prompt", "completion", "request", "overrides":
		case "image", "web_search", "internal_reasoning", "input_cache_read", "input_cache_write":
			if !exactZeroPrice(value) {
				return pricing.Rates{}, errors.New("unsupported pricing")
			}
		default:
			return pricing.Rates{}, errors.New("unknown pricing")
		}
	}
	overrides, present := object["overrides"]
	if !present || overrides == nil {
		return base, nil
	}
	entries, ok := overrides.([]any)
	if !ok || len(entries) > 256 {
		return pricing.Rates{}, errors.New("overrides")
	}
	maximum := base
	for _, item := range entries {
		entry, ok := item.(map[string]any)
		if !ok || validatePricingOverride(entry) != nil {
			return pricing.Rates{}, errors.New("overrides")
		}
		candidate, err := parsePriceSet(entry, base, false)
		if err != nil {
			return pricing.Rates{}, err
		}
		for key := range entry {
			switch key {
			case "prompt", "completion", "request", "min_prompt_tokens", "utc_start", "utc_end", "utc_days":
			default:
				return pricing.Rates{}, errors.New("unknown override")
			}
		}
		maximum.InputNanoUSDPerMillion = maxInt64(maximum.InputNanoUSDPerMillion, candidate.InputNanoUSDPerMillion)
		maximum.OutputNanoUSDPerMillion = maxInt64(maximum.OutputNanoUSDPerMillion, candidate.OutputNanoUSDPerMillion)
		maximum.RequestNanoUSD = maxInt64(maximum.RequestNanoUSD, candidate.RequestNanoUSD)
	}
	return maximum, nil
}

func validatePricingOverride(entry map[string]any) error {
	priceFields := 0
	conditionFields := 0
	for _, name := range []string{"prompt", "completion", "request"} {
		if _, present := entry[name]; present {
			priceFields++
		}
	}
	if value, present := entry["min_prompt_tokens"]; present {
		parsed, ok := exactPositiveInteger(value)
		if !ok || parsed > 1_000_000_000 {
			return errors.New("override")
		}
		conditionFields++
	}
	start, hasStart := entry["utc_start"]
	end, hasEnd := entry["utc_end"]
	if hasStart != hasEnd {
		return errors.New("override")
	}
	if hasStart {
		if !validUTCClock(start) || !validUTCClock(end) {
			return errors.New("override")
		}
		conditionFields++
	}
	if value, present := entry["utc_days"]; present {
		days, ok := value.([]any)
		if !ok || len(days) == 0 || len(days) > 7 {
			return errors.New("override")
		}
		allowed := map[string]struct{}{
			"monday": {}, "tuesday": {}, "wednesday": {}, "thursday": {},
			"friday": {}, "saturday": {}, "sunday": {},
		}
		seen := make(map[string]struct{}, len(days))
		for _, item := range days {
			day, ok := item.(string)
			_, valid := allowed[day]
			_, duplicate := seen[day]
			if !ok || !valid || duplicate {
				return errors.New("override")
			}
			seen[day] = struct{}{}
		}
		conditionFields++
	}
	if priceFields == 0 || conditionFields == 0 {
		return errors.New("override")
	}
	return nil
}

func validUTCClock(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	clock, err := number.Int64()
	return err == nil && clock >= 0 && clock <= 2359 && clock%100 < 60
}

func parsePriceSet(object map[string]any, inherited pricing.Rates, requireAll bool) (pricing.Rates, error) {
	result := inherited
	for _, field := range []struct {
		name     string
		perToken bool
		dest     *int64
	}{
		{name: "prompt", perToken: true, dest: &result.InputNanoUSDPerMillion},
		{name: "completion", perToken: true, dest: &result.OutputNanoUSDPerMillion},
		{name: "request", dest: &result.RequestNanoUSD},
	} {
		value, present := object[field.name]
		if !present {
			if requireAll {
				return pricing.Rates{}, errors.New("missing pricing")
			}
			continue
		}
		text, ok := value.(string)
		if !ok {
			return pricing.Rates{}, errors.New("pricing")
		}
		var nano int64
		var parseErr error
		if field.perToken {
			nano, parseErr = parseUSDPerTokenNanoPerMillion(text)
		} else {
			nano, parseErr = pricing.ParseUSDDecimalNanoUSD(text)
		}
		if parseErr != nil {
			return pricing.Rates{}, errors.New("pricing")
		}
		*field.dest = nano
	}
	return result, nil
}

// parseUSDPerTokenNanoPerMillion performs the unit conversion in one exact
// operation: USD/token * 10^9 nano-USD/USD * 10^6 tokens/million. Converting
// through nano-USD/token first would incorrectly reject valid sub-nano prices.
func parseUSDPerTokenNanoPerMillion(value string) (int64, error) {
	if len(value) == 0 || len(value) > 128 || !providerPricePattern.MatchString(value) {
		return 0, errors.New("pricing")
	}
	if exponentIndex := strings.IndexAny(value, "eE"); exponentIndex >= 0 {
		exponent, err := strconv.ParseInt(value[exponentIndex+1:], 10, 16)
		if err != nil || exponent < -100 || exponent > 100 {
			return 0, errors.New("pricing")
		}
	}
	parsed, ok := new(big.Rat).SetString(value)
	if !ok || parsed.Sign() < 0 {
		return 0, errors.New("pricing")
	}
	parsed.Mul(parsed, new(big.Rat).SetInt64(1_000_000_000_000_000))
	if !parsed.IsInt() || !parsed.Num().IsInt64() {
		return 0, errors.New("pricing")
	}
	result := parsed.Num().Int64()
	if result < 0 || result > math.MaxInt64 {
		return 0, errors.New("pricing")
	}
	return result, nil
}

func exactZeroPrice(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	nano, err := pricing.ParseUSDDecimalNanoUSD(text)
	return err == nil && nano == 0
}

func verifyOpenRouterKey(ctx context.Context, transport target, credential []byte, maximumCost int64, now time.Time) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://latchway.invalid/key", nil)
	if err != nil {
		return err
	}
	return transport.Do(ctx, request, "/key", credential, func(response *http.Response) error {
		body, err := boundedJSONResponse(response, maximumMetadataBytes)
		if err != nil {
			return err
		}
		return parseOpenRouterKey(body, maximumCost, now)
	})
}

func parseOpenRouterKey(body []byte, maximumCost int64, now time.Time) error {
	value, err := jsonsafe.Decode(body)
	root, ok := value.(map[string]any)
	if err != nil || !ok || len(root) != 1 {
		return errors.New("key")
	}
	data, ok := root["data"].(map[string]any)
	if !ok {
		return errors.New("key")
	}
	_, freeOK := data["is_free_tier"].(bool)
	management, managementOK := data["is_management_key"].(bool)
	provisioning, provisioningOK := data["is_provisioning_key"].(bool)
	if !freeOK || !managementOK || !provisioningOK || management || provisioning {
		return errors.New("key")
	}
	if expires, present := data["expires_at"]; present && expires != nil {
		text, ok := expires.(string)
		parsed, parseErr := time.Parse(time.RFC3339, text)
		if !ok || parseErr != nil || !parsed.After(now) {
			return errors.New("key")
		}
	}
	limit, limitPresent := data["limit"]
	remaining, remainingPresent := data["limit_remaining"]
	if !limitPresent || !remainingPresent {
		return errors.New("key")
	}
	if limit == nil {
		if remaining != nil {
			return errors.New("key")
		}
		return nil
	}
	limitNumber, ok := limit.(json.Number)
	if !ok {
		return errors.New("key")
	}
	limitNano, err := pricing.ParseUSDDecimalNanoUSD(limitNumber.String())
	if err != nil || limitNano < 0 {
		return errors.New("key")
	}
	remainingNumber, ok := remaining.(json.Number)
	if !ok {
		return errors.New("key")
	}
	remainingNano, err := pricing.ParseUSDDecimalNanoUSD(remainingNumber.String())
	if err != nil || remainingNano < maximumCost {
		return errors.New("key")
	}
	return nil
}

func boundedJSONResponse(response *http.Response, maximum int64) ([]byte, error) {
	if response == nil || response.Body == nil || response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > maximum {
		return nil, errors.New("response")
	}
	values := response.Header.Values("Content-Type")
	mediaType := ""
	var mediaTypeErr error
	if len(values) == 1 {
		mediaType, _, mediaTypeErr = mime.ParseMediaType(values[0])
	}
	if mediaTypeErr != nil || mediaType != "application/json" {
		return nil, errors.New("response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("response")
	}
	return body, nil
}

func exactPositiveInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil && parsed > 0
}

func containsString(value any, target string) bool {
	values, ok := value.([]any)
	if !ok || len(values) > 1024 {
		return false
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
