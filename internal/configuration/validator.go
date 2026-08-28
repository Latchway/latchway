package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	contractapi "github.com/latchway/latchway/api"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const canonicalSchemaURL = "https://latchway.dev/schemas/config/0.5.0/environment-config.schema.json"

const (
	// Configuration numbers ultimately fit int64 or the six-decimal refill
	// representation. These deliberately generous lexical bounds keep the JSON
	// Schema library from constructing pathological big.Rat values before the
	// field-specific exact parsers run.
	maximumSchemaNumberBytes             = 256
	maximumSchemaNumberExponentMagnitude = 1_024
)

var schemaCodePattern = regexp.MustCompile(`[^a-z0-9]+`)

// Validator compiles the canonical schema and bounded CEL environment once.
// It is safe for concurrent use after construction.
type Validator struct {
	schema    *jsonschema.Schema
	policyCEL *cel.Env
	claimCEL  *cel.Env
}

// NewValidator constructs the strict schema, semantic, and policy compiler.
func NewValidator() (*Validator, error) {
	schemaDocument, err := jsonsafe.Decode(contractapi.ConfigSchema())
	if err != nil {
		return nil, fmt.Errorf("decode canonical configuration schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(canonicalSchemaURL, schemaDocument); err != nil {
		return nil, fmt.Errorf("register canonical configuration schema: %w", err)
	}
	compiledSchema, err := compiler.Compile(canonicalSchemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile canonical configuration schema: %w", err)
	}
	policyEnvironment, err := cel.NewEnv(
		cel.Variable("principal", cel.DynType),
		cel.Variable("installation", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("environment", cel.DynType),
		cel.ParserExpressionSizeLimit(4096),
		cel.ParserRecursionLimit(64),
		cel.ExpressionNestingDepthLimit(32),
		cel.ExpressionNodeLimit(1_000),
		cel.RegexProgramSizeLimit(1_000),
		cel.ExtendedValidations(),
	)
	if err != nil {
		return nil, fmt.Errorf("construct configuration policy CEL environment: %w", err)
	}
	claimEnvironment, err := cel.NewEnv(
		cel.Variable("claims", cel.DynType),
		cel.ParserExpressionSizeLimit(4096),
		cel.ParserRecursionLimit(64),
		cel.ExpressionNestingDepthLimit(32),
		cel.ExpressionNodeLimit(1_000),
		cel.RegexProgramSizeLimit(1_000),
		cel.ExtendedValidations(),
	)
	if err != nil {
		return nil, fmt.Errorf("construct configuration claim-mapping CEL environment: %w", err)
	}
	return &Validator{schema: compiledSchema, policyCEL: policyEnvironment, claimCEL: claimEnvironment}, nil
}

// SchemaIssues validates only the canonical JSON Schema. It is used on draft
// writes so malformed or ambiguous documents never enter PostgreSQL.
func (validator *Validator) SchemaIssues(document json.RawMessage) []Issue {
	value, err := jsonsafe.Decode(document)
	if err != nil {
		return []Issue{errorIssue("schema_json_invalid", "/", "The configuration must be one unambiguous JSON document.")}
	}
	if issue, unsafe := unsafeSchemaNumberIssue(value, ""); unsafe {
		return []Issue{issue}
	}
	if _, ok := value.(map[string]any); !ok {
		return []Issue{errorIssue("schema_type", "/", "The configuration must be a JSON object.")}
	}
	if err := validator.schema.Validate(value); err != nil {
		return schemaIssues(err)
	}
	return nil
}

func unsafeSchemaNumberIssue(value any, path string) (Issue, bool) {
	switch typed := value.(type) {
	case json.Number:
		if schemaNumberLexicallySafe(typed) {
			return Issue{}, false
		}
		if path == "" {
			path = "/"
		}
		return errorIssue(
			"schema_number_unsafe",
			path,
			"Configuration numbers must use a bounded decimal representation.",
		), true
	case map[string]any:
		for _, key := range sortedObjectKeys(typed) {
			if issue, unsafe := unsafeSchemaNumberIssue(typed[key], path+"/"+pointerToken(key)); unsafe {
				return issue, true
			}
		}
	case []any:
		for index, element := range typed {
			if issue, unsafe := unsafeSchemaNumberIssue(element, fmt.Sprintf("%s/%d", path, index)); unsafe {
				return issue, true
			}
		}
	}
	return Issue{}, false
}

func schemaNumberLexicallySafe(number json.Number) bool {
	raw := number.String()
	if raw == "" || len(raw) > maximumSchemaNumberBytes {
		return false
	}
	exponentMarker := strings.IndexAny(raw, "eE")
	if exponentMarker < 0 {
		return true
	}
	index := exponentMarker + 1
	if index < len(raw) && (raw[index] == '+' || raw[index] == '-') {
		index++
	}
	if index == len(raw) {
		return false
	}
	exponent := 0
	for ; index < len(raw); index++ {
		digit := raw[index]
		if digit < '0' || digit > '9' {
			return false
		}
		value := int(digit - '0')
		if exponent > (maximumSchemaNumberExponentMagnitude-value)/10 {
			return false
		}
		exponent = exponent*10 + value
	}
	return true
}

// Validate performs schema, cross-reference, secret-reference, semantic, and
// CEL checks and returns a normalized snapshot only when every error is gone.
func (validator *Validator) Validate(document json.RawMessage, environment EnvironmentDescriptor, checkedAt time.Time) (ValidationReport, json.RawMessage) {
	issues := validator.SchemaIssues(document)
	if len(issues) != 0 {
		return report(checkedAt, issues), nil
	}
	value, err := jsonsafe.Decode(document)
	if err != nil {
		return report(checkedAt, []Issue{errorIssue("schema_json_invalid", "/", "The configuration must be one unambiguous JSON document.")}), nil
	}
	normalized := deepClone(value).(map[string]any)
	applyDefaults(normalized)
	issues = append(issues, validator.semanticIssues(normalized, environment)...)
	sortIssues(issues)
	result := report(checkedAt, issues)
	if !result.Valid {
		return result, nil
	}
	compiled, err := json.Marshal(normalized)
	if err != nil {
		return report(checkedAt, []Issue{errorIssue("compilation_failed", "/", "The normalized configuration could not be compiled.")}), nil
	}
	// Keep validation and active loading as one safety boundary. Runtime
	// configuration deliberately rechecks invariants because compiled snapshots
	// are persisted, but a newly validated document must never compile into a
	// snapshot that would take the active data plane offline.
	if _, err := newActiveSnapshot("validation", "validation", document, compiled); err != nil {
		issues = append(issues, errorIssue(
			"runtime_configuration_invalid",
			"/spec",
			"The normalized data-plane configuration could not be loaded safely.",
		))
		sortIssues(issues)
		return report(checkedAt, issues), nil
	}
	return result, compiled
}

func report(checkedAt time.Time, issues []Issue) ValidationReport {
	valid := true
	for _, issue := range issues {
		if issue.Severity == "error" {
			valid = false
			break
		}
	}
	if issues == nil {
		issues = []Issue{}
	}
	return ValidationReport{Valid: valid, CheckedAt: checkedAt.UTC(), Issues: issues}
}

func schemaIssues(err error) []Issue {
	var validationError *jsonschema.ValidationError
	if !errors.As(err, &validationError) {
		return []Issue{errorIssue("schema_invalid", "/", "The configuration does not satisfy the canonical schema.")}
	}
	output := validationError.BasicOutput()
	units := output.Errors
	if len(units) == 0 {
		units = []jsonschema.OutputUnit{*output}
	}
	result := make([]Issue, 0, len(units))
	seen := make(map[string]struct{})
	for _, unit := range units {
		keyword := lastPointerToken(unit.KeywordLocation)
		code := "schema_" + sanitizeCode(keyword)
		if code == "schema_" {
			code = "schema_invalid"
		}
		path := unit.InstanceLocation
		if path == "" {
			path = "/"
		}
		message := schemaMessage(keyword)
		key := code + "\x00" + path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, errorIssue(code, path, message))
		if len(result) == 1_000 {
			break
		}
	}
	sortIssues(result)
	return result
}

func schemaMessage(keyword string) string {
	switch keyword {
	case "required":
		return "A required configuration member is missing."
	case "additionalProperties", "unevaluatedProperties":
		return "The configuration contains an unsupported member."
	case "type":
		return "A configuration member has the wrong JSON type."
	case "format", "pattern":
		return "A configuration member has an invalid format."
	case "const", "enum":
		return "A configuration member is not an allowed value."
	case "oneOf", "anyOf", "allOf", "if":
		return "A configuration member violates a conditional schema rule."
	default:
		return "A configuration member violates the canonical schema."
	}
}

func lastPointerToken(pointer string) string {
	if index := strings.LastIndexByte(pointer, '/'); index >= 0 {
		return strings.ReplaceAll(strings.ReplaceAll(pointer[index+1:], "~1", "/"), "~0", "~")
	}
	return pointer
}

func sanitizeCode(value string) string {
	value = strings.ToLower(value)
	value = strings.Trim(schemaCodePattern.ReplaceAllString(value, "_"), "_")
	if len(value) > 100 {
		value = value[:100]
	}
	return value
}

func errorIssue(code, path, message string) Issue {
	return Issue{Severity: "error", Code: code, Path: path, Message: message}
}

func warningIssue(code, path, message string) Issue {
	return Issue{Severity: "warning", Code: code, Path: path, Message: message}
}

func sortIssues(issues []Issue) {
	slices.SortFunc(issues, func(left, right Issue) int {
		if comparison := strings.Compare(left.Path, right.Path); comparison != 0 {
			return comparison
		}
		if comparison := strings.Compare(left.Code, right.Code); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Message, right.Message)
	})
}

func deepClone(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			result[key] = deepClone(child)
		}
		return result
	case []any:
		result := make([]any, len(current))
		for index, child := range current {
			result[index] = deepClone(child)
		}
		return result
	default:
		return current
	}
}

func applyDefaults(root map[string]any) {
	spec := objectValue(root, "spec")
	setDefault(spec, "inputAccountingProfiles", []any{})
	setDefault(spec, "pricingCatalogs", []any{})

	for _, provider := range objectArray(spec, "identityProviders") {
		setDefault(provider, "acknowledgeSymmetricRisk", false)
		setDefault(provider, "subjectClaim", "sub")
		setDefault(provider, "clockSkewSeconds", json.Number("60"))
	}
	for _, policy := range objectArray(spec, "attestationPolicies") {
		setDefault(policy, "maxAge", "24h")
		platforms := objectValue(policy, "platforms")
		for _, platform := range sortedObjectKeys(platforms) {
			selection, ok := platforms[platform].(map[string]any)
			if !ok {
				continue
			}
			setDefault(selection, "dangerousAllowInProduction", false)
			minimumTrust := defaultTrustLevel(stringValue(selection, "provider"), platform)
			if playIntegrity := objectValue(selection, "playIntegrity"); len(playIntegrity) != 0 {
				if stringValue(playIntegrity, "minimumDeviceIntegrity") == "strong" {
					minimumTrust = "strong_device_verified"
				} else {
					minimumTrust = "device_verified"
				}
			}
			setDefault(selection, "minimumTrustLevel", minimumTrust)
		}
	}
	for _, upstream := range objectArray(spec, "upstreams") {
		setDefault(upstream, "dangerousAllowInsecureHttp", false)
		timeouts := ensureObject(upstream, "timeouts")
		setDefault(timeouts, "connect", "5s")
		setDefault(timeouts, "firstByte", "30s")
		setDefault(timeouts, "idle", "1m")
		setDefault(timeouts, "total", "2m")
		destination := ensureObject(upstream, "destinationPolicy")
		setDefault(destination, "allowedPorts", []any{json.Number(defaultPort(stringValue(upstream, "baseUrl")))})
		setDefault(destination, "allowRedirects", false)
		setDefault(destination, "allowPrivateNetworks", false)
		setDefault(destination, "dnsPinning", true)
	}
	upstreamTypes := make(map[string]string)
	for _, upstream := range objectArray(spec, "upstreams") {
		upstreamTypes[stringValue(upstream, "id")] = stringValue(upstream, "type")
	}
	for _, model := range objectArray(spec, "models") {
		if _, ok := model["capabilities"]; !ok {
			model["capabilities"] = inferredCapabilities(upstreamTypes[stringValue(model, "upstream")])
		}
	}
	for _, catalog := range objectArray(spec, "pricingCatalogs") {
		for _, entry := range objectArray(catalog, "entries") {
			setDefault(entry, "requestNanoUsd", json.Number("0"))
		}
	}
	for _, plan := range objectArray(spec, "limitPlans") {
		for _, limit := range objectArray(plan, "limits") {
			setDefault(limit, "algorithm", inferredLimitAlgorithm(limit))
			setDefault(limit, "hard", true)
			if raw, ok := limit["refillPerSecond"].(json.Number); ok {
				if rate, valid := parseJSONRefillRate(raw); valid {
					limit["refillPerSecond"] = json.Number(rate.String())
				}
			}
			if scope, ok := canonicalLimitScope(stringArray(limit, "scope")); ok {
				canonical := make([]any, len(scope))
				for index := range scope {
					canonical[index] = scope[index]
				}
				limit["scope"] = canonical
			}
		}
	}
	for _, feature := range objectArray(spec, "features") {
		for _, route := range objectArray(feature, "routes") {
			setDefault(route, "weight", json.Number("1"))
			setDefault(route, "stickyBy", "none")
			setDefault(route, "fallbackOn", []any{})
			if stringValue(feature, "protocol") == "opaque_http" {
				setDefault(route, "streamingAllowed", false)
				setDefault(route, "retryUnsafeMethods", false)
			}
			if retryPolicy, ok := route["retryPolicy"].(map[string]any); ok {
				setDefault(retryPolicy, "initialBackoffMilliseconds", json.Number("0"))
				setDefault(retryPolicy, "maximumBackoffMilliseconds", json.Number("0"))
				setDefault(retryPolicy, "jitterRatio", json.Number("0"))
			}
		}
	}
	session := ensureObject(spec, "session")
	setDefault(session, "accessTokenTtl", "10m")
	setDefault(session, "challengeTtl", "5m")
	setDefault(session, "refreshTokenTtl", "30d")
	setDefault(session, "maximumClockSkewSeconds", json.Number("60"))
	privacy := ensureObject(spec, "privacy")
	setDefault(privacy, "storePromptBodies", false)
	setDefault(privacy, "storeResponseBodies", false)
}

func inferredCapabilities(upstreamType string) []any {
	switch upstreamType {
	case "openai_compatible":
		return []any{"openai_responses", "openai_chat", "openai_embeddings"}
	case "anthropic":
		return []any{"anthropic_messages"}
	case "generic":
		return []any{"opaque_http"}
	default:
		return []any{}
	}
}

func inferredLimitAlgorithm(limit map[string]any) string {
	if _, ok := limit["capacity"]; ok {
		return "token_bucket"
	}
	if _, ok := limit["perRequestMaximum"]; ok {
		return "per_request"
	}
	metric := stringValue(limit, "metric")
	if metric == "concurrent_requests" || metric == "concurrent_streams" {
		return "concurrency"
	}
	return "calendar"
}

func defaultTrustLevel(provider, platform string) string {
	switch provider {
	case "app_attest", "play_integrity":
		return "app_verified"
	case "firebase_app_check":
		if platform == "web" {
			return "web_risk_verified"
		}
		return "app_verified"
	case "turnstile":
		return "web_risk_verified"
	case "debug":
		return "debug"
	default:
		return "none"
	}
}

func defaultPort(rawURL string) string {
	if strings.HasPrefix(rawURL, "http://") {
		return "80"
	}
	return "443"
}

func objectValue(parent map[string]any, key string) map[string]any {
	value, _ := parent[key].(map[string]any)
	return value
}

func ensureObject(parent map[string]any, key string) map[string]any {
	if value, ok := parent[key].(map[string]any); ok {
		return value
	}
	value := make(map[string]any)
	parent[key] = value
	return value
}

func objectArray(parent map[string]any, key string) []map[string]any {
	raw, _ := parent[key].([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if object, ok := item.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func stringValue(parent map[string]any, key string) string {
	value, _ := parent[key].(string)
	return value
}

func setDefault(parent map[string]any, key string, value any) {
	if _, ok := parent[key]; !ok {
		parent[key] = value
	}
}

func sortedObjectKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
