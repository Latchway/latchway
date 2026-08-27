package identity

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
)

const (
	maximumCELClaimMappings    = 32
	maximumCELClaimRuntimeCost = 10_000
	maximumCELClaimDepth       = 64
	maximumCELClaimElements    = 4_096
)

type compiledCELClaimMapping struct {
	name               string
	optionalDirectPath string
	program            cel.Program
}

// CELClaimMapper evaluates a bounded, precompiled CEL projection over verified
// JWT claims. It is immutable and safe for concurrent use after construction.
type CELClaimMapper struct {
	mappings []compiledCELClaimMapping
}

// NewCELClaimMapper compiles normalized-name-to-CEL-expression mappings. The
// expression environment exposes only the dynamic `claims` variable and uses
// the same parser bounds as configuration validation.
func NewCELClaimMapper(mappings map[string]string) (*CELClaimMapper, error) {
	if len(mappings) > maximumCELClaimMappings {
		return nil, fmt.Errorf("%w: too many claim mappings", ErrConfiguration)
	}
	environment, err := cel.NewEnv(
		cel.Variable("claims", cel.DynType),
		cel.ParserExpressionSizeLimit(4096),
		cel.ParserRecursionLimit(64),
		cel.ExpressionNestingDepthLimit(32),
		cel.ExpressionNodeLimit(1_000),
		cel.RegexProgramSizeLimit(1_000),
		cel.ExtendedValidations(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: construct claim CEL environment", ErrConfiguration)
	}
	names := make([]string, 0, len(mappings))
	for name := range mappings {
		if !normalizedClaimPattern.MatchString(name) {
			return nil, fmt.Errorf("%w: invalid normalized claim name", ErrConfiguration)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	compiled := make([]compiledCELClaimMapping, 0, len(names))
	for _, name := range names {
		expression := mappings[name]
		ast, issues := environment.Compile(expression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("%w: invalid claim CEL expression", ErrConfiguration)
		}
		if !supportedCELClaimType(ast.OutputType()) {
			return nil, fmt.Errorf("%w: unsupported claim CEL result type", ErrConfiguration)
		}
		program, err := environment.Program(
			ast,
			cel.CostLimit(maximumCELClaimRuntimeCost),
			cel.InterruptCheckFrequency(100),
		)
		if err != nil {
			return nil, fmt.Errorf("%w: compile claim CEL program", ErrConfiguration)
		}
		compiled = append(compiled, compiledCELClaimMapping{
			name: name, optionalDirectPath: directCELClaimPath(expression), program: program,
		})
	}
	return &CELClaimMapper{mappings: compiled}, nil
}

// Map evaluates each configured expression and retains only bounded JSON-safe
// scalar or scalar-list results. Missing/null results are omitted.
func (mapper *CELClaimMapper) Map(claims map[string]any) (map[string]any, error) {
	if mapper == nil || len(mapper.mappings) > maximumCELClaimMappings {
		return nil, fmt.Errorf("%w: invalid claim mapper", ErrConfiguration)
	}
	activationClaims, _, err := celClaimActivationValue(claims, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: claims cannot be evaluated", ErrCredentialInvalid)
	}
	result := make(map[string]any, len(mapper.mappings))
	for _, mapping := range mapper.mappings {
		// A direct claim projection preserves the optional semantics of the
		// original path mapper. requiredClaims remains the explicit way to make
		// an external claim mandatory; richer CEL expressions retain normal CEL
		// error semantics and must handle absence deliberately.
		if mapping.optionalDirectPath != "" {
			if direct, ok := claimAtPath(claims, mapping.optionalDirectPath); !ok || direct == nil {
				continue
			}
		}
		value, _, evalErr := mapping.program.Eval(map[string]any{"claims": activationClaims})
		if evalErr != nil || value == nil || types.IsError(value) || types.IsUnknown(value) {
			return nil, fmt.Errorf("%w: claim mapping evaluation failed", ErrCredentialInvalid)
		}
		native, conversionErr := value.ConvertToNative(reflect.TypeFor[any]())
		if conversionErr != nil {
			return nil, fmt.Errorf("%w: claim mapping result is invalid", ErrCredentialInvalid)
		}
		if native == nil {
			continue
		}
		normalized, normalizationErr := normalizeCELClaimResult(native)
		if normalizationErr != nil {
			return nil, fmt.Errorf("%w: mapped claim %s", ErrCredentialInvalid, mapping.name)
		}
		result[mapping.name] = normalized
	}
	return validateNormalizedClaims(result)
}

func directCELClaimPath(expression string) string {
	expression = strings.TrimSpace(expression)
	if !strings.HasPrefix(expression, "claims.") {
		return ""
	}
	path := strings.TrimPrefix(expression, "claims.")
	if !claimPathPattern.MatchString(path) {
		return ""
	}
	return path
}

func supportedCELClaimType(output *cel.Type) bool {
	if output == nil {
		return false
	}
	return slices.Contains([]cel.Kind{
		cel.DynKind, cel.StringKind, cel.BoolKind, cel.IntKind, cel.UintKind, cel.DoubleKind, cel.ListKind,
	}, output.Kind())
}

func celClaimActivationValue(value any, depth, elements int) (any, int, error) {
	if depth > maximumCELClaimDepth || elements >= maximumCELClaimElements {
		return nil, elements, ErrCredentialInvalid
	}
	switch typed := value.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, elements + 1, nil
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, elements, ErrCredentialInvalid
		}
		return typed, elements + 1, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, elements, ErrCredentialInvalid
		}
		return typed, elements + 1, nil
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return integer, elements + 1, nil
		}
		if unsigned, err := strconv.ParseUint(typed.String(), 10, 64); err == nil {
			return unsigned, elements + 1, nil
		}
		decimal, err := typed.Float64()
		if err != nil || math.IsNaN(decimal) || math.IsInf(decimal, 0) {
			return nil, elements, ErrCredentialInvalid
		}
		return decimal, elements + 1, nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		current := elements + 1
		for key, item := range typed {
			converted, next, err := celClaimActivationValue(item, depth+1, current)
			if err != nil {
				return nil, next, err
			}
			result[key] = converted
			current = next
		}
		return result, current, nil
	case []any:
		result := make([]any, len(typed))
		current := elements + 1
		for index, item := range typed {
			converted, next, err := celClaimActivationValue(item, depth+1, current)
			if err != nil {
				return nil, next, err
			}
			result[index] = converted
			current = next
		}
		return result, current, nil
	default:
		return nil, elements, ErrCredentialInvalid
	}
}

func normalizeCELClaimResult(value any) (any, error) {
	switch typed := value.(type) {
	case int:
		return json.Number(strconv.FormatInt(int64(typed), 10)), nil
	case int8:
		return json.Number(strconv.FormatInt(int64(typed), 10)), nil
	case int16:
		return json.Number(strconv.FormatInt(int64(typed), 10)), nil
	case int32:
		return json.Number(strconv.FormatInt(int64(typed), 10)), nil
	case int64:
		return json.Number(strconv.FormatInt(typed, 10)), nil
	case uint:
		return json.Number(strconv.FormatUint(uint64(typed), 10)), nil
	case uint8:
		return json.Number(strconv.FormatUint(uint64(typed), 10)), nil
	case uint16:
		return json.Number(strconv.FormatUint(uint64(typed), 10)), nil
	case uint32:
		return json.Number(strconv.FormatUint(uint64(typed), 10)), nil
	case uint64:
		return json.Number(strconv.FormatUint(typed, 10)), nil
	case float32:
		return finiteJSONNumber(float64(typed), 32)
	case float64:
		return finiteJSONNumber(typed, 64)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			normalized, err := normalizeCELClaimResult(item)
			if err != nil {
				return nil, err
			}
			result[index] = normalized
		}
		return normalizedClaimValue(result)
	default:
		return normalizedClaimValue(value)
	}
}

func finiteJSONNumber(value float64, bits int) (json.Number, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", ErrCredentialInvalid
	}
	return json.Number(strconv.FormatFloat(value, 'g', -1, bits)), nil
}
