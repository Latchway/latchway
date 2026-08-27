package identity

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const maxNormalizedClaimsBytes = 16 << 10

var normalizedClaimPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ClaimMapper copies a bounded, configured projection of verified claims.
type ClaimMapper interface {
	Map(map[string]any) (map[string]any, error)
}

// PathMapper maps normalized names to dot-separated source claim paths.
type PathMapper map[string]string

func (mapper PathMapper) Map(claims map[string]any) (map[string]any, error) {
	if err := mapper.validate(); err != nil {
		return nil, err
	}
	result := make(map[string]any, len(mapper))
	for normalized, source := range mapper {
		if !normalizedClaimPattern.MatchString(normalized) || !claimPathPattern.MatchString(source) {
			return nil, fmt.Errorf("%w: invalid claim mapping", ErrConfiguration)
		}
		value, ok := claimAtPath(claims, source)
		if !ok || value == nil {
			continue
		}
		safe, err := normalizedClaimValue(value)
		if err != nil {
			return nil, fmt.Errorf("%w: mapped claim %s", ErrCredentialInvalid, normalized)
		}
		result[normalized] = safe
	}
	return validateNormalizedClaims(result)
}

func (mapper PathMapper) validate() error {
	if len(mapper) > 32 {
		return fmt.Errorf("%w: too many claim mappings", ErrConfiguration)
	}
	for normalized, source := range mapper {
		if !normalizedClaimPattern.MatchString(normalized) || !claimPathPattern.MatchString(source) {
			return fmt.Errorf("%w: invalid claim mapping", ErrConfiguration)
		}
	}
	return nil
}

func claimAtPath(claims map[string]any, path string) (any, bool) {
	current := any(claims)
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func normalizedClaimValue(value any) (any, error) {
	switch typed := value.(type) {
	case string:
		if len(typed) > 2048 || strings.ContainsRune(typed, '\x00') {
			return nil, ErrCredentialInvalid
		}
		return typed, nil
	case bool:
		return typed, nil
	case json.Number:
		if len(typed.String()) > 64 {
			return nil, ErrCredentialInvalid
		}
		return typed, nil
	case []any:
		if len(typed) > 64 {
			return nil, ErrCredentialInvalid
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			scalar, err := normalizedClaimValue(item)
			if err != nil {
				return nil, err
			}
			switch scalar.(type) {
			case string, bool, json.Number:
			default:
				return nil, ErrCredentialInvalid
			}
			result[index] = scalar
		}
		return result, nil
	default:
		return nil, ErrCredentialInvalid
	}
}

func validateNormalizedClaims(claims map[string]any) (map[string]any, error) {
	if claims == nil || len(claims) > 32 {
		return nil, fmt.Errorf("%w: normalized claim set", ErrCredentialInvalid)
	}
	result := make(map[string]any, len(claims))
	for name, value := range claims {
		if !normalizedClaimPattern.MatchString(name) {
			return nil, fmt.Errorf("%w: normalized claim name", ErrCredentialInvalid)
		}
		safe, err := normalizedClaimValue(value)
		if err != nil {
			return nil, fmt.Errorf("%w: normalized claim %s", ErrCredentialInvalid, name)
		}
		result[name] = safe
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxNormalizedClaimsBytes {
		return nil, fmt.Errorf("%w: normalized claim size", ErrCredentialInvalid)
	}
	return result, nil
}
