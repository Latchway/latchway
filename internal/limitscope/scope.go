// Package limitscope owns the closed, canonical quota-scope vocabulary shared
// by configuration activation, policy facts, data-plane validation, and quota
// persistence. A limit plan is deliberately absent: its selected identifier is
// already an implicit part of every durable quota bucket identity.
package limitscope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	InstallationFamilyDimension  = "installation_family"
	ClientComponentDimension     = "client_component"
	ComponentDefinitionDimension = "component_definition"
	ComponentKindDimension       = "component_kind"
	TrustSourceDimension         = "trust_source"
	PlatformDimension            = "platform"
	NormalizedClaimPrefix        = "normalized_claim:"
	NormalizedClaimScopeType     = "normalized_claim"
	MaximumDimensions            = 16

	normalizedClaimDigestDomain = "latchway/quota-normalized-claim/v1\x00"
	maximumClaimStringBytes     = 2048
	maximumClaimNumberBytes     = 64
	maximumClaimArrayItems      = 64
	maximumClaimEncodedBytes    = 16 << 10
)

var (
	fixedOrder = []string{
		"organization",
		"application",
		"environment",
		"user",
		"installation",
		InstallationFamilyDimension,
		ClientComponentDimension,
		ComponentDefinitionDimension,
		ComponentKindDimension,
		TrustSourceDimension,
		"feature",
		"route",
		"upstream",
		"model",
		PlatformDimension,
	}
	normalizedClaimNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	canonicalClaimNumberPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$`)
	digestPattern               = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// CanonicalDimensions validates and orders one configured scope. At most one
// normalized-claim selector is accepted so "normalized claim" remains one
// dimension rather than an unbounded family hidden inside a single rule.
func CanonicalDimensions(input []string) ([]string, bool) {
	if len(input) == 0 || len(input) > MaximumDimensions {
		return nil, false
	}
	seen := make(map[string]struct{}, len(input))
	claimSelector := ""
	for _, dimension := range input {
		if _, duplicate := seen[dimension]; duplicate {
			return nil, false
		}
		seen[dimension] = struct{}{}
		if slices.Contains(fixedOrder, dimension) {
			continue
		}
		if _, ok := NormalizedClaimName(dimension); !ok || claimSelector != "" {
			return nil, false
		}
		claimSelector = dimension
	}
	result := make([]string, 0, len(input))
	for _, dimension := range fixedOrder {
		if _, ok := seen[dimension]; ok {
			result = append(result, dimension)
		}
	}
	if claimSelector != "" {
		result = append(result, claimSelector)
	}
	return result, true
}

// NormalizedClaimName returns the explicit top-level normalized claim selected
// by dimension. Names are already canonical identifiers; aliases, paths,
// uppercase spellings, and empty selectors are rejected.
func NormalizedClaimName(dimension string) (string, bool) {
	if !strings.HasPrefix(dimension, NormalizedClaimPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(dimension, NormalizedClaimPrefix)
	return name, normalizedClaimNamePattern.MatchString(name)
}

// ScopeType returns the non-secret persisted type for one canonical scope.
func ScopeType(dimensions []string) string {
	if len(dimensions) != 1 {
		return "composite"
	}
	if _, ok := NormalizedClaimName(dimensions[0]); ok {
		return NormalizedClaimScopeType
	}
	return dimensions[0]
}

// ClaimDigest produces the only representation of a normalized claim allowed
// to cross the policy/quota boundary. Presence is part of the domain-separated
// encoding, so an omitted claim remains a real scope identity and cannot skip
// enforcement. Normalized claim values are JSON scalars or scalar arrays;
// json.Number values must already use the single narrow decimal spelling
// accepted below, so equivalent lexical forms cannot split quota identity.
// encoding/json is deterministic for that bounded value surface.
func ClaimDigest(name string, value any, present bool) (string, bool) {
	if !normalizedClaimNamePattern.MatchString(name) {
		return "", false
	}
	encoded := []byte("missing")
	presence := "0"
	if present {
		canonical, ok := canonicalClaimValue(value)
		if !ok {
			return "", false
		}
		var err error
		encoded, err = json.Marshal(canonical)
		if err != nil || len(encoded) == 0 || len(encoded) > maximumClaimEncodedBytes {
			return "", false
		}
		presence = "1"
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(normalizedClaimDigestDomain))
	for _, part := range [][]byte{[]byte(name), []byte(presence), encoded} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(part)
	}
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil)), true
}

func canonicalClaimValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		return typed, utf8.ValidString(typed) && len(typed) <= maximumClaimStringBytes &&
			!strings.ContainsRune(typed, '\x00')
	case bool:
		return typed, true
	case json.Number:
		raw := typed.String()
		if len(raw) == 0 || len(raw) > maximumClaimNumberBytes || raw == "-0" ||
			!canonicalClaimNumberPattern.MatchString(raw) {
			return nil, false
		}
		if _, err := json.Marshal(typed); err != nil {
			return nil, false
		}
		return typed, true
	case []any:
		if len(typed) > maximumClaimArrayItems {
			return nil, false
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			canonical, ok := canonicalClaimValue(item)
			if !ok {
				return nil, false
			}
			switch canonical.(type) {
			case string, bool, json.Number:
				result[index] = canonical
			default:
				return nil, false
			}
		}
		return result, true
	default:
		return nil, false
	}
}

// ClaimDigests returns only selected opaque claim identities. It never copies
// raw values. Selectors are sorted so callers receive deterministic maps even
// when configuration input order differed.
func ClaimDigests(dimensions []string, claims map[string]any) (map[string]string, bool) {
	selectors := make([]string, 0, 1)
	for _, dimension := range dimensions {
		if name, ok := NormalizedClaimName(dimension); ok {
			selectors = append(selectors, name)
		}
	}
	sort.Strings(selectors)
	result := make(map[string]string, len(selectors))
	for _, name := range selectors {
		value, present := claims[name]
		digest, ok := ClaimDigest(name, value, present)
		if !ok {
			return nil, false
		}
		result[name] = digest
	}
	return result, true
}

// ValidClaimDigest validates an opaque value supplied by the sealed-policy
// boundary. Quota never accepts or reconstructs raw normalized claims.
func ValidClaimDigest(value string) bool { return digestPattern.MatchString(value) }
