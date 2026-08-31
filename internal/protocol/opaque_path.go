package protocol

import (
	"net/url"
	pathpkg "path"
	"regexp"
	"strings"
)

const (
	// MaximumOpaqueHTTPPathRules bounds either the preferred template set or
	// the legacy prefix set owned by one opaque feature.
	MaximumOpaqueHTTPPathRules = 32
	// MaximumOpaqueHTTPPathTemplateBytes bounds one administrator-authored
	// provider-relative template.
	MaximumOpaqueHTTPPathTemplateBytes = 512
	// MaximumOpaqueHTTPProviderPathBytes matches the public opaque endpoint
	// boundary. Templates are intentionally narrower than request paths.
	MaximumOpaqueHTTPProviderPathBytes = 2048
)

var opaqueHTTPPathCapturePattern = regexp.MustCompile(`^\{([a-z][a-z0-9_]{0,62})\}$`)

type opaqueHTTPPathTemplate struct {
	segments []opaqueHTTPPathTemplateSegment
	trailing bool
}

type opaqueHTTPPathTemplateSegment struct {
	literal string
	capture bool
}

// ValidOpaqueHTTPProviderPath reports whether value is a canonical,
// provider-relative opaque path. It cannot contain an authority, query,
// fragment, encoded alias, empty interior segment, or traversal segment.
func ValidOpaqueHTTPProviderPath(value string) bool {
	if len(value) < 2 || len(value) > MaximumOpaqueHTTPProviderPathBytes || value[0] != '/' ||
		strings.ContainsAny(value, "\\%?#") || strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] >= 0x7f {
			return false
		}
	}
	if (&url.URL{Path: value}).EscapedPath() != value {
		return false
	}
	canonical := pathpkg.Clean(value)
	if strings.HasSuffix(value, "/") && canonical != "/" {
		canonical += "/"
	}
	return canonical == value
}

// ValidOpaqueHTTPPathTemplate reports whether value is one exact-depth path
// template. A capture must occupy a complete segment and uses the form
// {lower_snake_name}. Catch-alls, partial captures, duplicate capture names,
// encoded aliases, queries, fragments, and traversal are rejected.
func ValidOpaqueHTTPPathTemplate(value string) bool {
	_, ok := parseOpaqueHTTPPathTemplate(value)
	return ok
}

// ValidOpaqueHTTPPathTemplates validates one bounded, pairwise-disjoint set.
// Pairwise disjointness ensures at most one template matches every path.
func ValidOpaqueHTTPPathTemplates(templates []string) bool {
	if len(templates) == 0 || len(templates) > MaximumOpaqueHTTPPathRules {
		return false
	}
	for index, template := range templates {
		if !ValidOpaqueHTTPPathTemplate(template) {
			return false
		}
		for previous := 0; previous < index; previous++ {
			if OpaqueHTTPPathTemplatesOverlap(templates[previous], template) {
				return false
			}
		}
	}
	return true
}

// OpaqueHTTPPathTemplatesOverlap reports whether one canonical provider path
// could match both templates. Valid template sets reject overlap so selection
// never depends on declaration order or capture naming.
func OpaqueHTTPPathTemplatesOverlap(left, right string) bool {
	leftTemplate, leftOK := parseOpaqueHTTPPathTemplate(left)
	rightTemplate, rightOK := parseOpaqueHTTPPathTemplate(right)
	if !leftOK || !rightOK || leftTemplate.trailing != rightTemplate.trailing ||
		len(leftTemplate.segments) != len(rightTemplate.segments) {
		return false
	}
	for index := range leftTemplate.segments {
		leftSegment := leftTemplate.segments[index]
		rightSegment := rightTemplate.segments[index]
		if !leftSegment.capture && !rightSegment.capture && leftSegment.literal != rightSegment.literal {
			return false
		}
	}
	return true
}

// OpaqueHTTPPathMatchesTemplate matches one already bounded provider path
// against one exact-depth template. Captures are matching constraints only;
// they are never substituted into an authority or another destination.
func OpaqueHTTPPathMatchesTemplate(providerPath, template string) bool {
	if !ValidOpaqueHTTPProviderPath(providerPath) {
		return false
	}
	parsed, ok := parseOpaqueHTTPPathTemplate(template)
	if !ok || parsed.trailing != strings.HasSuffix(providerPath, "/") {
		return false
	}
	pathSegments := opaqueHTTPPathSegments(providerPath)
	if len(pathSegments) != len(parsed.segments) {
		return false
	}
	for index, segment := range parsed.segments {
		if !segment.capture && segment.literal != pathSegments[index] {
			return false
		}
	}
	return true
}

func parseOpaqueHTTPPathTemplate(value string) (opaqueHTTPPathTemplate, bool) {
	if len(value) < 2 || len(value) > MaximumOpaqueHTTPPathTemplateBytes || value[0] != '/' ||
		strings.ContainsAny(value, "\\%?#*") || strings.Contains(value, "//") {
		return opaqueHTTPPathTemplate{}, false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] >= 0x7f {
			return opaqueHTTPPathTemplate{}, false
		}
	}
	trailing := strings.HasSuffix(value, "/")
	segments := opaqueHTTPPathSegments(value)
	if len(segments) == 0 {
		return opaqueHTTPPathTemplate{}, false
	}
	parsed := opaqueHTTPPathTemplate{
		segments: make([]opaqueHTTPPathTemplateSegment, 0, len(segments)),
		trailing: trailing,
	}
	seenCaptures := make(map[string]struct{})
	canonicalSegments := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" {
			return opaqueHTTPPathTemplate{}, false
		}
		matches := opaqueHTTPPathCapturePattern.FindStringSubmatch(segment)
		if len(matches) == 2 {
			if _, duplicate := seenCaptures[matches[1]]; duplicate {
				return opaqueHTTPPathTemplate{}, false
			}
			seenCaptures[matches[1]] = struct{}{}
			parsed.segments = append(parsed.segments, opaqueHTTPPathTemplateSegment{capture: true})
			canonicalSegments = append(canonicalSegments, "capture")
			continue
		}
		if strings.ContainsAny(segment, "{}") {
			return opaqueHTTPPathTemplate{}, false
		}
		parsed.segments = append(parsed.segments, opaqueHTTPPathTemplateSegment{literal: segment})
		canonicalSegments = append(canonicalSegments, segment)
	}
	canonical := "/" + strings.Join(canonicalSegments, "/")
	if trailing {
		canonical += "/"
	}
	if !ValidOpaqueHTTPProviderPath(canonical) {
		return opaqueHTTPPathTemplate{}, false
	}
	return parsed, true
}

func opaqueHTTPPathSegments(value string) []string {
	withoutRoot := strings.TrimPrefix(value, "/")
	withoutRoot = strings.TrimSuffix(withoutRoot, "/")
	if withoutRoot == "" {
		return nil
	}
	return strings.Split(withoutRoot, "/")
}
