package limitscope

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestCanonicalDimensionsOrdersPlatformAndOneExplicitClaim(t *testing.T) {
	t.Parallel()
	got, ok := CanonicalDimensions([]string{"normalized_claim:plan", "platform", "user"})
	want := []string{"user", "platform", "normalized_claim:plan"}
	if !ok || !slices.Equal(got, want) || ScopeType([]string{"normalized_claim:plan"}) != NormalizedClaimScopeType {
		t.Fatalf("canonical dimensions = %#v, %t", got, ok)
	}
	for _, invalid := range [][]string{
		{}, {"limit_plan"}, {"Platform"}, {"normalized_claim:"},
		{"normalized_claim:plan.tier"}, {"normalized_claim:plan", "normalized_claim:region"},
	} {
		if result, valid := CanonicalDimensions(invalid); valid || result != nil {
			t.Fatalf("invalid scope %#v accepted as %#v", invalid, result)
		}
	}
}

func TestClaimDigestRejectsValuesOutsideSealedNormalizedClaimGrammar(t *testing.T) {
	t.Parallel()

	tooMany := make([]any, maximumClaimArrayItems+1)
	invalidUTF8 := string([]byte{0xff})
	for name, value := range map[string]any{
		"present nil":       nil,
		"map":               map[string]any{"secret": "value"},
		"nested array":      []any{[]any{"value"}},
		"integer":           int64(1),
		"float":             1.5,
		"nul string":        "a\x00b",
		"invalid utf8":      invalidUTF8,
		"long string":       strings.Repeat("x", maximumClaimStringBytes+1),
		"invalid number":    json.Number("01"),
		"long number":       json.Number(strings.Repeat("1", maximumClaimNumberBytes+1)),
		"too many elements": tooMany,
	} {
		if digest, ok := ClaimDigest("plan", value, true); ok || digest != "" {
			t.Errorf("%s accepted with digest %q", name, digest)
		}
	}
	for name, value := range map[string]any{
		"string":       "premium",
		"boolean":      true,
		"number":       json.Number("1.25"),
		"scalar array": []any{"premium", false, json.Number("2")},
		"empty array":  []any{},
	} {
		if digest, ok := ClaimDigest("plan", value, true); !ok || !ValidClaimDigest(digest) {
			t.Errorf("%s rejected with digest %q", name, digest)
		}
	}
	if digest, ok := ClaimDigest("plan", map[string]any{"ignored": true}, false); !ok || !ValidClaimDigest(digest) {
		t.Fatalf("missing marker depended on an ignored caller value: %q", digest)
	}
}

func TestClaimDigestSeparatesSelectorPresenceAndValueWithoutRawText(t *testing.T) {
	t.Parallel()
	present, ok := ClaimDigest("plan", "premium-customer-secret", true)
	if !ok || !ValidClaimDigest(present) {
		t.Fatalf("present digest = %q, %t", present, ok)
	}
	missing, ok := ClaimDigest("plan", nil, false)
	otherName, otherOK := ClaimDigest("tier", "premium-customer-secret", true)
	otherValue, valueOK := ClaimDigest("plan", json.Number("7"), true)
	if !ok || !otherOK || !valueOK || present == missing || present == otherName || present == otherValue {
		t.Fatal("claim digest did not bind selector, presence, and canonical value")
	}
	if slices.Contains([]string{present, missing, otherName, otherValue}, "premium-customer-secret") {
		t.Fatal("raw normalized claim escaped the digest boundary")
	}
}

func TestClaimDigestRejectsAlternateNumericBucketIdentities(t *testing.T) {
	t.Parallel()

	for _, canonical := range []string{"0", "1", "-1", "0.5", "-0.5", "10.25"} {
		digest, ok := ClaimDigest("plan", json.Number(canonical), true)
		if !ok || !ValidClaimDigest(digest) {
			t.Errorf("canonical number %q rejected with digest %q", canonical, digest)
		}
	}
	for _, alternate := range []string{
		"-0", "0.0", "-0.0", "00", "01", "-01", "+1",
		"1.0", "1.00", "1.20", "0.50", "1e0", "1E+0", "10e-1",
	} {
		if digest, ok := ClaimDigest("plan", json.Number(alternate), true); ok || digest != "" {
			t.Errorf("alternate numeric spelling %q created bucket identity %q", alternate, digest)
		}
	}
}

func FuzzClaimDigestRejectsUnboundedOrNonCanonicalScalars(f *testing.F) {
	for _, seed := range []string{"premium", "a\x00b", string([]byte{0xff}), "01", "1.25", "1e309"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, candidate string) {
		for _, value := range []any{candidate, json.Number(candidate), []any{candidate}} {
			digest, ok := ClaimDigest("plan", value, true)
			if ok && !ValidClaimDigest(digest) {
				t.Fatalf("accepted value produced invalid opaque digest %q", digest)
			}
		}
	})
}
