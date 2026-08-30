package configuration

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func TestValidatorCompilesExplicitPrivateDestinationAllowlist(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	documentObject := privateDestinationDocument(t, "https://10.20.30.40/v1", []any{"10.20.30.40/32"})
	document, err := json.Marshal(documentObject)
	if err != nil {
		t.Fatal(err)
	}
	if issues := validator.SchemaIssues(document); len(issues) != 0 {
		t.Fatalf("private destination document is not schema-valid: %+v", issues)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("private destination configuration rejected: %+v", report.Issues)
	}

	decoded, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	compiledPolicy := objectValue(objectArray(objectValue(decoded.(map[string]any), "spec"), "upstreams")[0], "destinationPolicy")
	if compiledPolicy["allowPrivateNetworks"] != true || len(stringArray(compiledPolicy, "allowedCidrs")) != 1 ||
		stringArray(compiledPolicy, "allowedCidrs")[0] != "10.20.30.40/32" {
		t.Fatalf("compiled destination policy = %#v", compiledPolicy)
	}

	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000", "env_00000000000000000000000000", document, compiled,
	)
	if err != nil {
		t.Fatal(err)
	}
	configured, ok := snapshot.Upstream("primary")
	if !ok || !configured.DestinationPolicy.AllowPrivateNetworks ||
		len(configured.DestinationPolicy.AllowedCIDRs) != 1 ||
		configured.DestinationPolicy.AllowedCIDRs[0] != netip.MustParsePrefix("10.20.30.40/32") {
		t.Fatalf("runtime private destination policy = %+v ok=%t", configured.DestinationPolicy, ok)
	}
	configured.DestinationPolicy.AllowedCIDRs[0] = netip.MustParsePrefix("10.20.30.41/32")
	again, _ := snapshot.Upstream("primary")
	if again.DestinationPolicy.AllowedCIDRs[0] != netip.MustParsePrefix("10.20.30.40/32") {
		t.Fatalf("runtime private CIDR slice was mutable: %+v", again.DestinationPolicy)
	}

	publicDocument := privateDestinationDocument(t, "https://api.example.test/v1", []any{"10.20.30.40/32"})
	publicJSON, _ := json.Marshal(publicDocument)
	publicReport, publicCompiled := validator.Validate(publicJSON, testEnvironment(), time.Now())
	if !publicReport.Valid || len(publicCompiled) == 0 {
		t.Fatalf("public target with private allowlist rejected: %+v", publicReport.Issues)
	}

	ipv6Document := privateDestinationDocument(t, "https://[fd12:3456::7]/v1", []any{"fd12:3456::/48"})
	ipv6JSON, _ := json.Marshal(ipv6Document)
	ipv6Report, ipv6Compiled := validator.Validate(ipv6JSON, testEnvironment(), time.Now())
	if !ipv6Report.Valid || len(ipv6Compiled) == 0 {
		t.Fatalf("IPv6 ULA target rejected: %+v", ipv6Report.Issues)
	}
}

func TestValidatorRejectsUnsafePrivateDestinationPolicies(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tooManyCIDRs := make([]any, 33)
	for index := range tooManyCIDRs {
		tooManyCIDRs[index] = netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, 0, byte(index), 1}), 32,
		).String()
	}
	tests := []struct {
		name        string
		baseURL     string
		allow       bool
		includeFlag bool
		cidrs       []any
		schemaOnly  bool
		issue       string
	}{
		{name: "opt in without CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{}, schemaOnly: true},
		{name: "CIDR without opt in", baseURL: "https://api.example.test/v1", cidrs: []any{"10.0.0.0/8"}, schemaOnly: true},
		{name: "CIDR with explicit false", baseURL: "https://api.example.test/v1", includeFlag: true, cidrs: []any{"10.0.0.0/8"}, schemaOnly: true},
		{name: "duplicate CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"10.0.0.0/8", "10.0.0.0/8"}, schemaOnly: true},
		{name: "too many CIDRs", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: tooManyCIDRs, schemaOnly: true},
		{name: "noncanonical host bits", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"10.2.3.4/16"}, issue: "upstream_private_cidrs_invalid"},
		{name: "noncanonical text", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"FD00::/8"}, issue: "upstream_private_cidrs_invalid"},
		{name: "loopback CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"127.0.0.0/8"}, issue: "upstream_private_cidrs_invalid"},
		{name: "link local CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"169.254.0.0/16"}, issue: "upstream_private_cidrs_invalid"},
		{name: "metadata CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"169.254.169.254/32"}, issue: "upstream_private_cidrs_invalid"},
		{name: "carrier NAT CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"100.64.0.0/10"}, issue: "upstream_private_cidrs_invalid"},
		{name: "documentation CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"192.0.2.0/24"}, issue: "upstream_private_cidrs_invalid"},
		{name: "multicast CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"224.0.0.0/4"}, issue: "upstream_private_cidrs_invalid"},
		{name: "unspecified CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"0.0.0.0/32"}, issue: "upstream_private_cidrs_invalid"},
		{name: "public CIDR", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"1.1.1.1/32"}, issue: "upstream_private_cidrs_invalid"},
		{name: "overlap", baseURL: "https://api.example.test/v1", allow: true, includeFlag: true, cidrs: []any{"10.20.0.0/16", "10.20.30.0/24"}, issue: "upstream_private_cidrs_invalid"},
		{name: "literal outside allowlist", baseURL: "https://10.20.31.40/v1", allow: true, includeFlag: true, cidrs: []any{"10.20.30.0/24"}, issue: "upstream_private_destination"},
		{name: "loopback literal", baseURL: "https://127.0.0.1/v1", allow: true, includeFlag: true, cidrs: []any{"10.0.0.0/8"}, issue: "upstream_private_destination"},
		{name: "metadata literal", baseURL: "https://169.254.169.254/v1", allow: true, includeFlag: true, cidrs: []any{"10.0.0.0/8"}, issue: "upstream_private_destination"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			document := configurationObject(t)
			upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
			upstream["baseUrl"] = test.baseURL
			destination := map[string]any{"allowedCidrs": test.cidrs}
			if test.includeFlag {
				destination["allowPrivateNetworks"] = test.allow
			}
			upstream["destinationPolicy"] = destination
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if test.schemaOnly {
				if issues := validator.SchemaIssues(encoded); len(issues) == 0 {
					t.Fatal("unsafe flag/CIDR relationship was schema-valid")
				}
				return
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.issue) {
				t.Fatalf("unsafe private destination policy activated: report=%+v compiled=%s", report, compiled)
			}
		})
	}
}

func TestActiveSnapshotRevalidatesPrivateDestinationPolicy(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	documentObject := privateDestinationDocument(t, "https://10.20.30.40/v1", []any{"10.20.30.40/32"})
	document, _ := json.Marshal(documentObject)
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("valid private policy rejected: %+v", report.Issues)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{name: "missing CIDRs", mutate: func(_ map[string]any, policy map[string]any) { policy["allowedCidrs"] = []any{} }},
		{name: "flag disabled", mutate: func(_ map[string]any, policy map[string]any) { policy["allowPrivateNetworks"] = false }},
		{name: "noncanonical CIDR", mutate: func(_ map[string]any, policy map[string]any) { policy["allowedCidrs"] = []any{"10.20.30.40/24"} }},
		{name: "duplicate CIDR", mutate: func(_ map[string]any, policy map[string]any) {
			policy["allowedCidrs"] = []any{"10.20.30.40/32", "10.20.30.40/32"}
		}},
		{name: "overlapping CIDRs", mutate: func(_ map[string]any, policy map[string]any) {
			policy["allowedCidrs"] = []any{"10.20.0.0/16", "10.20.30.40/32"}
		}},
		{name: "literal outside allowlist", mutate: func(upstream map[string]any, policy map[string]any) {
			upstream["baseUrl"] = "https://10.20.30.41/v1"
		}},
		{name: "hard-blocked literal", mutate: func(upstream map[string]any, policy map[string]any) {
			upstream["baseUrl"] = "https://169.254.169.254/v1"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decoded, decodeErr := jsonsafe.Decode(compiled)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			root := decoded.(map[string]any)
			upstream := objectArray(objectValue(root, "spec"), "upstreams")[0]
			policy := objectValue(upstream, "destinationPolicy")
			test.mutate(upstream, policy)
			corrupt, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, snapshotErr := newActiveSnapshot(
				"rev_00000000000000000000000000", "env_00000000000000000000000000", document, corrupt,
			); snapshotErr == nil {
				t.Fatal("corrupt private destination snapshot was accepted")
			}
		})
	}
}

func privateDestinationDocument(t *testing.T, baseURL string, cidrs []any) map[string]any {
	t.Helper()
	document := configurationObject(t)
	upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
	upstream["baseUrl"] = baseURL
	upstream["destinationPolicy"] = map[string]any{
		"allowPrivateNetworks": true,
		"allowedCidrs":         cidrs,
	}
	return document
}
