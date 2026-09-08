package configuration

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalSharedNativeDelegatedVectors(t *testing.T) {
	data, err := os.ReadFile("../../api/test-vectors/shared-native/v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Components []struct {
			Host, Platform, Caller, Role string
			Policy                       []string
			Allowed                      bool
		} `json:"delegated_components"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Components) < 11 {
		t.Fatal("incomplete component vectors")
	}
	for _, row := range vectors.Components {
		snapshot := ActiveSnapshot{
			attestations: map[string]AttestationPolicy{"host": {ID: "host", Platforms: map[string]PlatformAttestation{
				row.Host: {Mode: "required", SharedNativeCallers: row.Policy},
			}}},
			components: map[string]ComponentDefinition{"component": {ID: "component", Platform: row.Platform, FamilyRole: row.Role}},
		}
		if got := snapshot.AllowsDelegatedClientRuntime("native", row.Caller, row.Host, "component"); got != row.Allowed {
			t.Errorf("component policy mismatch: %+v got %v", row, got)
		}
		if snapshot.AllowsDelegatedClientRuntime("native", row.Caller, row.Host, "missing") {
			t.Fatal("unknown component allowed")
		}
	}
}

func TestSharedNativePolicySurvivesStrictJSONDecoder(t *testing.T) {
	var selection PlatformAttestation
	if err := json.Unmarshal([]byte(`{"provider":"app_attest","mode":"required","sharedNativeCallers":["ios","react-native"]}`), &selection); err != nil {
		t.Fatal(err)
	}
	if !SharedNativeCallersValid("ios", selection) || len(selection.SharedNativeCallers) != 2 {
		t.Fatal("shared callers were lost during decoding")
	}
	if err := json.Unmarshal([]byte(`{"provider":"app_attest","mode":"required","sharedNativeCallers":null}`), &selection); err == nil {
		t.Fatal("null opt-in accepted")
	}
}

func TestSharedNativePolicyIsExplicitAndHostScoped(t *testing.T) {
	selection := PlatformAttestation{Mode: "required", Provider: "app_attest"}
	snapshot := func(value PlatformAttestation) ActiveSnapshot {
		return ActiveSnapshot{attestations: map[string]AttestationPolicy{
			"mobile": {ID: "mobile", Platforms: map[string]PlatformAttestation{"ios": value}},
		}}
	}
	if snapshot(selection).AllowsClientRuntime("native", "react-native", "ios", false) {
		t.Fatal("implicit shared policy")
	}
	selection.SharedNativeCallers = []string{"ios", "react-native"}
	active := snapshot(selection)
	if !active.AllowsClientRuntime("native", "react-native", "ios", false) || !active.AllowsClientRuntime("native", "ios", "ios", false) {
		t.Fatal("explicit callers rejected")
	}
	if !active.AllowsClientRuntime("native", "react-native", "ios", true) {
		t.Fatal("same-host delegated attribution rejected; independent component authorization is still required")
	}
	for _, row := range []struct {
		sdk, caller, platform string
		delegated             bool
	}{
		{"native", "android", "ios", false}, {"native", "react-native", "android", false},
		{"native", "android", "ios", true}, {"react-native", "", "ios", false},
		{"ios", "react-native", "ios", false}, {"native", "", "ios", false},
	} {
		if active.AllowsClientRuntime(row.sdk, row.caller, row.platform, row.delegated) {
			t.Fatalf("accepted %+v", row)
		}
	}
	if !active.AllowsClientRuntime("ios", "", "ios", false) {
		t.Fatal("changed legacy policy")
	}
	_, cloned, _ := active.RequiredAttestationForPlatform("ios")
	cloned.SharedNativeCallers[0] = "android"
	if !active.AllowsClientRuntime("native", "ios", "ios", false) {
		t.Fatal("snapshot leaked mutable caller slice")
	}
}

func TestSharedNativePolicyRejectsInvalidPlacement(t *testing.T) {
	for _, row := range []struct {
		platform, mode string
		callers        []string
	}{
		{"web", "required", []string{"react-native"}}, {"react_native_ios", "required", []string{"react-native"}},
		{"ios", "disabled", []string{"ios"}}, {"android", "preferred", []string{"android"}},
		{"ios", "required", []string{"android"}}, {"android", "required", []string{"ios"}},
		{"ios", "required", []string{"ios", "ios"}}, {"ios", "required", []string{"javascript"}},
	} {
		if SharedNativeCallersValid(row.platform, PlatformAttestation{Mode: row.mode, SharedNativeCallers: row.callers}) {
			t.Fatalf("accepted %+v", row)
		}
	}
}
