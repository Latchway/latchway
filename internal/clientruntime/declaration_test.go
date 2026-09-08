package clientruntime

import "testing"

func TestSharedDeclaration(t *testing.T) {
	for _, caller := range []string{"ios", "android", "react-native"} {
		if err := Validate("3", SharedSDK, caller); err != nil {
			t.Fatal(err)
		}
		for _, version := range []string{"1", "2", "03", "", "4"} {
			if Validate(version, SharedSDK, caller) == nil {
				t.Fatalf("accepted %q", version)
			}
		}
	}
	for _, caller := range []string{"", "javascript", "web", "ios,react-native", " ios"} {
		if Validate("3", SharedSDK, caller) == nil {
			t.Fatalf("accepted caller %q", caller)
		}
	}
	if Validate("3", "ios", "react-native") == nil {
		t.Fatal("legacy SDK accepted caller override")
	}
}

func TestHostAndLegacyBoundaries(t *testing.T) {
	for _, row := range []struct {
		sdk, caller, host string
		want              bool
	}{
		{SharedSDK, "react-native", "ios", true}, {SharedSDK, "ios", "ios", true},
		{SharedSDK, "react-native", "android", true}, {SharedSDK, "android", "android", true},
		{SharedSDK, "ios", "android", false}, {SharedSDK, "android", "ios", false},
		{SharedSDK, "react-native", "watchos", false}, {SharedSDK, "react-native", "react_native_ios", false},
		{"react-native", "", "ios", false}, {"ios", "", "react_native_ios", false},
		{"react-native", "", "react_native_ios", true}, {"javascript", "", "web", true},
	} {
		if got := MatchesHost(row.sdk, row.caller, row.host); got != row.want {
			t.Errorf("%+v: %v", row, got)
		}
	}
	if FrameworkSDK(SharedSDK, "react-native") != "react-native" || FrameworkSDK("ios", "") != "ios" {
		t.Fatal("framework attribution changed")
	}
}
