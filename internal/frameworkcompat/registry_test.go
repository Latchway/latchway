package frameworkcompat

import (
	"slices"
	"testing"
)

func TestRuntimeFrameworkRegistryIsCanonicalAndSDKBound(t *testing.T) {
	t.Parallel()
	want := []string{
		"android-okhttp", "foundation-models", "langchain-js", "macpaw-openai",
		"openai-js", "react-native-fetch", "swift-openai", "vercel-ai-sdk",
	}
	if got := IDs(); !slices.Equal(got, want) || !slices.IsSorted(got) {
		t.Fatalf("framework IDs = %#v, want %#v", got, want)
	}
	for _, pair := range [][2]string{
		{"android", "android-okhttp"},
		{"ios", "foundation-models"},
		{"ios", "macpaw-openai"},
		{"ios", "swift-openai"},
		{"javascript", "langchain-js"},
		{"javascript", "openai-js"},
		{"javascript", "vercel-ai-sdk"},
		{"react-native", "react-native-fetch"},
	} {
		if !Compatible(pair[0], pair[1]) {
			t.Errorf("expected %q to own %q", pair[0], pair[1])
		}
	}
	if Compatible("ios", "vercel-ai-sdk") || Compatible("javascript", "swift-openai") || Compatible("unknown", "openai-js") {
		t.Fatal("cross-SDK or unknown framework declaration accepted")
	}
}

func TestValidVersionRequiresCanonicalSemVer(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"0.0.0", "4.6.0", "1.0.0-beta.1", "1.0.0+build.001", "1.0.0-beta+exp.sha",
	} {
		if !ValidVersion(value) {
			t.Errorf("canonical version %q rejected", value)
		}
	}
	for _, value := range []string{
		"", "1", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.0.0-01", "1.0.0-..", "1.0.0+",
	} {
		if ValidVersion(value) {
			t.Errorf("noncanonical version %q accepted", value)
		}
	}
}
