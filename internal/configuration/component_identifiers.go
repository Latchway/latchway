package configuration

// nativeReactNativeRootPair permits the same signed mobile application to embed
// both SDKs. Resolution and attestation remain bound to the exact wire platform;
// this is not an alias and never permits a root to overlap a delegated component.
func nativeReactNativeRootPair(left, right ComponentDefinition) bool {
	if left.FamilyRole != "root" || right.FamilyRole != "root" ||
		left.Attestation.Strategy != "direct" || right.Attestation.Strategy != "direct" {
		return false
	}
	ios := ((left.Platform == "ios" && right.Platform == "react_native_ios") ||
		(left.Platform == "react_native_ios" && right.Platform == "ios")) &&
		left.Kind == "main_app" && right.Kind == "main_app" &&
		left.Attestation.Provider == "app_attest" && right.Attestation.Provider == "app_attest"
	android := ((left.Platform == "android" && right.Platform == "react_native_android") ||
		(left.Platform == "react_native_android" && right.Platform == "android")) &&
		left.Kind == "android_app" && right.Kind == "android_app" &&
		left.Attestation.Provider == "play_integrity" && right.Attestation.Provider == "play_integrity"
	return ios || android
}

func semanticIdentifierOwner(raw map[string]any) ComponentDefinition {
	attestation := objectValue(raw, "attestation")
	return ComponentDefinition{
		Platform: stringValue(raw, "platform"), Kind: stringValue(raw, "kind"),
		FamilyRole: stringValue(raw, "familyRole"),
		Attestation: ComponentAttestationPolicy{
			Strategy: stringValue(attestation, "strategy"), Provider: stringValue(attestation, "provider"),
		},
	}
}
