---
name: integrate-react-native
description: Integrate the Latchway React Native SDK with its native iOS and Android transports while preserving existing JavaScript identity, streaming, cancellation, native DPoP keys, and platform attestation.
---

# Integrate React Native

## Confirm the native-backed tuple

Read [Release status](/release-status), the generated
[Compatibility matrix](/reference/compatibility), and the
[React Native SDK path](/clients/react-native/index). The intended version
1 npm package is not yet published; use the documented authorized source checkout
and example until release status changes.

Record the exact React Native, iOS and Android SDK, server, contract, protocol,
New Architecture, and framework versions. Current React Native 0.82 source
evidence is experimental, not a broad version range or stable release.

## Keep JavaScript above the native trust boundary

- Complete [iOS native setup](/clients/react-native/ios-native-setup) and
  [Android native setup](/clients/react-native/android-native-setup) separately,
  then configure the JavaScript identity callback once.
- Use the native-backed client and `fetchFor` with a feature ID. Never place an
  upstream key or physical model in JavaScript.
- Keep Secure Enclave or Android Keystore key operations, DPoP signing, refresh
  storage, App Attest, and Play Integrity inside the native modules. Do not pass
  raw proofs, private keys, or refresh tokens across the bridge.
- Preserve streaming and `AbortSignal` cancellation within documented bridge
  bounds. Retry only the SDK's exact replayable pre-dispatch cases.
- Do not present this setup as a Web integration; browser WebCrypto and origin
  trust are different.

## Verify both platforms

Run the version-matched example and conformance coverage on iOS and Android and
confirm the same TypeScript feature request uses each native transport. Inspect
the console for the platform, component, trust source, feature, DPoP result,
status, and usage.

Development-signed iOS observations do not close protected distribution
evidence. React Native Android physical Play Integrity and delegated-extension
runtime remain separate gates. Finish the
[React Native production checklist](/clients/react-native/production-checklist)
and [Physical-device proof](/mobile/device-proof) before making a production
claim.
