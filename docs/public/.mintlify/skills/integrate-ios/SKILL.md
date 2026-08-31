---
name: integrate-ios
description: Integrate the Latchway Swift SDK into an iOS application while preserving its identity provider, URLSession or framework transport, streaming, cancellation, DPoP, and App Attest boundary.
---

# Integrate iOS

## Confirm the supported source tuple

Read [Release status](/release-status), the generated
[Compatibility matrix](/reference/compatibility), and the
[iOS SDK path](/clients/ios/index). The intended version 1 Swift and
CocoaPods artifacts are not yet published; use the documented authorized source
checkout and local package path until release status changes.

Record the exact server, Swift SDK, contract, protocol, iOS, framework, and
adapter versions. If the generated row is missing or experimental, report that
boundary rather than widening it.

## Preserve the application architecture

- Keep the existing user identity provider and networking or AI framework.
- Use the SDK client or authenticated URLSession transport and bind it to a
  client-facing feature ID. Never put a provider key or physical model selector
  in the app.
- Let the SDK create the P-256 key, DPoP proofs, rotating session, and redirect
  checks. Do not export private key material or share refresh state with another
  component.
- Configure the exact private root Keychain access group documented in
  [iOS installation](/clients/ios/installation), including explicit legacy
  shared groups when the signed app requires migration.
- Preserve async cancellation and streaming. Do not add a blind replay after a
  response byte or for a consumed request body.

## Verify then harden

First complete the local quickstart and confirm the request's user, component,
feature, DPoP result, status, and usage in the console. Then configure App Attest
through [Apple App Attest](/clients/ios/app-attest) and finish the
[iOS production checklist](/clients/ios/production-checklist). Simulator and
development-signed observations do not establish a published standalone Swift
consumer or distribution-derived production candidate.

For widgets or other extensions, follow the
[iOS app-extension path](/clients/ios/app-extensions). Never reuse the
containing app's key or refresh chain, and never describe delegated trust as
direct App Attest.
