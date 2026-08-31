---
name: integrate-android
description: Integrate the Latchway Kotlin SDK into an Android application while preserving its identity provider, OkHttp or framework transport, streaming, cancellation, DPoP, and Play Integrity boundary.
---

# Integrate Android

## Confirm the supported source tuple

Read [Release status](/release-status), the generated
[Compatibility matrix](/reference/compatibility), and the
[Android SDK path](/clients/android/index). The intended version 1 Maven
artifacts are not yet published; use the documented authorized source checkout
and source dependency path until release status changes.

Record the exact server, Kotlin SDK, contract, protocol, Android API, OkHttp or
framework, and adapter versions. Do not turn an experimental compatibility row
into a support claim.

## Preserve the application architecture

- Reuse the existing application identity flow and the SDK identity-token
  provider.
- Bind the Latchway client, OkHttp client, interceptor, authenticator, or call
  factory to one feature ID. Keep provider credentials, physical models, routes,
  prices, and usage out of client control.
- Install the exact interceptor, network origin guard, and authenticator roles
  from [Authorize OkHttp requests](/clients/android/okhttp).
- Let the SDK own the Android Keystore key, DPoP proof, encrypted refresh state,
  redirect checks, and the documented replay boundary. Do not implement those in
  application code.
- Preserve response streaming and coroutine or call cancellation. Do not replay
  after response commitment.
- Apply only the documented R8/ProGuard rules and framework seam for the exact
  tested versions.

## Verify then harden

Complete the local path and confirm the request's user, component, feature,
DPoP result, route, status, and usage in the console. Then configure
[Play Integrity](/clients/android/play-integrity) for the exact Play-distributed
signed app and finish the
[Android production checklist](/clients/android/production-checklist). An
emulator, sideloaded build, or local conformance test is not production
integrity evidence.
