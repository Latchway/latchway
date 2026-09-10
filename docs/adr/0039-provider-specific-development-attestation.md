# ADR 0039: Provider-specific development attestation acceptance

Status: Accepted for implementation, 2026-09-10. Publication and live-device proof pending.

## Context

A Latchway environment is an operator-owned authorization boundary, not an Apple
signing environment. A TestFlight build uses production App Attest even when it
connects to a Development backend. Conversely, Google Play Console testing
responses simulate verdicts and must never become genuine device trust.

## Decision

Extend `appAttest.environment` with `any` as a server-only acceptance policy.
Keep signed distribution categories independent. Record the actual verified
Apple environment on each key, never `any`; assertions and subsequent session
authorization must respect that actual environment when policy changes. Apple
development evidence remains `app_verified`. Missing signed launch metadata on
older OS versions is not invented and does not establish a distribution/build
claim. Other cryptographic and binding checks remain mandatory.

Production defaults to Apple production only. Development or any in Production
requires the existing explicit `dangerousAllowInProduction` selection flag and
audited activation. New Development Console setups default to any with categories
2 (TestFlight) and 3 (development signing); existing documents retain their values.

Google testing acceptance is an explicit `allowTestingResponses` opt-in restricted
to a Latchway Development environment. Keep minimum device trust/verdict settings;
the provider-specific exception recognizes only Google-verified testing evidence,
including the testing marker, while retaining `debug` as the stored trust level.
It must apply consistently to creation, refresh, access, and shared native/RN
Android root components, and must stop applying when the active policy removes
permission. Direct delegated-component step-up remains Apple-only; this change
does not add Android/Wear OS step-up or promote a delegated parent's simulated
`debug` trust through an Apple child's direct proof. A generic debug
provider or client-claimed trust value cannot use it. No production escape hatch
is allowed for Google testing responses.

For both providers, refresh across any configuration revision boundary requires
fresh attestation evidence. Same-revision refresh is unchanged. This conservative
rule prevents legacy records with incomplete normalized facts from carrying old
evidence into a newly narrowed policy. Existing access-revision checks remain in
place; activation is not a promise of uninterrupted old grants.

The Console separates Apple acceptance and distribution controls and defaults
Google testing to false. Staging is not Development for the Google exception.
SDKs do not select their trust level or add a debug bypass: they use existing
native provider APIs and server-owned challenge/configuration. Firebase identity
and quotas remain independent and unchanged.

## Compatibility and verification

The client wire contract is unchanged. Existing singular Apple policies preserve
their meaning; older servers reject `any` and cannot supply the new Google
exception. Revert affected configurations before rolling back. No existing frozen
contract bundle or SDK lock is replaced; release preparation must assign a new
bundle edition before publishing changed schema bytes.

Required tests cover three-way Apple policy acceptance, actual-key persistence,
assertions, policy narrowing, old-OS metadata absence, Google marked vs unmarked
debug evidence, Development vs Staging/Production, scoped feature access, refresh,
shared native/RN roots, and the existing Apple-only delegated-step-up boundary.
Automated tests are not live
Google/Apple or physical-device evidence.
