# Development attestation: implementation and verification

Source checkpoint: 2026-09-10. Prepared for server 1.1.3; publication and VPS
activation are separate steps and are not claimed by this source checkpoint.

## Implemented behavior

- App Attest's existing server `environment` setting accepts `development`,
  `production`, or `any`. Existing singleton settings keep their meaning.
- The cryptographically verified Apple AAGUID determines the key's actual
  environment. `any` is never a persisted key environment or an Apple entitlement.
  Assertions recheck the key's environment against current acceptance policy.
- Accepting Apple development in a Production-kind Latchway environment requires
  `dangerousAllowInProduction: true`; the Console exposes an explicit warning.
- Signing/distribution categories are independent of Apple environment. New
  Development Console setups default to `any` and categories 2/3 (TestFlight /
  development signing). Existing configurations do not change automatically.
  Older Apple evidence without signed category/build extensions is still handled
  as older evidence, not presented as cryptographic proof of a distribution type.
- Play `allowTestingResponses` is explicit, false by default in new Console
  setups, and valid only in Development. Minimum trust remains device/strong,
  and all configured package, certificate, version, request-binding, freshness,
  licensing and device-verdict checks remain enforced.
- Google testing evidence stays `debug`. A provider-specific exception permits
  it only under that Development policy; generic debug evidence cannot use the
  exception. CEL conditions explicitly demanding device-verified trust still
  reject it. Real Play evidence continues to work in the same opted-in policy.
- Session exchange, refresh and feature enforcement use the same scoped rule.
  After any active configuration revision change, App Attest/Play refresh
  requires fresh evidence. Even an unrelated revision can cause re-attestation;
  this is deliberately conservative for existing grants without immutable
  provider-specific facts. In-flight upstream requests are not terminated.
- Direct component step-up preserves normalized provider facts alongside its
  delegation markers. Native and React Native shared roots retain their existing
  scope, identity and key boundaries. Direct delegated step-up remains Apple-only;
  no Android/Wear OS step-up is added. A child cannot upgrade a delegated parent's
  simulated `debug` trust by presenting its own genuine Apple proof.

No SQL migration, client wire change, identity-provider dependency, client debug
flag, quota reset or additional host bootstrap is needed. SDK changes add
regressions and instructions around existing native behavior rather than a
second attestation implementation.

## Verification

The final server 1.1.3 candidate was rerun after the policy spelling changed to
`any`: complete PostgreSQL-backed Go tests, race checks for seven affected
packages, static analysis, executable build, Go module integrity, contract
validation, 18 focused schema/version/reference tests, Console lint/type checks,
307 Console unit tests, deterministic assets, and canonical public-docs checks
pass. The Console browser suite passes 43 tests with one optional live-stack
test skipped. Its first concurrent run had two navigation timeouts; the complete
single-worker rerun passes without changing test assertions. The pinned Go
vulnerability scanner finds no reachable vulnerable symbols; four imported-package
and three required-module advisories remain non-reachable follow-ups.

Measured local results from the implementation checkpoint (SDK release checks
are tracked separately in each SDK repository):

- The complete Go package suite passes with a dedicated PostgreSQL 18.6 test
  database, including cryptographic Apple acceptance/narrowing and ten Play
  exchange/authorization/refresh lifecycle scenarios. Race checks pass for
  attestation, configuration, session and policy packages. The server executable
  builds successfully and `go vet ./...` passes.
- Console: 307 unit and 43 control-plane browser tests pass across Chromium,
  Firefox, WebKit and mobile WebKit. TypeScript, lint, generated Admin API,
  production build and deterministic asset checks pass.
- iOS: 234 tests pass; one live-conformance test is skipped.
- Android: 189 tests pass; one live-conformance test is skipped.
- React Native: 188 unit, 13 runtime, 10 iOS bridge and 14 Android bridge tests
  pass. Type checking, lint and native-boundary checks pass. Bridge verification
  uses current local native SDKs, not newly published packages.
- All three SDK documentation bundles pass their four-test suites. The server's
  public-docs check, focused schema tests and contract validator pass.
- Release-candidate contract 1.1.2 regeneration is deterministic. The archive
  SHA-256 is `9f8bba706dc0f66a7285352bafbdc1698dda1851dc4827d31ff55dfe6c175b58`.
  Existing published bundle bytes and SDK contract locks remain unchanged.

One unrelated Python release-tooling regression remains: it expects a validation
CI step in `release.yml` that was previously deliberately removed. This task
does not restore CI or claim that historical release-tooling suite is green.
The existing public-docs contrast advisories are non-blocking and unchanged.
The full formatting check also reports pre-existing indentation in untouched
`internal/adminapi/credential_selftest.go`; all changed Go files are formatted.

Automated Apple/Google fixtures are not live provider or physical-device
verification. No real Google testing token, TestFlight build or VPS configuration
was exercised or changed by this implementation task.
The disposable PostgreSQL test container was stopped and removed after the final
checks; existing local and VPS deployments were left untouched.

## Deployment preparation (publication and activation pending)

1. Publish server 1.1.3 with the newly assigned contract-bundle edition 1.1.2.
   Do not rewrite a frozen existing bundle or an SDK's released lock.
2. Deploy the server before activating `environment: any` or Play testing.
3. For Habitify Development, the intended Apple setting is `any`, categories
   `[2, 3]`, and existing unrestricted build versions `["*"]`. Apply consistently
   to native and React Native iOS selections. Production remains unchanged.
4. For Android, configure dedicated Play Console tester accounts, confirm test
   track access, and allowlist the exact development app identity/certificate.
   Use Development project 9737128435. A Google test override is not a universal
   sideloaded-APK bypass; verify the actual decoded test evidence on a device.
5. Verify local iOS, TestFlight-to-Development, real Android Play verdicts, and
   opted-in Android testing verdicts before calling those flows live-verified.

For rollback, restore compatible configuration before installing an older server
that rejects `any` or cannot honor the testing exception. Never relax Production
as a workaround for a failed test.
