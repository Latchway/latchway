# Implementation status

Status date: 2026-09-02

Latchway version 1 product source is complete at the validated implementation
checkpoint. Core and all four final SDK heads are delivered to `main`.
Canonical public documentation is this checked-in `docs/public` tree; the
generated Mintlify mirror must bind its exact source through
`.latchway-docs-source.json`.
The released wire-2 contract, all four SDK locks, and the four
reproducible SDK documentation bundles converge on the exact coordinates below.
The core `make check` gate and complete uncached PostgreSQL 15 and PostgreSQL 18
suites pass. JavaScript `release:check`, the Android 665-actionable-task gate
and local publication smoke, and React Native `check` pass. The complete iOS
package/release gate passes 193 Swift tests: 166/166 XCTest, SwiftOpenAI 11/11,
Foundation Models 12/12, and App Extensions 4/4, plus all four CocoaPods
subspec lints;
the reproducible MacPaw contribution separately passes all 213 upstream tests
and its positive transport/cancellation probe.

The canonical tree imports the four final SDK bundles. Its generated mirror is
accepted only when `.latchway-docs-source.json` identifies the exact canonical
source. The six-repository
release-control desired state is
implemented locally, including the docs-only code-owner/reviewer policy, but it
has not been applied live because no distinct reviewer is available. npm 2FA is
enabled in `auth-and-writes` mode, but all five npm packages remain unpublished.
No tag, package, container, production documentation deployment, cloud proof,
or protected release evidence is claimed.
React Native predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99`
passed bounded Apple Development root/extension signing, entitlement,
registered-device install, and launch checks; the physical path was not rerun
at current head. The product is not published or production-proven. Protected
distribution, Android hardware, delegated runtime
execution, live-provider exact-image, cloud, resilience, protected registry
supply-chain, publication, and post-publication domains remain open.

## Required execution checkpoint

| Required field | Current value |
| --- | --- |
| Current phase | Phase 9: core and the four final SDK source heads are delivered to `main`; live release controls, publication, and protected exact-candidate execution remain open |
| Current objective | Bind the generated Mintlify mirror to this canonical tree, then add one distinct GitHub reviewer, apply and verify live controls, and execute protected registry, publication, deployment, and evidence domains |
| Validated implementation coordinates | Contract `cd47229eac32f4a93a0779903d927526b77817d6`; core implementation `d4693ee36bf8a018a027fb75e5e2ac2fb6b58d50`; JavaScript `e3a57617e75bf3d46e858a1084749f46f819db1f`; Swift `9f306d1e585069ca4aa703412c5d70656336e50f`; Android `a994f8b5ee81fa831b8b2e57885df39f50fa2777`; React Native `b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9` |
| Protocol contract version | Released `1.0.0` at `2026-09-01T20:25:00Z`; wire protocol `2`; contract source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Database schema version | `28` at contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6`; historical checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` remains schema `27` |
| Last full test time | `2026-09-02` — core `cd47229eac32f4a93a0779903d927526b77817d6` passed full `make check` and complete uncached PostgreSQL 15 and PostgreSQL 18 `go test -count=1 ./...` suites. JavaScript `e3a57617e75bf3d46e858a1084749f46f819db1f` passed 128 Vitest, 33 Node, 58 offline Python (57 pass and one skip), and 51 Playwright tests. Android `a994f8b5ee81fa831b8b2e57885df39f50fa2777` passed 75 offline release tests with one expected skip, its 665-actionable-task Gradle gate, local publication smoke, and 8/8 locked semantic slice. React Native `b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9` passed 103 Vitest, 58 Node, 4/4 docs-bundle, and 8/8 dependency-scan tests plus Swift bridge 5/5, Robolectric 6/6, locked iOS 10/10, locked Android 8/8, and a real CocoaPods/TurboModule build. Swift `9f306d1e585069ca4aa703412c5d70656336e50f` passed 50 offline Python (49 pass and one skip), 8/8 vulnerability, 166/166 XCTest, SwiftOpenAI 11/11, Foundation Models 12/12, App Extensions 4/4, external SwiftPM consumer, and all four CocoaPods lints. Its patched MacPaw 0.5.1 verifier separately passed 213/213 upstream tests plus the positive transport/cancellation probe. |
| Passing test commands | Verified commands and required working directories are listed below |
| Open blockers | Before stable release: one accepted reviewer distinct from the operator; live GitHub environment/ruleset/immutable-release enforcement; npm package bootstrap and exact trusted publishers; registry/package publication; Mintlify custom-domain/DNS production routing for `docs.latchway.dev`; Apple distribution evidence; the protected delegated-extension matrix; operator-deferred App Intent/extension and physical Android/Google Play proof; Turnstile; immutable-image provider/cloud/resilience; and post-publication receipts |
| External credentials still required | Repository-administrator access and an npm owner session with `auth-and-writes` 2FA are available. All five npm package names remain unpublished. GitHub has no distinct reviewer across the six controlled repositories, so the fail-closed control reconciler cannot yet apply the live policy. Later protected gates require the applicable Apple distribution, Play, Turnstile, cloud, registry, KMS/signing, collector, and finalizer identities. |
| Next executable task | Bind and validate the generated mirror against this canonical source, then add one distinct GitHub reviewer and apply/verify the six-repository control manifest before stable publication or tagging; npm package-name bootstrap may proceed separately without implying a stable release |

### Validated version 1 source coordinates

| Repository | Validated coordinate or state |
| --- | --- |
| Core contract/runtime checkpoints `latchway` | Frozen contract `cd47229eac32f4a93a0779903d927526b77817d6`; current implementation `d4693ee36bf8a018a027fb75e5e2ac2fb6b58d50` |
| Prior schema-27 performance checkpoint `latchway` | `77069816dd68174052e7ebc163911883f8f07e7e` |
| Canonical public documentation | This checked-in `docs/public` tree imports the final bundles based on core implementation `d4693ee36bf8a018a027fb75e5e2ac2fb6b58d50` |
| JavaScript `latchway-js` | `e3a57617e75bf3d46e858a1084749f46f819db1f` |
| Swift `latchway-ios-sdk` | `9f306d1e585069ca4aa703412c5d70656336e50f` |
| Android `latchway-android` | `a994f8b5ee81fa831b8b2e57885df39f50fa2777` |
| React Native `latchway-react-native-sdk` | `b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9` |
| JavaScript documentation bundle SHA-256 | `cf7073575aa1af89b1739387eca2cfa03bb822ab7dc397bbdf80e1ce7a2271ae` |
| Swift documentation bundle SHA-256 | `a61358527468627d24d9aa922c0db849d31828a81d94dd435928e2324b12f812` |
| Android documentation bundle SHA-256 | `21804871c9d8922eb245ae1308b35b0d6a51f44f4c11052d895597d7bc72e5dc` |
| React Native documentation bundle SHA-256 | `59d98e3f0f79a75b7540af31f518ac8cfd878a030406abcf6d07dd564c6a74aa` |
| Mintlify mirror `latchway-docs` | Generated deployment mirror; `.latchway-docs-source.json` must identify the exact canonical source, and no protected production deployment receipt exists |

The core and SDK coordinates form the validated product-source tuple delivered
to `main`; this checked-in tree is the canonical documentation source.
The deterministic
contract bundle SHA-256 is
`0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`.
The five product-source remote `main` heads match their intended final source
histories. The mirror/source manifest and six-repository source-conformance
gates must match the canonical source. This is source delivery only. No version 1 tag, GitHub
release, npm/CocoaPods/Maven package, GHCR image, product-runtime cloud
deployment, or protected production-documentation receipt is verified.

### Full-suite commands

These commands passed for the recorded source tuple.

```sh
# Core server, generated SQL, Go vet/tests, dashboard, and Playwright
mise exec -- make check

# Canonical public docs and synchronized Mintlify mirror (from core)
(cd docs/public && mise exec -- pnpm check)
python3 scripts/sync-public-docs.py --target ../latchway-docs --check
(cd ../latchway-docs && mise exec -- pnpm check)

# JavaScript SDK, including reproducible packages and browser consumers
(cd ../latchway-js && mise exec -- pnpm release:check)

# Swift SDK package/release/consumer/CocoaPods gate
(
  cd ../latchway-ios-sdk
  scripts/verify-package.sh
  tuist generate --path Examples/AppAttestConformance --no-open
  xcodebuild -project Examples/AppAttestConformance/AppAttestConformance.xcodeproj \
    -scheme AppAttestConformance -configuration Release \
    -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
  tuist generate --path Examples/AppExtensionComponents --no-open
  xcodebuild -project Examples/AppExtensionComponents/AppExtensionComponents.xcodeproj \
    -scheme AppExtensionComponents -destination 'generic/platform=iOS' \
    CODE_SIGNING_ALLOWED=NO build
)

# Android SDK
(cd ../latchway-android && \
  ANDROID_HOME="${ANDROID_HOME:?set ANDROID_HOME}" ./gradlew test assemble lint)
(cd ../latchway-android && ./scripts/verify-local-publication.sh)

# React Native SDK, release evidence, and physical-workflow invariants
(cd ../latchway-react-native-sdk && mise exec -- pnpm check)
(cd ../latchway-react-native-sdk && \
  python3 scripts/test-physical-candidate-producer.py)
(cd ../latchway-react-native-sdk && \
  python3 scripts/test-physical-evidence-workflow.py)
(cd ../latchway-react-native-sdk && \
  python3 scripts/test-physical-example-host.py)

# Clean local source convergence
python3 scripts/cross-repo-conformance.py --scope source \
  --workspace-root .. --output /private/tmp/latchway-source-final.json \
  --junit-output /private/tmp/latchway-source-final.xml
```

### Current core implementation gates

These checks passed on 2026-09-01:

```sh
mise exec -- make check
mise exec -- make test-race
mise exec -- make fuzz-smoke
```

The real PostgreSQL Admin, session, App Attest, configuration, lifecycle, and
lock-order suites also pass against the frozen implementation checkpoint.

## Candidate snapshot

| Field | Current value |
| --- | --- |
| Last fully tested core checkpoint | `cd47229eac32f4a93a0779903d927526b77817d6` |
| Contract | `1.0.0` released at `2026-09-01T20:25:00Z` |
| Contract source checkpoint | Core checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Bundle SHA-256 | `0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617` |
| Wire | Current `2`; discovery supports `[1, 2]` |
| Database | Schema `28` at contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6`; checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` remains the preceding schema-27 coordinate |
| Package/server range | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| Product release state | `unpublished` and not release-qualified; no local version 1 tags exist, and no package, image, or product-runtime cloud deployment is verified. A Mintlify preview exists, but no protected production deployment receipt is claimed and `docs.latchway.dev` is not routed. |

The historical `0.5.1`/wire-1 coordinate remains unchanged. Intermediate bundle
hashes are not release coordinates. All four SDK successor locks name the
released checkpoint and reproducible bundle above.

## Workstream status

| Workstream | Local source status | Remaining boundary |
| --- | --- | --- |
| Family/component contract and migrations | Implemented through schema 28 at contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6`; exact challenge Origin and authoritative root-definition selection remain hardened, schema 26 adds redaction-safe logical-request decision stages, schema 27 adds bounded audit source/reason attribution and browse indexes, and schema 28 adds durable retry-cost treatment plus physical-attempt quota ledger support. Wear OS vocabulary remains reserved, but active Wear OS Component Definitions fail with `component_wearos_unsupported_v1` until an end-to-end SDK/runtime path exists. | Protected exact-candidate evidence and future Wear OS implementation before any support claim |
| Server trust/session/revocation/policy/quota runtime | Complete in source, including a generic component App Attest step-up protocol and bounded CEL request context whose feature/protocol are immutable-server bound; the CEL `request.estimated_input_tokens` fact remains untrusted, while production hard `input_tokens`/`total_tokens` and input-priced cost enforcement use a server-owned preflight bound tied to the exact post-rewrite body and selected physical model; quota snapshots fail closed when required request-size policy facts are unavailable. Calendar, token-bucket, and aggregate per-request `upstream_attempts` limits charge each physical dispatch atomically while `logical_requests` remains once per request. Cost retry treatment defaults to all actual attempts; user `initial_attempt_only` allowances require paired organization-only actual-attempt accounting. Current lifecycle transactions explicitly use `READ COMMITTED` and consistent application→environment→family/component lock order, closing root-challenge, App Attest post-disable insertion, configuration, family/component deadlock, retry replay, and excess-attempt races under real PostgreSQL tests. | Exact-candidate rerun and protected observations |
| Responses, Chat, Embeddings, Anthropic, opaque protocols | Complete; opaque HTTP now has pairwise-disjoint exact-depth path templates while retaining the prior segment-bound `pathPrefixes` mode for existing v1 revisions; bounded OpenRouter verification passed against the current source gateway | Immutable-image provider rerun |
| Weighted/sticky routing, fallback, retry, accounting | Complete; the clean local source load suite and all nine automated failure scenarios pass at the implementation checkpoint | Protected exact-image load and destructive-failure evidence |
| Admin API, CLI, dashboard, wizard, request/usage/audit views | The frozen checkpoint includes redaction-safe audit filtering/detail, a shared doctor/support-bundle contract, the exact `latchway test-upstream serve` fixture command, separate first-byte/first-token request timestamps, canonical Admin-session inventory/revoke across API, CLI, and Console, negotiated server capabilities and read-only safe mode, bounded redaction-safe YAML/JSON configuration transfer with exact numeric preservation and strong-ETag activation review, and authenticated SSE refresh hints with reconnect, polling fallback, and no row data. The Usage plans task links operators to the server-resolved Users effective-limit inspector instead of presenting a stale endpoint limitation. Complete local core gates pass. | Protected deployment operator acceptance |
| Native/Web trust verifiers and component proof | Complete in source; a historical development-signed physical React Native iOS root run passed production App Attest registration and same-key assertion, the current source adds a Debug-only native App Intent delegated-request path, and a browser-minted Firebase App Check token passes the current source gateway | Apple distribution-derived protected candidate, physical invocation of the current Debug App Intent path, protected extension matrix, physical Play Integrity, protected immutable-candidate App Check rerun, and Turnstile evidence |
| Swift, Android, JavaScript SDKs | JavaScript `e3a57617e75bf3d46e858a1084749f46f819db1f` passed 128 Vitest, 33 Node, 58 offline Python (57 pass and one skip), and 51 Playwright tests. Android `a994f8b5ee81fa831b8b2e57885df39f50fa2777` passed 75 offline release tests with one expected skip, its full 665-actionable-task Gradle gate, local publication smoke, and 8/8 locked semantic slice. Swift `9f306d1e585069ca4aa703412c5d70656336e50f` passed 50 offline Python (49 pass and one skip), 8/8 vulnerability, 166/166 XCTest, SwiftOpenAI 11/11, Foundation Models 12/12, App Extensions 4/4 (193 Swift tests total), external SwiftPM consumer, and all four CocoaPods lints. | Physical proof where applicable, protected exact-candidate evidence, tags, and publication |
| React Native SDK | Successor commit `b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9` passes 103 Vitest, 58 Node, 4/4 docs-bundle, and 8/8 dependency-scan tests plus Swift bridge 5/5, Robolectric 6/6, locked iOS semantics 10/10, locked Android semantics 8/8, and a real CocoaPods/TurboModule build. It pins JavaScript `e3a57617e75bf3d46e858a1084749f46f819db1f`, Swift `9f306d1e585069ca4aa703412c5d70656336e50f`, and Android `a994f8b5ee81fa831b8b2e57885df39f50fa2777`. Its locked-source workflow fails closed because the live policy variable and protected environment are absent; that is an external-control blocker, not an implementation failure. Predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict Apple Development root/extension signing, provisioning, App Attest and Keychain entitlement, registered-device, install, and launch checks without new App Attest or App Intent execution. The physical path was not rerun at the current successor. The Release fixture has no Latchway request path and fails closed. Historical commit `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` remains the live root-app App Attest proof. | Hosted replay rejection; operator-deferred physical invocation of the Debug App Intent path; protected Apple distribution, extension-matrix, and native-isolation proof; physical Android/Google Play proof; protected controls/evidence, tags, and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests; schema 24 makes TTFT protocol-aware, schema 25 hardens ephemeral challenges and browser Origin, schema 26 records logical-request decision stages, and schema 27 supports bounded audit operations; doctor exposes redaction-safe revision, connectivity, job, replica, key-ID consistency, and capacity diagnostics, and scheduled self-tests retain the bounded `run_scheduled_self_test` job label instead of collapsing to `other` | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated. Cloudflare Container evidence now follows the provider's bounded application cursor directly, rejects malformed, duplicate, repeated-cursor, and oversized results, and retains the prior scoped-token boundary instead of relying on Wrangler's one-page JSON listing. | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Release controls | The closed desired-state manifest covers six repositories, 51 protected environments, exact main/tag rulesets, and five npm trusted-publisher tuples. `latchway-docs` uniquely requires CODEOWNERS review, one approval, and a written docs-not-required check; product repositories retain the no-source-review release model. Offline validation passes, but no live ruleset/environment apply is claimed. | One accepted independent reviewer, manual no-admin-bypass confirmation, live two-stage apply, and live verify; npm already has `auth-and-writes` 2FA but package bootstrap/trusted publishers remain open |
| Mintlify public docs | This canonical tree imports the four final reproducible bundles and retains task-oriented deployment comparison, release-image verification, and the completed Cloud Run/Cloudflare runbooks. The generated mirror must bind its exact source through `.latchway-docs-source.json`. | Configure `docs.latchway.dev`, deploy through protected controls, and seal post-deploy evidence |

## Local source evidence

- The loopback Console preview at `http://127.0.0.1:18082` runs local image
  `latchway:local-d4693ee-arm64`, whose embedded version reports core
  `d4693ee36bf8a018a027fb75e5e2ac2fb6b58d50`, contract `1.0.0`, and wire `2`.
  It runs as UID/GID `65532:65532` with a read-only root filesystem, all Linux
  capabilities dropped, `no-new-privileges`, and a `/tmp` tmpfs. Readiness,
  Console HTML, and the rotated disposable owner login each return `200`; the
  out-of-repository credential file remains mode `0600`.
  This preview is local operator evidence, not a registry or release receipt.
- PostgreSQL-backed unit, integration, migration, authorization, replay,
  refresh, revocation, and direct-component-attestation vertical tests.
- Core checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` passed
  complete uncached PostgreSQL 15 and PostgreSQL 18
  `go test -count=1 ./...` suites. Its quota integration cases prove two
  charged physical dispatches,
  atomic denial before a third calendar/token-bucket/per-request attempt,
  exactly one logical-request usage record, paired user/organization retry-cost
  accounting, replay rejection for changed retry allocations, and rejection of
  a known retry cost above its trusted bound.
- Contract/schema/error/vector determinism and the complete Python release,
  workflow, evidence, and validation suites.
- Dashboard lint, TypeScript checking, unit tests, deterministic builds,
  Playwright, and a real PostgreSQL-backed first-run browser flow.
- Credential-free deployment validation passed 9/9 checks, including Compose,
  Cloud Run and AWS Terraform static validation plus Cloudflare type, unit,
  build, and Wrangler dry-run gates. No live cloud API was used.
- A real browser-minted Firebase App Check token from an allowed localhost
  origin passed the current source gateway, including Firebase's
  multi-audience JWT form. This is not protected immutable-candidate evidence,
  and the arbitrary ngrok hostname was not claimed as passing.
- A real physical iPad running iPadOS 26.5 built React Native commit
  `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` in Debug configuration with
  automatic Apple Development signing and bundle `dev.latchway`. Apple App
  Attest was accepted as `app_verified`; Firebase identity, the native DPoP
  path, signed root/App Intents entitlement isolation, a real OpenRouter
  Responses request to `openai/gpt-5-mini`, reported token usage, all five
  quota settlements, bridge behavior, and terminal session/installation
  revocation passed. It was not a protected or distribution-signed release
  receipt.
- React Native predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99`
  passed strict Apple Development root/extension signing, provisioning, App
  Attest and Keychain entitlement, registered-device, installation, and launch
  verification on the connected iPad. It did not contact a provider, collect
  App Attest evidence, or physically invoke the Debug App Intent. Current
  released successor `b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9` includes the
  later release-lock and source-tuple transition; the physical path was not
  rerun at that head.
- The clean implementation-checkpoint load suite passed all targets: gateway
  overhead p50/p95/p99 was `13.441`/`16.554`/`20.027` ms against
  `15`/`20`/`30` ms limits, all `6000` requests completed at 100 requests per
  second, all `500` SSE streams completed without premature termination, and
  quota contention admitted and denied the exact expected `64` requests each.
  All nine automated failure scenarios also passed under the race detector.
  These are local source gates, not protected exact-image or destructive drill
  receipts.
- Actionlint across all workflows, deterministic contract regeneration,
  container smoke, strict non-root runtime inspection, and an OCI
  `linux/amd64` plus `linux/arm64` platform/runtime gate passed for exact
  implementation checkpoint `77069816dd68174052e7ebc163911883f8f07e7e`. Binary
  `govulncheck` found no called vulnerabilities. These are local source-image
  results, not registry, signature, SBOM, or provenance receipts.
- Twelve Foundation Models public-API tests passed on an iOS 27.0 simulator,
  covering single/multi-turn text, incremental streaming and usage,
  cancellation, quota/unavailable mapping, refresh, extension initialization,
  and explicit tools/structured-output rejection.
- An exact, minimal MacPaw/OpenAI 0.5.1 upstream patch propagates the caller's
  injected `URLSession` configuration into the package's internal streaming
  sessions. That permits a custom `URLProtocol` to own buffered and streaming
  Chat Completions/Responses dispatch, and cancellation reaches
  `URLProtocol.stopLoading`. The patched checkout passed 187 XCTest and 26
  Swift Testing cases (213/213) plus the positive transport/cancellation probe.
  Stock 0.5.1 remains unsupported because the seam is not released upstream.
- Koog 1.1.1 passed six exact integration cases through the Android OkHttp seam
  on OkHttp/okhttp-sse 5.3.0; its four non-streaming cases pass on 4.9.2, while
  its upstream SSE implementation links an OkHttp 5-only method.
- Mintlify structure, build, links/anchors/redirects/snippets, accessibility,
  and Vale MDX prose validation.
- Core `cd47229eac32f4a93a0779903d927526b77817d6` passed the full current
  `make check`, including generated-source checks, all Go tests and vet, the
  complete Python release/tool suite, Console lint/typecheck/tests, the
  production Console build, and Playwright. The live-stack Playwright case
  remains explicitly opt-in and skipped.
- The same checkpoint passed complete uncached PostgreSQL 15 and PostgreSQL 18
  suites with `go test -count=1 ./...`.
- `make test-race`, the bounded fuzz corpus, and real PostgreSQL Admin, session,
  App Attest, configuration, lifecycle, and lock-order suites pass. Independent
  review closed root-challenge and App Attest post-disable insertion races,
  configuration and family/component lock-order deadlocks, exact JSON/YAML
  numeric preservation, and explicit `READ COMMITTED` lifecycle behavior.
- The current SDK/documentation/control tuple passed source-scope conformance
  from six distinct clean worktrees. The gate also caught and rejected an
  operational release-control schema under the contract-locked `api/` tree;
  the schema now lives beside its `.github` manifest, and the rerun passes with
  byte-identical released contract sources.

These are source-development results, not protected release receipts. The
validated product-source tuple binds frozen core/contract
`cd47229eac32f4a93a0779903d927526b77817d6`, current core implementation
`d4693ee36bf8a018a027fb75e5e2ac2fb6b58d50`, bundle SHA-256
`0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`,
JavaScript `e3a57617e75bf3d46e858a1084749f46f819db1f`, iOS
`9f306d1e585069ca4aa703412c5d70656336e50f`, Android
`a994f8b5ee81fa831b8b2e57885df39f50fa2777`, and React Native
`b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9`. All four imported SDK
documentation bundles record those SDK coordinates and `source_tree_clean:
true`. React Native predecessor
`4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict development signing,
entitlement, embedded-extension, registered-iPad, install, and launch
verification. Current `b6f3c5c5bf011867c8b7d22eb3f46d15ed1136d9` was not
physically rerun. No successor collected new App Attest evidence or invoked the
Debug App Intent, so the earlier live root-app
observation remains bound to predecessor
`6de46e1c7264e1d45cdd31174e4ea040a8c24acf`. The exact core and SDK source
histories are delivered to `main`; the generated mirror and six-repository
source-conformance gates must bind this canonical source. None of these
results substitutes for a protected external domain.

## Direct component attestation boundary

Schema 25 retains the generic component-owned App Attest challenge/exchange
routes and binding version 2 introduced in schema 23. If an eligible platform
can produce component-owned evidence, a delegated component can rotate only its
own DPoP-bound session while retaining delegation ancestry under
`delegated_direct_attested`. The configured component policy remains
`preferred` so it cannot qualify an initial delegated session; the explicit
step-up exchange itself requires valid App Attest evidence.

Schema 25 also makes initial root-family attribution fail closed. A browser
challenge persists its exact canonical Origin and the exchange must present the
same value; native challenges persist an empty Origin. Root Component
Definitions are selected from the authoritative required attestation policy's
exact bundle, package, or web Origin rather than platform alone. Multiple web
roots are permitted only when disjoint exact origin sets partition every
allowed Origin across directly attested roots. Explicit root `identity_only` remains in the frozen schema only
for compatibility and cannot activate in version 1.

That wire capability is not an iOS Action/SSO support claim. Apple documents
that App Attest key generation fails in iOS app extensions; only eligible
watchOS extensions have an extension exception. Consequently, the Swift and
React Native iOS version 1 surfaces keep Widget, Share, Action, and SSO
extensions delegated-only. The containing application directly attests only
its own bundle and must never relabel that result as extension evidence. The
current Swift package does not claim a watch direct-step-up SDK surface, so no
current version 1 SDK has a supported direct-component producer. Android also
uses delegated component trust and only decodes the composite source for wire
compatibility.

## Framework claim boundary

The canonical registry currently records eight exact locally tested
integrations as `experimental`: OpenAI JavaScript 7.8.0, Vercel AI SDK 7.0.85,
LangChain OpenAI 1.5.10, SwiftOpenAI 4.6.0, OkHttp 4.9.2/5.3.0, Koog 1.1.1,
React Native 0.82.0, and Foundation Models 27.0.0. MacPaw/OpenAI 0.5.1 remains
`unsupported`; a passing local upstream patch is contribution evidence, not a
released framework seam. No framework is represented as released support.

The canonical schema-2 conformance manifest contains 58 cases: the original
27 integration-specific cases plus the 31-case addendum common suite. Every
owned integration must classify every case exactly once as passing,
evidence-bounded not-applicable, or explicitly pending with a local, hosted,
protected-device, or upstream blocker. Supported integrations cannot carry
pending cases; capability and native-ecosystem claims cannot use N/A to hide a
required surface; and common-suite passes resolve through a case-specific
catalog to executable test evidence. Replay rejection remains hosted evidence,
while hardware-key and real native-bridge isolation remain protected-device
evidence.

The JavaScript repository now runs a protocol-valid local debug fixture through
the real pinned OpenAI, Vercel AI, and LangChain packages. Its 62 registered
framework/case combinations cover Responses, Chat, embeddings, streaming usage,
cancellation/timeouts, tools, structured output, middleware, telemetry,
batch/concurrency behavior, quota/provider error, retry/refresh,
credential-stripping, origin/path, redaction, and fetch isolation. This does
not satisfy hosted/exact-image, live-provider, revocation, scheduled-run, or
clean-published-consumer gates; all three rows remain `experimental`.

## External-required gates

With local source convergence complete, the remaining non-repository domains
are:

1. a protected Apple Distribution, ad hoc, TestFlight, or App Store-derived
   immutable iOS candidate that repeats root-application App Attest, plus
   delegated Widget/Share/Action execution and isolation, including
   component-owned identity/key/session, sibling denial, no-host, background,
   termination, and no-user-presence behavior. The current React Native Debug
   App Intent must execute its native delegated request on-device; the Release
   fixture must retain no Latchway dependency or executable request path and
   must remain fail-closed;
2. Play-distributed Play Integrity and React Native Android flows on physical
   devices, a protected immutable-candidate rerun of the already-passing
   Firebase App Check flow, and a configured Turnstile observation;
3. exact-image all-SDK and hosted framework conformance; bounded live
   OpenRouter protocol/accounting verification has passed against the current
   source gateway but must be repeated for the immutable release image;
4. every claimed cloud plus protected multi-replica, load, destructive failure,
   backup/restore, upgrade/rollback, key-rotation, and worker recovery drill;
5. per-architecture vulnerability/license scans, SBOM, signature, provenance,
   and independent security review;
6. signed tags/releases, OCI and package publication, production Mintlify
   deployment, and clean post-publication consumers.

The connected iPad and Xcode-managed `dev.latchway` profile were sufficient
for automatic Apple Development signing and the supplemental physical result
above. They do not provide Apple Distribution, ad hoc, TestFlight, or App Store
release evidence, and no protected candidate-bound physical-device receipt has
been accepted by the release finalizer. The root-app run did not execute a
delegated extension. Play Integrity additionally requires a Play-distributed
signed application and is intentionally deferred until an Android device is
available. The CocoaPods lint passes with the beta Xcode toolchain; the stable
Xcode installation on this host is still missing the required platform
component, so it cannot independently run that lint.

## Execution authorization boundary

Offline and local device build, install, and launch work may continue when it
does not contact ngrok or a live provider and does not collect Apple App Attest
evidence. Starting or reusing an ngrok tunnel, contacting a provider as part of
device proof, collecting live App Attest evidence, or producing a protected
device receipt required the exact authorization phrase
`I authorize the scoped ngrok device proof.` The phrase was supplied for the
scoped run, but no tunnel, service, provider, App Attest, or protected-device
evidence was started or collected under it. Historical App Attest and
predecessor signed-launch observations remain separately bound to their stated
commits. The operator has now explicitly deferred App Intent/extension
invocation and Google Play physical evidence; those remain open release gates.

The user authorized a scoped non-force push of the audited source-branch
histories and separately requested GHCR and npm publication work. The exact
core and SDK successor histories are delivered to `main` and their remote
heads were verified. The generated mirror and source-conformance gates must
bind this canonical source. Namespace
bootstrap or explicitly non-stable preview artifacts do not authorize a stable
tag, version 1 GitHub release, release-qualified production documentation
receipt, or protected promotion.

## Release decision

The product repositories are source-converged and delivered, and canonical
documentation is this checked-in tree. The project is not ready for
release promotion. Tagging, production promotion, package/container
publication, release-qualified documentation
evidence, and a production-readiness claim remain blocked until the protected
finalizer binds every required receipt to one immutable set of core, SDK,
image, contract, package, and documentation coordinates.
