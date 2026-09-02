# Implementation status

Status date: 2026-09-02

Latchway version 1 is source-complete at the current local implementation
checkpoint. The released wire-2 contract, all four SDK locks, and the four
reproducible SDK documentation bundles converge on the exact coordinates below.
The core `make check` gate and complete uncached PostgreSQL 15 and PostgreSQL 18
suites pass. JavaScript `release:check`, the Android 665-task gate and local
publication smoke, and React Native `check` pass. The complete iOS
package/release gate passes, including production/debug builds, 159 core tests,
SwiftOpenAI 7/7, Foundation Models 9/9, and all four CocoaPods subspec lints;
the reproducible MacPaw contribution separately passes all 213 upstream tests
and its positive transport/cancellation probe.

Canonical documentation commit `f852a618757313fdef5a3d0ac71e9a421cc8518c`
is synchronized to Mintlify mirror
`c2c2e5426b35f7e94d0725972cc5a17ba964f137`. The six-repository
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
| Current phase | Phase 9: final local source tuple is assembled; clean source conformance/push, live release controls, publication, and protected exact-candidate execution remain open |
| Current objective | Run clean source conformance, audit and push the exact six commits, add one distinct GitHub reviewer, apply and verify the six-repository controls, then execute protected release domains |
| Validated implementation coordinates | Core/contract `cd47229eac32f4a93a0779903d927526b77817d6`; JavaScript `c1934b9decf122e0e118976d90cf898a190c8c2f`; Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f`; Android `52f055152431d640febd6c2d64f16799e0f05589`; React Native `55413d56b2e640cebfe3d77bf9462330d111193d`; canonical docs `f852a618757313fdef5a3d0ac71e9a421cc8518c`; Mintlify mirror `c2c2e5426b35f7e94d0725972cc5a17ba964f137` |
| Protocol contract version | Released `1.0.0` at `2026-09-01T20:25:00Z`; wire protocol `2`; contract source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Database schema version | `28` at contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6`; historical checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` remains schema `27` |
| Last full test time | `2026-09-02` — core `cd47229eac32f4a93a0779903d927526b77817d6` passed full `make check` and complete uncached PostgreSQL 15 and PostgreSQL 18 `go test -count=1 ./...` suites. JavaScript `c1934b9decf122e0e118976d90cf898a190c8c2f` passed `release:check`; Android `52f055152431d640febd6c2d64f16799e0f05589` passed the 665-task gate and local publication smoke; React Native `55413d56b2e640cebfe3d77bf9462330d111193d` passed `check`. Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` passed its full package/release gate: production/debug builds, 159 core tests, SwiftOpenAI 7/7, Foundation Models 9/9, and CocoaPods lint for AppAttest, AppExtensions, Core, and FirebaseAuth. Its patched MacPaw 0.5.1 verifier separately passed 213/213 upstream tests plus the positive transport/cancellation probe. |
| Passing test commands | Verified commands and required working directories are listed below |
| Open blockers | Before stable release: clean six-repository source conformance and audited push; one accepted reviewer distinct from the operator; live GitHub environment/ruleset/immutable-release enforcement; npm package bootstrap and exact trusted publishers; registry/package publication; Mintlify custom-domain/DNS production routing for `docs.latchway.dev`; Apple distribution evidence; the protected delegated-extension matrix; operator-deferred App Intent/extension and physical Android/Google Play proof; Turnstile; immutable-image provider/cloud/resilience; and post-publication receipts |
| External credentials still required | Repository-administrator access and an npm owner session with `auth-and-writes` 2FA are available. All five npm package names remain unpublished. GitHub has no distinct reviewer across the six controlled repositories, so the fail-closed control reconciler cannot yet apply the live policy. Later protected gates require the applicable Apple distribution, Play, Turnstile, cloud, registry, KMS/signing, collector, and finalizer identities. |
| Next executable task | Run clean source conformance, audit and non-force push the six exact commits, then add one distinct GitHub reviewer and apply/verify the six-repository control manifest before publication or tagging |

### Validated version 1 source coordinates

| Repository | Validated coordinate or state |
| --- | --- |
| Core contract/runtime checkpoint `latchway` | `cd47229eac32f4a93a0779903d927526b77817d6` |
| Prior schema-27 performance checkpoint `latchway` | `77069816dd68174052e7ebc163911883f8f07e7e` |
| Final canonical-public-doc source | `f852a618757313fdef5a3d0ac71e9a421cc8518c`, a documentation descendant of `cd47229eac32f4a93a0779903d927526b77817d6` |
| JavaScript `latchway-js` | `c1934b9decf122e0e118976d90cf898a190c8c2f` |
| Swift `latchway-ios-sdk` | `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` |
| Android `latchway-android` | `52f055152431d640febd6c2d64f16799e0f05589` |
| React Native `latchway-react-native-sdk` | `55413d56b2e640cebfe3d77bf9462330d111193d` |
| JavaScript documentation bundle SHA-256 | `1e185ca25f2b64ed8a08ccbd09a8e1f7ad3e24d99379dd7033bae9bead079a9e` |
| Swift documentation bundle SHA-256 | `a502896f1975d8bf2524cb56e4ed5d8270c5f8862b55f568d56369aa1b74a4a4` |
| Android documentation bundle SHA-256 | `2c5c9b42ac47a08fb97445830aa701456de86fb6bc7f4f5d46f3ba93c5965ef7` |
| React Native documentation bundle SHA-256 | `52bb0ba88bd52b5ea96296c100a6087f11bcce624a97bc3e3a5b6e25d9782ff9` |
| Final Mintlify mirror `latchway-docs` | `c2c2e5426b35f7e94d0725972cc5a17ba964f137`, generated from `f852a618757313fdef5a3d0ac71e9a421cc8518c` |

These coordinates form the final local implementation tuple. The deterministic
contract bundle SHA-256 is
`0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`.
The final clean six-repository source report must be regenerated from these
exact commits; no report digest is claimed in advance. No version 1 tag, GitHub
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
| Product release state | `unpublished` and not release-qualified; no local version 1 tags exist, and no package, image, or product-runtime cloud deployment is verified. A prior Mintlify preview exists, but final mirror `c2c2e5426b35f7e94d0725972cc5a17ba964f137` is not claimed as a protected production deployment and `docs.latchway.dev` is not routed. |

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
| Admin API, CLI, dashboard, wizard, request/usage/audit views | The frozen checkpoint includes redaction-safe audit filtering/detail, a shared doctor/support-bundle contract, the exact `latchway test-upstream serve` fixture command, separate first-byte/first-token request timestamps, canonical Admin-session inventory/revoke across API, CLI, and Console, negotiated server capabilities and read-only safe mode, bounded redaction-safe YAML/JSON configuration transfer with exact numeric preservation and strong-ETag activation review, and authenticated SSE refresh hints with reconnect, polling fallback, and no row data. Complete local core gates pass. | Protected deployment operator acceptance |
| Native/Web trust verifiers and component proof | Complete in source; a historical development-signed physical React Native iOS root run passed production App Attest registration and same-key assertion, the current source adds a Debug-only native App Intent delegated-request path, and a browser-minted Firebase App Check token passes the current source gateway | Apple distribution-derived protected candidate, physical invocation of the current Debug App Intent path, protected extension matrix, physical Play Integrity, protected immutable-candidate App Check rerun, and Turnstile evidence |
| Swift, Android, JavaScript SDKs | JavaScript `c1934b9decf122e0e118976d90cf898a190c8c2f` passed `release:check`. Android `52f055152431d640febd6c2d64f16799e0f05589` passed the 665-task gate and local publication smoke. Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` passed its full package/release gate: production and debug builds, 159 core tests, SwiftOpenAI 7/7, Foundation Models 9/9, and CocoaPods lint for AppAttest, AppExtensions, Core, and FirebaseAuth. | Physical proof where applicable, protected exact-candidate evidence, tags, and publication |
| React Native SDK | Successor commit `55413d56b2e640cebfe3d77bf9462330d111193d` is implemented, passes `mise exec -- pnpm check`, and is pinned to JavaScript `c1934b9decf122e0e118976d90cf898a190c8c2f`, Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f`, and Android `52f055152431d640febd6c2d64f16799e0f05589`. Its release workflow remains fail-closed until live protected controls exist. Predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict Apple Development root/extension signing, provisioning, App Attest and Keychain entitlement, registered-device, install, and launch checks without new App Attest or App Intent execution. The physical path was not rerun at the current successor. The Release fixture has no Latchway request path and fails closed. Historical commit `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` remains the live root-app App Attest proof. | Operator-deferred physical invocation of the Debug App Intent path; protected Apple distribution and extension-matrix proof; physical Android/Google Play proof; protected controls/evidence, tags, and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests; schema 24 makes TTFT protocol-aware, schema 25 hardens ephemeral challenges and browser Origin, schema 26 records logical-request decision stages, and schema 27 supports bounded audit operations; doctor exposes redaction-safe revision, connectivity, job, replica, key-ID consistency, and capacity diagnostics, and scheduled self-tests retain the bounded `run_scheduled_self_test` job label instead of collapsing to `other` | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Release controls | The closed desired-state manifest covers six repositories, 51 protected environments, exact main/tag rulesets, and five npm trusted-publisher tuples. `latchway-docs` uniquely requires CODEOWNERS review, one approval, and a written docs-not-required check; product repositories retain the no-source-review release model. Offline validation passes, but no live ruleset/environment apply is claimed. | One accepted independent reviewer, manual no-admin-bypass confirmation, live two-stage apply, and live verify; npm already has `auth-and-writes` 2FA but package bootstrap/trusted publishers remain open |
| Mintlify public docs | Canonical source `f852a618757313fdef5a3d0ac71e9a421cc8518c` imports the exact four reproducible bundles and mirror `c2c2e5426b35f7e94d0725972cc5a17ba964f137` names that source in its manifest. Local canonical/mirror checks are green. | Run clean source conformance, push the exact commits, configure `docs.latchway.dev`, deploy the exact mirror through protected controls, and seal post-deploy evidence |

## Local source evidence

- The loopback Console preview at `http://127.0.0.1:18082` runs local image
  `latchway:local-203d855-arm64`, whose embedded version reports core
  `203d855f70932c72a63f9c3745cf250b767f4225`, contract `1.0.0`, and wire `2`.
  Its readiness endpoint returns `200`; the rotated disposable owner login was
  reverified, and the out-of-repository credential file remains mode `0600`.
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
  released successor `55413d56b2e640cebfe3d77bf9462330d111193d` includes the
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
- Nine Foundation Models public-API tests passed on an iOS 27.0 simulator,
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
final local tuple binds core/contract
`cd47229eac32f4a93a0779903d927526b77817d6`, bundle SHA-256
`0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`,
JavaScript `c1934b9decf122e0e118976d90cf898a190c8c2f`, iOS
`ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f`, Android
`52f055152431d640febd6c2d64f16799e0f05589`, React Native
`55413d56b2e640cebfe3d77bf9462330d111193d`, canonical documentation
`f852a618757313fdef5a3d0ac71e9a421cc8518c`, and Mintlify mirror
`c2c2e5426b35f7e94d0725972cc5a17ba964f137`. All four imported SDK documentation bundles
record those SDK coordinates and `source_tree_clean: true`. React Native predecessor
`4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict development signing,
entitlement, embedded-extension, registered-iPad, install, and launch
verification. Current `55413d56b2e640cebfe3d77bf9462330d111193d` was not
physically rerun. No successor collected new App Attest evidence or invoked the
Debug App Intent, so the earlier live root-app
observation remains bound to predecessor
`6de46e1c7264e1d45cdd31174e4ea040a8c24acf`. The final documentation commits
and a fresh clean six-repository source-conformance report are required before
this tuple is synchronized. None of these results substitutes for a protected
external domain.

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

The user authorized a scoped non-force push of the six audited source-branch
histories and separately requested GHCR and npm publication work. The earlier
baseline is delivered to `main`; the exact current six-repository tuple remains
local and awaits clean conformance plus an audited non-force push. Namespace
bootstrap or explicitly non-stable preview artifacts do not authorize a stable
tag, version 1 GitHub release, release-qualified production documentation
receipt, or protected promotion.

## Release decision

The repositories are locally source-converged but are not ready for release
promotion. Final source delivery is still pending. Tagging, production
promotion, package/container publication, release-qualified documentation
evidence, and a production-readiness claim remain blocked until the protected
finalizer binds every required receipt to one immutable set of core, SDK,
image, contract, package, and documentation coordinates.
