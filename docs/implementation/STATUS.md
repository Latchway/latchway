# Implementation status

Status date: 2026-09-03

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
implemented locally, including the docs-only code-owner/reviewer policy. The
explicit `single_maintainer_v1` publication profile now permits a lower-
assurance launch without that reviewer while retaining `strict_full` unchanged;
it keeps every deferred control visibly `unverified` and forbids a
`release-qualified` claim. On 2026-09-03 the owner authorized the exact
reviewer-free, self-review-permitted, main-only environments and audited
non-secret policy sentinels for that profile, plus public visibility for
`ghcr.io/latchway/latchway` when created. The first environment creation
request returned GitHub HTTP 403 because the stored credential lacks the
necessary environment-administration permission. After owner browser sign-in,
the 13 authorized environments were created with main-only branch rules and
their exact non-secret policy sentinels. That policy-configuration step added
no reviewer requirement, wait timer, registry credential, other secret, or
strict-profile ruleset. The owner subsequently authorized and completed the
separate, scoped CocoaPods/signing credential installation recorded below.
npm 2FA is enabled in `auth-and-writes` mode. All five inert namespace records
(`@latchway/client`, `openai`, `vercel-ai`, `langchain`, and `react-native`) are
public at `0.0.0-bootstrap.0`. After npm rejected removal of its unexpected
`latest` alias with HTTP 400, the separately reviewed compatibility helper at
JavaScript tooling commit `75721b345ee7907a7ffd0f19ecd8216fe9ae9103` completed
publication and exact-byte registry verification for all five packages. Its
schema-2 receipt records both observed tags and `stable_release: false`; it
accepts `latest` only when it names the sole exact bootstrap version. These
placeholders contain no SDK implementation. After explicit owner authorization,
all five npm trusted publishers were configured and read back with the exact
repository, `single-maintainer-release.yml`, `single-maintainer-v1`, and sole
`createPackage` permission. Every stable `1.0.0` package remains outstanding.
No stable tag or `1.0.0` package, container, production documentation
deployment, cloud proof, or protected release evidence is claimed.
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
| Current phase | Phase 9: core and the four final SDK source heads are delivered to `main`; the selected profile's 13 authorized environment policies and npm/native publishing identities are configured. Candidate load verification, publication, and protected exact-image deployment remain open |
| Current objective | Execute the explicit `single_maintainer_v1` launch profile: publish the exact GHCR/npm/SwiftPM/CocoaPods/Maven coordinates, pass supply-chain verification, and verify Docker Compose plus Google Cloud Run. Strict independent review and the other external domains remain deferred and unverified. |
| Validated implementation coordinates | Contract `cd47229eac32f4a93a0779903d927526b77817d6`; core implementation `8bf4d9dede1490c3129f7f745f1017875bd4a005`; JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7`; Swift `92a394acbc00d1af6d258372f22b11ddae8e1750`; Android `694cb4d2bff9e91582896e3cbbe140e960d9e4e4`; React Native `ba23c750ec662834b4d480940c4067508723defb` |
| Protocol contract version | Released `1.0.0` at `2026-09-01T20:25:00Z`; wire protocol `2`; contract source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Database schema version | `28` at contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6`; historical checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` remains schema `27` |
| Last full test time | `2026-09-03` — core `8bf4d9dede1490c3129f7f745f1017875bd4a005` passed 423 Python release/workflow tests, generated documentation validation, actionlint, `go vet ./...`, and complete uncached `go test -count=1 ./...`; the frozen runtime checkpoint continues to carry the earlier full `make check` and PostgreSQL 15/18 gates. JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7` passed its full `pnpm check`, 71 offline release tests (70 pass and one skip), and 51 Playwright tests. Android `694cb4d2bff9e91582896e3cbbe140e960d9e4e4` passed 106 offline release tests (105 pass and one skip), actionlint, and the unchanged 665-actionable-task Gradle source gate. React Native `ba23c750ec662834b4d480940c4067508723defb` passed full `pnpm check`: 103 Vitest, 62 Node, 19 Python, 8 dependency-scan tests, TypeScript/build/codegen, deterministic iOS/Android bundles, and native-boundary checks. Swift `92a394acbc00d1af6d258372f22b11ddae8e1750` passed 65 offline release tests (64 pass and one skip), 166/166 XCTest, SwiftOpenAI 11/11, Foundation Models 12/12, App Extensions 4/4, external SwiftPM consumer, and all four CocoaPods lints. Its patched MacPaw 0.5.1 verifier separately passed 213/213 upstream tests plus the positive transport/cancellation probe. |
| Passing test commands | Verified commands and required working directories are listed below |
| Open blockers | For the selected single-maintainer launch profile: exact GHCR/npm/SwiftPM/CocoaPods/Maven publication, immutable tags and GitHub releases, multi-architecture supply-chain receipts, and exact-image Docker Compose plus Google Cloud Run observations. Independent review, Mintlify production, Apple/Android/browser/provider evidence, AWS, Fly.io, Cloudflare Containers, and operational-resilience observations are deferred rather than passed. |
| External credentials still required | The signed-in GitHub browser session successfully configured the authorized environments; the stored API credential still lacks Administration write. All five inert npm namespace publications and exact trusted-publisher grants are complete. The approved CocoaPods token is installed only in the iOS `single-maintainer-v1` environment; the Maven signing key/passphrase are installed only in Android `single-maintainer-v1-signing`, with the public fingerprint bound in Android's signing, Maven, and verification environments. Sonatype verified `dev.latchway` under Latchway on 2026-09-03. After separate explicit approval, one account-wide publishing token was created with expiration 2026-10-03; exactly its username/password secrets are installed in Android `single-maintainer-v1-maven`. Independent metadata/policy read-back passed. The updated disposable GCP identity passes all tested setup/evidence/cleanup permission checks for project `latchway`; protected short-lived workload identity configuration and deployment setup remain outstanding. The owner authorizes a disposable `asia-southeast1` verification stack only in `latchway`, at most two hours and $10, with cleanup of resources created for the test. No billable stack starts before a verified candidate image. A distinct reviewer and the Apple, Play, Turnstile, other-cloud, collector, and Mintlify identities are required only when completing the deferred strict profile. |
| Next executable task | Diagnose candidate load failures without relaxing the gates, publish and verify the passing candidate GHCR image and registry coordinates, retain scans/SBOM/signature/provenance, then run Docker Compose and Google Cloud Run against that exact digest and evaluate `single_maintainer_v1` without making a strict-assurance claim. |

### Validated version 1 source coordinates

| Repository | Validated coordinate or state |
| --- | --- |
| Core contract/runtime checkpoints `latchway` | Frozen contract `cd47229eac32f4a93a0779903d927526b77817d6`; current implementation `8bf4d9dede1490c3129f7f745f1017875bd4a005` |
| Prior schema-27 performance checkpoint `latchway` | `77069816dd68174052e7ebc163911883f8f07e7e` |
| Canonical public documentation | This checked-in `docs/public` tree imports the final bundles based on core implementation `8bf4d9dede1490c3129f7f745f1017875bd4a005` |
| JavaScript `latchway-js` | `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7` |
| Swift `latchway-ios-sdk` | `92a394acbc00d1af6d258372f22b11ddae8e1750` |
| Android `latchway-android` | `694cb4d2bff9e91582896e3cbbe140e960d9e4e4` |
| React Native `latchway-react-native-sdk` | `ba23c750ec662834b4d480940c4067508723defb` |
| JavaScript documentation bundle SHA-256 | `f4e814289055bad88d508dde862ebdbd105b03483db807c2f128b0681da07711` |
| Swift documentation bundle SHA-256 | `c0cdad255cde507faaad173f9a2dba05a29e6be53130f07a25c2e4e831498f00` |
| Android documentation bundle SHA-256 | `1a13c6834b960dbfc7fb91c390167624eadbf5f6e8d12325bd82423cc4f4a7f7` |
| React Native documentation bundle SHA-256 | `db7c9a569a86ec2f88750de80a1bc2f44dceb0c6db2d9f1613a309dcbbed37a2` |
| Mintlify mirror `latchway-docs` | Generated deployment mirror; `.latchway-docs-source.json` must identify the exact canonical source, and no protected production deployment receipt exists |

The core and SDK coordinates form the validated product-source tuple delivered
to `main`; this checked-in tree is the canonical documentation source.
The deterministic
contract bundle SHA-256 is
`0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`.
The five product-source remote `main` heads match their intended final source
histories at the recorded delivery checkpoint. The current local JavaScript
checkout has a pre-existing unresolved merge and is not a new validated
release coordinate; it is preserved without resolution or abort. Namespace
bootstrap instead used a clean isolated checkout of the separately reviewed
tooling commit `75721b345ee7907a7ffd0f19ecd8216fe9ae9103`, with all five
regenerated and registry-downloaded inert tarball hashes matching the reviewed
bytes. That tooling branch does not change the validated SDK source tuple.
The mirror/source manifest and six-repository source-conformance
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
| Product release state | `unpublished` and not release-qualified; no local version 1 tags exist, and no stable package, image, or product-runtime cloud deployment is verified. Five inert npm namespace placeholders are public at `0.0.0-bootstrap.0`, not usable SDK releases. A Mintlify preview exists, but no protected production deployment receipt is claimed and `docs.latchway.dev` is not routed. |

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
| Swift, Android, JavaScript SDKs | JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7` passed the full package/browser gate and 71 offline release tests. Android `694cb4d2bff9e91582896e3cbbe140e960d9e4e4` passed 106 offline release tests and its unchanged full 665-actionable-task Gradle gate. Swift `92a394acbc00d1af6d258372f22b11ddae8e1750` passed 65 offline release tests, 166/166 XCTest, SwiftOpenAI 11/11, Foundation Models 12/12, App Extensions 4/4 (193 Swift tests total), external SwiftPM consumer, and all four CocoaPods lints. | Physical proof where applicable, protected exact-candidate evidence, tags, and publication |
| React Native SDK | Successor commit `ba23c750ec662834b4d480940c4067508723defb` passes 103 Vitest, 62 Node, 19 Python, and 8/8 dependency-scan tests plus TypeScript/build/codegen, deterministic iOS/Android bundles, and native-boundary checks. It pins JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7`, Swift `92a394acbc00d1af6d258372f22b11ddae8e1750`, and Android `694cb4d2bff9e91582896e3cbbe140e960d9e4e4`; `Package.swift` and `Package.resolved` automatically enforce the same iOS revision. Its lower-assurance workflow remains fail-closed until the live policy environment is explicitly authorized and configured. Predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict Apple Development root/extension signing, provisioning, App Attest and Keychain entitlement, registered-device, install, and launch checks without new App Attest or App Intent execution. The physical path was not rerun at the current successor. The Release fixture has no Latchway request path and fails closed. Historical commit `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` remains the live root-app App Attest proof. | Hosted replay rejection; operator-deferred physical invocation of the Debug App Intent path; protected Apple distribution, extension-matrix, and native-isolation proof; physical Android/Google Play proof; protected controls/evidence, tags, and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests; schema 24 makes TTFT protocol-aware, schema 25 hardens ephemeral challenges and browser Origin, schema 26 records logical-request decision stages, and schema 27 supports bounded audit operations; doctor exposes redaction-safe revision, connectivity, job, replica, key-ID consistency, and capacity diagnostics, and scheduled self-tests retain the bounded `run_scheduled_self_test` job label instead of collapsing to `other` | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated. Cloudflare Container evidence now follows the provider's bounded application cursor directly, rejects malformed, duplicate, repeated-cursor, and oversized results, and retains the prior scoped-token boundary instead of relying on Wrangler's one-page JSON listing. | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Release controls | The closed strict desired-state manifest covers six repositories, 51 protected environments, exact main/tag rulesets, and five npm trusted-publisher tuples. `latchway-docs` uniquely requires CODEOWNERS review, one approval, and a written docs-not-required check; product repositories retain the no-source-review release model. The additive `single_maintainer_v1` environments and sentinels preserve a visibly lower-assurance path. Offline validation passes. After the initial API permission failure, all 13 owner-authorized reviewer-free, self-review-permitted, main-only environments and exact non-secret policy sentinels were configured through the signed-in browser on 2026-09-03. The five npm namespaces and exact selected-profile trusted publishers are verified. Separately authorized CocoaPods/signing secrets and fingerprint variables are installed only in their approved environments. Sonatype namespace verification and the one-month token's two exact Maven-environment secrets are complete, with independent metadata/policy verification. | Passing candidate load verification, protected GCP workload identity setup, and exact-candidate publication remain open. No strict ruleset application is claimed. A distinct reviewer and strict two-stage reconciliation remain deferred. |
| Mintlify public docs | This canonical tree imports the four final reproducible bundles and retains task-oriented deployment comparison, release-image verification, and the completed Cloud Run/Cloudflare runbooks. The generated mirror must bind its exact source through `.latchway-docs-source.json`. | Configure `docs.latchway.dev`, deploy through protected controls, and seal post-deploy evidence |

## Local source evidence

- A manually dispatched native AMD64 advisory diagnostic now profiles the
  quota lifecycle against the unchanged failed-candidate production source
  `568f4f6950acec79c65ca59b3f829d7612242a11`. Its separate test overlays record
  bounded, redacted client timing, PostgreSQL statement counters, lock groups,
  WAL and I/O counters, with exact accounting checks and owned-resource cleanup.
  It has no release, signing, publication, secret, or production configuration
  access. The runner's `25` offline tests, workflow lint, and fresh PostgreSQL
  18 query-shape checks passed before dispatch; these are tooling checks, not
  hosted timing or a passed load gate. All `474` existing script tests were
  accounted for, with one local loopback-port test rerun successfully after
  the sandbox initially blocked its temporary listener. The diagnostic excludes
  HTTP, authentication, upstream execution, retries, streaming and operational
  jobs, and cannot substitute for the protected full-load candidate.
- Protected candidate run `33730714475`, attempt `1`, at source
  `568f4f6950acec79c65ca59b3f829d7612242a11` failed its unchanged load gate
  on 2026-09-03 after core, Console, and failure/replica checks passed.
  Image build/publication/signing were skipped. The retained native AMD64
  run passed preflight, idle memory (`181.313 MiB`), and contention
  (`64` accepted, `64` denied, zero overspend), but failed overhead
  (`26.971 / 49.425 / 132.414 ms` p50/p95/p99), sustained load
  (`2,826` HTTP 200 and `3,174` HTTP 503 `server_not_ready` out of `6,000`),
  and SSE memory slope (`72.783 MiB/min`, unchanged bound `5`).
  Actual request-start lag stayed within `25 ms` at `12.507 ms`.
  Nonstream accounting remained unsettled after the bounded drain, with
  `1,372` logical-request units reserved. All `500` SSE requests established
  and remained open; memory grew `102.746 MiB`, under the `128 MiB` growth
  bound but not the independent plateau-slope bound. SSE terminal accounting
  was not measured after that earlier failure, not silently marked passed.
  New process-memory observations during the held-stream interval show
  roughly `68 MiB` additional anonymous huge pages alongside `69.769 MiB`
  RSS growth. This supports a kernel huge-page contribution but is not a
  controlled causal experiment or proof that there is no application leak.
  A subsequent two-container native Linux ARM64 synthetic sparse-heap
  comparison did not reproduce that growth in its default control: both
  default and per-process THP-disabled runs retained zero anonymous huge
  pages throughout. It establishes no application mitigation. The temporary
  containers/image were removed, and production runtime settings are unchanged.
  The candidate remains failed; no gate or resource cap was relaxed.
- A separate, unintegrated calendar-capacity vector experiment completed one
  fixed local ABBA comparison against `e064e671a8baa34bf0b559c7c8f3fccbcd6a1959`.
  All `1,600` measured requests had exact accounting and no traced errors.
  The two-run serial Reserve mean fell `4.451 → 4.285 ms`; concurrent
  whole-lifecycle means were effectively unchanged (`127.804 → 127.698 ms`).
  These overlapping local samples demonstrate fewer statements in the final
  batch, not a material end-to-end or hosted-release benefit. The experiment
  remains outside main. Its exact temporary database and anonymous volume
  were removed; the six existing preview containers were preserved.
- The owner separately approved up to 30 minutes of emergency removal beyond
  the temporary GCP test's two-hour deadline, including independently owned
  database/secrets when application shutdown cannot be confirmed. This does
  not authorize new resources, continued testing, or an increase above `$10`.
  The updated cleanup watchdog and terminal-intent reconciliation helper
  passed `58` offline tests; the bounded database/proxy child bridge passed
  `23`. Those are private operator-tool checks, not cloud evidence. No paid
  stack, live cleanup arm, or GCP workflow dispatch exists. Authenticated
  candidate verification and the integrated creator/supervisor/cleanup
  boundaries remain prerequisites for live provisioning.

- A second reviewed optimization batches only BeginAttempt's final attempt
  and allocation inserts. Its earlier reads, classifiers, ordered locks,
  identifier generation, fresh clock/expiry checks, and checked dispatch
  update remain unchanged. The measured three-token shape removes three
  explicit exchanges; retry insertion remains sequential. The full real
  PostgreSQL 18 quota suite passed in `22.825 s`, the new cases passed in
  simple-protocol mode, and the focused race suite passed in `6.529 s`.
  Tests cover rollback after the third allocation fails, exact attribution
  and counts, zero allocations, pending and terminal replay without a new
  identifier, and the existing 48 overlapping lifecycles. Independent review
  found no remaining issues. The complete subsequent local load suite is
  recorded below; it is not a passing release result.
- Integrated source `b6da040f22b8f9a67cc86c6486d2b533f6cd58f5` passed
  full uncached Go tests and vet, all 474 release/tool tests, Go formatting,
  workflow lint, and normative contract validation. Canonical public docs
  passed the complete check across 233 routes, including build, links,
  generated references, pinned prose checks, and accessibility. Initial
  sandbox-only cache/loopback restrictions were resolved by rerunning the
  same checks with the required local permissions; no tests were disabled.
- The subsequent unchanged full local load run at clean source
  `e064e671a8baa34bf0b559c7c8f3fccbcd6a1959` again passed five of six gates.
  Gateway overhead now passed all limits at `14.323833`/`18.296501`/
  `25.119375 ms` p50/p95/p99. All 6,000 non-stream requests returned HTTP
  200 with exact terminal accounting and zero pending reservations, but
  maximum request-start lag was `50.959086 ms`, exceeding the `25 ms`
  workload-pacing requirement; scheduler lag was `46.333253 ms`. Non-stream
  p99 latency was `625.838834 ms`. All 500 SSE streams held with a flat
  `158.695 MiB` plateau; preflight, idle memory, and contention also passed.
  The overall result remains failed. This run does not establish the cause
  of the scheduling/latency spike or a controlled before/after speedup.
- The complete unchanged local load suite at
  `ed0dfa345c8a4bf2fcf57bc3cc0794220f36b3f6` passed five of six gates.
  Gateway-overhead p50 was `15.070375 ms`, above the `15 ms` limit;
  p95/p99 passed at `19.876999`/`27.279041 ms`. All 6,000 non-stream
  requests returned HTTP 200, with exact terminal accounting and zero
  pending reservations. All 500 SSE streams held for 60 seconds; peak
  RSS was `155.133 MiB`, growth `96.203 MiB`, and the hold plateau was
  flat. Preflight, idle memory, and zero-overspend contention also passed.
  The overall result remains failed, not release evidence. Its exact
  temporary containers, network, and image tags were removed; the six
  existing preview containers remain running. This was not a matched
  before/after experiment, so it does not establish an optimization speedup.
- The same local source passed complete uncached `go test -count=1 ./...`
  and `go vet ./...`. Those commands had no database fixture; the separate
  complete PostgreSQL 18 quota suite is recorded below.
- A bounded, sanitized SQL profile of baseline `3eb76e7` completed 400
  exact-accounted lifecycles without query errors. Serial mean lifecycle
  time was `14.489 ms`; at concurrency 16, two shared-bucket lock-containing
  batches accounted for `85.1%` of the `146.064 ms` mean. This is consistent
  with contention, not direct server wait timing. BeginAttempt made 13
  separate client query calls, identifying its tail inserts as a narrower
  next optimization. These private diagnostic results are not release gates
  or an exact network-round-trip count.
- A reviewed Reserve-only optimization batches the post-lock clock and stage
  number reads with the existing sorted bucket locks, and batches decision
  provenance with capacity/reservation writes. It removes three explicit
  warmed-path database exchanges on accepted requests without dropping SQL
  commands, accounting checks, row-count guards, or ordered locks. Denial and
  replay behavior remain intact. The complete real PostgreSQL 18 quota suite
  passed in 21.290 seconds, including three injected rollback boundaries,
  48 overlapping complete lifecycles with exact accounting, and last-bucket
  lock waits in both cached-statement and simple-protocol modes. Independent
  review caught and reproduced a stale batched `statement_timestamp()` in
  simple protocol; a trailing `clock_timestamp()` corrects only this new
  path and preserves the full post-lock reservation lifetime. Offline quota
  tests and separate source review also passed. The subsequent full load
  result is recorded above and remains below release requirements.
- Advisory memory diagnostics now sample six numeric process-memory counters
  and four allowlisted Linux huge-page controls through the existing load
  runner, without elevated privileges, new services, or runtime tuning. Raw
  process mappings, paths, credentials, and dependency errors are discarded.
  Missing or denied measurements remain unknown, not zero. Sampling uses
  the existing slower lifecycle cadence, and interruption cleanup requires
  the exact owned runner label/image/create intent. The combined diagnostic,
  CI, release, and resilience script checks passed 104 tests. These counters
  are diagnostic only and do not establish the cause of the memory growth.
  The complete local ARM64 run successfully captured the counters and
  recorded `66 MiB` of anonymous huge pages during its flat SSE plateau.
  Huge-page configuration alone therefore does not establish the cause of
  the earlier CI memory staircase; CI process counters remain outstanding.
- Candidate run `33723723170`, at exact source
  `3eb76e733ca54304f7deb3fcd186409648d11b03`, passed core, Console, and
  deterministic failure/replica gates but failed the complete load suite.
  Image building, publication, and signing were skipped. The diagnostics
  recorded four actual runner CPUs, up to 31 blocked PostgreSQL backends
  (tuple/transaction-ID lock waits), and substantial CPU pressure, with no
  deadlocks or OOM. Overhead p50/p95/p99 was `26.481`/`32.927`/`37.606` ms.
  Of 6,000 non-stream requests, 3,637 returned HTTP 200 and 2,363 returned
  HTTP 503 `server_not_ready`; 1,196 reservations remained pending after the
  settlement wait. All 500 SSE streams held, but RSS slope was
  `82.642 MiB/min`, above the unchanged `<5` requirement. The remaining
  reservations belonged to the earlier non-stream gate, not the SSE
  cancellations. Preflight, idle memory, and zero-overspend contention
  passed. Row-lock contention is observed; its exact SQL cost and the
  streaming memory increase still require diagnosis. No passing release
  or protected deployment evidence is claimed from this run.
- That candidate included only advisory load-diagnostic tooling changes,
  not production-path changes or relaxed release gates. Bounded, read-only
  PostgreSQL activity/lifecycle aggregates, host/scoped-container resource
  measurements, and allowlisted database error labels retain neither SQL
  text nor credentials. Collector shutdown is bounded and cannot replace
  the gate's result; cleanup removes only the exact fixture's anonymous
  PostgreSQL volume. The reviewed tooling change passed 96 script/workflow
  tests, shell syntax, and a fresh pinned PostgreSQL 18 smoke with all 28
  migrations, both aggregate queries under a 500 ms timeout, and a rejected
  write proving read-only enforcement. A separate review found no remaining
  issues. Canonical public documentation passed its complete `pnpm check`
  across 233 routes, including pinned Vale 3.17.0, build/link validation, and
  accessibility checks. Its failed protected load result is recorded above.
- Candidate run `33718191675`, at exact remote source
  `3b4cf7bf4ea019202c01ca4f9224b19129660d38`, failed the complete isolated
  load gate after core, Console, and deterministic failure/replica gates
  passed. The PostgreSQL startup fix worked and all six load gates ran.
  Overhead p50/p95/p99 was `23.64`/`63.14`/`111.31` ms; the 6,000-request
  gate returned 3,750 HTTP 200 and 2,250 slow HTTP 503 `server_not_ready`
  results and retained 1,192 pending reservations after its settlement
  wait. All 500 SSE streams stayed open, but RSS slope was `75.26 MiB/min`
  against `<5`; terminal stream accounting was skipped after that failure,
  not independently failed. Preflight, idle memory, and zero-overspend
  contention passed. Image build, publication, and signing were skipped.
  The retained evidence does not identify the underlying database error or
  prove a product memory leak; actual host CPU metadata was not retained.
- One fresh, native ARM64 local diagnostic on exact `3b4cf7bf` retained
  unchanged workloads, resource caps, and thresholds. All 6,000 non-stream
  requests returned HTTP 200; all 7,021 fixture requests settled exactly
  with zero reservations. Overhead was `14.569`/`20.397`/`27.328` ms, so p95
  still failed its `<20 ms` gate. Nineteen bounded database samples found
  zero deadlocks or sampled blocked connections and a maximum of 11
  connections including the sampler. This partial suite differs from CI's
  AMD64 environment and is diagnostic evidence, not a passing release gate.
  Its exact temporary containers, network, and volume were removed; the
  six existing preview/E2E containers were preserved.
- A separate fresh ARM64 `preflight,idle,streams` diagnostic on the same
  committed source passed all three selected gates: 500/500 streams held
  for 60 seconds, RSS remained flat at `162.66 MiB`, and terminal concurrency
  quotas returned exactly to 600/600. Temporary natural-GC/scavenger tracing
  showed GC during establishment and cancellation, not the hold. This does
  not reproduce CI's memory staircase or distinguish full-suite history
  from platform effects. Its exact temporary containers, network, volume,
  and image tags were removed; existing previews were preserved.
- The subsequent single full native ARM64 diagnostic on `3b4cf7bf`, with
  only temporary natural-GC/scavenger tracing, passed all six original gates.
  Overhead p50/p95/p99 was `13.236`/`16.940`/`24.863` ms; all 6,000 non-stream
  requests succeeded at 100 requests/second with exact settlement. All 500
  SSE streams held for 60 seconds and terminal quotas settled exactly. RSS
  increased from `58.832` to `159.160 MiB` during establishment, then stayed
  effectively flat (`0.00274 MiB/min`); no GC occurred during the hold and
  live heap fell after cancellation. Full-suite history alone did not
  reproduce the CI failure locally. This temporary-instrumentation local
  run is diagnostic, not protected exact-image release evidence. All exact
  temporary resources were removed; the six previews were preserved.
- On 2026-09-03, authoritative and public-resolver DNS checks confirmed the
  owner's Sonatype TXT record, and Central Portal reported `dev.latchway`
  verified under Latchway. The separately authorized one-month Portal token
  expires on 2026-10-03. Its two approved GitHub environment secrets were
  created at `2026-09-03T06:03:47Z` and `2026-09-03T06:04:14Z`; independent
  metadata verification confirms no extra Maven secrets, unchanged signing
  secrets, zero verification-environment secrets, and exact unchanged
  main-only/reviewer-free policies and public variables. No Maven artifact
  has been published.
- A fresh, ephemeral GCP inventory used only `cloud-platform.read-only`
  without credential activation or persistence. Project `latchway` is active;
  Cloud Resource Manager, Logging, and Service Usage are enabled. Cloud Run,
  IAM, IAM Credentials, Secret Manager, Cloud SQL Admin, and Security Token
  Service are disabled. Their resource inventories were not queried, so
  resource existence remains unknown rather than empty. That inventory made
  no API, IAM, billing, configuration, or runtime changes. After the owner
  supplied the updated disposable identity, a separate in-memory scoped
  preflight passed all tested setup, evidence, and cleanup permissions.
  Billing readiness remained unknown because the Cloud Billing API was
  disabled. The approved temporary stack is restricted to project `latchway`,
  `asia-southeast1`, two hours, and $10; no billable resources have been
  created. The subsequent one-shot billing-readiness helper pinned project
  number `1016447222915`, recorded Cloud Billing's original disabled state,
  enabled only `cloudbilling.googleapis.com`, and verified
  `billingEnabled: true` at `2026-09-03T06:16:44Z`. Its non-secret cleanup
  receipt records that API change; no billable resources, IAM changes,
  billing-association changes, or persistent credentials/configuration were
  created by this setup step. The owner separately approved up to 30 minutes
  of emergency cleanup after the two-hour deadline, solely for removing
  this test's resources, including independently owned database/secrets
  when app shutdown cannot be confirmed. This does not increase the $10
  budget or authorize new resources or continued testing. The fixed-scope
  cleanup safeguard passed 35 offline tests; it is not armed and no paid
  resources have been created.
- Candidate run `33714186880` at
  `056fba2030b6573cfef69514a027a002a54d5eb6` passed contract/release-tooling,
  core/race/fuzz, Console, and deterministic failure/replica gates, then failed
  before load execution because the isolated PostgreSQL readiness probe
  accepted its temporary initialization server before the `latchway` database
  existed. Image building, publication, and signing were skipped. The harness
  now requires five consecutive TCP `SELECT 1` successes against the configured
  role/database, uses
  the same bounded TCP path for settings queries, and retains only bounded,
  fixed-label PostgreSQL startup diagnostics on failure. All 62 relevant
  CI/release/resilience tests pass, including 12 new behavioral regressions;
  the candidate tooling suite also passed its 88 tests before the two final
  additive regressions. Fresh pinned PostgreSQL 18 verification passed with
  five successful TCP probes, the expected connection limit, preserved caller
  credentials, and missing-database rejection; only the disposable test
  container and its volume were removed. Performance thresholds
  and resource limits are unchanged. Candidate run `33716493748` at
  `1adb8566aad1ba1f928da1e524edfefaae7fb3b6` passed core, Console, and
  deterministic failure/replica gates and reached the isolated load gate, but
  is superseded by the Compose workflow correction below. No passing load or
  container evidence is claimed from either prior run.
- The Compose evidence workflow had a separate runner-lifetime defect: its
  finalizer probed a loopback endpoint only after the capture runner had removed
  the deployment. It now captures bounded health/readiness responses while the
  restored service is alive, retains them before teardown, and requires the
  fresh signer to byte-bind all seven raw observations. Cloud probes remain on
  the finalizer. Source-build, release, and workflow-owned Compose models now
  share the target-database TCP readiness probe. The 24 deployment tests and
  38 broader release tests pass, as do actionlint, all 37 workflow shell
  fragments, both Compose model renders, independent diff review, and a fresh
  PostgreSQL initialization-race proof. The final combined 87-test release
  suite also passes. The probe supplies credentials, but
  the default image's loopback trust policy does not validate passwords; no
  production authentication policy was changed. A separate disposable SCRAM
  fixture proved wrong-password failures propagate without probe output.
  This workflow correction
  requires a replacement exact-source candidate before Compose evidence can
  qualify the release.
- All five npm namespace bootstrap publications completed on 2026-09-03 from
  isolated JavaScript tooling commit
  `75721b345ee7907a7ffd0f19ecd8216fe9ae9103`. The helper SHA-256 is
  `68427af1029ffd544467072980902f15cae214184a89cb39aa999890e7c4d1e0`.
  The completed schema-2 receipt verifies registry metadata, exact archive
  bytes, and the bootstrap/latest aliases for every package, explicitly with
  `stable_release: false`. Namespace reservation does not imply a stable SDK
  package release.
- The owner separately approved all five npm trusted publishers. Read-back
  confirms the four JavaScript packages trust `Latchway/latchway-js` and
  React Native trusts `Latchway/latchway-react-native-sdk`, each bound to
  `single-maintainer-release.yml`, `single-maintainer-v1`, and only the
  `createPackage` permission. Main-only enforcement is supplied by the already
  verified GitHub environment policy. No npm token was installed in GitHub.
- After separate explicit owner authorization, GitHub acknowledged installation
  of `COCOAPODS_TRUNK_TOKEN` only in iOS `single-maintainer-v1`, plus
  `LATCHWAY_SIGNING_KEY` and `LATCHWAY_SIGNING_PASSWORD` only in Android
  `single-maintainer-v1-signing`. `LATCHWAY_MAVEN_SIGNING_FINGERPRINT` was
  created in Android's `single-maintainer-v1-signing`,
  `single-maintainer-v1-maven`, and `single-maintainer-v1-verification`
  environments. Exact policy/inventory checks preceded every write, existing
  values were not overwritten, and post-write metadata verification passed.
  Secret material was read only from the approved local sources, retained in
  process memory, and passed through standard input rather than arguments or
  logs. No Sonatype token was created or installed.
- Core CI run `33676007601` passed all eight jobs at
  `5ae5bcf7862a3315bada388ae41974d87bf13ef8`: contracts, lint, Console,
  PostgreSQL 15, PostgreSQL 18, reliability, deployment validation, and
  multi-architecture image build. This is CI validation, not GHCR publication.
- The GCP deployment documentation now provides manual-first Cloud Run:
  choose the published image digest, connect PostgreSQL, set runtime secrets,
  migrate, and finish Console setup. Terraform remains optional. No GCP
  resources, IAM bindings, WIF configuration, API enablement, or billing
  changes were authorized or applied by this documentation request. Full
  canonical documentation validation passed for 233 routes, including build,
  links, metadata, prose, and accessibility; 20 deployment-evidence tests and
  shell syntax checks also passed. The live metadata test now uses the
  validator's current date, while an explicit future-date rejection regression
  remains deterministic. The
  selected release profile still requires actual exact-image Cloud Run
  evidence; manual deployment instructions do not satisfy that gate.
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
  successor `ba23c750ec662834b4d480940c4067508723defb` includes the
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
`8bf4d9dede1490c3129f7f745f1017875bd4a005`, bundle SHA-256
`0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`,
JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7`, iOS
`92a394acbc00d1af6d258372f22b11ddae8e1750`, Android
`694cb4d2bff9e91582896e3cbbe140e960d9e4e4`, and React Native
`ba23c750ec662834b4d480940c4067508723defb`. All four imported SDK
documentation bundles record those SDK coordinates and `source_tree_clean:
true`. React Native predecessor
`4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict development signing,
entitlement, embedded-extension, registered-iPad, install, and launch
verification. Current `ba23c750ec662834b4d480940c4067508723defb` was not
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
documentation is this checked-in tree. The project is not yet ready for the
selected lower-assurance public version 1 launch. That launch remains blocked
until authenticated `single_maintainer_v1` evidence binds the required public
tags and releases, package and GHCR bytes, multi-architecture supply-chain
artifacts, Docker Compose, and Google Cloud Run to one immutable source tuple.
The profile must retain `profile_status: incomplete`, keep deferred evidence
`unverified`, and forbid a production-ready or `release-qualified` claim.
Strict promotion and release-qualified documentation remain separately blocked
until the strict finalizer binds every required external receipt to the same
immutable coordinates.
