# Implementation status

Status date: 2026-09-02

Latchway version 1 is source-complete and locally converged. The frozen core
contract checkpoint includes Admin-session management, configuration transfer,
authenticated Admin event-stream refresh hints, and lifecycle-concurrency
hardening; the contract is marked released and every SDK successor is rebound
to its deterministic contract bundle with final `1.0.0` changelog headings.
All four SDK source/check gates pass, their exact documentation bundles are
imported, and stable release preflights no longer reject draft locks or
candidate changelogs. The coordinated core, SDK, and documentation tuple passes
the clean six-repository source-conformance gate; tags and protected evidence
are still required.
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
| Current phase | Phase 9: source integration is converged; live release-control provisioning and protected exact-candidate execution remain open |
| Current objective | Apply the reviewed GitHub/npm controls, then execute protected release domains only with their required authority |
| Validated implementation coordinates | The frozen contract and SDK coordinates below; the final source-conformance report records the canonical-doc and mirror commits |
| Protocol contract version | Released `1.0.0` at `2026-09-01T20:25:00Z`; wire protocol `2`; contract source checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d` |
| Database schema version | `28` at contract/source checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d` and the current candidate descendant; historical checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` remains schema `27` |
| Last full test time | `2026-09-02` — the schema-28 contract/source checkpoint and current candidate descendant passed the complete PostgreSQL-backed `go test -count=1 ./...` gate plus contract and canonical-public-documentation validation. The recorded successor tuple separately passed core check/race/fuzz/PostgreSQL and SDK source/check gates, deterministic contract and SDK-documentation rebuilds, canonical and mirror documentation suites, predecessor physical iPad signed-bundle verification/install/launch, and clean cross-repository source conformance. Stable SDK release preflights no longer reject draft locks or candidate changelogs, but still require tags and protected exact-candidate evidence. Local/static evidence is not protected release evidence. |
| Passing test commands | Verified commands and required working directories are listed below |
| Open blockers | Before stable release: live GitHub environment/ruleset/immutable-release enforcement with an independent reviewer; npm sign-in, account 2FA, namespace bootstrap and exact trusted publishers; registry/package publication; an Apple Distribution/ad hoc/TestFlight/App Store protected immutable candidate; the protected delegated-extension runtime matrix; operator-deferred App Intent and physical Android/Google Play proof; Turnstile; immutable-image provider/cloud/resilience; and post-publication receipts |
| External credentials still required | The connected GitHub token can deliver source but lacks repository-administration/environment authority. Live controls require an administrator session plus a reviewer distinct from the authenticated operator. npm requires an authenticated 2FA-enabled publisher account before namespace bootstrap/trusted-publisher creation. Later protected gates require the applicable Apple distribution, Play, Turnstile, cloud, registry, KMS/signing, collector, and finalizer identities. |
| Next executable task | Apply and verify the reviewed GitHub/npm control manifest before any package, image, tag, or stable-release mutation |

### Validated version 1 source coordinates

| Repository | Validated coordinate or state |
| --- | --- |
| Core contract checkpoint `latchway` | `437708fb56d45196720b5769f2f59b0ee51f521d` |
| Prior schema-27 performance checkpoint `latchway` | `77069816dd68174052e7ebc163911883f8f07e7e` |
| Core canonical-public-doc source | Clean-gate baseline `8c3783133698d569652def30b1003bb67c6a10b9`; ledger-only successors retain byte-identical `api/` sources |
| JavaScript `latchway-js` | `01dfa223773c20fe3a31559116f16e31f757b94a` |
| Swift `latchway-ios-sdk` | `c0fac916836bcfbdbf7f6a81808036726589d563` |
| Android `latchway-android` | `3e0a601fad28a5ccf6674472a473c4797a7b404d` |
| React Native `latchway-react-native-sdk` | `39fd86ef1f6f973953e4fd5d0057ae17cc035abb` |
| JavaScript documentation bundle SHA-256 | `f0d273acdf85f8d5f7ec79a4ac170f158729a40375d23961b11dd17c792636b2` |
| Swift documentation bundle SHA-256 | `e22d6e472de404b75396eee1db5fce05eba7175d7f4be6469fb7d0422120f6f9` |
| Android documentation bundle SHA-256 | `eebe14ec49a7c9493d238dcddaba57078188d9321623ff03e62659c0f8400f65` |
| React Native documentation bundle SHA-256 | `81fe9a5c4a365f0761b269d3ee1cbe55d60922544ad78dd42091e8ba7c4f31bb` |
| SDK documentation lock SHA-256 | `40dca672264d06c801a308c2cf6d774eff4d25c61e5630009c2e53cd3d9bcd4b` |
| Mintlify mirror `latchway-docs` | Clean-gate baseline `a99308cf8892a5a857ac15cc02474333e5b9482c`, bound to canonical core `8c3783133698d569652def30b1003bb67c6a10b9` |

These coordinates form the current candidate source-conformance tuple. A clean
six-repository run passed with the canonical core and generated mirror commits
recorded above. The contract bundle SHA-256 is
`14cd2d8ddc8c4b85b8ab002359b373772d599a4eaaa8e95b9b0b793c684215c6`.
Branch synchronization is a delivery operation, not release evidence. All six
audited histories are delivered to `main`. No local version 1 tags exist, and
no GitHub release, package/container publication, product-runtime deployment,
or protected production-documentation receipt is verified. The public
Mintlify content is live.

### Full-suite commands

These commands passed for the recorded source tuple.

```sh
# Core server, generated SQL, Go vet/tests, dashboard, and Playwright
mise exec -- make check

# Canonical public docs and synchronized Mintlify mirror (from core)
(cd docs/public && mise exec -- pnpm check)
python3 scripts/sync-public-docs.py --target ../latchway-docs --check
(cd ../latchway-docs && mise exec -- pnpm check)

# JavaScript SDK
(cd ../latchway-js && mise exec -- pnpm check)

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
| Core branch | `codex/v1-implementation` |
| Contract | `1.0.0` released at `2026-09-01T20:25:00Z` |
| Contract source checkpoint | Core checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d` |
| Bundle SHA-256 | `14cd2d8ddc8c4b85b8ab002359b373772d599a4eaaa8e95b9b0b793c684215c6` |
| Wire | Current `2`; discovery supports `[1, 2]` |
| Database | Schema `28` at contract/source checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d` and the current candidate descendant; checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` remains the preceding schema-27 coordinate |
| Package/server range | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| Product release state | `unpublished` and not release-qualified; no local version 1 tags exist, and no package, image, cloud deployment, or production documentation deployment is verified |

The historical `0.5.1`/wire-1 coordinate remains unchanged. Intermediate bundle
hashes are not release coordinates. All four SDK successor locks name the
released checkpoint and reproducible bundle above.

## Workstream status

| Workstream | Local source status | Remaining boundary |
| --- | --- | --- |
| Family/component contract and migrations | Implemented through schema 28 at contract/source checkpoint `437708fb56d45196720b5769f2f59b0ee51f521d` and the current candidate descendant; exact challenge Origin and authoritative root-definition selection remain hardened, schema 26 adds redaction-safe logical-request decision stages, schema 27 adds bounded audit source/reason attribution and browse indexes, and schema 28 adds durable retry-cost treatment plus physical-attempt quota ledger support. Wear OS vocabulary remains reserved, but active Wear OS Component Definitions fail with `component_wearos_unsupported_v1` until an end-to-end SDK/runtime path exists. | Protected exact-candidate evidence and future Wear OS implementation before any support claim |
| Server trust/session/revocation/policy/quota runtime | Complete in source, including a generic component App Attest step-up protocol and bounded CEL request context whose feature/protocol are immutable-server bound; the CEL `request.estimated_input_tokens` fact remains untrusted, while production hard `input_tokens`/`total_tokens` and input-priced cost enforcement use a server-owned preflight bound tied to the exact post-rewrite body and selected physical model; quota snapshots fail closed when required request-size policy facts are unavailable. Calendar, token-bucket, and aggregate per-request `upstream_attempts` limits charge each physical dispatch atomically while `logical_requests` remains once per request. Cost retry treatment defaults to all actual attempts; user `initial_attempt_only` allowances require paired organization-only actual-attempt accounting. Current lifecycle transactions explicitly use `READ COMMITTED` and consistent application→environment→family/component lock order, closing root-challenge, App Attest post-disable insertion, configuration, family/component deadlock, retry replay, and excess-attempt races under real PostgreSQL tests. | Exact-candidate rerun and protected observations |
| Responses, Chat, Embeddings, Anthropic, opaque protocols | Complete; opaque HTTP now has pairwise-disjoint exact-depth path templates while retaining the prior segment-bound `pathPrefixes` mode for existing v1 revisions; bounded OpenRouter verification passed against the current source gateway | Immutable-image provider rerun |
| Weighted/sticky routing, fallback, retry, accounting | Complete; the clean local source load suite and all nine automated failure scenarios pass at the implementation checkpoint | Protected exact-image load and destructive-failure evidence |
| Admin API, CLI, dashboard, wizard, request/usage/audit views | The frozen checkpoint includes redaction-safe audit filtering/detail, a shared doctor/support-bundle contract, the exact `latchway test-upstream serve` fixture command, separate first-byte/first-token request timestamps, canonical Admin-session inventory/revoke across API, CLI, and Console, negotiated server capabilities and read-only safe mode, bounded redaction-safe YAML/JSON configuration transfer with exact numeric preservation and strong-ETag activation review, and authenticated SSE refresh hints with reconnect, polling fallback, and no row data. Complete local core gates pass. | Protected deployment operator acceptance |
| Native/Web trust verifiers and component proof | Complete in source; a historical development-signed physical React Native iOS root run passed production App Attest registration and same-key assertion, the current source adds a Debug-only native App Intent delegated-request path, and a browser-minted Firebase App Check token passes the current source gateway | Apple distribution-derived protected candidate, physical invocation of the current Debug App Intent path, protected extension matrix, physical Play Integrity, protected immutable-candidate App Check rerun, and Turnstile evidence |
| Swift, Android, JavaScript SDKs | Implemented; source/check gates pass and released-contract successor locks name `v1.0.0` with final changelog headings. Stable preflights no longer reject draft metadata. | Physical proof where applicable, protected exact-candidate evidence, tags, and publication |
| React Native SDK | Successor commit `39fd86ef1f6f973953e4fd5d0057ae17cc035abb` is implemented, source/check gates pass, and it is pinned to the exact three SDK successor commits. Its lock and changelog now satisfy the released-contract portion of stable preflight. Predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict Apple Development root/extension signing, provisioning, App Attest and Keychain entitlement, registered-device, install, and launch checks without new App Attest or App Intent execution. The physical path was not rerun at the current successor. The Release fixture has no Latchway request path and fails closed. Historical commit `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` remains the live root-app App Attest proof. | Operator-deferred physical invocation of the Debug App Intent path; protected Apple distribution and extension-matrix proof; physical Android proof; protected evidence, tags, and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests; schema 24 makes TTFT protocol-aware, schema 25 hardens ephemeral challenges and browser Origin, schema 26 records logical-request decision stages, and schema 27 supports bounded audit operations; doctor exposes redaction-safe revision, connectivity, job, replica, key-ID consistency, and capacity diagnostics, and scheduled self-tests retain the bounded `run_scheduled_self_test` job label instead of collapsing to `other` | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Release controls | A canonical five-repository manifest covers 50 environments and 90 privileged jobs; its closed schema, deterministic 271-action offline plan, reversible fail-closed quarantine, partial-apply journal, exact main/tag rulesets, and five npm trusted-publisher tuples are implemented and independently validated without live mutation. | GitHub administrator login, independent reviewer selection, manual no-admin-bypass confirmation, npm account 2FA/bootstrap, live two-stage apply, and live verify |
| Mintlify public docs | The canonical core imports exact reproducible SDK bundles; both canonical and mirrored documentation suites pass, the mirror is byte-identical, clean source conformance passes, and the synchronized content is live on Mintlify. | Seal protected production-deployment and post-deploy evidence |

## Local source evidence

- PostgreSQL-backed unit, integration, migration, authorization, replay,
  refresh, revocation, and direct-component-attestation vertical tests.
- The schema-28 contract/source checkpoint and current candidate descendant passed the complete PostgreSQL-backed
  Go suite. Its quota integration cases prove two charged physical dispatches,
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
  released successor `39fd86ef1f6f973953e4fd5d0057ae17cc035abb` includes the
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
- An exact MacPaw/OpenAI 0.5.1 upstream patch adding ordered asynchronous
  request interception passed all 217 upstream tests. The published 0.5.1
  package remains unsupported until an equivalent seam is accepted and
  released upstream.
- Koog 1.1.1 passed six exact integration cases through the Android OkHttp seam
  on OkHttp/okhttp-sse 5.3.0; its four non-streaming cases pass on 4.9.2, while
  its upstream SSE implementation links an OkHttp 5-only method.
- Mintlify structure, build, links/anchors/redirects/snippets, accessibility,
  and Vale MDX prose validation.
- Current `make check` passes all Go tests and vet, 390 script tests, 167
  Console Vitest tests, the production Console build, and 34 Playwright tests;
  one live-stack Playwright case remains explicitly opt-in and skipped.
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
passing clean-tree cross-repository source gate binds core contract checkpoint
`437708fb56d45196720b5769f2f59b0ee51f521d`, bundle SHA-256
`14cd2d8ddc8c4b85b8ab002359b373772d599a4eaaa8e95b9b0b793c684215c6`,
JavaScript `01dfa223773c20fe3a31559116f16e31f757b94a`, iOS
`c0fac916836bcfbdbf7f6a81808036726589d563`, Android
`3e0a601fad28a5ccf6674472a473c4797a7b404d`, React Native
`39fd86ef1f6f973953e4fd5d0057ae17cc035abb`, and the generated Mintlify
mirror. All four imported SDK documentation bundles record those source coordinates and
`source_tree_clean: true`. React Native predecessor
`4264b47e270f5e9c05938d8108eacb79c7bf4e99` passed strict development signing,
entitlement, embedded-extension, registered-iPad, install, and launch
verification. Current `39fd86ef1f6f973953e4fd5d0057ae17cc035abb` was not
physically rerun. No successor collected new App Attest evidence or invoked the
Debug App Intent, so the earlier live root-app
observation remains bound to predecessor
`6de46e1c7264e1d45cdd31174e4ea040a8c24acf`. Source-branch synchronization is
complete and tracked separately as a delivery operation. None of these results
substitutes for a protected external domain.

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
histories and separately requested GHCR and npm publication work. Reviewed
histories are now delivered to `main`. Namespace bootstrap or explicitly
non-stable preview artifacts do not authorize a stable tag, version 1 GitHub
release, release-qualified production documentation receipt, or protected
promotion.

## Release decision

The repositories are locally source-converged but are not ready for release
promotion. Source delivery is complete. Tagging, production promotion,
package/container publication, release-qualified documentation evidence, and a
production-readiness claim remain blocked until the protected finalizer binds
every required receipt to one immutable set of core, SDK, image, contract,
package, and documentation coordinates.
