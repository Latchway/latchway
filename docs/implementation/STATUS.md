# Implementation status

Status date: 2026-09-01

Latchway version 1 is implemented as a locally validated source candidate. It
is locally source-converged and has supplemental development-signed physical
iOS root-application evidence, but it is not released or production-proven.
Protected distribution, Android hardware, physical execution of the current
Debug App Intent path, the broader extension runtime matrix, live-provider
exact-image, cloud, resilience, supply-chain, publication, and post-publication
domains remain open.

## Required execution checkpoint

| Required field | Current value |
| --- | --- |
| Current phase | Phase 9: source-converged candidate with supplemental physical iOS development evidence |
| Current objective | Close protected immutable-candidate release evidence without claiming, tagging, publishing, or deploying version 1 early |
| Validated implementation coordinates | Exact source and documentation-mirror coordinates are listed below |
| Protocol contract version | Draft `1.0.0`; wire protocol `2`; contract freeze `b07a4762f08e6b68d5829cda500bae9d79e5f16c` |
| Database schema version | `25` in the current working source; the recorded clean source coordinate was schema `24` |
| Last full test time | `2026-09-01` — the final contract/SDK tuple passes clean cross-repository source conformance, the React Native full check and GitHub policy check pass, four byte-reproducible clean SDK documentation bundles are imported at the exact recorded commits, and both the canonical and synchronized Mintlify suites pass |
| Passing test commands | Verified commands and required working directories are listed below |
| Open blockers | Before release: an Apple Distribution/ad hoc/TestFlight/App Store protected immutable candidate, physical invocation of the current Debug App Intent path, the protected delegated-extension runtime matrix, physical Android/Play proof, Turnstile, immutable-image provider/cloud/resilience, supply-chain, independent-review, publication, and post-publication receipts |
| External credentials still required | Known missing: Apple release-distribution signing and protected collector/finalizer authority. Later gates also require verified Play signing/console, Turnstile, cloud, registry, KMS/signing, reviewer, and package-publisher identities |
| Next executable task | Reconnect the provisioned iPad and invoke the exact current Debug App Intent path, then produce a protected Apple distribution-derived immutable candidate and run the remaining Android, extension, web, cloud, resilience, supply-chain, and publication gates |

### Validated implementation coordinates

| Repository | Validated coordinate or state |
| --- | --- |
| Core contract freeze checkpoint `latchway` | `b07a4762f08e6b68d5829cda500bae9d79e5f16c` |
| Core final SDK-bundle and canonical-doc checkpoint `latchway` | `18be09e7b1e053f969f03e289c461ef1f294ee6a` |
| JavaScript `latchway-js` | `379a6d20bed9cbda9af6210f5511250fbbe9b571` |
| Swift `latchway-ios-sdk` | `ab38ae00838a81be071f53740c624dc4f0558dcb` |
| Android `latchway-android` | `17c108706998f2c30fe511fd92ed049c024c8e85` |
| React Native `latchway-react-native-sdk` | `af3860cbf39ab6a8d1d76da392cb699b9e019e42` |
| Mintlify mirror `latchway-docs` | `a0c3559b11353a8196bde800d4b7484726e9f76a` |

### Passing test commands

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

## Candidate snapshot

| Field | Current value |
| --- | --- |
| Core branch | `codex/v1-implementation` |
| Contract | `1.0.0` draft, `released_at: null` |
| Contract freeze | Core checkpoint `b07a4762f08e6b68d5829cda500bae9d79e5f16c` |
| Bundle SHA-256 | `397a3920aaa2ed0438a96156cd8a51f0fa85ac2e3fb9266b4fe79618812a3d9a` |
| Wire | Current `2`; discovery supports `[1, 2]` |
| Database | Current working source schema `25`; recorded clean checkpoint schema `24` |
| Package/server range | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| Release state | `unreleased`; no tag or package publication authorized |

The historical `0.5.1`/wire-1 coordinate remains unchanged. Intermediate draft
bundle hashes are not release coordinates. All four current SDK locks name the
checkpoint and reproducible draft bundle above.

## Workstream status

| Workstream | Local source status | Remaining boundary |
| --- | --- | --- |
| Family/component contract and migrations | Implemented through schema 25; exact challenge Origin and authoritative root-definition selection are hardened without changing the frozen API/configuration contract | Refresh the clean core checkpoint and protected exact-candidate evidence |
| Server trust/session/revocation/policy/quota runtime | Complete in source, including a generic component App Attest step-up protocol | Exact-candidate rerun and protected observations |
| Responses, Chat, Embeddings, Anthropic, opaque protocols | Complete; opaque HTTP now has pairwise-disjoint exact-depth path templates while retaining the prior segment-bound `pathPrefixes` mode for existing v1 revisions; bounded OpenRouter verification passed against the current source gateway | Immutable-image provider rerun |
| Weighted/sticky routing, fallback, retry, accounting | Complete | Exact-image load/failure evidence |
| Admin API, CLI, dashboard, wizard, request/usage/audit views | Complete, including the exact `latchway test-upstream serve` fixture command and separate first-byte/first-token request timestamps | Deployment operator acceptance |
| Native/Web trust verifiers and component proof | Complete in source; a historical development-signed physical React Native iOS root run passed production App Attest registration and same-key assertion, the current source adds a Debug-only native App Intent delegated-request path, and a browser-minted Firebase App Check token passes the current source gateway | Apple distribution-derived protected candidate, physical invocation of the current Debug App Intent path, protected extension matrix, physical Play Integrity, protected immutable-candidate App Check rerun, and Turnstile evidence |
| Swift, Android, JavaScript SDKs | Implemented and locked to the frozen contract | Physical proof where applicable and publication |
| React Native SDK | Commit `af3860cbf39ab6a8d1d76da392cb699b9e019e42` is implemented, fully checked, and pinned to the exact three native/source commits. It adds root-owned component descriptor lifecycle plus a Debug-only native App Intent delegated request with exact-run challenge/receipt binding; the Release fixture has no Latchway request path and fails closed. Historical commit `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` remains the physical root-app proof. | Physical invocation of the current Debug App Intent path, protected Apple distribution and extension-matrix proof, physical Android proof, and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests; schema 24 makes TTFT protocol-aware, while schema 25 invalidates unverifiable ephemeral challenges and persists exact browser Origin for new ones | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Mintlify public docs | The canonical source, exact SDK bundles, and synchronized mirror commit `a0c3559b11353a8196bde800d4b7484726e9f76a` pass the complete local suite | Merge and production deploy/post-deploy validation |

## Local source evidence

- PostgreSQL-backed unit, integration, migration, authorization, replay,
  refresh, revocation, and direct-component-attestation vertical tests.
- Contract/schema/error/vector determinism and the complete Python release,
  workflow, evidence, and validation suites.
- Dashboard lint, TypeScript checking, unit tests, deterministic builds,
  Playwright, and a real PostgreSQL-backed first-run browser flow.
- Cloudflare unit/build checks and deployment dry-run; Compose, Cloud Run, and
  AWS Terraform static validation.
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
- Actionlint across all workflows, deterministic contract regeneration, and a
  binary `govulncheck` result with no called vulnerabilities.
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

These are source-development results, not protected release receipts. The
clean-tree cross-repository source gate passed for core bundle-import checkpoint
`4a39adfef2207aac05d09fae4bfaf36c1381ab5c`, JavaScript
`379a6d20bed9cbda9af6210f5511250fbbe9b571`, iOS
`ab38ae00838a81be071f53740c624dc4f0558dcb`, Android
`17c108706998f2c30fe511fd92ed049c024c8e85`, and React Native
`af3860cbf39ab6a8d1d76da392cb699b9e019e42`. The physical iPad root-app
observation remains bound to predecessor
`6de46e1c7264e1d45cdd31174e4ea040a8c24acf`. The current React Native source
materially adds component lifecycle and the Debug native App Intent request
path; its full local check plus generic iOS and isolated Debug/Release App
Intent build gates pass, but the App Intent has not yet been physically
invoked. All four clean SDK documentation bundles record the current source
coordinates and `source_tree_clean: true`. The final authored public docs are
synchronized to mirror commit
`a0c3559b11353a8196bde800d4b7484726e9f76a`, whose complete Mintlify suite
passed. These results do not substitute for any protected external domain.

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

These are the only remaining non-repository domains after clean source
convergence:

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

## Release decision

The user explicitly authorized pushing the audited source histories to the six
public implementation branches. That authorization does not include merging,
tagging, production promotion, package/container publication, or a
production-readiness claim. Those actions remain blocked until the protected
finalizer binds every required receipt to one immutable set of core, SDK,
image, contract, package, and documentation coordinates.
