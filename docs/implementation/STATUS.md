# Implementation status

Status date: 2026-08-31

Latchway version 1 is implemented as a locally validated source candidate. It
is locally source-converged and now has supplemental development-signed
physical iOS evidence, but it is not released or production-proven. Protected
distribution, Android hardware, extension runtime, live-provider exact-image,
cloud, resilience, supply-chain, publication, and post-publication domains
remain open.

## Required execution checkpoint

| Required field | Current value |
| --- | --- |
| Current phase | Phase 9: source-converged candidate with supplemental physical iOS development evidence |
| Current objective | Close protected immutable-candidate release evidence without claiming, tagging, publishing, or deploying version 1 early |
| Last passing commit in each repository | Exact coordinates are listed below |
| Protocol contract version | Draft `1.0.0`; wire protocol `2`; contract freeze `a62b0f6aa2328604101c1073c56f5ecb3bed3618` |
| Database schema version | `23` |
| Last full test time | `2026-08-31` — canonical public docs, generated compatibility data, synchronized mirror docs, and documentation conformance passed after recording the physical iOS observation; the prior full source gate remains recorded below |
| Passing test commands | Verified commands and required working directories are listed below |
| Open blockers | Before release: an Apple Distribution/ad hoc/TestFlight/App Store protected immutable candidate, physical Android/Play proof, delegated-extension runtime proof, Turnstile, immutable-image provider/cloud/resilience, supply-chain, independent-review, publication, and post-publication receipts |
| External credentials still required | Known missing: Apple release-distribution signing and protected collector/finalizer authority. Later gates also require verified Play signing/console, Turnstile, cloud, registry, KMS/signing, reviewer, and package-publisher identities |
| Next executable task | Produce and finalize a protected Apple distribution-derived immutable candidate, then run the remaining Android, extension, web, cloud, resilience, supply-chain, and publication gates |

### Last passing commit in each repository

| Repository | Passing source coordinate |
| --- | --- |
| Core `latchway` | `a9d8bd4b758427c7f8e046efc76e10f7c899f405` |
| JavaScript `latchway-js` | `87a46eab3853633e23a65525e451f1bdaf3ee0c3` |
| Swift `latchway-ios-sdk` | `94deb8cf33371a6943809dc12e19c936aba516ce` |
| Android `latchway-android` | `61d3292dd04c1d303bba6b3c4bf2f2de917efdbe` |
| React Native `latchway-react-native-sdk` | `4b28c9e0e56462ae3e15dd897bdffd0f79025cbb` |
| Mintlify mirror `latchway-docs` | `b4f72208c7f50fb715a512d4b81bea16fb88345e` |

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
| Contract freeze | Core checkpoint `a62b0f6aa2328604101c1073c56f5ecb3bed3618` |
| Bundle SHA-256 | `ad7afe992181553996eba39e44d4aeb498e8159e2b52671756b5c93ab68eb765` |
| Wire | Current `2`; discovery supports `[1, 2]` |
| Database | Schema `23` |
| Package/server range | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| Release state | `unreleased`; no tag or package publication authorized |

The historical `0.5.1`/wire-1 coordinate remains unchanged. Intermediate draft
bundle hashes are not release coordinates. All four current SDK locks name the
checkpoint and reproducible draft bundle above.

## Workstream status

| Workstream | Local source status | Remaining boundary |
| --- | --- | --- |
| Family/component contract and migrations | Implemented through schema 23; bundle and locks converged | Protected exact-candidate evidence |
| Server trust/session/revocation/policy/quota runtime | Complete in source, including a generic component App Attest step-up protocol | Exact-candidate rerun and protected observations |
| Responses, Chat, Embeddings, Anthropic, opaque protocols | Complete; bounded OpenRouter verification passed against the current source gateway | Immutable-image provider rerun |
| Weighted/sticky routing, fallback, retry, accounting | Complete | Exact-image load/failure evidence |
| Admin API, CLI, dashboard, wizard, request/usage/audit views | Complete | Deployment operator acceptance |
| Native/Web trust verifiers and component proof | Complete in source; a development-signed physical React Native iOS run passed production App Attest registration and same-key assertion, and a browser-minted Firebase App Check token passes the current source gateway | Apple distribution-derived protected candidate, physical Play Integrity, delegated-extension runtime, protected immutable-candidate App Check rerun, and Turnstile evidence |
| Swift, Android, JavaScript SDKs | Implemented and locked to the frozen contract | Physical proof where applicable and publication |
| React Native SDK | Implemented and pinned to the exact three native/source commits; a physical iOS 27 Release-configuration app passed the current-source development run | Protected Apple distribution candidate, physical Android proof, extension runtime proof, and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Mintlify public docs | Canonical source and generated mirror converge and pass locally | Merge and production deploy validation |

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
- A real physical iOS 27 React Native app built in Release configuration with
  automatic Apple Development signing and bundle `dev.latchway` passed Apple
  production App Attest trust at validation category `3` and bundle version
  `1`. Registration and a later assertion reused the same App Attest key
  through a temporary ngrok tunnel, the current source gateway, and Firebase
  identity; the server persisted the assertion counter and hash. The run also
  passed Secure Enclave DPoP, upstream non-streaming and streaming requests,
  quota, the typed `403 component_feature_not_granted` path, bridge behavior,
  and cleanup. It was not a protected or distribution-signed release receipt.
- Actionlint across all workflows, deterministic contract regeneration, and a
  binary `govulncheck` result with no called vulnerabilities.
- Mintlify structure, build, links/anchors/redirects/snippets, accessibility,
  and Vale MDX prose validation.

These are source-development results, not protected release receipts. The
clean-tree cross-repository source gate passed for core
`a9d8bd4b758427c7f8e046efc76e10f7c899f405`, JavaScript
`87a46eab3853633e23a65525e451f1bdaf3ee0c3`, iOS
`94deb8cf33371a6943809dc12e19c936aba516ce`, Android
`61d3292dd04c1d303bba6b3c4bf2f2de917efdbe`, and React Native
`4b28c9e0e56462ae3e15dd897bdffd0f79025cbb`. The synchronized documentation
mirror passed its separate gate. These results do not substitute for any
protected external domain.

## Direct component attestation boundary

Schema 23 and wire 2 contain generic component-owned App Attest
challenge/exchange routes and binding version 2. If an eligible platform can
produce component-owned evidence, a delegated component can rotate only its
own DPoP-bound session while retaining delegation ancestry under
`delegated_direct_attested`. The configured component policy remains
`preferred` so it cannot qualify an initial delegated session; the explicit
step-up exchange itself requires valid App Attest evidence.

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

The canonical registry currently records six exact locally tested integrations
as `experimental`: OpenAI JavaScript 7.8.0, Vercel AI SDK 7.0.85, LangChain
OpenAI 1.5.10, SwiftOpenAI 4.6.0, OkHttp 5.3.0/4.9.2, and React Native 0.82.0.
Foundation Models remains `planned` because its runtime suite could not execute
on the available host OS. MacPaw/OpenAI 0.5.1 remains `unsupported`. No
framework is represented as released support.

The JavaScript repository now runs a protocol-valid local debug fixture through
the real pinned OpenAI, Vercel AI, and LangChain packages. Its 50 registered
framework/case combinations cover the applicable Responses, Chat, embeddings,
streaming usage, cancellation, tools, structured output, quota/provider error,
retry/refresh, credential-stripping, origin/path, redaction, and fetch-isolation
paths. This upgrades LangChain streaming and OpenAI embeddings to locally
verified capabilities, but does not satisfy hosted/exact-image, live-provider,
revocation, scheduled-run, or clean-published-consumer gates; all three rows
therefore remain `experimental`.

## External-required gates

These are the only remaining non-repository domains after clean source
convergence:

1. a protected Apple Distribution, ad hoc, TestFlight, or App Store-derived
   immutable iOS candidate that repeats root-application App Attest, plus
   delegated Widget/Share/Action execution and isolation, including
   component-owned identity/key/session, sibling denial, no-host, background,
   termination, and no-user-presence behavior, plus App Intents signed-binary
   and entitlement isolation while its non-executing fixture remains
   fail-closed;
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

The connected iPhone and Xcode-managed `dev.latchway` profile were sufficient
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
