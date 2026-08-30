# Implementation status

Status date: 2026-08-31

Latchway version 1 is implemented as a locally validated source candidate. It
is locally source-converged but not yet released or production-proven.
Protected hardware, live-provider, cloud, resilience, supply-chain,
publication, and post-publication domains remain open.

## Required execution checkpoint

| Required field | Current value |
| --- | --- |
| Current phase | Phase 9: final source reconvergence and authorized public-branch handoff in progress |
| Current objective | Commit the final implementation ledger, pass the five-repository source-conformance gate plus the separate documentation-mirror gate, and push `codex/v1-implementation` without merging, tagging, publishing, or deploying |
| Last passing commit in each repository | Exact coordinates are listed below |
| Protocol contract version | Draft `1.0.0`; wire protocol `2`; contract freeze `a62b0f6aa2328604101c1073c56f5ecb3bed3618` |
| Database schema version | `23` |
| Last full test time | `2026-08-30T20:22:34Z` — the repository and platform test matrix completed through the final React Native tree; the clean current-coordinate source/docs aggregate rerun remains pending |
| Passing test commands | Exact commands are listed below |
| Open blockers | Before push: the final ledger commit, clean source/docs gates, and clean worktrees; before release: physical iOS/Android, Turnstile, immutable-image provider/cloud/resilience, supply-chain, independent-review, publication, and post-publication receipts |
| External credentials still required | Known missing: an authorized Apple code-signing certificate/private-key identity and protected collector/finalizer identity/lease. Later gates also require verified Play signing/console, Turnstile, cloud, registry, KMS/signing, reviewer, and package-publisher identities |
| Next executable task | Commit this exact-coordinate ledger, run clean source/docs conformance, and push the six authorized branches |

### Last passing commit in each repository

| Repository | Passing source coordinate |
| --- | --- |
| Core `latchway` | `cc5b4c520c40f4e97a7676a37b3eca054e7b7711` |
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
mise exec -- pnpm check

# Swift SDK package/release/consumer/CocoaPods gate
scripts/verify-package.sh
tuist generate --path Examples/AppAttestConformance --no-open
xcodebuild -project Examples/AppAttestConformance/AppAttestConformance.xcodeproj \
  -scheme AppAttestConformance -configuration Release \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
tuist generate --path Examples/AppExtensionComponents --no-open
xcodebuild -project Examples/AppExtensionComponents/AppExtensionComponents.xcodeproj \
  -scheme AppExtensionComponents -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build

# Android SDK
ANDROID_HOME=<android-sdk> ./gradlew test assemble lint

# React Native SDK, release evidence, and physical-workflow invariants
mise exec -- pnpm check
python3 scripts/test-physical-candidate-producer.py
python3 scripts/test-physical-evidence-workflow.py
python3 scripts/test-physical-example-host.py

# Clean local source convergence
python3 scripts/cross-repo-conformance.py --scope source \
  --workspace-root <workspace-root> --output <report.json> \
  --junit-output <report.xml>
```

## Candidate snapshot

| Field | Current value |
| --- | --- |
| Core branch | `codex/v1-implementation` |
| Contract | `1.0.0` draft, `released_at: null` |
| Contract freeze | Core checkpoint `a62b0f6aa2328604101c1073c56f5ecb3bed3618` |
| Bundle SHA-256 | `36aa3c4786e60f2cdbbc3d0cd2f65bffe894a099479517b2e1faa01361c74b00` |
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
| Native/Web trust verifiers and component proof | Complete in source; a browser-minted Firebase App Check token passes the current source gateway, while iOS extensions remain delegated-only because Apple rejects App Attest key generation there | Root-app physical App Attest, Play Integrity, protected immutable-candidate App Check rerun, and Turnstile evidence |
| Swift, Android, JavaScript SDKs | Implemented and locked to the frozen contract | Physical proof where applicable and publication |
| React Native SDK | Implemented and pinned to the exact three native/source commits | Physical iOS/Android proof and publication |
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
- Actionlint across all workflows, deterministic contract regeneration, and a
  binary `govulncheck` result with no called vulnerabilities.
- Mintlify structure, build, links/anchors/redirects/snippets, accessibility,
  and Vale MDX prose validation.

These are source-development results, not protected release receipts. The
current clean-tree cross-repository source gate is being rerun for core
`cc5b4c520c40f4e97a7676a37b3eca054e7b7711`, JavaScript
`87a46eab3853633e23a65525e451f1bdaf3ee0c3`, iOS
`94deb8cf33371a6943809dc12e19c936aba516ce`, Android
`61d3292dd04c1d303bba6b3c4bf2f2de917efdbe`, and React Native
`4b28c9e0e56462ae3e15dd897bdffd0f79025cbb`. Even a passing source gate does
not substitute for any protected external domain.

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

## External-required gates

These are the only remaining non-repository domains after clean source
convergence:

1. protected physical iOS and React Native iOS root-application App Attest plus
   delegated Widget/Share/Action isolation, including component-owned
   identity/key/session, sibling denial, no-host, background, termination, and
   no-user-presence behavior, plus App Intents signed-binary and entitlement
   isolation while its non-executing fixture remains fail-closed;
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

An iPhone is connected. The current Xcode-managed `dev.latchway` development
profile includes that device and its App Attest entitlement lists both
`development` and `production`, but the host Keychain contains zero valid
code-signing identities. No protected, candidate-bound physical-device receipt
has been accepted by the release finalizer. Connectivity and profile
registration alone cannot prove signing, App Attest, Play Integrity, component
isolation, or lifecycle behavior. Play Integrity additionally requires a
Play-distributed signed application and is intentionally deferred until an
Android device is available.

## Release decision

The user explicitly authorized pushing the audited source histories to the six
public implementation branches. That authorization does not include merging,
tagging, production promotion, package/container publication, or a
production-readiness claim. Those actions remain blocked until the protected
finalizer binds every required receipt to one immutable set of core, SDK,
image, contract, package, and documentation coordinates.
