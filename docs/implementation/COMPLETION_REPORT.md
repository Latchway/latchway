# Version 1 completion gap ledger

Status: **the version 1 implementation is source-converged at the exact
core, SDK, canonical-documentation, and Mintlify-mirror coordinates below. The
core `make check` gate and complete uncached PostgreSQL 15/18 suites pass;
JavaScript `release:check`, the Android 665-task/publication-smoke gate, React
Native `check`, and the complete Swift package/CocoaPods gate pass. The exact
successor histories are delivered to `main`, their remote heads were verified,
and clean six-repository source conformance passed. Release controls cover all
six repositories but are not applied live because no
distinct reviewer is available. npm 2FA is `auth-and-writes`, but all five npm
packages remain unpublished. App Intent/extension and physical Android/Google
Play evidence remain explicitly deferred. No candidate is tagged, published,
product-released, or production-proven**.

This checked-in file is a source-status ledger. It is not the immutable
candidate-bound completion report produced by the protected release workflow.
It must not claim tags, registry digests, package publication, production
deployments, or protected evidence that does not exist.

## Current source coordinate

| Field | Current source truth |
| --- | --- |
| Contract | Released `1.0.0`; `released_at: 2026-09-01T20:25:00Z` |
| Wire | Current `2`; discovery range `[1, 2]` |
| Database | Schema `28` at contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6`; schema `27` remains at prior checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` |
| Contract bundle | Reproducible SHA-256 `0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617` at contract/core checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Core implementation source | `cd47229eac32f4a93a0779903d927526b77817d6` |
| SDK source tuple | JavaScript `8baeffa74d0916e3b9299e3a29a6a2dccf154e41`; Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f`; Android `f847ce600f0a48859ad4cb534b95b6251c3c633e`; React Native `76fe88ce8053c6983f03422238e9da12360d435d` |
| SDK documentation bundles | JavaScript `5c5aec14d562e71842aed6912de21b451a7c70444cbbca4fa70a768066ddcdf4`; Swift `a502896f1975d8bf2524cb56e4ed5d8270c5f8862b55f568d56369aa1b74a4a4`; Android `a34faf101754c1e9c02253ca132bf21d7ad09e6eec4e57f792e0b451d8d3385b`; React Native `38470a5e38e8f7c2b86378145cbc6667c31d4764001f4931d181088a7dcbc10d` |
| Public documentation source | Canonical core docs `cd4387fa095556e044945bf6e1e3237d857d912e`; generated Mintlify mirror `f37fde259986683f4957627b24d2106b2db81c78` |
| SDK locks | All four released successor locks, four vector families, copied `protocol-version.json`, framework coordinates, final changelog headings, and reproducible documentation bundles converge on the current checkpoint. Stable preflights still require tags and protected exact-candidate evidence. |
| Public release | Source histories are delivered to `main`, but source delivery is not a release. No version 1 tag, GitHub release, npm/CocoaPods/Maven package, GHCR image, product-runtime deployment, canonical-domain routing, or protected production-docs receipt is verified. |

Historical contract `0.5.1`, wire 1, schema 20, and their SDK locks remain
immutable legacy coordinates. They are regression evidence only and cannot
authorize version 1.

## Source implementation summary

| Workstream | Implemented in local source | Remaining before release |
| --- | --- | --- |
| Contract and persistence | Family/component APIs, wire-2 claims, strict schemas/errors/vectors, migrations through schema 28, exact challenge-Origin binding, logical-request decision stages, bounded audit attribution/browse indexes, authoritative root-definition selection, retry-cost treatment, physical-attempt quota accounting, and the deterministic released contract bundle at the exact checkpoint above | Protected exact-candidate evidence |
| Trust and sessions | Identity/native/web verification, DPoP, independent component sessions, exact-tuple refresh idempotency, delegation, generic direct-component protocol support, composite provenance, scoped revocation; development-signed physical iOS registration and same-key assertion passed | Protected Apple distribution-derived and Android trust/lifecycle observations; iOS extensions remain delegated-only |
| Gateway | Trusted input-token preflight, input/total quotas, Responses, Chat, Embeddings, Anthropic, restricted opaque routes, deterministic weighted/sticky routing, fallback/retry/accounting; bounded OpenRouter plus local load/failure checks pass against the current source gateway | Protected immutable-image provider, load, and destructive-failure evidence |
| Admin/operator | The checkpoint includes the family/component Admin API, CLI, dashboard, wizard, trust graph, request/usage/audit/failure views, canonical redaction-safe doctor/support bundles, scoped actions, Admin-session inventory/revoke in API/CLI/Console, server-capability negotiation with read-only safe mode, bounded redaction-safe YAML/JSON configuration transfer with exact numeric preservation and strong-ETag activation review, and authenticated SSE refresh hints with reconnect and polling fallback. Complete local core gates pass. | Deployment operator acceptance on the final image |
| SDKs | JavaScript `8baeffa74d0916e3b9299e3a29a6a2dccf154e41` passes `release:check`; Android `f847ce600f0a48859ad4cb534b95b6251c3c633e` passes the 665-task gate and local publication smoke; React Native `76fe88ce8053c6983f03422238e9da12360d435d` passes `check`; Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` passes production/debug builds, 159 core tests, SwiftOpenAI 7/7, Foundation Models 9/9, and CocoaPods lint for all four subspecs. React Native retains its Debug-only native App Intent delegated request and fail-closed Release fixture; the current head was not physically rerun. | Operator-deferred physical invocation of the Debug App Intent/extension path; protected Apple distribution/extension-matrix proof; physical Android/Google Play proof; tags, protected evidence, and publication |
| Frameworks | Eight exact, locally tested integrations recorded as `experimental`; unsupported seams remain explicit | Hosted common conformance and release evidence before any `supported` claim |
| Operations | Telemetry, jobs, key rotation, recovery, upgrades, replicas, cloud definitions, load/failure tooling, and release workflows | Protected exact-image cloud/resilience runs |
| Supply chain | Multi-architecture build, scan, SBOM, signing, provenance, and finalizer workflows implemented and statically/dry-run checked | Registry-built artifacts, per-architecture observations, attestations, and independent review |
| Documentation | Canonical commit `cd4387fa095556e044945bf6e1e3237d857d912e` imports all four exact SDK bundles and synchronizes mirror commit `f37fde259986683f4957627b24d2106b2db81c78`; canonical and mirror validation, clean source conformance, and audited source delivery are complete | Route `docs.latchway.dev`, then collect protected production-deployment and post-deploy receipts |
| Release controls and npm | Desired state covers six repositories and 51 environments. Docs alone requires CODEOWNERS review, one approval, and a written docs-not-required check. npm 2FA is `auth-and-writes`. | Add a distinct reviewer, apply/verify the live controls, bootstrap the five unpublished package coordinates, and install exact trusted publishers |

## Schema-23 direct component App Attest step-up

The wire and server can issue a one-use version-2 attestation binding, verify
component-owned App Attest evidence, and rotate only that component's
DPoP-bound session. Successful verification produces composite
`delegated_direct_attested` trust while retaining the parent component,
delegation, component definition, family, provider, bundle, component key, and
JWK-thumbprint bindings. Component/family/install revocation and component
replacement revoke linked App Attest state.

Schema 25 invalidates only preexisting ephemeral session challenges, which
cannot be assigned a trustworthy historical browser Origin. New challenges
persist the exact canonical web Origin (or empty native Origin), and exchange
requires equality before attestation or token issuance. Root-family creation
uses the required attestation selection's exact App Attest bundle, Play package,
or persisted web Origin; platform-only selection is forbidden. Multiple root
definitions are valid only when disjoint, directly attested web-origin sets
partition every allowed Origin exactly once. The frozen schema still reserves root `identity_only`, but semantic
and compiled-snapshot validation reject activating it in version 1.

The referenced component-only App Attest policy must be configured in
`preferred` mode, require at least `app_verified`, and pin the exact component
bundle. This prevents that policy from qualifying the initial delegated
session; the explicit step-up exchange still requires direct proof. Wrong DPoP,
provider, bundle, key, family, parent, expired/revoked state, and challenge
replay fail closed. Retry recovery is limited to the exact assertion after a
transactional session failure, preserving App Attest counter semantics.

Apple's App Attest runtime rejects key generation from iOS app extensions.
Therefore the Swift and React Native iOS source surfaces do not expose direct
Action/SSO proof: the root application attests only itself, while Widget,
Share, Action, and SSO extensions retain explicit delegated provenance and
isolated keys/sessions. The server contract can model an eligible watchOS
component, but the current Swift package does not claim watch direct-step-up
support. Android direct component step-up is also unsupported in version 1.

## Local evidence boundary

Development runs cover PostgreSQL migrations and verticals, authorization,
replay, refresh/revocation, component attestation, policy/quota behavior,
protocol/routing behavior, SDK unit and native consumer builds, dashboard and
browser flows, deterministic contract/docs builds, workflow validation, and
static/dry-run deployment and supply-chain checks. The disposable loopback
Console preview was upgraded to local image `latchway:local-5dd351f-arm64`;
the binary reports core `5dd351fdc7e20d24d4ccdfcf96bf7b9e8623901d`, runs as
UID/GID `65532:65532` with a read-only root filesystem and hardened runtime
flags, and returns `200` for readiness, Console HTML, and its rotated owner
login. This is not a registry or protected deployment receipt. A real browser-minted
Firebase App Check token from an allowed localhost origin passes the current
source gateway, including the multi-audience token shape emitted by Firebase.
The arbitrary ngrok hostname was not claimed as passing, and this observation
is not protected immutable-candidate evidence.

A final real-device development run used React Native commit
`6de46e1c7264e1d45cdd31174e4ea040a8c24acf` in Debug configuration on an
iPad running iPadOS 26.5, with automatic Apple Development signing and bundle
`dev.latchway`. Apple production App Attest was accepted as `app_verified`;
Firebase identity, the native DPoP path, signed root/App Intents entitlement
isolation, a real OpenRouter Responses request to `openai/gpt-5-mini`, reported
input/output/total usage, production quota settlement, and terminal session and
installation revocation all passed. This is development-signed physical
evidence, not a protected immutable-candidate or distribution receipt.

React Native predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99`
materially extended that historical proof source with root-owned descriptor
lifecycle and a Debug App Intent that uses the native extension client for an
independently keyed delegated request with exact-run challenge/receipt binding.
Its Apple Development build passed strict root/extension signing, provisioning,
App Attest and Keychain entitlement, team, registered-device, install, and
launch checks. It did not collect new App Attest proof or invoke the App Intent.
Current successor `76fe88ce8053c6983f03422238e9da12360d435d` is a descendant
that adds release retry-closure, transition-order, wording,
development-runner hardening, and the released-contract/source-tuple lock. It
passes the full local plus generic iOS and isolated Debug/Release App Intent
build gates; the physical path was not rerun at that head. The Release target
deliberately contains no executable Latchway request path.

The Swift package gate at
`ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` also passed production and debug
builds, 159 core tests, SwiftOpenAI 7/7, Foundation Models 9/9, and CocoaPods
lint for AppAttest, AppExtensions, Core, and FirebaseAuth. The minimal pinned
MacPaw/OpenAI 0.5.1 upstream contribution propagates the injected
`URLSession.configuration` into internal stream sessions, enabling a custom
`URLProtocol` to own buffered and streaming Chat Completions/Responses
dispatch. Its patched checkout passed 187 XCTest plus 26 Swift Testing cases
(213/213), and the positive probe proved transport ownership and active-stream
cancellation through `URLProtocol.stopLoading`. Stock 0.5.1 remains
unsupported because that seam is not released upstream.

Those results establish implementation confidence; they are not release
receipts. The current convergence run:

- regenerated the contract bundle twice with identical bytes and recorded its
  final checksum;
- synchronized the current API/configuration contract, component-attestation schema/vector,
  protocol coordinate, and bundle lock across all SDK repositories;
- ran the clean-tree core, SDK, dashboard, documentation, workflow, and
  cross-repository conformance gate on the exact commits; and
- created canonical documentation commit
  `cd4387fa095556e044945bf6e1e3237d857d912e` and synchronized Mintlify mirror
  commit `f37fde259986683f4957627b24d2106b2db81c78` without creating a tag or
  package release; and
- delivered the exact successor histories to `main`, verified all six intended
  remote heads, and passed fresh clean six-repository source conformance.

Core `cd47229eac32f4a93a0779903d927526b77817d6` passes the full current
`make check`, including generated-source checks, all Go tests and vet, the
complete Python release/tool suite, Console lint/typecheck/tests, the
production Console build, and Playwright with its live-stack case explicitly
opt-in and skipped. `make test-race`, the bounded fuzz corpus, and real
PostgreSQL Admin/session/App Attest/configuration/lifecycle lock-order suites
also pass. Independent review closed
root-challenge and App Attest post-disable insertion races, configuration and
family/component lock-order deadlocks, exact JSON/YAML numeric preservation,
and explicit `READ COMMITTED` lifecycle behavior. Complete uncached PostgreSQL
15 and PostgreSQL 18 `go test -count=1 ./...` suites also pass at that exact
checkpoint. Fresh clean source conformance passed after source-branch
synchronization. That synchronization is a delivery operation and is not
release evidence.

Credential-free deployment validation also passes 9/9 static checks for the
Compose, Cloud Run, AWS, Fly, and Cloudflare definitions; the Wrangler path
completes with `--dry-run` and no account credentials. At implementation
checkpoint `77069816dd68174052e7ebc163911883f8f07e7e`, the clean local load
suite passes every latency, throughput, streaming, memory, and contention
target, and all nine automated failure scenarios pass under the race detector.
A clean archive of that same checkpoint passes container smoke, strict non-root
runtime inspection, and OCI `linux/amd64` plus `linux/arm64` platform/runtime
verification. Pinned binary `govulncheck` reports zero called vulnerabilities.
These results neither publish nor sign an image and are not protected
exact-image, destructive-drill, registry, SBOM, provenance, deployment, or
independent-review evidence.

## External-required completion evidence

One immutable candidate still requires all of the following:

1. a protected Apple Distribution, ad hoc, TestFlight, or App Store-derived
   immutable iOS candidate that repeats root-app App Attest, plus delegated
   Widget/Share/Action execution and isolation, with candidate-bound
   identities, independent keys/sessions, sibling denial, no-host, background,
   termination, and no-user-presence behavior. The current React Native Debug
   App Intent must execute its native delegated request on-device; the Release
   fixture must retain no Latchway dependency or executable request path and
   remain fail-closed;
2. Play-distributed Play Integrity and physical React Native Android flows, a
   protected immutable-candidate rerun of the already-passing Firebase App
   Check flow, and a configured Turnstile observation;
3. all SDKs and every advertised framework/version bound against the exact
   release image;
4. immutable-image live-provider streaming/non-streaming, usage, error, clamp,
   cancellation, fallback, and retry behavior; the equivalent bounded
   OpenRouter checks pass against the current source gateway;
5. every claimed cloud deployment and protected multi-replica, load,
   destructive failure, backup/restore, upgrade/rollback, key-rotation, and
   worker-recovery drill;
6. per-architecture vulnerability and license scans, SBOMs, signatures,
   provenance, and candidate-bound independent security review;
7. signed tags and releases, OCI/npm/Swift/CocoaPods/Maven publication, byte
   verification, and clean post-publication consumers; and
8. a protected Mintlify deployment receipt followed by candidate-bound link,
   accessibility, redirect, source-checkpoint, and AI-readable-output
   validation. A prior Mintlify preview exists, but final mirror
   `f37fde259986683f4957627b24d2106b2db81c78` is not claimed as a protected
   production deployment and `docs.latchway.dev` is not routed.

The connected iPad and Xcode-managed `dev.latchway` profile supported automatic
Apple Development signing for predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99`.
That predecessor passed strict signed root/extension verification, installation,
and launch; the earlier `6de46e1c7264e1d45cdd31174e4ea040a8c24acf`
root-app observation remains the only live App Attest/provider proof. The
physical path was not rerun for current `76fe88ce8053c6983f03422238e9da12360d435d`.
No physical result closes the release gate until the protected collector and
finalizer bind an Apple distribution-derived candidate to the exact repository,
contract, application identity, signing, entitlement, package, and image
coordinates. Neither the recorded root-app observation nor the current local
launch executed the delegated extension, so the Debug App Intent still
requires physical invocation.
Play Integrity additionally requires a Play-distributed signed application.
The operator has deferred App Intent and physical Android/Google Play evidence
for later submission. The CocoaPods lint passed
with the beta Xcode toolchain; the stable Xcode installation on this host lacks
the required platform component and cannot independently run that lint.

## Completion decision

Offline/local device build, install, and launch may proceed if it does not
contact ngrok or a live provider and does not collect Apple App Attest evidence.
Starting or reusing ngrok, contacting a provider for device proof, collecting
live App Attest evidence, or producing a protected device receipt requires the
exact phrase `I authorize the scoped ngrok device proof.` The phrase was
supplied for a scoped run, but no tunnel, service, provider, App Attest, or
protected-device evidence was started or collected under it. The historical
App Attest and predecessor signed-launch observations remain separately bound
to their stated commits.

The user authorized a scoped non-force push of the six audited source-branch
histories and separately requested GHCR and npm publication work. npm account
2FA is now `auth-and-writes`, but the five package coordinates remain
unpublished. The six-repository GitHub desired state is not live because a
distinct reviewer is unavailable. That authorization permits reviewed
namespace bootstrap or explicitly non-stable preview artifacts; it does not
make the source-delivered released-contract successor tuple eligible for a stable
version 1 tag, protected promotion, release-qualified production
documentation, or a production-readiness claim.
Only the protected finalizer may produce the
immutable completion report after every required domain closes without skips,
stale evidence, or coordinate drift.
