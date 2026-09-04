# Version 1 completion gap ledger

Status: **the version 1 product implementation and four SDKs are converged at
the exact source coordinates below. Canonical public documentation is this
checked-in source tree, and the generated mirror is required to bind that tree
through `.latchway-docs-source.json`. The
core `make check` gate and complete uncached PostgreSQL 15/18 suites pass;
JavaScript `release:check`, the Android 665-actionable-task/publication-smoke gate, React
Native `check`, and the complete Swift package/CocoaPods gate pass. The exact
core and SDK successor histories are delivered to `main` and their remote
heads were verified. Strict release controls cover all six repositories, and
the explicit `single_maintainer_v1` profile permits a lower-assurance launch
without an independent reviewer while keeping deferred controls `unverified`.
Its 13 exact environments and non-secret policy sentinels are applied live;
strict-profile rulesets are not. npm 2FA is `auth-and-writes`; all five inert
namespace records and their exact tokenless trusted publishers are configured,
but every stable `1.0.0` package remains unpublished. App Intent/extension,
Apple distribution, and physical Android/Google Play evidence remain explicitly
deferred. No candidate is tagged, published, product-released, or
production-proven**.

This ledger distinguishes two decisions. The authorized
`single_maintainer_v1` first-publication profile requires GHCR and package
publication, supply-chain receipts, and exact-image Docker Compose plus Google
Cloud Run evidence. It intentionally leaves independent review,
Apple/Android/browser/provider evidence, AWS, Fly.io, Cloudflare Containers,
operational-resilience drills, and Mintlify production `unverified`. The
original A-to-Z Definition of Done still requires those domains. Therefore a
passing selected profile may authorize lower-assurance public artifacts, but
it cannot close this strict completion ledger or support production-ready,
fully-evidence-gated, independently reviewed, or `release-qualified` wording.

This checked-in file is a source-status ledger. It is not the immutable
candidate-bound completion report produced by the protected release workflow.
It must not claim tags, registry digests, package publication, production
deployments, or protected evidence that does not exist.

## Current source coordinate

| Field | Current source truth |
| --- | --- |
| Contract | Released `1.0.0`; `released_at: 2026-09-01T20:25:00Z` |
| Wire | Current `2`; discovery range `[1, 2]` |
| Database | Current runtime source includes schema `29`, a terminal-validator function-body replacement; the frozen contract/source checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` remains schema `28`; schema `27` remains at prior checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` |
| Contract bundle | Reproducible SHA-256 `0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617` at contract/core checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Core implementation source | `8bf4d9dede1490c3129f7f745f1017875bd4a005`, a contract-preserving descendant of the frozen contract checkpoint |
| Current release-candidate worktree | Uncommitted pool-remediation, Console, deployment-evidence, and finalizer successor based on `86dae658676e7187a8db6a0deda3f8429ca6ab76`; it is not yet a release coordinate. Protected run `33755044849`, attempt `1`, passed verification at that base commit and failed the unchanged isolated load gate before image construction. |
| SDK source tuple | JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7`; Swift `92a394acbc00d1af6d258372f22b11ddae8e1750`; Android `694cb4d2bff9e91582896e3cbbe140e960d9e4e4`; React Native `ba23c750ec662834b4d480940c4067508723defb` |
| SDK documentation bundles | JavaScript `f4e814289055bad88d508dde862ebdbd105b03483db807c2f128b0681da07711`; Swift `c0cdad255cde507faaad173f9a2dba05a29e6be53130f07a25c2e4e831498f00`; Android `1a13c6834b960dbfc7fb91c390167624eadbf5f6e8d12325bd82423cc4f4a7f7`; React Native `db7c9a569a86ec2f88750de80a1bc2f44dceb0c6db2d9f1613a309dcbbed37a2` |
| Public documentation source | This checked-in canonical tree imports the final bundles based on core implementation `8bf4d9dede1490c3129f7f745f1017875bd4a005`; the generated mirror must bind its exact source through `.latchway-docs-source.json` |
| SDK locks | All four released successor locks, four vector families, copied `protocol-version.json`, framework coordinates, final changelog headings, and reproducible documentation bundles converge on the current checkpoint. Stable preflights still require tags and protected exact-candidate evidence. |
| Public release | Core and all four SDK source heads are delivered to `main`, but source delivery is not a release. No version 1 tag, GitHub release, npm/CocoaPods/Maven package, GHCR image, product-runtime deployment, canonical-domain routing, or protected production-docs receipt is verified. |

Historical contract `0.5.1`, wire 1, schema 20, and their SDK locks remain
immutable legacy coordinates. They are regression evidence only and cannot
authorize version 1.

## Source implementation summary

| Workstream | Implemented in local source | Remaining before release |
| --- | --- | --- |
| Contract and persistence | Family/component APIs, wire-2 claims, strict schemas/errors/vectors, migrations through schema 29 with consolidated terminal-validation reads, exact challenge-Origin binding, logical-request decision stages, bounded audit attribution/browse indexes, authoritative root-definition selection, retry-cost treatment, physical-attempt quota accounting, and the deterministic released contract bundle at the exact checkpoint above | Protected exact-candidate evidence |
| Trust and sessions | Identity/native/web verification, DPoP, independent component sessions, exact-tuple refresh idempotency, delegation, generic direct-component protocol support, composite provenance, scoped revocation; development-signed physical iOS registration and same-key assertion passed | Protected Apple distribution-derived and Android trust/lifecycle observations; iOS extensions remain delegated-only |
| Gateway | Trusted input-token preflight, input/total quotas, Responses, Chat, Embeddings, Anthropic, restricted opaque routes, deterministic weighted/sticky routing, fallback/retry/accounting; bounded OpenRouter plus local load/failure checks pass against the current source gateway | Protected immutable-image provider, load, and destructive-failure evidence |
| Admin/operator | The checkpoint includes the family/component Admin API, CLI, dashboard, wizard, trust graph, request/usage/audit/failure views, canonical redaction-safe doctor/support bundles, scoped actions, Admin-session inventory/revoke in API/CLI/Console, server-capability negotiation with read-only safe mode, bounded redaction-safe YAML/JSON configuration transfer with exact numeric preservation and strong-ETag activation review, and authenticated SSE refresh hints with reconnect and polling fallback. The successor adds the strict seven-check readiness CLI plus fail-closed first-run template resumption, active-revision/self-test endpoint binding, revision-drift checks, `manage_secrets` capability gates, platform-specific native examples, and application/environment task-state isolation. Console ESLint, both TypeScript checks, 292/292 unit tests, and 37 browser cases across Chromium, Firefox, WebKit, and mobile WebKit pass; the real-stack-only browser case remains intentionally opt-in. | Final integrated core gate and deployment operator acceptance on the final image |
| SDKs | JavaScript `efa0a1074fd5639a02c4b852eac9ecaf4baf00f7` passes its full `pnpm check`, 71 offline release tests (70 pass and one skip), and 51 Playwright tests. Android `694cb4d2bff9e91582896e3cbbe140e960d9e4e4` passes 106 offline release tests (105 pass and one skip), its full 665-actionable-task Gradle gate, publication smoke, and 8/8 locked semantic slice. React Native `ba23c750ec662834b4d480940c4067508723defb` passes 103 Vitest, 62 Node, 19 Python, and 8/8 dependency-scan tests plus Swift bridge 5/5, Robolectric 6/6, locked iOS 10/10, locked Android 8/8, and a real CocoaPods/TurboModule build. Swift `92a394acbc00d1af6d258372f22b11ddae8e1750` passes 65 offline release tests (64 pass and one skip), 166/166 XCTest, SwiftOpenAI 11/11, Foundation Models 12/12, App Extensions 4/4 (193 Swift tests total), external SwiftPM consumer, and four CocoaPods lint gates. React Native retains its Debug-only native App Intent delegated request and fail-closed Release fixture; the final head was not physically rerun. | Hosted React Native replay rejection; operator-deferred physical invocation of the Debug App Intent/extension path; protected Apple distribution/extension-matrix proof and native isolation; physical Android/Google Play proof; tags, protected evidence, and publication |
| Frameworks | Eight exact, locally tested integrations recorded as `experimental`; unsupported seams remain explicit | Hosted common conformance and release evidence before any `supported` claim |
| Operations | Telemetry, jobs, key rotation, recovery, upgrades, replicas, cloud definitions, load/failure tooling, and release workflows. The selected first-publication path is GHCR followed by exact-image Docker Compose and manual-first Google Cloud Run in project `latchway`; GCP Terraform remains optional. Cloudflare provider evidence uses bounded cursor pagination with strict schema, duplicate, cursor-cycle, record-count, and byte limits rather than Wrangler's one-page JSON listing. | Protected exact-image Compose/Cloud Run runs for the selected profile; the other cloud and resilience domains remain deferred |
| Supply chain | Multi-architecture build, scan, SBOM, signing, provenance, and finalizer workflows implemented and statically/dry-run checked | Registry-built artifacts, per-architecture observations, and attestations; independent review remains required only for later strict assurance |
| Documentation | This canonical tree imports all four final SDK bundles and retains the task-oriented deployment and release-image guidance. The generated mirror must bind its exact source through `.latchway-docs-source.json`. | Route `docs.latchway.dev`, deploy through protected controls, then collect production-deployment and post-deploy receipts |
| Release controls and npm | Strict desired state covers six repositories and 51 environments. Docs alone requires CODEOWNERS review, one approval, and a written docs-not-required check. The explicit lower-assurance profile permits single-maintainer v1 without marking deferred review as passed. Its 13 environments and policy sentinels are live. npm 2FA is `auth-and-writes`; all five exact inert placeholders and trusted publishers are verified without npm tokens. | Execute the protected selected-profile release and add a distinct reviewer later to complete strict assurance |

## Schema-29 runtime validation boundary

Schema `29` replaces only the deferred terminal-validator function body;
trigger timing, locks, constraints, check precedence, and legacy repair remain
unchanged. The schema-28 contract checkpoint, wire `2`, bundle, and SDK locks
are not rewritten. Local PostgreSQL 15/18 correctness and advisory performance
results are recorded in [STATUS.md](STATUS.md); they do not establish a passing
full-candidate load gate or a release.

Readiness requires current schema to equal the binary's bundled available
schema. A schema-28 binary therefore cannot be rolled back onto a schema-29
database. Application rollback needs an independently verified compatible
schema-29 release-candidate/stable pair. Recovering schema `28` instead requires
a pre-29 backup/PITR restore into a fresh database with the matching image; it
is not application-rollback evidence. Follow the
[upgrade runbook](../operations/upgrades.md#schema-29-terminal-attempt-validation).

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
Console preview was upgraded to local image `latchway:local-d4693ee-arm64`;
the binary reports core `d4693ee36bf8a018a027fb75e5e2ac2fb6b58d50`, runs as
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
Current successor `ba23c750ec662834b4d480940c4067508723defb` is a descendant
that adds release retry-closure, transition-order, wording,
development-runner hardening, and the released-contract/source-tuple lock. It
passes the full local plus generic iOS and isolated Debug/Release App Intent
build gates; the physical path was not rerun at that head. The Release target
deliberately contains no executable Latchway request path.

The Swift package gate at
`92a394acbc00d1af6d258372f22b11ddae8e1750` also passed 65 offline release tests
(64 pass and one skip), the keychain invariant gate,
166/166 XCTest cases, SwiftOpenAI 11/11, Foundation Models 12/12, App
Extensions 4/4 (193 Swift tests total), a clean external SwiftPM consumer
build, and CocoaPods lint for AppAttest, AppExtensions, Core, and FirebaseAuth.
The minimal pinned
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
- imported all four final clean SDK documentation bundles in the canonical
  working tree without creating a tag or package release; and
- delivered the exact core and four SDK successor histories to `main` and
  verified their intended remote heads. The generated documentation mirror is
  required to bind the exact canonical source through
  `.latchway-docs-source.json` before conformance is accepted.

Protected release-candidate run `33755044849`, attempt `1`, at base commit
`86dae658676e7187a8db6a0deda3f8429ca6ab76` passed its complete verification
job and failed the unchanged isolated load gate; image construction,
publication, and signing were skipped. The current uncommitted successor
partitions the aggregate PostgreSQL budget into regular and quota-completion
pools, bounds reservation admission, reuses the response relay timer/callback,
and hardens readiness, deployment evidence, the Console, and the selected-
profile finalizer. On 2026-09-04 it passed complete uncached normal and race Go
suites against local PostgreSQL 18 and every Makefile fuzz-smoke target. The
complete current working tree then passed integrated `mise exec -- make check`:
generated SQL, workflow lint, Go vet and all Go packages against PostgreSQL 18,
all 548 Python release/workflow cases, Console ESLint, Admin API generation,
both TypeScript checks, 292/292 unit tests, deterministic production build
verification, and 37 browser cases across Chromium, Firefox, WebKit, and mobile
WebKit, with the real-stack-only case intentionally skipped. Image, unchanged
local load, and protected-candidate reruns are still required on the committed
successor; this local result does not authorize publication or GCP resource
creation.

The reconciled canonical public tree separately passes its full local check:
generated references and SDK bundles, 233-page structure and metadata, Vale
with zero findings across 253 files, Mintlify build and link validation, and
media-alt inspection across 235 MDX files. Existing color output recommends
AAA improvement while meeting the configured accessibility gate. This is not a
Mintlify production-deployment receipt.

Core `cd47229eac32f4a93a0779903d927526b77817d6` passes the full current
`make check`, including generated-source checks, all Go tests and vet, the
complete Python release/tool suite, Console lint/typecheck/tests, the
production Console build, and Playwright with its live-stack case explicitly
opt-in and skipped. `make test-race`, the bounded fuzz corpus, and real
PostgreSQL Admin/session/App Attest/configuration/lifecycle lock-order suites
also pass. Local adversarial engineering review closed
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

## Strict-full external completion evidence

The selected `single_maintainer_v1` public launch requires only the authenticated
public-tag, registry, Docker Compose, Google Cloud Run, and supply-chain evidence
enumerated in the release-profile policy. It keeps this section's remaining
domains `unverified`, retains `profile_status: incomplete`, and cannot claim
production readiness or `release-qualified`.

Its protected finalizer may set only profile-scoped `publication_ready` to
true after authenticating the exact source, candidate, core-publication,
public-tag, selected-registry, and supply-chain runs. The fresh signer binds
immutable certificate run/path/digest/ref/runner fields, accepts only canonical
duplicate-free JSON, preserves the unchanged failed strict report and its exact
all-domain evidence-window failure, and independently reconstructs the
one-field profile-local projection. That outcome still fixes
`release_qualified`, `fully_evidence_gated`, and `independently_reviewed` to
false. It has not been produced for any candidate.

One immutable candidate still requires all of the following before the later
strict-full completion claim:

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
   validation. A Mintlify preview exists, but no protected production
   deployment receipt is claimed and `docs.latchway.dev` is not routed.

The connected iPad and Xcode-managed `dev.latchway` profile supported automatic
Apple Development signing for predecessor `4264b47e270f5e9c05938d8108eacb79c7bf4e99`.
That predecessor passed strict signed root/extension verification, installation,
and launch; the earlier `6de46e1c7264e1d45cdd31174e4ea040a8c24acf`
root-app observation remains the only live App Attest/provider proof. The
physical path was not rerun for current `ba23c750ec662834b4d480940c4067508723defb`.
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
histories and separately requested GHCR and package publication work. npm
account 2FA is `auth-and-writes`; all five namespaces contain only the exact
`0.0.0-bootstrap.0` placeholder, their bootstrap and `latest` aliases are
verified, and every stable `1.0.0` coordinate remains unpublished. The
selected profile's 13 reviewer-free, self-review-permitted, main-only
environments and exact non-secret sentinels are live; strict-profile rulesets
are not. That authorization permits execution of the explicit profile, but it
does not by itself authenticate a stable tag or package. A lower-assurance
public version 1 launch becomes eligible only after the selected protected
workflow authenticates all required profile evidence. It remains ineligible
for production-ready, independently reviewed, or `release-qualified` claims.
Only the later strict finalizer may produce the immutable completion report
after every strict domain closes without skips, stale evidence, or coordinate
drift.
