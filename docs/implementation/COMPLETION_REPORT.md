# Version 1 completion gap ledger

Status: **the version 1 source implementation is locally converged and has
supplemental development-signed physical iOS evidence, but the candidate is
not released or production-proven**.

This checked-in file is a source-status ledger. It is not the immutable
candidate-bound completion report produced by the protected release workflow.
It must not claim tags, registry digests, package publication, production
deployments, or protected evidence that does not exist.

## Current source coordinate

| Field | Current source truth |
| --- | --- |
| Contract | Draft `1.0.0`; `released_at: null` |
| Wire | Current `2`; discovery range `[1, 2]` |
| Database | Schema `27` at clean core implementation checkpoint `82c9d3663a0532210d6a99ebecaa179f05797115` |
| Contract bundle | SHA-256 `3a88fb69b911724da849229f34f735608e829bcfb0658087313c8d31441e9927` at contract source checkpoint `a59a2c1c807aec50093ae6346492a05148c72899` |
| Core implementation source | `82c9d3663a0532210d6a99ebecaa179f05797115`; subsequent ledger-only changes do not alter runtime source |
| SDK source tuple | JavaScript `6b0c08ded377011044462d1ba6aa46cb34d7ee8f`; Swift `af87b4454e4b6a159b9da7bd50550865c74684a2`; Android `9d83a635fc0e5f1a79582c73f0fb61acc9e24471`; React Native `111e7841f81e87ab471c18d381fed18ec8335760` |
| Public documentation source | Canonical core checkpoint `7bdf9cb6da312ea5f4282ae2caf686bcc1122fa3`; synchronized Mintlify mirror `ce4ea1e1cf56404da7146b98ca2744b194050fd5` |
| SDK locks | All four locks, four vector families, and the copied `protocol-version.json` manifest converge; clean source conformance passes |
| Public release | Pushed branch source candidates only; no version 1 merge, tag, package, image, or production-docs publication is authorized |

Historical contract `0.5.1`, wire 1, schema 20, and their SDK locks remain
immutable legacy coordinates. They are regression evidence only and cannot
authorize version 1.

## Source implementation summary

| Workstream | Implemented in local source | Remaining before release |
| --- | --- | --- |
| Contract and persistence | Family/component APIs, wire-2 claims, strict schemas/errors/vectors, migrations through schema 27, exact challenge-Origin binding, logical-request decision stages, bounded audit attribution/browse indexes, authoritative root-definition selection, and the deterministic draft contract bundle at the exact checkpoint above | Protected exact-candidate evidence |
| Trust and sessions | Identity/native/web verification, DPoP, independent component sessions, exact-tuple refresh idempotency, delegation, generic direct-component protocol support, composite provenance, scoped revocation; development-signed physical iOS registration and same-key assertion passed | Protected Apple distribution-derived and Android trust/lifecycle observations; iOS extensions remain delegated-only |
| Gateway | Trusted input-token preflight, input/total quotas, Responses, Chat, Embeddings, Anthropic, restricted opaque routes, deterministic weighted/sticky routing, fallback/retry/accounting; bounded OpenRouter checks pass against the current source gateway | Immutable-image provider and load/failure evidence |
| Admin/operator | Family/component Admin API, CLI, dashboard, wizard, trust graph, request/usage/audit/failure views, canonical redaction-safe doctor/support bundles, and scoped actions | Deployment operator acceptance on the final image |
| SDKs | Swift, Android, JavaScript, and React Native transports, component sessions, replay-safe retry, streaming/cancellation, adapters, composite-trust decoding, final locks, and clean cross-repository gate. React Native `111e7841f81e87ab471c18d381fed18ec8335760` adds root-owned component lifecycle and a Debug-only native App Intent delegated request while keeping the Release fixture fail-closed; historical root-app commit `6de46e1c7264e1d45cdd31174e4ea040a8c24acf` passed a real iPadOS 26.5 Debug run with automatic Apple Development signing. | Physical invocation of the current Debug App Intent, protected Apple distribution/extension-matrix proof, physical Android proof, and publication |
| Frameworks | Eight exact, locally tested integrations recorded as `experimental`; unsupported seams remain explicit | Hosted common conformance and release evidence before any `supported` claim |
| Operations | Telemetry, jobs, key rotation, recovery, upgrades, replicas, cloud definitions, load/failure tooling, and release workflows | Protected exact-image cloud/resilience runs |
| Supply chain | Multi-architecture build, scan, SBOM, signing, provenance, and finalizer workflows implemented and statically/dry-run checked | Registry-built artifacts, per-architecture observations, attestations, and independent review |
| Documentation | Canonical Mintlify source at core checkpoint `7bdf9cb6da312ea5f4282ae2caf686bcc1122fa3`, exact SDK bundles, tested snippets, validation, and synchronized mirror commit `ce4ea1e1cf56404da7146b98ca2744b194050fd5` pass locally | Merge, production deployment, and post-deploy validation |

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
static/dry-run deployment and supply-chain checks. A real browser-minted
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

Current React Native source `111e7841f81e87ab471c18d381fed18ec8335760`
materially extends that predecessor with root-owned descriptor lifecycle and a
Debug App Intent that uses the native extension client for an independently
keyed delegated request with exact-run challenge/receipt binding. Its full
local checks plus generic iOS and isolated Debug/Release App Intent build gates
pass. The App Intent has not yet been physically invoked, and the Release
target deliberately contains no executable Latchway request path.

Those results establish implementation confidence; they are not release
receipts. The final convergence run has:

- regenerated the contract bundle twice with identical bytes and recorded its
  final checksum;
- synchronized the frozen API/configuration contract, component-attestation schema/vector,
  protocol coordinate, and bundle lock across all SDK repositories;
- run the clean-tree core, SDK, dashboard, documentation, workflow, and
  cross-repository conformance gate on the exact commits; and
- prepared six implementation branches without creating a public tag or
  package release. The user explicitly authorized pushing those audited
  histories to the six now-public repositories.

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
8. production Mintlify deployment followed by link, accessibility, redirect,
   and AI-readable-output validation.

The connected iPad and Xcode-managed `dev.latchway` profile supported
automatic Apple Development signing and the supplemental historical root-app
observation.
No physical result closes the release gate until the protected collector and
finalizer bind an Apple distribution-derived candidate to the exact repository,
contract, application identity, signing, entitlement, package, and image
coordinates. The recorded root-app observation did not execute the delegated
extension, and the current Debug App Intent still requires physical invocation.
Play Integrity additionally requires a Play-distributed signed application and
is deferred until an Android device is available. The CocoaPods lint passed
with the beta Xcode toolchain; the stable Xcode installation on this host lacks
the required platform component and cannot independently run that lint.

## Completion decision

The user explicitly authorized committing and pushing the audited histories to
the six public implementation branches. They are not ready for a version 1 tag,
merge, production promotion, package/container publication, or a
production-readiness claim. Only the protected finalizer may produce the
immutable completion report after every required domain closes without skips,
stale evidence, or coordinate drift.
