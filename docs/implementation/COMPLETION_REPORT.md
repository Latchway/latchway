# Version 1 completion gap ledger

Status: **the version 1 source implementation is locally converged, but the
candidate is not released or production-proven**.

This checked-in file is a source-status ledger. It is not the immutable
candidate-bound completion report produced by the protected release workflow.
It must not claim tags, registry digests, package publication, production
deployments, or protected evidence that does not exist.

## Current source coordinate

| Field | Current source truth |
| --- | --- |
| Contract | Draft `1.0.0`; `released_at: null` |
| Wire | Current `2`; discovery range `[1, 2]` |
| Database | Schema `23` |
| Contract bundle | SHA-256 `36aa3c4786e60f2cdbbc3d0cd2f65bffe894a099479517b2e1faa01361c74b00` at core checkpoint `a62b0f6aa2328604101c1073c56f5ecb3bed3618` |
| SDK locks | All four locks, four vector families, and the copied `protocol-version.json` manifest converge; clean source conformance passes |
| Public release | None; no version 1 tag, package, image, or production-docs publication is authorized |

Historical contract `0.5.1`, wire 1, schema 20, and their SDK locks remain
immutable legacy coordinates. They are regression evidence only and cannot
authorize version 1.

## Source implementation summary

| Workstream | Implemented in local source | Remaining before release |
| --- | --- | --- |
| Contract and persistence | Family/component APIs, wire-2 claims, strict schemas/errors/vectors, migrations through schema 23, frozen bundle and synchronized locks | Protected exact-candidate evidence |
| Trust and sessions | Identity/native/web verification, DPoP, independent component sessions, exact-tuple refresh idempotency, delegation, generic direct-component protocol support, composite provenance, scoped revocation | Protected physical trust and lifecycle observations; iOS extensions remain delegated-only |
| Gateway | Trusted input-token preflight, input/total quotas, Responses, Chat, Embeddings, Anthropic, restricted opaque routes, deterministic weighted/sticky routing, fallback/retry/accounting; bounded OpenRouter checks pass against the current source gateway | Immutable-image provider and load/failure evidence |
| Admin/operator | Family/component Admin API, CLI, dashboard, wizard, trust graph, request/usage/audit/failure views, and scoped actions | Deployment operator acceptance on the final image |
| SDKs | Swift, Android, JavaScript, and React Native transports, component sessions, replay-safe retry, streaming/cancellation, adapters, composite-trust decoding, final locks, and clean cross-repository gate | Physical platform proof and publication |
| Frameworks | Six exact, locally tested integrations recorded as `experimental`; unsupported/planned seams remain explicit | Hosted common conformance and release evidence before any `supported` claim |
| Operations | Telemetry, jobs, key rotation, recovery, upgrades, replicas, cloud definitions, load/failure tooling, and release workflows | Protected exact-image cloud/resilience runs |
| Supply chain | Multi-architecture build, scan, SBOM, signing, provenance, and finalizer workflows implemented and statically/dry-run checked | Registry-built artifacts, per-architecture observations, attestations, and independent review |
| Documentation | Canonical Mintlify source, synchronized generated mirror, tested snippets, validation, and credential-free checkpoint workflow | Merge, production deployment, and post-deploy validation |

## Schema-23 direct component App Attest step-up

The wire and server can issue a one-use version-2 attestation binding, verify
component-owned App Attest evidence, and rotate only that component's
DPoP-bound session. Successful verification produces composite
`delegated_direct_attested` trust while retaining the parent component,
delegation, component definition, family, provider, bundle, component key, and
JWK-thumbprint bindings. Component/family/install revocation and component
replacement revoke linked App Attest state.

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

Those results establish implementation confidence; they are not release
receipts. The final convergence run has:

- regenerated the contract bundle twice with identical bytes and recorded its
  final checksum;
- synchronized the schema-23 contract, component-attestation schema/vector,
  protocol coordinate, and bundle lock across all SDK repositories;
- run the clean-tree core, SDK, dashboard, documentation, workflow, and
  cross-repository conformance gate on the exact commits; and
- prepared six implementation branches without creating a public tag or
  package release. The user explicitly authorized pushing those audited
  histories to the six now-public repositories.

## External-required completion evidence

One immutable candidate still requires all of the following:

1. protected physical iOS and React Native iOS root-app App Attest plus
   delegated Widget/Share/Action isolation, with candidate-bound identities,
   independent keys/sessions, sibling denial, no-host, background,
   termination, and no-user-presence behavior, plus App Intents signed-binary
   and entitlement isolation while its non-executing fixture remains
   fail-closed;
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

An iPhone is connected and registered with Xcode. The current Xcode-managed
`dev.latchway` development profile includes that device and its App Attest
entitlement lists both `development` and `production`, but the host Keychain
contains zero valid code-signing identities. Device connectivity and profile
registration are execution capacity, not proof by themselves. No physical result closes a gate
until the protected collector and finalizer bind it to the exact repository,
contract, application identity, signing, entitlement, package, and image
coordinates. Play Integrity additionally requires a Play-distributed signed
application and is deferred until an Android device is available.

## Completion decision

The user explicitly authorized committing and pushing the audited histories to
the six public implementation branches. They are not ready for a version 1 tag,
merge, production promotion, package/container publication, or a
production-readiness claim. Only the protected finalizer may produce the
immutable completion report after every required domain closes without skips,
stale evidence, or coordinate drift.
