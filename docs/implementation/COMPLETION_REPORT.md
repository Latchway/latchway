# Version 1 completion gap ledger

Status: **the version 1 source implementation is present and locally
exercised, but the candidate is not yet source-converged, released, or
production-proven**.

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
| Contract bundle | Deterministic inputs implemented; final checksum pending atomic convergence |
| SDK locks | Final component-attestation schema/vector and bundle coordinate still converging |
| Public release | None; no version 1 tag, package, image, or production-docs publication is authorized |

Historical contract `0.5.1`, wire 1, schema 20, and their SDK locks remain
immutable legacy coordinates. They are regression evidence only and cannot
authorize version 1.

## Source implementation summary

| Workstream | Implemented in local source | Remaining before release |
| --- | --- | --- |
| Contract and persistence | Family/component APIs, wire-2 claims, strict schemas/errors/vectors, migrations through schema 23 | Freeze final bundle and synchronize every SDK lock/commit |
| Trust and sessions | Identity/native/web verification, DPoP, independent component sessions, exact-tuple refresh idempotency, delegation, direct component App Attest step-up, composite provenance, scoped revocation | Protected physical trust and lifecycle observations |
| Gateway | Trusted input-token preflight, input/total quotas, Responses, Chat, Embeddings, Anthropic, restricted opaque routes, deterministic weighted/sticky routing, fallback/retry/accounting | Exact-image live-provider and load/failure evidence |
| Admin/operator | Family/component Admin API, CLI, dashboard, wizard, trust graph, request/usage/audit/failure views, and scoped actions | Deployment operator acceptance on the final image |
| SDKs | Swift, Android, JavaScript, and React Native transports, component sessions, replay-safe retry, streaming/cancellation, adapters, and composite-trust decoding | Final locks, clean cross-repository gate, physical platform proof, publication |
| Frameworks | Six exact, locally tested integrations recorded as `experimental`; unsupported/planned seams remain explicit | Hosted common conformance and release evidence before any `supported` claim |
| Operations | Telemetry, jobs, key rotation, recovery, upgrades, replicas, cloud definitions, load/failure tooling, and release workflows | Protected exact-image cloud/resilience runs |
| Supply chain | Multi-architecture build, scan, SBOM, signing, provenance, and finalizer workflows implemented and statically/dry-run checked | Registry-built artifacts, per-architecture observations, attestations, and independent review |
| Documentation | Canonical Mintlify source, generated API/compatibility content, tested snippets, validation, and deployment mirror workflow | Final mirror convergence, merge, production deployment, and post-deploy validation |

## Schema-23 direct component App Attest step-up

An eligible delegated Apple component can request a one-use version-2
attestation binding, submit its own App Attest assertion, and rotate only its
own DPoP-bound component session. Successful verification produces composite
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

The Swift and React Native iOS source surfaces implement Action/SSO proof from
the extension process. A containing application cannot attest the extension
bundle for it, and no root credential or proof crosses the React Native
JavaScript bridge. The server contract can model an eligible watch component,
but the current Swift package does not claim watch direct-step-up support.
Android direct component step-up is intentionally unsupported in version 1.

## Local evidence boundary

Development runs cover PostgreSQL migrations and verticals, authorization,
replay, refresh/revocation, component attestation, policy/quota behavior,
protocol/routing behavior, SDK unit and native consumer builds, dashboard and
browser flows, deterministic contract/docs builds, workflow validation, and
static/dry-run deployment and supply-chain checks.

Those results establish implementation confidence; they are not release
receipts. Before a candidate can enter protected validation, the final
convergence run must:

- regenerate the contract bundle twice with identical bytes and record its
  final checksum;
- synchronize the schema-23 contract, component-attestation schema/vector,
  protocol coordinate, and bundle lock across all SDK repositories;
- run every clean-tree core, SDK, dashboard, documentation, workflow, and
  cross-repository conformance gate on the exact commits; and
- record the six private implementation branches without creating a public tag
  or package release.

## External-required completion evidence

One immutable candidate still requires all of the following:

1. protected physical iOS containing-app/widget/share isolation and Action/SSO
   direct App Attest step-up, with candidate-bound identities, independent
   keys/sessions, sibling denial, no-host, background, termination, and
   no-user-presence behavior, including React Native iOS extension processes;
2. Play-distributed Play Integrity and physical React Native Android flows,
   plus configured App Check and Turnstile observations;
3. all SDKs and every advertised framework/version bound against the exact
   release image;
4. bounded live-provider streaming/non-streaming, usage, error, clamp,
   cancellation, fallback, and retry behavior;
5. every claimed cloud deployment and protected multi-replica, load,
   destructive failure, backup/restore, upgrade/rollback, key-rotation, and
   worker-recovery drill;
6. per-architecture vulnerability and license scans, SBOMs, signatures,
   provenance, and candidate-bound independent security review;
7. signed tags and releases, OCI/npm/Swift/CocoaPods/Maven publication, byte
   verification, and clean post-publication consumers; and
8. production Mintlify deployment followed by link, accessibility, redirect,
   and AI-readable-output validation.

A connected device is useful execution capacity, not proof by itself. No
physical result closes a gate until the protected collector and finalizer bind
it to the exact repository, contract, application identity, signing,
entitlement, package, and image coordinates. Play Integrity additionally
requires a Play-distributed signed application.

## Completion decision

The locally implemented histories may be reviewed, committed, and pushed to
private implementation branches. They are not ready for a version 1 tag,
production promotion, package/container publication, or a production-readiness
claim. Only the protected finalizer may produce the immutable completion report
after every required domain closes without skips, stale evidence, or coordinate
drift.
