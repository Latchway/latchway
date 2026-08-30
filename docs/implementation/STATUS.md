# Implementation status

Status date: 2026-08-30

Latchway version 1 is implemented as a locally validated source candidate. It
is not yet a released or production-proven version: the final contract bundle,
SDK locks, and repository commits are still converging, and protected hardware,
live-provider, cloud, resilience, supply-chain, publication, and
post-publication domains remain open.

## Candidate snapshot

| Field | Current value |
| --- | --- |
| Core branch | `codex/v1-implementation` |
| Contract | `1.0.0` draft, `released_at: null` |
| Contract freeze | Pending final atomic cross-repository convergence |
| Bundle SHA-256 | Pending deterministic regeneration after contract convergence |
| Wire | Current `2`; discovery supports `[1, 2]` |
| Database | Schema `23` |
| Package/server range | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| Release state | `unreleased`; no tag or package publication authorized |

The historical `0.5.1`/wire-1 coordinate remains unchanged. Intermediate draft
bundle hashes are not release coordinates; the final draft hash must be
regenerated reproducibly and copied into every SDK lock after the component
attestation contract stops changing.

## Workstream status

| Workstream | Local source status | Remaining boundary |
| --- | --- | --- |
| Family/component contract and migrations | Implemented through schema 23 | Final bundle and cross-repository lock convergence |
| Server trust/session/revocation/policy/quota runtime | Complete in source, including component App Attest step-up | Exact-candidate rerun and protected observations |
| Responses, Chat, Embeddings, Anthropic, opaque protocols | Complete | Bounded live-provider runs |
| Weighted/sticky routing, fallback, retry, accounting | Complete | Exact-image load/failure evidence |
| Admin API, CLI, dashboard, wizard, request/usage/audit views | Complete | Deployment operator acceptance |
| Native/Web trust verifiers and component proof | Complete in source, including composite delegated/direct trust | Physical App Attest/Play Integrity/App Check/Turnstile evidence |
| Swift, Android, JavaScript SDKs | Implemented; lock synchronization running | Clean cross-repository source gate and publication |
| React Native SDK | Implemented; final native/source pins running | Physical iOS/Android proof and publication |
| Framework adapters | Locally tested experimental scope | Hosted common conformance; physical native proof |
| Telemetry, jobs, rotation, recovery, upgrades, replicas | Complete in source/local tests | Protected exact-image drills |
| Cloud and supply-chain workflows | Complete and statically/dry-run validated | Registry digests, scans, SBOM, signature, provenance, cloud smokes |
| Mintlify public docs | Canonical 59-page source passes locally | Mirror synchronization, merge, production deploy validation |

## Local source evidence

- PostgreSQL-backed unit, integration, migration, authorization, replay,
  refresh, revocation, and direct-component-attestation vertical tests.
- Contract/schema/error/vector determinism and the complete Python release,
  workflow, evidence, and validation suites.
- Dashboard lint, TypeScript checking, unit tests, deterministic builds,
  Playwright, and a real PostgreSQL-backed first-run browser flow.
- Cloudflare unit/build checks and deployment dry-run; Compose, Cloud Run, and
  AWS Terraform static validation.
- Actionlint across all workflows, deterministic contract regeneration, and a
  binary `govulncheck` result with no called vulnerabilities.
- Mintlify structure, build, links/anchors/redirects/snippets, accessibility,
  and Vale MDX prose validation.

These are source-development results, not protected release receipts. The final
clean-tree Go/race, SDK, contract, dashboard, documentation, workflow, and
cross-repository gates must be rerun after the atomic convergence commits.
Repository-specific SDK test counts and final commit coordinates are recorded
only after that convergence finishes.

## Direct component attestation boundary

Schema 23 and wire 2 add component-owned App Attest challenge/exchange routes
and binding version 2. An eligible delegated Apple component can prove its own
bundle and component key, rotate only its own DPoP-bound session, and retain
the delegation ancestry under the composite trust source
`delegated_direct_attested`. The configured component policy remains
`preferred` so it cannot qualify an initial delegated session; the explicit
step-up exchange itself requires valid App Attest evidence.

The Swift and React Native iOS sources expose this direct step-up for Action and
SSO extensions running in their own extension process. A containing React
Native application cannot attest an extension bundle on its behalf. The server
contract also models eligible watch components, but the current Swift package
does not claim a watch direct-step-up SDK surface. Android component direct
step-up is intentionally unsupported; Android continues to use delegated
component trust and can decode the composite trust source returned for other
platforms.

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

1. protected physical iOS containing-app/widget/share isolation and Action/SSO
   direct App Attest step-up, including component-owned identity/key/session,
   sibling denial, no-host, background, termination, and no-user-presence
   behavior, plus React Native iOS extension-process flows;
2. Play-distributed Play Integrity and React Native Android flows on physical
   devices, plus configured App Check/Turnstile observations;
3. exact-image live provider, all-SDK, and hosted framework conformance;
4. every claimed cloud plus protected multi-replica, load, destructive failure,
   backup/restore, upgrade/rollback, key-rotation, and worker recovery drill;
5. per-architecture vulnerability/license scans, SBOM, signature, provenance,
   and independent security review;
6. signed tags/releases, OCI and package publication, production Mintlify
   deployment, and clean post-publication consumers.

A real device is connected to the development host, but no protected,
candidate-bound physical-device receipt has yet been captured and accepted by
the release finalizer. Device visibility alone cannot prove signing,
entitlements, App Attest, Play Integrity, component isolation, or lifecycle
behavior. Play Integrity additionally requires a Play-distributed signed
application.

## Release decision

The source candidate may be reviewed and pushed to private implementation
branches. It must not be tagged, promoted, advertised as production-ready, or
published until the protected finalizer binds every required receipt to one
immutable set of core, SDK, image, contract, package, and documentation
coordinates.
