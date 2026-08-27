# Implementation status

## Current phase

The core repository has committed and validated the governance/contract foundation, runnable Go/PostgreSQL/embedded-console foundation, one-time administrative bootstrap and tenant slice, and the standalone Phase 5 identity-verification subsystem. The browser/Node JavaScript and Android SDKs are committed. iOS and React Native implementations are active in their own repositories.

This is not a functional or releasable end-to-end gateway yet. Immutable configuration activation, challenge/session issuance, attestation verification, authenticated proxying, quota settlement, complete administration, operations, deployment proof, and release evidence remain open.

## Current objective

Complete the iOS and React Native SDK local gates, then connect immutable active configuration, verified identities, RFC 9449 DPoP, attestation, and short-lived sessions into the first authenticated mock-upstream proxy path.

## Last passing commit in each repository

“Passing” means the named immutable commit passed the evidence listed here. Uncommitted implementation work is not promoted into this table.

| Repository | Revision | Evidence |
| --- | --- | --- |
| `latchway` | `c83703e3eb226451ca3928b91982dfb376f35b4a` | Full Go suite with isolated PostgreSQL schemas, `go vet ./...`, contract validation, identity race tests, and diff hygiene pass |
| `latchway-js` | `273925d73a5a959f95664b1b1d838505dcce5f6c` | Lint, typecheck, 22 tests, build, examples, exports, CSP, package audit, tarball and two-build reproducibility pass |
| `latchway-ios-sdk` | `6587af0c510e43fea0d7c3fa9167149785468215` | Final contract lock only; SDK implementation remains uncommitted while local validation finishes |
| `latchway-android` | `0042a916580d14295bd944104aae6deb2ac136c5` | SDK/build/samples plus 34 static unit tests and independent Kotlin/JVM compatibility compilation pass; official Android compilation remains license-blocked |
| `latchway-react-native-sdk` | `61d827a32d8b36e2177fa4d4f2eb8b4ac5019f99` | Final contract lock only; SDK implementation remains uncommitted while local validation runs |

## Protocol contract version

Contract `0.1.0`; wire protocol `1`; status `draft`.

Core contract revision: `5c98dc4d656d8140e0b4af90f42ea6d884f0d60a`.

Deterministic bundle SHA-256: `1228820f87744334ec8091b9ebbe737500016daa844175bd1ad64fd0095d1afd`.

Every SDK repository records this exact draft revision and checksum in `contract.lock`. The bundle is validation evidence only and has not been published.

## Database schema version

`3`. Fresh isolated schemas migrate through all three forward-only migrations on PostgreSQL 18.6. PostgreSQL 15 or newer remains the compatibility floor.

## Last full test time

2026-08-27T18:50:50+07:00 for the core full Go/PostgreSQL regression suite. This is not cross-repository release evidence.

## Passing evidence

- `go test ./... -count=1` with `LATCHWAY_TEST_DATABASE_URL` — every Go package passed, including fresh-schema migration, one-time owner/bootstrap, Admin API, identity persistence, console embedding, DPoP primitives, secrets, outbound destination controls, OpenAI Chat adapter, and deterministic mock upstream.
- `go test -race ./internal/identity -count=1` — verifier, rotating key cache, concurrency, privacy, and user-resolution unit paths passed under the race detector.
- `go vet ./...` — passed.
- `python3 scripts/validate-contracts.py` — OpenAPI structure/references, registry parity, schemas/examples, attestation hashes, and DPoP signatures/semantics passed.
- Two independent contract-bundle builds were byte-identical at SHA-256 `1228820f87744334ec8091b9ebbe737500016daa844175bd1ad64fd0095d1afd`.
- Embedded console `pnpm check`, 16 Vitest tests, production distribution verification, and two-build reproducibility passed at core commit `3ee1177f1b251fb3dda6ace40209c079c3ebca3e`.
- JavaScript SDK Node/browser checks, 22 tests, examples, packaging, audit, and reproducibility passed at `273925d73a5a959f95664b1b1d838505dcce5f6c`.
- Android wrapper/task discovery, independent clean Kotlin/JVM compatibility compilation, 34 static unit tests, contract-vector equality, XML checks, and diff hygiene passed at `0042a916580d14295bd944104aae6deb2ac136c5`; Android Gradle compilation/tests are not claimed.
- The earlier single-image Compose foundation gate passed with PostgreSQL and the embedded console healthy; the current post-identity image must be rebuilt before release evidence can cite it.

## Implemented security boundaries

- One-time administrative bootstrap creates exactly one owner; later bootstrap attempts fail closed.
- Admin cookies are secure/host-only, cookie mutations require exact Origin plus session-bound CSRF, API tokens are scope-bounded, and administrative mutations produce redacted audit records.
- JWT verification pins issuer, permitted audiences and algorithms; rejects duplicate JSON, token-selected key URLs, algorithm confusion, invalid time claims and invalid subjects; and supports RSA, ECDSA, explicitly acknowledged legacy HS256, Firebase, Supabase, and Clerk presets.
- Remote verification keys use fixed server-selected HTTPS endpoints, protected outbound networking by default, conditional caching, single-flight refresh, bounded last-known-good grace, forced-refresh throttling, and rotation tests.
- Raw identity credentials and external subjects cannot enter the user store. PostgreSQL retains an issuer digest, application/provider-scoped subject HMAC, selected normalized claims, and an opaque internal user ID.
- P-256 JWK/thumbprint/proof primitives, envelope encryption, protected outbound targets/header filtering, and a deterministic mock upstream are implemented, but they are not yet joined into a session/proxy pipeline.

## Open blockers and unfinished gates

- Phase 4 immutable configuration revisions, validation, activation, conflict detection, rollback, and compiled-policy snapshots are not yet committed.
- Challenge creation/consumption, access-token signing/JWKS publication, refresh-family rotation/reuse detection, DPoP replay persistence, revocation, and the authenticated proxy path are not implemented.
- Native attestation server verification, quota reservation/settlement, pricing provenance, complete adapters/routing, complete Admin API/dashboard/CLI, telemetry/jobs, deployment smoke tests, and hardening/release gates remain.
- Android Gradle compile/test execution requires the user to accept the Android Platform 37 and Build-Tools 36.0.0 license terms; automation will not accept legal agreements on the user’s behalf.
- Physical App Attest and Play Integrity conformance, a live OpenRouter canary, cloud smoke tests, registry publishing, signing, tags, and release artifacts require external accounts or credentials.
- Root private security-reporting configuration still needs verification before a public release.

None of the external credentials blocks fixture-based implementation, local security tests, documentation, or reproducibility work.

## Next executable task

Implement and test immutable configuration revisions and activation, then build the client challenge/session endpoints over the committed identity and DPoP primitives and prove one authenticated debug-attested request through the deterministic mock upstream.
