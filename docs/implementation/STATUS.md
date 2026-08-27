# Implementation status

## Current phase

The core repository has committed and locally validated the governance and draft-contract foundation, runnable Go/PostgreSQL/embedded-console foundation, one-time administrative bootstrap and tenant slice, immutable configuration revisions, identity verification, signed debug attestation, the Phase 6 RFC 9449 DPoP session slice, and the first authenticated OpenAI Chat proxy vertical. A real PostgreSQL-backed test now proves custom JWT verification, signed debug attestation, challenge/exchange, DPoP-bound authorization, immutable policy resolution, request-count reservation, protected upstream dispatch, model rewrite, output clamp, response relay, usage settlement, and DPoP replay rejection without a second dispatch.

JavaScript, iOS, Android, and React Native source implementations are committed in their own repositories. Their contract locks identify the prior synchronized core/bundle baseline, not the newer proxy implementation commit. Lock synchronization is bookkeeping evidence, not a compatibility result; a fresh lock decision and live current-core conformance are still required.

This is a functional local debug/mock vertical, not a production-ready or releasable gateway. The full quota and pricing engine, production native attestation, broader protocols/routing, complete administration and operations, current deployment proof, cross-repository conformance, and release evidence remain open.

## Current objective

Expand the proven single-rule request-count quota into atomic deterministic multi-rule calendar reservations, then add token/output reservation, usage settlement, and integer nano-USD pricing. Keep unsupported configuration shapes from activating until their runtime capability exists.

## Last passing commit in each repository

The table names the current immutable evidence commit in each repository. For lock-only SDK commits, the row separately identifies the parent implementation revision whose source gates passed. None of these entries means released, published, physically attested, or cross-repository compatible with the current core.

| Repository | Revision | Evidence |
| --- | --- | --- |
| `latchway` | `ab688f5221d681ea1cdd42397ec14a85208d6d4b` | Full normal Go suite; focused API/server/worker normal, race and vet gates; focused authenticated PostgreSQL proxy normal and race gates; earlier full race/PostgreSQL/fuzz/contract/`make check` evidence remains recorded at `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` |
| `latchway-js` | `8df68931730bad05ef110fe53e09d857b5bd61f8` | Baseline core/bundle lock synchronized; local source/package gates passed at parent implementation commit `273925d73a5a959f95664b1b1d838505dcce5f6c`; latest-core live conformance remains |
| `latchway-ios-sdk` | `fd670a04004787901bb19b3ab762f4d2dc050a07` | Baseline core/bundle lock synchronized; local Swift/fixture gates passed at parent implementation commit `2972f99c59b652722a586510a9c943ac57a69a5c`; latest-core and physical App Attest proof are not claimed |
| `latchway-android` | `cd96781426831f464fc1e5350094aab91ca11dd2` | Baseline core/bundle lock synchronized; local static/JVM gates passed at parent implementation commit `0042a916580d14295bd944104aae6deb2ac136c5`; official Android SDK/Gradle validation remains toolchain-blocked |
| `latchway-react-native-sdk` | `bf1d5e9319c859edc215677e6c02b7d0f91cc811` | Baseline core/bundle lock synchronized; local source gates passed at parent implementation commit `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0`; latest-core, CocoaPods/native-consumer and device conformance remain open |

## Protocol contract version

Contract `0.1.0`; wire protocol `1`; status `draft`.

Current validated core implementation revision: `ab688f5221d681ea1cdd42397ec14a85208d6d4b`.

Deterministic bundle SHA-256: `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.

Two independent builds of the most recently reproduced bundle were byte-identical. That bundle is local validation evidence only and has not been published. Every SDK `contract.lock` still pins the synchronized baseline core revision `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` and bundle `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`; no SDK lock or compatibility claim has been advanced to `ab688f5221d681ea1cdd42397ec14a85208d6d4b`. Lock equality alone does not prove compatibility.

## Database schema version

`9`. Fresh isolated schemas migrate through all nine forward-only migrations, including durable quota request identity and logical-request fingerprint hardening. PostgreSQL 15 or newer remains the compatibility floor.

## Last full test date

2026-08-28 (Asia/Ho_Chi_Minh). This is local implementation evidence, not cross-repository release evidence.

## Passing evidence

- `go test ./... -count=1` — the full normal Go suite passed.
- `go test -race ./... -count=1` — the full Go suite passed under the race detector at the synchronized `0a03d936` baseline; focused changed-package race gates pass at the current implementation revision.
- The full PostgreSQL integration set passed against fresh schemas; the focused session revocation race gate and 20 repeated contention runs also passed.
- `go vet ./...` — passed.
- `python3 scripts/validate-contracts.py` — OpenAPI structure/references, registry parity, schemas/examples, attestation hashes, and DPoP signatures/semantics passed.
- Two independent contract-bundle builds were byte-identical at SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.
- All six security-sensitive fuzz targets passed their smoke gates: canonical attestation binding, DPoP validation, public-JWK parsing, HTU normalization, access-token preflight, and protected credential-header parsing.
- The complete `make check` gate passed, including formatting, reproducible sqlc output, vet, Go tests, frozen console dependency installation, lint/typecheck/tests, build, and embedded-asset checks.
- The PostgreSQL-backed authenticated Chat vertical passes normally and under the race detector. It asserts exact prompt/answer relay, target-bound authority, credential/header isolation, model rewrite, token clamp, request-count settlement, first-byte/attempt state, absence of plaintext credential/body markers, and proof replay without redispatch.
- `api`, `worker`, and `all` process roles now compose distinct responsibilities. The bounded worker immediately and periodically expires abandoned quota reservations and removes expired DPoP replay rows; focused normal/race/vet and shutdown-error propagation gates pass. This is an initial jobs slice, not Phase 15 completion.
- A fresh local OCI build for `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` completed at image ID `sha256:c0dcae33d48658d41557fbf6a7886beec53a0c4a14f2322d77da179e303a32e0` and declares non-root runtime user `65532`; no registry digest or current Compose smoke is claimed.
- The SDK lock-sync commits are clean and identify the synchronized baseline core revision and bundle. Earlier repository-specific local source gates remain recorded separately; the latest core, hardware attestation, published dependency resolution, and live conformance are not included in the lock-sync evidence.

## Implemented security boundaries

- One-time administrative bootstrap creates exactly one owner; later bootstrap attempts fail closed.
- Admin cookies are secure/host-only, cookie mutations require exact Origin plus session-bound CSRF, API tokens are scope-bounded, and administrative mutations produce redacted audit records.
- Validated configuration revisions are immutable, activation and rollback are conflict-safe, and session challenge/refresh decisions bind to the applicable active policy revision.
- JWT verification pins issuer, permitted audiences and algorithms; rejects duplicate JSON, token-selected key URLs, algorithm confusion, invalid time claims and invalid subjects; and supports RSA, ECDSA, explicitly acknowledged legacy HS256, Firebase, Supabase, and Clerk presets.
- Remote verification keys use fixed server-selected HTTPS endpoints, protected outbound networking by default, conditional caching, single-flight refresh, bounded last-known-good grace, forced-refresh throttling, and rotation tests.
- Raw identity credentials and external subjects cannot enter the user store. PostgreSQL retains an issuer digest, application/provider-scoped subject HMAC, selected normalized claims, and an opaque internal user ID.
- The local debug-attested session plane issues short-lived DPoP-bound access tokens and rotating refresh families, enforces proof replay transactionally, publishes public signing keys, detects refresh reuse, and fails closed when active identity or attestation policy is no longer satisfied.
- Protected installation revocation validates the access token and request-bound DPoP proof in one transactional boundary, consumes replay state atomically, and terminates the installation, active grants, refresh tokens, and accepted attestation keys. Adversarial, idempotency, clock-regression, race, and contention tests pass.
- Runtime secret resolution and master-key consistency checks fail closed on missing, corrupt, or drifting key material; no development master-key fallback is used.
- The authenticated OpenAI Chat path composes protected destinations, scoped credential injection, forbidden-header stripping, server-owned model selection, output clamps, request/attempt accounting, and deterministic response/usage relay. The conformance target uses an explicit test-only private-network exception and is not public-DNS/TLS evidence.
- A hard single-rule UTC calendar `logical_requests` quota uses reserve/execute/settle with PostgreSQL locking, idempotent lifecycle transitions, bounded expiry recovery, and contention tests. Other quota metrics and algorithms remain fail-closed.

## Open blockers and unfinished gates

- The local Phase 7 authenticated debug/mock gate passes. `latchway verify local`, a live OpenRouter canary, and production target/DNS/TLS deployment evidence remain open.
- Only the bounded single hard calendar request-count quota is executable. Atomic multi-rule plans, token buckets, per-request limits, concurrency leases, token/cost settlement, pricing provenance, quota snapshots, user overrides, and retry-cost accounting remain open.
- Apple App Attest, Play Integrity, and other native production attestation verification are not implemented in the server. The validated debug provider is test/development evidence only.
- Complete Admin API/dashboard/CLI resources, telemetry, the remaining durable jobs, current-image deployment smoke tests, and operational recovery gates remain.
- The refresh contract still advertises optional fresh identity and attestation inputs, while the server safely requires a new challenge for step-up because refresh has no fresh server binding. That mismatch requires an explicit contract/version decision before release; unsafe acceptance is not implemented.
- The cross-repository server conformance matrix must be rerun at the synchronized contract locks before compatibility can be reported.
- Official Android SDK/Gradle validation requires a configured Android SDK/`ANDROID_HOME` and the required license terms accepted by the user; automation will not accept legal agreements on the user’s behalf.
- React Native iOS podspec/native-consumer validation requires CocoaPods; `pod` is unavailable in the current environment.
- Physical App Attest and Play Integrity conformance, a live OpenRouter canary, cloud smoke tests, registry publishing, signing, tags, and release artifacts require external accounts or credentials.
- Root private security-reporting configuration still needs verification before a public release.

None of the external credential blockers prevents fixture-based implementation, local security tests, documentation, or reproducibility work.

## Next executable task

Implement and test atomic multi-rule hard calendar request-count reservations across overlapping trusted scopes, with capability-gated activation, deterministic rule/lock ordering, atomic denial, idempotent settlement/release/recovery, and high-contention PostgreSQL proof. Then add token/output reservation and usage-based settlement.
