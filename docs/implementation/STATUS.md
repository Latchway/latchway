# Implementation status

## Current phase

The core repository has committed and locally validated the governance and draft-contract foundation, runnable Go/PostgreSQL/embedded-console foundation, one-time administrative bootstrap and tenant slice, immutable configuration revisions, identity verification, signed debug attestation, and the Phase 6 RFC 9449 DPoP session vertical slice. That local session slice now covers identity verification, challenge/exchange, DPoP-bound access and rotating refresh tokens, replay enforcement, JWKS publication, protected authorization, and the public `DELETE /client/v1/installations/current` revocation gate.

JavaScript, iOS, Android, and React Native source implementations are committed in their own repositories. Their contract locks now identify the current validated core revision and bundle. Lock synchronization is bookkeeping evidence, not a compatibility result; live current-core conformance is still required.

This is not a functional or releasable end-to-end gateway yet. Authenticated proxy composition, quota reserve/execute/settle, native attestation verification, broader protocols/routing, complete administration and operations, current deployment proof, cross-repository conformance, and release evidence remain open.

## Current objective

Deliver the first authenticated debug-attested request through the deterministic mock upstream, then implement quota reservation and settlement. Run the affected SDK conformance gates against the selected core image before making any compatibility claim.

## Last passing commit in each repository

The table names the current immutable evidence commit in each repository. For lock-only SDK commits, the row separately identifies the parent implementation revision whose source gates passed. None of these entries means released, published, physically attested, or cross-repository compatible with the current core.

| Repository | Revision | Evidence |
| --- | --- | --- |
| `latchway` | `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` | Full normal and race Go suites, full PostgreSQL suite, focused PostgreSQL race and 20 repeated revocation-contention gates, vet, six fuzz targets, contract validation and deterministic bundle proof, and the complete `make check` gate |
| `latchway-js` | `8df68931730bad05ef110fe53e09d857b5bd61f8` | Current core commit/bundle lock synchronized; local source/package gates passed at parent implementation commit `273925d73a5a959f95664b1b1d838505dcce5f6c`; live current-core conformance remains |
| `latchway-ios-sdk` | `fd670a04004787901bb19b3ab762f4d2dc050a07` | Current core commit/bundle lock synchronized; local Swift/fixture gates passed at parent implementation commit `2972f99c59b652722a586510a9c943ac57a69a5c`; physical App Attest proof is not claimed |
| `latchway-android` | `cd96781426831f464fc1e5350094aab91ca11dd2` | Current core commit/bundle lock synchronized; local static/JVM gates passed at parent implementation commit `0042a916580d14295bd944104aae6deb2ac136c5`; official Android SDK/Gradle validation remains toolchain-blocked |
| `latchway-react-native-sdk` | `bf1d5e9319c859edc215677e6c02b7d0f91cc811` | Current core commit/bundle lock synchronized; local source gates passed at parent implementation commit `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0`; CocoaPods/native-consumer and device conformance remain open |

## Protocol contract version

Contract `0.1.0`; wire protocol `1`; status `draft`.

Current validated core implementation revision: `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e`.

Deterministic bundle SHA-256: `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.

Two independent builds of the current bundle were byte-identical. The bundle is local validation evidence only and has not been published. Every SDK `contract.lock` now pins core revision `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` and bundle `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`. Lock equality alone does not prove compatibility; affected shared-vector and live server conformance must still pass.

## Database schema version

`7`. Fresh isolated schemas migrate through all seven forward-only migrations, including the fail-closed identity-provider identifier-bounds migration. PostgreSQL 15 or newer remains the compatibility floor.

## Last full test date

2026-08-27 (Asia/Ho_Chi_Minh). This is local implementation evidence, not cross-repository release evidence.

## Passing evidence

- `go test ./... -count=1` — the full normal Go suite passed.
- `go test -race ./... -count=1` — the full Go suite passed under the race detector.
- The full PostgreSQL integration set passed against fresh schemas; the focused session revocation race gate and 20 repeated contention runs also passed.
- `go vet ./...` — passed.
- `python3 scripts/validate-contracts.py` — OpenAPI structure/references, registry parity, schemas/examples, attestation hashes, and DPoP signatures/semantics passed.
- Two independent contract-bundle builds were byte-identical at SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.
- All six security-sensitive fuzz targets passed their smoke gates: canonical attestation binding, DPoP validation, public-JWK parsing, HTU normalization, access-token preflight, and protected credential-header parsing.
- The complete `make check` gate passed, including formatting, reproducible sqlc output, vet, Go tests, frozen console dependency installation, lint/typecheck/tests, build, and embedded-asset checks.
- A fresh local OCI build for `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` completed at image ID `sha256:c0dcae33d48658d41557fbf6a7886beec53a0c4a14f2322d77da179e303a32e0` and declares non-root runtime user `65532`; no registry digest or current Compose smoke is claimed.
- The SDK lock-sync commits are clean and identify the current core revision and bundle. Earlier repository-specific local source gates remain recorded separately; hardware attestation, published dependency resolution, and live current-core conformance are not included in the lock-sync evidence.

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
- Protected outbound destinations, header filtering, and a deterministic mock upstream are implemented, but they are not yet composed into an authenticated client proxy path.

## Open blockers and unfinished gates

- Phase 7 authenticated proxy composition is not implemented. No client request has yet traversed the complete protected session-to-upstream path.
- Quota reserve/execute/settle, pricing provenance, expanded protocol adapters/routing, and fallback policy remain open.
- Apple App Attest, Play Integrity, and other native production attestation verification are not implemented in the server. The validated debug provider is test/development evidence only.
- Complete Admin API/dashboard/CLI resources, telemetry, durable jobs, current-image deployment smoke tests, and operational recovery gates remain.
- The refresh contract still advertises optional fresh identity and attestation inputs, while the server safely requires a new challenge for step-up because refresh has no fresh server binding. That mismatch requires an explicit contract/version decision before release; unsafe acceptance is not implemented.
- The cross-repository server conformance matrix must be rerun at the synchronized contract locks before compatibility can be reported.
- Official Android SDK/Gradle validation requires a configured Android SDK/`ANDROID_HOME` and the required license terms accepted by the user; automation will not accept legal agreements on the user’s behalf.
- React Native iOS podspec/native-consumer validation requires CocoaPods; `pod` is unavailable in the current environment.
- Physical App Attest and Play Integrity conformance, a live OpenRouter canary, cloud smoke tests, registry publishing, signing, tags, and release artifacts require external accounts or credentials.
- Root private security-reporting configuration still needs verification before a public release.

None of the external credential blockers prevents fixture-based implementation, local security tests, documentation, or reproducibility work.

## Next executable task

Implement and test the authenticated Phase 7 proxy path through the deterministic mock upstream using the committed active-configuration, identity, debug-attestation, DPoP session, and protected authorization boundaries. Then add quota reserve/execute/settle before broadening adapters and routing.
