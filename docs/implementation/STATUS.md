# Implementation status

## Current phase

The core repository has committed and locally validated the governance and draft-contract foundation, runnable Go/PostgreSQL/embedded-console foundation, one-time administrative bootstrap and tenant slice, immutable configuration revisions, identity verification, signed debug attestation, the Phase 6 RFC 9449 DPoP session slice, and the first authenticated OpenAI Chat proxy vertical. Real PostgreSQL-backed tests now prove custom JWT verification, signed debug attestation, challenge/exchange, DPoP-bound authorization, immutable policy resolution, atomic mixed request-count/output-token reservation, protected upstream dispatch, model rewrite, an exact server-applied output clamp, response relay, provider-reported usage settlement, configured integer nano-USD attribution, exact quota-store reservation replay, DPoP replay rejection without a second dispatch, atomic daily request denial without output-bucket mutation, a durable stream-concurrency hold/deny/release/reuse lifecycle that rejects before target acquisition or provider dispatch, and a bounded hard `logical_requests` rolling token bucket with exact refill, denial, replay, refund, settlement, expiry, and conservative policy-transition behavior.

JavaScript, iOS, Android, and React Native source implementations are committed in their own repositories. Their contract locks identify the prior synchronized core/bundle baseline, not the newer proxy implementation commit. Lock synchronization is bookkeeping evidence, not a compatibility result; a fresh lock decision and live current-core conformance are still required.

This is a functional local debug/mock vertical, not a production-ready or releasable gateway. The remaining quota and pricing capabilities, production native attestation, broader protocols/routing, complete administration and operations, current deployment proof, cross-repository conformance, and release evidence remain open.

## Current objective

Add `output_tokens` token buckets, then quota snapshots. Keep unsupported configuration shapes, including hard cost limits, from activating until their runtime capability exists.

## Last passing commit in each repository

The table names the current immutable evidence commit in each repository. For lock-only SDK commits, the row separately identifies the parent implementation revision whose source gates passed. None of these entries means released, published, physically attested, or cross-repository compatible with the current core.

| Repository | Revision | Evidence |
| --- | --- | --- |
| `latchway` | `971e7f63a3ed2cc619ef93fd92b296caa216b6cd` | Full PostgreSQL-enabled normal and race Go suites; full vet and contract validation; configuration refill/snapshot fuzz smokes; token-bucket store and authenticated PostgreSQL E2E each repeated three times; two deterministic bundle builds at the unchanged hash; zero `api` and migration diff; clean P0-P2 implementation reviews |
| `latchway-js` | `8df68931730bad05ef110fe53e09d857b5bd61f8` | Baseline core/bundle lock synchronized; local source/package gates passed at parent implementation commit `273925d73a5a959f95664b1b1d838505dcce5f6c`; latest-core live conformance remains |
| `latchway-ios-sdk` | `fd670a04004787901bb19b3ab762f4d2dc050a07` | Baseline core/bundle lock synchronized; local Swift/fixture gates passed at parent implementation commit `2972f99c59b652722a586510a9c943ac57a69a5c`; latest-core and physical App Attest proof are not claimed |
| `latchway-android` | `cd96781426831f464fc1e5350094aab91ca11dd2` | Baseline core/bundle lock synchronized; local static/JVM gates passed at parent implementation commit `0042a916580d14295bd944104aae6deb2ac136c5`; official Android SDK/Gradle validation remains toolchain-blocked |
| `latchway-react-native-sdk` | `bf1d5e9319c859edc215677e6c02b7d0f91cc811` | Baseline core/bundle lock synchronized; local source gates passed at parent implementation commit `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0`; latest-core, CocoaPods/native-consumer and device conformance remain open |

## Protocol contract version

Contract `0.1.0`; wire protocol `1`; status `draft`.

Current validated core implementation revision: `971e7f63a3ed2cc619ef93fd92b296caa216b6cd` (quota store `c57aed5`, configuration activation `89f4489`, dataplane/E2E `971e7f6`).

Deterministic bundle SHA-256: `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`.

Two independent builds of the most recently reproduced bundle were byte-identical. That bundle is local validation evidence only and has not been published. Every SDK `contract.lock` still pins the synchronized baseline core revision `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` and bundle `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`; no SDK lock or compatibility claim has been advanced to `971e7f63a3ed2cc619ef93fd92b296caa216b6cd`. Lock equality alone does not prove compatibility.

## Database schema version

`9`. Fresh isolated schemas migrate through all nine forward-only migrations, including durable quota request identity and logical-request fingerprint hardening. PostgreSQL 15 or newer remains the compatibility floor.

## Last full test date

2026-08-28 (Asia/Ho_Chi_Minh). This is local implementation evidence, not cross-repository release evidence.

## Passing evidence

- `go test ./... -count=1` — the full normal Go suite passed.
- `go test -race ./... -count=1` — the full Go suite passed under the race detector at the current implementation revision.
- The full PostgreSQL integration set passed against fresh schemas; the focused session revocation race gate and 20 repeated contention runs also passed.
- `go vet ./...` — passed.
- `python3 scripts/validate-contracts.py` — OpenAPI structure/references, registry parity, schemas/examples, attestation hashes, and DPoP signatures/semantics passed.
- Two independent contract-bundle builds were byte-identical at SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`; `api` and the nine migrations have zero diff from the preceding milestone.
- The changed configuration fuzz targets for exact refill-rate canonicalization and active-snapshot compilation passed at the current implementation revision. The six established security-sensitive fuzz-target smoke gates remain recorded at the synchronized `0a03d936` baseline: canonical attestation binding, DPoP validation, public-JWK parsing, HTU normalization, access-token preflight, and protected credential-header parsing.
- The focused PostgreSQL concurrency quota suite passed five consecutive runs and under the race detector. It proves exact maximum occupancy under contention, immediate reuse, request-versus-stream applicability, stable accepted and denied replay after release, calendar-denial precedence, all settlement outcomes, pre-dispatch release, both expiry paths, terminal tamper detection, and settle-versus-expiry serialization.
- The focused PostgreSQL logical-request token-bucket store suite and its authenticated Chat E2E each passed three consecutive runs. The store proof covers exact integer refill and saturation on complete PostgreSQL-microsecond ticks, contention at capacity, accepted and denied replay, pre-dispatch and undispatched-expiry refunds, debit retention after dispatch/settlement/dispatched expiry, mixed-rule atomicity, corrupt-state rejection, positive retry timing, and conservative capacity/rate transitions. The authenticated proof exhausts a real configured rolling bucket before target acquisition/provider dispatch, replays the durable denial without dispatch, backdates only the durable refill cursor by the exact refill interval, and then succeeds after exact refill. Clean independent reviews reported no open P0-P2 findings.
- The complete `make check` gate remains recorded at the synchronized `0a03d936` baseline, including formatting, reproducible sqlc output, vet, Go tests, frozen console dependency installation, lint/typecheck/tests, build, and embedded-asset checks.
- The PostgreSQL-backed authenticated Chat vertical passed with count `3` and under the race detector. It asserts exact prompt/answer relay, target-bound authority, credential/header isolation, model rewrite, an applied output maximum of 64, and calendar output reservation of 64. Each successful request settles 7 provider-reported output tokens and releases 57; after two requests the shared output bucket records 14 used tokens. Each success records five provenance-bearing rows: logical request, provider input/output/total tokens, and a dedicated configured-cost row. The known cost is exactly `65,236` nano-USD from `request fee + ceil(input tokens * input rate / 1,000,000) + ceil(output tokens * output rate / 1,000,000)`, with the token classes rounded separately. The attempt and cost row retain the catalog ID, USD, exact configuration revision, and calculated confidence; the cost row additionally carries `configured_flat_rate:<attempt-id>` provenance. A mock provider cost extension is relayed but ignored for attribution. Exact opaque reservation replay leaves state unchanged, first-byte/attempt state and plaintext exclusions hold, DPoP proof replay does not redispatch, and atomic daily request denial does not mutate the non-exceeded output bucket. A second authenticated feature holds one real stream open, denies a concurrent stream with feature-scoped `concurrency_exceeded` and no time-based retry guidance before target acquisition, permits a non-stream request without materializing stream state, releases the lease on settlement, and immediately reuses capacity. Durable concurrency buckets keep `used_units` at zero, active occupancy in `reserved_units`, retained released lease rows, and no concurrency usage records.
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
- One to 128 supported hard rules can compose atomically across canonical trusted scopes using deterministic PostgreSQL lock ordering and idempotent lifecycle transitions. Executable shapes are UTC-calendar `logical_requests`, a rolling `logical_requests` token bucket, UTC-calendar `output_tokens`, `output_tokens` per request, and durable `concurrent_requests`/`concurrent_streams` leases. The request token bucket stores one semantic request as exactly `1,000,000,000,000` integer balance quanta, applies every complete `1us` PostgreSQL timestamp tick, accepts capacities from 1 through `9,223,372`, and accepts refill rates from `0.000001` through `1,000,000` requests/second only when exactly representable with at most six decimal places. It keeps calendar counters `used_units` and `reserved_units` at zero, debits one semantic unit in a rolling bucket and reservation entry, returns a positive `Retry-After` on denial, and reports zero calendar reset for token-only decisions. Accepted replay is stable; denied replay is mutation-free with advisory retry recomputation. Pre-dispatch release and undispatched expiry refund the debit, while any begun attempt, settlement, or dispatched expiry retains it. Refunds saturate at capacity without stale refill credit, and a policy change conservatively uses the lower old/new capacity and rate for the unprocessed interval before rebasing, so it cannot grant an increase windfall. Output reservations use the exact adapter-applied cap; known provider output settles to measured usage and releases the difference, while unknown post-dispatch outcomes, failures, and stateful reservation expiry conservatively charge the reserved output. Concurrency uses one retained audit lease per applicable rule, counts active occupancy only in `reserved_units`, releases without consuming `used_units`, and omits stream capacity entirely for trusted non-stream requests. Usage rows retain exact reported, calculated, or unknown provenance; concurrency produces no occupancy usage row. Per-request-only and non-applicable stream policies use a durable entryless request/reservation/attempt lifecycle without creating capacity buckets. Unsupported metrics, algorithms, and soft limits remain fail-closed.
- Immutable USD pricing catalogs are compiled into the active snapshot and selected with the exact configuration revision before reservation. RFC 3339 `effectiveAt` instants retain activation precision beyond `time.Time` nanoseconds and cannot activate early. Known usage on successful or failed attempts produces the exact separately rounded integer charge; an explicit zero is durable, while unknown usage or arithmetic overflow preserves catalog/revision/currency metadata with unknown confidence and creates no false zero-cost row. Provider-reported price extensions are not trusted. Hard cost limits and upstream-reported pricing remain inactive.

## Open blockers and unfinished gates

- The local Phase 7 authenticated debug/mock gate passes. `latchway verify local`, a live OpenRouter canary, and production target/DNS/TLS deployment evidence remain open.
- Hard calendar and rolling-token-bucket request-count rules, calendar/per-request output-token rules, durable request/stream concurrency leases, and configured integer nano-USD attribution are executable. `output_tokens/token_bucket`, hard cost limits, input/total-token limits, quota snapshots, user overrides, upstream-reported pricing, and retry/cost accounting remain open; this milestone does not claim general token-bucket support.
- Schema version 9 has one bounded recovery limitation: if a per-request-only entryless attempt expires, the worker cannot reconstruct the adapter-applied cap and therefore cannot add an unknown-output usage row. No durable capacity exists to recover or mutate for that rule shape; normal known settlement persists provider usage.
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

Implement `output_tokens` token buckets, then quota snapshots. Hard cost limits remain capability-gated.
