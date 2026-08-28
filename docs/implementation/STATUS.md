# Implementation status

## Local working-tree update — challenge-bound reauthentication (2026-08-29)

The draft refresh contract now matches the server's fail-closed behavior:
session refresh accepts exactly the rotating `refresh_token`, with the endpoint
protected by a fresh DPoP proof. Optional identity and attestation refresh
fields have been removed because refresh has no new server challenge to bind
that evidence. Identity reauthentication, stale attestation, and attestation
step-up clear the old SDK session and start a new challenge and exchange.
ADR 0020 records why this pre-release correction remains contract `0.5.0` and
wire protocol `1`. Focused server and JavaScript tests pass; complete cross-SDK
and live-server conformance remains required before release.

## Local working-tree update — production input/total token quota shapes (2026-08-29)

The trusted exact-model OpenAI Chat preflight now activates hard
`input_tokens` and `total_tokens` limits for all three enforceable algorithms:
UTC calendar, rolling token bucket, and per request. Every applicable rule for
one metric reserves the same server-owned bound, and total remains the checked
sum of the trusted input bound and exact server-applied output bound. Other
protocols, routes, models, body shapes, and accounting methods continue to fail
closed before provider dispatch.

Input/total token buckets reuse the atomic fixed-point lifecycle: contention
cannot overspend, known successful usage refunds only unused units, and
unknown, failed, or provider-over-bound outcomes retain the conservative
debit. A trusted bound above a token-bucket capacity or per-request maximum is
recorded as a durable, exact-replay-stable quota denial before any bucket,
reservation, or attempt is created. Retries reserve fresh proof-bound units,
and an impossible retry is rejected before another attempt is materialized.
Read-only snapshots project pristine and populated token buckets plus stateless
per-request maxima. The authenticated PostgreSQL data-plane proof combines the
new shapes with nonzero configured input pricing. The PostgreSQL-enabled full
normal and race suites, full vet, contract validation, and all ten five-second
fuzz-smoke targets pass in the shared local working tree. This changes no client
wire shape, database schema, contract bundle, or SDK lock and is not
release-readiness evidence.

## Local working-tree update — web and cross-platform attestation configuration (2026-08-29)

The uncommitted working tree now has typed, fail-closed configuration and
active-snapshot validation for Firebase App Check on iOS, Android, React
Native iOS/Android, and web, plus Cloudflare Turnstile on web. Firebase pins a
strict positive decimal project number and a bounded unique app-ID allow-list
without a secret reference. Turnstile pins bounded unique canonical hostnames
and an exact action and requires a server-side secret reference while enabled.
Provider/platform/configuration coexistence and trust capabilities are checked
both during validation and again when an active snapshot is loaded.

Every enabled web selection now requires a bounded allow-list of exact
canonical HTTPS browser Origin serializations, shared with request-time CORS
and authorization parsing; origins are forbidden for native, Node, and
disabled selections. Firebase is capped at `app_verified` on native platforms
and `web_risk_verified` on web, while Turnstile is capped at
`web_risk_verified` and debug at `debug`. Focused configuration normal/race
tests, configuration vet, and contract validation pass. This is local
configuration/runtime-boundary evidence, not physical-device attestation,
external-provider canary, deployment, or release evidence.

## Local working-tree update — restricted opaque HTTP (2026-08-29)

The uncommitted working tree now contains an executable restricted opaque HTTP
adapter at `/proxy/{feature}/{remainingPath...}`. It binds the path feature
exactly to the signed feature header, accepts only configured methods and
canonical segment-bound paths, buffers request bytes within the feature limit,
forwards only configured non-sensitive headers, dispatches only through protected
`generic` upstreams, applies a required per-route response limit and explicit
SSE policy, and records provider usage as unknown. Unsafe opaque methods do not
retry or fall back unless every executed route explicitly declares replay safe.

The PostgreSQL-enabled full Go suite, full vet, contract validation, focused
opaque/configuration/data-plane race tests, an opaque adapter fuzz smoke,
formatting/diff checks, and two byte-identical contract bundles at SHA-256
`2953d71bde0f2414734114400d3ad3e4c829f7f3cc195f2ea9857046d6030b9f` pass in
the shared local working tree. This closes the restricted opaque-route
implementation item locally; it is not an immutable checkpoint, SDK
conformance result, publication, or release-readiness claim.

## Current phase

The core repository has committed and locally validated the governance and draft-contract foundation, runnable Go/PostgreSQL/embedded-console foundation, one-time administrative bootstrap and tenant slice, immutable configuration revisions, identity verification, signed debug attestation, the Phase 6 RFC 9449 DPoP session slice, the first authenticated OpenAI Chat proxy vertical, tenant-scoped write-only provider-secret lifecycle, and a restricted production-grade trusted input/total-token preflight. The immutable contract-`0.4.0`/schema-`11` core checkpoint is `c9347421fac4c729f20ea87f9205c66c15fa983f`.

JavaScript, iOS, Android, and React Native now have committed contract-`0.4.0` locks and byte-exact shared fixtures pointing to that immutable core checkpoint and deterministic bundle. All four repository-local source, contract, packaging, and reproducibility gates pass. Lock equality is bookkeeping evidence only: live current-core conformance, published dependency resolution, and physical attestation remain separate open gates.

This is a functional local debug/mock vertical, not a production-ready or releasable gateway. Multi-attempt accounting, broader protocols/routing/retries, production native attestation, complete administration and operations, current deployment proof, cross-repository conformance, and release evidence remain open.

## Current objective

Complete the multi-attempt quota lifecycle and endpoint-correct protocol registry, then implement Responses, Embeddings, Anthropic Messages, restricted opaque routes, deterministic weighted/sticky routing, and configured fallback/retry semantics without replaying bodies or retrying after response commitment.

## Last passing commit in each repository

The table names the current immutable evidence commit in each repository. None of these entries means released, published, physically attested, or cross-repository compatible with the current core.

| Repository | Revision | Evidence |
| --- | --- | --- |
| `latchway` | `c9347421fac4c729f20ea87f9205c66c15fa983f` | Full PostgreSQL normal/race suites, vet, contract validation, ten fuzz targets, console gates, deterministic bundle, byte-exact generated SQL, authenticated trusted-preflight E2E, and independent P0-P2 review pass |
| `latchway-js` | `e2d69505d0bba796ac6129e528b640dccb917b1c` | Contract `0.4.0` lock/fixtures; Node/pnpm lint, typecheck, 24 tests, build, examples, exports, package validation, and reproducibility pass |
| `latchway-ios-sdk` | `922347286157f15ad24785ac735861c6455c2e0e` | Contract `0.4.0` lock/fixtures, package/build gates, deterministic bundle, and all 49 Swift tests pass; physical App Attest proof remains open |
| `latchway-android` | `652f14e9fd1fa6b8f60bdb3c419d4d6b0f526840` | Contract `0.4.0` lock/fixtures plus hardened process-wide session/key lifecycle; all 670 Gradle test/assemble/lint tasks and 68 tests pass with no new license acceptance |
| `latchway-react-native-sdk` | `dcca2e2a9070af95bcfd4babe0cef6677487cd5c` | Contract `0.4.0` lock/fixtures; lint, typecheck, 19 tests, codegen, native boundaries, examples, build/reproducibility, podspec, and staged-package gates pass |

## Protocol contract version

Contract `0.4.0`; wire protocol `1`; status `draft` and unreleased. The contract change adds operator-owned input-accounting profiles and exact model bindings for a restricted text-only OpenAI Chat preflight without changing client session/DPoP transport semantics.

Last committed validated core implementation revision: `c9347421fac4c729f20ea87f9205c66c15fa983f`.

Current deterministic contract `0.4.0` bundle SHA-256: `39d32a2c9e4b0381ff815a40d87d75b51e4f37d6de55121b7bb0beef690c5c59`.

Two independent builds of the current bundle were byte-identical. That bundle is local validation evidence only and has not been published. Every SDK `contract.lock` pins core `c9347421fac4c729f20ea87f9205c66c15fa983f`, bundle `39d32a2c9e4b0381ff815a40d87d75b51e4f37d6de55121b7bb0beef690c5c59`, minimum server `0.4.0`, maximum tested series `0.4.x`, and wire protocol `1`. Lock equality is not behavioral compatibility.

## Database schema version

`11`. Fresh isolated schemas migrate through all eleven forward-only migrations. Migration 10 installs the validated canonical secret-name constraint and deliberately fails transactionally when invalid legacy rows require operator repair; migration 11 permits truthful `indeterminate` audit outcomes. PostgreSQL 15 or newer remains the compatibility floor.

## Last full test date

2026-08-28 (Asia/Ho_Chi_Minh). This is local implementation evidence, not cross-repository release evidence.

## Passing evidence

- `go test ./... -count=1` — the full normal Go suite passed.
- `go test -race ./... -count=1` — the full Go suite passed under the race detector at the current implementation revision.
- The full PostgreSQL integration set passed against fresh schemas; focused session revocation and user-override lock-order/coherence/concurrent-replacement races also passed.
- `go vet ./...` — passed.
- `python3 scripts/validate-contracts.py` — OpenAPI structure/references, registry parity, schemas/examples, attestation hashes, and DPoP signatures/semantics passed.
- Two independent contract-`0.4.0` bundle builds were byte-identical at SHA-256 `39d32a2c9e4b0381ff815a40d87d75b51e4f37d6de55121b7bb0beef690c5c59`; client wire protocol remains `1`, and database schema is `11`.
- `make fuzz-smoke` passed all ten security-sensitive targets at the current implementation revision, including the established attestation, DPoP, JWK, HTU, access-token, protected-header, configuration, policy, trusted-input adapter, and trusted-input configuration targets.
- The secret lifecycle proof covers one-character through 63-character canonical names, valid UTF-8 values bounded to 1 MiB of encoded bytes, authorization before body consumption, envelope encryption, no plaintext return/persistence/logging, tenant isolation, permanent tombstones, reference checks restricted to schema-defined secret-reference fields, concurrent current-version rotation, idempotent exact-ID deletion, database clock regression, runtime decryption without process-clock gating, strict CLI transport/Problem parsing/redaction, and correlated `succeeded`/`indeterminate` audit outcomes for ambiguous commits. Recovery guidance never infers that a caller's value committed from current metadata or a later conflict.
- Hard `input_tokens` and `total_tokens` UTC-calendar, rolling token-bucket, and per-request limits are executable only through the contract-`0.4.0` trusted preflight. An operator profile is bound to the exact OpenAI Chat protocol and physical model; the restricted adapter accepts bounded text-only messages, rewrites model/output fields first, and returns a proof containing its method, model, profile digest, exact rewritten-body hash/length, message count, input bound, output bound, and checked total bound. The data plane independently recomputes the framing formula and verifies/rebinds the exact body before reservation and again before target acquisition. The quota fingerprint binds the complete proof, input/total rules reserve uniform server-owned bounds, and nonzero configured input pricing can contribute to a hard cost reservation. Malicious underbounds, altered replay, same-length body replacement after reservation, overflow, rich unsupported request shapes, and provider usage above a bound all fail closed; the last case settles conservatively as unknown. Token buckets preserve atomic fixed-point contention and conservative settlement, while impossible bucket/per-request bounds become mutation-free durable denials. Independent review of the immutable calendar-only checkpoint reported no open P0-P2 findings; review of this working-tree extension remains part of consolidation.
- The user-override proof covers strict bounded documents, administrator-only environment/user scoping, user-before-environment lock order, exact no-op idempotency with a success audit on every PUT/DELETE, expired-row healing, providerless clear, attributed denied audits, and eight concurrent replacements with exactly one active row. Authorization seals either the exact override ID/plan or its absence after coherent installation/user/grant/environment locking. Access policy is always evaluated first; the override can replace only the limit plan, never route or access. Request enforcement uses that authorization-sealed selection. The repeatable-read, read-only quota snapshot revalidates the exact active override or exact absence before projecting counters, while configuration activation and rollback reject removal of any plan referenced by an active override. Corrupt or mismatched state fails closed. The bearer-token CLI requires a named environment variable, HTTPS except loopback HTTP, no redirects, bounded responses, and never prints the token. Independent review reported no open P0-P2 findings.
- The focused PostgreSQL concurrency quota suite passed five consecutive runs and under the race detector. It proves exact maximum occupancy under contention, immediate reuse, request-versus-stream applicability, stable accepted and denied replay after release, calendar-denial precedence, all settlement outcomes, pre-dispatch release, both expiry paths, terminal tamper detection, and settle-versus-expiry serialization.
- The focused PostgreSQL output-token-bucket store suite and its authenticated Chat E2E each passed three consecutive runs and under the race detector, alongside the established logical-request proof. Output reservations debit the exact adapter-applied cap; the static clamp is the minimum of the feature absolute maximum, every applicable per-request maximum, and every applicable token-bucket capacity, independent of rule order and current balance. Known successful measured output refunds only reserved-minus-actual units; equal usage avoids a bucket write and zero usage refunds in full. Failure, unknown usage, and dispatched expiry retain the full debit, while pre-dispatch release and undispatched expiry refund it. Both token metrics use exact integer refill on complete PostgreSQL-microsecond ticks, preserve exact retry timestamps beyond a `time.Duration` horizon, keep `used_units=0` and `reserved_units=0`, saturate refunds at the current capacity after a policy decrease, and emit overflow-safe public `Retry-After` advice capped at `MaxInt32` seconds. Focused proof also covers contention, stable accepted and denied replay, mixed-rule atomicity, corrupt-state rejection, conservative capacity/rate transitions, and denial before target acquisition/provider dispatch. Clean independent review reported no open P0-P2 findings.
- The focused quota-snapshot PostgreSQL suite and authenticated E2E passed normally and under the race detector. The store uses a repeatable-read, read-only transaction, obtains its time and verifies the expected active revision inside that same MVCC snapshot, batches bucket reads, and neither locks nor materializes quota state. Missing buckets project pristine state. Calendar limits expose exact maximum, used, reserved, saturating remaining, and reset; token limits project virtual exact refill with whole-unit remaining and availability-derived used rather than cumulative historical usage; per-request limits expose only their maximum; concurrency exposes active occupancy as reserved. The canonical authenticated `GET /client/v1/features/{feature}/quota` requires a DPoP proof, so authorization consumes replay state even though quota counters remain read-only. The E2E proves invalid query rejection does not consume the proof, success does not call an upstream or mutate quota/request/reservation/attempt/usage state, and proof replay is rejected. Access and limit-plan selection must remain stable across streaming facts; route-, upstream-, and model-scoped rules fail closed because the snapshot has no selected physical route. Individually unsafe JavaScript integer fields are omitted. Independent review reported no open P0-P2 findings.
- The focused hard-cost PostgreSQL suite and authenticated E2E passed normally and under the race detector. Only hard `cost_nano_usd/calendar` rules activate. Every applicable cost rule receives the same checked reservation from immutable configured pricing. Routes without trusted input preflight still require a zero input-token rate; the contract-`0.4.0` restricted Chat path adds the separately rounded trusted input bound to the request and output reservation. Known provider usage settles calculated actual cost and releases the difference, while unknown or over-bound post-dispatch usage consumes the full reservation without manufacturing a known-cost row. Predispatch release and undispatched expiry refund in full; dispatched expiry charges in full. Exact replay, zero-priced requests, mixed-rule atomicity, contention, terminal tamper rejection, expiry pricing corruption, profile/catalog substitution, and historical reservation compatibility are covered. Other cost algorithms remain gated. Independent review reported no open P0-P2 findings.
- The current console lint, typecheck, 16 tests, production build, and deterministic embedded-asset verification pass. Full Go normal/race PostgreSQL suites, vet, contract validation, formatting/diff checks, and all ten fuzz targets also pass at the immutable core checkpoint.
- The pinned sqlc `1.31.1` generator was run against a disposable input containing only `sqlc.yaml`, the eleven migrations, and canonical queries; its output is byte-exact with `internal/database/dbsql`. The broader container mount used by `make check-generated` was intentionally not granted access to the full repository.
- The PostgreSQL-backed authenticated Chat vertical passed in the full normal and race suites. It asserts exact prompt/answer relay, target-bound authority, credential/header isolation, model rewrite, an applied output maximum of 64, and calendar output reservation of 64. Each successful request settles 7 provider-reported output tokens and releases 57; after two requests the shared output bucket records 14 used tokens. Each success records five provenance-bearing rows: logical request, provider input/output/total tokens, and a dedicated configured-cost row. The shared hard-cost-capable fixture now uses a zero input-token rate so every feature can safely receive a global override; its known cost is exactly `43,235` nano-USD from the configured request fee plus separately rounded zero-input and measured-output charges. General nonzero input-cost math remains covered by focused pricing tests. The attempt and cost row retain the catalog ID, USD, exact configuration revision, and calculated confidence; the cost row additionally carries `configured_flat_rate:<attempt-id>` provenance. A mock provider cost extension is relayed but ignored for attribution. Exact opaque reservation replay leaves state unchanged, first-byte/attempt state and plaintext exclusions hold, DPoP proof replay does not redispatch, and atomic daily request denial does not mutate the non-exceeded output bucket. A second authenticated feature holds one real stream open, denies a concurrent stream with feature-scoped `concurrency_exceeded` and no time-based retry guidance before target acquisition, permits a non-stream request without materializing stream state, releases the lease on settlement, and immediately reuses capacity. Durable concurrency buckets keep `used_units` at zero, active occupancy in `reserved_units`, retained released lease rows, and no concurrency usage records.
- `api`, `worker`, and `all` process roles now compose distinct responsibilities. The bounded worker immediately and periodically expires abandoned quota reservations and removes expired DPoP replay rows; focused normal/race/vet and shutdown-error propagation gates pass. This is an initial jobs slice, not Phase 15 completion.
- A fresh local OCI build for `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` completed at image ID `sha256:c0dcae33d48658d41557fbf6a7886beec53a0c4a14f2322d77da179e303a32e0` and declares non-root runtime user `65532`; no registry digest or current Compose smoke is claimed.
- All four committed SDK locks are synchronized to contract `0.4.0`, exact core revision `c9347421fac4c729f20ea87f9205c66c15fa983f`, bundle hash `39d32a2c9e4b0381ff815a40d87d75b51e4f37d6de55121b7bb0beef690c5c59`, minimum server `0.4.0`, maximum tested series `0.4.x`, and unchanged wire protocol `1`. Hardware attestation, published dependency resolution, and live current-core conformance remain separate evidence requirements.

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
- One to 128 supported hard rules can compose atomically across canonical trusted scopes using deterministic PostgreSQL lock ordering and idempotent lifecycle transitions. Executable shapes are UTC-calendar `logical_requests`, rolling token buckets for `logical_requests` and `output_tokens`, UTC-calendar `output_tokens`, `output_tokens` per request, durable `concurrent_requests`/`concurrent_streams` leases, and the bounded UTC-calendar `cost_nano_usd` slice. One semantic request is exactly `1,000,000,000,000` integer balance quanta; an output-token token bucket debits the exact adapter-applied cap. The static output clamp is the minimum of the feature absolute maximum, all applicable per-request maxima, and all applicable token-bucket capacities, independent of rule order and current balance. Token buckets apply every complete `1us` PostgreSQL timestamp tick, preserve exact retry horizons beyond `time.Duration`, keep `used_units` and `reserved_units` at zero, return positive retry guidance on denial, and report zero calendar reset for token-only decisions. Accepted replay is stable and denied replay is mutation-free with advisory retry recomputation. For output tokens, a known successful measurement refunds only unused units; equal usage avoids a bucket write and zero usage refunds in full. Failures, unknown usage, and dispatched expiry retain the full debit, while pre-dispatch release and undispatched expiry refund it. Refunds saturate at the current capacity after policy decrease without retaining stale credit, and public retry advice is overflow-safe and capped at `MaxInt32` seconds. Concurrency uses one retained audit lease per applicable rule, counts active occupancy only in `reserved_units`, releases without consuming `used_units`, and omits stream capacity entirely for trusted non-stream requests. Cost reservations use checked integer nano-USD from a configured request fee plus the exact output cap at its configured rate; known usage settles actual cost, unknown post-dispatch usage charges the reservation, and undispatched paths refund. Every applicable cost rule receives the same reservation and binds its catalog independently for expiry recovery. Usage rows retain exact reported, calculated, or unknown provenance; concurrency produces no occupancy usage row, and unknown cost produces no false billing row. Per-request-only and non-applicable stream policies use a durable entryless request/reservation/attempt lifecycle without creating capacity buckets. Unsupported metrics, algorithms, and soft limits remain fail-closed.
- Hard UTC-calendar, rolling token-bucket, and per-request `input_tokens` and `total_tokens` execute only when a post-route, exact-model accounting profile and the restricted text-only Chat adapter produce a conservative proof over the exact rewritten body. Unsupported protocols, models, body shapes, profile substitutions, and unbound or inconsistent token values fail before provider dispatch. Bounds above a per-request maximum or token-bucket capacity are quota denials with no provider attempt.
- Authenticated quota snapshots reuse the same canonical rule/scope identities as reservation and bind policy projection to one sealed authorization, one logical identity, and one database revision/time snapshot. Only supported hard OpenAI Chat plans whose access and limit-plan decisions are stable across streaming facts are projected. Physical route/upstream/model scopes fail closed. The quota-state transaction is read-only, while RFC 9449 authorization still consumes DPoP replay state as required.
- User-specific limit-plan overrides are administrator-owned, environment-scoped, capability-gated, strictly bounded, auditable, and server-selected. Session authorization seals an exact override or exact absence under a coherent lock order; policy always evaluates access first and never allows an override to select a route. Request enforcement uses the sealed selection, the read-only quota snapshot revalidates it before projection, configuration transitions cannot strand an active override, and every successful or denied Admin mutation is attributed without storing credentials or provider subjects.
- Immutable USD pricing catalogs are compiled into the active snapshot and selected with the exact configuration revision before reservation. RFC 3339 `effectiveAt` instants retain activation precision beyond `time.Time` nanoseconds and cannot activate early. Known usage on successful or failed attempts produces the exact separately rounded integer charge; an explicit zero is durable, while unknown usage or arithmetic overflow preserves catalog/revision/currency metadata with unknown confidence and creates no false zero-cost row. Provider-reported price extensions are not trusted. Hard UTC-calendar cost limits may include nonzero configured input-token pricing only on an exact trusted-preflight route; otherwise the prior zero-input-rate restriction remains fail-closed. Other cost algorithms, upstream-reported pricing, and retry-cost accounting remain inactive.

## Open blockers and unfinished gates

- The local Phase 7 authenticated debug/mock gate passes. `latchway verify local`, a live OpenRouter canary, and production target/DNS/TLS deployment evidence remain open.
- Hard calendar request/input/output/total/cost rules, bounded rolling request/input/output/total token buckets, per-request input/output/total bounds, durable request/stream concurrency leases, configured integer nano-USD attribution, supported context-stable quota snapshots, and bounded user limit-plan overrides are executable within their recorded capability gates. Input/total activation and nonzero input-priced hard cost require the restricted exact-model trusted preflight. Other cost algorithms, upstream-reported pricing, and the remaining multi-attempt/retry-cost work remain open.
- Schema version 9 has one bounded recovery limitation: if a per-request-only entryless attempt expires, the worker cannot reconstruct the adapter-applied cap and therefore cannot add an unknown-output usage row. No durable capacity exists to recover or mutate for that rule shape; normal known settlement persists provider usage.
- Apple App Attest, Play Integrity, and other native production attestation verification are not implemented in the server. The validated debug provider is test/development evidence only.
- The override Admin API and CLI slice is implemented, but broader Admin API/dashboard/CLI resources, telemetry, the remaining durable jobs, current-image deployment smoke tests, and operational recovery gates remain.
- Session refresh is intentionally credential-rotation-only. Identity
  reauthentication and attestation renewal or step-up require a new bound
  challenge and exchange as recorded in ADR 0020.
- The cross-repository server conformance matrix must be rerun at the synchronized contract locks before compatibility can be reported.
- Android core JVM tests and lint pass with the installed API 37 SDK. Any additional SDK components or license-bound tooling must be installed and accepted explicitly by the user; automation will not accept legal agreements on the user’s behalf.
- React Native podspec syntax passes, but native-consumer validation still depends on synchronized publishable iOS/Android artifacts and the required consumer toolchains.
- Physical App Attest and Play Integrity conformance, a live OpenRouter canary, cloud smoke tests, registry publishing, signing, tags, and release artifacts require external accounts or credentials.
- Root private security-reporting configuration still needs verification before a public release.

None of the external credential blockers prevents fixture-based implementation, local security tests, documentation, or reproducibility work.

## Next executable task

Complete the durable multi-attempt lifecycle and endpoint-correct protocol registry, then add the remaining protocol adapters and deterministic fallback/retry executor. Preserve one logical-request charge, account every dispatched attempt and billed cost, use fresh per-attempt credentials, and never retry after response bytes reach the client.
