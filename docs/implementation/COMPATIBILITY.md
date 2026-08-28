# Protocol compatibility

## Current contract

| Field | Value |
| --- | --- |
| Contract version | `0.3.0` |
| Wire protocol version | `1` |
| Status | Draft and unreleased; Admin secret-lifecycle contract, no compatibility promise |
| Latest immutable passing core implementation | `c56612b3d9828b3e02ca6b14a33da95afa04e006`; newer fully green secret checkpoint commit pending |
| Last synchronized SDK baseline core | `68fa1ba28a80cd3fb1e50dffdefc7de935da9f4c` (`0.2.0`; intentionally stale until checkpoint commit) |
| Current deterministic bundle SHA-256 | `ea265cfa750df8faeeaeac7bc60c04c4d907384205b5bf4d78a22a79dfc4d24c` |
| Database schema version | `11` |
| Minimum released server | None |
| Previous wire version supported | None; version 1 is the initial draft |

Contract `0.3.0` adds canonical write-only secret metadata/list/create/rotate/delete shapes to the Admin API, a normative 1 MiB valid-UTF-8 value bound, an `operation_indeterminate` Problem whose `operation_id` is required exactly for that code, and the `indeterminate` audit result. Database migrations 10 and 11 install the canonical secret-name constraint and audit outcome. Client session endpoints, headers, DPoP, attestation binding, and wire semantics do not change, so wire protocol version `1` remains current. The four SDKs still pin the last synchronized `0.2.0` baseline while the fully tested core working tree awaits its immutable checkpoint; no `0.3.0` compatibility claim exists until those locks, fixtures, and repository gates are synchronized.

Contract `0.2.0` was the preceding Admin-only user-override correction. Its historical bundle and lock evidence remains recorded below and must not be confused with the current contract.

At the latest passing core commit, the server also composes a local authenticated OpenAI Chat vertical with policy, atomic mixed request-count/output-token/cost reservation, bounded rolling token buckets for the currently supported `logical_requests` and `output_tokens` metrics, bounded hard UTC-calendar cost rules, durable request/stream concurrency leases, an exact adapter-applied output cap, protected upstream dispatch, provider-usage settlement and release, conservative stateful unknown charging, provenance-bearing usage, exact quota-store reservation replay, DPoP replay rejection, atomic daily denial without unrelated mutation, authenticated quota snapshots for supported context-stable plans, administrator-owned user limit-plan overrides, and distinct `api`/`worker`/`all` process responsibilities. One semantic request is exactly `1,000,000,000,000` integer balance quanta; an output reservation debits the exact adapter-applied cap. The static output clamp is the minimum of the feature absolute maximum, every applicable per-request maximum, and every applicable token-bucket capacity, independent of rule order and current balance. Token buckets credit every complete `1us` PostgreSQL timestamp tick, preserve exact internal retry timestamps beyond a `time.Duration` horizon, and keep `used_units=0` and `reserved_units=0`. A known successful measured output refunds only unused units; equal usage avoids a bucket write and zero usage refunds in full. Failures, unknown usage, and dispatched expiry retain the full debit; pre-dispatch release and undispatched expiry refund it. Refunds after a policy decrease saturate at the new capacity, and overflow-safe public `Retry-After` advice caps at `MaxInt32` seconds. Accepted replay is stable and denied replay is mutation-free. Per-request-only output and non-applicable stream policies retain a durable entryless lifecycle. Concurrency counts active leases in `reserved_units`, retains released audit rows, emits no occupancy usage record, and maps denial to feature-scoped `concurrency_exceeded` without time-based retry guidance. Immutable USD catalogs attribute known successful and failed attempts with `request fee + ceil(input tokens * input rate / 1,000,000) + ceil(output tokens * output rate / 1,000,000)`, rounding token classes separately. The attempt and dedicated cost record persist catalog ID, USD, exact configuration revision, and calculated confidence; the cost record additionally carries `configured_flat_rate:<attempt-id>` provenance. Explicit zero is durable; unknown usage or overflow retains selected metadata without a false cost row; exact RFC 3339 activation precision is preserved; provider cost extensions are ignored for attribution. Hard cost activates only as `cost_nano_usd/calendar` where configured request/output pricing and a zero input-token rate make the configured cap-bounded predispatch reservation exact. Known cost refunds unused capacity; unknown post-dispatch cost charges the reservation. Quota snapshots use one repeatable-read, read-only quota transaction, project missing buckets as pristine, preserve distinct calendar/token/per-request/concurrency/cost meanings, and perform no route selection or upstream call. They require stable access/plan resolution and fail closed for route-, upstream-, and model-scoped rules. DPoP authorization still consumes replay state. An override is sealed as exact presence or absence during authorization, is revalidated in the quota snapshot, replaces only limit-plan selection after access evaluation, and cannot select a route. This is bounded debug/mock evidence; input/total-token limits, other cost shapes, input-priced hard-cost routes, upstream-reported pricing, retries, the rest of the quota engine, native attestation, complete control plane, operations, deployment, and release gates are not implemented. General token-bucket support is complete only for the currently supported `logical_requests` and `output_tokens` metrics.

The bounded output-token implementation is split across quota-store commit `294c6e86c156178f583d4bbd9c1936942ece1e46`, configuration commit `4513b826be8b2cdc14dbd1186a64d20af2bf2d5a`, and dataplane/E2E commit `3f9a8496ca1ec141cc289ecd40d93c5b88862b29`, which is also the passing aggregate revision. Full PostgreSQL-enabled normal/race suites, full vet and contract validation, both changed configuration fuzz targets for 5 seconds, focused token-store and authenticated E2E count-3 repetitions and race runs, two byte-identical bundle builds at unchanged SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`, zero `api`/migration diff, and an independent clean P0-P2 review pass. These are implementation results, not a new wire, database, SDK-lock, release-readiness, native-attestation, or live-provider compatibility claim.

The quota-snapshot implementation is split across policy projection `4f8ccf55b5c6e3d2113e319fb3ab1c279b0037d1`, read-only store projection `0eb7345837865aae3fd8541d0c31a7b20946ac8d`, authenticated client transport `75d96b9e252f17e8b80640c6cd6572ffffade02b`, and dataplane/E2E aggregate `3fcc0400cc9da7def1a6ad0d54718d7f5b62674e`, which was the passing aggregate revision for that milestone. Full PostgreSQL-enabled normal/race suites, full vet and contract validation, policy fuzzing for 5 seconds, focused snapshot PostgreSQL/authenticated E2E normal and race gates, two byte-identical bundle builds at the unchanged hash, zero `api`/migration diff, and an independent clean P0-P2 review pass. No wire, database, bundle, SDK-lock, release-readiness, native-attestation, or live-provider compatibility claim changed.

The bounded hard-cost implementation is split across quota lifecycle `925cb91fa9e96e459ef476aefd2bce8822e9c224`, configuration activation/runtime compilation `5033d0db1faa15ae687b9bcde3e65b2631376950`, and data-plane/client transport plus authenticated E2E aggregate `6304b655d0e2690cbe154b4a66c4ec87966f4387`, which was the passing aggregate revision for that milestone. It adds no public wire or database-schema shape: the existing `cost_nano_usd` quota metric now projects through the existing quota response, and the store uses the existing reservation idempotency field for a hard-cost-specific catalog binding while preserving historical non-cost priced keys. Full PostgreSQL-enabled normal/race suites, full vet and contract validation, configuration/policy fuzzing, focused hard-cost PostgreSQL/authenticated E2E normal and race gates, byte-identical unchanged bundles, zero `api`/migration/generated-database diff, and an independent clean P0-P2 review pass. No contract, wire, database, bundle, SDK-lock, release-readiness, native-attestation, or live-provider compatibility claim changed.

The bounded user-limit-override implementation is split across isolated Admin contract correction `68fa1ba28a80cd3fb1e50dffdefc7de935da9f4c`, transactional runtime enforcement `6ae461a50da97ffe48d32359700ddcc3a21fd9b6`, and Admin API/CLI management plus aggregate evidence `b2fdfe330175ea8c023ce2af6d8693437010b348`, which is the latest passing core revision. The contract change is Admin-only: user operations require an environment, override reasons are bounded, clear is explicit, identity providers are plural, and override state is structured; client wire protocol remains `1`. Runtime authorization locks installation, user, grant/environment/application/organization state coherently and seals exact override presence/absence. Access remains authoritative; only the limit plan can change, and request enforcement uses that sealed selection. Read-only quota snapshots revalidate the seal in the same repeatable-read state snapshot before projecting counters, and configuration transitions reject removal of referenced plans. Admin mutations require `activate_configuration`, preserve exact tenant scope, use user-before-environment ordering, heal expiry, serialize concurrent replacements, audit every successful no-op and attributed denial, and expose strict PUT/DELETE plus a secret-safe CLI. Full PostgreSQL-enabled normal/race suites, full vet and contract validation, all eight fuzz-smoke targets, focused corruption/concurrency/denial/audit proof, the established authenticated Chat E2E remaining green, two byte-identical bundles at the new hash, and an independent clean P0-P2 review pass. Database schema remains `9`. This does not establish release readiness, live SDK compatibility, native attestation, or a minimum released pair.

Schema version 9 has a bounded recovery limitation: an expired per-request-only entryless attempt cannot reconstruct its applied cap or add an unknown-output usage row. That rule shape has no durable capacity to recover or mutate; normal known settlement persists provider usage. This limitation is not a compatibility claim or a release exception.

All four SDK repositories currently pin contract `0.2.0`, wire protocol `1`, its isolated contract commit, and its historical bundle hash. They are therefore explicitly unsynchronized with the current `0.3.0` core contract. After the core checkpoint receives an immutable revision, each SDK must pin that revision and the current bundle and pass its full repository gate; shared vectors, current-core live server conformance, published dependency resolution where applicable, and externally blocked device gates remain required before compatibility is reported.

## Required client declaration

SDKs send:

```http
X-Latchway-SDK: ios|android|javascript|react-native
X-Latchway-SDK-Version: <semantic-version>
X-Latchway-Protocol-Version: 1
X-Latchway-Feature: <configured-feature>
```

The optional `X-Latchway-Request-ID` is a client correlation hint, not an authorization input. The server preserves a safe hint and generates a safe request identifier when it is absent, ambiguous, or invalid.

## Compatibility policy

- Contract versions use Semantic Versioning for the bundle as a whole.
- Wire protocol changes are explicit in `api/protocol-version.json`; file-only clarifications do not automatically change the wire version.
- Before 1.0, coordinated breaking changes are allowed only with a new contract and explicit compatibility record.
- At server 1.0, the current wire version and at least the previous minor protocol version must be supported during the documented migration window.
- An incompatible client receives an RFC 9457 problem with `protocol_version_unsupported`, the request ID, supported versions, and safe upgrade guidance.
- Generated wire DTOs may change with the contract. Handwritten public SDK APIs remain idiomatic and must not be replaced by generated surfaces.
- A matching `contract.lock` is necessary but insufficient evidence. Compatibility also requires the affected shared-vector, fixture, live-server, packaging, and platform gates.

## Repository matrix

| Component | Intended package | Current implementation evidence | Synchronized lock commit | Remaining compatibility evidence |
| --- | --- | --- | --- | --- |
| Server and CLI | `github.com/latchway/latchway` | Current fully green working tree adds contract-`0.3.0` write-only secret lifecycle and schema 11 to the prior authenticated quota/proxy vertical; full PostgreSQL normal/race, vet, contract, eight fuzz, console, deterministic-bundle and independent review gates pass; immutable checkpoint pending | Source of truth | SDK `0.3.0` lock sync, production input/total preflight, broader protocols/routing, native attestation, live conformance, operations, deployment and release gates |
| JavaScript | `@latchway/client` | Contract verification, Node 24/pnpm 10 lint/type/build, 22 tests, examples, package validation, and reproducibility pass | `14d45bc5e343eb15f74d0fa35e7ab694b145b044` | Live current-core conformance and publication evidence |
| Swift | `Latchway` | Contract/bundle validation and all 48 Swift package tests pass | `e58426a704677f6c184b180b5512020204f1fc13` | Live current-core conformance, published dependency proof, and physical App Attest validation |
| Android | `dev.latchway:latchway-*` | Exact fixture checks, all 19 core JVM tests, and Android lint pass with the installed API 37 SDK without new license acceptance | `de458c21206c6d6732b95f503101a632969b6848` | Live current-core conformance, publication, and Play-distributed Integrity validation |
| React Native | `@latchway/react-native` | Contract, lint/type/test/codegen/native-boundary/example/build/reproducibility/podspec/package-content gates pass; 19 tests pass | `8e837d1f6f3df5686046a9a7e6b9a5b5f5cb5861` | Pinned Node/pnpm wrapper evidence, native-consumer/published-dependency gates, live current-core conformance, and physical-device validation |

## Last synchronized lock fields

Each SDK's existing lock serialization still records these historical `0.2.0` values. They are not the current core contract and must be replaced after the pending core checkpoint:

| Field | Synchronized value |
| --- | --- |
| Contract version | `0.2.0` |
| Core commit | `68fa1ba28a80cd3fb1e50dffdefc7de935da9f4c` |
| Bundle SHA-256 | `a4b320906d1bb02712451224c2111d3a673b4df24631c2f1de01ca5dfbfd0059` |
| Wire protocol | `1` |
| Declared minimum server version | `0.2.0` |
| Declared maximum tested server series | `0.2.x` |

The field name for wire protocol is repository-specific (`wire_protocol` or `wire_protocol_version`). Release-label metadata is also repository-specific and is not evidence that a server or SDK release exists. No release tag, registry publication, or minimum compatible released pair is claimed by this document.
