# Protocol compatibility

## Current contract

| Field | Value |
| --- | --- |
| Contract version | `0.1.0` |
| Wire protocol version | `1` |
| Status | Draft and unreleased; no compatibility promise |
| Latest passing core implementation | `3f9a8496ca1ec141cc289ecd40d93c5b88862b29` |
| Synchronized bundle baseline core | `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` |
| Deterministic bundle SHA-256 | `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12` |
| Database schema version | `9` |
| Minimum released server | None |
| Previous wire version supported | None; version 1 is the initial draft |

At the latest passing core commit, the server also composes a local authenticated OpenAI Chat vertical with policy, atomic mixed request-count/output-token reservation, bounded rolling token buckets for the currently supported `logical_requests` and `output_tokens` metrics, durable request/stream concurrency leases, an exact adapter-applied output cap, protected upstream dispatch, provider-usage settlement and release, conservative stateful unknown charging, provenance-bearing usage, exact quota-store reservation replay, DPoP replay rejection, atomic daily request denial without output mutation, and distinct `api`/`worker`/`all` process responsibilities. One semantic request is exactly `1,000,000,000,000` integer balance quanta; an output reservation debits the exact adapter-applied cap. The static output clamp is the minimum of the feature absolute maximum, every applicable per-request maximum, and every applicable token-bucket capacity, independent of rule order and current balance. Token buckets credit every complete `1us` PostgreSQL timestamp tick, preserve exact internal retry timestamps beyond a `time.Duration` horizon, and keep `used_units=0` and `reserved_units=0`. A known successful measured output refunds only unused units; equal usage avoids a bucket write and zero usage refunds in full. Failures, unknown usage, and dispatched expiry retain the full debit; pre-dispatch release and undispatched expiry refund it. Refunds after a policy decrease saturate at the new capacity, and overflow-safe public `Retry-After` advice caps at `MaxInt32` seconds. Accepted replay is stable and denied replay is mutation-free. Per-request-only output and non-applicable stream policies retain a durable entryless lifecycle. Concurrency counts active leases in `reserved_units`, retains released audit rows, emits no occupancy usage record, and maps denial to feature-scoped `concurrency_exceeded` without time-based retry guidance. Immutable USD catalogs attribute known successful and failed attempts with `request fee + ceil(input tokens * input rate / 1,000,000) + ceil(output tokens * output rate / 1,000,000)`, rounding token classes separately. The attempt and dedicated cost record persist catalog ID, USD, exact configuration revision, and calculated confidence; the cost record additionally carries `configured_flat_rate:<attempt-id>` provenance. Explicit zero is durable; unknown usage or overflow retains selected metadata without a false cost row; exact RFC 3339 activation precision is preserved; provider cost extensions are ignored for attribution. This is bounded debug/mock evidence; hard cost limits, quota snapshots, upstream-reported pricing, retries, the rest of the quota engine, native attestation, complete control plane, operations, deployment, and release gates are not implemented. General token-bucket support is complete only for the currently supported `logical_requests` and `output_tokens` metrics.

The bounded output-token implementation is split across quota-store commit `294c6e86c156178f583d4bbd9c1936942ece1e46`, configuration commit `4513b826be8b2cdc14dbd1186a64d20af2bf2d5a`, and dataplane/E2E commit `3f9a8496ca1ec141cc289ecd40d93c5b88862b29`, which is also the passing aggregate revision. Full PostgreSQL-enabled normal/race suites, full vet and contract validation, both changed configuration fuzz targets for 5 seconds, focused token-store and authenticated E2E count-3 repetitions and race runs, two byte-identical bundle builds at unchanged SHA-256 `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12`, zero `api`/migration diff, and an independent clean P0-P2 review pass. These are implementation results, not a new wire, database, SDK-lock, release-readiness, native-attestation, or live-provider compatibility claim.

Schema version 9 has a bounded recovery limitation: an expired per-request-only entryless attempt cannot reconstruct its applied cap or add an unknown-output usage row. That rule shape has no durable capacity to recover or mutate; normal known settlement persists provider usage. This limitation is not a compatibility claim or a release exception.

All four SDK repositories still pin the synchronized baseline core and bundle hash above, not the latest passing implementation. That synchronization proves only that the repositories identify the same draft contract artifact. It does not prove behavioral compatibility. A fresh lock decision, shared vectors, current-core live server conformance, published dependency resolution where applicable, and the externally blocked device gates must pass before compatibility is reported.

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
| Server and CLI | `github.com/latchway/latchway` | Latest local authenticated mixed-quota/configured-pricing/concurrency/token-bucket proxy evidence for the supported logical-request and output-token metrics plus full PostgreSQL-enabled normal/race, vet, contracts, both changed configuration fuzz smokes, focused token-store and authenticated E2E count-3/race runs, reproducible unchanged bundle, zero `api`/migration diff, and clean P0-P2 review at `3f9a8496ca1ec141cc289ecd40d93c5b88862b29`; earlier `make check` and local non-root OCI evidence at `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` | Source of truth | Quota snapshots and remaining quota work, hard cost limits, upstream-reported pricing/retries, native attestation, live canary/SDK conformance, operations, current Compose/registry image proof, and release gates |
| JavaScript | `@latchway/client` | Local browser/Node/package gates pass at `273925d73a5a959f95664b1b1d838505dcce5f6c` | `8df68931730bad05ef110fe53e09d857b5bd61f8` | Live current-core conformance and publication evidence |
| Swift | `Latchway` | Local Swift package, fixture, and conformance-source gates pass at `2972f99c59b652722a586510a9c943ac57a69a5c` | `fd670a04004787901bb19b3ab762f4d2dc050a07` | Live current-core conformance, published dependency proof, and physical App Attest validation |
| Android | `dev.latchway:latchway-*` | Local static tests and independent Kotlin/JVM compatibility gates pass at `0042a916580d14295bd944104aae6deb2ac136c5` | `cd96781426831f464fc1e5350094aab91ca11dd2` | Configured Android SDK/`ANDROID_HOME`, user-accepted licenses, official Gradle gates, live current-core conformance, publication, and Play-distributed validation |
| React Native | `@latchway/react-native` | Local source, type, test, code-generation, build, and native-boundary gates pass at `d730b3e4b4798f0a200caf0d0fb164ab54cfdad0` | `bf1d5e9319c859edc215677e6c02b7d0f91cc811` | CocoaPods (`pod` is absent locally), native-consumer/published-dependency gates, live current-core conformance, and physical-device validation |

## Synchronized lock fields

Each SDK's existing lock serialization now records these shared values:

| Field | Synchronized value |
| --- | --- |
| Contract version | `0.1.0` |
| Core commit | `0a03d9369c0ebcf793f00bac6b002d1caaea6b8e` |
| Bundle SHA-256 | `74fc7ada8d835d46b25f763a703b79003cdc8243d6f4b2509645e5a82367ab12` |
| Wire protocol | `1` |
| Declared minimum server version | `0.1.0` |
| Declared maximum tested server series | `0.1.x` |

The field name for wire protocol is repository-specific (`wire_protocol` or `wire_protocol_version`). Release-label metadata is also repository-specific and is not evidence that a server or SDK release exists. No release tag, registry publication, or minimum compatible released pair is claimed by this document.
