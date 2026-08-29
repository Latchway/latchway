# ADR 0007: Reserve, execute and settle quotas

## Context

Counting only after an upstream request permits concurrent overspend, while holding a database transaction during streaming harms reliability. Actual tokens and cost are often unknown before execution.

## Decision

Use three stages. A short transaction estimates usage, locks/updates all applicable buckets deterministically, reserves capacity and acquires concurrency leases. The upstream executes with no open database transaction. A second transaction settles actual/estimated usage and releases unused reservation; failure paths release or allow bounded expiry recovery. Operations are idempotent.

Calendar rules use a server-configured IANA timezone, defaulting to UTC. Minute
and hour windows are fixed elapsed-time buckets anchored at local
1970-01-01 midnight, so a daylight-saving fold cannot merge two repeated wall
hours. Day, week, and month windows use local civil boundaries; weeks begin on
Monday. Consequently, a day or week that crosses a daylight-saving transition
may contain 23/25 or 167/169 elapsed hours. The canonical rule identity includes
the exact configured timezone for non-UTC rules, and the bucket key includes
both that timezone and the boundary's UTC instant. Omitted and explicit UTC
preserve the pre-timezone rule digest and `utc:v1` bucket-key serialization.

## Alternatives

- Post-charge only: cannot enforce hard limits under concurrency.
- Hold locks through the request: serializes latency and leaks resources during streams.
- Distributed approximate counters: incompatible with hard no-overspend guarantees.

## Consequences

Each adapter needs conservative estimates, settlement provenance and failure handling. Workers reclaim abandoned reservations. Retry attempts and logical requests have separate accounting.

## Security implications

Checked arithmetic, non-negative constraints, deterministic lock order and unique settlement operations prevent overflow, deadlock-driven abuse, double release and double settlement. Calendar boundaries use only the active server-owned rule; client timestamps and timezone headers cannot select a bucket. Unknown, malformed, local-process, and unavailable timezone identifiers fail closed. Hard cost caps fail closed without trusted pricing.

## Migration implications

New metrics register reservation/settlement semantics before activation. Schema changes must preserve in-flight reservation recovery and idempotency during rolling upgrades.

## Status

Accepted for version 1 on 2026-08-27.
