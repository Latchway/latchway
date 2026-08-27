# ADR 0007: Reserve, execute and settle quotas

## Context

Counting only after an upstream request permits concurrent overspend, while holding a database transaction during streaming harms reliability. Actual tokens and cost are often unknown before execution.

## Decision

Use three stages. A short transaction estimates usage, locks/updates all applicable buckets deterministically, reserves capacity and acquires concurrency leases. The upstream executes with no open database transaction. A second transaction settles actual/estimated usage and releases unused reservation; failure paths release or allow bounded expiry recovery. Operations are idempotent.

## Alternatives

- Post-charge only: cannot enforce hard limits under concurrency.
- Hold locks through the request: serializes latency and leaks resources during streams.
- Distributed approximate counters: incompatible with hard no-overspend guarantees.

## Consequences

Each adapter needs conservative estimates, settlement provenance and failure handling. Workers reclaim abandoned reservations. Retry attempts and logical requests have separate accounting.

## Security implications

Checked arithmetic, non-negative constraints, deterministic lock order and unique settlement operations prevent overflow, deadlock-driven abuse, double release and double settlement. Hard cost caps fail closed without trusted pricing.

## Migration implications

New metrics register reservation/settlement semantics before activation. Schema changes must preserve in-flight reservation recovery and idempotency during rolling upgrades.

## Status

Accepted for version 1 on 2026-08-27.
