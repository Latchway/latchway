# ADR 0003: PostgreSQL as the only required external service

## Context

Sessions, replay prevention, quotas, jobs, configuration and audit need durable coordination across replicas. Requiring Redis, a queue and analytics stores would increase the self-hosting burden before scale justifies them.

## Decision

Support PostgreSQL 15 or newer without required extensions and use it for every durable version-1 concern. Use row locks and conditional updates for quota state, uniqueness for replay and token invariants, `FOR UPDATE SKIP LOCKED` for jobs, and `LISTEN/NOTIFY` only as a cache hint. Default Compose uses the current PostgreSQL 18 maintenance release while avoiding 18-only features.

## Alternatives

- Redis for rate limits/replay and PostgreSQL for records: lower latency but split correctness and more infrastructure.
- Kafka/ClickHouse for events/usage: powerful at scale but disproportionate to version 1.
- In-memory coordination: fails across replicas and restarts.

## Consequences

Database contention and retention require careful schema, indexes, partition/pruning strategy and load tests. PostgreSQL availability is on the request critical path for hard security invariants.

## Security implications

Fail closed when authoritative replay, revocation or hard-quota checks cannot execute. Use least privilege, TLS where appropriate, parameterized SQL, tenant ownership columns and encrypted backups.

## Developer-experience implications

A local or test deployment needs PostgreSQL but no Redis, queue or analytics service. Contributors implementing coordination must use and test the same PostgreSQL locking, uniqueness and transaction semantics that enforce production invariants, including unavailable-database behavior.

## Migration implications

Future optional accelerators must preserve PostgreSQL as source of truth or define an explicit consistency migration. Version-1 deployments need only upgrade within supported PostgreSQL majors.

## Documentation implications

Deployment guidance must state the supported PostgreSQL majors, absence of required extensions and PostgreSQL's critical-path role. Operations material must cover least privilege, TLS, backup/restore, maintenance and failure behavior without presenting another store as authoritative.

## Status

Accepted for version 1 on 2026-08-27.
