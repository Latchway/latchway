# Production deployment

Latchway ships one non-root OCI image for API, worker, migration, diagnostics,
and the embedded dashboard. Deploy by immutable digest and use PostgreSQL 15 or
newer as the only required external service.

Supported templates:

- `deploy/cloud-run`: Cloud Run, private Cloud SQL, Secret Manager, migration job
- `deploy/aws`: ECS/Fargate, private RDS, Secrets Manager, HTTPS ALB
- `deploy/fly`: Fly Machines, attached PostgreSQL, release-command migrations
- `deploy/cloudflare`: a streaming Worker shim around the same OCI image

## Required runtime values

`LATCHWAY_DATABASE_URL`, `LATCHWAY_MASTER_KEY`, and
`LATCHWAY_PUBLIC_ORIGIN` are mandatory. The public origin is security-sensitive
protocol input: it must exactly match the external HTTPS origin used by mobile
and web clients. `LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` is temporary and should be
removed immediately after the first administrator is created.

Start with the combined `all` role. At higher scale, API and worker replicas may
be separated with `serve --role api` and `serve --role worker`; all coordination,
quota recovery, signing rotation, and maintenance leases are PostgreSQL-backed.

## Production gate

Before accepting traffic:

1. Verify the image digest, keyless signature, provenance, and SPDX attestation.
2. Restore a recent backup into an isolated database and run `doctor` against it.
3. Run `migrate up`, then confirm `migrate status` reports current equals available.
4. Confirm `/healthz` and `/readyz`; readiness must include the worker heartbeat.
5. Exercise session exchange from each supported client platform and one real
   non-streaming plus one streaming upstream request.
6. Run the quota-contention and failure matrix, then the target load profiles.
7. Confirm logs, metrics, traces, alerts, database backups, and secret custody.

Cloud/provider account smoke tests, DNS/TLS, physical App Attest and Play
Integrity evidence, and post-publication package tests cannot be replaced by a
local build. Record those results against the exact release digest and SDK tags.

## Database pool sizing

Budget the worst case, not the steady state:

```text
maximum application connections
  = maximum API replicas × API pool size
  + maximum worker replicas × worker pool size
```

Leave at least 20% plus explicit slots for migration jobs, administration,
backup tooling, and provider maintenance. Reduce `LATCHWAY_DB_MAX_CONNECTIONS`
before raising replica limits. A connection pooler may improve efficiency, but
it does not replace a hard end-to-end connection budget.

## Timeouts and draining

Keep the platform request timeout longer than the maximum supported stream and
configure clients to reconnect. The image handles `SIGTERM`, stops accepting
new work, and drains in-flight requests for `LATCHWAY_SHUTDOWN_TIMEOUT` (30
seconds by default). Load balancer deregistration or rollout grace must be at
least that long. Never configure a proxy that buffers SSE.

See `docs/operations/upgrades.md`, `docs/operations/backup-restore.md`, and
`docs/operations/key-rotation.md` before operating a production environment.
