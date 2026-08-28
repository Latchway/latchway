# Cloudflare Containers

This deployment keeps authentication, attestation, routing, quota, secret,
and upstream logic in the standard Latchway OCI image. The Worker only selects
one of four container-backed Durable Objects, starts it when necessary, and
streams the HTTP request and response without buffering.

Cloudflare Containers is still a beta platform. Treat this target as a
production-candidate template until your own account has passed the smoke,
streaming, failure, and restore gates. Containers run `linux/amd64`; the root
Dockerfile is also published for `linux/arm64` on other platforms.

## Prerequisites

- Node.js 24 and pnpm 10
- Wrangler 4 authenticated to a Containers-enabled Cloudflare account
- Docker for local container builds
- a publicly reachable PostgreSQL 15+ database with TLS enforced

The four container instances are each limited to five PostgreSQL connections,
for a maximum of 20 application connections. Leave capacity for migrations,
administration, and database maintenance; adjust both values together.

## Configure and validate

```bash
cd deploy/cloudflare
pnpm install --frozen-lockfile
pnpm types:check
pnpm check
pnpm deploy:dry-run
```

Install secrets interactively. `LATCHWAY_PUBLIC_ORIGIN` must be the final HTTPS
origin users will call, with no path, query, or fragment. Generate the master
key once, store it outside Cloudflare as a recovery secret, and never rotate it
by merely replacing the environment value.

```bash
wrangler secret put LATCHWAY_DATABASE_URL
wrangler secret put LATCHWAY_MASTER_KEY
wrangler secret put LATCHWAY_PUBLIC_ORIGIN
wrangler secret put LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
```

The database URL should use `sslmode=verify-full` when the provider exposes a
trusted CA. Apply embedded forward migrations before a controlled upgrade:

```bash
docker run --rm \
  -e LATCHWAY_DATABASE_URL \
  ghcr.io/latchway/latchway@sha256:REPLACE_WITH_VERIFIED_DIGEST \
  migrate up
```

`LATCHWAY_MIGRATE_ON_START=true` is retained as a safe first-deploy fallback;
migrations use a PostgreSQL advisory lock. Mature installations should run the
explicit migration command, change it to `false`, and deploy by verified image
digest.

Deploy, create the first administrator, then remove the bootstrap token and
its entry from `secrets.required` in the same change:

```bash
pnpm deploy
wrangler secret delete LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
```

The platform-only health endpoint is
`/__latchway/cloudflare/healthz`. Use Latchway's forwarded `/healthz` for
liveness and `/readyz` for database, schema, configuration, signing-key,
master-key, and worker-heartbeat readiness.

## Rollout and rollback

The checked-in rollout advances 10%, 50%, then 100%, with 35 seconds for active
requests to drain. Verify `/readyz`, a non-streaming request, and a long-lived
SSE request at each step. `wrangler versions list` shows deployable versions;
use `wrangler rollback VERSION_ID` for application rollback. Database
migrations are forward-only, so restore a tested backup for a schema rollback.
