# Cloudflare Containers

This deployment keeps authentication, attestation, routing, quota, secret,
and upstream logic in the standard Latchway OCI image. The Worker only selects
one of four container-backed Durable Objects, starts it when necessary, and
streams the HTTP request and response without buffering.

Cloudflare Containers is generally available. This repository still treats
the deployment as unverified until the exact release image passes the account's
smoke, streaming, failure, and restore gates. Containers require
`linux/amd64`; the root Dockerfile also publishes `linux/arm64` for other
platforms.

## Prerequisites

- Node.js 24 and pnpm 10
- Wrangler 4 authenticated to a Containers-enabled Cloudflare account
- Docker for local container builds
- a publicly reachable PostgreSQL 15+ database with TLS enforced

The four container instances are each limited to five PostgreSQL connections,
for a maximum of 20 application connections. A one-minute Cron Trigger sends a
private health request to `instance-0`, keeping at least one `all`-role runtime
active for signing-key rotation, reservation recovery, retention, usage
rollups, and shared JWKS refresh even when user traffic is quiet. Leave
capacity for migrations, administration, and database maintenance; adjust the
instance count, pool size, and database ceiling together.

## Configure and validate

```bash
cd deploy/cloudflare
pnpm install --frozen-lockfile
pnpm types:check
pnpm check
pnpm deploy:dry-run
```

The checked-in configuration builds the repository Dockerfile so a source
checkout can be reviewed and dry-run without a registry account. A production
release must deploy the already verified `linux/amd64` release image, not
rebuild mutable source. Cloudflare Containers can pull prebuilt images from
Cloudflare Registry, Docker Hub, Amazon ECR, or Google Artifact Registry; GHCR
is not a direct source. If the canonical release is only in GHCR, copy its
verified amd64 manifest into Cloudflare Registry without rebuilding it and
verify that the source and mirror config/layer digests match.

Generate the ignored production-only configuration from an immutable mirror
digest. The generator rejects tag-only references, unsupported registries,
GHCR, a mutable Dockerfile build, and a source template that has drifted from
the reviewed shape:

```bash
pnpm release:config -- \
  --image registry.cloudflare.com/ACCOUNT/latchway@sha256:REPLACE_WITH_MIRROR_DIGEST
pnpm release:dry-run
pnpm release:deploy
```

Retain the signed multi-architecture release index digest, its verified amd64
child digest, and the content-equivalent mirror digest in deployment evidence.
The cross-repository release record continues to identify the canonical signed
release index; the platform artifact additionally proves which child and mirror
Cloudflare executed. Never use `latest` or a tag-only reference as release
evidence.

Cloudflare updates Worker code before it finishes the container rollout. Treat
deployment as asynchronous: wait for the rollout, verify the platform and
Latchway health endpoints, then exercise authenticated non-streaming and SSE
requests against the exact deployed digest before recording the target as
verified.

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

Deploy and create the first administrator. Then delete the bootstrap secret,
remove its optional declaration from `secrets.required`, regenerate types,
re-run the checks, and deploy that source change:

```bash
pnpm deploy
wrangler secret delete LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
# edit wrangler.jsonc, then:
pnpm types
pnpm check
pnpm deploy
```

The platform-only health endpoint is
`/__latchway/cloudflare/healthz`. Use Latchway's forwarded `/healthz` for
liveness and `/readyz` for database, schema, configuration, signing-key,
master-key, and worker-heartbeat readiness.

## Release evidence

Create the protected GitHub environment
`deployment-evidence-cloudflare_containers` with account-scoped
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and a random
`CLOUDFLARE_EVIDENCE_TOKEN` of 32–256 characters. Install the same evidence
token as the Worker secret `LATCHWAY_EVIDENCE_TOKEN`; it is used only to
authorize the bounded migration and graceful-stop evidence operations and is
never written to the artifact:

```bash
wrangler secret put LATCHWAY_EVIDENCE_TOKEN
```

Mirror the candidate's verified `linux/amd64` child into
`registry.cloudflare.com/ACCOUNT/latchway` without rebuilding it. Then dispatch
`.github/workflows/deployment-evidence.yml` from protected `main` with
`platform=cloudflare_containers`, the exact candidate commit, intended tag,
candidate workflow run ID, canonical GHCR index digest, public HTTPS endpoint,
and `cloudflare_mirror_image` pinned by digest.

The collector verifies the candidate attestation, hashes the canonical child
and mirror manifests, and requires identical config and ordered layer
descriptors before deploying. It then waits for the asynchronous Container
rollout, executes `/latchway --output json migrate status` inside `instance-0`
through the Durable Object Container API, confirms Worker secret names without
reading their values, sends SIGTERM through the same API, records the
provider-reported reason and exit code, and proves a newly created healthy
instance serves the same mirror digest. The signed report continues to bind the
canonical multi-architecture OCI index used by the other platforms.

## Rollout and rollback

The checked-in rollout advances 10%, 50%, then 100%. Its 35-second active grace
period makes a recently connected container ineligible for replacement until
that connection reaches the configured age; it is not a request-drain
guarantee. After Cloudflare selects an instance for replacement it sends
`SIGTERM`; the platform allows up to 15 minutes before SIGKILL, while Latchway's
own configured drain is 30 seconds. Verify `/readyz`, a
non-streaming request, and a long-lived SSE request through the rollout, and
wait for rollout completion before recording evidence. `wrangler versions
list` shows deployable versions; use `wrangler rollback VERSION_ID` for
application rollback. Database migrations are forward-only, so restore a
tested backup for a schema rollback.
