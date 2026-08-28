# Fly.io

Run Fly from the repository root so the root Dockerfile and complete build
context are available. Replace the globally unique `app` value and choose a
region near the PostgreSQL primary.

Create or attach a PostgreSQL 15+ cluster. Fly commonly installs its URL as
`DATABASE_URL`, which Latchway accepts; production URLs must require TLS.

```bash
fly postgres create --name replace-latchway-db --region sin
fly postgres attach replace-latchway-db --app replace-with-your-latchway-app
```

Set the remaining values interactively. The public origin is the final HTTPS
origin with no path, query, or fragment. Generate the master key once, escrow
it outside Fly, and do not replace it as a shortcut for key rotation.

```bash
fly secrets set --app replace-with-your-latchway-app LATCHWAY_MASTER_KEY
fly secrets set --app replace-with-your-latchway-app LATCHWAY_PUBLIC_ORIGIN
fly secrets set --app replace-with-your-latchway-app LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
```

Deploy a verified release source checkout or set `[build].image` to a verified
release digest:

```bash
fly config validate --config deploy/fly/fly.toml
fly deploy --config deploy/fly/fly.toml
```

The release command applies forward migrations once before the rolling
deployment. Two 2 vCPU / 2 GiB Machines run the combined API/worker role; the
database-backed worker leases are multi-replica safe. With the default 20
connections per Machine, reserve at least 40 application connections plus
operational headroom.

After creating the first administrator, remove the bootstrap token:

```bash
fly secrets unset --app replace-with-your-latchway-app LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
```

Fly's proxy can carry streaming responses, but clients should reconnect and
the upstream should emit periodic SSE events. Monitor `/readyz` during rollout.
Use `fly releases` and `fly deploy --image IMAGE@sha256:DIGEST` to roll the
application back; a schema rollback requires a tested database restore.
