# Fly.io

Run Fly from the repository root so the root Dockerfile and complete build
context are available. Replace the globally unique `app` value and choose a
region near the PostgreSQL primary.

Create or attach a PostgreSQL 15+ cluster. Fly commonly installs its URL as
`DATABASE_URL`, which Latchway accepts; production URLs must require TLS.

```bash
flyctl postgres create --name replace-latchway-db --region sin
flyctl postgres attach replace-latchway-db --app replace-with-your-latchway-app \
  --variable-name LATCHWAY_DATABASE_URL
```

Set the remaining values interactively. The public origin is the final HTTPS
origin with no path, query, or fragment. Generate the master key once, escrow
it outside Fly, and do not replace it as a shortcut for key rotation.

```bash
flyctl secrets set --app replace-with-your-latchway-app LATCHWAY_MASTER_KEY
flyctl secrets set --app replace-with-your-latchway-app LATCHWAY_PUBLIC_ORIGIN
flyctl secrets set --app replace-with-your-latchway-app LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
```

For a release deployment, bypass the Dockerfile build and deploy the public
release image by immutable digest. This makes the release command and every
application Machine use the same released image:

```bash
export LATCHWAY_IMAGE='ghcr.io/latchway/latchway@sha256:<64 lowercase hex>'
export FLY_APP='replace-with-your-latchway-app'
flyctl config validate --strict --app "$FLY_APP" --config deploy/fly/fly.toml
flyctl deploy --app replace-with-your-latchway-app \
  --config deploy/fly/fly.toml \
  --image "$LATCHWAY_IMAGE" \
  --wait-timeout 10m
```

The release command applies forward migrations once before the rolling
deployment. Two 2 vCPU / 2 GiB Machines run the combined API/worker role; the
database-backed worker leases are multi-replica safe. Each Machine has an
aggregate ceiling of 20 connections: five are completion-reserved inside that
total and 15 serve regular work. Two Machines therefore reserve 40 application
connections, not 50. Add migration, administration, backup, maintenance, and
rollout demand, then keep the planned peak at or below 80% of usable PostgreSQL
connections for 20% headroom.
The rolling strategy permits at most one unavailable Machine. Fly sends
SIGTERM, waits 35 seconds before forcing the Machine down, and Latchway drains
for 30 seconds.

After creating the first administrator, remove the bootstrap token:

```bash
flyctl secrets unset --app replace-with-your-latchway-app LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
```

Fly's proxy can carry streaming responses, but clients should reconnect and
the upstream should emit periodic SSE events. Monitor `/readyz` during rollout.
Use `flyctl releases` and `flyctl deploy --image IMAGE@sha256:DIGEST` to roll the
application back; a schema rollback requires a tested database restore.

## Release evidence

Create the fixed protected GitHub environment `deployment-evidence-fly_io`
with an app-scoped `FLY_API_TOKEN`. The token must be able to list the target
app and its Machines, list secret metadata, execute the read-only migration
status command on an existing Machine, and restart one Machine. Secret payloads
are never requested.

Confirm the provider response before dispatching the evidence workflow:

```bash
flyctl apps list --json
flyctl machine list --app replace-with-your-latchway-app --json
flyctl secrets list --app replace-with-your-latchway-app --json
flyctl console --app replace-with-your-latchway-app --machine MACHINE_ID \
  --command '/latchway --output json migrate status'
```

Both `LATCHWAY_DATABASE_URL` and `LATCHWAY_MASTER_KEY` must appear as
`Deployed`, not staged or partial. Every running application Machine must
resolve to the release digest and at least two must be started.

Run `.github/workflows/deployment-evidence.yml` from protected `main` with
`platform=fly_io`, the candidate commit/run/intended tag, exact OCI index,
public HTTPS endpoint, and Fly app name. The pinned collector records the provider-returned app ID, checks the
resolved digest of every running Machine, binds migration output to an existing
Machine, restarts one Machine explicitly with SIGTERM and a 35-second timeout,
waits for a new Machine instance, and probes `/healthz` plus `/readyz`.
The credential-free structural gate is:

```bash
python3 scripts/deployment-evidence.py static \
  --output /tmp/latchway-deployment-static.json
```

It rejects unknown Fly configuration fields and validates the fixed migration,
health, rollout, resource, and drain contract without contacting Fly. The
authoritative `flyctl config validate --strict` command requires an authenticated
Fly session and is executed again inside the protected provider-capture job; its
success is still static evidence only.
