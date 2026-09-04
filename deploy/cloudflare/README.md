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
- Docker Buildx, `jq`, and `sha256sum` for image mirroring and verification
- an active Cloudflare DNS zone for the final hostname, with no existing CNAME
  at that hostname
- a publicly reachable PostgreSQL 15+ database with TLS enforced

The four container instances each have an aggregate ceiling of five PostgreSQL
connections: two are completion-reserved inside that total and three serve
regular work. The application maximum is therefore 20 connections—eight
completion-reserved and 12 regular—not 28. A one-minute Cron Trigger sends a
private health request to `instance-0`, keeping at least one `all`-role runtime
active for signing-key rotation, reservation recovery, retention, usage
rollups, and shared JWKS refresh even when user traffic is quiet. Include
migrations, administration, backups, maintenance, and rollout overlap, then
keep planned peak demand at or below 80% of usable PostgreSQL connections.
Adjust instance count, aggregate pool size, completion reservation, and the
database ceiling together.

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

```bash
set -Eeuo pipefail
umask 077
export LATCHWAY_AMD64_IMAGE='ghcr.io/latchway/latchway@sha256:REPLACE_WITH_AMD64_CHILD_DIGEST'
docker pull --platform linux/amd64 "$LATCHWAY_AMD64_IMAGE"
docker tag "$LATCHWAY_AMD64_IMAGE" latchway:1.0.0-amd64
pnpm exec wrangler containers push latchway:1.0.0-amd64

export LATCHWAY_CLOUDFLARE_TAG='registry.cloudflare.com/ACCOUNT_ID/latchway:1.0.0-amd64'
latchway_manifest_dir=$(mktemp -d "${TMPDIR:-/tmp}/latchway-manifests.XXXXXX")
install -d -m 0700 "$latchway_manifest_dir/docker-config"
trap 'rm -rf "$latchway_manifest_dir"' EXIT HUP INT TERM
pnpm exec wrangler containers registries credentials registry.cloudflare.com \
  --pull --expiration-minutes 15 --json \
  > "$latchway_manifest_dir/cloudflare-registry-credentials.json"
latchway_registry_username=$(jq -er '.username | select(type == "string" and length > 0)' \
  "$latchway_manifest_dir/cloudflare-registry-credentials.json")
jq -er '.password | select(type == "string" and length > 0)' \
  "$latchway_manifest_dir/cloudflare-registry-credentials.json" \
  | docker --config "$latchway_manifest_dir/docker-config" \
      login registry.cloudflare.com \
      --username "$latchway_registry_username" --password-stdin
docker --config "$latchway_manifest_dir/docker-config" \
  buildx imagetools inspect --raw "$LATCHWAY_AMD64_IMAGE" \
  > "$latchway_manifest_dir/canonical.json"
docker --config "$latchway_manifest_dir/docker-config" \
  buildx imagetools inspect --raw "$LATCHWAY_CLOUDFLARE_TAG" \
  > "$latchway_manifest_dir/mirror.json"
latchway_canonical_digest="sha256:$(sha256sum \
  "$latchway_manifest_dir/canonical.json" | awk '{print $1}')"
latchway_mirror_digest="sha256:$(sha256sum \
  "$latchway_manifest_dir/mirror.json" | awk '{print $1}')"
test "$latchway_canonical_digest" = "${LATCHWAY_AMD64_IMAGE##*@}"
jq -S '{config_digest:.config.digest,layers:[.layers[]|{digest,size}]}' \
  "$latchway_manifest_dir/canonical.json" \
  > "$latchway_manifest_dir/canonical-descriptors.json"
jq -S '{config_digest:.config.digest,layers:[.layers[]|{digest,size}]}' \
  "$latchway_manifest_dir/mirror.json" \
  > "$latchway_manifest_dir/mirror-descriptors.json"
cmp "$latchway_manifest_dir/canonical-descriptors.json" \
  "$latchway_manifest_dir/mirror-descriptors.json"
export LATCHWAY_CLOUDFLARE_IMAGE="${LATCHWAY_CLOUDFLARE_TAG%:*}@$latchway_mirror_digest"
rm -rf "$latchway_manifest_dir"
trap - EXIT HUP INT TERM
unset latchway_manifest_dir latchway_registry_username
```

Generate the ignored production-only configuration from an immutable mirror
digest. The generator rejects tag-only references, unsupported registries,
GHCR, a mutable Dockerfile build, and a source template that has drifted from
the reviewed shape. It also requires one exact, lowercase, non-wildcard Custom
Domain:

```bash
export LATCHWAY_DOMAIN='ai.example.com'
pnpm release:config -- \
  --image "$LATCHWAY_CLOUDFLARE_IMAGE" \
  --domain "$LATCHWAY_DOMAIN"
pnpm release:dry-run
```

The generated config retains the exact Custom Domain on every deploy.
Cloudflare creates its DNS record and manages the certificate. The hostname
must belong to an active zone and must not already have a CNAME. The deploy
command byte-compares the ignored config with deterministic regeneration from
the reviewed source, so comments, extra routes, and manual edits fail closed.

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

For a brand-new Worker, prepare a protected temporary JSON file containing the
four required secrets. A new Worker cannot receive required secrets in advance
with `wrangler secret put`; the first reviewed deployment must upload them
atomically with `--secrets-file`. `LATCHWAY_PUBLIC_ORIGIN` must be the final
HTTPS origin users will call, with no path, query, or fragment. Generate the
master key once, store it outside Cloudflare as a recovery secret, and never
rotate it by merely replacing the environment value.

```bash
umask 077
latchway_secrets_file=$(mktemp "${TMPDIR:-/tmp}/latchway-wrangler-secrets.json.XXXXXX")
trap 'rm -f "$latchway_secrets_file"' EXIT
"${EDITOR:-vi}" "$latchway_secrets_file"
jq --exit-status '
  (keys | sort) == [
    "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN",
    "LATCHWAY_DATABASE_URL",
    "LATCHWAY_MASTER_KEY",
    "LATCHWAY_PUBLIC_ORIGIN"
  ] and all(.[]; type == "string" and length > 0)
' "$latchway_secrets_file" >/dev/null
pnpm exec wrangler deploy \
  --config wrangler.release.jsonc \
  --secrets-file "$latchway_secrets_file"
rm -f "$latchway_secrets_file"
unset latchway_secrets_file
trap - EXIT
```

For an existing Worker, `pnpm exec wrangler secret put NAME --config
wrangler.release.jsonc` rotates one value. Every secret mutation creates and
deploys a Worker version. Always bind the reviewed generated release config
explicitly; using the checked-in development config can reactivate a Dockerfile
build and bootstrap defaults.

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

Deploy and create the first administrator. Then generate the reviewed
post-bootstrap configuration from the same release source and image. This mode
sets startup migrations to false and omits the bootstrap binding without an ad
hoc tracked-source edit. Deploy it before deleting the now-unreferenced secret:

```bash
pnpm release:config -- \
  --image "$LATCHWAY_CLOUDFLARE_IMAGE" \
  --domain "$LATCHWAY_DOMAIN" \
  --post-bootstrap
pnpm check
pnpm release:deploy
pnpm exec wrangler secret delete LATCHWAY_ADMIN_BOOTSTRAP_TOKEN --config wrangler.release.jsonc
```

The delete deploys another Worker version, so it must use the post-bootstrap
generated config shown above.

The platform-only health endpoint is
`/__latchway/cloudflare/healthz`. Use Latchway's forwarded `/healthz` for
liveness and `/readyz` for database, schema, configuration, signing-key,
master-key, reserved quota-completion-pool, and worker-heartbeat readiness.

## Release evidence

Create the protected GitHub environment
`deployment-evidence-cloudflare_containers` with account-scoped
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and a random
`CLOUDFLARE_EVIDENCE_TOKEN` of 32–256 characters. Install the same evidence
token as the Worker secret `LATCHWAY_EVIDENCE_TOKEN`; it is used only to
authorize the bounded migration and graceful-stop evidence operations and is
never written to the artifact:

```bash
pnpm exec wrangler secret put LATCHWAY_EVIDENCE_TOKEN --config wrangler.release.jsonc
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
