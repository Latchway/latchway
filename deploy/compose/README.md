# Release-image Compose deployment

The root `compose.yaml` is the source-build quickstart. This file is the
release-image gate: it never has a build fallback and requires
`LATCHWAY_IMAGE` to identify the verified Latchway release by immutable digest.
It runs the same image once as a migration job before starting the combined API
and worker role.

Create an untracked environment file. URL-encode the database password in the
PostgreSQL URL and keep the generated master key stable for the lifetime of the
installation.

```bash
export LATCHWAY_IMAGE='ghcr.io/latchway/latchway@sha256:<64 lowercase hex>'
export POSTGRES_PASSWORD='<random password>'
export LATCHWAY_DATABASE_URL='postgresql://latchway:<url-encoded password>@postgres:5432/latchway?sslmode=disable'
export LATCHWAY_MASTER_KEY="$(openssl rand -base64 32)"
export LATCHWAY_PUBLIC_ORIGIN='https://ai.example.com'
export LATCHWAY_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -base64 36)"

docker compose -f deploy/compose/compose.release.yaml config --quiet
docker compose -f deploy/compose/compose.release.yaml pull
docker compose -f deploy/compose/compose.release.yaml up -d --wait
curl --fail --show-error --silent http://127.0.0.1:8080/healthz
curl --fail --show-error --silent http://127.0.0.1:8080/readyz
docker compose -f deploy/compose/compose.release.yaml run --rm --no-deps \
  latchway --output json migrate status
```

`sslmode=disable` is limited to the private Compose network in this example.
Use TLS for an external PostgreSQL service. After creating the first
administrator, remove `LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` and recreate only the
Latchway service. Keep the database volume and master key.

The release template pins PostgreSQL 18 and mounts its named volume at
`/var/lib/postgresql`, the 18+ major-version-aware layout. Do not attach a
volume created by a PostgreSQL 17-or-earlier `/var/lib/postgresql/data`
deployment directly. Restore a verified backup or complete the documented
`pg_upgrade` procedure before switching the image, then preserve the new named
volume across ordinary Latchway upgrades.

Before calling this a release deployment, use
`scripts/deployment-evidence.py` as documented in
`docs/deployment/README.md`. A successful `docker compose up` from a source
checkout does not prove that a released digest, cloud platform, or provider
secret store was tested.

For repeatable prepublication evidence, use the fixed GitHub environment
`deployment-evidence-compose` and dispatch the pinned workflow from protected
`main` with the attested candidate coordinates. Under `strict_full`, keep the
required independent reviewer. Under the explicitly selected
`single_maintainer_v1` profile, the same environment may temporarily have no
reviewer, but it must retain the exact policy sentinel documented in
`docs/release/release-profiles.md`; strict-policy reconciliation then remains
failed/unverified until reviewer protection is restored.

```bash
gh workflow run deployment-evidence.yml --ref main \
  -f platform=compose \
  -f candidate_commit='<40 lowercase hex>' \
  -f intended_tag=v1.0.0 \
  -f candidate_run_id='<release-candidate workflow run ID>' \
  -f candidate_run_attempt='<release-candidate workflow run attempt>' \
  -f image='ghcr.io/latchway/latchway@sha256:<64 lowercase hex>' \
  -f endpoint='http://127.0.0.1:18080'
```

The workflow generates ephemeral database/bootstrap material, pulls rather
than builds the exact image, waits for the migration service and health check,
captures `migrate status`, sends SIGTERM with a 35-second platform grace around
the application's 30-second drain, recreates the healthy service, and removes
the entire Compose project and volume. Its provider identity is the
GitHub-hosted Docker engine and the Compose project label returned by Docker.
The signed archive contains no generated secret values.
