# Production deployment

Latchway ships one non-root OCI image for API, worker, migration, diagnostics,
and the embedded dashboard. Deploy by immutable digest and use PostgreSQL 15 or
newer as the only required external service.

Supported templates:

- `deploy/compose`: release-image Compose with an explicit migration service
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
local build. Record prepublication results against the attested candidate
commit, intended tags, and exact OCI index; promotion creates public tags only
after those records pass.

## Deployment evidence gate

Static validation and live deployment evidence are deliberately different
results. The local gate checks Compose rendering, both Terraform modules, the
Cloud Run YAML, Fly configuration, the capture schema, and fail-closed unit
tests:

```bash
./scripts/validate-deployments.sh /tmp/latchway-deployment-static.json
```

That command may pass without a cloud account. It never sets any
`*_verified` release claim. Live claims are produced only by the pinned
`.github/workflows/deployment-evidence.yml` workflow from protected `main`, an
attested release-candidate run, and a fixed protected environment:

- `deployment-evidence-compose`
- `deployment-evidence-cloud_run`
- `deployment-evidence-aws`
- `deployment-evidence-fly_io`
- `deployment-evidence-cloudflare_containers`

Each run observes the provider identity and resource ID, the configured and
resolved image digest, a remote `migrate status`, secret references without
secret values, `/healthz`, `/readyz`, and a SIGTERM replacement. Provider CLI
responses are reduced to bounded JSON before upload. The resulting archive is
deterministic and receives a GitHub artifact attestation. A missing command,
log record, provider permission, digest match, health check, or archive fails
the run; there is no manual-pass input.

Start each capture against the exact candidate image before any public tag is
created. The candidate commit must be the commit in the downloaded candidate
manifest; the workflow source revision is recorded separately. For example:

```bash
gh workflow run deployment-evidence.yml --ref main \
  -f platform=cloud_run \
  -f candidate_commit='<40 lowercase hex>' \
  -f intended_tag=v1.0.0 \
  -f candidate_run_id='<release-candidate workflow run ID>' \
  -f image='ghcr.io/latchway/latchway@sha256:<64 lowercase hex>' \
  -f endpoint='https://ai.example.com' \
  -f gcp_project='<project-id>' \
  -f gcp_region='asia-southeast1' \
  -f gcp_service='latchway' \
  -f gcp_migration_job='latchway-migrate'
```

Run the equivalent dispatch for `compose`, `aws`, `fly_io`, and
`cloudflare_containers`; their exact provider inputs and permissions are
documented in the platform READMEs.
Compose accepts only a loopback HTTP endpoint. Cloud platforms require a
public HTTPS origin; private, loopback, link-local, and redirect targets are
rejected by the observer.

### Aggregate release evidence

Place all five provider archives and their attestation bundles under the
cross-repository evidence root. Every archive must come from the same pinned
workflow, the platform's fixed protected environment, and the same candidate
identity. A capture or attestation produced by another workflow is rejected by
the finalizer.

The Cloudflare capture comes from provider-observed state, not operator
assertions. In addition to the common digest, secret-reference, health, and
readiness checks, it includes a ready Worker and Container application ID, the
canonical signed index and amd64 child, a content-equivalent Cloudflare Registry
mirror (identical config and ordered layer descriptors), and a successful
in-container migration execution whose
`migration.provider_execution.reported_status` is equal to
`migration.status`. Its shutdown observation must record a SIGTERM container
replacement with the same mirror digest before and after, Cloudflare's
15-minute force-stop bound, the application's 30-second drain limit, provider
exit code zero, and
`shutdown.readiness_restored == true`. Missing provider-returned identifiers,
timestamps, execution results, or restored readiness fail closed.

```text
EVIDENCE_ROOT/
  artifacts/cloud-deployments/
    compose.tar.gz
    compose.attestation.json
    cloud_run.tar.gz
    cloud_run.attestation.json
    aws.tar.gz
    aws.attestation.json
    fly_io.tar.gz
    fly_io.attestation.json
    cloudflare_containers.tar.gz
    cloudflare_containers.attestation.json
```

Prepare `release-coordinates.json` with exactly `core`, `javascript`, `ios`,
`android`, and `react_native` entries; every entry has `commit`, `tag`, and
`version`. On an online trusted machine, refresh the GitHub/Sigstore roots with
`gh attestation trusted-root > trusted_root.jsonl`. Import that file with the
archives into the verification environment, then run:

```bash
python3 scripts/deployment-evidence.py finalize \
  --evidence-root "$EVIDENCE_ROOT" \
  --coordinates release-coordinates.json \
  --trusted-root trusted_root.jsonl \
  --core-commit '<40 lowercase hex>' \
  --core-release v1.0.0 \
  --contract-version 1.0.0 \
  --bundle-sha256 '<64 lowercase hex>' \
  --image 'ghcr.io/latchway/latchway@sha256:<64 lowercase hex>'
```

The finalizer performs offline attestation verification with the repository,
signer workflow, protected-main source revision, and GitHub-hosted runner policy
fixed. Candidate commit/tag/image bindings are verified independently inside
every archive. Only after all five signed archives pass does it write
`cloud_deployments.json` in the shape accepted by the cross-repository release
gate. Preserve the evidence directory and `trusted_root.jsonl` with the release
record; the generated verification summary includes their cryptographic
hashes. Never author `cloud_deployments.json` by hand.

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
