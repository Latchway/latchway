# Google Cloud Run

The Terraform example provisions a private-IP Cloud SQL PostgreSQL 18
instance, Secret Manager values, a Serverless VPC Access connector, a 2 vCPU / 2
GiB Cloud Run service, and a one-shot migration job. Cloud Run's managed Cloud
SQL connector presents short-lived client certificates over a Unix socket; the
database rejects connections without trusted client certificates. The raw YAML files support
teams that manage those dependencies separately.

## Terraform deployment

Authenticate Google Cloud and create or select a tightly scoped, versioned GCS
bucket for the partial backend declared in `versions.tf`. Terraform state
contains generated database, master-key, and bootstrap material even though the
running service receives those values through Secret Manager. A local backend
is not an allowed production path.

```bash
cd deploy/cloud-run/terraform
cp terraform.tfvars.example terraform.tfvars
export LATCHWAY_TF_STATE_BUCKET='replace-with-existing-versioned-state-bucket'
terraform init \
  -backend-config="bucket=$LATCHWAY_TF_STATE_BUCKET" \
  -backend-config='prefix=latchway/cloud-run'
umask 077
latchway_plan=$(mktemp "${TMPDIR:-/tmp}/latchway.tfplan.XXXXXX")
trap 'rm -f "$latchway_plan"' EXIT
terraform plan -out="$latchway_plan"
terraform apply "$latchway_plan"
rm -f "$latchway_plan"
unset latchway_plan
trap - EXIT
```

Set `service_image`, `migration_image`, and
`migration_approved_service_image` to exact digests, never mutable tags. Every
service digest has an explicit `service_revision_name`; Terraform refuses to
create or route to it until the approved migration digest equals the service
digest. `public_origin` must be the final custom HTTPS origin. The default
allows unauthenticated Cloud Run ingress because Latchway performs its own
session and DPoP authorization; use an external load balancer or Cloud Armor if
additional edge policy is required.

The first deployment permits advisory-lock-protected startup migrations. Once
the service is healthy, execute the one-shot job shown by
`terraform output -raw migration_command`, then execute that job with the
argument override `--args=--output,json,migrate,status`. Only a report where
`current` equals `available` is current. Set `migrate_on_start=false` and apply
again before the next controlled upgrade.

Future upgrades are three explicit applies. First advance only
`migration_image`, keeping the current service image, revision, approval, and
100% traffic unchanged; apply and execute both `migrate up` and `migrate
status`. Second, after the status passes, set the new `service_image`, matching
`migration_approved_service_image`, a new `service_revision_name`, the old
revision as `previous_service_revision_name`, and
`service_traffic_percent=0`; apply and probe the tagged candidate URL. Third,
set `service_traffic_percent=100` and apply. Do not combine these phases in one
plan or mix unrelated infrastructure changes into them.

Terraform creates a random administrator bootstrap secret and grants the
runtime identity access only while `inject_admin_bootstrap_token=true`. Read it
directly from Secret Manager into a password manager, create the first
administrator, then set that variable and `migrate_on_start` to `false`. Give
the post-bootstrap template a new `service_revision_name`, retain the current
revision as `previous_service_revision_name`, set
`service_traffic_percent=0`, apply, and probe the tagged candidate. Set traffic
to 100 and apply only after readiness succeeds. The promoted revision no longer
references the secret and its secret-level accessor grant is removed. Delete
the unused secret only under the team's recorded secret-retirement policy.

Cloud Run request timeout is 60 minutes so SSE clients must reconnect before
that boundary. CPU remains allocated for the combined worker role. `/healthz`
is the liveness probe and `/readyz` checks PostgreSQL, schema, active
configuration, master/signing keys, and worker heartbeat.
Cloud Run allows ten seconds between SIGTERM and forced termination; this
template gives the application eight seconds to drain so the process can exit
before the platform deadline.

## Connection budget

The maximum application pool is `max_instances ×
db_connections_per_instance` (200 with defaults). Add migration and operations
headroom and keep the total below Cloud SQL's limit. Reduce the per-instance
pool before increasing autoscaling. A production database should remain
`REGIONAL`; the `ZONAL` option is for evaluation only.

## Raw YAML

Export the placeholders and render with `envsubst` into an untracked file:

```bash
export LATCHWAY_IMAGE='ghcr.io/latchway/latchway@sha256:...'
export LATCHWAY_PUBLIC_ORIGIN='https://ai.example.com'
export SERVICE_ACCOUNT='latchway-runtime@PROJECT_ID.iam.gserviceaccount.com'
export VPC_CONNECTOR='projects/PROJECT_ID/locations/REGION/connectors/latchway'
export CLOUD_SQL_CONNECTION_NAME='PROJECT_ID:REGION:latchway-postgres'
envsubst < deploy/cloud-run/migration-job.yaml > /tmp/latchway-migration-job.yaml
gcloud run jobs replace /tmp/latchway-migration-job.yaml --region REGION
gcloud run jobs execute latchway-migrate --region REGION --wait
gcloud run jobs execute latchway-migrate --region REGION \
  --args=--output,json,migrate,status --wait
envsubst < deploy/cloud-run/service.yaml > /tmp/latchway-service.yaml
gcloud run services replace /tmp/latchway-service.yaml --region REGION
```

The raw-YAML path preserves migration-before-service ordering but does not
provide Terraform's named 0%-traffic candidate probe. Use the Terraform path
for a production rollout and protected release evidence.

Grant the runtime service account Secret Manager accessor only on the named
database and master-key secrets, plus the temporary bootstrap secret during
initial setup. Keep Cloud SQL on private IP, require encrypted connections,
enable point-in-time recovery, and test the procedures in
`docs/operations/backup-restore.md` before taking traffic.

## Release evidence

Create the fixed protected GitHub environment
`deployment-evidence-cloud_run`. It contains `GCP_WORKLOAD_IDENTITY_PROVIDER`
and `GCP_SERVICE_ACCOUNT`; do not store a JSON service-account key. The OIDC
identity needs only the ability to read the project/service/revision/job and
secret metadata, execute and inspect the migration job, read that execution's
Cloud Logging entries, update the service twice for a controlled revision
replacement, and act as the existing runtime service account. It does not need
permission to read Secret Manager payloads.

Before dispatching the evidence workflow, confirm the provider sees the exact
release digest and the expected resources:

```bash
gcloud run services describe SERVICE --project PROJECT --region REGION --format=json
gcloud run jobs describe MIGRATION_JOB --project PROJECT --region REGION --format=json
gcloud run jobs execute MIGRATION_JOB --project PROJECT --region REGION \
  --args=--output,json,migrate,status --wait
```

Then run `.github/workflows/deployment-evidence.yml` from protected `main` with
`platform=cloud_run`, the exact candidate commit, intended tag, candidate run
ID, `ghcr.io/latchway/latchway@sha256:...` OCI index, public endpoint, project,
region, service, and migration job. The
collector reads the remote status from execution-scoped provider logs, checks
the service and job image, resolves the revision digest, verifies secret
references without retrieving their values, performs a two-revision SIGTERM
rollout, and probes `/healthz` plus `/readyz`. Static validation alone is not a
Cloud Run release claim.
