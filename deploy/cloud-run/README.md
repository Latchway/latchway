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

The one-time Terraform bootstrap identity must be able to enable the APIs in
`main.tf`, create the VPC/private-services connection and VPC connector, manage
Cloud SQL, Secret Manager, Cloud Run services and jobs, create and attach the
runtime service account, and write the narrow project/secret/service IAM
bindings declared by the stack. A practical bootstrap role set is Service
Usage Admin, Compute Network Admin, Serverless VPC Access Admin, Cloud SQL
Admin, Secret Manager Admin, Service Account Admin, Service Account User,
Cloud Run Admin, and Project IAM Admin. Scope Storage Admin to the dedicated
Terraform-state bucket rather than the project. Prefer a custom role containing
only the permissions in the reviewed plan, and remove the bootstrap roles after
the apply; the runtime identity keeps only the Cloud SQL Client and named-secret
access that Terraform grants. Existing Cloud Run Admin, Cloud SQL Admin, and
Service Account Admin roles alone are not sufficient for this stack.

Confirm billing first, then enable or allow Terraform to enable these APIs:

```text
cloudresourcemanager.googleapis.com
compute.googleapis.com
iam.googleapis.com
run.googleapis.com
secretmanager.googleapis.com
servicenetworking.googleapis.com
sqladmin.googleapis.com
vpcaccess.googleapis.com
```

Review the plan as a cost boundary. The production defaults create a regional
high-availability Cloud SQL instance, a Serverless VPC Access connector with at
least two instances, and one always-on 2-vCPU/2-GiB Cloud Run instance. These
resources continue billing until deliberately scaled down or removed; do not
apply the plan merely to perform static validation.

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
digest. PostgreSQL 18 is explicitly configured with the Cloud SQL Enterprise
edition because the default `db-custom-2-7680` tier is not valid for Enterprise
Plus. Keep `database_edition="ENTERPRISE"` unless the tier and its validation
are changed together. `public_origin` must be the final custom HTTPS origin.
The default allows unauthenticated Cloud Run ingress because Latchway performs
its own session and DPoP authorization; use an external load balancer or Cloud
Armor if additional edge policy is required.

The stack does not provision a custom-domain frontend. For production, bind
`public_origin` through Google's recommended global external Application Load
Balancer with a serverless NEG, managed certificate, and final DNS record. Keep
buffering and caching disabled for API and SSE paths. Native Cloud Run domain
mapping remains limited-availability Preview and is not production-ready; use
it only for evaluation after reviewing Google's current region and TLS
limitations:

For the first deployment, reserve the final hostname before applying this
stack and set `public_origin` to that exact HTTPS origin even while DNS is not
yet live. Apply the service, attach its serverless NEG to the external load
balancer, provision the managed certificate, and then publish the final DNS
record. Do not create an administrator, distribute SDK configuration, or call
the deployment ready until the certificate is active and `/healthz` plus
`/readyz` succeed through the final hostname. This avoids issuing sessions for
a temporary Cloud Run URL and later changing the security origin.

```bash
gcloud domains list-user-verified
gcloud domains verify example.com
gcloud beta run domain-mappings create \
  --service latchway \
  --domain ai.example.com \
  --project PROJECT_ID \
  --region REGION
gcloud beta run domain-mappings describe \
  --domain ai.example.com \
  --project PROJECT_ID \
  --region REGION \
  --format='yaml(status,resourceRecords)'
```

Add the returned `resourceRecords` at the authoritative DNS provider and wait
for the managed certificate before using that origin.

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

Verify the ready revision resolved the configured immutable image before
accepting traffic:

```bash
export LATCHWAY_IMAGE='ghcr.io/latchway/latchway@sha256:REPLACE_WITH_RELEASE_DIGEST'
latchway_revision=$(gcloud run services describe latchway \
  --project PROJECT_ID \
  --region REGION \
  --format='value(status.latestReadyRevisionName)')
test -n "$latchway_revision"
latchway_configured_image=$(gcloud run services describe latchway \
  --project PROJECT_ID \
  --region REGION \
  --format='value(spec.template.spec.containers[0].image)')
test "$latchway_configured_image" = "$LATCHWAY_IMAGE"
latchway_resolved_digest=$(gcloud run revisions describe "$latchway_revision" \
  --project PROJECT_ID \
  --region REGION \
  --format='value(status.imageDigest)')
test "$latchway_resolved_digest" = "${LATCHWAY_IMAGE##*@}"
```

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

Keep an independent required reviewer on this environment for `strict_full`.
For the explicitly selected `single_maintainer_v1` profile it may temporarily
be reviewer-free, provided its exact policy sentinel remains configured and
the resulting release stays labeled lower-assurance. Do not report the strict
release-control policy as passing again until reviewer protection is restored.

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
