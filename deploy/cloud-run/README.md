# Google Cloud Run

## Manual deployment: recommended starting point

Use the [manual Cloud Run guide](../../docs/public/operations/deploy-google-cloud-run.mdx)
to deploy the public GHCR image in Google Cloud Console or Cloud Shell and
connect an existing PostgreSQL 15+ database. No fork, source checkout, build,
Terraform, GitHub Actions, or Workload Identity Federation is required for an
ordinary installation. The embedded Console ships in the same image.

The stable image is not published yet. Replace
`ghcr.io/latchway/latchway@sha256:REPLACE_WITH_RELEASE_DIGEST` only after the
release record supplies a verified digest. The image must include
`linux/amd64`; do not use a mutable tag or silently substitute a local build.
Cloud Run can consume a public GHCR image directly; an Artifact Registry
remote repository is optional. See Google's
[image deployment guide](https://docs.cloud.google.com/run/docs/deploying).

The manual path is:

1. Select a billing-enabled project and region. Use a reachable PostgreSQL 15+
   database with `sslmode=verify-full`, appropriate access controls, and a
   dedicated database user. A Cloud SQL managed Unix socket is an alternative;
   its connector provides encrypted network transport. Do not use plaintext
   TCP or open database ingress to all addresses to work around networking.
2. Create named Secret Manager values for the database URL, one stable
   base64-encoded 32-byte master key, and a separate temporary bootstrap token
   of at least 32 characters. Escrow the master key outside the database.
3. Give a `latchway-migrator` service account access only to the database secret.
   Give `latchway-runtime` access to the three named secrets, not project-wide
   secret access. No service-account JSON keys are needed. Pin numeric secret
   versions in the job and service.
4. Create a one-task Cloud Run job using the verified digest and
   `/latchway migrate up`; execute it before deploying the service. Run it again
   with `--output json migrate status`, and require `up_to_date=true` and
   `current=available` in that execution's logs. The migration job needs the
   same database route and any custom CA mount as the service.
5. Deploy that exact digest with the settings below, verify both probes, and
   create the first owner in the embedded Console. Choose your own email and
   password; there are no default administrator credentials.
6. Remove the bootstrap secret environment binding, deploy and verify a new
   revision, shift all traffic to it, remove old traffic tags, and revoke only
   the runtime account's bootstrap-secret accessor grant. Keep the database URL
   and master key unchanged.

| Manual service setting | Value |
| --- | --- |
| Command and arguments | `/latchway serve --role all` |
| Container port | `8080`; Cloud Run sets `PORT` |
| CPU and memory | 2 vCPU / 2 GiB |
| CPU allocation and scale | Instance-based billing; minimum 1, maximum 3 service instances |
| Concurrency and request timeout | 100 / 3600 seconds |
| `LATCHWAY_PUBLIC_ORIGIN` | `https://latchway-PROJECT_NUMBER.REGION.run.app` |
| `LATCHWAY_MIGRATE_ON_START` | `false` after the explicit migration job |
| `LATCHWAY_DB_MAX_CONNECTIONS` | `20` |
| `LATCHWAY_SHUTDOWN_TIMEOUT` | `8s`, inside Cloud Run's ten-second shutdown window |
| `LATCHWAY_LOG_LEVEL` | `info` |
| Secret-backed variables | `LATCHWAY_DATABASE_URL`, `LATCHWAY_MASTER_KEY`, temporary `LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` |
| HTTP probes | Startup `/readyz`; liveness `/healthz`, both port 8080 |

The short service name `latchway` permits Google's
[deterministic HTTPS URL](https://docs.cloud.google.com/run/docs/triggering/https-request),
using the numeric project number. Confirm that exact URL after creation. A
custom domain, load balancer, new Cloud SQL instance, VPC connector, and
Terraform-state bucket are not required by the existing-database path.

Allow public Cloud Run access so clients reach Latchway's own authentication
and authorization. This also exposes the unauthenticated `/metrics` endpoint
on that listener; use a reviewed path-restricting edge with no `run.app` bypass
if your operating policy requires private metrics. Readiness checks more than
process health, including schema, active-environment configuration, keys, and
worker heartbeat. Do not scale the combined worker to zero or throttle CPU
between requests. Budget 60 application connections plus migrations, backups,
administration, and temporary rollout/maximum-instance overshoot.

The manual guide includes Console fields, complete Cloud Shell commands,
Cloud SQL alternatives, migration status checks, bootstrap removal, and a
no-traffic candidate rollout. Run authenticated and SSE smoke checks on the
canonical origin; tagged candidate URLs are for health/readiness probes, not
new SDK origins. The deployment is billable and must pass the separate
production-readiness and backup/restore checks before production use. No GCP
resources are created by reading or validating this guide.

## Optional advanced Terraform deployment

The Terraform example provisions a private-IP Cloud SQL PostgreSQL 18
instance, Secret Manager values, a Serverless VPC Access connector, a 2 vCPU / 2
GiB Cloud Run service, and a one-shot migration job. Cloud Run's managed Cloud
SQL connector presents short-lived client certificates over a Unix socket; the
database rejects connections without trusted client certificates. The raw YAML files support
teams that manage those dependencies separately. This is an optional
infrastructure-as-code path, not a prerequisite for using or forking Latchway.

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
are changed together. `public_origin` must be the final HTTPS origin; the
deterministic `run.app` origin is valid and avoids a separate domain frontend.
The default allows unauthenticated Cloud Run ingress because Latchway performs
its own session and DPoP authorization; use an external load balancer or Cloud
Armor if additional edge policy is required.

The stack does not provision a custom-domain frontend. If a custom domain is
required, bind `public_origin` through Google's recommended global external
Application Load Balancer with a serverless NEG, managed certificate, and final DNS record. Keep
buffering and caching disabled for API and SSE paths. Native Cloud Run domain
mapping remains limited-availability Preview and is not production-ready; use
it only for evaluation after reviewing Google's current region and TLS
limitations:

For a first deployment with a custom domain, reserve the final hostname before
applying this stack and set `public_origin` to that exact HTTPS origin even
while DNS is not yet live. Apply the service, attach its serverless NEG to the external load
balancer, provision the managed certificate, and then publish the final DNS
record. Do not create an administrator, distribute SDK configuration, or call
the deployment ready until the certificate is active and `/healthz` plus
`/readyz` succeed through the final hostname. This avoids issuing sessions for
a temporary Cloud Run URL and later changing the security origin.

See Google's current
[custom-domain guide](https://docs.cloud.google.com/run/docs/mapping-custom-domains)
for frontend choices and limitations. Skip this frontend setup when the
canonical origin is the built-in HTTPS `run.app` URL.

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

The raw-YAML path preserves migration-before-service ordering. The checked-in
service YAML still includes the initial bootstrap binding and startup-migration
fallback: remove the bootstrap binding after first-owner setup and set
`LATCHWAY_MIGRATE_ON_START=false` after the explicit job succeeds. Replace
`latest` secret references with reviewed numeric versions in the rendered
manifest. Do not reintroduce those bootstrap defaults during upgrades.

For controlled rollout without Terraform, use Cloud Run's no-traffic revision
and explicit traffic controls described in the manual guide. Terraform is not
required for those controls. Keep provider-observed release evidence separate
from ordinary deployment success.

Grant the runtime service account Secret Manager accessor only on the named
database and master-key secrets, plus the temporary bootstrap secret during
initial setup. Keep Cloud SQL on private IP, require encrypted connections,
enable point-in-time recovery, and test the procedures in
`docs/operations/backup-restore.md` before taking traffic.

## Maintainer release evidence, not an adopter prerequisite

The following GitHub setup belongs to Latchway's release-verification pipeline.
An operator running an already published image does not need a GitHub
environment or WIF identity, whether deploying manually or with Terraform.

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
