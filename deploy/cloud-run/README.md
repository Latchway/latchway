# Google Cloud Run

The Terraform example provisions a private-IP Cloud SQL PostgreSQL 18
instance, Secret Manager values, a Serverless VPC Access connector, a 2 vCPU / 2
GiB Cloud Run service, and a one-shot migration job. Cloud Run's managed Cloud
SQL connector presents short-lived client certificates over a Unix socket; the
database rejects connections without trusted client certificates. The raw YAML files support
teams that manage those dependencies separately.

## Terraform deployment

Authenticate Google Cloud and use an encrypted remote Terraform state backend.
Terraform state contains generated database and master-key material even though
the running service receives it through Secret Manager.

```bash
cd deploy/cloud-run/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan -out latchway.tfplan
terraform apply latchway.tfplan
```

Set `image` to the exact digest from the signed release artifact, never a
mutable tag. `public_origin` must be the final custom HTTPS origin. The default
allows unauthenticated Cloud Run ingress because Latchway performs its own
session and DPoP authorization; use an external load balancer or Cloud Armor if
additional edge policy is required.

The first deployment permits advisory-lock-protected startup migrations. For a
controlled upgrade, first run the output migration command, verify `migrate
status`, set `LATCHWAY_MIGRATE_ON_START=false` in the service template, and only
then shift traffic to the new image.

Cloud Run request timeout is 60 minutes so SSE clients must reconnect before
that boundary. CPU remains allocated for the combined worker role. `/healthz`
is the liveness probe and `/readyz` checks PostgreSQL, schema, active
configuration, master/signing keys, and worker heartbeat.

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
envsubst < deploy/cloud-run/service.yaml > /tmp/latchway-service.yaml
gcloud run services replace /tmp/latchway-service.yaml --region REGION
```

Grant the runtime service account Secret Manager accessor only on the two
named secrets. Keep Cloud SQL on private IP, require encrypted connections,
enable point-in-time recovery, and test the procedures in
`docs/operations/backup-restore.md` before taking traffic.
