# AWS ECS/Fargate and RDS

The Terraform example deploys the unchanged Latchway OCI image on two or more
private Fargate tasks behind an HTTPS Application Load Balancer. It provisions
private, encrypted PostgreSQL 18 RDS, Secrets Manager values, a 2 vCPU / 4 GiB
task, health checks, deployment rollback, autoscaling, logs, and least-privilege
secret reads.

Mirror the signed GHCR release into private ECR without rebuilding it, preserve
the manifest digest, and set `image` to the resulting ECR reference by digest.
Compare the source and destination `sha256` values before applying; a tag match
is not sufficient. Configure the ACM certificate and
point the `public_origin` DNS name at the ALB.

```bash
cd deploy/aws/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan -out latchway.tfplan
terraform apply latchway.tfplan
```

Use an encrypted, locked remote Terraform backend. Generated credentials are
stored in Terraform state before being delivered through Secrets Manager.

## First run and migrations

Startup migrations are enabled for the first deploy and serialize on a
PostgreSQL advisory lock. Fetch the generated bootstrap value directly into a
password manager, create the first administrator, then set
`inject_admin_bootstrap_token=false` and apply immediately. Schedule deletion
of the now-unused bootstrap secret after confirming access. The second apply
also removes its task-definition reference and the execution role's permission
to read it.

For controlled upgrades, run a one-off task with the deployed task definition
and command override `migrate up` before updating the service. Use the output
subnet and security-group values; do not assign a public IP. Then set
`migrate_on_start=false` and roll out the new digest. The ECS circuit breaker
rolls application tasks back when `/readyz` never becomes healthy; migrations
remain forward-only.

Run a second one-off task with `--output json migrate status` after the
migration. Its CloudWatch stream must report `up_to_date=true` with `current`
equal to `available`. A successful `RunTask` API response is not itself proof
that a migration command finished successfully.

## Networking and streaming

Tasks and RDS have no public address. The example uses one NAT gateway for
provider egress; deploy one per availability zone if NAT-zone failure tolerance
is required. RDS accepts port 5432 only from the task security group and forces
TLS. The ALB idle timeout is 4,000 seconds for SSE; clients should still
reconnect and servers should emit periodic events.

At maximum scale, application pools reserve `maximum_tasks ×
db_connections_per_task` connections (200 by default). Leave separate capacity
for migrations, operations, and PostgreSQL maintenance before increasing either
number.

The application drains for 30 seconds. ECS waits 35 seconds before a forced
stop, and the ALB target group drains for 60 seconds. Keep these values ordered
when changing them: application timeout < ECS stop timeout <= target
deregistration delay.

Backups, point-in-time recovery, master-key custody, restore drills, and
forward-only rollback are covered in `docs/operations/backup-restore.md` and
`docs/operations/upgrades.md`.

## Release evidence

Create the fixed protected GitHub environment `deployment-evidence-aws` with
`AWS_ROLE_TO_ASSUME`. Its GitHub OIDC trust policy must restrict the repository,
release-tag ref, and this environment. The role needs read access to the ECS
cluster, service, task definition, and tasks; permission to run and stop tasks
on the named service/task definition; `iam:PassRole` only for the task and
execution roles; and read-only access to the named CloudWatch log group. It
does not need `secretsmanager:GetSecretValue`.

Before dispatch, inspect the provider-returned identifiers and resolved task
digests:

```bash
aws ecs describe-services --cluster CLUSTER --services SERVICE --region REGION
aws ecs describe-task-definition --task-definition TASK_DEFINITION --region REGION
aws ecs list-tasks --cluster CLUSTER --service-name SERVICE --desired-status RUNNING --region REGION
aws ecs describe-tasks --cluster CLUSTER --tasks TASK_ARNS --region REGION
```

Run `.github/workflows/deployment-evidence.yml` from the release tag with
`platform=aws`, the source GHCR release identity by digest, public HTTPS
endpoint, region, cluster, and service. The collector launches a private
one-off status task, obtains its exact JSON report from that task's authenticated
CloudWatch stream, confirms every running task resolved to the same digest,
checks Secrets Manager ARN references without fetching values, stops one of at
least two service tasks, waits for a distinct replacement, and probes
`/healthz` and `/readyz`. Missing log permissions or eventual log delivery time
out and fail the evidence run; they never become a manual pass.
