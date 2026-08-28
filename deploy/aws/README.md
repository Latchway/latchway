# AWS ECS/Fargate and RDS

The Terraform example deploys the unchanged Latchway OCI image on two or more
private Fargate tasks behind an HTTPS Application Load Balancer. It provisions
private, encrypted PostgreSQL 18 RDS, Secrets Manager values, a 2 vCPU / 4 GiB
task, health checks, deployment rollback, autoscaling, logs, and least-privilege
secret reads.

Mirror the signed GHCR release into private ECR without rebuilding it, preserve
the digest, and set `image` to that digest. Configure the ACM certificate and
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
of the now-unused bootstrap secret after confirming access.

For controlled upgrades, run a one-off task with the deployed task definition
and command override `migrate up` before updating the service. Use the output
subnet and security-group values; do not assign a public IP. Then set
`migrate_on_start=false` and roll out the new digest. The ECS circuit breaker
rolls application tasks back when `/readyz` never becomes healthy; migrations
remain forward-only.

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

Backups, point-in-time recovery, master-key custody, restore drills, and
forward-only rollback are covered in `docs/operations/backup-restore.md` and
`docs/operations/upgrades.md`.
