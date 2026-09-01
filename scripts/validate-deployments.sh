#!/usr/bin/env bash
set -Eeuo pipefail

output=${1:-/tmp/latchway-deployment-static.json}
terraform_image='hashicorp/terraform@sha256:6bbb82d575aa7bd4f0a2c6e3a0838ab9590426c08a71d7a2783643f01004d356'
release_image='ghcr.io/latchway/latchway@sha256:0000000000000000000000000000000000000000000000000000000000000000'

python3 scripts/deployment-evidence.py static --output "$output"
python3 -m unittest scripts/test_deployment_evidence.py

for ignored in \
  deploy/cloud-run/terraform/.terraform/provider \
  deploy/cloud-run/terraform/terraform.tfstate \
  deploy/cloud-run/terraform/terraform.tfstate.backup \
  deploy/cloud-run/terraform/production.tfvars \
  deploy/cloud-run/terraform/latchway.tfplan \
  deploy/cloud-run/terraform/crash.log \
  deploy/cloud-run/terraform/operator_override.tf; do
  git check-ignore --quiet "$ignored"
done
if git check-ignore --quiet deploy/cloud-run/terraform/terraform.tfvars.example; then
  echo "terraform.tfvars.example must remain tracked and reviewable" >&2
  exit 1
fi

LATCHWAY_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  docker compose -f compose.yaml config --quiet

LATCHWAY_IMAGE="$release_image" \
POSTGRES_PASSWORD='deployment-static-password' \
LATCHWAY_DATABASE_URL='postgresql://latchway:deployment-static-password@postgres:5432/latchway?sslmode=disable' \
LATCHWAY_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
LATCHWAY_PUBLIC_ORIGIN='https://ai.example.com' \
  docker compose -f deploy/compose/compose.release.yaml config --quiet

docker run --rm \
  --volume "$PWD/deploy/cloud-run/terraform:/work" \
  --workdir /work \
  --env TF_DATA_DIR=/tmp/latchway-cloud-run-tfdata \
  --entrypoint /bin/sh \
  "$terraform_image" \
  -c 'terraform fmt -check -recursive && terraform init -backend=false -input=false -lockfile=readonly && terraform validate'

docker run --rm \
  --volume "$PWD/deploy/aws/terraform:/work" \
  --workdir /work \
  --env TF_DATA_DIR=/tmp/latchway-aws-tfdata \
  --entrypoint /bin/sh \
  "$terraform_image" \
  -c 'terraform fmt -check -recursive && terraform init -backend=false -input=false -lockfile=readonly && terraform validate'

if [[ -n "${FLY_API_TOKEN:-}" ]]; then
  : "${FLY_APP:?FLY_APP is required when FLY_API_TOKEN is set}"
  if command -v flyctl >/dev/null 2>&1; then
    flyctl config validate --strict --app "$FLY_APP" --config deploy/fly/fly.toml
  elif command -v fly >/dev/null 2>&1; then
    fly config validate --strict --app "$FLY_APP" --config deploy/fly/fly.toml
  else
    echo "Fly CLI is required when FLY_API_TOKEN is set" >&2
    exit 1
  fi
fi

printf 'deployment validation passed; evidence: %s\n' "$output"
