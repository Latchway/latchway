#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-operational-resilience-drills.sh \
  --acknowledge-isolated-destructive-drill \
  --evidence-dir ABSOLUTE_EMPTY_DIRECTORY \
  --core-commit 40_HEX \
  --previous-candidate-commit 40_HEX \
  --previous-candidate-manifest ABSOLUTE_PATH \
  --candidate-image ghcr.io/latchway/latchway@sha256:... \
  --candidate-platform-image ghcr.io/latchway/latchway@sha256:... \
  --postgres-image docker.io/library/postgres@sha256:... \
  [--preloaded-candidate-platform-image-id sha256:... \
   --preloaded-previous-platform-image-id sha256:... \
   --preloaded-postgres-image-id sha256:...]
EOF
  exit 2
}

acknowledged=false
evidence_dir=
core_commit=
previous_candidate_commit=
previous_candidate_manifest=
candidate_image=
candidate_platform_image=
postgres_image=
preloaded_candidate_platform_image_id=
preloaded_previous_platform_image_id=
preloaded_postgres_image_id=
while (($#)); do
  case "$1" in
    --acknowledge-isolated-destructive-drill)
      acknowledged=true
      shift
      ;;
    --evidence-dir|--core-commit|--previous-candidate-commit|--previous-candidate-manifest|--candidate-image|--candidate-platform-image|--postgres-image|--preloaded-candidate-platform-image-id|--preloaded-previous-platform-image-id|--preloaded-postgres-image-id)
      (($# >= 2)) || usage
      case "$1" in
        --evidence-dir) evidence_dir=$2 ;;
        --core-commit) core_commit=$2 ;;
        --previous-candidate-commit) previous_candidate_commit=$2 ;;
        --previous-candidate-manifest) previous_candidate_manifest=$2 ;;
        --candidate-image) candidate_image=$2 ;;
        --candidate-platform-image) candidate_platform_image=$2 ;;
        --postgres-image) postgres_image=$2 ;;
        --preloaded-candidate-platform-image-id) preloaded_candidate_platform_image_id=$2 ;;
        --preloaded-previous-platform-image-id) preloaded_previous_platform_image_id=$2 ;;
        --preloaded-postgres-image-id) preloaded_postgres_image_id=$2 ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ "$acknowledged" == true ]] || usage
[[ "$evidence_dir" == /* ]] || { echo "evidence directory must be absolute" >&2; exit 2; }
[[ "$core_commit" =~ ^[0-9a-f]{40}$ ]] || { echo "core commit must be exactly 40 lowercase hexadecimal characters" >&2; exit 2; }
[[ "$previous_candidate_commit" =~ ^[0-9a-f]{40}$ ]] || { echo "previous candidate commit must be exactly 40 lowercase hexadecimal characters" >&2; exit 2; }
[[ "$previous_candidate_commit" != "$core_commit" ]] || { echo "previous and current candidate commits must differ" >&2; exit 2; }
[[ "$previous_candidate_manifest" == /* && -f "$previous_candidate_manifest" && ! -L "$previous_candidate_manifest" ]] || { echo "previous candidate manifest must be an absolute regular file" >&2; exit 2; }
[[ "$candidate_image" =~ ^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$ ]] || { echo "candidate image must be an exact Latchway OCI digest" >&2; exit 2; }
[[ "$candidate_platform_image" =~ ^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$ ]] || { echo "candidate platform image must be an exact Latchway OCI digest" >&2; exit 2; }
[[ "$postgres_image" =~ ^docker\.io/library/postgres@sha256:[0-9a-f]{64}$ ]] || { echo "PostgreSQL image must be an exact Docker Hub OCI digest" >&2; exit 2; }

preloaded_mode=false
if [[ -n "$preloaded_candidate_platform_image_id$preloaded_previous_platform_image_id$preloaded_postgres_image_id" ]]; then
  [[ -n "$preloaded_candidate_platform_image_id" && -n "$preloaded_previous_platform_image_id" && -n "$preloaded_postgres_image_id" ]] || {
    echo "credential-free preloaded mode requires all three immutable local image IDs" >&2
    exit 2
  }
  for image_id in "$preloaded_candidate_platform_image_id" "$preloaded_previous_platform_image_id" "$preloaded_postgres_image_id"; do
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo "preloaded image IDs must be immutable sha256 image IDs" >&2
      exit 2
    }
  done
  [[ "$(printf '%s\n' "$preloaded_candidate_platform_image_id" "$preloaded_previous_platform_image_id" "$preloaded_postgres_image_id" | sort -u | wc -l | tr -d ' ')" == 3 ]] || {
    echo "preloaded candidate, prior-candidate, and PostgreSQL image IDs must differ" >&2
    exit 2
  }
  preloaded_mode=true
fi
[[ ! -L "$evidence_dir" ]] || { echo "evidence directory cannot be a symbolic link" >&2; exit 2; }
mkdir -p -- "$evidence_dir"
[[ -d "$evidence_dir" ]] || { echo "evidence path is not a directory" >&2; exit 2; }
[[ -z "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { echo "evidence directory must be empty" >&2; exit 2; }
chmod 700 -- "$evidence_dir"

for command in docker curl jq openssl python3 git awk; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 2; }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
[[ "$(git -C "$repository_root" rev-parse HEAD)" == "$core_commit" ]] || { echo "checkout does not match the candidate commit" >&2; exit 2; }
[[ -z "$(git -C "$repository_root" status --porcelain=v1)" ]] || { echo "drill evidence requires a clean candidate checkout" >&2; exit 2; }
[[ "$(git -C "$repository_root" rev-parse --verify "$previous_candidate_commit^{commit}")" == "$previous_candidate_commit" ]] || { echo "previous candidate commit is unavailable" >&2; exit 2; }
git -C "$repository_root" merge-base --is-ancestor "$previous_candidate_commit" "$core_commit" || { echo "previous candidate must be a distinct ancestor of the current candidate" >&2; exit 2; }

previous_candidate_tag=$(jq --raw-output .intended_tag "$previous_candidate_manifest")
previous_candidate_version=$(jq --raw-output .version "$previous_candidate_manifest")
previous_candidate_image=$(jq --raw-output '.image.repository + "@" + .image.index_digest' "$previous_candidate_manifest")
previous_candidate_platform_image=$(jq --raw-output '.image.repository + "@" + .image.platforms["linux/amd64"]' "$previous_candidate_manifest")
python3 "$script_dir/release-candidate.py" \
  --verify \
  --manifest "$previous_candidate_manifest" \
  --commit "$previous_candidate_commit" \
  --tag "$previous_candidate_tag" \
  --image ghcr.io/latchway/latchway >/dev/null
[[ "$previous_candidate_version" == "${previous_candidate_tag#v}" ]] || { echo "previous candidate version and intended tag disagree" >&2; exit 2; }
for image in "$previous_candidate_image" "$previous_candidate_platform_image" "$candidate_image" "$candidate_platform_image"; do
  [[ "$image" =~ ^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$ ]] || { echo "candidate manifest contains an invalid immutable image reference" >&2; exit 2; }
done
[[ "$(printf '%s\n' "$previous_candidate_image" "$previous_candidate_platform_image" "$candidate_image" "$candidate_platform_image" | sort -u | wc -l | tr -d ' ')" == 4 ]] || { echo "candidate index and platform image references must all differ" >&2; exit 2; }

suffix="${core_commit:0:12}-$$-$(date -u +%Y%m%d%H%M%S)"
network="latchway-operational-$suffix"
source_postgres="latchway-operational-source-$suffix"
restore_postgres="latchway-operational-restore-$suffix"
gateway="latchway-operational-gateway-$suffix"
network_created=false
source_created=false
restore_created=false
gateway_created=false

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ "$gateway_created" == true ]]; then
    docker rm --force "$gateway" >/dev/null 2>&1
  fi
  if [[ "$restore_created" == true ]]; then
    docker rm --volumes --force "$restore_postgres" >/dev/null 2>&1
  fi
  if [[ "$source_created" == true ]]; then
    docker rm --volumes --force "$source_postgres" >/dev/null 2>&1
  fi
  if [[ "$network_created" == true ]]; then
    docker network rm "$network" >/dev/null 2>&1
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
candidate_runtime_image=$candidate_platform_image
previous_candidate_runtime_image=$previous_candidate_platform_image
postgres_runtime_image=$postgres_image
if [[ "$preloaded_mode" == true ]]; then
  candidate_runtime_image=$preloaded_candidate_platform_image_id
  previous_candidate_runtime_image=$preloaded_previous_platform_image_id
  postgres_runtime_image=$preloaded_postgres_image_id
  [[ "$(docker image inspect --format '{{.Id}}' "$candidate_runtime_image")" == "$preloaded_candidate_platform_image_id" ]]
  [[ "$(docker image inspect --format '{{.Id}}' "$previous_candidate_runtime_image")" == "$preloaded_previous_platform_image_id" ]]
  [[ "$(docker image inspect --format '{{.Id}}' "$postgres_runtime_image")" == "$preloaded_postgres_image_id" ]]
else
  docker pull --platform linux/amd64 "$previous_candidate_platform_image" >/dev/null
  docker pull --platform linux/amd64 "$candidate_platform_image" >/dev/null
  docker pull --platform linux/amd64 "$postgres_image" >/dev/null
fi

candidate_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$candidate_runtime_image")
previous_candidate_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$previous_candidate_runtime_image")
candidate_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$candidate_runtime_image")
previous_candidate_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$previous_candidate_runtime_image")
postgres_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$postgres_runtime_image")
[[ "$candidate_revision" == "$core_commit" ]] || { echo "candidate image revision label does not match the candidate commit" >&2; exit 1; }
[[ "$previous_candidate_revision" == "$previous_candidate_commit" ]] || { echo "previous candidate image revision label does not match its candidate commit" >&2; exit 1; }
[[ "$candidate_platform" == linux/amd64 && "$previous_candidate_platform" == linux/amd64 && "$postgres_platform" == linux/amd64 ]] || { echo "drill images must be exact linux/amd64 children" >&2; exit 1; }

docker network create --internal "$network" >/dev/null
network_created=true
[[ "$(docker network inspect --format '{{.Internal}}' "$network")" == true ]] || { echo "drill network is not internal" >&2; exit 1; }

postgres_password=$(openssl rand -hex 32)
master_key=$(openssl rand -base64 32 | tr -d '\n')
export POSTGRES_DB=latchway
export POSTGRES_USER=latchway
export POSTGRES_PASSWORD=$postgres_password
export LATCHWAY_MASTER_KEY=$master_key
export LATCHWAY_PUBLIC_ORIGIN=http://localhost:8080
export LATCHWAY_ROLE=all
export LATCHWAY_MIGRATE_ON_START=false
export LATCHWAY_DB_MAX_CONNECTIONS=5

start_postgres() {
  local name=$1
  docker run --detach \
    --name "$name" \
    --network "$network" \
    --tmpfs /tmp:size=64m,mode=1777 \
    --security-opt no-new-privileges:true \
    --env POSTGRES_DB \
    --env POSTGRES_USER \
    --env POSTGRES_PASSWORD \
    "$postgres_runtime_image" >/dev/null
  if [[ "$name" == "$source_postgres" ]]; then
    source_created=true
  elif [[ "$name" == "$restore_postgres" ]]; then
    restore_created=true
  else
    echo "refusing an unexpected PostgreSQL container name" >&2
    exit 1
  fi
  local ready=false
  for _ in $(seq 1 90); do
    if docker exec "$name" pg_isready --username latchway --dbname latchway >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ "$ready" == true ]] || { echo "isolated PostgreSQL did not become ready: $name" >&2; exit 1; }
}

database_url() {
  local name=$1
  printf 'postgres://latchway:%s@%s:5432/latchway?sslmode=disable' "$postgres_password" "$name"
}

run_cli() {
  local image=$1
  local database=$2
  local output=$3
  shift 3
  export LATCHWAY_DATABASE_URL
  LATCHWAY_DATABASE_URL=$(database_url "$database")
  docker run --rm \
    --network "$network" \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --env LATCHWAY_DATABASE_URL \
    --env LATCHWAY_MASTER_KEY \
    --env LATCHWAY_PUBLIC_ORIGIN \
    --env LATCHWAY_ROLE \
    --env LATCHWAY_MIGRATE_ON_START \
    --env LATCHWAY_DB_MAX_CONNECTIONS \
    "$image" --output json "$@" >"$output"
}

capture_state() {
  local database=$1
  local prefix=$2
  local identity=$3
  local raw="$evidence_dir/.${prefix}-state.raw.json"
  docker exec "$database" psql \
    --username latchway \
    --dbname latchway \
    --tuples-only \
    --no-align \
    --command "SELECT json_build_object(
      'row_counts', json_build_object(
        'organizations', (SELECT count(*) FROM organizations WHERE slug = 'operational-drill'),
        'applications', (SELECT count(*) FROM applications WHERE slug = 'operational-drill'),
        'environments', (SELECT count(*) FROM environments WHERE slug = 'operational-drill'),
        'admin_users', (SELECT count(*) FROM admin_users WHERE email_normalized = 'operator@operational-drill.invalid'),
        'admin_memberships', (SELECT count(*) FROM admin_memberships WHERE admin_membership_id = 'amb_01ARZ3NDEKTSV4RRFFQ69G5FAZ'),
        'admin_sessions', (SELECT count(*) FROM admin_sessions WHERE admin_session_id = 'asn_01ARZ3NDEKTSV4RRFFQ69G5FB0'),
        'config_revisions', (SELECT count(*) FROM config_revisions WHERE config_revision_id = 'rev_01ARZ3NDEKTSV4RRFFQ69G5FB1'),
        'secret_records', (SELECT count(*) FROM secret_records WHERE secret_record_id = 'sec_01ARZ3NDEKTSV4RRFFQ69G5FB2'),
        'quota_buckets', (SELECT count(*) FROM quota_buckets WHERE quota_bucket_id = 'qbk_01ARZ3NDEKTSV4RRFFQ69G5FB3'),
        'usage_rollups_daily', (SELECT count(*) FROM usage_rollups_daily WHERE environment_id = 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX' AND dimension_key = 'environment:operational-drill'),
        'jobs', (SELECT count(*) FROM jobs WHERE job_id = 'job_01ARZ3NDEKTSV4RRFFQ69G5FB4'),
        'audit_events', (SELECT count(*) FROM audit_events WHERE audit_event_id = 'aud_01ARZ3NDEKTSV4RRFFQ69G5FB5')
      ),
      'markers', json_build_object(
        'organization', (SELECT json_build_object('id', organization_id, 'status', status) FROM organizations WHERE slug = 'operational-drill'),
        'environment', (SELECT json_build_object('id', environment_id, 'kind', kind, 'status', status) FROM environments WHERE slug = 'operational-drill'),
        'administrator', (SELECT json_build_object('id', admin_user_id, 'status', status) FROM admin_users WHERE email_normalized = 'operator@operational-drill.invalid'),
        'configuration', (SELECT json_build_object('id', config_revision_id, 'status', status, 'document', document) FROM config_revisions WHERE config_revision_id = 'rev_01ARZ3NDEKTSV4RRFFQ69G5FB1'),
        'secret', (SELECT json_build_object('id', secret_record_id, 'name', name, 'version', version, 'ciphertext_bytes', octet_length(ciphertext)) FROM secret_records WHERE secret_record_id = 'sec_01ARZ3NDEKTSV4RRFFQ69G5FB2'),
        'quota', (SELECT json_build_object('id', quota_bucket_id, 'metric', metric, 'used_units', used_units) FROM quota_buckets WHERE quota_bucket_id = 'qbk_01ARZ3NDEKTSV4RRFFQ69G5FB3'),
        'usage', (SELECT json_build_object('metric', metric, 'units', units, 'request_count', request_count) FROM usage_rollups_daily WHERE environment_id = 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX' AND dimension_key = 'environment:operational-drill'),
        'job', (SELECT json_build_object('id', job_id, 'type', job_type, 'status', status) FROM jobs WHERE job_id = 'job_01ARZ3NDEKTSV4RRFFQ69G5FB4'),
        'audit', (SELECT json_build_object('id', audit_event_id, 'action', action, 'outcome', outcome) FROM audit_events WHERE audit_event_id = 'aud_01ARZ3NDEKTSV4RRFFQ69G5FB5')
      )
    )" >"$raw"
  jq --compact-output --sort-keys . "$raw" >"$evidence_dir/.${prefix}-state.canonical.json"
  local fingerprint
  fingerprint=$(openssl dgst -sha256 "$evidence_dir/.${prefix}-state.canonical.json" | awk '{print $NF}')
  jq -n \
    --arg database_identity_sha256 "$identity" \
    --arg state_fingerprint_sha256 "$fingerprint" \
    --slurpfile state "$raw" \
    '{
      database_identity_sha256: $database_identity_sha256,
      state_fingerprint_sha256: $state_fingerprint_sha256,
      row_counts: $state[0].row_counts
    }' >"$evidence_dir/${prefix}-state.json"
  rm -f -- "$raw" "$evidence_dir/.${prefix}-state.canonical.json"
}

start_gateway_and_capture() {
  local image=$1
  local database=$2
  local prefix=$3
  export LATCHWAY_DATABASE_URL
  LATCHWAY_DATABASE_URL=$(database_url "$database")
  docker run --detach \
    --name "$gateway" \
    --network "$network" \
    --publish 127.0.0.1:0:8080/tcp \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --env LATCHWAY_DATABASE_URL \
    --env LATCHWAY_MASTER_KEY \
    --env LATCHWAY_PUBLIC_ORIGIN \
    --env LATCHWAY_ROLE \
    --env LATCHWAY_MIGRATE_ON_START \
    --env LATCHWAY_DB_MAX_CONNECTIONS \
    "$image" >/dev/null
  gateway_created=true
  local published port ready=false
  published=$(docker port "$gateway" 8080/tcp)
  port=${published##*:}
  [[ "$port" =~ ^[0-9]+$ ]] || { echo "could not resolve isolated gateway port" >&2; exit 1; }
  for _ in $(seq 1 90); do
    if curl --fail --silent --show-error "http://127.0.0.1:${port}/readyz" >"$evidence_dir/${prefix}-readiness.json" 2>/dev/null; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ "$ready" == true ]] || { docker logs "$gateway" >&2; echo "isolated gateway did not become ready" >&2; exit 1; }
  curl --fail --silent --show-error "http://127.0.0.1:${port}/healthz" >"$evidence_dir/${prefix}-health.json"
  docker stop --time 35 "$gateway" >/dev/null
  docker rm "$gateway" >/dev/null
  gateway_created=false
}

start_postgres "$source_postgres"
source_identity=$(docker inspect --format '{{.Id}}' "$source_postgres")
[[ "$source_identity" =~ ^[0-9a-f]{64}$ ]] || { echo "source database identity is not immutable" >&2; exit 1; }

run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/.previous-migrate-up.json" migrate up
run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/previous-migration.json" migrate status
run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/previous-doctor.json" doctor
run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/previous-version.json" version
previous_version=$(jq --raw-output .version "$evidence_dir/previous-version.json")
previous_version_commit=$(jq --raw-output .commit "$evidence_dir/previous-version.json")
[[ "$previous_version" == "$previous_candidate_version" ]] || { echo "previous candidate runtime version does not match its manifest" >&2; exit 1; }
[[ "$previous_version_commit" == "$previous_candidate_commit" ]] || { echo "previous candidate runtime version and OCI revision disagree" >&2; exit 1; }

docker exec "$source_postgres" psql --username latchway --dbname latchway --set ON_ERROR_STOP=1 --command "
  INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name)
  VALUES ('adm_01ARZ3NDEKTSV4RRFFQ69G5FAY', 'operator@operational-drill.invalid', 'operator@operational-drill.invalid', 'Operational Drill Operator');
  INSERT INTO organizations (organization_id, slug, display_name)
  VALUES ('org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'operational-drill', 'Operational Drill');
  INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role, created_by_admin_user_id)
  VALUES ('amb_01ARZ3NDEKTSV4RRFFQ69G5FAZ', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'adm_01ARZ3NDEKTSV4RRFFQ69G5FAY', 'owner', 'adm_01ARZ3NDEKTSV4RRFFQ69G5FAY');
  INSERT INTO applications (application_id, organization_id, slug, display_name)
  VALUES ('app_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'operational-drill', 'Operational Drill');
  INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, status, disabled_at)
  VALUES ('env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'app_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'operational-drill', 'Operational Drill', 'staging', 'disabled', now());
  INSERT INTO admin_sessions (admin_session_id, organization_id, admin_user_id, token_hash, token_hint, csrf_token_hash, expires_at)
  VALUES ('asn_01ARZ3NDEKTSV4RRFFQ69G5FB0', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'adm_01ARZ3NDEKTSV4RRFFQ69G5FAY', decode(repeat('11', 32), 'hex'), 'Drill1', decode(repeat('12', 32), 'hex'), now() + interval '1 day');
  INSERT INTO config_revisions (config_revision_id, organization_id, application_id, environment_id, revision_number, etag, status, document, created_by_admin_user_id)
  VALUES ('rev_01ARZ3NDEKTSV4RRFFQ69G5FB1', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'app_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 1, 'operational-drill', 'draft', '{\"drill\":\"backup-upgrade\"}'::jsonb, 'adm_01ARZ3NDEKTSV4RRFFQ69G5FAY');
  INSERT INTO secret_records (secret_record_id, organization_id, application_id, environment_id, name, version, encryption_format_version, algorithm, master_key_identifier, ciphertext, nonce, created_by_admin_user_id)
  VALUES ('sec_01ARZ3NDEKTSV4RRFFQ69G5FB2', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'app_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'drill-secret', 1, 1, 'aes-256-gcm', 'operational-drill', decode(repeat('21', 17), 'hex'), decode(repeat('22', 12), 'hex'), 'adm_01ARZ3NDEKTSV4RRFFQ69G5FAY');
  INSERT INTO quota_buckets (quota_bucket_id, organization_id, application_id, environment_id, metric, scope_type, scope_key, algorithm, window_key, hard_maximum, used_units)
  VALUES ('qbk_01ARZ3NDEKTSV4RRFFQ69G5FB3', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'app_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'logical_requests', 'environment', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'calendar', '2026-09-01', 10, 1);
  INSERT INTO usage_rollups_daily (organization_id, application_id, environment_id, bucket_date, dimension_key, dimensions, metric, units, request_count)
  VALUES ('org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'app_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', DATE '2026-09-01', 'environment:operational-drill', '{\"environment\":\"operational-drill\"}'::jsonb, 'logical_requests', 1, 1);
  INSERT INTO jobs (job_id, organization_id, environment_id, job_type, idempotency_key, payload, status, max_attempts, created_at, updated_at, completed_at)
  VALUES ('job_01ARZ3NDEKTSV4RRFFQ69G5FB4', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'enforce_retention', 'operational-drill-completed', '{\"drill\":true}'::jsonb, 'succeeded', 1, statement_timestamp(), statement_timestamp(), statement_timestamp());
  INSERT INTO audit_events (audit_event_id, organization_id, environment_id, actor_kind, action, resource_type, resource_id, outcome, occurred_at)
  VALUES ('aud_01ARZ3NDEKTSV4RRFFQ69G5FB5', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'system', 'system.operational_drill', 'environment', 'env_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'succeeded', statement_timestamp());
" >/dev/null
capture_state "$source_postgres" previous "$source_identity"
start_gateway_and_capture "$previous_candidate_runtime_image" "$source_postgres" previous

docker exec "$source_postgres" pg_dump \
  --username latchway \
  --dbname latchway \
  --format custom \
  --no-owner \
  --no-acl \
  --file /tmp/latchway-operational.dump
docker cp "$source_postgres:/tmp/latchway-operational.dump" "$evidence_dir/backup.dump"
[[ -s "$evidence_dir/backup.dump" ]] || { echo "backup archive is empty" >&2; exit 1; }

start_postgres "$restore_postgres"
restore_identity=$(docker inspect --format '{{.Id}}' "$restore_postgres")
[[ "$restore_identity" =~ ^[0-9a-f]{64}$ && "$restore_identity" != "$source_identity" ]] || { echo "restore database identity is invalid" >&2; exit 1; }
docker cp "$evidence_dir/backup.dump" "$restore_postgres:/tmp/latchway-operational.dump"
docker exec "$restore_postgres" pg_restore \
  --username latchway \
  --dbname latchway \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  --exit-on-error \
  /tmp/latchway-operational.dump
run_cli "$previous_candidate_runtime_image" "$restore_postgres" "$evidence_dir/restore-migration.json" migrate status
run_cli "$previous_candidate_runtime_image" "$restore_postgres" "$evidence_dir/restore-doctor.json" doctor
capture_state "$restore_postgres" restore "$restore_identity"
start_gateway_and_capture "$previous_candidate_runtime_image" "$restore_postgres" restore

run_cli "$candidate_runtime_image" "$source_postgres" "$evidence_dir/.candidate-migrate-up.json" migrate up
run_cli "$candidate_runtime_image" "$source_postgres" "$evidence_dir/candidate-migration.json" migrate status
run_cli "$candidate_runtime_image" "$source_postgres" "$evidence_dir/candidate-doctor.json" doctor
run_cli "$candidate_runtime_image" "$source_postgres" "$evidence_dir/candidate-version.json" version
capture_state "$source_postgres" candidate "$source_identity"
start_gateway_and_capture "$candidate_runtime_image" "$source_postgres" candidate

run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/rollback-migration.json" migrate status
run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/rollback-doctor.json" doctor
run_cli "$previous_candidate_runtime_image" "$source_postgres" "$evidence_dir/rollback-version.json" version
capture_state "$source_postgres" rollback "$source_identity"
start_gateway_and_capture "$previous_candidate_runtime_image" "$source_postgres" rollback

if [[ "$preloaded_mode" == true ]]; then
  candidate_platform_repo_digests=$(jq --compact-output --null-input --arg value "$candidate_platform_image" '[$value]')
  previous_candidate_platform_repo_digests=$(jq --compact-output --null-input --arg value "$previous_candidate_platform_image" '[$value]')
  postgres_repo_digests=$(jq --compact-output --null-input --arg value "$postgres_image" '[$value]')
else
  candidate_platform_repo_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$candidate_platform_image")
  previous_candidate_platform_repo_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$previous_candidate_platform_image")
  postgres_repo_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$postgres_image")
fi
jq -n \
  --arg candidate_oci_reference "$candidate_image" \
  --arg candidate_platform_oci_reference "$candidate_platform_image" \
  --arg candidate_revision "$candidate_revision" \
  --argjson candidate_platform_repo_digests "$candidate_platform_repo_digests" \
  --arg previous_candidate_oci_reference "$previous_candidate_image" \
  --arg previous_candidate_platform_oci_reference "$previous_candidate_platform_image" \
  --arg previous_candidate_revision "$previous_candidate_revision" \
  --arg previous_candidate_version "$previous_candidate_version" \
  --arg previous_candidate_intended_tag "$previous_candidate_tag" \
  --argjson previous_candidate_platform_repo_digests "$previous_candidate_platform_repo_digests" \
  --arg postgres_oci_reference "$postgres_image" \
  --argjson postgres_repo_digests "$postgres_repo_digests" \
  --arg source_database_identity_sha256 "$source_identity" \
  --arg restore_database_identity_sha256 "$restore_identity" \
  '{
    candidate_oci_reference: $candidate_oci_reference,
    candidate_platform_oci_reference: $candidate_platform_oci_reference,
    candidate_revision: $candidate_revision,
    candidate_platform_repo_digests: $candidate_platform_repo_digests,
    previous_candidate_oci_reference: $previous_candidate_oci_reference,
    previous_candidate_platform_oci_reference: $previous_candidate_platform_oci_reference,
    previous_candidate_revision: $previous_candidate_revision,
    previous_candidate_version: $previous_candidate_version,
    previous_candidate_intended_tag: $previous_candidate_intended_tag,
    previous_candidate_platform_repo_digests: $previous_candidate_platform_repo_digests,
    platform: "linux/amd64",
    postgres_oci_reference: $postgres_oci_reference,
    postgres_repo_digests: $postgres_repo_digests,
    network_internal: true,
    source_database_identity_sha256: $source_database_identity_sha256,
    restore_database_identity_sha256: $restore_database_identity_sha256
  }' >"$evidence_dir/image-inspection.json"

rm -f -- "$evidence_dir/.previous-migrate-up.json" "$evidence_dir/.candidate-migrate-up.json"
finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 "$script_dir/operational-drill-report.py" \
  --evidence-directory "$evidence_dir" \
  --core-commit "$core_commit" \
  --previous-candidate-commit "$previous_candidate_commit" \
  --previous-candidate-version "$previous_candidate_version" \
  --previous-candidate-tag "$previous_candidate_tag" \
  --previous-candidate-image "$previous_candidate_image" \
  --previous-candidate-platform-image "$previous_candidate_platform_image" \
  --candidate-image "$candidate_image" \
  --candidate-platform-image "$candidate_platform_image" \
  --postgres-image "$postgres_image" \
  --started-at "$started_at" \
  --finished-at "$finished_at"

echo "isolated backup, restore, upgrade, and application rollback drills passed: $evidence_dir"
