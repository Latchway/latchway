#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 --acknowledge-disposable-target --run-id SAFE_ID --output-dir ABSOLUTE_EMPTY_DIRECTORY --commit COMMIT --image INDEX_OCI --platform-image AMD64_CHILD_OCI --candidate-image-id SHA256_ID --postgres-image POSTGRES_OCI --postgres-image-id SHA256_ID --operator TEXT" >&2
  exit 2
}

acknowledge=false
run_id=
output_dir=
commit=
image=
platform_image=
candidate_image_id=
postgres_image=
postgres_image_id=
operator=
while (($#)); do
  case "$1" in
    --acknowledge-disposable-target) acknowledge=true; shift ;;
    --run-id) (($# >= 2)) || usage; run_id=$2; shift 2 ;;
    --output-dir) (($# >= 2)) || usage; output_dir=$2; shift 2 ;;
    --commit) (($# >= 2)) || usage; commit=$2; shift 2 ;;
    --image) (($# >= 2)) || usage; image=$2; shift 2 ;;
    --platform-image) (($# >= 2)) || usage; platform_image=$2; shift 2 ;;
    --candidate-image-id) (($# >= 2)) || usage; candidate_image_id=$2; shift 2 ;;
    --postgres-image) (($# >= 2)) || usage; postgres_image=$2; shift 2 ;;
    --postgres-image-id) (($# >= 2)) || usage; postgres_image_id=$2; shift 2 ;;
    --operator) (($# >= 2)) || usage; operator=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$acknowledge" == true ]] || usage
if ((EUID == 0)); then
  echo "refusing to create a destructive failure topology as root" >&2
  exit 2
fi
[[ "$run_id" =~ ^[a-z0-9][a-z0-9-]{7,40}$ ]] || { echo "run ID is invalid" >&2; exit 2; }
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "commit is invalid" >&2; exit 2; }
[[ "$image" =~ ^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$ ]] || { echo "candidate index reference is invalid" >&2; exit 2; }
[[ "$platform_image" =~ ^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$ ]] || { echo "candidate platform reference is invalid" >&2; exit 2; }
[[ "$image" != "$platform_image" ]] || { echo "candidate index and platform references must differ" >&2; exit 2; }
[[ "$candidate_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "candidate image ID is invalid" >&2; exit 2; }
[[ "$postgres_image" =~ ^docker\.io/library/postgres@sha256:[0-9a-f]{64}$ ]] || { echo "PostgreSQL reference is invalid" >&2; exit 2; }
[[ "$postgres_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "PostgreSQL image ID is invalid" >&2; exit 2; }
[[ "$candidate_image_id" != "$postgres_image_id" ]] || { echo "candidate and PostgreSQL image IDs must differ" >&2; exit 2; }
[[ ${#operator} -ge 1 && ${#operator} -le 200 && "$operator" != *$'\n'* && "$operator" != *$'\r'* ]] || { echo "operator identity is invalid" >&2; exit 2; }
[[ "$output_dir" == /* ]] || { echo "evidence directory must be absolute" >&2; exit 2; }
[[ -d "$output_dir" && ! -L "$output_dir" ]] || { echo "evidence directory must be one real directory" >&2; exit 2; }
[[ -z "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { echo "evidence directory must be empty" >&2; exit 2; }
chmod 0700 "$output_dir"

for dependency in docker git python3 openssl sha256sum timeout; do
  command -v "$dependency" >/dev/null || { echo "required failure dependency is unavailable: $dependency" >&2; exit 2; }
done
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo "failure release topology requires a Linux x86_64 runner" >&2; exit 2; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
[[ "$(git -C "$repository_root" rev-parse --verify HEAD)" == "$commit" ]] || { echo "source checkout does not match candidate commit" >&2; exit 1; }
[[ -z "$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all)" ]] || { echo "failure release topology requires one exact clean checkout" >&2; exit 1; }

observed_candidate_id=$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Id}}' "$candidate_image_id")
observed_postgres_id=$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Id}}' "$postgres_image_id")
[[ "$observed_candidate_id" == "$candidate_image_id" && "$observed_postgres_id" == "$postgres_image_id" ]] || { echo "preloaded image identity changed" >&2; exit 1; }
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Os}}/{{.Architecture}}' "$candidate_image_id")" == linux/amd64 ]] || { echo "candidate image is not linux/amd64" >&2; exit 1; }
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Os}}/{{.Architecture}}' "$postgres_image_id")" == linux/amd64 ]] || { echo "PostgreSQL image is not linux/amd64" >&2; exit 1; }
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$candidate_image_id")" == "$commit" ]] || { echo "candidate image revision label does not match commit" >&2; exit 1; }
candidate_digests=$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{json .RepoDigests}}' "$candidate_image_id")
postgres_digests=$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{json .RepoDigests}}' "$postgres_image_id")
python3 - "$candidate_digests" "$platform_image" "$postgres_digests" "$postgres_image" <<'PY'
import json
import sys
candidate, candidate_reference, postgres, postgres_reference = sys.argv[1:]
if candidate_reference not in json.loads(candidate) or postgres_reference not in json.loads(postgres):
    raise SystemExit("preloaded image IDs are not bound to the exact authenticated OCI references")
PY

host_uid=$(id -u)
host_gid=$(id -g)
[[ "$host_uid:$host_gid" =~ ^[0-9]+:[0-9]+$ ]] || { echo "host user identity is invalid" >&2; exit 2; }

temporary_root=$(mktemp -d /tmp/latchway-failure-topology.XXXXXX)
[[ "$temporary_root" == /tmp/latchway-failure-topology.* ]] || { echo "unsafe failure temporary directory" >&2; exit 1; }
runtime_dir="$temporary_root/runtime"
mkdir -m 0700 "$runtime_dir"
plan_path="$temporary_root/controller-plan.json"

prefix="latchway-failure-$run_id"
network=$prefix
postgres="$prefix-postgres"
fixture="$prefix-fixture"
load_balancer="$prefix-load-balancer"
driver="$prefix-driver"
apis=("$prefix-api-1" "$prefix-api-2")
workers=("$prefix-worker-1" "$prefix-worker-2")
tools_tag="latchway-failure-tools:$run_id"
run_label="dev.latchway.failure.run"
role_label="dev.latchway.failure.role"
scenario_timeout=300
overall_timeout=1800
drain_timeout=45
network_created=false
expected_network_id=
tools_image_id=

declare -A expected_roles=(
  ["$postgres"]="postgres"
  ["$fixture"]="fixture"
  ["$load_balancer"]="load-balancer"
  ["$driver"]="driver"
  ["${apis[0]}"]="api"
  ["${apis[1]}"]="api"
  ["${workers[0]}"]="worker"
  ["${workers[1]}"]="worker"
)
declare -A expected_container_ids=()

record_created_container() {
  local container=$1
  local reported_id=$2
  local observed_id
  [[ "$reported_id" =~ ^[0-9a-f]{64}$ ]] || { echo "created failure container ID is invalid" >&2; exit 1; }
  observed_id=$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.Id}}' "$container")
  [[ "$observed_id" == "$reported_id" ]] || { echo "created failure container identity changed" >&2; exit 1; }
  expected_container_ids["$container"]=$reported_id
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  for container in "$driver" "${workers[1]}" "${workers[0]}" "${apis[1]}" "${apis[0]}" "$load_balancer" "$fixture" "$postgres"; do
    expected_id=${expected_container_ids[$container]:-}
    if [[ -n "$expected_id" ]] && timeout --signal=TERM --kill-after=5s 30s docker inspect "$container" >/dev/null 2>&1; then
      observed_id=$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.Id}}' "$container" 2>/dev/null)
      observed_run=$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format "{{index .Config.Labels \"$run_label\"}}" "$container" 2>/dev/null)
      observed_role=$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format "{{index .Config.Labels \"$role_label\"}}" "$container" 2>/dev/null)
      if [[ "$observed_id" == "$expected_id" && "$observed_run" == "$run_id" && "$observed_role" == "${expected_roles[$container]}" ]]; then
        timeout --signal=TERM --kill-after=5s 30s docker rm --force "$container" >/dev/null 2>&1
      fi
    fi
  done
  if [[ "$network_created" == true && -n "$expected_network_id" ]] && timeout --signal=TERM --kill-after=5s 30s docker network inspect "$network" >/dev/null 2>&1; then
    observed_network_id=$(timeout --signal=TERM --kill-after=5s 30s docker network inspect --format '{{.Id}}' "$network" 2>/dev/null)
    observed_run=$(timeout --signal=TERM --kill-after=5s 30s docker network inspect --format "{{index .Labels \"$run_label\"}}" "$network" 2>/dev/null)
    [[ "$observed_network_id" == "$expected_network_id" && "$observed_run" == "$run_id" ]] && timeout --signal=TERM --kill-after=5s 30s docker network rm "$network" >/dev/null 2>&1
  fi
  if [[ -n "$tools_image_id" ]] && timeout --signal=TERM --kill-after=5s 30s docker image inspect "$tools_tag" >/dev/null 2>&1; then
    observed_tools_id=$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Id}}' "$tools_tag" 2>/dev/null)
    [[ "$observed_tools_id" == "$tools_image_id" ]] && timeout --signal=TERM --kill-after=5s 30s docker image rm "$tools_tag" >/dev/null 2>&1
  fi
  if [[ "$temporary_root" == /tmp/latchway-failure-topology.* ]]; then
    rm -rf -- "$temporary_root"
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

if timeout --signal=TERM --kill-after=5s 30s docker network inspect "$network" >/dev/null 2>&1; then
  echo "refusing to reuse an existing failure network" >&2
  exit 1
fi
for container in "$driver" "${workers[1]}" "${workers[0]}" "${apis[1]}" "${apis[0]}" "$load_balancer" "$fixture" "$postgres"; do
  if timeout --signal=TERM --kill-after=5s 30s docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to reuse an existing failure container" >&2
    exit 1
  fi
done
if timeout --signal=TERM --kill-after=5s 30s docker image inspect "$tools_tag" >/dev/null 2>&1; then
  echo "refusing to replace an existing failure tools tag" >&2
  exit 1
fi

timeout --signal=TERM --kill-after=15s 900s docker build \
  --build-arg "COMMIT=$commit" \
  --file "$repository_root/tests/load/Dockerfile" \
  --tag "$tools_tag" \
  "$repository_root" >/dev/null
tools_image_id=$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Id}}' "$tools_tag")
[[ "$tools_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "failure tools build did not produce an immutable image ID" >&2; exit 1; }
[[ "$tools_image_id" != "$candidate_image_id" && "$tools_image_id" != "$postgres_image_id" ]] || { echo "failure tools image identity collided" >&2; exit 1; }
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$tools_image_id")" == "$commit" ]] || { echo "failure tools image revision is invalid" >&2; exit 1; }
[[ -z "$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all)" ]] || { echo "failure tools build changed the source checkout" >&2; exit 1; }

seed=$((16#$(printf '%s' "$run_id" | sha256sum | cut -c1-2)))
for offset in {0..15}; do
  third_octet=$((64 + (seed + offset) % 128))
  subnet="10.238.$third_octet.0/24"
  if timeout --signal=TERM --kill-after=5s 30s docker network create \
      --driver bridge --internal --subnet "$subnet" \
      --label "$run_label=$run_id" "$network" >/dev/null 2>&1; then
    network_created=true
    break
  fi
done
[[ "$network_created" == true ]] || { echo "could not allocate an isolated failure subnet" >&2; exit 1; }
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker network inspect --format '{{.Internal}}/{{.Driver}}' "$network")" == true/bridge ]] || { echo "failure network is not an internal bridge" >&2; exit 1; }
expected_network_id=$(timeout --signal=TERM --kill-after=5s 30s docker network inspect --format '{{.Id}}' "$network")
[[ "$expected_network_id" =~ ^[0-9a-f]{64}$ ]] || { echo "created failure network ID is invalid" >&2; exit 1; }

fixture_ip="10.238.$third_octet.10"
postgres_ip="10.238.$third_octet.20"
load_balancer_ip="10.238.$third_octet.30"
api_ips=("10.238.$third_octet.41" "10.238.$third_octet.42")
worker_ips=("10.238.$third_octet.51" "10.238.$third_octet.52")
driver_ip="10.238.$third_octet.60"

postgres_password=$(openssl rand -hex 32)
master_key=$(openssl rand -base64 32 | tr -d '\n')
bootstrap_token=$(openssl rand -hex 32)
admin_password=$(openssl rand -base64 36 | tr -d '\n')
fixture_token=$(openssl rand -hex 32)
balancer_token=$(openssl rand -hex 32)
umask 077
gateway_environment="$temporary_root/gateway.env"
{
  printf 'LATCHWAY_DATABASE_URL=postgres://latchway:%s@%s:5432/latchway?sslmode=disable\n' "$postgres_password" "$postgres_ip"
  printf 'LATCHWAY_MASTER_KEY=%s\n' "$master_key"
  printf 'LATCHWAY_PUBLIC_ORIGIN=http://127.0.0.1:18080\n'
  printf 'LATCHWAY_ADMIN_BOOTSTRAP_TOKEN=%s\n' "$bootstrap_token"
  printf 'LATCHWAY_LOG_LEVEL=info\n'
  printf 'LATCHWAY_DB_MAX_CONNECTIONS=16\n'
  printf 'LATCHWAY_SHUTDOWN_TIMEOUT=%ss\n' "$drain_timeout"
} > "$gateway_environment"

created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
  --name "$postgres" --network "$network" --ip "$postgres_ip" \
  --label "$run_label=$run_id" --label "$role_label=postgres" \
  --cpus 2 --memory 2g --memory-swap 2g --pids-limit 2048 \
  --security-opt no-new-privileges:true \
  --env POSTGRES_DB=latchway --env POSTGRES_USER=latchway \
  --env "POSTGRES_PASSWORD=$postgres_password" \
  "$postgres_image_id" -c max_connections=100)
record_created_container "$postgres" "$created_container_id"
postgres_ready=false
for _ in {1..90}; do
  if timeout --signal=TERM --kill-after=2s 10s docker exec "$postgres" pg_isready --username latchway --dbname latchway >/dev/null 2>&1; then postgres_ready=true; break; fi
  sleep 1
done
[[ "$postgres_ready" == true ]] || { echo "isolated failure PostgreSQL did not become ready" >&2; exit 1; }

created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
  --name "$fixture" --network "$network" --ip "$fixture_ip" \
  --label "$run_label=$run_id" --label "$role_label=fixture" \
  --user "$host_uid:$host_gid" --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --cpus 1 --memory 256m --memory-swap 256m --pids-limit 512 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env "LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN=$fixture_token" \
  "$tools_image_id" /tools/latchway-load-fixture \
    -listen "$fixture_ip:19090" -stream-hold 120s \
    -acknowledge-isolated-container-network)
record_created_container "$fixture" "$created_container_id"

created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
  --name "${apis[0]}" --network "$network" --ip "${api_ips[0]}" \
  --label "$run_label=$run_id" --label "$role_label=api" \
  --env-file "$gateway_environment" --env LATCHWAY_ROLE=api --env LATCHWAY_MIGRATE_ON_START=true \
  --cpus 1 --memory 1g --memory-swap 1g --pids-limit 2048 --read-only --tmpfs /tmp:size=32m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true "$candidate_image_id")
record_created_container "${apis[0]}" "$created_container_id"

timeout --signal=TERM --kill-after=5s 120s docker run --rm --network "$network" --read-only --tmpfs /tmp:size=8m,mode=1777 \
  --cpus 1 --memory 256m --memory-swap 256m --pids-limit 512 \
  --cap-drop ALL --security-opt no-new-privileges:true "$tools_image_id" \
  /tools/latchway-failure-driver probe "http://${api_ips[0]}:8080/healthz"

created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
  --name "${apis[1]}" --network "$network" --ip "${api_ips[1]}" \
  --label "$run_label=$run_id" --label "$role_label=api" \
  --env-file "$gateway_environment" --env LATCHWAY_ROLE=api --env LATCHWAY_MIGRATE_ON_START=false \
  --cpus 1 --memory 1g --memory-swap 1g --pids-limit 2048 --read-only --tmpfs /tmp:size=32m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true "$candidate_image_id")
record_created_container "${apis[1]}" "$created_container_id"

for index in 0 1; do
  created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
    --name "${workers[$index]}" --network "$network" --ip "${worker_ips[$index]}" \
    --label "$run_label=$run_id" --label "$role_label=worker" \
    --env-file "$gateway_environment" --env LATCHWAY_ROLE=worker --env LATCHWAY_MIGRATE_ON_START=false \
    --cpus 1 --memory 1g --memory-swap 1g --pids-limit 2048 --read-only --tmpfs /tmp:size=32m,mode=1777 \
    --cap-drop ALL --security-opt no-new-privileges:true "$candidate_image_id")
  record_created_container "${workers[$index]}" "$created_container_id"
done

for api_ip in "${api_ips[@]}"; do
  timeout --signal=TERM --kill-after=5s 120s docker run --rm --network "$network" --read-only --tmpfs /tmp:size=8m,mode=1777 \
    --cpus 1 --memory 256m --memory-swap 256m --pids-limit 512 \
    --cap-drop ALL --security-opt no-new-privileges:true "$tools_image_id" \
    /tools/latchway-failure-driver probe "http://$api_ip:8080/readyz"
done

created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
  --name "$load_balancer" --network "$network" --ip "$load_balancer_ip" \
  --label "$run_label=$run_id" --label "$role_label=load-balancer" \
  --user "$host_uid:$host_gid" --read-only --tmpfs /tmp:size=8m,mode=1777 \
  --cpus 1 --memory 256m --memory-swap 256m --pids-limit 512 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env "LATCHWAY_FAILURE_BALANCER_CONTROL_TOKEN=$balancer_token" \
  "$tools_image_id" /tools/latchway-failure-balancer \
    -listen 0.0.0.0:18080 \
    -backend "http://${api_ips[0]}:8080" -backend "http://${api_ips[1]}:8080" \
    -acknowledge-isolated-container-network)
record_created_container "$load_balancer" "$created_container_id"

export LATCHWAY_LOAD_BOOTSTRAP_TOKEN=$bootstrap_token
export LATCHWAY_LOAD_ADMIN_PASSWORD=$admin_password
timeout --signal=TERM --kill-after=10s 240s docker run --rm \
  --network "container:$load_balancer" --user "$host_uid:$host_gid" \
  --read-only --tmpfs /tmp:size=16m,mode=1777 --cap-drop ALL \
  --cpus 1 --memory 512m --memory-swap 512m --pids-limit 1024 \
  --security-opt no-new-privileges:true \
  --env LATCHWAY_LOAD_BOOTSTRAP_TOKEN --env LATCHWAY_LOAD_ADMIN_PASSWORD \
  --volume "$runtime_dir:/evidence/runtime" \
  "$tools_image_id" /tools/latchway-load-provision \
    -gateway-url http://127.0.0.1:18080 \
    -upstream-base-url "http://$fixture_ip:19090/v1" \
    -output-dir /evidence/runtime \
    -release-oci-reference "$image" \
    -release-oci-platform-reference "$platform_image" \
    -commit "$commit" \
    -postgres-identity "exact PostgreSQL failure image $postgres_image_id" \
    -postgres-network "internal-only bridge $network ($subnet), exact address $postgres_ip" \
    -postgres-cpu-millicores 2000 \
    -postgres-memory-bytes 2147483648 \
    -postgres-memory-swap-bytes 2147483648 \
    -postgres-max-connections 100 \
    -gateway-db-pool-max-connections 16
unset LATCHWAY_LOAD_BOOTSTRAP_TOKEN LATCHWAY_LOAD_ADMIN_PASSWORD

created_container_id=$(timeout --signal=TERM --kill-after=5s 60s docker run --detach \
  --name "$driver" --network "$network" --ip "$driver_ip" \
  --label "$run_label=$run_id" --label "$role_label=driver" \
  --user "$host_uid:$host_gid" --read-only --tmpfs /tmp:size=32m,mode=1777 \
  --cpus 1 --memory 512m --memory-swap 512m --pids-limit 1024 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env-file "$runtime_dir/load.env" \
  --env "LATCHWAY_FAILURE_CONFIG=/evidence/runtime/load-config.json" \
  --env "LATCHWAY_FAILURE_PROVISION=/evidence/runtime/provision.json" \
  --env "LATCHWAY_FAILURE_GATEWAY_DIAL_ADDRESS=$load_balancer_ip:18080" \
  --env "LATCHWAY_FAILURE_DATABASE_URL=postgres://latchway:$postgres_password@$postgres_ip:5432/latchway?sslmode=disable" \
  --env "LATCHWAY_FAILURE_FIXTURE_URL=http://$fixture_ip:19090" \
  --env "LATCHWAY_FAILURE_FIXTURE_CONTROL_TOKEN=$fixture_token" \
  --env "LATCHWAY_FAILURE_BALANCER_CONTROL_TOKEN=$balancer_token" \
  --env "LATCHWAY_FAILURE_SCENARIO_TIMEOUT_SECONDS=$scenario_timeout" \
  --env "LATCHWAY_FAILURE_DRAIN_TIMEOUT_SECONDS=$drain_timeout" \
  --env LATCHWAY_FAILURE_API_REPLICAS=2 \
  --env LATCHWAY_FAILURE_WORKER_REPLICAS=2 \
  --volume "$runtime_dir:/evidence/runtime:ro" \
  "$tools_image_id" /tools/latchway-failure-driver serve)
record_created_container "$driver" "$created_container_id"

driver_ready=false
for _ in {1..60}; do
  if timeout --signal=TERM --kill-after=2s 10s docker exec "$driver" /bin/sh -c 'test -S /tmp/latchway-failure-driver.sock' >/dev/null 2>&1; then driver_ready=true; break; fi
  sleep 1
done
[[ "$driver_ready" == true ]] || { echo "repo-owned failure driver did not become ready" >&2; exit 1; }

cat > "$plan_path" <<EOF
{
  "schema_version": 1,
  "kind": "latchway_disposable_fault_plan",
  "run_id": "$run_id",
  "api_replicas": 2,
  "worker_replicas": 2,
  "candidate_image_id": "$candidate_image_id",
  "postgres_image_id": "$postgres_image_id",
  "tools_image_id": "$tools_image_id",
  "scenario_timeout_seconds": $scenario_timeout,
  "overall_timeout_seconds": $overall_timeout,
  "drain_timeout_seconds": $drain_timeout
}
EOF
chmod 0400 "$plan_path"

timeout --signal=TERM --kill-after=30s 1860s python3 "$repository_root/scripts/fault-controller.py" \
  --acknowledge-disposable-target \
  --plan "$plan_path" \
  --output-dir "$output_dir" \
  --commit "$commit" \
  --image "$image" \
  --platform-image "$platform_image" \
  --postgres-image "$postgres_image" \
  --operator "$operator"

echo "repo-owned destructive failure matrix passed; evidence: $output_dir"
