#!/bin/sh
set -eu

usage() {
  echo "usage: $0 -acknowledge-load -evidence-dir ABSOLUTE_EMPTY_DIRECTORY [-release-image INDEX_OCI -release-platform-image AMD64_CHILD_OCI -core-commit COMMIT]" >&2
  exit 2
}

acknowledge=false
evidence_dir=
release_image=
release_platform_image=
requested_commit=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -acknowledge-load)
      acknowledge=true
      shift
      ;;
    -evidence-dir)
      [ "$#" -ge 2 ] || usage
      evidence_dir=$2
      shift 2
      ;;
    -release-image)
      [ "$#" -ge 2 ] || usage
      release_image=$2
      shift 2
      ;;
    -release-platform-image)
      [ "$#" -ge 2 ] || usage
      release_platform_image=$2
      shift 2
      ;;
    -core-commit)
      [ "$#" -ge 2 ] || usage
      requested_commit=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

release_mode=false
if [ -n "$release_image$release_platform_image$requested_commit" ]; then
  [ -n "$release_image" ] && [ -n "$release_platform_image" ] && [ -n "$requested_commit" ] || usage
  release_digest=${release_image#ghcr.io/latchway/latchway@sha256:}
  platform_digest=${release_platform_image#ghcr.io/latchway/latchway@sha256:}
  if [ "$release_image" = "$release_digest" ] || [ "${#release_digest}" -ne 64 ]; then
    echo "release image must be the exact Latchway OCI index digest" >&2; exit 2
  fi
  if [ "$release_platform_image" = "$platform_digest" ] || [ "${#platform_digest}" -ne 64 ]; then
    echo "release platform image must be the exact Latchway OCI child digest" >&2; exit 2
  fi
  case "$release_digest$platform_digest" in *[!0-9a-f]*) echo "release digests must be lowercase hexadecimal" >&2; exit 2 ;; esac
  if [ "${#requested_commit}" -ne 40 ]; then
    echo "release core commit must contain exactly 40 characters" >&2; exit 2
  fi
  case "$requested_commit" in *[!0-9a-f]*) echo "release core commit must be lowercase hexadecimal" >&2; exit 2 ;; esac
  [ "$release_image" != "$release_platform_image" ] || { echo "release index and platform child must differ" >&2; exit 2; }
  release_mode=true
fi

[ "$acknowledge" = true ] || usage
case "$evidence_dir" in
  /*) ;;
  *) echo "evidence directory must be absolute" >&2; exit 2 ;;
esac
if [ -L "$evidence_dir" ]; then
  echo "evidence directory cannot be a symbolic link" >&2
  exit 2
fi
mkdir -p "$evidence_dir"
if [ ! -d "$evidence_dir" ] || [ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  echo "evidence directory must be one empty real directory" >&2
  exit 2
fi
chmod 700 "$evidence_dir"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
run_dir=$(mktemp -d /tmp/latchway-load-local.XXXXXX)
case "$run_dir" in
  /tmp/latchway-load-local.*) ;;
  *) echo "refusing unsafe temporary directory" >&2; exit 2 ;;
esac

suffix="$$-$(date -u +%Y%m%d%H%M%S)"
network="latchway-load-network-$suffix"
postgres="latchway-load-postgres-$suffix"
fixture="latchway-load-fixture-$suffix"
gateway="latchway-load-gateway-$suffix"
gateway_tag="latchway-load-gateway:$suffix"
tools_tag="latchway-load-tools:$suffix"
network_created=false
gateway_image_created=false
tools_image_created=false
postgres_cpu_millicores=4000
postgres_nano_cpus=4000000000
postgres_memory_bytes=4294967296
postgres_memory_swap_bytes=4294967296
postgres_max_connections=100
gateway_db_pool_max_connections=32

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  if docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$evidence_dir/gateway.log" 2>&1
  fi
  if docker inspect "$fixture" >/dev/null 2>&1; then
    docker logs "$fixture" >"$evidence_dir/fixture.log" 2>&1
  fi
  docker rm --force "$gateway" >/dev/null 2>&1
  docker rm --force "$fixture" >/dev/null 2>&1
  docker rm --force "$postgres" >/dev/null 2>&1
  if [ "$network_created" = true ]; then
    docker network rm "$network" >/dev/null 2>&1
  fi
  if [ "$gateway_image_created" = true ]; then
    docker image rm "$gateway_tag" >/dev/null 2>&1
  fi
  if [ "$tools_image_created" = true ]; then
    docker image rm "$tools_tag" >/dev/null 2>&1
  fi
  case "$run_dir" in
    /tmp/latchway-load-local.*) rm -rf -- "$run_dir" ;;
  esac
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

git clone --quiet --no-hardlinks "$repository_root" "$run_dir/source"
commit=$(git -C "$run_dir/source" rev-parse HEAD)
if [ -n "$(git -C "$run_dir/source" status --porcelain=v1)" ]; then
  echo "isolated source clone is unexpectedly dirty" >&2
  exit 1
fi

if [ "$release_mode" = true ] && [ "$commit" != "$requested_commit" ]; then
  echo "release image commit does not match the exact source checkout" >&2
  exit 1
fi

gateway_runtime_image=
provision_local_image_id=
if [ "$release_mode" = true ]; then
  docker pull --platform linux/amd64 "$release_platform_image" >/dev/null
  gateway_runtime_image=$release_platform_image
  gateway_image_id=$(docker image inspect --format '{{.Id}}' "$release_platform_image")
  observed_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$release_platform_image")
  observed_os=$(docker image inspect --format '{{.Os}}' "$release_platform_image")
  observed_architecture=$(docker image inspect --format '{{.Architecture}}' "$release_platform_image")
  [ "$observed_revision" = "$commit" ] || { echo "release platform image revision does not match source commit" >&2; exit 1; }
  [ "$observed_os/$observed_architecture" = linux/amd64 ] || { echo "release platform child is not linux/amd64" >&2; exit 1; }
else
  docker build --build-arg "COMMIT=$commit" --tag "$gateway_tag" "$run_dir/source"
  gateway_image_created=true
  gateway_runtime_image=$gateway_tag
  gateway_image_id=$(docker image inspect --format '{{.Id}}' "$gateway_tag")
  provision_local_image_id=$gateway_image_id
fi
case "$gateway_image_id" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "gateway build did not produce an immutable sha256 image ID" >&2; exit 1 ;;
esac

docker build --file "$run_dir/source/tests/load/Dockerfile" --tag "$tools_tag" "$run_dir/source"
tools_image_created=true
tools_image_id=$(docker image inspect --format '{{.Id}}' "$tools_tag")
case "$tools_image_id" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "load tools build did not produce an immutable sha256 image ID" >&2; exit 1 ;;
esac

third_octet=$((100 + $$ % 100))
subnet="10.239.$third_octet.0/24"
fixture_ip="10.239.$third_octet.10"
postgres_ip="10.239.$third_octet.20"
docker network create --internal --subnet "$subnet" "$network" >/dev/null
network_created=true
if [ "$(docker network inspect --format '{{.Internal}}' "$network")" != true ]; then
  echo "load network is not internal-only" >&2
  exit 1
fi

postgres_password=$(openssl rand -hex 32)
export POSTGRES_DB=latchway
export POSTGRES_USER=latchway
export POSTGRES_PASSWORD=$postgres_password
docker run --detach \
  --name "$postgres" \
  --network "$network" \
  --ip "$postgres_ip" \
  --cpus 4 \
  --memory 4g \
  --memory-swap 4g \
  --pids-limit 2048 \
  --security-opt no-new-privileges:true \
  --env POSTGRES_DB \
  --env POSTGRES_USER \
  --env POSTGRES_PASSWORD \
  postgres:18.6-alpine \
  -c "max_connections=$postgres_max_connections" >/dev/null

postgres_ready=false
attempt=0
while [ "$attempt" -lt 90 ]; do
  if docker exec "$postgres" pg_isready --username latchway --dbname latchway >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$postgres_ready" != true ]; then
  echo "isolated PostgreSQL did not become ready" >&2
  exit 1
fi

postgres_image_id=$(docker inspect --format '{{.Image}}' "$postgres")
postgres_observed_nano_cpus=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$postgres")
postgres_observed_memory_bytes=$(docker inspect --format '{{.HostConfig.Memory}}' "$postgres")
postgres_observed_memory_swap_bytes=$(docker inspect --format '{{.HostConfig.MemorySwap}}' "$postgres")
postgres_observed_ip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$postgres")
postgres_observed_max_connections=$(docker exec --user postgres "$postgres" \
  psql --username latchway --dbname latchway --tuples-only --no-align --command 'SHOW max_connections')
case "$postgres_image_id" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "PostgreSQL did not resolve to an immutable sha256 image ID" >&2; exit 1 ;;
esac
if [ "$postgres_observed_nano_cpus" != "$postgres_nano_cpus" ] || \
   [ "$postgres_observed_memory_bytes" != "$postgres_memory_bytes" ] || \
   [ "$postgres_observed_memory_swap_bytes" != "$postgres_memory_swap_bytes" ] || \
   [ "$postgres_observed_ip" != "$postgres_ip" ] || \
   [ "$postgres_observed_max_connections" != "$postgres_max_connections" ]; then
  echo "PostgreSQL resource, network, or connection settings do not match the isolated load fixture" >&2
  exit 1
fi

fixture_token=$(openssl rand -hex 32)
export LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN=$fixture_token
docker run --detach \
  --name "$fixture" \
  --network "$network" \
  --ip "$fixture_ip" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 1024 \
  --env LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN \
  "$tools_image_id" \
  /tools/latchway-load-fixture \
  -listen "$fixture_ip:19090" \
  -stream-hold 150s \
  -acknowledge-isolated-container-network >/dev/null

master_key=$(openssl rand -base64 32)
bootstrap_token=$(openssl rand -hex 32)
admin_password=$(openssl rand -base64 36 | tr -d '\n')
export LATCHWAY_DATABASE_URL="postgres://latchway:$postgres_password@$postgres_ip:5432/latchway?sslmode=disable"
export LATCHWAY_MASTER_KEY=$master_key
export LATCHWAY_PUBLIC_ORIGIN=http://127.0.0.1:8080
export LATCHWAY_ADMIN_BOOTSTRAP_TOKEN=$bootstrap_token
export LATCHWAY_ROLE=all
export LATCHWAY_LOG_LEVEL=info
export LATCHWAY_MIGRATE_ON_START=true
export LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections
export LATCHWAY_SHUTDOWN_TIMEOUT=30s
docker run --detach \
  --name "$gateway" \
  --network "$network" \
  --cpus 2 \
  --memory 2g \
  --memory-swap 2g \
  --pids-limit 4096 \
  --read-only \
  --tmpfs /tmp:size=32m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env LATCHWAY_DATABASE_URL \
  --env LATCHWAY_MASTER_KEY \
  --env LATCHWAY_PUBLIC_ORIGIN \
  --env LATCHWAY_ADMIN_BOOTSTRAP_TOKEN \
  --env LATCHWAY_ROLE \
  --env LATCHWAY_LOG_LEVEL \
  --env LATCHWAY_MIGRATE_ON_START \
  --env LATCHWAY_DB_MAX_CONNECTIONS \
  --env LATCHWAY_SHUTDOWN_TIMEOUT \
  "$gateway_runtime_image" >/dev/null

nano_cpus=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$gateway")
memory_bytes=$(docker inspect --format '{{.HostConfig.Memory}}' "$gateway")
memory_swap_bytes=$(docker inspect --format '{{.HostConfig.MemorySwap}}' "$gateway")
observed_image=$(docker inspect --format '{{.Image}}' "$gateway")
gateway_pool_env=$(docker inspect --format "{{range .Config.Env}}{{if eq . \"LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections\"}}{{.}}{{end}}{{end}}" "$gateway")
if [ "$nano_cpus" != 2000000000 ] || [ "$memory_bytes" != 2147483648 ] || \
   [ "$memory_swap_bytes" != 2147483648 ] || [ "$observed_image" != "$gateway_image_id" ] || \
   [ "$gateway_pool_env" != "LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections" ]; then
  echo "gateway resource or image identity does not match the required 2 CPU / 2 GiB candidate" >&2
  exit 1
fi

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "kind": "latchway_local_load_environment",' \
  "  \"started_at\": \"$started_at\"," \
  "  \"commit\": \"$commit\"," \
  "  \"gateway_local_docker_image_id\": \"$gateway_image_id\"," \
  "  \"load_tools_local_docker_image_id\": \"$tools_image_id\"," \
  "  \"gateway_nano_cpus\": $nano_cpus," \
  "  \"gateway_memory_bytes\": $memory_bytes," \
  "  \"gateway_memory_swap_bytes\": $memory_swap_bytes," \
  "  \"gateway_db_pool_max_connections\": $gateway_db_pool_max_connections," \
  '  "gateway_expected_pid_in_shared_namespace": 1,' \
  '  "postgres_image": "postgres:18.6-alpine",' \
  "  \"postgres_local_docker_image_id\": \"$postgres_image_id\"," \
  "  \"postgres_cpu_millicores\": $postgres_cpu_millicores," \
  "  \"postgres_nano_cpus\": $postgres_observed_nano_cpus," \
  "  \"postgres_memory_bytes\": $postgres_observed_memory_bytes," \
  "  \"postgres_memory_swap_bytes\": $postgres_observed_memory_swap_bytes," \
  "  \"postgres_max_connections\": $postgres_observed_max_connections," \
  "  \"postgres_network_ip\": \"$postgres_observed_ip\"," \
  '  "network_internal": true,' \
  "  \"network_subnet\": \"$subnet\"," \
  '  "trust_mode": "debug-non-production"' \
  '}' >"$evidence_dir/environment.json"

mkdir "$run_dir/runtime"
chmod 700 "$run_dir/runtime"
export LATCHWAY_LOAD_BOOTSTRAP_TOKEN=$bootstrap_token
export LATCHWAY_LOAD_ADMIN_PASSWORD=$admin_password
docker run --rm \
  --network "container:$gateway" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env LATCHWAY_LOAD_BOOTSTRAP_TOKEN \
  --env LATCHWAY_LOAD_ADMIN_PASSWORD \
  --volume "$run_dir/runtime:/evidence/runtime" \
  "$tools_image_id" \
  /tools/latchway-load-provision \
  -gateway-url http://127.0.0.1:8080 \
  -upstream-base-url "http://$fixture_ip:19090/v1" \
  -output-dir /evidence/runtime \
  -local-docker-image-id "$provision_local_image_id" \
  -release-oci-reference "$release_image" \
  -release-oci-platform-reference "$release_platform_image" \
  -commit "$commit" \
  -postgres-identity "PostgreSQL 18.6 Alpine local Docker image $postgres_image_id" \
  -postgres-network "same internal-only Docker bridge $network ($subnet); PostgreSQL address $postgres_observed_ip" \
  -postgres-cpu-millicores "$postgres_cpu_millicores" \
  -postgres-memory-bytes "$postgres_observed_memory_bytes" \
  -postgres-memory-swap-bytes "$postgres_observed_memory_swap_bytes" \
  -postgres-max-connections "$postgres_observed_max_connections" \
  -gateway-db-pool-max-connections "$gateway_db_pool_max_connections"

cp "$run_dir/runtime/provision.json" "$evidence_dir/provision.json"
cp "$run_dir/runtime/load-config.json" "$evidence_dir/load-config.json"

docker run --rm \
  --network "container:$gateway" \
  --pid "container:$gateway" \
  --read-only \
  --tmpfs /tmp:size=32m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env-file "$run_dir/runtime/load.env" \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/src \
  --volume "$run_dir/source:/src:ro" \
  --volume "$run_dir/runtime:/evidence/runtime:ro" \
  --volume "$evidence_dir:/evidence/output" \
  --workdir /src \
  "$tools_image_id" \
  /tools/latchway-load \
  -acknowledge-load \
  -config /evidence/runtime/load-config.json \
  -output /evidence/output/load-v1.json

echo "local v1 load gates passed; evidence: $evidence_dir/load-v1.json"
