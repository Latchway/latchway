#!/bin/sh
set -eu

usage() {
  echo "usage: $0 -acknowledge-load -evidence-dir ABSOLUTE_EMPTY_DIRECTORY [-release-image INDEX_OCI -release-platform-image AMD64_CHILD_OCI -core-commit COMMIT [-preloaded-platform-image-id SHA256_ID -preloaded-postgres-image-id SHA256_ID]]" >&2
  exit 2
}

require_clean_source_repository() {
  if ! source_status=$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all 2>/dev/null); then
    echo "unable to verify source repository cleanliness" >&2
    exit 2
  fi
  if [ -n "$source_status" ]; then
    echo "source repository must be clean before load evidence is collected" >&2
    exit 2
  fi
}

acknowledge=false
evidence_dir=
release_image=
release_platform_image=
requested_commit=
preloaded_platform_image_id=
preloaded_postgres_image_id=
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
    -preloaded-platform-image-id)
      [ "$#" -ge 2 ] || usage
      preloaded_platform_image_id=$2
      shift 2
      ;;
    -preloaded-postgres-image-id)
      [ "$#" -ge 2 ] || usage
      preloaded_postgres_image_id=$2
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

preloaded_mode=false
if [ -n "$preloaded_platform_image_id$preloaded_postgres_image_id" ]; then
  [ "$release_mode" = true ] || usage
  [ -n "$preloaded_platform_image_id" ] && [ -n "$preloaded_postgres_image_id" ] || usage
  case "$preloaded_platform_image_id" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "preloaded platform image ID must be an immutable sha256 image ID" >&2; exit 2 ;;
  esac
  case "$preloaded_postgres_image_id" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "preloaded PostgreSQL image ID must be an immutable sha256 image ID" >&2; exit 2 ;;
  esac
  case "${preloaded_platform_image_id#sha256:}${preloaded_postgres_image_id#sha256:}" in
    *[!0-9a-f]*) echo "preloaded image IDs must be lowercase hexadecimal" >&2; exit 2 ;;
  esac
  [ "$preloaded_platform_image_id" != "$preloaded_postgres_image_id" ] || {
    echo "preloaded candidate and PostgreSQL image IDs must differ" >&2
    exit 2
  }
  preloaded_mode=true
fi

[ "$acknowledge" = true ] || usage
case "$evidence_dir" in
  /*) ;;
  *) echo "evidence directory must be absolute" >&2; exit 2 ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
require_clean_source_repository
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

# The image defaults to UID/GID 65532. Bind-mounted evidence is host-owned, so
# run the tools as the invoking non-root user on both Linux and Docker Desktop.
host_uid=$(id -u)
host_gid=$(id -g)
case "$host_uid:$host_gid" in
  *[!0-9:]*|:*|*:) echo "host UID and GID must be numeric" >&2; exit 2 ;;
esac
if [ "$host_uid" -eq 0 ]; then
  echo "refusing to run load tooling as root" >&2
  exit 2
fi
tools_user="$host_uid:$host_gid"
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
tools_runner="latchway-load-runner-$suffix"
gateway_tag="latchway-load-gateway:$suffix"
tools_tag="latchway-load-tools:$suffix"
network_created=false
gateway_image_created=false
tools_image_created=false
tools_runner_create_intended=false
diagnostics_pid=
postgres_cpu_millicores=4000
postgres_nano_cpus=4000000000
postgres_memory_bytes=4294967296
postgres_memory_swap_bytes=4294967296
postgres_max_connections=100
gateway_db_pool_max_connections=32
gateway_db_regular_pool_max_connections=24
gateway_db_completion_pool_max_connections=8
if [ "$gateway_db_regular_pool_max_connections" -lt 1 ] ||
   [ "$gateway_db_completion_pool_max_connections" -lt 1 ] ||
   [ "$gateway_db_regular_pool_max_connections" -ne "$((gateway_db_pool_max_connections - gateway_db_completion_pool_max_connections))" ]; then
  echo "gateway database pool partition is incoherent" >&2
  exit 2
fi

capture_postgres_startup_events() {
  # Database logs can contain SQL and parameters. Keep only fixed, allowlisted
  # startup-event labels, never raw lines, and bound both input lines and bytes.
  docker logs --tail 200 "$postgres" 2>&1 | head -c 32768 | awk '
    /PostgreSQL init process complete; ready for start up/ {
      print "postgres: initialization complete"; events++; next
    }
    /database system is ready to accept connections/ {
      print "postgres: accepting connections"; events++; next
    }
    /database system is shut down/ {
      print "postgres: shut down"; events++; next
    }
    /database system is starting up/ {
      print "postgres: starting up"; events++; next
    }
    /FATAL:  database "latchway" does not exist/ {
      print "postgres: expected database absent"; events++; next
    }
    /FATAL:  password authentication failed/ {
      print "postgres: authentication failed"; events++; next
    }
    /FATAL:/ {
      print "postgres: fatal error (details withheld)"; events++; next
    }
    END {
      if (events == 0) print "postgres: no allowlisted event in bounded log tail"
    }
  '
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  # Diagnostics are advisory. Stop them before removing their exact fixture,
  # preserving the original gate exit status even if collection was unavailable.
  if [ -n "$diagnostics_pid" ]; then
    touch "$run_dir/runtime-diagnostics.stop"
    diagnostics_stop_attempt=0
    while kill -0 "$diagnostics_pid" 2>/dev/null && [ "$diagnostics_stop_attempt" -lt 15 ]; do
      sleep 1
      diagnostics_stop_attempt=$((diagnostics_stop_attempt + 1))
    done
    if kill -0 "$diagnostics_pid" 2>/dev/null; then
      kill -TERM "$diagnostics_pid" 2>/dev/null
      sleep 1
    fi
    if kill -0 "$diagnostics_pid" 2>/dev/null; then
      kill -KILL "$diagnostics_pid" 2>/dev/null
    fi
    if kill -0 "$diagnostics_pid" 2>/dev/null; then
      # Never wait indefinitely for an uninterruptible collector. The process
      # is our own child; all fixture and evidence targets remain exact.
      printf '%s\n' '{"kind":"collector","status":"stop_timeout"}' >>"$evidence_dir/runtime-diagnostics.jsonl"
    elif ! wait "$diagnostics_pid"; then
      printf '%s\n' '{"kind":"collector","status":"unavailable"}' >>"$evidence_dir/runtime-diagnostics.jsonl"
    fi
  fi
  if docker inspect "$gateway" >/dev/null 2>&1; then
    docker logs "$gateway" >"$evidence_dir/gateway.log" 2>&1
  fi
  if docker inspect "$fixture" >/dev/null 2>&1; then
    docker logs "$fixture" >"$evidence_dir/fixture.log" 2>&1
  fi
  if [ "$status" -ne 0 ] && docker inspect "$postgres" >/dev/null 2>&1; then
    capture_postgres_startup_events >"$evidence_dir/postgres-startup.log"
  fi
  # The foreground runner normally removes itself. On interruption, remove
  # only the exact name with this invocation's label and immutable tools image.
  if [ "${tools_runner_create_intended:-false}" = true ] && \
     [ -n "${tools_runner:-}" ] && [ -n "${tools_image_id:-}" ] && \
     [ "$(docker inspect --format '{{index .Config.Labels "dev.latchway.load-run"}}' "$tools_runner" 2>/dev/null)" = "$suffix" ] && \
     [ "$(docker inspect --format '{{.Image}}' "$tools_runner" 2>/dev/null)" = "$tools_image_id" ]; then
    docker rm --force "$tools_runner" >/dev/null 2>&1
  fi
  docker rm --force "$gateway" >/dev/null 2>&1
  docker rm --force "$fixture" >/dev/null 2>&1
  docker rm --force --volumes "$postgres" >/dev/null 2>&1
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
  if [ "$preloaded_mode" = true ]; then
    gateway_runtime_image=$preloaded_platform_image_id
    gateway_image_id=$(docker image inspect --format '{{.Id}}' "$preloaded_platform_image_id")
    [ "$gateway_image_id" = "$preloaded_platform_image_id" ] || {
      echo "preloaded candidate image ID changed after import" >&2
      exit 1
    }
  else
    docker pull --platform linux/amd64 "$release_platform_image" >/dev/null
    gateway_runtime_image=$release_platform_image
    gateway_image_id=$(docker image inspect --format '{{.Id}}' "$release_platform_image")
  fi
  observed_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$gateway_runtime_image")
  observed_os=$(docker image inspect --format '{{.Os}}' "$gateway_runtime_image")
  observed_architecture=$(docker image inspect --format '{{.Architecture}}' "$gateway_runtime_image")
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
postgres_runtime_image=docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2
if [ "$preloaded_mode" = true ]; then
  postgres_runtime_image=$preloaded_postgres_image_id
  observed_postgres_image_id=$(docker image inspect --format '{{.Id}}' "$postgres_runtime_image")
  [ "$observed_postgres_image_id" = "$preloaded_postgres_image_id" ] || {
    echo "preloaded PostgreSQL image ID changed after import" >&2
    exit 1
  }
  observed_postgres_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$postgres_runtime_image")
  [ "$observed_postgres_platform" = linux/amd64 ] || {
    echo "preloaded PostgreSQL image is not linux/amd64" >&2
    exit 1
  }
fi
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
  "$postgres_runtime_image" \
  -c "max_connections=$postgres_max_connections" >/dev/null

postgres_query() (
  # Keep the password out of Docker's argument list and out of the caller's
  # environment after the query. TCP excludes the socket-only init server.
  export PGPASSWORD=$POSTGRES_PASSWORD
  docker exec --user postgres \
    --env PGPASSWORD \
    --env PGCONNECT_TIMEOUT=2 \
    --env 'PGOPTIONS=-c statement_timeout=2000' \
    "$postgres" \
    psql --host 127.0.0.1 \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --no-password --no-psqlrc --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --command "$1"
)

postgres_ready=false
postgres_tcp_ready_streak=0
postgres_required_ready_streak=5
attempt=0
while [ "$attempt" -lt 90 ]; do
  if [ "$(docker inspect --format '{{.State.Running}}' "$postgres" 2>/dev/null || true)" != true ]; then
    break
  fi
  # pg_isready accepts a missing database and can observe the temporary init
  # postmaster. Require successful SQL on the final TCP listener using the
  # configured role/database, then a stable streak. Password verification still
  # follows pg_hba.conf; loopback trust is not a password-policy audit.
  if postgres_query 'SELECT 1' >/dev/null 2>&1; then
    postgres_tcp_ready_streak=$((postgres_tcp_ready_streak + 1))
    if [ "$postgres_tcp_ready_streak" -ge "$postgres_required_ready_streak" ]; then
      postgres_ready=true
      break
    fi
  else
    postgres_tcp_ready_streak=0
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$postgres_ready" != true ]; then
  echo "isolated PostgreSQL did not become ready for authenticated TCP queries" >&2
  exit 1
fi

postgres_image_id=$(docker inspect --format '{{.Image}}' "$postgres")
postgres_observed_nano_cpus=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$postgres")
postgres_observed_memory_bytes=$(docker inspect --format '{{.HostConfig.Memory}}' "$postgres")
postgres_observed_memory_swap_bytes=$(docker inspect --format '{{.HostConfig.MemorySwap}}' "$postgres")
postgres_observed_ip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$postgres")
postgres_observed_max_connections=$(postgres_query 'SHOW max_connections')
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
  --user "$tools_user" \
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
export LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections
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
  --env LATCHWAY_DB_COMPLETION_CONNECTIONS \
  --env LATCHWAY_SHUTDOWN_TIMEOUT \
  "$gateway_runtime_image" >/dev/null

nano_cpus=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$gateway")
memory_bytes=$(docker inspect --format '{{.HostConfig.Memory}}' "$gateway")
memory_swap_bytes=$(docker inspect --format '{{.HostConfig.MemorySwap}}' "$gateway")
observed_image=$(docker inspect --format '{{.Image}}' "$gateway")
gateway_pool_env=$(docker inspect --format "{{range .Config.Env}}{{if eq . \"LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections\"}}{{.}}{{end}}{{end}}" "$gateway")
gateway_completion_pool_env=$(docker inspect --format "{{range .Config.Env}}{{if eq . \"LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections\"}}{{.}}{{end}}{{end}}" "$gateway")
if [ "$nano_cpus" != 2000000000 ] || [ "$memory_bytes" != 2147483648 ] || \
   [ "$memory_swap_bytes" != 2147483648 ] || [ "$observed_image" != "$gateway_image_id" ] || \
   [ "$gateway_pool_env" != "LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections" ] || \
   [ "$gateway_completion_pool_env" != "LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections" ]; then
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
  "  \"gateway_db_regular_pool_max_connections\": $gateway_db_regular_pool_max_connections," \
  "  \"gateway_db_completion_pool_max_connections\": $gateway_db_completion_pool_max_connections," \
  '  "gateway_expected_pid_in_shared_namespace": 1,' \
  '  "postgres_image": "docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",' \
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
  --user "$tools_user" \
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
  -gateway-db-pool-max-connections "$gateway_db_pool_max_connections" \
  -gateway-db-regular-pool-max-connections "$gateway_db_regular_pool_max_connections" \
  -gateway-db-completion-pool-max-connections "$gateway_db_completion_pool_max_connections"

cp "$run_dir/runtime/provision.json" "$evidence_dir/provision.json"
cp "$run_dir/runtime/load-config.json" "$evidence_dir/load-config.json"

if docker inspect "$tools_runner" >/dev/null 2>&1; then
  echo "refusing to reuse an existing load runner name" >&2
  exit 1
fi
if command -v python3 >/dev/null 2>&1; then
  python3 "$run_dir/source/scripts/load-runtime-diagnostics.py" \
    --postgres "$postgres" --gateway "$gateway" --tools-runner "$tools_runner" \
    --pool-max-connections "$gateway_db_pool_max_connections" \
    --regular-pool-max-connections "$gateway_db_regular_pool_max_connections" \
    --completion-pool-max-connections "$gateway_db_completion_pool_max_connections" \
    --output "$evidence_dir/runtime-diagnostics.jsonl" \
    --stop-file "$run_dir/runtime-diagnostics.stop" >/dev/null 2>&1 &
  diagnostics_pid=$!
else
  printf '%s\n' '{"kind":"collector","status":"python_unavailable"}' >"$evidence_dir/runtime-diagnostics.jsonl"
fi

tools_runner_create_intended=true
docker run --rm \
  --name "$tools_runner" \
  --label "dev.latchway.load-run=$suffix" \
  --network "container:$gateway" \
  --pid "container:$gateway" \
  --user "$tools_user" \
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
