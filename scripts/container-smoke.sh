#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi

image=$1
suffix=$$
network="latchway-smoke-${suffix}"
postgres="latchway-smoke-postgres-${suffix}"
gateway="latchway-smoke-gateway-${suffix}"

cleanup() {
  status=$?
  trap - EXIT
  if (( status != 0 )); then
    if docker inspect "$gateway" >/dev/null 2>&1; then
      echo "--- Latchway gateway logs ---" >&2
      docker logs "$gateway" >&2 || true
    fi
    if docker inspect "$postgres" >/dev/null 2>&1; then
      echo "--- PostgreSQL logs ---" >&2
      docker logs "$postgres" >&2 || true
    fi
  fi
  docker rm --force "$gateway" >/dev/null 2>&1 || true
  docker rm --force "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

docker network create "$network" >/dev/null

export POSTGRES_DB=latchway
export POSTGRES_USER=latchway
export POSTGRES_PASSWORD=latchway-container-smoke
docker run --detach \
  --name "$postgres" \
  --network "$network" \
  --env POSTGRES_DB \
  --env POSTGRES_USER \
  --env POSTGRES_PASSWORD \
  docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 >/dev/null

postgres_ready=false
postgres_tcp_ready_streak=0
postgres_required_ready_streak=5
for _ in $(seq 1 60); do
  if [[ "$(docker inspect --format '{{.State.Running}}' "$postgres" 2>/dev/null || true)" != true ]]; then
    break
  fi

  # The official PostgreSQL entrypoint runs a temporary postmaster over a Unix
  # socket while initializing the database, with TCP listening disabled. Probe
  # an authenticated TCP query repeatedly so that server can never satisfy this
  # gate and a short-lived final postmaster is treated as a failed startup.
  if docker exec \
    --env "PGPASSWORD=${POSTGRES_PASSWORD}" \
    "$postgres" \
    psql \
    --host 127.0.0.1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --no-password \
    --command 'SELECT 1' >/dev/null 2>&1; then
    postgres_tcp_ready_streak=$((postgres_tcp_ready_streak + 1))
    if (( postgres_tcp_ready_streak >= postgres_required_ready_streak )); then
      postgres_ready=true
      break
    fi
  else
    postgres_tcp_ready_streak=0
  fi
  sleep 1
done
if [[ "$postgres_ready" != true ]]; then
  echo "PostgreSQL did not become ready" >&2
  exit 1
fi

export LATCHWAY_DATABASE_URL="postgres://latchway:latchway-container-smoke@${postgres}:5432/latchway?sslmode=disable"
export LATCHWAY_MASTER_KEY
LATCHWAY_MASTER_KEY=$(openssl rand -base64 32)
export LATCHWAY_PUBLIC_ORIGIN=http://localhost:8080
export LATCHWAY_ROLE=all
export LATCHWAY_MIGRATE_ON_START=true
gateway_db_pool_max_connections=5
gateway_db_regular_pool_max_connections=3
gateway_db_completion_pool_max_connections=2
if ((gateway_db_regular_pool_max_connections < 1 ||
     gateway_db_completion_pool_max_connections < 1 ||
     gateway_db_regular_pool_max_connections != gateway_db_pool_max_connections - gateway_db_completion_pool_max_connections)); then
  echo "gateway database pool partition is incoherent" >&2
  exit 2
fi
export LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections
export LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections

docker run --detach \
  --name "$gateway" \
  --network "$network" \
  --publish 127.0.0.1:0:8080/tcp \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env LATCHWAY_DATABASE_URL \
  --env LATCHWAY_MASTER_KEY \
  --env LATCHWAY_PUBLIC_ORIGIN \
  --env LATCHWAY_ROLE \
  --env LATCHWAY_MIGRATE_ON_START \
  --env LATCHWAY_DB_MAX_CONNECTIONS \
  --env LATCHWAY_DB_COMPLETION_CONNECTIONS \
  "$image" >/dev/null

if [[ "$(docker inspect --format '{{.State.Running}}' "$gateway")" != true ]]; then
  echo "Latchway exited before its port was published" >&2
  exit 1
fi

observed_gateway_pool=$(docker inspect --format "{{range .Config.Env}}{{if eq . \"LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections\"}}{{.}}{{end}}{{end}}" "$gateway")
observed_gateway_completion_pool=$(docker inspect --format "{{range .Config.Env}}{{if eq . \"LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections\"}}{{.}}{{end}}{{end}}" "$gateway")
if [[ "$observed_gateway_pool" != "LATCHWAY_DB_MAX_CONNECTIONS=$gateway_db_pool_max_connections" ||
      "$observed_gateway_completion_pool" != "LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections" ]]; then
  echo "container smoke gateway pool environment does not match the exact aggregate/completion partition" >&2
  exit 1
fi

published=$(docker port "$gateway" 8080/tcp || true)
port=${published##*:}
if [[ ! "$port" =~ ^[0-9]+$ ]]; then
  echo "could not resolve the published gateway port" >&2
  exit 1
fi

gateway_ready=false
for _ in $(seq 1 90); do
  if curl --fail --silent --show-error "http://127.0.0.1:${port}/readyz" >/tmp/latchway-container-ready.json 2>/dev/null; then
    gateway_ready=true
    break
  fi
  sleep 1
done
if [[ "$gateway_ready" != true ]]; then
  echo "Latchway did not become ready" >&2
  exit 1
fi

curl --fail --silent --show-error "http://127.0.0.1:${port}/healthz" >/tmp/latchway-container-health.json
docker exec "$gateway" /latchway doctor --output json >/tmp/latchway-container-doctor.json
docker exec "$gateway" /latchway version --output json >/tmp/latchway-container-version.json

runtime_user=$(docker image inspect --format '{{.Config.User}}' "$image")
if [[ "$runtime_user" != "65532:65532" ]]; then
  echo "unexpected runtime user: $runtime_user" >&2
  exit 1
fi

python3 - <<'PY'
import json
from pathlib import Path

ready = json.loads(Path("/tmp/latchway-container-ready.json").read_text())
health = json.loads(Path("/tmp/latchway-container-health.json").read_text())
doctor = json.loads(Path("/tmp/latchway-container-doctor.json").read_text())
version = json.loads(Path("/tmp/latchway-container-version.json").read_text())
assert ready["status"] == "ready", ready
assert health["status"] == "ok", health
assert doctor["status"] == "ok", doctor
assert isinstance(version["version"], str) and version["version"], version
assert isinstance(version["contract_version"], str) and version["contract_version"], version
PY

docker stop --time 35 "$gateway" >/dev/null
echo "container smoke test passed for ${image}"
