#!/usr/bin/env bash

# Return the complete, normalized Cloudflare Containers application list.
# Wrangler 4.127.1 reads only the first Dash API page for JSON output, so both
# the operator runbook and protected deployment evidence use this bounded
# cursor traversal instead of treating `wrangler containers list --json` as a
# complete account inventory.

set -Eeuo pipefail

usage() {
  printf 'usage: CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... %s OUTPUT.json\n' "$0" >&2
}

if (( $# != 1 )) || [[ -z "$1" || "$1" == -* ]]; then
  usage
  exit 64
fi

destination="$1"
if [[ -e "$destination" && ( ! -f "$destination" || -L "$destination" ) ]]; then
  printf 'error: output must be a regular file or an unused path\n' >&2
  exit 65
fi
destination_directory=$(dirname -- "$destination")
if [[ ! -d "$destination_directory" ]]; then
  printf 'error: output directory must already exist\n' >&2
  exit 65
fi

: "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"
: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
[[ "$CLOUDFLARE_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]]
[[ "$CLOUDFLARE_API_TOKEN" =~ ^[A-Za-z0-9._~-]{20,256}$ ]]

for required_command in awk curl install jq mktemp sha256sum wc; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'error: required command is unavailable: %s\n' "$required_command" >&2
    exit 69
  fi
done

umask 077
cloudflare_application_state=$(mktemp -d "${TMPDIR:-/tmp}/latchway-cloudflare-applications.XXXXXX")
cleanup() {
  rm -rf -- "$cloudflare_application_state"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

cloudflare_api_headers="$cloudflare_application_state/api.headers"
printf 'Authorization: Bearer %s\n' "$CLOUDFLARE_API_TOKEN" > "$cloudflare_api_headers"

cloudflare_applications_api="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/containers/dash/applications"
cloudflare_application_per_page=100
cloudflare_application_max_pages=100
cloudflare_application_max_records=5000
cloudflare_application_max_page_bytes=1048576
cloudflare_application_max_output_bytes=8388608
response="$cloudflare_application_state/response.json"
normalized="$cloudflare_application_state/normalized.json"
accumulator="$cloudflare_application_state/accumulator.json"
combined="$cloudflare_application_state/combined.json"
page_token=""
seen_page_token_hashes=""
page_number=0
printf '[]\n' > "$accumulator"

while true; do
  page_number=$((page_number + 1))
  test "$page_number" -le "$cloudflare_application_max_pages"
  curl_arguments=(
    --silent --show-error --fail-with-body
    --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30
    --max-filesize "$cloudflare_application_max_page_bytes"
    --get --header @"$cloudflare_api_headers"
    --header 'Accept: application/json'
    --data-urlencode "per_page=$cloudflare_application_per_page"
    --output "$response"
  )
  if [[ -n "$page_token" ]]; then
    curl_arguments+=(--data-urlencode "page_token=$page_token")
  fi
  curl "${curl_arguments[@]}" "$cloudflare_applications_api"
  test -s "$response"
  test "$(wc -c < "$response")" -le "$cloudflare_application_max_page_bytes"
  jq -e '
    def nonnegative_integer:
      type == "number" and . >= 0 and floor == .;
    type == "object" and
    .success == true and
    .errors == [] and
    (.messages | type == "array") and
    (.result | type == "array") and
    (.result_info | type == "object") and
    (
      .result_info.next_page_token == null or
      (
        .result_info.next_page_token | type == "string" and
        length >= 1 and length <= 2048 and
        test("^[!-~]+$")
      )
    ) and
    all(.result[];
      type == "object" and
      (.id | type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) and
      (.name | type == "string" and length >= 1 and length <= 256) and
      (.image | type == "string" and length >= 1 and length <= 2048) and
      (.instances | nonnegative_integer) and
      (.version | nonnegative_integer) and
      (.updated_at | type == "string" and length >= 1) and
      (.created_at | type == "string" and length >= 1) and
      (.health | type == "object") and
      (.health.instances | type == "object") and
      (.health.instances.failed | nonnegative_integer) and
      (.health.instances.starting | nonnegative_integer) and
      (.health.instances.scheduling | nonnegative_integer) and
      (.health.instances.active | nonnegative_integer)
    )
  ' "$response" >/dev/null
  jq --compact-output '
    .result | map({
      id: .id,
      name: .name,
      state: (
        if .health.instances.failed > 0 then "degraded"
        elif .health.instances.starting > 0 or .health.instances.scheduling > 0 then "provisioning"
        elif .health.instances.active > 0 then "active"
        else "ready"
        end
      ),
      instances: .instances,
      image: .image,
      version: .version,
      updated_at: .updated_at,
      created_at: .created_at
    })
  ' "$response" > "$normalized"
  jq --slurp '.[0] + .[1]' "$accumulator" "$normalized" > "$combined"
  mv -- "$combined" "$accumulator"
  test "$(jq -er 'length' "$accumulator")" -le "$cloudflare_application_max_records"
  test "$(wc -c < "$accumulator")" -le "$cloudflare_application_max_output_bytes"
  next_page_token=$(jq -er '.result_info.next_page_token // empty' "$response" || true)
  if [[ -z "$next_page_token" ]]; then
    break
  fi
  page_token_hash=$(printf '%s' "$next_page_token" | sha256sum | awk '{print $1}')
  if [[ " $seen_page_token_hashes " == *" $page_token_hash "* ]]; then
    printf 'error: Cloudflare application pagination repeated a cursor\n' >&2
    exit 65
  fi
  seen_page_token_hashes="${seen_page_token_hashes:+$seen_page_token_hashes }$page_token_hash"
  page_token="$next_page_token"
done

jq -e --argjson max_records "$cloudflare_application_max_records" '
  type == "array" and
  length <= $max_records and
  ([.[].id] | length) == ([.[].id] | unique | length) and
  all(.[];
    (keys | sort) == ["created_at", "id", "image", "instances", "name", "state", "updated_at", "version"] and
    (.state == "active" or .state == "degraded" or .state == "provisioning" or .state == "ready")
  )
' "$accumulator" >/dev/null
jq --sort-keys 'sort_by(.id)' "$accumulator" > "$combined"
install -m 0644 "$combined" "$destination"
