# Latchway

Latchway is an Apache-2.0-licensed, self-hostable access gateway that lets untrusted iOS, Android, web, and React Native applications call configured AI infrastructure without embedding upstream provider credentials.

The current source candidate implements the mobile-first gateway, native and
web attestation verifiers, structured and restricted opaque protocols, quotas,
routing, the operator control plane, telemetry/jobs, deployment templates, and
evidence-gated release automation. It is **not yet a published or supported
release**: live provider, physical-device, cloud, resilience, public tag, and
registry receipts must still pass for the exact immutable candidate. The
evidence-based state is maintained in
[`docs/implementation/STATUS.md`](docs/implementation/STATUS.md); release claims
are tracked in
[`docs/implementation/COMPLETION_REPORT.md`](docs/implementation/COMPLETION_REPORT.md).

## Product boundary

Latchway verifies an application's existing user identity, evaluates platform-appropriate attestation, issues short-lived DPoP-bound sessions, authorizes application features, reserves quotas before dispatch, routes to a server-selected upstream, injects credentials, streams protocol-compatible responses, and settles actual usage.

Applications keep their identity provider and HTTP request format. Clients never receive an upstream provider secret and cannot assert trusted user, plan, route, price, or usage information.

## Contract foundation

Draft protocol contract `1.0.0` uses current wire protocol version `2`; the
gateway continues to accept version `1` for compatible legacy
installation/session clients. Normative artifacts live in [`api/`](api/):

- client and Admin OpenAPI 3.1 descriptions;
- the immutable environment configuration JSON Schema;
- the stable error registry;
- protocol compatibility metadata;
- canonical attestation-binding and RFC 9449 DPoP test vectors.

See [`docs/architecture/overview.md`](docs/architecture/overview.md), [`docs/threat-model/overview.md`](docs/threat-model/overview.md), [`docs/reference/upstream-routing.md`](docs/reference/upstream-routing.md), and [`docs/protocol/`](docs/protocol/) before implementing a client or server.

Start with the [mobile-first five-minute quickstart](docs/quickstart.md). The
[identity and attestation guide](docs/guides/identity-and-attestation.md),
[upstream provider guide](docs/guides/upstream-providers.md),
[API reference](docs/reference/api.md), [CLI reference](docs/reference/cli.md),
and [troubleshooting guide](docs/troubleshooting.md) cover the production path.

## Development

Repository rules are in [`AGENTS.md`](AGENTS.md). The reproducible foundation can be exercised with:

```sh
if [ -L .env ]; then
  printf '%s\n' '.env must not be a symbolic link' >&2
  exit 1
fi
if [ ! -e .env ]; then
  umask 077
  latchway_env_tmp=$(mktemp ./.env.bootstrap.XXXXXX)
  trap 'rm -f -- "$latchway_env_tmp"' EXIT HUP INT TERM
  chmod 0600 "$latchway_env_tmp"
  awk '1' .env.example > "$latchway_env_tmp"
  printf 'LATCHWAY_MASTER_KEY=%s\n' "$(openssl rand -base64 32)" >> "$latchway_env_tmp"
  printf 'LATCHWAY_ADMIN_BOOTSTRAP_TOKEN=%s\n' "$(openssl rand -hex 32)" >> "$latchway_env_tmp"
  test ! -e .env && test ! -L .env
  mv -- "$latchway_env_tmp" .env
  unset latchway_env_tmp
  trap - EXIT HUP INT TERM
fi
docker compose up -d --build
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Generate the local master key only once and keep the untracked `.env` with its
database volume. Changing or losing it makes existing encrypted secrets and
gateway signing keys intentionally unusable, and Latchway fails startup before
deriving user lookup values or serving traffic. Production deployments must
supply an independently generated 32-byte key through their secret-management
environment; Compose has no built-in master-key fallback.

This smoke check proves the container, embedded console, PostgreSQL connection, and migrations. Repository tests additionally cover the local custom-JWT, signed debug-attestation, DPoP session, policy, OpenAI Chat proxy, quota, and mock-upstream vertical. Neither check is evidence of production native attestation, a live upstream, cloud deployment, or released SDK compatibility.

### First-owner bootstrap

The first-start command above writes a freshly generated
`LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` before Compose can initialize the database.
Open `http://127.0.0.1:8080`, choose first-owner setup, and transfer that token
from the protected local `.env` into the Console. Alternatively, read only the
exact bootstrap assignment from that file and prompt for the owner password
without putting either value in shell history:

```bash
latchway_bootstrap_count=$(awk -F= '$1 == "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN" {count++} END {print count+0}' .env)
test "$latchway_bootstrap_count" -eq 1
LATCHWAY_ADMIN_BOOTSTRAP_TOKEN=$(awk -F= '$1 == "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN" {print substr($0, index($0, "=") + 1)}' .env)
[[ "$LATCHWAY_ADMIN_BOOTSTRAP_TOKEN" =~ ^[0-9a-f]{64}$ ]]
export LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
printf 'First-owner password: ' >&2
IFS= read -r -s LATCHWAY_ADMIN_PASSWORD
printf '\n' >&2
printf 'Confirm first-owner password: ' >&2
IFS= read -r -s latchway_admin_password_confirmation
printf '\n' >&2
test "$LATCHWAY_ADMIN_PASSWORD" = "$latchway_admin_password_confirmation"
unset latchway_admin_password_confirmation
export LATCHWAY_ADMIN_PASSWORD

latchway --server http://127.0.0.1:8080 admin bootstrap \
  --organization-slug example \
  --organization-name "Example Organization" \
  --email owner@example.com \
  --display-name "Example Owner"

unset LATCHWAY_ADMIN_BOOTSTRAP_TOKEN LATCHWAY_ADMIN_PASSWORD
```

Bootstrap creates the owner and secure browser session atomically, stores only
hashes for credentials, and closes permanently after the first owner exists.
Remove the consumed token from `.env`, then recreate only the gateway service
so future processes never receive it:

```sh
umask 077
test -f .env && test ! -L .env
latchway_bootstrap_count=$(awk -F= '$1 == "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN" {count++} END {print count+0}' .env)
test "$latchway_bootstrap_count" -eq 1
latchway_env_tmp=$(mktemp ./.env.after-bootstrap.XXXXXX)
trap 'rm -f -- "$latchway_env_tmp"' EXIT HUP INT TERM
chmod 0600 "$latchway_env_tmp"
awk '!/^LATCHWAY_ADMIN_BOOTSTRAP_TOKEN=/' .env > "$latchway_env_tmp"
test "$(awk -F= '$1 == "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN" {count++} END {print count+0}' "$latchway_env_tmp")" -eq 0
mv -- "$latchway_env_tmp" .env
unset latchway_env_tmp latchway_bootstrap_count
trap - EXIT HUP INT TERM
docker compose up -d --force-recreate latchway
```

The CLI deliberately has no secret-valued flags. Remote Admin API origins must
use HTTPS. If a database volume was already initialized with a different,
unexpired bootstrap token, Latchway fails closed; use the original protected
token or recreate only the disposable local volume instead of guessing a new
one.

### Provider secrets

Create an Admin API token scoped to `manage_secrets`, load it into the environment named by `--api-token-env` (default `LATCHWAY_ADMIN_API_TOKEN`), and use the canonical API through the same binary:

```sh
latchway --server http://127.0.0.1:8080 secret list \
  --environment env_00000000000000000000000000

# Supply the value from a protected prompt or secret-manager command.
latchway --server http://127.0.0.1:8080 secret set openrouter \
  --environment env_00000000000000000000000000 \
  --from-stdin

latchway --server http://127.0.0.1:8080 secret rotate \
  sec_00000000000000000000000000 --from-stdin

latchway --server http://127.0.0.1:8080 secret delete \
  sec_00000000000000000000000000
```

Values can come only from standard input, a named environment variable, a bounded regular file, or an open file descriptor. They are encrypted with authenticated envelope encryption and never returned by the API or CLI. Rotation and deletion require the latest metadata ID; a superseded ID fails with `409` so a stale administrator cannot overwrite or destroy a newer credential. A logical name cannot be reused after its permanent tombstone, and deletion is rejected while any valid, active, or rollback-eligible configuration revision references it.

If PostgreSQL loses a commit acknowledgement, the API returns retryable `operation_indeterminate` with a correlated `operation_id` instead of asserting failure. Preserve that identifier: only a `succeeded` audit event with the same request/operation ID proves that the original mutation committed. Current metadata, name existence, or a stale-version conflict proves only the present state and may reflect another administrator's later mutation. Reconcile the correlated audit event before retrying creation or rotation; deletion alone may be repeated with the exact same record ID because that operation is idempotent. Remote origins require HTTPS and redirects are not followed.

Security vulnerabilities must follow [`SECURITY.md`](SECURITY.md), not public issue discussion. Contributions require Developer Certificate of Origin sign-off as described in [`CONTRIBUTING.md`](CONTRIBUTING.md).
