# Latchway CLI reference

The `latchway` binary operates the gateway through the same canonical Admin API
used by the console. Except for `serve`, `migrate`, the local bootstrap doctor,
and the explicitly isolated `verify local` gate, control-plane commands do not
open PostgreSQL or read server configuration files.

## Authentication and output

Set the server origin and place a scoped Admin API token in an environment
variable. HTTPS is mandatory except for an explicit loopback origin.

```bash
export LATCHWAY_SERVER=https://ai.example.com
export LATCHWAY_ADMIN_API_TOKEN='value-from-a-secret-manager'
latchway --output table status
latchway --output json status
```

Use `--api-token-env NAME` to select a different variable. The token is never
accepted as a flag, printed, or included in a browser `Origin` header. Commands
return a non-zero status for invalid input, denied operations, invalid server
documents, and RFC 9457 failures.

Version 1 deliberately does not persist an administrator password, session
cookie, CSRF token, or API token. `latchway login` is a token-mode validation
command: it reads the selected environment variable, calls
`GET /admin/v1/auth/session`, and prints only administrator, organization,
capability, and expiration metadata. It neither accepts a password nor creates
or stores a credential. `latchway logout` calls `POST /admin/v1/auth/logout`
with that same environment-supplied bearer, revoking it server-side; the dead
value remains in the parent shell until the operator unsets or replaces it.

```bash
latchway login
# Run scoped administrative commands.
latchway logout
unset LATCHWAY_ADMIN_API_TOKEN
```

Browser password sessions remain confined to the embedded console. A
password-based cross-process CLI session would require a reviewed portable OS
credential store or device authorization flow and is intentionally absent.

Generate completion with Cobra's built-in commands:

```bash
latchway completion bash
latchway completion zsh
latchway completion fish
latchway completion powershell
```

## Administrator lifecycle

Only an active owner, or an owner API token scoped with `manage_owners`, can
list or mutate administrator memberships. Passwords are write-only and must
come from stdin, a regular file, a file descriptor, or a named environment
variable; they are never accepted as command arguments or returned.

```bash
latchway admin accounts list
latchway admin accounts create \
  --email operator@example.com \
  --display-name Operator \
  --role operator \
  --value-file ./new-administrator-password
latchway admin accounts role adm_... --role admin
latchway admin accounts disable adm_...
latchway admin accounts enable adm_...
printf '%s' "$NEW_ADMIN_PASSWORD" | \
  latchway admin accounts reset-password adm_... --from-stdin
```

Disabling a membership revokes its sessions and API tokens in that
organization. Password reset also revokes affected credentials. The final
active owner cannot be demoted or disabled. Because a local password belongs
to the global administrator identity, an owner-driven reset is rejected when
that identity also belongs to another organization.

## API tokens

List and revoke only the current administrator's token metadata through the
canonical API:

```bash
latchway admin api-tokens list
latchway admin api-tokens revoke tok_...
```

Creation requires one or more explicit capabilities and a new output path:

```bash
latchway admin api-tokens create \
  --name mobile-ci \
  --scope inspect_users \
  --scope run_self_tests \
  --token-output-file ./mobile-ci.token
```

The output path must not already exist. Before asking the server to mutate
state, the CLI creates an exclusive regular file, fixes and verifies mode
`0600`, then writes the one-time token and synchronizes it. Standard output
contains metadata only. Existing files and symlinks are never overwritten; an
incomplete file is removed after failure, and a token is compensating-revoked
when a post-creation write cannot be completed. Move the file into the chosen
secret manager, then remove the local copy using the operator's normal secure
workflow. A bearer-authenticated token cannot create a token with capabilities
outside its own effective scope.

## Immutable configuration

Pull the active redaction-safe document:

```bash
latchway --output json config pull --environment env_...
```

Apply one duplicate-key-safe JSON object from a regular file or stdin. A dry
run creates and validates an immutable draft but does not activate it. A normal
apply validates, produces the redacted structural plan when an active base
exists, and activates with the strong ETag returned for that exact draft.

```bash
latchway config apply --environment env_... --file environment.json --dry-run
latchway config apply --environment env_... --file environment.json
latchway config apply --environment env_... --base-revision rev_... --file environment.json
```

The base-revision form first copies the current active revision and then
replaces that draft with `If-Match`, preventing a stale operator from silently
rebasing. Other lifecycle commands are:

```bash
latchway config validate rev_...
latchway config plan rev_...
latchway config diff rev_...
latchway config rollback rev_... --environment env_...
```

## Operational views

```bash
latchway users list --environment env_...
latchway users inspect usr_... --environment env_...
latchway users block usr_... --environment env_...
latchway users unblock usr_... --environment env_...

latchway installations list --environment env_...
latchway installations inspect ins_...
latchway installations revoke ins_... --reason 'operator-approved response'

latchway requests list --environment env_...
latchway requests inspect req_...
latchway usage summary --environment env_...
latchway usage timeseries --environment env_... --interval hour
latchway audit --organization org_...
```

List commands use bounded keyset pages. Pass the printed opaque cursor back via
`--cursor`; never decode or modify it. Request output contains metadata,
contiguously ordered attempt numbers, routes, start/first-byte/completion
times, optional HTTP status, the closed sanitized failure category, normalized
usage, and separate token/cost provenance. It never contains prompt/response
bodies, provider error text, or raw internal errors; unrecognized durable
failure values appear only as `unknown`. An opted-in OpenRouter report is
labeled `upstream_reported` with source `openrouter_usage_cost`; see
[Provider-reported cost](provider-reported-cost.md).

## Exact route simulation

Simulation accepts only normalized facts and runs the server's exact compiled
production resolver. Claims are read from a bounded regular JSON file so they
do not enter shell history.

```bash
latchway routes simulate rev_... \
  --feature assistant \
  --platform react_native_ios \
  --trust-level app_verified \
  --claims-file normalized-claims.json \
  --requested-input-tokens 1200 \
  --requested-output-max 800 \
  --rewritten-request-bytes 4096 \
  --framing-unit-count 3 \
  --image-units 1 \
  --tool-calls 2
```

The response binds the authoritative application, environment, and revision;
explains access, every applicable limit, primary routing, physical model,
fallback order, and pricing; and projects the exact conservative units that
the production quota path would reserve. The byte and framing-unit flags model
the exact post-rewrite values a production adapter proves and are required when
the selected plan needs trusted input or total-token accounting. Simulation
uses the image/tool flags as hypothetical exact structured counts for
`per_request` guards. Their allocations are displayed with `durable: false`
because request-local guards create no quota bucket. Opaque HTTP can project
request bytes but cannot safely project image or tool counts. Simulation
performs no durable reservation and no upstream dispatch. App version and the
requested-input-token estimate are explicitly explanatory: they are returned
for comparison but cannot influence CEL or reservation.

## Secrets and verification

Secret values must come from stdin, a regular file, a file descriptor, or a
named environment variable; they are never returned:

```bash
printf '%s' "$PROVIDER_KEY" | latchway secret set provider_key --environment env_... --from-stdin
latchway secret list --environment env_...
```

`latchway verify local` is a destructive test only inside a generated,
short-lived PostgreSQL schema. It applies every embedded migration, creates an
ephemeral tenant, starts deterministic OIDC and upstream fixtures, and executes
the production session, proxy, trusted-accounting, quota, fallback, recovery,
header-boundary, SSRF, and configuration rollback paths. It then drops the
entire schema and proves that it no longer exists, including when an earlier
check fails.

Supply the database URL by environment-variable name so credentials never enter
process arguments. The database role needs permission to create and drop
schemas. The host also needs one non-loopback private IPv4 address for the
test-owned protected upstreams.

```bash
export LATCHWAY_DATABASE_URL='postgres://...'
latchway verify local
latchway --output json verify local --timeout 2m --junit ./local-verify.xml

# Select a differently named variable without exposing its value.
latchway verify local --database-url-env TEST_DATABASE_URL
```

Human and JSON output are written to stdout. Optional JUnit XML is replaced
atomically with mode `0600`; it contains the same ordered checks and deliberately
omits timestamps, durations, generated identifiers, database coordinates, and
secrets. A failed check still emits the report and JUnit evidence, returns a
non-zero status, marks later dependent checks skipped, and always attempts
cleanup. `DATABASE_URL` is used only as the default fallback when
`LATCHWAY_DATABASE_URL` was not explicitly selected.

Ephemeral provider verification runs locally and never sends the provider key
to Latchway's Admin API. Supply the key by environment-variable name or through
bounded stdin; plaintext provider keys are never accepted as command arguments.

```bash
OPENROUTER_API_KEY=... latchway verify openrouter \
  --api-key-env OPENROUTER_API_KEY \
  --model openai/gpt-4o-mini \
  --max-cost-usd 0.01

PROVIDER_API_KEY=... latchway verify upstream \
  --base-url https://api.example.com/v1 \
  --protocol openai_chat \
  --api-key-env PROVIDER_API_KEY \
  --model provider-model

# stdin is exact: do not append a newline.
printf %s "$OPENROUTER_API_KEY" | latchway verify openrouter \
  --api-key-stdin --model openai/gpt-4o-mini --max-cost-usd 0.01
```

`--api-key-env` and `--api-key-stdin` are mutually exclusive. Empty, oversized,
multiline, control-byte, or invalid bearer-token values are rejected. OpenRouter
requires an exact positive `--max-cost-usd` decimal (up to US$1.00); Latchway
converts it directly to integer nano-USD without floating point and proves the
two-request worst case before dispatch. Generic `openai_chat` verification has
no trusted price catalog and therefore reports monetary cost as `unverified`.

To test an active server-owned target and its write-only stored credential, opt
in explicitly with `--server-owned`. These flags cannot be combined with the
ephemeral flags:

```bash
latchway verify upstream --server-owned \
  --environment env_... --upstream primary --model canary
latchway verify openrouter --server-owned \
  --environment env_... --upstream openrouter --model canary \
  --max-cost-nano-usd 10000000
```

The server-owned default ceiling is `10,000,000` nano-USD (US$0.01). The server
requires configured pricing and trusted model-aware input accounting. In this
mode the CLI never reads or forwards the provider credential; it remains in the
server's write-only secret store.

Use the same `run_self_tests`-scoped Admin API token to create a persistent
schedule. Creation binds that authenticating token's stable ID; there is no
credential-ID or token-value request flag.

```bash
latchway verify schedule create \
  --environment env_... \
  --kind upstream \
  --upstream primary \
  --model canary \
  --interval-seconds 3600 \
  --max-cost-nano-usd 10000000 \
  --daily-cost-limit-nano-usd 240000000

latchway verify schedule list --environment env_...
latchway verify schedule get sts_...
latchway verify schedule disable sts_...
```

The cadence must be one hour through 30 days. The server also requires the
UTC-day ceiling to cover the theoretical cadence at the per-run maximum,
limits each organization to 32 active schedules, and permits only one active
schedule for the same environment/kind/upstream/model selection. Output shows
the exact pinned revision, durable credential ID, cadence, cost ceilings, next
run, last run, and lifecycle state; it never prints the token or a provider
secret.
