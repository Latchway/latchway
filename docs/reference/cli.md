# Latchway CLI reference

The `latchway` binary operates the gateway through the same canonical Admin API
used by the console. Except for `serve`, `migrate`, and the local bootstrap
doctor, control-plane commands do not open PostgreSQL or read server
configuration files.

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

Generate completion with Cobra's built-in commands:

```bash
latchway completion bash
latchway completion zsh
latchway completion fish
latchway completion powershell
```

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
attempts, normalized usage, and provenance, not prompt or response bodies.

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
  --requested-output-max 800
```

The response explains access, limits, primary routing, physical model,
fallback order, and pricing confidence. It performs no quota reservation and
no upstream dispatch. Facts that production CEL does not yet consume are
reported as non-decisional warnings instead of being simulated in the CLI.

## Secrets and verification

Secret values must come from stdin, a regular file, a file descriptor, or a
named environment variable; they are never returned:

```bash
printf '%s' "$PROVIDER_KEY" | latchway secret set provider_key --environment env_... --from-stdin
latchway secret list --environment env_...
```

`latchway verify local --environment env_...` persists a bounded database,
schema, and active-configuration self-test. Upstream and OpenRouter verification
remain fail-closed unless the server has a credential-aware bounded dispatcher;
the CLI never obtains or forwards a provider credential itself.
