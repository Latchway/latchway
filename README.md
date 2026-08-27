# Latchway

Latchway is an Apache-2.0-licensed, self-hostable access gateway that lets untrusted iOS, Android, web, and React Native applications call configured AI infrastructure without embedding upstream provider credentials.

The project is under active construction. The current working tree has a runnable Go/PostgreSQL/dashboard foundation, but it is **not yet a functional access gateway or a released package**. The evidence-based state is maintained in [`docs/implementation/STATUS.md`](docs/implementation/STATUS.md); release claims are tracked in [`docs/implementation/COMPLETION_REPORT.md`](docs/implementation/COMPLETION_REPORT.md).

## Product boundary

Latchway verifies an application's existing user identity, evaluates platform-appropriate attestation, issues short-lived DPoP-bound sessions, authorizes application features, reserves quotas before dispatch, routes to a server-selected upstream, injects credentials, streams protocol-compatible responses, and settles actual usage.

Applications keep their identity provider and HTTP request format. Clients never receive an upstream provider secret and cannot assert trusted user, plan, route, price, or usage information.

## Contract foundation

Protocol contract `0.1.0` uses wire protocol version `1`. Normative artifacts live in [`api/`](api/):

- client and Admin OpenAPI 3.1 descriptions;
- the immutable environment configuration JSON Schema;
- the stable error registry;
- protocol compatibility metadata;
- canonical attestation-binding and RFC 9449 DPoP test vectors.

See [`docs/architecture/overview.md`](docs/architecture/overview.md), [`docs/threat-model/overview.md`](docs/threat-model/overview.md), and [`docs/protocol/`](docs/protocol/) before implementing a client or server.

## Development

Repository rules are in [`AGENTS.md`](AGENTS.md). The reproducible foundation can be exercised with:

```sh
if [ ! -e .env ]; then
  umask 077
  cp .env.example .env
  printf 'LATCHWAY_MASTER_KEY=%s\n' "$(openssl rand -base64 32)" >> .env
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

This proves the container, embedded console, PostgreSQL connection, and migrations; it does not prove the identity, attestation, DPoP, policy, proxy, quota, or SDK flows. The first functional vertical slice tracked in the master plan must add debug attestation, custom JWT verification, a DPoP session, an OpenAI Chat proxy, request limits, and a JavaScript fetch client.

### First-owner bootstrap

Set a freshly generated `LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` of at least 32 bytes before the first server start. The embedded console can consume it, or the same canonical Admin API can be called through the CLI:

```sh
export LATCHWAY_ADMIN_BOOTSTRAP_TOKEN
export LATCHWAY_ADMIN_PASSWORD

latchway --server http://127.0.0.1:8080 admin bootstrap \
  --organization-slug example \
  --organization-name "Example Organization" \
  --email owner@example.com \
  --display-name "Example Owner"

unset LATCHWAY_ADMIN_BOOTSTRAP_TOKEN LATCHWAY_ADMIN_PASSWORD
```

Populate the two environment variables with a protected prompt or secret manager; the CLI deliberately has no secret-valued flags. Bootstrap creates the owner and secure browser session atomically, stores only hashes for credentials, and closes permanently after the first owner exists. Remote Admin API origins must use HTTPS.

Security vulnerabilities must follow [`SECURITY.md`](SECURITY.md), not public issue discussion. Contributions require Developer Certificate of Origin sign-off as described in [`CONTRIBUTING.md`](CONTRIBUTING.md).
