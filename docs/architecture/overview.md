# Architecture overview

Latchway owns the security and accounting boundary between an untrusted application client and trusted AI infrastructure.

```text
Untrusted app
  existing identity token + platform attestation + P-256 DPoP key + AI request
       |
       v
Latchway data plane
  identity -> attestation -> session/DPoP -> feature policy -> quota reservation
  -> route/model selection -> credential injection -> streaming proxy -> settlement
       |
       v
Configured AI or HTTP upstream
```

The control plane consists of one revisioned Admin API. The CLI and embedded React dashboard are clients of that API. PostgreSQL is the sole version-1 source of durable truth and provides configuration storage, replay uniqueness, quota serialization, job claiming, audit history, and usage records.

## Deployment shape

One Go binary provides `serve`, `migrate`, configuration, administration, diagnostics, verification, and version commands. The same image can run `all`, `api`, or `worker` roles. A multi-stage build compiles the React dashboard and embeds static assets and forward-only migrations into the binary. Production contains neither Node nor the Go toolchain.

The server remains stateless outside PostgreSQL and process-local caches. Cache invalidation may use PostgreSQL notification, but correctness always falls back to the database and periodic reconciliation.

## Domain boundaries

- **Organization → application → environment** owns configuration and tenancy.
- **Application user** is derived from a verified external identity; raw external subjects are HMAC-pseudonymized by default.
- **Installation** binds platform trust and revocation state to a P-256 JWK thumbprint.
- **Feature** is the client-facing authorization and routing abstraction.
- **Configuration revision** is immutable; an environment has exactly one atomically selected active revision.
- **Logical request** represents one client operation. **Upstream attempts** record routing and fallback without double-counting the user operation.
- **Quota reservation** prevents concurrent overspend before network dispatch and settles to actual metered usage afterward.

## Protected request pipeline

1. Apply transport limits and assign a request ID.
2. Resolve the fixed route family and protocol adapter.
3. Verify the Latchway access token and RFC 9449 DPoP proof, then reserve the proof replay key in PostgreSQL.
4. Resolve tenant, user, installation and active configuration; reject revocation or stale trust.
5. Normalize the request, resolve the feature, evaluate CEL access and select a limit plan.
6. Estimate and atomically reserve every applicable quota and concurrency lease.
7. Select a configured route, upstream and physical model.
8. Strip credentials and forbidden forwarding headers, validate the destination against SSRF policy, rewrite bounded fields, and inject the server-held credential.
9. Dispatch without an open database transaction; stream response bytes while parsing protocol frames for usage.
10. Record attempts and actual/estimated usage, settle or release the reservation idempotently, emit redacted telemetry, and release concurrency.

No fallback or retry occurs after response bytes reach the client. SDKs may refresh an expired Latchway session but must not automatically replay a request that might have reached an upstream.

## Extension boundaries

Identity, attestation, protocol, upstream, and pricing behavior use narrow internal interfaces, while trusted implementations are statically compiled for version 1. Arbitrary JavaScript, shell, Go plugins, SQL, or runtime-downloaded code is prohibited. CEL is the only operator-configurable policy language.

## Normative sources

- `api/` owns wire and configuration contracts.
- `docs/adr/` records durable decisions.
- `docs/threat-model/` records assets, trust boundaries, attacks, and residual risk.
- `docs/implementation/STATUS.md` records what is actually implemented and tested.
