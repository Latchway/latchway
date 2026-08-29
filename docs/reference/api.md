# API reference

Latchway's normative APIs are OpenAPI 3.1 documents, not duplicated prose:

- `api/client.openapi.yaml` — client session, quota, diagnostics, structured AI,
  restricted opaque proxy, JWKS, and discovery endpoints
- `api/admin.openapi.yaml` — authentication, tenant resources, immutable
  configuration, secrets, administrators, tokens, users, installations,
  requests, usage, audit, self-tests, and system health
- `api/error-codes.yaml` — stable RFC 9457 problem codes, status, title, and
  retry semantics
- `api/config.schema.json` — the complete immutable environment configuration
- `api/protocol-version.json` — contract and supported wire versions

Run the repository validator before using generated clients or publishing a
contract bundle:

```bash
python3 scripts/validate-contracts.py
python3 scripts/build-contract-bundle.py --output /tmp/latchway-contract.tar.gz
```

## Client request boundary

Every SDK request declares its SDK kind/version, wire protocol, and feature.
Protected endpoints also use a short-lived DPoP access token and a fresh proof
bound to the exact public method and URL. The optional client request ID is a
correlation hint; the server replaces invalid or ambiguous values.

The server never accepts a client-supplied destination, upstream credential,
physical model, price, trusted user/plan, or usage value. Provider-compatible
placeholder authorization is stripped and never forwarded.

## Admin request boundary

The embedded console uses a secure same-origin cookie plus session-bound CSRF.
The CLI uses a scoped, expirable, revocable API token supplied only through an
environment variable. Mutation endpoints are audited and configuration
updates use strong ETags. Secret-valued inputs are write-only.

Admin and client errors are canonical `application/problem+json` documents.
They contain a stable safe code, request ID, retry guidance, and optional
operation correlation—not provider payloads, raw internal errors, identity
tokens, proofs, or credentials.

## Generated clients

Generated DTOs may be derived from OpenAPI for internal use, but public mobile
SDK APIs remain handwritten and idiomatic. A generated client must preserve
the SDK's origin pinning, DPoP, secure storage, attestation, bounded parsing,
retry, redaction, and non-replayable-body guarantees; schema generation alone
does not implement those controls.
