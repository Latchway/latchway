# Administration threats

## Bootstrap and identity

The first owner flow requires a high-entropy `LATCHWAY_ADMIN_BOOTSTRAP_TOKEN`, stores only its hash, consumes it transactionally, and permanently closes after an owner exists. A remaining environment variable triggers a warning but cannot reopen bootstrap. Local passwords use Argon2id with versioned parameters. Cookie sessions require secure attributes, CSRF tokens, origin checks, expiry and revocation.

## Authorization

Capabilities derive from server-side memberships and the roles `owner`, `admin`, `operator`, and `viewer`. Every Admin API handler checks the specific capability and tenant scope. UI hiding is not authorization. API tokens are high-entropy, displayed once, hashed, scoped, expirable, revocable, and audited. A bearer-authenticated token creation request may delegate only capabilities in that bearer's effective scope; the administrator's broader underlying role cannot elevate it.

## Configuration and secrets

Draft revisions use ETags to prevent lost updates. Activation validates schema, references, secret availability, CEL compilation, protocol capability, pricing, and route simulation, then changes one active pointer atomically. Rollback activates a prior immutable revision.

Secret create/rotate input is write-only. Responses contain metadata, never plaintext. Authenticated encryption associated data binds organization, environment, secret, version, and format. The environment master key is required only at runtime, never stored in PostgreSQL or logs.

## Audit and privacy

Every administrative mutation records actor, capability, tenant, action, target, result, request ID, timestamp, and a redacted change summary. Audit records exclude passwords, bootstrap/API tokens, provider secrets, identity/refresh tokens, DPoP proofs, raw attestation evidence, and prompt bodies. Access to users, installations, request metadata, and optional prompt bodies is separately authorized and logged.

## Operational attacks

Rate-limit login and token endpoints; detect credential stuffing and session fixation; prevent cross-tenant ID enumeration; enforce secure proxy/host configuration; redact diagnostics; and ensure CLI secrets enter by stdin, file descriptor, or named environment variable rather than command arguments. A newly issued CLI API token goes only to a caller-selected, exclusive mode-`0600` regular file and never to terminal output. Browser copy actions explicitly warn that an operating-system clipboard is outside the console's storage boundary. Backup and restore must preserve encryption metadata and audit integrity without capturing the external master key in the database backup.
