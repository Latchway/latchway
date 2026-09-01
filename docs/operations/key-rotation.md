# Key and secret rotation

Latchway has distinct key classes with different procedures. Treating them as
interchangeable can make encrypted data unrecoverable or invalidate every
mobile session.

## Environment master key

`LATCHWAY_MASTER_KEY` protects stored managed secrets and gateway signing-key
material. Version 1 uses the environment master-key provider. Replacing the
value in-place is not a rotation procedure: readiness deliberately fails when
persisted records refer to another master-key identifier.

Back up and escrow this key separately from PostgreSQL. A future rewrap workflow
must decrypt and re-encrypt every protected record under an audited exclusive
operation before the old key can be retired. Until that workflow is available,
master-key change means restore/migration planning, not an environment edit.

## Gateway signing keys

The worker performs scheduled gateway signing-key rotation. New keys become
active while old public keys remain in JWKS long enough for issued access
tokens and verifier caches to expire; expired historical keys are retired
automatically. Version 1 exposes no Admin API or CLI operation to force
signing-key rotation, select a new active key, or shorten JWKS overlap.
Scheduled rotation is not emergency containment.

Monitor rotation jobs, signing readiness, JWKS publication, and clock skew
across all replicas. An emergency that requires invalidating live sessions is
an incident-response action outside the v1 Admin and CLI surface. Record the
active/retiring key IDs and timestamps, never private key bytes.

## Identity-provider JWKS

Remote identity keys are cached in PostgreSQL so API replicas share refresh and
failure behavior. Respect issuer cache metadata, retain stale-but-valid keys
only within the configured safety window, and alert on refresh failures. Test
provider rollover with multiple API replicas before production.

## Upstream credentials

Create a new managed-secret version through the canonical Admin API, activate a
configuration revision that references it, verify traffic, then delete the old
version only after reference checks pass. The API never returns plaintext.
Use correlated audit/operation IDs to reconcile indeterminate administrative
commits before retrying rotation.

## Admin bootstrap and sessions

Remove `LATCHWAY_ADMIN_BOOTSTRAP_TOKEN` after the first administrator is
created. Rotate compromised admin credentials through the canonical Admin API,
revoke affected sessions/installations, and review redaction-safe audit events.
