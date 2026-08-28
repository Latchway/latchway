# Administrative operational views

The canonical Admin API exposes tenant-scoped operational state without
returning provider credentials, identity subjects, bearer or refresh tokens,
DPoP proofs, attestation evidence, or request bodies. The embedded console and
CLI must consume these HTTP resources rather than querying PostgreSQL.

## Authorization and tenancy

- User, installation, request, usage, and audit reads require the
  `inspect_users` capability. A scoped API token must include it even when the
  administrator's membership role would otherwise allow the read.
- User block/unblock and installation revocation require
  `revoke_installations`. Blocking suspends future sessions and revokes current
  grants and refresh tokens; unblocking never restores revoked credentials.
- Local self-tests require `run_self_tests`.
- Every lookup derives the organization from the authenticated principal.
  Supplied organization filters must exactly match that organization, and
  cross-tenant identifiers are reported as not found or denied.

Cookie-authenticated mutations retain the Admin API's strict Origin and CSRF
checks. Successful user status changes, installation revocations, and
self-tests write a value-free audit summary in the same transaction. An
ambiguous commit returns `operation_indeterminate` with the operation ID used
by the potentially committed audit event.

## Bounded query behavior

The users, installations, requests, and audit collections use opaque keyset
cursors and return at most 200 records. Duplicate or unknown query parameters
are rejected. User claims are limited to 64 top-level fields and 64 KiB of
encoded JSON; at most 64 distinct identity-provider identifiers are returned.
Each request contains at most the schema-enforced 32 upstream attempts, and
usage rows are aggregated in PostgreSQL before their bounded result is decoded.

Usage summary ranges are half-open (`start <= recorded_at < end`) and limited
to 366 days. Timeseries data uses UTC hour or UTC day buckets and rejects a
range that would emit more than 10,000 points. Token and cost values come from
the immutable usage ledger; multi-attempt usage is summed while the logical
request record remains single-counted. The request explorer returns metadata,
attempt lifecycle, model/upstream selection, and provenance, never prompt or
response bodies.

Audit events expose actor and target opaque IDs plus ordered field,
operation, and classification markers. They do not expose before/after values
or free-form mutation reasons.

## Self-tests and system status

`POST /admin/v1/self-tests` currently executes the durable `local` diagnostic:
PostgreSQL transaction availability, migration compatibility, and presence of
an active compiled environment configuration. The completed redaction-safe
result is stored in the existing jobs ledger and can be retrieved after a
restart. The API never converts a failed check into a transport success claim;
the accepted run has a terminal `passed` or `failed` state.

Credential-aware `upstream` and `openrouter` runners remain intentionally
unavailable until the worker owns a bounded dispatcher, secret capability,
budget reservation, cancellation, and durable run-state transition. Requests
for those kinds fail validation instead of returning a fabricated result.

`GET /admin/v1/system` reports build version, contract and protocol versions,
the configured process role, current migration version, and a readiness bit.
Dependency errors are reduced to `ready: false`; endpoint output does not
include database addresses or error text.
