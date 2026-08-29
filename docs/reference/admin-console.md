# Admin console resource workflows

The embedded console is a same-origin client of the canonical Admin API. It
does not connect to PostgreSQL, invent a second configuration model, evaluate
policy locally, or retain administrative credentials in Web Storage.

## Named navigation

The authenticated sidebar maps the v1 operator areas literally:

| Group | Named views |
| --- | --- |
| Workspace | Applications, Environments, Setup wizard |
| Administration | Administrators, API tokens |
| Identity | Authentication providers, Attestation, Users, Installations |
| AI Configuration | Features, Routes, Upstreams, Models & pricing, Secrets, Full configuration |
| Governance | Access policies, Limit plans, User overrides, Abuse controls |
| Observability | Requests, Usage, Cost, Latency, Errors, Attestation failures |
| Operations | Configuration revisions, Route simulator, Self-tests, Audit log |
| System | System health |

Authentication providers, attestation, features, nested routes, upstreams,
models/input-accounting/pricing, access policies, limit plans, and abuse
composition each have a dedicated resource editor. An editor exposes only its
canonical resource wrapper, but stages that value into a clone of the complete
active document and preserves every other parsed JSON value. It then asks the
server to clone the exact active revision, replaces that draft with the full
preserved document under the draft's strong ETag, validates, plans, and
optionally activates under the newest strong ETag. A stale base or ETag fails
before activation. The Admin API accepts the replacement document itself as
the PATCH body; the console does not invent a `{document: ...}` wrapper or a
partial server configuration model.

Cost, latency, errors, and attestation failures are separate focused pages over
the canonical bounded analytics endpoints. They deliberately render only the
relevant totals, denominators, distributions, attribution, or provenance; they
are not aliases for the complete Usage page and do not create another
analytics source of truth.

## Resource workflows

Applications are listed within the administrator session's organization.
Environments are listed and created under an exact application ID. Both create
operations require `activate_configuration`; the server remains authoritative
for tenant scope, uniqueness, validation, audit attribution, and returned IDs.

The Secrets view requires `manage_secrets`. Lists contain only redaction-safe
metadata. Create and rotate values are uncontrolled password inputs: plaintext
is never persisted in browser storage and each input is cleared before its
request completes. The server never returns plaintext. Permanent deletion is a
two-step, in-page operation: the console displays the exact current
version-specific secret ID, explains the permanent name tombstone, requires the
operator to type the logical name, and rechecks the currently loaded name-to-ID
binding before sending `DELETE`. Cancellation sends no mutation. The server
still rejects referenced, stale, superseded, or cross-tenant IDs.

The User overrides view requires `inspect_users` to load one pseudonymous user
within an exact environment. Replacing or clearing the limit-plan override
requires `activate_configuration`. The console sends only the bounded plan,
reason, optional expiration, environment ID, and opaque user ID; it cannot
alter access or route selection.

Configuration revisions are paged one full redaction-safe document at a time
because an individual document may approach the Admin client's response bound.
Rollback is enabled only for a previously activated, non-current revision and
an active strong ETag. On click, the console fetches the active revision again
and sends that fresh ETag with the exact target revision ID. The server performs
the atomic conflict check and audit mutation.

Selecting a logical request loads the exact request-detail endpoint. The view
shows request status, start/completion/duration, aggregate usage, and ordered
attempt start/completion/duration, upstream, physical model, public status,
usage, cost, and independent usage/cost provenance. The v1 Admin API does not
expose a route ID, upstream HTTP status, or public failure code on an attempt,
so the console states that boundary instead of fabricating those fields. Raw
request/response bodies and identity subjects remain excluded.

The route simulator can load one environment's exact active revision and its
bounded canonical feature IDs. It preselects that revision/feature and rejects
a changed selection or a simulation response whose environment, revision, or
feature does not match the loaded context. Production CEL and route resolution
still execute only on the server; loading context does not reserve quota or
dispatch upstream traffic.

## Browser boundary

All non-GET Admin requests pass through the shared same-origin client, which
adds the session-bound CSRF header and refuses non-canonical paths. Zod schemas
are strict and bounded; unknown response fields, including an accidental
secret `value`, fail closed. The production bundle has no database client,
connection string, browser policy evaluator, or browser-storage credential
path.
