# Admin console resource workflows

The embedded console is a same-origin client of the canonical Admin API. It
does not connect to PostgreSQL, invent a second configuration model, evaluate
policy locally, or retain administrative credentials in Web Storage.

## Workspace context and navigation

The selected application and environment are first-class workspace context,
not free-form IDs on task pages. The top bar resolves both through the
canonical organization/application/environment endpoints and places their
slugs in URL search parameters. Navigation preserves that search. An explicitly
invalid URL is blocked, production is labeled with text as well as color, and
the console never silently substitutes another environment.

Primary navigation follows common operator tasks. Technical resources remain
reachable under Configure, Investigate, Operations, and Advanced:

| Group | Named views |
| --- | --- |
| Primary | Features, Requests, Users, Usage |
| Configure | AI connections, Client access, Environments, Setup guide |
| Investigate | Cost, Latency, Errors, Attestation failures |
| Operations | Configuration revisions, Route simulator, Self-tests, Audit log |
| Advanced | Applications, Routes, Models & pricing, Secrets, policies, limits, full configuration |
| Team and system | Administrators, API tokens, System health |

`Command-K` / `Control-K` opens a searchable palette over those destinations.
The palette can navigate to dangerous workflows but cannot activate, rotate,
delete, revoke, or otherwise mutate data itself.

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

Features additionally have a task-level workspace. Read-only cards summarize
the active access expression, limit plan, primary/fallback route, and physical
models, with full JSON behind an advanced disclosure. The add-feature wizard
accepts only schema-backed fields. Saving clones the exact active revision,
PATCHes the preserved full document, validates it, and obtains a redacted
server plan; it never activates. Publishing is a separate action under the
newest strong ETag and states the selected environment and production
consequence next to the button. Client setup output includes only gateway and
feature identifiers, never provider credentials.

AI connections are also task-oriented. One form assembles an HTTPS upstream,
write-only bearer secret reference (or explicit no-auth choice), physical model,
input-accounting profile, and operator-reviewed USD pricing. Decimal prices are
converted exactly to integer nano-USD without floating-point arithmetic. The
secret value is cleared before the request completes and never enters the
configuration document. The full document is staged and validated first;
publishing and the bounded upstream self-test are separate, deliberate actions.
The self-test uses only API-supported OpenAI-compatible targets and never acts
as a client application.

Client access groups the normally separate identity-provider, attestation-policy,
component-definition, and feature-grant resources. The common path supports an
iOS App Attest root component, an Android Play Integrity root component, or a
Web Firebase App Check root component, with production-aware defaults and an
optional Firebase authentication provider. Usage plans similarly translate
daily request/token/cost ceilings, per-request token ceilings, concurrency,
scope, and an IANA timezone into explicit hard server rules. The console shows
configured plan sentences, but does not claim to show resolved effective limits:
the Admin API does not expose effective values and their contributing sources.

For the isolated Development workspace, `latchway develop` owns the mock
identity, debug proof material, loopback upstream, seeded configuration, and
one-run Console access. The console detects that active loopback fixture and
guides the operator to run the official `habit-assistant` client sample. Its
verification button only reads the bounded durable request list; it cannot
provision the mock or submit a client request through the Admin API. The normal
connection wizard remains HTTPS-only.

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

The workspace top bar separately asks for the newest revision and surfaces its
server state when it is draft, valid, or invalid. Following that indicator opens
history already scoped to the selected environment. This is the strongest
global draft affordance supported by the contract: there is no organization-wide
draft count/filter endpoint and no abandon, delete, or archive operation for a
configuration revision. The console labels that limitation and leaves an
unpublished revision inert rather than presenting a destructive control that
cannot be honored.

Selecting a logical request stores the exact selection in the workspace URL and
loads the exact request-detail endpoint. The view begins with a chronological
identity/trust/feature/attempt/settlement timeline plus short explanations of
outcome, fallback, and cost confidence. It then shows request status,
start/completion/duration, aggregate usage, and ordered
attempt number, route, start/first-byte/first-token/completion timing, upstream,
physical model, public status, optional HTTP status, sanitized failure category,
usage, cost, and independent usage/cost provenance. Failure values are restricted to
the canonical public vocabulary and unknown durable values appear only as
`unknown`. Raw request/response or provider error bodies, provider error text,
internal errors, and identity subjects remain excluded.

## Generated Admin API contract

`web/console/scripts/generate-admin-api.mjs` compiles the canonical
`api/admin.openapi.yaml` document with the exactly pinned `openapi-typescript`
version into `web/console/src/generated/admin-api.ts`. The generated artifact is
checked in for deterministic Go builds. `pnpm check:api` compares generated
bytes and is part of `pnpm check` and `pnpm build`; `pnpm generate:api` is the
only update path. Generated component types constrain console resource schemas,
while strict bounded Zod schemas continue to validate untrusted runtime JSON.

The route simulator can load one environment's exact active revision and its
bounded canonical feature IDs. It preselects that revision/feature and rejects
a changed selection or a simulation response whose environment, revision, or
feature does not match the loaded context. Production CEL and route resolution
still execute only on the server; loading context does not reserve quota or
dispatch upstream traffic.

The Self-tests view combines immediate diagnostics with persistent scheduled
upstream checks. Schedule list, detail, and disable use the signed-in session
and require `run_self_tests`. Creation cannot derive durable execution
authority from that session: the operator enters an existing scoped Admin API
token into a password field, and the shared client sends it only as
`Authorization: Bearer` with `credentials: omit`. The field is cleared as soon
as it is read and again after the call. Token plaintext is absent from the JSON
body, Zod response types, component state, storage, and rendered detail; the
returned stable token ID, pinned configuration revision, target, cadence, and
cost ceilings are shown for review.

## Browser boundary

All non-GET Admin requests pass through the shared canonical client. Normal
cookie mutations add the session-bound CSRF header. The scheduled self-test
create call instead uses only its transient bearer, explicitly omits cookies,
and adds no CSRF header, preventing ambiguous dual authentication. Zod schemas
are strict and bounded; unknown response fields, including an accidental
secret `value`, fail closed. The production bundle has no database client,
connection string, browser policy evaluator, or browser-storage credential
path.
