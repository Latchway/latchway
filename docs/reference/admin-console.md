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
The self-test uses only API-supported Responses, Chat, Embeddings, or Anthropic
Messages targets and never acts as a client application.

The first-run wizard is server-state-backed rather than browser-state-backed.
On reload it reconstructs only non-secret progress from the selected
application/environment, latest configuration revision, and secret metadata.
It never restores a credential value. Repeating application or environment
creation resolves an exact matching slug and immutable scope, including
conflict reconciliation, while a mismatched name or environment kind fails
closed. Applying an unchanged document reuses the latest draft/valid revision,
or the already-active revision, instead of creating another revision.

Client access groups the normally separate identity-provider, attestation-policy,
component-definition, and feature-grant resources. The common path supports an
iOS App Attest root component, an Android Play Integrity root component, or a
Web Firebase App Check root component, with production-aware defaults and an
optional Firebase authentication provider. Usage plans similarly translate
daily request/token/cost ceilings, per-request token ceilings, concurrency,
scope, and an IANA timezone into explicit hard server rules. The user inspector
can now project one feature through the exact active compiled revision and
production policy resolver. It shows the selected plan, algorithm-specific
effective limits, output-token clamps, component decision, and ordered
priority/weight/sticky/fallback/retry route inputs with their sources. This is
a read-only projection: it neither reserves quota nor dispatches upstream.
Normalized claim keys can be named, but claim values and credential material
are excluded.

For the isolated Development workspace, `latchway develop` owns the mock
identity, debug proof material, loopback upstream, seeded configuration, and
one-run Console access. The console detects that active loopback fixture and
offers a one-click, bounded synthetic `habit-assistant` client. The helper is
mounted only by the loopback development process and exercises mock OIDC,
challenge-bound debug attestation, DPoP, policy, quota, routing, mock upstream,
settlement, and durable request storage. The Console separately fetches that
exact request record and verifies its environment, feature, protocol, status,
and physical model before reporting success. One sample may run at a time; a
second invocation fails immediately instead of queuing, and every run has a
30-second server deadline. Operators can still run an
official SDK client and inspect its record. The helper is not production
attestation or physical-device proof, and the normal connection wizard remains
HTTPS-only.

Cost, latency, errors, and attestation failures are separate focused pages over
the canonical bounded analytics endpoints. They deliberately render only the
relevant totals, denominators, distributions, attribution, or provenance; they
are not aliases for the complete Usage page and do not create another
analytics source of truth.

Live operational views use the authenticated `/admin/v1/events` Server-Sent
Events endpoint. The stream carries only closed refresh-topic names for
requests, usage, configuration, audit, self-tests, and health; it never carries
resource IDs, identity data, counts, bodies, credentials, proofs, or provider
errors. A topic hint causes the visible view to reload its canonical bounded
Admin API query. The server sends heartbeats, closes every connection within
one minute, and requires the browser to reauthenticate on reconnect, which also
bounds the effect of administrator-session revocation. Reconnects always
rehydrate canonical state because event IDs are not a durable replay log.

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

The application-user inspector treats blocking, unblocking, forced
reauthentication, and forced app reverification as reviewed tasks. It first
loads an application-wide impact preview with exact bounded counts for active
user/component sessions, refresh credentials, installation families, and
components. The operator must then supply a reason, type the exact user ID, and
acknowledge the immediate effect. The mutation presents the preview's
optimistic impact token; a status or count change produces `409 Conflict` and
requires a new review. Blocking denies future access and revokes active
credentials. Unblocking restores eligibility but never resurrects credentials.
Reauthentication revokes user and component sessions/refresh credentials.
App reverification expires platform trust and refresh credentials while
existing access grants retain only their original bounded expiry. The free-form
reason is not copied into audit metadata; only a reason-present marker is kept.

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
identity, client-trust, client-context, configuration, inspection, policy,
route, quota-rule, quota-reservation, attempt, and settlement timeline plus
short explanations of outcome, fallback, and cost confidence. A
`lifecycle_recovered` terminal stage explicitly identifies a stale authenticated
row closed by the bounded worker after a persistence interruption. Durable decision
rows name the exact configuration revision and bounded policy, limit, and route
provenance where the server had selected them; a post-auth denial remains
visible even when no reservation or attempt exists. The explorer uses the
Admin API's server-side status, feature, user, platform, component, trust,
route, upstream, model, public error, request-ID, time, latency, token, cost,
and start-order filters rather than filtering only the loaded page. It then shows request status,
start/completion/duration, aggregate usage, and ordered
attempt number, route, start/first-byte/first-token/completion timing, upstream,
physical model, public status, optional HTTP status, sanitized failure category,
usage, cost, and independent usage/cost provenance. Failure values are restricted to
the canonical public vocabulary and unknown durable values appear only as
`unknown`. Raw request/response or provider error bodies, provider error text,
internal errors, and identity subjects remain excluded.

From request detail, **Explain recorded configuration** loads the immutable
revision named by the request and validates the durable selected plan,
pre-dispatch route selection, observed attempts, and append-only decision
stages against that historical compiled revision. Historical claim values and
the identity of any user override were not persisted in v1, so the view marks
them unavailable and never substitutes the user's current claims or override.
Legacy requests that predate plan, route, or stage provenance receive the same
explicit unavailable treatment rather than a reconstructed narrative.

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

The Audit log applies exact actor kind/ID, action, resource type/ID,
environment, descriptive source, stable reason code, outcome, and time filters
on the server. Pagination uses the opaque next cursor. Selecting an event loads
the exact detail endpoint and renders its ordered value-free field changes;
the raw disclosure is the same strict redaction-safe document. Console source
is derived from an authenticated browser session. CLI versus API is only a
bounded client claim by an authenticated API token and is not a security fact.

System health combines the unauthenticated liveness/readiness probes with the
authenticated canonical doctor report. Operators can rerun checks, copy the
validated JSON, or download a structurally allowlisted support bundle. The
bundle intentionally excludes credentials, tokens, cookies, proofs, the
master key, evidence bytes, and request/response content.

## Browser boundary

All non-GET Admin requests pass through the shared canonical client. Normal
cookie mutations add the session-bound CSRF header. The scheduled self-test
create call instead uses only its transient bearer, explicitly omits cookies,
and adds no CSRF header, preventing ambiguous dual authentication. Zod schemas
are strict and bounded; unknown response fields, including an accidental
secret `value`, fail closed. The production bundle has no database client,
connection string, browser policy evaluator, or browser-storage credential
path.
