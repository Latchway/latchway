# Latchway admin console

The console is a same-origin React application for operating a self-hosted
Latchway gateway. It uses the canonical HTTP boundary: `/healthz`, `/readyz`,
and `/admin/v1/*`. It never connects to PostgreSQL or evaluates policy locally.

## Development

The repository toolchain pins Node 24.19.0 and pnpm 10.15.0. From this
directory:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

Vite proxies are intentionally not configured. Development requests use the
same origin, so run the console behind the Latchway development server or a
local reverse proxy when exercising real endpoints.

## Administrator access

An unauthenticated session check renders sign-in and first-owner setup on the
same page. The console posts only to the canonical same-origin authentication
endpoints and then invalidates and refetches `/admin/v1/auth/session` after a
successful response. Passwords and the one-time bootstrap token remain in
uncontrolled password inputs: they are never placed in React state, query
caches, Web Storage, IndexedDB, URLs, or logs, and are cleared after each failed
attempt. Error UI accepts only validated RFC 9457 problem fields and never
renders an unstructured response body.

The secure, SameSite=Strict administrator cookie persists the browser session.
A separate secure double-submit cookie lets a refreshed tab recover the CSRF
token without making the administrator credential script-readable. Sign out
revokes the server-side session and clears both cookies.

Authenticated routes cover applications and environments; write-only secret
metadata/create/rotate/delete; user override inspect/set/clear; immutable
configuration history and exact-ETag rollback; first-run setup; the complete
schema-backed configuration document; users; installations; request attempts;
usage analytics; audit; the exact production route simulator; bounded
self-tests; and build/schema status. Primary navigation follows operator tasks:
Features, Requests, Users, Usage, setup, client access, and AI connections.
Lower-level resources remain under Configure, Investigate, Operations, and
Advanced. A keyboard command palette (`Command-K` or `Control-K`) searches the
same safe destinations and never executes a destructive action directly.

The application and environment are server-owned workspace context. Both are
visible in the top bar, environment kind is stated in text, production has an
explicit warning badge, and selected slugs persist in the URL across
navigation. A URL naming an unavailable application or environment is blocked
rather than silently falling back. Named configuration areas use dedicated
resource editors:
each merges only its canonical slice into a preserved clone of the full active
document, then performs server clone, full-document PATCH, validation, plan,
and optional activation with the successive strong ETags. Focused Cost,
Latency, Errors, and Attestation failures pages use the canonical aggregate
endpoints without aliasing the whole Usage screen. Request selection loads the
exact detail endpoint and renders bounded aggregate/attempt timing, usage,
cost, provenance, attempt number, route, first-byte time, HTTP status, and the
closed sanitized failure category. Request detail starts with an execution
timeline and plain-language explanations of outcome, fallback, usage, and cost
confidence. Unknown durable failure values collapse to
`unknown`; provider error text and raw internal errors never enter the browser.
The route simulator can bind its inputs to an exact active environment revision
and feature list and cross-checks the response.
Every mutation uses `/admin/v1/*`; browser code has no database client,
connection string, or local policy evaluator.

The Features workspace is the first task-level configuration editor. It reads
the active environment revision, renders access/plan/route summaries, and
provides a bounded wizard for client feature ID, protocol, access preset, plan,
primary/fallback models, verification posture, and output-token defaults. Save
always creates and validates a server draft while preserving the rest of the
full configuration document. Activation is a separate publish action after a
redacted plan and production consequence are visible.

AI connections, Client access, and Limit plans use the same draft-first
contract. The connection flow groups an HTTPS destination, a write-only
server-held credential, a physical model, bounded input-accounting assumptions,
and exact decimal-to-nano-USD pricing into one preserved change. A bounded
upstream self-test is offered only after publish. The client-access flow creates
one production-aware iOS App Attest, Android Play Integrity, or Web Firebase
App Check root component, verification policy, feature grant, and optional
Firebase user-authentication provider. The usage-plan flow turns daily volume,
cost, per-request token, concurrency, scope, and timezone choices into only the
hard rules supported by the configuration schema. All three show the server's
validation and redacted plan before a separate publish action.

In a Development environment, AI connections recognize the loopback mock
configuration owned by `latchway develop`. The console does not create a local
server, mint a client proof, or impersonate an application. It guides the
operator to run the official client sample and then verifies success by reading
the durable `habit-assistant` request record. Guided creation remains HTTPS-only
because ordinary Admin API drafts cannot opt a loopback destination through the
production destination validator.

The top bar inspects the newest revision for the selected environment and links
to Configuration revisions when that revision is draft, valid, or invalid.
History loads directly from the selected workspace. The current Admin API has
no cross-environment draft count and no abandon/delete mutation, so the console
does not invent either behavior: an unpublished revision remains inert and
auditable, and the history page states that it cannot be removed.

The Admin OpenAPI document is compiled into checked-in TypeScript types. Use
`pnpm generate:api` after changing `api/admin.openapi.yaml`; `pnpm check:api`
fails when the generated artifact drifts. Runtime Zod validation remains the
fail-closed boundary for responses consumed by the UI.

## Validation

```bash
pnpm lint
pnpm typecheck
pnpm check:api
pnpm test
pnpm test:e2e
pnpm build
pnpm verify:reproducible
```

The fast component and default Playwright tests mock only the HTTP boundary and
verify the exact canonical endpoint paths. Zod validates all server payloads
before UI code consumes them. The default Playwright gate proves first-run
activation with a strong ETag; application/environment creation; secret
create/rotate and deliberate exact-current-ID deletion; cancellation without a
mutation; write-only form clearing and absence of DOM/Web Storage retention;
user override replacement/clear; fresh-ETag rollback; user blocking; CSRF on
every cookie mutation; and server-side logout in Chromium. It also proves
cancellation and activation of a targeted resource merge, full-document
preservation, the successive draft/activation ETags, focused observability
navigation, exact request detail, and active route-context simulation.
It additionally covers exact task-builder output for AI connections, all three
client-verification platforms, and usage plans; a development mock/sample
verification path; the selected-environment draft indicator; and a complete
connection secret/draft/publish browser workflow.

The release and CI workflows additionally run
`TestConsoleFirstRunAgainstLiveStack` with an isolated PostgreSQL schema. That
gate serves the embedded production bundle from the real Go process and drives
first-owner bootstrap, application/environment creation, encrypted write-only
secret creation, native-mobile configuration validation and activation, logout,
and password login through Chromium. It makes no provider request. Its
bootstrap, owner, and placeholder provider credentials are randomly generated;
browser traces, screenshots, and video are disabled for this credential-bearing
proof, and the schema is dropped after the process drains.

## Embedded build contract

`pnpm build` creates `dist/` with:

- relative asset URLs, allowing the console to be mounted under a server-owned
  prefix;
- content-addressed JavaScript and CSS filenames;
- a Vite `manifest.json`;
- no source maps or local absolute paths; and
- a sorted `SHA256SUMS` covering every shipped asset.

The generated `dist/` directory is versioned so a clean Go checkout always has
the files required by `go:embed`. `pnpm verify:reproducible` performs two clean
Vite builds and requires identical checksums; regenerate the bundle and review
its checksum diff whenever console source changes. The colocated Go `console`
package embeds `all:dist`, including nested hashed assets. The HTTP integration
must provide SPA fallback to `index.html` only for console routes; API paths
must never fall through to the SPA.
