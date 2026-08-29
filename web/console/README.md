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
self-tests; and build/schema status. Literal named navigation for identity, AI
configuration, governance, observability, and operations maps to those
canonical workflows. Named configuration areas use dedicated resource editors:
each merges only its canonical slice into a preserved clone of the full active
document, then performs server clone, full-document PATCH, validation, plan,
and optional activation with the successive strong ETags. Focused Cost,
Latency, Errors, and Attestation failures pages use the canonical aggregate
endpoints without aliasing the whole Usage screen. Request selection loads the
exact detail endpoint and renders bounded aggregate/attempt timing, usage,
cost, and provenance; route/HTTP/failure fields remain absent because the v1
API does not expose them. The route simulator can bind its inputs to an exact
active environment revision and feature list and cross-checks the response.
Every mutation uses `/admin/v1/*`; browser code has no database client,
connection string, or local policy evaluator.

## Validation

```bash
pnpm lint
pnpm typecheck
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
