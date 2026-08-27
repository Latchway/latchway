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

## Validation

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm verify:reproducible
```

Tests mock only the HTTP boundary and verify the exact canonical endpoint
paths. Zod validates all server payloads before UI code consumes them.

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
