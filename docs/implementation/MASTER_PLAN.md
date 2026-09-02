# Latchway version 1 master plan

This is the canonical merged implementation plan as of 2026-09-02. It combines
the original A-to-Z plan with the framework-integration, Installation Family,
Admin Console, and Mintlify addenda. The version 1 API contract is frozen at
the contract checkpoint below; the runtime and control-plane implementation is
the named contract-preserving descendant. The protocol manifest is released,
and every SDK successor is bound to that frozen contract with a final `1.0.0`
changelog. Source/check gates pass; stable release preflights no longer reject
draft metadata, but still require tags and protected evidence. Canonical SDK
documentation bundles are imported into canonical documentation commit
`cd4387fa095556e044945bf6e1e3237d857d912e` and synchronized Mintlify mirror
commit `f37fde259986683f4957627b24d2106b2db81c78`. The current local tuple passes
the core, SDK, package, and documentation gates recorded below. The
six-repository release-control desired state is implemented, including the
docs-only review policy, but has not been applied live because no distinct
reviewer is available. npm uses `auth-and-writes` 2FA; all five npm packages
remain unpublished. The canonical `docs.latchway.dev` custom domain and DNS
are not yet live. Release promotion remains blocked on live controls,
publication, and protected exact-candidate evidence.

## Architectural truth

```text
Application User
└── Installation Family (fam_...)
    ├── Root Client Component (cmp_...)
    │   ├── independent P-256 key and session family
    │   └── direct trust evidence and explicit feature grants
    └── Delegated or composite-trust Client Component (cmp_...)
        ├── independent P-256 key and session family
        └── bounded delegation plus optional component-owned direct evidence
```

Latchway supplies authenticated, attested HTTP transport and thin framework
adapters. It does not own chat, prompt, tool, agent, message, or model
abstractions. Public documentation is a tested product surface whose canonical
source lives in the core monorepo; `latchway-docs` is its generated deployment
mirror.

## Version 1 source coordinates

| Field | Version 1 source coordinate |
| --- | --- |
| Contract | `1.0.0`, status `released`, `released_at: 2026-09-01T20:25:00Z` |
| Contract source checkpoint | Core checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` |
| Bundle SHA-256 | `0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617` |
| Wire protocol | Current `2`; supported discovery range `[1, 2]` |
| Core implementation checkpoint | `cd47229eac32f4a93a0779903d927526b77817d6` |
| Canonical SDK-bundle/public-doc source | `cd4387fa095556e044945bf6e1e3237d857d912e`, a documentation descendant of the core checkpoint |
| Database | Schema `28` at `cd47229eac32f4a93a0779903d927526b77817d6`; schema `27` remains at prior performance checkpoint `77069816dd68174052e7ebc163911883f8f07e7e` |
| Server compatibility | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| JavaScript source | `8baeffa74d0916e3b9299e3a29a6a2dccf154e41` |
| Swift source | `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` |
| Android source | `f847ce600f0a48859ad4cb534b95b6251c3c633e` |
| React Native source | `76fe88ce8053c6983f03422238e9da12360d435d` |
| Mintlify mirror source | `f37fde259986683f4957627b24d2106b2db81c78`, generated from canonical docs `cd4387fa095556e044945bf6e1e3237d857d912e` |
| Product release state | `unpublished` and not release-qualified; no version 1 tag, GitHub release, npm/CocoaPods/Maven package, GHCR image, product-runtime cloud deployment, or protected production-documentation receipt exists |

The historical `0.5.1`/wire-1 bundle remains immutable at its historical
checkpoint. It is not rewritten by this plan.

## Status vocabulary

- **Source complete** means the required implementation and local deterministic
  gates pass for the named source.
- **Converging** means implemented repositories are being bound to the same
  immutable coordinates.
- **External required** means hardware, protected credentials, hosted services,
  registries, or publication are genuinely required.
- **Release-qualified** is reserved for protected promotion after every
  applicable external domain binds to one candidate. A contract manifest with
  status `released` does not by itself publish or qualify the product.

## Execution status

### Phase 0: Reconcile architecture and completion policy — source complete

- [x] Reconcile the master, status, compatibility, and completion ledgers.
- [x] Preserve legacy ADRs without number collisions and record ADRs 0017–0034.
- [x] Replace installation-only active architecture with family/component
  terminology and fail-closed release-domain validation.
- [x] Establish the strict framework compatibility registry, schema, generator,
  and adversarial validation.

### Phase 1: Capability decisions — source complete

- [x] Exercise request-time seams for OpenAI JavaScript, Vercel AI SDK,
  LangChain JavaScript, SwiftOpenAI, Apple Foundation Models, MacPaw/OpenAI,
  OkHttp, and React Native native-backed fetch.
- [x] Implement only seams that preserve per-request asynchronous DPoP,
  streaming, cancellation, origin restriction, and placeholder removal.
- [x] Initially record Foundation Models as planned while runtime execution is
  unavailable, then elevate it to `experimental` after nine simulator public-
  API tests; keep MacPaw/OpenAI 0.5.1 `unsupported` until its safe seam is
  available in a released upstream version.
- [x] Implement Swift component-specific Keychain access groups and containing-
  app preparation APIs with unsigned host/extension consumer evidence.

Protected Apple distribution, sibling-denial, background execution, and
candidate-bound root-app App Attest evidence remain external gates, not missing
source. A historical development-signed root-app observation exists. iOS
extensions are delegated-only because Apple's App Attest runtime rejects key
generation from iOS app extensions.

### Phase 2: Contract and schema — source complete and bound

- [x] Define Installation Family, Client Component, Component Definition,
  delegation, component sessions/refresh/revocation, claims, policy/quota
  dimensions, framework metadata, errors, and vectors.
- [x] Define component App Attest step-up challenge/exchange operations,
  component binding version 2, and composite `delegated_direct_attested`
  provenance without relabeling delegated ancestry.
- [x] Update Client/Admin OpenAPI, configuration JSON Schema, error registry,
  examples, compatibility registry, and deterministic bundle inputs.
- [x] Freeze released contract `1.0.0`, wire 2, and all four canonical fixture
  families deterministically.
- [x] Make cross-repository conformance reject fixture, lock, coordinate, or
  post-freeze `api/**` drift.
- [x] Regenerate the final released bundle after contract convergence and bind
  its exact checksum and core commit into every SDK successor lock.
- [x] Regenerate the released bundle twice after the final contract/runtime,
  release-control, and compatibility delta; bind byte-identical SHA-256
  `0d8eed1d275a2a3783e3d8ba1d8d62ab850faa8dc071a647d777317df8c3e617`
  and checkpoint `cd47229eac32f4a93a0779903d927526b77817d6` into every SDK successor lock.

### Phase 3: Server runtime — source complete

- [x] Implement families, definitions, components, keys, delegations,
  independent session/refresh families, and encrypted rotation-result storage.
- [x] Migrate legacy installations transactionally to a family/root component
  while preserving request, usage, session, key, and audit attribution.
- [x] Implement bounded provenance/effective trust, independent and cascading
  revocation, key replacement, and 30-second exact-tuple refresh idempotency.
- [x] Implement schema-23 component-owned App Attest step-up with one-use
  challenges, binding-version-2 verification, retry-safe assertion handling,
  component-only session rotation, provider binding, key cleanup on
  replacement/revocation, and preserved delegation ancestry; retain it through
  schema 27.
- [x] Persist the exact canonical browser Origin on every schema-25 session
  challenge and require the exchange to present that same Origin. The migration
  invalidates only preexisting ephemeral challenge rows because they have no
  trustworthy origin value to backfill.
- [x] Select root Component Definitions from the unique required attestation
  selection: exact App Attest bundle, exact Play package, or exact persisted web
  Origin. Multiple roots are accepted only when disjoint, directly attested web
  origin sets partition every allowed Origin exactly once; debug or otherwise
  identifier-free roots remain singular.
- [x] Keep the frozen configuration contract unchanged: explicit root
  `identity_only` remains schema-reserved for compatibility but fails semantic
  and compiled-snapshot validation in version 1.
- [x] Make policy, production input/total quotas, requests, usage, telemetry,
  retention, and audit component-aware.
- [x] Pass complete unit, PostgreSQL integration, migration, race, replay,
  multi-replica, and browser-backed first-run tests locally.

The direct-step-up configuration deliberately references a component-only App
Attest policy in `preferred` mode so it cannot satisfy initial delegated-session
eligibility. The explicit step-up endpoint nevertheless requires valid direct
evidence and fails closed on component, bundle, key, DPoP, provider, family, or
parent mismatch.

### Phase 4: SDK transport primitives — current local checkpoint converged

- [x] Implement feature-bound Swift, Kotlin, JavaScript, and React Native
  transports with wire-2 metadata, origin restrictions, cancellation,
  streaming, refresh single-flight, and replay-safe retry.
- [x] Keep native keys, refresh tokens, and device proofs outside the React
  Native JavaScript bridge.
- [x] Finish the atomic cross-repository commit/lock convergence and run the
  common source gate from clean worktrees for the current tuple.
- [x] Repeat commit/lock convergence and the clean source gate for the current
  core contract delta.
- [x] Bind the final SDK source tuple: JavaScript
  `8baeffa74d0916e3b9299e3a29a6a2dccf154e41`, Swift
  `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f`, Android
  `f847ce600f0a48859ad4cb534b95b6251c3c633e`, and React Native
  `76fe88ce8053c6983f03422238e9da12360d435d`.

### Phase 5: iOS Installation Family SDK — source complete,
external proof open

- [x] Implement `LatchwayAppExtensions`, component preparation, component-local
  Keychain storage, session restore/sign-out, diagnostics, and host/widget/share
  consumer projects.
- [x] Implement delegated-only Widget/Share/Action/SSO extension sessions in
  Swift and React Native iOS without passing a root credential or native proof
  through the React Native JavaScript bridge.
- [x] Require a fully resolved private root Keychain access group in the Swift
  and React Native iOS root clients, prove that it is the signed default with a
  disposable sentinel, and scan every explicit extension-shared group only at
  known legacy root-record coordinates. Stale shared-first root state fails
  closed and requires an explicit migration.
- [x] Include a Debug-only React Native App Intents native integration that
  executes an independently keyed delegated request with an exact-run
  Keychain challenge/receipt, while keeping the Release target free of a
  Latchway request path and fail-closed.
- [x] Pass the final Swift package/release gate at
  `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f`: production and debug builds,
  159 core tests, SwiftOpenAI 7/7, Foundation Models 9/9, and CocoaPods lint for
  AppAttest, AppExtensions, Core, and FirebaseAuth.
- [x] Build the React Native example for the connected physical iPad with
  automatic Apple Development signing; strictly verify the root and App
  Intents identifiers, provisioning, App Attest and Keychain entitlements,
  embedded extension, team, and registered device; then install and launch
  bundle `dev.latchway`. This is local execution evidence only and does not
  collect App Attest proof or invoke the delegated App Intent.
- [ ] Capture protected physical root-app App Attest and
  containing-app/widget/share/action isolation, App Intents signed-binary and
  entitlement isolation, component identity and sibling denial,
  no-host/background/termination/no-user-presence behavior, and signing
  evidence for the exact candidate. The Debug App Intent must be physically
  invoked before it counts as development execution evidence; the Release
  fixture must continue to fail closed without a Latchway request path.

The server contract retains generic direct-component routes and can represent
an eligible watchOS component, but the current Swift package does not claim a
watch direct-step-up client API. Apple rejects App Attest key generation in
iOS app extensions, so no Action/SSO direct-step-up claim exists in version 1.
Android direct component step-up is also unsupported; Play Integrity continues
to apply to supported Android application trust surfaces.

### Phase 6: Framework adapters — source complete at experimental scope

- [x] Implement and locally test OpenAI JavaScript 7.8.0, Vercel AI SDK 7.0.85,
  LangChain OpenAI 1.5.10, SwiftOpenAI 4.6.0, OkHttp 5.3.0/4.9.2, and React
  Native 0.82.0 integration seams.
- [x] Generate capability and limitation claims from the canonical registry.
- [x] Implement the narrow Foundation Models 27 source adapter and pass its
  nine iOS 27.0 simulator cases while keeping physical framework and delegated
  extension evidence open. Keep stock MacPaw/OpenAI 0.5.1 unsupported; its
  minimal upstream contribution propagates injected `URLSession`
  configuration to internal streams and passes all 213 upstream tests plus a
  positive custom-`URLProtocol` transport/cancellation probe, but that seam is
  not released upstream.
- [ ] Run hosted common conformance and physical native proof before elevating
  any experimental entry to supported.

### Phase 7: Admin and operator experience — source complete and converged

- [x] Implement family/component list/detail, trust graph, provenance, feature
  grants, session/refresh failures, requests, usage, cost, quotas, and audit.
- [x] Implement scoped revoke, re-attest, renew, and component replacement in
  the canonical Admin API, CLI, dashboard, roles, and audit events.
- [x] Implement the configuration wizard and generated framework compatibility
  reference.
- [x] Pass dashboard lint, typecheck, unit tests, deterministic builds,
  Playwright, and a real PostgreSQL-backed first-run browser test.
- [x] Implement canonical Admin-session inventory and immediate revoke across
  Admin API, CLI, and Console without exposing credentials.
- [x] Implement server-capability negotiation and clear read-only safe mode;
  add bounded redaction-safe YAML/JSON configuration transfer with immutable
  strong-ETag staging, exact JSON/YAML numeric preservation, server
  validation/plan review, and explicit activation.
- [x] Implement authenticated Admin SSE refresh hints with no row data,
  periodic principal revalidation, reconnect behavior, and polling/manual
  fallback when `admin_event_stream` is absent.
- [x] Pass the full current `make check`, including generated-source checks,
  all Go tests and vet, the complete Python release/tool suite, Console
  lint/typecheck/tests, the production build, and Playwright with its live-stack
  case explicitly opt-in; also pass `make test-race`, the bounded fuzz corpus,
  and real PostgreSQL Admin/session/App Attest/configuration/lifecycle
  lock-order suites.
- [x] Pass complete uncached PostgreSQL 15 and PostgreSQL 18
  `go test -count=1 ./...` suites at core checkpoint
  `cd47229eac32f4a93a0779903d927526b77817d6`.
- [x] Close the reviewed root-challenge and App Attest post-disable insertion
  races, configuration and family/component lock-order deadlocks, and pin
  lifecycle transactions to explicit `READ COMMITTED` semantics.
- [x] Commit the fully checked delta, regenerate the contract, and reconverge
  all repositories.

### Phase 8: Public documentation — source complete and preview live; production routing and protected evidence open

- [x] Separate canonical public MDX from maintainer plans and make the external
  docs repository a generated, ownership-checked mirror.
- [x] Generate API/compatibility references and validate snippets, navigation,
  Mermaid, redirects, links/anchors, accessibility, AI-readable outputs, and
  mirror drift.
- [x] Pin Mintlify, Vale, and the MDX parser; enforce product terminology and
  verifiable-language rules.
- [x] Pass the local 228-page Mintlify validation suite.
- [x] Import clean, reproducible documentation bundles from JavaScript
  `8baeffa74d0916e3b9299e3a29a6a2dccf154e41` (SHA-256
  `5c5aec14d562e71842aed6912de21b451a7c70444cbbca4fa70a768066ddcdf4`),
  Swift `ff1ba5c7b4a586019a5cd5e3b158b86c1d2bf98f` (SHA-256
  `a502896f1975d8bf2524cb56e4ed5d8270c5f8862b55f568d56369aa1b74a4a4`),
  Android `f847ce600f0a48859ad4cb534b95b6251c3c633e` (SHA-256
  `a34faf101754c1e9c02253ca132bf21d7ad09e6eec4e57f792e0b451d8d3385b`),
  and React Native `76fe88ce8053c6983f03422238e9da12360d435d`
  (SHA-256
  `38470a5e38e8f7c2b86378145cbc6667c31d4764001f4931d181088a7dcbc10d`).
- [x] Regenerate and synchronize the current canonical source to the generated
  mirror, then rerun both complete local suites from clean exact commits.
- [x] Bind canonical documentation commit
  `cd4387fa095556e044945bf6e1e3237d857d912e` to synchronized Mintlify mirror
  `f37fde259986683f4957627b24d2106b2db81c78` and pass their local validation
  suites.
- [ ] Configure and verify the canonical `docs.latchway.dev` custom domain and
  DNS. Until then, protocol-generated documentation URLs and AI-readable link
  inventories intentionally retain their canonical origin but are not
  publicly resolvable.
- [ ] Seal the protected deployment and post-deploy accessibility, link,
  redirect, source-checkpoint, and AI-output receipt.

### Phase 9: Operations, supply chain, and final convergence — local source
complete; protected execution open

- [x] Implement telemetry, reconciliation/retention jobs, key rotation,
  backup/restore, upgrade/rollback, multi-replica, load/failure, and cloud
  deployment gates.
- [x] Implement multi-architecture image, vulnerability/license scan, SPDX
  SBOM, signing, provenance, exact-candidate receipt, and protected promotion
  workflows.
- [x] Validate the current source, release workflows, Cloudflare dry-run,
  Compose/Cloud Run/AWS definitions, security scanners, and deterministic builds
  locally for the current tuple.
- [x] Pass credential-free 9/9 deployment static validation, Cloudflare type/
  unit/build/dry-run checks, container smoke, strict non-root runtime
  inspection, OCI `linux/amd64` plus `linux/arm64` platform/runtime validation,
  and pinned binary `govulncheck` with zero called vulnerabilities at exact
  implementation checkpoint `77069816dd68174052e7ebc163911883f8f07e7e`.
- [x] Pass the clean local load suite at that checkpoint, including all
  latency, throughput, streaming, memory, and exact-contention targets, plus
  all nine automated failure scenarios under the race detector.
- [x] Pass the complete current core implementation gate, race detector,
  bounded fuzz corpus, and real PostgreSQL lifecycle/lock-order suites.
- [x] Commit the current delta, regenerate all derived contracts and docs,
  synchronize locks, and pass clean cross-repository source conformance.
- [x] Deliver the earlier six-repository converged baseline to `main` by audited
  non-force fast-forward; do not infer a tag, release, runtime deployment, or
  package publication from source delivery.
- [x] Prepare the stable successor source tuple before candidate production:
  create the released contract checkpoint with a fresh `released_at`, promote
  the core binary metadata and changelog to `1.0.0`, regenerate the contract
  bundle, update the JavaScript/iOS/Android locks and final changelogs, update
  the React Native dependency pins and final changelog, rebuild and import all
  SDK documentation bundles, synchronize the Mintlify mirror, and rerun clean
  cross-repository source conformance. The resulting successor tuple is
  contract-released, internally converged, and locally green; it has not yet
  been pushed, tagged, published, or admitted by protected exact-candidate
  evidence.
- [x] Extend the fail-closed release-control desired state to all six
  repositories and 51 environments. Require CODEOWNERS review, one approval,
  and a written docs-not-required check only for `latchway-docs`; retain the
  zero-source-review policy for product repositories. npm account 2FA is now
  `auth-and-writes`, but the five package coordinates remain unpublished.
- [ ] Audit and non-force push the exact final local tuple, then regenerate the
  clean six-repository source-conformance report from the pushed commits.
- [ ] Build and observe one final immutable multi-architecture image in the
  protected registry and run all external domains against its exact digests.
- [ ] Produce the protected prepublication promotion record, then publish the
  immutable product tag, GHCR image, SDK packages, and their GitHub releases
  while the completion record remains `release_ready: false`.
- [ ] Run clean public-consumer and registry conformance, close every domain in
  the post-publication finalizer, and only then publish final completion
  evidence and release-qualified documentation claims.

## Version 1 Definition of Done

Source implementation is complete when the clean cross-repository source gate
passes on synchronized commits. Version 1 is released only when the same
candidate also has protected evidence for:

1. physical root-app App Attest, Play Integrity, browser App Check/Turnstile
   where configured, and delegated app-extension/component isolation;
2. live providers and every advertised protocol/framework/version bound;
3. every claimed cloud, multi-replica, load, failure, backup/restore, upgrade,
   rollback, key-rotation, and worker-recovery path;
4. per-architecture scans, license policy, SBOMs, signatures, provenance, and
   independent security review;
5. tags, releases, registries, package publication, clean public consumers,
   production Mintlify deployment, and post-publication conformance.

## Promotion rule

No source edit, local test, manually written receipt, prior-candidate result, or
version string may substitute for protected exact-candidate evidence. The
prepublication promotion record must accept every gate that can be evaluated
before registry mutation before an immutable `v1.0.0` product tag, GHCR image,
or SDK package is published. Those artifacts are publicly published but are not
release-qualified, and the completion record remains `release_ready: false`,
while clean public consumers and registry bytes are verified. Only the
post-publication finalizer may close every domain and authorize final evidence
plus release-qualified claims.

Offline/local device build, install, and launch may proceed when it does not
contact ngrok or a live provider and does not collect Apple App Attest evidence.
The operator supplied the scoped ngrok authorization, but no tunnel, service,
provider, App Attest, or protected-device evidence was started or collected
under that authorization. App Intent/extension invocation and physical
Android/Google Play evidence are explicitly deferred for later operator
submission. Apple distribution-derived proof remains open but was not
explicitly deferred; none of these gates may be inferred from local builds or
earlier observations.
