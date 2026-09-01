# Latchway version 1 master plan

This is the canonical merged implementation plan as of 2026-09-01. It combines
the original A-to-Z plan with the framework-integration, Installation Family,
and Mintlify addendum. A historical version 1 tuple passed local source
convergence. The current core working tree adds Admin-session,
configuration-transfer, Admin event-stream, and lifecycle-concurrency work and
passes its complete local implementation gates, but it is not committed or
reconverged, so it is not yet a clean source candidate. Release promotion also
remains blocked on protected external evidence.

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

## Last clean checkpoint coordinates

| Field | Version 1 source coordinate |
| --- | --- |
| Contract | `1.0.0`, status `draft`, `released_at: null` |
| Contract source checkpoint | Core checkpoint `a59a2c1c807aec50093ae6346492a05148c72899` |
| Bundle SHA-256 | `3a88fb69b911724da849229f34f735608e829bcfb0658087313c8d31441e9927` |
| Wire protocol | Current `2`; supported discovery range `[1, 2]` |
| Clean core implementation checkpoint | `82c9d3663a0532210d6a99ebecaa179f05797115` |
| Canonical SDK-bundle/public-doc checkpoint | `7bdf9cb6da312ea5f4282ae2caf686bcc1122fa3` |
| Database | Schema `27` at the clean implementation checkpoint above |
| Server compatibility | Minimum `1.0.0`; maximum locally tested `1.0.x` |
| JavaScript source | `f9439bdeb56d93218cd63008f7c0f2b2d14821bf` |
| Swift source | `8acd72a7fbbff019ffeb1c7be0264f671c636168` |
| Android source | `349f2effe8f9abe2f07b59fafc47b1bf70b1a1c7` |
| React Native source | `2d78f588671d35512c6d0d244c89ec61e6a48cfa` |
| Mintlify mirror source | `ce4ea1e1cf56404da7146b98ca2744b194050fd5` |
| Release state | `unreleased`; historical local checkpoint only; current exact branch heads are unpushed and the core working tree is dirty |

The historical `0.5.1`/wire-1 bundle remains immutable at its historical
checkpoint. It is not rewritten by this plan.

## Status vocabulary

- **Source complete** means the required implementation and local deterministic
  gates pass for the named source.
- **Converging** means implemented repositories are being bound to the same
  immutable coordinates.
- **External required** means hardware, protected credentials, hosted services,
  registries, or publication are genuinely required.
- **Released** is reserved for protected promotion after every applicable
  external domain binds to one candidate.

## Execution status

### Phase 0: Reconcile architecture and completion policy — historical checkpoint complete

- [x] Reconcile the master, status, compatibility, and completion ledgers.
- [x] Preserve legacy ADRs without number collisions and record ADRs 0017–0034.
- [x] Replace installation-only active architecture with family/component
  terminology and fail-closed release-domain validation.
- [x] Establish the strict framework compatibility registry, schema, generator,
  and adversarial validation.

### Phase 1: Capability decisions — historical checkpoint complete

- [x] Exercise request-time seams for OpenAI JavaScript, Vercel AI SDK,
  LangChain JavaScript, SwiftOpenAI, Apple Foundation Models, MacPaw/OpenAI,
  OkHttp, and React Native native-backed fetch.
- [x] Implement only seams that preserve per-request asynchronous DPoP,
  streaming, cancellation, origin restriction, and placeholder removal.
- [x] Record Foundation Models as planned when runtime execution is unavailable
  and MacPaw/OpenAI 0.5.1 as unsupported when no safe seam exists.
- [x] Implement Swift component-specific Keychain access groups and containing-
  app preparation APIs with unsigned host/extension consumer evidence.

Protected Apple distribution, sibling-denial, background execution, and
candidate-bound root-app App Attest evidence remain external gates, not missing
source. A historical development-signed root-app observation exists. iOS
extensions are delegated-only because Apple's App Attest runtime rejects key
generation from iOS app extensions.

### Phase 2: Contract and schema — historical checkpoint complete; current delta unbound

- [x] Define Installation Family, Client Component, Component Definition,
  delegation, component sessions/refresh/revocation, claims, policy/quota
  dimensions, framework metadata, errors, and vectors.
- [x] Define component App Attest step-up challenge/exchange operations,
  component binding version 2, and composite `delegated_direct_attested`
  provenance without relabeling delegated ancestry.
- [x] Update Client/Admin OpenAPI, configuration JSON Schema, error registry,
  examples, compatibility registry, and deterministic bundle inputs.
- [x] Keep draft contract `1.0.0`, wire 2, and all four canonical fixture
  families deterministic.
- [x] Make cross-repository conformance reject fixture, lock, coordinate, or
  post-freeze `api/**` drift.
- [x] Regenerate the final draft bundle after contract convergence and bind its
  exact checksum and core commit into every SDK lock.
- [ ] Regenerate the draft bundle after the current Admin-session,
  configuration-transfer, server-capability, and Admin event-stream API delta;
  bind the resulting immutable checkpoint into every SDK lock before calling
  the current tree converged.

### Phase 3: Server runtime — historical checkpoint complete

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

### Phase 4: SDK transport primitives — historical checkpoint converged

- [x] Implement feature-bound Swift, Kotlin, JavaScript, and React Native
  transports with wire-2 metadata, origin restrictions, cancellation,
  streaming, refresh single-flight, and replay-safe retry.
- [x] Keep native keys, refresh tokens, and device proofs outside the React
  Native JavaScript bridge.
- [x] Finish the atomic cross-repository commit/lock convergence and run the
  common source gate from clean worktrees for the recorded historical tuple.
- [ ] Repeat commit/lock convergence and the clean source gate for the current
  core contract delta.

### Phase 5: iOS Installation Family SDK — historical checkpoint complete,
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
- [x] Pass Swift package, CocoaPods, Tuist, unsigned extension-host, adapter,
  conformance, and reproducibility gates locally.
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

### Phase 6: Framework adapters — historical checkpoint complete at experimental scope

- [x] Implement and locally test OpenAI JavaScript 7.8.0, Vercel AI SDK 7.0.85,
  LangChain OpenAI 1.5.10, SwiftOpenAI 4.6.0, OkHttp 5.3.0/4.9.2, and React
  Native 0.82.0 integration seams.
- [x] Generate capability and limitation claims from the canonical registry.
- [x] Implement the narrow Foundation Models 27 source adapter and pass its
  nine iOS 27.0 simulator cases while keeping physical framework and delegated
  extension evidence open; keep the unsafe MacPaw seam unsupported.
- [ ] Run hosted common conformance and physical native proof before elevating
  any experimental entry to supported.

### Phase 7: Admin and operator experience — current local gates pass;
convergence open

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
- [x] Pass `make check`, including all Go tests and vet, 343 script tests, 164
  Console Vitest tests, production build, and 34 Playwright tests with one
  explicitly opt-in live-stack case skipped; also pass `make test-race`, the
  bounded fuzz corpus, and real PostgreSQL Admin/session/App Attest/
  configuration/lifecycle lock-order suites.
- [x] Close the reviewed root-challenge and App Attest post-disable insertion
  races, configuration and family/component lock-order deadlocks, and pin
  lifecycle transactions to explicit `READ COMMITTED` semantics.
- [ ] Commit the fully checked delta, regenerate the contract, and reconverge
  all repositories.

### Phase 8: Public documentation — historical checkpoint complete locally;
current synchronization open

- [x] Separate canonical public MDX from maintainer plans and make the external
  docs repository a generated, ownership-checked mirror.
- [x] Generate API/compatibility references and validate snippets, navigation,
  Mermaid, redirects, links/anchors, accessibility, AI-readable outputs, and
  mirror drift.
- [x] Pin Mintlify, Vale, and the MDX parser; enforce product terminology and
  verifiable-language rules.
- [x] Pass the local 127-page Mintlify validation suite.
- [x] Synchronize the final authored pages to the generated mirror and rerun
  the mirror's complete local suite at the recorded historical source coordinate;
  core checkpoint `7bdf9cb6da312ea5f4282ae2caf686bcc1122fa3` and mirror commit
  `ce4ea1e1cf56404da7146b98ca2744b194050fd5` passed.
- [ ] Regenerate and synchronize the current source delta, then rerun the
  canonical and mirror suites from clean exact commits.
- [ ] Deploy the synchronized mirror through the authorized Mintlify GitHub App
  and validate the production URL after the branch merges.

### Phase 9: Operations, supply chain, and final convergence — implementation
exists; current source reconvergence and external execution open

- [x] Implement telemetry, reconciliation/retention jobs, key rotation,
  backup/restore, upgrade/rollback, multi-replica, load/failure, and cloud
  deployment gates.
- [x] Implement multi-architecture image, vulnerability/license scan, SPDX
  SBOM, signing, provenance, exact-candidate receipt, and protected promotion
  workflows.
- [x] Validate the recorded historical source, release workflows, Cloudflare dry-run,
  Compose/Cloud Run/AWS definitions, security scanners, and deterministic builds
  locally for the recorded historical tuple.
- [x] Pass the complete current core implementation gate, race detector,
  bounded fuzz corpus, and real PostgreSQL lifecycle/lock-order suites.
- [ ] Commit the current delta, regenerate all derived contracts and docs,
  synchronize locks, and pass clean cross-repository source conformance.
- [ ] Reauthenticate GitHub CLI and push only the already-authorized audited
  branch histories; do not infer a merge, tag, release, deployment, or
  publication from that push.
- [ ] Build and observe one final immutable multi-architecture image in the
  protected registry and run all external domains against its exact digests.
- [ ] Publish signed tags, GitHub releases, OCI image, packages, and docs only
  after the release finalizer accepts every domain.

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
version string may substitute for protected exact-candidate evidence. The draft
coordinate stays unreleased and no `v1.0.0` tag or public package is authorized
until the finalizer closes every applicable domain without skips or drift.

Offline/local device build, install, and launch may proceed when it does not
contact ngrok or a live provider and does not collect Apple App Attest evidence.
Any scoped ngrok/provider/App Attest device proof requires the exact phrase
`I authorize the scoped ngrok device proof.` That phrase has not been supplied
for the current run. Physical Android verification is intentionally deferred
because no Android device is available.
