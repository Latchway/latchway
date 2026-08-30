# Latchway version 1 master plan

This is the canonical merged implementation plan as of 2026-08-30. It combines
the original A-to-Z plan with the framework integration, Installation Family,
and Mintlify addendum. The addendum supersedes legacy assumptions where they
conflict; passing work from the original plan remains reusable evidence but is
not proof that the superseding version 1 architecture is complete.

## Current architectural truth

The version 1 target is:

```text
Application User
└── Installation Family (fam_...)
    ├── Root Client Component (cmp_...)
    │   ├── independent P-256 key
    │   ├── direct trust evidence
    │   └── independent session family
    └── Delegated or directly attested Client Component (cmp_...)
        ├── independent P-256 key
        ├── explicit trust provenance and feature grants
        └── independent session family
```

Latchway supplies authenticated, attested HTTP transport and thin framework
adapters. It does not own chat, prompt, tool, agent, message, or model
abstractions. Public documentation is a tested product surface built with
Mintlify from the core monorepo.

The last committed executable baseline implements the legacy `Application User
→ Installation → Session` model. The current uncommitted working tree contains
initial component-definition, ID, migration, token, and root-session work, but
not a complete or releasable family/component implementation. Contract `0.5.1`,
wire protocol `1`, database schema `20`, its SDK locks, and prior load/release
evidence describe the legacy baseline. Current contract-schema edits invalidate
that freeze in the working tree until a deliberate prerelease coordinate and
regenerated SDK locks replace it. Neither state is completion evidence for this
plan.

## Status vocabulary

- **Complete** means source and required local tests satisfy the merged target.
- **Partial** means reusable legacy work exists but the merged target is open.
- **Not started** means the required target source is absent.
- **External required** is reserved for hardware, credentials, hosted services,
  or protected exact-candidate observations that cannot be produced in source.
- **Historical evidence** remains auditable but cannot close a changed gate.

## Original-plan baseline retained

| Original phases | Reusable result | Merged-plan classification |
| --- | --- | --- |
| 0–6 | Repository foundation, contracts, PostgreSQL domain, configuration, identity, attestation, DPoP, and legacy sessions | Historical legacy baseline; family/component contract and runtime supersede installation-only assumptions |
| 7–9 | Data plane, reserve-execute-settle quotas, structured protocols, protected opaque HTTP, deterministic routing, retry, and accounting | Reusable, but request attribution, policy context, quota scopes, refresh, and revocation must become component-aware |
| 10–13 | Swift, Android, JavaScript, and React Native SDK foundations | Reusable transport/package work; framework seams, component sessions, and physical extension isolation remain open |
| 14–18 | Admin API/CLI/dashboard, operations, deployment, conformance, security, load, and release-evidence machinery | Reusable machinery; family/component/operator surfaces and new security gates are missing |
| 19 | Markdown documentation and release automation | Historical baseline only; Mintlify site/content gates and the merged Definition of Done are open |

ADR numbers 0017–0028 are reserved for the addendum decisions. The six legacy
decisions formerly using 0017–0022 are preserved as ADRs 0029–0034. ADR 0032
records current legacy refresh behavior and is superseded by ADR 0024 for the
Installation Family target.

## Merged execution plan

### Phase 0: Reconcile the plan — in progress

- [x] Replace source-complete claims in the canonical master, status,
  compatibility, and completion ledgers.
- [x] Record the framework-transparent transport and documentation-as-product
  principles.
- [x] Add ADRs 0017–0028 with collision-safe preservation of old decisions.
- [x] Establish `compatibility/frameworks.yaml`, its strict schema, offline
  validator, deterministic generated table, and focused tests.
- [ ] Audit every active architecture, threat-model, guide, and reference page;
  replace installation-only diagrams and shared-extension credential advice or
  label it explicitly legacy.
- [ ] Update the active terminology and Definition-of-Done validators so no
  release path can classify missing addendum source as external-only.

Gate: no active planning document contradicts the merged target, and release
validation fails closed while any source phase below is incomplete.

### Phase 1: Capability spikes — not started

- [ ] Verify request-time integration seams for OpenAI JavaScript, Vercel AI
  SDK, LangChain JavaScript, Apple Foundation Models, MacPaw/OpenAI, Android
  OkHttp reuse, and React Native native-backed fetch.
- [ ] Prove containing-app-created component keys, component-specific Keychain
  access groups, extension retrieval, sibling isolation, background execution,
  and component refresh races.
- [ ] Store decisions and reproducible spike evidence under
  `engineering/spikes/`.

Gate: every Tier 1 framework has a proven safe extension point; physical iOS
key provisioning works or a documented fail-closed fallback is chosen.

### Phase 2: Contract and schema — in progress

- [ ] Define Installation Family, Client Component, Component Definition,
  provisioning, component-session, revocation, claims, errors, policy context,
  quota dimensions, framework headers, and test vectors.
- [ ] Update Client/Admin OpenAPI, canonical configuration JSON Schema, error
  registry, examples, and compatibility manifest bundle entry.
- [ ] Select and publish a new prerelease contract coordinate, regenerate the
  deterministic bundle, and update every SDK lock atomically.

An uncommitted Component Definition configuration draft exists. It has already
changed the contract archive inputs without changing the `0.5.1` coordinate,
so the working-tree bundle and old SDK locks are deliberately invalid until the
remaining contract is designed and the prerelease bump is performed.

Gate: all SDKs validate or generate the new wire types and every example and
vector passes. Historical contract `0.5.1` remains byte-frozen at its normative
checkpoint; the current working tree is not a valid `0.5.1` source.

### Phase 3: Server runtime model — in progress

- [ ] Add families, definitions, components, keys, delegations, component
  session/refresh families, and encrypted rotation-result persistence.
- [ ] Migrate each legacy installation to one family and root component without
  losing keys, sessions, requests, usage, or audit history.
- [ ] Implement provenance/effective trust, bounded delegation, independent
  revocation, key replacement, and 30-second exact-tuple refresh idempotency.
- [ ] Make policy, quotas, request attribution, telemetry, retention, and audit
  component-aware.
- [ ] Pass the complete component security, replay, race, migration, and
  PostgreSQL multi-replica suites.

The working tree contains initial family/component IDs, schema-21 migration,
configuration snapshot/validation, token claims, and root-session persistence.
This is partial implementation only: provisioning/delegation APIs, complete
refresh, policy/quota/request/audit integration, migration proof, Admin
surfaces, and the security suite remain blocked.

Gate: debug clients can create a root family, delegate two isolated components,
use independent sessions, attribute usage, and revoke component/family scopes
correctly.

### Phase 4: SDK transport primitives — partial legacy foundation

- [ ] Provide feature-bound Swift, Kotlin, JavaScript, and React Native
  transports with framework metadata, origin restrictions, placeholder removal,
  cancellation, streaming, and replay-safe retry.
- [ ] Ensure private keys and refresh tokens remain in platform storage and do
  not cross the React Native JavaScript bridge.
- [ ] Run raw HTTP conformance on every supported platform against the new
  contract.

Gate: the common raw transport suite passes for the same prerelease bundle.

### Phase 5: iOS Installation Family SDK — not started

- [ ] Build `LatchwayAppExtensions`, component preparation, Keychain isolation,
  component-session restore, sign-out, diagnostics, widget/share examples, and
  direct-attestation step-up where supported.
- [ ] Pass physical main-app, widget, and share-extension flows with independent
  keys and session families.

Gate: a physical device proves the intended access and sibling denial for the
same component configuration.

### Phase 6: Framework adapters — not started

Implement and conformance-test in order: OpenAI JavaScript, Vercel AI SDK,
LangChain JavaScript, Apple Foundation Models, MacPaw/OpenAI, Android ecosystem
examples, and React Native compatibility. Static-header examples cannot satisfy
this phase.

Gate: each supported entry has pinned minimum/latest versions and passes the
common authentication, request, framework, and security suites.

### Phase 7: Admin experience — not started

- [ ] Add family list/detail, component hierarchy and trust graph, provenance,
  feature grants, session failures, refresh reuse, usage, cost, and limits.
- [ ] Add component/family revoke, re-attest, renew, and replacement actions to
  the canonical Admin API, CLI, dashboard, roles, and audit event set.
- [ ] Expose framework metadata and a generated compatibility reference.

Gate: an operator can identify the component and framework for a request,
understand its trust, usage, and failure state, and revoke the correct scope.

### Phase 8: Mintlify foundation — in progress

- [ ] Separate public content from maintainer planning and create split
  `docs.json` navigation, MDX foundations, OpenAPI reference generation, and
  dependency-free visual components.
- [ ] Add tested snippet extraction, compatibility generation, Vale, link,
  accessibility, redirect, alt-text, AI-output, and Mintlify validation.
- [ ] Add canonical visual language, Assistant instructions, agent instructions,
  `llms.txt`, and the versioned documentation bundle contract.

An uncommitted `docs/public` foundation now contains Mintlify configuration,
navigation, audience pages, planned integration/family content, assistant/agent
resources, and structure checks. It remains partial until installation,
Mintlify validation, links, accessibility, generated registry/API/snippets,
visual assets, public/internal separation, and CI evidence all pass.

Gate: the Mintlify preview and every offline documentation quality check pass.

### Phase 9: Public content and final convergence — in progress

- [ ] Publish start, concepts, SDK quickstarts, framework integrations,
  Installation Families/extensions, operator/security/reference/contributor
  guides, troubleshooting, glossary, and release notes.
- [ ] Compile every quickstart and generated snippet and verify all claims
  against implementation and compatibility evidence.
- [ ] Run exact-candidate all-SDK/framework/device/provider/cloud/resilience/
  supply-chain/publication gates only after source phases are complete.

Initial public pages exist but are prerelease design content, not verified
support documentation. Compilation, generated-source ownership, implementation
accuracy, navigation completeness, and production deployment remain open.

Gate: a new developer can deploy Latchway and complete an authenticated,
attested, quota-enforced request through a supported SDK/framework, while an
operator can diagnose and revoke the exact family/component.

## Version 1 Definition of Done

Version 1 is incomplete until all of the following are true for one immutable
candidate:

- the Installation Family is the runtime parent; every component has an
  independent key/session family, explicit trust provenance, bounded feature
  delegation, component-aware policy/quota/audit, and proven revocation;
- all required refresh, cross-family, sibling-isolation, delegation, key,
  replacement, policy, quota, audit, and physical extension tests pass;
- every claimed framework integration has a safe request-time seam, pinned
  minimum/latest versions, common conformance, generated compatibility, and
  accurate limitations;
- the Mintlify site builds from core, generated references/snippets do not
  drift, public/internal content is separated, and accessibility, links, prose,
  diagrams, redirects, and AI-readable outputs pass;
- live providers, physical App Attest/Play Integrity and extension flows, cloud
  deployments, protected load/resilience, independent security review,
  per-architecture scans/SBOM/signing/provenance, tags, registries, and clean
  post-publication consumers all bind to that same candidate.

## Promotion rule

Source work is never reclassified as external evidence. Historical legacy
receipts remain useful regression evidence but cannot authorize `v1.0.0` under
the merged target. Promotion stays blocked until Phases 0–9 and every applicable
external gate close without skips, stale receipts, coordinate drift, or
fabricated support claims.
