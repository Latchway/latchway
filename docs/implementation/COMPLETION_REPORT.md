# Version 1 completion gap ledger

Status: **incomplete; the merged version 1 target is not source-complete and no
final completion report exists**.

This file replaces the prior source-complete claim. It records reusable legacy
evidence, completed Phase 0 reconciliation artifacts, missing source gates, and
future external gates. The immutable post-publication report may be rendered
only for one candidate that satisfies the merged master plan.

## Completion summary

| Workstream | Implemented now | Required before completion | Classification |
| --- | --- | --- | --- |
| Legacy gateway | Identity/attestation verifiers, DPoP, installation sessions, configuration, routing, protocols, quotas, Admin, CLI/dashboard, operations/deployment/release machinery | Preserve as regression foundation while migrating affected semantics | Reusable historical source |
| Framework transport | Raw SDK/HTTP foundations; Android OkHttp groundwork | Safe framework seams, feature-bound transports, framework headers, adapters, common conformance, min/latest/scheduled CI | Missing source |
| Installation Family | Architecture/ADRs plus uncommitted component config, IDs, schema-21 tables, token claims, and root-session scaffolding | Complete contracts, migration proof, provenance/delegation, component sessions/refresh/revocation, policy/quota/audit attribution, SDKs and security tests | Partial source |
| Admin/operator | Flat legacy installation/request views | Family/component API, CLI, dashboard, trust graph, actions, usage/failures, framework metadata | Missing source |
| Compatibility | Canonical planning registry, strict schema/validator, and generated public table | Version pins, conformance evidence, contract-bundle inclusion, and release notes | Partial source |
| Public documentation | Existing maintainer Markdown plus an uncommitted Mintlify site/config/navigation and initial audience content | Complete public/internal split, generated API/registry/snippets, content/diagrams, install/build, accessibility/links/prose/AI outputs | Partial source |
| Release evidence | Historical local legacy receipts | New exact-candidate device/provider/cloud/resilience/security/supply-chain/publication evidence | External after source |

## Phase 0 reconciliation evidence

Completed in the current working tree:

- the master, status, compatibility, and completion ledgers no longer classify
  the addendum as externally blocked or claim source completion;
- ADRs 0017–0028 exist with Context, Decision, Alternatives, Security
  implications, Developer-experience implications, Migration implications,
  Documentation implications, and Status;
- the legacy ADR collision is preserved as 0029–0034, with links updated and
  legacy refresh ADR 0032 explicitly superseded by target ADR 0024;
- `compatibility/frameworks.yaml`, its closed JSON Schema, duplicate-safe
  semantic validator, deterministic generator, and adversarial unit tests exist;
- contract validation checks registry and generated-table drift offline.

Concurrent Phase 2/3 work has begun in the same working tree. It changes a
legacy bundle input before the required prerelease coordinate exists. Therefore
the historical `0.5.1` digest/checkpoint and every old SDK lock are invalid for
this tree; no new bundle digest is a supported coordinate yet.

Still open in Phase 0:

- audit and reconcile all remaining active architecture diagrams, terminology,
  extension credential advice, reference pages, and completion validators;
- ensure release machinery fails closed for every new source domain without
  changing the frozen legacy contract prematurely.

## Legacy evidence retained without overclaiming

| Evidence | Historical coordinate | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Contract | Core `2f5e5e67c824e270431f1232cc6dc2824848e380`, contract `0.5.1`, wire `1` | Deterministic legacy contracts and SDK locks | Family/component/framework contract |
| Database/runtime | Schema `20` and current legacy Go tests | Installation-based behavior remains internally consistent | Family migration, component isolation, idempotent refresh |
| Core load | `73743b1633e4521aeda7ba1228cd18b78ef3a185`; corrected targets recorded by ADR 0034 | Historical local gateway/load behavior | Current addendum source or exact release image |
| JavaScript SDK | `5765a905086bbd39cdfb3d4b5c571a5df0066787` | Legacy package/transport tests | Framework adapter or component session support |
| Swift SDK | `73677929adfc4703e014927e11c28192426d4660` | Legacy package/App Attest source tests | Extension component Keychain isolation or physical proof |
| Android SDK | `f9132d307cdc1b0bc971caeff07d9ab00254a015` | Legacy package/OkHttp source tests | Framework minimum/latest matrix or component contract |
| React Native SDK | `fddd9db30e9678d5edd597784c05f1a10d8584e5` | Legacy native bridge/package tests | Native-backed framework fetch or component isolation |

Historical scan, SBOM, Compose, recovery, failure, and load receipts remain
valid for their named sources. Any changed candidate must reproduce applicable
evidence; none closes an addendum source gate.

## Required source completion evidence

### Installation Family and runtime

- [ ] Complete the partial `fam_`/`cmp_` configuration, persistence, and claim
  work; version APIs, errors, headers, policy fields, quota dimensions, and test
  vectors under a deliberate prerelease coordinate with regenerated SDK locks.
- [ ] Prove legacy rows migrate transactionally to one family/root component with
  preserved keys, sessions, requests, usage, and audit history.
- [ ] Every component has an independent key and session/refresh family.
- [ ] Delegation is configured, feature-scoped, key/parent/evidence-bound,
  single-use, time-bounded, and records explicit provenance/effective trust.
- [ ] Component replacement/revoke and family revoke have correct independent
  and cascading semantics.
- [ ] Refresh duplicates are exact-tuple idempotent for 30 seconds with encrypted
  response storage; mismatches and late reuse fail closed and audit correctly.
- [ ] Component-aware policy, quota, request, usage, telemetry, retention, and
  audit behavior passes normal, PostgreSQL, race, replay, migration, and the
  complete named security suite.

### SDK and frameworks

- [ ] Raw feature-bound component transports pass on Swift, Kotlin, JavaScript,
  and React Native without leaking keys/tokens or attaching credentials to
  another host.
- [ ] Tier 1 capability spikes identify safe request-time asynchronous seams.
- [ ] Supported adapters preserve request bodies, model/limit rewrite,
  streaming, cancellation, tools, structured output, errors, request IDs,
  refresh, fresh proofs, and safe retries.
- [ ] Registry minimum/latest and scheduled compatibility jobs pass; failed
  newest probes open issues and never automatically widen support.
- [ ] All SDK locks bind the same new prerelease contract and manifest.

### Admin and public documentation

- [ ] Canonical Admin API, CLI, and dashboard identify families/components,
  trust chains, feature grants, sessions/failures/reuse, usage/cost/limits,
  framework metadata, and correctly scoped actions/audit events.
- [ ] Mintlify builds from core with public/internal separation, generated
  OpenAPI and registry pages, tested SDK snippets, canonical diagrams,
  troubleshooting, glossary, release notes, `llms.txt`, and agent/assistant
  instructions.
- [ ] Documentation validation, links, accessibility, prose, alt text, redirects,
  snippet drift/compilation, references, and unsupported-claim checks pass.

## External-required completion evidence

After source completion, one immutable candidate still requires:

1. physical iOS root/widget/share component provisioning, independent Keychain
   access, sibling denial, background execution, refresh races, and App Attest;
2. Play-distributed Play Integrity and physical React Native platform flows;
3. all SDKs and supported framework version bounds against the exact image;
4. live provider streaming/non-streaming, usage, error, clamp, and cancellation;
5. exact-image Compose and every claimed cloud platform;
6. protected load, multi-replica, destructive failure, backup/restore, upgrade,
   rollback, and worker recovery;
7. candidate-bound independent security review, per-architecture vulnerability
   and license scans, SBOM, signatures, and provenance;
8. annotated tags, GitHub releases, OCI/npm/Swift/CocoaPods/Maven publication,
   byte verification, and clean public consumers;
9. final Mintlify production deploy and link/accessibility/AI-output validation.

## Completion decision

No current commit is eligible for merged version 1 completion or promotion.
The protected finalizer must remain blocked until every source checkbox and
external gate above binds to one immutable candidate and all repository,
contract, package, image, documentation, and registry coordinates agree.
