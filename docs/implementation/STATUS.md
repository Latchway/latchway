# Implementation status

Status date: 2026-08-30

Latchway is **not source-complete for the merged version 1 plan**. The last
committed server, schema, contracts, SDK locks, Admin surfaces, and release
machinery form a locally validated legacy-installation baseline. The current
working tree combines Phase 0 reconciliation with partial Phase 2/3 family
configuration, migration, ID, token, and root-session work. Framework support,
the complete runtime/Admin surface, and Mintlify public documentation remain
source work.

## Current execution snapshot

| Field | Current value |
| --- | --- |
| Current phase | Merged Phase 0, plan reconciliation |
| Base core commit at reconciliation start | `c54159b227dab758404e154db593a1b866b2ebdb`; Phase 0 edits are an uncommitted working tree until reviewed |
| Current objective | Finish active-document reconciliation while completing the partial family/docs source safely; then run bounded framework/iOS capability spikes before selecting new protocol coordinates |
| Legacy contract | Contract `0.5.1`, status `released`, wire protocol `1`, normative checkpoint `2f5e5e67c824e270431f1232cc6dc2824848e380` |
| Legacy database | Last committed schema `20`; the working tree contains an uncommitted schema-21 family/component migration that is not completion evidence |
| Target contract | New prerelease coordinate not yet selected; Phase 2 must update OpenAPI/schema/errors/vectors/bundle and every SDK lock together |
| Framework compatibility | Canonical planning registry exists; all seven Tier 1 entries are `planned`, with no minimum/latest support claim |
| Contract compatibility | Current configuration-schema edits change the `0.5.1` bundle inputs without a coordinate/lock update; the working tree is intentionally incompatible until Phase 2 selects a prerelease coordinate and regenerates every lock |
| Release state | Blocked by invalid contract coordinates and missing source phases before external exact-candidate evidence is relevant |

`contract_status: released` describes the historical legacy bundle at its
normative checkpoint. The current working tree no longer reproduces that
contract because addendum schema work has begun. It must not emit or publish a
new archive under `0.5.1`, and old SDK locks cannot validate it. This is not a
claim that the merged product is released.

## Phase status

| Merged phase | Status | Open gate |
| --- | --- | --- |
| 0. Reconcile plan | In progress | Four canonical ledgers, ADRs, numbering, and registry are reconciled; remaining active diagrams, terminology, extension advice, and fail-closed completion validation require audit |
| 1. Capability spikes | Not started | Framework request-time seams and physical iOS component-key/access-group strategy |
| 2. Contract and schema | In progress | Component Definition config draft exists; APIs/errors/policy/quota/framework fields/vectors, prerelease bump, valid bundle, and SDK locks remain open |
| 3. Server runtime | In progress | Initial IDs, schema-21 tables, config snapshots, token/root-session persistence exist; migration proof, provisioning/delegation, refresh, revocation, attribution, audit, and security suite remain open |
| 4. SDK transports | Partial legacy foundation | Feature-bound component-aware transports and new raw conformance |
| 5. iOS family SDK | Not started | `LatchwayAppExtensions`, isolated storage, examples, diagnostics, physical proof |
| 6. Framework adapters | Not started | Adapter implementations, minimum/latest/scheduled CI, common conformance |
| 7. Admin experience | Not started | Family/component Admin API, CLI, dashboard, trust graph/actions, framework metadata |
| 8. Mintlify foundation | In progress | Uncommitted site/config/navigation/content exist; generated references/snippets, install/build/lint/link/a11y evidence, visual system, and CI remain open |
| 9. Public content/convergence | In progress | Initial prerelease audience pages exist; implementation accuracy, generated ownership, complete content, production deploy, and exact-candidate release evidence remain open |

## Implemented legacy baseline

- Generic identity providers, native/web attestation verifiers, RFC 9449 DPoP,
  legacy installation challenge/exchange/refresh, signing keys, replay, and
  installation revocation.
- Canonical configuration revisions, legacy CEL policy, feature-first routing,
  protected upstreams, structured protocols, restricted opaque HTTP,
  deterministic retry/fallback, and reserve-execute-settle quotas.
- Canonical Admin API, CLI, and embedded dashboard for legacy users,
  installations, requests, usage, audit, configuration, secrets, simulation,
  health, and self-tests.
- PostgreSQL schema 20, deployment assets, observability/jobs, all-SDK package
  foundations, legacy conformance fixtures, and release-evidence machinery.

This baseline remains testable and reusable. Partial working-tree family/
component scaffolding does not yet implement the full delegation, independent
component lifecycle, idempotent refresh results, component policy/quota
dimensions, framework headers, Admin surface, or Mintlify target.

## Phase 0 changes in the current working tree

- Canonical ledgers now distinguish legacy implementation, pending source, and
  truly external gates.
- ADRs 0017–0028 record framework transport, Installation Family/component,
  refresh, Apple storage, Mintlify, snippet, visual, and registry decisions with
  all required sections.
- Former ADRs 0017–0022 are preserved as 0029–0034; legacy refresh ADR 0032 is
  explicitly superseded by target ADR 0024.
- `compatibility/frameworks.yaml` is validated by a strict JSON Schema and
  semantic validator; its public compatibility page is generated deterministically.
- The registry was intentionally not added to the contract-bundle source list.
  Concurrent component configuration-schema edits have nevertheless invalidated
  the old `0.5.1` archive digest and SDK locks in this working tree. No bundle
  from this tree is eligible until the Phase 2 prerelease bump and synchronized
  locks.

## Missing source gates

The following are repository work and cannot be labeled external blockers:

1. Remaining Phase 0 active-document and completion-validator reconciliation.
2. Framework and iOS capability spike projects and decisions.
3. Complete the partial family/component contract work with APIs, errors,
   claims, policy, quota, headers, vectors, and a protocol-coordinate update.
4. Complete and prove the partial database/runtime implementation, including
   legacy migration, provisioning/delegation, encrypted 30-second refresh
   rotation results, and the complete security/race suite.
5. Component-aware SDKs, framework adapters, conformance/version CI, Admin API,
   CLI, dashboard, audit, usage, and compatibility UI/reference.
6. Complete and validate the partial Mintlify foundation, generated/tested
   snippets and API/compatibility references, canonical diagrams, public
   content, and documentation quality gates.

## External-required gates

These gates remain external only after their source preconditions exist:

- physical iOS containing-app/component Keychain provisioning, widget/share
  execution, sibling denial, background refresh, and App Attest;
- Play-distributed Play Integrity and physical React Native iOS/Android flows;
- exact-image live provider and all-SDK/framework conformance;
- claimed-cloud smokes and protected multi-replica/load/destructive resilience;
- candidate-bound independent security reviews, scans, SBOMs, signatures, and
  provenance;
- public tags/releases/OCI/npm/Swift/CocoaPods/Maven publication and clean
  consumer verification.

## Next executable work

Complete the remaining active-document terminology/diagram audit without
changing the frozen contract, then perform the bounded Phase 1 framework and
physical iOS spikes. Only their recorded results may shape the Phase 2
prerelease contract and component provisioning design.
