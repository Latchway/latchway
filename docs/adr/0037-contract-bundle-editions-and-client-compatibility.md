# ADR 0037: Separate immutable bundle editions from client compatibility

Status: Accepted for the next release candidate, 2026-09-08.

## Context

The released 1.1.0 bundle contains both client and Admin contracts. The next
Admin contract adds operational accounting diagnostics and schema-aware route
simulation without changing client requests, responses, error codes, or wire 3.
Rebuilding the 1.1.0 archive with those changes would substitute a different
artifact at a frozen coordinate. Advertising client contract 1.1.1 instead is
also inaccurate: released Android and JavaScript diagnostics parsers require
the supported exact client version, and would reject that metadata. iOS ignores
incompatible remote diagnostics; React Native inherits exact-version checks.

## Decision

Extend ADR 0014 with two explicit coordinates in the protocol manifest:

- `contract_version` identifies the immutable bundle edition and Admin OpenAPI
  version. The new edition is 1.1.1, named `latchway-contract-1.1.1.tar.gz`.
- `client_contract_version` identifies the client OpenAPI and shared client
  error registries. It remains 1.1.0 and is the value advertised by server
  discovery, client diagnostics, and Admin server information. Historical
  manifests without this field use their existing `contract_version` for both.

Client OpenAPI, wire version 3, and configuration schema identity 1.1.0 remain
unchanged. `buildinfo.ContractVersion` continues to mean the advertised client
contract. Validators compare each document with its own coordinate; packaging
and archive hashes use the bundle edition. A distinct bundle is not a new
client capability or permission to ignore exact SDK compatibility checks.

## Release and compatibility consequences

The new source manifest remains an undated draft until the release process
freezes it. Previously published 1.1.0 bundles, hashes, and SDK lock files are
not rewritten. Existing SDKs retain their pinned artifacts; adopting another
bundle requires their normal lock, hash, generated-fixture, and conformance
checks. An unchanged client contract is not a substitute for those checks or
evidence of new SDK/device acceptance.

The current full cross-repository gate still binds every SDK to one exact
bundle. It fails with `split_contract_bundle_requires_pinned_client_baseline`
for split editions until an explicitly retained, hash-pinned client baseline is
supported. This change does not claim a full SDK rebundle/conformance run and
does not bypass existing artifact or copied-fixture checks.

Release tooling and compatibility documentation must distinguish the core
release, bundle edition, client contract, configuration schema, and wire
protocol. Future client contract changes still require the API/version decision
and affected SDK conformance required by ADR 0014 and repository policy.

## Accounting scope

The Admin additions expose optional aggregate input-bound components for new
attempts and preserve absent components for historical rows. They contain no
prompt or schema content. These diagnostics do not change the trusted
byte/framing method, fingerprint, quota enforcement, or claim an exact model
token count. Route simulation now includes the already-enforced expanded-schema
term when supplied; it remains a projection from operator-provided facts.
