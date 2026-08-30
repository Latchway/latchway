# ADR 0028: Make the framework compatibility registry canonical

## Context

Framework APIs and transport hooks change independently of Latchway. A manual
support table can overstate capabilities, omit minimum versions, or drift from
conformance and release notes.

## Decision

`compatibility/frameworks.yaml` is the canonical framework-integration
registry. A strict schema and semantic validator reject unknown fields,
duplicate IDs, invalid capability/security states, unsorted entries, and
support claims without minimum/latest tested versions. Documentation tables are
generated deterministically from the registry. Supported integrations test the
minimum and latest declared versions plus a scheduled newest-compatible probe;
failures open an issue and never widen a range automatically.

## Alternatives

- Maintain tables independently in docs and SDK repositories: rejected because
  they inevitably disagree.
- Advertise compatibility from package dependency ranges: rejected because a
  resolvable dependency is not conformance evidence.

## Security implications

Security capability fields distinguish full, partial, not-tested, and not-
applicable DPoP and native-key isolation. A support state cannot bypass the
common authentication, request, framework, and security suites.

## Developer-experience implications

Developers get one honest table for integration seam, package, tested range,
capabilities, security posture, and limitations. Maintainers update one
reviewable record.

## Migration implications

The Phase 0 registry initially records planned integrations without version or
support claims. It enters the contract bundle only with the Phase 2 prerelease
contract bump and synchronized SDK locks; released contract 0.5.1 remains
byte-frozen in this reconciliation.

## Documentation implications

Public compatibility pages and release-note compatibility sections consume
generated output. Hand-maintained duplicate framework tables are prohibited.
Breaking framework changes are recorded beside the affected registry evidence.

## Consequences

A framework support claim is a generated release artifact backed by an exact
registry row and conformance evidence. Updating support takes more than widening
a dependency constraint, but docs, SDK locks, tests, and release notes cannot
quietly advertise different compatibility states.

## Status

Accepted on 2026-08-30 and implemented in draft contract `1.0.0`. The closed
registry and schema are deterministic bundle members; semantic, adversarial,
generated-page, version-bound adapter, and workflow gates pass locally. Six
entries remain experimental, Foundation Models remains planned, and
MacPaw/OpenAI 0.5.1 remains unsupported until new evidence changes those exact
registry rows.
