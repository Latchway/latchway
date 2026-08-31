# ADR 0025: Build public documentation with Mintlify

## Context

Latchway needs coherent learning paths for application developers, operators,
security reviewers, framework integrators, contributors, and AI assistants.
The current Markdown tree mixes implementation ledgers with prospective public
content and has no validated navigation or public build.

## Decision

The public documentation site lives in the core monorepo and uses Mintlify,
MDX, and a split `docs.json` navigation as it grows. Public content and
maintainer-only planning are separated before publication. The site generates
API reference from the normative OpenAPI documents and treats validation,
accessibility, links, prose, snippets, compatibility, and AI-readable outputs
as release-tested product surfaces.

## Alternatives

- Keep an unstructured Markdown collection: rejected because navigation,
  reference generation, accessibility, and drift are not enforced.
- Use a separate docs repository: rejected because it weakens atomic review of
  contracts, SDK compatibility, and documentation.

## Security implications

The site must not publish secrets, private implementation plans, unsafe debug
defaults, client-side provider credentials, or unsupported security claims.
API playground behavior is explicitly bounded.

## Developer-experience implications

Users get audience-specific quickstarts, concepts, framework and extension
guides, operator workflows, reference, troubleshooting, and versioned release
notes in one searchable site.

## Migration implications

Existing maintainer material under `docs/implementation` remains authoritative
during Phase 0 but must move outside the Mintlify content root before public
publication. No content is silently dropped.

## Documentation implications

Mintlify configuration, public navigation, `llms.txt`, assistant instructions,
redirects, and generated API pages become reviewed source. A preview build is a
Phase 8 gate, not evidence that the content is complete.

## Consequences

Public documentation is reviewed and tested with the product rather than
published as an independent prose artifact. The core repository remains the
source of truth and the deployment repository is generated, so releases must
validate and synchronize both coordinates before deployment.

## Status

Accepted on 2026-08-30. The canonical, committed public source lives under
`docs/public`; the standalone `latchway-docs` repository is a generated
deployment mirror. Navigation, generated compatibility, Admin API, error, and
configuration references, redirects, links, accessibility, AI-readable
outputs, and Mintlify source validation are locally checked. SDK documentation-
bundle consumption, executable-snippet drift checks, production deployment,
and exact-release content remain open gates.
