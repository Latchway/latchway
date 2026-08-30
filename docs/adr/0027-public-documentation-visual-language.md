# ADR 0027: Use a canonical public documentation visual language

## Context

Security boundaries, session sequences, quota lifecycle, routing, and
Installation Family delegation are easier to misunderstand when diagrams use
inconsistent shapes, colors, labels, or duplicated stale topology.

## Decision

Public documentation uses a small, accessible visual system with stable colors,
type, spacing, trust-boundary notation, component naming, and light/dark
behavior. Mermaid is used for maintainable flows, sequences, state, and small
data models. Hand-authored SVG is reserved for canonical architecture and trust
diagrams. Every visual has meaningful text alternatives and a source owner.

## Alternatives

- Let each page invent a style: rejected because the same security concept can
  appear to have different meaning.
- Use screenshots for architecture: rejected because they are inaccessible,
  hard to diff, and poor in dark mode or narrow layouts.

## Security implications

Trust boundaries and evidence provenance must be visually explicit. Diagrams
cannot imply shared keys, direct attestation for delegated components, client-
selected providers, or guarantees stronger than runtime evidence.

## Developer-experience implications

Reusable primitives make diagrams quicker to author and easier to scan across
concept, quickstart, security, and troubleshooting pages.

## Migration implications

Legacy Installation-only and shared-credential diagrams are replaced as the
new runtime lands. Historical diagrams remain labeled with their applicable
contract rather than silently rewritten as evidence of current behavior.

## Documentation implications

The site maintains canonical diagrams for system boundaries, session bootstrap,
protected requests, quota lifecycle, routing, family hierarchy, delegation,
revocation, framework transport, and PostgreSQL-only deployment. Accessibility
and missing-alt checks are required.

## Status

Accepted on 2026-08-30. The design tokens, canonical SVGs, and Mintlify visual
components remain pending.
