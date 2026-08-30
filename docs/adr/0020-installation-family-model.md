# ADR 0020: Make Installation Family the runtime client boundary

## Context

A logical application installation can contain independently executing main
applications, widgets, share extensions, background services, and web workers.
The legacy one-installation/one-key/one-session model cannot represent their
separate keys, trust evidence, feature scopes, lifecycle, or usage.

## Decision

The runtime hierarchy is Application User → Installation Family (`fam_`) →
Client Component (`cmp_`). Each family has one root component and zero or more
configured delegated or directly attested components. Every component has its
own key, trust provenance, session family, status, feature grants, and request
attribution. Revoking a component does not revoke siblings; revoking a family
revokes every component.

## Alternatives

- Keep one installation with shared extension credentials: rejected because it
  collapses isolation and revocation boundaries.
- Model each component as an unrelated installation: rejected because it loses
  the logical family, root delegation, and family-wide lifecycle.

## Security implications

Independent component identity limits credential blast radius and makes policy,
quota, audit, and revocation component-aware. Family membership never grants
implicit access to a sibling's key or session.

## Developer-experience implications

Applications configure named component definitions and use the family model for
main app, extension, widget, service, or worker flows. The term is unrelated to
Apple Family Sharing.

## Migration implications

Each legacy installation migrates to one family with one root component. Its
key, attestation, sessions, requests, and usage are moved or backfilled without
inventing delegated trust. The migration must be transactional and tested
before legacy columns are retired.

## Documentation implications

All active architecture diagrams, API concepts, quickstarts, Admin references,
and troubleshooting guides must use the family/component hierarchy and clearly
label legacy installation behavior during migration.

## Status

Accepted as the target runtime model on 2026-08-30. The uncommitted working
tree contains initial schema, ID, claim, and root-session scaffolding, while the
complete API, migration proof, delegation, revocation, attribution, and
security model remain pending.
