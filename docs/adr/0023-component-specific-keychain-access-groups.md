# ADR 0023: Isolate Apple component keys with specific Keychain access groups

## Context

Apple application extensions may share selected Keychain groups with a
containing app, but a broad shared credential lets sibling extensions
impersonate one another. Extensions also have background-execution and access-
group failure modes that simulators cannot fully prove.

## Decision

The containing application creates or provisions each component's non-
exportable P-256 key into a component-specific Keychain access group. An
extension can retrieve only its configured key; sibling groups remain
inaccessible. The root key and refresh token are never copied into an extension
or across the React Native JavaScript bridge. Capability detection and errors
fail closed when entitlements or containing-app setup are missing.

## Alternatives

- One shared access group for all Latchway state: rejected because it erases
  sibling isolation.
- Export keys for application-managed transfer: rejected because private key
  export expands compromise and logging risk.

## Security implications

Entitlements and access groups become part of the component isolation boundary.
Physical-device tests must prove containing-app creation, intended extension
retrieval, sibling denial, replacement, deletion, and background access.

## Developer-experience implications

SDK configuration should derive stable component storage names and return
actionable diagnostics for missing entitlements, unopened containing apps, or
unavailable key material.

## Migration implications

The existing root SDK key remains root-only. Extension support cannot be
declared until new storage namespaces, entitlements, and physical migration
tests exist.

## Documentation implications

iOS guides must provide exact entitlement examples, containing-app setup,
widget/share flows, sign-out behavior, limitations, and recovery steps without
including real team or bundle identifiers.

## Status

Accepted as the target Apple storage model on 2026-08-30. The required physical
iOS spike and component SDK implementation are external and source gates,
respectively, and both remain open.
