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

## Consequences

Apple projects need a distinct entitlement and provisioning contract for every
component that reads a Latchway key. Setup is less convenient than one shared
group, but sibling denial becomes enforceable and a compromised extension
cannot retrieve the root or another extension's credential.

## Status

Accepted on 2026-08-30 and implemented in the Swift and React Native iOS source
candidate, including component-specific storage, containing-app preparation,
extension diagnostics, and delegated-only Widget/Share/Action/SSO sessions.
Apple rejects App Attest key generation in iOS app extensions; only the root
application performs App Attest, and it never relabels that evidence as an
extension proof. Unsigned host/extension consumers and local source tests do
not prove real entitlements: candidate-bound physical sibling denial,
no-host/background/termination/no-user-presence behavior, signing, and root-app
App Attest remain release gates.
