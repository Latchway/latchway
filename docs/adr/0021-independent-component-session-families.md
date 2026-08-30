# ADR 0021: Give every client component an independent session family

## Context

Sharing a DPoP key or refresh chain across an application and its extensions
lets one compromised surface impersonate every sibling and makes targeted
revocation impossible. Independently executing components also refresh under
different scheduling and storage constraints.

## Decision

Every client component owns an independent P-256 component key and component
session family. Access-token, refresh-token, rotation-result, replay, and
revocation records bind to the component ID and JWK thumbprint. Replacing a
component key revokes that component's prior session chains while preserving
historical usage and audit attribution. Family revocation cascades; component
revocation never cascades to siblings.

## Alternatives

- Share the root key and refresh token: rejected because it defeats isolation.
- Share a family refresh chain but issue component access tokens: rejected
  because refresh compromise would still cross component boundaries.

## Security implications

Possession of one component key proves only that component. Cross-component
token, refresh, and proof substitution fail closed. Sign-out and deletion must
erase the correct key material and revoke the intended scope.

## Developer-experience implications

Each executable surface restores and refreshes its own session. SDK diagnostics
must identify missing containing-app setup, inaccessible key storage, revoked
components, and required re-provisioning without exposing tokens.

## Migration implications

Legacy installation session grants become the root component's session family.
SDK state formats need an explicit component identifier and per-component
storage namespace before delegated components are enabled.

## Documentation implications

Platform guides must show component/session ownership, sign-out semantics,
replacement behavior, and why copying the root credential into an extension is
forbidden.

## Status

Accepted on 2026-08-30. Initial component-session persistence exists in the
uncommitted working tree; complete contracts, provisioning, refresh,
replacement, revocation, migration, and adversarial proof remain Phase 2 and
Phase 3 work.
