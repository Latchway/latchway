# ADR 0035: Shared native app sessions

Status: accepted for implementation; not released.

## Decision

One native host app registry owns configuration and account-bound root sessions.
Swift/Kotlin and embedded React Native are callers of that backend, not separate
root security identities. Equivalent configuration retrieves the same backend;
conflicting configuration fails without replacing its identity authority.
Configuration does not authenticate or reactivate a logged-out account.

Wire protocol 3 adds SDK kind `native` for this shared native backend and requires
`X-Latchway-Caller: ios|android|react-native`. The installation platform remains
the attested host `ios` or `android`. Per-request caller and framework declarations
describe attribution; they do not prove identity, attestation or trust. Every
request still requires its own RFC 9449 DPoP proof. Shared clients do not send a
legacy native SDK declaration to disguise a React Native caller.

The required host attestation selection explicitly lists `sharedNativeCallers`.
An empty/missing list disables the new SDK kind. Existing runtime-specific
policies retain their behavior; enabling a list is an explicit operator decision
to use that host policy for those callers, never an inferred union of policies.
Only iOS/Android required root selections support this option. Shared root tokens
cannot be used as delegated component credentials. Existing family/feature and
identity/key binding checks remain authoritative.

Independently authorized delegated components on the same iOS/Android host may
also use protocol 3 with their truthful caller. They use component-local keys,
grants and sessions. The configured component platform must match the actual
parent installation platform, with the host caller allowlist checked before
grant consumption, refresh rotation or access-proof acceptance. This does not
convert remote watch or legacy runtime-specific definitions into shared-host
components. A local lifecycle marker contains opaque account/generation scope,
not root credentials or Firebase tokens.

Protocols 1 and 2 remain supported with their original declaration rules and
response versions. Protocol 3 is required for SDK `native`; older servers reject
it before shared establishment. No silent legacy fallback is permitted. New
clients use fresh versioned account-scoped storage; legacy native/RN refresh
chains and keys are not merged or reassigned to another principal.

Logout is local, offline-safe retirement of a captured account generation. It
does not sign out Firebase, revoke remote installations or reset quotas. Durable
retirement precedes credential cleanup; late callbacks cannot publish into an
old generation. SDK-owned requests are cancelled; disposal of one consumer does
not dispose shared state. The registry survives logout, but account-bound client
handles do not follow new logins. Components retain distinct keys and grants and
participate through authorized durable lifecycle markers, not shared root tokens.

## Consequences

The server contract and SDKs must ship together with an explicit compatibility
matrix. App Attest/Play Integrity still attest the native host. No database key or
installation-platform rewrite is required by the new declaration itself. Caller
policy must be checked before any protected mutation, including refresh and
revocation, not just data-plane dispatch. Public docs and SDK contract fixtures
must identify this as an unreleased capability until conformance is complete.
