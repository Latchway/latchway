# ADR 0019: Do not classify static-header integration as full support

## Context

Some frameworks accept only fixed custom headers. Latchway authorization can
expire, rotate, be revoked, and must include a fresh DPoP proof bound to the
actual request. Static headers cannot preserve those semantics across retries,
streaming, redirects, cancellation, or identity reauthentication.

## Decision

A static-header example is never classified as a supported Latchway framework
integration. Full support requires a request-time asynchronous interception
point that can authorize the final method and URI, propagate cancellation and
streaming, refresh safely, and pass the common framework conformance suite. If
no such hook exists, the registry records the integration as planned,
conditional, or unsupported and documents the limitation.

## Alternatives

- Call any successful demo supported: rejected because it conceals expiry and
  replay failures.
- Fork frameworks without an extension point: rejected because maintaining a
  full fork is disproportionate and obscures upstream compatibility.

## Security implications

The decision prevents stale bearer reuse, DPoP proof reuse, credential leakage
after redirects, and false claims about native key isolation. Placeholder
provider keys are not a substitute for Latchway authorization.

## Developer-experience implications

Developers receive an honest compatibility state and actionable fallback. When
a safe hook is absent, Latchway may prepare a focused upstream contribution
rather than publishing a fragile integration.

## Migration implications

Existing static-header samples may remain only when prominently marked as
unsupported local experiments. They must not appear in the supported matrix or
release claims.

## Documentation implications

Compatibility pages must distinguish supported, experimental, planned,
conditional, and unsupported behavior and explain the missing request-time
capability. Marketing language cannot override registry evidence.

## Status

Accepted on 2026-08-30. No framework is considered supported until the
registry contains tested version bounds and conformance evidence.
