# ADR 0016: Web trust is weaker than native hardware-backed trust

## Context

WebCrypto can create non-exportable keys and risk providers can attest requests, but browser script execution remains user-controlled and can invoke those keys. Native platforms can provide app identity and hardware-backed key evidence with different assurance.

## Decision

Normalize web verification as `web_risk_verified`, never as `app_verified`, `device_verified`, or `strong_device_verified`. Policies must explicitly allow the web level for a feature. Web sessions still use DPoP, origin/hostname/CORS enforcement, short lifetimes, risk verification, revocation and quotas.

## Alternatives

- Treat WebCrypto non-exportability as native hardware assurance: overstates protection against same-origin malicious code.
- Deny all web clients: secure for some products but violates supported platform goals.
- Omit trust levels and use provider booleans: encourages provider-specific and misleading policy.

## Consequences

Cross-platform features may use different policies and limits. Operators see clear diagnostics when a feature requires native trust. Documentation avoids claims that web clients cannot be automated or reverse engineered.

## Security implications

XSS, extensions, compromised dependencies and browser control can use the legitimate key. Sensitive features should require native trust, identity freshness, narrower quotas or explicit step-up. DPoP still mitigates off-device bearer replay.

## Developer-experience implications

Web and native applications can share feature-level APIs, but operators must deliberately allow the web trust level and may assign it different policies or limits. Web SDKs still provide DPoP and risk verification, while diagnostics must say when a feature requires a stronger native trust signal.

## Migration implications

If browser platforms later expose stronger verifiable hardware/application signals, they receive a new normalized level only after threat-model review and compatibility-safe policy semantics.

## Documentation implications

Trust-level references must distinguish `web_risk_verified` from native application and device verification and give explicit policy examples for opting web clients in. Security guidance must cover XSS, extensions and controlled browsers and must not describe WebCrypto non-exportability as hardware-backed native assurance.

## Status

Accepted for version 1 on 2026-08-27.
