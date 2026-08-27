# Native mobile threats

## Key and installation compromise

iOS uses Secure Enclave when available; Android prefers StrongBox then hardware-backed Keystore. A policy-controlled software fallback is lower assurance and must be reflected in normalized trust signals. The server stores only the public JWK and RFC 7638 thumbprint.

Device compromise can still authorize malicious requests while the key is usable. Short access-token lifetimes, rotating refresh tokens, attestation freshness, application/user/environment revocation, anomaly visibility, and per-installation quotas limit impact; they do not prove a device is uncompromised.

## Attestation binding and replay

App Attest and Play Integrity evidence must cover the SHA-256 hash of the exact canonical `AttestationBinding` bytes issued through a one-time challenge. The server atomically consumes challenges and rejects expiry, binding mismatch, duplicate evidence, invalid counters, stale verdicts, wrong app identity, and trust-root failure. Provider-specific payloads become stable normalized signals before policy evaluation.

App Attest assertion counters must increase. Play Integrity standard-token `requestHash` must match the canonical binding hash and the returned request details must be fresh. A valid application identity is not automatically a verified physical device or licensed account.

## SDK transport behavior

Native SDKs authorize arbitrary application HTTP requests rather than own AI semantics. Session refresh is single-flight. A request may be retried automatically only when the SDK can prove it never reached the upstream; an expired response after dispatch requires an actionable error, not transparent replay. Streaming and non-repeatable bodies receive special handling.

Refresh tokens use platform secure storage, never logs or shared preferences/defaults. Diagnostics reveal capability and recovery guidance without tokens, evidence, raw keys, or provider payloads.

## Residual risks

Rooted/jailbroken devices, application instrumentation, accessibility abuse, compromised identity sessions, stolen unlocked devices, and provider outages remain possible. Policy can require stronger trust for sensitive features and deny software fallback; Latchway cannot restore integrity to a fully compromised endpoint.
