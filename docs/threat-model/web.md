# Web client threats

Browser code runs in a user-controlled environment. WebCrypto can make a P-256 key non-exportable through its API and IndexedDB can persist it, but script execution in the same origin may still invoke the key. XSS, malicious extensions, compromised dependencies, developer tools, browser profiles, and automation weaken possession guarantees.

## Controls

- Bind sessions to a WebCrypto public-key thumbprint and verify RFC 9449 proof on every protected request.
- Enforce configured `Origin`, allowed hostname, CORS method/header rules, and credentials policy.
- Treat Turnstile or Firebase App Check as risk signals, not equivalent to Secure Enclave, StrongBox, or native app identity.
- Use short sessions, rotating refresh tokens, replay detection, feature-specific limits, anomaly telemetry, and revocation.
- Require CSP, dependency integrity practices, secure application authentication, and XSS prevention in the integrating application.
- Do not store upstream provider credentials or accept them from browser requests.

## Policy representation

Normalized trust levels distinguish `web_risk_verified` from `app_verified`, `device_verified`, and `strong_device_verified`. Policies that accept web clients must opt into that lower assurance. Server defaults must not silently upgrade web risk evidence to native trust.

## Residual risks

A malicious user who controls the browser can call authorized features at the user's permitted rate. DPoP prevents simple bearer-token reuse on another key, but does not prevent same-origin malicious code from asking the legitimate key to sign. High-risk features should require stronger identity freshness, narrower quotas, step-up signals, or a native client.
