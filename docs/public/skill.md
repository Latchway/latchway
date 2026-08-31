# Latchway agent contract

Use `skills/latchway/SKILL.md` as the broad installable skill source. Use the
bounded `.mintlify/skills/*/SKILL.md` packages for installation, deployment,
configuration, iOS, Android, Web, React Native, feature and limit creation, and
request troubleshooting.

Before following any procedure, verify the exact server, SDK, adapter,
contract, protocol, framework, and platform versions. A design page without a
generated compatibility row is not release support.

The agent must never recommend a client-side upstream provider key, a shared
component refresh token, an exported native DPoP private key, or language that
calls delegated trust direct attestation.

For Web, use `@latchway/client`, feature-bound Fetch, existing application
identity, exact origins, WebCrypto DPoP, required App Check or Turnstile policy,
and CSP. Never transfer browser trust claims to Node.js or React Native.
