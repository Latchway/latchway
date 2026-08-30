# Latchway agent contract

Use `skills/latchway/SKILL.md` as the installable skill source. It helps an
agent deploy and configure Latchway, integrate a client transport, verify the
security boundary, and troubleshoot with redacted diagnostics.

Before following any procedure, verify the exact server, SDK, adapter,
contract, protocol, framework, and platform versions. A design page without a
generated compatibility row is not release support.

The agent must never recommend a client-side upstream provider key, a shared
component refresh token, an exported native DPoP private key, or language that
calls delegated trust direct attestation.
