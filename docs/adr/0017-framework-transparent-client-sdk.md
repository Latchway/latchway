# ADR 0017: Keep client SDKs framework-transparent

## Context

Applications already use provider SDKs and AI frameworks whose chat, tool,
message, agent, and model abstractions change independently of Latchway. A
Latchway-owned AI abstraction would duplicate those APIs and force application
rewrites whenever either side evolves.

## Decision

Latchway SDKs provide authenticated, attested HTTP transports and thin
framework adapters. They do not own chat, prompt, tool, agent, message, or model
abstractions. An adapter binds a configured Latchway feature, preserves the
framework's request and response behavior, and delegates request-time
authorization to the platform SDK. Raw transport remains the normative seam.

## Alternatives

- Build a cross-platform Latchway AI framework: rejected because it creates a
  second, fast-changing application API.
- Support only raw HTTP: rejected because small adapters materially improve
  adoption when a framework exposes a safe transport hook.

## Security implications

Thin adapters must not weaken DPoP, origin restrictions, header filtering,
redirect validation, cancellation, replay rules, or native key isolation.
Framework objects and logs must never receive private keys or refresh tokens.

## Developer-experience implications

Developers retain their existing framework and configure a Latchway transport,
provider, executor, interceptor, or fetch function at the supported extension
point. Public SDK APIs remain handwritten and idiomatic.

## Migration implications

ADR 0011 remains the historical foundation and is refined by this decision.
Existing raw HTTP integrations remain valid. Framework-specific modules are
additive and cannot become prerequisites for the base SDK.

## Documentation implications

Every integration guide must start from the framework's native API, identify
the exact injection seam, state unsupported behavior, and link to raw transport
and security guarantees. Documentation must not imply that Latchway owns AI
semantics.

## Status

Accepted on 2026-08-30 and implemented for the exact experimental entries in
the framework registry. Local adapter, streaming, cancellation, package, and
consumer gates pass at the pinned versions; hosted common conformance and
physical native evidence remain release gates.
