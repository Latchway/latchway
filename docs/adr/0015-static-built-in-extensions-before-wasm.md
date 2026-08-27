# ADR 0015: Static trusted extensions before WASM

## Context

Identity, attestation, protocol, upstream and pricing integrations need extensibility. Runtime plugins introduce code-loading, sandboxing, compatibility and supply-chain risks before the stable interface is proven.

## Decision

Version 1 defines narrow internal extension interfaces but ships only reviewed, statically compiled implementations. Operator-authored logic is limited to validated configuration and CEL policies. Do not support Go shared objects, JavaScript, shell, SQL, downloaded binaries or WASM extensions in the version-1 critical path.

## Alternatives

- Go plugins: platform/toolchain coupling and unsafe in-process execution.
- WASM sandbox now: promising isolation but significant host API, resource and lifecycle design.
- External webhook adapters: network trust and availability on the authorization path.

## Consequences

Adding an integration requires a core build/release and conformance tests. Interfaces can mature based on actual built-ins before becoming a public plugin ABI.

## Security implications

Static review narrows the runtime attack surface. CEL remains non-Turing-complete, input-bounded and compiled at configuration activation. Built-ins still require dependency and parser hardening.

## Migration implications

A future WASM extension system requires a new ADR covering signed distribution, capability-based host APIs, deterministic resource limits, secret access, observability, compatibility and failure isolation.

## Status

Accepted for version 1 on 2026-08-27.
