# ADR 0002: Go for the core binary

## Context

The server must perform low-overhead HTTP proxying, incremental SSE streaming, cryptographic verification, PostgreSQL transactions, workers, CLI commands, observability and static deployment in one image.

## Decision

Implement the server, workers, CLI and verification tools in the current stable Go release selected in Phase 2. Pin the exact toolchain in `go.mod`, a developer tool file, Docker build and CI. Keep domain packages independent from HTTP and database adapters. Build dashboard assets separately and embed them into the Go binary.

## Alternatives

- TypeScript/Node for all components: good dashboard sharing, but a larger production runtime and different streaming/concurrency profile.
- Rust: strong safety and performance, but greater implementation cost for the selected team and ecosystem.
- Multiple languages/services: isolates concerns but violates the simple single-image operational target.

## Consequences

Go API design, context propagation, explicit error handling, bounded goroutines and race testing become mandatory. Frontend and contract generation remain separate build steps.

## Security implications

Static compilation reduces runtime surface, but memory/resource exhaustion, parser flaws and concurrency races remain. Cryptography uses maintained implementations and strict algorithm allowlists rather than custom primitives.

## Developer-experience implications

Core contributors use the repository-pinned Go toolchain and keep domain logic independent of HTTP and database adapters. Context propagation, bounded concurrency, explicit errors and race-tested changes are part of the normal contribution workflow, while dashboard asset generation remains a separate frontend step.

## Migration implications

Changing the core language would require a new ADR and conformance-equivalent replacement, not an incremental package migration. Wire contracts remain language-neutral.

## Documentation implications

Contributor and build documentation must name the pinned Go version, the separate dashboard build prerequisite and the package-boundary conventions. Operator instructions should describe the produced binary or image and must not suggest that a Go toolchain is needed at runtime.

## Status

Accepted for version 1 on 2026-08-27.
