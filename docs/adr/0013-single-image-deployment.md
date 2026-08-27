# ADR 0013: Single image with selectable roles

## Context

Self-hosters need a simple quickstart, while larger deployments need independent API and worker scaling. Separate service images create version skew and operational complexity.

## Decision

Ship one multi-architecture OCI image containing one Go binary, embedded dashboard, migrations, CA certificates and notices. The binary runs `serve --role all`, `api`, or `worker`, and exposes migration/doctor/verification commands. PostgreSQL is the only required external service. The minimal non-root production image contains no Node, Go toolchain, source tree or package caches.

## Alternatives

- Separate API, worker and dashboard images: independent scaling but drift and more deployment coordination.
- Runtime Node dashboard server: additional process and attack surface.
- Platform-specific binaries: harms portability and conformance.

## Consequences

Build ordering embeds immutable web assets; API and workers share exact schema and contract versions. Compose can run `all`; cloud deployments may split roles using the same digest.

## Security implications

Run non-root with read-only filesystem where possible, minimal packages, SBOM and vulnerability scan. Development skills and build credentials must not enter the final layers.

## Migration implications

Rolling upgrades coordinate application compatibility and forward-only migrations. A future image split requires digest/version compatibility proof and an ADR.

## Status

Accepted for version 1 on 2026-08-27.
