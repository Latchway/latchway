# ADR 0010: Separate protocol adapters from upstream transports

## Context

OpenAI, Anthropic and opaque HTTP shapes define request rewriting, streaming and usage extraction, while deployment targets define base URL, credentials, timeouts and destination policy. Combining both multiplies implementations and bugs.

## Decision

Protocol adapters own input validation, model/output rewriting, response/SSE interpretation, usage extraction and normalized errors. Upstream transports own configured destination, authentication injection, headers, connection behavior and SSRF enforcement. Routing composes a compatible adapter with an upstream/model target.

## Alternatives

- One adapter per provider: duplicates compatible protocols and couples parsing to credentials.
- Blind reverse proxy: cannot safely clamp output or meter protocol usage.
- Convert every request to a proprietary format: breaks existing libraries.

## Consequences

Capability validation rejects incompatible route combinations before activation. Shared proxy code handles streaming lifecycle while adapters inspect bounded frames.

## Security implications

Protocol parsing never chooses an arbitrary destination, and transport code never trusts client provider headers. Opaque HTTP has stricter explicit path/header/body restrictions and cannot expose arbitrary URLs.

## Migration implications

New protocols and upstreams can be added independently behind conformance interfaces. Behavioral changes update protocol vectors and may require a compatibility revision without changing unrelated targets.

## Status

Accepted for version 1 on 2026-08-27.
