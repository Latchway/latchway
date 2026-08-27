# Upstream proxy threats

## SSRF and destination control

Opaque routes select only an operator-configured upstream and constrained path policy. Clients never supply an absolute destination. Configuration validation and request-time resolution reject non-HTTP(S) schemes, embedded credentials, fragments, invalid ports, loopback, link-local, private, multicast, unspecified, metadata, and other prohibited IP ranges. Every resolved address must be acceptable. Redirects are disabled by default; an enabled redirect is revalidated as a new destination. DNS rebinding defenses must pin or recheck the dialed address.

## Header and request smuggling

Reject ambiguous framing, conflicting content lengths, malformed transfer encoding, duplicate authorization, oversized fields, invalid header names/values, and unsafe path normalization. Strip inbound `Authorization`, proxy credentials, provider-key headers, cookies unless explicitly required, hop-by-hop headers, forwarding headers not established by the trusted edge, and all internal Latchway context before injection.

## Streaming and retries

Apply route-specific limits for body, headers, connections, first byte, idle, and total duration. Parse SSE incrementally with bounded event and line sizes; do not buffer the response. Do not retry or fall back once any response byte reaches the client. Record each upstream attempt separately while counting the logical request once.

## Response handling

Do not trust upstream usage, cost, content type, headers, or error bodies without protocol validation and size bounds. Strip hop-by-hop and sensitive response headers. Label configured, upstream-reported, calculated, estimated, and unknown usage provenance distinctly. A hard cost limit fails closed when required pricing is unavailable.

## Residual risks

An explicitly configured public upstream receives request content and may log, retain, or misuse it under its own policy. Latchway cannot validate model truth or safety. Operators remain responsible for upstream contracts, data residency, moderation, and account security.
