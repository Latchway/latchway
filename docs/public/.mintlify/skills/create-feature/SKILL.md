---
name: create-feature
description: Create or revise a client-facing Latchway AI feature with server-owned policy, routes, models, accounting, pricing, and verification. Use for operator configuration, not for client-selected physical models.
---

# Create a feature

## Define the application contract

Choose a stable feature ID and the client-visible capability and protocol it
represents. The client requests this feature only; it must not select a provider,
physical model, credential, price, route, limit plan, or authoritative usage.

Read [Configuration](/administration/configuration),
[Routing and quotas](/concepts/routing-and-quotas), and the generated
[configuration schema](/reference/config-schema) for the exact source version.
Do not invent a field or copy a shape from an older revision.

## Build and stage the complete revision

Ensure every reference resolves: identity and trust policy, server-owned upstream,
physical model capability, trusted input-accounting profile, pricing catalog,
limit plan, feature access and output bounds, and ordered route set. Match the
feature protocol to every route and configure retry, fallback, destination, and
response bounds explicitly.

Use the immutable lifecycle documented for Console, CLI, or Admin API: clone the
active document, edit a draft, validate it, inspect its redacted plan and diff,
simulate representative claims/platforms/trust, and activate with the current
strong ETag. Never mutate the active revision directly.

## Verify and retain rollback

Simulate both an allowed and denied principal before activation. After activation,
send a bounded request through a supported SDK and verify feature, selected route,
model alias, limit plan, status, usage, cost provenance, and safe request ID in
the console. Preserve the prior valid revision so it can be atomically
reactivated if the effective behavior is wrong.

Treat named framework support as experimental unless its generated compatibility
row and release status establish the exact tuple.
