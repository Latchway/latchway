---
name: troubleshoot-request
description: Diagnose a failed or unexpected Latchway request from its stable problem code, safe request ID, versions, and redacted operational views. Use for identity, trust, DPoP, quota, routing, upstream, and component failures.
---

# Troubleshoot a request

## Collect only safe correlation data

Ask for the stable problem `code`, HTTP status, safe request ID, `retryable` and
`retry_after` fields when present, target platform, feature ID, and the exact
server, SDK, adapter, contract, protocol, and framework versions. Never request
identity or access tokens, refresh credentials, private keys, DPoP proofs, raw
attestation evidence, identity subjects, upstream credentials, provider payloads,
prompt bodies, or unredacted logs.

Begin at the exact code row in [Error reference](/reference/errors). Do not infer
a code or remediation from similar wording. Then use [Troubleshooting](/troubleshooting),
the platform page, and the request, usage, attestation, or audit view described in
[Operational views](/administration/observability).

## Locate the failing boundary

Check in order: exact public origin and protocol tuple; application identity
expiry; required attestation provider, trust level, identifiers and freshness;
component provenance and feature grant; DPoP method, URL, token binding, nonce
and replay state; feature and limit-plan selection; quota reservation; route and
upstream attempts; response commitment; revocation. Keep Web risk verification
separate from native trust and delegated authorization separate from direct
attestation.

## Remediate without weakening policy

Respect the registry's retry guidance. `retryable: true` never authorizes a blind
replay: do not retry a consumed body, an already committed response, an upstream
timeout that may have dispatched, or a terminal trust/revocation error. For
`operation_indeterminate`, preserve the operation ID and require the correlated
durable audit result before deciding whether to repeat a mutation.

Correct the exact configuration, identity, trust, component, quota, route, or
upstream cause and verify with a new safe request ID. Do not disable attestation,
widen origins, allow arbitrary destinations, share credentials, clear unrelated
components, or bypass DPoP to make the request pass. If release or compatibility
evidence is absent, report an open gate rather than a product failure or success.
