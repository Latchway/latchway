---
name: latchway
description: Deploy, configure, integrate, verify, or troubleshoot Latchway, including its identity and attestation boundary, feature routing, DPoP sessions, platform SDKs, Installation Families and Client Components, and AI framework adapters. Use when a task asks how to run Latchway, add an application or provider, protect an AI feature, integrate iOS, Android, React Native, web, or an AI framework, interpret a Latchway error, or review Latchway security and version compatibility.
---

# Latchway

## Establish the support boundary

1. Read release status and the generated compatibility entry for the exact
   server, SDK, adapter, contract, protocol, framework, and platform versions.
2. If a compatibility entry or conformance receipt is absent, describe the path
   as unverified or planned. Do not invent package names, APIs, or version ranges.
3. Treat Installation Families, Client Components, delegated app extensions,
   and named framework adapters as pre-release until published evidence says
   otherwise.

## Preserve the security model

- Keep upstream provider credentials on the Latchway server. Never place one in
  an application client or framework placeholder.
- Keep authentication, attestation, authorization, and DPoP distinct.
- Let the client select a feature. Keep routes, providers, physical models,
  prices, and authoritative usage server-controlled.
- Keep a Client Component's P-256 private key and refresh chain independent.
  Never share a rotating refresh token between components.
- Describe delegated trust precisely: a trusted root authorized a bounded
  component key. The delegated component did not independently complete App
  Attest unless a verified step-up occurred.
- Sign only the configured Latchway origin, revalidate redirects, and create a
  fresh DPoP proof for each permitted request attempt.
- Never request or expose tokens, private keys, proofs, raw attestation evidence,
  identity subjects, upstream credentials, or provider payloads in diagnostics.

## Choose the integration path

1. Prefer the platform SDK or authenticated transport.
2. Keep the application's AI framework. Inject a guarded fetch, URLSession,
   OkHttp client, interceptor, middleware, call factory, or framework provider.
3. Reject static-base-URL or static-header-only approaches for full DPoP.
4. Bind the transport to a feature, preserve streaming and cancellation, and
   retry only an exact replayable pre-dispatch rejection.
5. Do not recreate chat, prompt, agent, tool, memory, RAG, structured-output, or
   framework session abstractions inside Latchway.

## Deploy and verify

1. Configure PostgreSQL, application identity verification, platform trust,
   features, server-owned routes, upstream credentials, limits, and pricing.
2. Run the documented self-tests and the exact platform or framework
   conformance suite.
3. For native production claims, require protected physical-device evidence for
   the exact release candidate. Simulator, emulator, fixture, and sideloaded
   debug success are development signals only.
4. Verify discovery reports the expected contract, protocol, server, and SDK
   ranges before sending protected traffic.

## Troubleshoot safely

Collect the stable problem code, safe request ID, version tuple, and redacted
diagnostics. Check origin, identity expiry, trust provider and level, DPoP nonce
and replay state, feature scope, quota, route availability, component
provenance, and revocation. Escalate missing release evidence instead of
weakening policy or bypassing verification.
