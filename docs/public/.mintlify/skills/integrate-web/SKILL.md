---
name: integrate-web
description: Integrate the Latchway browser SDK into a Web application with existing user identity, WebCrypto DPoP, exact origins, browser trust, streaming, cancellation, and CSP-aware runtime boundaries.
---

# Integrate Web

## Choose the browser path

Read [Release status](/release-status), [Web quickstart](/clients/web/quickstart),
and [Browser versus Node.js](/clients/web/browser-vs-node). Use
`@latchway/client` from the authorized source checkout until release status says
the package is published. Do not substitute the React Native package because
both APIs use TypeScript, and do not move browser identity into a server runtime.

Start with vanilla TypeScript and `fetch`. Preserve the application's existing
identity provider and framework. Record the exact browser SDK, server, contract,
protocol, browser, bundler, and framework versions being tested.

## Preserve the browser security boundary

- Create a feature-bound fetch with `fetchFor`. The browser chooses a feature,
  never a provider credential, physical model, route, price, or usage value.
- Let the SDK create the non-exportable WebCrypto P-256 key, DPoP proof, session,
  and IndexedDB state. Do not return its refresh token to application code.
- Configure exact allowed HTTPS origins and CORS, plus the gateway origin in CSP
  `connect-src`. Never use a wildcard for an authenticated production origin.
- Use Firebase App Check or Turnstile when the active production policy requires
  it. They are Web trust or abuse-risk signals, not user authentication, native
  attestation, or physical-device proof.
- Preserve `ReadableStream` delivery and `AbortSignal` cancellation. Do not add
  blind retries or follow an unvalidated redirect.

A non-exportable WebCrypto key cannot normally be read as raw material, but
same-origin JavaScript may still invoke it. Follow [WebCrypto and DPoP](/clients/web/webcrypto-dpop)
and [Content Security Policy](/clients/web/content-security-policy); do not claim
Secure Enclave-equivalent isolation.

## Verify the actual runtimes

Run the repository browser conformance coverage for the browsers and bundler
used by the application, including bootstrap, persistence, streaming,
cancellation, refresh coordination, exact-origin rejection, CORS, CSP, storage
reset, and revocation. Confirm the console reports a browser component, identity,
trust source, feature, DPoP result, and usage. If any required browser or case is
absent from the exact source tuple, report it as unverified rather than inventing
a test or support result.

The release status records a Firebase App Check source-gateway observation but
no protected exact-candidate rerun, and no configured Turnstile observation.
Keep those production gates explicit.
