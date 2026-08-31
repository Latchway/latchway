---
name: configure-firebase
description: Configure Firebase Authentication and, for Web, Firebase App Check with Latchway. Use when connecting an existing Firebase user identity or browser trust signal; keep those two verification inputs distinct.
---

# Configure Firebase

## Identify the Firebase role

Ask whether the task needs Firebase Authentication, Firebase App Check, or both,
and ask for the target platform. Authentication identifies the application user.
App Check is a Web application or abuse-risk signal; it is not user identity,
native attestation, or proof of a physical device.

Read [Identity and attestation](/concepts/identity-and-attestation), the generated
[configuration schema](/reference/config-schema), and the target client guide.
For Web App Check, also use [Firebase App Check](/clients/web/firebase-app-check)
and [Browser trust](/clients/web/browser-trust).

## Configure the server boundary

- Reuse the application's existing Firebase sign-in flow. Configure Latchway to
  verify its current ID token; do not create a second user identity system.
- Pin the exact Firebase project and the schema-required audiences, application
  identifiers, and allowed origins. Do not use wildcard production origins.
- Treat Firebase identity and App Check tokens as short-lived verification input.
  Never expose them in documentation, diagnostics, logs, or configuration exports.
- Configure App Check only for the browser component and trust level required by
  policy. Do not relabel its result as App Attest or Play Integrity.

## Integrate and verify

Use the platform SDK's Firebase identity provider or callback and let it obtain a
fresh application-user token. For Web, use the SDK App Check provider; application
code must not persist or forward Latchway refresh credentials.

Verify the request log shows the expected pseudonymous user, browser or native
component, trust source, feature, DPoP result, and usage without exposing tokens.
The current release status records a Web App Check source-gateway observation,
but protected exact-candidate evidence remains required for a production support
claim.
