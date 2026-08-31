---
name: configure-app-attest
description: Configure Apple App Attest for a Latchway iOS or React Native iOS client. Use for entitlements, server policy, physical-device verification, and trust troubleshooting; not for delegated-only app extensions.
---

# Configure App Attest

## Bind the exact application

Read [Identity and attestation](/concepts/identity-and-attestation),
[Native iOS](/mobile/ios), and [Physical-device proof](/mobile/device-proof).
Collect the App ID prefix, bundle ID, App Attest environment, signed validation
category, and exact `CFBundleVersion`/`CURRENT_PROJECT_VERSION`. Do not substitute
the marketing version or infer values from an unrelated target.

Keep the entitlement, signed executable, provisioning profile, server policy,
application resource ID, environment, and public origin consistent. Use the
official SDK provider so the challenge, key registration, assertion, session,
and DPoP binding remain intact. Never ask application code to construct, inspect,
persist, or transmit raw App Attest evidence outside that flow.

## Separate development from production

A simulator or fixture cannot establish App Attest. A development-signed physical
device observation remains development evidence even when Apple returns accepted
production App Attest trust. A production support claim needs protected evidence
from the exact distribution-derived candidate described by the release gates.

Use only the validation categories and bundle versions allowed by the generated
configuration schema. Do not broaden policy to make a mismatched binary pass.

## Handle components precisely

Apple app extensions in the documented version 1 path are delegated-only. Follow
[App extensions](/build/app-extensions/overview): the trusted containing app
authorizes a bounded, component-owned key and refresh chain. Never submit the
containing app's assertion as extension evidence or call the extension directly
attested.

Verify registration and a later same-key assertion, DPoP, request success,
counter persistence, and terminal revocation on a supported physical device.
Retain only redacted request IDs and exact candidate/version metadata.
