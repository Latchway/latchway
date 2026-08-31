---
name: configure-play-integrity
description: Configure Google Play Integrity for a Latchway Android or React Native Android client. Use for server policy, Play-distributed device verification, signing identifiers, and verdict troubleshooting.
---

# Configure Play Integrity

## Bind the Play application

Read [Identity and attestation](/concepts/identity-and-attestation),
[Native Android](/mobile/android), and [Physical-device proof](/mobile/device-proof).
Pin the exact package name, signing-certificate digest, numeric Google Cloud
project, application resource ID, environment, and public origin required by the
generated [configuration schema](/reference/config-schema).

Use the official Android or React Native native provider. It must pass the
server challenge as Play Integrity `requestHash`; JavaScript and application code
must never construct, read, log, or persist the integrity token. Keep user
authentication separate from the integrity verdict and let feature policy decide
the required trust level.

## Separate verification modes

Local fixtures and sideloaded or emulator builds are development signals. A
production verdict requires the exact signed app uploaded to an authorized
internal, closed, or production Google Play track, installed from Google Play on
a supported physical device, with licensing and device policy matching the
active environment.

Do not weaken package, signing, licensing, device-integrity, hardware-backed key,
or StrongBox requirements to make an unqualified build pass. The current release
status records no physical Play Integrity evidence, so that release gate remains
open.

## Verify safely

Exercise installation creation, session reuse, DPoP replay rejection, refresh
rotation, a bounded request, diagnostics, and revocation. Confirm the console
shows the normalized trust result and redacted request ID. Retain no raw verdict,
identity token, session token, DPoP material, signing file, or provider credential.
