---
name: install-latchway
description: Install and verify a local Latchway source candidate. Use when setting up the gateway for evaluation or preparing the prerequisites for a deployment; use deploy-latchway for a cloud or production rollout.
---

# Install Latchway

## Establish the install mode

Read [Release status](/release-status) before selecting an artifact. The current
version 1 build is a source candidate: public container and package publication
must not be inferred from intended names or versions.

For a deterministic local evaluation, follow the
[operator quickstart](/operate/quickstart) and [self-test guide](/operations/self-tests).
Use the source-built Compose path documented there. Do not replace pinned images,
invent an install script, or silently switch to a public registry artifact.

## Preserve the local boundary

- Use PostgreSQL 15 or newer and the documented exact database layout.
- Generate the 32-byte master key once. Keep it outside source control and retain
  it with the database lifecycle; changing it in place is not key rotation.
- Keep the bootstrap token local and temporary. Bootstrap closes permanently
  after the first owner exists.
- Use loopback HTTP and debug fixtures only for the local mode that explicitly
  permits them.
- Treat `latchway verify local` as destructive only inside its generated temporary
  schema. Do not point it at a role that cannot safely create and drop that schema.

## Verify and report

Require health and readiness to pass, then require the documented local verifier
to complete and prove cleanup. Report the exact server source revision, database
version, verification result, and any redacted request IDs. Do not describe this
as live-provider, physical-device, cloud, signed-image, or production evidence.

Use [Deployment](/operations/deployment) and
[Production readiness](/operations/production-readiness) only after the local
result is established.
