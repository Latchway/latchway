---
name: deploy-latchway
description: Plan, deploy, verify, or roll back a Latchway runtime with PostgreSQL and production secret custody. Use for Compose, Cloud Run, AWS, Fly.io, Cloudflare, or another production hosting target.
---

# Deploy Latchway

## Select an evidence-backed target

Confirm the requested provider, environment, traffic mode, and authorization to
change external resources. Read [Deployment](/operations/deployment),
[Production readiness](/operations/production-readiness), and
[Release status](/release-status). A checked-in cloud template is source evidence,
not proof that the target account or exact candidate has been deployed.

The current source candidate has no promoted stable image. Build or select only
the exact authorized candidate, retain its immutable digest, and do not replace a
pinned dependency with a mutable tag.

## Preserve runtime invariants

- PostgreSQL 15 or newer is the only required external state service. Keep it
  private and retain the matching 32-byte master key for backup and restore.
- Put the master key, administrator credentials, and upstream secrets in the
  provider's secret custody. Do not expose values in plans, logs, image layers,
  or client applications.
- Set the exact external HTTPS public origin. It is DPoP protocol input, not
  display metadata.
- Run migrations as the documented job before accepting traffic. Require both
  health and readiness; production readiness includes a current worker heartbeat.
- Preserve streaming at the ingress, disable response buffering, allow the
  documented drain interval, and keep request timeouts longer than supported
  streams.

## Verify rollback readiness

Before traffic, verify the immutable image, schema status, readiness, streaming,
secret references without values, and a restore of the matching database and
master key. Record provider-observed evidence for the exact candidate. Keep a
reviewed rollback and restore path; never treat changing the master key in place
as rollback or rotation.

If protected cloud, signing, provenance, resilience, or restore evidence is
missing, report the release gate as open instead of weakening the deployment.
