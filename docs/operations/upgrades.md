# Upgrades and rollback

Latchway database migrations are transactional, advisory-lock protected, and
forward-only. Application rollback and schema rollback are therefore different
operations: a previous image may be redeployed only when its documented schema
range includes the current database; otherwise restore a tested backup.

## Preflight

Record the current image digest, binary/contract version, schema version,
configuration revision, SDK versions, and worker heartbeat. Confirm the new
release's image signature and attestations before pulling it:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/latchway/latchway/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/latchway/latchway@sha256:REPLACE

gh attestation verify \
  oci://ghcr.io/latchway/latchway@sha256:REPLACE \
  --repo latchway/latchway
```

Review the SBOM and vulnerability/license results attached to the same digest.
Take a backup and complete a recent restore drill. Ensure PostgreSQL and pool
headroom can carry the rolling overlap of old and new replicas.

## Roll forward

1. Deploy the new migration job with zero application traffic to the new image.
2. Run `latchway migrate status`, then exactly one `latchway migrate up` job.
3. Re-run `migrate status` and `doctor` against the new image.
4. Roll worker replicas first when release notes require new maintenance logic;
   otherwise keep at least one compatible worker heartbeat throughout.
5. Send a small percentage of API traffic to the new digest.
6. Verify session refresh, non-streaming, streaming, quota settlement, fallback,
   metrics, logs, and traces before each traffic increase.
7. Drain old replicas for at least `LATCHWAY_SHUTDOWN_TIMEOUT` and retain the
   prior image digest until the observation window closes.

Do not change the environment master key during an ordinary upgrade. Do not
combine a schema migration, public-origin change, signing-key emergency
rotation, and upstream configuration rewrite in one rollout.

## Application rollback

Stop the rollout and route traffic to the previous digest when readiness,
latency, error rate, or correctness gates regress. Confirm that the previous
binary supports the current schema before starting it. Preserve failed replica
logs and traces, and let workers reclaim expired reservations rather than
editing quota tables manually.

## Schema recovery

There are no down migrations. If a migration itself must be undone:

1. remove application traffic;
2. restore the pre-upgrade backup/PITR point into a new database;
3. start the matching previous image with the matching master key;
4. run the complete restore verification gate;
5. switch traffic to the recovered environment.

Directly deleting migration-ledger rows or hand-editing production tables is
unsupported and can invalidate quota, audit, signing, or replay guarantees.

## Release evidence drill

Before promotion, run the exact `linux/amd64` child from an authenticated,
distinct-ancestor prior release candidate, then the exact current candidate
child, then the prior candidate child again against one isolated database. The
prior manifest and retained Sigstore bundle must come from an exact successful
protected-main `release.yml` run; neither candidate needs a public tag. The
automated procedure and its fail-closed report contract are in
[`../testing/operational-resilience-evidence.md`](../testing/operational-resilience-evidence.md).
The prior candidate must have a strictly lower semantic version, report the
candidate schema as current, and become ready
after application rollback. If it cannot, the candidate has no proven
application rollback path and must not be promoted; a pre-upgrade database
restore is schema recovery, not evidence that the prior binary supports the
new schema.
