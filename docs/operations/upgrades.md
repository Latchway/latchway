# Upgrades and rollback

Latchway database migrations are transactional, advisory-lock protected, and
forward-only. Application rollback and schema recovery are different
operations. The binary has no declared schema range: readiness requires the
database's current migration version to equal its bundled available version.
Verify a previous image against that database before routing traffic to it;
otherwise restore a tested pre-upgrade backup into a fresh database.

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

The rolling-overlap steps require both binaries to support the current schema.
When the bundled schema changes, use the release-specific drained maintenance
transition instead; an unhealthy container does not necessarily stop a reverse
proxy from forwarding requests to it.

## Schema 21: Installation Families

Schema 21 upgrades each legacy installation transactionally into one
Installation Family, one root client component, its existing public P-256 key,
and a component session family. The identifiers are deterministic: the legacy
ULID payload is retained under the `fam_`, `cmp_`, `cky_`, and `csf_` prefixes.
Attestation and logical-request rows gain family/component provenance without
rewriting already-issued access grants.

Legacy refresh rows are retained for rollback analysis and duplicated into the
component refresh table so the next successful rotation becomes
component-aware. The old schema allowed separate refresh families for one
installation to each contain an active token. Schema 21 intentionally permits
only one active refresh credential per component, so the newest active token is
kept active in the component table and older active branches are marked revoked
there. Existing short-lived access tokens remain valid until their normal
expiry; an older refresh branch fails closed on a schema-21 replica.

Before this upgrade:

1. ensure clients can recover from a refresh rejection by returning through the
   containing application's normal authenticated session exchange;
2. avoid a prolonged mixed-version window in which an old replica can create a
   new legacy refresh branch after the backfill;
3. retain the pre-upgrade backup until component refresh, family/component
   revocation, request attribution, and the application rollback drill pass;
4. run the populated upgrade proof with
   `go test ./internal/database -run TestMigratorPostgreSQLUpgradeV21InstallationFamilies`.

The migration does not copy a private key, provider credential, bearer token,
or plaintext refresh token. Public JWKs and stored token hashes retain their
existing confidentiality classification.

## Application rollback

Stop the rollout when readiness, latency, error rate, or correctness gates
regress. Before routing traffic back, run the exact previous binary's migration
status, doctor, and readiness checks against an isolated copy of the current
database; current and bundled available migration versions must match.
Preserve failed replica logs and traces, and let workers reclaim expired
reservations rather than editing quota tables manually.

## Schema 29: Terminal-attempt validation

Migration `29` replaces only the deferred terminal-validator function body,
consolidating its reads without changing check outcomes, error precedence,
legacy settlement repair, trigger timing, locking, tables, indexes, or
constraints. Historical migration `28` remains unchanged. Wire `2`, the frozen
schema-28 contract bundle, and SDK locks do not change.

A schema-28 binary becomes unready once migration `29` commits, even though
the table layout is unchanged. Do not assume schema-28 and schema-29 replicas
can maintain a ready rolling overlap. Rehearse the migration and traffic
transition with the exact images before deployment.

For application rollback, retain and verify a compatible schema-29 release
candidate before promoting a schema-29 stable image. The RC-to-stable-to-RC
drill must keep current and available schema equal to `29` for both binaries;
an older schema-28 image does not qualify. To recover schema `28`, restore a
pre-29 backup/PITR point into a fresh database and start the matching previous
image and master key. That is schema recovery, not application rollback.
Never remove migration-ledger rows, edit migration `28`, or weaken readiness
to make an incompatible image appear usable.

## Schema 30: Caller attribution

Migration `30` adds nullable `logical_requests.caller_sdk` and a check constraint
allowing `ios`, `android`, `react-native`, and `javascript`. Existing rows remain
null. This is observational request attribution, not a trust input or a new
quota scope; existing principals, buckets, and usage are unchanged. The migration
is transactional, but its `ALTER TABLE` operations require a table lock and
constraint validation may scan existing requests. Rehearse against a populated
isolated database and allow a maintenance window for large request histories.

A schema-29 binary becomes unready immediately after migration `30` commits.
For a 29-to-30 deployment:

1. Retain the exact old image, matching master key, active configuration revision
   IDs, and a verified pre-upgrade backup/PITR recovery path. Prepare and test a
   schema-30-compatible rollback artifact separately from that backup.
2. Remove application traffic and drain old API/worker processes for their
   configured shutdown timeout before the migration. Keep the origin, TLS state,
   database connection, and master key unchanged.
3. Run exactly one new-image `migrate up` job with the existing valid environment
   configuration. Set `LATCHWAY_MIGRATE_ON_START=false` on application processes
   so starting a canary does not unexpectedly apply migrations.
4. Run `latchway --output json migrate status` using the new image and explicitly
   require `current: 30`, `available: 30`, and `up_to_date: true`. A mismatched
   status response does not itself produce a nonzero command exit code.
5. Start the compatible application/worker, check doctor output and readiness,
   then restore traffic after request, refresh, streaming, and settlement checks.
   Only then activate the explicitly selected shared-native policy changes;
   unchanged applications retain their existing configuration.

An older application rebuilt with migration `30` must be labeled as a distinct
artifact and verified against schema `30`; it is not the original release and
does not acquire wire-3 support. Before rolling back to it, restore the affected
environments' prior compatible configuration revisions through the Admin API.
Leave other applications' revisions alone. New shared-native clients fail closed
on an older wire-1/2 server and cannot be silently converted to legacy sessions.

To recover schema `29`, restore the pre-30 backup/PITR point into a fresh database
with the original matching image and master key. Schema recovery affects every
application in that database, and writes after the recovery point may be lost;
record that RPO before accepting traffic. Never delete migration-ledger rows,
drop the attribution column manually, or weaken readiness to fake compatibility.

## Schema recovery

There are no down migrations. If a migration itself must be undone:

1. remove application traffic;
2. restore the pre-upgrade backup/PITR point into a new database;
3. start the matching previous image with the matching master key;
4. run the complete restore verification gate;
5. switch traffic to the recovered environment.

Directly deleting migration-ledger rows or hand-editing production tables is
unsupported and can invalidate quota, audit, signing, or replay guarantees.

## PostgreSQL major upgrades

Treat a PostgreSQL major-version change as a database migration, not an image
refresh. The Compose templates pin PostgreSQL 18 and mount the named volume at
`/var/lib/postgresql`, which lets the official 18+ image place data in its
major-version-specific subdirectory. A PostgreSQL 17-or-earlier volume mounted
at `/var/lib/postgresql/data` is not directly reusable by that image. Take and
verify a backup, rehearse `pg_upgrade` (or restore into a fresh PostgreSQL 18
database), validate the Latchway state fingerprint and `doctor`, and switch
only after the isolated rehearsal passes. Never change the image and volume
layout together on the production database without that proof.

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
