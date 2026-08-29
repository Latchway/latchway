# Backup and restore

A recoverable Latchway installation requires both PostgreSQL and the exact
environment master key. Database backups without that key cannot decrypt
provider credentials or signing material; a key without the database cannot
reconstruct tenants, sessions, quotas, audit records, or configuration.

## Backup set

Retain together, under separate access controls:

- a PostgreSQL physical backup/PITR stream or `pg_dump` custom archive;
- the exact `LATCHWAY_MASTER_KEY` in an external secrets vault;
- the deployed image digest, SBOM, signature/provenance references, and version;
- the public origin, replica roles, pool sizes, and non-secret platform config;
- contract/SDK versions and the most recent restore-drill result.

Do not export plaintext managed secrets through the Admin API. They are already
encrypted in PostgreSQL and recover only with the master key.

## Logical backup

Run from a trusted administrative host. Supply credentials through a protected
environment or password file; never put them in shell history.

```bash
export PGAPPNAME=latchway-backup
pg_dump \
  --dbname="$LATCHWAY_DATABASE_URL" \
  --format=custom \
  --no-owner \
  --no-acl \
  --file=/secure/backup/latchway.dump
sha256sum /secure/backup/latchway.dump > /secure/backup/latchway.dump.sha256
```

Encrypt the archive at rest with your organization-approved backup key. Record
the database engine major, current schema from `latchway migrate status`, image
digest, start/end time, checksum, and retention class. Prefer managed continuous
backups with point-in-time recovery in addition to logical exports.

## Restore drill

Restore only into a newly created, isolated PostgreSQL database. The following
command is destructive to its target; confirm `LATCHWAY_RESTORE_DATABASE_URL`
does not name production before running it.

```bash
sha256sum --check /secure/backup/latchway.dump.sha256
pg_restore \
  --dbname="$LATCHWAY_RESTORE_DATABASE_URL" \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  /secure/backup/latchway.dump
```

Install the escrowed master key in the isolated runtime, then verify:

```bash
LATCHWAY_DATABASE_URL="$LATCHWAY_RESTORE_DATABASE_URL" latchway migrate status
LATCHWAY_DATABASE_URL="$LATCHWAY_RESTORE_DATABASE_URL" latchway doctor --output json
```

Use the image version that created the backup first. After it is healthy, test
the normal forward upgrade procedure. Confirm active configuration, signing
and JWKS availability, managed-secret decryption, audit continuity, quota
snapshots, maintenance recovery, and one debug-only session/proxy flow. Revoke
test sessions and destroy the isolated environment after recording evidence.

## Production recovery

1. Freeze writes or remove traffic and capture the failure timestamp.
2. Restore to a new database/instance at the selected point in time.
3. Install the matching master key and trusted image digest.
4. Run `migrate status` and `doctor`; do not blindly migrate until the restored
   image/schema pair is understood.
5. Run read-only reconciliation, then a controlled verification request.
6. Shift traffic gradually and monitor quota recovery, worker heartbeat, and
   signing/JWKS state.
7. Preserve the failed environment for forensics under incident controls.

Never solve a master-key mismatch by overwriting the runtime key. Stop and
recover the correct key or restore a database encrypted under the available key.

## Release evidence drill

The release gate uses the isolated executable launcher documented in
[`../testing/operational-resilience-evidence.md`](../testing/operational-resilience-evidence.md).
It creates fresh source and restore PostgreSQL containers, verifies an
immutable custom archive and distinct database identities, compares a bounded
tenant-state fingerprint, and runs the previous released image's migration
status and doctor checks on the restore. The launcher cannot accept an
operator-supplied database URL, so it cannot be pointed at production. A
handwritten restore summary or an archive that was not restored does not
satisfy the gate.
