# Operational-resilience release evidence

Operational resilience is a promotion gate, not a checklist declaration. The
gate emits `operational_resilience.json` only after one exact candidate passes
all of the following machine reports:

1. the complete six-gate v1 load suite against the immutable candidate OCI
   digest (a local Docker image ID is rejected);
2. the release-scope failure matrix, including all six destructive scenarios
   and at least two API replicas, two workers, and a real load-balancer path;
3. a PostgreSQL custom-format backup restored into a distinct fresh database,
   with the previous release's `migrate status` and `doctor` passing and a
   bounded state fingerprint preserved; and
4. the previously released image, exact candidate, and previous image again on
   the same isolated database, with readiness, health, schema compatibility,
   and the bounded state fingerprint preserved through application rollback.

This tooling has no synthetic success mode. Until the protected workflow runs
with live artifacts, `operational_resilience` remains unverified.

## Input identity

Run source-scope cross-repository conformance and the release-candidate
workflow first, both from protected `main` at the exact untagged candidate
commit. The protected producer verifies both GitHub attestations against that
commit, `refs/heads/main`, their exact repository workflow paths, and hosted
runners before the finalizer runs. This prepublication path deliberately does
not require the intended tag to exist. The finalizer then requires the reports
to agree on:

- all five repository commits, versions, and intended tags;
- released contract version, release time, bundle name, and bundle SHA-256;
- the exact 40-character core commit; and
- `ghcr.io/latchway/latchway@sha256:<64 lowercase hexadecimal characters>`.

Every input timestamp must start at or after the contract release time, finish
no later than the verifier's clock, be no more than seven days old, and fit in
one seven-day aggregate window.

The load artifact must be named `load-v1.json` and contain
`complete_suite: true`, `load_targets_passed: true`, a clean candidate commit,
all six fixed passing gate names, and only `metadata.release_oci_reference`
for image identity. Output from `run-local-load-gates.sh` intentionally fails
this release check because it identifies a locally built image.

The release failure artifact must contain `failure-release.json` and:

```text
failure-release.logs/
└── ... exact SHA-256-addressed go test JSONL logs ...
live-failures/
├── live-process-kill-after-reservation.json
├── live-process-kill-during-stream.json
├── live-database-outage-boundaries.json
├── live-graceful-shutdown-and-drain.json
├── live-upstream-and-client-disconnect.json
├── live-config-and-key-rotation-across-api-replicas.json
└── ... hash-addressed raw artifacts ...
```

The finalizer compares every automated invocation to the committed failure
matrix, rehashes its fixed JSONL filename, requires exit code zero, and requires
a concrete passing JSON event for every exact test name in the committed
invocation with no skip or failing event. A report-level boolean without those
logs is rejected.

Every destructive document must have exactly the fixed assertion set below;
arbitrary true booleans do not satisfy the gate:

- reservation kill: `process_sigkill_observed`,
  `reservation_was_durable_before_kill`,
  `replacement_worker_reclaimed_reservation`,
  `no_usage_recorded_for_undispatched_attempt`, and
  `hard_quota_not_overspent`;
- stream kill: `sse_first_byte_observed_before_sigkill`,
  `process_sigkill_observed`, `replacement_api_and_worker_recovered`,
  `reservation_settled_conservatively`, `no_permanent_reservation`, and
  `hard_quota_not_overspent`;
- database outage: `database_network_cut_observed`,
  `predispatch_outage_failed_closed`,
  `no_upstream_dispatch_during_predispatch_outage`,
  `settlement_outage_created_bounded_pending_usage`,
  `worker_reconciled_pending_usage_after_restore`, and
  `no_permanent_reservation`;
- graceful drain: `sigterm_observed`,
  `listener_rejected_new_work_during_drain`,
  `nonstream_completed_or_terminated_within_drain_bound`,
  `sse_completed_or_terminated_within_drain_bound`,
  `process_exited_within_drain_bound`, and `no_permanent_reservation`;
- disconnects: `pre_response_upstream_disconnect_observed`,
  `mid_sse_upstream_disconnect_observed`,
  `downstream_client_cancel_observed`, `one_terminal_attempt_per_case`,
  `usage_provenance_bounded_per_case`, and `no_permanent_reservation`.

All six documents also bind the exact image, platform, isolated PostgreSQL,
fault tool, and operator. The replica document has the fixed assertions below
and additionally binds replica counts and the load balancer.

The replica scenario additionally records `api_replicas` and
`worker_replicas` as values of at least `2`, a nonempty `load_balancer`, and
passing assertions named:

- `at_least_two_api_replicas_observed`;
- `at_least_two_workers_observed`;
- `load_balancer_routed_multiple_api_replicas`;
- `configuration_revision_atomic_across_replicas`;
- `signing_rotation_preserved_active_sessions`; and
- `jwks_rotation_converged`.

## Executable recovery and rollback drill

The drill launcher creates only fresh, uniquely named containers on a Docker
`--internal` network. It requires a deliberate acknowledgement, an absolute
empty evidence directory, a clean exact candidate checkout, two distinct
immutable Latchway image digests, and an immutable PostgreSQL digest. It never
accepts a database URL and cannot target an existing database.

```bash
scripts/run-operational-resilience-drills.sh \
  --acknowledge-isolated-destructive-drill \
  --evidence-dir /tmp/latchway-operational-drill \
  --core-commit "$CANDIDATE_COMMIT" \
  --previous-image "ghcr.io/latchway/latchway@sha256:$PREVIOUS_DIGEST" \
  --candidate-image "ghcr.io/latchway/latchway@sha256:$CANDIDATE_DIGEST" \
  --postgres-image "docker.io/library/postgres@sha256:$POSTGRES_DIGEST"
```

The launcher verifies OCI `RepoDigests` and revision labels, creates a small
disabled tenant fixture, captures a canonical state fingerprint, performs
`pg_dump`/`pg_restore`, migrates and starts the candidate, then starts the
previous image against the candidate schema. The previous image must report a
strictly lower semantic version and exact revision, that revision must be the
target of its existing annotated `v<version>` Git tag, and the public
`ghcr.io/latchway/latchway:<version>` tag must resolve to the supplied digest.
These checks apply only to the previous release; the current intended tag is
not required to exist. If the prior binary cannot run the candidate schema,
rollback evidence fails; restoring the pre-upgrade backup is a separate
schema-recovery operation and does not satisfy application rollback.

Raw observations are sealed by `operational-drill-report.py`. The sealer and
the aggregate finalizer independently validate report shape, image identity,
schema equality, health/readiness, state equality, assertions, and every raw
artifact SHA-256.

## Finalize and export

The protected `Operational resilience evidence` workflow downloads candidate,
source, release-load, and release-failure artifacts by numeric run ID from the
same repository. It verifies the candidate and source report attestations for
the exact candidate commit on protected `main`, executes the isolated drills,
finalizes the domain, attests the domain document with GitHub OIDC, and uploads
the bounded reports.

For offline verification of already captured inputs:

```bash
python3 scripts/operational-resilience-evidence.py \
  --candidate-manifest /evidence/candidate/latchway-candidate.json \
  --source-conformance /evidence/source/latchway-cross-repository.json \
  --load-report /evidence/load/load-v1.json \
  --failure-report /evidence/failure/failure-release.json \
  --failure-evidence-dir /evidence/failure/live-failures \
  --backup-restore-report /evidence/drills/backup-restore.json \
  --upgrade-rollback-report /evidence/drills/upgrade-rollback.json \
  --output-directory /evidence/final-operational-resilience
```

The output directory is absolute and empty. It receives the exact
cross-repository domain document plus copied input reports and a raw-artifact
hash index. It contains no database credential, master key, DPoP key, provider
payload, prompt, response, device identifier, or absolute developer path.

Run the deterministic validator suite with:

```bash
python3 -m unittest scripts/test_operational_resilience_evidence.py
bash -n scripts/run-operational-resilience-drills.sh
```
