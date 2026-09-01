# Operational-resilience release evidence

Operational resilience is a promotion gate, not a checklist declaration. The
gate emits `operational_resilience.json` only after one exact candidate passes
all of the following machine reports:

1. the complete six-gate v1 load suite against the immutable candidate OCI
   index and its exact executed `linux/amd64` child (a local Docker image ID is
   rejected);
2. the release-scope failure matrix, including all six destructive scenarios
   and at least two API replicas, two workers, and a real load-balancer path;
3. a PostgreSQL custom-format backup restored into a distinct fresh database,
   with the authenticated prior candidate's `migrate status` and `doctor`
   passing and a bounded representative-state fingerprint preserved across
   tenant hierarchy, administrator/session, configuration revision, encrypted
   secret, quota, usage, job, and audit rows; and
4. a distinct-ancestor prior candidate, the exact current candidate, and the
   prior candidate again on the same isolated database, with readiness, health,
   schema compatibility, and the bounded state fingerprint preserved through
   application rollback.

This tooling has no synthetic success mode. Until the protected workflow runs
with live artifacts, `operational_resilience` remains unverified.

## Canonical RC checkpoint sequence

A stable release needs two different protected-main source commits and two
successful candidate runs. For `v1.0.0`, the first commit must coherently set
the binary version, console version, and changelog coordinate to
`1.0.0-rc.1`. The second must be its Git descendant and coherently restore
those source coordinates to `1.0.0`. The frozen `api/` tree, contract version,
release time, and deterministic bundle must be byte-identical at both commits.

Advance protected `main` only to the RC commit, then dispatch and wait for the
exact candidate run to succeed:

```bash
gh workflow run release.yml \
  --repo Latchway/latchway \
  --ref main \
  -f candidate_commit="$RC_COMMIT" \
  -f intended_tag=v1.0.0-rc.1
```

Record that run's numeric ID and actual attempt before advancing `main`. The
candidate workflow publishes only the immutable
`candidate-$RC_COMMIT` image coordinate and evidence artifact; it does not
create or push an RC Git tag, GitHub release, or stable OCI alias.

After the RC run succeeds, advance `main` to the stable descendant and run the
source-conformance and stable-candidate workflows at that exact new head. Keep
`main` fixed there through promotion and finalization. Supplying the RC commit
as an input after skipping its protected-main candidate run, advancing both
commits before dispatching the RC run, reusing one commit for both versions,
or rebuilding either version from a dirty checkout does not satisfy the gate.

The operational workflow receives the retained RC commit/run/attempt through
`previous_candidate_*`. It still independently requires exact run identity,
Git ancestry, canonical same-base `rc.N` to stable versions, equal frozen
contracts, increasing creation time, and four distinct OCI index/platform
digests. This sequence prepares evidence; it never creates a public tag.

## Input identity

Run source-scope cross-repository conformance and the release-candidate
workflow first, both from protected `main` at the exact untagged candidate
commit. A separately retained successful `release.yml` run on protected
`main` supplies the prior candidate at a distinct ancestor commit. The
protected load and failure producers verify both upstream GitHub
attestations against that commit, `refs/heads/main`, their exact repository
workflow paths, and hosted runners before executing or importing observations.
The aggregate workflow then verifies five attestation bundles: current and
prior candidate manifests against `release.yml` at their respective source
commits, plus source, load, and failure evidence against the current commit.
It also queries both candidate runs, requires successful `workflow_dispatch`
on `main` with the exact head SHA and active fixed workflow path, and hash-binds
the prior artifact and bundle into a strict run receipt. This prepublication
path deliberately does not require either intended tag to exist. The finalizer
requires the reports and producer manifests to agree on:

- all five repository commits, versions, and intended tags;
- released contract version, release time, bundle name, and bundle SHA-256;
- the exact 40-character core commit; and
- `ghcr.io/latchway/latchway@sha256:<64 lowercase hexadecimal characters>`
  for the candidate index and a distinct digest in the same repository for the
  executed `linux/amd64` child;
- a prior candidate manifest whose commit is a distinct Git ancestor, whose
  semantic version and creation time are lower/earlier than the current
  candidate (for example `v1.0.0-rc.1` to `v1.0.0`), and whose index and
  executed child are distinct from the current candidate;
- the protected workflow path, protected environment, source commit, run ID
  and attempt, runner class/OS/architecture, fixed invocation, configuration
  checksums, primary-report checksum, and exhaustive raw-artifact checksums.

Every input timestamp must start at or after the contract release time, finish
no later than the verifier's clock, be no more than seven days old, and fit in
one seven-day aggregate window.

The load artifact must be named `load-v1.json` and contain
`complete_suite: true`, `load_targets_passed: true`, a clean candidate commit,
all six fixed passing gate names, and both
`metadata.release_oci_reference` and
`metadata.release_oci_platform_reference` for index and executed-child
identity. A self-contained local invocation of `run-local-load-gates.sh`
intentionally fails this release check because it identifies a locally built
image. The protected load workflow invokes the same launcher in its explicit
release mode, after pulling and inspecting the exact candidate child.

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

All six documents also bind the exact index image, exact platform-child image,
platform, isolated PostgreSQL, fault tool, and operator. The replica document
has the fixed assertions below and additionally binds replica counts and the
load balancer.

The replica scenario additionally records `api_replicas` and
`worker_replicas` as values of at least `2`, a nonempty `load_balancer`, and
passing assertions named:

- `at_least_two_api_replicas_observed`;
- `at_least_two_workers_observed`;
- `load_balancer_routed_multiple_api_replicas`;
- `configuration_revision_atomic_across_replicas`;
- `signing_rotation_preserved_active_sessions`; and
- `gateway_signing_jwks_converged` (issuer-JWKS rotation and shared replica cache behavior are proved by the separate `jwks-rotation-and-shared-cache` PostgreSQL scenario).

## Repo-owned disposable fault controller

The protected producer does not accept prewritten passing scenario documents.
`scripts/run-release-failure-controller.sh` builds the repository-owned
fixture, balancer, provisioner, and failure driver from the exact clean
candidate source, provisions the complete topology, writes the controller's
strict plan, and invokes `scripts/fault-controller.py`. The example
`tests/failure/controller-plan.example.json` documents that generated plan's
closed schema; operators do not supply it. The plan contains no URL, hostname,
command, credential, or production resource identifier. One bounded `run_id`
deterministically names the internal bridge and every container. The launcher
and controller require:

- the explicit `--acknowledge-disposable-target` switch and a non-root caller;
- one internal-only, label-bound Docker bridge with no published container
  ports;
- exactly two to four API replicas, two to four workers, PostgreSQL, the
  deterministic fixture, a load balancer, and an observer container, all using
  controller-derived `latchway-failure-<run-id>-...` names;
- `dev.latchway.failure.run=<run-id>` and the exact fixed role label on every
  object, no host PID namespace or privileged container, the exact candidate
  image ID/revision on API and worker containers, the authenticated platform
  digest in that image's Docker `RepoDigests`, and the exact PostgreSQL image
  ID and digest; the fixture, balancer, and driver must use one distinct
  repository-built tools image whose revision label matches the candidate;
  container and network object IDs are revalidated immediately before every
  destructive action and again before cleanup;
- the fixed observer executable `/tools/latchway-failure-driver`; it receives
  only `<phase> <scenario-id>`, emits one bounded strict JSON document, and
  cannot ask the host controller to execute an arbitrary command; and
- per-scenario and overall timeouts, a bounded SIGTERM drain deadline, exact
  fixed assertion names, hash-addressed artifacts, and successful removal of
  every validated container and the internal network before a passing evidence
  document is emitted.

The controller itself injects both SIGKILLs, the PostgreSQL network partition,
the SIGTERM, restart, and restore actions. For disconnect and replicated
rotation cases it invokes the fixed observer `inject` phase inside the isolated
network. The observer must create authenticated traffic, control the
deterministic fixture, inspect redacted durable state, perform configuration,
signing, and issuer-JWKS rotation, and return the exact machine-checked
assertions. Phase documents must include `boundary_ready`, `fault_observed`,
`recovery_observed`, or `verification_complete` as appropriate; an arbitrary
true assertion or skipped phase fails closed.

The failure driver, balancer, deterministic barriers, topology construction,
machine checks, and cleanup are all repository source. No protected variable,
operator-installed `/tools` binary, pre-provisioned topology, or externally
authored plan remains. The runner supplies only Linux Docker capacity and
network access to pull the already-authenticated exact candidate and
PostgreSQL digests. Registry credentials are removed and replaced by an empty
Docker configuration before the repository-owned topology launcher executes.

## Protected load and failure producers

`Protected exact-candidate load evidence` uses three fresh jobs. A no-checkout
job in the `release-load-evidence` protected environment authenticates the
exact candidate and source runs and their attestations. On that no-checkout
runner only, it uses package-read authentication to pull the exact
`linux/amd64` child, preloads PostgreSQL, exports both under local-only tags,
and uploads a one-day, size-bounded archive with a SHA-256 receipt that binds
the authenticated candidate manifest, OCI child, image IDs, revision, and
platform. The fresh candidate job has neither package permission, registry
configuration, protected external credential, nor OIDC permission. It checks
out the exact protected-`main` commit, verifies the archive allowlist, size,
hash, receipt, imported image IDs, revision, and platforms, and executes the
complete fixed load launcher by immutable local image ID. The launcher keeps
the canonical authenticated OCI index and child in the evidence and performs
no registry pull in this preloaded mode. A final no-checkout job in
`release-evidence-signing` validates the producer schema, invocation, complete
file set, and every SHA-256 with fixed inline shell and `jq` before requesting
OIDC and attesting the manifest. The signer redownloads the protected
authenticator's immutable candidate and source artifact and independently
matches their hashes and release coordinates to the unsigned producer. It uploads
`latchway-release-load-<commit>` with `load-producer.json`, its Sigstore bundle,
the primary report, exact configuration, redacted provisioning record, logs,
and all other raw files hash-indexed by the manifest.

`Protected exact-candidate destructive-failure evidence` applies the same
three-job boundary. Its protected no-checkout authenticator verifies the
upstream runs and retains only their authenticated candidate and source
artifacts. The candidate and fault validator runs without OIDC on a runner
labeled `self-hosted`, `linux`, `x64`, and `latchway-release-failure`. It uses
package-read authentication only to pull the exact `linux/amd64` candidate
child and exact PostgreSQL digest, binds both references to Docker image IDs,
then logs out and removes the registry configuration before executing any
topology source. The repo-owned launcher provisions two APIs, two workers,
PostgreSQL, the deterministic fixture, the round-robin balancer, and the
long-lived observer on one internal bridge; generates its strict bounded plan;
executes all six cases; and cleans up. The workflow then runs the fixed
release-scope validator against the already-loaded exact PostgreSQL image and
transfers the unsigned evidence to a fresh hosted no-checkout signer. That
signer checks
the complete manifest and artifact tree with fixed inline logic before OIDC
attestation, including an independent comparison to the authenticator's
candidate and source inputs, and uploads
`latchway-release-failure-<commit>` with `failure-producer.json`, its Sigstore
bundle, the report, committed matrix, non-secret environment record, automated
logs, and destructive observations.

The self-hosted runner and protected environment are an explicit trust
boundary: the workflow authenticates what the repo-owned controller injected
and what the isolated observer measured, and prevents cross-candidate
substitution, but cannot turn an unavailable Docker host into an observation.
Environment approval, runner isolation/capacity, registry availability, and
review of the attested checksums remain operational controls. Disposable
topology behavior is no longer an unversioned runner responsibility. The
finalizer never synthesizes external claims.

## Executable recovery and rollback drill

The drill launcher creates only fresh, uniquely named containers on a Docker
`--internal` network. It requires a deliberate acknowledgement, an absolute
empty evidence directory, a clean exact candidate checkout, the authenticated
prior-candidate manifest and commit, the current index and exact
`linux/amd64` child, and an immutable PostgreSQL digest. It never accepts a
database URL and cannot target an existing database.

```bash
scripts/run-operational-resilience-drills.sh \
  --acknowledge-isolated-destructive-drill \
  --evidence-dir /tmp/latchway-operational-drill \
  --core-commit "$CANDIDATE_COMMIT" \
  --previous-candidate-commit "$PREVIOUS_CANDIDATE_COMMIT" \
  --previous-candidate-manifest /evidence/previous-candidate/latchway-candidate.json \
  --candidate-image "ghcr.io/latchway/latchway@sha256:$CANDIDATE_INDEX_DIGEST" \
  --candidate-platform-image "ghcr.io/latchway/latchway@sha256:$CANDIDATE_AMD64_DIGEST" \
  --postgres-image "docker.io/library/postgres@sha256:$POSTGRES_DIGEST" \
  --preloaded-candidate-platform-image-id "$CANDIDATE_LOCAL_IMAGE_ID" \
  --preloaded-previous-platform-image-id "$PREVIOUS_LOCAL_IMAGE_ID" \
  --preloaded-postgres-image-id "$POSTGRES_LOCAL_IMAGE_ID"
```

The launcher revalidates every artifact named by the prior manifest, derives
its immutable OCI index and exact `linux/amd64` child, verifies Git ancestry,
then checks the executed child images' platform, `RepoDigests`, revision labels,
and runtime version output. It creates a disabled tenant plus non-empty
administrator/session, configuration revision, encrypted-secret, quota, usage,
completed-job, and audit fixtures, captures a canonical fingerprint over their
counts and bounded semantic markers, performs `pg_dump`/`pg_restore`,
migrates and starts the current candidate, then starts the prior candidate
against the candidate schema. The prior candidate must report its exact
manifest version and revision and a strictly lower semantic version. Neither
an annotated Git tag nor a public/stable OCI tag is read or created. A mutable
tag, a made-up v0.9 coordinate, or reusing the current candidate as its own
predecessor is not acceptable evidence. If the prior binary cannot run the
candidate schema, rollback evidence fails; restoring the pre-upgrade backup is
a separate schema-recovery operation and does not satisfy application rollback.
The three preloaded ID options are all-or-none. When present, each must be an
exact distinct `sha256:<64 lowercase hexadecimal>` Docker image ID already
imported by the workflow; the launcher verifies the IDs and platforms, skips
all registry pulls, executes those local images, and continues to record the
authenticated OCI index/child/PostgreSQL digest coordinates above. Existing
offline callers may omit the three options and retain the original pull path.

Raw observations are sealed by `operational-drill-report.py`. The sealer and
the aggregate finalizer independently validate report shape, image identity,
schema equality, health/readiness, state equality, assertions, and every raw
artifact SHA-256.

## Finalize and export

The protected `Operational resilience evidence` workflow also has three fresh
jobs. Its no-checkout authenticator downloads current and prior candidate,
source, release-load, and release-failure artifacts by numeric run ID from the
same repository. It queries both candidate and both producer run records to
require their fixed workflow paths, successful `workflow_dispatch`, protected
`main`, exact head SHA, and exact run attempt, then verifies every upstream
attestation. That no-checkout authenticator alone receives package-read access;
it pulls the exact current, prior, and PostgreSQL digests and exports a
size-bounded one-day archive plus SHA-256 receipt. The next fresh job has no
package permission, Docker registry credential, protected environment, or OIDC
permission. It checks out the exact candidate, proves the prior commit is a
distinct ancestor, verifies and imports the archive, executes all images by
the receipt's immutable local IDs without registry pulls, and revalidates every
report and producer checksum. A final fresh no-checkout signer validates the domain schema, exact
14-file allowlist, every SHA-256, current/prior candidate identities, and exact
load/failure run coordinates using only fixed inline shell and `jq`. Only that
last job can request GitHub OIDC and attest the domain document. It separately
redownloads the protected authenticator artifact and byte-compares every
upstream input copied into the final domain before signing.

For offline verification of already captured inputs:

```bash
python3 scripts/operational-resilience-evidence.py \
  --candidate-manifest /evidence/candidate/latchway-candidate.json \
  --previous-candidate-manifest /evidence/previous-candidate/latchway-candidate.json \
  --previous-candidate-attestation /evidence/previous-candidate/latchway-candidate.attestation.sigstore.json \
  --previous-candidate-run /evidence/previous-candidate-run.json \
  --previous-candidate-commit "$PREVIOUS_CANDIDATE_COMMIT" \
  --previous-candidate-run-id "$PREVIOUS_CANDIDATE_RUN_ID" \
  --source-conformance /evidence/source/latchway-cross-repository.json \
  --load-report /evidence/load/load-v1.json \
  --load-producer-manifest /evidence/load/load-producer.json \
  --load-producer-attestation /evidence/load/load-producer.attestation.sigstore.json \
  --load-producer-run-id "$LOAD_RUN_ID" \
  --failure-report /evidence/failure/failure-release.json \
  --failure-producer-manifest /evidence/failure/failure-producer.json \
  --failure-producer-attestation /evidence/failure/failure-producer.attestation.sigstore.json \
  --failure-producer-run-id "$FAILURE_RUN_ID" \
  --failure-evidence-dir /evidence/failure/live-failures \
  --backup-restore-report /evidence/drills/backup-restore.json \
  --upgrade-rollback-report /evidence/drills/upgrade-rollback.json \
  --output-directory /evidence/final-operational-resilience
```

The output directory is absolute and empty. It receives
`operational_resilience.json` at its root plus copied reports, producer
manifests, their retained attestation bundles, the prior candidate manifest,
bundle and run receipt, and a raw-artifact hash index under
`artifacts/operational-resilience/`. In the protected workflow,
`operational_resilience.attestation.sigstore.json` is copied beside the domain
document before the directory is uploaded as
`latchway-operational-resilience-<commit>`. Every path directly named by the
domain document is relative to that artifact root. The bundle contains no
database credential, master key, DPoP key, provider payload, prompt, response,
or device identifier.

Run the deterministic validator suite with:

```bash
python3 -m unittest scripts/test_operational_resilience_evidence.py
bash -n scripts/run-local-load-gates.sh
bash -n scripts/run-operational-resilience-drills.sh
```
