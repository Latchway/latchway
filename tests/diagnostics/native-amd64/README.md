# Native AMD64 quota diagnostic — advisory only

This tooling collects **one** database-lifecycle sample from production source
`568f4f6950acec79c65ca59b3f829d7612242a11`. It does not modify production code,
change a release threshold, publish anything, or constitute release evidence.
There are no timing pass/fail thresholds. Exact accounting is still checked.

## Controlled execution

The manual workflow runs only on the first attempt of a `main` dispatch in
`Latchway/latchway`, on native Linux AMD64 `ubuntu-24.04`. Its permissions are
`contents: read`; there is no environment, new secret, OIDC permission, input
source reference, or publication step. The runner requires four host CPUs.

The reviewed tooling checkout must match the workflow SHA and current public
remote `main`. Its entire diff from the pinned production commit must contain
only the six files in this directory, the diagnostic workflow, and optionally
`docs/implementation/STATUS.md`. The diagnostic files must be new additions.
All other tracked product paths must remain byte-identical. A second clean
checkout of the fixed production commit receives only the two test templates;
these access package-private lifecycle helpers without modifying product code.
Both source and tooling commits are recorded, along with both template hashes.

One fresh pinned PostgreSQL 18 container has four CPUs, 4 GiB memory, no swap
beyond its memory limit, and `max_connections=100`. The test container has two
CPUs and 2 GiB memory. Both are native AMD64 and share one exact, newly created,
internal Docker network; neither publishes a host port. PostgreSQL uses a fresh
named and labeled volume. The test container runs as UID 65532 with a read-only
root filesystem and a 16 MiB temporary filesystem. Build and readiness checks
finish before measured work. Shared pinned base-image/cache layers are not
pruned; the exact run-owned test image, containers, volume, and network are
removed and their absence independently verified.

The lifecycle uses a pool capped at 32, 16 excluded warmup requests, then exactly
200 serial requests and 200 requests with concurrency 16. Each measured phase
shares four calendar buckets. Reserve, BeginAttempt, MarkFirstByte, and Settle
are included. Authentication, HTTP, upstream/provider behavior, sessions,
retries, streaming, and maintenance jobs are **not** included. Thus this is four
database lifecycle transactions, not the HTTP request's complete persistence
path. There is no implicit retry or second sample. A failed first attempt needs
review before a separately authorized new workflow dispatch.

## Interpreting the observations

- Client query, stage, batch, and pool-acquisition observations are wall-clock
  times, not database CPU measurements. Inclusive stage times overlap query and
  acquisition times. Prepare time can overlap query or batch time. Batch member
  callbacks are counted, not treated as individual statement execution timers;
  the batch wall time includes network/result consumption. Batch auto-prepare is
  not reported by the prepare tracer. Do not sum these overlapping categories.
- `pg_stat_statements(showtext := false)` provides numeric server statement
  counters and execution times, including nested statements (`track=all`).
  Planning tracking is not enabled. Setup and warmup counters are reset once,
  only on this exclusively owned disposable cluster, before measured work.
  There is no reset between phases. A reset, eviction, disappearance, counter
  regression, or snapshot above 512 entries stops the sample rather than silently
  truncating it. Deltas cover **all sessions in the current database**, not just
  the workload application name. Observer-session statement tracking is disabled.
- Numeric server query IDs and the client's static SQL hashes are distinct,
  **unjoined identifiers**. This report does not prove an exact query-ID-to-label
  mapping; query IDs are not assumed stable across independently created schemas
  or clusters. `total_exec_time` includes executor waits and is not CPU time.
- Lock sampling is once per second, bounded to 750 ms per query, at most 120
  samples and 128 groups per sample. It selects only workload-labelled sessions
  and uses fixed relation/state/wait/mode allowlists. Transaction IDs and process,
  row, request, user, schema, and connection identifiers are never output.
  `granted` is retained because the join includes held and requested tuple or
  transaction-ID locks, **not an exact matched contended-lock inventory**.
  A held tuple's relation does not establish the cause of a transaction-ID wait.
  One waiter may occur in several groups; do not sum groups as unique waiters.
  Unavailable/oversized samples are explicit, not silently successful empties.
- WAL and I/O counters are cluster-wide and can flush asynchronously. Exact
  phase attribution is not guaranteed. The observer itself consumes one extra
  connection, CPU, and I/O, and the timing settings add measurement overhead.
  `wal_delta` order is records, full-page images, bytes, buffers-full events.
  `io_delta` order is non-WAL read ms, write ms, fsync ms, read count; then WAL
  write ms, fsync ms, write count, fsync count. PostgreSQL 18 WAL timing comes
  from `pg_stat_io`, not removed `pg_stat_wal` timing columns. Neither metric is a
  direct storage utilization measurement.
- Workload-container cgroup CPU deltas contain only usage/user/system microseconds,
  period/throttled-period counts, and throttled microseconds. A missing or invalid
  cgroup-v2 file is explicitly unavailable. These are **not PostgreSQL cgroup
  counters**, host CPU utilization, or proof of database CPU saturation.

These observations help choose a smaller follow-up experiment. They cannot alone
prove that lock strength, CPU scheduling, WAL, or query count causes the failed
HTTP release load. No production setting is changed by this diagnostic.

## Data handling, failures, and cleanup

The randomly generated database password and connection URL exist only in
process memory and the exact Docker container environment. They are passed by
environment variable name, never as argument values, host files, or artifacts.
Raw test stdout is bounded to 2 MiB in memory; stderr is discarded. Existing
fixture assertions can contain raw database errors, so **never upload raw test
or Docker logs**. Only the closed, validated JSON report is retained. Static
error counts and static SQL hashes contain no raw query text or arguments.

`failure.json` records only the fixed launcher stage plus validated phase/event
and completion/failure counts. If an observer or accounting assertion fails,
the last valid progress record is retained; no successful report is fabricated.
Timeouts may produce a partial or empty progress record. A killed runner or
host loss may prevent any final receipt; absence of a receipt is not success.

The private ownership ledger is written and synchronized before every create.
Cleanup only considers those exact intents whose target was absent beforehand.
Readback must match the run labels and immutable saved identity (for volumes,
exact name plus provider creation timestamp). An acknowledged identity change
is refused. A create with uncertain acknowledgment can be reconciled only with
the exact unique run/attempt name, absent-before intent, labels, and scope.
Deletion is bounded, then independently checked against exact-target inventory.
There is no broad list/prune, shared-image deletion, or adoption of preexisting
resources. A failure does not suppress cleanup of other owned targets; unknown
targets are reported unresolved and cause a nonzero result. The workflow always
rechecks cleanup from the ledger. Keep `ownership.json` private; it is not an
uploaded artifact. No cleanup can be guaranteed after total hosted-runner loss.

The only retained artifact files are `report.json`, `environment.json`,
`failure.json` when applicable, and `cleanup.json`, in
`$RUNNER_TEMP/latchway-native-amd64-$GITHUB_RUN_ID-1/`.

## Offline validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -W error::ResourceWarning -m unittest discover \
  -s tests/diagnostics/native-amd64 -p test_run.py
```

The image build separately runs the Go redaction/shape-validator unit tests,
then compiles the fixed test binary. Neither build-time test opens a database.
`TestAdvisoryDatabaseQueryShape` is a separately opted-in, fixed-loopback local
smoke of PostgreSQL 18 result shapes. It is not selected by the hosted workflow;
its result is not AMD64 timing or performance evidence.

Reference semantics: PostgreSQL's official
[statement statistics](https://www.postgresql.org/docs/18/pgstatstatements.html),
[statistics views](https://www.postgresql.org/docs/18/monitoring-stats.html), and
[explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html).
