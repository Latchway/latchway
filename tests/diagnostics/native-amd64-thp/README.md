# Private actual-gateway THP pair

This is an advisory diagnostic, **not a release gate, release evidence, or a
production configuration recommendation**. It runs one A→B pair without retries.
No fixture or hosted execution is authorized merely by adding these files.

Both arms build from fixed product source
`568f4f6950acec79c65ca59b3f829d7612242a11`, using one shared immutable gateway
image and one shared immutable tools image. The workflow tooling checkout must
be the current `Latchway/latchway` main SHA, with only the existing native
diagnostic, these exact six files, its optional dispatch workflow, and STATUS
different from that product commit. No arbitrary source/ref input is accepted.
The reviewed native helper and original runtime collector are SHA-256 pinned.

The sole treatment is B's process `GODEBUG=disablethp=1`. Other existing GODEBUG
entries retain their order and values; all other image environment is inherited.
A baseline already disabling THP is refused. Both arms use identical explicit
gateway settings and shared synthetic credentials, fresh independent databases,
the same fixed internal network addresses, no published ports, and the original
full-load resource caps: gateway 2 CPU/2 GiB, PostgreSQL 4 CPU/4 GiB,
`max_connections=100`, gateway pool 32. A is removed and absence verified before
B can start. No host THP settings, GC controls, memory limits or quota gates are
changed. A→B order is not randomized and is not a statistical population sample.

The selected runtime-environment parser accepts Docker's empty/trailing newline
formatting by ignoring empty lines only. It retains strict ASCII, the four known
unique keys, byte/value bounds and unchanged setting values; malformed or unknown
entries are not normalized into an accepted environment. Failures retain an
allowlisted setup substage and an allowlisted internal stop code. Unrecognized
exceptions, captured output, command arguments and dependency messages remain
redacted rather than becoming diagnostic artifacts.

## Workload and observation

The existing load/provision/fixture source and default image CMD are unchanged.
The exact subset is `preflight,idle,overhead,nonstream,streams`: the original
preflight warm request, 10-second idle warmup and idle sampling, 20 overhead
warmups plus 1,000 paired requests, 6,000 requests at 100 RPS for 60 seconds with
the original settlement drain, and 500 SSE clients held for 60 seconds. It omits
only the later contention gate. The fixture holds streams for 150 seconds.
Original statuses and numeric measurements survive; failed performance gates
do not become successes. Incomplete preconditioning or held-stream observation
stops the pair. The manifest never asserts all release targets passed.

The only gateway source overlay is an `init`-activated sampler, requiring exactly
`/latchway serve --role all` in the existing image CMD (verified from image
metadata). Every five seconds, for at most 180 samples/15 minutes, it reads a
fixed `runtime/metrics` list and atomically replaces one mode-0600 numeric JSON
snapshot in the gateway's existing `/tmp` tmpfs. It adds no endpoint, logging
payload, forced collection or runtime setting mutation. A preexisting, changed,
symlinked or unwriteable target stops sampling. The sampler adds small allocation
and filesystem-observation overhead equally to both images/arms.

The private collector wraps the original SQL/resource/process collector at its
unchanged approximately 15–18-second lifecycle cadence. It reads the snapshot
from the existing load tools container in the gateway PID namespace, using UID
65532, no additional privilege, network, service or Docker socket mount. Reads
are bounded at 4 KiB/3 seconds, and unknown keys, strings, duplicate keys,
nonintegers and malformed values are discarded. Snapshots older than 10 seconds
or over one second in the future are explicitly unavailable. Permissions may
also make smaps/snapshot reads unavailable; this must not be interpreted as zero.
The observer has its own absolute deadline before the launcher's cleanup reserve.

The manifest distinguishes `workload_pair_complete` from
`memory_comparison_complete`. Memory completeness requires at least three fresh,
strictly increasing Go+OS samples spanning at least 30 seconds inside each held
window, excluding its first six seconds because capture times are not perfectly
simultaneous. Complete OS samples must include RSS, PSS, AnonHugePages, RssAnon,
RssFile and VmRSS. Host THP controls, GOGC and GOMEMLIMIT must be available and
stable within and across arms. Otherwise the result is explicitly inconclusive
and nonzero even if both workload arms completed. Completeness is an observation
quality condition, not a claim of causal proof or a release-performance pass.

Interpret numeric Go counters cautiously: heap objects include uncollected dead
objects; `heap_live_last_gc_bytes` describes the last completed GC, not a current
reachability scan. Heap free/released/unused and stack classes are runtime
accounting estimates, not exact RSS partitions. Compare their changes together
with GC cycles, allocated/freed totals, OS RSS/RssAnon/RssFile and AnonHugePages.
The first load RSS sample reuses a pre-establishment measurement with a later
timestamp; exclude it from instantaneous attribution. A flat Go heap with rising
huge-page-backed RSS supports a THP explanation; it does not by itself prove
kernel causality or exclude all application retention. Missing counters, host
THP changes, different preconditioning outcomes, CPU contention or timing/order
effects limit the pair's interpretation. The earlier synthetic test did not
reproduce the full gateway effect.

## Scope, deadlines and cleanup

Only explicit `--run` can create resources, and only in a native Linux x86_64
GitHub ubuntu-24.04 dispatch on main, attempt 1, with a four-CPU Docker host.
There are no cloud APIs, persistent credentials, environments, OIDC, publishing
or release-policy writes. An independent dispatch workflow remains a separate
review/authorization boundary.

Two arms plus image build, setup and cleanup share one 25-minute wall **and**
monotonic budget. Forward work stops with two minutes reserved for cleanup;
individual workload invocations have a 450-second ceiling. Insufficient time
for a second arm produces an incomplete pair, never a retry or relaxed workload.
Five seconds are additionally reserved for child termination before the hard
budget. An unresponsive daemon, job hard kill or lost process acknowledgment can
still make cleanup unknown; the diagnostic never claims absence it could not
verify. The ephemeral hosted runner is the final containment boundary.

The private mode-0700 root is unique to the exact GitHub run/attempt. A producer
lock prevents concurrent `--run` and `--cleanup`. Docker names are derived only
from that identity; the fixed fourteen-digit suffix is compatibility syntax,
not an observed timestamp. Before each create, exact-target absence and the
intent are durably recorded. Every observed image/container/network UID, or
volume name plus creation-time hash, is bound to exact owner and target labels.
Scope/caps/network/image identity are rechecked before removing only those
targets. Missing create acknowledgment can reconcile only a matching labeled
target with an existing absence-before intent; no existing target is adopted.
No broad list, prune, force image deletion, external image deletion or shared
Docker-cache cleanup is allowed. The pinned downloaded PostgreSQL/base images
and ordinary build cache are not treated as uniquely owned deletable resources.

`--cleanup` is cleanup-only: it validates the exact private ledger, clocks,
names, labels and observed identities, then removes verified owned targets and
confirms exact absence. A stopped collector receipt permits overall completion.
If a hard-killed parent never recorded collector shutdown, this remains unknown;
the restart never guesses or kills a recycled host PID. Docker cleanup continues
independently, and its observer already has a bounded lifetime. All uncertainty
is explicit/nonzero, with no automatic recreation or repeat.

Only `artifacts/manifest.json`, `failure.json`, `cleanup.json`, and the exact
`A/B-{load,environment,runtime,cleanup}` JSON/JSONL files may be retained. They
contain closed numeric metrics, allowlisted labels, hashes, and status only.
Never upload the private source/runtime/output directory, generated config,
`load.env`, provision output, raw load report/JUnit, or raw gateway/fixture logs.
The manifest identifies source/tooling and each overlay hash. Synthetic secrets
remain in memory or the private generated files needed by unchanged tools, and
are never placed in argv, diagnostic output or artifacts.

## Offline checks

Run `python3 -W error::ResourceWarning -m unittest discover -s
tests/diagnostics/native-amd64-thp -p test_run.py`. These tests use only synthetic
in-memory Docker responses and temporary files, never a daemon/network/database.
The two Go templates can be overlaid into a private source clone for focused
`TestAdvisoryMemory` tests and a Linux/AMD64 compile. The unchanged Dockerfile
runs the Go tests, including sampler tests, before any hosted gateway image
build completes. Compilation on ARM is not native AMD64 performance evidence.
