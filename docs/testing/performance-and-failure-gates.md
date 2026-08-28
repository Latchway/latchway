# Performance and failure gates

These gates turn the version 1 performance and reliability contract into
repeatable evidence. They do not convert a laptop run, a mocked semantic test,
or an absent external artifact into a release pass.

## What constitutes release evidence

The initial performance environment is exactly:

- 2 vCPU and 2 GiB RAM for one Latchway instance;
- PostgreSQL on a measured low-latency network;
- prompt and response body logging disabled;
- a warm configuration cache;
- the exact release OCI reference (`registry/repository@sha256:<64 lowercase
  hexadecimal characters>`), not a mutable tag.

Record the PostgreSQL version and placement, host/container limits, image
identity, core commit, deployment revision, and runner identity in the load
configuration. The harness records those declarations but cannot prove a
cloud control plane applied them. Preserve platform resource descriptions as
separate artifacts.

Image identity has two deliberately separate evidence fields. A self-contained
local run sets only `metadata.local_docker_image_id` to Docker's immutable
`sha256:<64 lowercase hexadecimal characters>` image ID. Release and cloud
runs set only `metadata.release_oci_reference` to a fully qualified registry
repository plus digest. Exactly one field is required. A local Docker image ID
is useful local evidence, but it is never registry or release evidence.

The load report passes only when the complete six-gate suite runs. A selected
single-gate run can exit successfully for iteration, but its JSON contains
`complete_suite: false` and `load_targets_passed: false`.
The complete suite also requires a clean source worktree so its commit identity
actually describes the harness being run.

The failure report has two independent verdicts:

- `automated_passed` covers deterministic unit/PostgreSQL semantic evidence;
- `release_passed` additionally requires every destructive live fault artifact
  for the same commit.

## Isolated load fixture

The fixture is a bounded localhost-only OpenAI-compatible upstream. It returns
fixed 11/7/18 token usage, can hold valid SSE responses open, and retains only
counters. It never stores request bodies.

```bash
LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN="$(openssl rand -hex 32)" \
  ./scripts/run-load-fixture.sh \
  -listen 127.0.0.1:19090 \
  -stream-hold 90s
```

Configure the isolated Latchway environment to route the three load features
to `http://127.0.0.1:19090` (or the fixture's private container address). Never
expose the fixture control surface publicly and never package it in the
production image.

The fixture's authenticated control endpoint supports only `healthy`,
`fail-500`, `delayed-first-byte`, `disconnect-before-response`, and
`disconnect-during-stream`. The stream hold must exceed the load harness hold
plus establishment time.

For the self-contained Docker gate only, the fixture may bind one exact RFC1918
address when `-acknowledge-isolated-container-network` is supplied and the
control token is enabled. The launcher creates that address on a disposable
Docker `--internal` network with no external route. The active configuration
must name only the fixture's exact `/32` in `destinationPolicy.allowedCidrs` and
must explicitly enable private-network dispatch; using an apparently public
test subnet to bypass destination policy is forbidden.

## Self-contained local acceptance run

The local launcher provisions a disposable PostgreSQL database, fixture,
canonical Admin configuration, React Native/iOS debug-attested session, and
the complete six-gate run. It clones the exact committed source before
building, runs the gateway by immutable image ID with Docker enforcing exactly
2 CPUs and 2 GiB, and lets the runner observe PID 1 by sharing only the
gateway's network and PID namespaces.

The local PostgreSQL fixture is separately limited to 4 CPU cores and 4 GiB
with swap disabled, advertises 100 server connections, and shares the same
Docker `--internal` bridge as the gateway. The gateway pool is capped at 32
connections so it cannot consume the server connection budget or amplify a
hot-row convoy with the previous 80-connection setting. These PostgreSQL
resources are not part of the published 2-vCPU/2-GiB gateway target. The
launcher inspects the PostgreSQL image ID, CPU/memory controls, exact private
address and `max_connections`, and verifies the gateway pool environment
entry. `environment.json` and the load report preserve those non-secret facts.

```bash
mkdir -p /tmp/latchway-v1-load-evidence

./scripts/run-local-load-gates.sh \
  -acknowledge-load \
  -evidence-dir /tmp/latchway-v1-load-evidence
```

The evidence directory must be absolute, real, and empty. It receives the load
JSON/JUnit report, a redacted provision summary, exact local Docker image
IDs/resource/network facts, and bounded gateway/fixture logs. Session tokens,
the private DPoP JWK, database password, master key, bootstrap token, and owner
password stay in the private disposable runtime directory and are removed with
the exact generated containers/network. The launcher never targets an existing
Compose project or database.

This is deliberately `debug-non-production` trust evidence. It proves the
gateway load and quota behavior, not physical App Attest or Play Integrity.
It also requires the core private-destination contract to support the explicit
`allowedCidrs` allowlist; a core that still hard-disables every private
destination must reject provisioning, and that rejection is a blocked run—not
a load pass.

## Required Latchway test configuration

Create a dedicated organization/application/environment and session. Do not
reuse production subjects or provider credentials. The session access token
must be bound to the P-256 key in the private JWK file and remain valid for the
whole run. Store the token only in the named environment variable and the JWK
in a mode `0600` file. The harness generates a fresh RFC 9449 proof and request
identifier for every request and never writes either credential to evidence.

Configure distinct features so one gate cannot invalidate another:

1. `load` routes to the healthy fixture and has enough hard quota for the
   warmup, paired overhead samples, and the full 100 RPS interval. Its quota
   snapshot must be context-stable and expose no retained reservations after
   requests settle.
2. `stream-load` routes to the holdable fixture and permits at least 500
   concurrent streams. The configured stream-memory growth and plateau-slope
   bounds are explicit local acceptance choices because the original contract
   says “no unbounded growth” without assigning a byte/slope number.
3. `contention` has exactly one hard calendar `logical_requests` limit visible
   in its quota snapshot. Start with a fresh window whose remaining capacity is
   less than `contention_attempts`. Other limits must not be tighter. The gate
   requires exactly the initial remaining capacity to succeed, every other
   request to receive the configured denial status, `used + reserved <=
   maximum`, and zero reservations after settlement.

The generated local `load` plan is deliberately capacity-proved rather than
merely oversized. Before the 100-RPS interval, exactly 1 protected preflight,
20 warmups, and 1,000 measured gateway requests have settled: 1,021 requests.
The interval schedules another 6,000 requests. The rewritten deterministic
request reserves at most 140 input, 8 output, and 148 total tokens; the fixture
reports exactly 11 input, 7 output, and 18 total tokens. For a stronger bound
that does not assume an earlier response's settlement is already visible, the
capacity proof treats all 7,021 requests as simultaneously reserved. Therefore
the largest possible bucket occupancy is:

- `logical_requests`: `1,021 + 6,000 = 7,021` (maximum 10,000);
- `input_tokens`: `7,021*140 = 982,940` (maximum 1,000,000);
- `output_tokens`: `7,021*8 = 56,168` (maximum 100,000);
- `total_tokens`: `7,021*148 = 1,039,108` (maximum 1,100,000).

After settlement, the exact terminal `used/reserved/remaining` states are
`7,021/0/2,979`, `77,231/0/922,769`, `49,147/0/50,853`, and
`126,378/0/973,622`, respectively. The harness validates that the configured
request counts, reservation bounds, quota maxima, and terminal expectations
still satisfy this arithmetic; changing a target, prompt, provider fixture, or
limit without updating the proof fails configuration validation.

Copy and edit
[`tests/load/config/v1.example.json`](../../tests/load/config/v1.example.json).
Its 128 MiB stream-growth and 5 MiB/min plateau-slope values are explicit
example thresholds, not values invented by the product contract.
The example uses `release_oci_reference`, because it is the form required for
release and cloud evidence. Do not replace it with a bare `sha256:...` local
image ID. The self-contained launcher generates its separate local-only config
automatically.

## Run the load gates

Write the gateway PID to the configured PID file (or set an exact `pid` in the
config). `process_name_contains` must match the executable resolved for that
PID; this prevents an unrelated low-memory process from satisfying the RSS
gate. On Linux the runner resolves the basename of bounded, NUL-delimited
`argv[0]` from `/proc/<pid>/cmdline`; this remains readable when the runner and
gateway share a PID namespace but not a mount namespace. Missing, oversized,
or malformed procfs identity fails closed. Other platforms use their native
`ps` executable-name lookup. Then run:

```bash
export LATCHWAY_LOAD_ACCESS_TOKEN="<dedicated DPoP access token>"
export LATCHWAY_LOAD_DPOP_JWK_FILE="/absolute/path/to/load-private.jwk"

./scripts/run-load-gates.sh \
  -acknowledge-load \
  -config tests/load/config/v1.json \
  -output /tmp/latchway-v1-evidence/load-v1.json
```

`-acknowledge-load` is mandatory because the run opens 500 streams and sends at
least 100 requests/second. The harness refuses a configuration below the
contract targets.

The output includes JSON plus JUnit. It fails on:

- readiness or authenticated warmup failure;
- paired nearest-rank P50/P95/P99 overhead at or above 5/15/30 ms;
- any unexpected status at 100 RPS, excessive scheduler lag, overspent hard
  quota, or retained reservation;
- fewer than 500 simultaneously established SSE responses, a premature stream
  end, excessive RSS growth, or a positive plateau slope at/above its bound;
- idle RSS at or above 256 MiB;
- contention accepting anything other than the exact initial remaining hard
  capacity.

Each request-producing gate records only status counts, bounded stable problem
code counts, request-error counts, and invalid-problem-response counts. Response
bodies, prompts, DPoP proofs, tokens, and headers are never copied into the
evidence report. The non-stream and stream gates also record expected versus
observed quota limits and require the exact feature plus every
`maximum/used/reserved/remaining/hard` value to match; a merely non-overspent
snapshot is not a pass.

Gateway overhead is measured as paired client-observed gateway latency minus a
direct request to the same deterministic upstream, floored at zero. Pair order
alternates to limit drift. The report also preserves raw gateway and direct
upstream percentiles. Network placement therefore matters: the runner,
gateway, and direct fixture path must be documented and comparable.

## Deterministic failure matrix

The matrix audits all required reliability cases against existing semantic
tests and explicitly lists the live cases those tests cannot prove.

```bash
export LATCHWAY_TEST_DATABASE_URL="postgres://.../latchway_test?sslmode=disable"

./scripts/run-failure-gates.sh \
  -scope automated \
  -output /tmp/latchway-v1-evidence/failure-automated.json
```

Each fixed invocation uses `go test -race -json`, refuses to count a skipped
package as passing evidence, and stores a SHA-256-addressed JSONL log beside the
report. A missing PostgreSQL environment is `blocked`, not passed.

The automated matrix proves the repository semantics for:

| Required case | Deterministic evidence |
| --- | --- |
| reservation expiry and reclamation | undispatched release, dispatched conservative settlement, multi-entry recovery, settlement/expiry serialization |
| quota overspend | calendar, token-bucket, input/total/output variable-unit, and concurrency contention |
| DB dependency failures | pre-attempt release boundary, ambiguous begin failure, first-byte persistence boundary |
| upstream/client disconnect | partial client writes, cancellation cleanup, truncated provider body settlement, no problem append after commit |
| configuration changes | revision activation/rollback races and repeatable-read quota snapshot generations |
| signing rotation | single active initialization, active/retiring JWKS, pre-rotation session verification |
| JWKS rotation | unknown-kid refresh, bounded stale fallback, singleflight, database-shared cache/lease |
| workers/replicas | exactly-once job claims, stale-heartbeat recovery, idempotent rollups/retention |
| graceful drain | coordinated API/worker cancellation and bounded drain error propagation |
| clock skew/regression | DPoP, identifiers, session verification/revocation, and token-bucket cursor behavior |

## Destructive live failure evidence

Semantic tests cannot prove that an operating system actually killed the
release process, a network actually cut PostgreSQL, or a load balancer actually
routed across replicas. The six `external` matrix entries therefore remain
release-blocking until supplied.

For every live case:

1. use the exact release OCI reference pinned as
   `registry/repository@sha256:<digest>` and an isolated database;
2. capture a bounded before-state (quota snapshot plus relevant durable row
   identifiers, never prompt bodies or credentials);
3. create the in-flight boundary using the deterministic fixture;
4. inject exactly the documented SIGKILL, SIGTERM, database network cut, config
   activation, signing rotation, or JWKS rotation;
5. restore the dependency/start replacement replicas;
6. wait no longer than the configured reservation, reconciliation, or drain
   bound;
7. capture the after-state and assert no permanent reservation, no overspend,
   no post-commit retry, and the expected known/unknown usage provenance;
8. record raw logs/state as files and SHA-256 every artifact.

Create one document named `<scenario-id>.json` from
[`tests/failure/external-evidence.example.json`](../../tests/failure/external-evidence.example.json).
Artifact paths must be relative to the evidence directory. The validator checks
the scenario ID, exact current commit, timestamps, all assertions, artifact
presence, and every SHA-256 digest.

Then run the release scope:

```bash
./scripts/run-failure-gates.sh \
  -scope release \
  -external-evidence-dir /tmp/latchway-v1-evidence/live-failures \
  -output /tmp/latchway-v1-evidence/failure-release.json
```

Release scope fails if even one live artifact is missing or belongs to another
commit, and it refuses a dirty worktree. Write release evidence outside the
checkout (or to a pre-ignored CI artifact directory) so evidence creation does
not dirty the candidate. Cloud platform smoke, physical App Attest/Play
Integrity, and published
artifact conformance are separate release gates; neither of these runners
claims them.
