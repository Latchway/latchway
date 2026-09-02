# ADR 0034: Correct the version 1 gateway-overhead targets

> Renumbering note: this decision was originally ADR 0022. It was renumbered
> without changing its scope when the Installation Family addendum reserved
> ADRs 0017 through 0028.

## Context

The version 1 implementation plan defines an initial acceptance environment of
one 2-vCPU/2-GiB Latchway instance, low-latency PostgreSQL, disabled body
logging, and a warm configuration cache. It calls the P50/P95/P99 gateway
overhead values of `<5/<15/<30 ms` initial targets. The Phase 18 hardening gate
allows an explicit corrected target when evidence justifies it.

Four complete exact-shape local runs measured paired client-observed gateway
latency minus direct deterministic-fixture latency, floored at zero:

| Core candidate and run | P50 (ms) | P95 (ms) | P99 (ms) |
| --- | ---: | ---: | ---: |
| `f5d9e4b` baseline A | 13.799 | 19.160 | 29.262 |
| `f5d9e4b` baseline B | 14.751 | 18.570 | 24.244 |
| `10fca0f` batched reservation | 12.744 | 17.332 | 24.015 |
| `1f6f45b` batched lifecycle | 13.077 | 16.728 | 23.605 |

The abbreviated candidates above are
`f5d9e4bdbc114751c3304e603c2084bf96deac90`,
`10fca0f522728a06ada9424026eac6eb4a395126`, and
`1f6f45b17961f8788cf8d9d71b846e88fd82c751`.

Temporary diagnostic instrumentation counted 39 sequential PostgreSQL round
trips across the full common successful request lifecycle and five synchronous
durable write transactions. It proved that the optimized settlement path was
used by 1,100 of 1,100 instrumented requests. The correlated common-path P50
was 11.307 ms; independently measured phase P50 values were reservation 2.649
ms, attempt begin 2.082 ms, first-byte persistence 1.474 ms, and settlement
4.899 ms. Phase percentiles are not additive, which is why the correlated
common-path result is stated separately.

The final exact local load report and bounded gateway log had SHA-256 digests
`fcae0c0b7376e9d79f913cbf0d3ae0cbbf47598135883a5f4df5751e994d8560`
and `795d6046bbe9ec89675f48650e2afc95113bd427e6f89bb36efeeb00a6140eb2`.
They are local diagnostic evidence, not release artifacts.

## Decision

Under the Phase 18 correction provision, version 1 uses these strict gateway
overhead targets in the unchanged initial acceptance environment:

```text
P50 under 15 ms
P95 under 20 ms
P99 under 30 ms
```

An observed value equal to its target fails. Release-evidence validation may
accept a stricter declared threshold, but rejects any declared P50/P95/P99
threshold above `15/20/30 ms`.

This decision changes only the P50 and P95 overhead targets. It preserves the
original P99 target and all existing requirements for 100 non-streaming RPS,
500 concurrent SSE streams, exact terminal quota state, zero quota overspend,
scheduler lag, bounded stream memory growth and slope, idle memory below 256
MiB, graceful behavior, and deterministic and live failure evidence.

Durable request, quota, attempt, first-byte, and settlement boundaries remain
synchronous. The target is not achieved by deferring accounting, weakening
transaction isolation, sampling correctness work, or omitting security checks.

## Alternatives

- Keep `<5/<15/<30 ms`: all four exact-shape runs fail both P50 and P95 even
  after safe batching, while the instrumented durable lifecycle explains the
  stable common-path floor.
- Make quota and attempt writes asynchronous: this could reduce response
  latency but would violate dispatch, settlement, overspend, and recovery
  invariants.
- Remove or sample authentication, DPoP, routing, accounting, or audit work:
  this would turn the benchmark into a different and less secure gateway.
- Raise P99 or weaken the load, memory, or contention gates: the collected
  evidence does not justify those changes, so they remain unchanged.
- Report server-only handler time instead of paired client-observed overhead:
  this would discard the existing acceptance method and make historical runs
  incomparable.

## Consequences

Generated and example load configurations use `15/20/30 ms`, and the protected
operational-evidence finalizer rejects wider values. Existing configurations
that intentionally retain stricter values remain valid and must still pass the
thresholds they declare.

The correction gives P50 and P95 targets consistent with four repeated
exact-shape observations while retaining the original P99 bound. It does not
by itself make a candidate release-ready. Exact released-image, physical
mobile-device, live-provider, cloud-platform, destructive multi-replica,
supply-chain, publication, and clean-consumer evidence remain independent
release gates.

## Security implications

No authorization, attestation, DPoP, destination-policy, request-bound,
routing, quota, accounting, transaction, audit, or redaction behavior changes.
In particular, preserving synchronous durable writes avoids accepting lower
latency at the cost of quota overspend, ambiguous attempt ownership, lost
settlement, or incomplete recovery evidence. The release finalizer continues
to fail closed when a report declares thresholds wider than this decision.

## Developer-experience implications

Load configurations default to strict `15/20/30 ms` P50/P95/P99 thresholds,
and the evidence finalizer rejects a wider declaration while allowing a
stricter one. Contributors evaluating performance must use the unchanged
acceptance environment and paired client-observed method; the correction is
not permission to bypass synchronous correctness work or to advertise a
general latency guarantee from local runs.

## Migration implications

There is no database, wire-protocol, Admin API, or client SDK migration. Load
configurations and external evidence producers should adopt the corrected
P50/P95 defaults. A producer may keep stricter targets, but previously failing
evidence does not become a release pass unless the complete unchanged suite is
rerun against the exact candidate artifact and satisfies every current gate.

## Documentation implications

Performance and release documentation must publish the strict corrected
thresholds together with the unchanged throughput, streaming, quota, memory
and correctness gates. It must distinguish the cited local diagnostic runs
from exact-release evidence, describe the paired overhead calculation and
tell external evidence producers to update defaults or retain their stricter
values.

## Status

Accepted under the Phase 18 hardening provision for contract `0.5.1` and wire
protocol `1` on 2026-08-29. Acceptance records a justified target correction;
it does not claim that version 1 release finalization or publication is
complete.

The decision was renumbered from ADR 0022 to ADR 0034 on 2026-08-30. Its
implementation and historical evidence remain unchanged.
