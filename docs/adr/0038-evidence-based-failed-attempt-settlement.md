# ADR 0038: Evidence-based failed-attempt settlement

Status: accepted, 2026-09-08.

## Context

Conservative settlement protects hard quotas after a request has been
dispatched and usage is unavailable. Treating a definitive validation rejection
like an interrupted generation can consume an entire user's token allowance
without any provider-reported usage. Conversely, refunding every HTTP error
would undercount requests that performed work or produced partial output.

## Decision

Keep unknown usage distinct from known zero and from a quota-policy charge.
For the exact protected HTTPS OpenRouter origin, parse a non-success error with
a 16 KiB bound and an absolute two-second ceiling, capped by existing request
timeouts. Reject ambiguous JSON, contradictory status/category/usage/output,
and unrecognized categories as non-authoritative. Preserve only a closed set
of diagnostic values; never persist raw messages, payloads or credentials.

`provider_rejection_v1` requires confirmed pre-generation validation rejection,
HTTP 400, a failed attempt, and no observed output. It releases token and cost
quota reservations; request and attempt counters retain abuse accounting.
Calculated zero-token records describe the settlement decision, not reported
provider usage. Billing remains unknown unless independently reported.

`reported_usage_v1` allows validated, bounded provider token measurements to
settle new failed attempts. Provider measurements exceeding trusted bounds
still become unknown and settle conservatively. Existing failed attempts
without this sidecar retain their original rules and immutable usage records.

The policy and safe diagnostics are committed in the settlement transaction.
Replay checks the same evidence, usage provenance and ledger allocations;
conflicting replay cannot change or duplicate charges. Interrupted migrations
remain transactional. No historical records are automatically reclassified.

Admin usage details distinguish recorded policy units, reported units, unknown
units and absent measurements. Existing numeric summary fields are retained
for API compatibility, but first-party interfaces use the explicit evidence.

Input-bound components are optional content-free diagnostics, validated against
the existing bound. They do not become quota authority, alter fingerprints or
justify reducing a hard bound. A new tokenizer/accounting method still needs a
validated physical-model/provider proof and a separate versioned decision.

## Verification

Cover rejection, contradictory partial output, unknown/truncated/slow bodies,
timeout, known failed usage, retries, conflicting replay, old settlement replay,
database upgrade/rollback, and absence-versus-zero rendering. The original
provider prompt cannot be reconstructed from its body digest; diagnostics must
not pretend otherwise.

Provider semantics are grounded in [OpenRouter's error reference](https://openrouter.ai/docs/api_reference/errors-and-debugging).
