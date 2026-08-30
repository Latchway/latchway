# Quota-bypass threats

## Required invariant

For every hard bucket, concurrent work must never make `used + reserved` exceed the configured maximum. The client cannot supply price, usage, plan, bucket key, or settlement totals.

## Reserve, execute, settle

Before dispatch, one short PostgreSQL transaction resolves every applicable organization, application, environment, user, installation, feature, route, upstream, model, and claim-selected bucket; locks or atomically updates them in a deterministic order; creates one idempotent reservation; and acquires concurrency leases. Dispatch begins only after commit.

After completion or failure, a separate transaction records actual/estimated usage and settles or releases each reservation entry exactly once. Expiry jobs reclaim abandoned reservations and leases after process failure. Retry attempts record their own upstream consumption while the logical request count remains singular.

## Attacks and controls

- **Parallel overspend:** row locking or atomic conditional updates and non-negative constraints.
- **Boundary hopping:** server-calculated calendar windows use the active rule's
  bounded IANA timezone (UTC by default), never a client timestamp or timezone
  header. Weeks begin Monday; local civil day/week/month boundaries remain
  deterministic across daylight-saving changes, while fixed elapsed
  minute/hour buckets do not alias repeated wall-clock time. The exact
  non-UTC timezone and UTC boundary instant are part of bucket identity.
- **Integer abuse:** bounded integers, checked arithmetic, integer nano-USD, no floating-point currency.
- **Negative/unknown usage:** reject negative values; preserve token and cost
  provenance independently; fail closed when a hard reservation cannot be
  reconciled.
- **Provider cost spoofing:** provider-reported cost is an explicit,
  compatible-upstream opt-in; exact final USD decimals only. Configured pricing
  still creates the pre-dispatch reservation, and an invalid, missing, or
  over-bound report retains the full hard reservation.
- **Double settlement/release:** unique operation identifiers and terminal reservation states.
- **Crash after reservation:** bounded expiry plus idempotent recovery workers.
- **Fallback amplification:** separate attempt cost from one logical request and reserve a configured worst case where enforceable.
- **Output overspend:** rewrite protocol output clamps before dispatch, stream accounting, and stop generation where the adapter safely supports it.
- **Claim manipulation:** limit-plan inputs come only from verified normalized
  claims and active configuration. A quota claim selector is explicit and
  top-level; policy converts its sealed scalar value, including a distinct
  missing marker, into a domain-separated opaque digest. Raw values never
  reach quota persistence or operational views. Platform scope likewise comes
  only from the sealed installation authorization. `limit_plan` cannot be an
  optional duplicate scope because selected-plan identity is already implicit
  in every rule and request fingerprint.
- **Request-shape under-reporting:** request bytes are the exact post-rewrite
  body length and digest, not a client counter. Structured adapters count
  images and historical tool calls from their closed request grammar; opaque
  protocols fail closed for those two metrics. The data plane owns and
  re-verifies the body immediately before target acquisition, and quota binds
  the proof across initial reserve, retry, replay, and crash recovery.

## Residual risks

Some providers reveal token or cost usage only after execution, and opaque
protocols may provide none. Estimates can be conservative and unused
reservation released, but perfect pre-dispatch cost knowledge is impossible.
An opted-in valid cost report can be retained when token usage is incomplete;
the token reservation still settles conservatively. Missing or invalid cost
never becomes zero, and a hard cost reservation is charged in full.
