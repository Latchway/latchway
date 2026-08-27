# Quota-bypass threats

## Required invariant

For every hard bucket, concurrent work must never make `used + reserved` exceed the configured maximum. The client cannot supply price, usage, plan, bucket key, or settlement totals.

## Reserve, execute, settle

Before dispatch, one short PostgreSQL transaction resolves every applicable organization, application, environment, user, installation, feature, route, upstream, model, and claim-selected bucket; locks or atomically updates them in a deterministic order; creates one idempotent reservation; and acquires concurrency leases. Dispatch begins only after commit.

After completion or failure, a separate transaction records actual/estimated usage and settles or releases each reservation entry exactly once. Expiry jobs reclaim abandoned reservations and leases after process failure. Retry attempts record their own upstream consumption while the logical request count remains singular.

## Attacks and controls

- **Parallel overspend:** row locking or atomic conditional updates and non-negative constraints.
- **Boundary hopping:** server-calculated calendar windows in a defined timezone, not client timestamps.
- **Integer abuse:** bounded integers, checked arithmetic, integer nano-USD, no floating-point currency.
- **Negative/unknown usage:** reject negative values; preserve provenance; fail closed when hard pricing is unavailable.
- **Double settlement/release:** unique operation identifiers and terminal reservation states.
- **Crash after reservation:** bounded expiry plus idempotent recovery workers.
- **Fallback amplification:** separate attempt cost from one logical request and reserve a configured worst case where enforceable.
- **Output overspend:** rewrite protocol output clamps before dispatch, stream accounting, and stop generation where the adapter safely supports it.
- **Claim manipulation:** limit-plan inputs come only from verified normalized claims and active configuration.

## Residual risks

Some providers reveal token or cost usage only after execution, and opaque protocols may provide none. Estimates can be conservative and unused reservation released, but perfect pre-dispatch cost knowledge is impossible. Policies must decide whether unknown usage is allowed; hard cost caps deny it.
