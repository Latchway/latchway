# ADR 0008: Integer cost accounting

## Context

Floating-point currency creates rounding drift, inconsistent cross-language behavior and boundary errors in hard limits. Provider prices can be small fractions of a US dollar.

## Decision

Represent cost as signed 64-bit integer nano-USD (`1 USD = 1,000,000,000 nano-USD`) with checked non-negative arithmetic for runtime usage and limits. Configuration accepts explicit integer nano-USD values; any human decimal conversion occurs at a validated boundary with documented rounding. Record currency and pricing revision/provenance.

## Alternatives

- Binary floating point: convenient but not exact.
- Decimal strings everywhere: exact but cumbersome for hot-path atomic arithmetic.
- Micros or cents: insufficient precision for token pricing.

## Consequences

UI and CLI format integers for humans. Maximum values need validation to avoid overflow when multiplying tokens, attempts and unit prices.

## Security implications

Reject negative, overflowed, missing or ambiguous currency values. A hard cost limit fails closed when an applicable price is unknown or stale beyond policy.

## Migration implications

Changing scale or adding currencies requires a versioned schema and data migration with exact conversion. Existing records retain original pricing revision and currency rather than being reinterpreted.

## Status

Accepted for version 1 on 2026-08-27.
