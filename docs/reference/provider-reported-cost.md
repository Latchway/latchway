# Provider-reported cost

Latchway can use the final OpenRouter `usage.cost` value as an exact attempt
cost. This behavior is disabled by default and currently applies only to
OpenAI-compatible Chat Completions, Responses, and Embeddings upstreams.
Anthropic and opaque HTTP routes remain ineligible because they do not expose
this supported final-cost contract.

Enable it on the exact compatible upstream:

```json
{
  "id": "openrouter",
  "type": "openai_compatible",
  "baseUrl": "https://openrouter.ai/api/v1",
  "providerReportedCost": {
    "source": "openrouter_usage_cost",
    "currency": "USD"
  }
}
```

Both fields are closed enums. Presence on any other upstream type, a partial
object, an unknown field, or another source/currency makes the configuration
invalid. Omitting `providerReportedCost` preserves configured-catalog cost
calculation.

## Accounting rules

- Pre-dispatch reservations always use the configured pricing catalog and the
  trusted model-aware token bounds. A provider value never changes the amount
  reserved or weakens a hard limit.
- Only the final response usage object is considered. `cost_details` is
  explanatory and is never summed or used for settlement.
- The JSON number is converted directly to signed 64-bit integer nano-USD.
  Binary floating point and rounding are not used. Negative, malformed,
  overflowing, or non-zero sub-nano values are invalid measurements.
- A valid opted-in report is persisted even if the final token counts are
  absent. Token reservations remain conservative while cost retains
  `upstream_reported` provenance.
- When a hard cost reservation exists, a report above its conservative bound
  becomes unknown. The full reservation is charged and no reported cost usage
  row is manufactured.
- A missing or invalid opted-in report is unknown. With a hard cost rule, the
  full reservation is charged; without one, no cost is invented.
- Each retry or fallback attempt is accounted independently. The logical
  request remains single-counted, while every dispatched attempt can carry its
  own reported cost and replay identity.

The immutable attempt keeps its configured pricing selection for reservation
replay. The cost usage record and Admin API expose the separate fixed source
`openrouter_usage_cost`, currency `USD`, and provenance `upstream_reported`.
Request views show token-usage provenance and cost provenance independently.
