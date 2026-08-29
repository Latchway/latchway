# Ephemeral provider verification

`providerverify` is the database-free verification engine used by future CLI
and Admin API surfaces. It accepts a credential only through `CredentialSource`,
keeps provider bodies outside the result contract, and sends every production
request through `upstream.Target` with HTTPS, DNS-rebinding defenses, no proxy,
and redirects disabled.

OpenRouter behavior is pinned to its official contracts:

- [`GET /api/v1/key`](https://openrouter.ai/docs/api/api-reference/api-keys/get-current-api-key)
  validates the currently authenticated key.
- [single-model lookup and pricing](https://openrouter.ai/docs/guides/overview/models)
  supplies the selected model's per-token/request prices and context window.
- [`provider.max_price`](https://openrouter.ai/docs/guides/routing/provider-selection#max-price)
  is expressed in USD per million tokens. The verifier converts the catalog's
  USD-per-token strings with exact integer nano-USD arithmetic and installs a
  price ceiling before inference.
- [usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting)
  places usage and cost on the complete JSON response or final SSE frame.

The OpenRouter check performs key and model metadata validation, proves the
worst-case cost of one non-streaming and one streaming request before either is
sent, clamps each output to one token, validates input/output/total usage and
reported cost, and finally probes body-free error normalization. Unsupported or
unknown pricing shapes fail closed. Generic `openai_chat` runs the same protocol
and transport checks, but reports monetary cost as `unverified` because no
trusted price source exists.

Integration should call:

```go
report, err := providerverify.New().Verify(ctx, providerverify.Request{
    Mode:           providerverify.ModeOpenRouter,
    Model:          model,
    MaxCostNanoUSD: maximum,
    Credential: func(ctx context.Context, consume func([]byte) error) error {
        return consume(ephemeralBytes)
    },
})
```

The CLI must read `ephemeralBytes` from the named environment variable or
standard input, never from an argument, and clear its local buffer after
`Verify` returns.
