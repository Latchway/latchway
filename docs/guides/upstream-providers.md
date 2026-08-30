# Upstream provider guide

Latchway separates a public client protocol from a protected upstream target.
Clients choose a feature, not a destination, credential, route, physical model,
price, retry policy, or timeout.

## Supported protocol adapters

| Feature protocol | Public endpoint | Provider family |
| --- | --- | --- |
| OpenAI Responses | `POST /v1/responses` | OpenAI-compatible |
| OpenAI Chat Completions | `POST /v1/chat/completions` | OpenAI-compatible |
| OpenAI Embeddings | `POST /v1/embeddings` | OpenAI-compatible |
| Anthropic Messages | `POST /v1/messages` | Anthropic-compatible |
| Restricted opaque HTTP | `/proxy/{feature}/{path...}` | configured generic HTTP only |

OpenRouter, direct provider APIs, Bifrost, LiteLLM, Cloudflare AI Gateway, and
internal compatible proxies are represented as configured upstreams and model
catalog entries. No provider-specific identity or quota code is required.

## Add a credential

Use the Secrets view or a scoped Admin API token with the CLI. Values are
write-only, envelope-encrypted, and never returned:

```bash
printf '%s' "$UPSTREAM_API_KEY" | \
  latchway secret set provider_key --environment env_... --from-stdin
```

An upstream can use no authentication, Bearer, one configured header, Basic,
or one-to-eight independently secret-backed headers. Authentication and static
headers cannot collide with Latchway control, protocol-owned, forwarding, or
hop-by-hop fields.

## Configure the target and route

In the console:

1. Create the protected upstream base URL and authentication reference.
2. add the physical model and its supported protocol capabilities.
3. add immutable configured pricing and trusted input-accounting profile when
   input/total-token or input-priced cost enforcement is required.
4. create a feature and ordered routes.
5. configure weight, sticky selection, fallback conditions, retry policy,
   replay safety, and timeout overrides.
6. validate, inspect the structural plan, simulate representative facts, and
   activate the revision with its strong ETag.

The gateway resolves and pins public DNS results, rejects prohibited address
ranges unless an operator has explicitly allow-listed exact private CIDRs,
rejects redirects, strips client credentials, and applies route request/body
bounds before dispatch.

## Trusted token and cost enforcement

For Responses, Chat, Embeddings, and Anthropic text-only shapes, a model can
reference a conservative server-owned input-accounting profile. The adapter
rewrites the physical model/output bound first, then binds the exact rewritten
body hash, byte count, framing units, input bound, output bound, total bound,
profile, and physical model into the durable reservation. Richer unsupported
shapes fail closed when a hard input/total/cost rule needs that proof.

Known provider usage settles the reservation. Missing, malformed, or
over-bound usage retains the conservative charge. OpenRouter provider-reported
cost may be accepted only through the explicit trusted OpenRouter parser and
is stored with separate provenance; arbitrary provider price fields are never
trusted.

## Verify a configured credential

Credential self-tests execute on the server so provider keys never enter the
CLI process:

```bash
latchway verify upstream --server-owned \
  --environment env_... --upstream primary --model canary
latchway verify openrouter --server-owned \
  --environment env_... --upstream openrouter \
  --model canary --max-cost-nano-usd 10000000
```

The live OpenRouter release gate additionally proves non-streaming, streaming,
usage, total tokens, cost when reported, output clamping, and normalized error
behavior against the exact candidate image.

See `docs/reference/upstream-routing.md` for authentication, header, request,
and timeout details.
