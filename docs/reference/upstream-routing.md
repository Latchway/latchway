# Upstream authentication, request bounds, and timeouts

An upstream is selected only from the active server configuration. A client
cannot provide a destination, credential, physical model, timeout, or retry
policy.

## Scoped upstream authentication

`authentication` is an exact tagged object. Extra fields are rejected.

- `{"type":"none"}` applies no credential.
- `{"type":"bearer","secretRef":"secret/provider"}` applies an
  `Authorization: Bearer` credential.
- `{"type":"header","headerName":"X-Provider-Key","secretRef":"secret/provider"}`
  applies one configured credential header.
- `{"type":"basic","username":"provider-user","secretRef":"secret/provider"}`
  applies HTTP Basic authentication. The username is visible ASCII without a
  space, control byte, or colon; the referenced secret is the password.
- `{"type":"headers","headers":[...]}` applies between one and eight
  independently referenced credential headers. Header names must be unique
  ignoring case.

Basic and header credentials are decrypted only inside synchronous secret-use
callbacks. Multi-header authentication nests those callbacks so every required
value remains available through the single request, response consumption, and
response close. Values never enter configuration snapshots, target-cache keys,
read APIs, logs, or asynchronous work. Authentication headers cannot collide
with static headers, Latchway control fields, protocol-owned fields, forwarding
fields, or hop-by-hop fields.

## Request bounds

`maxRequestHeaderBytes` is an optional route-level limit up to 32 KiB. It is
checked before provider rewriting and quota reservation over a deterministic
canonical representation of the parsed fields. It includes `Host`, a positive
`Content-Length`, every value of every header, all Latchway control fields, and
client authorization/proof fields. Ambiguous explicit `Host` or
`Content-Length`, malformed names or values, and over-limit requests fail as
`request_invalid` before target acquisition.

`maxRequestBodyBytes` is an optional route-level limit up to 100 MiB. It is
checked against the exact body after the selected protocol adapter has replaced
the client model, applied the output bound, and installed any required provider
fields. It therefore cannot be bypassed by a small client body that expands
during rewriting. Every fallback or retry is checked again against its selected
route and physical model.

These route values can only narrow the server's 32 KiB parsed-header boundary,
the protocol adapter's configured request-body boundary, and protocol-specific
shape limits. They do not enlarge an ingress or adapter limit.

## Timeout stages

Upstream defaults are:

| Field | Default | Stage |
| --- | ---: | --- |
| `connect` | 5s | DNS-pinned TCP connection and TLS handshake |
| `responseHeader` | 30s | request dispatch until valid response headers |
| `firstByte` | 30s | response headers until the first response-body byte |
| `idle` | 1m | gap between later response-body reads |
| `total` | 2m | complete physical attempt |

Every stage is positive and no longer than `total`; `total` cannot exceed ten
minutes. A route may provide a non-empty partial `timeouts` object. Its fields
overlay the referenced upstream, and the compiler stores the fully effective
route value. The resolver applies that value to the selected target, including
on retry and fallback.

`timeout_before_headers` covers connect, TLS, and response-header timeouts.
`first_byte_timeout` covers only the response-body first-byte stage.
`connect_error` covers a non-timeout dispatch failure. A route may list these
conditions in `fallbackOn` or `retryPolicy.retryOn`; Latchway never replays once
any response byte has reached the client. Restricted opaque HTTP routes also
require the method to be safely replayable under their explicit policy.

The HTTP server's ingress read and idle timeouts remain independent of these
selected upstream stages. Route timeouts cannot relax the server-wide ingress
deadlines.
