# Trust boundaries

```text
 [Untrusted client process]
 identity token | public JWK | DPoP proof | attestation | AI request
                         |
                   Public TLS edge
                         |
       +-----------------v------------------+
       | Latchway API role                 |
       | parsing / identity / DPoP / policy|
       | quota reserve / proxy / metering  |
       +-------+--------------------+-------+
               |                    |
       SQL boundary          outbound HTTP boundary
               |                    |
       +-------v-------+      +-----v----------------+
       | PostgreSQL    |      | IdP / attestation   |
       | durable truth |      | DNS / AI upstreams  |
       +-------+-------+      +----------------------+
               |
       +-------v-------+
       | Worker role   |
       | recovery/jobs |
       +---------------+

 [Admin browser / CLI] -- authenticated Admin API --^
```

## Boundary rules

1. The client boundary accepts no trusted tenancy, identity, plan, trust level, route, upstream, price, or usage claim from headers or bodies.
2. The public HTTP boundary enforces method, path, content type, header/body limits, decompression policy, deadlines, and duplicate-header rejection before expensive work.
3. The SQL boundary uses parameterized queries, tenant ownership columns, least-privilege deployment credentials, transaction scopes that exclude upstream latency, and database uniqueness/locking for security invariants.
4. The outbound boundary permits only configured schemes, hosts, ports and path behavior after DNS/IP validation. Redirects are disabled or revalidated. Client credentials and hop-by-hop headers never cross it.
5. The control-plane boundary requires authenticated administrative identity, explicit capability checks, CSRF/origin protection for cookies, ETags for mutable drafts, audit records, and secret-redacted responses.
6. The process-role boundary must not change authorization semantics: API replicas and workers coordinate through PostgreSQL, and the `all` role is the same components co-located.
7. Cache state is an optimization, never an authorization source of truth after its bounded freshness or invalidation contract expires.

TLS termination outside the process is permitted only when the deployment provides authenticated, integrity-protected forwarding metadata and prevents direct access that could spoof it.
