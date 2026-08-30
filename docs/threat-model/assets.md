# Protected assets

| Asset | Required protection | Prohibited exposure |
| --- | --- | --- |
| Provider credentials | Confidentiality, integrity, rotation, tenant binding | Client responses, logs, audit payloads, process arguments, diagnostics |
| Environment master key | Confidentiality and availability outside the database | Persistence by Latchway, API access, logs, crash reports |
| Gateway signing private keys | Confidentiality, controlled rotation, issuer binding | JWKS, database plaintext, client bundles |
| Installation DPoP private keys | Non-exportability where platform permits | Server receipt, diagnostics, backup to insecure storage |
| Refresh tokens | Confidentiality, one-time rotation and reuse detection | Plaintext database or logs, replay after rotation |
| Access tokens and proofs | Short-lived confidentiality and replay resistance | Persistent raw request records or analytics |
| External identity credentials | Verification and minimal retention | Complete token persistence or unconfigured claims |
| External subject | Pseudonymous deterministic lookup | Raw value in routine database access or telemetry |
| Attestation evidence | Integrity, challenge binding, size limits, minimal retention | Raw evidence in logs or general Admin API responses |
| Active configuration | Integrity, tenant isolation, atomicity and provenance | Silent overwrite, partial activation, secret material in revisions |
| Quota and usage state | Atomicity, idempotency and non-negative arithmetic | Client-controlled totals, double settlement, unbounded reservation |
| Audit trail | Completeness, actor attribution and secret redaction | Mutation without record, plaintext secrets in record |
| Request bodies and model output | Confidentiality and minimal collection | Storage or logging by default |
| Tenant metadata | Isolation and authorized access | Cross-organization enumeration |
| Availability | Bounded resource consumption and recoverable work | Unbounded body, header, stream, parser, job, or connection state |

Identifiers such as request IDs, internal user IDs, installation IDs, configuration revision IDs, and upstream-attempt IDs are not credentials, but remain tenant-scoped and must not be enumerable across authorization boundaries.
