# Security policy

## Supported versions

Latchway has not published a production release. Until the first supported
release, fixes are developed only on the default branch; source version strings
and release-candidate metadata do not create a support promise.

| Version or channel | Security support |
| --- | --- |
| Unreleased default branch | Receives security fixes; not production-supported |
| Tags, packages, and images | None published or supported yet |

The table will name supported release lines only after their immutable tags and
artifacts pass the documented release gate. Older lines become unsupported only
through a published policy update, never merely because a newer source commit
exists.

## Private vulnerability reporting

Do not disclose a suspected vulnerability in a public issue, discussion, pull request, chat transcript, or test fixture.

The intended official channel is GitHub's **Report a vulnerability** flow for
`github.com/Latchway/latchway`. It was verified as not yet enabled on
2026-09-01 and remains a publication blocker. Once the repository setting is
enabled and the private form is independently verified, use that flow and
include:

- affected commit or release;
- deployment and client platform;
- impact and realistic attack prerequisites;
- minimal reproduction steps or a private proof of concept;
- whether secrets, user identity, attestation, quotas, routing, or upstream traffic are exposed;
- any suggested remediation or coordinated-disclosure deadline.

Until that private form is enabled, do not send vulnerability details through
a public fallback. Contact a repository owner through an existing private
organization channel and request a draft security advisory before sending
technical material. The release gate must verify the private form; Latchway
does not advertise an unmonitored email address or an unescrowed encryption key
as a substitute.

Maintainers should acknowledge a complete report within three business days, establish severity and next steps within seven business days, and coordinate a fix and disclosure timeline with the reporter. These targets are not a promise of bounty or compensation.

## Sensitive data handling

Reports and diagnostic bundles must not include live provider keys, master keys, refresh tokens, identity tokens, DPoP private keys, App Attest evidence, Play Integrity payloads, or unredacted prompts. Use deterministic fixtures or revoke and rotate any accidentally disclosed credential immediately.

## Security model

The current security architecture and known validation gaps are documented under [`docs/threat-model/`](docs/threat-model/). No pre-1.0 checkout should be treated as production-ready without explicit evidence in the completion report.

Branch, pull-request, scheduled scan logs, and historical review notes are not
security evidence for a later release candidate. The protected exact-candidate
producer, retained raw-output contract, redacted summary, and promotion gate
are documented in
[`docs/testing/security-evidence.md`](docs/testing/security-evidence.md).
Its `automated_gate: passed` result does not claim that the explicitly
unavailable independent P0-P2, SSRF, cryptography, native-attestation,
Admin-auth, or browser-XSS reviews ran.
