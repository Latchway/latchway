# Exact-candidate security evidence

The ordinary pull-request, protected-branch, and weekly jobs in
`.github/workflows/security.yml` are continuous feedback. Their logs are not
release evidence. A historical note that a reviewer found no P0-P2 issue is
also not evidence for a later commit.

The same workflow has manually dispatched candidate scan, authentication,
sealing, and attestation jobs. The scan job runs the fixed current-candidate
checks and uploads only raw evidence. A fresh protected runner authenticates
and snapshots the candidate, promotion conformance, and independent review
without checking out or executing candidate code. A second fresh runner has no
external-review credential or OIDC permission; it validates and seals the exact
snapshot against a clean candidate checkout. A final no-checkout runner alone
receives OIDC permission and attests only the fixed summary coordinates before
publishing the release evidence artifact. The jobs run only from
`refs/heads/main` and require the dispatch SHA and clean checkout `HEAD` to equal
the exact commit. The authentication job uses the protected
`security-evidence` environment. Configure that environment with required
reviewers before using the workflow for a release. Configure the final
no-checkout attestation job on the separately protected
`release-evidence-signing` environment as well; that environment contains no
review or provider credential.

## Candidate identity

The dispatch accepts only:

- the exact 40-character candidate commit;
- its intended semantic tag; and
- the numeric successful release-candidate workflow run ID and exact run
  attempt;
- the numeric successful promotion-scope cross-repository run ID and exact run
  attempt; and
- the numeric successful independent-review workflow run ID and exact run
  attempt.

The candidate artifact name is derived from the commit, run ID, and run
attempt. It is not supplied by the operator. The job queries the Actions API
and requires that exact attempt to be a completed successful
`workflow_dispatch` run of `.github/workflows/release.yml` on `main` at that
commit. It then verifies the retained candidate-manifest Sigstore bundle with
the exact repository, workflow, source digest, signer digest, protected-main
ref, and hosted-runner policy.

`scripts/security-evidence.py` revalidates every candidate-manifest artifact
hash. The resulting summary binds:

- the exact clean commit and Git tree;
- intended tag and version;
- released contract version, bundle name, and bundle SHA-256;
- OCI index digest and distinct `linux/amd64` and `linux/arm64` child digests;
- the SHA-256 of the attested promotion report and exact core, JavaScript, iOS,
  Android, and React Native commit/version/tag coordinates;
- both platform vulnerability reports; and
- both platform license reports.

Changing the manifest, contract bundle, image digest, platform digest, or a
candidate scan file makes finalization fail.

## Fixed current checks

The candidate workflow captures only the fixed source-controlled plan:

1. `govulncheck v1.1.4` in binary mode against a retained, exact-source,
   `CGO_ENABLED=0`, `-trimpath` build of `./cmd/latchway`;
2. `go vet ./...`;
3. the complete `make fuzz-smoke` target;
4. `go test -race -json -count=1 ./...` with PostgreSQL enabled;
5. Trivy source vulnerability, secret, and misconfiguration output;
6. Trivy source license output; and
7. the four hash-bound candidate image vulnerability/license reports.

Command invocations are selected by check ID inside the producer. There is no
generic command, claim, pass/fail, severity override, or uploaded result input.
Each command envelope binds the candidate commit, exact argv, tool/version,
fixed execution context, start and finish times, exit code, log name, and log
SHA-256. The Go vulnerability result additionally binds the exact package,
build argv, disabled CGO setting, binary scan mode, retained binary name, and
binary SHA-256. Retaining the binary lets finalization recompute the hash
instead of trusting an uploaded digest. Binary mode is required because the
pinned scanner can analyze Go 1.27 binaries while its source-package loader
cannot parse Go 1.27 source syntax. Fuzzing always uses the committed
three-second/two-worker smoke parameters; the race capture refuses to start
without the PostgreSQL test database. The finalizer
requires exit code zero and recomputes every hash. It rejects unknown, missing,
extra, symlinked, oversized, duplicate-key, stale, future, or cross-candidate
files. The evidence window starts after candidate creation, is at most seven
days, and must still be current when promotion recomputes it.

Trivy is asked to retain JSON with exit code zero so the source-controlled
finalizer—not action control flow—derives the policy result. Any current
`CRITICAL` or `HIGH` vulnerability, secret, failing misconfiguration, or
license finding rejects the report. Scanner details are never copied into the
redacted summary.

## Raw evidence and redaction

Successful finalization creates:

```text
security-final/
├── latchway-candidate.json
├── security-summary.json
├── security-summary.attestation.sigstore.json
├── independent-review/
│   ├── independent-security-review.json
│   ├── independent-security-review.attestation.sigstore.json
│   ├── producer-verification.json
│   ├── attestation-verification.json
│   └── reviews/
│       └── <eight-fixed-review-id>.json
├── promotion-conformance/
│   ├── latchway-cross-repository.json
│   ├── latchway-cross-repository.attestation.sigstore.json
│   ├── producer-verification.json
│   └── attestation-verification.json
└── raw/
    ├── scan-window.json
    ├── source-go-vulnerability.binary
    ├── source-*.result.json
    ├── source-*.log
    ├── source-trivy-*.json
    └── latchway-linux-*-{vulnerability,license}.json
```

The raw directory is retained from the protected environment and is hash-bound
by the summary. A run that fails before sealing still uploads a separately
named, run-specific protected raw diagnostic artifact; that artifact cannot be
substituted for the fixed successful artifact.

The deterministic summary contains only candidate coordinates, hashes, fixed
tool identities, zero blocked-finding counts, and derived statuses. It contains
no source snippets, scanner matches, test logs, absolute paths, environment
values, provider payloads, credentials, or user-authored claims. Rebuilding the
summary from identical inputs produces identical bytes.

## Independent review gate

The candidate workflow cannot manufacture or waive an independent assessment.
It requires the exact run ID and run attempt of an allowlisted workflow in a
separately controlled, non-Latchway GitHub repository. The protected
`security-evidence` environment supplies these values:

- `INDEPENDENT_SECURITY_REVIEW_REPOSITORY`;
- `INDEPENDENT_SECURITY_REVIEW_WORKFLOW`;
- `INDEPENDENT_SECURITY_REVIEWER_IDENTITY`;
- `INDEPENDENT_SECURITY_REVIEWER_ORGANIZATION`;
- `INDEPENDENT_SECURITY_REVIEWER_LOGIN`; and
- the `INDEPENDENT_SECURITY_REVIEW_TOKEN` secret, with read access only to the
  review workflow run, artifact, and attestation.

Absent settings, credentials, or artifacts fail the candidate security job.
The repository owner and reviewer organization must not be `Latchway`. The
workflow requires both the actor and triggering actor to equal the allowlisted
reviewer login, authenticates the exact successful hosted-run and attempt,
verifies the review report's Sigstore bundle against the allowlisted external
workflow and its exact source commit, and retains normalized run and
attestation verification records.

The report follows
[`independent-security-review.schema.json`](independent-security-review.schema.json)
and must contain exactly these eight review IDs:

- independent P0-P2 review;
- SSRF and cryptography review;
- App Attest and Play Integrity review;
- quota-race and Admin-auth review; and
- browser-XSS review.

Every review has an exact candidate commit, tag, version, contract bundle,
image index, `linux/amd64` and `linux/arm64` digest, promotion-report SHA-256,
and five-repository coordinate binding. The overall and per-review UTC windows
must start after both candidate creation and promotion evidence completion,
remain no more than seven days old, and span no more than seven days. Finding
totals and unresolved counts are retained for `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and
`INFORMATIONAL`; unresolved `CRITICAL` or `HIGH` findings fail closed. Every
unresolved `MEDIUM`, `LOW`, or `INFORMATIONAL` finding must have one
accepted-risk record with a review-scoped stable ID, severity, bounded summary,
and explicit acceptance rationale. The array must be sorted by ID and its
severity counts must exactly equal the unresolved finding counts; omitted or
generic count-only risk documentation fails closed.

The validator accepts no partial review set, extra JSON fields, duplicate keys,
non-finite values, secret-shaped keys or values, symlinks, unexpected files, or
files larger than four MiB. Each fixed per-review receipt, the report, Sigstore
bundle, and both normalized verification documents are SHA-256 bound into the
version 2 security summary. Sealing copies the exact validated bytes and
promotion recomputes every binding. Lower-severity findings and their accepted
risk rationales remain visible and are not reclassified as absent.

## Promotion gate

Promotion requires the successful security workflow run ID and exact run
attempt. Before any OCI tag, Git tag, release, or SDK dispatch is created,
promotion:

1. requires that exact attempt to be a successful dispatch of `security.yml`
   on main at the candidate commit;
2. downloads only
   `latchway-security-<candidate-commit>-<security-run-id>-<security-run-attempt>`;
3. verifies the summary attestation against the exact security workflow,
   source digest, signer digest, ref, repository, and hosted runner; and
4. reruns `security-evidence.py --verify` against the immutable candidate,
   retained raw directory, retained independent-review tree, retained promotion
   conformance tree, and clean candidate checkout. The promotion workflow also
   requires the security-bound report hash and all five coordinates to equal
   its own attested promotion report before mutation.

Stale or altered evidence cannot be reused for a later candidate.
The immutable product release publishes the redacted summary and its Sigstore
bundle. The scanner inputs, independent review material, and
promotion-conformance binding remain in the protected workflow artifact;
finalization copies all three into the deterministic durable evidence archive
before rendering the completion report.

## Local validator tests

Fixture tests do not claim that external scanners passed. They prove only the
producer/finalizer and workflow policy:

```bash
python3 -m unittest -v \
  scripts/test_security_evidence.py \
  scripts/test_security_workflow.py
```
