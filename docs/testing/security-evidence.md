# Exact-candidate security evidence

The ordinary pull-request, protected-branch, and weekly jobs in
`.github/workflows/security.yml` are continuous feedback. Their logs are not
release evidence. A historical note that a reviewer found no P0-P2 issue is
also not evidence for a later commit.

The same workflow has a separate, manually dispatched candidate job. It runs
only from `refs/heads/main`, checks out the exact dispatch commit, requires the
dispatch SHA and clean checkout `HEAD` to equal that commit, and uses the
protected `security-evidence` environment. Configure that environment with
required reviewers before using the job for a release.

## Candidate identity

The dispatch accepts only:

- the exact 40-character candidate commit;
- its intended semantic tag; and
- the numeric successful release-candidate workflow run ID.

The artifact name is derived from the commit. It is not supplied by the
operator. The job queries the Actions API and requires a completed successful
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
- both platform vulnerability reports; and
- both platform license reports.

Changing the manifest, contract bundle, image digest, platform digest, or a
candidate scan file makes finalization fail.

## Fixed current checks

The candidate workflow captures only the fixed source-controlled plan:

1. `govulncheck v1.1.4` against all source packages;
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
SHA-256. Fuzzing always uses the committed three-second/two-worker smoke
parameters; the race capture refuses to start without the PostgreSQL test
database. The finalizer
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
└── raw/
    ├── scan-window.json
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

## External review status

This automated gate does not manufacture an independent security assessment.
The summary explicitly records the following as `unavailable` with reason
`no_candidate_bound_protected_external_result`:

- independent P0-P2 review;
- SSRF and cryptography review;
- App Attest and Play Integrity review;
- quota-race and Admin-auth review; and
- browser-XSS review.

Therefore `automated_gate: passed` means only that the fixed candidate-current
automation passed. It is not a statement that those external observations ran,
that the candidate has no lower-severity risk, or that the entire v1 security
review is complete.

## Promotion gate

Promotion requires the successful security workflow run ID. Before any OCI
tag, Git tag, release, or SDK dispatch is created, promotion:

1. requires that run to be a successful dispatch of `security.yml` on main at
   the candidate commit;
2. downloads only `latchway-security-<candidate-commit>`;
3. verifies the summary attestation against the exact security workflow,
   source digest, signer digest, ref, repository, and hosted runner; and
4. reruns `security-evidence.py --verify` against the immutable candidate,
   retained raw directory, and clean candidate checkout.

Stale or altered evidence cannot be reused for a later candidate.
The immutable release publishes the redacted summary and its Sigstore bundle;
the raw scanner and command evidence remains in the protected workflow
artifact and is not added to the public release.

## Local validator tests

Fixture tests do not claim that external scanners passed. They prove only the
producer/finalizer and workflow policy:

```bash
python3 -m unittest -v \
  scripts/test_security_evidence.py \
  scripts/test_security_workflow.py
```
