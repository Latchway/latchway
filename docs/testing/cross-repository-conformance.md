# Cross-repository conformance and release evidence

`scripts/cross-repo-conformance.py` is the offline, fail-closed evidence
orchestrator for the core repository, all four SDK repositories, and the
generated Mintlify documentation repository. It reads
only local Git checkouts and an optional directory of independently produced
external evidence. It never fetches a default branch, queries a registry,
creates a tag, contacts a device or cloud, or publishes an artifact.

## Current status (2026-09-02)

The current candidate tuple binds core contract checkpoint
`437708fb56d45196720b5769f2f59b0ee51f521d`, reproducible bundle SHA-256
`14cd2d8ddc8c4b85b8ab002359b373772d599a4eaaa8e95b9b0b793c684215c6`,
JavaScript `01dfa223773c20fe3a31559116f16e31f757b94a`, Swift
`c0fac916836bcfbdbf7f6a81808036726589d563`, Android
`3e0a601fad28a5ccf6674472a473c4797a7b404d`, and React Native
`39fd86ef1f6f973953e4fd5d0057ae17cc035abb`. A clean six-repository source
report passed with canonical core commit
`8c3783133698d569652def30b1003bb67c6a10b9` and generated Mintlify mirror
commit `a99308cf8892a5a857ac15cc02474333e5b9482c`. The first attempt correctly
rejected an operational release-control schema placed under the contract-locked
`api/` tree; moving that schema beside its `.github` manifest restored exact
contract ancestry without changing the released checkpoint or bundle.

Branch synchronization is tracked independently as a delivery operation and
does not change the source report's meaning. No local version 1 tag exists.
Promotion and release scope have not passed, and no GitHub release, registry
artifact, package publication, production documentation deployment, or
protected external-domain receipt is claimed.

Offline/local device build, install, and launch may proceed when it does not
contact ngrok or a live provider and does not collect Apple App Attest evidence.
Starting or reusing ngrok, contacting a provider for device proof, collecting
live App Attest evidence, or producing a protected device receipt requires the
exact phrase `I authorize the scoped ngrok device proof.` The phrase was
supplied for a scoped run, but no tunnel, service, provider, App Attest, or
protected-device evidence was started or collected under it. The operator then
deferred App Intent/extension and physical Android/Google Play evidence.

## Evidence scopes

`source` scope proves local source alignment. It requires:

- six explicit, distinct, clean Git worktrees;
- every SDK `contract.lock` to name the same immutable core contract checkpoint,
  contract version, wire version, server range, core release label, and
  generated bundle SHA-256. The checkpoint must exist, be an ancestor of the
  candidate, and have no `api/` drift through the candidate commit;
- two fresh core bundle builds to be byte-identical, safe to extract, complete,
  internally checksummed, and byte-identical to the canonical `api/` sources;
- the DPoP, attestation-binding, and protocol fixtures in every SDK to be
  byte-identical to the bundle;
- core, JavaScript, Swift/CocoaPods, Android/Maven, and React Native package
  version declarations to agree with their public source constants; and
- each canonical SDK documentation bundle lock entry to name the exact clean
  JavaScript, Swift, Android, or React Native candidate commit and version;
- React Native's compatibility manifest and native/JavaScript coordinates to
  pin the exact local dependency commits and versions; and
- the `latchway-docs` mirror manifest to bind every generated file byte to an
  unchanged canonical `docs/public` tree and an exact core source commit.

A passing source report deliberately records release tags, public artifacts,
live SDK/server behavior, physical devices, a live provider, and cloud
deployments as `unverified`. Source alignment is necessary release input; it is
not a publication, runtime compatibility, or hardware-trust claim.

`promotion` scope is the prepublication gate. It repeats every source check and
additionally requires:

- a canonical intended core tag matching the core and console versions;
- released contract metadata, including a `released_at` no more than seven
  days old and not in the future, and the exact intended `core_release` in
  every SDK lock;
- release changelog entries and no tracked local build output or
  credential-shaped files, without requiring any tag to exist yet;
- one exact immutable candidate OCI digest supplied independently on the
  command line; and
- valid, artifact-hash-bound evidence for live SDK conformance, physical
  devices, the live provider, all cloud deployments, operational resilience,
  and supply-chain verification.

`release` scope is the postpublication gate. It repeats every promotion check
and additionally requires:

- annotated tags pointing to each exact local repository commit; and
- public-tag and public-registry evidence in addition to the six promotion
  domains.

An absent external document is `unverified` and release-blocking. A malformed,
wrong-commit, wrong-version, failed-claim, unsafe-path, or digest-mismatched
document is `failed`. The command never upgrades either result to a pass.

## Repository discovery and source run

The default workspace layout is the six sibling directories from the project
plan. Discovery is local and deterministic; no remote URL is followed:

```text
<workspace>/latchway
<workspace>/latchway-js
<workspace>/latchway-ios-sdk
<workspace>/latchway-android
<workspace>/latchway-react-native-sdk
<workspace>/latchway-docs
```

Run from any directory, naming the workspace and an output outside every source
checkout:

```bash
python3 latchway/scripts/cross-repo-conformance.py \
  --workspace-root /path/to/workspace \
  --scope source \
  --output /tmp/latchway-cross-repo-source.json
```

The JUnit report defaults to
`/tmp/latchway-cross-repo-source.json.junit.xml`. Use `--junit-output` to choose
another path. `--core-repo`, `--javascript-repo`, `--ios-repo`,
`--android-repo`, `--react-native-repo`, and `--documentation-repo` can replace
individual defaults.
Absolute developer paths are never written to either report.

The output must be outside all six repositories. This prevents evidence
creation from making a previously clean candidate dirty after the clean-tree
check.

## External promotion and release evidence

Promotion scope requires the six non-public documents below. Release scope
requires the same documents plus `public_tags.json` and
`public_registries.json`:

```text
external-evidence/
├── live_sdk_conformance.json
├── public_tags.json
├── public_registries.json
├── physical_devices.json
├── live_provider.json
├── cloud_deployments.json
├── operational_resilience.json
├── supply_chain.json
└── artifacts/
    └── ... bounded raw reports referenced by SHA-256 ...
```

Each JSON document has the exact following top-level shape:

```json
{
  "schema_version": 1,
  "kind": "latchway_cross_repository_external_evidence",
  "domain": "public_tags",
  "status": "passed",
  "started_at": "2026-08-29T00:00:00Z",
  "finished_at": "2026-08-29T00:10:00Z",
  "core_commit": "<40 lowercase hexadecimal characters>",
  "core_release": "v1.0.0",
  "contract_version": "1.0.0",
  "bundle_sha256": "<64 lowercase hexadecimal characters>",
  "oci_image_digest": "ghcr.io/latchway/latchway@sha256:<64 lowercase hexadecimal characters>",
  "repositories": {
    "core": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
    "javascript": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
    "ios": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
    "android": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"},
    "react_native": {"commit": "...", "tag": "v1.0.0", "version": "1.0.0"}
  },
  "claims": {
    "remote_annotated_tags_verified": true,
    "github_releases_verified": true
  },
  "artifacts": [
    {"path": "artifacts/public-tags.json", "sha256": "..."}
  ]
}
```

Repository tags and versions need not all be equal; they must equal the exact
coordinates derived from the five local candidates. The repository and draft
contract coordinates in this version-1 example use `1.0.0`.

For stable promotion, the lock's `core_commit` is a successor contract
checkpoint whose manifest is already `released`, whose fresh `released_at` is
inside the evidence window, and whose deterministic archive has been rebuilt.
It is not the earlier draft checkpoint and not a self-referential final
release-metadata commit. This preserves an acyclic chain: released contract
checkpoint → successor SDK locks/changelogs → final core documentation and
release-metadata candidate. The final candidate must retain byte-identical
`api/` sources and the same deterministic bundle hash as that released
checkpoint.

Documents are accepted only when their timestamps are ordered, start on or
after the contract's `released_at`, finish no later than the current time, and
are no more than seven days old. Each document and the common earliest-start
to latest-finish evidence window may span no more than seven days. Their
repository map must exactly match the candidates, all
domain-specific claims are present and literally `true`, and every referenced
regular file is inside the evidence directory with the declared SHA-256. Every
domain must name the independently supplied canonical immutable
`ghcr.io/latchway/latchway@sha256:...` image; a syntactically valid but
different digest is rejected.
Symlinks, traversal, duplicate artifacts, unknown fields, and oversized files
are rejected. The fixed claim names are defined beside `EXTERNAL_DOMAINS` in
the orchestrator and cover:

- all four SDKs and both React Native platforms against the exact released
  image, including DPoP, errors, refresh, revocation, streaming, quota, and
  protocol rejection;
- remote annotated tags and GitHub releases;
- the OCI digest, the ordered four-package JavaScript npm set, React Native npm,
  Swift/CocoaPods, Maven Central, and the source-bound production documentation
  deployment;
- production App Attest, Play-distributed Play Integrity, and both React Native
  device paths;
- bounded OpenRouter non-streaming/streaming, usage, clamping, and error proof;
  and
- Compose, Cloud Run, AWS, Fly.io, and Cloudflare Containers using the release
  image;
- v1 load targets, destructive live failure injection, multiple replicas,
  backup/restore, and released-version upgrade plus rollback; and
- the multi-architecture image, vulnerability and license scans, SBOM,
  signature, and provenance.

These documents must be exported by the responsible authenticated platform
workflows together with their raw reports. Hand-writing `status: passed` is not
platform evidence; the orchestrator only validates identity, completeness, and
artifact integrity so that evidence from another system cannot be silently
substituted.

The five release, provider, SDK, and publication documents that previously had
only this envelope validator now use the protected producer/finalizer described
in [`release-domain-evidence.md`](release-domain-evidence.md). It requires an
attested exact-workflow receipt over a complete fixed set of candidate-bound,
hash-bound machine results; it rejects claim booleans as input and retains all
redacted raw outputs. Missing external access remains an unverified release
gate rather than a locally manufactured pass.

The `operational_resilience.json` producer is
[`scripts/operational-resilience-evidence.py`](../../scripts/operational-resilience-evidence.py).
It is intentionally stricter than the generic domain-envelope validator: it
requires exact release-image load evidence, release-scope live failure and
replica evidence, an executed restore, and authenticated distinct-ancestor
prior-candidate application rollback against the candidate schema. See
[`operational-resilience-evidence.md`](operational-resilience-evidence.md).

Run the prepublication aggregation before creating tags or publishing:

```bash
python3 latchway/scripts/cross-repo-conformance.py \
  --workspace-root /path/to/workspace \
  --scope promotion \
  --release-tag v1.0.0 \
  --oci-image-digest ghcr.io/latchway/latchway@sha256:<64 lowercase hexadecimal characters> \
  --external-evidence-dir /path/to/external-evidence \
  --output /tmp/latchway-cross-repo-promotion.json
```

A passing promotion report has `promotion_ready: true` and
`release_ready: false`. After publication, run the final aggregation with all
eight documents:

```bash
python3 latchway/scripts/cross-repo-conformance.py \
  --workspace-root /path/to/workspace \
  --scope release \
  --release-tag v1.0.0 \
  --oci-image-digest ghcr.io/latchway/latchway@sha256:<64 lowercase hexadecimal characters> \
  --external-evidence-dir /path/to/external-evidence \
  --output /tmp/latchway-cross-repo-release.json
```

Exit status is zero only when every required check passes. JSON and JUnit are
still written when a verification check fails. CLI usage or evidence-write
errors use exit status 2.

Every report is validated before either output is written against the checked
out core's strict `api/release-evidence.schema.json`. The report binds the
contract status and release time, bundle name and hash, exact intended tag for
all five repositories, candidate OCI digest, per-domain document and artifact
hashes, and the common evidence window.

## Report safety and determinism

Reports contain repository IDs, public package versions, commits, release tags,
contract hashes, the generated documentation commit and canonical tree hashes,
fixed reason codes, claim names, artifact hashes, and counts.
They do not contain absolute paths, environment values, Git stderr, registry
credentials, attestation payloads, provider responses, device identifiers, or
cloud secrets. Dirty trees report only the repository ID and entry count, not
filenames.

For unchanged inputs, JSON and JUnit bytes are stable: no wall-clock time,
duration, host identity, temporary path, or output path is embedded. Files are
atomically written with mode `0600`.

## GitHub workflow

`.github/workflows/cross-repository-conformance.yml` is a read-only manual
workflow. Supply `scope` plus immutable `core_ref`, `javascript_ref`, `ios_ref`,
`android_ref`, `react_native_ref`, and `documentation_ref` values. Promotion and release scopes also
require `core_release_tag`, `candidate_oci_image_digest`, and the exact
`external_evidence_run_id` plus `external_evidence_run_attempt` of the protected
aggregate producer. The artifact name is derived from that run identity; it is
not an operator input. The `private-sibling-read` authority job resolves those
refs, fetches Git objects without creating a worktree, and seals credential-free
source archives. The current core repository is resolved with the job-scoped,
read-only workflow token; the fixed public SDK and documentation repositories
are read anonymously over HTTPS. A separate job runs this command with no
repository credential or OIDC permission. A fresh no-checkout job in the
protected `release-evidence-signing` environment validates the fixed report
coordinates before attesting the exact source, promotion, or release JSON
report with GitHub OIDC. Consumers of
source-scope evidence must verify the attestation against this exact workflow,
`refs/heads/main`, and the candidate source digest; the source report itself
neither needs nor claims an already-created tag. The workflow has no package,
registry, release, or deployment-environment mutation permission.

Sibling-source retrieval is deliberately anonymous. The authority job disables
Git credential helpers and interactive prompting, fetches only the fixed public
Latchway repository URLs over HTTPS, and fails closed if a requested ref cannot
be resolved. It validates every resolved commit and packages Git objects without
checking out or executing repository code. Private forks and mirrors are not a
supported input to this public-release workflow; they require a separately
reviewed workflow rather than a repository-read fallback credential.
Configure required reviewers on `release-evidence-signing`; it contains no
repository or provider secret.

The workflow does not dispatch SDK updates or publish releases. Those remain
separate, explicitly authorized operations after a passing evidence report.

## Test the orchestrator

```bash
python3 -m unittest -v scripts/test_cross_repo_conformance.py
```

The tests create six isolated Git repositories and cover a complete source
pass, byte determinism, dirty-tree redaction, lock/fixture drift, pre-tag
promotion, the six-versus-eight domain split, valid hash-bound release
evidence, artifact tamper, coordinate and OCI digest substitution,
pre-contract/future/stale timestamps, an over-wide aggregate window,
schema-before-write validation, and output-path safety.
