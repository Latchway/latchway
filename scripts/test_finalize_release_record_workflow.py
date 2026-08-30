#!/usr/bin/env python3

from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/finalize-release-record.yml"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


class FinalizeReleaseRecordWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        value = yaml.safe_load(self.text)
        if not isinstance(value, dict):
            raise AssertionError("finalizer workflow must be a mapping")
        if True in value and "on" not in value:
            value["on"] = value.pop(True)
        self.workflow = value
        self.authority = value["jobs"]["authenticate-inputs"]
        self.immutable_settings = value["jobs"]["immutable-release-settings"]
        self.public_state = value["jobs"]["capture-public-state"]
        self.public_state_steps = self.public_state["steps"]
        self.public_state_names = [
            item.get("name", "") for item in self.public_state_steps
        ]
        self.prepare = value["jobs"]["prepare"]
        self.prepare_steps = self.prepare["steps"]
        self.prepare_names = [item.get("name", "") for item in self.prepare_steps]
        self.job = value["jobs"]["finalize"]
        self.steps = self.job["steps"]
        self.names = [item.get("name", "") for item in self.steps]

    def assert_credential_boundary(self, workflow: dict) -> None:
        jobs = workflow["jobs"]
        prepare = jobs["prepare"]
        self.assertEqual(prepare.get("permissions"), {})
        prepare_text = str(prepare)
        for credential_expression in (
            "${{ github.token }}",
            "${{github.token}}",
            "${{ secrets.",
            "${{secrets.",
        ):
            self.assertNotIn(credential_expression, prepare_text)

        names = [step.get("name", "") for step in prepare["steps"]]
        candidate_start = names.index(
            "Materialize authenticated candidate verification tooling without credentials"
        )
        for step in prepare["steps"][candidate_start:]:
            env = step.get("env", {})
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("GITHUB_TOKEN", env)
            serialized = str(step)
            self.assertNotIn("${{ github.token }}", serialized)
            self.assertNotIn("${{ secrets.", serialized)

        candidate_execution_markers = (
            "python3 scripts/",
            "python scripts/",
            "node scripts/",
            "bash scripts/",
            "./scripts/",
        )
        for name in (
            "authenticate-inputs",
            "immutable-release-settings",
            "capture-public-state",
            "finalize",
        ):
            job_text = str(jobs[name])
            for marker in candidate_execution_markers:
                self.assertNotIn(marker, job_text, name)
            self.assertNotIn("actions/checkout@", job_text, name)

    def test_is_protected_exact_candidate_postpublication_workflow(self) -> None:
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(self.job["environment"], "release")
        self.assertEqual(self.authority["environment"], "security-evidence")
        self.assertEqual(self.job["if"], "github.ref == 'refs/heads/main'")
        self.assertEqual(
            set(self.job["needs"]), {"authenticate-inputs", "prepare"}
        )
        self.assertEqual(
            set(self.prepare["needs"]),
            {
                "authenticate-inputs",
                "capture-public-state",
                "immutable-release-settings",
            },
        )
        self.assertEqual(self.public_state["needs"], "authenticate-inputs")
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            set(inputs),
            {
                "candidate_commit",
                "release_tag",
                "candidate_run_id",
                "candidate_run_attempt",
                "security_run_id",
                "security_run_attempt",
                "release_conformance_run_id",
                "release_conformance_run_attempt",
            },
        )
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', self.text)
        self.assertIn('.run_attempt == $attempt', self.text)
        self.assertIn('/actions/runs/$run_id/attempts/$run_attempt', self.text)
        for workflow in (
            ".github/workflows/release.yml",
            ".github/workflows/security.yml",
            ".github/workflows/cross-repository-conformance.yml",
        ):
            self.assertIn(workflow, self.text)
        promotion = yaml.safe_load(
            (WORKFLOW.parent / "promote-release.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.workflow["concurrency"]["group"],
            promotion["concurrency"]["group"],
        )
        self.assertFalse(self.workflow["concurrency"]["cancel-in-progress"])

    def test_attested_release_evidence_precedes_render_and_mutation(self) -> None:
        authority_names = [item.get("name", "") for item in self.authority["steps"]]
        immutable_names = [
            item.get("name", "") for item in self.immutable_settings["steps"]
        ]
        provenance = authority_names.index(
            "Authenticate every fixed evidence run and attempt without candidate code"
        )
        attestations = authority_names.index(
            "Verify all Latchway evidence and nested promotion attestations without candidate code"
        )
        public = self.public_state_names.index(
            "Capture and authenticate exact public tag release OCI and npm state"
        )
        handoff = self.prepare_names.index(
            "Validate the exact public-state handoff before candidate execution"
        )
        materialize = self.prepare_names.index(
            "Materialize authenticated candidate verification tooling without credentials"
        )
        recompute = self.prepare_names.index(
            "Recompute the candidate and security gates offline"
        )
        offline_public = self.prepare_names.index(
            "Validate the captured public state with candidate tooling offline"
        )
        durable = self.prepare_names.index(
            "Build deterministic durable release-evidence assets"
        )
        independent = self.names.index(
            "Independently recompute registry proof and verify the durable archive"
        )
        render = self.names.index(
            "Generate the canonical completion report without candidate tooling"
        )
        reconcile = self.names.index(
            "Reconcile any existing evidence-release completion attestation"
        )
        attest = self.names.index("Attest the exact final completion report when absent")
        checksums = self.names.index(
            "Create deterministic checksums for the complete evidence release"
        )
        preflight = self.names.index(
            "Preflight evidence tag draft and every fixed final asset before mutation"
        )
        publish = self.names.index(
            "Publish and verify the separate immutable final-evidence release"
        )
        self.assertLess(provenance, attestations)
        self.assertLess(
            public,
            self.public_state_names.index(
                "Seal the strict hash-bound public-state handoff"
            ),
        )
        self.assertLess(handoff, materialize)
        self.assertLess(materialize, recompute)
        self.assertLess(recompute, offline_public)
        self.assertLess(offline_public, durable)
        self.assertLess(independent, render)
        self.assertLess(reconcile, attest)
        self.assertLess(render, reconcile)
        self.assertLess(attest, checksums)
        self.assertLess(checksums, preflight)
        self.assertLess(preflight, publish)
        self.assertIn(
            "Preflight protected immutable-release settings without a checkout",
            immutable_names,
        )
        self.assertLess(
            attestations,
            authority_names.index(
                "Verify nested independent-review attestation on the credential-isolated runner"
            ),
        )
        self.assertIn("prepare", self.job["needs"])
        self.assertEqual(self.prepare["permissions"], {})
        self.assertEqual(self.job["permissions"]["id-token"], "write")
        for privileged in (
            self.authority,
            self.immutable_settings,
            self.public_state,
            self.prepare,
            self.job,
        ):
            self.assertFalse(
                any(
                    item.get("uses", "").startswith("actions/checkout@")
                    for item in privileged["steps"]
                ),
                privileged,
            )
        self.assertGreaterEqual(self.text.count("--deny-self-hosted-runners"), 7)
        self.assertGreaterEqual(self.text.count('--source-ref refs/heads/main'), 6)
        self.assertGreaterEqual(self.text.count('--source-digest "$CANDIDATE_COMMIT"'), 6)
        self.assertGreaterEqual(self.text.count('--signer-digest "$CANDIDATE_COMMIT"'), 6)
        immutable_script = self.immutable_settings["steps"][0]["run"]
        self.assertIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", self.text)
        self.assertEqual(
            immutable_script.count('"repos/$repository/immutable-releases"'), 1
        )
        self.assertIn('(keys | sort) == ["enabled", "enforced_by_owner"]', immutable_script)
        self.assertIn(".enabled == true", immutable_script)
        self.assertIn('(.enforced_by_owner | type) == "boolean"', immutable_script)
        self.assertIn("INDEPENDENT_SECURITY_REVIEW_TOKEN", str(self.authority))
        self.assertNotIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", str(self.job))
        self.assertIn(
            '--promotion-directory "$RUNNER_TEMP/security/promotion-conformance"',
            self.text,
        )
        self.assertIn(".promotion_conformance.repositories", self.text)
        self.assertIn(".review_authority.producer.repository", self.text)
        self.assertIn(
            "actions/runs/$promotion_run_id/attempts/$promotion_run_attempt",
            str(self.authority),
        )
        self.assertIn(".review_authority.reviewer", str(self.authority))
        self.assertNotIn("authenticated-inputs", str(self.job))
        self.assertNotIn("GITHUB_WORKSPACE", str(self.job))
        self.assert_credential_boundary(self.workflow)

    def test_public_state_authority_is_source_free_and_hash_bound(self) -> None:
        public_text = str(self.public_state)
        self.assertNotIn("GITHUB_WORKSPACE", public_text)
        self.assertNotIn("latchway.source.tar.gz", public_text)
        self.assertNotIn("latchway.git.tar.gz", public_text)
        self.assertNotIn("scripts/", public_text)
        self.assertIn("source_free", public_text)
        self.assertIn("file_count", public_text)
        self.assertIn("total_size", public_text)
        self.assertIn("sha256sum", public_text)
        self.assertEqual(
            self.authority["outputs"]["public_inputs_manifest_sha256"],
            "${{ steps.public-inputs.outputs.manifest_sha256 }}",
        )
        self.assertEqual(
            self.public_state["outputs"]["manifest_sha256"],
            "${{ steps.seal-public-state.outputs.manifest_sha256 }}",
        )
        self.assertIn(
            "needs.authenticate-inputs.outputs.public_inputs_manifest_sha256",
            public_text,
        )
        self.assertIn("actual-authority-input-files.txt", public_text)
        self.assertIn("expected-authority-input-files.txt", public_text)
        self.assertIn("public-state-authority-handoff", public_text)
        self.assertIn("latchway-finalizer-public-state-", public_text)
        self.assertIn("docker logout ghcr.io", public_text)
        self.assertIn("trap cleanup_registry EXIT", public_text)

        prepare_text = str(self.prepare)
        for network_command in (
            "gh api",
            "gh attestation",
            "gh release",
            "docker ",
            "npm ",
            "curl ",
            "wget ",
            "git fetch",
            "git clone",
        ):
            self.assertNotIn(network_command, prepare_text)
        for marker in (
            "latchway_finalizer_public_state_handoff",
            "expected-public-state-files.txt",
            "actual-public-state-files.txt",
            "stat --format=%s",
            "sha256sum",
            "source_free",
            "file_count == 9",
            "needs.capture-public-state.outputs.manifest_sha256",
        ):
            self.assertIn(marker, prepare_text)

    def test_credential_boundary_mutations_are_rejected(self) -> None:
        injected_token = deepcopy(self.workflow)
        steps = injected_token["jobs"]["prepare"]["steps"]
        target = next(
            step
            for step in steps
            if step.get("name")
            == "Validate the captured public state with candidate tooling offline"
        )
        target.setdefault("env", {})["GH_TOKEN"] = "${{ github.token }}"
        with self.assertRaises(AssertionError):
            self.assert_credential_boundary(injected_token)

        injected_permission = deepcopy(self.workflow)
        injected_permission["jobs"]["prepare"]["permissions"] = {
            "contents": "read"
        }
        with self.assertRaises(AssertionError):
            self.assert_credential_boundary(injected_permission)

        injected_candidate_execution = deepcopy(self.workflow)
        capture = injected_candidate_execution["jobs"]["capture-public-state"]
        capture["steps"][-1]["run"] = "python3 scripts/render-completion-report.py"
        with self.assertRaises(AssertionError):
            self.assert_credential_boundary(injected_candidate_execution)

    def test_public_coordinates_are_derived_and_independently_checked(self) -> None:
        for value in (
            'name: latchway-cross-repository-release',
            '.scope == "release"',
            '.release_ready == true',
            '.id == "public_tags" or .id == "public_registries"',
            'git/ref/tags/$RELEASE_TAG',
            '.object.type == "commit"',
            'releases/tags/$RELEASE_TAG',
            'docker buildx imagetools inspect --raw "$image"',
            'gh attestation verify "oci://$image"',
            'npm --userconfig=/dev/null view "@latchway/client@$javascript_version"',
            '._npmUser.trustedPublisher.id == "github"',
            '.dist.signatures | type == "array" and length > 0',
            '.dist.attestations.provenance.predicateType == "https://slsa.dev/provenance/v1"',
            '"dev.latchway:latchway-bom:" + $android',
            'scripts/verify-public-registry-proof.py',
            'latchway-public-registry-byte-proof.json',
            'latchway-release-evidence-v1.tar.gz',
            'latchway-product-release-attestation.json',
            '$RUNNER_TEMP/security/raw',
            '$RUNNER_TEMP/security/independent-review',
            '--review-directory "$RUNNER_TEMP/security/independent-review"',
            'latchway-release-evidence-v1',
            'evidence/$RELEASE_TAG',
            '.immutable == true',
            'gh release verify "$RELEASE_TAG"',
            "verify-github-release-attestation.py",
            "fixed-product-release-assets.txt",
            "expected-product-release-assets.txt",
            "release_attestation_sha256",
            "promotion_evidence_sha256",
            "assets: $release_assets",
            "Independently recompute registry proof and verify the durable archive",
            "Generate the canonical completion report without candidate tooling",
            "independently-recomputed-public-registry-proof.json",
            "candidate-produced registry proof differs from independent recomputation",
            "durable archive entry closure mismatch",
            "No checked-out candidate source or candidate-owned helper executed",
        ):
            self.assertIn(value, self.text)
        self.assertNotIn("registry_coordinates", self.workflow["on"]["workflow_dispatch"]["inputs"])

    def test_rerun_verifies_existing_bytes_and_never_clobbers(self) -> None:
        reconcile = self.steps[
            self.names.index(
                "Reconcile any existing evidence-release completion attestation"
            )
        ]["run"]
        preflight = self.steps[
            self.names.index(
                "Preflight evidence tag draft and every fixed final asset before mutation"
            )
        ]["run"]
        publish = self.steps[
            self.names.index(
                "Publish and verify the separate immutable final-evidence release"
            )
        ]["run"]
        for value in (
            'test "$existing" = "$expected"',
            "cmp --silent",
            "gh attestation verify",
            'echo "report_exists=true"',
            'echo "bundle_exists=true"',
            "attestation bundle exists without its report",
        ):
            self.assertIn(value, reconcile)
        for value in (
            "COMPLETION_REPORT.md",
            "COMPLETION_REPORT.attestation.sigstore.json",
            "latchway-cross-repository-release.json",
            "latchway-cross-repository-release.attestation.sigstore.json",
            "latchway-publication-state.json",
            "latchway-public-registry-byte-proof.json",
            "latchway-product-release-attestation.json",
            "latchway-release-evidence-v1.tar.gz",
            "SHA256SUMS",
            'test "$existing" = "$expected"',
            "cmp --silent",
            "fixed final release asset duplicated",
            "final-release-asset-plan.tsv",
        ):
            self.assertIn(value, preflight)
        self.assertEqual(preflight.count("gh release upload"), 0)
        self.assertIn("done < \"$plan\"", publish)
        self.assertIn('absent) gh release upload "$evidence_tag" "$asset"', publish)
        self.assertIn("final release asset missing or duplicated", publish)
        self.assertIn('gh release create "$evidence_tag" --draft', publish)
        self.assertIn("'{draft: false}'", publish)
        self.assertIn('.immutable == true', publish)
        self.assertIn('gh release verify "$evidence_tag"', publish)
        self.assertIn('gh release verify-asset "$evidence_tag"', publish)
        self.assertIn("pre-publish-evidence-tag-ref.json", publish)
        self.assertIn("pre-publish-final-evidence-assets.txt", publish)
        self.assertIn("expected-final-evidence-assets.txt", publish)
        self.assertIn("latchway_github_release_attestation_verification", publish)
        self.assertIn("evidence-release-statement.json", publish)
        self.assertIn(
            '.subject | type == "array" and length == (($r.assets | length) + 1)',
            publish,
        )
        self.assertIn('test("^sha256:[0-9a-f]{64}$")', publish)
        self.assertIn("If-None-Match:", publish)
        self.assertIn(
            'parse_snapshot "$RUNNER_TEMP/pre-publish-evidence-unchanged.http" 304',
            publish,
        )
        self.assertNotIn("python3 scripts/", str(self.job))
        self.assertIn("python3 -", str(self.job))
        self.assertNotIn("If-Match:", publish)
        self.assertNotIn('gh release upload "$RELEASE_TAG"', self.text)
        for forbidden in ("--clobber", "gh release delete", "git push --force", "continue-on-error"):
            self.assertNotIn(forbidden, self.text)

    def test_all_third_party_actions_are_commit_pinned(self) -> None:
        actions = [
            item["uses"]
            for job in self.workflow["jobs"].values()
            for item in job.get("steps", [])
            if "uses" in item
        ]
        self.assertTrue(actions)
        self.assertTrue(all(PINNED_ACTION.fullmatch(item) for item in actions), actions)

    def test_privileged_finalizer_uses_only_fixed_inline_validation_logic(self) -> None:
        job_text = str(self.job)
        self.assertNotIn("actions/checkout@", job_text)
        self.assertNotIn("GITHUB_WORKSPACE", job_text)
        self.assertNotIn("scripts/render-completion-report.py", job_text)
        self.assertNotIn("scripts/verify-public-registry-proof.py", job_text)
        self.assertIn("latchway-finalizer-public-inputs-", job_text)
        self.assertIn(
            "needs.authenticate-inputs.outputs.public_inputs_manifest_sha256",
            job_text,
        )
        independent = self.steps[
            self.names.index(
                "Independently recompute registry proof and verify the durable archive"
            )
        ]["run"]
        for marker in (
            "object_pairs_hook=strict_object",
            "parse_constant=lambda value: reject",
            "regular_tree(payload)",
            "set(declared) != set(payload_tree)",
            "set(aggregate_tree) != set(aggregate_hashes)",
            "aggregate-manifest.attestation.sigstore.json",
            "canonical_proof",
            "read_regular(prepared_proof, maximum=max_json) != canonical_proof",
            "security/promotion-conformance/",
            "member.uid != 0",
            "member.gid != 0",
            "member.mtime != 0",
            "stat.S_IMODE(member.mode) != 0o600",
            "seen_files != expected_file_names",
            "seen_directories != expected_directories",
        ):
            self.assertIn(marker, independent)
        source = independent.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        compile(source, "<fixed-finalizer-validator>", "exec")
        metadata = ROOT / "docs/release/final-report-metadata.json"
        expected_metadata_hash = hashlib.sha256(metadata.read_bytes()).hexdigest()
        self.assertIn(
            f'metadata_sha256 = "{expected_metadata_hash}"', independent
        )
        canonical = self.steps[
            self.names.index(
                "Generate the canonical completion report without candidate tooling"
            )
        ]["run"]
        self.assertIn("test ! -e \"$completion\"", canonical)
        self.assertIn("latchway_completion_report_v1", canonical)
        self.assertIn("install -m 0600", canonical)
        self.assertNotIn("scripts/", canonical)

    def test_fixed_inline_validator_accepts_exact_fixture_and_rejects_tampering(self) -> None:
        independent = self.steps[
            self.names.index(
                "Independently recompute registry proof and verify the durable archive"
            )
        ]["run"]
        source = independent.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        commit = "a" * 40
        tag = "v1.0.0"
        with tempfile.TemporaryDirectory(prefix="latchway-fixed-finalizer-") as raw:
            root = Path(raw)
            authority = root / "authority"
            payload = authority / "payload"

            def write(relative: str, data: bytes) -> None:
                path = payload / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            write("candidate/latchway-candidate.json", b'{"candidate":true}\n')
            write(
                "candidate/latchway-candidate.attestation.sigstore.json",
                b'{"attestation":"candidate"}\n',
            )
            write("security/security-summary.json", b'{"security":true}\n')
            write(
                "security/security-summary.attestation.sigstore.json",
                b'{"attestation":"security"}\n',
            )
            write("security/raw/gate.log", b"passed\n")
            write("security/independent-review/review.json", b'{"passed":true}\n')
            write(
                "security/promotion-conformance/promotion.json",
                b'{"scope":"promotion"}\n',
            )
            write(
                "conformance/latchway-cross-repository.json",
                b'{"scope":"release"}\n',
            )
            external = payload / "conformance/latchway-external-evidence"
            external.mkdir(parents=True)
            suffixes = {
                "oci": "artifacts--registry-oci--tool-output.json",
                "javascript": "artifacts--registry-npm-javascript--tool-output.json",
                "react_native": "artifacts--registry-npm-react-native--tool-output.json",
                "ios": "artifacts--registry-cocoapods--tool-output.json",
                "android": "artifacts--registry-maven-central--tool-output.json",
            }
            artifacts = []
            for name, suffix in suffixes.items():
                relative = f"retained/{name}-{suffix}"
                data = (json.dumps({"proof": name}, sort_keys=True) + "\n").encode()
                path = external / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                artifacts.append(
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
            registry = {
                "schema_version": 1,
                "kind": "latchway_cross_repository_external_evidence",
                "domain": "public_registries",
                "status": "passed",
                "core_commit": commit,
                "core_release": tag,
                "repositories": {},
                "claims": {"public_registry_bytes_verified": True},
                "artifacts": artifacts,
            }
            registry_bytes = (
                json.dumps(registry, indent=2, sort_keys=True) + "\n"
            ).encode()
            (external / "public_registries.json").write_bytes(registry_bytes)
            aggregate_file_paths = ["public_registries.json", *[item["path"] for item in artifacts]]
            aggregate_files = [
                {
                    "path": relative,
                    "sha256": hashlib.sha256((external / relative).read_bytes()).hexdigest(),
                }
                for relative in aggregate_file_paths
            ]
            aggregate = {
                "schema_version": 1,
                "kind": "latchway_external_evidence_aggregate",
                "scope": "release",
                "candidate_commit": commit,
                "domains": ["public_registries"],
                "identity": {"fixture": True},
                "files": aggregate_files,
            }
            (external / "aggregate-manifest.json").write_text(
                json.dumps(aggregate, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (external / "aggregate-manifest.attestation.sigstore.json").write_text(
                '{"attestation":"aggregate"}\n', encoding="utf-8"
            )
            payload_files = sorted(path for path in payload.rglob("*") if path.is_file())
            manifest_files = [
                {
                    "path": path.relative_to(payload).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in payload_files
            ]
            manifest = {
                "schema_version": 1,
                "kind": "latchway_finalizer_public_state_inputs",
                "source_free": True,
                "candidate_commit": commit,
                "release_tag": tag,
                "file_count": len(manifest_files),
                "total_size": sum(item["size"] for item in manifest_files),
                "files": manifest_files,
            }
            manifest_bytes = (
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            ).encode()
            (authority / "manifest.json").write_bytes(manifest_bytes)
            proof = {
                "schema_version": 1,
                "kind": "latchway_public_registry_byte_proof_verification",
                "candidate_commit": commit,
                "release_tag": tag,
                "status": "passed",
                "proofs": {
                    name: {"path": item["path"], "sha256": item["sha256"]}
                    for name, item in zip(suffixes, artifacts, strict=True)
                },
            }
            prepared = root / "prepared-proof.json"
            prepared.write_text(
                json.dumps(proof, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            archive_files: dict[str, bytes] = {
                "candidate/latchway-candidate.json": (
                    payload / "candidate/latchway-candidate.json"
                ).read_bytes(),
                "candidate/latchway-candidate.attestation.sigstore.json": (
                    payload / "candidate/latchway-candidate.attestation.sigstore.json"
                ).read_bytes(),
                "security/latchway-candidate.json": (
                    payload / "candidate/latchway-candidate.json"
                ).read_bytes(),
                "security/security-summary.json": (
                    payload / "security/security-summary.json"
                ).read_bytes(),
                "security/security-summary.attestation.sigstore.json": (
                    payload / "security/security-summary.attestation.sigstore.json"
                ).read_bytes(),
                "source/final-report-metadata.json": (
                    ROOT / "docs/release/final-report-metadata.json"
                ).read_bytes(),
            }
            for source_prefix, archive_prefix in (
                ("security/raw/", "security/raw/"),
                ("security/independent-review/", "security/independent-review/"),
                ("security/promotion-conformance/", "security/promotion-conformance/"),
                (
                    "conformance/latchway-external-evidence/",
                    "external/latchway-external-evidence/",
                ),
            ):
                for path in payload_files:
                    relative = path.relative_to(payload).as_posix()
                    if relative.startswith(source_prefix):
                        archive_files[
                            archive_prefix + relative.removeprefix(source_prefix)
                        ] = path.read_bytes()
            prefix = "latchway-release-evidence-v1"
            archive = root / "evidence.tar.gz"
            directories = {prefix}
            for relative in archive_files:
                for parent in Path(relative).parents:
                    if parent.as_posix() != ".":
                        directories.add(f"{prefix}/{parent.as_posix()}")
            with tarfile.open(
                archive, "w:gz", format=tarfile.USTAR_FORMAT
            ) as bundle:
                for directory in sorted(directories):
                    item = tarfile.TarInfo(f"{directory}/")
                    item.type = tarfile.DIRTYPE
                    item.mode = 0o700
                    item.uid = item.gid = item.mtime = 0
                    bundle.addfile(item)
                for relative, data in sorted(archive_files.items()):
                    item = tarfile.TarInfo(f"{prefix}/{relative}")
                    item.mode = 0o600
                    item.uid = item.gid = item.mtime = 0
                    item.size = len(data)
                    bundle.addfile(item, io.BytesIO(data))
            validator = root / "validator.py"
            validator.write_text(source, encoding="utf-8")
            recomputed = root / "recomputed.json"
            command = [
                sys.executable,
                str(validator),
                str(authority),
                str(archive),
                str(prepared),
                str(recomputed),
                commit,
                tag,
                hashlib.sha256(manifest_bytes).hexdigest(),
            ]
            accepted = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(recomputed.read_bytes(), prepared.read_bytes())
            recomputed.unlink()
            prepared.write_text('{"status":"passed"}\n', encoding="utf-8")
            rejected = subprocess.run(command, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "candidate-produced registry proof differs",
                rejected.stderr,
            )

    def test_two_release_model_is_documented(self) -> None:
        document = (ROOT / "docs/release/immutable-evidence-release.md").read_text(
            encoding="utf-8"
        )
        for value in (
            "`vX.Y.Z` is the product release",
            "`evidence/vX.Y.Z` is the final-evidence release",
            "draft",
            "immutable: true",
            "exact physical-device receipt/proof bytes",
        ):
            self.assertIn(value, document)
        final_record = (ROOT / "docs/release/final-release-record.md").read_text(
            encoding="utf-8"
        )
        for value in (
            "independently reconstructs the public-registry",
            "byte-identical",
            "durable tar archive without extracting it",
            "fixed inline workflow logic",
            "candidate-rendered Markdown is accepted by the publisher",
        ):
            self.assertIn(value, final_record)


if __name__ == "__main__":
    unittest.main()
