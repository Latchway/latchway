#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("release-domain-evidence.py")
SPEC = importlib.util.spec_from_file_location("release_domain_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceFixture:
    def __init__(self, root: Path, domain: str):
        self.root = root
        self.root.mkdir(parents=True)
        self.domain = domain
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        self.commit = "a" * 40
        self.bundle = hashlib.sha256(b"contract").hexdigest()
        self.image = "ghcr.io/latchway/latchway@sha256:" + "1" * 64
        self.source = root / "source.json"
        self.candidate_root = root / "candidate"
        self.candidate_root.mkdir()
        self.candidate = self.candidate_root / "latchway-candidate.json"
        self.raw = root / "raw"
        self.raw.mkdir()
        self.receipt = root / "receipt.json"
        self.source_bundle = root / "source-attestation.sigstore.json"
        self.candidate_bundle = root / "candidate-attestation.sigstore.json"
        self.receipt_bundle = root / "machine-attestation.sigstore.json"
        self._write_source()
        self._write_candidate()
        identity, _, _ = MODULE.identity_from_inputs(self.source, self.candidate, self.now)
        self.identity = identity
        self._write_results()
        for bundle in (self.source_bundle, self.candidate_bundle, self.receipt_bundle):
            self.write(bundle, {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"})

    @staticmethod
    def write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_source(self) -> None:
        checks = [
            {
                "id": identifier,
                "domain": "local_source",
                "required": True,
                "status": "passed",
                "summary": "verified source input",
                "details": {"verified": True},
            }
            for identifier in sorted(MODULE.COMMON.SOURCE_CHECK_IDS)
        ]
        checks.extend(
            {
                "id": identifier,
                "domain": domain,
                "required": False,
                "status": "unverified",
                "summary": "not required by source scope",
                "reason": reason,
            }
            for identifier, (domain, reason) in sorted(
                MODULE.COMMON.SOURCE_UNVERIFIED_CHECKS.items()
            )
        )
        repositories = [
            {
                "id": identifier,
                "commit": self.commit if identifier == "core" else chr(98 + index) * 40,
                "version": "1.0.0",
                "intended_tag": "v1.0.0",
            }
            for index, identifier in enumerate(MODULE.COMMON.REPOSITORY_IDS)
        ]
        self.write(
            self.source,
            {
                "schema_version": 1,
                "kind": "latchway_cross_repository_conformance_evidence",
                "scope": "source",
                "verdict": "passed",
                "source_conformance_passed": True,
                "promotion_ready": False,
                "release_ready": False,
                "contract": {
                    "version": "1.0.0",
                    "status": "released",
                    "released_at": "2026-08-29T10:00:00Z",
                    "wire_protocol": 1,
                    "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                    "bundle_sha256": self.bundle,
                    "core_release": "v1.0.0",
                    "oci_image_digest": None,
                },
                "repositories": repositories,
                "documentation": {
                    "repository": "https://github.com/Latchway/latchway-docs.git",
                    "commit": "8" * 40,
                    "canonical_core_commit": self.commit,
                    "source_commit": self.commit,
                    "source_manifest_sha256": "9" * 64,
                    "source_tree_sha256": "a" * 64,
                    "owned_file_count": 308,
                },
                "evidence_window": None,
                "evidence_domains": [
                    {
                        "id": identifier,
                        "required": identifier == "local_source",
                        "status": "passed" if identifier == "local_source" else "unverified",
                        "started_at": None,
                        "finished_at": None,
                        "document_sha256": None,
                        "oci_image_digest": None,
                        "artifact_sha256": [],
                    }
                    for identifier in sorted(MODULE.COMMON.SOURCE_DOMAIN_IDS)
                ],
                "checks": checks,
            },
        )

    def _write_candidate(self) -> None:
        for index, name in enumerate(sorted(MODULE.COMMON.CANDIDATE_ARTIFACTS)):
            payload = b"contract" if name == "latchway-contract.tar.gz" else f"candidate-{index}".encode()
            (self.candidate_root / name).write_bytes(payload)
        entries = [
            {"path": name, "sha256": self.digest(self.candidate_root / name)}
            for name in sorted(MODULE.COMMON.CANDIDATE_ARTIFACTS)
        ]
        self.write(
            self.candidate,
            {
                "schema_version": 1,
                "kind": "latchway_release_candidate",
                "status": "passed",
                "created_at": "2026-08-29T10:05:00Z",
                "candidate_commit": self.commit,
                "intended_tag": "v1.0.0",
                "version": "1.0.0",
                "contract": {
                    "version": "1.0.0",
                    "status": "released",
                    "released_at": "2026-08-29T10:00:00Z",
                    "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                    "bundle_sha256": self.bundle,
                },
                "image": {
                    "repository": "ghcr.io/latchway/latchway",
                    "index_digest": "sha256:" + "1" * 64,
                    "platforms": {
                        "linux/amd64": "sha256:" + "2" * 64,
                        "linux/arm64": "sha256:" + "3" * 64,
                    },
                },
                "artifacts": entries,
            },
        )

    def _write_results(self) -> None:
        for index, observation in enumerate(MODULE.expected_observations(self.domain)):
            slug = observation.replace(".", "-")
            artifact = self.raw / "artifacts" / slug / "tool-output.json"
            self.write(artifact, {"records": index + 1, "tool": MODULE.OBSERVATION_TOOLS[observation]})
            result = {
                "schema_version": 1,
                "kind": "latchway_release_machine_result",
                "domain": self.domain,
                "observation": observation,
                "started_at": "2026-08-29T10:10:00Z",
                "finished_at": "2026-08-29T10:11:00Z",
                "candidate": self.identity,
                "tool": {
                    "name": MODULE.OBSERVATION_TOOLS[observation],
                    "version": "1.0.0",
                    "invocation_sha256": hashlib.sha256(observation.encode()).hexdigest(),
                },
                "exit_code": 0,
                "artifacts": [
                    {
                        "path": f"artifacts/{slug}/tool-output.json",
                        "sha256": self.digest(artifact),
                    }
                ],
            }
            self.write(self.raw / MODULE.result_name(observation), result)

    def produce(self) -> dict[str, object]:
        return MODULE.produce(
            domain=self.domain,
            source_path=self.source,
            candidate_path=self.candidate,
            raw_root=self.raw,
            receipt_path=self.receipt,
            now=self.now,
            context={
                "repository": MODULE.REPOSITORY,
                "workflow": MODULE.WORKFLOW,
                "run_id": "12345",
                "run_attempt": 1,
            },
        )

    def finalize(self, output_name: str = "output") -> dict[str, object]:
        if not self.receipt.exists():
            self.produce()
        return MODULE.finalize(
            domain=self.domain,
            source_path=self.source,
            candidate_path=self.candidate,
            raw_root=self.raw,
            receipt_path=self.receipt,
            receipt_bundle=self.receipt_bundle,
            source_bundle=self.source_bundle,
            candidate_bundle=self.candidate_bundle,
            output_root=self.root / output_name,
            now=self.now,
            verifier=lambda *args, **kwargs: [{"verified": True}],
        )


class ReleaseDomainEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-release-domain-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, domain: str = "live_provider") -> EvidenceFixture:
        return EvidenceFixture(self.root / domain, domain)

    @staticmethod
    def mutate(path: Path, operation) -> None:
        value = json.loads(path.read_text(encoding="utf-8"))
        operation(value)
        EvidenceFixture.write(path, value)

    def test_every_domain_derives_only_the_fixed_claims(self) -> None:
        for domain, requirements in MODULE.CLAIM_REQUIREMENTS.items():
            with self.subTest(domain=domain):
                fixture = self.fixture(domain)
                receipt = fixture.produce()
                self.assertNotIn("claims", receipt)
                self.assertNotIn("status", receipt)
                document = fixture.finalize()
                self.assertEqual(document["claims"], {claim: True for claim in requirements})
                self.assertEqual(document["core_commit"], fixture.commit)
                self.assertEqual(document["oci_image_digest"], fixture.image)
                output = fixture.root / "output"
                for artifact in document["artifacts"]:
                    self.assertEqual(
                        hashlib.sha256((output / artifact["path"]).read_bytes()).hexdigest(),
                        artifact["sha256"],
                    )

    def test_javascript_release_image_claim_requires_both_fixed_web_providers(self) -> None:
        requirements = MODULE.CLAIM_REQUIREMENTS["live_sdk_conformance"][
            "javascript_against_release_image"
        ]
        self.assertEqual(
            requirements,
            (
                "sdk.javascript.firebase-app-check.release-image",
                "sdk.javascript.turnstile.release-image",
            ),
        )
        fixture = self.fixture("live_sdk_conformance")
        missing = fixture.raw / MODULE.result_name(requirements[1])
        missing.unlink()
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "input_file_invalid"
        ):
            fixture.produce()

    def test_physical_receipt_envelope_survives_finalization_byte_for_byte(self) -> None:
        fixture = self.fixture("physical_devices")
        observation = MODULE.expected_observations(fixture.domain)[0]
        slug = observation.replace(".", "-")
        relative = f"artifacts/{slug}/physical-receipt.json"
        envelope = fixture.raw / relative
        payload = b'{"kind":"latchway_retained_physical_device_receipt","raw":"exact"}\n'
        envelope.write_bytes(payload)
        result_path = fixture.raw / MODULE.result_name(observation)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["artifacts"].append(
            {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
        )
        fixture.write(result_path, result)

        document = fixture.finalize()
        retained_relative = (
            "artifacts/physical-devices/"
            f"artifacts--{slug}--physical-receipt.json"
        )
        retained = fixture.root / "output" / retained_relative
        self.assertEqual(retained.read_bytes(), payload)
        entry = next(
            item for item in document["artifacts"] if item["path"] == retained_relative
        )
        self.assertEqual(entry["sha256"], hashlib.sha256(payload).hexdigest())

    def test_rejects_nonzero_machine_exit_and_self_asserted_fields(self) -> None:
        fixture = self.fixture()
        result = fixture.raw / MODULE.result_name(MODULE.expected_observations(fixture.domain)[0])
        self.mutate(result, lambda value: value.update(exit_code=1))
        with self.assertRaisesRegex(MODULE.EvidenceError, "result_identity_or_exit_invalid"):
            fixture.produce()

        fixture = EvidenceFixture(self.root / "asserted", "live_provider")
        result = fixture.raw / MODULE.result_name(MODULE.expected_observations(fixture.domain)[0])
        self.mutate(result, lambda value: value.update(claims={"anything": True}))
        with self.assertRaisesRegex(MODULE.EvidenceError, "self_asserted_result_rejected"):
            fixture.produce()

    def test_rejects_substitution_unknown_files_and_secret_shaped_output(self) -> None:
        fixture = self.fixture()
        result_path = fixture.raw / MODULE.result_name(MODULE.expected_observations(fixture.domain)[0])
        result = json.loads(result_path.read_text())
        artifact = fixture.raw / result["artifacts"][0]["path"]
        artifact.write_text('{"substituted":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(MODULE.EvidenceError, "result_artifact_hash_mismatch"):
            fixture.produce()

        fixture = EvidenceFixture(self.root / "unknown", "live_provider")
        (fixture.raw / "operator-note.txt").write_text("looks good\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.EvidenceError, "raw_directory_file_set_invalid"):
            fixture.produce()

        fixture = EvidenceFixture(self.root / "secret", "live_provider")
        result_path = fixture.raw / MODULE.result_name(MODULE.expected_observations(fixture.domain)[0])
        result = json.loads(result_path.read_text())
        artifact = fixture.raw / result["artifacts"][0]["path"]
        artifact.write_text('{"authorization":"Bearer abcdefghijklmnopqrstuvwxyz"}\n', encoding="utf-8")
        result["artifacts"][0]["sha256"] = fixture.digest(artifact)
        fixture.write(result_path, result)
        with self.assertRaisesRegex(MODULE.EvidenceError, "raw_result_contains_secret"):
            fixture.produce()

    def test_rejects_wrong_candidate_and_tampered_receipt(self) -> None:
        fixture = self.fixture()
        result = fixture.raw / MODULE.result_name(MODULE.expected_observations(fixture.domain)[0])
        self.mutate(result, lambda value: value["candidate"].update(core_commit="f" * 40))
        with self.assertRaisesRegex(MODULE.EvidenceError, "result_identity_or_exit_invalid"):
            fixture.produce()

        fixture = EvidenceFixture(self.root / "receipt-tamper", "live_provider")
        fixture.produce()
        self.mutate(fixture.receipt, lambda value: value["observations"][0].update(result_sha256="f" * 64))
        with self.assertRaisesRegex(MODULE.EvidenceError, "receipt_observations_mismatch"):
            fixture.finalize()

    def test_attestation_failure_is_release_blocking_and_leaves_no_output(self) -> None:
        fixture = self.fixture()
        fixture.produce()

        def reject(*args, **kwargs):
            raise MODULE.EvidenceError("github_attestation_invalid")

        with self.assertRaisesRegex(MODULE.EvidenceError, "github_attestation_invalid"):
            MODULE.finalize(
                domain=fixture.domain,
                source_path=fixture.source,
                candidate_path=fixture.candidate,
                raw_root=fixture.raw,
                receipt_path=fixture.receipt,
                receipt_bundle=fixture.receipt_bundle,
                source_bundle=fixture.source_bundle,
                candidate_bundle=fixture.candidate_bundle,
                output_root=fixture.root / "rejected-output",
                now=fixture.now,
                verifier=reject,
            )
        self.assertFalse((fixture.root / "rejected-output").exists())

    def test_producer_cli_requires_exact_protected_workflow_context(self) -> None:
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": MODULE.REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": f"{MODULE.REPOSITORY}/{MODULE.WORKFLOW}@refs/heads/main",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "LATCHWAY_RELEASE_EVIDENCE_ENVIRONMENT": "release-evidence",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual(MODULE.protected_context()["run_attempt"], 2)
        environment["GITHUB_REF"] = "refs/heads/feature"
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(MODULE.EvidenceError, "protected_workflow_required"):
                MODULE.protected_context()

    def test_attestation_verification_pins_workflow_ref_commit_and_hosted_runner(self) -> None:
        fixture = self.fixture()
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='[{"verificationResult":{"verified":true}}]', stderr=""
        )
        runner = mock.Mock(return_value=completed)
        with mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/gh"):
            verified = MODULE.verify_attestation(
                fixture.source,
                repository=MODULE.REPOSITORY,
                workflow=MODULE.SOURCE_WORKFLOW,
                source_digest=fixture.commit,
                bundle=None,
                runner=runner,
            )
        self.assertTrue(verified)
        command = runner.call_args.args[0]
        self.assertIn(f"{MODULE.REPOSITORY}/{MODULE.SOURCE_WORKFLOW}", command)
        self.assertIn(fixture.commit, command)
        self.assertEqual(command.count(fixture.commit), 2)
        self.assertIn("--signer-digest", command)
        self.assertIn("refs/heads/main", command)
        self.assertIn("--deny-self-hosted-runners", command)


if __name__ == "__main__":
    unittest.main()
