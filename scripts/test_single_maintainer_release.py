#!/usr/bin/env python3

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("single-maintainer-release.py")
SPEC = importlib.util.spec_from_file_location("single_maintainer_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)

COMMIT = "a" * 40
INDEX_DIGEST = "b" * 64
IMAGE = f"ghcr.io/latchway/latchway@sha256:{INDEX_DIGEST}"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class SingleMaintainerReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-single-release-")
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.make_candidate(self.candidate)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def make_candidate(root: Path) -> str:
        artifact_hashes: dict[str, str] = {}
        for name in release.CANDIDATE.ARTIFACT_NAMES:
            path = root / name
            if name.endswith("vulnerability.json") or name.endswith("license.json"):
                write_json(path, {"SchemaVersion": 2, "Results": []})
            elif name.endswith(".spdx.json"):
                write_json(
                    path,
                    {
                        "spdxVersion": "SPDX-2.3",
                        "SPDXID": "SPDXRef-DOCUMENT",
                        "documentNamespace": "https://latchway.dev/test/sbom",
                        "creationInfo": {"created": "2026-08-29T11:00:00Z"},
                        "packages": [{"SPDXID": "SPDXRef-Package", "name": "latchway"}],
                    },
                )
            else:
                path.write_bytes(b"contract")
            artifact_hashes[name] = sha256(path.read_bytes())
        manifest = {
            "schema_version": 1,
            "kind": "latchway_release_candidate",
            "status": "passed",
            "created_at": "2026-08-29T11:30:00Z",
            "candidate_commit": COMMIT,
            "intended_tag": "v1.0.0",
            "version": "1.0.0",
            "contract": {
                "version": "1.0.0",
                "status": "released",
                "released_at": "2026-08-29T10:00:00Z",
                "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                "bundle_sha256": artifact_hashes["latchway-contract.tar.gz"],
            },
            "image": {
                "repository": "ghcr.io/latchway/latchway",
                "index_digest": f"sha256:{INDEX_DIGEST}",
                "platforms": {
                    "linux/amd64": "sha256:" + "d" * 64,
                    "linux/arm64": "sha256:" + "e" * 64,
                },
            },
            "artifacts": [
                {"path": name, "sha256": artifact_hashes[name]}
                for name in release.CANDIDATE.ARTIFACT_NAMES
            ],
        }
        write_json(root / "latchway-candidate.json", manifest)
        write_json(root / "latchway-candidate.attestation.sigstore.json", {"bundle": "test"})
        return artifact_hashes["latchway-contract.tar.gz"]

    def arguments(self, output: Path | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            candidate_commit=COMMIT,
            candidate_run_id="555",
            candidate_run_attempt="1",
            candidate_dir=self.candidate,
            output_directory=output,
        )

    def verify_arguments(self, handoff: Path) -> argparse.Namespace:
        value = self.arguments()
        value.handoff_directory = handoff
        return value

    def prepare(self) -> Path:
        output = self.root / "handoff"
        release.prepare_handoff(self.arguments(output), NOW)
        return output

    @staticmethod
    def rewrite_checksum(handoff: Path, name: str) -> None:
        values = {}
        for line in (handoff / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, relative = line.split("  ", 1)
            values[relative] = digest
        values[name] = sha256((handoff / name).read_bytes())
        (handoff / "SHA256SUMS").write_text(
            "".join(f"{values[item]}  {item}\n" for item in sorted(values)),
            encoding="utf-8",
        )

    def test_round_trip_closes_candidate_and_defers_deployments(self) -> None:
        handoff = self.prepare()
        record = release.verify_handoff(self.verify_arguments(handoff), NOW)
        self.assertEqual(record["profile"], "single_maintainer_v1")
        self.assertEqual(record["profile_status"], "incomplete")
        self.assertEqual(
            record["claims"],
            {
                "release_qualified": False,
                "fully_evidence_gated": False,
                "independently_reviewed": False,
            },
        )
        self.assertEqual(record["deployment_evidence"], {})
        self.assertIn("cloud_deployments", record["deferred_evidence"])
        self.assertEqual(
            record["release_policy"],
            {
                "mode": "single_maintainer_v1",
                "independent_reviewer_required": False,
                "strict_full_controls_satisfied": False,
                "environment_policy_ids": release.PROFILE_ENVIRONMENT_POLICY_IDS,
            },
        )

    def test_rejects_high_vulnerability_before_handoff(self) -> None:
        write_json(
            self.candidate / "latchway-linux-amd64-vulnerability.json",
            {
                "SchemaVersion": 2,
                "Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}],
            },
        )
        manifest = json.loads(
            (self.candidate / "latchway-candidate.json").read_text(encoding="utf-8")
        )
        for item in manifest["artifacts"]:
            if item["path"] == "latchway-linux-amd64-vulnerability.json":
                item["sha256"] = sha256(
                    (self.candidate / item["path"]).read_bytes()
                )
        write_json(self.candidate / "latchway-candidate.json", manifest)
        with self.assertRaisesRegex(
            release.ReleaseError, "candidate_vulnerability_scan_invalid"
        ):
            release.prepare_handoff(self.arguments(self.root / "handoff"), NOW)

    def test_rejects_candidate_run_substitution(self) -> None:
        handoff = self.prepare()
        arguments = self.verify_arguments(handoff)
        arguments.candidate_run_id = "99999"
        with self.assertRaisesRegex(
            release.ReleaseError, "release_record_identity_invalid"
        ):
            release.verify_handoff(arguments, NOW)

    def test_rejects_recalculated_false_assurance_claim(self) -> None:
        handoff = self.prepare()
        path = handoff / "latchway-single-maintainer-v1.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["claims"]["release_qualified"] = True
        write_json(path, record)
        self.rewrite_checksum(handoff, path.name)
        with self.assertRaisesRegex(release.ReleaseError, "release_record_identity_invalid"):
            release.verify_handoff(self.verify_arguments(handoff), NOW)

    def test_rejects_recalculated_release_profile_policy(self) -> None:
        handoff = self.prepare()
        path = handoff / "latchway-single-maintainer-v1.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["release_policy"]["strict_full_controls_satisfied"] = True
        write_json(path, record)
        self.rewrite_checksum(handoff, path.name)
        with self.assertRaisesRegex(release.ReleaseError, "release_record_identity_invalid"):
            release.verify_handoff(self.verify_arguments(handoff), NOW)

    def test_rejects_extra_handoff_file(self) -> None:
        handoff = self.prepare()
        (handoff / "unreviewed.txt").write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(release.ReleaseError, "handoff_artifact_closure_invalid"):
            release.verify_handoff(self.verify_arguments(handoff), NOW)

    def test_rejects_legacy_deployment_asset(self) -> None:
        handoff = self.prepare()
        (handoff / "compose.tar.gz").write_bytes(b"legacy deployment evidence")
        with self.assertRaisesRegex(release.ReleaseError, "handoff_artifact_closure_invalid"):
            release.verify_handoff(self.verify_arguments(handoff), NOW)


if __name__ == "__main__":
    unittest.main()
