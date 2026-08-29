#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release-candidate.py")
SPEC = importlib.util.spec_from_file_location("release_candidate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-candidate-")
        self.root = Path(self.temporary.name)
        (self.root / "api").mkdir()
        (self.root / "web/console").mkdir(parents=True)
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        (self.root / "api/protocol-version.json").write_text(
            json.dumps(
                {
                    "contract_version": "1.0.0",
                    "contract_status": "released",
                    "released_at": "2026-08-29T10:00:00Z",
                    "bundle": {"file_name": "latchway-contract-1.0.0.tar.gz"},
                }
            ),
            encoding="utf-8",
        )
        (self.root / "web/console/package.json").write_text(
            json.dumps({"version": "1.0.0"}), encoding="utf-8"
        )
        self.artifacts: dict[str, Path] = {}
        for index, name in enumerate(MODULE.ARTIFACT_NAMES):
            path = self.root / name
            path.write_bytes(f"artifact-{index}".encode())
            self.artifacts[name] = path
        self.previous_root = MODULE.ROOT
        MODULE.ROOT = self.root

    def tearDown(self) -> None:
        MODULE.ROOT = self.previous_root
        self.temporary.cleanup()

    def build(self) -> dict[str, object]:
        return MODULE.build_manifest(
            commit="a" * 40,
            tag="v1.0.0",
            image="ghcr.io/latchway/latchway",
            index_digest="sha256:" + "1" * 64,
            platform_digests={
                "linux/amd64": "sha256:" + "2" * 64,
                "linux/arm64": "sha256:" + "3" * 64,
            },
            artifacts=self.artifacts,
            now=self.now,
        )

    def write(self, document: dict[str, object]) -> Path:
        path = self.root / "latchway-candidate.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def verify(self, path: Path) -> dict[str, object]:
        return MODULE.verify_manifest(
            path,
            expected_commit="a" * 40,
            expected_tag="v1.0.0",
            expected_image="ghcr.io/latchway/latchway",
            now=self.now,
        )

    def test_round_trip_binds_contract_image_platforms_and_artifacts(self) -> None:
        path = self.write(self.build())
        verified = self.verify(path)
        self.assertEqual(verified["candidate_commit"], "a" * 40)
        self.assertEqual(verified["image"]["index_digest"], "sha256:" + "1" * 64)

    def test_rejects_substituted_artifact(self) -> None:
        path = self.write(self.build())
        self.artifacts["latchway-contract.tar.gz"].write_bytes(b"substituted")
        with self.assertRaisesRegex(MODULE.CandidateError, "artifact_hash_mismatch"):
            self.verify(path)

    def test_rejects_wrong_commit_tag_and_image(self) -> None:
        path = self.write(self.build())
        for field, value, code in (
            ("candidate_commit", "b" * 40, "identity_mismatch"),
            ("intended_tag", "v1.0.1", "identity_mismatch"),
        ):
            with self.subTest(field=field):
                document = self.build()
                document[field] = value
                path = self.write(document)
                with self.assertRaisesRegex(MODULE.CandidateError, code):
                    self.verify(path)
        with self.assertRaisesRegex(MODULE.CandidateError, "image_repository_invalid"):
            MODULE.verify_manifest(
                path,
                expected_commit="a" * 40,
                expected_tag="v1.0.0",
                expected_image="docker.io/attacker/latchway",
                now=self.now,
            )

    def test_rejects_stale_candidate_and_future_contract(self) -> None:
        for created_at, released_at, code in (
            (self.now - timedelta(days=8), self.now - timedelta(days=9), "created_at_invalid"),
            (self.now, self.now + timedelta(seconds=1), "contract_invalid"),
        ):
            with self.subTest(code=code):
                document = self.build()
                document["created_at"] = created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                document["contract"]["released_at"] = released_at.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                path = self.write(document)
                with self.assertRaisesRegex(MODULE.CandidateError, code):
                    self.verify(path)

    def test_rejects_duplicate_platform_digest(self) -> None:
        with self.assertRaisesRegex(
            MODULE.CandidateError, "platform_digests_not_distinct"
        ):
            MODULE.build_manifest(
                commit="a" * 40,
                tag="v1.0.0",
                image="ghcr.io/latchway/latchway",
                index_digest="sha256:" + "1" * 64,
                platform_digests={
                    "linux/amd64": "sha256:" + "2" * 64,
                    "linux/arm64": "sha256:" + "2" * 64,
                },
                artifacts=self.artifacts,
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
