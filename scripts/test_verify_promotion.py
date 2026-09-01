#!/usr/bin/env python3

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("verify-promotion.py")
SPEC = importlib.util.spec_from_file_location("verify_promotion", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifyPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-promotion-")
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        self.commit = "a" * 40
        self.candidate = {
            "schema_version": 1,
            "kind": "latchway_release_candidate",
            "status": "passed",
            "created_at": "2026-08-29T10:30:00Z",
            "candidate_commit": self.commit,
            "intended_tag": "v1.0.0",
            "version": "1.0.0",
            "contract": {
                "version": "1.0.0",
                "status": "released",
                "released_at": "2026-08-29T10:00:00Z",
                "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                "bundle_sha256": "b" * 64,
            },
            "image": {
                "repository": "ghcr.io/latchway/latchway",
                "index_digest": "sha256:" + "c" * 64,
                "platforms": {
                    "linux/amd64": "sha256:" + "d" * 64,
                    "linux/arm64": "sha256:" + "e" * 64,
                },
            },
            "artifacts": [],
        }
        repositories = []
        for index, repository_id in enumerate(MODULE.REPOSITORIES):
            version = "1.0.0" if repository_id == "core" else f"1.0.{index}"
            repositories.append(
                {
                    "id": repository_id,
                    "commit": self.commit if repository_id == "core" else f"{index + 1:x}" * 40,
                    "version": version,
                    "intended_tag": f"v{version}",
                }
            )
        self.report = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_conformance_evidence",
            "scope": "promotion",
            "verdict": "passed",
            "source_conformance_passed": True,
            "promotion_ready": True,
            "release_ready": False,
            "contract": {
                **self.candidate["contract"],
                "wire_protocol": 1,
                "core_release": "v1.0.0",
                "oci_image_digest": "ghcr.io/latchway/latchway@sha256:" + "c" * 64,
            },
            "repositories": repositories,
            "documentation": {
                "repository": "https://github.com/Latchway/latchway-docs.git",
                "commit": "f" * 40,
                "canonical_core_commit": self.commit,
                "source_commit": self.commit,
                "source_manifest_sha256": "1" * 64,
                "source_tree_sha256": "2" * 64,
                "owned_file_count": 308,
            },
            "evidence_window": {
                "started_at": "2026-08-29T10:40:00Z",
                "finished_at": "2026-08-29T11:40:00Z",
                "maximum_age_seconds": 604800,
            },
            "evidence_domains": [
                {"id": domain, "required": True, "status": "passed"}
                for domain in sorted(MODULE.PROMOTION_DOMAINS)
            ],
            "checks": [{"id": "all", "required": True, "status": "passed"}],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, value: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def verify(self, report: dict[str, object] | None = None, candidate: dict[str, object] | None = None) -> dict[str, str]:
        return MODULE.verify(
            self.write("report.json", report or self.report),
            self.write("candidate.json", candidate or self.candidate),
            expected_commit=self.commit,
            expected_tag="v1.0.0",
            now=self.now,
        )

    def test_accepts_exact_ready_promotion(self) -> None:
        result = self.verify()
        self.assertEqual(
            result["oci_image_digest"],
            "ghcr.io/latchway/latchway@sha256:" + "c" * 64,
        )
        self.assertEqual(result["react_native_intended_tag"], "v1.0.4")
        self.assertEqual(result["documentation_commit"], "f" * 40)

    def test_rejects_not_ready_or_failed_required_check(self) -> None:
        for mutation, code in (
            (("promotion_ready", False), "not_ready"),
            (("verdict", "failed"), "not_ready"),
        ):
            report = deepcopy(self.report)
            report[mutation[0]] = mutation[1]
            with self.subTest(field=mutation[0]):
                with self.assertRaisesRegex(MODULE.PromotionError, code):
                    self.verify(report=report)
        report = deepcopy(self.report)
        report["checks"][0]["status"] = "failed"
        with self.assertRaisesRegex(MODULE.PromotionError, "required_check_failed"):
            self.verify(report=report)

    def test_rejects_commit_tag_digest_or_bundle_substitution(self) -> None:
        mutations = (
            ("repositories", lambda value: value[0].update(commit="f" * 40), "core_coordinate"),
            ("contract", lambda value: value.update(core_release="v1.0.1"), "contract_invalid"),
            ("contract", lambda value: value.update(oci_image_digest="ghcr.io/latchway/latchway@sha256:" + "f" * 64), "contract_invalid"),
            ("contract", lambda value: value.update(bundle_sha256="f" * 64), "contract_candidate_mismatch"),
        )
        for field, mutate, code in mutations:
            report = deepcopy(self.report)
            mutate(report[field])
            with self.subTest(code=code):
                with self.assertRaisesRegex(MODULE.PromotionError, code):
                    self.verify(report=report)

    def test_rejects_missing_domain_and_future_window(self) -> None:
        report = deepcopy(self.report)
        report["evidence_domains"] = report["evidence_domains"][:-1]
        with self.assertRaisesRegex(MODULE.PromotionError, "domains_incomplete"):
            self.verify(report=report)
        report = deepcopy(self.report)
        report["evidence_window"]["finished_at"] = "2026-08-29T12:00:01Z"
        with self.assertRaisesRegex(MODULE.PromotionError, "evidence_window_invalid"):
            self.verify(report=report)


if __name__ == "__main__":
    unittest.main()
