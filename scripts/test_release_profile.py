from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("release-profile.py")
SPEC = importlib.util.spec_from_file_location("latchway_release_profile", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ReleaseProfileTests(unittest.TestCase):
    now = datetime(2026, 9, 3, tzinfo=timezone.utc)
    image = "ghcr.io/latchway/latchway@sha256:" + "9" * 64
    bundle = "8" * 64

    def report(self, strict_pass: bool = False) -> dict[str, object]:
        repositories = []
        for index, identifier in enumerate(MODULE.CROSS.REPOSITORY_IDS, start=1):
            repositories.append(
                {
                    "id": identifier,
                    "commit": f"{index:x}" * 40,
                    "version": "1.0.0",
                    "intended_tag": "v1.0.0",
                }
            )
        domains = []
        for identifier in (
            *MODULE.LOCAL_DOMAINS,
            *MODULE.CROSS.EXTERNAL_DOMAINS,
        ):
            passed = identifier in MODULE.LOCAL_DOMAINS or strict_pass
            domains.append(
                {
                    "id": identifier,
                    "required": True,
                    "status": "passed" if passed else "unverified",
                    "started_at": "2026-09-02T01:00:00Z" if passed else None,
                    "finished_at": "2026-09-02T02:00:00Z" if passed else None,
                    "document_sha256": "7" * 64 if passed else None,
                    "oci_image_digest": self.image if passed else None,
                    "artifact_sha256": ["6" * 64] if passed else [],
                }
            )
        return {
            "schema_version": 1,
            "kind": "latchway_cross_repository_conformance_evidence",
            "scope": "release",
            "verdict": "passed" if strict_pass else "failed",
            "source_conformance_passed": True,
            "promotion_ready": strict_pass,
            "release_ready": strict_pass,
            "contract": {
                "version": "1.0.0",
                "status": "released",
                "released_at": "2026-09-02T00:00:00Z",
                "wire_protocol": 2,
                "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                "bundle_sha256": self.bundle,
                "core_release": "v1.0.0",
                "oci_image_digest": self.image,
            },
            "repositories": repositories,
            "documentation": {
                "repository": "https://github.com/Latchway/latchway-docs.git",
                "commit": None,
                "canonical_core_commit": None,
                "source_commit": None,
                "source_manifest_sha256": None,
                "source_tree_sha256": None,
                "owned_file_count": None,
            },
            "evidence_window": (
                {
                    "started_at": "2026-09-02T01:00:00Z",
                    "finished_at": "2026-09-02T02:00:00Z",
                    "maximum_age_seconds": 604800,
                }
                if strict_pass
                else None
            ),
            "evidence_domains": domains,
            "checks": [
                {
                    "id": "source.repository_layout",
                    "domain": "local_source",
                    "required": True,
                    "status": "passed",
                    "summary": "Source layout passed.",
                }
            ],
        }

    def write_report(self, root: Path, strict_pass: bool = False) -> Path:
        path = root / "release.json"
        path.write_text(json.dumps(self.report(strict_pass)), encoding="utf-8")
        return path

    def write_domain(
        self,
        root: Path,
        report: dict[str, object],
        domain: str,
        claims: list[str],
    ) -> None:
        artifact = root / "artifacts" / f"{domain}.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(domain, encoding="utf-8")
        repositories = {
            item["id"]: {
                "commit": item["commit"],
                "tag": item["intended_tag"],
                "version": item["version"],
            }
            for item in report["repositories"]  # type: ignore[index]
        }
        document = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_external_evidence",
            "domain": domain,
            "status": "passed",
            "started_at": "2026-09-02T01:00:00Z",
            "finished_at": "2026-09-02T02:00:00Z",
            "core_commit": repositories["core"]["commit"],
            "core_release": "v1.0.0",
            "contract_version": "1.0.0",
            "bundle_sha256": self.bundle,
            "oci_image_digest": self.image,
            "repositories": repositories,
            "claims": {claim: True for claim in claims},
            "artifacts": [
                {
                    "path": f"artifacts/{domain}.txt",
                    "sha256": hashlib.sha256(domain.encode()).hexdigest(),
                }
            ],
        }
        (root / f"{domain}.json").write_text(
            json.dumps(document), encoding="utf-8"
        )

    def single_fixture(self, root: Path) -> tuple[Path, Path]:
        report = self.report()
        report_path = root / "release.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        evidence = root / "evidence"
        evidence.mkdir()
        for domain, claims in MODULE.SINGLE_MAINTAINER_REQUIRED_CLAIMS.items():
            self.write_domain(evidence, report, domain, list(claims))
        return report_path, evidence

    def test_policy_preserves_strict_and_explicit_single_profiles(self) -> None:
        policy = MODULE.validate_policy()
        self.assertEqual(policy["default_profile"], "strict_full")
        self.assertTrue(
            policy["profiles"]["strict_full"]["requires_independent_human_review"]
        )
        self.assertFalse(
            policy["profiles"]["single_maintainer_v1"][
                "requires_independent_human_review"
            ]
        )

    def test_policy_rejects_weakening_strict_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = json.loads(MODULE.DEFAULT_POLICY.read_text(encoding="utf-8"))
            policy["profiles"]["strict_full"]["required_external_claims"][
                "supply_chain"
            ].pop()
            path = root / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ProfileError, "strict_full_profile_weakened"):
                MODULE.validate_policy(path)

    def test_single_maintainer_passes_only_structural_profile_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, evidence = self.single_fixture(Path(temporary))
            result = MODULE.evaluate(
                "single_maintainer_v1", report, evidence, self.now
            )
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["profile_requirements_satisfied"])
        self.assertEqual(result["authentication_status"], "not_performed")
        self.assertFalse(result["publication_ready"])
        self.assertEqual(
            result["status_claim"],
            "v1_profile_projection_passed_with_deferred_assurance",
        )
        self.assertFalse(result["strict_cross_repository_ready"])
        self.assertFalse(result["release_qualified"])
        self.assertEqual(
            result["forbidden_claims"],
            list(MODULE.SINGLE_MAINTAINER_FORBIDDEN_CLAIMS),
        )
        self.assertTrue(result["deferred_evidence"])
        self.assertTrue(
            all(item["status"] == "unverified" for item in result["deferred_evidence"])
        )

    def test_single_maintainer_defers_cloud_deployments_without_a_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, evidence = self.single_fixture(root)
            result = MODULE.evaluate(
                "single_maintainer_v1", report, evidence, self.now
            )
        self.assertEqual(result["status"], "passed")
        self.assertNotIn(
            "cloud_deployments", {item["id"] for item in result["required_gates"]}
        )
        cloud = next(
            item
            for item in result["deferred_evidence"]
            if item["id"] == "cloud_deployments"
        )
        self.assertEqual(cloud["status"], "unverified")

    def test_strict_profile_delegates_to_unchanged_canonical_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self.write_report(Path(temporary), strict_pass=True)
            result = MODULE.evaluate("strict_full", report, None, self.now)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["publication_ready"])
        self.assertTrue(result["strict_cross_repository_ready"])
        self.assertFalse(result["release_qualified"])


if __name__ == "__main__":
    unittest.main()
