from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("finalize-release-profile.py")
SPEC = importlib.util.spec_from_file_location("latchway_finalize_release_profile", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SINGLE_TEST_PATH = Path(__file__).with_name("test_single_maintainer_release.py")
SINGLE_SPEC = importlib.util.spec_from_file_location(
    "latchway_finalize_profile_single_fixture", SINGLE_TEST_PATH
)
assert SINGLE_SPEC is not None and SINGLE_SPEC.loader is not None
SINGLE_FIXTURE = importlib.util.module_from_spec(SINGLE_SPEC)
sys.modules[SINGLE_SPEC.name] = SINGLE_FIXTURE
SINGLE_SPEC.loader.exec_module(SINGLE_FIXTURE)

DOMAIN_TEST_PATH = Path(__file__).with_name("test_release_domain_evidence.py")
DOMAIN_SPEC = importlib.util.spec_from_file_location(
    "latchway_finalize_profile_domain_fixture", DOMAIN_TEST_PATH
)
assert DOMAIN_SPEC is not None and DOMAIN_SPEC.loader is not None
DOMAIN_FIXTURE = importlib.util.module_from_spec(DOMAIN_SPEC)
sys.modules[DOMAIN_SPEC.name] = DOMAIN_FIXTURE
DOMAIN_SPEC.loader.exec_module(DOMAIN_FIXTURE)

def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FinalizeReleaseProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-profile-final-")
        self.root = Path(self.temporary.name)
        self.single = SINGLE_FIXTURE.SingleMaintainerReleaseTests(methodName="runTest")
        self.single.setUp()
        self.handoff = self.single.prepare()
        domain = DOMAIN_FIXTURE.EvidenceFixture(self.root / "source-fixture", "public_tags")
        self.source = domain.source
        self.source_document = json.loads(self.source.read_text(encoding="utf-8"))
        self.source_document["contract"]["released_at"] = "2026-08-29T00:00:00Z"
        write_json(self.source, self.source_document)
        self.external = self.root / "external"
        self.external.mkdir()

    def tearDown(self) -> None:
        self.single.tearDown()
        self.temporary.cleanup()

    def domain_document(self, domain: str, claims: list[str]) -> None:
        artifact = self.external / "artifacts" / domain / "receipt.json"
        write_json(artifact, {"domain": domain, "verified": True})
        candidate = json.loads(
            (self.handoff / "latchway-candidate.json").read_text(encoding="utf-8")
        )
        coordinates = {
            item["id"]: {
                "commit": item["commit"],
                "tag": item["intended_tag"],
                "version": item["version"],
            }
            for item in self.source_document["repositories"]
        }
        write_json(
            self.external / f"{domain}.json",
            {
                "schema_version": 1,
                "kind": "latchway_cross_repository_external_evidence",
                "domain": domain,
                "status": "passed",
                "started_at": "2026-08-29T11:40:00Z",
                "finished_at": "2026-08-29T11:41:00Z",
                "core_commit": SINGLE_FIXTURE.COMMIT,
                "core_release": "v1.0.0",
                "contract_version": "1.0.0",
                "bundle_sha256": candidate["contract"]["bundle_sha256"],
                "oci_image_digest": SINGLE_FIXTURE.IMAGE,
                "repositories": coordinates,
                "claims": {claim: True for claim in claims},
                "artifacts": [
                    {
                        "path": f"artifacts/{domain}/receipt.json",
                        "sha256": digest(artifact),
                    }
                ],
            },
        )

    def strict_release_report(self) -> Path:
        report = json.loads(json.dumps(self.source_document))
        report.update(
            {
                "scope": "release",
                "verdict": "failed",
                "source_conformance_passed": True,
                "promotion_ready": False,
                "release_ready": False,
                "evidence_window": None,
            }
        )
        report["contract"]["oci_image_digest"] = SINGLE_FIXTURE.IMAGE
        report["evidence_domains"] = [
            MODULE.expected_domain(identifier, self.external)
            for identifier in MODULE.STRICT_DOMAIN_ORDER
        ]
        source_checks = {
            item["id"]: item for item in self.source_document["checks"]
        }
        intended_tags = {
            item["id"]: item["intended_tag"]
            for item in self.source_document["repositories"]
        }
        checks = [
            source_checks[identifier] for identifier in MODULE.SOURCE_CHECK_ORDER
        ]
        checks.extend(
            (
                {
                    "id": "promotion.local_preconditions",
                    "domain": "local_promotion",
                    "required": True,
                    "status": "passed",
                    "summary": MODULE.CROSS.CHECK_SUMMARIES[
                        "promotion.local_preconditions"
                    ],
                    "details": {
                        "intended_tags": intended_tags,
                        "contract_released_at": self.source_document["contract"][
                            "released_at"
                        ],
                        "oci_image_digest": SINGLE_FIXTURE.IMAGE,
                    },
                },
                {
                    "id": "release.local_preconditions",
                    "domain": "local_release",
                    "required": True,
                    "status": "passed",
                    "summary": MODULE.CROSS.CHECK_SUMMARIES[
                        "release.local_preconditions"
                    ],
                    "details": {"tags": intended_tags, "annotated_tag_count": 5},
                },
            )
        )
        checks.extend(
            MODULE.expected_external_check(domain, self.external)
            for domain in MODULE.CROSS.EXTERNAL_DOMAINS
        )
        checks.append(
            {
                "id": "promotion.evidence_window",
                "domain": "local_promotion",
                "required": True,
                "status": "failed",
                "summary": MODULE.CROSS.CHECK_SUMMARIES[
                    "promotion.evidence_window"
                ],
                "reason": "prerequisite_evidence_failed",
            }
        )
        report["checks"] = checks
        path = self.root / MODULE.STRICT_REPORT_NAME
        write_json(path, report)
        return path

    def authority(self) -> tuple[Path, Path]:
        authenticated = self.root / "authenticated"
        shutil.copytree(self.handoff, authenticated / "core")
        shutil.copytree(self.source.parent, authenticated / "source-fixture")
        (authenticated / "source").mkdir()
        shutil.copyfile(self.source, authenticated / "source/latchway-cross-repository.json")
        for domain in ("public_tags", "public_registries", "supply_chain"):
            (authenticated / domain).mkdir()
            shutil.copyfile(
                self.external / f"{domain}.json",
                authenticated / domain / f"{domain}.json",
            )
            artifact = authenticated / domain / "artifacts" / domain / "receipt.json"
            artifact.parent.mkdir(parents=True)
            shutil.copyfile(
                self.external / "artifacts" / domain / "receipt.json", artifact
            )
        release_record = json.loads(
            (authenticated / "core/latchway-single-maintainer-v1.json").read_text(
                encoding="utf-8"
            )
        )
        runs = {
            "source_report": 101,
            "candidate": int(release_record["candidate_run"]["run_id"]),
            "core_release": 103,
            "public_tags": 104,
            "public_registries": 105,
            "supply_chain": 106,
        }
        inputs = {}
        for identifier, (workflow, relative) in MODULE.EXPECTED_INPUTS.items():
            path = authenticated / relative
            inputs[identifier] = {
                "workflow_path": workflow,
                "run_id": runs[identifier],
                "run_attempt": 1,
                "subject_path": relative,
                "sha256": digest(path),
            }
        authority = {
            "schema_version": 1,
            "kind": "latchway_single_maintainer_v1_authority",
            "profile": MODULE.PROFILE,
            "policy_id": MODULE.POLICY_ID,
            "candidate_commit": SINGLE_FIXTURE.COMMIT,
            "oci_image_digest": SINGLE_FIXTURE.IMAGE,
            "inputs": inputs,
        }
        path = authenticated / "authority.json"
        write_json(path, authority)
        return authenticated, path

    def prepared(self) -> tuple[object, Path]:
        for domain, claims in MODULE.PROFILE_EVALUATOR.SINGLE_MAINTAINER_REQUIRED_CLAIMS.items():
            self.domain_document(domain, list(claims))
        strict_report = self.strict_release_report()
        profile_report = self.root / MODULE.PROFILE_REPORT_NAME
        MODULE.derive_profile_report(
            type(
                "Arguments",
                (),
                {
                    "strict_release_report": strict_report,
                    "source_report": self.source,
                    "external_evidence_dir": self.external,
                    "output": profile_report,
                },
            )()
        )
        projection = MODULE.PROFILE_EVALUATOR.evaluate(
            MODULE.PROFILE, profile_report, self.external, SINGLE_FIXTURE.NOW
        )
        self.assertEqual(projection["status"], "passed", projection)
        projection_path = self.root / MODULE.PROFILE_EVALUATION_NAME
        write_json(projection_path, projection)
        authenticated, authority = self.authority()
        arguments = type(
            "Arguments",
            (),
            {
                "authority_manifest": authority,
                "authenticated_root": authenticated,
                "strict_release_report": strict_report,
                "profile_release_report": profile_report,
                "external_evidence_dir": self.external,
                "profile_evaluation": projection_path,
                "evaluation_time": SINGLE_FIXTURE.NOW,
            },
        )()
        return arguments, projection_path

    def test_cloud_deployments_remain_absent_and_deferred(self) -> None:
        arguments, _ = self.prepared()
        self.assertFalse((self.external / "cloud_deployments.json").exists())
        result = MODULE.finalize_profile(arguments)
        self.assertIn(
            "cloud_deployments",
            [item["id"] for item in result["deferred_evidence"]],
        )
        self.assertNotIn(
            "cloud_deployments",
            [item["id"] for item in result["required_gates"]],
        )

    def test_rejects_cloud_document_in_the_deferred_profile(self) -> None:
        arguments, _ = self.prepared()
        write_json(self.external / "cloud_deployments.json", {"claims": {}})
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "deferred_cloud_evidence_present"
        ):
            MODULE.finalize_profile(arguments)

    def test_finalizes_authenticated_profile_without_strict_claims(self) -> None:
        arguments, _ = self.prepared()
        result = MODULE.finalize_profile(arguments)
        self.assertTrue(result["publication_ready"])
        self.assertEqual(result["authentication_status"], "passed")
        self.assertEqual(result["status_claim"], MODULE.FINAL_STATUS_CLAIM)
        self.assertFalse(result["release_qualified"])
        self.assertFalse(result["fully_evidence_gated"])
        self.assertFalse(result["independently_reviewed"])
        self.assertTrue(result["deferred_evidence"])

    def test_profile_input_only_reclassifies_passed_local_preconditions(self) -> None:
        arguments, _ = self.prepared()
        strict = json.loads(arguments.strict_release_report.read_text(encoding="utf-8"))
        profile = json.loads(arguments.profile_release_report.read_text(encoding="utf-8"))
        promotion_check = next(
            item
            for item in strict["checks"]
            if item["id"] == "promotion.local_preconditions"
        )
        window_check = next(
            item
            for item in strict["checks"]
            if item["id"] == "promotion.evidence_window"
        )
        self.assertEqual(promotion_check["status"], "passed")
        self.assertEqual(
            (window_check["status"], window_check["reason"]),
            ("failed", "prerequisite_evidence_failed"),
        )
        promoted = next(
            item
            for item in profile["evidence_domains"]
            if item["id"] == "local_promotion"
        )
        self.assertEqual(promoted["status"], "passed")
        promoted["status"] = "failed"
        self.assertEqual(profile, strict)

    def test_fails_closed_on_authority_or_projection_substitution(self) -> None:
        arguments, projection = self.prepared()
        authority = json.loads(arguments.authority_manifest.read_text(encoding="utf-8"))
        original_authority = json.loads(json.dumps(authority))
        authority["inputs"]["public_registries"]["sha256"] = "f" * 64
        write_json(arguments.authority_manifest, authority)
        with self.assertRaisesRegex(MODULE.FinalizationError, "authority_input_hash_mismatch"):
            MODULE.finalize_profile(arguments)

        write_json(arguments.authority_manifest, original_authority)
        value = json.loads(projection.read_text(encoding="utf-8"))
        value["publication_ready"] = True
        write_json(projection, value)
        with self.assertRaisesRegex(MODULE.FinalizationError, "profile_evaluation_mismatch"):
            MODULE.finalize_profile(arguments)

    def test_rejects_external_document_not_bound_to_authenticated_subject(self) -> None:
        arguments, _ = self.prepared()
        document = json.loads(
            (self.external / "public_tags.json").read_text(encoding="utf-8")
        )
        document["finished_at"] = "2026-08-29T11:42:00Z"
        write_json(self.external / "public_tags.json", document)
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "external_evidence_authority_mismatch"
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_alternate_authority_manifest_path(self) -> None:
        arguments, _ = self.prepared()
        substituted = self.root / "substituted-authority.json"
        shutil.copyfile(arguments.authority_manifest, substituted)
        arguments.authority_manifest = substituted
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "authority_manifest_path_invalid"
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_strict_report_readiness_overstatement(self) -> None:
        arguments, _ = self.prepared()
        report = json.loads(
            arguments.strict_release_report.read_text(encoding="utf-8")
        )
        report["verdict"] = "passed"
        write_json(arguments.strict_release_report, report)
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "strict_release_report_semantics_invalid"
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_wrong_expected_evidence_window_failure(self) -> None:
        arguments, _ = self.prepared()
        report = json.loads(
            arguments.strict_release_report.read_text(encoding="utf-8")
        )
        window = next(
            item
            for item in report["checks"]
            if item["id"] == "promotion.evidence_window"
        )
        window["reason"] = "external_evidence_window_too_wide"
        write_json(arguments.strict_release_report, report)
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "strict_release_report_checks_invalid"
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_missing_or_modified_local_check(self) -> None:
        arguments, _ = self.prepared()
        report = json.loads(
            arguments.strict_release_report.read_text(encoding="utf-8")
        )
        report["checks"][0]["details"]["repository_count"] = 999
        write_json(arguments.strict_release_report, report)
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "strict_release_report_checks_invalid"
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_deferred_strict_domain_promoted_to_passed(self) -> None:
        arguments, _ = self.prepared()
        report = json.loads(
            arguments.strict_release_report.read_text(encoding="utf-8")
        )
        physical = next(
            item
            for item in report["evidence_domains"]
            if item["id"] == "physical_devices"
        )
        physical["status"] = "passed"
        write_json(arguments.strict_release_report, report)
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "strict_release_report_domains_invalid"
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_profile_report_with_any_extra_transformation(self) -> None:
        arguments, _ = self.prepared()
        report = json.loads(
            arguments.profile_release_report.read_text(encoding="utf-8")
        )
        report["promotion_ready"] = True
        write_json(arguments.profile_release_report, report)
        with self.assertRaisesRegex(
            MODULE.FinalizationError,
            "profile_release_report_transformation_invalid",
        ):
            MODULE.finalize_profile(arguments)

    def test_rejects_duplicate_key_in_candidate_controlled_json(self) -> None:
        arguments, _ = self.prepared()
        arguments.profile_evaluation.write_text(
            '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(MODULE.FinalizationError, "json_duplicate_member"):
            MODULE.finalize_profile(arguments)

    def test_rejects_non_v1_source_coordinates(self) -> None:
        report = json.loads(json.dumps(self.source_document))
        report["contract"]["version"] = "1.0.1"
        report["contract"]["core_release"] = "v1.0.1"
        report["contract"]["bundle_file_name"] = "latchway-contract-1.0.1.tar.gz"
        for repository in report["repositories"]:
            repository["version"] = "1.0.1"
            repository["intended_tag"] = "v1.0.1"
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "v1_release_coordinates_invalid"
        ):
            MODULE.validate_source_report(report)

    def test_rejects_core_handoff_not_bound_to_authority_candidate_run(self) -> None:
        arguments, _ = self.prepared()
        authority = json.loads(arguments.authority_manifest.read_text(encoding="utf-8"))
        authority["inputs"]["candidate"]["run_id"] += 1
        write_json(arguments.authority_manifest, authority)
        with self.assertRaisesRegex(
            MODULE.FinalizationError, "release_record_identity_invalid"
        ):
            MODULE.finalize_profile(arguments)

    def test_finalize_cli_does_not_allow_a_backdated_evaluation_clock(self) -> None:
        arguments = [
            "finalize",
            "--authority-manifest",
            "authority.json",
            "--authenticated-root",
            "authenticated",
            "--strict-release-report",
            MODULE.STRICT_REPORT_NAME,
            "--profile-release-report",
            MODULE.PROFILE_REPORT_NAME,
            "--external-evidence-dir",
            "external",
            "--profile-evaluation",
            MODULE.PROFILE_EVALUATION_NAME,
            "--output",
            "final.json",
            "--evaluation-time",
            "2026-08-29T12:00:00Z",
        ]
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parser().parse_args(arguments)


if __name__ == "__main__":
    unittest.main()
