#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("security-evidence.py")
SPEC = importlib.util.spec_from_file_location("latchway_security_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class SecurityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-security-")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.candidate = self.root / "candidate"
        self.raw = self.root / "raw"
        self.review = self.root / "review"
        self.promotion = self.root / "promotion"
        self.repository.mkdir()
        self.candidate.mkdir()
        self.raw.mkdir()
        self.review.mkdir()
        self.promotion.mkdir()
        (self.repository / "source.txt").write_text("exact source\n", encoding="utf-8")
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "Latchway Test")
        self.run_git("config", "user.email", "test@latchway.dev")
        self.run_git("add", "source.txt")
        self.run_git("commit", "-q", "-m", "fixture")
        self.commit = self.run_git("rev-parse", "HEAD").stdout.strip()
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        self.created_at = self.now - timedelta(hours=2)
        self.tag = "v1.0.0"
        self.review_repository = "ExternalSecurity/latchway-review"
        self.review_workflow = ".github/workflows/independent-security-review.yml"
        self.reviewer_identity = "urn:security-reviewer:example-audit-firm"
        self.reviewer_organization = "Example Audit Firm"
        self.reviewer_login = "example-auditor"
        self.review_run_id = 81234
        self.review_run_attempt = 2
        self.review_source_commit = "a" * 40
        self.promotion_run_id = 71234
        self.promotion_run_attempt = 3
        self.build_candidate()
        self.build_raw()
        self.build_promotion()
        self.build_review()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_published_review_schema_has_the_fixed_closed_review_set(self) -> None:
        schema_path = (
            SCRIPT.parents[1]
            / "docs/testing/independent-security-review.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["$defs"]["review_id"]["enum"]),
            set(MODULE.INDEPENDENT_REVIEWS),
        )
        self.assertEqual(schema["properties"]["reviews"]["minItems"], 8)
        self.assertEqual(schema["properties"]["reviews"]["maxItems"], 8)

    def run_git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("git", *arguments),
            cwd=self.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @property
    def candidate_manifest(self) -> Path:
        return self.candidate / "latchway-candidate.json"

    def write_json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def build_candidate(self) -> None:
        artifact_hashes: dict[str, str] = {}
        for index, name in enumerate(MODULE.CANDIDATE_ARTIFACTS):
            path = self.candidate / name
            if name.endswith("vulnerability.json") or name.endswith("license.json"):
                payload = json.dumps(
                    {"SchemaVersion": 2, "Results": []}, sort_keys=True
                ).encode() + b"\n"
            elif name.endswith(".spdx.json"):
                payload = json.dumps(
                    {"spdxVersion": "SPDX-2.3", "packages": [{"name": name}]},
                    sort_keys=True,
                ).encode() + b"\n"
            else:
                payload = f"contract-{index}\n".encode()
            path.write_bytes(payload)
            artifact_hashes[name] = digest(payload)
        manifest = {
            "schema_version": 1,
            "kind": "latchway_release_candidate",
            "status": "passed",
            "created_at": MODULE.canonical_time(self.created_at),
            "candidate_commit": self.commit,
            "intended_tag": self.tag,
            "version": "1.0.0",
            "contract": {
                "version": "1.0.0",
                "status": "released",
                "released_at": MODULE.canonical_time(
                    self.created_at - timedelta(hours=1)
                ),
                "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                "bundle_sha256": artifact_hashes["latchway-contract.tar.gz"],
            },
            "image": {
                "repository": MODULE.IMAGE_REPOSITORY,
                "index_digest": "sha256:" + "1" * 64,
                "platforms": {
                    "linux/amd64": "sha256:" + "2" * 64,
                    "linux/arm64": "sha256:" + "3" * 64,
                },
            },
            "artifacts": [
                {"path": name, "sha256": artifact_hashes[name]}
                for name in MODULE.CANDIDATE_ARTIFACTS
            ],
        }
        self.write_json(self.candidate_manifest, manifest)

    def build_raw(self) -> None:
        base = self.created_at + timedelta(minutes=5)
        for index, check in enumerate(MODULE.COMMAND_CHECKS):
            result_path, log_path = MODULE.command_paths(self.raw, check)
            log_path.write_bytes(f"{check.identifier} completed\n".encode())
            binary = None
            binary_path = MODULE.command_binary_path(self.raw, check)
            if binary_path is not None:
                binary_path.write_bytes(b"exact captured release binary\n")
                binary = {
                    "path": binary_path.name,
                    "sha256": MODULE.sha256_file(binary_path),
                }
            version = check.fixed_version
            if version is None:
                version = "go1.25.0" if check.tool == "go" else "GNU Make 3.81"
            result: dict[str, object] = {
                "schema_version": 1,
                "kind": "latchway_security_command_result",
                "check": check.identifier,
                "candidate_commit": self.commit,
                "started_at": MODULE.canonical_time(base + timedelta(minutes=index)),
                "finished_at": MODULE.canonical_time(
                    base + timedelta(minutes=index, seconds=30)
                ),
                "tool": {"name": check.tool, "version": version},
                "argv": list(check.argv),
                "execution_context": MODULE.command_execution_context(check),
                "exit_code": 0,
                "log": {"path": log_path.name, "sha256": MODULE.sha256_file(log_path)},
            }
            if binary is not None:
                result["binary"] = binary
            self.write_json(result_path, result)
        self.write_json(
            self.raw / "scan-window.json",
            {
                "schema_version": 1,
                "kind": "latchway_security_scan_window",
                "candidate_commit": self.commit,
                "started_at": MODULE.canonical_time(base + timedelta(minutes=10)),
                "finished_at": MODULE.canonical_time(base + timedelta(minutes=15)),
            },
        )
        self.write_json(
            self.raw / "source-trivy-policy.json",
            {"SchemaVersion": 2, "Results": []},
        )
        self.write_json(
            self.raw / "source-trivy-license.json",
            {"SchemaVersion": 2, "Results": []},
        )
        for _, filename, _, candidate_name in MODULE.TRIVY_CHECKS:
            if candidate_name is not None:
                (self.raw / filename).write_bytes((self.candidate / filename).read_bytes())

    def build_promotion(self) -> None:
        candidate = json.loads(self.candidate_manifest.read_text(encoding="utf-8"))
        repositories = [
            {
                "id": repository_id,
                "commit": self.commit if repository_id == "core" else str(index + 4) * 40,
                "version": "1.0.0",
                "intended_tag": "v1.0.0",
            }
            for index, repository_id in enumerate(MODULE.REPOSITORY_IDS)
        ]
        report = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_conformance_evidence",
            "scope": "promotion",
            "verdict": "passed",
            "source_conformance_passed": True,
            "promotion_ready": True,
            "release_ready": False,
            "contract": {
                "version": candidate["contract"]["version"],
                "status": candidate["contract"]["status"],
                "released_at": candidate["contract"]["released_at"],
                "wire_protocol": 1,
                "bundle_file_name": candidate["contract"]["bundle_file_name"],
                "bundle_sha256": candidate["contract"]["bundle_sha256"],
                "core_release": self.tag,
                "oci_image_digest": (
                    f"{candidate['image']['repository']}@"
                    f"{candidate['image']['index_digest']}"
                ),
            },
            "repositories": repositories,
            "documentation": {
                "repository": "https://github.com/Latchway/latchway-docs.git",
                "commit": "5" * 40,
                "canonical_core_commit": self.commit,
                "source_commit": self.commit,
                "source_manifest_sha256": "6" * 64,
                "source_tree_sha256": "7" * 64,
                "owned_file_count": 308,
            },
            "evidence_window": {
                "started_at": MODULE.canonical_time(
                    self.created_at + timedelta(minutes=10)
                ),
                "finished_at": MODULE.canonical_time(
                    self.created_at + timedelta(minutes=15)
                ),
                "maximum_age_seconds": int(MODULE.MAXIMUM_AGE.total_seconds()),
            },
            "evidence_domains": [],
            "checks": [],
        }
        report_path = self.promotion / MODULE.PROMOTION_REPORT_NAME
        self.write_json(report_path, report)
        self.write_json(
            self.promotion / MODULE.PROMOTION_BUNDLE_NAME,
            {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
        )
        self.write_json(
            self.promotion / MODULE.PROMOTION_PRODUCER_VERIFICATION_NAME,
            {
                "schema_version": 1,
                "kind": "latchway_security_promotion_conformance_producer_verification",
                "repository": "Latchway/latchway",
                "workflow_path": MODULE.PROMOTION_WORKFLOW,
                "run_id": self.promotion_run_id,
                "run_attempt": self.promotion_run_attempt,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "head_sha": self.commit,
                "head_branch": "main",
            },
        )
        self.write_json(
            self.promotion / MODULE.PROMOTION_ATTESTATION_VERIFICATION_NAME,
            {
                "schema_version": 1,
                "kind": "latchway_security_promotion_conformance_attestation_verification",
                "repository": "Latchway/latchway",
                "signer_workflow": f"Latchway/latchway/{MODULE.PROMOTION_WORKFLOW}",
                "source_digest": self.commit,
                "source_ref": "refs/heads/main",
                "subject_sha256": MODULE.sha256_file(report_path),
                "hosted_runner": True,
                "verified": True,
            },
        )

    def promotion_binding(self) -> dict[str, object]:
        report_path = self.promotion / MODULE.PROMOTION_REPORT_NAME
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return {
            "scope": "promotion",
            "run_id": self.promotion_run_id,
            "run_attempt": self.promotion_run_attempt,
            "report_sha256": MODULE.sha256_file(report_path),
            "repositories": report["repositories"],
            "documentation": report["documentation"],
        }

    def write_promotion_report(self, report: dict[str, object]) -> None:
        report_path = self.promotion / MODULE.PROMOTION_REPORT_NAME
        self.write_json(report_path, report)
        verification_path = (
            self.promotion / MODULE.PROMOTION_ATTESTATION_VERIFICATION_NAME
        )
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        verification["subject_sha256"] = MODULE.sha256_file(report_path)
        self.write_json(verification_path, verification)

    def finding_counts(self) -> dict[str, dict[str, int]]:
        return {
            "total": {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "informational": 4,
            },
            "unresolved": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 2,
                "informational": 4,
            },
        }

    def accepted_risks(
        self, identifier: str, counts: dict[str, dict[str, int]]
    ) -> list[dict[str, str]]:
        risks: list[dict[str, str]] = []
        for severity in ("medium", "low", "informational"):
            for index in range(counts["unresolved"][severity]):
                risks.append(
                    {
                        "id": f"{identifier}.{severity}-{index + 1}",
                        "severity": severity,
                        "summary": f"Retained {severity} test risk {index + 1}",
                        "acceptance_rationale": (
                            "The independent reviewer documented this bounded residual "
                            "risk for explicit release review."
                        ),
                    }
                )
        return sorted(risks, key=lambda risk: risk["id"])

    def build_review(self) -> None:
        reviews_directory = self.review / "reviews"
        reviews_directory.mkdir(exist_ok=True)
        reviewer = {
            "identity": self.reviewer_identity,
            "organization": self.reviewer_organization,
            "github_login": self.reviewer_login,
            "independent_from": "Latchway",
            "control": "separately_controlled",
        }
        review_started = self.created_at + timedelta(minutes=20)
        review_finished = self.created_at + timedelta(minutes=50)
        reviews: list[dict[str, object]] = []
        for index, identifier in enumerate(MODULE.INDEPENDENT_REVIEWS):
            started_at = review_started + timedelta(minutes=index * 2)
            finished_at = started_at + timedelta(minutes=1)
            counts = self.finding_counts()
            accepted_risks = self.accepted_risks(identifier, counts)
            receipt = {
                "schema_version": 1,
                "kind": "latchway_independent_security_review_result",
                "id": identifier,
                "status": "passed",
                "candidate_commit": self.commit,
                "reviewer": reviewer,
                "started_at": MODULE.canonical_time(started_at),
                "finished_at": MODULE.canonical_time(finished_at),
                "findings": counts,
                "accepted_risks": accepted_risks,
            }
            receipt_path = reviews_directory / f"{identifier}.json"
            self.write_json(receipt_path, receipt)
            reviews.append(
                {
                    "id": identifier,
                    "status": "passed",
                    "started_at": receipt["started_at"],
                    "finished_at": receipt["finished_at"],
                    "findings": counts,
                    "accepted_risks": accepted_risks,
                    "artifact": {
                        "path": f"reviews/{identifier}.json",
                        "sha256": MODULE.sha256_file(receipt_path),
                    },
                }
            )
        candidate = json.loads(self.candidate_manifest.read_text(encoding="utf-8"))
        report = {
            "schema_version": 1,
            "kind": "latchway_independent_security_review",
            "status": "passed",
            "review_window": {
                "started_at": MODULE.canonical_time(review_started),
                "finished_at": MODULE.canonical_time(review_finished),
                "maximum_age_seconds": int(MODULE.MAXIMUM_AGE.total_seconds()),
            },
            "candidate": {
                "commit": self.commit,
                "intended_tag": self.tag,
                "version": candidate["version"],
                "contract": {
                    "version": candidate["contract"]["version"],
                    "bundle_file_name": candidate["contract"]["bundle_file_name"],
                    "bundle_sha256": candidate["contract"]["bundle_sha256"],
                },
                "image": candidate["image"],
                "promotion_conformance": self.promotion_binding(),
            },
            "reviewer": reviewer,
            "producer": {
                "repository": self.review_repository,
                "workflow_path": self.review_workflow,
                "run_id": self.review_run_id,
                "run_attempt": self.review_run_attempt,
                "source_commit": self.review_source_commit,
            },
            "reviews": reviews,
        }
        report_path = self.review / MODULE.REVIEW_REPORT_NAME
        self.write_json(report_path, report)
        self.write_json(
            self.review / MODULE.REVIEW_BUNDLE_NAME,
            {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
        )
        self.write_json(
            self.review / MODULE.REVIEW_PRODUCER_VERIFICATION_NAME,
            {
                "schema_version": 1,
                "kind": "latchway_independent_security_review_producer_verification",
                "repository": self.review_repository,
                "workflow_path": self.review_workflow,
                "run_id": self.review_run_id,
                "run_attempt": self.review_run_attempt,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "head_sha": self.review_source_commit,
                "head_branch": "main",
                "actor_login": self.reviewer_login,
                "triggering_actor_login": self.reviewer_login,
            },
        )
        self.write_json(
            self.review / MODULE.REVIEW_ATTESTATION_VERIFICATION_NAME,
            {
                "schema_version": 1,
                "kind": "latchway_independent_security_review_attestation_verification",
                "repository": self.review_repository,
                "signer_workflow": f"{self.review_repository}/{self.review_workflow}",
                "source_digest": self.review_source_commit,
                "source_ref": "refs/heads/main",
                "subject_sha256": MODULE.sha256_file(report_path),
                "hosted_runner": True,
                "verified": True,
            },
        )

    def review_arguments(self) -> dict[str, object]:
        return {
            "review_directory": self.review,
            "promotion_directory": self.promotion,
            "expected_review_repository": self.review_repository,
            "expected_review_workflow": self.review_workflow,
            "expected_reviewer_identity": self.reviewer_identity,
            "expected_reviewer_organization": self.reviewer_organization,
            "expected_reviewer_login": self.reviewer_login,
            "expected_review_run_id": self.review_run_id,
            "expected_review_run_attempt": self.review_run_attempt,
            "expected_promotion_run_id": self.promotion_run_id,
            "expected_promotion_run_attempt": self.promotion_run_attempt,
        }

    def review_report(self) -> dict[str, object]:
        return json.loads(
            (self.review / MODULE.REVIEW_REPORT_NAME).read_text(encoding="utf-8")
        )

    def write_review_report(self, report: dict[str, object]) -> None:
        report_path = self.review / MODULE.REVIEW_REPORT_NAME
        self.write_json(report_path, report)
        verification_path = self.review / MODULE.REVIEW_ATTESTATION_VERIFICATION_NAME
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        verification["subject_sha256"] = MODULE.sha256_file(report_path)
        self.write_json(verification_path, verification)

    def derive(self, *, now: datetime | None = None) -> dict[str, object]:
        return MODULE.derive_summary(
            candidate_manifest=self.candidate_manifest,
            raw_directory=self.raw,
            **self.review_arguments(),
            repository=self.repository,
            expected_commit=self.commit,
            expected_tag=self.tag,
            now=now or self.now,
        )

    def seal(self, name: str = "sealed") -> tuple[Path, dict[str, object]]:
        output = self.root / name
        report = MODULE.seal(
            candidate_manifest=self.candidate_manifest,
            raw_directory=self.raw,
            **self.review_arguments(),
            repository=self.repository,
            expected_commit=self.commit,
            expected_tag=self.tag,
            output_directory=output,
            now=self.now,
        )
        return output, report

    def test_round_trip_binds_source_contract_image_and_current_raw(self) -> None:
        output, report = self.seal()
        verified = MODULE.verify(
            report=output / "security-summary.json",
            candidate_manifest=self.candidate_manifest,
            raw_directory=output / "raw",
            review_directory=output / "independent-review",
            promotion_directory=output / "promotion-conformance",
            repository=self.repository,
            expected_commit=self.commit,
            expected_tag=self.tag,
            now=self.now,
        )
        self.assertEqual(verified, report)
        self.assertEqual(report["automated_gate"], "passed")
        self.assertEqual(report["candidate"]["commit"], self.commit)
        self.assertEqual(
            report["candidate"]["contract"]["bundle_sha256"],
            MODULE.sha256_file(self.candidate / "latchway-contract.tar.gz"),
        )
        self.assertEqual(
            report["candidate"]["image"]["index_digest"], "sha256:" + "1" * 64
        )
        self.assertEqual(report["independent_review_gate"], "passed")
        self.assertEqual(
            {item["id"] for item in report["independent_reviews"]},
            set(MODULE.INDEPENDENT_REVIEWS),
        )
        serialized = (output / "security-summary.json").read_text(encoding="utf-8")
        self.assertNotIn("completed", serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_summary_is_deterministic_for_identical_inputs(self) -> None:
        first, _ = self.seal("first")
        second, _ = self.seal("second")
        self.assertEqual(
            (first / "security-summary.json").read_bytes(),
            (second / "security-summary.json").read_bytes(),
        )

    def test_rejects_dirty_wrong_or_changed_source(self) -> None:
        (self.repository / "dirty").write_text("untracked", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "repository_dirty"):
            self.derive()
        (self.repository / "dirty").unlink()
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "commit_mismatch"):
            MODULE.derive_summary(
                candidate_manifest=self.candidate_manifest,
                raw_directory=self.raw,
                **self.review_arguments(),
                repository=self.repository,
                expected_commit="f" * 40,
                expected_tag=self.tag,
                now=self.now,
            )

    def test_rejects_wrong_contract_image_tag_and_stale_candidate(self) -> None:
        cases = (
            ("contract", "bundle_sha256", "f" * 64, "contract_hash_mismatch"),
            ("image", "index_digest", "sha256:invalid", "candidate_image_invalid"),
        )
        for section, field, value, code in cases:
            with self.subTest(field=field):
                candidate = json.loads(self.candidate_manifest.read_text(encoding="utf-8"))
                candidate[section][field] = value
                self.write_json(self.candidate_manifest, candidate)
                with self.assertRaisesRegex(MODULE.SecurityEvidenceError, code):
                    self.derive()
                self.build_candidate()
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "identity_mismatch"):
            MODULE.derive_summary(
                candidate_manifest=self.candidate_manifest,
                raw_directory=self.raw,
                **self.review_arguments(),
                repository=self.repository,
                expected_commit=self.commit,
                expected_tag="v1.0.1",
                now=self.now,
            )
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "candidate_time_invalid"):
            self.derive(now=self.now + timedelta(days=8))

    def test_rejects_missing_extra_symlink_and_tampered_raw_files(self) -> None:
        target = self.raw / "source-trivy-license.json"
        original = target.read_bytes()
        target.unlink()
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "raw_file_set_invalid"):
            self.derive()
        target.write_bytes(original)
        (self.raw / "unexpected.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "raw_file_set_invalid"):
            self.derive()
        (self.raw / "unexpected.json").unlink()
        target.unlink()
        target.symlink_to(self.candidate / "latchway-linux-amd64-license.json")
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "raw_file_invalid"):
            self.derive()

    def test_rejects_missing_partial_and_extra_review_evidence(self) -> None:
        receipt = self.review / "reviews" / f"{MODULE.INDEPENDENT_REVIEWS[0]}.json"
        receipt.unlink()
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "review_file_set_invalid"):
            self.derive()

        self.build_review()
        report = self.review_report()
        report["reviews"] = report["reviews"][:-1]
        self.write_review_report(report)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "results_incomplete"):
            self.derive()

        self.build_review()
        (self.review / "unexpected.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "review_file_set_invalid"):
            self.derive()

    def test_rejects_symlinked_review_and_promotion_evidence(self) -> None:
        review_report = self.review / MODULE.REVIEW_REPORT_NAME
        review_report.unlink()
        review_report.symlink_to(self.review / MODULE.REVIEW_BUNDLE_NAME)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "review_file_invalid"):
            self.derive()

        review_report.unlink()
        self.build_review()
        promotion_report = self.promotion / MODULE.PROMOTION_REPORT_NAME
        promotion_report.unlink()
        promotion_report.symlink_to(self.promotion / MODULE.PROMOTION_BUNDLE_NAME)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "review_file_invalid"):
            self.derive()

    def test_rejects_stale_or_wrong_candidate_review(self) -> None:
        report = self.review_report()
        report["review_window"]["started_at"] = MODULE.canonical_time(
            self.now - timedelta(days=9)
        )
        report["review_window"]["finished_at"] = MODULE.canonical_time(
            self.now - timedelta(days=8)
        )
        self.write_review_report(report)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "review_window_invalid"):
            self.derive()

        self.build_review()
        report = self.review_report()
        report["candidate"]["commit"] = "f" * 40
        self.write_review_report(report)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "candidate_mismatch"):
            self.derive()

    def test_review_is_bound_to_the_exact_source_promotion(self) -> None:
        report = self.review_report()
        report["candidate"]["promotion_conformance"]["repositories"][1][
            "commit"
        ] = "f" * 40
        self.write_review_report(report)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "candidate_mismatch"):
            self.derive()

        self.build_review()
        promotion = json.loads(
            (self.promotion / MODULE.PROMOTION_REPORT_NAME).read_text(encoding="utf-8")
        )
        promotion["repositories"][1]["commit"] = "e" * 40
        self.write_promotion_report(promotion)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "candidate_mismatch"):
            self.derive()

        self.build_promotion()
        self.build_review()
        promotion = json.loads(
            (self.promotion / MODULE.PROMOTION_REPORT_NAME).read_text(encoding="utf-8")
        )
        promotion["documentation"]["source_tree_sha256"] = "f" * 64
        self.write_promotion_report(promotion)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "candidate_mismatch"):
            self.derive()

    def test_rejects_review_tamper_and_unresolved_high_findings(self) -> None:
        identifier = MODULE.INDEPENDENT_REVIEWS[0]
        receipt_path = self.review / "reviews" / f"{identifier}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["status"] = "failed"
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "artifact_mismatch"):
            self.derive()

        self.build_review()
        report = self.review_report()
        result = next(item for item in report["reviews"] if item["id"] == identifier)
        result["findings"]["total"]["high"] = 2
        result["findings"]["unresolved"]["high"] = 1
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["findings"] = result["findings"]
        self.write_json(receipt_path, receipt)
        result["artifact"]["sha256"] = MODULE.sha256_file(receipt_path)
        self.write_review_report(report)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "blocking_findings"):
            self.derive()

    def test_requires_exact_documented_accepted_lower_severity_risks(self) -> None:
        identifier = MODULE.INDEPENDENT_REVIEWS[0]
        receipt_path = self.review / "reviews" / f"{identifier}.json"
        report = self.review_report()
        result = next(item for item in report["reviews"] if item["id"] == identifier)
        result["accepted_risks"] = result["accepted_risks"][:-1]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["accepted_risks"] = result["accepted_risks"]
        self.write_json(receipt_path, receipt)
        result["artifact"]["sha256"] = MODULE.sha256_file(receipt_path)
        self.write_review_report(report)
        with self.assertRaisesRegex(
            MODULE.SecurityEvidenceError, "accepted_risks_incomplete"
        ):
            self.derive()

        self.build_review()
        report = self.review_report()
        result = next(item for item in report["reviews"] if item["id"] == identifier)
        result["accepted_risks"][0]["acceptance_rationale"] = " "
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["accepted_risks"] = result["accepted_risks"]
        self.write_json(receipt_path, receipt)
        result["artifact"]["sha256"] = MODULE.sha256_file(receipt_path)
        self.write_review_report(report)
        with self.assertRaisesRegex(
            MODULE.SecurityEvidenceError, "accepted_risk_invalid"
        ):
            self.derive()

    def test_rejects_self_controlled_reviewer_and_redaction_failure(self) -> None:
        arguments = self.review_arguments()
        arguments["expected_reviewer_organization"] = "Latchway"
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "not_independent"):
            MODULE.derive_summary(
                candidate_manifest=self.candidate_manifest,
                raw_directory=self.raw,
                **arguments,
                repository=self.repository,
                expected_commit=self.commit,
                expected_tag=self.tag,
                now=self.now,
            )

        report = self.review_report()
        report["api_key"] = "redacted"
        self.write_review_report(report)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "redaction_failed"):
            self.derive()

    def test_rejects_claims_wrong_invocation_nonzero_and_stale_times(self) -> None:
        check = MODULE.COMMAND_CHECKS[0]
        result_path, _ = MODULE.command_paths(self.raw, check)
        original = json.loads(result_path.read_text(encoding="utf-8"))
        mutations = (
            ("claim", "passed", "raw_claim_forbidden"),
            ("argv", ["echo", "passed"], "command_result_invalid"),
            (
                "execution_context",
                {"postgresql_enabled": True, "fuzz_time": None, "fuzz_parallel": None},
                "command_result_invalid",
            ),
            ("exit_code", 1, "command_failed"),
            (
                "finished_at",
                MODULE.canonical_time(self.now + timedelta(seconds=1)),
                "command_time_invalid",
            ),
        )
        for field, value, code in mutations:
            with self.subTest(field=field):
                mutated = dict(original)
                mutated[field] = value
                self.write_json(result_path, mutated)
                with self.assertRaisesRegex(MODULE.SecurityEvidenceError, code):
                    self.derive()
        self.write_json(result_path, original)

    def test_race_capture_refuses_missing_postgresql_context(self) -> None:
        capture_raw = self.root / "capture-raw"
        with mock.patch.dict(
            MODULE.os.environ, {"LATCHWAY_TEST_DATABASE_URL": ""}, clear=False
        ):
            with self.assertRaisesRegex(
                MODULE.SecurityEvidenceError, "postgresql_evidence_unavailable"
            ):
                MODULE.capture_command(
                    MODULE.COMMAND_BY_ID["source_race"],
                    repository=self.repository,
                    raw_directory=capture_raw,
                    candidate_commit=self.commit,
                )

    def test_go_vulnerability_capture_builds_and_hashes_exact_binary(self) -> None:
        capture_raw = self.root / "capture-govuln"
        check = MODULE.COMMAND_BY_ID["source_go_vulnerability"]
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def run(
            command: tuple[str, ...], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            argv = tuple(command)
            environment = dict(kwargs["env"])
            calls.append((argv, environment))
            if argv[:3] == ("go", "build", "-trimpath"):
                output = Path(argv[argv.index("-o") + 1])
                output.write_bytes(b"captured binary bytes\n")
            return subprocess.CompletedProcess(argv, 0)

        with (
            mock.patch.object(
                MODULE, "validate_clean_repository", return_value="a" * 40
            ),
            mock.patch.object(MODULE.subprocess, "run", side_effect=run),
        ):
            result = MODULE.capture_command(
                check,
                repository=self.repository,
                raw_directory=capture_raw,
                candidate_commit=self.commit,
            )

        binary_path = MODULE.command_binary_path(capture_raw, check)
        assert binary_path is not None
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(
            result["binary"],
            {"path": binary_path.name, "sha256": MODULE.sha256_file(binary_path)},
        )
        self.assertEqual(
            result["execution_context"]["vulnerability_scan_mode"], "binary"
        )
        self.assertEqual(
            result["execution_context"]["vulnerability_binary_package"],
            "./cmd/latchway",
        )
        self.assertEqual(calls[0][0][-1], "./cmd/latchway")
        self.assertEqual(calls[0][1]["CGO_ENABLED"], "0")
        self.assertEqual(calls[1][0][-2], "-mode=binary")
        self.assertEqual(calls[1][0][-1], str(binary_path))

    def test_rejects_substituted_go_vulnerability_binary(self) -> None:
        check = MODULE.COMMAND_BY_ID["source_go_vulnerability"]
        binary_path = MODULE.command_binary_path(self.raw, check)
        assert binary_path is not None
        binary_path.write_bytes(b"substituted binary\n")
        with self.assertRaisesRegex(
            MODULE.SecurityEvidenceError, "command_binary_hash_mismatch"
        ):
            self.derive()

        self.build_raw()
        result_path, _ = MODULE.command_paths(self.raw, check)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["execution_context"]["vulnerability_binary_package"] = "./..."
        self.write_json(result_path, result)
        with self.assertRaisesRegex(
            MODULE.SecurityEvidenceError, "command_result_invalid"
        ):
            self.derive()

    def test_rejects_log_and_candidate_scan_substitution(self) -> None:
        _, log_path = MODULE.command_paths(self.raw, MODULE.COMMAND_CHECKS[1])
        log_path.write_text("altered\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "log_hash_mismatch"):
            self.derive()
        self.build_raw()
        scan = self.raw / "latchway-linux-amd64-vulnerability.json"
        self.write_json(
            scan,
            {"SchemaVersion": 2, "ArtifactName": "substituted", "Results": []},
        )
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "scan_hash_mismatch"):
            self.derive()

    def test_rejects_blocked_vulnerability_secret_misconfiguration_and_license(self) -> None:
        cases = (
            ("source-trivy-policy.json", "Vulnerabilities", {"Severity": "CRITICAL"}),
            ("source-trivy-policy.json", "Secrets", {"Severity": "HIGH"}),
            (
                "source-trivy-policy.json",
                "Misconfigurations",
                {"Severity": "HIGH", "Status": "FAIL"},
            ),
            ("source-trivy-license.json", "Licenses", {"Severity": "HIGH"}),
        )
        for filename, key, finding in cases:
            with self.subTest(key=key):
                self.write_json(
                    self.raw / filename,
                    {"SchemaVersion": 2, "Results": [{key: [finding]}]},
                )
                with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "policy_failed"):
                    self.derive()
                self.write_json(
                    self.raw / filename, {"SchemaVersion": 2, "Results": []}
                )

    def test_rejects_altered_summary_fields_claims_and_times(self) -> None:
        output, _ = self.seal()
        report_path = output / "security-summary.json"
        original = json.loads(report_path.read_text(encoding="utf-8"))
        mutations = (
            ("gate", lambda value: value.update(automated_gate="failed")),
            ("kind", lambda value: value.update(kind="historical_security_note")),
            ("claim", lambda value: value.update(claims={"p0_p2": "passed"})),
            (
                "commit",
                lambda value: value["candidate"].update(commit="f" * 40),
            ),
            (
                "image_digest",
                lambda value: value["candidate"]["image"].update(
                    index_digest="sha256:" + "f" * 64
                ),
            ),
            (
                "contract_digest",
                lambda value: value["candidate"]["contract"].update(
                    bundle_sha256="f" * 64
                ),
            ),
            (
                "independent_claim",
                lambda value: value["independent_reviews"][0].update(
                    status="failed"
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                mutated = json.loads(json.dumps(original))
                mutate(mutated)
                self.write_json(report_path, mutated)
                with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "summary_mismatch"):
                    MODULE.verify(
                        report=report_path,
                        candidate_manifest=self.candidate_manifest,
                        raw_directory=output / "raw",
                        review_directory=output / "independent-review",
                        promotion_directory=output / "promotion-conformance",
                        repository=self.repository,
                        expected_commit=self.commit,
                        expected_tag=self.tag,
                        now=self.now,
                    )
        self.write_json(report_path, original)
        window = output / "raw/scan-window.json"
        changed = json.loads(window.read_text(encoding="utf-8"))
        changed["finished_at"] = MODULE.canonical_time(self.now + timedelta(seconds=1))
        self.write_json(window, changed)
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "window_time_invalid"):
            MODULE.verify(
                report=report_path,
                candidate_manifest=self.candidate_manifest,
                raw_directory=output / "raw",
                review_directory=output / "independent-review",
                promotion_directory=output / "promotion-conformance",
                repository=self.repository,
                expected_commit=self.commit,
                expected_tag=self.tag,
                now=self.now,
            )

    def test_rejects_duplicate_keys_and_output_reuse(self) -> None:
        path, _ = MODULE.command_paths(self.raw, MODULE.COMMAND_CHECKS[0])
        path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "duplicate_key"):
            self.derive()
        self.build_raw()
        output, _ = self.seal()
        with self.assertRaisesRegex(MODULE.SecurityEvidenceError, "output_directory_invalid"):
            MODULE.seal(
                candidate_manifest=self.candidate_manifest,
                raw_directory=self.raw,
                **self.review_arguments(),
                repository=self.repository,
                expected_commit=self.commit,
                expected_tag=self.tag,
                output_directory=output,
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
