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
        self.repository.mkdir()
        self.candidate.mkdir()
        self.raw.mkdir()
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
        self.build_candidate()
        self.build_raw()

    def tearDown(self) -> None:
        self.temporary.cleanup()

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
            version = check.fixed_version
            if version is None:
                version = "go1.25.0" if check.tool == "go" else "GNU Make 3.81"
            result = {
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

    def derive(self, *, now: datetime | None = None) -> dict[str, object]:
        return MODULE.derive_summary(
            candidate_manifest=self.candidate_manifest,
            raw_directory=self.raw,
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
        self.assertTrue(
            all(item["status"] == "unavailable" for item in report["external_observations"])
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
                "external_claim",
                lambda value: value["external_observations"][0].update(
                    status="passed", reason="reviewed"
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
                repository=self.repository,
                expected_commit=self.commit,
                expected_tag=self.tag,
                output_directory=output,
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
