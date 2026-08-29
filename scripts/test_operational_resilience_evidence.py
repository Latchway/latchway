#!/usr/bin/env python3

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("operational-resilience-evidence.py")
SPEC = importlib.util.spec_from_file_location("operational_resilience_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
DRILL_SCRIPT = Path(__file__).with_name("operational-drill-report.py")
DRILL_SPEC = importlib.util.spec_from_file_location("operational_drill_report", DRILL_SCRIPT)
assert DRILL_SPEC is not None and DRILL_SPEC.loader is not None
DRILL = importlib.util.module_from_spec(DRILL_SPEC)
DRILL_SPEC.loader.exec_module(DRILL)
WORKFLOW = Path(__file__).parents[1] / ".github/workflows/operational-resilience-evidence.yml"


class OperationalEvidenceFixture:
    def __init__(self, root: Path):
        self.root = root
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        self.commit = "a" * 40
        self.previous_commit = "e" * 40
        self.bundle_hash = hashlib.sha256(b"contract").hexdigest()
        self.image = "ghcr.io/latchway/latchway@sha256:" + "1" * 64
        self.previous_image = "ghcr.io/latchway/latchway@sha256:" + "2" * 64
        self.postgres_image = "docker.io/library/postgres@sha256:" + "3" * 64
        self.candidate_dir = root / "candidate"
        self.failure_dir = root / "failure"
        self.drill_dir = root / "drills"
        self.candidate_dir.mkdir()
        self.failure_dir.mkdir()
        self.drill_dir.mkdir()
        self.source_path = root / "source.json"
        self.candidate_path = self.candidate_dir / "latchway-candidate.json"
        self.load_path = root / "load.json"
        self.failure_path = root / "failure.json"
        self.backup_path = self.drill_dir / "backup-restore.json"
        self.upgrade_path = self.drill_dir / "upgrade-rollback.json"
        self._write_source()
        self._write_candidate()
        self._write_load()
        self._write_failure()
        self._write_drills()

    @staticmethod
    def timestamp(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def write(path: Path, value: object) -> None:
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
                "summary": "passed",
                "details": {"verified": True},
            }
            for identifier in sorted(MODULE.SOURCE_CHECK_IDS)
        ]
        checks.extend(
            {
                "id": identifier,
                "domain": domain,
                "required": False,
                "status": "unverified",
                "summary": "not required in source scope",
                "reason": reason,
            }
            for identifier, (domain, reason) in sorted(
                MODULE.SOURCE_UNVERIFIED_CHECKS.items()
            )
        )
        repositories = [
            {
                "id": identifier,
                "commit": self.commit if identifier == "core" else chr(98 + index) * 40,
                "version": "1.0.0",
                "intended_tag": "v1.0.0",
            }
            for index, identifier in enumerate(MODULE.REPOSITORY_IDS)
        ]
        self.write(
            self.source_path,
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
                    "bundle_sha256": self.bundle_hash,
                    "core_release": "v1.0.0",
                    "oci_image_digest": None,
                },
                "repositories": repositories,
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
                    for identifier in sorted(MODULE.SOURCE_DOMAIN_IDS)
                ],
                "checks": checks,
            },
        )

    def _write_candidate(self) -> None:
        for index, name in enumerate(sorted(MODULE.CANDIDATE_ARTIFACTS)):
            contents = b"contract" if name == "latchway-contract.tar.gz" else f"artifact-{index}".encode()
            (self.candidate_dir / name).write_bytes(contents)
        entries = [
            {"path": name, "sha256": self.digest(self.candidate_dir / name)}
            for name in sorted(MODULE.CANDIDATE_ARTIFACTS)
        ]
        self.write(
            self.candidate_path,
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
                    "bundle_sha256": self.bundle_hash,
                },
                "image": {
                    "repository": "ghcr.io/latchway/latchway",
                    "index_digest": "sha256:" + "1" * 64,
                    "platforms": {
                        "linux/amd64": "sha256:" + "4" * 64,
                        "linux/arm64": "sha256:" + "5" * 64,
                    },
                },
                "artifacts": entries,
            },
        )

    @staticmethod
    def result_evidence(total: int, *, denied: int = 0) -> dict[str, object]:
        statuses = {"200": total - denied}
        problems: dict[str, int] = {}
        if denied:
            statuses["429"] = denied
            problems["quota_exceeded"] = denied
        return {
            "statuses": statuses,
            "problem_codes": problems,
            "request_errors": 0,
            "invalid_problem_responses": 0,
        }

    @staticmethod
    def quota_check(expected: list[dict[str, object]]) -> dict[str, object]:
        return {
            "exact": True,
            "expected_feature": "operational-load",
            "observed_feature": "operational-load",
            "expected": expected,
            "observed": [dict(item, resets_at=None) for item in expected],
        }

    def _write_load(self) -> None:
        nonstream_limits = [
            {
                "metric": metric,
                "maximum": maximum,
                "used": used,
                "reserved": 0,
                "remaining": maximum - used,
                "hard": True,
            }
            for metric, maximum, used in (
                ("logical_requests", 10000, 1022),
                ("input_tokens", 100000, 10220),
                ("output_tokens", 100000, 5110),
                ("total_tokens", 200000, 15330),
            )
        ]
        stream_limits = [
            {
                "metric": "concurrent_streams",
                "maximum": 600,
                "used": 0,
                "reserved": 0,
                "remaining": 600,
                "hard": True,
            }
        ]
        gate_metrics = {
            "preflight": {
                "ready_url": "http://isolated.invalid/readyz",
                "protected_results": self.result_evidence(1),
            },
            "idle_memory": {
                "pid": 123,
                "rss_samples_mib": [100, 100, 100, 100, 100],
                "maximum_rss_mib": 100,
                "target_mib": 256,
            },
            "gateway_overhead": {
                "method": "paired client-observed gateway minus direct fixture latency, floored at zero",
                "samples": 20,
                "p50_overhead_ms": 1,
                "p95_overhead_ms": 2,
                "p99_overhead_ms": 3,
                "p50_gateway_e2e_ms": 2,
                "p95_gateway_e2e_ms": 3,
                "p99_gateway_e2e_ms": 4,
                "p50_direct_upstream_ms": 1,
                "p95_direct_upstream_ms": 1,
                "p99_direct_upstream_ms": 1,
                "targets_ms": {"p50": 5, "p95": 15, "p99": 30},
                "gateway_results": self.result_evidence(21),
                "direct_upstream_results": self.result_evidence(21),
            },
            "non_stream_100_rps": {
                "target_rps": 100,
                "duration_seconds": 10,
                "scheduled": 1000,
                "successful": 1000,
                "failed": 0,
                "results": self.result_evidence(1000),
                "maximum_scheduler_lag_ms": 1,
                "maximum_request_start_lag_ms": 1,
                "schedule_lag_target_ms": 25,
                "completion_elapsed_seconds": 10,
                "p50_e2e_ms": 1,
                "p95_e2e_ms": 2,
                "p99_e2e_ms": 3,
                "terminal_quota_check": self.quota_check(nonstream_limits),
            },
            "sse_500_concurrent_memory": {
                "established": 500,
                "target_concurrency": 500,
                "hold_seconds": 10,
                "premature_completions": 0,
                "baseline_rss_mib": 100,
                "peak_rss_mib": 101,
                "growth_mib": 1,
                "growth_target_mib": 128,
                "plateau_slope_mib_per_minute": 0,
                "slope_target_mib_per_minute": 5,
                "rss_samples": [{"At": "2026-08-29T10:10:00Z", "MiB": 100}],
                "establishment_results": self.result_evidence(500),
                "terminal_quota_check": self.quota_check(stream_limits),
            },
            "quota_contention_zero_overspend": {
                "metric": "logical_requests",
                "attempts": 11,
                "accepted": 10,
                "expected_accepted": 10,
                "denied": 1,
                "expected_denied": 1,
                "unexpected": 0,
                "expected_denial_problem_code": "quota_exceeded",
                "results": self.result_evidence(11, denied=1),
                "before": {
                    "feature": "operational-load",
                    "observed_at": "2026-08-29T10:10:00Z",
                    "limits": [
                        {
                            "metric": "logical_requests",
                            "maximum": 10,
                            "used": 0,
                            "reserved": 0,
                            "remaining": 10,
                            "resets_at": "2026-08-30T00:00:00Z",
                            "hard": True,
                        }
                    ],
                },
                "after": {
                    "feature": "operational-load",
                    "observed_at": "2026-08-29T10:10:01Z",
                    "limits": [
                        {
                            "metric": "logical_requests",
                            "maximum": 10,
                            "used": 10,
                            "reserved": 0,
                            "remaining": 0,
                            "resets_at": "2026-08-30T00:00:00Z",
                            "hard": True,
                        }
                    ],
                },
            },
        }
        self.write(
            self.load_path,
            {
                "schema_version": 1,
                "kind": "latchway_load_evidence",
                "started_at": "2026-08-29T10:10:00Z",
                "finished_at": "2026-08-29T10:20:00Z",
                "commit": self.commit,
                "environment": {
                    "label": "isolated-release-load",
                    "cpu": "2 vCPU",
                    "memory": "2 GiB",
                    "postgresql": "isolated-postgresql",
                    "postgresql_cpu_millicores": 1000,
                    "postgresql_memory_bytes": 1073741824,
                    "postgresql_memory_swap_bytes": 1073741824,
                    "postgresql_max_connections": 100,
                    "postgresql_network": "low-latency-internal",
                    "gateway_db_pool_max_connections": 32,
                    "body_logging_disabled": True,
                    "warm_configuration_cache": True,
                },
                "quota_fixture": {
                    "protected_preflight_requests": 1,
                    "overhead_warmup_requests": 1,
                    "overhead_sample_requests": 20,
                    "non_stream_load_requests": 1000,
                    "settled_input_tokens_per_request": 10,
                    "settled_output_tokens_per_request": 5,
                    "settled_total_tokens_per_request": 15,
                    "input_reservation_per_request": 20,
                    "output_reservation_per_request": 10,
                    "total_reservation_per_request": 30,
                },
                "metadata": {
                    "release_oci_reference": self.image,
                    "deployment": "isolated release load environment",
                    "operator": "authenticated-ci",
                },
                "observed_process_executable": "latchway",
                "worktree_clean": True,
                "gates": [
                    {
                        "name": name,
                        "status": "passed",
                        "started_at": "2026-08-29T10:10:00Z",
                        "duration_ms": 1,
                        "metrics": gate_metrics[name],
                    }
                    for name in (
                        "preflight",
                        "idle_memory",
                        "gateway_overhead",
                        "non_stream_100_rps",
                        "sse_500_concurrent_memory",
                        "quota_contention_zero_overspend",
                    )
                ],
                "complete_suite": True,
                "load_targets_passed": True,
            },
        )

    def _write_failure(self) -> None:
        logs_root = self.root / "failure.logs"
        logs_root.mkdir()
        results = []
        matrix, requirements, evidence_notes = MODULE.failure_matrix_details()
        for identifier in sorted(MODULE.AUTOMATED_FAILURE_IDS):
            logs = []
            for position, invocation in enumerate(matrix[identifier], 1):
                log_path = logs_root / f"{identifier}-{position:02d}.jsonl"
                log_path.write_text(
                    "".join(
                        json.dumps(
                            {
                                "Time": "2026-08-29T10:30:00Z",
                                "Action": "pass",
                                "Package": invocation["package"],
                                "Test": test_name,
                            }
                        )
                        + "\n"
                        for test_name in invocation["run"].split("|")
                    ),
                    encoding="utf-8",
                )
                logs.append(
                    {
                        "package": invocation["package"],
                        "run": invocation["run"],
                        "race": invocation["race"],
                        "log": str(log_path),
                        "sha256": self.digest(log_path),
                        "exit_code": 0,
                    }
                )
            results.append(
                {
                    "id": identifier,
                    "requirement": requirements[identifier],
                    "kind": "automated",
                    "status": "passed",
                    "duration_ms": 1,
                    "logs": logs,
                }
            )
        for index, identifier in enumerate(sorted(MODULE.EXTERNAL_FAILURE_IDS)):
            artifact = self.failure_dir / f"{identifier}.log"
            artifact.write_text(f"bounded observation {identifier}\n", encoding="utf-8")
            assertions = [
                {"name": name, "passed": True, "detail": "machine observed"}
                for name in sorted(MODULE.EXTERNAL_FAILURE_ASSERTIONS[identifier])
            ]
            environment = {
                "image_digest": self.image,
                "platform": "isolated-linux",
                "postgresql": "isolated-postgresql",
                "fault_tool": "isolated-fault-controller",
                "operator": "authenticated-ci",
            }
            if identifier == "live-config-and-key-rotation-across-api-replicas":
                environment.update(
                    {"api_replicas": "2", "worker_replicas": "2", "load_balancer": "isolated-lb"}
                )
            self.write(
                self.failure_dir / f"{identifier}.json",
                {
                    "schema_version": 1,
                    "scenario_id": identifier,
                    "status": "passed",
                    "commit": self.commit,
                    "started_at": self.timestamp(self.now - timedelta(minutes=90 - index)),
                    "finished_at": self.timestamp(self.now - timedelta(minutes=89 - index)),
                    "environment": environment,
                    "assertions": assertions,
                    "artifacts": [{"path": artifact.name, "sha256": self.digest(artifact)}],
                },
            )
            results.append(
                {
                    "id": identifier,
                    "requirement": requirements[identifier],
                    "kind": "external",
                    "status": "passed",
                    "duration_ms": 1,
                    "evidence": str(self.failure_dir / f"{identifier}.json"),
                    "notes": evidence_notes[identifier],
                }
            )
        self.write(
            self.failure_path,
            {
                "schema_version": 1,
                "kind": "latchway_failure_evidence",
                "scope": "release",
                "commit": self.commit,
                "worktree_clean": True,
                "started_at": "2026-08-29T10:35:00Z",
                "finished_at": "2026-08-29T10:45:00Z",
                "results": results,
                "automated_passed": True,
                "release_passed": True,
            },
        )

    @staticmethod
    def migration() -> dict[str, object]:
        return {"current": 16, "available": 16, "up_to_date": True}

    @staticmethod
    def doctor() -> dict[str, object]:
        return {"status": "ok", "database": "reachable", "schema_version": 16, "role": "all"}

    @staticmethod
    def version(version: str, commit: str) -> dict[str, str]:
        return {
            "version": version,
            "commit": commit,
            "build_date": "2026-08-29T10:01:00Z",
            "contract_version": version,
            "protocol_version": "1",
        }

    @staticmethod
    def readiness() -> dict[str, object]:
        return {
            "status": "ready",
            "checks": {
                "database": "ok",
                "schema": "ok",
                "active_configuration": "ok",
                "master_key": "ok",
                "signing_key": "ok",
                "worker_heartbeat": "ok",
            },
        }

    def stage(self, image: str, version: str, commit: str) -> dict[str, object]:
        build = self.version(version, commit)
        return {
            "image": image,
            "version": build,
            "migration": self.migration(),
            "doctor": self.doctor(),
            "health": {"status": "ok", "build": build},
            "readiness": self.readiness(),
            "state_fingerprint_sha256": "6" * 64,
            "row_counts": {"organizations": 1, "applications": 1, "environments": 1},
        }

    def _write_drills(self) -> None:
        self._write_image_inspection()
        archive = self.drill_dir / "backup.dump"
        archive.write_bytes(b"PGDMP bounded test archive")
        backup_log = self.drill_dir / "backup.log.json"
        backup_log.write_text('{"status":"passed"}\n', encoding="utf-8")
        upgrade_log = self.drill_dir / "upgrade.log.json"
        upgrade_log.write_text('{"status":"passed"}\n', encoding="utf-8")
        previous_version = self.version("0.9.0", self.previous_commit)
        source = {
            "database_identity_sha256": "7" * 64,
            "image": self.previous_image,
            "version": previous_version,
            "migration": self.migration(),
            "doctor": self.doctor(),
            "health": {"status": "ok", "build": previous_version},
            "readiness": self.readiness(),
            "state_fingerprint_sha256": "6" * 64,
            "row_counts": {"organizations": 1, "applications": 1, "environments": 1},
        }
        restore = copy.deepcopy(source)
        restore["database_identity_sha256"] = "8" * 64
        self.write(
            self.backup_path,
            {
                "schema_version": 1,
                "kind": "latchway_backup_restore_drill",
                "status": "passed",
                "core_commit": self.commit,
                "previous_oci_reference": self.previous_image,
                "candidate_oci_reference": self.image,
                "postgres_oci_reference": self.postgres_image,
                "started_at": "2026-08-29T10:50:00Z",
                "finished_at": "2026-08-29T11:00:00Z",
                "isolation": {
                    "network_internal": True,
                    "source_database_container_fresh": True,
                    "restore_database_container_fresh": True,
                    "production_targeted": False,
                },
                "source": source,
                "backup": {
                    "format": "postgresql-custom",
                    "artifact_path": archive.name,
                    "sha256": self.digest(archive),
                    "size_bytes": archive.stat().st_size,
                },
                "restore": restore,
                "assertions": {name: True for name in MODULE.BACKUP_ASSERTIONS},
                "artifacts": [
                    {"path": archive.name, "sha256": self.digest(archive)},
                    {"path": backup_log.name, "sha256": self.digest(backup_log)},
                    {
                        "path": "image-inspection.json",
                        "sha256": self.digest(self.drill_dir / "image-inspection.json"),
                    },
                ],
            },
        )
        self.write(
            self.upgrade_path,
            {
                "schema_version": 1,
                "kind": "latchway_upgrade_application_rollback_drill",
                "status": "passed",
                "core_commit": self.commit,
                "previous_oci_reference": self.previous_image,
                "candidate_oci_reference": self.image,
                "postgres_oci_reference": self.postgres_image,
                "started_at": "2026-08-29T11:00:01Z",
                "finished_at": "2026-08-29T11:10:00Z",
                "previous_before": self.stage(self.previous_image, "0.9.0", self.previous_commit),
                "candidate_after": self.stage(self.image, "1.0.0", self.commit),
                "previous_rollback": self.stage(self.previous_image, "0.9.0", self.previous_commit),
                "assertions": {name: True for name in MODULE.UPGRADE_ASSERTIONS},
                "artifacts": [
                    {"path": upgrade_log.name, "sha256": self.digest(upgrade_log)},
                    {
                        "path": "image-inspection.json",
                        "sha256": self.digest(self.drill_dir / "image-inspection.json"),
                    },
                ],
            },
        )

    def _write_image_inspection(self) -> None:
        self.write(
            self.drill_dir / "image-inspection.json",
            {
                "candidate_oci_reference": self.image,
                "candidate_revision": self.commit,
                "candidate_repo_digests": [self.image],
                "previous_oci_reference": self.previous_image,
                "previous_revision": self.previous_commit,
                "previous_repo_digests": [self.previous_image],
                "previous_version": "0.9.0",
                "previous_release_tag": "v0.9.0",
                "previous_release_tag_type": "tag",
                "previous_release_tag_commit": self.previous_commit,
                "previous_version_tag_repo_digests": [self.previous_image],
                "postgres_oci_reference": self.postgres_image,
                "postgres_repo_digests": [self.postgres_image],
                "network_internal": True,
                "source_database_identity_sha256": "7" * 64,
                "restore_database_identity_sha256": "8" * 64,
            },
        )

    def write_raw_drill_observations(self) -> None:
        previous = self.stage(self.previous_image, "0.9.0", self.previous_commit)
        candidate = self.stage(self.image, "1.0.0", self.commit)
        rollback = self.stage(self.previous_image, "0.9.0", self.previous_commit)
        for prefix, stage in (
            ("previous", previous),
            ("candidate", candidate),
            ("rollback", rollback),
        ):
            for suffix in ("version", "migration", "doctor", "health", "readiness"):
                self.write(self.drill_dir / f"{prefix}-{suffix}.json", stage[suffix])
            self.write(
                self.drill_dir / f"{prefix}-state.json",
                {
                    "database_identity_sha256": "7" * 64,
                    "state_fingerprint_sha256": stage["state_fingerprint_sha256"],
                    "row_counts": stage["row_counts"],
                },
            )
        self.write(self.drill_dir / "restore-migration.json", self.migration())
        self.write(self.drill_dir / "restore-doctor.json", self.doctor())
        previous_build = self.version("0.9.0", self.previous_commit)
        self.write(
            self.drill_dir / "restore-health.json",
            {"status": "ok", "build": previous_build},
        )
        self.write(self.drill_dir / "restore-readiness.json", self.readiness())
        self.write(
            self.drill_dir / "restore-state.json",
            {
                "database_identity_sha256": "8" * 64,
                "state_fingerprint_sha256": "6" * 64,
                "row_counts": {"organizations": 1, "applications": 1, "environments": 1},
            },
        )
        self._write_image_inspection()


class OperationalResilienceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-operational-")
        self.root = Path(self.temporary.name)
        self.fixture = OperationalEvidenceFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def finalize(self, name: str = "output") -> dict[str, object]:
        return MODULE.finalize(
            candidate_manifest=self.fixture.candidate_path,
            source_conformance=self.fixture.source_path,
            load_report=self.fixture.load_path,
            failure_report=self.fixture.failure_path,
            failure_evidence_dir=self.fixture.failure_dir,
            backup_report=self.fixture.backup_path,
            upgrade_report=self.fixture.upgrade_path,
            output_directory=self.root / name,
            now=self.fixture.now,
        )

    @staticmethod
    def mutate(path: Path, operation) -> None:
        value = json.loads(path.read_text(encoding="utf-8"))
        operation(value)
        OperationalEvidenceFixture.write(path, value)

    def test_finalizer_emits_exact_hash_bound_operational_domain(self) -> None:
        document = self.finalize()
        self.assertEqual(document["domain"], "operational_resilience")
        self.assertEqual(document["oci_image_digest"], self.fixture.image)
        self.assertEqual(document["claims"], MODULE.DOMAIN_CLAIMS)
        self.assertEqual(len(document["artifacts"]), 7)
        output = self.root / "output"
        self.assertEqual(json.loads((output / "operational_resilience.json").read_text()), document)
        for artifact in document["artifacts"]:
            self.assertEqual(
                hashlib.sha256((output / artifact["path"]).read_bytes()).hexdigest(),
                artifact["sha256"],
            )

    def test_workflow_verifies_untagged_candidate_and_source_attestations(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        verification = workflow.index(
            "- name: Verify candidate and source-conformance attestations"
        )
        finalization = workflow.index("- name: Seal the operational-resilience domain")
        self.assertLess(verification, finalization)
        self.assertIn(
            '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
            workflow,
        )
        self.assertIn(
            '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/cross-repository-conformance.yml"',
            workflow,
        )
        self.assertEqual(workflow.count('--source-digest "$CANDIDATE_COMMIT"'), 2)
        self.assertEqual(workflow.count("--source-ref refs/heads/main"), 2)
        self.assertEqual(workflow.count("--deny-self-hosted-runners"), 2)
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', workflow)
        self.assertNotIn("refs/tags/", workflow)

    def test_rejects_tampered_raw_artifact(self) -> None:
        (self.fixture.drill_dir / "backup.dump").write_bytes(b"substituted archive")
        with self.assertRaisesRegex(MODULE.EvidenceError, "artifact_hash_mismatch"):
            self.finalize()

    def test_rejects_tampered_automated_failure_log(self) -> None:
        log = next((self.root / "failure.logs").iterdir())
        log.write_text('{"Action":"pass","Test":"Substituted"}\n', encoding="utf-8")
        with self.assertRaisesRegex(MODULE.EvidenceError, "automated_log_not_passed"):
            self.finalize()

    def test_rejects_wrong_commit_and_digest(self) -> None:
        cases = (
            (
                self.fixture.load_path,
                lambda value: value.__setitem__("commit", "b" * 40),
                "load_not_release_passed",
            ),
            (
                self.fixture.load_path,
                lambda value: value["metadata"].__setitem__(
                    "release_oci_reference",
                    "ghcr.io/latchway/latchway@sha256:" + "9" * 64,
                ),
                "load_image_mismatch",
            ),
        )
        for index, (path, operation, code) in enumerate(cases):
            with self.subTest(code=code):
                original = path.read_bytes()
                self.mutate(path, operation)
                with self.assertRaisesRegex(MODULE.EvidenceError, code):
                    self.finalize(f"output-{index}")
                path.write_bytes(original)

    def test_rejects_automated_scope_and_failed_claims(self) -> None:
        original_failure = self.fixture.failure_path.read_bytes()
        self.mutate(self.fixture.failure_path, lambda value: value.__setitem__("scope", "automated"))
        with self.assertRaisesRegex(MODULE.EvidenceError, "failure_not_release_passed"):
            self.finalize("scope-output")
        self.fixture.failure_path.write_bytes(original_failure)
        self.mutate(
            self.fixture.backup_path,
            lambda value: value["assertions"].__setitem__("archive_digest_verified", False),
        )
        with self.assertRaisesRegex(MODULE.EvidenceError, "backup_claims_invalid"):
            self.finalize("claims-output")

    def test_rejects_unproved_multi_replica_claim(self) -> None:
        path = self.fixture.failure_dir / "live-config-and-key-rotation-across-api-replicas.json"
        self.mutate(path, lambda value: value["environment"].__setitem__("api_replicas", "1"))
        with self.assertRaisesRegex(MODULE.EvidenceError, "multi_replica_environment_invalid"):
            self.finalize()

    def test_rejects_tampered_load_target_and_scenario_claim_set(self) -> None:
        original_load = self.fixture.load_path.read_bytes()

        def widen_overhead(value: dict[str, object]) -> None:
            gate = next(
                gate for gate in value["gates"] if gate["name"] == "gateway_overhead"
            )
            gate["metrics"]["targets_ms"]["p99"] = 31

        self.mutate(self.fixture.load_path, widen_overhead)
        with self.assertRaisesRegex(MODULE.EvidenceError, "load_gate_metrics_invalid"):
            self.finalize("load-target-output")
        self.fixture.load_path.write_bytes(original_load)

        scenario = self.fixture.failure_dir / "live-process-kill-after-reservation.json"
        self.mutate(scenario, lambda value: value["assertions"].pop())
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "failure_external_assertions_invalid"
        ):
            self.finalize("scenario-claim-output")

    def test_rejects_future_stale_and_reversed_times(self) -> None:
        cases = (
            ("2026-08-29T11:00:00Z", "2026-08-29T12:00:01Z"),
            ("2026-08-20T11:00:00Z", "2026-08-20T11:10:00Z"),
            ("2026-08-29T11:10:00Z", "2026-08-29T11:00:00Z"),
        )
        for index, (started, finished) in enumerate(cases):
            with self.subTest(index=index):
                original = self.fixture.upgrade_path.read_bytes()
                self.mutate(
                    self.fixture.upgrade_path,
                    lambda value: value.update(started_at=started, finished_at=finished),
                )
                with self.assertRaisesRegex(MODULE.EvidenceError, "upgrade_time_invalid"):
                    self.finalize(f"time-output-{index}")
                self.fixture.upgrade_path.write_bytes(original)

    def test_rejects_previous_image_that_cannot_run_candidate_schema(self) -> None:
        def incompatible(value: dict[str, object]) -> None:
            value["previous_rollback"]["migration"] = {
                "current": 16,
                "available": 15,
                "up_to_date": False,
            }

        self.mutate(self.fixture.upgrade_path, incompatible)
        with self.assertRaisesRegex(MODULE.EvidenceError, "upgrade_rollback_invalid"):
            self.finalize()

    def test_drill_producer_seals_only_digest_resolved_observations(self) -> None:
        self.fixture.write_raw_drill_observations()
        backup, upgrade = DRILL.build_reports(
            root=self.fixture.drill_dir,
            commit=self.fixture.commit,
            previous_image=self.fixture.previous_image,
            candidate_image=self.fixture.image,
            postgres_image=self.fixture.postgres_image,
            started_at="2026-08-29T10:50:00Z",
            finished_at="2026-08-29T11:10:00Z",
        )
        self.assertEqual(backup["status"], "passed")
        self.assertEqual(upgrade["candidate_after"]["version"]["commit"], self.fixture.commit)

        inspection = self.fixture.drill_dir / "image-inspection.json"
        self.mutate(inspection, lambda value: value.__setitem__("candidate_revision", "b" * 40))
        with self.assertRaisesRegex(DRILL.DrillError, "drill_image_identity_mismatch"):
            DRILL.build_reports(
                root=self.fixture.drill_dir,
                commit=self.fixture.commit,
                previous_image=self.fixture.previous_image,
                candidate_image=self.fixture.image,
                postgres_image=self.fixture.postgres_image,
                started_at="2026-08-29T10:50:00Z",
                finished_at="2026-08-29T11:10:00Z",
            )


if __name__ == "__main__":
    unittest.main()
