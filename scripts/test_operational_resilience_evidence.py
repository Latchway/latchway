#!/usr/bin/env python3

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml


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
PRODUCER_SCRIPT = Path(__file__).with_name("operational-producer-evidence.py")
PRODUCER_SPEC = importlib.util.spec_from_file_location(
    "operational_producer_evidence_test", PRODUCER_SCRIPT
)
assert PRODUCER_SPEC is not None and PRODUCER_SPEC.loader is not None
PRODUCER = importlib.util.module_from_spec(PRODUCER_SPEC)
PRODUCER_SPEC.loader.exec_module(PRODUCER)
WORKFLOW = Path(__file__).parents[1] / ".github/workflows/operational-resilience-evidence.yml"
LOAD_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/release-load-evidence.yml"
FAILURE_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/release-failure-evidence.yml"
AGGREGATE_WORKFLOW = (
    Path(__file__).parents[1] / ".github/workflows/aggregate-release-evidence.yml"
)
LOAD_LAUNCHER = Path(__file__).with_name("run-local-load-gates.sh")
OPERATIONAL_LAUNCHER = Path(__file__).with_name(
    "run-operational-resilience-drills.sh"
)


class OperationalEvidenceFixture:
    def __init__(self, root: Path):
        self.root = root
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        self.repository_root = root / "repository"
        self.repository_root.mkdir()
        self._initialize_repository()
        self.bundle_hash = hashlib.sha256(b"contract").hexdigest()
        self.image = "ghcr.io/latchway/latchway@sha256:" + "1" * 64
        self.platform_image = "ghcr.io/latchway/latchway@sha256:" + "4" * 64
        self.previous_candidate_image = (
            "ghcr.io/latchway/latchway@sha256:" + "2" * 64
        )
        self.previous_candidate_platform_image = (
            "ghcr.io/latchway/latchway@sha256:" + "6" * 64
        )
        self.previous_candidate_version = "1.0.0-rc.1"
        self.previous_candidate_tag = "v" + self.previous_candidate_version
        self.previous_candidate_run_id = "12344"
        self.postgres_image = "docker.io/library/postgres@sha256:" + "3" * 64
        self.candidate_dir = root / "candidate"
        self.previous_candidate_dir = root / "previous-candidate"
        self.load_dir = root / "load"
        self.failure_root = root / "failure-artifact"
        self.failure_dir = self.failure_root / "live-failures"
        self.drill_dir = root / "drills"
        self.candidate_dir.mkdir()
        self.previous_candidate_dir.mkdir()
        self.load_dir.mkdir()
        self.failure_dir.mkdir(parents=True)
        self.drill_dir.mkdir()
        self.source_path = root / "source.json"
        self.candidate_path = self.candidate_dir / "latchway-candidate.json"
        self.previous_candidate_path = (
            self.previous_candidate_dir / "latchway-candidate.json"
        )
        self.previous_candidate_attestation_path = (
            self.previous_candidate_dir
            / "latchway-candidate.attestation.sigstore.json"
        )
        self.previous_candidate_run_path = root / "previous-candidate-run.json"
        self.load_path = self.load_dir / "load-v1.json"
        self.failure_path = self.failure_root / "failure-release.json"
        self.load_producer_path = self.load_dir / "load-producer.json"
        self.failure_producer_path = self.failure_root / "failure-producer.json"
        self.load_attestation_path = self.load_dir / "load-producer.attestation.sigstore.json"
        self.failure_attestation_path = self.failure_root / "failure-producer.attestation.sigstore.json"
        self.backup_path = self.drill_dir / "backup-restore.json"
        self.upgrade_path = self.drill_dir / "upgrade-rollback.json"
        self._write_source()
        self._write_candidate()
        self._write_previous_candidate()
        self._write_load()
        self._write_failure()
        self._write_producers()
        self._write_drills()

    def _git(self, *arguments: str) -> str:
        environment = {
            "GIT_AUTHOR_NAME": "Latchway Test",
            "GIT_AUTHOR_EMAIL": "test@latchway.invalid",
            "GIT_COMMITTER_NAME": "Latchway Test",
            "GIT_COMMITTER_EMAIL": "test@latchway.invalid",
            "GIT_AUTHOR_DATE": "2026-08-29T09:00:00Z",
            "GIT_COMMITTER_DATE": "2026-08-29T09:00:00Z",
        }
        completed = subprocess.run(
            ["git", "-C", str(self.repository_root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, **environment},
        )
        return completed.stdout.strip()

    def _initialize_repository(self) -> None:
        self._git("init", "--initial-branch=main")
        marker = self.repository_root / "candidate.txt"
        marker.write_text("previous\n", encoding="utf-8")
        self._git("add", "candidate.txt")
        self._git("commit", "-m", "previous candidate")
        self.previous_commit = self._git("rev-parse", "HEAD")
        marker.write_text("current\n", encoding="utf-8")
        self._git("add", "candidate.txt")
        self._git("commit", "-m", "current candidate")
        self.commit = self._git("rev-parse", "HEAD")

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

    def _write_previous_candidate(self) -> None:
        for index, name in enumerate(sorted(MODULE.CANDIDATE_ARTIFACTS)):
            contents = (
                b"contract"
                if name == "latchway-contract.tar.gz"
                else f"previous-artifact-{index}".encode()
            )
            (self.previous_candidate_dir / name).write_bytes(contents)
        entries = [
            {
                "path": name,
                "sha256": self.digest(self.previous_candidate_dir / name),
            }
            for name in sorted(MODULE.CANDIDATE_ARTIFACTS)
        ]
        self.write(
            self.previous_candidate_path,
            {
                "schema_version": 1,
                "kind": "latchway_release_candidate",
                "status": "passed",
                "created_at": "2026-08-29T10:04:00Z",
                "candidate_commit": self.previous_commit,
                "intended_tag": self.previous_candidate_tag,
                "version": self.previous_candidate_version,
                "contract": {
                    "version": "1.0.0",
                    "status": "released",
                    "released_at": "2026-08-29T10:00:00Z",
                    "bundle_file_name": "latchway-contract-1.0.0.tar.gz",
                    "bundle_sha256": self.bundle_hash,
                },
                "image": {
                    "repository": "ghcr.io/latchway/latchway",
                    "index_digest": "sha256:" + "2" * 64,
                    "platforms": {
                        "linux/amd64": "sha256:" + "6" * 64,
                        "linux/arm64": "sha256:" + "7" * 64,
                    },
                },
                "artifacts": entries,
            },
        )
        self.write(
            self.previous_candidate_attestation_path,
            {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"},
        )
        self.write(
            self.previous_candidate_run_path,
            {
                "schema_version": 1,
                "kind": "latchway_previous_candidate_run",
                "repository": "Latchway/latchway",
                "workflow_path": ".github/workflows/release.yml",
                "workflow_id": "1001",
                "workflow_state": "active",
                "run_id": self.previous_candidate_run_id,
                "run_attempt": 1,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "head_sha": self.previous_commit,
                "head_branch": "main",
                "artifact_name": f"latchway-candidate-{self.previous_commit}",
                "manifest_sha256": self.digest(self.previous_candidate_path),
                "attestation_sha256": self.digest(
                    self.previous_candidate_attestation_path
                ),
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
        self.write(
            self.load_dir / "load-config.json",
            {"schema_version": 1, "candidate": self.image, "platform": self.platform_image},
        )
        self.write(
            self.load_dir / "environment.json",
            {"schema_version": 1, "runner": "github-hosted", "platform": "linux/amd64"},
        )
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
                "targets_ms": {"p50": 15, "p95": 20, "p99": 30},
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
                    "release_oci_platform_reference": self.platform_image,
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
        logs_root = self.failure_root / "failure-release.logs"
        logs_root.mkdir()
        shutil.copyfile(
            MODULE.ROOT / "tests/failure/matrix.json",
            self.failure_root / "failure-matrix.json",
        )
        self.write(
            self.failure_root / "failure-environment.json",
            {"schema_version": 1, "runner": "self-hosted", "platform": "linux/amd64"},
        )
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
                "platform_image_digest": self.platform_image,
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

    def _write_producers(self) -> None:
        def context(domain: str) -> dict[str, object]:
            producer = PRODUCER.PRODUCERS[domain]
            return {
                "repository": PRODUCER.REPOSITORY,
                "workflow_ref": f"{PRODUCER.REPOSITORY}/{producer['workflow']}@refs/heads/main",
                "source_commit": self.commit,
                "run_id": "12345" if domain == "load" else "12346",
                "run_attempt": 1,
                "environment": producer["environment"],
                "runner_environment": producer["runner_environment"],
                "runner_os": "Linux",
                "runner_arch": "X64",
                "runner_name_sha256": "9" * 64,
            }

        PRODUCER.produce(
            domain="load",
            source_path=self.source_path,
            candidate_path=self.candidate_path,
            evidence_root=self.load_dir,
            report_path=self.load_path,
            output_path=self.load_producer_path,
            context=context("load"),
            now=self.now,
        )
        PRODUCER.produce(
            domain="failure",
            source_path=self.source_path,
            candidate_path=self.candidate_path,
            evidence_root=self.failure_root,
            report_path=self.failure_path,
            output_path=self.failure_producer_path,
            context=context("failure"),
            now=self.now,
        )
        bundle = {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"}
        self.write(self.load_attestation_path, bundle)
        self.write(self.failure_attestation_path, bundle)

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
            "contract_version": "1.0.0",
            "protocol_version": "1",
        }

    @staticmethod
    def representative_row_counts() -> dict[str, int]:
        return {name: 1 for name in MODULE.OPERATIONAL_STATE_TABLES}

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
            "row_counts": self.representative_row_counts(),
        }

    def _write_drills(self) -> None:
        self._write_image_inspection()
        archive = self.drill_dir / "backup.dump"
        archive.write_bytes(b"PGDMP bounded test archive")
        backup_log = self.drill_dir / "backup.log.json"
        backup_log.write_text('{"status":"passed"}\n', encoding="utf-8")
        upgrade_log = self.drill_dir / "upgrade.log.json"
        upgrade_log.write_text('{"status":"passed"}\n', encoding="utf-8")
        previous_version = self.version(
            self.previous_candidate_version, self.previous_commit
        )
        source = {
            "database_identity_sha256": "7" * 64,
            "image": self.previous_candidate_platform_image,
            "version": previous_version,
            "migration": self.migration(),
            "doctor": self.doctor(),
            "health": {"status": "ok", "build": previous_version},
            "readiness": self.readiness(),
            "state_fingerprint_sha256": "6" * 64,
            "row_counts": self.representative_row_counts(),
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
                "previous_candidate_commit": self.previous_commit,
                "previous_candidate_intended_tag": self.previous_candidate_tag,
                "previous_candidate_oci_reference": self.previous_candidate_image,
                "previous_candidate_platform_oci_reference": self.previous_candidate_platform_image,
                "candidate_oci_reference": self.image,
                "candidate_platform_oci_reference": self.platform_image,
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
                "previous_candidate_commit": self.previous_commit,
                "previous_candidate_intended_tag": self.previous_candidate_tag,
                "previous_candidate_oci_reference": self.previous_candidate_image,
                "previous_candidate_platform_oci_reference": self.previous_candidate_platform_image,
                "candidate_oci_reference": self.image,
                "candidate_platform_oci_reference": self.platform_image,
                "postgres_oci_reference": self.postgres_image,
                "started_at": "2026-08-29T11:00:01Z",
                "finished_at": "2026-08-29T11:10:00Z",
                "previous_before": self.stage(
                    self.previous_candidate_platform_image,
                    self.previous_candidate_version,
                    self.previous_commit,
                ),
                "candidate_after": self.stage(
                    self.platform_image, "1.0.0", self.commit
                ),
                "previous_rollback": self.stage(
                    self.previous_candidate_platform_image,
                    self.previous_candidate_version,
                    self.previous_commit,
                ),
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
                "candidate_platform_oci_reference": self.platform_image,
                "candidate_revision": self.commit,
                "candidate_platform_repo_digests": [self.platform_image],
                "previous_candidate_oci_reference": self.previous_candidate_image,
                "previous_candidate_platform_oci_reference": self.previous_candidate_platform_image,
                "previous_candidate_revision": self.previous_commit,
                "previous_candidate_version": self.previous_candidate_version,
                "previous_candidate_intended_tag": self.previous_candidate_tag,
                "previous_candidate_platform_repo_digests": [
                    self.previous_candidate_platform_image
                ],
                "platform": "linux/amd64",
                "postgres_oci_reference": self.postgres_image,
                "postgres_repo_digests": [self.postgres_image],
                "network_internal": True,
                "source_database_identity_sha256": "7" * 64,
                "restore_database_identity_sha256": "8" * 64,
            },
        )

    def write_raw_drill_observations(self) -> None:
        previous = self.stage(
            self.previous_candidate_platform_image,
            self.previous_candidate_version,
            self.previous_commit,
        )
        candidate = self.stage(self.platform_image, "1.0.0", self.commit)
        rollback = self.stage(
            self.previous_candidate_platform_image,
            self.previous_candidate_version,
            self.previous_commit,
        )
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
        previous_build = self.version(
            self.previous_candidate_version, self.previous_commit
        )
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
                "row_counts": self.representative_row_counts(),
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

    def finalize(
        self,
        name: str = "output",
        *,
        previous_candidate_commit: str | None = None,
        previous_candidate_run_id: str | None = None,
    ) -> dict[str, object]:
        return MODULE.finalize(
            candidate_manifest=self.fixture.candidate_path,
            previous_candidate_manifest=self.fixture.previous_candidate_path,
            previous_candidate_attestation=self.fixture.previous_candidate_attestation_path,
            previous_candidate_run=self.fixture.previous_candidate_run_path,
            previous_candidate_commit=(
                previous_candidate_commit or self.fixture.previous_commit
            ),
            previous_candidate_run_id=(
                previous_candidate_run_id or self.fixture.previous_candidate_run_id
            ),
            source_conformance=self.fixture.source_path,
            load_report=self.fixture.load_path,
            load_producer_manifest=self.fixture.load_producer_path,
            load_producer_attestation=self.fixture.load_attestation_path,
            load_producer_run_id="12345",
            failure_report=self.fixture.failure_path,
            failure_producer_manifest=self.fixture.failure_producer_path,
            failure_producer_attestation=self.fixture.failure_attestation_path,
            failure_producer_run_id="12346",
            failure_evidence_dir=self.fixture.failure_dir,
            backup_report=self.fixture.backup_path,
            upgrade_report=self.fixture.upgrade_path,
            output_directory=self.root / name,
            now=self.fixture.now,
            repository_root=self.fixture.repository_root,
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
        self.assertTrue(
            MODULE.semver_less(self.fixture.previous_candidate_version, "1.0.0")
        )
        self.assertEqual(len(document["artifacts"]), 14)
        output = self.root / "output"
        self.assertEqual(json.loads((output / "operational_resilience.json").read_text()), document)
        raw = json.loads(
            (
                output
                / "artifacts/operational-resilience/raw-artifact-index.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            raw["previous_candidate"],
            {
                "attestation_sha256": self.fixture.digest(
                    self.fixture.previous_candidate_attestation_path
                ),
                "commit": self.fixture.previous_commit,
                "intended_tag": "v1.0.0-rc.1",
                "manifest_sha256": self.fixture.digest(
                    self.fixture.previous_candidate_path
                ),
                "oci_index_reference": self.fixture.previous_candidate_image,
                "oci_platform_reference": self.fixture.previous_candidate_platform_image,
                "run_attempt": 1,
                "run_id": self.fixture.previous_candidate_run_id,
                "run_receipt_sha256": self.fixture.digest(
                    self.fixture.previous_candidate_run_path
                ),
                "version": "1.0.0-rc.1",
            },
        )
        for artifact in document["artifacts"]:
            self.assertEqual(
                hashlib.sha256((output / artifact["path"]).read_bytes()).hexdigest(),
                artifact["sha256"],
            )

    def test_source_requires_exact_sdk_documentation_bundle_conformance(self) -> None:
        identifier = "source.sdk_documentation_bundles"
        self.assertIn(identifier, MODULE.SOURCE_CHECK_IDS)

        def remove_check(document: dict[str, object]) -> None:
            document["checks"] = [
                check
                for check in document["checks"]
                if check["id"] != identifier
            ]

        self.mutate(self.fixture.source_path, remove_check)
        with self.assertRaisesRegex(MODULE.EvidenceError, "source_checks_invalid"):
            self.finalize("missing-sdk-documentation-check")

    def test_rejects_tampered_or_substituted_prior_candidate_evidence(self) -> None:
        artifact = (
            self.fixture.previous_candidate_dir
            / "latchway-linux-amd64-vulnerability.json"
        )
        original_artifact = artifact.read_bytes()
        artifact.write_bytes(b"substituted scan")
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_artifact_hash_mismatch"
        ):
            self.finalize("prior-artifact-tamper")
        artifact.write_bytes(original_artifact)

        original_manifest = self.fixture.previous_candidate_path.read_bytes()
        self.fixture.previous_candidate_path.write_bytes(
            self.fixture.candidate_path.read_bytes()
        )
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_manifest_identity_mismatch"
        ):
            self.finalize("prior-manifest-substitution")
        self.fixture.previous_candidate_path.write_bytes(original_manifest)

        original_bundle = self.fixture.previous_candidate_attestation_path.read_bytes()
        self.fixture.previous_candidate_attestation_path.write_bytes(b"tampered bundle")
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_run_mismatch"
        ):
            self.finalize("prior-bundle-tamper")
        self.fixture.previous_candidate_attestation_path.write_bytes(original_bundle)

        self.fixture.previous_candidate_attestation_path.unlink()
        with self.assertRaisesRegex(MODULE.EvidenceError, "artifact_not_regular_file"):
            self.finalize("prior-bundle-missing")

    def test_rejects_wrong_prior_candidate_run_identity(self) -> None:
        cases = (
            (lambda value: value.__setitem__("run_id", "99999")),
            (
                lambda value: value.__setitem__(
                    "workflow_path", ".github/workflows/security.yml"
                )
            ),
            (lambda value: value.__setitem__("head_sha", self.fixture.commit)),
            (lambda value: value.__setitem__("head_branch", "release")),
            (lambda value: value.__setitem__("conclusion", "failure")),
            (
                lambda value: value.__setitem__(
                    "artifact_name", f"latchway-candidate-{self.fixture.commit}"
                )
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index):
                original = self.fixture.previous_candidate_run_path.read_bytes()
                self.mutate(self.fixture.previous_candidate_run_path, operation)
                with self.assertRaisesRegex(
                    MODULE.EvidenceError, "previous_candidate_run_mismatch"
                ):
                    self.finalize(f"prior-run-{index}")
                self.fixture.previous_candidate_run_path.write_bytes(original)
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_run_mismatch"
        ):
            self.finalize(
                "prior-run-input",
                previous_candidate_run_id="99999",
            )

    def test_requires_exact_lower_distinct_ancestor_candidate(self) -> None:
        self.assertTrue(MODULE.semver_less("1.0.0-rc.1", "1.0.0"))
        self.assertTrue(MODULE.semver_less("1.0.0-rc.2", "1.0.0-rc.10"))
        self.assertFalse(MODULE.semver_less("1.0.0-rc.1", "1.0.0-rc.1"))
        self.assertFalse(MODULE.semver_less("1.0.0", "1.0.0-rc.1"))
        self.assertTrue(MODULE.canonical_rc_to_final("1.0.0-rc.1", "1.0.0"))
        self.assertTrue(MODULE.canonical_rc_to_final("1.0.0-rc.10", "1.0.0"))
        for previous, current in (
            ("0.9.0", "1.0.0"),
            ("1.0.0-alpha.1", "1.0.0"),
            ("1.0.0-rc.0", "1.0.0"),
            ("1.0.0-rc.01", "1.0.0"),
            ("1.0.1-rc.1", "1.0.0"),
            ("1.0.0-rc.1", "1.0.0-rc.2"),
        ):
            with self.subTest(previous=previous, current=current):
                self.assertFalse(MODULE.canonical_rc_to_final(previous, current))
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_same_as_current"
        ):
            self.finalize(
                "same-candidate",
                previous_candidate_commit=self.fixture.commit,
            )

        tree = self.fixture._git("rev-parse", f"{self.fixture.previous_commit}^{{tree}}")
        unrelated = self.fixture._git("commit-tree", tree, "-m", "unrelated candidate")
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_not_ancestor"
        ):
            MODULE.validate_distinct_ancestor(
                self.fixture.repository_root, unrelated, self.fixture.commit
            )

        original = self.fixture.previous_candidate_path.read_bytes()
        self.mutate(
            self.fixture.previous_candidate_path,
            lambda value: value.update(
                intended_tag="v1.0.1", version="1.0.1"
            ),
        )
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_identity_mismatch"
        ):
            self.finalize("prior-not-lower")
        self.fixture.previous_candidate_path.write_bytes(original)

        self.mutate(
            self.fixture.previous_candidate_path,
            lambda value: value.__setitem__("created_at", "2026-08-29T10:06:00Z"),
        )
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "previous_candidate_identity_mismatch"
        ):
            self.finalize("prior-not-earlier")
        self.fixture.previous_candidate_path.write_bytes(original)

    def test_workflow_authenticates_current_and_prior_untagged_candidates(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        verification = workflow.index(
            "- name: Verify current, prior-candidate, source, load, and failure attestations"
        )
        finalization = workflow.index("- name: Seal the operational-resilience domain")
        self.assertLess(verification, finalization)
        for signer in (
            "release.yml",
            "cross-repository-conformance.yml",
            "release-load-evidence.yml",
            "release-failure-evidence.yml",
        ):
            self.assertIn(
                f'--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/{signer}"',
                workflow,
            )
        self.assertEqual(workflow.count('--source-digest "$CANDIDATE_COMMIT"'), 4)
        self.assertEqual(
            workflow.count('--source-digest "$PREVIOUS_CANDIDATE_COMMIT"'), 1
        )
        self.assertEqual(workflow.count("--source-ref refs/heads/main"), 5)
        self.assertEqual(workflow.count("--deny-self-hosted-runners"), 5)
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', workflow)
        self.assertIn(
            'git merge-base --is-ancestor "$PREVIOUS_CANDIDATE_COMMIT" "$CANDIDATE_COMMIT"',
            workflow,
        )
        self.assertIn(
            '.path == ".github/workflows/release.yml" and .state == "active"',
            workflow,
        )
        self.assertIn("latchway_previous_candidate_run", workflow)
        self.assertIn("previous-candidate-run-receipt.json", workflow)
        self.assertIn("manifest_sha256: $manifest_sha256", workflow)
        self.assertIn("attestation_sha256: $attestation_sha256", workflow)
        self.assertIn("$LOAD_RUN_ID:$LOAD_RUN_ATTEMPT:.github/workflows/release-load-evidence.yml", workflow)
        self.assertIn("$FAILURE_RUN_ID:$FAILURE_RUN_ATTEMPT:.github/workflows/release-failure-evidence.yml", workflow)
        self.assertIn("/actions/runs/$run_id/attempts/$attempt", workflow)
        self.assertIn('--load-producer-run-id "${{ inputs.load_evidence_run_id }}"', workflow)
        self.assertIn(
            '--failure-producer-run-id "${{ inputs.failure_evidence_run_id }}"',
            workflow,
        )
        self.assertIn("operational_resilience.attestation.sigstore.json", workflow)
        self.assertNotIn("refs/tags/", workflow)
        self.assertNotIn("ghcr.io/latchway/latchway:$", workflow)

    def test_fixed_producer_workflows_are_protected_and_commit_pinned(self) -> None:
        load = LOAD_WORKFLOW.read_text(encoding="utf-8")
        failure = FAILURE_WORKFLOW.read_text(encoding="utf-8")
        for workflow in (load, failure):
            self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
            self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', workflow)
            self.assertIn("--signer-digest \"$CANDIDATE_COMMIT\"", workflow)
            self.assertEqual(workflow.count("--source-ref refs/heads/main"), 2)
            self.assertEqual(workflow.count("--deny-self-hosted-runners"), 2)
            self.assertNotIn("refs/tags/", workflow)
            for action in re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn("environment: release-load-evidence", load)
        self.assertIn("runs-on: ubuntu-24.04", load)
        self.assertIn("-release-image \"$CANDIDATE_INDEX\"", load)
        self.assertIn("-release-platform-image \"$CANDIDATE_AMD64\"", load)
        self.assertIn(
            "-preloaded-platform-image-id \"$CANDIDATE_LOCAL_IMAGE_ID\"", load
        )
        self.assertIn(
            "-preloaded-postgres-image-id \"$POSTGRES_LOCAL_IMAGE_ID\"", load
        )
        self.assertIn("--domain load", load)
        self.assertIn("load-producer.attestation.sigstore.json", load)
        self.assertIn("environment: release-failure-evidence", failure)
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, latchway-release-failure]",
            failure,
        )
        self.assertNotIn("LATCHWAY_RELEASE_FAILURE_CONTROLLER_PLAN", failure)
        self.assertIn("scripts/run-release-failure-controller.sh", failure)
        launcher = SCRIPT.with_name("run-release-failure-controller.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("/tools/latchway-failure-driver serve", launcher)
        self.assertIn("docker pull --platform linux/amd64", failure)
        self.assertIn("docker logout ghcr.io", failure)
        self.assertIn("--acknowledge-disposable-target", failure)
        self.assertIn("-scope release", failure)
        self.assertIn("--domain failure", failure)
        self.assertIn("failure-producer.attestation.sigstore.json", failure)

    def test_workflow_privilege_boundaries_are_job_isolated(self) -> None:
        workflows = {
            "operational-resilience-evidence.yml": (
                WORKFLOW,
                {"authenticate", "finalize", "attest"},
                "authenticate",
                "finalize",
                "operational-resilience-evidence",
            ),
            "release-load-evidence.yml": (
                LOAD_WORKFLOW,
                {"authenticate", "load", "attest"},
                "authenticate",
                "load",
                "release-load-evidence",
            ),
            "release-failure-evidence.yml": (
                FAILURE_WORKFLOW,
                {"authenticate", "failure", "attest"},
                "authenticate",
                "failure",
                "release-failure-evidence",
            ),
        }
        candidate_command = re.compile(
            r"(?m)^\s*(?:sudo\s+)?(?:python3?|node|npm|pnpm|go|make|gradle|swift|"
            r"xcodebuild|(?:\./)?scripts/)(?:\s|$)"
        )
        for workflow_name, (
            path,
            expected_jobs,
            authentication_name,
            candidate_name,
            authentication_environment,
        ) in workflows.items():
            with self.subTest(workflow=workflow_name):
                value = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertEqual(value["permissions"], {})
                jobs = value["jobs"]
                self.assertEqual(set(jobs), expected_jobs)
                authentication = jobs[authentication_name]
                candidate = jobs[candidate_name]
                attester = jobs["attest"]

                self.assertEqual(
                    authentication["environment"], authentication_environment
                )
                self.assertNotIn("environment", candidate)
                self.assertEqual(attester["environment"], "release-evidence-signing")
                self.assertEqual(candidate["needs"], authentication_name)
                self.assertEqual(attester["needs"], candidate_name)

                for name in (authentication_name, candidate_name):
                    permissions = jobs[name]["permissions"]
                    self.assertNotIn("id-token", permissions, name)
                    self.assertNotIn("attestations", permissions, name)
                    self.assertNotIn("artifact-metadata", permissions, name)
                if workflow_name in {
                    "operational-resilience-evidence.yml",
                    "release-load-evidence.yml",
                }:
                    self.assertEqual(
                        authentication["permissions"].get("packages"), "read"
                    )
                    self.assertNotIn("packages", candidate["permissions"])
                else:
                    self.assertEqual(candidate["permissions"].get("packages"), "read")
                self.assertEqual(attester["permissions"]["id-token"], "write")
                self.assertEqual(attester["permissions"]["attestations"], "write")
                self.assertEqual(
                    attester["permissions"]["artifact-metadata"], "write"
                )

                authentication_text = json.dumps(authentication, sort_keys=True)
                attester_text = json.dumps(attester, sort_keys=True)
                self.assertNotIn("actions/checkout@", authentication_text)
                self.assertNotIn("actions/checkout@", attester_text)
                self.assertNotIn("${{ secrets.", authentication_text)
                self.assertNotIn("${{ secrets.", attester_text)
                self.assertNotIn("${{ github.token }}", attester_text)
                for protected_job in (authentication, attester):
                    for step in protected_job["steps"]:
                        self.assertIsNone(
                            candidate_command.search(str(step.get("run", ""))),
                            step.get("name"),
                        )

                authentication_uses = [
                    str(step.get("uses", "")) for step in authentication["steps"]
                ]
                candidate_uses = [
                    str(step.get("uses", "")) for step in candidate["steps"]
                ]
                candidate_runs = "\n".join(
                    str(step.get("run", "")) for step in candidate["steps"]
                )
                if workflow_name in {
                    "operational-resilience-evidence.yml",
                    "release-load-evidence.yml",
                }:
                    self.assertEqual(
                        sum(
                            value.startswith("docker/login-action@")
                            for value in authentication_uses
                        ),
                        1,
                    )
                    authentication_runs = "\n".join(
                        str(step.get("run", ""))
                        for step in authentication["steps"]
                    )
                    for forbidden in (
                        "docker run",
                        "docker build",
                        "docker load",
                        "docker compose",
                    ):
                        self.assertNotIn(forbidden, authentication_runs)
                    self.assertIn("docker pull --platform linux/amd64", authentication_runs)
                    self.assertIn("docker save --output", authentication_runs)
                    self.assertFalse(
                        any(
                            value.startswith("docker/login-action@")
                            for value in candidate_uses
                        )
                    )
                    self.assertNotIn("docker pull", candidate_runs)
                    self.assertIn("docker load", candidate_runs)
                    self.assertIn("preloaded-images.tar", candidate_runs)
                    self.assertIn("archive_size <= 2147483648", candidate_runs)
                    self.assertIn("(.auths // {}) | length", candidate_runs)
                    self.assertIn(
                        "DOCKER_CONFIG=%s\\n", candidate_runs
                    )
                    self.assertIn(
                        "$RUNNER_TEMP/credential-free-docker", candidate_runs
                    )
                else:
                    self.assertEqual(
                        sum(
                            value.startswith("docker/login-action@")
                            for value in candidate_uses
                        ),
                        1,
                    )
                    self.assertIn("docker pull --platform linux/amd64", candidate_runs)
                    self.assertIn("docker logout ghcr.io", candidate_runs)
                    self.assertLess(
                        candidate_runs.index("docker logout ghcr.io"),
                        candidate_runs.index("scripts/run-release-failure-controller.sh"),
                    )

                checkouts = [
                    step
                    for step in candidate["steps"]
                    if str(step.get("uses", "")).startswith("actions/checkout@")
                ]
                self.assertEqual(len(checkouts), 1)
                self.assertFalse(checkouts[0]["with"]["persist-credentials"])
                candidate_text = json.dumps(candidate, sort_keys=True)
                self.assertLessEqual(
                    set(re.findall(r"\$\{\{ secrets\.([A-Za-z0-9_]+) \}\}", candidate_text)),
                    {"GITHUB_TOKEN"},
                )
                self.assertIn(
                    'test -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}"',
                    "\n".join(str(step.get("run", "")) for step in candidate["steps"]),
                )
                attester_names = [step.get("name", "") for step in attester["steps"]]
                self.assertTrue(
                    any(
                        name.startswith("Download the independently authenticated")
                        for name in attester_names
                    )
                )
                validation = next(
                    step
                    for step in attester["steps"]
                    if step.get("name", "").startswith("Validate the complete")
                )["run"]
                self.assertIn("sha256sum", validation)
                self.assertIn("cmp --silent", validation)

                for job_name, job in jobs.items():
                    permissions = job.get("permissions", {})
                    privileged = (
                        permissions.get("id-token") == "write"
                        or permissions.get("attestations") == "write"
                        or permissions.get("artifact-metadata") == "write"
                    )
                    if not privileged:
                        continue
                    serialized = json.dumps(job, sort_keys=True)
                    self.assertNotIn("actions/checkout@", serialized, job_name)
                    for step in job["steps"]:
                        self.assertIsNone(
                            candidate_command.search(str(step.get("run", ""))),
                            step.get("name"),
                        )

    def test_preloaded_launchers_forbid_registry_fallback_and_preserve_coordinates(self) -> None:
        load = LOAD_LAUNCHER.read_text(encoding="utf-8")
        operational = OPERATIONAL_LAUNCHER.read_text(encoding="utf-8")

        for value in (
            "-preloaded-platform-image-id",
            "-preloaded-postgres-image-id",
            'preloaded_mode=true',
            'gateway_runtime_image=$preloaded_platform_image_id',
            'postgres_runtime_image=$preloaded_postgres_image_id',
            '-release-oci-platform-reference "$release_platform_image"',
        ):
            self.assertIn(value, load)
        self.assertIn('if [ "$preloaded_mode" = true ]; then', load)
        self.assertIn('else\n    docker pull --platform linux/amd64', load)
        self.assertIn('"$gateway_runtime_image" >/dev/null', load)
        self.assertIn('"$postgres_runtime_image" \\', load)

        for value in (
            "--preloaded-candidate-platform-image-id",
            "--preloaded-previous-platform-image-id",
            "--preloaded-postgres-image-id",
            'preloaded_mode=true',
            'candidate_runtime_image=$preloaded_candidate_platform_image_id',
            'previous_candidate_runtime_image=$preloaded_previous_platform_image_id',
            'postgres_runtime_image=$preloaded_postgres_image_id',
            '--candidate-platform-image "$candidate_platform_image"',
            '--previous-candidate-platform-image "$previous_candidate_platform_image"',
            '--postgres-image "$postgres_image"',
        ):
            self.assertIn(value, operational)
        self.assertIn('if [[ "$preloaded_mode" == true ]]; then', operational)
        self.assertIn('else\n  docker pull --platform linux/amd64', operational)
        self.assertIn('run_cli "$candidate_runtime_image"', operational)
        self.assertIn('run_cli "$previous_candidate_runtime_image"', operational)
        self.assertIn('"$postgres_runtime_image" >/dev/null', operational)

    def test_final_artifact_coordinates_match_every_consumer(self) -> None:
        operational = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        load = yaml.safe_load(LOAD_WORKFLOW.read_text(encoding="utf-8"))
        failure = yaml.safe_load(FAILURE_WORKFLOW.read_text(encoding="utf-8"))
        aggregate = yaml.safe_load(AGGREGATE_WORKFLOW.read_text(encoding="utf-8"))

        def artifact_name(workflow: dict, job: str, step_name: str) -> str:
            step = next(
                item
                for item in workflow["jobs"][job]["steps"]
                if item.get("name") == step_name
            )
            return step["with"]["name"]

        self.assertEqual(
            artifact_name(
                load, "attest", "Retain only exact attested release-load evidence"
            ),
            "latchway-release-load-${{ inputs.candidate_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        self.assertEqual(
            artifact_name(
                operational,
                "authenticate",
                "Download exact-release-image load evidence",
            ),
            "latchway-release-load-${{ inputs.candidate_commit }}-${{ inputs.load_evidence_run_id }}-${{ inputs.load_evidence_run_attempt }}",
        )
        self.assertEqual(
            artifact_name(
                failure,
                "attest",
                "Retain only exact attested destructive-failure evidence",
            ),
            "latchway-release-failure-${{ inputs.candidate_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        self.assertEqual(
            artifact_name(
                operational,
                "authenticate",
                "Download release-scope destructive failure evidence",
            ),
            "latchway-release-failure-${{ inputs.candidate_commit }}-${{ inputs.failure_evidence_run_id }}-${{ inputs.failure_evidence_run_attempt }}",
        )
        self.assertEqual(
            artifact_name(
                operational,
                "attest",
                "Retain the domain document and bounded reports",
            ),
            "latchway-operational-resilience-${{ inputs.candidate_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        self.assertEqual(
            artifact_name(
                aggregate,
                "authenticate",
                "Download operational-resilience domain",
            ),
            "latchway-operational-resilience-${{ inputs.candidate_commit }}-${{ inputs.operational_resilience_run_id }}-${{ inputs.operational_resilience_run_attempt }}",
        )

    def test_rejects_tampered_or_unlisted_producer_artifact(self) -> None:
        config = self.fixture.load_dir / "load-config.json"
        original = config.read_bytes()
        self.mutate(config, lambda value: value.__setitem__("candidate", "substituted"))
        with self.assertRaisesRegex(MODULE.EvidenceError, "producer_artifact_hash_mismatch"):
            self.finalize("producer-config-tamper")
        config.write_bytes(original)

        unexpected = self.fixture.load_dir / "unlisted-observation.json"
        self.fixture.write(unexpected, {"unexpected": True})
        with self.assertRaisesRegex(MODULE.EvidenceError, "producer_artifact_set_mismatch"):
            self.finalize("producer-extra-artifact")
        unexpected.unlink()

    def test_rejects_producer_identity_run_digest_and_time_substitution(self) -> None:
        cases = (
            (
                lambda value: value["producer"].__setitem__(
                    "workflow_ref",
                    "Latchway/latchway/.github/workflows/release.yml@refs/heads/main",
                ),
                "producer_context_invalid",
            ),
            (
                lambda value: value["producer"].__setitem__(
                    "environment", "unprotected"
                ),
                "producer_context_invalid",
            ),
            (
                lambda value: value["producer"].__setitem__(
                    "runner_environment", "self-hosted"
                ),
                "producer_context_invalid",
            ),
            (
                lambda value: value["producer"].__setitem__("run_id", "54321"),
                "producer_run_mismatch",
            ),
            (
                lambda value: value["producer"].__setitem__("source_commit", "b" * 40),
                "producer_source_mismatch",
            ),
            (
                lambda value: value["candidate"].__setitem__(
                    "oci_platform_reference",
                    "ghcr.io/latchway/latchway@sha256:" + "8" * 64,
                ),
                "producer_candidate_mismatch",
            ),
            (
                lambda value: value["inputs"].__setitem__(
                    "candidate_manifest_sha256", "8" * 64
                ),
                "producer_input_mismatch",
            ),
            (
                lambda value: value["invocation"]["command"].__setitem__(
                    -1, "b" * 40
                ),
                "producer_invocation_mismatch",
            ),
            (
                lambda value: value.__setitem__("finished_at", "2026-08-29T10:19:59Z"),
                "producer_evidence_interval_mismatch",
            ),
        )
        for index, (operation, code) in enumerate(cases):
            with self.subTest(code=code):
                original = self.fixture.load_producer_path.read_bytes()
                self.mutate(self.fixture.load_producer_path, operation)
                with self.assertRaisesRegex(MODULE.EvidenceError, code):
                    self.finalize(f"producer-identity-{index}")
                self.fixture.load_producer_path.write_bytes(original)

    def test_rejects_missing_or_cross_domain_producer(self) -> None:
        original = self.fixture.load_producer_path.read_bytes()
        self.fixture.load_producer_path.unlink()
        with self.assertRaisesRegex(MODULE.EvidenceError, "artifact_not_regular_file"):
            self.finalize("producer-missing")
        self.fixture.load_producer_path.write_bytes(original)

        attestation = self.fixture.load_attestation_path.read_bytes()
        self.fixture.load_attestation_path.unlink()
        with self.assertRaisesRegex(MODULE.EvidenceError, "artifact_not_regular_file"):
            self.finalize("producer-attestation-missing")
        self.fixture.load_attestation_path.write_bytes(attestation)

        self.fixture.load_producer_path.write_bytes(
            self.fixture.failure_producer_path.read_bytes()
        )
        with self.assertRaisesRegex(MODULE.EvidenceError, "producer_manifest_invalid"):
            self.finalize("producer-cross-domain")
        self.fixture.load_producer_path.write_bytes(original)

    def test_rejects_tampered_raw_artifact(self) -> None:
        (self.fixture.drill_dir / "backup.dump").write_bytes(b"substituted archive")
        with self.assertRaisesRegex(MODULE.EvidenceError, "artifact_hash_mismatch"):
            self.finalize()

    def test_rejects_tampered_automated_failure_log(self) -> None:
        log = next((self.fixture.failure_root / "failure-release.logs").iterdir())
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

    def test_rejects_shallow_operational_state(self) -> None:
        def remove_representative_domains(value: dict[str, object]) -> None:
            value["source"]["row_counts"] = {
                "organizations": 1,
                "applications": 1,
                "environments": 1,
            }

        self.mutate(self.fixture.backup_path, remove_representative_domains)
        with self.assertRaisesRegex(MODULE.EvidenceError, "backup_source_invalid"):
            self.finalize("shallow-state-output")

    def test_rejects_unproved_multi_replica_claim(self) -> None:
        path = self.fixture.failure_dir / "live-config-and-key-rotation-across-api-replicas.json"
        self.mutate(path, lambda value: value["environment"].__setitem__("api_replicas", "1"))
        with self.assertRaisesRegex(MODULE.EvidenceError, "multi_replica_environment_invalid"):
            self.finalize()

    def test_rejects_tampered_load_target_and_scenario_claim_set(self) -> None:
        original_load = self.fixture.load_path.read_bytes()

        for percentile, widened in (("p50", 16), ("p95", 21), ("p99", 31)):
            def widen_overhead(
                value: dict[str, object],
                percentile: str = percentile,
                widened: int = widened,
            ) -> None:
                gate = next(
                    gate for gate in value["gates"] if gate["name"] == "gateway_overhead"
                )
                gate["metrics"]["targets_ms"][percentile] = widened

            self.mutate(self.fixture.load_path, widen_overhead)
            with self.assertRaisesRegex(MODULE.EvidenceError, "load_gate_metrics_invalid"):
                self.finalize(f"load-{percentile}-target-output")
            self.fixture.load_path.write_bytes(original_load)

        for percentile, boundary in (("p50", 15), ("p95", 20), ("p99", 30)):
            def reach_overhead_boundary(
                value: dict[str, object],
                percentile: str = percentile,
                boundary: int = boundary,
            ) -> None:
                gate = next(
                    gate for gate in value["gates"] if gate["name"] == "gateway_overhead"
                )
                gate["metrics"][f"{percentile}_overhead_ms"] = boundary

            self.mutate(self.fixture.load_path, reach_overhead_boundary)
            with self.assertRaisesRegex(MODULE.EvidenceError, "load_gate_metrics_invalid"):
                self.finalize(f"load-{percentile}-boundary-output")
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

    def test_rejects_prior_candidate_that_cannot_run_candidate_schema(self) -> None:
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
            previous_candidate_commit=self.fixture.previous_commit,
            previous_candidate_version=self.fixture.previous_candidate_version,
            previous_candidate_tag=self.fixture.previous_candidate_tag,
            previous_candidate_image=self.fixture.previous_candidate_image,
            previous_candidate_platform_image=self.fixture.previous_candidate_platform_image,
            candidate_image=self.fixture.image,
            candidate_platform_image=self.fixture.platform_image,
            postgres_image=self.fixture.postgres_image,
            started_at="2026-08-29T10:50:00Z",
            finished_at="2026-08-29T11:10:00Z",
        )
        self.assertEqual(backup["status"], "passed")
        self.assertTrue(
            backup["assertions"]["representative_operational_state_preserved"]
        )
        self.assertTrue(
            upgrade["assertions"]["candidate_migration_status_validated"]
        )
        self.assertNotIn("candidate_migrations_applied", upgrade["assertions"])
        self.assertEqual(
            backup["previous_candidate_intended_tag"], "v1.0.0-rc.1"
        )
        self.assertEqual(
            backup["source"]["image"],
            self.fixture.previous_candidate_platform_image,
        )
        self.assertEqual(upgrade["candidate_after"]["version"]["commit"], self.fixture.commit)
        self.assertEqual(
            upgrade["candidate_after"]["image"], self.fixture.platform_image
        )
        self.assertNotIn("previous_oci_reference", backup)
        self.assertNotIn("previous_release_tag", backup)

        inspection = self.fixture.drill_dir / "image-inspection.json"
        self.mutate(inspection, lambda value: value.__setitem__("candidate_revision", "b" * 40))
        with self.assertRaisesRegex(DRILL.DrillError, "drill_image_identity_mismatch"):
            DRILL.build_reports(
                root=self.fixture.drill_dir,
                commit=self.fixture.commit,
                previous_candidate_commit=self.fixture.previous_commit,
                previous_candidate_version=self.fixture.previous_candidate_version,
                previous_candidate_tag=self.fixture.previous_candidate_tag,
                previous_candidate_image=self.fixture.previous_candidate_image,
                previous_candidate_platform_image=self.fixture.previous_candidate_platform_image,
                candidate_image=self.fixture.image,
                candidate_platform_image=self.fixture.platform_image,
                postgres_image=self.fixture.postgres_image,
                started_at="2026-08-29T10:50:00Z",
                finished_at="2026-08-29T11:10:00Z",
            )


if __name__ == "__main__":
    unittest.main()
