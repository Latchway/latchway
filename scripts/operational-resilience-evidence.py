#!/usr/bin/env python3
"""Validate and seal release-blocking operational-resilience evidence.

This finalizer does not run load or destructive tests itself. It accepts only
the machine reports emitted by the dedicated release environments, revalidates
their candidate identity and raw artifact hashes, and emits the exact external
domain document consumed by the cross-repository promotion gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
TAG = re.compile(r"^v" + SEMVER.pattern[1:])
OCI = re.compile(r"^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$")
POSTGRES_OCI = re.compile(
    r"^docker\.io/library/postgres@sha256:[0-9a-f]{64}$"
)
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)
MAXIMUM_AGE = timedelta(days=7)
MAXIMUM_FILE_BYTES = 100 * 1024 * 1024
MAXIMUM_JSON_BYTES = 16 * 1024 * 1024
REPOSITORY_IDS = ("core", "javascript", "ios", "android", "react_native")
SOURCE_CHECK_IDS = frozenset(
    (
        "source.repository_layout",
        "source.clean_worktrees",
        "source.core_contract",
        "source.contract_bundle",
        "source.contract_locks",
        "source.generated_fixtures",
        "source.package_versions",
        "source.react_native_pins",
    )
)
SOURCE_UNVERIFIED_CHECKS = {
    "promotion.local_preconditions": ("local_promotion", "promotion_scope_not_requested"),
    "release.local_preconditions": ("local_release", "release_scope_not_requested"),
    "promotion.evidence_window": ("local_promotion", "promotion_scope_not_requested"),
    "external.live_sdk_conformance": (
        "live_sdk_conformance",
        "external_evidence_not_required_by_scope",
    ),
    "external.public_tags": ("public_tags", "external_evidence_not_required_by_scope"),
    "external.public_registries": (
        "public_registries",
        "external_evidence_not_required_by_scope",
    ),
    "external.physical_devices": (
        "physical_devices",
        "external_evidence_not_required_by_scope",
    ),
    "external.live_provider": (
        "live_provider",
        "external_evidence_not_required_by_scope",
    ),
    "external.cloud_deployments": (
        "cloud_deployments",
        "external_evidence_not_required_by_scope",
    ),
    "external.operational_resilience": (
        "operational_resilience",
        "external_evidence_not_required_by_scope",
    ),
    "external.supply_chain": (
        "supply_chain",
        "external_evidence_not_required_by_scope",
    ),
}
SOURCE_DOMAIN_IDS = frozenset(
    (
        "local_source",
        "local_promotion",
        "local_release",
        "live_sdk_conformance",
        "public_tags",
        "public_registries",
        "physical_devices",
        "live_provider",
        "cloud_deployments",
        "operational_resilience",
        "supply_chain",
    )
)
LOAD_GATES = frozenset(
    (
        "preflight",
        "idle_memory",
        "gateway_overhead",
        "non_stream_100_rps",
        "sse_500_concurrent_memory",
        "quota_contention_zero_overspend",
    )
)
AUTOMATED_FAILURE_IDS = frozenset(
    (
        "reservation-reclamation-and-contention",
        "database-failure-semantics",
        "upstream-and-client-disconnect-semantics",
        "configuration-revision-atomicity",
        "gateway-signing-key-rotation",
        "jwks-rotation-and-shared-cache",
        "worker-failure-and-multiple-workers",
        "graceful-runtime-drain-semantics",
        "clock-skew-and-regression",
    )
)
EXTERNAL_FAILURE_IDS = frozenset(
    (
        "live-process-kill-after-reservation",
        "live-process-kill-during-stream",
        "live-database-outage-boundaries",
        "live-graceful-shutdown-and-drain",
        "live-upstream-and-client-disconnect",
        "live-config-and-key-rotation-across-api-replicas",
    )
)
MULTI_REPLICA_ASSERTIONS = frozenset(
    (
        "at_least_two_api_replicas_observed",
        "at_least_two_workers_observed",
        "load_balancer_routed_multiple_api_replicas",
        "configuration_revision_atomic_across_replicas",
        "signing_rotation_preserved_active_sessions",
        "jwks_rotation_converged",
    )
)
EXTERNAL_FAILURE_ASSERTIONS = {
    "live-process-kill-after-reservation": frozenset(
        (
            "process_sigkill_observed",
            "reservation_was_durable_before_kill",
            "replacement_worker_reclaimed_reservation",
            "no_usage_recorded_for_undispatched_attempt",
            "hard_quota_not_overspent",
        )
    ),
    "live-process-kill-during-stream": frozenset(
        (
            "sse_first_byte_observed_before_sigkill",
            "process_sigkill_observed",
            "replacement_api_and_worker_recovered",
            "reservation_settled_conservatively",
            "no_permanent_reservation",
            "hard_quota_not_overspent",
        )
    ),
    "live-database-outage-boundaries": frozenset(
        (
            "database_network_cut_observed",
            "predispatch_outage_failed_closed",
            "no_upstream_dispatch_during_predispatch_outage",
            "settlement_outage_created_bounded_pending_usage",
            "worker_reconciled_pending_usage_after_restore",
            "no_permanent_reservation",
        )
    ),
    "live-graceful-shutdown-and-drain": frozenset(
        (
            "sigterm_observed",
            "listener_rejected_new_work_during_drain",
            "nonstream_completed_or_terminated_within_drain_bound",
            "sse_completed_or_terminated_within_drain_bound",
            "process_exited_within_drain_bound",
            "no_permanent_reservation",
        )
    ),
    "live-upstream-and-client-disconnect": frozenset(
        (
            "pre_response_upstream_disconnect_observed",
            "mid_sse_upstream_disconnect_observed",
            "downstream_client_cancel_observed",
            "one_terminal_attempt_per_case",
            "usage_provenance_bounded_per_case",
            "no_permanent_reservation",
        )
    ),
    "live-config-and-key-rotation-across-api-replicas": MULTI_REPLICA_ASSERTIONS,
}
BACKUP_ASSERTIONS = frozenset(
    (
        "archive_nonempty",
        "archive_digest_verified",
        "source_and_restore_databases_distinct",
        "state_fingerprint_preserved",
        "schema_version_preserved",
        "previous_image_doctor_passed",
        "restored_runtime_ready_with_escrowed_master_key",
    )
)
UPGRADE_ASSERTIONS = frozenset(
    (
        "previous_release_started",
        "candidate_migrations_applied",
        "candidate_doctor_passed",
        "candidate_runtime_ready",
        "state_preserved_through_upgrade",
        "previous_image_application_rollback_started",
        "previous_image_doctor_passed_after_candidate",
        "previous_image_runtime_ready_after_candidate",
        "state_preserved_through_rollback",
        "schema_compatible_with_previous_image",
    )
)
DOMAIN_CLAIMS = {
    "v1_load_targets_verified": True,
    "live_failure_injection_verified": True,
    "multi_replica_verified": True,
    "backup_restore_drill_verified": True,
    "released_version_upgrade_rollback_verified": True,
}
CANDIDATE_ARTIFACTS = frozenset(
    (
        "latchway-contract.tar.gz",
        "latchway-linux-amd64.spdx.json",
        "latchway-linux-arm64.spdx.json",
        "latchway-linux-amd64-vulnerability.json",
        "latchway-linux-arm64-vulnerability.json",
        "latchway-linux-amd64-license.json",
        "latchway-linux-arm64-license.json",
    )
)


class EvidenceError(Exception):
    """A stable, redaction-safe operational-evidence failure."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("duplicate_json_member")
        value[key] = item
    return value


def real_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def real_directory(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)


def read_json(path: Path) -> dict[str, Any]:
    if not real_file(path):
        raise EvidenceError("evidence_file_invalid")
    size = path.stat().st_size
    if size <= 0 or size > MAXIMUM_JSON_BYTES:
        raise EvidenceError("evidence_file_invalid")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EvidenceError("evidence_json_invalid") from None
    if not isinstance(value, dict):
        raise EvidenceError("evidence_json_invalid")
    return value


def require_fields(value: Any, fields: Iterable[str], code: str) -> dict[str, Any]:
    expected = set(fields)
    if not isinstance(value, dict) or set(value) != expected:
        raise EvidenceError(code)
    return value


def parse_time(value: Any, code: str = "evidence_time_invalid") -> datetime:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        raise EvidenceError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise EvidenceError(code) from None
    return parsed.astimezone(timezone.utc)


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def parse_build_time(value: Any, code: str) -> datetime:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})",
            value,
        )
        is None
    ):
        raise EvidenceError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError(code) from None
    if parsed.tzinfo is None:
        raise EvidenceError(code)
    return parsed.astimezone(timezone.utc)


def semver_less(left: str, right: str) -> bool:
    def parts(value: str) -> tuple[tuple[int, int, int], list[str] | None]:
        base, separator, prerelease = value.partition("-")
        major, minor, patch = (int(item) for item in base.split("."))
        return ((major, minor, patch), prerelease.split(".") if separator else None)

    left_base, left_pre = parts(left)
    right_base, right_pre = parts(right)
    if left_base != right_base:
        return left_base < right_base
    if left_pre is None or right_pre is None:
        return left_pre is not None and right_pre is None
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdigit()
        right_numeric = right_item.isdigit()
        if left_numeric and right_numeric:
            return int(left_item) < int(right_item)
        if left_numeric != right_numeric:
            return left_numeric
        return left_item < right_item
    return len(left_pre) < len(right_pre)


def validate_interval(
    started_value: Any,
    finished_value: Any,
    *,
    released_at: datetime,
    now: datetime,
    code: str,
) -> tuple[datetime, datetime]:
    started = parse_time(started_value, code)
    finished = parse_time(finished_value, code)
    if (
        finished <= started
        or finished - started > MAXIMUM_AGE
        or started < released_at
        or finished > now
        or now - finished > MAXIMUM_AGE
    ):
        raise EvidenceError(code)
    return started, finished


def sha256_file(path: Path) -> str:
    if not real_file(path):
        raise EvidenceError("artifact_not_regular_file")
    size = path.stat().st_size
    if size <= 0 or size > MAXIMUM_FILE_BYTES:
        raise EvidenceError("artifact_size_invalid")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        return False
    path = PurePosixPath(value)
    return path.as_posix() == value and not any(
        part in ("", ".", "..") for part in path.parts
    )


def resolve_artifact(root: Path, relative: Any) -> Path:
    if not safe_relative_path(relative):
        raise EvidenceError("artifact_path_invalid")
    candidate = root / PurePosixPath(relative)
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise EvidenceError("artifact_path_invalid")
        except FileNotFoundError:
            raise EvidenceError("artifact_missing") from None
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise EvidenceError("artifact_path_invalid") from None
    return candidate


def validate_artifact_list(
    report_path: Path, artifacts: Any, code: str
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if not real_directory(report_path.parent):
        raise EvidenceError(code)
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 64:
        raise EvidenceError(code)
    seen: set[str] = set()
    normalized: list[dict[str, str]] = []
    index: list[dict[str, str]] = []
    for item in artifacts:
        item = require_fields(item, ("path", "sha256"), code)
        relative, expected = item["path"], item["sha256"]
        if (
            not safe_relative_path(relative)
            or relative in seen
            or not isinstance(expected, str)
            or SHA256.fullmatch(expected) is None
        ):
            raise EvidenceError(code)
        seen.add(relative)
        path = resolve_artifact(report_path.parent, relative)
        actual = sha256_file(path)
        if actual != expected:
            raise EvidenceError("artifact_hash_mismatch")
        normalized.append({"path": relative, "sha256": actual})
        index.append({"path": relative, "sha256": actual})
    return normalized, index


def validate_candidate(
    path: Path, source: Mapping[str, Any], now: datetime
) -> tuple[dict[str, Any], str, datetime]:
    if not real_directory(path.parent):
        raise EvidenceError("candidate_artifacts_invalid")
    value = require_fields(
        read_json(path),
        (
            "schema_version",
            "kind",
            "status",
            "created_at",
            "candidate_commit",
            "intended_tag",
            "version",
            "contract",
            "image",
            "artifacts",
        ),
        "candidate_fields_invalid",
    )
    repositories = source["repositories"]
    core = repositories["core"]
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_release_candidate"
        or value["status"] != "passed"
        or value["candidate_commit"] != core["commit"]
        or value["intended_tag"] != core["tag"]
        or value["version"] != core["version"]
    ):
        raise EvidenceError("candidate_identity_mismatch")
    created = parse_time(value["created_at"], "candidate_time_invalid")
    released_at = source["released_at"]
    if created < released_at or created > now or now - created > MAXIMUM_AGE:
        raise EvidenceError("candidate_time_invalid")
    contract = require_fields(
        value["contract"],
        ("version", "status", "released_at", "bundle_file_name", "bundle_sha256"),
        "candidate_contract_invalid",
    )
    source_contract = source["contract"]
    if (
        contract["version"] != source_contract["version"]
        or contract["status"] != "released"
        or parse_time(contract["released_at"], "candidate_contract_invalid")
        != released_at
        or contract["bundle_file_name"] != source_contract["bundle_file_name"]
        or contract["bundle_sha256"] != source_contract["bundle_sha256"]
    ):
        raise EvidenceError("candidate_contract_invalid")
    image = require_fields(
        value["image"], ("repository", "index_digest", "platforms"), "candidate_image_invalid"
    )
    platforms = image["platforms"]
    if (
        image["repository"] != "ghcr.io/latchway/latchway"
        or not isinstance(image["index_digest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image["index_digest"]) is None
        or not isinstance(platforms, dict)
        or set(platforms) != {"linux/amd64", "linux/arm64"}
        or any(
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            for digest in platforms.values()
        )
        or len(set(platforms.values())) != 2
    ):
        raise EvidenceError("candidate_image_invalid")
    reference = image["repository"] + "@" + image["index_digest"]
    if OCI.fullmatch(reference) is None:
        raise EvidenceError("candidate_image_invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(CANDIDATE_ARTIFACTS):
        raise EvidenceError("candidate_artifacts_invalid")
    seen: set[str] = set()
    for artifact in artifacts:
        artifact = require_fields(
            artifact, ("path", "sha256"), "candidate_artifacts_invalid"
        )
        relative, expected = artifact["path"], artifact["sha256"]
        if (
            relative not in CANDIDATE_ARTIFACTS
            or relative in seen
            or not isinstance(expected, str)
            or SHA256.fullmatch(expected) is None
        ):
            raise EvidenceError("candidate_artifacts_invalid")
        seen.add(relative)
        if sha256_file(resolve_artifact(path.parent, relative)) != expected:
            raise EvidenceError("candidate_artifact_hash_mismatch")
        if relative == "latchway-contract.tar.gz" and expected != contract["bundle_sha256"]:
            raise EvidenceError("candidate_contract_hash_mismatch")
    if seen != CANDIDATE_ARTIFACTS:
        raise EvidenceError("candidate_artifacts_invalid")
    return value, reference, created


def validate_source(path: Path, now: datetime) -> dict[str, Any]:
    value = read_json(path)
    required = {
        "schema_version",
        "kind",
        "scope",
        "verdict",
        "source_conformance_passed",
        "promotion_ready",
        "release_ready",
        "contract",
        "repositories",
        "evidence_window",
        "evidence_domains",
        "checks",
    }
    if set(value) != required:
        raise EvidenceError("source_conformance_fields_invalid")
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_cross_repository_conformance_evidence"
        or value["scope"] != "source"
        or value["verdict"] != "passed"
        or value["source_conformance_passed"] is not True
        or value["promotion_ready"] is not False
        or value["release_ready"] is not False
        or value["evidence_window"] is not None
    ):
        raise EvidenceError("source_conformance_not_passed")
    contract = value["contract"]
    required_contract = {
        "version",
        "status",
        "released_at",
        "wire_protocol",
        "bundle_file_name",
        "bundle_sha256",
        "core_release",
        "oci_image_digest",
    }
    if not isinstance(contract, dict) or set(contract) != required_contract:
        raise EvidenceError("source_contract_invalid")
    released_at = parse_time(contract["released_at"], "source_contract_invalid")
    if (
        contract["status"] != "released"
        or not isinstance(contract["version"], str)
        or SEMVER.fullmatch(contract["version"]) is None
        or contract["bundle_file_name"]
        != f"latchway-contract-{contract['version']}.tar.gz"
        or not isinstance(contract["bundle_sha256"], str)
        or SHA256.fullmatch(contract["bundle_sha256"]) is None
        or not isinstance(contract["core_release"], str)
        or TAG.fullmatch(contract["core_release"]) is None
        or contract["oci_image_digest"] is not None
        or released_at > now
    ):
        raise EvidenceError("source_contract_invalid")
    if (
        not isinstance(contract["wire_protocol"], int)
        or isinstance(contract["wire_protocol"], bool)
        or contract["wire_protocol"] < 1
    ):
        raise EvidenceError("source_contract_invalid")
    checks = value["checks"]
    expected_checks = SOURCE_CHECK_IDS | frozenset(SOURCE_UNVERIFIED_CHECKS)
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        raise EvidenceError("source_checks_invalid")
    observed_checks: dict[str, dict[str, Any]] = {}
    for check in checks:
        if not isinstance(check, dict):
            raise EvidenceError("source_checks_invalid")
        identifier = check.get("id")
        if identifier not in expected_checks or identifier in observed_checks:
            raise EvidenceError("source_checks_invalid")
        if (
            not isinstance(check.get("summary"), str)
            or not 1 <= len(check["summary"]) <= 500
        ):
            raise EvidenceError("source_checks_invalid")
        if identifier in SOURCE_CHECK_IDS:
            if (
                set(check) != {"id", "domain", "required", "status", "summary", "details"}
                or check["domain"] != "local_source"
                or check["required"] is not True
                or check["status"] != "passed"
                or not isinstance(check["details"], dict)
                or not check["details"]
            ):
                raise EvidenceError("source_checks_invalid")
        else:
            domain, reason = SOURCE_UNVERIFIED_CHECKS[identifier]
            if (
                set(check) != {"id", "domain", "required", "status", "summary", "reason"}
                or check["domain"] != domain
                or check["required"] is not False
                or check["status"] != "unverified"
                or check["reason"] != reason
            ):
                raise EvidenceError("source_checks_invalid")
        observed_checks[identifier] = check
    if set(observed_checks) != expected_checks:
        raise EvidenceError("source_checks_invalid")
    domains = value["evidence_domains"]
    if not isinstance(domains, list) or len(domains) != len(SOURCE_DOMAIN_IDS):
        raise EvidenceError("source_domains_invalid")
    observed_domains: set[str] = set()
    for domain in domains:
        domain = require_fields(
            domain,
            (
                "id",
                "required",
                "status",
                "started_at",
                "finished_at",
                "document_sha256",
                "oci_image_digest",
                "artifact_sha256",
            ),
            "source_domains_invalid",
        )
        identifier = domain["id"]
        if identifier not in SOURCE_DOMAIN_IDS or identifier in observed_domains:
            raise EvidenceError("source_domains_invalid")
        expected_passed = identifier == "local_source"
        if (
            domain["required"] is not expected_passed
            or domain["status"] != ("passed" if expected_passed else "unverified")
            or domain["started_at"] is not None
            or domain["finished_at"] is not None
            or domain["document_sha256"] is not None
            or domain["oci_image_digest"] is not None
            or domain["artifact_sha256"] != []
        ):
            raise EvidenceError("source_domains_invalid")
        observed_domains.add(identifier)
    if observed_domains != SOURCE_DOMAIN_IDS:
        raise EvidenceError("source_domains_invalid")
    repository_list = value["repositories"]
    if not isinstance(repository_list, list) or len(repository_list) != len(REPOSITORY_IDS):
        raise EvidenceError("source_repositories_invalid")
    repositories: dict[str, dict[str, str]] = {}
    for item in repository_list:
        item = require_fields(
            item,
            ("id", "commit", "version", "intended_tag"),
            "source_repositories_invalid",
        )
        repository_id = item["id"]
        commit, version, tag = item["commit"], item["version"], item["intended_tag"]
        if (
            repository_id not in REPOSITORY_IDS
            or repository_id in repositories
            or not isinstance(commit, str)
            or COMMIT.fullmatch(commit) is None
            or not isinstance(version, str)
            or SEMVER.fullmatch(version) is None
            or tag != "v" + version
        ):
            raise EvidenceError("source_repositories_invalid")
        repositories[repository_id] = {
            "commit": commit,
            "tag": tag,
            "version": version,
        }
    if set(repositories) != set(REPOSITORY_IDS):
        raise EvidenceError("source_repositories_invalid")
    if repositories["core"]["tag"] != contract["core_release"]:
        raise EvidenceError("source_contract_invalid")
    return {
        "document": value,
        "contract": contract,
        "repositories": repositories,
        "released_at": released_at,
    }


def evidence_number(value: Any) -> float | None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        return None
    return float(value)


def validate_result_evidence(
    value: Any, *, expected_total: int, allow_problem_codes: bool, code: str
) -> None:
    value = require_fields(
        value,
        ("statuses", "problem_codes", "request_errors", "invalid_problem_responses"),
        code,
    )
    statuses = value["statuses"]
    problems = value["problem_codes"]
    if (
        not isinstance(statuses, dict)
        or not statuses
        or any(
            not isinstance(status, str)
            or re.fullmatch(r"[1-5][0-9]{2}", status) is None
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            for status, count in statuses.items()
        )
        or sum(statuses.values()) != expected_total
        or not isinstance(problems, dict)
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            for name, count in problems.items()
        )
        or (not allow_problem_codes and problems != {})
        or value["request_errors"] != 0
        or value["invalid_problem_responses"] != 0
    ):
        raise EvidenceError(code)


def validate_terminal_quota_check(value: Any, metrics: set[str], code: str) -> None:
    value = require_fields(
        value,
        ("exact", "expected_feature", "observed_feature", "expected", "observed"),
        code,
    )
    if (
        value["exact"] is not True
        or not isinstance(value["expected_feature"], str)
        or not value["expected_feature"]
        or value["observed_feature"] != value["expected_feature"]
        or not isinstance(value["expected"], list)
        or not isinstance(value["observed"], list)
        or len(value["expected"]) != len(metrics)
        or len(value["observed"]) != len(metrics)
    ):
        raise EvidenceError(code)
    expected: dict[str, dict[str, Any]] = {}
    for limit in value["expected"]:
        limit = require_fields(
            limit,
            ("metric", "maximum", "used", "reserved", "remaining", "hard"),
            code,
        )
        metric = limit["metric"]
        if (
            metric not in metrics
            or metric in expected
            or any(
                not isinstance(limit[field], int)
                or isinstance(limit[field], bool)
                or limit[field] < 0
                for field in ("maximum", "used", "reserved", "remaining")
            )
            or limit["hard"] is not True
            or limit["reserved"] != 0
            or limit["remaining"] != limit["maximum"] - limit["used"]
        ):
            raise EvidenceError(code)
        expected[metric] = limit
    observed: set[str] = set()
    for limit in value["observed"]:
        limit = require_fields(
            limit,
            (
                "metric",
                "maximum",
                "used",
                "reserved",
                "remaining",
                "resets_at",
                "hard",
            ),
            code,
        )
        metric = limit["metric"]
        if (
            metric not in expected
            or metric in observed
            or any(limit[field] != expected[metric][field] for field in expected[metric])
            or (
                limit["resets_at"] is not None
                and (
                    not isinstance(limit["resets_at"], str)
                    or not limit["resets_at"]
                )
            )
        ):
            raise EvidenceError(code)
        observed.add(metric)
    if observed != metrics:
        raise EvidenceError(code)


def validate_contention_snapshot(value: Any, metric: str, code: str) -> dict[str, Any]:
    value = require_fields(value, ("feature", "observed_at", "limits"), code)
    if (
        not isinstance(value["feature"], str)
        or not value["feature"]
        or not isinstance(value["observed_at"], str)
        or not value["observed_at"]
        or not isinstance(value["limits"], list)
        or not 1 <= len(value["limits"]) <= 32
    ):
        raise EvidenceError(code)
    matches: list[dict[str, Any]] = []
    seen: set[str] = set()
    for limit in value["limits"]:
        limit = require_fields(
            limit,
            (
                "metric",
                "maximum",
                "used",
                "reserved",
                "remaining",
                "resets_at",
                "hard",
            ),
            code,
        )
        name = limit["metric"]
        if not isinstance(name, str) or not name or name in seen:
            raise EvidenceError(code)
        seen.add(name)
        if name == metric:
            if (
                any(
                    not isinstance(limit[field], int)
                    or isinstance(limit[field], bool)
                    or limit[field] < 0
                    for field in ("maximum", "used", "reserved", "remaining")
                )
                or limit["hard"] is not True
                or limit["used"] + limit["reserved"] > limit["maximum"]
                or limit["remaining"]
                != limit["maximum"] - limit["used"] - limit["reserved"]
            ):
                raise EvidenceError(code)
            matches.append(limit)
    if len(matches) != 1:
        raise EvidenceError(code)
    return matches[0]


def validate_load_gate_metrics(
    name: str, metrics: Any, fixture: Mapping[str, Any]
) -> None:
    code = "load_gate_metrics_invalid"
    if not isinstance(metrics, dict):
        raise EvidenceError(code)
    if name == "preflight":
        require_fields(metrics, ("ready_url", "protected_results"), code)
        if not isinstance(metrics["ready_url"], str) or not metrics["ready_url"]:
            raise EvidenceError(code)
        validate_result_evidence(
            metrics["protected_results"],
            expected_total=1,
            allow_problem_codes=False,
            code=code,
        )
        return
    if name == "idle_memory":
        require_fields(
            metrics,
            ("pid", "rss_samples_mib", "maximum_rss_mib", "target_mib"),
            code,
        )
        samples = metrics["rss_samples_mib"]
        maximum = evidence_number(metrics["maximum_rss_mib"])
        target = evidence_number(metrics["target_mib"])
        if (
            not isinstance(metrics["pid"], int)
            or isinstance(metrics["pid"], bool)
            or metrics["pid"] <= 0
            or not isinstance(samples, list)
            or len(samples) != 5
            or any(evidence_number(sample) is None or float(sample) < 0 for sample in samples)
            or maximum is None
            or target is None
            or maximum != max(float(sample) for sample in samples)
            or not 0 < target <= 256
            or maximum >= target
        ):
            raise EvidenceError(code)
        return
    if name == "gateway_overhead":
        require_fields(
            metrics,
            (
                "method",
                "samples",
                "p50_overhead_ms",
                "p95_overhead_ms",
                "p99_overhead_ms",
                "p50_gateway_e2e_ms",
                "p95_gateway_e2e_ms",
                "p99_gateway_e2e_ms",
                "p50_direct_upstream_ms",
                "p95_direct_upstream_ms",
                "p99_direct_upstream_ms",
                "targets_ms",
                "gateway_results",
                "direct_upstream_results",
            ),
            code,
        )
        samples = metrics["samples"]
        targets = metrics["targets_ms"]
        if (
            metrics["method"]
            != "paired client-observed gateway minus direct fixture latency, floored at zero"
            or not isinstance(samples, int)
            or isinstance(samples, bool)
            or samples < 20
            or samples != fixture["overhead_sample_requests"]
            or not isinstance(targets, dict)
            or set(targets) != {"p50", "p95", "p99"}
        ):
            raise EvidenceError(code)
        for percentile, ceiling in (("p50", 5), ("p95", 15), ("p99", 30)):
            target = evidence_number(targets[percentile])
            observed = evidence_number(metrics[f"{percentile}_overhead_ms"])
            if target is None or observed is None or not 0 < target <= ceiling or observed >= target:
                raise EvidenceError(code)
        result_total = samples + fixture["overhead_warmup_requests"]
        validate_result_evidence(
            metrics["gateway_results"],
            expected_total=result_total,
            allow_problem_codes=False,
            code=code,
        )
        validate_result_evidence(
            metrics["direct_upstream_results"],
            expected_total=result_total,
            allow_problem_codes=False,
            code=code,
        )
        return
    if name == "non_stream_100_rps":
        require_fields(
            metrics,
            (
                "target_rps",
                "duration_seconds",
                "scheduled",
                "successful",
                "failed",
                "results",
                "maximum_scheduler_lag_ms",
                "maximum_request_start_lag_ms",
                "schedule_lag_target_ms",
                "completion_elapsed_seconds",
                "p50_e2e_ms",
                "p95_e2e_ms",
                "p99_e2e_ms",
                "terminal_quota_check",
            ),
            code,
        )
        integers = (
            metrics["target_rps"],
            metrics["duration_seconds"],
            metrics["scheduled"],
            metrics["successful"],
            metrics["failed"],
        )
        lag = evidence_number(metrics["maximum_request_start_lag_ms"])
        lag_target = evidence_number(metrics["schedule_lag_target_ms"])
        if (
            any(not isinstance(item, int) or isinstance(item, bool) for item in integers)
            or metrics["target_rps"] < 100
            or metrics["duration_seconds"] < 10
            or metrics["scheduled"]
            != metrics["target_rps"] * metrics["duration_seconds"]
            or metrics["scheduled"] != fixture["non_stream_load_requests"]
            or metrics["successful"] != metrics["scheduled"]
            or metrics["failed"] != 0
            or lag is None
            or lag_target is None
            or lag >= lag_target
        ):
            raise EvidenceError(code)
        validate_result_evidence(
            metrics["results"],
            expected_total=metrics["scheduled"],
            allow_problem_codes=False,
            code=code,
        )
        validate_terminal_quota_check(
            metrics["terminal_quota_check"],
            {"logical_requests", "input_tokens", "output_tokens", "total_tokens"},
            code,
        )
        return
    if name == "sse_500_concurrent_memory":
        required = {
            "established",
            "target_concurrency",
            "hold_seconds",
            "premature_completions",
            "baseline_rss_mib",
            "peak_rss_mib",
            "growth_mib",
            "growth_target_mib",
            "plateau_slope_mib_per_minute",
            "slope_target_mib_per_minute",
            "rss_samples",
            "establishment_results",
            "terminal_quota_check",
        }
        if set(metrics) != required:
            raise EvidenceError(code)
        baseline = evidence_number(metrics["baseline_rss_mib"])
        peak = evidence_number(metrics["peak_rss_mib"])
        growth = evidence_number(metrics["growth_mib"])
        growth_target = evidence_number(metrics["growth_target_mib"])
        slope = evidence_number(metrics["plateau_slope_mib_per_minute"])
        slope_target = evidence_number(metrics["slope_target_mib_per_minute"])
        if (
            not isinstance(metrics["target_concurrency"], int)
            or isinstance(metrics["target_concurrency"], bool)
            or metrics["target_concurrency"] < 500
            or metrics["established"] != metrics["target_concurrency"]
            or not isinstance(metrics["hold_seconds"], int)
            or isinstance(metrics["hold_seconds"], bool)
            or metrics["hold_seconds"] < 10
            or metrics["premature_completions"] != 0
            or baseline is None
            or peak is None
            or baseline < 0
            or peak < baseline
            or growth is None
            or growth < 0
            or not math.isclose(growth, peak - baseline, rel_tol=0, abs_tol=1e-9)
            or growth_target is None
            or growth_target <= 0
            or slope is None
            or slope_target is None
            or slope_target <= 0
            or growth >= growth_target
            or slope >= slope_target
            or not isinstance(metrics["rss_samples"], list)
            or not metrics["rss_samples"]
        ):
            raise EvidenceError(code)
        validate_result_evidence(
            metrics["establishment_results"],
            expected_total=metrics["target_concurrency"],
            allow_problem_codes=False,
            code=code,
        )
        validate_terminal_quota_check(
            metrics["terminal_quota_check"], {"concurrent_streams"}, code
        )
        return
    if name == "quota_contention_zero_overspend":
        require_fields(
            metrics,
            (
                "metric",
                "attempts",
                "accepted",
                "expected_accepted",
                "denied",
                "expected_denied",
                "unexpected",
                "expected_denial_problem_code",
                "results",
                "before",
                "after",
            ),
            code,
        )
        count_fields = (
            "attempts",
            "accepted",
            "expected_accepted",
            "denied",
            "expected_denied",
            "unexpected",
        )
        if (
            not isinstance(metrics["metric"], str)
            or not metrics["metric"]
            or any(
                not isinstance(metrics[field], int)
                or isinstance(metrics[field], bool)
                or metrics[field] < 0
                for field in count_fields
            )
            or metrics["attempts"] < 2
            or metrics["accepted"] != metrics["expected_accepted"]
            or metrics["denied"] != metrics["expected_denied"]
            or metrics["accepted"] + metrics["denied"] != metrics["attempts"]
            or metrics["unexpected"] != 0
            or not isinstance(metrics["expected_denial_problem_code"], str)
            or not metrics["expected_denial_problem_code"]
        ):
            raise EvidenceError(code)
        validate_result_evidence(
            metrics["results"],
            expected_total=metrics["attempts"],
            allow_problem_codes=True,
            code=code,
        )
        if metrics["results"]["problem_codes"] != {
            metrics["expected_denial_problem_code"]: metrics["denied"]
        }:
            raise EvidenceError(code)
        before = validate_contention_snapshot(
            metrics["before"], metrics["metric"], code
        )
        after = validate_contention_snapshot(
            metrics["after"], metrics["metric"], code
        )
        if (
            before["reserved"] != 0
            or after["reserved"] != 0
            or after["maximum"] != before["maximum"]
            or after["used"] != before["used"] + metrics["accepted"]
            or after["remaining"] != before["remaining"] - metrics["accepted"]
            or after["resets_at"] != before["resets_at"]
        ):
            raise EvidenceError(code)
        return
    raise EvidenceError(code)


def validate_load(
    path: Path,
    *,
    commit: str,
    image: str,
    released_at: datetime,
    now: datetime,
) -> tuple[datetime, datetime]:
    value = require_fields(
        read_json(path),
        (
            "schema_version",
            "kind",
            "started_at",
            "finished_at",
            "commit",
            "environment",
            "quota_fixture",
            "metadata",
            "observed_process_executable",
            "worktree_clean",
            "gates",
            "complete_suite",
            "load_targets_passed",
        ),
        "load_fields_invalid",
    )
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_load_evidence"
        or value["commit"] != commit
        or value["worktree_clean"] is not True
        or value["complete_suite"] is not True
        or value["load_targets_passed"] is not True
    ):
        raise EvidenceError("load_not_release_passed")
    interval = validate_interval(
        value["started_at"],
        value["finished_at"],
        released_at=released_at,
        now=now,
        code="load_time_invalid",
    )
    metadata = require_fields(
        value["metadata"],
        ("release_oci_reference", "deployment", "operator"),
        "load_metadata_invalid",
    )
    if (
        metadata["release_oci_reference"] != image
        or not isinstance(metadata["deployment"], str)
        or not metadata["deployment"].strip()
        or len(metadata["deployment"]) > 500
        or not isinstance(metadata["operator"], str)
        or not metadata["operator"].strip()
        or len(metadata["operator"]) > 500
        or any(
            character in metadata[field]
            for field in ("deployment", "operator")
            for character in "\r\n\x00"
        )
    ):
        raise EvidenceError("load_image_mismatch")
    environment = require_fields(
        value["environment"],
        (
            "label",
            "cpu",
            "memory",
            "postgresql",
            "postgresql_cpu_millicores",
            "postgresql_memory_bytes",
            "postgresql_memory_swap_bytes",
            "postgresql_max_connections",
            "postgresql_network",
            "gateway_db_pool_max_connections",
            "body_logging_disabled",
            "warm_configuration_cache",
        ),
        "load_environment_invalid",
    )
    if (
        any(
            not isinstance(environment[field], str)
            or not environment[field].strip()
            or len(environment[field]) > 500
            for field in ("label", "cpu", "memory", "postgresql", "postgresql_network")
        )
        or any(
            not isinstance(environment[field], int)
            or isinstance(environment[field], bool)
            for field in (
                "postgresql_cpu_millicores",
                "postgresql_memory_bytes",
                "postgresql_memory_swap_bytes",
                "postgresql_max_connections",
                "gateway_db_pool_max_connections",
            )
        )
        or environment["postgresql_cpu_millicores"] < 1000
        or environment["postgresql_memory_bytes"] < 1 << 30
        or environment["postgresql_memory_swap_bytes"]
        < environment["postgresql_memory_bytes"]
        or not 2 <= environment["postgresql_max_connections"] <= 500
        or not 2
        <= environment["gateway_db_pool_max_connections"]
        <= environment["postgresql_max_connections"]
        or environment["body_logging_disabled"] is not True
        or environment["warm_configuration_cache"] is not True
    ):
        raise EvidenceError("load_environment_invalid")
    fixture = require_fields(
        value["quota_fixture"],
        (
            "protected_preflight_requests",
            "overhead_warmup_requests",
            "overhead_sample_requests",
            "non_stream_load_requests",
            "settled_input_tokens_per_request",
            "settled_output_tokens_per_request",
            "settled_total_tokens_per_request",
            "input_reservation_per_request",
            "output_reservation_per_request",
            "total_reservation_per_request",
        ),
        "load_quota_fixture_invalid",
    )
    if (
        any(
            not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in fixture.values()
        )
        or fixture["protected_preflight_requests"] != 1
        or fixture["overhead_warmup_requests"] < 1
        or fixture["overhead_sample_requests"] < 20
        or fixture["non_stream_load_requests"] < 1000
        or fixture["settled_total_tokens_per_request"]
        != fixture["settled_input_tokens_per_request"]
        + fixture["settled_output_tokens_per_request"]
        or fixture["input_reservation_per_request"]
        < fixture["settled_input_tokens_per_request"]
        or fixture["output_reservation_per_request"]
        < fixture["settled_output_tokens_per_request"]
        or fixture["total_reservation_per_request"]
        != fixture["input_reservation_per_request"]
        + fixture["output_reservation_per_request"]
        or value["observed_process_executable"] != "latchway"
    ):
        raise EvidenceError("load_quota_fixture_invalid")
    gates = value["gates"]
    if not isinstance(gates, list) or len(gates) != len(LOAD_GATES):
        raise EvidenceError("load_gate_set_invalid")
    if [gate.get("name") if isinstance(gate, dict) else None for gate in gates] != [
        "preflight",
        "idle_memory",
        "gateway_overhead",
        "non_stream_100_rps",
        "sse_500_concurrent_memory",
        "quota_contention_zero_overspend",
    ]:
        raise EvidenceError("load_gate_set_invalid")
    observed: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != {
            "name",
            "status",
            "started_at",
            "duration_ms",
            "metrics",
        }:
            raise EvidenceError("load_gate_set_invalid")
        name = gate.get("name")
        gate_started = parse_time(gate["started_at"], "load_gate_time_invalid")
        if (
            name not in LOAD_GATES
            or name in observed
            or gate["status"] != "passed"
            or not isinstance(gate["duration_ms"], int)
            or isinstance(gate["duration_ms"], bool)
            or gate["duration_ms"] < 0
            or gate_started < interval[0]
            or gate_started + timedelta(milliseconds=gate["duration_ms"])
            > interval[1] + timedelta(seconds=1)
        ):
            raise EvidenceError("load_gate_set_invalid")
        validate_load_gate_metrics(name, gate["metrics"], fixture)
        observed.add(name)
    if observed != LOAD_GATES:
        raise EvidenceError("load_gate_set_invalid")
    return interval


def validate_external_failure(
    root: Path,
    scenario_id: str,
    *,
    commit: str,
    image: str,
    released_at: datetime,
    now: datetime,
) -> tuple[tuple[datetime, datetime], list[dict[str, str]]]:
    path = root / f"{scenario_id}.json"
    value = require_fields(
        read_json(path),
        (
            "schema_version",
            "scenario_id",
            "status",
            "commit",
            "started_at",
            "finished_at",
            "environment",
            "assertions",
            "artifacts",
        ),
        "failure_external_fields_invalid",
    )
    if (
        value["schema_version"] != 1
        or value["scenario_id"] != scenario_id
        or value["status"] != "passed"
        or value["commit"] != commit
    ):
        raise EvidenceError("failure_external_identity_mismatch")
    environment = value["environment"]
    required_environment = {
        "image_digest",
        "platform",
        "postgresql",
        "fault_tool",
        "operator",
    }
    if scenario_id == "live-config-and-key-rotation-across-api-replicas":
        required_environment |= {"api_replicas", "worker_replicas", "load_balancer"}
    if not isinstance(environment, dict) or set(environment) != required_environment:
        raise EvidenceError("failure_external_environment_invalid")
    if environment["image_digest"] != image or any(
        not isinstance(environment[key], str)
        or not environment[key].strip()
        or len(environment[key]) > 500
        or any(character in environment[key] for character in "\r\n\x00")
        for key in required_environment
    ):
        raise EvidenceError("failure_external_image_mismatch")
    assertions = value["assertions"]
    if not isinstance(assertions, list) or not assertions:
        raise EvidenceError("failure_external_assertions_invalid")
    names: set[str] = set()
    for assertion in assertions:
        assertion = require_fields(
            assertion, ("name", "passed", "detail"), "failure_external_assertions_invalid"
        )
        if (
            not isinstance(assertion["name"], str)
            or not assertion["name"]
            or assertion["name"] in names
            or assertion["passed"] is not True
            or not isinstance(assertion["detail"], str)
            or not assertion["detail"].strip()
        ):
            raise EvidenceError("failure_external_assertions_invalid")
        names.add(assertion["name"])
    expected_assertions = EXTERNAL_FAILURE_ASSERTIONS[scenario_id]
    if names != expected_assertions:
        raise EvidenceError("failure_external_assertions_invalid")
    if scenario_id == "live-config-and-key-rotation-across-api-replicas":
        try:
            api_replicas = int(environment.get("api_replicas", ""))
            worker_replicas = int(environment.get("worker_replicas", ""))
        except (TypeError, ValueError):
            raise EvidenceError("failure_multi_replica_environment_invalid") from None
        if (
            api_replicas < 2
            or api_replicas > 64
            or worker_replicas < 2
            or worker_replicas > 64
            or environment["api_replicas"] != str(api_replicas)
            or environment["worker_replicas"] != str(worker_replicas)
            or not isinstance(environment.get("load_balancer"), str)
            or not environment["load_balancer"].strip()
        ):
            raise EvidenceError("failure_multi_replica_environment_invalid")
    _, artifact_index = validate_artifact_list(
        path, value["artifacts"], "failure_external_artifacts_invalid"
    )
    document_hash = sha256_file(path)
    indexed = [{"path": f"failure/{path.name}", "sha256": document_hash}]
    indexed.extend(
        {"path": f"failure/{scenario_id}/{item['path']}", "sha256": item["sha256"]}
        for item in artifact_index
    )
    interval = validate_interval(
        value["started_at"],
        value["finished_at"],
        released_at=released_at,
        now=now,
        code="failure_external_time_invalid",
    )
    return interval, indexed


def failure_matrix_details() -> tuple[
    dict[str, list[dict[str, Any]]], dict[str, str], dict[str, str]
]:
    matrix = read_json(ROOT / "tests/failure/matrix.json")
    if matrix.get("schema_version") != 1 or not isinstance(matrix.get("scenarios"), list):
        raise EvidenceError("failure_matrix_invalid")
    automated: dict[str, list[dict[str, Any]]] = {}
    external: set[str] = set()
    requirements: dict[str, str] = {}
    notes: dict[str, str] = {}
    for scenario in matrix["scenarios"]:
        if not isinstance(scenario, dict) or not isinstance(scenario.get("id"), str):
            raise EvidenceError("failure_matrix_invalid")
        identifier = scenario["id"]
        requirement = scenario.get("requirement")
        if (
            identifier in requirements
            or not isinstance(requirement, str)
            or not requirement.strip()
        ):
            raise EvidenceError("failure_matrix_invalid")
        requirements[identifier] = requirement
        if scenario.get("kind") == "automated":
            invocations = scenario.get("invocations")
            if identifier in automated or not isinstance(invocations, list) or not invocations:
                raise EvidenceError("failure_matrix_invalid")
            expected: list[dict[str, Any]] = []
            for invocation in invocations:
                if not isinstance(invocation, dict) or set(invocation) != {
                    "package",
                    "run",
                    "race",
                }:
                    raise EvidenceError("failure_matrix_invalid")
                run = invocation["run"]
                if (
                    not isinstance(invocation["package"], str)
                    or not invocation["package"].startswith("./")
                    or not isinstance(run, str)
                    or any(
                        re.fullmatch(r"Test[A-Za-z0-9_]+", name) is None
                        for name in run.split("|")
                    )
                    or not isinstance(invocation["race"], bool)
                ):
                    raise EvidenceError("failure_matrix_invalid")
                expected.append(invocation)
            automated[identifier] = expected
        elif scenario.get("kind") == "external":
            if identifier in external:
                raise EvidenceError("failure_matrix_invalid")
            note = scenario.get("evidence_notes")
            if not isinstance(note, str) or not note.strip():
                raise EvidenceError("failure_matrix_invalid")
            notes[identifier] = note
            external.add(identifier)
        else:
            raise EvidenceError("failure_matrix_invalid")
    if (
        set(automated) != AUTOMATED_FAILURE_IDS
        or external != EXTERNAL_FAILURE_IDS
        or set(requirements) != AUTOMATED_FAILURE_IDS | EXTERNAL_FAILURE_IDS
        or set(notes) != EXTERNAL_FAILURE_IDS
    ):
        raise EvidenceError("failure_matrix_invalid")
    return automated, requirements, notes


def failure_matrix() -> dict[str, list[dict[str, Any]]]:
    automated, _, _ = failure_matrix_details()
    return automated


def go_test_log_passed(path: Path, run: str) -> bool:
    expected = set(run.split("|"))
    passed: set[str] = set()
    try:
        with path.open("r", encoding="utf-8") as source:
            for line in source:
                event = json.loads(line, object_pairs_hook=strict_object)
                if not isinstance(event, dict):
                    return False
                if event.get("Action") == "fail":
                    return False
                test = event.get("Test")
                if test in expected and event.get("Action") == "skip":
                    return False
                if test in expected and event.get("Action") == "pass":
                    passed.add(test)
    except (EvidenceError, OSError, UnicodeError, json.JSONDecodeError):
        return False
    return passed == expected


def validate_failure(
    path: Path,
    external_root: Path,
    *,
    commit: str,
    image: str,
    released_at: datetime,
    now: datetime,
) -> tuple[list[tuple[datetime, datetime]], list[dict[str, str]]]:
    if not real_directory(external_root):
        raise EvidenceError("failure_external_directory_invalid")
    value = require_fields(
        read_json(path),
        (
            "schema_version",
            "kind",
            "scope",
            "commit",
            "worktree_clean",
            "started_at",
            "finished_at",
            "results",
            "automated_passed",
            "release_passed",
        ),
        "failure_fields_invalid",
    )
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_failure_evidence"
        or value["scope"] != "release"
        or value["commit"] != commit
        or value["worktree_clean"] is not True
        or value["automated_passed"] is not True
        or value["release_passed"] is not True
    ):
        raise EvidenceError("failure_not_release_passed")
    report_interval = validate_interval(
        value["started_at"],
        value["finished_at"],
        released_at=released_at,
        now=now,
        code="failure_time_invalid",
    )
    results = value["results"]
    expected = AUTOMATED_FAILURE_IDS | EXTERNAL_FAILURE_IDS
    if not isinstance(results, list) or len(results) != len(expected):
        raise EvidenceError("failure_result_set_invalid")
    matrix, requirements, evidence_notes = failure_matrix_details()
    observed: dict[str, str] = {}
    index: list[dict[str, str]] = []
    log_root = path.with_suffix("").with_name(path.with_suffix("").name + ".logs")
    for result in results:
        if not isinstance(result, dict):
            raise EvidenceError("failure_result_set_invalid")
        identifier = result.get("id")
        expected_kind = "automated" if identifier in AUTOMATED_FAILURE_IDS else "external"
        expected_fields = (
            {"id", "requirement", "kind", "status", "duration_ms", "logs"}
            if expected_kind == "automated"
            else {"id", "requirement", "kind", "status", "duration_ms", "evidence", "notes"}
        )
        if (
            identifier not in expected
            or identifier in observed
            or set(result) != expected_fields
            or result.get("requirement") != requirements.get(identifier)
            or result.get("kind") != expected_kind
            or result.get("status") != "passed"
            or not isinstance(result.get("duration_ms"), int)
            or isinstance(result.get("duration_ms"), bool)
            or result["duration_ms"] < 0
        ):
            raise EvidenceError("failure_result_set_invalid")
        observed[identifier] = expected_kind
        if expected_kind == "automated":
            logs = result.get("logs")
            invocations = matrix[identifier]
            if not isinstance(logs, list) or len(logs) != len(invocations):
                raise EvidenceError("failure_automated_logs_invalid")
            for position, (log, invocation) in enumerate(zip(logs, invocations), 1):
                log = require_fields(
                    log,
                    ("package", "run", "race", "log", "sha256", "exit_code"),
                    "failure_automated_logs_invalid",
                )
                expected_name = f"{identifier}-{position:02d}.jsonl"
                stored_log = log["log"]
                if (
                    log["package"] != invocation["package"]
                    or log["run"] != invocation["run"]
                    or log["race"] is not invocation["race"]
                    or log["exit_code"] != 0
                    or not isinstance(stored_log, str)
                    or Path(stored_log).name != expected_name
                    or not isinstance(log["sha256"], str)
                    or SHA256.fullmatch(log["sha256"]) is None
                ):
                    raise EvidenceError("failure_automated_logs_invalid")
                local_log = log_root / expected_name
                actual = sha256_file(local_log)
                if actual != log["sha256"] or not go_test_log_passed(
                    local_log, invocation["run"]
                ):
                    raise EvidenceError("failure_automated_log_not_passed")
                index.append(
                    {"path": f"failure/automated/{expected_name}", "sha256": actual}
                )
        elif (
            result["notes"] != evidence_notes[identifier]
            or not isinstance(result["evidence"], str)
            or Path(result["evidence"]).name != f"{identifier}.json"
        ):
            raise EvidenceError("failure_external_reference_invalid")
    if set(observed) != expected:
        raise EvidenceError("failure_result_set_invalid")
    intervals = [report_interval]
    for scenario_id in sorted(EXTERNAL_FAILURE_IDS):
        interval, scenario_index = validate_external_failure(
            external_root,
            scenario_id,
            commit=commit,
            image=image,
            released_at=released_at,
            now=now,
        )
        intervals.append(interval)
        index.extend(scenario_index)
    return intervals, index


def validate_version(value: Any, code: str) -> dict[str, str]:
    value = require_fields(
        value,
        ("version", "commit", "build_date", "contract_version", "protocol_version"),
        code,
    )
    if (
        not isinstance(value["version"], str)
        or SEMVER.fullmatch(value["version"]) is None
        or not isinstance(value["commit"], str)
        or COMMIT.fullmatch(value["commit"]) is None
        or not isinstance(value["contract_version"], str)
        or SEMVER.fullmatch(value["contract_version"]) is None
        or not isinstance(value["protocol_version"], str)
        or not value["protocol_version"].isdigit()
    ):
        raise EvidenceError(code)
    parse_build_time(value["build_date"], code)
    return value


def validate_image_inspection(
    path: Path,
    *,
    commit: str,
    previous_image: str,
    candidate_image: str,
    postgres_image: str,
) -> dict[str, Any]:
    value = require_fields(
        read_json(path),
        (
            "candidate_oci_reference",
            "candidate_revision",
            "candidate_repo_digests",
            "previous_oci_reference",
            "previous_revision",
            "previous_repo_digests",
            "previous_version",
            "previous_release_tag",
            "previous_release_tag_type",
            "previous_release_tag_commit",
            "previous_version_tag_repo_digests",
            "postgres_oci_reference",
            "postgres_repo_digests",
            "network_internal",
            "source_database_identity_sha256",
            "restore_database_identity_sha256",
        ),
        "drill_image_inspection_fields_invalid",
    )

    def digest_list(name: str) -> list[str]:
        values = value[name]
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 16
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 256
                or any(character in item for character in "\r\n\x00")
                for item in values
            )
            or len(set(values)) != len(values)
        ):
            raise EvidenceError("drill_image_digest_unresolved")
        return values

    candidate_digests = digest_list("candidate_repo_digests")
    previous_digests = digest_list("previous_repo_digests")
    previous_tag_digests = digest_list("previous_version_tag_repo_digests")
    postgres_digests = digest_list("postgres_repo_digests")
    previous_version = value["previous_version"]
    previous_revision = value["previous_revision"]
    source_identity = value["source_database_identity_sha256"]
    restore_identity = value["restore_database_identity_sha256"]
    short_postgres = postgres_image.removeprefix("docker.io/library/")
    if (
        value["candidate_oci_reference"] != candidate_image
        or value["candidate_revision"] != commit
        or candidate_image not in candidate_digests
        or value["previous_oci_reference"] != previous_image
        or previous_image not in previous_digests
        or previous_image not in previous_tag_digests
        or not isinstance(previous_version, str)
        or SEMVER.fullmatch(previous_version) is None
        or not isinstance(previous_revision, str)
        or COMMIT.fullmatch(previous_revision) is None
        or value["previous_release_tag"] != "v" + previous_version
        or value["previous_release_tag_type"] != "tag"
        or value["previous_release_tag_commit"] != previous_revision
        or value["postgres_oci_reference"] != postgres_image
        or (
            postgres_image not in postgres_digests
            and short_postgres not in postgres_digests
        )
        or value["network_internal"] is not True
    ):
        raise EvidenceError("drill_image_identity_mismatch")
    if (
        not isinstance(source_identity, str)
        or SHA256.fullmatch(source_identity) is None
        or not isinstance(restore_identity, str)
        or SHA256.fullmatch(restore_identity) is None
        or source_identity == restore_identity
    ):
        raise EvidenceError("drill_database_identity_invalid")
    return value


def validate_migration(value: Any, code: str) -> dict[str, Any]:
    value = require_fields(value, ("current", "available", "up_to_date"), code)
    if (
        not isinstance(value["current"], int)
        or isinstance(value["current"], bool)
        or not isinstance(value["available"], int)
        or isinstance(value["available"], bool)
        or value["current"] <= 0
        or value["current"] != value["available"]
        or value["up_to_date"] is not True
    ):
        raise EvidenceError(code)
    return value


def validate_doctor(value: Any, schema: int, code: str) -> dict[str, Any]:
    value = require_fields(value, ("status", "database", "schema_version", "role"), code)
    if (
        value["status"] != "ok"
        or value["database"] != "reachable"
        or value["schema_version"] != schema
        or value["role"] not in ("all", "api", "worker")
    ):
        raise EvidenceError(code)
    return value


def validate_runtime_observations(
    health: Any, readiness: Any, version: Mapping[str, Any], code: str
) -> None:
    if (
        not isinstance(health, dict)
        or set(health) != {"status", "build"}
        or health["status"] != "ok"
        or health["build"] != version
        or not isinstance(readiness, dict)
        or set(readiness) != {"status", "checks"}
        or readiness["status"] != "ready"
        or not isinstance(readiness["checks"], dict)
        or set(readiness["checks"])
        != {
            "database",
            "schema",
            "active_configuration",
            "master_key",
            "signing_key",
            "worker_heartbeat",
        }
        or any(status != "ok" for status in readiness["checks"].values())
    ):
        raise EvidenceError(code)


def validate_state(value: Any, image: str, code: str) -> dict[str, Any]:
    value = require_fields(
        value,
        (
            "database_identity_sha256",
            "image",
            "version",
            "migration",
            "doctor",
            "health",
            "readiness",
            "state_fingerprint_sha256",
            "row_counts",
        ),
        code,
    )
    if (
        not isinstance(value["database_identity_sha256"], str)
        or SHA256.fullmatch(value["database_identity_sha256"]) is None
        or value["image"] != image
        or not isinstance(value["state_fingerprint_sha256"], str)
        or SHA256.fullmatch(value["state_fingerprint_sha256"]) is None
        or not isinstance(value["row_counts"], dict)
        or not value["row_counts"]
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            for key, count in value["row_counts"].items()
        )
    ):
        raise EvidenceError(code)
    value["version"] = validate_version(value["version"], code)
    value["migration"] = validate_migration(value["migration"], code)
    value["doctor"] = validate_doctor(
        value["doctor"], value["migration"]["current"], code
    )
    validate_runtime_observations(
        value["health"], value["readiness"], value["version"], code
    )
    return value


def validate_assertions(value: Any, expected: frozenset[str], code: str) -> None:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise EvidenceError(code)
    if any(value[name] is not True for name in expected):
        raise EvidenceError(code)


def validate_backup(
    path: Path,
    *,
    commit: str,
    candidate_image: str,
    released_at: datetime,
    now: datetime,
) -> tuple[
    tuple[datetime, datetime],
    str,
    str,
    list[dict[str, str]],
    dict[str, Any],
    dict[str, Any],
]:
    value = require_fields(
        read_json(path),
        (
            "schema_version",
            "kind",
            "status",
            "core_commit",
            "previous_oci_reference",
            "candidate_oci_reference",
            "postgres_oci_reference",
            "started_at",
            "finished_at",
            "isolation",
            "source",
            "backup",
            "restore",
            "assertions",
            "artifacts",
        ),
        "backup_fields_invalid",
    )
    previous = value["previous_oci_reference"]
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_backup_restore_drill"
        or value["status"] != "passed"
        or value["core_commit"] != commit
        or not isinstance(previous, str)
        or OCI.fullmatch(previous) is None
        or previous == candidate_image
        or value["candidate_oci_reference"] != candidate_image
        or not isinstance(value["postgres_oci_reference"], str)
        or POSTGRES_OCI.fullmatch(value["postgres_oci_reference"]) is None
    ):
        raise EvidenceError("backup_identity_invalid")
    isolation = require_fields(
        value["isolation"],
        (
            "network_internal",
            "source_database_container_fresh",
            "restore_database_container_fresh",
            "production_targeted",
        ),
        "backup_isolation_invalid",
    )
    if isolation != {
        "network_internal": True,
        "source_database_container_fresh": True,
        "restore_database_container_fresh": True,
        "production_targeted": False,
    }:
        raise EvidenceError("backup_isolation_invalid")
    source = validate_state(value["source"], previous, "backup_source_invalid")
    restore = validate_state(value["restore"], previous, "backup_restore_invalid")
    if (
        source["database_identity_sha256"] == restore["database_identity_sha256"]
        or source["version"] != restore["version"]
        or source["migration"] != restore["migration"]
        or source["state_fingerprint_sha256"] != restore["state_fingerprint_sha256"]
        or source["row_counts"] != restore["row_counts"]
    ):
        raise EvidenceError("backup_restore_mismatch")
    backup = require_fields(
        value["backup"],
        ("format", "artifact_path", "sha256", "size_bytes"),
        "backup_archive_invalid",
    )
    if (
        backup["format"] != "postgresql-custom"
        or not safe_relative_path(backup["artifact_path"])
        or not isinstance(backup["sha256"], str)
        or SHA256.fullmatch(backup["sha256"]) is None
        or not isinstance(backup["size_bytes"], int)
        or isinstance(backup["size_bytes"], bool)
        or backup["size_bytes"] <= 0
        or backup["size_bytes"] > MAXIMUM_FILE_BYTES
    ):
        raise EvidenceError("backup_archive_invalid")
    artifacts, index = validate_artifact_list(
        path, value["artifacts"], "backup_artifacts_invalid"
    )
    archive_entries = [item for item in artifacts if item["path"] == backup["artifact_path"]]
    archive_path = resolve_artifact(path.parent, backup["artifact_path"])
    try:
        with archive_path.open("rb") as archive_file:
            archive_magic = archive_file.read(5)
    except OSError:
        raise EvidenceError("backup_archive_invalid") from None
    if (
        len(archive_entries) != 1
        or archive_entries[0]["sha256"] != backup["sha256"]
        or archive_path.stat().st_size != backup["size_bytes"]
        or archive_magic != b"PGDMP"
    ):
        raise EvidenceError("backup_archive_invalid")
    validate_assertions(value["assertions"], BACKUP_ASSERTIONS, "backup_claims_invalid")
    interval = validate_interval(
        value["started_at"],
        value["finished_at"],
        released_at=released_at,
        now=now,
        code="backup_time_invalid",
    )
    return interval, previous, value["postgres_oci_reference"], index, source, restore


def validate_runtime_stage(value: Any, image: str, code: str) -> dict[str, Any]:
    value = require_fields(
        value,
        (
            "image",
            "version",
            "migration",
            "doctor",
            "health",
            "readiness",
            "state_fingerprint_sha256",
            "row_counts",
        ),
        code,
    )
    if (
        value["image"] != image
        or not isinstance(value["state_fingerprint_sha256"], str)
        or SHA256.fullmatch(value["state_fingerprint_sha256"]) is None
        or not isinstance(value["row_counts"], dict)
        or not value["row_counts"]
        or any(
            not isinstance(count, int) or isinstance(count, bool) or count < 1
            for count in value["row_counts"].values()
        )
    ):
        raise EvidenceError(code)
    value["version"] = validate_version(value["version"], code)
    value["migration"] = validate_migration(value["migration"], code)
    value["doctor"] = validate_doctor(
        value["doctor"], value["migration"]["current"], code
    )
    validate_runtime_observations(
        value["health"], value["readiness"], value["version"], code
    )
    return value


def validate_upgrade(
    path: Path,
    *,
    commit: str,
    core_version: str,
    contract_version: str,
    wire_protocol: int | str,
    candidate_image: str,
    previous_image: str,
    postgres_image: str,
    released_at: datetime,
    now: datetime,
) -> tuple[
    tuple[datetime, datetime],
    list[dict[str, str]],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    value = require_fields(
        read_json(path),
        (
            "schema_version",
            "kind",
            "status",
            "core_commit",
            "previous_oci_reference",
            "candidate_oci_reference",
            "postgres_oci_reference",
            "started_at",
            "finished_at",
            "previous_before",
            "candidate_after",
            "previous_rollback",
            "assertions",
            "artifacts",
        ),
        "upgrade_fields_invalid",
    )
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_upgrade_application_rollback_drill"
        or value["status"] != "passed"
        or value["core_commit"] != commit
        or value["previous_oci_reference"] != previous_image
        or value["candidate_oci_reference"] != candidate_image
        or value["postgres_oci_reference"] != postgres_image
    ):
        raise EvidenceError("upgrade_identity_invalid")
    before = validate_runtime_stage(
        value["previous_before"], previous_image, "upgrade_previous_invalid"
    )
    candidate = validate_runtime_stage(
        value["candidate_after"], candidate_image, "upgrade_candidate_invalid"
    )
    rollback = validate_runtime_stage(
        value["previous_rollback"], previous_image, "upgrade_rollback_invalid"
    )
    if (
        before["version"] != rollback["version"]
        or not semver_less(before["version"]["version"], core_version)
        or before["version"]["commit"] == commit
        or candidate["version"]["version"] != core_version
        or candidate["version"]["commit"] != commit
        or candidate["version"]["contract_version"] != contract_version
        or candidate["version"]["protocol_version"] != str(wire_protocol)
        or parse_build_time(candidate["version"]["build_date"], "upgrade_candidate_invalid")
        < released_at
        or parse_build_time(candidate["version"]["build_date"], "upgrade_candidate_invalid")
        > now
        or parse_build_time(before["version"]["build_date"], "upgrade_previous_invalid")
        > now
        or before["migration"]["current"] > candidate["migration"]["current"]
        or rollback["migration"] != candidate["migration"]
        or before["state_fingerprint_sha256"]
        != candidate["state_fingerprint_sha256"]
        or candidate["state_fingerprint_sha256"]
        != rollback["state_fingerprint_sha256"]
        or before["row_counts"] != candidate["row_counts"]
        or candidate["row_counts"] != rollback["row_counts"]
    ):
        raise EvidenceError("upgrade_rollback_mismatch")
    validate_assertions(value["assertions"], UPGRADE_ASSERTIONS, "upgrade_claims_invalid")
    _, index = validate_artifact_list(
        path, value["artifacts"], "upgrade_artifacts_invalid"
    )
    interval = validate_interval(
        value["started_at"],
        value["finished_at"],
        released_at=released_at,
        now=now,
        code="upgrade_time_invalid",
    )
    return interval, index, before, candidate, rollback


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def finalize(
    *,
    candidate_manifest: Path,
    source_conformance: Path,
    load_report: Path,
    failure_report: Path,
    failure_evidence_dir: Path,
    backup_report: Path,
    upgrade_report: Path,
    output_directory: Path,
    now: datetime,
) -> dict[str, Any]:
    report_paths = (
        candidate_manifest,
        source_conformance,
        load_report,
        failure_report,
        backup_report,
        upgrade_report,
    )
    report_hashes = {path: sha256_file(path) for path in report_paths}
    source = validate_source(source_conformance, now)
    _, image, _ = validate_candidate(candidate_manifest, source, now)
    contract = source["contract"]
    commit = source["repositories"]["core"]["commit"]
    released_at = source["released_at"]
    intervals: list[tuple[datetime, datetime]] = []
    intervals.append(
        validate_load(
            load_report,
            commit=commit,
            image=image,
            released_at=released_at,
            now=now,
        )
    )
    failure_intervals, failure_index = validate_failure(
        failure_report,
        failure_evidence_dir,
        commit=commit,
        image=image,
        released_at=released_at,
        now=now,
    )
    intervals.extend(failure_intervals)
    (
        backup_interval,
        previous_image,
        postgres_image,
        backup_index,
        backup_source,
        backup_restore,
    ) = validate_backup(
        backup_report,
        commit=commit,
        candidate_image=image,
        released_at=released_at,
        now=now,
    )
    intervals.append(backup_interval)
    (
        upgrade_interval,
        upgrade_index,
        upgrade_before,
        _,
        _,
    ) = validate_upgrade(
        upgrade_report,
        commit=commit,
        core_version=source["repositories"]["core"]["version"],
        contract_version=contract["version"],
        wire_protocol=contract["wire_protocol"],
        candidate_image=image,
        previous_image=previous_image,
        postgres_image=postgres_image,
        released_at=released_at,
        now=now,
    )
    intervals.append(upgrade_interval)
    backup_inspection_path = backup_report.parent / "image-inspection.json"
    upgrade_inspection_path = upgrade_report.parent / "image-inspection.json"
    backup_inspection_hash = sha256_file(backup_inspection_path)
    upgrade_inspection_hash = sha256_file(upgrade_inspection_path)
    if (
        [
            item
            for item in backup_index
            if item == {
                "path": "image-inspection.json",
                "sha256": backup_inspection_hash,
            }
        ]
        != [
            {
                "path": "image-inspection.json",
                "sha256": backup_inspection_hash,
            }
        ]
        or [
            item
            for item in upgrade_index
            if item == {
                "path": "image-inspection.json",
                "sha256": upgrade_inspection_hash,
            }
        ]
        != [
            {
                "path": "image-inspection.json",
                "sha256": upgrade_inspection_hash,
            }
        ]
    ):
        raise EvidenceError("drill_image_inspection_not_hash_bound")
    backup_inspection = validate_image_inspection(
        backup_inspection_path,
        commit=commit,
        previous_image=previous_image,
        candidate_image=image,
        postgres_image=postgres_image,
    )
    upgrade_inspection = validate_image_inspection(
        upgrade_inspection_path,
        commit=commit,
        previous_image=previous_image,
        candidate_image=image,
        postgres_image=postgres_image,
    )
    if (
        backup_inspection != upgrade_inspection
        or backup_inspection_hash != upgrade_inspection_hash
        or backup_source["database_identity_sha256"]
        != backup_inspection["source_database_identity_sha256"]
        or backup_restore["database_identity_sha256"]
        != backup_inspection["restore_database_identity_sha256"]
        or backup_source["version"]["version"]
        != backup_inspection["previous_version"]
        or backup_source["version"]["commit"]
        != backup_inspection["previous_revision"]
        or upgrade_before["version"] != backup_source["version"]
    ):
        raise EvidenceError("drill_image_observations_mismatch")
    earliest = min(started for started, _ in intervals)
    latest = max(finished for _, finished in intervals)
    if latest - earliest > MAXIMUM_AGE:
        raise EvidenceError("operational_evidence_window_too_wide")
    if any(sha256_file(path) != report_hashes[path] for path in report_paths):
        raise EvidenceError("evidence_changed_during_validation")

    if not output_directory.is_absolute():
        raise EvidenceError("output_directory_not_absolute")
    if output_directory.is_symlink():
        raise EvidenceError("output_directory_invalid")
    if output_directory.exists() and (
        not output_directory.is_dir() or any(output_directory.iterdir())
    ):
        raise EvidenceError("output_directory_not_empty")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}.tmp-", dir=output_directory.parent
        )
    )
    try:
        staging.chmod(0o700)
        artifact_root = staging / "artifacts" / "operational-resilience"
        artifact_root.mkdir(parents=True)
        artifact_root.chmod(0o700)
        inputs = (
            (candidate_manifest, "candidate-manifest.json"),
            (source_conformance, "source-conformance.json"),
            (load_report, "load-report.json"),
            (failure_report, "failure-report.json"),
            (backup_report, "backup-restore-report.json"),
            (upgrade_report, "upgrade-rollback-report.json"),
        )
        output_artifacts: list[dict[str, str]] = []
        for source_path, name in inputs:
            destination = artifact_root / name
            shutil.copyfile(source_path, destination)
            destination.chmod(0o600)
            copied_hash = sha256_file(destination)
            if copied_hash != report_hashes[source_path]:
                raise EvidenceError("evidence_changed_during_validation")
            output_artifacts.append(
                {
                    "path": f"artifacts/operational-resilience/{name}",
                    "sha256": copied_hash,
                }
            )
        raw_index = {
            "schema_version": 1,
            "kind": "latchway_operational_resilience_raw_artifact_index",
            "failure_external": sorted(failure_index, key=lambda item: item["path"]),
            "backup_restore": sorted(backup_index, key=lambda item: item["path"]),
            "upgrade_rollback": sorted(upgrade_index, key=lambda item: item["path"]),
        }
        index_path = artifact_root / "raw-artifact-index.json"
        write_json(index_path, raw_index)
        output_artifacts.append(
            {
                "path": "artifacts/operational-resilience/raw-artifact-index.json",
                "sha256": sha256_file(index_path),
            }
        )
        document = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_external_evidence",
            "domain": "operational_resilience",
            "status": "passed",
            "started_at": format_time(earliest),
            "finished_at": format_time(latest),
            "core_commit": commit,
            "core_release": contract["core_release"],
            "contract_version": contract["version"],
            "bundle_sha256": contract["bundle_sha256"],
            "oci_image_digest": image,
            "repositories": source["repositories"],
            "claims": dict(DOMAIN_CLAIMS),
            "artifacts": sorted(output_artifacts, key=lambda item: item["path"]),
        }
        write_json(staging / "operational_resilience.json", document)
        if output_directory.exists():
            output_directory.rmdir()
        os.replace(staging, output_directory)
        return document
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--candidate-manifest", type=Path, required=True)
    value.add_argument("--source-conformance", type=Path, required=True)
    value.add_argument("--load-report", type=Path, required=True)
    value.add_argument("--failure-report", type=Path, required=True)
    value.add_argument("--failure-evidence-dir", type=Path, required=True)
    value.add_argument("--backup-restore-report", type=Path, required=True)
    value.add_argument("--upgrade-rollback-report", type=Path, required=True)
    value.add_argument("--output-directory", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        document = finalize(
            candidate_manifest=arguments.candidate_manifest,
            source_conformance=arguments.source_conformance,
            load_report=arguments.load_report,
            failure_report=arguments.failure_report,
            failure_evidence_dir=arguments.failure_evidence_dir,
            backup_report=arguments.backup_restore_report,
            upgrade_report=arguments.upgrade_rollback_report,
            output_directory=arguments.output_directory,
            now=datetime.now(timezone.utc),
        )
    except (EvidenceError, OSError) as error:
        code = str(error) if isinstance(error, EvidenceError) else "evidence_io_failed"
        print(f"operational resilience evidence failed: {code}", file=sys.stderr)
        return 1
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
