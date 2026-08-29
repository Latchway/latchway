#!/usr/bin/env python3
"""Capture, seal, and verify exact-candidate automated security evidence.

The security workflow is the only production caller of the capture modes.  A
sealed report is derived from a fixed raw file set; callers cannot provide
claims or pass/fail booleans.  Verification replays every validation against a
clean checkout, the immutable candidate manifest, and the retained raw files.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, NamedTuple, Sequence


COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG = re.compile(
    r"^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TOOL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+ -]{0,127}$")
MAXIMUM_AGE = timedelta(days=7)
MAXIMUM_RAW_BYTES = 128 * 1024 * 1024
IMAGE_REPOSITORY = "ghcr.io/latchway/latchway"
BLOCKED_SEVERITIES = ("CRITICAL", "HIGH")
FORBIDDEN_CLAIM_FIELDS = frozenset(("claim", "claims", "passed", "success", "verdict"))
CAPTURED_BINARY = "<captured-binary>"
VULNERABILITY_BINARY_PACKAGE = "./cmd/latchway"
VULNERABILITY_BINARY_BUILD_ARGV = (
    "go",
    "build",
    "-trimpath",
    "-o",
    CAPTURED_BINARY,
    VULNERABILITY_BINARY_PACKAGE,
)

CANDIDATE_ARTIFACTS = (
    "latchway-contract.tar.gz",
    "latchway-linux-amd64.spdx.json",
    "latchway-linux-arm64.spdx.json",
    "latchway-linux-amd64-vulnerability.json",
    "latchway-linux-arm64-vulnerability.json",
    "latchway-linux-amd64-license.json",
    "latchway-linux-arm64-license.json",
)


class CommandCheck(NamedTuple):
    identifier: str
    file_stem: str
    argv: tuple[str, ...]
    tool: str
    fixed_version: str | None = None
    timeout_seconds: int = 3600


COMMAND_CHECKS: tuple[CommandCheck, ...] = (
    CommandCheck(
        "source_go_vulnerability",
        "source-go-vulnerability",
        (
            "go",
            "run",
            "golang.org/x/vuln/cmd/govulncheck@v1.1.4",
            "-json",
            "-mode=binary",
            CAPTURED_BINARY,
        ),
        "govulncheck",
        "v1.1.4",
    ),
    CommandCheck(
        "source_static_analysis",
        "source-static-analysis",
        ("go", "vet", "./..."),
        "go",
    ),
    CommandCheck(
        "source_fuzz_smoke",
        "source-fuzz-smoke",
        ("make", "fuzz-smoke"),
        "make",
        timeout_seconds=5400,
    ),
    CommandCheck(
        "source_race",
        "source-race",
        ("go", "test", "-race", "-json", "-count=1", "./..."),
        "go",
        timeout_seconds=5400,
    ),
)
COMMAND_BY_ID = {check.identifier: check for check in COMMAND_CHECKS}

TRIVY_CHECKS: tuple[tuple[str, str, tuple[str, ...], str | None], ...] = (
    (
        "source_vulnerability_secret_misconfiguration",
        "source-trivy-policy.json",
        ("Vulnerabilities", "Secrets", "Misconfigurations"),
        None,
    ),
    ("source_license", "source-trivy-license.json", ("Licenses",), None),
    (
        "image_amd64_vulnerability",
        "latchway-linux-amd64-vulnerability.json",
        ("Vulnerabilities",),
        "latchway-linux-amd64-vulnerability.json",
    ),
    (
        "image_arm64_vulnerability",
        "latchway-linux-arm64-vulnerability.json",
        ("Vulnerabilities",),
        "latchway-linux-arm64-vulnerability.json",
    ),
    (
        "image_amd64_license",
        "latchway-linux-amd64-license.json",
        ("Licenses",),
        "latchway-linux-amd64-license.json",
    ),
    (
        "image_arm64_license",
        "latchway-linux-arm64-license.json",
        ("Licenses",),
        "latchway-linux-arm64-license.json",
    ),
)

EXTERNAL_OBSERVATIONS = (
    "independent_p0_p2_review",
    "ssrf_review",
    "cryptography_review",
    "app_attest_review",
    "play_integrity_review",
    "quota_race_review",
    "admin_auth_review",
    "browser_xss_review",
)


class SecurityEvidenceError(Exception):
    """A stable, redaction-safe evidence error."""


def canonical_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_time(value: Any, code: str = "security_evidence_time_invalid") -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise SecurityEvidenceError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise SecurityEvidenceError(code) from None


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityEvidenceError("security_json_duplicate_key")
        result[key] = value
    return result


def reject_nonfinite(_: str) -> Any:
    raise SecurityEvidenceError("security_json_nonfinite_number")


def real_file(path: Path, *, allow_empty: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and (allow_empty or metadata.st_size > 0)
        and metadata.st_size <= MAXIMUM_RAW_BYTES
    )


def read_bytes(path: Path, *, allow_empty: bool = False) -> bytes:
    if not real_file(path, allow_empty=allow_empty):
        raise SecurityEvidenceError("security_evidence_file_invalid")
    try:
        return path.read_bytes()
    except OSError:
        raise SecurityEvidenceError("security_evidence_file_invalid") from None


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            read_bytes(path).decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except SecurityEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SecurityEvidenceError("security_evidence_json_invalid") from None
    if not isinstance(value, dict):
        raise SecurityEvidenceError("security_evidence_json_invalid")
    return value


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path, *, allow_empty: bool = False) -> str:
    return sha256_bytes(read_bytes(path, allow_empty=allow_empty))


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        path.write_bytes(payload)
        path.chmod(0o600)
    except OSError:
        raise SecurityEvidenceError("security_evidence_write_failed") from None


def run_git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ("git", *arguments),
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SecurityEvidenceError("security_git_command_failed") from None
    if result.returncode != 0:
        raise SecurityEvidenceError("security_git_command_failed")
    return result.stdout.strip()


def validate_clean_repository(repository: Path, expected_commit: str) -> str:
    if COMMIT.fullmatch(expected_commit) is None:
        raise SecurityEvidenceError("security_candidate_commit_invalid")
    try:
        metadata = repository.lstat()
        resolved = repository.resolve(strict=True)
    except OSError:
        raise SecurityEvidenceError("security_repository_invalid") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecurityEvidenceError("security_repository_invalid")
    if run_git(resolved, "rev-parse", "--verify", "HEAD") != expected_commit:
        raise SecurityEvidenceError("security_candidate_commit_mismatch")
    if run_git(resolved, "status", "--porcelain=v1", "--untracked-files=all"):
        raise SecurityEvidenceError("security_repository_dirty")
    tree = run_git(resolved, "rev-parse", "--verify", "HEAD^{tree}")
    if COMMIT.fullmatch(tree) is None:
        raise SecurityEvidenceError("security_source_tree_invalid")
    return tree


def validate_candidate(
    path: Path,
    *,
    expected_commit: str,
    expected_tag: str,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, str], datetime]:
    if COMMIT.fullmatch(expected_commit) is None or TAG.fullmatch(expected_tag) is None:
        raise SecurityEvidenceError("security_candidate_coordinate_invalid")
    candidate = load_json(path)
    if set(candidate) != {
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
    }:
        raise SecurityEvidenceError("security_candidate_fields_invalid")
    if (
        candidate.get("schema_version") != 1
        or candidate.get("kind") != "latchway_release_candidate"
        or candidate.get("status") != "passed"
        or candidate.get("candidate_commit") != expected_commit
        or candidate.get("intended_tag") != expected_tag
        or candidate.get("version") != expected_tag[1:]
    ):
        raise SecurityEvidenceError("security_candidate_identity_mismatch")
    created_at = parse_time(candidate.get("created_at"), "security_candidate_time_invalid")
    if created_at > now or now - created_at > MAXIMUM_AGE:
        raise SecurityEvidenceError("security_candidate_time_invalid")

    contract = candidate.get("contract")
    if not isinstance(contract, dict) or set(contract) != {
        "version",
        "status",
        "released_at",
        "bundle_file_name",
        "bundle_sha256",
    }:
        raise SecurityEvidenceError("security_candidate_contract_invalid")
    released_at = parse_time(
        contract.get("released_at"), "security_candidate_contract_invalid"
    )
    version = contract.get("version")
    if (
        contract.get("status") != "released"
        or not isinstance(version, str)
        or contract.get("bundle_file_name")
        != f"latchway-contract-{version}.tar.gz"
        or not isinstance(contract.get("bundle_sha256"), str)
        or SHA256.fullmatch(contract["bundle_sha256"]) is None
        or released_at > created_at
        or now - released_at > MAXIMUM_AGE
    ):
        raise SecurityEvidenceError("security_candidate_contract_invalid")

    image = candidate.get("image")
    if not isinstance(image, dict) or set(image) != {
        "repository",
        "index_digest",
        "platforms",
    }:
        raise SecurityEvidenceError("security_candidate_image_invalid")
    platforms = image.get("platforms")
    if (
        image.get("repository") != IMAGE_REPOSITORY
        or not isinstance(image.get("index_digest"), str)
        or DIGEST.fullmatch(image["index_digest"]) is None
        or not isinstance(platforms, dict)
        or set(platforms) != {"linux/amd64", "linux/arm64"}
        or any(
            not isinstance(digest, str) or DIGEST.fullmatch(digest) is None
            for digest in platforms.values()
        )
        or len(set(platforms.values())) != 2
    ):
        raise SecurityEvidenceError("security_candidate_image_invalid")

    artifacts = candidate.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(CANDIDATE_ARTIFACTS):
        raise SecurityEvidenceError("security_candidate_artifacts_invalid")
    artifact_hashes: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise SecurityEvidenceError("security_candidate_artifacts_invalid")
        name = artifact.get("path")
        digest = artifact.get("sha256")
        if (
            name not in CANDIDATE_ARTIFACTS
            or name in artifact_hashes
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise SecurityEvidenceError("security_candidate_artifacts_invalid")
        artifact_path = path.parent / name
        if sha256_file(artifact_path) != digest:
            raise SecurityEvidenceError("security_candidate_artifact_hash_mismatch")
        artifact_hashes[name] = digest
    if set(artifact_hashes) != set(CANDIDATE_ARTIFACTS):
        raise SecurityEvidenceError("security_candidate_artifacts_invalid")
    if artifact_hashes["latchway-contract.tar.gz"] != contract["bundle_sha256"]:
        raise SecurityEvidenceError("security_candidate_contract_hash_mismatch")
    return candidate, artifact_hashes, created_at


def command_paths(raw_directory: Path, check: CommandCheck) -> tuple[Path, Path]:
    return (
        raw_directory / f"{check.file_stem}.result.json",
        raw_directory / f"{check.file_stem}.log",
    )


def command_binary_path(raw_directory: Path, check: CommandCheck) -> Path | None:
    if check.identifier != "source_go_vulnerability":
        return None
    return raw_directory / f"{check.file_stem}.binary"


def command_execution_context(check: CommandCheck) -> dict[str, Any]:
    context: dict[str, Any] = {
        "postgresql_enabled": check.identifier == "source_race",
        "fuzz_time": "3s" if check.identifier == "source_fuzz_smoke" else None,
        "fuzz_parallel": 2 if check.identifier == "source_fuzz_smoke" else None,
    }
    if check.identifier == "source_go_vulnerability":
        context.update(
            {
                "vulnerability_scan_mode": "binary",
                "vulnerability_binary_package": VULNERABILITY_BINARY_PACKAGE,
                "vulnerability_binary_build_argv": list(
                    VULNERABILITY_BINARY_BUILD_ARGV
                ),
                "vulnerability_binary_cgo_enabled": False,
            }
        )
    return context


def discover_tool_version(check: CommandCheck, repository: Path) -> str:
    if check.fixed_version is not None:
        return check.fixed_version
    command = ("go", "env", "GOVERSION") if check.tool == "go" else ("make", "--version")
    try:
        result = subprocess.run(
            command,
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SecurityEvidenceError("security_tool_version_unavailable") from None
    first_line = result.stdout.splitlines()[0].strip() if result.stdout.splitlines() else ""
    if result.returncode != 0 or TOOL_VERSION.fullmatch(first_line) is None:
        raise SecurityEvidenceError("security_tool_version_unavailable")
    return first_line


def capture_command(
    check: CommandCheck,
    *,
    repository: Path,
    raw_directory: Path,
    candidate_commit: str,
) -> dict[str, Any]:
    validate_clean_repository(repository, candidate_commit)
    if not raw_directory.is_absolute():
        raise SecurityEvidenceError("security_raw_directory_invalid")
    raw_directory.mkdir(parents=True, exist_ok=True)
    if raw_directory.is_symlink():
        raise SecurityEvidenceError("security_raw_directory_invalid")
    result_path, log_path = command_paths(raw_directory, check)
    binary_path = command_binary_path(raw_directory, check)
    if (
        result_path.exists()
        or log_path.exists()
        or (binary_path is not None and binary_path.exists())
    ):
        raise SecurityEvidenceError("security_capture_already_exists")
    version = discover_tool_version(check, repository)
    started_at = datetime.now(timezone.utc).replace(microsecond=0)
    exit_code = 125
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "PATH",
            "HOME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "GOCACHE",
            "GOMODCACHE",
            "GOPATH",
            "GOPROXY",
            "GONOSUMDB",
            "GOPRIVATE",
            "GOSUMDB",
            "GOTOOLCHAIN",
            "CGO_ENABLED",
            "LATCHWAY_TEST_DATABASE_URL",
        }
    }
    if check.identifier == "source_race" and not environment.get(
        "LATCHWAY_TEST_DATABASE_URL"
    ):
        raise SecurityEvidenceError("security_postgresql_evidence_unavailable")
    if check.identifier == "source_fuzz_smoke":
        environment["FUZZ_TIME"] = "3s"
        environment["FUZZ_PARALLEL"] = "2"
    binary: dict[str, str] | None = None
    try:
        with log_path.open("xb") as output:
            try:
                if binary_path is not None:
                    build_environment = dict(environment)
                    build_environment["CGO_ENABLED"] = "0"
                    build_argv = tuple(
                        str(binary_path) if item == CAPTURED_BINARY else item
                        for item in VULNERABILITY_BINARY_BUILD_ARGV
                    )
                    result = subprocess.run(
                        build_argv,
                        cwd=repository,
                        env=build_environment,
                        check=False,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        timeout=check.timeout_seconds,
                    )
                    exit_code = result.returncode
                    if exit_code == 0:
                        if not real_file(binary_path):
                            exit_code = 125
                        else:
                            binary_path.chmod(0o600)
                            binary = {
                                "path": binary_path.name,
                                "sha256": sha256_file(binary_path),
                            }
                    if exit_code == 0:
                        scan_argv = tuple(
                            str(binary_path) if item == CAPTURED_BINARY else item
                            for item in check.argv
                        )
                        result = subprocess.run(
                            scan_argv,
                            cwd=repository,
                            env=environment,
                            check=False,
                            stdout=output,
                            stderr=subprocess.STDOUT,
                            timeout=check.timeout_seconds,
                        )
                        exit_code = result.returncode
                else:
                    result = subprocess.run(
                        check.argv,
                        cwd=repository,
                        env=environment,
                        check=False,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        timeout=check.timeout_seconds,
                    )
                    exit_code = result.returncode
            except subprocess.TimeoutExpired:
                exit_code = 124
            except OSError:
                exit_code = 125
        log_path.chmod(0o600)
    except OSError:
        raise SecurityEvidenceError("security_capture_write_failed") from None
    if not real_file(log_path, allow_empty=True):
        raise SecurityEvidenceError("security_capture_log_invalid")
    finished_at = datetime.now(timezone.utc).replace(microsecond=0)
    result_document: dict[str, Any] = {
        "schema_version": 1,
        "kind": "latchway_security_command_result",
        "check": check.identifier,
        "candidate_commit": candidate_commit,
        "started_at": canonical_time(started_at),
        "finished_at": canonical_time(finished_at),
        "tool": {"name": check.tool, "version": version},
        "argv": list(check.argv),
        "execution_context": command_execution_context(check),
        "exit_code": exit_code,
        "log": {
            "path": log_path.name,
            "sha256": sha256_file(log_path, allow_empty=True),
        },
    }
    if binary_path is not None:
        result_document["binary"] = binary
    write_json(result_path, result_document)
    validate_clean_repository(repository, candidate_commit)
    return result_document


def validate_command_result(
    raw_directory: Path,
    check: CommandCheck,
    *,
    expected_commit: str,
    candidate_created_at: datetime,
    now: datetime,
) -> tuple[dict[str, Any], datetime, datetime, list[dict[str, str]]]:
    result_path, log_path = command_paths(raw_directory, check)
    result = load_json(result_path)
    if set(result) & FORBIDDEN_CLAIM_FIELDS:
        raise SecurityEvidenceError("security_raw_claim_forbidden")
    expected_binary_path = command_binary_path(raw_directory, check)
    expected_fields = {
        "schema_version",
        "kind",
        "check",
        "candidate_commit",
        "started_at",
        "finished_at",
        "tool",
        "argv",
        "execution_context",
        "exit_code",
        "log",
    }
    if expected_binary_path is not None:
        expected_fields.add("binary")
    if set(result) != expected_fields:
        raise SecurityEvidenceError("security_command_result_fields_invalid")
    tool = result.get("tool")
    log = result.get("log")
    if (
        result.get("schema_version") != 1
        or result.get("kind") != "latchway_security_command_result"
        or result.get("check") != check.identifier
        or result.get("candidate_commit") != expected_commit
        or result.get("argv") != list(check.argv)
        or result.get("execution_context") != command_execution_context(check)
        or not isinstance(tool, dict)
        or set(tool) != {"name", "version"}
        or tool.get("name") != check.tool
        or not isinstance(tool.get("version"), str)
        or TOOL_VERSION.fullmatch(tool["version"]) is None
        or (check.fixed_version is not None and tool["version"] != check.fixed_version)
        or not isinstance(result.get("exit_code"), int)
        or isinstance(result.get("exit_code"), bool)
        or not isinstance(log, dict)
        or set(log) != {"path", "sha256"}
        or log.get("path") != log_path.name
        or not isinstance(log.get("sha256"), str)
        or SHA256.fullmatch(log["sha256"]) is None
    ):
        raise SecurityEvidenceError("security_command_result_invalid")
    started_at = parse_time(result.get("started_at"))
    finished_at = parse_time(result.get("finished_at"))
    if (
        started_at < candidate_created_at
        or finished_at < started_at
        or finished_at > now
        or now - finished_at > MAXIMUM_AGE
    ):
        raise SecurityEvidenceError("security_command_time_invalid")
    actual_log_hash = sha256_file(log_path, allow_empty=True)
    if actual_log_hash != log["sha256"]:
        raise SecurityEvidenceError("security_command_log_hash_mismatch")
    if result["exit_code"] != 0:
        raise SecurityEvidenceError("security_command_failed")
    binary = result.get("binary")
    binary_hash: str | None = None
    if expected_binary_path is not None:
        if (
            not isinstance(binary, dict)
            or set(binary) != {"path", "sha256"}
            or binary.get("path") != expected_binary_path.name
            or not isinstance(binary.get("sha256"), str)
            or SHA256.fullmatch(binary["sha256"]) is None
        ):
            raise SecurityEvidenceError("security_command_binary_invalid")
        binary_hash = sha256_file(expected_binary_path)
        if binary_hash != binary["sha256"]:
            raise SecurityEvidenceError("security_command_binary_hash_mismatch")
    elif binary is not None:
        raise SecurityEvidenceError("security_command_binary_invalid")
    artifacts = [
        {"path": f"raw/{result_path.name}", "sha256": sha256_file(result_path)},
        {"path": f"raw/{log_path.name}", "sha256": actual_log_hash},
    ]
    if expected_binary_path is not None and binary_hash is not None:
        artifacts.append(
            {"path": f"raw/{expected_binary_path.name}", "sha256": binary_hash}
        )
    return result, started_at, finished_at, artifacts


def validate_scan_window(
    path: Path,
    *,
    expected_commit: str,
    candidate_created_at: datetime,
    now: datetime,
) -> tuple[datetime, datetime]:
    window = load_json(path)
    if set(window) & FORBIDDEN_CLAIM_FIELDS or set(window) != {
        "schema_version",
        "kind",
        "candidate_commit",
        "started_at",
        "finished_at",
    }:
        raise SecurityEvidenceError("security_scan_window_invalid")
    if (
        window.get("schema_version") != 1
        or window.get("kind") != "latchway_security_scan_window"
        or window.get("candidate_commit") != expected_commit
    ):
        raise SecurityEvidenceError("security_scan_window_invalid")
    started_at = parse_time(window.get("started_at"))
    finished_at = parse_time(window.get("finished_at"))
    if (
        started_at < candidate_created_at
        or finished_at < started_at
        or finished_at > now
        or now - finished_at > MAXIMUM_AGE
    ):
        raise SecurityEvidenceError("security_scan_window_time_invalid")
    return started_at, finished_at


def begin_scan(path: Path, candidate_commit: str) -> None:
    if COMMIT.fullmatch(candidate_commit) is None or not path.is_absolute():
        raise SecurityEvidenceError("security_scan_window_invalid")
    if path.exists():
        raise SecurityEvidenceError("security_scan_window_exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(
        path,
        {
            "schema_version": 1,
            "kind": "latchway_security_scan_window",
            "candidate_commit": candidate_commit,
            "started_at": canonical_time(datetime.now(timezone.utc)),
            "finished_at": None,
        },
    )


def finish_scan(path: Path, candidate_commit: str) -> None:
    window = load_json(path)
    if (
        set(window)
        != {
            "schema_version",
            "kind",
            "candidate_commit",
            "started_at",
            "finished_at",
        }
        or window.get("schema_version") != 1
        or window.get("kind") != "latchway_security_scan_window"
        or window.get("candidate_commit") != candidate_commit
        or window.get("finished_at") is not None
    ):
        raise SecurityEvidenceError("security_scan_window_invalid")
    started_at = parse_time(window.get("started_at"))
    finished_at = datetime.now(timezone.utc).replace(microsecond=0)
    if finished_at < started_at:
        raise SecurityEvidenceError("security_scan_window_time_invalid")
    window["finished_at"] = canonical_time(finished_at)
    write_json(path, window)


def validate_trivy(path: Path, keys: Sequence[str]) -> dict[str, int]:
    report = load_json(path)
    if set(report) & FORBIDDEN_CLAIM_FIELDS or not isinstance(report.get("Results"), list):
        raise SecurityEvidenceError("security_trivy_report_invalid")
    counts = {severity.lower(): 0 for severity in BLOCKED_SEVERITIES}
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise SecurityEvidenceError("security_trivy_report_invalid")
        for key in keys:
            findings = result.get(key, [])
            if findings is None:
                findings = []
            if not isinstance(findings, list):
                raise SecurityEvidenceError("security_trivy_report_invalid")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise SecurityEvidenceError("security_trivy_report_invalid")
                severity = finding.get("Severity")
                if severity in BLOCKED_SEVERITIES:
                    if key == "Misconfigurations" and finding.get("Status") == "PASS":
                        continue
                    counts[severity.lower()] += 1
    if any(counts.values()):
        raise SecurityEvidenceError("security_trivy_policy_failed")
    return counts


def expected_raw_names() -> set[str]:
    names = {"scan-window.json"}
    for check in COMMAND_CHECKS:
        names.update((f"{check.file_stem}.result.json", f"{check.file_stem}.log"))
        binary_path = command_binary_path(Path("."), check)
        if binary_path is not None:
            names.add(binary_path.name)
    names.update(filename for _, filename, _, _ in TRIVY_CHECKS)
    return names


def validate_raw_directory(raw_directory: Path) -> None:
    try:
        metadata = raw_directory.lstat()
        resolved = raw_directory.resolve(strict=True)
        entries = list(resolved.iterdir())
    except OSError:
        raise SecurityEvidenceError("security_raw_directory_invalid") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecurityEvidenceError("security_raw_directory_invalid")
    if {entry.name for entry in entries} != expected_raw_names():
        raise SecurityEvidenceError("security_raw_file_set_invalid")
    if any(not real_file(entry, allow_empty=entry.suffix == ".log") for entry in entries):
        raise SecurityEvidenceError("security_raw_file_invalid")


def derive_summary(
    *,
    candidate_manifest: Path,
    raw_directory: Path,
    repository: Path,
    expected_commit: str,
    expected_tag: str,
    now: datetime,
) -> dict[str, Any]:
    tree = validate_clean_repository(repository, expected_commit)
    candidate_manifest_hash = sha256_file(candidate_manifest)
    candidate, candidate_hashes, candidate_created_at = validate_candidate(
        candidate_manifest,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        now=now,
    )
    validate_raw_directory(raw_directory)
    started_times: list[datetime] = []
    finished_times: list[datetime] = []
    raw_evidence: list[dict[str, str]] = []
    checks: list[dict[str, Any]] = []

    for check in COMMAND_CHECKS:
        result, started_at, finished_at, artifacts = validate_command_result(
            raw_directory,
            check,
            expected_commit=expected_commit,
            candidate_created_at=candidate_created_at,
            now=now,
        )
        started_times.append(started_at)
        finished_times.append(finished_at)
        raw_evidence.extend(artifacts)
        checks.append(
            {
                "id": check.identifier,
                "status": "passed",
                "source": "current_candidate_automation",
                "tool": result["tool"],
                "artifact_sha256": sorted(item["sha256"] for item in artifacts),
            }
        )

    scan_window_path = raw_directory / "scan-window.json"
    scan_started, scan_finished = validate_scan_window(
        scan_window_path,
        expected_commit=expected_commit,
        candidate_created_at=candidate_created_at,
        now=now,
    )
    started_times.append(scan_started)
    finished_times.append(scan_finished)
    raw_evidence.append(
        {
            "path": "raw/scan-window.json",
            "sha256": sha256_file(scan_window_path),
        }
    )

    for identifier, filename, keys, candidate_name in TRIVY_CHECKS:
        path = raw_directory / filename
        counts = validate_trivy(path, keys)
        digest = sha256_file(path)
        if candidate_name is not None and candidate_hashes[candidate_name] != digest:
            raise SecurityEvidenceError("security_candidate_scan_hash_mismatch")
        raw_evidence.append({"path": f"raw/{filename}", "sha256": digest})
        checks.append(
            {
                "id": identifier,
                "status": "passed",
                "source": (
                    "immutable_candidate_artifact"
                    if candidate_name is not None
                    else "current_candidate_automation"
                ),
                "tool": {"name": "trivy", "version": "v0.74.0"},
                "blocked_findings": counts,
                "artifact_sha256": [digest],
            }
        )

    started_at = min(started_times)
    finished_at = max(finished_times)
    if (
        finished_at <= started_at
        or finished_at - started_at > MAXIMUM_AGE
        or now - finished_at > MAXIMUM_AGE
    ):
        raise SecurityEvidenceError("security_evidence_window_invalid")

    contract = candidate["contract"]
    image = candidate["image"]
    summary = {
        "schema_version": 1,
        "kind": "latchway_candidate_security_evidence",
        "automated_gate": "passed",
        "candidate": {
            "commit": expected_commit,
            "intended_tag": expected_tag,
            "version": candidate["version"],
            "candidate_created_at": candidate["created_at"],
            "source_tree": tree,
            "candidate_manifest_sha256": candidate_manifest_hash,
            "contract": {
                "version": contract["version"],
                "status": contract["status"],
                "released_at": contract["released_at"],
                "bundle_file_name": contract["bundle_file_name"],
                "bundle_sha256": contract["bundle_sha256"],
            },
            "image": {
                "repository": image["repository"],
                "index_digest": image["index_digest"],
                "platforms": image["platforms"],
            },
        },
        "evidence_window": {
            "started_at": canonical_time(started_at),
            "finished_at": canonical_time(finished_at),
            "maximum_age_seconds": int(MAXIMUM_AGE.total_seconds()),
        },
        "policy": {
            "blocked_severities": list(BLOCKED_SEVERITIES),
            "raw_claims_accepted": False,
        },
        "checks": checks,
        "external_observations": [
            {
                "id": identifier,
                "status": "unavailable",
                "reason": "no_candidate_bound_protected_external_result",
            }
            for identifier in EXTERNAL_OBSERVATIONS
        ],
        "raw_evidence": sorted(raw_evidence, key=lambda item: item["path"]),
    }
    candidate_after, hashes_after, created_after = validate_candidate(
        candidate_manifest,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        now=now,
    )
    if (
        sha256_file(candidate_manifest) != candidate_manifest_hash
        or candidate_after != candidate
        or hashes_after != candidate_hashes
        or created_after != candidate_created_at
    ):
        raise SecurityEvidenceError("security_candidate_changed_during_validation")
    for artifact in summary["raw_evidence"]:
        relative = artifact["path"].removeprefix("raw/")
        if relative == artifact["path"] or sha256_file(
            raw_directory / relative, allow_empty=relative.endswith(".log")
        ) != artifact["sha256"]:
            raise SecurityEvidenceError("security_raw_changed_during_validation")
    if validate_clean_repository(repository, expected_commit) != tree:
        raise SecurityEvidenceError("security_source_changed_during_validation")
    return summary


def copy_real_file(source: Path, destination: Path, *, allow_empty: bool = False) -> None:
    before = sha256_file(source, allow_empty=allow_empty)
    try:
        shutil.copyfile(source, destination, follow_symlinks=False)
        destination.chmod(0o600)
    except OSError:
        raise SecurityEvidenceError("security_evidence_copy_failed") from None
    if before != sha256_file(destination, allow_empty=allow_empty):
        raise SecurityEvidenceError("security_evidence_changed_during_copy")


def seal(
    *,
    candidate_manifest: Path,
    raw_directory: Path,
    repository: Path,
    expected_commit: str,
    expected_tag: str,
    output_directory: Path,
    now: datetime,
) -> dict[str, Any]:
    if (
        not output_directory.is_absolute()
        or output_directory.exists()
        or output_directory.is_symlink()
    ):
        raise SecurityEvidenceError("security_output_directory_invalid")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    summary = derive_summary(
        candidate_manifest=candidate_manifest,
        raw_directory=raw_directory,
        repository=repository,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        now=now,
    )
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}.", dir=output_directory.parent
        )
    )
    try:
        (staging / "raw").mkdir(mode=0o700)
        copy_real_file(candidate_manifest, staging / "latchway-candidate.json")
        for name in sorted(expected_raw_names()):
            copy_real_file(
                raw_directory / name,
                staging / "raw" / name,
                allow_empty=name.endswith(".log"),
            )
        write_json(staging / "security-summary.json", summary)
        os.replace(staging, output_directory)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return summary


def verify(
    *,
    report: Path,
    candidate_manifest: Path,
    raw_directory: Path,
    repository: Path,
    expected_commit: str,
    expected_tag: str,
    now: datetime,
) -> dict[str, Any]:
    actual = load_json(report)
    expected = derive_summary(
        candidate_manifest=candidate_manifest,
        raw_directory=raw_directory,
        repository=repository,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        now=now,
    )
    if actual != expected:
        raise SecurityEvidenceError("security_summary_mismatch")
    return actual


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--capture", choices=sorted(COMMAND_BY_ID))
    modes.add_argument("--begin-scan", action="store_true")
    modes.add_argument("--finish-scan", action="store_true")
    modes.add_argument("--seal", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--raw-directory", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--tag")
    parser.add_argument("--window", type=Path)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--report", type=Path)
    return parser


def required(value: Any, code: str = "security_arguments_missing") -> Any:
    if value is None:
        raise SecurityEvidenceError(code)
    return value


def main() -> int:
    arguments = build_parser().parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if arguments.capture is not None:
            result = capture_command(
                COMMAND_BY_ID[arguments.capture],
                repository=required(arguments.repository),
                raw_directory=required(arguments.raw_directory),
                candidate_commit=required(arguments.commit),
            )
        elif arguments.begin_scan:
            begin_scan(required(arguments.window), required(arguments.commit))
            result = {"status": "scan_started"}
        elif arguments.finish_scan:
            finish_scan(required(arguments.window), required(arguments.commit))
            result = {"status": "scan_finished"}
        elif arguments.seal:
            result = seal(
                candidate_manifest=required(arguments.candidate_manifest),
                raw_directory=required(arguments.raw_directory),
                repository=required(arguments.repository),
                expected_commit=required(arguments.commit),
                expected_tag=required(arguments.tag),
                output_directory=required(arguments.output_directory),
                now=now,
            )
        else:
            result = verify(
                report=required(arguments.report),
                candidate_manifest=required(arguments.candidate_manifest),
                raw_directory=required(arguments.raw_directory),
                repository=required(arguments.repository),
                expected_commit=required(arguments.commit),
                expected_tag=required(arguments.tag),
                now=now,
            )
    except (SecurityEvidenceError, OSError) as error:
        code = str(error) if isinstance(error, SecurityEvidenceError) else "security_io_failed"
        print(f"security evidence rejected: {code}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
