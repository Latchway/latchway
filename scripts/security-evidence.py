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
MAXIMUM_REVIEW_BYTES = 4 * 1024 * 1024
MAXIMUM_ACCEPTED_RISKS = 512
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

INDEPENDENT_REVIEWS = (
    "independent_p0_p2_review",
    "ssrf_review",
    "cryptography_review",
    "app_attest_review",
    "play_integrity_review",
    "quota_race_review",
    "admin_auth_review",
    "browser_xss_review",
)
REPOSITORY_IDS = ("core", "javascript", "ios", "android", "react_native")
FINDING_SEVERITIES = ("critical", "high", "medium", "low", "informational")
REPOSITORY_COORDINATE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,38})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.ya?ml$")
REVIEWER_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:@./+ _-]{0,255}$")
GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
ACCEPTED_RISK_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SENSITIVE_REVIEW_KEY = re.compile(
    r"(?:^|_)(?:access_token|api_key|authorization|cookie|credential|identity_token|"
    r"password|private_key|refresh_token|secret)(?:$|_)",
    re.IGNORECASE,
)
SENSITIVE_REVIEW_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:^|\s)Bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)
REVIEW_REPORT_NAME = "independent-security-review.json"
REVIEW_BUNDLE_NAME = "independent-security-review.attestation.sigstore.json"
REVIEW_PRODUCER_VERIFICATION_NAME = "producer-verification.json"
REVIEW_ATTESTATION_VERIFICATION_NAME = "attestation-verification.json"
PROMOTION_REPORT_NAME = "latchway-cross-repository.json"
PROMOTION_BUNDLE_NAME = "latchway-cross-repository.attestation.sigstore.json"
PROMOTION_PRODUCER_VERIFICATION_NAME = "producer-verification.json"
PROMOTION_ATTESTATION_VERIFICATION_NAME = "attestation-verification.json"
PROMOTION_WORKFLOW = ".github/workflows/cross-repository-conformance.yml"


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


def load_review_snapshot(path: Path) -> tuple[dict[str, Any], bytes, str]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None:
        raise SecurityEvidenceError("security_review_file_invalid")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow | close_on_exec)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAXIMUM_REVIEW_BYTES
        ):
            raise SecurityEvidenceError("security_review_file_invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAXIMUM_REVIEW_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAXIMUM_REVIEW_BYTES:
                raise SecurityEvidenceError("security_review_file_invalid")
        after = os.fstat(descriptor)
    except OSError:
        raise SecurityEvidenceError("security_review_file_invalid") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    identity = lambda metadata: (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    payload = b"".join(chunks)
    if identity(before) != identity(after) or len(payload) != before.st_size:
        raise SecurityEvidenceError("security_review_file_changed")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except SecurityEvidenceError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SecurityEvidenceError("security_review_json_invalid") from None
    if not isinstance(value, dict):
        raise SecurityEvidenceError("security_review_json_invalid")
    reject_sensitive_review_value(value)
    return value, payload, sha256_bytes(payload)


def load_review_json(path: Path) -> dict[str, Any]:
    return load_review_snapshot(path)[0]


def reject_sensitive_review_value(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or SENSITIVE_REVIEW_KEY.search(key):
                raise SecurityEvidenceError("security_review_redaction_failed")
            reject_sensitive_review_value(item)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_review_value(item)
    elif isinstance(value, str) and SENSITIVE_REVIEW_VALUE.search(value):
        raise SecurityEvidenceError("security_review_redaction_failed")


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


def positive_integer(value: Any, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise SecurityEvidenceError(code)
    return value


def validate_finding_counts(value: Any) -> dict[str, dict[str, int]]:
    if not isinstance(value, dict) or set(value) != {"total", "unresolved"}:
        raise SecurityEvidenceError("security_review_findings_invalid")
    result: dict[str, dict[str, int]] = {}
    for category in ("total", "unresolved"):
        counts = value.get(category)
        if not isinstance(counts, dict) or set(counts) != set(FINDING_SEVERITIES):
            raise SecurityEvidenceError("security_review_findings_invalid")
        if any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in counts.values()
        ):
            raise SecurityEvidenceError("security_review_findings_invalid")
        result[category] = dict(counts)
    if any(
        result["unresolved"][severity] > result["total"][severity]
        for severity in FINDING_SEVERITIES
    ):
        raise SecurityEvidenceError("security_review_findings_invalid")
    if result["unresolved"]["critical"] or result["unresolved"]["high"]:
        raise SecurityEvidenceError("security_review_blocking_findings")
    return result


def bounded_review_text(value: Any, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise SecurityEvidenceError("security_review_accepted_risk_invalid")
    return value


def validate_accepted_risks(
    value: Any,
    findings: Mapping[str, Mapping[str, int]],
    *,
    review_id: str,
) -> list[dict[str, str]]:
    expected_count = sum(
        findings["unresolved"][severity]
        for severity in ("medium", "low", "informational")
    )
    if (
        not isinstance(value, list)
        or len(value) != expected_count
        or len(value) > MAXIMUM_ACCEPTED_RISKS
    ):
        raise SecurityEvidenceError("security_review_accepted_risks_incomplete")
    accepted: list[dict[str, str]] = []
    identifiers: set[str] = set()
    counts = {severity: 0 for severity in ("medium", "low", "informational")}
    for risk in value:
        if not isinstance(risk, dict) or set(risk) != {
            "id",
            "severity",
            "summary",
            "acceptance_rationale",
        }:
            raise SecurityEvidenceError("security_review_accepted_risk_invalid")
        identifier = risk.get("id")
        severity = risk.get("severity")
        if (
            not isinstance(identifier, str)
            or ACCEPTED_RISK_ID.fullmatch(identifier) is None
            or not identifier.startswith(f"{review_id}.")
            or identifier in identifiers
            or severity not in counts
        ):
            raise SecurityEvidenceError("security_review_accepted_risk_invalid")
        identifiers.add(identifier)
        counts[severity] += 1
        accepted.append(
            {
                "id": identifier,
                "severity": severity,
                "summary": bounded_review_text(risk.get("summary"), maximum=256),
                "acceptance_rationale": bounded_review_text(
                    risk.get("acceptance_rationale"), maximum=2048
                ),
            }
        )
    if counts != {
        severity: findings["unresolved"][severity]
        for severity in ("medium", "low", "informational")
    } or [risk["id"] for risk in accepted] != sorted(identifiers):
        raise SecurityEvidenceError("security_review_accepted_risks_incomplete")
    return accepted


def review_file_hash(path: Path) -> str:
    return load_review_snapshot(path)[2]


def validate_review_tree(review_directory: Path) -> None:
    try:
        metadata = review_directory.lstat()
        root = review_directory.resolve(strict=True)
        entries = list(root.iterdir())
    except OSError:
        raise SecurityEvidenceError("security_review_directory_invalid") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecurityEvidenceError("security_review_directory_invalid")
    if {entry.name for entry in entries} != {
        REVIEW_REPORT_NAME,
        REVIEW_BUNDLE_NAME,
        REVIEW_PRODUCER_VERIFICATION_NAME,
        REVIEW_ATTESTATION_VERIFICATION_NAME,
        "reviews",
    }:
        raise SecurityEvidenceError("security_review_file_set_invalid")
    reviews = root / "reviews"
    try:
        reviews_metadata = reviews.lstat()
        review_entries = list(reviews.iterdir())
    except OSError:
        raise SecurityEvidenceError("security_review_directory_invalid") from None
    if not stat.S_ISDIR(reviews_metadata.st_mode) or stat.S_ISLNK(
        reviews_metadata.st_mode
    ):
        raise SecurityEvidenceError("security_review_directory_invalid")
    if {entry.name for entry in review_entries} != {
        f"{identifier}.json" for identifier in INDEPENDENT_REVIEWS
    }:
        raise SecurityEvidenceError("security_review_file_set_invalid")


def validate_promotion_conformance(
    *,
    promotion_directory: Path,
    candidate: Mapping[str, Any],
    candidate_created_at: datetime,
    expected_commit: str,
    expected_tag: str,
    expected_run_id: int,
    expected_run_attempt: int,
    now: datetime,
) -> tuple[dict[str, Any], list[dict[str, str]], datetime]:
    positive_integer(expected_run_id, "security_promotion_run_invalid")
    positive_integer(expected_run_attempt, "security_promotion_run_invalid")
    try:
        metadata = promotion_directory.lstat()
        root = promotion_directory.resolve(strict=True)
        entries = list(root.iterdir())
    except OSError:
        raise SecurityEvidenceError("security_promotion_directory_invalid") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecurityEvidenceError("security_promotion_directory_invalid")
    expected_names = {
        PROMOTION_REPORT_NAME,
        PROMOTION_BUNDLE_NAME,
        PROMOTION_PRODUCER_VERIFICATION_NAME,
        PROMOTION_ATTESTATION_VERIFICATION_NAME,
    }
    if {entry.name for entry in entries} != expected_names:
        raise SecurityEvidenceError("security_promotion_file_set_invalid")

    report_path = root / PROMOTION_REPORT_NAME
    report, _, report_hash = load_review_snapshot(report_path)
    if set(report) != {
        "schema_version",
        "kind",
        "scope",
        "verdict",
        "source_conformance_passed",
        "promotion_ready",
        "release_ready",
        "contract",
        "repositories",
        "documentation",
        "evidence_window",
        "evidence_domains",
        "checks",
    } or (
        report.get("schema_version") != 1
        or report.get("kind") != "latchway_cross_repository_conformance_evidence"
        or report.get("scope") != "promotion"
        or report.get("verdict") != "passed"
        or report.get("source_conformance_passed") is not True
        or report.get("promotion_ready") is not True
        or report.get("release_ready") is not False
    ):
        raise SecurityEvidenceError("security_promotion_report_invalid")

    candidate_contract = candidate["contract"]
    candidate_image = candidate["image"]
    contract = report.get("contract")
    if not isinstance(contract, dict) or set(contract) != {
        "version",
        "status",
        "released_at",
        "wire_protocol",
        "bundle_file_name",
        "bundle_sha256",
        "core_release",
        "oci_image_digest",
    } or (
        contract.get("version") != candidate_contract["version"]
        or contract.get("status") != candidate_contract["status"]
        or contract.get("released_at") != candidate_contract["released_at"]
        or contract.get("bundle_file_name") != candidate_contract["bundle_file_name"]
        or contract.get("bundle_sha256") != candidate_contract["bundle_sha256"]
        or contract.get("core_release") != expected_tag
        or contract.get("oci_image_digest")
        != f"{candidate_image['repository']}@{candidate_image['index_digest']}"
        or not isinstance(contract.get("wire_protocol"), int)
        or isinstance(contract.get("wire_protocol"), bool)
        or contract["wire_protocol"] < 1
    ):
        raise SecurityEvidenceError("security_promotion_contract_mismatch")

    repositories = report.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != len(REPOSITORY_IDS):
        raise SecurityEvidenceError("security_promotion_repositories_invalid")
    normalized_repositories: list[dict[str, str]] = []
    seen_repositories: set[str] = set()
    for coordinate in repositories:
        if not isinstance(coordinate, dict) or set(coordinate) != {
            "id",
            "commit",
            "version",
            "intended_tag",
        }:
            raise SecurityEvidenceError("security_promotion_repositories_invalid")
        repository_id = coordinate.get("id")
        commit = coordinate.get("commit")
        version = coordinate.get("version")
        intended_tag = coordinate.get("intended_tag")
        if (
            repository_id not in REPOSITORY_IDS
            or repository_id in seen_repositories
            or not isinstance(commit, str)
            or COMMIT.fullmatch(commit) is None
            or not isinstance(version, str)
            or intended_tag != f"v{version}"
            or not isinstance(intended_tag, str)
            or TAG.fullmatch(intended_tag) is None
        ):
            raise SecurityEvidenceError("security_promotion_repositories_invalid")
        seen_repositories.add(repository_id)
        normalized_repositories.append(dict(coordinate))
    if seen_repositories != set(REPOSITORY_IDS):
        raise SecurityEvidenceError("security_promotion_repositories_invalid")
    normalized_repositories.sort(key=lambda item: REPOSITORY_IDS.index(item["id"]))
    core = normalized_repositories[0]
    if (
        core["id"] != "core"
        or core["commit"] != expected_commit
        or core["version"] != candidate["version"]
        or core["intended_tag"] != expected_tag
    ):
        raise SecurityEvidenceError("security_promotion_core_mismatch")
    documentation = report.get("documentation")
    if (
        not isinstance(documentation, dict)
        or set(documentation)
        != {
            "repository",
            "commit",
            "canonical_core_commit",
            "source_commit",
            "source_manifest_sha256",
            "source_tree_sha256",
            "owned_file_count",
        }
        or documentation.get("repository")
        != "https://github.com/Latchway/latchway-docs.git"
        or documentation.get("canonical_core_commit") != expected_commit
        or not isinstance(documentation.get("commit"), str)
        or COMMIT.fullmatch(documentation["commit"]) is None
        or not isinstance(documentation.get("source_commit"), str)
        or COMMIT.fullmatch(documentation["source_commit"]) is None
        or not isinstance(documentation.get("source_manifest_sha256"), str)
        or SHA256.fullmatch(documentation["source_manifest_sha256"]) is None
        or not isinstance(documentation.get("source_tree_sha256"), str)
        or SHA256.fullmatch(documentation["source_tree_sha256"]) is None
        or not isinstance(documentation.get("owned_file_count"), int)
        or isinstance(documentation.get("owned_file_count"), bool)
        or not 1 <= documentation["owned_file_count"] <= 4096
    ):
        raise SecurityEvidenceError("security_promotion_documentation_invalid")

    evidence_window = report.get("evidence_window")
    if not isinstance(evidence_window, dict) or set(evidence_window) != {
        "started_at",
        "finished_at",
        "maximum_age_seconds",
    }:
        raise SecurityEvidenceError("security_promotion_window_invalid")
    started_at = parse_time(
        evidence_window.get("started_at"), "security_promotion_window_invalid"
    )
    finished_at = parse_time(
        evidence_window.get("finished_at"), "security_promotion_window_invalid"
    )
    if (
        evidence_window.get("maximum_age_seconds")
        != int(MAXIMUM_AGE.total_seconds())
        or started_at < candidate_created_at
        or finished_at <= started_at
        or finished_at > now
        or now - finished_at > MAXIMUM_AGE
        or finished_at - started_at > MAXIMUM_AGE
    ):
        raise SecurityEvidenceError("security_promotion_window_invalid")

    producer_path = root / PROMOTION_PRODUCER_VERIFICATION_NAME
    producer, _, producer_hash = load_review_snapshot(producer_path)
    expected_producer = {
        "schema_version": 1,
        "kind": "latchway_security_promotion_conformance_producer_verification",
        "repository": "Latchway/latchway",
        "workflow_path": PROMOTION_WORKFLOW,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": expected_commit,
        "head_branch": "main",
    }
    if producer != expected_producer:
        raise SecurityEvidenceError("security_promotion_producer_invalid")

    attestation_path = root / PROMOTION_ATTESTATION_VERIFICATION_NAME
    attestation, _, attestation_hash = load_review_snapshot(attestation_path)
    expected_attestation = {
        "schema_version": 1,
        "kind": "latchway_security_promotion_conformance_attestation_verification",
        "repository": "Latchway/latchway",
        "signer_workflow": f"Latchway/latchway/{PROMOTION_WORKFLOW}",
        "source_digest": expected_commit,
        "source_ref": "refs/heads/main",
        "subject_sha256": report_hash,
        "hosted_runner": True,
        "verified": True,
    }
    if attestation != expected_attestation:
        raise SecurityEvidenceError("security_promotion_attestation_invalid")
    _, _, bundle_hash = load_review_snapshot(root / PROMOTION_BUNDLE_NAME)

    binding = {
        "scope": "promotion",
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "report_sha256": report_hash,
        "repositories": normalized_repositories,
        "documentation": dict(documentation),
    }
    hashes = {
        PROMOTION_REPORT_NAME: report_hash,
        PROMOTION_BUNDLE_NAME: bundle_hash,
        PROMOTION_PRODUCER_VERIFICATION_NAME: producer_hash,
        PROMOTION_ATTESTATION_VERIFICATION_NAME: attestation_hash,
    }
    evidence = [
        {"path": f"promotion-conformance/{name}", "sha256": digest}
        for name, digest in sorted(hashes.items())
    ]
    return binding, evidence, finished_at
def validate_independent_review(
    *,
    review_directory: Path,
    candidate: Mapping[str, Any],
    candidate_created_at: datetime,
    promotion_binding: Mapping[str, Any],
    promotion_finished_at: datetime,
    expected_commit: str,
    expected_tag: str,
    expected_repository: str,
    expected_workflow: str,
    expected_reviewer_identity: str,
    expected_reviewer_organization: str,
    expected_reviewer_login: str,
    expected_run_id: int,
    expected_run_attempt: int,
    now: datetime,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, str]],
    datetime,
    datetime,
]:
    validate_review_tree(review_directory)
    if (
        not isinstance(expected_repository, str)
        or REPOSITORY_COORDINATE.fullmatch(expected_repository) is None
        or not isinstance(expected_workflow, str)
        or WORKFLOW_PATH.fullmatch(expected_workflow) is None
        or not isinstance(expected_reviewer_identity, str)
        or REVIEWER_VALUE.fullmatch(expected_reviewer_identity) is None
        or not isinstance(expected_reviewer_organization, str)
        or REVIEWER_VALUE.fullmatch(expected_reviewer_organization) is None
        or not isinstance(expected_reviewer_login, str)
        or GITHUB_LOGIN.fullmatch(expected_reviewer_login) is None
    ):
        raise SecurityEvidenceError("security_review_authority_invalid")
    producer_owner = expected_repository.split("/", 1)[0]
    if (
        producer_owner.casefold() == "latchway"
        or expected_reviewer_organization.strip().casefold() == "latchway"
    ):
        raise SecurityEvidenceError("security_review_not_independent")
    positive_integer(expected_run_id, "security_review_run_invalid")
    positive_integer(expected_run_attempt, "security_review_run_invalid")

    root = review_directory.resolve(strict=True)
    report_path = root / REVIEW_REPORT_NAME
    report, _, report_hash = load_review_snapshot(report_path)
    if set(report) != {
        "schema_version",
        "kind",
        "status",
        "review_window",
        "candidate",
        "reviewer",
        "producer",
        "reviews",
    }:
        raise SecurityEvidenceError("security_review_report_fields_invalid")
    if (
        report.get("schema_version") != 1
        or report.get("kind") != "latchway_independent_security_review"
        or report.get("status") != "passed"
    ):
        raise SecurityEvidenceError("security_review_report_invalid")

    candidate_binding = report.get("candidate")
    contract = candidate["contract"]
    image = candidate["image"]
    expected_candidate_binding = {
        "commit": expected_commit,
        "intended_tag": expected_tag,
        "version": candidate["version"],
        "contract": {
            "version": contract["version"],
            "bundle_file_name": contract["bundle_file_name"],
            "bundle_sha256": contract["bundle_sha256"],
        },
        "image": {
            "repository": image["repository"],
            "index_digest": image["index_digest"],
            "platforms": image["platforms"],
        },
        "promotion_conformance": promotion_binding,
    }
    if candidate_binding != expected_candidate_binding:
        raise SecurityEvidenceError("security_review_candidate_mismatch")

    reviewer = report.get("reviewer")
    expected_reviewer = {
        "identity": expected_reviewer_identity,
        "organization": expected_reviewer_organization,
        "github_login": expected_reviewer_login,
        "independent_from": "Latchway",
        "control": "separately_controlled",
    }
    if reviewer != expected_reviewer:
        raise SecurityEvidenceError("security_review_reviewer_mismatch")

    producer = report.get("producer")
    if not isinstance(producer, dict) or set(producer) != {
        "repository",
        "workflow_path",
        "run_id",
        "run_attempt",
        "source_commit",
    }:
        raise SecurityEvidenceError("security_review_producer_invalid")
    if (
        producer.get("repository") != expected_repository
        or producer.get("workflow_path") != expected_workflow
        or producer.get("run_id") != expected_run_id
        or producer.get("run_attempt") != expected_run_attempt
        or not isinstance(producer.get("source_commit"), str)
        or COMMIT.fullmatch(producer["source_commit"]) is None
    ):
        raise SecurityEvidenceError("security_review_producer_mismatch")

    review_window = report.get("review_window")
    if not isinstance(review_window, dict) or set(review_window) != {
        "started_at",
        "finished_at",
        "maximum_age_seconds",
    }:
        raise SecurityEvidenceError("security_review_window_invalid")
    review_started = parse_time(
        review_window.get("started_at"), "security_review_window_invalid"
    )
    review_finished = parse_time(
        review_window.get("finished_at"), "security_review_window_invalid"
    )
    if (
        review_window.get("maximum_age_seconds")
        != int(MAXIMUM_AGE.total_seconds())
        or review_started < candidate_created_at
        or review_started < promotion_finished_at
        or review_finished <= review_started
        or review_finished > now
        or review_finished - review_started > MAXIMUM_AGE
        or now - review_finished > MAXIMUM_AGE
    ):
        raise SecurityEvidenceError("security_review_window_invalid")

    reviews = report.get("reviews")
    if not isinstance(reviews, list) or len(reviews) != len(INDEPENDENT_REVIEWS):
        raise SecurityEvidenceError("security_review_results_incomplete")
    normalized_reviews: list[dict[str, Any]] = []
    retained: list[dict[str, str]] = []
    seen: set[str] = set()
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {
            "id",
            "status",
            "started_at",
            "finished_at",
            "findings",
            "accepted_risks",
            "artifact",
        }:
            raise SecurityEvidenceError("security_review_result_invalid")
        identifier = review.get("id")
        if identifier not in INDEPENDENT_REVIEWS or identifier in seen:
            raise SecurityEvidenceError("security_review_results_incomplete")
        seen.add(identifier)
        started_at = parse_time(
            review.get("started_at"), "security_review_result_time_invalid"
        )
        finished_at = parse_time(
            review.get("finished_at"), "security_review_result_time_invalid"
        )
        findings = validate_finding_counts(review.get("findings"))
        accepted_risks = validate_accepted_risks(
            review.get("accepted_risks"), findings, review_id=identifier
        )
        artifact = review.get("artifact")
        expected_relative = f"reviews/{identifier}.json"
        if (
            review.get("status") != "passed"
            or started_at < review_started
            or finished_at <= started_at
            or finished_at > review_finished
            or not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256"}
            or artifact.get("path") != expected_relative
            or not isinstance(artifact.get("sha256"), str)
            or SHA256.fullmatch(artifact["sha256"]) is None
        ):
            raise SecurityEvidenceError("security_review_result_invalid")
        artifact_path = root / expected_relative
        receipt, _, receipt_hash = load_review_snapshot(artifact_path)
        expected_receipt = {
            "schema_version": 1,
            "kind": "latchway_independent_security_review_result",
            "id": identifier,
            "status": "passed",
            "candidate_commit": expected_commit,
            "reviewer": reviewer,
            "started_at": review["started_at"],
            "finished_at": review["finished_at"],
            "findings": findings,
            "accepted_risks": accepted_risks,
        }
        if receipt != expected_receipt or receipt_hash != artifact["sha256"]:
            raise SecurityEvidenceError("security_review_artifact_mismatch")
        normalized_reviews.append(dict(review))
        retained.append(
            {
                "path": f"independent-review/{expected_relative}",
                "sha256": artifact["sha256"],
            }
        )
    if seen != set(INDEPENDENT_REVIEWS):
        raise SecurityEvidenceError("security_review_results_incomplete")

    producer_verification_path = root / REVIEW_PRODUCER_VERIFICATION_NAME
    producer_verification, _, producer_verification_hash = load_review_snapshot(
        producer_verification_path
    )
    expected_producer_verification = {
        "schema_version": 1,
        "kind": "latchway_independent_security_review_producer_verification",
        "repository": expected_repository,
        "workflow_path": expected_workflow,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": producer["source_commit"],
        "head_branch": "main",
        "actor_login": expected_reviewer_login,
        "triggering_actor_login": expected_reviewer_login,
    }
    if producer_verification != expected_producer_verification:
        raise SecurityEvidenceError("security_review_producer_verification_invalid")

    attestation_verification_path = root / REVIEW_ATTESTATION_VERIFICATION_NAME
    attestation_verification, _, attestation_verification_hash = load_review_snapshot(
        attestation_verification_path
    )
    expected_attestation_verification = {
        "schema_version": 1,
        "kind": "latchway_independent_security_review_attestation_verification",
        "repository": expected_repository,
        "signer_workflow": f"{expected_repository}/{expected_workflow}",
        "source_digest": producer["source_commit"],
        "source_ref": "refs/heads/main",
        "subject_sha256": report_hash,
        "hosted_runner": True,
        "verified": True,
    }
    if attestation_verification != expected_attestation_verification:
        raise SecurityEvidenceError("security_review_attestation_verification_invalid")

    _, _, bundle_hash = load_review_snapshot(root / REVIEW_BUNDLE_NAME)
    fixed_hashes = {
        REVIEW_REPORT_NAME: report_hash,
        REVIEW_BUNDLE_NAME: bundle_hash,
        REVIEW_PRODUCER_VERIFICATION_NAME: producer_verification_hash,
        REVIEW_ATTESTATION_VERIFICATION_NAME: attestation_verification_hash,
    }
    for relative, digest in fixed_hashes.items():
        retained.append(
            {
                "path": f"independent-review/{relative}",
                "sha256": digest,
            }
        )
    authority = {
        "reviewer": reviewer,
        "producer": producer,
        "report_sha256": report_hash,
    }
    return (
        authority,
        sorted(normalized_reviews, key=lambda item: item["id"]),
        sorted(retained, key=lambda item: item["path"]),
        review_started,
        review_finished,
    )


def derive_summary(
    *,
    candidate_manifest: Path,
    raw_directory: Path,
    review_directory: Path,
    promotion_directory: Path,
    repository: Path,
    expected_commit: str,
    expected_tag: str,
    expected_review_repository: str,
    expected_review_workflow: str,
    expected_reviewer_identity: str,
    expected_reviewer_organization: str,
    expected_reviewer_login: str,
    expected_review_run_id: int,
    expected_review_run_attempt: int,
    expected_promotion_run_id: int,
    expected_promotion_run_attempt: int,
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
    promotion_binding, promotion_evidence, promotion_finished = (
        validate_promotion_conformance(
            promotion_directory=promotion_directory,
            candidate=candidate,
            candidate_created_at=candidate_created_at,
            expected_commit=expected_commit,
            expected_tag=expected_tag,
            expected_run_id=expected_promotion_run_id,
            expected_run_attempt=expected_promotion_run_attempt,
            now=now,
        )
    )
    (
        review_authority,
        independent_reviews,
        review_evidence,
        review_started,
        review_finished,
    ) = validate_independent_review(
        review_directory=review_directory,
        candidate=candidate,
        candidate_created_at=candidate_created_at,
        promotion_binding=promotion_binding,
        promotion_finished_at=promotion_finished,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        expected_repository=expected_review_repository,
        expected_workflow=expected_review_workflow,
        expected_reviewer_identity=expected_reviewer_identity,
        expected_reviewer_organization=expected_reviewer_organization,
        expected_reviewer_login=expected_reviewer_login,
        expected_run_id=expected_review_run_id,
        expected_run_attempt=expected_review_run_attempt,
        now=now,
    )
    validate_raw_directory(raw_directory)
    started_times: list[datetime] = [review_started]
    finished_times: list[datetime] = [review_finished]
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
        "schema_version": 2,
        "kind": "latchway_candidate_security_evidence",
        "automated_gate": "passed",
        "independent_review_gate": "passed",
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
        "promotion_conformance": promotion_binding,
        "review_authority": review_authority,
        "independent_reviews": independent_reviews,
        "raw_evidence": sorted(raw_evidence, key=lambda item: item["path"]),
        "review_evidence": review_evidence,
        "promotion_evidence": promotion_evidence,
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
    for artifact in summary["review_evidence"]:
        relative = artifact["path"].removeprefix("independent-review/")
        if relative == artifact["path"] or review_file_hash(
            review_directory / relative
        ) != artifact["sha256"]:
            raise SecurityEvidenceError("security_review_changed_during_validation")
    for artifact in summary["promotion_evidence"]:
        relative = artifact["path"].removeprefix("promotion-conformance/")
        if relative == artifact["path"] or review_file_hash(
            promotion_directory / relative
        ) != artifact["sha256"]:
            raise SecurityEvidenceError("security_promotion_changed_during_validation")
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


def copy_review_snapshot(source: Path, destination: Path, expected_digest: str) -> None:
    _, payload, digest = load_review_snapshot(source)
    if digest != expected_digest:
        raise SecurityEvidenceError("security_review_changed_during_copy")
    try:
        with destination.open("xb") as output:
            output.write(payload)
        destination.chmod(0o600)
    except OSError:
        raise SecurityEvidenceError("security_evidence_copy_failed") from None
    if review_file_hash(destination) != expected_digest:
        raise SecurityEvidenceError("security_review_changed_during_copy")


def seal(
    *,
    candidate_manifest: Path,
    raw_directory: Path,
    review_directory: Path,
    promotion_directory: Path,
    repository: Path,
    expected_commit: str,
    expected_tag: str,
    expected_review_repository: str,
    expected_review_workflow: str,
    expected_reviewer_identity: str,
    expected_reviewer_organization: str,
    expected_reviewer_login: str,
    expected_review_run_id: int,
    expected_review_run_attempt: int,
    expected_promotion_run_id: int,
    expected_promotion_run_attempt: int,
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
        review_directory=review_directory,
        promotion_directory=promotion_directory,
        repository=repository,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        expected_review_repository=expected_review_repository,
        expected_review_workflow=expected_review_workflow,
        expected_reviewer_identity=expected_reviewer_identity,
        expected_reviewer_organization=expected_reviewer_organization,
        expected_reviewer_login=expected_reviewer_login,
        expected_review_run_id=expected_review_run_id,
        expected_review_run_attempt=expected_review_run_attempt,
        expected_promotion_run_id=expected_promotion_run_id,
        expected_promotion_run_attempt=expected_promotion_run_attempt,
        now=now,
    )
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}.", dir=output_directory.parent
        )
    )
    try:
        (staging / "raw").mkdir(mode=0o700)
        (staging / "independent-review" / "reviews").mkdir(
            mode=0o700, parents=True
        )
        (staging / "promotion-conformance").mkdir(mode=0o700)
        copy_real_file(candidate_manifest, staging / "latchway-candidate.json")
        for name in sorted(expected_raw_names()):
            copy_real_file(
                raw_directory / name,
                staging / "raw" / name,
                allow_empty=name.endswith(".log"),
            )
        for artifact in summary["review_evidence"]:
            relative = artifact["path"].removeprefix("independent-review/")
            if relative == artifact["path"]:
                raise SecurityEvidenceError("security_review_copy_invalid")
            copy_review_snapshot(
                review_directory / relative,
                staging / "independent-review" / relative,
                artifact["sha256"],
            )
        for artifact in summary["promotion_evidence"]:
            relative = artifact["path"].removeprefix("promotion-conformance/")
            if relative == artifact["path"]:
                raise SecurityEvidenceError("security_promotion_copy_invalid")
            copy_review_snapshot(
                promotion_directory / relative,
                staging / "promotion-conformance" / relative,
                artifact["sha256"],
            )
        write_json(staging / "security-summary.json", summary)
        os.replace(staging, output_directory)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return summary


def verify_review(
    *,
    candidate_manifest: Path,
    review_directory: Path,
    promotion_directory: Path,
    expected_commit: str,
    expected_tag: str,
    expected_review_repository: str,
    expected_review_workflow: str,
    expected_reviewer_identity: str,
    expected_reviewer_organization: str,
    expected_reviewer_login: str,
    expected_review_run_id: int,
    expected_review_run_attempt: int,
    expected_promotion_run_id: int,
    expected_promotion_run_attempt: int,
    now: datetime,
) -> dict[str, Any]:
    candidate, _, candidate_created_at = validate_candidate(
        candidate_manifest,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        now=now,
    )
    promotion_binding, promotion_evidence, promotion_finished = (
        validate_promotion_conformance(
            promotion_directory=promotion_directory,
            candidate=candidate,
            candidate_created_at=candidate_created_at,
            expected_commit=expected_commit,
            expected_tag=expected_tag,
            expected_run_id=expected_promotion_run_id,
            expected_run_attempt=expected_promotion_run_attempt,
            now=now,
        )
    )
    authority, reviews, evidence, started_at, finished_at = validate_independent_review(
        review_directory=review_directory,
        candidate=candidate,
        candidate_created_at=candidate_created_at,
        promotion_binding=promotion_binding,
        promotion_finished_at=promotion_finished,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        expected_repository=expected_review_repository,
        expected_workflow=expected_review_workflow,
        expected_reviewer_identity=expected_reviewer_identity,
        expected_reviewer_organization=expected_reviewer_organization,
        expected_reviewer_login=expected_reviewer_login,
        expected_run_id=expected_review_run_id,
        expected_run_attempt=expected_review_run_attempt,
        now=now,
    )
    return {
        "status": "passed",
        "authority": authority,
        "review_ids": [item["id"] for item in reviews],
        "evidence_sha256": [item["sha256"] for item in evidence],
        "promotion_evidence_sha256": [
            item["sha256"] for item in promotion_evidence
        ],
        "started_at": canonical_time(started_at),
        "finished_at": canonical_time(finished_at),
    }


def verify(
    *,
    report: Path,
    candidate_manifest: Path,
    raw_directory: Path,
    review_directory: Path,
    promotion_directory: Path,
    repository: Path,
    expected_commit: str,
    expected_tag: str,
    now: datetime,
) -> dict[str, Any]:
    actual = load_json(report)
    authority = actual.get("review_authority")
    reviewer = authority.get("reviewer") if isinstance(authority, dict) else None
    producer = authority.get("producer") if isinstance(authority, dict) else None
    if not isinstance(reviewer, dict) or not isinstance(producer, dict):
        raise SecurityEvidenceError("security_review_authority_invalid")
    promotion = actual.get("promotion_conformance")
    if not isinstance(promotion, dict):
        raise SecurityEvidenceError("security_promotion_binding_invalid")
    expected = derive_summary(
        candidate_manifest=candidate_manifest,
        raw_directory=raw_directory,
        review_directory=review_directory,
        promotion_directory=promotion_directory,
        repository=repository,
        expected_commit=expected_commit,
        expected_tag=expected_tag,
        expected_review_repository=producer.get("repository"),
        expected_review_workflow=producer.get("workflow_path"),
        expected_reviewer_identity=reviewer.get("identity"),
        expected_reviewer_organization=reviewer.get("organization"),
        expected_reviewer_login=reviewer.get("github_login"),
        expected_review_run_id=producer.get("run_id"),
        expected_review_run_attempt=producer.get("run_attempt"),
        expected_promotion_run_id=promotion.get("run_id"),
        expected_promotion_run_attempt=promotion.get("run_attempt"),
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
    modes.add_argument("--verify-review", action="store_true")
    modes.add_argument("--seal", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--raw-directory", type=Path)
    parser.add_argument("--review-directory", type=Path)
    parser.add_argument("--promotion-directory", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--tag")
    parser.add_argument("--window", type=Path)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--review-repository")
    parser.add_argument("--review-workflow")
    parser.add_argument("--reviewer-identity")
    parser.add_argument("--reviewer-organization")
    parser.add_argument("--reviewer-login")
    parser.add_argument("--review-run-id", type=int)
    parser.add_argument("--review-run-attempt", type=int)
    parser.add_argument("--promotion-run-id", type=int)
    parser.add_argument("--promotion-run-attempt", type=int)
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
        elif arguments.verify_review:
            result = verify_review(
                candidate_manifest=required(arguments.candidate_manifest),
                review_directory=required(arguments.review_directory),
                promotion_directory=required(arguments.promotion_directory),
                expected_commit=required(arguments.commit),
                expected_tag=required(arguments.tag),
                expected_review_repository=required(arguments.review_repository),
                expected_review_workflow=required(arguments.review_workflow),
                expected_reviewer_identity=required(arguments.reviewer_identity),
                expected_reviewer_organization=required(
                    arguments.reviewer_organization
                ),
                expected_reviewer_login=required(arguments.reviewer_login),
                expected_review_run_id=required(arguments.review_run_id),
                expected_review_run_attempt=required(arguments.review_run_attempt),
                expected_promotion_run_id=required(arguments.promotion_run_id),
                expected_promotion_run_attempt=required(
                    arguments.promotion_run_attempt
                ),
                now=now,
            )
        elif arguments.seal:
            result = seal(
                candidate_manifest=required(arguments.candidate_manifest),
                raw_directory=required(arguments.raw_directory),
                review_directory=required(arguments.review_directory),
                promotion_directory=required(arguments.promotion_directory),
                repository=required(arguments.repository),
                expected_commit=required(arguments.commit),
                expected_tag=required(arguments.tag),
                expected_review_repository=required(arguments.review_repository),
                expected_review_workflow=required(arguments.review_workflow),
                expected_reviewer_identity=required(arguments.reviewer_identity),
                expected_reviewer_organization=required(
                    arguments.reviewer_organization
                ),
                expected_reviewer_login=required(arguments.reviewer_login),
                expected_review_run_id=required(arguments.review_run_id),
                expected_review_run_attempt=required(arguments.review_run_attempt),
                expected_promotion_run_id=required(arguments.promotion_run_id),
                expected_promotion_run_attempt=required(
                    arguments.promotion_run_attempt
                ),
                output_directory=required(arguments.output_directory),
                now=now,
            )
        else:
            result = verify(
                report=required(arguments.report),
                candidate_manifest=required(arguments.candidate_manifest),
                raw_directory=required(arguments.raw_directory),
                review_directory=required(arguments.review_directory),
                promotion_directory=required(arguments.promotion_directory),
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
