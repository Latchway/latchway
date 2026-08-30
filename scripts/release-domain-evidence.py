#!/usr/bin/env python3
"""Produce and finalize attested external release-domain evidence.

The producer accepts only fixed, candidate-bound machine result envelopes.  It
does not accept claim names or pass/fail booleans.  The finalizer independently
rehashes every retained result, verifies the source, candidate, and producer
GitHub attestations, and only then derives the fixed claims consumed by the
cross-repository release gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
COMMON_PATH = Path(__file__).with_name("operational-resilience-evidence.py")
COMMON_SPEC = importlib.util.spec_from_file_location(
    "latchway_operational_evidence_common", COMMON_PATH
)
if COMMON_SPEC is None or COMMON_SPEC.loader is None:
    raise RuntimeError("release evidence common validator cannot be loaded")
COMMON = importlib.util.module_from_spec(COMMON_SPEC)
COMMON_SPEC.loader.exec_module(COMMON)

GH_VERSION_PATH = Path(__file__).with_name("require-gh-version.py")
GH_VERSION_SPEC = importlib.util.spec_from_file_location(
    "latchway_release_domain_require_gh_version", GH_VERSION_PATH
)
if GH_VERSION_SPEC is None or GH_VERSION_SPEC.loader is None:
    raise RuntimeError("GitHub CLI version policy cannot be loaded")
GH_VERSION = importlib.util.module_from_spec(GH_VERSION_SPEC)
GH_VERSION_SPEC.loader.exec_module(GH_VERSION)

SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
TOOL_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAXIMUM_AGE = timedelta(days=7)
MAXIMUM_RESULT_BYTES = 2 * 1024 * 1024
MAXIMUM_RAW_BYTES = 32 * 1024 * 1024
MAXIMUM_DOMAIN_BYTES = 64 * 1024 * 1024
MAXIMUM_ARTIFACTS_PER_RESULT = 8
REPOSITORY = "Latchway/latchway"
WORKFLOW = ".github/workflows/release-domain-observations.yml"
FINALIZER_WORKFLOW = ".github/workflows/release-domain-evidence.yml"
SOURCE_WORKFLOW = ".github/workflows/cross-repository-conformance.yml"
CANDIDATE_WORKFLOW = ".github/workflows/release.yml"
REPOSITORY_IDS = ("core", "javascript", "ios", "android", "react_native")


# A claim is derived only when all of its fixed machine observations exist.
# Observation IDs are deliberately distinct from the public claim names.
CLAIM_REQUIREMENTS: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "live_sdk_conformance": {
        "javascript_against_release_image": (
            "sdk.javascript.firebase-app-check.release-image",
            "sdk.javascript.turnstile.release-image",
        ),
        "ios_against_release_image": ("sdk.ios.release-image",),
        "android_against_release_image": ("sdk.android.release-image",),
        "react_native_ios_against_release_image": ("sdk.react-native-ios.release-image",),
        "react_native_android_against_release_image": ("sdk.react-native-android.release-image",),
        "dpop_vectors": ("sdk.behavior.dpop-vectors",),
        "error_mapping": ("sdk.behavior.error-mapping",),
        "session_refresh": ("sdk.behavior.session-refresh",),
        "installation_revocation": ("sdk.behavior.installation-revocation",),
        "streaming": ("sdk.behavior.streaming",),
        "quota_snapshots": ("sdk.behavior.quota-snapshots",),
        "protocol_version_rejection": ("sdk.behavior.protocol-version-rejection",),
    },
    "physical_devices": {
        "app_attest_production_verified": ("sdk.ios.release-image",),
        "play_integrity_play_distributed_verified": ("sdk.android.release-image",),
        "react_native_ios_verified": ("sdk.react-native-ios.release-image",),
        "react_native_android_verified": ("sdk.react-native-android.release-image",),
    },
    "live_provider": {
        "openrouter_nonstreaming_verified": (
            "provider.gateway-identity",
            "provider.openrouter.non-streaming",
        ),
        "openrouter_streaming_verified": (
            "provider.gateway-identity",
            "provider.openrouter.streaming",
        ),
        "usage_verified": ("provider.gateway-identity", "provider.openrouter.usage"),
        "output_clamp_verified": (
            "provider.gateway-identity",
            "provider.openrouter.output-clamp",
        ),
        "error_normalization_verified": (
            "provider.gateway-identity",
            "provider.openrouter.error-normalization",
        ),
    },
    "supply_chain": {
        "multi_arch_image_verified": (
            "supply.oci-index",
            "supply.platform.amd64",
            "supply.platform.arm64",
        ),
        "vulnerability_scan_verified": (
            "supply.vulnerability.amd64",
            "supply.vulnerability.arm64",
        ),
        "license_scan_verified": (
            "supply.license.amd64",
            "supply.license.arm64",
        ),
        "sbom_verified": ("supply.sbom.amd64", "supply.sbom.arm64"),
        "signature_verified": ("supply.cosign-signature",),
        "provenance_verified": ("supply.github-provenance",),
    },
    "public_tags": {
        "remote_annotated_tags_verified": tuple(
            f"publication.annotated-tag.{repository}" for repository in REPOSITORY_IDS
        ),
        "github_releases_verified": tuple(
            f"publication.github-release.{repository}" for repository in REPOSITORY_IDS
        ),
    },
    "public_registries": {
        "oci_digest_verified": ("registry.oci",),
        "npm_javascript_verified": ("registry.npm.javascript",),
        "npm_react_native_verified": ("registry.npm.react-native",),
        "swift_package_verified": ("registry.swift",),
        "cocoapods_verified": ("registry.cocoapods",),
        "maven_central_verified": ("registry.maven-central",),
    },
}

OBSERVATION_TOOLS: Mapping[str, str] = {
    **{
        observation: "latchway-live-sdk-harness"
        for requirements in CLAIM_REQUIREMENTS["live_sdk_conformance"].values()
        for observation in requirements
    },
    **{
        observation: "latchway-live-sdk-harness"
        for requirements in CLAIM_REQUIREMENTS["physical_devices"].values()
        for observation in requirements
    },
    **{
        observation: "latchway-admin-self-test"
        for requirements in CLAIM_REQUIREMENTS["live_provider"].values()
        for observation in requirements
    },
    "provider.gateway-identity": "latchway-gateway-health",
    "supply.oci-index": "docker-buildx",
    "supply.platform.amd64": "docker-buildx",
    "supply.platform.arm64": "docker-buildx",
    "supply.vulnerability.amd64": "candidate-trivy-report-validator",
    "supply.vulnerability.arm64": "candidate-trivy-report-validator",
    "supply.license.amd64": "candidate-trivy-report-validator",
    "supply.license.arm64": "candidate-trivy-report-validator",
    "supply.sbom.amd64": "candidate-spdx-report-validator",
    "supply.sbom.arm64": "candidate-spdx-report-validator",
    "supply.cosign-signature": "cosign",
    "supply.github-provenance": "github-attestation",
    **{
        observation: "github-api"
        for requirements in CLAIM_REQUIREMENTS["public_tags"].values()
        for observation in requirements
    },
    "registry.oci": "cosign",
    "registry.npm.javascript": "npm",
    "registry.npm.react-native": "npm",
    "registry.swift": "swift",
    "registry.cocoapods": "cocoapods",
    "registry.maven-central": "maven",
}

SENSITIVE_TEXT = (
    re.compile(r"(?i)(authorization|proxy-authorization|cookie|set-cookie|password|api[_-]?key)\s*[:=]"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})\b"),
)
FORBIDDEN_ASSERTION_KEYS = frozenset(("claims", "claim", "passed", "success", "verdict"))


class EvidenceError(Exception):
    """A stable, redaction-safe evidence failure."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("json_duplicate_key")
        value[key] = item
    return value


def reject_nonfinite(_: str) -> Any:
    raise EvidenceError("json_nonfinite_number")


def real_file(path: Path, maximum: int) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and 1 <= metadata.st_size <= maximum
    )


def read_bytes(path: Path, maximum: int = MAXIMUM_RAW_BYTES) -> bytes:
    if not real_file(path, maximum):
        raise EvidenceError("input_file_invalid")
    try:
        return path.read_bytes()
    except OSError:
        raise EvidenceError("input_file_invalid") from None


def scan_safe(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceError("raw_result_not_utf8") from None
    if any(pattern.search(text) for pattern in SENSITIVE_TEXT):
        raise EvidenceError("raw_result_contains_secret")


def read_json(path: Path, maximum: int = MAXIMUM_RESULT_BYTES) -> dict[str, Any]:
    payload = read_bytes(path, maximum)
    scan_safe(payload)
    try:
        value = json.loads(
            payload,
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except EvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise EvidenceError("input_json_invalid") from None
    if not isinstance(value, dict):
        raise EvidenceError("input_json_invalid")
    return value


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path, maximum: int = MAXIMUM_RAW_BYTES) -> str:
    return sha256_bytes(read_bytes(path, maximum))


def safe_relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    relative = PurePosixPath(value)
    return relative.as_posix() == value and not any(
        part in ("", ".", "..") for part in relative.parts
    )


def resolve_inside(root: Path, relative: str) -> Path:
    if not safe_relative(relative):
        raise EvidenceError("artifact_path_invalid")
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate /= part
        try:
            if stat.S_ISLNK(candidate.lstat().st_mode):
                raise EvidenceError("artifact_path_invalid")
        except FileNotFoundError:
            raise EvidenceError("artifact_missing") from None
    if not real_file(candidate, MAXIMUM_RAW_BYTES):
        raise EvidenceError("artifact_missing")
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise EvidenceError("artifact_path_invalid") from None
    return candidate


def parse_time(value: Any, code: str = "result_time_invalid") -> datetime:
    try:
        return COMMON.parse_time(value, code)
    except COMMON.EvidenceError as error:
        raise EvidenceError(str(error)) from None


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def require_fields(value: Any, fields: Sequence[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise EvidenceError(code)
    return value


def identity_from_inputs(
    source_path: Path, candidate_path: Path, now: datetime
) -> tuple[dict[str, Any], dict[str, Any], datetime]:
    try:
        source = COMMON.validate_source(source_path, now)
        candidate, image, created = COMMON.validate_candidate(candidate_path, source, now)
    except COMMON.EvidenceError as error:
        raise EvidenceError(str(error)) from None
    contract = source["contract"]
    return (
        {
            "core_commit": source["repositories"]["core"]["commit"],
            "core_release": contract["core_release"],
            "contract_version": contract["version"],
            "bundle_sha256": contract["bundle_sha256"],
            "oci_image_digest": image,
            "repositories": source["repositories"],
        },
        candidate,
        created,
    )


def result_name(observation: str) -> str:
    return observation.replace(".", "-") + ".json"


def expected_observations(domain: str) -> tuple[str, ...]:
    requirements = CLAIM_REQUIREMENTS.get(domain)
    if requirements is None:
        raise EvidenceError("domain_invalid")
    return tuple(sorted({item for values in requirements.values() for item in values}))


def validate_result(
    path: Path,
    raw_root: Path,
    domain: str,
    observation: str,
    identity: Mapping[str, Any],
    minimum_time: datetime,
    now: datetime,
) -> tuple[dict[str, Any], datetime, datetime, list[dict[str, str]]]:
    value = read_json(path)
    if FORBIDDEN_ASSERTION_KEYS & set(value):
        raise EvidenceError("self_asserted_result_rejected")
    value = require_fields(
        value,
        (
            "schema_version",
            "kind",
            "domain",
            "observation",
            "started_at",
            "finished_at",
            "candidate",
            "tool",
            "exit_code",
            "artifacts",
        ),
        "result_fields_invalid",
    )
    if (
        value["schema_version"] != 1
        or value["kind"] != "latchway_release_machine_result"
        or value["domain"] != domain
        or value["observation"] != observation
        or value["candidate"] != identity
        or value["exit_code"] != 0
        or isinstance(value["exit_code"], bool)
    ):
        raise EvidenceError("result_identity_or_exit_invalid")
    tool = require_fields(value["tool"], ("name", "version", "invocation_sha256"), "result_tool_invalid")
    if (
        tool["name"] != OBSERVATION_TOOLS[observation]
        or not isinstance(tool["version"], str)
        or TOOL_VALUE.fullmatch(tool["version"]) is None
        or not isinstance(tool["invocation_sha256"], str)
        or SHA256.fullmatch(tool["invocation_sha256"]) is None
    ):
        raise EvidenceError("result_tool_invalid")
    started = parse_time(value["started_at"])
    finished = parse_time(value["finished_at"])
    if (
        started < minimum_time
        or finished <= started
        or finished > now
        or now - finished > MAXIMUM_AGE
        or finished - started > MAXIMUM_AGE
    ):
        raise EvidenceError("result_time_invalid")
    artifacts = value["artifacts"]
    if (
        not isinstance(artifacts, list)
        or not 1 <= len(artifacts) <= MAXIMUM_ARTIFACTS_PER_RESULT
    ):
        raise EvidenceError("result_artifacts_invalid")
    prefix = f"artifacts/{observation.replace('.', '-')}/"
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in artifacts:
        item = require_fields(item, ("path", "sha256"), "result_artifacts_invalid")
        relative, expected = item["path"], item["sha256"]
        if (
            not safe_relative(relative)
            or not relative.startswith(prefix)
            or relative in seen
            or not isinstance(expected, str)
            or SHA256.fullmatch(expected) is None
        ):
            raise EvidenceError("result_artifacts_invalid")
        seen.add(relative)
        artifact = resolve_inside(raw_root, relative)
        payload = read_bytes(artifact)
        scan_safe(payload)
        if sha256_bytes(payload) != expected:
            raise EvidenceError("result_artifact_hash_mismatch")
        normalized.append({"path": relative, "sha256": expected})
    return value, started, finished, normalized


def validate_raw_results(
    raw_root: Path,
    domain: str,
    identity: Mapping[str, Any],
    minimum_time: datetime,
    now: datetime,
) -> tuple[list[dict[str, Any]], datetime, datetime, set[Path]]:
    if not raw_root.is_absolute() or not raw_root.is_dir() or raw_root.is_symlink():
        raise EvidenceError("raw_directory_invalid")
    observations: list[dict[str, Any]] = []
    intervals: list[tuple[datetime, datetime]] = []
    used_files: set[Path] = set()
    for observation in expected_observations(domain):
        path = raw_root / result_name(observation)
        value, started, finished, artifacts = validate_result(
            path, raw_root, domain, observation, identity, minimum_time, now
        )
        used_files.add(path.resolve())
        for artifact in artifacts:
            used_files.add(resolve_inside(raw_root, artifact["path"]).resolve())
        observations.append(
            {
                "id": observation,
                "result_path": path.name,
                "result_sha256": sha256_file(path, MAXIMUM_RESULT_BYTES),
                "artifacts": artifacts,
            }
        )
        intervals.append((started, finished))
        # Detect changes after parsing and artifact validation.
        if sha256_file(path, MAXIMUM_RESULT_BYTES) != observations[-1]["result_sha256"]:
            raise EvidenceError("result_changed_during_validation")
        del value
    actual_files: set[Path] = set()
    total = 0
    for path in raw_root.rglob("*"):
        if path.is_symlink():
            raise EvidenceError("raw_directory_contains_symlink")
        if path.is_file():
            resolved = path.resolve()
            actual_files.add(resolved)
            total += path.stat().st_size
    if actual_files != used_files or total > MAXIMUM_DOMAIN_BYTES:
        raise EvidenceError("raw_directory_file_set_invalid")
    earliest = min(started for started, _ in intervals)
    latest = max(finished for _, finished in intervals)
    if latest - earliest > MAXIMUM_AGE:
        raise EvidenceError("result_window_invalid")
    return observations, earliest, latest, used_files


def protected_context() -> dict[str, Any]:
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "LATCHWAY_RELEASE_EVIDENCE_ENVIRONMENT": "release-evidence",
    }
    if any(os.environ.get(name) != value for name, value in expected.items()):
        raise EvidenceError("protected_workflow_required")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if workflow_ref != f"{REPOSITORY}/{WORKFLOW}@refs/heads/main":
        raise EvidenceError("protected_workflow_required")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if (
        RUN_ID.fullmatch(run_id) is None
        or RUN_ID.fullmatch(attempt) is None
    ):
        raise EvidenceError("protected_workflow_required")
    return {
        "repository": REPOSITORY,
        "workflow": WORKFLOW,
        "run_id": run_id,
        "run_attempt": int(attempt),
    }


def write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def produce(
    *,
    domain: str,
    source_path: Path,
    candidate_path: Path,
    raw_root: Path,
    receipt_path: Path,
    now: datetime,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if domain not in CLAIM_REQUIREMENTS:
        raise EvidenceError("domain_invalid")
    if not receipt_path.is_absolute() or receipt_path.exists() or receipt_path.is_symlink():
        raise EvidenceError("receipt_output_invalid")
    producer = dict(context if context is not None else protected_context())
    if set(producer) != {
        "repository", "workflow", "run_id", "run_attempt",
    }:
        raise EvidenceError("producer_identity_invalid")
    if (
        producer["repository"] != REPOSITORY
        or producer["workflow"] != WORKFLOW
        or RUN_ID.fullmatch(str(producer["run_id"])) is None
        or not isinstance(producer["run_attempt"], int)
        or isinstance(producer["run_attempt"], bool)
        or producer["run_attempt"] < 1
    ):
        raise EvidenceError("producer_identity_invalid")
    identity, _, candidate_created = identity_from_inputs(source_path, candidate_path, now)
    observations, started, finished, _ = validate_raw_results(
        raw_root, domain, identity, candidate_created, now
    )
    receipt = {
        "schema_version": 1,
        "kind": "latchway_release_domain_producer_receipt",
        "domain": domain,
        "producer": producer,
        "started_at": format_time(started),
        "finished_at": format_time(finished),
        "candidate": identity,
        "observations": observations,
    }
    write_exclusive(receipt_path, receipt)
    return receipt


def verify_attestation(
    subject: Path,
    *,
    repository: str,
    workflow: str,
    source_digest: str,
    bundle: Path | None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[Any]:
    executable = shutil.which("gh")
    if executable is None:
        raise EvidenceError("github_attestation_verifier_unavailable")
    arguments = [
        executable,
        "attestation",
        "verify",
        str(subject),
        "--repo",
        repository,
        "--signer-workflow",
        f"{repository}/{workflow}",
        "--source-digest",
        source_digest,
        "--signer-digest",
        source_digest,
        "--source-ref",
        "refs/heads/main",
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]
    if bundle is not None:
        if not real_file(bundle, MAXIMUM_RESULT_BYTES):
            raise EvidenceError("attestation_bundle_invalid")
        arguments.extend(("--bundle", str(bundle)))
    environment = dict(os.environ)
    environment["GH_PROMPT_DISABLED"] = "1"
    try:
        result = runner(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        raise EvidenceError("github_attestation_invalid") from None
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > MAXIMUM_RESULT_BYTES:
        raise EvidenceError("github_attestation_invalid")
    try:
        value = json.loads(result.stdout, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (EvidenceError, json.JSONDecodeError):
        raise EvidenceError("github_attestation_invalid") from None
    if not isinstance(value, list) or not value:
        raise EvidenceError("github_attestation_invalid")
    return value


def validate_receipt(
    receipt_path: Path,
    raw_root: Path,
    domain: str,
    identity: Mapping[str, Any],
    minimum_time: datetime,
    now: datetime,
) -> tuple[dict[str, Any], datetime, datetime]:
    receipt = read_json(receipt_path)
    if FORBIDDEN_ASSERTION_KEYS & set(receipt):
        raise EvidenceError("self_asserted_receipt_rejected")
    receipt = require_fields(
        receipt,
        (
            "schema_version", "kind", "domain", "producer", "started_at",
            "finished_at", "candidate", "observations",
        ),
        "receipt_fields_invalid",
    )
    producer = require_fields(
        receipt["producer"],
        (
            "repository", "workflow", "run_id", "run_attempt",
        ),
        "receipt_producer_invalid",
    )
    if (
        receipt["schema_version"] != 1
        or receipt["kind"] != "latchway_release_domain_producer_receipt"
        or receipt["domain"] != domain
        or receipt["candidate"] != identity
        or producer["repository"] != REPOSITORY
        or producer["workflow"] != WORKFLOW
        or RUN_ID.fullmatch(str(producer["run_id"])) is None
        or not isinstance(producer["run_attempt"], int)
        or isinstance(producer["run_attempt"], bool)
        or producer["run_attempt"] < 1
    ):
        raise EvidenceError("receipt_identity_invalid")
    observed, started, finished, _ = validate_raw_results(
        raw_root, domain, identity, minimum_time, now
    )
    if receipt["observations"] != observed:
        raise EvidenceError("receipt_observations_mismatch")
    if receipt["started_at"] != format_time(started) or receipt["finished_at"] != format_time(finished):
        raise EvidenceError("receipt_time_mismatch")
    return receipt, started, finished


def copy_file(source: Path, destination: Path, maximum: int = MAXIMUM_RAW_BYTES) -> str:
    payload = read_bytes(source, maximum)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return sha256_bytes(payload)


def finalize(
    *,
    domain: str,
    source_path: Path,
    candidate_path: Path,
    raw_root: Path,
    receipt_path: Path,
    receipt_bundle: Path | None,
    source_bundle: Path | None,
    candidate_bundle: Path | None,
    output_root: Path,
    now: datetime,
    verifier: Callable[..., list[Any]] = verify_attestation,
) -> dict[str, Any]:
    if domain not in CLAIM_REQUIREMENTS:
        raise EvidenceError("domain_invalid")
    if any(
        bundle is None or not real_file(bundle, MAXIMUM_RESULT_BYTES)
        for bundle in (receipt_bundle, source_bundle, candidate_bundle)
    ):
        raise EvidenceError("attestation_bundle_required")
    if not output_root.is_absolute() or output_root.is_symlink():
        raise EvidenceError("output_directory_invalid")
    if output_root.exists() and (not output_root.is_dir() or any(output_root.iterdir())):
        raise EvidenceError("output_directory_not_empty")
    initial_hashes = {
        "source": sha256_file(source_path, MAXIMUM_RESULT_BYTES),
        "candidate": sha256_file(candidate_path, MAXIMUM_RESULT_BYTES),
        "receipt": sha256_file(receipt_path, MAXIMUM_RESULT_BYTES),
    }
    identity, _, candidate_created = identity_from_inputs(source_path, candidate_path, now)
    receipt, started, finished = validate_receipt(
        receipt_path, raw_root, domain, identity, candidate_created, now
    )
    commit = identity["core_commit"]
    source_verification = verifier(
        source_path,
        repository=REPOSITORY,
        workflow=SOURCE_WORKFLOW,
        source_digest=commit,
        bundle=source_bundle,
    )
    candidate_verification = verifier(
        candidate_path,
        repository=REPOSITORY,
        workflow=CANDIDATE_WORKFLOW,
        source_digest=commit,
        bundle=candidate_bundle,
    )
    receipt_verification = verifier(
        receipt_path,
        repository=REPOSITORY,
        workflow=WORKFLOW,
        source_digest=commit,
        bundle=receipt_bundle,
    )
    if any(
        sha256_file(path, MAXIMUM_RESULT_BYTES) != initial_hashes[name]
        for name, path in (("source", source_path), ("candidate", candidate_path), ("receipt", receipt_path))
    ):
        raise EvidenceError("evidence_changed_during_validation")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.tmp-", dir=output_root.parent))
    try:
        staging.chmod(0o700)
        artifact_root = staging / "artifacts" / domain.replace("_", "-")
        artifact_root.mkdir(parents=True)
        artifact_root.chmod(0o700)
        output_artifacts: list[dict[str, str]] = []

        fixed_inputs = (
            (source_path, "source-conformance.json", MAXIMUM_RESULT_BYTES),
            (source_bundle, "source-attestation.sigstore.json", MAXIMUM_RESULT_BYTES),
            (candidate_path, "candidate-manifest.json", MAXIMUM_RESULT_BYTES),
            (candidate_bundle, "candidate-attestation.sigstore.json", MAXIMUM_RESULT_BYTES),
            (receipt_path, "machine-results-manifest.json", MAXIMUM_RESULT_BYTES),
            (receipt_bundle, "machine-results-attestation.sigstore.json", MAXIMUM_RESULT_BYTES),
        )
        for source, name, maximum in fixed_inputs:
            digest = copy_file(source, artifact_root / name, maximum)
            output_artifacts.append(
                {"path": f"artifacts/{domain.replace('_', '-')}/{name}", "sha256": digest}
            )
        verification_documents = (
            ("source-attestation-verification.json", source_verification),
            ("candidate-attestation-verification.json", candidate_verification),
            ("producer-attestation-verification.json", receipt_verification),
        )
        for name, value in verification_documents:
            destination = artifact_root / name
            write_exclusive(destination, {"verified": value})
            output_artifacts.append(
                {"path": f"artifacts/{domain.replace('_', '-')}/{name}", "sha256": sha256_file(destination)}
            )

        copied: set[str] = set()
        for observation in receipt["observations"]:
            result_source = raw_root / observation["result_path"]
            result_name_out = f"result-{observation['result_path']}"
            result_destination = artifact_root / result_name_out
            result_hash = copy_file(result_source, result_destination, MAXIMUM_RESULT_BYTES)
            if result_hash != observation["result_sha256"]:
                raise EvidenceError("result_changed_during_copy")
            output_artifacts.append(
                {"path": f"artifacts/{domain.replace('_', '-')}/{result_name_out}", "sha256": result_hash}
            )
            for artifact in observation["artifacts"]:
                if artifact["path"] in copied:
                    continue
                copied.add(artifact["path"])
                source = resolve_inside(raw_root, artifact["path"])
                safe_name = artifact["path"].replace("/", "--")
                digest = copy_file(source, artifact_root / safe_name)
                if digest != artifact["sha256"]:
                    raise EvidenceError("artifact_changed_during_copy")
                output_artifacts.append(
                    {"path": f"artifacts/{domain.replace('_', '-')}/{safe_name}", "sha256": digest}
                )

        claims = {
            claim: all(
                observation in {item["id"] for item in receipt["observations"]}
                for observation in requirements
            )
            for claim, requirements in CLAIM_REQUIREMENTS[domain].items()
        }
        if not all(claims.values()):
            raise EvidenceError("required_observation_missing")
        document = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_external_evidence",
            "domain": domain,
            "status": "passed",
            "started_at": format_time(started),
            "finished_at": format_time(finished),
            **identity,
            "claims": claims,
            "artifacts": sorted(output_artifacts, key=lambda item: item["path"]),
        }
        write_exclusive(staging / f"{domain}.json", document)
        if output_root.exists():
            output_root.rmdir()
        os.replace(staging, output_root)
        return document
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    modes = value.add_mutually_exclusive_group(required=True)
    modes.add_argument("--produce", action="store_true")
    modes.add_argument("--finalize", action="store_true")
    value.add_argument("--domain", choices=tuple(CLAIM_REQUIREMENTS), required=True)
    value.add_argument("--source-conformance", type=Path, required=True)
    value.add_argument("--candidate-manifest", type=Path, required=True)
    value.add_argument("--raw-directory", type=Path, required=True)
    value.add_argument("--receipt", type=Path, required=True)
    value.add_argument("--receipt-attestation", type=Path)
    value.add_argument("--source-attestation", type=Path)
    value.add_argument("--candidate-attestation", type=Path)
    value.add_argument("--output-directory", type=Path)
    return value


def main() -> int:
    arguments = parser().parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if arguments.produce:
            if arguments.output_directory is not None or any(
                value is not None
                for value in (arguments.receipt_attestation, arguments.source_attestation, arguments.candidate_attestation)
            ):
                raise EvidenceError("produce_arguments_invalid")
            document = produce(
                domain=arguments.domain,
                source_path=arguments.source_conformance,
                candidate_path=arguments.candidate_manifest,
                raw_root=arguments.raw_directory,
                receipt_path=arguments.receipt,
                now=now,
            )
        else:
            if arguments.output_directory is None:
                raise EvidenceError("output_directory_required")
            try:
                GH_VERSION.installed_version()
            except GH_VERSION.VersionError as error:
                raise EvidenceError(str(error)) from error
            document = finalize(
                domain=arguments.domain,
                source_path=arguments.source_conformance,
                candidate_path=arguments.candidate_manifest,
                raw_root=arguments.raw_directory,
                receipt_path=arguments.receipt,
                receipt_bundle=arguments.receipt_attestation,
                source_bundle=arguments.source_attestation,
                candidate_bundle=arguments.candidate_attestation,
                output_root=arguments.output_directory,
                now=now,
            )
    except (EvidenceError, OSError) as error:
        code = str(error) if isinstance(error, EvidenceError) else "evidence_io_failed"
        print(f"release domain evidence rejected: {code}", file=sys.stderr)
        return 1
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
