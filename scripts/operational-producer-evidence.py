#!/usr/bin/env python3
"""Seal and revalidate exact-candidate load and destructive-failure producers.

The manifest is intentionally not a replacement for the underlying load or
failure reports. Those reports are independently revalidated by the
operational-resilience finalizer. This layer binds every input and raw file to
one fixed protected workflow invocation so a similarly named artifact from an
unrelated workflow cannot be substituted.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Mapping


COMMON_PATH = Path(__file__).with_name("operational-resilience-evidence.py")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
MAXIMUM_JSON_BYTES = 2 * 1024 * 1024
MAXIMUM_FILE_BYTES = 100 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 512 * 1024 * 1024
MAXIMUM_FILES = 128
REPOSITORY = "Latchway/latchway"
PRODUCERS: Mapping[str, Mapping[str, str]] = {
    "load": {
        "workflow": ".github/workflows/release-load-evidence.yml",
        "environment": "release-load-evidence",
        "runner_environment": "github-hosted",
        "manifest": "load-producer.json",
    },
    "failure": {
        "workflow": ".github/workflows/release-failure-evidence.yml",
        "environment": "release-failure-evidence",
        "runner_environment": "self-hosted",
        "manifest": "failure-producer.json",
    },
}


class EvidenceError(Exception):
    """A stable, non-sensitive producer-evidence error."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("producer_json_duplicate_key")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    if not regular_file(path) or path.stat().st_size > MAXIMUM_JSON_BYTES:
        raise EvidenceError("producer_input_invalid")
    try:
        result = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EvidenceError("producer_json_invalid") from None
    if not isinstance(result, dict):
        raise EvidenceError("producer_json_invalid")
    return result


def regular_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and 0 < metadata.st_size <= MAXIMUM_FILE_BYTES
    )


def sha256_file(path: Path) -> str:
    if not regular_file(path):
        raise EvidenceError("producer_artifact_invalid")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
    ):
        return False
    path = PurePosixPath(value)
    return path.as_posix() == value and not any(
        part in ("", ".", "..") for part in path.parts
    )


def resolve_inside(root: Path, relative: str) -> Path:
    if not safe_relative(relative):
        raise EvidenceError("producer_artifact_path_invalid")
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate /= part
        try:
            if stat.S_ISLNK(candidate.lstat().st_mode):
                raise EvidenceError("producer_artifact_path_invalid")
        except FileNotFoundError:
            raise EvidenceError("producer_artifact_missing") from None
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise EvidenceError("producer_artifact_path_invalid") from None
    return candidate


def artifact_index(root: Path, *, exclude: set[str] | None = None) -> list[dict[str, str]]:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise EvidenceError("producer_artifact_root_invalid")
    excluded = exclude or set()
    indexed: list[dict[str, str]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        if not safe_relative(relative) or not regular_file(path):
            raise EvidenceError("producer_artifact_invalid")
        total_bytes += path.stat().st_size
        if total_bytes > MAXIMUM_TOTAL_BYTES:
            raise EvidenceError("producer_artifact_set_invalid")
        indexed.append({"path": relative, "sha256": sha256_file(path)})
    if not indexed or len(indexed) > MAXIMUM_FILES:
        raise EvidenceError("producer_artifact_set_invalid")
    return indexed


def load_common() -> Any:
    spec = importlib.util.spec_from_file_location("operational_resilience_common", COMMON_PATH)
    if spec is None or spec.loader is None:
        raise EvidenceError("producer_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixed_invocation(
    domain: str, commit: str, image: str, platform_image: str
) -> dict[str, Any]:
    if domain == "load":
        command = [
            "scripts/run-local-load-gates.sh",
            "-acknowledge-load",
            "-evidence-dir",
            "$EVIDENCE_DIRECTORY",
            "-release-image",
            image,
            "-release-platform-image",
            platform_image,
            "-core-commit",
            commit,
        ]
        configuration = ("load-config.json", "environment.json")
    elif domain == "failure":
        command = [
            "scripts/run-failure-gates.sh",
            "-scope",
            "release",
            "-external-evidence-dir",
            "$EVIDENCE_DIRECTORY/live-failures",
            "-output",
            "$EVIDENCE_DIRECTORY/failure-release.json",
        ]
        configuration = ("failure-matrix.json", "failure-environment.json")
    else:
        raise EvidenceError("producer_domain_invalid")
    return {"command": command, "configuration_paths": list(configuration)}


def github_context_from_environment(domain: str) -> dict[str, Any]:
    expected = PRODUCERS.get(domain)
    if expected is None:
        raise EvidenceError("producer_domain_invalid")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if RUN_ID.fullmatch(run_attempt) is None:
        raise EvidenceError("producer_context_invalid")
    context = {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "source_commit": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": int(run_attempt),
        "environment": os.environ.get("LATCHWAY_RELEASE_EVIDENCE_ENVIRONMENT", ""),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT", ""),
        "runner_os": os.environ.get("RUNNER_OS", ""),
        "runner_arch": os.environ.get("RUNNER_ARCH", ""),
        "runner_name_sha256": hashlib.sha256(
            os.environ.get("RUNNER_NAME", "").encode("utf-8")
        ).hexdigest(),
    }
    validate_context(domain, context)
    return context


def validate_context(domain: str, context: Any) -> dict[str, Any]:
    expected = PRODUCERS.get(domain)
    fields = {
        "repository",
        "workflow_ref",
        "source_commit",
        "run_id",
        "run_attempt",
        "environment",
        "runner_environment",
        "runner_os",
        "runner_arch",
        "runner_name_sha256",
    }
    if expected is None or not isinstance(context, dict) or set(context) != fields:
        raise EvidenceError("producer_context_invalid")
    workflow_ref = f"{REPOSITORY}/{expected['workflow']}@refs/heads/main"
    if (
        context["repository"] != REPOSITORY
        or context["workflow_ref"] != workflow_ref
        or not isinstance(context["source_commit"], str)
        or COMMIT.fullmatch(context["source_commit"]) is None
        or not isinstance(context["run_id"], str)
        or RUN_ID.fullmatch(str(context["run_id"])) is None
        or not isinstance(context["run_attempt"], int)
        or isinstance(context["run_attempt"], bool)
        or RUN_ID.fullmatch(str(context["run_attempt"])) is None
        or context["environment"] != expected["environment"]
        or context["runner_environment"] != expected["runner_environment"]
        or context["runner_os"] != "Linux"
        or context["runner_arch"] != "X64"
        or not isinstance(context["runner_name_sha256"], str)
        or SHA256.fullmatch(context["runner_name_sha256"]) is None
        or context["runner_name_sha256"] == hashlib.sha256(b"").hexdigest()
    ):
        raise EvidenceError("producer_context_invalid")
    return {
        **context,
        "run_id": str(context["run_id"]),
        "run_attempt": int(context["run_attempt"]),
    }


def identity(
    common: Any, source_path: Path, candidate_path: Path, now: datetime
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    try:
        source = common.validate_source(source_path, now)
        candidate, image, _ = common.validate_candidate(candidate_path, source, now)
    except common.EvidenceError as error:
        raise EvidenceError(str(error)) from None
    platform_image = (
        candidate["image"]["repository"]
        + "@"
        + candidate["image"]["platforms"]["linux/amd64"]
    )
    return source, candidate, image, platform_image


def produce(
    *,
    domain: str,
    source_path: Path,
    candidate_path: Path,
    evidence_root: Path,
    report_path: Path,
    output_path: Path,
    context: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    common = load_common()
    source, candidate, image, platform_image = identity(
        common, source_path, candidate_path, now
    )
    commit = source["repositories"]["core"]["commit"]
    released_at = source["released_at"]
    if domain == "load":
        interval = common.validate_load(
            report_path,
            commit=commit,
            image=image,
            platform_image=platform_image,
            released_at=released_at,
            now=now,
        )
    elif domain == "failure":
        intervals, _ = common.validate_failure(
            report_path,
            evidence_root / "live-failures",
            commit=commit,
            image=image,
            platform_image=platform_image,
            released_at=released_at,
            now=now,
        )
        interval = (
            min(started for started, _ in intervals),
            max(finished for _, finished in intervals),
        )
    else:
        raise EvidenceError("producer_domain_invalid")
    expected_name = PRODUCERS[domain]["manifest"]
    expected_report = "load-v1.json" if domain == "load" else "failure-release.json"
    if (
        output_path.parent != evidence_root
        or output_path.name != expected_name
        or output_path.exists()
        or output_path.is_symlink()
        or report_path != evidence_root / expected_report
    ):
        raise EvidenceError("producer_output_invalid")
    artifacts = artifact_index(evidence_root, exclude={expected_name})
    paths = {item["path"] for item in artifacts}
    report_relative = report_path.relative_to(evidence_root).as_posix()
    invocation = fixed_invocation(domain, commit, image, platform_image)
    if report_relative not in paths or any(
        path not in paths for path in invocation["configuration_paths"]
    ):
        raise EvidenceError("producer_required_artifact_missing")
    configuration = [
        {"path": path, "sha256": sha256_file(resolve_inside(evidence_root, path))}
        for path in invocation.pop("configuration_paths")
    ]
    contract = source["contract"]
    document = {
        "schema_version": 1,
        "kind": "latchway_release_operational_producer_manifest",
        "domain": domain,
        "status": "passed",
        "started_at": common.format_time(interval[0]),
        "finished_at": common.format_time(interval[1]),
        "candidate": {
            "core_commit": commit,
            "intended_tag": candidate["intended_tag"],
            "contract_version": contract["version"],
            "contract_bundle_sha256": contract["bundle_sha256"],
            "oci_index_reference": image,
            "platform": "linux/amd64",
            "oci_platform_reference": platform_image,
        },
        "inputs": {
            "source_conformance_sha256": sha256_file(source_path),
            "candidate_manifest_sha256": sha256_file(candidate_path),
        },
        "producer": validate_context(domain, dict(context)),
        "invocation": {"command": invocation["command"], "configuration": configuration},
        "primary_report": {
            "path": report_relative,
            "sha256": sha256_file(report_path),
        },
        "artifacts": artifacts,
    }
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    output_path.chmod(0o600)
    return document


def validate_manifest(
    *,
    path: Path,
    domain: str,
    source_path: Path,
    candidate_path: Path,
    evidence_root: Path,
    commit: str,
    intended_tag: str,
    contract_version: str,
    contract_bundle_sha256: str,
    image: str,
    platform_image: str,
    expected_run_id: str,
) -> dict[str, Any]:
    expected_manifest = PRODUCERS.get(domain, {}).get("manifest")
    if (
        expected_manifest is None
        or not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or path.parent != evidence_root
        or path.name != expected_manifest
    ):
        raise EvidenceError("producer_manifest_invalid")
    value = read_json(path)
    expected_fields = {
        "schema_version",
        "kind",
        "domain",
        "status",
        "started_at",
        "finished_at",
        "candidate",
        "inputs",
        "producer",
        "invocation",
        "primary_report",
        "artifacts",
    }
    if (
        set(value) != expected_fields
        or value.get("schema_version") != 1
        or value.get("kind") != "latchway_release_operational_producer_manifest"
        or value.get("domain") != domain
        or value.get("status") != "passed"
    ):
        raise EvidenceError("producer_manifest_invalid")
    candidate = value["candidate"]
    if not isinstance(candidate, dict) or candidate != {
        "core_commit": commit,
        "intended_tag": intended_tag,
        "contract_version": contract_version,
        "contract_bundle_sha256": contract_bundle_sha256,
        "oci_index_reference": image,
        "platform": "linux/amd64",
        "oci_platform_reference": platform_image,
    }:
        raise EvidenceError("producer_candidate_mismatch")
    inputs = value["inputs"]
    if not isinstance(inputs, dict) or inputs != {
        "source_conformance_sha256": sha256_file(source_path),
        "candidate_manifest_sha256": sha256_file(candidate_path),
    }:
        raise EvidenceError("producer_input_mismatch")
    context = validate_context(domain, value["producer"])
    if context["source_commit"] != commit:
        raise EvidenceError("producer_source_mismatch")
    if (
        not isinstance(expected_run_id, str)
        or RUN_ID.fullmatch(expected_run_id) is None
        or context["run_id"] != expected_run_id
    ):
        raise EvidenceError("producer_run_mismatch")
    fixed = fixed_invocation(domain, commit, image, platform_image)
    invocation = value["invocation"]
    if (
        not isinstance(invocation, dict)
        or set(invocation) != {"command", "configuration"}
        or invocation["command"] != fixed["command"]
    ):
        raise EvidenceError("producer_invocation_mismatch")
    artifacts = value["artifacts"]
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or len(artifacts) > MAXIMUM_FILES
    ):
        raise EvidenceError("producer_artifact_set_invalid")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise EvidenceError("producer_artifact_set_invalid")
        relative, digest = item["path"], item["sha256"]
        if (
            not safe_relative(relative)
            or relative in seen
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise EvidenceError("producer_artifact_set_invalid")
        seen.add(relative)
        actual = sha256_file(resolve_inside(evidence_root, relative))
        if actual != digest:
            raise EvidenceError("producer_artifact_hash_mismatch")
        normalized.append({"path": relative, "sha256": actual})
    actual_index = artifact_index(
        evidence_root,
        exclude={path.name, f"{domain}-producer.attestation.sigstore.json"},
    )
    if normalized != actual_index:
        raise EvidenceError("producer_artifact_set_mismatch")
    configuration = invocation["configuration"]
    if not isinstance(configuration, list) or [
        item.get("path") if isinstance(item, dict) else None
        for item in configuration
    ] != fixed["configuration_paths"]:
        raise EvidenceError("producer_configuration_mismatch")
    for item in configuration:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or item not in normalized
        ):
            raise EvidenceError("producer_configuration_mismatch")
    primary = value["primary_report"]
    expected_report = "load-v1.json" if domain == "load" else "failure-release.json"
    if not isinstance(primary, dict) or primary != {
        "path": expected_report,
        "sha256": sha256_file(resolve_inside(evidence_root, expected_report)),
    } or primary not in normalized:
        raise EvidenceError("producer_primary_report_mismatch")
    return value


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", choices=sorted(PRODUCERS), required=True)
    parser.add_argument("--source-conformance", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    values = arguments()
    try:
        produce(
            domain=values.domain,
            source_path=values.source_conformance.resolve(),
            candidate_path=values.candidate_manifest.resolve(),
            evidence_root=values.evidence_directory.resolve(),
            report_path=values.report.resolve(),
            output_path=values.output.resolve(),
            context=github_context_from_environment(values.domain),
            now=datetime.now(timezone.utc),
        )
    except (EvidenceError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
