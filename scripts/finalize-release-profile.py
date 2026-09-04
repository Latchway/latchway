#!/usr/bin/env python3
"""Finalize the authenticated, explicitly lower-assurance v1 release profile.

The structural evaluator intentionally cannot authenticate its inputs.  This
tool consumes only the closed handoff assembled by the protected workflow,
revalidates the exact profile projection, and emits the profile-wide decision.
It never upgrades that decision to the independent-review or strict release
claims.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
from types import SimpleNamespace
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
PROFILE = "single_maintainer_v1"
TAG = "v1.0.0"
VERSION = "1.0.0"
FINAL_STATUS_CLAIM = "v1_profile_publication_ready_with_deferred_assurance"
POLICY_ID = (
    "latchway-release-profile-v1:latchway:single_maintainer_v1:"
    "release-evidence-signing"
)
EXPECTED_INPUTS: Mapping[str, tuple[str, str]] = {
    "source_report": (
        ".github/workflows/cross-repository-conformance.yml",
        "source/latchway-cross-repository.json",
    ),
    "candidate": (
        ".github/workflows/release.yml",
        "core/latchway-candidate.json",
    ),
    "core_release": (
        ".github/workflows/single-maintainer-release.yml",
        "core/latchway-single-maintainer-v1.json",
    ),
    "public_tags": (
        ".github/workflows/release-domain-evidence.yml",
        "public_tags/public_tags.json",
    ),
    "public_registries": (
        ".github/workflows/release-domain-evidence.yml",
        "public_registries/public_registries.json",
    ),
    "supply_chain": (
        ".github/workflows/release-domain-evidence.yml",
        "supply_chain/supply_chain.json",
    ),
}
MAXIMUM_JSON_BYTES = 8 * 1024 * 1024
REPORT_FIELDS = {
    "checks",
    "contract",
    "documentation",
    "evidence_domains",
    "evidence_window",
    "kind",
    "promotion_ready",
    "release_ready",
    "repositories",
    "schema_version",
    "scope",
    "source_conformance_passed",
    "verdict",
}
DOMAIN_FIELDS = {
    "id",
    "required",
    "status",
    "started_at",
    "finished_at",
    "document_sha256",
    "oci_image_digest",
    "artifact_sha256",
}
STRICT_DOMAIN_STATUS = {
    "local_source": "passed",
    "local_promotion": "failed",
    "local_release": "passed",
    "live_sdk_conformance": "unverified",
    "public_tags": "passed",
    "public_registries": "failed",
    "physical_devices": "unverified",
    "live_provider": "unverified",
    "cloud_deployments": "failed",
    "operational_resilience": "unverified",
    "supply_chain": "passed",
}
STRICT_MISSING_DOMAINS = frozenset(
    (
        "live_sdk_conformance",
        "physical_devices",
        "live_provider",
        "operational_resilience",
    )
)
STRICT_PARTIAL_DOMAINS = frozenset(("public_registries", "cloud_deployments"))
STRICT_PASSED_EXTERNAL_DOMAINS = frozenset(("public_tags", "supply_chain"))
PROFILE_REPORT_NAME = "latchway-single-maintainer-v1-profile-input.json"
STRICT_REPORT_NAME = "latchway-cross-repository-release-strict.json"
PROFILE_EVALUATION_NAME = "latchway-single-maintainer-v1-projection.json"


def load_module(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILE_EVALUATOR = load_module("latchway_profile_finalizer_evaluator", "release-profile.py")
SINGLE = load_module("latchway_profile_finalizer_core", "single-maintainer-release.py")
CROSS = PROFILE_EVALUATOR.CROSS
SOURCE_CHECK_ORDER = tuple(
    identifier
    for identifier in CROSS.CHECK_SUMMARIES
    if identifier.startswith("source.")
)
STRICT_DOMAIN_ORDER = (
    *PROFILE_EVALUATOR.LOCAL_DOMAINS,
    *CROSS.EXTERNAL_DOMAINS,
)
STRICT_CHECK_ORDER = (
    *SOURCE_CHECK_ORDER,
    "promotion.local_preconditions",
    "release.local_preconditions",
    *(f"external.{domain}" for domain in CROSS.EXTERNAL_DOMAINS),
    "promotion.evidence_window",
)


class FinalizationError(Exception):
    """A stable, redaction-safe finalization failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise FinalizationError("json_duplicate_member")
        value[key] = item
    return value


def require_file(path: Path, maximum: int = MAXIMUM_JSON_BYTES) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise FinalizationError("required_file_missing") from None
    if path.is_symlink() or not path.is_file() or not 0 < metadata.st_size <= maximum:
        raise FinalizationError("required_file_unsafe")


def read_json(path: Path) -> dict[str, Any]:
    require_file(path)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except FinalizationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise FinalizationError("json_document_invalid") from None
    if not isinstance(value, dict):
        raise FinalizationError("json_document_invalid")
    return value


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise FinalizationError("output_write_failed") from None


def sha256_file(path: Path, maximum: int = 64 * 1024 * 1024) -> str:
    require_file(path, maximum)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_time(value: Any, code: str) -> datetime:
    try:
        return CROSS.parse_timestamp(value, code)
    except CROSS.VerificationError as error:
        raise FinalizationError(error.code) from None


def require_exact_fields(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise FinalizationError(code)
    return value


def require_real_directory(path: Path, code: str) -> Path:
    if not path.is_absolute():
        raise FinalizationError(code)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise FinalizationError(code) from None
    if path.is_symlink() or not path.is_dir() or not resolved.is_dir():
        raise FinalizationError(code)
    return resolved


def require_bound_file(path: Path, root: Path, relative: str, code: str) -> Path:
    expected = root / PurePosixPath(relative)
    try:
        resolved = path.resolve(strict=True)
        expected_resolved = expected.resolve(strict=True)
    except OSError:
        raise FinalizationError(code) from None
    if resolved != expected_resolved or path.name != PurePosixPath(relative).name:
        raise FinalizationError(code)
    require_file(path)
    return resolved


def index_by_id(values: Any, expected: tuple[str, ...], code: str) -> dict[str, Any]:
    if not isinstance(values, list) or len(values) != len(expected):
        raise FinalizationError(code)
    indexed: dict[str, Any] = {}
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise FinalizationError(code)
        identifier = item["id"]
        if identifier in indexed or identifier not in expected:
            raise FinalizationError(code)
        indexed[identifier] = item
    if set(indexed) != set(expected):
        raise FinalizationError(code)
    return indexed


def validate_source_report(report: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    try:
        CROSS.validate_release_report(report, ROOT / "api/release-evidence.schema.json")
        coordinates = PROFILE_EVALUATOR.release_coordinates(report)
    except (CROSS.VerificationError, PROFILE_EVALUATOR.ProfileError) as error:
        raise FinalizationError(getattr(error, "code", str(error))) from None
    if set(report) != REPORT_FIELDS or (
        report.get("scope") != "source"
        or report.get("verdict") != "passed"
        or report.get("source_conformance_passed") is not True
        or report.get("promotion_ready") is not False
        or report.get("release_ready") is not False
    ):
        raise FinalizationError("source_report_invalid")
    contract = report.get("contract")
    if (
        not isinstance(contract, dict)
        or contract.get("version") != VERSION
        or contract.get("status") != "released"
        or contract.get("core_release") != TAG
        or contract.get("bundle_file_name")
        != f"latchway-contract-{VERSION}.tar.gz"
        or any(
            coordinate["version"] != VERSION or coordinate["tag"] != TAG
            for coordinate in coordinates.values()
        )
    ):
        raise FinalizationError("v1_release_coordinates_invalid")
    domains = PROFILE_EVALUATOR.domain_index(report)
    if set(domains) != set(STRICT_DOMAIN_ORDER):
        raise FinalizationError("source_report_invalid")
    for identifier in STRICT_DOMAIN_ORDER:
        domain = require_exact_fields(
            domains[identifier], DOMAIN_FIELDS, "source_report_invalid"
        )
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
            raise FinalizationError("source_report_invalid")

    checks = index_by_id(
        report.get("checks"), STRICT_CHECK_ORDER, "source_report_checks_invalid"
    )
    for identifier in SOURCE_CHECK_ORDER:
        check = require_exact_fields(
            checks[identifier],
            {"id", "domain", "required", "status", "summary", "details"},
            "source_report_checks_invalid",
        )
        if (
            check["domain"] != "local_source"
            or check["required"] is not True
            or check["status"] != "passed"
            or not isinstance(check["summary"], str)
            or not check["summary"]
            or not isinstance(check["details"], dict)
            or not check["details"]
        ):
            raise FinalizationError("source_report_checks_invalid")
    source_unverified = {
        "promotion.local_preconditions": (
            "local_promotion",
            "promotion_scope_not_requested",
        ),
        "release.local_preconditions": ("local_release", "release_scope_not_requested"),
        "promotion.evidence_window": (
            "local_promotion",
            "promotion_scope_not_requested",
        ),
        **{
            f"external.{domain}": (domain, "external_evidence_not_required_by_scope")
            for domain in CROSS.EXTERNAL_DOMAINS
        },
    }
    for identifier, (domain, reason) in source_unverified.items():
        check = require_exact_fields(
            checks[identifier],
            {"id", "domain", "required", "status", "summary", "reason"},
            "source_report_checks_invalid",
        )
        if (
            check["domain"] != domain
            or check["required"] is not False
            or check["status"] != "unverified"
            or check["reason"] != reason
            or not isinstance(check["summary"], str)
            or not check["summary"]
        ):
            raise FinalizationError("source_report_checks_invalid")
    return coordinates


def safe_relative(value: Any) -> str:
    if not isinstance(value, str):
        raise FinalizationError("authority_input_path_invalid")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise FinalizationError("authority_input_path_invalid")
    return value


def validate_authority(
    manifest: Mapping[str, Any], authenticated_root: Path
) -> tuple[str, dict[str, dict[str, Any]]]:
    if set(manifest) != {
        "schema_version",
        "kind",
        "profile",
        "policy_id",
        "candidate_commit",
        "oci_image_digest",
        "inputs",
    }:
        raise FinalizationError("authority_fields_invalid")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "latchway_single_maintainer_v1_authority"
        or manifest.get("profile") != PROFILE
        or manifest.get("policy_id") != POLICY_ID
    ):
        raise FinalizationError("authority_identity_invalid")
    commit = manifest.get("candidate_commit")
    image = manifest.get("oci_image_digest")
    if (
        not isinstance(commit, str)
        or CROSS.COMMIT.fullmatch(commit) is None
        or not isinstance(image, str)
        or CROSS.OCI_IMAGE_DIGEST.fullmatch(image) is None
    ):
        raise FinalizationError("authority_coordinates_invalid")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != set(EXPECTED_INPUTS):
        raise FinalizationError("authority_inputs_invalid")
    normalized: dict[str, dict[str, Any]] = {}
    root = require_real_directory(
        authenticated_root, "authenticated_root_invalid"
    )
    for identifier, (workflow, expected_path) in EXPECTED_INPUTS.items():
        item = inputs[identifier]
        if not isinstance(item, dict) or set(item) != {
            "workflow_path",
            "run_id",
            "run_attempt",
            "subject_path",
            "sha256",
        }:
            raise FinalizationError("authority_input_fields_invalid")
        relative = safe_relative(item.get("subject_path"))
        run_id = item.get("run_id")
        attempt = item.get("run_attempt")
        digest = item.get("sha256")
        if (
            item.get("workflow_path") != workflow
            or relative != expected_path
            or not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or run_id < 1
            or not isinstance(attempt, int)
            or isinstance(attempt, bool)
            or attempt < 1
            or not isinstance(digest, str)
            or CROSS.SHA256.fullmatch(digest) is None
        ):
            raise FinalizationError("authority_input_invalid")
        path = (root / relative).resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError:
            raise FinalizationError("authority_input_path_invalid") from None
        if sha256_file(path) != digest:
            raise FinalizationError("authority_input_hash_mismatch")
        normalized[identifier] = dict(item)
    return image, normalized


def external_document_details(path: Path) -> dict[str, Any]:
    document = read_json(path)
    artifacts = document.get("artifacts")
    if (
        not isinstance(artifacts, list)
        or not 1 <= len(artifacts) <= 64
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not isinstance(item.get("sha256"), str)
            or CROSS.SHA256.fullmatch(item["sha256"]) is None
            for item in artifacts
        )
    ):
        raise FinalizationError("external_evidence_artifacts_invalid")
    image = document.get("oci_image_digest")
    if not isinstance(image, str) or CROSS.OCI_IMAGE_DIGEST.fullmatch(image) is None:
        raise FinalizationError("external_evidence_oci_digest_invalid")
    return {
        "document_sha256": sha256_file(path),
        "oci_image_digest": image,
        "started_at": document.get("started_at"),
        "finished_at": document.get("finished_at"),
        "artifact_count": len(artifacts),
        "artifact_sha256": sorted(item["sha256"] for item in artifacts),
    }


def expected_external_check(
    domain: str, external_evidence_dir: Path
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": f"external.{domain}",
        "domain": domain,
        "required": True,
        "summary": CROSS.external_summary(domain),
    }
    if domain in STRICT_PASSED_EXTERNAL_DOMAINS:
        return {
            **base,
            "status": "passed",
            "details": external_document_details(
                external_evidence_dir / f"{domain}.json"
            ),
        }
    if domain in STRICT_PARTIAL_DOMAINS:
        return {
            **base,
            "status": "failed",
            "reason": "external_evidence_claims_invalid",
        }
    if domain in STRICT_MISSING_DOMAINS:
        return {
            **base,
            "status": "unverified",
            "reason": "external_evidence_missing",
        }
    raise FinalizationError("strict_release_report_domain_invalid")


def expected_domain(
    identifier: str, external_evidence_dir: Path
) -> dict[str, Any]:
    status_value = STRICT_DOMAIN_STATUS[identifier]
    result: dict[str, Any] = {
        "id": identifier,
        "required": True,
        "status": status_value,
        "started_at": None,
        "finished_at": None,
        "document_sha256": None,
        "oci_image_digest": None,
        "artifact_sha256": [],
    }
    if identifier in STRICT_PASSED_EXTERNAL_DOMAINS:
        details = external_document_details(
            external_evidence_dir / f"{identifier}.json"
        )
        result.update(
            {
                "started_at": details["started_at"],
                "finished_at": details["finished_at"],
                "document_sha256": details["document_sha256"],
                "oci_image_digest": details["oci_image_digest"],
                "artifact_sha256": details["artifact_sha256"],
            }
        )
    return result


def validate_strict_release_report(
    report: Mapping[str, Any],
    source: Mapping[str, Any],
    external_evidence_dir: Path,
    image: str,
) -> None:
    try:
        CROSS.validate_release_report(report, ROOT / "api/release-evidence.schema.json")
    except CROSS.VerificationError as error:
        raise FinalizationError(error.code) from None
    if set(report) != REPORT_FIELDS or (
        report.get("schema_version") != 1
        or report.get("kind")
        != "latchway_cross_repository_conformance_evidence"
        or report.get("scope") != "release"
        or report.get("verdict") != "failed"
        or report.get("source_conformance_passed") is not True
        or report.get("promotion_ready") is not False
        or report.get("release_ready") is not False
        or report.get("evidence_window") is not None
    ):
        raise FinalizationError("strict_release_report_semantics_invalid")
    expected_contract = copy.deepcopy(source.get("contract"))
    if not isinstance(expected_contract, dict):
        raise FinalizationError("source_report_invalid")
    expected_contract["oci_image_digest"] = image
    if (
        report.get("contract") != expected_contract
        or report.get("repositories") != source.get("repositories")
        or report.get("documentation") != source.get("documentation")
    ):
        raise FinalizationError("strict_release_report_source_mismatch")

    domains = report.get("evidence_domains")
    if (
        not isinstance(domains, list)
        or [item.get("id") if isinstance(item, dict) else None for item in domains]
        != list(STRICT_DOMAIN_ORDER)
    ):
        raise FinalizationError("strict_release_report_domains_invalid")
    for item in domains:
        identifier = item["id"]
        require_exact_fields(
            item, DOMAIN_FIELDS, "strict_release_report_domains_invalid"
        )
        if item != expected_domain(identifier, external_evidence_dir):
            raise FinalizationError("strict_release_report_domains_invalid")

    source_checks = index_by_id(
        source.get("checks"), STRICT_CHECK_ORDER, "source_report_checks_invalid"
    )
    intended_tags = {
        item["id"]: item["intended_tag"] for item in source["repositories"]
    }
    expected_checks = [source_checks[identifier] for identifier in SOURCE_CHECK_ORDER]
    expected_checks.extend(
        (
            {
                "id": "promotion.local_preconditions",
                "domain": "local_promotion",
                "required": True,
                "status": "passed",
                "summary": CROSS.CHECK_SUMMARIES["promotion.local_preconditions"],
                "details": {
                    "intended_tags": intended_tags,
                    "contract_released_at": source["contract"]["released_at"],
                    "oci_image_digest": image,
                },
            },
            {
                "id": "release.local_preconditions",
                "domain": "local_release",
                "required": True,
                "status": "passed",
                "summary": CROSS.CHECK_SUMMARIES["release.local_preconditions"],
                "details": {"tags": intended_tags, "annotated_tag_count": 5},
            },
        )
    )
    expected_checks.extend(
        expected_external_check(domain, external_evidence_dir)
        for domain in CROSS.EXTERNAL_DOMAINS
    )
    expected_checks.append(
        {
            "id": "promotion.evidence_window",
            "domain": "local_promotion",
            "required": True,
            "status": "failed",
            "summary": CROSS.CHECK_SUMMARIES["promotion.evidence_window"],
            "reason": "prerequisite_evidence_failed",
        }
    )
    if report.get("checks") != expected_checks:
        raise FinalizationError("strict_release_report_checks_invalid")


def projected_profile_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Derive the evaluator input without changing the strict report.

    The exact strict report proves ``promotion.local_preconditions`` passed but
    keeps ``local_promotion`` failed because its all-domain evidence-window
    prerequisite includes domains this profile explicitly defers.  The narrow
    profile therefore reclassifies only that domain status; the failed window
    check and every strict top-level failure remain intact and authenticated.
    """
    result = copy.deepcopy(report)
    domains = result.get("evidence_domains")
    if not isinstance(domains, list):
        raise FinalizationError("strict_release_report_domains_invalid")
    matched = [item for item in domains if item.get("id") == "local_promotion"]
    if len(matched) != 1 or matched[0].get("status") != "failed":
        raise FinalizationError("strict_release_report_domains_invalid")
    matched[0]["status"] = "passed"
    return result


def derive_profile_report(args: argparse.Namespace) -> dict[str, Any]:
    source = read_json(args.source_report)
    validate_source_report(source)
    report = read_json(args.strict_release_report)
    contract = report.get("contract")
    image = contract.get("oci_image_digest") if isinstance(contract, dict) else None
    if not isinstance(image, str) or CROSS.OCI_IMAGE_DIGEST.fullmatch(image) is None:
        raise FinalizationError("strict_release_report_image_invalid")
    external = require_real_directory(
        args.external_evidence_dir, "external_evidence_directory_invalid"
    )
    validate_strict_release_report(report, source, external, image)
    result = projected_profile_report(report)
    write_json(args.output, result)
    return result


def validate_authenticated_external_inputs(
    authority_inputs: Mapping[str, Mapping[str, Any]],
    authenticated_root: Path,
    external_evidence_dir: Path,
) -> None:
    for domain in ("public_tags", "public_registries", "supply_chain"):
        actual = external_evidence_dir / f"{domain}.json"
        require_file(actual)
        if sha256_file(actual) != authority_inputs[domain]["sha256"]:
            raise FinalizationError("external_evidence_authority_mismatch")

    cloud = read_json(external_evidence_dir / "cloud_deployments.json")
    artifacts = cloud.get("artifacts")
    expected_names = (
        "SHA256SUMS",
        "cloud_run.attestation.json",
        "cloud_run.tar.gz",
        "compose.attestation.json",
        "compose.tar.gz",
        "latchway-single-maintainer-v1.json",
    )
    if (
        not isinstance(artifacts, list)
        or sorted(item.get("path") for item in artifacts if isinstance(item, dict))
        != [f"artifacts/single-maintainer-cloud/{name}" for name in expected_names]
    ):
        raise FinalizationError("cloud_evidence_artifacts_invalid")
    by_path = {item["path"]: item for item in artifacts}
    for name in expected_names:
        relative = f"artifacts/single-maintainer-cloud/{name}"
        item = by_path[relative]
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or item["sha256"] != sha256_file(authenticated_root / "core" / name)
        ):
            raise FinalizationError("cloud_evidence_authority_mismatch")


def validate_authenticated_core_handoff(
    source: Mapping[str, Any],
    authority_inputs: Mapping[str, Mapping[str, Any]],
    authenticated_root: Path,
    image: str,
    now: datetime,
) -> None:
    coordinates = validate_source_report(source)
    core = authenticated_root / "core"
    record = read_json(core / "latchway-single-maintainer-v1.json")
    deployments = record.get("deployment_evidence")
    if not isinstance(deployments, dict):
        raise FinalizationError("core_release_record_invalid")
    try:
        compose = deployments["compose"]
        cloud_run = deployments["cloud_run"]
        if not isinstance(compose, dict) or not isinstance(cloud_run, dict):
            raise TypeError
        verify_args = SimpleNamespace(
            candidate_commit=coordinates["core"]["commit"],
            candidate_run_id=str(authority_inputs["candidate"]["run_id"]),
            candidate_run_attempt=str(authority_inputs["candidate"]["run_attempt"]),
            compose_run_id=str(compose["run_id"]),
            compose_run_attempt=str(compose["run_attempt"]),
            cloud_run_run_id=str(cloud_run["run_id"]),
            cloud_run_run_attempt=str(cloud_run["run_attempt"]),
            handoff_directory=core,
        )
        verified = SINGLE.verify_handoff(verify_args, now)
    except (KeyError, TypeError, SINGLE.ReleaseError) as error:
        raise FinalizationError(
            getattr(error, "code", "core_release_record_invalid")
        ) from None
    candidate = read_json(core / "latchway-candidate.json")
    if (
        verified != record
        or record.get("profile") != PROFILE
        or record.get("tag") != TAG
        or record.get("version") != VERSION
        or record.get("candidate_commit") != coordinates["core"]["commit"]
        or record.get("image", {}).get("coordinate") != image
        or candidate.get("candidate_commit") != coordinates["core"]["commit"]
        or candidate.get("intended_tag") != TAG
        or candidate.get("version") != VERSION
        or candidate.get("contract", {}).get("version") != VERSION
        or candidate.get("contract", {}).get("status") != "released"
    ):
        raise FinalizationError("core_release_record_invalid")


def derive_cloud_evidence(args: argparse.Namespace) -> dict[str, Any]:
    source = read_json(args.source_report)
    coordinates = validate_source_report(source)
    core = args.core_handoff
    record = read_json(core / "latchway-single-maintainer-v1.json")
    candidate_run = record.get("candidate_run")
    deployments = record.get("deployment_evidence")
    if not isinstance(candidate_run, dict) or not isinstance(deployments, dict):
        raise FinalizationError("core_release_record_invalid")
    try:
        verify_args = SimpleNamespace(
            candidate_commit=coordinates["core"]["commit"],
            candidate_run_id=str(candidate_run["run_id"]),
            candidate_run_attempt=str(candidate_run["run_attempt"]),
            compose_run_id=str(deployments["compose"]["run_id"]),
            compose_run_attempt=str(deployments["compose"]["run_attempt"]),
            cloud_run_run_id=str(deployments["cloud_run"]["run_id"]),
            cloud_run_run_attempt=str(deployments["cloud_run"]["run_attempt"]),
            handoff_directory=core,
        )
        verified = SINGLE.verify_handoff(verify_args, args.evaluation_time)
    except (KeyError, TypeError, SINGLE.ReleaseError) as error:
        raise FinalizationError(
            getattr(error, "code", "core_release_record_invalid")
        ) from None
    if verified != record or record.get("profile") != PROFILE:
        raise FinalizationError("core_release_record_invalid")
    image = record.get("image", {}).get("coordinate")
    if not isinstance(image, str) or CROSS.OCI_IMAGE_DIGEST.fullmatch(image) is None:
        raise FinalizationError("core_release_image_invalid")
    candidate = read_json(core / "latchway-candidate.json")
    if (
        candidate.get("candidate_commit") != coordinates["core"]["commit"]
        or image
        != f"{candidate.get('image', {}).get('repository')}@{candidate.get('image', {}).get('index_digest')}"
    ):
        raise FinalizationError("core_release_candidate_mismatch")

    output = args.external_evidence_dir
    if not output.is_absolute() or not output.is_dir() or output.is_symlink():
        raise FinalizationError("external_evidence_directory_invalid")
    document_path = output / "cloud_deployments.json"
    artifact_root = output / "artifacts" / "single-maintainer-cloud"
    if document_path.exists() or artifact_root.exists():
        raise FinalizationError("cloud_evidence_output_exists")
    artifact_root.mkdir(parents=True, mode=0o700)
    copied: list[dict[str, str]] = []
    for name in (
        "latchway-single-maintainer-v1.json",
        "SHA256SUMS",
        "compose.tar.gz",
        "compose.attestation.json",
        "cloud_run.tar.gz",
        "cloud_run.attestation.json",
    ):
        source_path = core / name
        require_file(source_path, 64 * 1024 * 1024)
        destination = artifact_root / name
        shutil.copyfile(source_path, destination)
        destination.chmod(0o600)
        copied.append(
            {
                "path": f"artifacts/single-maintainer-cloud/{name}",
                "sha256": sha256_file(destination),
            }
        )
    times: list[datetime] = []
    for platform in ("compose", "cloud_run"):
        try:
            values, _ = SINGLE.read_archive(core / f"{platform}.tar.gz")
            capture = SINGLE.decode_json_bytes(
                values["manifest.json"], "deployment_manifest_invalid"
            )
        except SINGLE.ReleaseError as error:
            raise FinalizationError(error.code) from None
        times.extend(
            (
                parse_time(capture.get("started_at"), "cloud_evidence_time_invalid"),
                parse_time(capture.get("finished_at"), "cloud_evidence_time_invalid"),
            )
        )
    earliest, latest = min(times), max(times)
    if earliest >= latest or latest > args.evaluation_time:
        raise FinalizationError("cloud_evidence_time_invalid")
    identity = {
        "core_commit": coordinates["core"]["commit"],
        "core_release": coordinates["core"]["tag"],
        "contract_version": candidate["contract"]["version"],
        "bundle_sha256": candidate["contract"]["bundle_sha256"],
        "oci_image_digest": image,
        "repositories": coordinates,
    }
    document = {
        "schema_version": 1,
        "kind": "latchway_cross_repository_external_evidence",
        "domain": "cloud_deployments",
        "status": "passed",
        "started_at": CROSS.format_timestamp(earliest),
        "finished_at": CROSS.format_timestamp(latest),
        **identity,
        "claims": {"compose_verified": True, "cloud_run_verified": True},
        "artifacts": sorted(copied, key=lambda item: item["path"]),
    }
    write_json(document_path, document)
    return document


def finalize_profile(args: argparse.Namespace) -> dict[str, Any]:
    authenticated_root = require_real_directory(
        args.authenticated_root, "authenticated_root_invalid"
    )
    require_bound_file(
        args.authority_manifest,
        authenticated_root,
        "authority.json",
        "authority_manifest_path_invalid",
    )
    authority = read_json(args.authority_manifest)
    image, authority_inputs = validate_authority(authority, authenticated_root)
    source_path = authenticated_root / EXPECTED_INPUTS["source_report"][1]
    source = read_json(source_path)
    validate_source_report(source)
    external_root = require_real_directory(
        args.external_evidence_dir, "external_evidence_directory_invalid"
    )
    validate_authenticated_external_inputs(
        authority_inputs, authenticated_root, external_root
    )
    validate_authenticated_core_handoff(
        source,
        authority_inputs,
        authenticated_root,
        image,
        args.evaluation_time,
    )

    generated_root = args.strict_release_report.parent.resolve(strict=True)
    require_bound_file(
        args.strict_release_report,
        generated_root,
        STRICT_REPORT_NAME,
        "strict_release_report_path_invalid",
    )
    require_bound_file(
        args.profile_release_report,
        generated_root,
        PROFILE_REPORT_NAME,
        "profile_release_report_path_invalid",
    )
    require_bound_file(
        args.profile_evaluation,
        generated_root,
        PROFILE_EVALUATION_NAME,
        "profile_evaluation_path_invalid",
    )
    strict_report = read_json(args.strict_release_report)
    validate_strict_release_report(strict_report, source, external_root, image)
    profile_report = read_json(args.profile_release_report)
    if profile_report != projected_profile_report(strict_report):
        raise FinalizationError("profile_release_report_transformation_invalid")
    try:
        expected = PROFILE_EVALUATOR.evaluate(
            PROFILE,
            args.profile_release_report,
            external_root,
            args.evaluation_time,
        )
    except PROFILE_EVALUATOR.ProfileError as error:
        raise FinalizationError(error.code) from None
    projection = read_json(args.profile_evaluation)
    if projection != expected:
        raise FinalizationError("profile_evaluation_mismatch")
    if (
        projection.get("status") != "passed"
        or projection.get("profile_requirements_satisfied") is not True
        or projection.get("authentication_status") != "not_performed"
        or projection.get("publication_ready") is not False
        or projection.get("strict_cross_repository_ready") is not False
        or projection.get("release_qualified") is not False
        or projection.get("profile") != PROFILE
        or projection.get("candidate", {}).get("oci_image_digest") != image
    ):
        raise FinalizationError("profile_projection_not_eligible")
    domains = PROFILE_EVALUATOR.domain_index(profile_report)
    if (
        profile_report.get("scope") != "release"
        or profile_report.get("verdict") != "failed"
        or profile_report.get("source_conformance_passed") is not True
        or profile_report.get("promotion_ready") is not False
        or profile_report.get("release_ready") is not False
        or profile_report.get("evidence_window") is not None
        or any(
            domains.get(domain, {}).get("status") != "passed"
            for domain in PROFILE_EVALUATOR.LOCAL_DOMAINS
        )
    ):
        raise FinalizationError("release_report_local_domains_invalid")
    forbidden = list(PROFILE_EVALUATOR.SINGLE_MAINTAINER_FORBIDDEN_CLAIMS)
    if projection.get("forbidden_claims") != forbidden:
        raise FinalizationError("forbidden_claims_invalid")
    deferred = projection.get("deferred_evidence")
    if (
        not isinstance(deferred, list)
        or [item.get("id") for item in deferred]
        != list(PROFILE_EVALUATOR.SINGLE_MAINTAINER_DEFERRED)
        or any(
            item.get("status") != "unverified"
            or item.get("reason") != "deferred_by_profile"
            for item in deferred
        )
    ):
        raise FinalizationError("deferred_evidence_invalid")
    core_commit = projection["candidate"]["core_commit"]
    if authority.get("candidate_commit") != core_commit:
        raise FinalizationError("authority_candidate_mismatch")
    input_digests = {
        "authority_manifest": sha256_file(args.authority_manifest),
        "strict_release_report": sha256_file(args.strict_release_report),
        "profile_release_report": sha256_file(args.profile_release_report),
        "profile_evaluation": sha256_file(args.profile_evaluation),
        **{
            f"external_{domain}": sha256_file(
                args.external_evidence_dir / f"{domain}.json"
            )
            for domain in PROFILE_EVALUATOR.SINGLE_MAINTAINER_REQUIRED_CLAIMS
        },
    }
    return {
        "schema_version": 1,
        "kind": "latchway_authenticated_release_profile",
        "evaluation_scope": "cross_repository_publication_profile",
        "profile": PROFILE,
        "status": "passed",
        "status_claim": FINAL_STATUS_CLAIM,
        "profile_requirements_satisfied": True,
        "authentication_status": "passed",
        "publication_ready": True,
        "strict_cross_repository_ready": False,
        "release_qualified": False,
        "fully_evidence_gated": False,
        "independently_reviewed": False,
        "requires_independent_human_review": False,
        "candidate": projection["candidate"],
        "required_gates": projection["required_gates"],
        "deferred_evidence": deferred,
        "forbidden_claims": forbidden,
        "authority": {
            "policy_id": POLICY_ID,
            "inputs": authority_inputs,
        },
        "input_digests": input_digests,
    }


def evaluation_time(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    return parse_time(value, "evaluation_time_invalid")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    derive = commands.add_parser(
        "derive-cloud-evidence",
        help="derive the profile cloud domain from the authenticated core handoff",
    )
    derive.add_argument("--source-report", type=Path, required=True)
    derive.add_argument("--core-handoff", type=Path, required=True)
    derive.add_argument("--external-evidence-dir", type=Path, required=True)
    derive.add_argument("--evaluation-time")
    project = commands.add_parser(
        "derive-profile-report",
        help="derive the exact profile-local input while retaining the failed strict report",
    )
    project.add_argument("--strict-release-report", type=Path, required=True)
    project.add_argument("--source-report", type=Path, required=True)
    project.add_argument("--external-evidence-dir", type=Path, required=True)
    project.add_argument("--output", type=Path, required=True)
    final = commands.add_parser(
        "finalize", help="issue the authenticated profile-wide decision"
    )
    final.add_argument("--authority-manifest", type=Path, required=True)
    final.add_argument("--authenticated-root", type=Path, required=True)
    final.add_argument("--strict-release-report", type=Path, required=True)
    final.add_argument("--profile-release-report", type=Path, required=True)
    final.add_argument("--external-evidence-dir", type=Path, required=True)
    final.add_argument("--profile-evaluation", type=Path, required=True)
    final.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    if arguments.command == "derive-cloud-evidence":
        arguments.evaluation_time = evaluation_time(arguments.evaluation_time)
    elif arguments.command == "finalize":
        # Authenticated readiness is always evaluated against the current clock.
        # A caller-provided historical time could otherwise make stale evidence
        # appear eligible outside the fresh no-checkout workflow signer.
        arguments.evaluation_time = evaluation_time(None)
    try:
        if arguments.command == "derive-cloud-evidence":
            result = derive_cloud_evidence(arguments)
        elif arguments.command == "derive-profile-report":
            result = derive_profile_report(arguments)
        else:
            result = finalize_profile(arguments)
            write_json(arguments.output, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (FinalizationError, OSError) as error:
        code = error.code if isinstance(error, FinalizationError) else "profile_io_failed"
        print(f"release profile finalization failed: {code}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
