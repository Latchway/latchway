#!/usr/bin/env python3
"""Render the immutable, post-publication Latchway release record.

The renderer is deliberately offline. Network observations are captured by the
protected finalizer workflow in ``latchway_public_release_state`` and the
public registry/tag proofs are carried by the attested release-scope
cross-repository report. This command rejects partial, ambiguous, or
coordinate-mismatched inputs before writing deterministic Markdown.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
from typing import Any, Mapping


COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$")
ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEMVER = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
TAG = re.compile(r"^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
EVIDENCE_TAG = re.compile(
    r"^evidence/v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$"
)
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MIGRATION = re.compile(r"^(\d{6})_[a-z0-9_]+\.sql$")
MAXIMUM_INPUT_BYTES = 32 * 1024 * 1024
MAXIMUM_DURABLE_FILE_BYTES = 1024 * 1024 * 1024
MAXIMUM_DURABLE_FILES = 8192
REPOSITORY_IDS = ("core", "javascript", "ios", "android", "react_native")
EXTERNAL_DOMAINS = (
    "live_sdk_conformance",
    "physical_devices",
    "live_provider",
    "cloud_deployments",
    "operational_resilience",
    "supply_chain",
    "public_tags",
    "public_registries",
)
LOCAL_DOMAINS = ("local_source", "local_promotion", "local_release")
ANDROID_MODULES = (
    "latchway-core",
    "latchway-okhttp",
    "latchway-play-integrity",
    "latchway-firebase-auth",
    "latchway-bom",
)
REQUIRED_CONFORMANCE_CHECKS = {
    "source.repository_layout": "local_source",
    "source.clean_worktrees": "local_source",
    "source.core_contract": "local_source",
    "source.contract_bundle": "local_source",
    "source.contract_locks": "local_source",
    "source.generated_fixtures": "local_source",
    "source.package_versions": "local_source",
    "source.react_native_pins": "local_source",
    "promotion.local_preconditions": "local_promotion",
    "release.local_preconditions": "local_release",
    **{f"external.{domain}": domain for domain in EXTERNAL_DOMAINS},
    "promotion.evidence_window": "local_promotion",
}
REQUIRED_SECURITY_CHECKS = frozenset(
    {
        "source_go_vulnerability",
        "source_static_analysis",
        "source_fuzz_smoke",
        "source_race",
        "source_vulnerability_secret_misconfiguration",
        "source_license",
        "image_amd64_vulnerability",
        "image_arm64_vulnerability",
        "image_amd64_license",
        "image_arm64_license",
    }
)
REQUIRED_EXTERNAL_CLAIMS = {
    "live_sdk_conformance": frozenset(
        {
            "javascript_against_release_image",
            "ios_against_release_image",
            "android_against_release_image",
            "react_native_ios_against_release_image",
            "react_native_android_against_release_image",
            "dpop_vectors",
            "error_mapping",
            "session_refresh",
            "installation_revocation",
            "streaming",
            "quota_snapshots",
            "protocol_version_rejection",
        }
    ),
    "physical_devices": frozenset(
        {
            "app_attest_production_verified",
            "play_integrity_play_distributed_verified",
            "react_native_ios_verified",
            "react_native_android_verified",
        }
    ),
    "live_provider": frozenset(
        {
            "openrouter_nonstreaming_verified",
            "openrouter_streaming_verified",
            "usage_verified",
            "output_clamp_verified",
            "error_normalization_verified",
        }
    ),
    "cloud_deployments": frozenset(
        {
            "compose_verified",
            "cloud_run_verified",
            "aws_verified",
            "fly_io_verified",
            "cloudflare_containers_verified",
        }
    ),
    "operational_resilience": frozenset(
        {
            "v1_load_targets_verified",
            "live_failure_injection_verified",
            "multi_replica_verified",
            "backup_restore_drill_verified",
            "previous_candidate_upgrade_rollback_verified",
        }
    ),
    "supply_chain": frozenset(
        {
            "multi_arch_image_verified",
            "vulnerability_scan_verified",
            "license_scan_verified",
            "sbom_verified",
            "signature_verified",
            "provenance_verified",
        }
    ),
    "public_tags": frozenset(
        {"remote_annotated_tags_verified", "github_releases_verified"}
    ),
    "public_registries": frozenset(
        {
            "oci_digest_verified",
            "npm_javascript_verified",
            "npm_react_native_verified",
            "swift_package_verified",
            "cocoapods_verified",
            "maven_central_verified",
        }
    ),
}
PHYSICAL_OBSERVATIONS = {
    "sdk.ios.release-image": ("app-attest-profile.json", "app-attest-evidence.json"),
    "sdk.android.release-image": (
        "play-integrity-profile.json",
        "play-integrity-evidence.json",
    ),
    "sdk.react-native-ios.release-image": (
        "react-native-ios-profile.json",
        "react-native-ios-evidence.json",
    ),
    "sdk.react-native-android.release-image": (
        "react-native-android-profile.json",
        "react-native-android-evidence.json",
    ),
}
REMAINING_WORK_CATEGORIES = frozenset(
    {"post_1_0_enhancement", "documented_non_goal", "low_severity_accepted_risk"}
)
CORE_PRODUCT_RELEASE_ASSETS = frozenset(
    {
        "latchway-cross-repository-promotion.json",
        "latchway-cross-repository-promotion.attestation.sigstore.json",
        "latchway-candidate.json",
        "latchway-candidate.attestation.sigstore.json",
        "latchway-contract.tar.gz",
        "latchway-linux-amd64.spdx.json",
        "latchway-linux-arm64.spdx.json",
        "latchway-linux-amd64-vulnerability.json",
        "latchway-linux-arm64-vulnerability.json",
        "latchway-linux-amd64-license.json",
        "latchway-linux-arm64-license.json",
        "security-summary.json",
        "security-summary.attestation.sigstore.json",
        "oci-alias-promotion.json",
    }
)
CANONICAL_SECURITY_STATEMENT: Mapping[str, Any] = {
    "known_accepted_risks": [
        "Web App Check and Turnstile verdicts are intentionally treated as lower-trust risk signals than native hardware-backed attestation.",
        "An upstream provider can retain request content under its own account policy after Latchway dispatches an authorized request.",
    ],
    "prompt_logging_defaults": "Prompt and response body logging is disabled. Normal request, usage, audit, and telemetry records exclude prompt bodies, provider credentials, identity tokens, attestation evidence, and DPoP proofs.",
    "secret_storage_behavior": "Committed and activated configuration stores bounded secret references, never plaintext upstream or identity-provider credentials. Runtime secret values are resolved only by the configured secret provider and are redacted from Admin responses, logs, audit records, and release evidence.",
    "key_rotation_behavior": "The worker rotates gateway signing keys with an overlap window, keeps previously issued sessions verifiable through the retained public keys, audits rotation, and supports operator-triggered rotation and retirement.",
    "attestation_limitations": "Production App Attest and Play Integrity prove the configured application and device verdicts for a bound challenge; they do not prove a human identity, and availability remains subject to the platform provider and eligible hardware.",
    "web_threat_model_limitations": "Web clients cannot provide Secure Enclave or StrongBox-equivalent identity. Firebase App Check and Turnstile are combined with identity, DPoP, origin/action/hostname binding, replay controls, rate limits, and server-owned policy rather than treated as native device proof.",
}


class ReportError(Exception):
    """A stable, secret-safe validation failure."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("release_record_json_duplicate_key")
        result[key] = value
    return result


def reject_nonfinite(_: str) -> Any:
    raise ReportError("release_record_json_nonfinite_number")


def read_bytes(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError:
        raise ReportError("release_record_input_missing") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > MAXIMUM_INPUT_BYTES
    ):
        raise ReportError("release_record_input_invalid")
    try:
        return path.read_bytes()
    except OSError:
        raise ReportError("release_record_input_invalid") from None


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            read_bytes(path).decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except ReportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReportError("release_record_json_invalid") from None
    if not isinstance(value, dict):
        raise ReportError("release_record_json_invalid")
    return value


def require_fields(value: Mapping[str, Any], fields: set[str], code: str) -> None:
    if set(value) != fields:
        raise ReportError(code)


def require_string(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReportError(code)
    return value


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise ReportError(code)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ReportError(code) from None
    return parsed.replace(tzinfo=timezone.utc)


def sha256_file(
    path: Path,
    *,
    maximum: int = MAXIMUM_INPUT_BYTES,
    allow_empty: bool = False,
) -> str:
    try:
        metadata = path.lstat()
    except OSError:
        raise ReportError("release_record_input_missing") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size > maximum
        or (metadata.st_size < 1 and not allow_empty)
    ):
        raise ReportError("release_record_input_invalid")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise ReportError("release_record_input_invalid") from None
    return digest.hexdigest()


def bounded_text(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or "\n" in value
        or "\r" in value
        or any(ord(character) < 32 and character != "\t" for character in value)
    ):
        raise ReportError(code)
    return value


def safe_relative(value: Any, code: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise ReportError(code)
    result = PurePosixPath(value)
    if result.as_posix() != value or any(part in ("", ".", "..") for part in result.parts):
        raise ReportError(code)
    return result


def resolve_regular(root: Path, relative: PurePosixPath, code: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        path = (resolved_root / Path(*relative.parts)).resolve(strict=True)
        path.relative_to(resolved_root)
        metadata = path.lstat()
    except (OSError, ValueError):
        raise ReportError(code) from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReportError(code)
    return path


def regular_tree(root: Path, code: str) -> dict[str, Path]:
    try:
        metadata = root.lstat()
    except OSError:
        raise ReportError(code) from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReportError(code)
    result: dict[str, Path] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            raise ReportError(code) from None
        for child in children:
            try:
                child_metadata = child.lstat()
            except OSError:
                raise ReportError(code) from None
            if stat.S_ISLNK(child_metadata.st_mode):
                raise ReportError(code)
            if stat.S_ISDIR(child_metadata.st_mode):
                pending.append(child)
                continue
            if not stat.S_ISREG(child_metadata.st_mode):
                raise ReportError(code)
            relative = child.relative_to(root).as_posix()
            safe_relative(relative, code)
            result[relative] = child
            if len(result) > MAXIMUM_DURABLE_FILES:
                raise ReportError(code)
    return result


def validate_report_metadata(
    repository: Path, derived_platforms: Mapping[str, str] | None = None
) -> Mapping[str, Any]:
    metadata = read_json(repository / "docs/release/final-report-metadata.json")
    require_fields(
        metadata,
        {"schema_version", "kind", "compatibility", "security_statement", "remaining_work"},
        "release_record_metadata_fields_invalid",
    )
    if metadata.get("schema_version") != 1 or metadata.get("kind") != "latchway_v1_final_report_metadata":
        raise ReportError("release_record_metadata_invalid")
    compatibility = metadata.get("compatibility")
    if not isinstance(compatibility, dict) or set(compatibility) != {"minimum_platform_versions"}:
        raise ReportError("release_record_compatibility_metadata_invalid")
    platforms = compatibility["minimum_platform_versions"]
    expected_platforms = {"ios_sdk", "android_sdk", "javascript_sdk", "react_native_sdk"}
    if not isinstance(platforms, dict) or set(platforms) != expected_platforms:
        raise ReportError("release_record_compatibility_metadata_invalid")
    for value in platforms.values():
        bounded_text(value, "release_record_compatibility_metadata_invalid")
    if derived_platforms is not None and platforms != derived_platforms:
        raise ReportError("release_record_compatibility_metadata_mismatch")
    security = metadata.get("security_statement")
    expected_security = {
        "known_accepted_risks",
        "prompt_logging_defaults",
        "secret_storage_behavior",
        "key_rotation_behavior",
        "attestation_limitations",
        "web_threat_model_limitations",
    }
    if not isinstance(security, dict) or set(security) != expected_security:
        raise ReportError("release_record_security_metadata_invalid")
    if security != CANONICAL_SECURITY_STATEMENT:
        raise ReportError("release_record_security_metadata_mismatch")
    risks = security["known_accepted_risks"]
    if not isinstance(risks, list) or not 1 <= len(risks) <= 8 or len(set(risks)) != len(risks):
        raise ReportError("release_record_security_metadata_invalid")
    for value in risks:
        bounded_text(value, "release_record_security_metadata_invalid")
    for key in expected_security - {"known_accepted_risks"}:
        bounded_text(security[key], "release_record_security_metadata_invalid")
    remaining = metadata.get("remaining_work")
    if not isinstance(remaining, list) or not 1 <= len(remaining) <= 16:
        raise ReportError("release_record_remaining_work_invalid")
    seen_categories: set[str] = set()
    forbidden = re.compile(r"(?i)\b(?:unfinished|incomplete|todo|pending|blocker|missing|not implemented)\b")
    for item in remaining:
        if not isinstance(item, dict) or set(item) != {"category", "description"}:
            raise ReportError("release_record_remaining_work_invalid")
        category = item.get("category")
        description = bounded_text(item.get("description"), "release_record_remaining_work_invalid")
        if category not in REMAINING_WORK_CATEGORIES or category in seen_categories or forbidden.search(description):
            raise ReportError("release_record_remaining_work_invalid")
        seen_categories.add(category)
    if seen_categories != REMAINING_WORK_CATEGORIES:
        raise ReportError("release_record_remaining_work_invalid")
    return metadata


def validate_physical_receipts(external: Path) -> int:
    domain = read_json(external / "physical_devices.json")
    artifact_entries = domain.get("artifacts")
    if not isinstance(artifact_entries, list):
        raise ReportError("release_record_physical_receipts_invalid")
    by_path = {
        item.get("path"): item
        for item in artifact_entries
        if isinstance(item, dict) and set(item) == {"path", "sha256"}
    }
    if len(by_path) != len(artifact_entries):
        raise ReportError("release_record_physical_receipts_invalid")
    retained_count = 0
    for observation, required_names in PHYSICAL_OBSERVATIONS.items():
        slug = observation.replace(".", "-")
        result_relative = f"artifacts/physical-devices/result-{slug}.json"
        summary_relative = (
            f"artifacts/physical-devices/artifacts--{slug}--tool-output.json"
        )
        receipt_relative = (
            f"artifacts/physical-devices/artifacts--{slug}--physical-receipt.json"
        )
        for relative in (result_relative, summary_relative, receipt_relative):
            if relative not in by_path:
                raise ReportError("release_record_physical_receipts_missing")
            path = resolve_regular(
                external,
                safe_relative(relative, "release_record_physical_receipts_invalid"),
                "release_record_physical_receipts_invalid",
            )
            if sha256_file(path) != by_path[relative].get("sha256"):
                raise ReportError("release_record_physical_receipts_hash_mismatch")
        result = read_json(external / result_relative)
        expected_original = f"artifacts/{slug}/physical-receipt.json"
        result_artifacts = result.get("artifacts")
        if (
            result.get("observation") != observation
            or not isinstance(result_artifacts, list)
            or len(
                [
                    item
                    for item in result_artifacts
                    if isinstance(item, dict)
                    and item.get("path") == expected_original
                    and item.get("sha256") == by_path[receipt_relative]["sha256"]
                ]
            )
            != 1
        ):
            raise ReportError("release_record_physical_receipts_invalid")
        summary = read_json(external / summary_relative)
        hashes = summary.get("receipt_sha256")
        receipt = read_json(external / receipt_relative)
        files = receipt.get("files")
        if (
            receipt.get("schema_version") != 1
            or receipt.get("kind") != "latchway_retained_physical_device_receipt"
            or receipt.get("observation") != observation
            or not isinstance(files, list)
            or not 4 <= len(files) <= 64
            or not isinstance(hashes, dict)
        ):
            raise ReportError("release_record_physical_receipts_invalid")
        decoded_hashes: dict[str, str] = {}
        for item in files:
            if not isinstance(item, dict) or set(item) != {"name", "sha256", "content_base64"}:
                raise ReportError("release_record_physical_receipts_invalid")
            name = item.get("name")
            expected = item.get("sha256")
            if (
                not isinstance(name, str)
                or ASSET_NAME.fullmatch(name) is None
                or name in decoded_hashes
                or not isinstance(expected, str)
                or SHA256.fullmatch(expected) is None
                or not isinstance(item.get("content_base64"), str)
            ):
                raise ReportError("release_record_physical_receipts_invalid")
            try:
                payload = base64.b64decode(item["content_base64"], validate=True)
            except (binascii.Error, ValueError):
                raise ReportError("release_record_physical_receipts_invalid") from None
            if not payload or len(payload) > MAXIMUM_INPUT_BYTES or hashlib.sha256(payload).hexdigest() != expected:
                raise ReportError("release_record_physical_receipts_hash_mismatch")
            decoded_hashes[name] = expected
        required = {
            "SHA256SUMS",
            "github-attestation.sigstore.json",
            "device-inventory.json",
            "gateway-deployment-verification.json",
            *required_names,
        }
        if decoded_hashes != hashes or not required.issubset(decoded_hashes):
            raise ReportError("release_record_physical_receipts_invalid")
        retained_count += len(decoded_hashes)
    return retained_count


def derive_compatibility_from_registry_proofs(external: Path) -> dict[str, str]:
    domain = read_json(external / "public_registries.json")
    artifacts = domain.get("artifacts")
    if not isinstance(artifacts, list):
        raise ReportError("release_record_compatibility_proof_invalid")

    def proof(suffix: str) -> Mapping[str, Any]:
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict)
            and set(item) == {"path", "sha256"}
            and isinstance(item.get("path"), str)
            and item["path"].endswith(suffix)
        ]
        if len(matches) != 1:
            raise ReportError("release_record_compatibility_proof_invalid")
        relative = safe_relative(
            matches[0]["path"], "release_record_compatibility_proof_invalid"
        )
        path = resolve_regular(
            external, relative, "release_record_compatibility_proof_invalid"
        )
        if sha256_file(path) != matches[0]["sha256"]:
            raise ReportError("release_record_compatibility_proof_invalid")
        return read_json(path)

    javascript = proof("artifacts--registry-npm-javascript--tool-output.json")
    react_native = proof("artifacts--registry-npm-react-native--tool-output.json")
    ios = proof("artifacts--registry-cocoapods--tool-output.json")
    android = proof("artifacts--registry-maven-central--tool-output.json")
    javascript_facts = javascript.get("compatibility")
    react_native_facts = react_native.get("compatibility")
    ios_facts = ios.get("compatibility")
    android_facts = android.get("compatibility")
    if (
        javascript.get("registry") != "npm"
        or javascript.get("package") != "@latchway/client"
        or react_native.get("registry") != "npm"
        or react_native.get("package") != "@latchway/react-native"
        or ios.get("registry") != "cocoapods"
        or android.get("registry") != "maven_central"
        or not isinstance(javascript_facts, dict)
        or set(javascript_facts) != {"minimum_node"}
        or not isinstance(react_native_facts, dict)
        or set(react_native_facts)
        != {
            "minimum_node",
            "react_native",
            "minimum_ios",
            "minimum_android_api",
        }
        or not isinstance(ios_facts, dict)
        or set(ios_facts) != {"minimum_ios"}
        or not isinstance(android_facts, dict)
        or set(android_facts) != {"minimum_android_api"}
    ):
        raise ReportError("release_record_compatibility_proof_invalid")
    node = javascript_facts.get("minimum_node")
    rn_node = react_native_facts.get("minimum_node")
    rn_version = react_native_facts.get("react_native")
    ios_minimum = ios_facts.get("minimum_ios")
    rn_ios_minimum = react_native_facts.get("minimum_ios")
    android_minimum = android_facts.get("minimum_android_api")
    rn_android_minimum = react_native_facts.get("minimum_android_api")
    if (
        not isinstance(node, str)
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", node) is None
        or rn_node != node
        or not isinstance(rn_version, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]+\.x", rn_version) is None
        or not isinstance(ios_minimum, str)
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+", ios_minimum) is None
        or rn_ios_minimum != ios_minimum
        or not isinstance(android_minimum, int)
        or isinstance(android_minimum, bool)
        or android_minimum < 1
        or not isinstance(rn_android_minimum, int)
        or isinstance(rn_android_minimum, bool)
        or rn_android_minimum < android_minimum
    ):
        raise ReportError("release_record_compatibility_proof_mismatch")
    return {
        "javascript_sdk": f"Node.js {node}",
        "ios_sdk": f"iOS {ios_minimum}",
        "android_sdk": f"Android API {android_minimum}",
        "react_native_sdk": (
            f"React Native {rn_version}; iOS {rn_ios_minimum}; "
            f"Android API {rn_android_minimum}"
        ),
    }


def validate_durable_evidence_root(
    *,
    root: Path,
    candidate_path: Path,
    security_path: Path,
    conformance: Mapping[str, Any],
    commit: str,
    metadata_path: Path,
) -> tuple[int, int, dict[str, str]]:
    files = regular_tree(root, "release_record_durable_evidence_invalid")
    if set(path.split("/", 1)[0] for path in files) != {
        "candidate",
        "security",
        "external",
        "source",
    }:
        raise ReportError("release_record_durable_evidence_invalid")
    required_fixed = {
        "candidate/latchway-candidate.json",
        "candidate/latchway-candidate.attestation.sigstore.json",
        "security/security-summary.json",
        "security/security-summary.attestation.sigstore.json",
        "security/latchway-candidate.json",
        "external/latchway-external-evidence/aggregate-manifest.json",
        "external/latchway-external-evidence/aggregate-manifest.attestation.sigstore.json",
        "source/final-report-metadata.json",
    }
    if not required_fixed.issubset(files):
        raise ReportError("release_record_durable_evidence_incomplete")
    if (
        read_bytes(files["candidate/latchway-candidate.json"]) != read_bytes(candidate_path)
        or read_bytes(files["security/latchway-candidate.json"]) != read_bytes(candidate_path)
        or read_bytes(files["security/security-summary.json"]) != read_bytes(security_path)
        or read_bytes(files["source/final-report-metadata.json"])
        != read_bytes(metadata_path)
    ):
        raise ReportError("release_record_durable_evidence_identity_mismatch")

    security = read_json(security_path)
    candidate = read_json(candidate_path)
    candidate_created_at = parse_utc(
        candidate.get("created_at"), "release_record_candidate_time_invalid"
    )
    security_candidate = security.get("candidate")
    security_window = security.get("evidence_window")
    if (
        not isinstance(security_candidate, dict)
        or security_candidate.get("candidate_created_at") != candidate.get("created_at")
        or not isinstance(security_window, dict)
    ):
        raise ReportError("release_record_security_time_invalid")
    security_started_at = parse_utc(
        security_window.get("started_at"), "release_record_security_time_invalid"
    )
    security_finished_at = parse_utc(
        security_window.get("finished_at"), "release_record_security_time_invalid"
    )
    if not candidate_created_at <= security_started_at < security_finished_at:
        raise ReportError("release_record_security_time_invalid")
    raw_evidence = security.get("raw_evidence")
    if not isinstance(raw_evidence, list) or not raw_evidence:
        raise ReportError("release_record_durable_security_raw_invalid")
    expected_security_raw: set[str] = set()
    for item in raw_evidence:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ReportError("release_record_durable_security_raw_invalid")
        relative = safe_relative(item.get("path"), "release_record_durable_security_raw_invalid")
        if not relative.parts or relative.parts[0] != "raw" or len(relative.parts) != 2:
            raise ReportError("release_record_durable_security_raw_invalid")
        durable_relative = f"security/{relative.as_posix()}"
        expected = item.get("sha256")
        if (
            durable_relative in expected_security_raw
            or durable_relative not in files
            or not isinstance(expected, str)
            or SHA256.fullmatch(expected) is None
            or sha256_file(
                files[durable_relative],
                allow_empty=durable_relative.endswith(".log"),
            )
            != expected
        ):
            raise ReportError("release_record_durable_security_raw_invalid")
        expected_security_raw.add(durable_relative)
    actual_security_raw = {path for path in files if path.startswith("security/raw/")}
    if actual_security_raw != expected_security_raw:
        raise ReportError("release_record_durable_security_raw_invalid")
    for relative in sorted(expected_security_raw):
        if not relative.endswith(".result.json"):
            continue
        result = read_json(files[relative])
        started_at = parse_utc(
            result.get("started_at"), "release_record_security_raw_time_invalid"
        )
        finished_at = parse_utc(
            result.get("finished_at"), "release_record_security_raw_time_invalid"
        )
        if not (
            security_started_at
            <= started_at
            <= finished_at
            <= security_finished_at
        ):
            raise ReportError("release_record_security_raw_time_invalid")

    # The operational report may claim live configuration activation and
    # rollback only when the retained PostgreSQL-enabled race run proves that
    # the vertical local-verification test itself passed. That test asserts the
    # named activation and rollback checks internally.
    race_result_relative = "security/raw/source-race.result.json"
    race_log_relative = "security/raw/source-race.log"
    if not {race_result_relative, race_log_relative}.issubset(expected_security_raw):
        raise ReportError("release_record_configuration_proof_missing")
    race_result = read_json(files[race_result_relative])
    race_log = race_result.get("log")
    if (
        race_result.get("schema_version") != 1
        or race_result.get("kind") != "latchway_security_command_result"
        or race_result.get("check") != "source_race"
        or race_result.get("candidate_commit") != commit
        or race_result.get("argv")
        != ["go", "test", "-race", "-json", "-count=1", "./..."]
        or race_result.get("execution_context")
        != {"postgresql_enabled": True, "fuzz_time": None, "fuzz_parallel": None}
        or race_result.get("exit_code") != 0
        or not isinstance(race_log, dict)
        or race_log.get("path") != "source-race.log"
        or race_log.get("sha256")
        != sha256_file(files[race_log_relative], allow_empty=False)
    ):
        raise ReportError("release_record_configuration_proof_invalid")
    try:
        race_events = [
            json.loads(line, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
            for line in files[race_log_relative].read_text(encoding="utf-8").splitlines()
            if line
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReportError):
        raise ReportError("release_record_configuration_proof_invalid") from None
    if not any(
        isinstance(event, dict)
        and event.get("Action") == "pass"
        and event.get("Package")
        == "github.com/latchway/latchway/internal/localverify"
        and event.get("Test") == "TestRunPostgreSQLV1Vertical"
        for event in race_events
    ):
        raise ReportError("release_record_configuration_proof_invalid")

    external = root / "external/latchway-external-evidence"
    manifest = read_json(external / "aggregate-manifest.json")
    require_fields(
        manifest,
        {"schema_version", "kind", "scope", "candidate_commit", "domains", "identity", "files"},
        "release_record_durable_aggregate_invalid",
    )
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "latchway_external_evidence_aggregate"
        or manifest.get("scope") != "release"
        or manifest.get("candidate_commit") != commit
        or manifest.get("domains") != list(EXTERNAL_DOMAINS)
        or not isinstance(manifest.get("files"), list)
    ):
        raise ReportError("release_record_durable_aggregate_invalid")
    aggregate_paths: set[str] = set()
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ReportError("release_record_durable_aggregate_invalid")
        relative = safe_relative(item.get("path"), "release_record_durable_aggregate_invalid")
        serialized = relative.as_posix()
        expected = item.get("sha256")
        if (
            serialized in aggregate_paths
            or not isinstance(expected, str)
            or SHA256.fullmatch(expected) is None
            or sha256_file(resolve_regular(external, relative, "release_record_durable_aggregate_invalid")) != expected
        ):
            raise ReportError("release_record_durable_aggregate_invalid")
        aggregate_paths.add(serialized)
    actual_external = set(regular_tree(external, "release_record_durable_aggregate_invalid"))
    if actual_external != aggregate_paths | {
        "aggregate-manifest.json",
        "aggregate-manifest.attestation.sigstore.json",
    }:
        raise ReportError("release_record_durable_aggregate_invalid")

    domain_by_id = {item["id"]: item for item in conformance["evidence_domains"]}
    for domain, required_claims in REQUIRED_EXTERNAL_CLAIMS.items():
        document = read_json(external / f"{domain}.json")
        artifacts = document.get("artifacts")
        if (
            document.get("domain") != domain
            or document.get("status") != "passed"
            or document.get("core_commit") != commit
            or not isinstance(document.get("claims"), dict)
            or set(document["claims"]) != set(required_claims)
            or any(value is not True for value in document["claims"].values())
            or not isinstance(artifacts, list)
            or sha256_file(external / f"{domain}.json")
            != domain_by_id[domain]["document_sha256"]
        ):
            raise ReportError("release_record_durable_domain_invalid")
        document_started_at = parse_utc(
            document.get("started_at"), "release_record_durable_domain_time_invalid"
        )
        document_finished_at = parse_utc(
            document.get("finished_at"), "release_record_durable_domain_time_invalid"
        )
        if (
            document.get("started_at") != domain_by_id[domain].get("started_at")
            or document.get("finished_at") != domain_by_id[domain].get("finished_at")
            or not candidate_created_at <= document_started_at < document_finished_at
        ):
            raise ReportError("release_record_durable_domain_time_invalid")
        hashes: list[str] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
                raise ReportError("release_record_durable_domain_invalid")
            relative = safe_relative(artifact.get("path"), "release_record_durable_domain_invalid")
            expected = artifact.get("sha256")
            if (
                not isinstance(expected, str)
                or SHA256.fullmatch(expected) is None
                or sha256_file(resolve_regular(external, relative, "release_record_durable_domain_invalid")) != expected
            ):
                raise ReportError("release_record_durable_domain_invalid")
            hashes.append(expected)
        if sorted(hashes) != sorted(domain_by_id[domain]["artifact_sha256"]):
            raise ReportError("release_record_durable_domain_invalid")
    physical_file_count = validate_physical_receipts(external)
    compatibility = derive_compatibility_from_registry_proofs(external)
    return len(expected_security_raw), physical_file_count, compatibility


def validate_durable_archive(archive: Path, root: Path) -> None:
    sha256_file(archive, maximum=MAXIMUM_DURABLE_FILE_BYTES)
    expected = regular_tree(root, "release_record_durable_archive_invalid")
    expected_hashes = {
        path: sha256_file(file, maximum=MAXIMUM_DURABLE_FILE_BYTES, allow_empty=True)
        for path, file in expected.items()
    }
    seen: set[str] = set()
    seen_directories: set[str] = set()
    expected_directories = {
        parent.as_posix()
        for path in expected
        for parent in PurePosixPath(path).parents
        if parent.as_posix() != "."
    }
    prefix = "latchway-release-evidence-v1/"
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) > MAXIMUM_DURABLE_FILES * 2:
                raise ReportError("release_record_durable_archive_invalid")
            for member in members:
                if member.issym() or member.islnk() or member.isdev():
                    raise ReportError("release_record_durable_archive_invalid")
                if member.name == prefix.rstrip("/"):
                    if not member.isdir():
                        raise ReportError("release_record_durable_archive_invalid")
                    continue
                if not member.name.startswith(prefix):
                    raise ReportError("release_record_durable_archive_invalid")
                relative = member.name.removeprefix(prefix).rstrip("/")
                if not relative:
                    if not member.isdir():
                        raise ReportError("release_record_durable_archive_invalid")
                    continue
                safe_relative(relative, "release_record_durable_archive_invalid")
                if member.isdir():
                    if relative in seen_directories or relative not in expected_directories:
                        raise ReportError("release_record_durable_archive_invalid")
                    seen_directories.add(relative)
                    continue
                if (
                    not member.isfile()
                    or relative in seen
                    or relative not in expected_hashes
                    or member.size > MAXIMUM_DURABLE_FILE_BYTES
                ):
                    raise ReportError("release_record_durable_archive_invalid")
                source = bundle.extractfile(member)
                if source is None:
                    raise ReportError("release_record_durable_archive_invalid")
                digest = hashlib.sha256()
                total = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    total += len(chunk)
                    if total > MAXIMUM_DURABLE_FILE_BYTES:
                        raise ReportError("release_record_durable_archive_invalid")
                    digest.update(chunk)
                if total != member.size or digest.hexdigest() != expected_hashes[relative]:
                    raise ReportError("release_record_durable_archive_hash_mismatch")
                seen.add(relative)
    except ReportError:
        raise
    except (OSError, tarfile.TarError):
        raise ReportError("release_record_durable_archive_invalid") from None
    if seen != set(expected_hashes):
        raise ReportError("release_record_durable_archive_incomplete")
    if seen_directories != expected_directories:
        raise ReportError("release_record_durable_archive_incomplete")


def database_schema_version(repository: Path) -> int:
    migrations = repository / "migrations"
    try:
        metadata = migrations.lstat()
    except OSError:
        raise ReportError("release_record_migrations_missing") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReportError("release_record_migrations_invalid")
    versions: list[int] = []
    for path in migrations.iterdir():
        if not path.is_file() or path.is_symlink():
            continue
        match = MIGRATION.fullmatch(path.name)
        if match is not None:
            versions.append(int(match.group(1)))
    versions.sort()
    if not versions or versions != list(range(1, versions[-1] + 1)):
        raise ReportError("release_record_migration_sequence_invalid")
    return versions[-1]


def validate_candidate(
    candidate: Mapping[str, Any], commit: str, tag: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    require_fields(
        candidate,
        {
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
        },
        "release_record_candidate_fields_invalid",
    )
    version = tag[1:]
    candidate_created_at = parse_utc(
        candidate.get("created_at"), "release_record_candidate_identity_mismatch"
    )
    if (
        candidate.get("schema_version") != 1
        or candidate.get("kind") != "latchway_release_candidate"
        or candidate.get("status") != "passed"
        or candidate.get("candidate_commit") != commit
        or candidate.get("intended_tag") != tag
        or candidate.get("version") != version
    ):
        raise ReportError("release_record_candidate_identity_mismatch")
    contract = candidate.get("contract")
    image = candidate.get("image")
    if not isinstance(contract, dict) or not isinstance(image, dict):
        raise ReportError("release_record_candidate_invalid")
    require_fields(
        contract,
        {"version", "status", "released_at", "bundle_file_name", "bundle_sha256"},
        "release_record_candidate_contract_invalid",
    )
    contract_version = require_string(
        contract.get("version"), SEMVER, "release_record_contract_version_invalid"
    )
    contract_released_at = parse_utc(
        contract.get("released_at"), "release_record_candidate_contract_invalid"
    )
    if (
        contract.get("status") != "released"
        or contract.get("bundle_file_name")
        != f"latchway-contract-{contract_version}.tar.gz"
        or contract_released_at > candidate_created_at
        or not isinstance(contract.get("bundle_sha256"), str)
        or SHA256.fullmatch(contract["bundle_sha256"]) is None
    ):
        raise ReportError("release_record_candidate_contract_invalid")
    require_fields(
        image,
        {"repository", "index_digest", "platforms"},
        "release_record_candidate_image_invalid",
    )
    if image.get("repository") != "ghcr.io/latchway/latchway":
        raise ReportError("release_record_candidate_image_invalid")
    require_string(
        image.get("index_digest"), DIGEST, "release_record_candidate_image_invalid"
    )
    platforms = image.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != {
        "linux/amd64",
        "linux/arm64",
    }:
        raise ReportError("release_record_candidate_image_invalid")
    if any(not isinstance(item, str) or DIGEST.fullmatch(item) is None for item in platforms.values()):
        raise ReportError("release_record_candidate_image_invalid")
    artifacts = candidate.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReportError("release_record_candidate_artifacts_invalid")
    seen: set[str] = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256"}
            or not isinstance(artifact.get("path"), str)
            or "/" in artifact["path"]
            or artifact["path"] in seen
            or not isinstance(artifact.get("sha256"), str)
            or SHA256.fullmatch(artifact["sha256"]) is None
        ):
            raise ReportError("release_record_candidate_artifacts_invalid")
        seen.add(artifact["path"])
    return contract, image


def validate_conformance(
    report: Mapping[str, Any],
    commit: str,
    tag: str,
    contract: Mapping[str, Any],
    image: Mapping[str, Any],
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    required_top = {
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
    require_fields(report, required_top, "release_record_conformance_fields_invalid")
    if (
        report.get("schema_version") != 1
        or report.get("kind")
        != "latchway_cross_repository_conformance_evidence"
        or report.get("scope") != "release"
        or report.get("verdict") != "passed"
        or report.get("source_conformance_passed") is not True
        or report.get("promotion_ready") is not True
        or report.get("release_ready") is not True
    ):
        raise ReportError("release_record_conformance_not_release_ready")
    summary = report.get("contract")
    if not isinstance(summary, dict):
        raise ReportError("release_record_conformance_contract_invalid")
    require_fields(
        summary,
        {
            "version",
            "status",
            "released_at",
            "wire_protocol",
            "bundle_file_name",
            "bundle_sha256",
            "core_release",
            "oci_image_digest",
        },
        "release_record_conformance_contract_invalid",
    )
    expected_oci = f"{image['repository']}@{image['index_digest']}"
    if (
        summary.get("version") != contract["version"]
        or summary.get("status") != "released"
        or summary.get("released_at") != contract["released_at"]
        or summary.get("bundle_file_name") != contract["bundle_file_name"]
        or summary.get("bundle_sha256") != contract["bundle_sha256"]
        or summary.get("core_release") != tag
        or summary.get("oci_image_digest") != expected_oci
        or not isinstance(summary.get("wire_protocol"), int)
        or isinstance(summary.get("wire_protocol"), bool)
        or summary["wire_protocol"] < 1
    ):
        raise ReportError("release_record_conformance_contract_mismatch")
    repositories = report.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != len(REPOSITORY_IDS):
        raise ReportError("release_record_repository_coordinates_invalid")
    by_id: dict[str, Mapping[str, Any]] = {}
    for coordinate in repositories:
        if not isinstance(coordinate, dict):
            raise ReportError("release_record_repository_coordinates_invalid")
        require_fields(
            coordinate,
            {"id", "commit", "version", "intended_tag"},
            "release_record_repository_coordinates_invalid",
        )
        identifier = coordinate.get("id")
        if not isinstance(identifier, str) or identifier in by_id:
            raise ReportError("release_record_repository_coordinates_invalid")
        require_string(
            coordinate.get("commit"), COMMIT, "release_record_repository_coordinates_invalid"
        )
        version = require_string(
            coordinate.get("version"), SEMVER, "release_record_repository_coordinates_invalid"
        )
        if coordinate.get("intended_tag") != f"v{version}":
            raise ReportError("release_record_repository_coordinates_invalid")
        by_id[identifier] = coordinate
    if tuple(by_id) != REPOSITORY_IDS or by_id["core"]["commit"] != commit or by_id["core"]["intended_tag"] != tag:
        raise ReportError("release_record_repository_coordinates_mismatch")
    domains = report.get("evidence_domains")
    if not isinstance(domains, list):
        raise ReportError("release_record_domains_invalid")
    domain_by_id: dict[str, Mapping[str, Any]] = {}
    for domain in domains:
        if not isinstance(domain, dict):
            raise ReportError("release_record_domains_invalid")
        identifier = domain.get("id")
        if not isinstance(identifier, str) or identifier in domain_by_id:
            raise ReportError("release_record_domains_invalid")
        domain_by_id[identifier] = domain
    if set(domain_by_id) != set(LOCAL_DOMAINS + EXTERNAL_DOMAINS):
        raise ReportError("release_record_domains_incomplete")
    external_starts: list[datetime] = []
    external_finishes: list[datetime] = []
    for identifier in LOCAL_DOMAINS + EXTERNAL_DOMAINS:
        domain = domain_by_id[identifier]
        if domain.get("required") is not True or domain.get("status") != "passed":
            raise ReportError("release_record_required_domain_not_passed")
        if identifier in EXTERNAL_DOMAINS:
            if domain.get("oci_image_digest") != expected_oci:
                raise ReportError("release_record_domain_image_mismatch")
            if (
                not isinstance(domain.get("document_sha256"), str)
                or SHA256.fullmatch(domain["document_sha256"]) is None
            ):
                raise ReportError("release_record_domain_proof_invalid")
            started_at = parse_utc(
                domain.get("started_at"), "release_record_domain_proof_invalid"
            )
            finished_at = parse_utc(
                domain.get("finished_at"), "release_record_domain_proof_invalid"
            )
            if started_at >= finished_at:
                raise ReportError("release_record_domain_proof_invalid")
            external_starts.append(started_at)
            external_finishes.append(finished_at)
            artifact_hashes = domain.get("artifact_sha256")
            if (
                not isinstance(artifact_hashes, list)
                or not artifact_hashes
                or len(artifact_hashes) > 64
                or len(set(artifact_hashes)) != len(artifact_hashes)
                or any(
                    not isinstance(item, str) or SHA256.fullmatch(item) is None
                    for item in artifact_hashes
                )
            ):
                raise ReportError("release_record_domain_artifact_proof_invalid")
    evidence_window = report.get("evidence_window")
    if not isinstance(evidence_window, dict) or set(evidence_window) != {
        "started_at",
        "finished_at",
        "maximum_age_seconds",
    }:
        raise ReportError("release_record_evidence_window_invalid")
    evidence_started_at = parse_utc(
        evidence_window.get("started_at"), "release_record_evidence_window_invalid"
    )
    evidence_finished_at = parse_utc(
        evidence_window.get("finished_at"), "release_record_evidence_window_invalid"
    )
    if (
        evidence_started_at != min(external_starts)
        or evidence_finished_at != max(external_finishes)
        or evidence_started_at >= evidence_finished_at
        or not isinstance(evidence_window.get("maximum_age_seconds"), int)
        or isinstance(evidence_window.get("maximum_age_seconds"), bool)
        or evidence_window["maximum_age_seconds"] < 1
        or (
            evidence_finished_at - evidence_started_at
        ).total_seconds()
        > evidence_window["maximum_age_seconds"]
    ):
        raise ReportError("release_record_evidence_window_invalid")
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ReportError("release_record_checks_invalid")
    seen_checks: set[str] = set()
    for check in checks:
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("id"), str)
            or check["id"] in seen_checks
        ):
            raise ReportError("release_record_checks_invalid")
        seen_checks.add(check["id"])
        if (
            check["id"] not in REQUIRED_CONFORMANCE_CHECKS
            or check.get("domain") != REQUIRED_CONFORMANCE_CHECKS[check["id"]]
            or check.get("required") is not True
            or check.get("status") != "passed"
        ):
            raise ReportError("release_record_checks_invalid")
        if check.get("required") is True and check.get("status") != "passed":
            raise ReportError("release_record_required_check_not_passed")
    if seen_checks != set(REQUIRED_CONFORMANCE_CHECKS):
        raise ReportError("release_record_checks_incomplete")
    return repositories, domains, checks


def validate_security(
    security: Mapping[str, Any],
    commit: str,
    tag: str,
    contract: Mapping[str, Any],
    image: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    if (
        security.get("schema_version") != 1
        or security.get("kind") != "latchway_candidate_security_evidence"
        or security.get("automated_gate") != "passed"
    ):
        raise ReportError("release_record_security_not_passed")
    candidate = security.get("candidate")
    if not isinstance(candidate, dict):
        raise ReportError("release_record_security_candidate_invalid")
    security_image = candidate.get("image")
    security_contract = candidate.get("contract")
    if (
        candidate.get("commit") != commit
        or candidate.get("intended_tag") != tag
        or candidate.get("version") != tag[1:]
        or not isinstance(security_image, dict)
        or security_image.get("repository") != image["repository"]
        or security_image.get("index_digest") != image["index_digest"]
        or not isinstance(security_contract, dict)
        or security_contract.get("version") != contract["version"]
        or security_contract.get("bundle_sha256") != contract["bundle_sha256"]
    ):
        raise ReportError("release_record_security_candidate_mismatch")
    checks = security.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ReportError("release_record_security_checks_invalid")
    identifiers: set[str] = set()
    for check in checks:
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("id"), str)
            or check["id"] in identifiers
            or check.get("status") != "passed"
        ):
            raise ReportError("release_record_security_checks_invalid")
        identifiers.add(check["id"])
    if identifiers != REQUIRED_SECURITY_CHECKS:
        raise ReportError("release_record_security_checks_incomplete")
    return checks


def canonical_registries(repositories: list[Mapping[str, Any]], oci: str) -> dict[str, Any]:
    by_id = {item["id"]: item for item in repositories}
    android_version = by_id["android"]["version"]
    return {
        "oci": oci,
        "npm_javascript": f"@latchway/client@{by_id['javascript']['version']}",
        "npm_react_native": f"@latchway/react-native@{by_id['react_native']['version']}",
        "swift_package": (
            "https://github.com/Latchway/latchway-ios-sdk.git@"
            f"{by_id['ios']['intended_tag']}"
        ),
        "cocoapods": f"Latchway/{by_id['ios']['version']}",
        "maven_central": [
            f"dev.latchway:{module}:{android_version}" for module in ANDROID_MODULES
        ],
    }


def canonical_oci_aliases(
    repositories: list[Mapping[str, Any]], image: Mapping[str, Any]
) -> dict[str, Any]:
    by_id = {item["id"]: item for item in repositories}
    version = by_id["core"]["version"]
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ReportError("release_record_oci_aliases_invalid")
    major, minor, _ = version.split(".")
    digest = image["index_digest"]
    repository = image["repository"]
    tags = (version, f"{major}.{minor}", major, "latest")
    return {
        "immutable_version": version,
        "references": {
            tag: {"reference": f"{repository}:{tag}", "digest": digest}
            for tag in tags
        },
    }


def validate_publication(
    publication: Mapping[str, Any],
    commit: str,
    tag: str,
    repositories: list[Mapping[str, Any]],
    image: Mapping[str, Any],
) -> None:
    require_fields(
        publication,
        {
            "schema_version",
            "kind",
            "repository",
            "core_commit",
            "core_tag",
            "tag_object_sha",
            "promotion_evidence_sha256",
            "github_release",
            "oci_image_digest",
            "oci_aliases",
            "registries",
        },
        "release_record_publication_fields_invalid",
    )
    expected_oci = f"{image['repository']}@{image['index_digest']}"
    if (
        publication.get("schema_version") != 1
        or publication.get("kind") != "latchway_public_release_state"
        or publication.get("repository") != "Latchway/latchway"
        or publication.get("core_commit") != commit
        or publication.get("core_tag") != tag
        or publication.get("oci_image_digest") != expected_oci
    ):
        raise ReportError("release_record_publication_identity_mismatch")
    require_string(
        publication.get("tag_object_sha"), COMMIT, "release_record_tag_object_invalid"
    )
    promotion_sha256 = require_string(
        publication.get("promotion_evidence_sha256"),
        SHA256,
        "release_record_promotion_hash_invalid",
    )
    release = publication.get("github_release")
    if not isinstance(release, dict):
        raise ReportError("release_record_github_release_invalid")
    require_fields(
        release,
        {
            "id",
            "url",
            "tag_name",
            "name",
            "body",
            "draft",
            "prerelease",
            "immutable",
            "published_at",
            "release_attestation_sha256",
            "assets",
        },
        "release_record_github_release_invalid",
    )
    if (
        not isinstance(release.get("id"), int)
        or isinstance(release.get("id"), bool)
        or release["id"] < 1
        or release.get("url")
        != f"https://github.com/Latchway/latchway/releases/tag/{tag}"
        or release.get("tag_name") != tag
        or release.get("name") != f"Latchway {tag}"
        or release.get("body")
        != (
            f"Immutable Latchway product release {tag}.\n\n"
            f"Candidate commit: {commit}\n"
            f"Promotion evidence SHA-256: {promotion_sha256}"
        )
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
        or not isinstance(release.get("release_attestation_sha256"), str)
        or SHA256.fullmatch(release["release_attestation_sha256"]) is None
    ):
        raise ReportError("release_record_github_release_invalid")
    parse_utc(release.get("published_at"), "release_record_github_release_invalid")
    assets = release.get("assets")
    if not isinstance(assets, list) or len(assets) != len(CORE_PRODUCT_RELEASE_ASSETS):
        raise ReportError("release_record_github_release_assets_invalid")
    names: list[str] = []
    for asset in assets:
        if (
            not isinstance(asset, dict)
            or set(asset) != {"id", "name", "size", "digest"}
            or not isinstance(asset.get("id"), int)
            or isinstance(asset.get("id"), bool)
            or asset["id"] < 1
            or not isinstance(asset.get("name"), str)
            or asset["name"] in names
            or not isinstance(asset.get("size"), int)
            or isinstance(asset.get("size"), bool)
            or asset["size"] < 1
            or not isinstance(asset.get("digest"), str)
            or DIGEST.fullmatch(asset["digest"]) is None
        ):
            raise ReportError("release_record_github_release_assets_invalid")
        names.append(asset["name"])
    if names != sorted(CORE_PRODUCT_RELEASE_ASSETS):
        raise ReportError("release_record_github_release_assets_invalid")
    promotion_assets = [
        asset
        for asset in assets
        if asset.get("name") == "latchway-cross-repository-promotion.json"
    ]
    if (
        len(promotion_assets) != 1
        or promotion_assets[0].get("digest") != f"sha256:{promotion_sha256}"
    ):
        raise ReportError("release_record_promotion_hash_invalid")
    if publication.get("registries") != canonical_registries(repositories, expected_oci):
        raise ReportError("release_record_registry_coordinates_mismatch")
    if publication.get("oci_aliases") != canonical_oci_aliases(repositories, image):
        raise ReportError("release_record_oci_aliases_invalid")


def validate_evidence_chronology(
    *,
    candidate: Mapping[str, Any],
    security: Mapping[str, Any],
    conformance: Mapping[str, Any],
    publication: Mapping[str, Any],
) -> None:
    candidate_created_at = parse_utc(
        candidate.get("created_at"), "release_record_chronology_invalid"
    )
    contract = candidate.get("contract")
    if not isinstance(contract, dict):
        raise ReportError("release_record_chronology_invalid")
    contract_released_at = parse_utc(
        contract.get("released_at"), "release_record_chronology_invalid"
    )
    security_window = security.get("evidence_window")
    if not isinstance(security_window, dict):
        raise ReportError("release_record_chronology_invalid")
    security_started_at = parse_utc(
        security_window.get("started_at"), "release_record_chronology_invalid"
    )
    security_finished_at = parse_utc(
        security_window.get("finished_at"), "release_record_chronology_invalid"
    )
    release = publication.get("github_release")
    if not isinstance(release, dict):
        raise ReportError("release_record_chronology_invalid")
    published_at = parse_utc(
        release.get("published_at"), "release_record_chronology_invalid"
    )
    if not (
        contract_released_at
        <= candidate_created_at
        <= security_started_at
        < security_finished_at
        <= published_at
    ):
        raise ReportError("release_record_chronology_invalid")
    domain_by_id = {
        item.get("id"): item
        for item in conformance.get("evidence_domains", [])
        if isinstance(item, dict)
    }
    for domain in EXTERNAL_DOMAINS:
        value = domain_by_id.get(domain)
        if not isinstance(value, dict):
            raise ReportError("release_record_chronology_invalid")
        started_at = parse_utc(
            value.get("started_at"), "release_record_chronology_invalid"
        )
        finished_at = parse_utc(
            value.get("finished_at"), "release_record_chronology_invalid"
        )
        if not candidate_created_at <= started_at < finished_at:
            raise ReportError("release_record_chronology_invalid")
        if domain in {"public_tags", "public_registries"} and started_at < published_at:
            raise ReportError("release_record_post_publication_evidence_invalid")


def escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(
    *,
    candidate_path: Path,
    security_path: Path,
    conformance_path: Path,
    publication_path: Path,
    repository: Path,
    commit: str,
    tag: str,
    evidence_tag: str,
    durable_evidence_root: Path,
    durable_assets: Mapping[str, Path] | None = None,
) -> str:
    require_string(commit, COMMIT, "release_record_commit_invalid")
    require_string(tag, TAG, "release_record_tag_invalid")
    require_string(evidence_tag, EVIDENCE_TAG, "release_record_evidence_tag_invalid")
    if evidence_tag != f"evidence/{tag}":
        raise ReportError("release_record_evidence_tag_invalid")
    candidate = read_json(candidate_path)
    security = read_json(security_path)
    conformance = read_json(conformance_path)
    publication = read_json(publication_path)
    contract, image = validate_candidate(candidate, commit, tag)
    repositories, domains, checks = validate_conformance(
        conformance, commit, tag, contract, image
    )
    security_checks = validate_security(security, commit, tag, contract, image)
    validate_publication(
        publication,
        commit,
        tag,
        repositories,
        image,
    )
    validate_evidence_chronology(
        candidate=candidate,
        security=security,
        conformance=conformance,
        publication=publication,
    )
    metadata = validate_report_metadata(repository)
    (
        security_raw_count,
        physical_receipt_file_count,
        derived_platforms,
    ) = validate_durable_evidence_root(
        root=durable_evidence_root,
        candidate_path=candidate_path,
        security_path=security_path,
        conformance=conformance,
        commit=commit,
        metadata_path=repository / "docs/release/final-report-metadata.json",
    )
    if metadata["compatibility"]["minimum_platform_versions"] != derived_platforms:
        raise ReportError("release_record_compatibility_metadata_mismatch")
    schema_version = database_schema_version(repository)
    oci = f"{image['repository']}@{image['index_digest']}"
    registries = publication["registries"]
    durable = durable_assets or {}
    if not durable or len(durable) > 16:
        raise ReportError("release_record_durable_assets_invalid")
    archive_name = "latchway-release-evidence-v1.tar.gz"
    product_attestation_name = "latchway-product-release-attestation.json"
    if archive_name not in durable or product_attestation_name not in durable:
        raise ReportError("release_record_durable_assets_invalid")
    validate_durable_archive(durable[archive_name], durable_evidence_root)
    if (
        sha256_file(durable[product_attestation_name])
        != publication["github_release"]["release_attestation_sha256"]
    ):
        raise ReportError("release_record_product_attestation_mismatch")
    durable_hashes: list[tuple[str, str]] = []
    for name, path in sorted(durable.items()):
        if ASSET_NAME.fullmatch(name) is None or path.name != name:
            raise ReportError("release_record_durable_assets_invalid")
        durable_hashes.append(
            (name, sha256_file(path, maximum=MAXIMUM_DURABLE_FILE_BYTES))
        )

    by_repository = {item["id"]: item for item in repositories}
    lines = [
        f"# Latchway {tag} final release record",
        "",
        "> Product status: **released and fully evidence-gated**. This report was rendered only after the immutable product release and every required v1 evidence domain passed.",
        "",
        f"> Evidence publication target: [`{evidence_tag}`](https://github.com/Latchway/latchway/releases/tag/{evidence_tag}). The finalizer publishes this exact report and its complete fixed asset set through a draft, then separately requires GitHub immutability and release-attestation verification; this pre-publication document does not claim that evidence release already exists.",
        "",
        "## Release artifacts",
        "",
        "| Required artifact | Exact value |",
        "| --- | --- |",
        f"| Core repository commit and tag | `{commit}` / `{tag}` |",
        f"| iOS repository commit and tag | `{by_repository['ios']['commit']}` / `{by_repository['ios']['intended_tag']}` |",
        f"| Android repository commit and tag | `{by_repository['android']['commit']}` / `{by_repository['android']['intended_tag']}` |",
        f"| JavaScript repository commit and tag | `{by_repository['javascript']['commit']}` / `{by_repository['javascript']['intended_tag']}` |",
        f"| React Native repository commit and tag | `{by_repository['react_native']['commit']}` / `{by_repository['react_native']['intended_tag']}` |",
        f"| OCI image digest | `{oci}` |",
        f"| Contract bundle hash | `{contract['bundle_sha256']}` |",
        f"| Database schema version | `{schema_version}` |",
        "",
        "### Release identity",
        "",
        "| Field | Exact value |",
        "| --- | --- |",
        f"| Core version | `{escape(tag[1:])}` |",
        f"| Git tag object | `{escape(publication['tag_object_sha'])}` |",
        f"| GitHub release | [release {escape(tag)}]({escape(publication['github_release']['url'])}) (`{publication['github_release']['id']}`) |",
        f"| Final evidence release target | [`{escape(evidence_tag)}`](https://github.com/Latchway/latchway/releases/tag/{escape(evidence_tag)}) |",
        "| Final evidence checksum manifest | `SHA256SUMS` (covers every other fixed evidence-release asset) |",
        f"| Published at | `{escape(publication['github_release']['published_at'])}` |",
        f"| Contract | `{escape(contract['version'])}` (`released`, wire `{escape(conformance['contract']['wire_protocol'])}`) |",
        "",
        "### Exact repository coordinates",
        "",
        "| Repository | Version | Annotated tag | Commit |",
        "| --- | --- | --- | --- |",
    ]
    for coordinate in repositories:
        lines.append(
            f"| `{escape(coordinate['id'])}` | `{escape(coordinate['version'])}` | `{escape(coordinate['intended_tag'])}` | `{escape(coordinate['commit'])}` |"
        )
    lines.extend(
        [
            "",
            "### Published package coordinates",
            "",
            f"- OCI: `{escape(registries['oci'])}`",
            f"- JavaScript: `{escape(registries['npm_javascript'])}`",
            f"- React Native: `{escape(registries['npm_react_native'])}`",
            f"- Swift Package: `{escape(registries['swift_package'])}`",
            f"- CocoaPods: `{escape(registries['cocoapods'])}`",
            "- Maven Central:",
            "",
        ]
    )
    lines.extend(f"  - `{escape(item)}`" for item in registries["maven_central"])
    lines.extend(
        [
            "",
            "### Multi-architecture image",
            "",
            "| Platform | Immutable digest |",
            "| --- | --- |",
        ]
    )
    for platform in ("linux/amd64", "linux/arm64"):
        lines.append(f"| `{platform}` | `{escape(image['platforms'][platform])}` |")
    lines.extend(
        [
            "",
            "### Candidate artifacts",
            "",
            "| Artifact | SHA-256 |",
            "| --- | --- |",
        ]
    )
    for artifact in candidate["artifacts"]:
        lines.append(f"| `{escape(artifact['path'])}` | `{escape(artifact['sha256'])}` |")
    lines.extend(
        [
            "",
            "### Evidence provenance and durable assets",
            "",
            "| Input document | SHA-256 |",
            "| --- | --- |",
            f"| Release candidate manifest | `{sha256_file(candidate_path)}` |",
            f"| Candidate security report | `{sha256_file(security_path)}` |",
            f"| Release-scope cross-repository report | `{sha256_file(conformance_path)}` |",
            f"| Verified public release state | `{sha256_file(publication_path)}` |",
            "",
            "| Durable release asset | SHA-256 |",
            "| --- | --- |",
        ]
    )
    lines.extend(f"| `{escape(name)}` | `{digest}` |" for name, digest in durable_hashes)
    lines.extend(
        [
            "",
            f"The immutable evidence archive retains all `{security_raw_count}` exact redacted security inputs and all `{physical_receipt_file_count}` exact physical-device receipt files, together with their manifests, producer proofs, and attestations. It is byte-checked against the tree used by this renderer and can be revalidated after Actions artifact expiry.",
            "",
            "## Test evidence",
            "",
            "| Required test evidence | Result | Validated evidence |",
            "| --- | --- | --- |",
            "| Unit tests | `passed` | Candidate-bound full Go test execution in `source_race` |",
            "| Integration tests | `passed` | PostgreSQL-backed candidate test execution plus live SDK conformance |",
            "| Race tests | `passed` | `source_race` |",
            "| Fuzz tests | `passed` | `source_fuzz_smoke` |",
            "| Conformance tests | `passed` | Source, contract, SDK-lock, live-SDK, tag, and registry checks |",
            "| OpenRouter live test | `passed` | `live_provider` |",
            "| App Attest real-device test | `passed` | `physical_devices.app_attest_production_verified` |",
            "| Play Integrity real-device test | `passed` | `physical_devices.play_integrity_play_distributed_verified` |",
            "| Cloud deployment smoke tests | `passed` | `cloud_deployments` |",
            "| Load tests | `passed` | `operational_resilience.v1_load_targets_verified` |",
            "| Security scans | `passed` | Candidate security and `supply_chain` evidence |",
            "",
            "### Required release evidence domains",
            "",
            "| Domain | Status | Evidence window | Document SHA-256 | Retained proof SHA-256 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for domain in domains:
        window = "local candidate proof"
        document_hash = "n/a"
        artifact_hashes = "n/a"
        if domain["id"] in EXTERNAL_DOMAINS:
            window = f"{domain['started_at']} — {domain['finished_at']}"
            document_hash = domain["document_sha256"]
            artifact_hashes = "<br>".join(f"`{item}`" for item in domain["artifact_sha256"])
        lines.append(
            f"| `{escape(domain['id'])}` | `{escape(domain['status'])}` | {escape(window)} | `{escape(document_hash)}` | {artifact_hashes} |"
        )
    platforms = metadata["compatibility"]["minimum_platform_versions"]
    lines.extend(
        [
            "",
            "## Compatibility matrix",
            "",
            "| Compatibility item | Supported version |",
            "| --- | --- |",
            f"| Server version | `{tag[1:]}` |",
            f"| Protocol version | `{conformance['contract']['wire_protocol']}` |",
            f"| iOS SDK version | `{by_repository['ios']['version']}` |",
            f"| Android SDK version | `{by_repository['android']['version']}` |",
            f"| JavaScript SDK version | `{by_repository['javascript']['version']}` |",
            f"| React Native SDK version | `{by_repository['react_native']['version']}` |",
            f"| Minimum supported iOS platform | `{escape(platforms['ios_sdk'])}` |",
            f"| Minimum supported Android platform | `{escape(platforms['android_sdk'])}` |",
            f"| Minimum supported JavaScript platform | `{escape(platforms['javascript_sdk'])}` |",
            f"| Minimum supported React Native platforms | `{escape(platforms['react_native_sdk'])}` |",
            "",
            "## Security statement",
            "",
            "### Known accepted risks",
            "",
        ]
    )
    lines.extend(f"- {escape(item)}" for item in metadata["security_statement"]["known_accepted_risks"])
    security_labels = (
        ("Prompt-logging defaults", "prompt_logging_defaults"),
        ("Secret-storage behavior", "secret_storage_behavior"),
        ("Key-rotation behavior", "key_rotation_behavior"),
        ("Attestation limitations", "attestation_limitations"),
        ("Web threat-model limitations", "web_threat_model_limitations"),
    )
    lines.extend(["", "| Security property | Statement |", "| --- | --- |"])
    for label, key in security_labels:
        lines.append(f"| {label} | {escape(metadata['security_statement'][key])} |")
    lines.extend(
        [
            "| Dependency scan results | All candidate-bound vulnerability, secret, misconfiguration, dependency-license, per-architecture image, SBOM, signature, and provenance gates passed. |",
            "",
            "### Automated security gate",
            "",
            "| Check | Result | Tool |",
            "| --- | --- | --- |",
        ]
    )
    for check in security_checks:
        tool = check.get("tool", {})
        tool_value = "n/a"
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            tool_value = tool["name"]
            if isinstance(tool.get("version"), str):
                tool_value += f" {tool['version']}"
        lines.append(f"| `{escape(check['id'])}` | `{escape(check['status'])}` | `{escape(tool_value)}` |")
    required_checks = [item for item in checks if item.get("required") is True]
    lines.extend(
        [
            "",
            f"All `{len(required_checks)}` required cross-repository checks and all `{len(security_checks)}` candidate security checks passed.",
            "",
            "## Operational proof",
            "",
            "| Required operational proof | Result | Validated evidence |",
            "| --- | --- | --- |",
            "| Clean Docker Compose startup | `passed` | `cloud_deployments.compose_verified` |",
            "| Fresh database migration | `passed` | Candidate migration preconditions plus cloud release-image smoke |",
            "| Upgrade from previous release candidate | `passed` | `operational_resilience.previous_candidate_upgrade_rollback_verified` |",
            "| Configuration activation | `passed` | PostgreSQL-enabled `source_race` executes `TestRunPostgreSQLV1Vertical` and its `configuration_activation` check |",
            "| Configuration rollback | `passed` | PostgreSQL-enabled `source_race` executes `TestRunPostgreSQLV1Vertical` and its `configuration_rollback` check |",
            "| Backup and restore | `passed` | `operational_resilience.backup_restore_drill_verified` |",
            "| Graceful shutdown | `passed` | `operational_resilience.live_failure_injection_verified` |",
            "| Worker recovery | `passed` | `operational_resilience.live_failure_injection_verified` and `multi_replica_verified` |",
            "",
            "## Remaining work",
            "",
        ]
    )
    category_labels = {
        "post_1_0_enhancement": "Post-1.0 enhancement",
        "documented_non_goal": "Documented non-goal",
        "low_severity_accepted_risk": "Low-severity accepted risk",
    }
    for item in metadata["remaining_work"]:
        lines.append(f"- **{category_labels[item['category']]}:** {escape(item['description'])}")
    lines.append("")
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--candidate", type=Path, required=True)
    result.add_argument("--security", type=Path, required=True)
    result.add_argument("--release-conformance", type=Path, required=True)
    result.add_argument("--publication-state", type=Path, required=True)
    result.add_argument("--repository", type=Path, required=True)
    result.add_argument("--durable-evidence-root", type=Path, required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--tag", required=True)
    result.add_argument("--evidence-tag", required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument(
        "--durable-asset",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Durable release asset name and local path (repeatable)",
    )
    return result


def parse_durable_assets(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if value.count("=") != 1:
            raise ReportError("release_record_durable_assets_invalid")
        name, raw_path = value.split("=", 1)
        if name in result or ASSET_NAME.fullmatch(name) is None or not raw_path:
            raise ReportError("release_record_durable_assets_invalid")
        result[name] = Path(raw_path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        output = arguments.output
        if not output.is_absolute() or output.exists() or output.is_symlink():
            raise ReportError("release_record_output_invalid")
        contents = render(
            candidate_path=arguments.candidate,
            security_path=arguments.security,
            conformance_path=arguments.release_conformance,
            publication_path=arguments.publication_state,
            repository=arguments.repository,
            commit=arguments.commit,
            tag=arguments.tag,
            evidence_tag=arguments.evidence_tag,
            durable_evidence_root=arguments.durable_evidence_root,
            durable_assets=parse_durable_assets(arguments.durable_asset),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(contents, encoding="utf-8", newline="\n")
        output.chmod(0o600)
    except (ReportError, OSError) as error:
        code = str(error) if isinstance(error, ReportError) else "release_record_io_failed"
        print(f"release record rejected: {code}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(arguments.output), "sha256": sha256_file(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
