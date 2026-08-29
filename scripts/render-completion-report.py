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
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping


COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$")
ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEMVER = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
TAG = re.compile(r"^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MIGRATION = re.compile(r"^(\d{6})_[a-z0-9_]+\.sql$")
MAXIMUM_INPUT_BYTES = 32 * 1024 * 1024
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


def sha256_file(path: Path) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


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
    if (
        candidate.get("schema_version") != 1
        or candidate.get("kind") != "latchway_release_candidate"
        or candidate.get("status") != "passed"
        or candidate.get("candidate_commit") != commit
        or candidate.get("intended_tag") != tag
        or candidate.get("version") != version
        or not isinstance(candidate.get("created_at"), str)
        or UTC.fullmatch(candidate["created_at"]) is None
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
    if (
        contract.get("status") != "released"
        or contract.get("bundle_file_name")
        != f"latchway-contract-{contract_version}.tar.gz"
        or not isinstance(contract.get("released_at"), str)
        or UTC.fullmatch(contract["released_at"]) is None
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
                or not isinstance(domain.get("started_at"), str)
                or UTC.fullmatch(domain["started_at"]) is None
                or not isinstance(domain.get("finished_at"), str)
                or UTC.fullmatch(domain["finished_at"]) is None
            ):
                raise ReportError("release_record_domain_proof_invalid")
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
        if check.get("required") is True and check.get("status") != "passed":
            raise ReportError("release_record_required_check_not_passed")
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
            "github_release",
            "oci_image_digest",
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
    release = publication.get("github_release")
    if not isinstance(release, dict):
        raise ReportError("release_record_github_release_invalid")
    require_fields(
        release,
        {"id", "url", "tag_name", "draft", "prerelease", "published_at"},
        "release_record_github_release_invalid",
    )
    if (
        not isinstance(release.get("id"), int)
        or isinstance(release.get("id"), bool)
        or release["id"] < 1
        or release.get("url")
        != f"https://github.com/Latchway/latchway/releases/tag/{tag}"
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("published_at"), str)
        or UTC.fullmatch(release["published_at"]) is None
    ):
        raise ReportError("release_record_github_release_invalid")
    if publication.get("registries") != canonical_registries(repositories, expected_oci):
        raise ReportError("release_record_registry_coordinates_mismatch")


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
    durable_assets: Mapping[str, Path] | None = None,
) -> str:
    require_string(commit, COMMIT, "release_record_commit_invalid")
    require_string(tag, TAG, "release_record_tag_invalid")
    candidate = read_json(candidate_path)
    security = read_json(security_path)
    conformance = read_json(conformance_path)
    publication = read_json(publication_path)
    contract, image = validate_candidate(candidate, commit, tag)
    repositories, domains, checks = validate_conformance(
        conformance, commit, tag, contract, image
    )
    security_checks = validate_security(security, commit, tag, contract, image)
    validate_publication(publication, commit, tag, repositories, image)
    schema_version = database_schema_version(repository)
    oci = f"{image['repository']}@{image['index_digest']}"
    registries = publication["registries"]
    durable = durable_assets or {}
    if not durable or len(durable) > 16:
        raise ReportError("release_record_durable_assets_invalid")
    durable_hashes: list[tuple[str, str]] = []
    for name, path in sorted(durable.items()):
        if ASSET_NAME.fullmatch(name) is None or path.name != name:
            raise ReportError("release_record_durable_assets_invalid")
        durable_hashes.append((name, sha256_file(path)))

    lines = [
        f"# Latchway {tag} final release record",
        "",
        "> Status: **released and fully evidence-gated**. This immutable asset was rendered only after the public release and every required v1 evidence domain passed.",
        "",
        "## Release identity",
        "",
        "| Field | Exact value |",
        "| --- | --- |",
        f"| Core version | `{escape(tag[1:])}` |",
        f"| Core annotated tag | `{escape(tag)}` |",
        f"| Core commit | `{escape(commit)}` |",
        f"| Git tag object | `{escape(publication['tag_object_sha'])}` |",
        f"| GitHub release | [release {escape(tag)}]({escape(publication['github_release']['url'])}) (`{publication['github_release']['id']}`) |",
        f"| Published at | `{escape(publication['github_release']['published_at'])}` |",
        f"| OCI index | `{escape(oci)}` |",
        f"| Contract | `{escape(contract['version'])}` (`released`, wire `{escape(conformance['contract']['wire_protocol'])}`) |",
        f"| Contract bundle SHA-256 | `{escape(contract['bundle_sha256'])}` |",
        f"| Database schema | `{schema_version}` |",
        "",
        "## Exact repository coordinates",
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
            "## Published package coordinates",
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
            "## Multi-architecture image",
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
            "## Required release evidence",
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
            artifact_hashes = "<br>".join(
                f"`{item}`" for item in domain["artifact_sha256"]
            )
        lines.append(
            f"| `{escape(domain['id'])}` | `{escape(domain['status'])}` | {escape(window)} | `{escape(document_hash)}` | {artifact_hashes} |"
        )
    lines.extend(
        [
            "",
            "The operational-resilience proof above includes load targets, destructive failure injection, multi-replica behavior, backup/restore, and released-version upgrade/rollback. The mobile proofs include App Attest, Play Integrity, and React Native on physical iOS and Android distributions. The public registry proof binds every coordinate listed above to this candidate and OCI digest.",
            "",
            "## Automated security gate",
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
        lines.append(
            f"| `{escape(check['id'])}` | `{escape(check['status'])}` | `{escape(tool_value)}` |"
        )
    required_checks = [item for item in checks if item.get("required") is True]
    lines.extend(
        [
            "",
            f"All `{len(required_checks)}` required cross-repository checks and all `{len(security_checks)}` automated security checks passed. Security evidence covers source/static checks, race and fuzz gates, dependency and image vulnerability/license policy, SBOMs, signatures, and provenance as defined by the candidate-bound security report.",
            "",
            "## Candidate artifacts",
            "",
            "| Artifact | SHA-256 |",
            "| --- | --- |",
        ]
    )
    for artifact in candidate["artifacts"]:
        lines.append(
            f"| `{escape(artifact['path'])}` | `{escape(artifact['sha256'])}` |"
        )
    lines.extend(
        [
            "",
            "## Evidence provenance",
            "",
            "| Input document | SHA-256 |",
            "| --- | --- |",
            f"| Release candidate manifest | `{sha256_file(candidate_path)}` |",
            f"| Candidate security report | `{sha256_file(security_path)}` |",
            f"| Release-scope cross-repository report | `{sha256_file(conformance_path)}` |",
            f"| Verified public release state | `{sha256_file(publication_path)}` |",
            "",
            "The final report and its Sigstore bundle are release assets. The finalizer authenticates each producer workflow, exact run attempt, candidate commit, protected `main` ref, signer workflow identity, and public release state before rendering; reruns may add a missing asset but never replace different bytes.",
            "",
            "## Durable release evidence assets",
            "",
            "| Asset | SHA-256 |",
            "| --- | --- |",
        ]
    )
    lines.extend(
        f"| `{escape(name)}` | `{digest}` |" for name, digest in durable_hashes
    )
    lines.extend(
        [
            "",
            "These immutable no-clobber release assets retain the release-scope conformance report, its Sigstore bundle, the verified publication state, and the complete hash-bound external evidence tree beyond Actions artifact retention.",
            "",
        ]
    )
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--candidate", type=Path, required=True)
    result.add_argument("--security", type=Path, required=True)
    result.add_argument("--release-conformance", type=Path, required=True)
    result.add_argument("--publication-state", type=Path, required=True)
    result.add_argument("--repository", type=Path, required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--tag", required=True)
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
