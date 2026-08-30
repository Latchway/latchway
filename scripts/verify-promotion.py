#!/usr/bin/env python3
"""Bind an attested promotion report to the exact immutable OCI candidate."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


COMMIT = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(
    r"^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
DIGEST = re.compile(r"^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REPOSITORIES = ("core", "javascript", "ios", "android", "react_native")
PROMOTION_DOMAINS = {
    "live_sdk_conformance",
    "physical_devices",
    "live_provider",
    "cloud_deployments",
    "operational_resilience",
    "supply_chain",
}
MAXIMUM_AGE = timedelta(days=7)


class PromotionError(Exception):
    """A stable, redaction-safe promotion verification failure."""


def load_json(path: Path) -> dict[str, Any]:
    def strict(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PromotionError("promotion_json_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict
        )
    except PromotionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise PromotionError("promotion_json_invalid") from None
    if not isinstance(value, dict):
        raise PromotionError("promotion_json_invalid")
    return value


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise PromotionError("promotion_time_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise PromotionError("promotion_time_invalid") from None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise PromotionError("promotion_report_unreadable") from None
    return digest.hexdigest()


def verify(
    report_path: Path,
    candidate_path: Path,
    *,
    expected_commit: str,
    expected_tag: str,
    now: datetime,
) -> dict[str, str]:
    if COMMIT.fullmatch(expected_commit) is None or TAG.fullmatch(expected_tag) is None:
        raise PromotionError("promotion_expected_coordinate_invalid")
    report = load_json(report_path)
    candidate = load_json(candidate_path)
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
        "evidence_window",
        "evidence_domains",
        "checks",
    }:
        raise PromotionError("promotion_report_fields_invalid")
    if (
        report.get("schema_version") != 1
        or report.get("kind") != "latchway_cross_repository_conformance_evidence"
        or report.get("scope") != "promotion"
        or report.get("verdict") != "passed"
        or report.get("source_conformance_passed") is not True
        or report.get("promotion_ready") is not True
        or report.get("release_ready") is not False
    ):
        raise PromotionError("promotion_report_not_ready")
    if (
        candidate.get("schema_version") != 1
        or candidate.get("kind") != "latchway_release_candidate"
        or candidate.get("status") != "passed"
        or candidate.get("candidate_commit") != expected_commit
        or candidate.get("intended_tag") != expected_tag
    ):
        raise PromotionError("promotion_candidate_identity_mismatch")

    candidate_image = candidate.get("image")
    if not isinstance(candidate_image, dict):
        raise PromotionError("promotion_candidate_image_invalid")
    image_repository = candidate_image.get("repository")
    index_digest = candidate_image.get("index_digest")
    image_digest = f"{image_repository}@{index_digest}"
    if not isinstance(image_repository, str) or not isinstance(index_digest, str) or DIGEST.fullmatch(image_digest) is None:
        raise PromotionError("promotion_candidate_image_invalid")

    contract = report.get("contract")
    candidate_contract = candidate.get("contract")
    contract_fields = {
        "version",
        "status",
        "released_at",
        "wire_protocol",
        "bundle_file_name",
        "bundle_sha256",
        "core_release",
        "oci_image_digest",
    }
    candidate_contract_fields = {
        "version",
        "status",
        "released_at",
        "bundle_file_name",
        "bundle_sha256",
    }
    if (
        not isinstance(contract, dict)
        or set(contract) != contract_fields
        or not isinstance(candidate_contract, dict)
        or set(candidate_contract) != candidate_contract_fields
    ):
        raise PromotionError("promotion_contract_invalid")
    for field in candidate_contract_fields:
        if contract.get(field) != candidate_contract.get(field):
            raise PromotionError("promotion_contract_candidate_mismatch")
    if (
        contract.get("status") != "released"
        or contract.get("core_release") != expected_tag
        or contract.get("oci_image_digest") != image_digest
        or not isinstance(contract.get("wire_protocol"), int)
        or isinstance(contract.get("wire_protocol"), bool)
        or contract["wire_protocol"] < 1
    ):
        raise PromotionError("promotion_contract_invalid")

    released_at = parse_time(contract.get("released_at"))
    if released_at > now or now - released_at > MAXIMUM_AGE:
        raise PromotionError("promotion_contract_time_invalid")
    repositories = report.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != len(REPOSITORIES):
        raise PromotionError("promotion_repositories_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for repository in repositories:
        if not isinstance(repository, dict) or set(repository) != {
            "id",
            "commit",
            "version",
            "intended_tag",
        }:
            raise PromotionError("promotion_repositories_invalid")
        repository_id = repository.get("id")
        commit = repository.get("commit")
        version = repository.get("version")
        tag = repository.get("intended_tag")
        if (
            repository_id not in REPOSITORIES
            or repository_id in by_id
            or not isinstance(commit, str)
            or COMMIT.fullmatch(commit) is None
            or not isinstance(version, str)
            or tag != f"v{version}"
            or TAG.fullmatch(tag) is None
        ):
            raise PromotionError("promotion_repositories_invalid")
        by_id[repository_id] = repository
    if set(by_id) != set(REPOSITORIES):
        raise PromotionError("promotion_repositories_invalid")
    if (
        by_id["core"]["commit"] != expected_commit
        or by_id["core"]["intended_tag"] != expected_tag
        or by_id["core"]["version"] != candidate.get("version")
    ):
        raise PromotionError("promotion_core_coordinate_mismatch")

    evidence_window = report.get("evidence_window")
    if not isinstance(evidence_window, dict) or set(evidence_window) != {
        "started_at",
        "finished_at",
        "maximum_age_seconds",
    }:
        raise PromotionError("promotion_evidence_window_invalid")
    started = parse_time(evidence_window.get("started_at"))
    finished = parse_time(evidence_window.get("finished_at"))
    if (
        evidence_window.get("maximum_age_seconds") != int(MAXIMUM_AGE.total_seconds())
        or started < released_at
        or finished <= started
        or finished > now
        or now - finished > MAXIMUM_AGE
        or finished - started > MAXIMUM_AGE
    ):
        raise PromotionError("promotion_evidence_window_invalid")

    domains = report.get("evidence_domains")
    if not isinstance(domains, list):
        raise PromotionError("promotion_domains_invalid")
    passed_domains = {
        domain.get("id")
        for domain in domains
        if isinstance(domain, dict)
        and domain.get("required") is True
        and domain.get("status") == "passed"
    }
    if not PROMOTION_DOMAINS.issubset(passed_domains):
        raise PromotionError("promotion_domains_incomplete")
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        raise PromotionError("promotion_checks_invalid")
    if any(
        not isinstance(check, dict)
        or (check.get("required") is True and check.get("status") != "passed")
        for check in checks
    ):
        raise PromotionError("promotion_required_check_failed")

    return {
        "report_sha256": sha256_file(report_path),
        "candidate_sha256": sha256_file(candidate_path),
        "image": image_repository,
        "oci_image_digest": image_digest,
        "index_digest": index_digest,
        "core_tag": expected_tag,
        "core_version": expected_tag[1:],
        **{
            f"{repository_id}_{field}": str(by_id[repository_id][field])
            for repository_id in REPOSITORIES
            for field in ("commit", "version", "intended_tag")
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--github-output", type=Path)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        result = verify(
            arguments.report,
            arguments.candidate,
            expected_commit=arguments.commit,
            expected_tag=arguments.tag,
            now=datetime.now(timezone.utc).replace(microsecond=0),
        )
        if arguments.github_output is not None:
            with arguments.github_output.open("a", encoding="utf-8") as output:
                for key in sorted(result):
                    value = result[key]
                    if "\n" in value or "\r" in value:
                        raise PromotionError("promotion_output_invalid")
                    output.write(f"{key}={value}\n")
    except (PromotionError, OSError) as error:
        code = str(error) if isinstance(error, PromotionError) else "promotion_output_failed"
        print(f"promotion verification failed: {code}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
