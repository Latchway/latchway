#!/usr/bin/env python3
"""Evaluate an explicit Latchway release profile without weakening strict gates.

The strict cross-repository report remains the canonical source of local and
full-assurance status.  The single-maintainer profile is a narrower,
unauthenticated projection over that report and separately retained external
documents.  It can establish only profile-requirement satisfaction; it never
emits publication readiness or a release-qualified or independent-review claim.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / ".github/release-profiles.json"
CROSS_REPOSITORY_PATH = Path(__file__).with_name("cross-repo-conformance.py")
CROSS_REPOSITORY_SPEC = importlib.util.spec_from_file_location(
    "latchway_cross_repository_conformance", CROSS_REPOSITORY_PATH
)
if CROSS_REPOSITORY_SPEC is None or CROSS_REPOSITORY_SPEC.loader is None:
    raise RuntimeError("cross-repository verifier cannot be loaded")
CROSS = importlib.util.module_from_spec(CROSS_REPOSITORY_SPEC)
sys.modules[CROSS_REPOSITORY_SPEC.name] = CROSS
CROSS_REPOSITORY_SPEC.loader.exec_module(CROSS)

PROFILE_IDS = ("strict_full", "single_maintainer_v1")
LOCAL_DOMAINS = ("local_source", "local_promotion", "local_release")
SINGLE_MAINTAINER_REQUIRED_CLAIMS: Mapping[str, tuple[str, ...]] = {
    "public_tags": CROSS.EXTERNAL_DOMAINS["public_tags"],
    "public_registries": tuple(
        claim
        for claim in CROSS.EXTERNAL_DOMAINS["public_registries"]
        if claim != "documentation_production_verified"
    ),
    "cloud_deployments": ("compose_verified", "cloud_run_verified"),
    "supply_chain": CROSS.EXTERNAL_DOMAINS["supply_chain"],
}
SINGLE_MAINTAINER_DEFERRED = (
    "independent_human_review",
    "live_sdk_conformance",
    "physical_devices",
    "apple_distribution_and_extensions",
    "play_integrity_and_android_device",
    "firebase_app_check",
    "turnstile",
    "live_provider",
    "cloud_deployments.aws_verified",
    "cloud_deployments.fly_io_verified",
    "cloud_deployments.cloudflare_containers_verified",
    "operational_resilience",
    "public_registries.documentation_production_verified",
    "mintlify_production",
)
SINGLE_MAINTAINER_FORBIDDEN_CLAIMS = (
    "release_qualified",
    "fully_evidence_gated",
    "independently_reviewed",
)


class ProfileError(Exception):
    """A stable, redaction-safe profile failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def read_json(path: Path) -> dict[str, Any]:
    try:
        return CROSS.read_json(path)
    except CROSS.VerificationError as error:
        raise ProfileError(error.code) from error
    except OSError:
        raise ProfileError("json_document_unreadable") from None


def require_exact_fields(
    value: Any, expected: set[str], code: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProfileError(code)
    return value


def require_string_list(value: Any, code: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ProfileError(code)
    return value


def validate_profile_shape(identifier: str, value: Any) -> dict[str, Any]:
    profile = require_exact_fields(
        value,
        {
            "status_claim",
            "requires_independent_human_review",
            "required_local_domains",
            "required_external_claims",
            "deferred_evidence",
            "forbidden_claims",
        },
        "release_profile_fields_invalid",
    )
    if not isinstance(profile["status_claim"], str) or not profile["status_claim"]:
        raise ProfileError("release_profile_status_claim_invalid")
    if not isinstance(profile["requires_independent_human_review"], bool):
        raise ProfileError("release_profile_review_policy_invalid")
    local = require_string_list(
        profile["required_local_domains"], "release_profile_local_domains_invalid"
    )
    if tuple(local) != LOCAL_DOMAINS:
        raise ProfileError("release_profile_local_domains_invalid")
    external = profile["required_external_claims"]
    if not isinstance(external, dict) or not external:
        raise ProfileError("release_profile_external_claims_invalid")
    for domain, claims in external.items():
        if domain not in CROSS.EXTERNAL_DOMAINS:
            raise ProfileError("release_profile_external_domain_invalid")
        required = require_string_list(
            claims, "release_profile_external_claims_invalid"
        )
        allowed = CROSS.EXTERNAL_DOMAINS[domain]
        if any(claim not in allowed for claim in required):
            raise ProfileError("release_profile_external_claim_invalid")
    require_string_list(
        profile["deferred_evidence"], "release_profile_deferred_evidence_invalid"
    )
    require_string_list(
        profile["forbidden_claims"], "release_profile_forbidden_claims_invalid"
    )
    if identifier not in PROFILE_IDS:
        raise ProfileError("release_profile_identifier_invalid")
    return profile


def validate_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    policy = require_exact_fields(
        read_json(path),
        {"$schema", "schema_version", "kind", "default_profile", "profiles"},
        "release_profile_policy_fields_invalid",
    )
    if (
        policy["$schema"] != "./release-profiles.schema.json"
        or policy["schema_version"] != 1
        or policy["kind"] != "latchway_release_profiles"
        or policy["default_profile"] != "strict_full"
    ):
        raise ProfileError("release_profile_policy_identity_invalid")
    profiles = policy["profiles"]
    if not isinstance(profiles, dict) or tuple(profiles) != PROFILE_IDS:
        raise ProfileError("release_profile_set_invalid")
    strict = validate_profile_shape("strict_full", profiles["strict_full"])
    single = validate_profile_shape(
        "single_maintainer_v1", profiles["single_maintainer_v1"]
    )

    expected_strict = {
        domain: list(claims) for domain, claims in CROSS.EXTERNAL_DOMAINS.items()
    }
    expected_single = {
        domain: list(claims)
        for domain, claims in SINGLE_MAINTAINER_REQUIRED_CLAIMS.items()
    }
    if (
        strict["status_claim"] != "strict_cross_repository_release_ready"
        or strict["requires_independent_human_review"] is not True
        or strict["required_external_claims"] != expected_strict
        or strict["deferred_evidence"] != []
        or strict["forbidden_claims"] != []
    ):
        raise ProfileError("strict_full_profile_weakened")
    if (
        single["status_claim"]
        != "v1_profile_projection_passed_with_deferred_assurance"
        or single["requires_independent_human_review"] is not False
        or single["required_external_claims"] != expected_single
        or tuple(single["deferred_evidence"]) != SINGLE_MAINTAINER_DEFERRED
        or tuple(single["forbidden_claims"])
        != SINGLE_MAINTAINER_FORBIDDEN_CLAIMS
    ):
        raise ProfileError("single_maintainer_v1_profile_invalid")
    return policy


def domain_index(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    domains = report.get("evidence_domains")
    if not isinstance(domains, list):
        raise ProfileError("release_report_domains_invalid")
    result: dict[str, Mapping[str, Any]] = {}
    for item in domains:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ProfileError("release_report_domains_invalid")
        identifier = item["id"]
        if identifier in result:
            raise ProfileError("release_report_domain_duplicate")
        result[identifier] = item
    return result


def release_coordinates(report: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    repositories = report.get("repositories")
    if not isinstance(repositories, list):
        raise ProfileError("release_report_repositories_invalid")
    result: dict[str, dict[str, str]] = {}
    for item in repositories:
        if not isinstance(item, dict):
            raise ProfileError("release_report_repositories_invalid")
        identifier = item.get("id")
        commit = item.get("commit")
        version = item.get("version")
        tag = item.get("intended_tag")
        if (
            not isinstance(identifier, str)
            or identifier in result
            or not isinstance(commit, str)
            or CROSS.COMMIT.fullmatch(commit) is None
            or not isinstance(version, str)
            or CROSS.SEMVER.fullmatch(version) is None
            or not isinstance(tag, str)
            or CROSS.RELEASE_TAG.fullmatch(tag) is None
            or tag != f"v{version}"
        ):
            raise ProfileError("release_report_repositories_invalid")
        result[identifier] = {"commit": commit, "tag": tag, "version": version}
    if set(result) != set(CROSS.REPOSITORY_IDS):
        raise ProfileError("release_report_repositories_invalid")
    return result


def validate_release_report(report: Mapping[str, Any]) -> None:
    try:
        CROSS.validate_release_report(report, ROOT / "api/release-evidence.schema.json")
    except CROSS.VerificationError as error:
        raise ProfileError(error.code) from error
    if report.get("scope") != "release":
        raise ProfileError("release_profile_requires_release_scope_report")


def gate(
    identifier: str,
    status_value: str,
    source: str,
    reason: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "status": status_value,
        "source": source,
    }
    if reason is not None:
        result["reason"] = reason
    if details:
        result["details"] = dict(details)
    return result


def report_domain_gate(
    identifier: str, domains: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    observed = domains.get(identifier)
    if observed is None:
        return gate(
            identifier,
            "unverified",
            "cross_repository_release_report",
            "release_report_domain_missing",
        )
    status_value = observed.get("status")
    if status_value == "passed":
        return gate(identifier, "passed", "cross_repository_release_report")
    if status_value == "failed":
        return gate(
            identifier,
            "failed",
            "cross_repository_release_report",
            "release_report_domain_failed",
        )
    return gate(
        identifier,
        "unverified",
        "cross_repository_release_report",
        "release_report_domain_unverified",
    )


def validate_profile_document(
    domain: str,
    required_claims: list[str],
    evidence_root: Path | None,
    coordinates: Mapping[str, Mapping[str, str]],
    contract: Mapping[str, Any],
    evaluation_time: datetime,
) -> tuple[dict[str, Any], Mapping[str, Any] | None]:
    if evidence_root is None:
        return (
            gate(
                domain,
                "unverified",
                "external_evidence_document",
                "external_evidence_directory_not_supplied",
            ),
            None,
        )
    try:
        metadata = evidence_root.lstat()
    except OSError:
        return (
            gate(
                domain,
                "unverified",
                "external_evidence_document",
                "external_evidence_directory_missing",
            ),
            None,
        )
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return (
            gate(
                domain,
                "failed",
                "external_evidence_document",
                "external_evidence_directory_unsafe",
            ),
            None,
        )
    document_path = evidence_root / f"{domain}.json"
    if not document_path.exists():
        return (
            gate(
                domain,
                "unverified",
                "external_evidence_document",
                "external_evidence_missing",
            ),
            None,
        )
    try:
        document = CROSS.read_json(
            document_path, maximum_bytes=CROSS.MAX_EVIDENCE_BYTES
        )
        claims = document.get("claims")
        if not isinstance(claims, dict):
            raise CROSS.VerificationError("external_evidence_claims_invalid")
        actual_claims = set(claims)
        required = set(required_claims)
        allowed = set(CROSS.EXTERNAL_DOMAINS[domain])
        if not required.issubset(actual_claims):
            raise CROSS.VerificationError(
                "release_profile_required_claim_missing"
            )
        if not actual_claims.issubset(allowed):
            raise CROSS.VerificationError("external_evidence_claims_invalid")
        ordered_claims = tuple(
            claim
            for claim in CROSS.EXTERNAL_DOMAINS[domain]
            if claim in actual_claims
        )
        released_at = CROSS.parse_timestamp(
            contract.get("released_at"), "contract_released_at_invalid"
        )
        details = CROSS.validate_external_document(
            evidence_root.resolve(strict=True),
            document_path,
            domain,
            ordered_claims,
            coordinates,
            str(contract.get("version")),
            str(contract.get("bundle_sha256")),
            coordinates["core"]["commit"],
            coordinates["core"]["tag"],
            released_at,
            evaluation_time,
            str(contract.get("oci_image_digest")),
        )
    except CROSS.VerificationError as error:
        return (
            gate(
                domain,
                "failed",
                "external_evidence_document",
                error.code,
            ),
            None,
        )
    except OSError:
        return (
            gate(
                domain,
                "failed",
                "external_evidence_document",
                "external_evidence_read_failed",
            ),
            None,
        )
    gate_details = {
        "required_claims": required_claims,
        "observed_claims": list(ordered_claims),
        "document_sha256": details["document_sha256"],
        "artifact_sha256": details["artifact_sha256"],
    }
    return gate(domain, "passed", "external_evidence_document", details=gate_details), details


def evaluate(
    profile_id: str,
    release_report_path: Path,
    external_evidence_dir: Path | None,
    evaluation_time: datetime,
    policy_path: Path = DEFAULT_POLICY,
) -> dict[str, Any]:
    policy = validate_policy(policy_path)
    if profile_id not in PROFILE_IDS:
        raise ProfileError("release_profile_identifier_invalid")
    report = read_json(release_report_path)
    validate_release_report(report)
    domains = domain_index(report)
    coordinates = release_coordinates(report)
    contract = report.get("contract")
    if not isinstance(contract, dict):
        raise ProfileError("release_report_contract_invalid")
    if (
        contract.get("status") != "released"
        or not isinstance(contract.get("version"), str)
        or not isinstance(contract.get("bundle_sha256"), str)
        or not isinstance(contract.get("released_at"), str)
        or not isinstance(contract.get("oci_image_digest"), str)
    ):
        raise ProfileError("release_report_contract_invalid")

    profile = policy["profiles"][profile_id]
    required_gates = [
        report_domain_gate(identifier, domains)
        for identifier in profile["required_local_domains"]
    ]
    if report.get("source_conformance_passed") is not True:
        required_gates.append(
            gate(
                "source_conformance_passed",
                "failed",
                "cross_repository_release_report",
                "source_conformance_not_passed",
            )
        )
    else:
        required_gates.append(
            gate(
                "source_conformance_passed",
                "passed",
                "cross_repository_release_report",
            )
        )

    verified_documents: list[Mapping[str, Any]] = []
    if profile_id == "strict_full":
        for identifier in profile["required_external_claims"]:
            required_gates.append(report_domain_gate(identifier, domains))
        canonical_ready = (
            report.get("verdict") == "passed"
            and report.get("promotion_ready") is True
            and report.get("release_ready") is True
        )
        required_gates.append(
            gate(
                "canonical_release_ready",
                "passed" if canonical_ready else "unverified",
                "cross_repository_release_report",
                None if canonical_ready else "canonical_release_not_ready",
            )
        )
    else:
        evidence_root = (
            external_evidence_dir.absolute()
            if external_evidence_dir is not None
            else None
        )
        for domain, claims in profile["required_external_claims"].items():
            result, verified = validate_profile_document(
                domain,
                claims,
                evidence_root,
                coordinates,
                contract,
                evaluation_time,
            )
            required_gates.append(result)
            if verified is not None:
                verified_documents.append(verified)
        external_passed = len(verified_documents) == len(
            profile["required_external_claims"]
        )
        if external_passed:
            started = [
                CROSS.parse_timestamp(
                    item["started_at"], "external_evidence_time_invalid"
                )
                for item in verified_documents
            ]
            finished = [
                CROSS.parse_timestamp(
                    item["finished_at"], "external_evidence_time_invalid"
                )
                for item in verified_documents
            ]
            earliest = min(started)
            latest = max(finished)
            window_passed = latest - earliest <= CROSS.MAXIMUM_EVIDENCE_AGE
            required_gates.append(
                gate(
                    "required_evidence_window",
                    "passed" if window_passed else "failed",
                    "external_evidence_documents",
                    None
                    if window_passed
                    else "external_evidence_window_too_wide",
                    {
                        "started_at": CROSS.format_timestamp(earliest),
                        "finished_at": CROSS.format_timestamp(latest),
                        "maximum_age_seconds": CROSS.MAXIMUM_EVIDENCE_SECONDS,
                    },
                )
            )
        else:
            required_gates.append(
                gate(
                    "required_evidence_window",
                    "unverified",
                    "external_evidence_documents",
                    "prerequisite_evidence_failed",
                )
            )

    passed = all(item["status"] == "passed" for item in required_gates)
    deferred = [
        gate(
            identifier,
            "unverified",
            "release_profile_policy",
            "deferred_by_profile",
        )
        for identifier in profile["deferred_evidence"]
    ]
    core = coordinates["core"]
    return {
        "schema_version": 1,
        "kind": "latchway_release_profile_evaluation",
        "evaluation_scope": "cross_repository_publication_profile",
        "profile": profile_id,
        "status": "passed" if passed else "failed",
        "status_claim": profile["status_claim"] if passed else None,
        "profile_requirements_satisfied": passed,
        "authentication_status": "not_performed",
        "publication_ready": False,
        "strict_cross_repository_ready": report.get("release_ready") is True,
        "release_qualified": False,
        "requires_independent_human_review": profile[
            "requires_independent_human_review"
        ],
        "candidate": {
            "core_commit": core["commit"],
            "release_tag": core["tag"],
            "oci_image_digest": contract["oci_image_digest"],
        },
        "required_gates": required_gates,
        "deferred_evidence": deferred,
        "forbidden_claims": profile["forbidden_claims"],
    }


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
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise ProfileError("release_profile_output_write_failed") from None


def parse_evaluation_time(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    try:
        return CROSS.parse_timestamp(value, "evaluation_time_invalid")
    except CROSS.VerificationError as error:
        raise ProfileError(error.code) from error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    subcommands = result.add_subparsers(dest="command", required=True)
    subcommands.add_parser("validate-policy", help="validate the fixed profile policy")
    evaluator = subcommands.add_parser(
        "evaluate", help="project an exact release report through one profile"
    )
    evaluator.add_argument("--profile", choices=PROFILE_IDS, required=True)
    evaluator.add_argument("--release-report", type=Path, required=True)
    evaluator.add_argument("--external-evidence-dir", type=Path)
    evaluator.add_argument("--evaluation-time")
    evaluator.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "validate-policy":
            validate_policy(arguments.policy)
            print("release profile policy passed")
            return 0
        report = evaluate(
            arguments.profile,
            arguments.release_report.absolute(),
            arguments.external_evidence_dir,
            parse_evaluation_time(arguments.evaluation_time),
            arguments.policy,
        )
        write_json(arguments.output.absolute(), report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    except ProfileError as error:
        print(f"release profile failed: {error.code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
