#!/usr/bin/env python3
"""Validate the canonical framework case manifest and repository evidence reports."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "conformance/framework-cases.json"
DEFAULT_REGISTRY = ROOT / "compatibility/frameworks.yaml"
CASE_ID = re.compile(r"^FW-[A-Z]+-[0-9]{3}$")
INTEGRATION_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
REPOSITORY = re.compile(r"^latchway(?:-[a-z0-9-]+)?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CATEGORIES = {
    "authentication", "request", "behavior", "security", "openai", "vercel-ai", "langchain",
}
ECOSYSTEM_REPOSITORY = {
    "android": "latchway-android",
    "apple": "latchway-ios-sdk",
    "javascript": "latchway-js",
    "react_native": "latchway-react-native-sdk",
}
CAPABILITY_CASES = {
    "responses": "FW-REQ-001",
    "chat_completions": "FW-REQ-002",
    "embeddings": "FW-REQ-003",
    "streaming": "FW-REQ-005",
    "cancellation": "FW-REQ-006",
    "tools": "FW-BEH-001",
    "structured_output": "FW-BEH-002",
}
COMMON_CAPABILITY_CASES = {
    "cancellation": ("FW-REQ-105",),
    "streaming": ("FW-REQ-108", "FW-REQ-109"),
    "tools": ("FW-BEH-101",),
    "structured_output": ("FW-BEH-102",),
}
SUPPORT_STATES = {"supported", "experimental", "unsupported"}
NOT_APPLICABLE_POLICIES = {"forbidden", "evidence_required"}
PENDING_BLOCKERS = {"local", "hosted", "protected_device", "upstream"}


class ConformanceError(ValueError):
    """A framework conformance manifest or report is invalid."""


def _load_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ConformanceError(f"{path}: duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as error:
        raise ConformanceError(f"cannot load {path}: {error}") from error


def _exact(value: Any, keys: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ConformanceError(f"{location} must contain exactly {sorted(keys)}")
    return value


def load_manifest(path: Path) -> tuple[list[dict[str, str]], str]:
    raw = path.read_bytes()
    loaded = _load_json(path)
    if not isinstance(loaded, dict) or type(loaded.get("schema_version")) is not int:
        raise ConformanceError("manifest.schema_version must be an integer")
    schema_version = loaded["schema_version"]
    if schema_version == 1:
        root = _exact(loaded, {"schema_version", "cases"}, "manifest")
        suite_policies: dict[str, str] = {}
    elif schema_version == 2:
        root = _exact(loaded, {"schema_version", "suites", "cases"}, "manifest")
        suites = _exact(root["suites"], {"addendum_common_v1"}, "manifest.suites")
        common = suites["addendum_common_v1"]
        if not isinstance(common, list) or not common:
            raise ConformanceError("manifest.suites.addendum_common_v1 must be a nonempty array")
        suite_policies = {}
        for index, candidate in enumerate(common):
            item = _exact(
                candidate,
                {"case_id", "not_applicable"},
                f"manifest.suites.addendum_common_v1[{index}]",
            )
            case_id, policy = item["case_id"], item["not_applicable"]
            if (not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None
                    or case_id in suite_policies):
                raise ConformanceError("manifest addendum suite contains an invalid or duplicated case")
            if policy not in NOT_APPLICABLE_POLICIES:
                raise ConformanceError(f"manifest addendum case {case_id} has an invalid N/A policy")
            suite_policies[case_id] = policy
    else:
        raise ConformanceError("manifest.schema_version must be integer 1 or 2")
    cases = root["cases"]
    if not isinstance(cases, list) or not cases:
        raise ConformanceError("manifest.cases must be a nonempty array")
    validated: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, candidate in enumerate(cases):
        item = _exact(candidate, {"id", "category", "title"}, f"manifest.cases[{index}]")
        case_id, category, title = item["id"], item["category"], item["title"]
        if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None or case_id in seen:
            raise ConformanceError(f"manifest.cases[{index}].id is invalid or duplicated")
        if category not in CATEGORIES:
            raise ConformanceError(f"manifest.cases[{index}].category is invalid")
        if not isinstance(title, str) or not title.strip() or title != title.strip() or len(title) > 160:
            raise ConformanceError(f"manifest.cases[{index}].title is invalid")
        seen.add(case_id)
        validated.append({
            "id": case_id,
            "category": category,
            "title": title,
            **({"common_not_applicable": suite_policies[case_id]} if case_id in suite_policies else {}),
        })
    missing_suite_cases = sorted(set(suite_policies) - seen)
    if missing_suite_cases:
        raise ConformanceError(f"manifest addendum suite names missing cases: {missing_suite_cases}")
    return validated, hashlib.sha256(raw).hexdigest()


def load_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Read only the closed registry fields used by this source gate.

    The parser intentionally accepts the repository's simple, indentation-bound
    YAML subset so validation has no package-manager or PyYAML dependency.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ConformanceError(f"cannot load {path}: {error}") from error
    rows: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    in_capabilities = False
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"  - id: ([a-z][a-z0-9-]{1,63})", line)
        if match:
            integration_id = match.group(1)
            if integration_id in rows:
                raise ConformanceError(f"{path}:{line_number}: duplicate framework id")
            current = {"id": integration_id, "capabilities": {}}
            rows[integration_id] = current
            in_capabilities = False
            continue
        if current is None:
            continue
        field = re.fullmatch(r"    (ecosystem|support): ([a-z][a-z0-9_]*)", line)
        if field:
            current[field.group(1)] = field.group(2)
            in_capabilities = False
            continue
        if line == "    capabilities:":
            in_capabilities = True
            continue
        if re.match(r"^    [a-z_]", line):
            in_capabilities = False
        if in_capabilities:
            capability = re.fullmatch(r"      ([a-z_]+): (true|false|conditional)", line)
            if capability:
                raw_value = capability.group(2)
                value: bool | str = raw_value == "true" if raw_value != "conditional" else raw_value
                current["capabilities"][capability.group(1)] = value
    if not rows:
        raise ConformanceError(f"{path}: framework registry is empty")
    for integration_id, row in rows.items():
        if row.get("ecosystem") not in ECOSYSTEM_REPOSITORY:
            raise ConformanceError(f"{path}: {integration_id} has an unknown ecosystem")
        if row.get("support") not in SUPPORT_STATES:
            raise ConformanceError(f"{path}: {integration_id} has an invalid support state")
        row["repository"] = ECOSYSTEM_REPOSITORY[row["ecosystem"]]
    return rows


def validate_report(
    path: Path,
    cases: list[dict[str, str]],
    digest: str,
    registry: dict[str, dict[str, Any]] | None = None,
) -> tuple[str, set[str]]:
    root = _exact(
        _load_json(path),
        {"schema_version", "manifest_sha256", "repository", "integrations"},
        f"report {path}",
    )
    common_policies = {
        item["id"]: item["common_not_applicable"]
        for item in cases if "common_not_applicable" in item
    }
    expected_report_version = 2 if common_policies else 1
    if root["schema_version"] != expected_report_version or type(root["schema_version"]) is not int:
        raise ConformanceError(f"{path}: schema_version must be integer {expected_report_version}")
    if root["manifest_sha256"] != digest or SHA256.fullmatch(str(root["manifest_sha256"])) is None:
        raise ConformanceError(f"{path}: manifest_sha256 does not bind the canonical manifest bytes")
    if not isinstance(root["repository"], str) or REPOSITORY.fullmatch(root["repository"]) is None:
        raise ConformanceError(f"{path}: repository is invalid")
    integrations = root["integrations"]
    if not isinstance(integrations, list) or not integrations:
        raise ConformanceError(f"{path}: integrations must be a nonempty array")
    expected_ids = [item["id"] for item in cases]
    seen_integrations: set[str] = set()
    repository_root = path.parent.parent
    for index, candidate in enumerate(integrations):
        location = f"{path}: integrations[{index}]"
        required = {"id", "support", "pass", "not_applicable"}
        if common_policies:
            required.add("pending")
        allowed = required | {"unsupported_evidence"}
        if not isinstance(candidate, dict) or not required.issubset(candidate) or not set(candidate).issubset(allowed):
            raise ConformanceError(f"{location} must contain {sorted(required)} and only {sorted(allowed)}")
        item = candidate
        integration_id = item["id"]
        if (not isinstance(integration_id, str) or INTEGRATION_ID.fullmatch(integration_id) is None
                or integration_id in seen_integrations):
            raise ConformanceError(f"{path}: integration id is invalid or duplicated")
        if item["support"] not in SUPPORT_STATES:
            raise ConformanceError(f"{path}: {integration_id} support is invalid")
        registry_row: dict[str, Any] | None = None
        if registry is not None:
            registry_row = registry.get(integration_id)
            if registry_row is None:
                raise ConformanceError(f"{path}: {integration_id} is not in compatibility/frameworks.yaml")
            if registry_row["support"] != item["support"]:
                raise ConformanceError(f"{path}: {integration_id} support disagrees with the registry")
            if registry_row["repository"] != root["repository"]:
                raise ConformanceError(
                    f"{path}: {integration_id} belongs to {registry_row['repository']}, not {root['repository']}"
                )
        unsupported_evidence = item.get("unsupported_evidence")
        if item["support"] == "unsupported":
            if not isinstance(unsupported_evidence, list) or not unsupported_evidence:
                raise ConformanceError(f"{path}: {integration_id}.unsupported_evidence must be nonempty")
            for reference in unsupported_evidence:
                _validate_evidence_reference(reference, repository_root, f"{path}: {integration_id}")
        elif unsupported_evidence is not None:
            raise ConformanceError(f"{path}: non-unsupported integration {integration_id} cannot have unsupported evidence")
        observed_ids: list[str] = []
        passed = item["pass"]
        if not isinstance(passed, dict):
            raise ConformanceError(f"{path}: {integration_id}.pass must be an object")
        for case_id, evidence in passed.items():
            location = f"{path}: {integration_id}.pass[{case_id!r}]"
            if case_id not in expected_ids:
                raise ConformanceError(f"{location} is not a canonical case")
            if not isinstance(evidence, list) or not evidence:
                raise ConformanceError(f"{location} evidence must be nonempty")
            for reference in evidence:
                if not isinstance(reference, str) or not reference or len(reference) > 300:
                    raise ConformanceError(f"{location} contains an invalid evidence reference")
                _validate_evidence_reference(
                    reference,
                    repository_root,
                    location,
                    require_fragment=True,
                    exact_case_id=case_id if case_id in common_policies else None,
                )
            observed_ids.append(case_id)

        not_applicable = item["not_applicable"]
        if not isinstance(not_applicable, list):
            raise ConformanceError(f"{path}: {integration_id}.not_applicable must be an array")
        not_applicable_evidence: dict[str, list[str]] = {}
        for group_index, group_candidate in enumerate(not_applicable):
            location = f"{path}: {integration_id}.not_applicable[{group_index}]"
            required_group = {"case_ids", "reason"}
            if (not isinstance(group_candidate, dict) or not required_group.issubset(group_candidate)
                    or not set(group_candidate).issubset(required_group | {"evidence"})):
                raise ConformanceError(f"{location} must contain case_ids/reason and optional evidence")
            group = group_candidate
            case_ids, reason = group["case_ids"], group["reason"]
            if not isinstance(case_ids, list) or not case_ids:
                raise ConformanceError(f"{location}.case_ids must be nonempty")
            for case_id in case_ids:
                if not isinstance(case_id, str) or case_id not in expected_ids:
                    raise ConformanceError(f"{location} contains a noncanonical case")
                observed_ids.append(case_id)
            if not isinstance(reason, str) or not reason.strip() or reason != reason.strip() or len(reason) > 300:
                raise ConformanceError(f"{location}.reason is invalid")
            evidence = group.get("evidence", [])
            if not isinstance(evidence, list):
                raise ConformanceError(f"{location}.evidence must be an array")
            for reference in evidence:
                _validate_evidence_reference(reference, repository_root, location)
            for case_id in case_ids:
                policy = common_policies.get(case_id)
                if policy == "forbidden":
                    raise ConformanceError(
                        f"{path}: {integration_id} cannot mark required common case {case_id} not applicable"
                    )
                if policy == "evidence_required" and not evidence:
                    raise ConformanceError(
                        f"{path}: {integration_id} N/A common case {case_id} requires bounded evidence"
                    )
                not_applicable_evidence[case_id] = evidence

        pending = item.get("pending", [])
        if not isinstance(pending, list):
            raise ConformanceError(f"{path}: {integration_id}.pending must be an array")
        pending_ids: set[str] = set()
        for group_index, group_candidate in enumerate(pending):
            location = f"{path}: {integration_id}.pending[{group_index}]"
            group = _exact(group_candidate, {"case_ids", "reason", "blocker", "evidence"}, location)
            case_ids, reason = group["case_ids"], group["reason"]
            if not isinstance(case_ids, list) or not case_ids:
                raise ConformanceError(f"{location}.case_ids must be nonempty")
            if not isinstance(reason, str) or not reason.strip() or reason != reason.strip() or len(reason) > 300:
                raise ConformanceError(f"{location}.reason is invalid")
            if group["blocker"] not in PENDING_BLOCKERS:
                raise ConformanceError(f"{location}.blocker is invalid")
            evidence = group["evidence"]
            if not isinstance(evidence, list) or not evidence:
                raise ConformanceError(f"{location}.evidence must be nonempty")
            for reference in evidence:
                _validate_evidence_reference(reference, repository_root, location)
            for case_id in case_ids:
                if case_id not in expected_ids or case_id not in common_policies or case_id in pending_ids:
                    raise ConformanceError(f"{location} contains an invalid, non-common, or duplicated case")
                pending_ids.add(case_id)
                observed_ids.append(case_id)
        if item["support"] == "supported" and pending_ids:
            raise ConformanceError(f"{path}: supported integration {integration_id} cannot contain pending cases")

        if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(expected_ids):
            missing = sorted(set(expected_ids) - set(observed_ids))
            duplicated = sorted({case_id for case_id in observed_ids if observed_ids.count(case_id) > 1})
            raise ConformanceError(
                f"{path}: {integration_id} must cover every canonical case exactly once; "
                f"missing={missing}; duplicated={duplicated}"
            )
        if registry_row is not None and common_policies:
            capabilities = registry_row["capabilities"]
            for capability, case_ids in COMMON_CAPABILITY_CASES.items():
                claim = capabilities.get(capability, False)
                if claim is True:
                    for case_id in case_ids:
                        if case_id in not_applicable_evidence:
                            raise ConformanceError(
                                f"{path}: {integration_id} claims {capability}=true and cannot mark "
                                f"common case {case_id} not applicable"
                            )
            if (registry_row["ecosystem"] in {"apple", "android", "react_native"}
                    and "FW-SEC-105" in not_applicable_evidence):
                raise ConformanceError(
                    f"{path}: native integration {integration_id} cannot mark FW-SEC-105 not applicable"
                )
            if integration_id == "react-native-fetch" and "FW-SEC-106" in not_applicable_evidence:
                raise ConformanceError(
                    f"{path}: react-native-fetch cannot mark FW-SEC-106 not applicable"
                )
        seen_integrations.add(integration_id)
        if registry_row is not None:
            capabilities = registry_row["capabilities"]
            for capability, case_id in CAPABILITY_CASES.items():
                if case_id not in expected_ids:
                    continue
                claim = capabilities.get(capability, False)
                if claim is True and case_id not in passed:
                    raise ConformanceError(
                        f"{path}: {integration_id} claims {capability}=true but does not pass {case_id}"
                    )
                if claim == "conditional" and case_id not in passed and not not_applicable_evidence.get(case_id):
                    raise ConformanceError(
                        f"{path}: {integration_id} conditionally claims {capability}; "
                        f"its N/A {case_id} requires bounded evidence"
                    )
    return root["repository"], seen_integrations


def _validate_evidence_reference(
    reference: Any,
    repository_root: Path,
    location: str,
    *,
    require_fragment: bool = False,
    exact_case_id: str | None = None,
    require_test_path: bool = False,
    forbidden_target: Path | None = None,
) -> None:
    if not isinstance(reference, str) or not reference or len(reference) > 300:
        raise ConformanceError(f"{location} contains an invalid evidence reference")
    relative, separator, fragment = reference.partition("#")
    if require_fragment and (not separator or not fragment):
        raise ConformanceError(f"{location} pass evidence must name a test or case fragment")
    if exact_case_id is not None and fragment != exact_case_id:
        raise ConformanceError(
            f"{location} common-suite pass evidence fragment must equal its case ID {exact_case_id}"
        )
    if fragment and re.fullmatch(r"[A-Za-z0-9_.:-]+", fragment) is None:
        raise ConformanceError(f"{location} contains an invalid evidence fragment")
    target = (repository_root / relative).resolve()
    if repository_root.resolve() not in target.parents or not target.is_file():
        raise ConformanceError(f"{location} does not name a repository file: {reference}")
    relative_target = target.relative_to(repository_root.resolve())
    if forbidden_target is not None and target == forbidden_target.resolve():
        raise ConformanceError(f"{location} common evidence catalog cannot self-reference: {reference}")
    if require_test_path and target.name == "common-framework-evidence.json":
        raise ConformanceError(f"{location} common evidence source cannot reference another catalog: {reference}")
    if require_test_path and not any(
        part.casefold() in {"test", "tests", "__tests__"}
        for part in relative_target.parts
    ):
        raise ConformanceError(f"{location} common evidence source must resolve under a test path: {reference}")
    if exact_case_id is not None:
        if (
            len(relative_target.parts) != 2
            or relative_target.parts[0].casefold() != "conformance"
            or relative_target.parts[1] != "common-framework-evidence.json"
        ):
            raise ConformanceError(
                f"{location} common-suite pass evidence must use Conformance/common-framework-evidence.json"
            )
        catalog = _exact(
            _load_json(target),
            {"schema_version", "cases"},
            f"common evidence catalog {target}",
        )
        if catalog["schema_version"] != 1 or type(catalog["schema_version"]) is not int:
            raise ConformanceError(f"{target}: schema_version must be integer 1")
        mappings = catalog["cases"]
        if not isinstance(mappings, dict) or exact_case_id not in mappings:
            raise ConformanceError(f"{target}: missing explicit mapping for {exact_case_id}")
        sources = mappings[exact_case_id]
        if not isinstance(sources, list) or not sources:
            raise ConformanceError(f"{target}: {exact_case_id} must map to test evidence")
        for source in sources:
            _validate_evidence_reference(
                source,
                repository_root,
                f"{target}: {exact_case_id}",
                require_fragment=True,
                require_test_path=True,
                forbidden_target=target,
            )
        return
    if fragment:
        try:
            evidence_text = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ConformanceError(f"{location} cannot inspect evidence fragment: {error}") from error
        if fragment not in evidence_text:
            raise ConformanceError(f"{location} evidence fragment is not present: {reference}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--report", type=Path, action="append", default=[])
    parser.add_argument("--require-repository", action="append", default=[])
    parser.add_argument("--aggregate", action="store_true")
    arguments = parser.parse_args()
    cases, digest = load_manifest(arguments.manifest)
    registry = load_registry(arguments.registry)
    reported: dict[str, set[str]] = {}
    for report in arguments.report:
        repository, integrations = validate_report(report, cases, digest, registry)
        if repository in reported:
            raise ConformanceError(f"duplicate report for {repository}")
        reported[repository] = integrations
    required_repositories = set(arguments.require_repository)
    if arguments.aggregate:
        required_repositories = {row["repository"] for row in registry.values()}
    for repository in required_repositories:
        expected = {integration_id for integration_id, row in registry.items() if row["repository"] == repository}
        if reported.get(repository) != expected:
            raise ConformanceError(
                f"{repository} report coverage must exactly match registry ownership; "
                f"expected={sorted(expected)}; actual={sorted(reported.get(repository, set()))}"
            )
    print(f"framework conformance manifest valid: {len(cases)} cases; reports={len(arguments.report)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
