#!/usr/bin/env python3
"""Validate and render the canonical Latchway framework registry offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "compatibility/frameworks.yaml"
DEFAULT_SCHEMA = ROOT / "compatibility/frameworks.schema.json"
DEFAULT_OUTPUT = ROOT / "docs/public/reference/compatibility.mdx"

ROOT_FIELDS = {"schema_version", "frameworks"}
FRAMEWORK_FIELDS = {
    "id",
    "name",
    "tier",
    "ecosystem",
    "package",
    "integration",
    "latchway_package",
    "support",
    "tested",
    "capabilities",
    "security",
    "limitations",
}
CAPABILITY_FIELDS = {
    "responses",
    "chat_completions",
    "text",
    "streaming",
    "tools",
    "structured_output",
    "embeddings",
    "audio",
    "images",
    "cancellation",
    "app_extensions",
}
SECURITY_FIELDS = {"dpop", "native_key_isolation"}
SUPPORT_STATES = {"planned", "experimental", "supported", "unsupported"}
CAPABILITY_STRING_STATES = {"conditional", "planned"}
SECURITY_STATES = {"full", "partial", "not_tested", "not_applicable"}
TIERS = {"tier_1", "tier_2"}
ECOSYSTEMS = {"javascript", "apple", "android", "react_native"}
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
INTEGRATION_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class RegistryError(ValueError):
    """The framework registry or its generated output is invalid."""


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise RegistryError(
                f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _exact_keys(value: Any, expected: set[str], location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{location} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RegistryError(f"{location} fields differ: missing={missing}, extra={extra}")
    return value


def _nonempty_string(value: Any, location: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RegistryError(f"{location} must be a nonempty trimmed string")
    if len(value) > maximum:
        raise RegistryError(f"{location} exceeds {maximum} characters")
    return value


def _version_key(value: str) -> tuple[Any, ...]:
    core, separator, prerelease = value.partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    padded = numbers + (0,) * (3 - len(numbers))
    if not separator:
        return padded + (1, ())
    identifiers: tuple[tuple[int, Any], ...] = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in prerelease.split(".")
    )
    return padded + (0, identifiers)


def _validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict):
        raise RegistryError("framework schema must be an object")
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id") != "https://latchway.dev/schemas/frameworks.schema.json"
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        raise RegistryError("framework schema identity or strict root drifted")
    if set(schema.get("required", [])) != ROOT_FIELDS:
        raise RegistryError("framework schema root requirements drifted")
    if set(schema.get("properties", {})) != ROOT_FIELDS:
        raise RegistryError("framework schema root properties drifted")
    if schema["properties"]["frameworks"].get("minItems") != 1:
        raise RegistryError("framework schema must require at least one entry")
    framework = schema.get("$defs", {}).get("framework")
    if not isinstance(framework, dict) or framework.get("additionalProperties") is not False:
        raise RegistryError("framework item schema is not strict")
    if set(framework.get("required", [])) != FRAMEWORK_FIELDS:
        raise RegistryError("framework item requirements drifted")
    if set(framework.get("properties", {})) != FRAMEWORK_FIELDS:
        raise RegistryError("framework item properties drifted")
    capabilities = framework["properties"].get("capabilities", {})
    if (
        capabilities.get("additionalProperties") is not False
        or set(capabilities.get("required", [])) != CAPABILITY_FIELDS
        or set(capabilities.get("properties", {})) != CAPABILITY_FIELDS
    ):
        raise RegistryError("capability schema is not closed")
    security = framework["properties"].get("security", {})
    if (
        security.get("additionalProperties") is not False
        or set(security.get("required", [])) != SECURITY_FIELDS
        or set(security.get("properties", {})) != SECURITY_FIELDS
    ):
        raise RegistryError("security schema is not closed")
    tested = framework["properties"].get("tested", {})
    if (
        tested.get("additionalProperties") is not False
        or set(tested.get("required", [])) != {"minimum", "latest"}
        or set(tested.get("properties", {})) != {"minimum", "latest"}
    ):
        raise RegistryError("tested-version schema is not closed")


def _validate_framework(value: Any, index: int) -> Mapping[str, Any]:
    location = f"frameworks[{index}]"
    item = _exact_keys(value, FRAMEWORK_FIELDS, location)
    identifier = _nonempty_string(item["id"], f"{location}.id", 64)
    if ID_RE.fullmatch(identifier) is None:
        raise RegistryError(f"{location}.id has invalid syntax")
    _nonempty_string(item["name"], f"{location}.name", 100)
    if item["tier"] not in TIERS:
        raise RegistryError(f"{location}.tier is invalid")
    if item["ecosystem"] not in ECOSYSTEMS:
        raise RegistryError(f"{location}.ecosystem is invalid")
    _nonempty_string(item["package"], f"{location}.package", 160)
    integration = _nonempty_string(item["integration"], f"{location}.integration", 64)
    if INTEGRATION_RE.fullmatch(integration) is None:
        raise RegistryError(f"{location}.integration has invalid syntax")
    _nonempty_string(item["latchway_package"], f"{location}.latchway_package", 160)

    support = item["support"]
    if support not in SUPPORT_STATES:
        raise RegistryError(f"{location}.support is invalid")
    tested = _exact_keys(item["tested"], {"minimum", "latest"}, f"{location}.tested")
    minimum = tested["minimum"]
    latest = tested["latest"]
    if support in {"supported", "experimental", "unsupported"}:
        for label, candidate in (("minimum", minimum), ("latest", latest)):
            if not isinstance(candidate, str) or VERSION_RE.fullmatch(candidate) is None:
                raise RegistryError(f"{location}.tested.{label} must be a pinned version")
        if _version_key(minimum) > _version_key(latest):
            raise RegistryError(f"{location}.tested minimum exceeds latest")
    elif minimum is not None or latest is not None:
        raise RegistryError(
            f"{location}.tested versions are forbidden while support is planned"
        )

    capabilities = _exact_keys(
        item["capabilities"], CAPABILITY_FIELDS, f"{location}.capabilities"
    )
    for key, state in capabilities.items():
        if not isinstance(state, bool) and not (
            isinstance(state, str) and state in CAPABILITY_STRING_STATES
        ):
            raise RegistryError(f"{location}.capabilities.{key} has invalid state")
    security = _exact_keys(item["security"], SECURITY_FIELDS, f"{location}.security")
    for key, state in security.items():
        if state not in SECURITY_STATES:
            raise RegistryError(f"{location}.security.{key} has invalid state")
    if support in {"experimental", "supported"} and "not_tested" in security.values():
        raise RegistryError(f"{location}.security must be tested before claiming support")
    if support == "supported" and "planned" in capabilities.values():
        raise RegistryError(f"{location}.capabilities cannot remain planned when supported")
    limitations = item["limitations"]
    if not isinstance(limitations, list) or not limitations:
        raise RegistryError(f"{location}.limitations must be a nonempty array")
    for limitation_index, limitation in enumerate(limitations):
        _nonempty_string(
            limitation,
            f"{location}.limitations[{limitation_index}]",
            300,
        )
    return item


def load_registry(registry_path: Path, schema_path: Path) -> Mapping[str, Any]:
    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise RegistryError(f"cannot load framework schema: {error}") from error
    _validate_schema(schema)
    try:
        registry = yaml.load(
            registry_path.read_text(encoding="utf-8"),
            Loader=UniqueKeyLoader,
        )
    except (OSError, yaml.YAMLError) as error:
        raise RegistryError(f"cannot load framework registry: {error}") from error
    root = _exact_keys(registry, ROOT_FIELDS, "registry")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise RegistryError("registry.schema_version must be 1")
    frameworks = root["frameworks"]
    if not isinstance(frameworks, list) or not frameworks:
        raise RegistryError("registry.frameworks must be a nonempty array")
    validated = [_validate_framework(value, index) for index, value in enumerate(frameworks)]
    identifiers = [str(item["id"]) for item in validated]
    if identifiers != sorted(identifiers):
        raise RegistryError("framework entries must be sorted by id")
    if len(identifiers) != len(set(identifiers)):
        raise RegistryError("framework ids must be unique")
    return root


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _state(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return str(value).replace("_", " ").title()


def render_markdown(registry: Mapping[str, Any]) -> str:
    supported = sum(item["support"] == "supported" for item in registry["frameworks"])
    warning = (
        "No current row is a `supported` release; experimental rows record "
        "bounded local evidence and unsupported rows record a failed safe seam."
        if supported == 0
        else "Only rows explicitly marked `supported` are supported releases."
    )
    lines = [
        "---",
        'title: "Compatibility"',
        'description: "Check tested Latchway framework ranges and security capabilities without mistaking planned adapters for supported releases."',
        "---",
        "",
        "{/* Generated by scripts/framework_compatibility.py. Do not edit. */}",
        "{/* Canonical source: compatibility/frameworks.yaml; schema version: 1. */}",
        "",
        "<Warning>",
        f"  {warning}",
        "  A planned page, package name, source example, or successful local",
        "  request does not mean supported compatibility.",
        "</Warning>",
        "",
        "This page is generated from `compatibility/frameworks.yaml`. A support",
        "claim requires pinned minimum/latest versions and the common conformance",
        "evidence defined by ADR 0028. Do not edit this page by hand.",
        "",
        "## Integration matrix",
        "",
        "| Framework | Ecosystem | Framework package | Integration | Latchway package | Support | Tested range | DPoP | Native key isolation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in registry["frameworks"]:
        tested = item["tested"]
        tested_range = (
            f"{tested['minimum']}–{tested['latest']}"
            if tested["minimum"] is not None
            else "Not yet tested"
        )
        values = [
            item["name"],
            _state(item["ecosystem"]),
            f"`{item['package']}`",
            f"`{item['integration']}`",
            f"`{item['latchway_package']}`",
            _state(item["support"]),
            tested_range,
            _state(item["security"]["dpop"]),
            _state(item["security"]["native_key_isolation"]),
        ]
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.extend(
        [
            "",
            "## Capability matrix",
            "",
            "| Framework | Responses | Chat completions | Text | Streaming | Tools | Structured output | Embeddings | Audio | Images | Cancellation | App extensions |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    capability_columns = [
        "responses",
        "chat_completions",
        "text",
        "streaming",
        "tools",
        "structured_output",
        "embeddings",
        "audio",
        "images",
        "cancellation",
        "app_extensions",
    ]
    for item in registry["frameworks"]:
        values = [item["name"]] + [
            _state(item["capabilities"][key]) for key in capability_columns
        ]
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.extend(["", "## Current limitations", ""])
    for item in registry["frameworks"]:
        joined = " ".join(str(value) for value in item["limitations"])
        lines.append(f"- **{_cell(item['name'])} (`{item['id']}`):** {_cell(joined)}")
    lines.extend(
        [
            "",
            "## Evidence required for support",
            "",
            "A supported tuple names the framework and adapter versions, Latchway",
            "SDK/platform and server range, contract/wire coordinate, integration",
            "class, security level, capabilities, limitations, and exact conformance",
            "evidence. Minimum and latest declared versions must pass, and scheduled",
            "newest-compatible failures open an issue without widening the range.",
            "",
            "See [Release status](/release-status) for source and publication blockers.",
            "",
        ]
    )
    return "\n".join(lines)


def validate_repository(check_generated: bool = True) -> Mapping[str, Any]:
    registry = load_registry(DEFAULT_REGISTRY, DEFAULT_SCHEMA)
    if check_generated:
        expected = render_markdown(registry)
        try:
            actual = DEFAULT_OUTPUT.read_text(encoding="utf-8")
        except OSError as error:
            raise RegistryError(f"cannot read generated compatibility table: {error}") from error
        if actual != expected:
            raise RegistryError(
                "generated framework compatibility table is stale; run "
                "python3 scripts/framework_compatibility.py --write-generated"
            )
    return registry


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--check-generated", action="store_true")
    actions.add_argument("--write-generated", action="store_true")
    actions.add_argument("--print-generated", action="store_true")
    args = parser.parse_args(argv)

    registry = load_registry(args.registry.resolve(), args.schema.resolve())
    rendered = render_markdown(registry)
    output = args.output.resolve()
    if args.check_generated:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            raise RegistryError(f"generated framework compatibility table is stale: {output}")
    elif args.write_generated:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    elif args.print_generated:
        print(rendered, end="")
        return 0
    print(f"framework compatibility registry valid: {len(registry['frameworks'])} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
