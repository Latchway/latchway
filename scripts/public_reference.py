#!/usr/bin/env python3
"""Render deterministic public reference pages from normative v1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

import yaml

try:
    from scripts import framework_compatibility
except ModuleNotFoundError:  # Direct execution adds scripts/, not its parent.
    import framework_compatibility  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
ADMIN_SOURCE = ROOT / "api/admin.openapi.yaml"
CLIENT_SOURCE = ROOT / "api/client.openapi.yaml"
ERROR_SOURCE = ROOT / "api/error-codes.yaml"
CONFIG_SOURCE = ROOT / "api/config.schema.json"
ADMIN_OUTPUT = ROOT / "docs/public/reference/admin-api.mdx"
CLIENT_OUTPUT = ROOT / "docs/public/reference/client-api.mdx"
ERROR_OUTPUT = ROOT / "docs/public/reference/errors.mdx"
CONFIG_OUTPUT = ROOT / "docs/public/reference/config-schema.mdx"
COMPATIBILITY_OUTPUT = ROOT / "docs/public/reference/compatibility.mdx"
MANIFEST_OUTPUT = ROOT / "docs/public/config/generated-reference.json"

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
EXPECTED_ERROR_FIELDS = {"status", "title", "retryable", "guidance"}
WHITESPACE = re.compile(r"\s+")


class ReferenceError(ValueError):
    """A normative source or checked-in generated page is invalid."""


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ReferenceError(
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
            raise ReferenceError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_yaml(path: Path) -> Mapping[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as error:
        raise ReferenceError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReferenceError(f"{path} must contain an object")
    return value


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ReferenceError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReferenceError(f"{path} must contain an object")
    return value


def _text(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReferenceError(f"{location} must be a nonempty string")
    return WHITESPACE.sub(" ", value.strip())


def _cell(value: Any) -> str:
    return (
        WHITESPACE.sub(" ", str(value))
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .strip()
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _literal(value: Any) -> str:
    return "`" + json.dumps(value, sort_keys=True, separators=(",", ":")) + "`"


def _ref_name(reference: str) -> str:
    return reference.rsplit("/", 1)[-1]


def _resolve_local(document: Mapping[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ReferenceError(f"only local references are supported: {reference}")
    current: Any = document
    for encoded in reference[2:].split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            raise ReferenceError(f"unresolved local reference: {reference}")
        current = current[key]
    return current


def _schema_shape(schema: Any) -> str:
    if not isinstance(schema, dict):
        return "unspecified"
    reference = schema.get("$ref")
    if isinstance(reference, str):
        return f"`{_ref_name(reference)}`"
    if "const" in schema:
        return f"constant {_literal(schema['const'])}"
    enum = schema.get("enum")
    if isinstance(enum, list):
        return "enum " + ", ".join(_literal(value) for value in enum)
    for combinator, label in (("oneOf", "one of"), ("anyOf", "any of")):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            return label + " " + " / ".join(_schema_shape(branch) for branch in branches)
    schema_type = schema.get("type")
    if schema_type == "array":
        return f"array of {_schema_shape(schema.get('items', {}))}"
    if schema_type == "object":
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            return f"map to {_schema_shape(additional)}"
        return "object"
    if isinstance(schema_type, list):
        return " or ".join(str(value) for value in schema_type)
    if isinstance(schema_type, str):
        return schema_type
    if "allOf" in schema:
        return "combined schema"
    return "any JSON value"


def _schema_constraints(schema: Any) -> str:
    if not isinstance(schema, dict):
        return "—"
    parts: list[str] = []
    labels = {
        "format": "format",
        "pattern": "pattern",
        "minimum": "minimum",
        "maximum": "maximum",
        "exclusiveMinimum": "exclusive minimum",
        "exclusiveMaximum": "exclusive maximum",
        "minLength": "minimum length",
        "maxLength": "maximum length",
        "minItems": "minimum items",
        "maxItems": "maximum items",
        "minProperties": "minimum properties",
        "maxProperties": "maximum properties",
        "multipleOf": "multiple of",
        "default": "default",
    }
    for key, label in labels.items():
        if key in schema:
            parts.append(f"{label}: {_literal(schema[key])}")
    if schema.get("uniqueItems") is True:
        parts.append("unique items")
    if schema.get("additionalProperties") is False:
        parts.append("unknown properties rejected")
    if isinstance(schema.get("contains"), dict):
        parts.append(f"contains {_schema_shape(schema['contains'])}")
    property_names = schema.get("propertyNames")
    if isinstance(property_names, dict):
        details = _schema_constraints(property_names)
        parts.append(f"property names: {details if details != '—' else _schema_shape(property_names)}")
    items = schema.get("items")
    if isinstance(items, dict):
        details = _schema_constraints(items)
        if details != "—":
            parts.append(f"items: {details}")
    if "allOf" in schema:
        parts.append(f"{len(schema['allOf'])} combined rule(s)")
    if "not" in schema:
        parts.append("includes a forbidden-shape rule")
    return "; ".join(parts) if parts else "—"


def _content_schema(content: Any) -> str:
    if not isinstance(content, dict) or not content:
        return "no body"
    preferred = content.get("application/json")
    media_type = "application/json"
    if not isinstance(preferred, dict):
        media_type, preferred = next(iter(content.items()))
    if not isinstance(preferred, dict):
        return f"`{media_type}`"
    return f"`{media_type}` {_schema_shape(preferred.get('schema', {}))}"


def _operation_parameters(
    document: Mapping[str, Any], path_item: Mapping[str, Any], operation: Mapping[str, Any]
) -> str:
    parameters: list[Any] = []
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        if isinstance(source, list):
            parameters.extend(source)
    rendered: list[str] = []
    for parameter in parameters:
        if isinstance(parameter, dict) and isinstance(parameter.get("$ref"), str):
            parameter = _resolve_local(document, parameter["$ref"])
        if not isinstance(parameter, dict):
            raise ReferenceError("operation parameter must be an object")
        name = _text(parameter.get("name"), "parameter.name")
        location = _text(parameter.get("in"), f"parameter {name}.in")
        required = ", required" if parameter.get("required") is True else ""
        rendered.append(f"`{name}` ({location}{required})")
    return "; ".join(rendered) if rendered else "None"


def _operation_request(document: Mapping[str, Any], operation: Mapping[str, Any]) -> str:
    request = operation.get("requestBody")
    if request is None:
        return "None"
    if isinstance(request, dict) and isinstance(request.get("$ref"), str):
        request = _resolve_local(document, request["$ref"])
    if not isinstance(request, dict):
        raise ReferenceError("operation requestBody must be an object")
    requirement = "required" if request.get("required") is True else "optional"
    return f"{_content_schema(request.get('content'))} ({requirement})"


def _operation_responses(document: Mapping[str, Any], operation: Mapping[str, Any]) -> str:
    responses = operation.get("responses")
    if not isinstance(responses, dict) or not responses:
        raise ReferenceError("operation must declare responses")
    rendered: list[str] = []
    for status, response in responses.items():
        if status == "default" or not str(status).startswith("2"):
            continue
        if isinstance(response, dict) and isinstance(response.get("$ref"), str):
            response = _resolve_local(document, response["$ref"])
        if not isinstance(response, dict):
            raise ReferenceError("operation response must be an object")
        rendered.append(f"`{status}` {_content_schema(response.get('content'))}")
    return "; ".join(rendered) if rendered else "No success response declared"


def _operation_security(
    document: Mapping[str, Any], operation: Mapping[str, Any]
) -> str:
    security = operation.get("security", document.get("security", []))
    if security == []:
        return "Unauthenticated"
    if not isinstance(security, list):
        raise ReferenceError("operation security must be an array")
    alternatives: list[str] = []
    for alternative in security:
        if not isinstance(alternative, dict):
            raise ReferenceError("security alternative must be an object")
        if not alternative:
            alternatives.append("Unauthenticated")
            continue
        alternatives.append(" + ".join(f"`{name}`" for name in alternative))
    return " or ".join(dict.fromkeys(alternatives))


def _operation_details(operation: Mapping[str, Any], location: str) -> str:
    summary = _text(operation.get("summary"), f"{location}.summary")
    description = operation.get("description")
    if description is None:
        return summary
    return f"{summary} {_text(description, f'{location}.description')}"


def load_client_contract(path: Path = CLIENT_SOURCE) -> Mapping[str, Any]:
    document = _load_yaml(path)
    if document.get("openapi") != "3.1.0":
        raise ReferenceError("Client API must use OpenAPI 3.1.0")
    info = document.get("info")
    if not isinstance(info, dict):
        raise ReferenceError("Client API info is missing")
    _text(info.get("title"), "client.info.title")
    _text(info.get("version"), "client.info.version")
    _text(info.get("summary"), "client.info.summary")
    _text(info.get("description"), "client.info.description")
    tags = document.get("tags")
    paths = document.get("paths")
    if not isinstance(tags, list) or not isinstance(paths, dict) or not paths:
        raise ReferenceError("Client API tags or paths are missing")
    tag_names = [
        _text(tag.get("name"), "client.tags.name")
        for tag in tags
        if isinstance(tag, dict)
    ]
    if len(tag_names) != len(tags) or len(tag_names) != len(set(tag_names)):
        raise ReferenceError("Client API tags must be unique objects")
    operation_ids: set[str] = set()
    operation_count = 0
    allowed_prefixes = ("/.well-known/", "/client/v1/", "/v1/", "/proxy/")
    for route, path_item in paths.items():
        if (
            not isinstance(route, str)
            or not route.startswith(allowed_prefixes)
            or not isinstance(path_item, dict)
        ):
            raise ReferenceError(f"invalid Client API path item: {route}")
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise ReferenceError(f"{method.upper()} {route} must be an object")
            operation_id = _text(
                operation.get("operationId"),
                f"{method.upper()} {route}.operationId",
            )
            _text(operation.get("summary"), f"{method.upper()} {route}.summary")
            operation_tags = operation.get("tags")
            if (
                not isinstance(operation_tags, list)
                or len(operation_tags) != 1
                or operation_tags[0] not in tag_names
            ):
                raise ReferenceError(f"{method.upper()} {route} must use one declared tag")
            if operation_id in operation_ids:
                raise ReferenceError(f"duplicate Client API operationId: {operation_id}")
            operation_ids.add(operation_id)
            _operation_parameters(document, path_item, operation)
            _operation_request(document, operation)
            _operation_responses(document, operation)
            _operation_security(document, operation)
            operation_count += 1
    if operation_count == 0:
        raise ReferenceError("Client API has no operations")
    return document


def render_client_reference(document: Mapping[str, Any]) -> str:
    info = document["info"]
    tag_names = [tag["name"] for tag in document["tags"]]
    operations_by_tag: dict[
        str,
        list[tuple[str, str, Mapping[str, Any], Mapping[str, Any]]],
    ] = {name: [] for name in tag_names}
    for route, path_item in document["paths"].items():
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if isinstance(operation, dict):
                operations_by_tag[operation["tags"][0]].append(
                    (method, route, path_item, operation)
                )
    operation_count = sum(len(values) for values in operations_by_tag.values())
    lines = [
        "---",
        'title: "Client API"',
        'description: "Inspect every generated Latchway discovery, session, component, quota, diagnostics, AI, and restricted HTTP client operation."',
        'icon: "book-key"',
        'audience: "reference"',
        'pageType: "reference"',
        'serverVersion: "1.0.0"',
        'sdkVersion: "1.0.0"',
        'lastVerified: "2026-08-31"',
        'owner: "core-api"',
        "---",
        "",
        "{/* Generated by scripts/public_reference.py. Do not edit. */}",
        f"{{/* Canonical source: api/client.openapi.yaml; OpenAPI {document['openapi']}; contract {info['version']}. */}}",
        "",
        "<Warning>",
        "  This reference describes the version 1 source candidate. It is not a",
        "  publication claim. The page intentionally embeds no interactive API",
        "  playground: client applications should use a platform Latchway SDK.",
        "</Warning>",
        "",
        _text(info.get("summary"), "client.info.summary"),
        "",
        _text(info.get("description"), "client.info.description"),
        "",
        "The SDK owns platform attestation, secure key storage, RFC 9449 DPoP,",
        "origin enforcement, renewal, bounded parsing, redaction, and safe replay.",
        "The operation index is a wire reference, not a replacement SDK recipe.",
        "",
        "## Authentication schemes",
        "",
        "| Scheme | Type | Location | Credential |",
        "| --- | --- | --- | --- |",
    ]
    security_schemes = document.get("components", {}).get("securitySchemes", {})
    if not isinstance(security_schemes, dict) or not security_schemes:
        raise ReferenceError("Client API security schemes are missing")
    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            raise ReferenceError(f"Client API security scheme {name} must be an object")
        kind = _text(scheme.get("type"), f"securitySchemes.{name}.type")
        location = str(scheme.get("in", "Authorization header"))
        credential = (
            scheme.get("name")
            or scheme.get("bearerFormat")
            or scheme.get("scheme")
            or "documented scheme"
        )
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (f"`{name}`", kind, location, f"`{credential}`")
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "A plus sign in the operation table means that the same request requires",
            "both schemes. Discovery operations explicitly declare an unauthenticated",
            "alternative. Every non-success response resolves to the canonical RFC 9457",
            "problem contract in [Errors](/reference/errors).",
            "",
            "## Operation index",
            "",
            f"The normative OpenAPI document currently declares {operation_count} operations.",
            "Each row below is generated; a source change without this page changing fails CI.",
            "",
        ]
    )
    for tag in tag_names:
        lines.extend(
            [
                f"### {tag}",
                "",
                "| Method | Path | Operation ID | Authentication | Parameters | Request body | Success response | Contract details |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for method, route, path_item, operation in operations_by_tag[tag]:
            values = (
                f"`{method.upper()}`",
                f"`{route}`",
                f"`{operation['operationId']}`",
                _operation_security(document, operation),
                _operation_parameters(document, path_item, operation),
                _operation_request(document, operation),
                _operation_responses(document, operation),
                _operation_details(operation, f"{method.upper()} {route}"),
            )
            lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
        lines.append("")
    lines.extend(
        [
            "## SDK and correlation boundary",
            "",
            "Start with the [SDK chooser](/clients/choose-an-sdk). Preserve the safe",
            "request ID when diagnosing a failure, follow the generated",
            "[error registry](/reference/errors), and never export a session credential,",
            "DPoP private key, proof, or raw attestation object into application logs.",
            "",
        ]
    )
    return "\n".join(lines)


def load_admin_contract(path: Path = ADMIN_SOURCE) -> Mapping[str, Any]:
    document = _load_yaml(path)
    if document.get("openapi") != "3.1.0":
        raise ReferenceError("Admin API must use OpenAPI 3.1.0")
    info = document.get("info")
    if not isinstance(info, dict):
        raise ReferenceError("Admin API info is missing")
    _text(info.get("title"), "admin.info.title")
    _text(info.get("version"), "admin.info.version")
    tags = document.get("tags")
    paths = document.get("paths")
    if not isinstance(tags, list) or not isinstance(paths, dict) or not paths:
        raise ReferenceError("Admin API tags or paths are missing")
    tag_names = [_text(tag.get("name"), "admin.tags.name") for tag in tags if isinstance(tag, dict)]
    if len(tag_names) != len(tags) or len(tag_names) != len(set(tag_names)):
        raise ReferenceError("Admin API tags must be unique objects")
    operation_ids: set[str] = set()
    operation_count = 0
    for route, path_item in paths.items():
        if not isinstance(route, str) or not route.startswith("/admin/v1/") or not isinstance(path_item, dict):
            raise ReferenceError(f"invalid Admin API path item: {route}")
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise ReferenceError(f"{method.upper()} {route} must be an object")
            operation_id = _text(operation.get("operationId"), f"{method.upper()} {route}.operationId")
            _text(operation.get("summary"), f"{method.upper()} {route}.summary")
            operation_tags = operation.get("tags")
            if not isinstance(operation_tags, list) or len(operation_tags) != 1 or operation_tags[0] not in tag_names:
                raise ReferenceError(f"{method.upper()} {route} must use one declared tag")
            if operation_id in operation_ids:
                raise ReferenceError(f"duplicate Admin API operationId: {operation_id}")
            operation_ids.add(operation_id)
            _operation_parameters(document, path_item, operation)
            _operation_request(document, operation)
            _operation_responses(document, operation)
            _operation_security(document, operation)
            operation_count += 1
    if operation_count == 0:
        raise ReferenceError("Admin API has no operations")
    return document


def render_admin_reference(document: Mapping[str, Any]) -> str:
    info = document["info"]
    tag_names = [tag["name"] for tag in document["tags"]]
    operations_by_tag: dict[str, list[tuple[str, str, Mapping[str, Any], Mapping[str, Any]]]] = {
        name: [] for name in tag_names
    }
    for route, path_item in document["paths"].items():
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if isinstance(operation, dict):
                operations_by_tag[operation["tags"][0]].append((method, route, path_item, operation))
    operation_count = sum(len(values) for values in operations_by_tag.values())
    lines = [
        "---",
        'title: "Admin API"',
        'description: "Inspect every generated Latchway control-plane operation, parameter, request schema, and success response."',
        'icon: "brackets"',
        'audience: "reference"',
        'pageType: "reference"',
        'serverVersion: "1.0.0"',
        'sdkVersion: "not-applicable"',
        'lastVerified: "2026-08-31"',
        'owner: "core-api"',
        "---",
        "",
        "{/* Generated by scripts/public_reference.py. Do not edit. */}",
        f"{{/* Canonical source: api/admin.openapi.yaml; OpenAPI {document['openapi']}; contract {info['version']}. */}}",
        "",
        "<Warning>",
        "  This reference describes the version 1 source candidate. It is not a",
        "  publication claim. The page intentionally embeds no interactive API",
        "  playground; run administrative calls only against an environment you own.",
        "</Warning>",
        "",
        _text(info.get("summary"), "admin.info.summary"),
        "",
        _text(info.get("description"), "admin.info.description"),
        "",
        "## Authentication schemes",
        "",
        "| Scheme | Type | Location | Credential |",
        "| --- | --- | --- | --- |",
    ]
    security_schemes = document.get("components", {}).get("securitySchemes", {})
    if not isinstance(security_schemes, dict):
        raise ReferenceError("Admin API security schemes are missing")
    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            raise ReferenceError(f"Admin API security scheme {name} must be an object")
        kind = _text(scheme.get("type"), f"securitySchemes.{name}.type")
        location = str(scheme.get("in", "Authorization header"))
        credential = scheme.get("name") or scheme.get("bearerFormat") or scheme.get("scheme") or "documented scheme"
        lines.append(
            "| " + " | ".join(_cell(value) for value in (f"`{name}`", kind, location, f"`{credential}`")) + " |"
        )
    lines.extend(
        [
            "",
            "Cookie-authenticated mutations also require the same-origin CSRF",
            "contract declared by their `X-CSRF-Token` parameter. Bearer tokens are",
            "scoped and are supplied through an environment variable, never a command",
            "argument. Every non-success response resolves to the canonical RFC 9457",
            "problem contract in [Errors](/reference/errors).",
            "",
            "## Operation index",
            "",
            f"The normative OpenAPI document currently declares {operation_count} operations.",
            "Each row below is generated; a source change without this page changing fails CI.",
            "",
        ]
    )
    for tag in tag_names:
        lines.extend(
            [
                f"### {tag}",
                "",
                "| Method | Path | Operation ID | Authentication | Parameters | Request body | Success response | Contract details |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for method, route, path_item, operation in operations_by_tag[tag]:
            values = (
                f"`{method.upper()}`",
                f"`{route}`",
                f"`{operation['operationId']}`",
                _operation_security(document, operation),
                _operation_parameters(document, path_item, operation),
                _operation_request(document, operation),
                _operation_responses(document, operation),
                _operation_details(operation, f"{method.upper()} {route}"),
            )
            lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
        lines.append("")
    lines.extend(
        [
            "## Mutation safety",
            "",
            "Configuration replacements use strong ETags. Write-only secrets and",
            "one-time API-token values are never returned after creation. A response",
            "with `operation_indeterminate` may represent a committed mutation; use its",
            "operation ID and durable state to reconcile before retrying.",
            "",
            "Use the [CLI reference](/reference/cli) for credential-safe automation and",
            "the [configuration schema](/reference/config-schema) for the immutable",
            "environment document.",
            "",
        ]
    )
    return "\n".join(lines)


def load_error_registry(path: Path = ERROR_SOURCE) -> Mapping[str, Any]:
    registry = _load_yaml(path)
    if registry.get("registry_version") != 1 or registry.get("contract_version") != "1.0.0":
        raise ReferenceError("unexpected error registry coordinate")
    if registry.get("problem_media_type") != "application/problem+json":
        raise ReferenceError("unexpected problem media type")
    fields = registry.get("fields")
    codes = registry.get("codes")
    if not isinstance(fields, dict) or not isinstance(codes, dict) or not codes:
        raise ReferenceError("error registry fields or codes are missing")
    seen: set[str] = set()
    for code, definition in codes.items():
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code) is None:
            raise ReferenceError(f"invalid error code: {code}")
        if code in seen or not isinstance(definition, dict) or set(definition) != EXPECTED_ERROR_FIELDS:
            raise ReferenceError(f"invalid error definition: {code}")
        if type(definition["status"]) is not int or not 400 <= definition["status"] <= 599:
            raise ReferenceError(f"invalid HTTP status for {code}")
        if type(definition["retryable"]) is not bool:
            raise ReferenceError(f"invalid retryable value for {code}")
        _text(definition["title"], f"errors.{code}.title")
        _text(definition["guidance"], f"errors.{code}.guidance")
        seen.add(code)
    return registry


def render_error_reference(registry: Mapping[str, Any]) -> str:
    fields = registry["fields"]
    required = fields.get("required", [])
    optional = fields.get("optional", [])
    conditional = fields.get("conditional", {})
    operation_rule = conditional.get("operation_id", {}) if isinstance(conditional, dict) else {}
    if not isinstance(required, list) or not isinstance(optional, list):
        raise ReferenceError("error field lists are invalid")
    lines = [
        "---",
        'title: "Errors"',
        'description: "Handle every generated stable RFC 9457 problem code with its exact HTTP status, retryability, and operator guidance."',
        'icon: "circle-alert"',
        'audience: "reference"',
        'pageType: "reference"',
        'serverVersion: "1.0.0"',
        'sdkVersion: "1.0.0"',
        'lastVerified: "2026-08-31"',
        'owner: "core-api"',
        "---",
        "",
        "{/* Generated by scripts/public_reference.py. Do not edit. */}",
        f"{{/* Canonical source: api/error-codes.yaml; registry {registry['registry_version']}; contract {registry['contract_version']}. */}}",
        "",
        f"Latchway returns `{registry['problem_media_type']}`. The registry currently",
        f"defines {len(registry['codes'])} stable codes. Provider payloads, credentials,",
        "identity tokens, proofs, and raw internal errors are excluded.",
        "",
        "## Problem fields",
        "",
        "| Class | Fields |",
        "| --- | --- |",
        "| Required | " + ", ".join(f"`{value}`" for value in required) + " |",
        "| Optional | " + ", ".join(f"`{value}`" for value in optional) + " |",
        "",
    ]
    required_for = operation_rule.get("required_for", []) if isinstance(operation_rule, dict) else []
    if isinstance(required_for, list) and operation_rule.get("forbidden_otherwise") is True:
        lines.extend(
            [
                "`operation_id` is required only for "
                + ", ".join(f"`{value}`" for value in required_for)
                + " and is forbidden for every other code.",
                "",
            ]
        )
    lines.extend(
        [
            "<Warning>",
            "  `retryable: true` does not authorize a blind replay. Respect",
            "  `retry_after`, the SDK's pre-dispatch boundary, and the route/session",
            "  contract. Reconcile indeterminate mutations from durable state.",
            "</Warning>",
            "",
            "## Stable code registry",
            "",
            "| Code | HTTP | Retryable | Title | Required action |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for code, definition in registry["codes"].items():
        values = (
            f"`{code}`",
            definition["status"],
            "Yes" if definition["retryable"] else "No",
            _text(definition["title"], f"errors.{code}.title"),
            _text(definition["guidance"], f"errors.{code}.guidance"),
        )
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.extend(
        [
            "",
            "## Direct diagnostic links",
            "",
            "Each stable code has a deterministic heading so SDK errors and request",
            "views can link to the exact action.",
            "",
        ]
    )
    for code, definition in registry["codes"].items():
        lines.extend(
            [
                f"### `{code}`",
                "",
                f"**HTTP {definition['status']} · Retryable: "
                + ("Yes" if definition["retryable"] else "No")
                + "**",
                "",
                _text(definition["guidance"], f"errors.{code}.guidance"),
                "",
            ]
        )
    lines.extend(
        [
            "For `operation_indeterminate`, retain the operation ID and request ID,",
            "query audit or the affected resource, and decide from durable state before",
            "another mutation. For terminal component or family codes, clear only the",
            "credential scope named by the code unless family revocation is explicit.",
            "",
        ]
    )
    return "\n".join(lines)


def load_config_schema(path: Path = CONFIG_SOURCE) -> Mapping[str, Any]:
    schema = _load_json(path)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ReferenceError("configuration must use JSON Schema 2020-12")
    if schema.get("$id") != "https://latchway.dev/schemas/config/1.0.0/environment-config.schema.json":
        raise ReferenceError("unexpected configuration schema coordinate")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise ReferenceError("configuration schema root must be a closed object")
    properties = schema.get("properties")
    definitions = schema.get("$defs")
    if not isinstance(properties, dict) or not isinstance(definitions, dict) or not definitions:
        raise ReferenceError("configuration properties or definitions are missing")
    for reference in _walk_references(schema):
        _resolve_local(schema, reference)
    return schema


def _walk_references(value: Any) -> Sequence[str]:
    references: list[str] = []
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            references.append(reference)
        for child in value.values():
            references.extend(_walk_references(child))
    elif isinstance(value, list):
        for child in value:
            references.extend(_walk_references(child))
    return references


def _render_property_table(schema: Mapping[str, Any], lines: list[str]) -> None:
    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or not properties:
        return
    required = schema.get("required", [])
    required_names = set(required) if isinstance(required, list) else set()
    lines.extend(
        [
            "| Property | Shape | Required | Constraints | Notes |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for name, definition in properties.items():
        if not isinstance(definition, dict):
            raise ReferenceError(f"configuration property {name} must be an object")
        values = (
            f"`{name}`",
            _schema_shape(definition),
            "Yes" if name in required_names else "No",
            _schema_constraints(definition),
            _text(definition["description"], f"configuration.{name}.description")
            if "description" in definition
            else "—",
        )
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.append("")


def render_config_reference(schema: Mapping[str, Any]) -> str:
    definitions = schema["$defs"]
    lines = [
        "---",
        'title: "Configuration schema"',
        'description: "Inspect the generated immutable EnvironmentConfig fields, required properties, shapes, bounds, and closed-object rules."',
        'icon: "file-json"',
        'audience: "reference"',
        'pageType: "reference"',
        'serverVersion: "1.0.0"',
        'sdkVersion: "not-applicable"',
        'lastVerified: "2026-08-31"',
        'owner: "core-configuration"',
        "---",
        "",
        "{/* Generated by scripts/public_reference.py. Do not edit. */}",
        f"{{/* Canonical source: api/config.schema.json; coordinate: {schema['$id']}. */}}",
        "",
        "<Warning>",
        "  This generated index helps humans review a candidate document; the",
        "  canonical JSON Schema and authoritative server validation remain decisive.",
        "  Conditional `if`/`then`, reference, CEL, secret, pricing, and runtime",
        "  semantic checks can reject a document that satisfies one property row.",
        "</Warning>",
        "",
        _text(schema.get("description"), "configuration.description"),
        "",
        "## Contract coordinate",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| JSON Schema dialect | `{schema['$schema']}` |",
        f"| Schema ID | `{schema['$id']}` |",
        f"| Root type | `{schema['type']}` |",
        "| Unknown root properties | Rejected |",
        "",
        "## Root document",
        "",
    ]
    _render_property_table(schema, lines)
    lines.extend(
        [
            "The root constants are `apiVersion: latchway.dev/v1alpha1` and",
            "`kind: EnvironmentConfig`. Configuration revisions replace the complete",
            "document under a strong ETag; they are not partial patches.",
            "",
            "## Definition index",
            "",
            f"The canonical schema currently declares {len(definitions)} reusable definitions.",
            "",
        ]
    )
    for name, definition in definitions.items():
        if not isinstance(definition, dict):
            raise ReferenceError(f"configuration definition {name} must be an object")
        lines.append(f"### {name}")
        lines.append("")
        if "description" in definition:
            lines.append(_text(definition["description"], f"configuration.$defs.{name}.description"))
            lines.append("")
        lines.append(f"Shape: {_schema_shape(definition)}. Definition constraints: {_schema_constraints(definition)}.")
        lines.append("")
        _render_property_table(definition, lines)
        rules = definition.get("allOf")
        if isinstance(rules, list) and rules:
            lines.extend(
                [
                    f"This definition also has {len(rules)} canonical conditional rule(s).",
                    "They are enforced in addition to the property summary above.",
                    "",
                ]
            )
    lines.extend(
        [
            "## Validation workflow",
            "",
            "```bash",
            "latchway config apply --environment env_... --file candidate.json --dry-run",
            "latchway config apply --environment env_... --file candidate.json",
            "latchway config validate rev_...",
            "latchway config plan rev_...",
            "```",
            "",
            "A successful schema parse is only the first gate. Validation also resolves",
            "references and secrets, compiles bounded CEL, proves protocol capabilities,",
            "checks trusted input accounting and pricing, and rejects unsafe route or",
            "quota combinations. See [Configuration](/administration/configuration) and",
            "[CEL policy context](/reference/cel-policy-context).",
            "",
        ]
    )
    return "\n".join(lines)


def render_all() -> Mapping[Path, str]:
    registry = framework_compatibility.load_registry(
        framework_compatibility.DEFAULT_REGISTRY,
        framework_compatibility.DEFAULT_SCHEMA,
    )
    documents = {
        ADMIN_OUTPUT: render_admin_reference(load_admin_contract()),
        CLIENT_OUTPUT: render_client_reference(load_client_contract()),
        ERROR_OUTPUT: render_error_reference(load_error_registry()),
        CONFIG_OUTPUT: render_config_reference(load_config_schema()),
        COMPATIBILITY_OUTPUT: framework_compatibility.render_markdown(registry),
    }
    sources = (
        ADMIN_SOURCE,
        CLIENT_SOURCE,
        ERROR_SOURCE,
        CONFIG_SOURCE,
        framework_compatibility.DEFAULT_REGISTRY,
        framework_compatibility.DEFAULT_SCHEMA,
    )
    manifest = {
        "format": 1,
        "generator": "scripts/public_reference.py",
        "sources": [
            {
                "path": str(path.relative_to(ROOT)),
                "sha256": _sha256(path.read_bytes()),
            }
            for path in sorted(sources)
        ],
        "outputs": [
            {
                "path": str(path.relative_to(ROOT / "docs/public")),
                "sha256": _sha256(content.encode("utf-8")),
            }
            for path, content in sorted(documents.items())
        ],
    }
    return {
        **documents,
        MANIFEST_OUTPUT: json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    }


def validate_repository(check_generated: bool = True) -> Mapping[Path, str]:
    rendered = render_all()
    if check_generated:
        stale: list[str] = []
        for output, expected in rendered.items():
            try:
                actual = output.read_text(encoding="utf-8")
            except OSError:
                stale.append(str(output.relative_to(ROOT)))
                continue
            if actual != expected:
                stale.append(str(output.relative_to(ROOT)))
        if stale:
            raise ReferenceError(
                "generated public reference is stale: "
                + ", ".join(stale)
                + "; run python3 scripts/public_reference.py --write-generated"
            )
    return rendered


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--check-generated", action="store_true")
    actions.add_argument("--write-generated", action="store_true")
    actions.add_argument(
        "--print-generated",
        choices=("admin", "client", "errors", "config", "compatibility"),
        metavar="DOCUMENT",
    )
    args = parser.parse_args(argv)
    rendered = render_all()
    if args.check_generated:
        validate_repository(check_generated=True)
    elif args.write_generated:
        for output, content in rendered.items():
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
    elif args.print_generated:
        selected = {
            "admin": ADMIN_OUTPUT,
            "client": CLIENT_OUTPUT,
            "errors": ERROR_OUTPUT,
            "config": CONFIG_OUTPUT,
            "compatibility": COMPATIBILITY_OUTPUT,
        }[args.print_generated]
        print(rendered[selected], end="")
        return 0
    print(
        "public references valid: "
        f"{len(load_client_contract()['paths'])} client paths, "
        f"{len(load_admin_contract()['paths'])} admin paths, "
        f"{len(load_error_registry()['codes'])} errors, "
        f"{len(load_config_schema()['$defs'])} config definitions, "
        f"{len(framework_compatibility.load_registry(framework_compatibility.DEFAULT_REGISTRY, framework_compatibility.DEFAULT_SCHEMA)['frameworks'])} compatibility entries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
