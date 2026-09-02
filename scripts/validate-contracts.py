#!/usr/bin/env python3
"""Validate Latchway Phase 1 contract integrity without network access."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlparse

import yaml

from framework_compatibility import validate_repository as validate_framework_compatibility


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "api"
PROMOTION_EVIDENCE_DOMAINS = [
    "live_sdk_conformance",
    "physical_devices",
    "live_provider",
    "cloud_deployments",
    "operational_resilience",
    "supply_chain",
]
RELEASE_EVIDENCE_DOMAINS = [
    "live_sdk_conformance",
    "public_tags",
    "public_registries",
    "physical_devices",
    "live_provider",
    "cloud_deployments",
    "operational_resilience",
    "supply_chain",
]
MAXIMUM_RELEASE_EVIDENCE_SECONDS = 7 * 24 * 60 * 60


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as source:
        return yaml.load(source, Loader=UniqueKeyLoader)


def load_json(path: Path) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def json_pointer(document: Any, fragment: str) -> Any:
    if fragment in ("", "#"):
        return document
    if not fragment.startswith("#/"):
        raise ValueError(f"unsupported JSON Pointer fragment: {fragment}")
    current = document
    for encoded in fragment[2:].split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        current = current[int(key)] if isinstance(current, list) else current[key]
    return current


def split_ref(path: Path, ref: str) -> tuple[Path, str]:
    if ref.startswith("#"):
        return path, ref
    relative, marker, fragment = ref.partition("#")
    target = (path.parent / relative).resolve()
    if ROOT not in target.parents and target != ROOT:
        raise ValueError(f"reference escapes repository: {path}: {ref}")
    return target, f"#{fragment}" if marker else "#"


DOCUMENT_CACHE: dict[Path, Any] = {}


def load_document(path: Path) -> Any:
    path = path.resolve()
    if path not in DOCUMENT_CACHE:
        if not path.is_file():
            raise FileNotFoundError(f"missing referenced file: {path}")
        DOCUMENT_CACHE[path] = load_json(path) if path.suffix == ".json" else load_yaml(path)
    return DOCUMENT_CACHE[path]


def resolve_ref(path: Path, ref: str) -> tuple[Path, Any]:
    target_path, fragment = split_ref(path.resolve(), ref)
    return target_path, json_pointer(load_document(target_path), fragment)


def walk_refs(path: Path, value: Any) -> None:
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            resolve_ref(path, ref)
        for child in value.values():
            walk_refs(path, child)
    elif isinstance(value, list):
        for child in value:
            walk_refs(path, child)


def is_type(instance: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "null":
        return instance is None
    raise ValueError(f"unsupported schema type {expected}")


def format_valid(value: str, name: str) -> bool:
    if name in ("uri", "uri-reference"):
        parsed = urlparse(value)
        return name == "uri-reference" or bool(parsed.scheme)
    if name == "email":
        return "@" in value and not value.startswith("@") and not value.endswith("@")
    if name == "date-time":
        try:
            dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return "T" in value
        except ValueError:
            return False
    return True


def schema_errors(schema_path: Path, schema: Any, instance: Any, location: str = "$") -> list[str]:
    errors: list[str] = []
    if not isinstance(schema, dict):
        return errors
    if "$ref" in schema:
        target_path, target = resolve_ref(schema_path, schema["$ref"])
        errors.extend(schema_errors(target_path, target, instance, location))
    for subschema in schema.get("allOf", []):
        errors.extend(schema_errors(schema_path, subschema, instance, location))
    if "anyOf" in schema:
        outcomes = [schema_errors(schema_path, sub, instance, location) for sub in schema["anyOf"]]
        if all(outcome for outcome in outcomes):
            errors.append(f"{location}: does not satisfy anyOf")
    if "oneOf" in schema:
        matches = sum(not schema_errors(schema_path, sub, instance, location) for sub in schema["oneOf"])
        if matches != 1:
            errors.append(f"{location}: satisfies {matches} oneOf branches, expected exactly one")
    if "not" in schema and not schema_errors(schema_path, schema["not"], instance, location):
        errors.append(f"{location}: satisfies forbidden schema")
    if "if" in schema:
        if not schema_errors(schema_path, schema["if"], instance, location):
            errors.extend(schema_errors(schema_path, schema.get("then", {}), instance, location))
        else:
            errors.extend(schema_errors(schema_path, schema.get("else", {}), instance, location))

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(is_type(instance, candidate) for candidate in allowed):
            return errors + [f"{location}: expected type {allowed}, got {type(instance).__name__}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{location}: expected const {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{location}: value is not in enum")

    if isinstance(instance, dict):
        for required in schema.get("required", []):
            if required not in instance:
                errors.append(f"{location}: missing required property {required!r}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                errors.extend(schema_errors(schema_path, properties[key], value, f"{location}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{location}: additional property {key!r} is forbidden")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(schema_errors(schema_path, schema["additionalProperties"], value, f"{location}.{key}"))
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            errors.append(f"{location}: fewer than minProperties")
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            errors.append(f"{location}: more than maxProperties")
        if "propertyNames" in schema:
            for key in instance:
                errors.extend(schema_errors(schema_path, schema["propertyNames"], key, f"{location}.<propertyName>"))

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{location}: fewer than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{location}: more than maxItems")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{location}: duplicate array items")
        prefix_items = schema.get("prefixItems", [])
        if prefix_items and not isinstance(prefix_items, list):
            errors.append(f"{location}: prefixItems is not an array")
            prefix_items = []
        for index, subschema in enumerate(prefix_items[: len(instance)]):
            errors.extend(
                schema_errors(
                    schema_path,
                    subschema,
                    instance[index],
                    f"{location}[{index}]",
                )
            )
        remaining_start = len(prefix_items)
        if schema.get("items") is False and len(instance) > remaining_start:
            errors.append(f"{location}: items after prefixItems are forbidden")
        elif isinstance(schema.get("items"), dict):
            for index, value in enumerate(instance[remaining_start:], start=remaining_start):
                errors.extend(schema_errors(schema_path, schema["items"], value, f"{location}[{index}]"))
        if "contains" in schema:
            contains_matches = sum(
                not schema_errors(schema_path, schema["contains"], item, location)
                for item in instance
            )
            minimum_contains = schema.get("minContains", 1)
            maximum_contains = schema.get("maxContains")
            if contains_matches < minimum_contains:
                errors.append(f"{location}: fewer than minContains")
            if maximum_contains is not None and contains_matches > maximum_contains:
                errors.append(f"{location}: more than maxContains")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{location}: shorter than minLength")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{location}: longer than maxLength")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append(f"{location}: does not match pattern {schema['pattern']!r}")
        if "format" in schema and not format_valid(instance, schema["format"]):
            errors.append(f"{location}: invalid {schema['format']} format")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{location}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{location}: above maximum")
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            errors.append(f"{location}: not above exclusiveMinimum")
    return errors


def resolved_parameter(spec_path: Path, spec: dict[str, Any], parameter: Any) -> dict[str, Any]:
    if "$ref" in parameter:
        target_path, target = resolve_ref(spec_path, parameter["$ref"])
        if target_path != spec_path.resolve():
            raise ValueError("OpenAPI parameters must resolve inside their source document")
        return target
    return parameter


def validate_openapi(path: Path, spec: dict[str, Any], contract_version: str) -> None:
    if spec.get("openapi") != "3.1.0":
        raise ValueError(f"{path}: expected OpenAPI 3.1.0")
    if spec.get("jsonSchemaDialect") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError(f"{path}: unexpected JSON Schema dialect")
    if spec.get("info", {}).get("version") != contract_version:
        raise ValueError(f"{path}: info.version differs from protocol manifest")
    security_schemes = set(spec.get("components", {}).get("securitySchemes", {}))
    operation_ids: set[str] = set()
    methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
    for route, path_item in spec.get("paths", {}).items():
        if not route.startswith("/"):
            raise ValueError(f"{path}: invalid route {route}")
        template_names = set(re.findall(r"\{([^{}]+)\}", route))
        shared_parameters = path_item.get("parameters", []) if isinstance(path_item, dict) else []
        for method, operation in path_item.items():
            if method not in methods:
                continue
            operation_id = operation.get("operationId")
            if not operation_id or operation_id in operation_ids:
                raise ValueError(f"{path}: missing or duplicate operationId at {method.upper()} {route}")
            operation_ids.add(operation_id)
            if not operation.get("responses"):
                raise ValueError(f"{path}: operation has no responses: {operation_id}")
            parameters = [resolved_parameter(path, spec, item) for item in shared_parameters + operation.get("parameters", [])]
            path_parameters = {item.get("name") for item in parameters if item.get("in") == "path"}
            if path_parameters != template_names:
                raise ValueError(f"{path}: path parameters {path_parameters} do not match {template_names} at {route}")
            if any(item.get("in") == "path" and item.get("required") is not True for item in parameters):
                raise ValueError(f"{path}: path parameters must be required at {route}")
            security = operation.get("security", spec.get("security", []))
            for requirement in security:
                unknown = set(requirement) - security_schemes
                if unknown:
                    raise ValueError(f"{path}: unknown security scheme(s) {sorted(unknown)}")
    walk_refs(path, spec)


def validate_admin_user_override_contract(path: Path, spec: dict[str, Any]) -> None:
    operations = {
        ("/admin/v1/users/{userId}", "get"),
        ("/admin/v1/users/{userId}/block", "post"),
        ("/admin/v1/users/{userId}/unblock", "post"),
        ("/admin/v1/users/{userId}/limit-override", "put"),
        ("/admin/v1/users/{userId}/limit-override", "delete"),
    }
    for route, method in operations:
        operation = spec.get("paths", {}).get(route, {}).get(method)
        if not isinstance(operation, dict):
            raise ValueError(f"{path}: missing {method.upper()} {route}")
        parameters = [resolved_parameter(path, spec, item) for item in operation.get("parameters", [])]
        environment = [item for item in parameters if item.get("in") == "query" and item.get("name") == "environment_id"]
        if len(environment) != 1 or environment[0].get("required") is not True:
            raise ValueError(f"{path}: {method.upper()} {route} requires one environment_id query parameter")

    put = spec["paths"]["/admin/v1/users/{userId}/limit-override"]["put"]
    request_schema = put.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
    if set(request_schema.get("required", [])) != {"limit_plan", "reason"}:
        raise ValueError(f"{path}: limit override PUT must require limit_plan and reason")
    reason = request_schema.get("properties", {}).get("reason", {})
    if reason.get("minLength") != 1 or reason.get("maxLength") != 500:
        raise ValueError(f"{path}: limit override reason bounds must match PostgreSQL")

    schemas = spec.get("components", {}).get("schemas", {})
    user = schemas.get("ApplicationUser", {})
    if "identity_providers" not in user.get("required", []) or "identity_provider" in user.get("properties", {}):
        raise ValueError(f"{path}: ApplicationUser must require plural identity_providers")
    providers = user.get("properties", {}).get("identity_providers", {})
    if providers.get("type") != "array" or providers.get("minItems") != 1 or providers.get("uniqueItems") is not True:
        raise ValueError(f"{path}: ApplicationUser.identity_providers must be a non-empty unique array")
    if user.get("properties", {}).get("limit_plan_override", {}).get("$ref") != "#/components/schemas/UserLimitOverride":
        raise ValueError(f"{path}: ApplicationUser.limit_plan_override must be structured")

    override = schemas.get("UserLimitOverride", {})
    if set(override.get("required", [])) != {"id", "limit_plan", "reason", "created_at"}:
        raise ValueError(f"{path}: UserLimitOverride required fields drifted")
    if set(override.get("properties", {})) != {"id", "limit_plan", "reason", "created_at", "expires_at"}:
        raise ValueError(f"{path}: UserLimitOverride properties drifted")


def validate_admin_administrator_contract(path: Path, spec: dict[str, Any]) -> None:
    operations = {
        ("/admin/v1/administrators", "get"),
        ("/admin/v1/administrators", "post"),
        ("/admin/v1/administrators/{adminUserId}/role", "put"),
        ("/admin/v1/administrators/{adminUserId}/disable", "post"),
        ("/admin/v1/administrators/{adminUserId}/enable", "post"),
        ("/admin/v1/administrators/{adminUserId}/reset-password", "post"),
    }
    for route, method in operations:
        if not isinstance(spec.get("paths", {}).get(route, {}).get(method), dict):
            raise ValueError(f"{path}: missing administrator lifecycle operation {method.upper()} {route}")

    schemas = spec.get("components", {}).get("schemas", {})
    administrator = schemas.get("Administrator", {})
    if "password" in administrator.get("properties", {}) or "password_hash" in administrator.get("properties", {}):
        raise ValueError(f"{path}: administrator response exposes credential material")
    for name in ("CreateAdministratorRequest", "ResetAdministratorPasswordRequest"):
        password = schemas.get(name, {}).get("properties", {}).get("password", {})
        if password.get("writeOnly") is not True or password.get("minLength") != 12 or password.get("maxLength") != 1024:
            raise ValueError(f"{path}: {name} password must remain bounded and write-only")


def validate_admin_secret_contract(path: Path, spec: dict[str, Any]) -> None:
    schemas = spec.get("components", {}).get("schemas", {})
    secret_value = schemas.get("SecretValue", {})
    expected = {
        "type": "string",
        "minLength": 1,
        "maxLength": 1048576,
        "writeOnly": True,
        "x-latchway-max-utf8-bytes": 1048576,
    }
    for key, value in expected.items():
        if secret_value.get(key) != value:
            raise ValueError(f"{path}: SecretValue {key} must be {value!r}")
    if "UTF-8" not in secret_value.get("description", ""):
        raise ValueError(f"{path}: SecretValue must document its UTF-8 byte bound")
    write_value = schemas.get("WriteSecretRequest", {}).get("properties", {}).get("value", {})
    rotate_value = (
        spec.get("paths", {})
        .get("/admin/v1/secrets/{secretId}/rotate", {})
        .get("post", {})
        .get("requestBody", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
        .get("properties", {})
        .get("value", {})
    )
    expected_ref = "#/components/schemas/SecretValue"
    if write_value.get("$ref") != expected_ref or rotate_value.get("$ref") != expected_ref:
        raise ValueError(f"{path}: secret writes must share the normative SecretValue schema")


def validate_problem_operation_id_contract(path: Path, spec: dict[str, Any]) -> None:
    problem = spec.get("components", {}).get("schemas", {}).get("Problem", {})
    base = {
        "type": "https://docs.latchway.dev/errors/conflict",
        "documentation_url": "https://docs.latchway.dev/errors/conflict",
        "title": "Resource conflict",
        "status": 409,
        "detail": "The operation conflicts with current state.",
        "code": "conflict",
        "request_id": "req_00000000000000000000000000",
        "retryable": False,
    }
    operation_id = "arq_00000000000000000000000000"
    cases = [
        ("ordinary without operation ID", base, True),
        ("ordinary with operation ID", {**base, "operation_id": operation_id}, False),
        (
            "indeterminate without operation ID",
            {
                **base,
                "type": "https://docs.latchway.dev/errors/operation-indeterminate",
                "documentation_url": "https://docs.latchway.dev/errors/operation-indeterminate",
                "title": "Operation outcome indeterminate",
                "status": 503,
                "code": "operation_indeterminate",
                "retryable": True,
            },
            False,
        ),
        (
            "indeterminate with operation ID",
            {
                **base,
                "type": "https://docs.latchway.dev/errors/operation-indeterminate",
                "documentation_url": "https://docs.latchway.dev/errors/operation-indeterminate",
                "title": "Operation outcome indeterminate",
                "status": 503,
                "code": "operation_indeterminate",
                "retryable": True,
                "operation_id": operation_id,
            },
            True,
        ),
    ]
    for label, document, should_validate in cases:
        valid = not schema_errors(path, problem, document, f"Problem.{label}")
        if valid != should_validate:
            raise ValueError(f"{path}: Problem operation_id conditional failed for {label}")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + bytes([len(value)]) + value


def raw_signature_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("ES256 JWS signature is not 64 bytes")
    body = der_integer(signature[:32]) + der_integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def public_jwk_pem(jwk: dict[str, str]) -> bytes:
    x = b64url_decode(jwk["x"])
    y = b64url_decode(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 coordinates must be 32 bytes")
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    der = prefix + b"\x04" + x + y
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n").encode("ascii")


def verify_es256(proof: str, jwk: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    encoded_header, encoded_payload, encoded_signature = proof.split(".")
    header = json.loads(b64url_decode(encoded_header))
    payload = json.loads(b64url_decode(encoded_payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = raw_signature_to_der(b64url_decode(encoded_signature))
    with tempfile.TemporaryDirectory(prefix="latchway-dpop-") as temporary:
        directory = Path(temporary)
        (directory / "public.pem").write_bytes(public_jwk_pem(jwk))
        (directory / "input").write_bytes(signing_input)
        (directory / "signature.der").write_bytes(signature)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(directory / "public.pem"), "-signature", str(directory / "signature.der"), str(directory / "input")],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        raise ValueError(f"DPoP signature verification failed: {result.stderr.strip() or result.stdout.strip()}")
    return header, payload


def validate_dpop_vectors(vector_set: dict[str, Any]) -> None:
    public = vector_set["public_jwk"]
    canonical = json.dumps(
        {"crv": public["crv"], "kty": public["kty"], "x": public["x"], "y": public["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")
    if canonical != vector_set["jwk_thumbprint_canonical_json"] or thumbprint != vector_set["jwk_thumbprint_sha256_base64url"]:
        raise ValueError("DPoP JWK thumbprint fixture mismatch")
    token = vector_set["fixture_access_token"]
    ath = base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    if ath != vector_set["fixture_access_token_hash"]:
        raise ValueError("DPoP access-token hash fixture mismatch")

    for vector in vector_set["vectors"]:
        header, payload = verify_es256(vector["proof"], {key: public[key] for key in ("kty", "crv", "x", "y")})
        request = vector["request"]
        error: str | None = None
        jwk = header.get("jwk", {})
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            error = "dpop_invalid"
        elif set(jwk) != {"kty", "crv", "x", "y"} or any(jwk.get(key) != public.get(key) for key in ("kty", "crv", "x", "y")):
            error = "dpop_invalid"
        elif payload.get("htm") != request["method"] or payload.get("htu") != request["uri"]:
            error = "dpop_invalid"
        elif not isinstance(payload.get("iat"), int) or abs(vector_set["reference_time"] - payload["iat"]) > vector_set["maximum_iat_skew_seconds"]:
            error = "dpop_invalid"
        elif not isinstance(payload.get("jti"), str) or not payload["jti"]:
            error = "dpop_invalid"
        elif request.get("use_fixture_access_token") and payload.get("ath") != ath:
            error = "dpop_invalid"
        elif "required_nonce" in request and payload.get("nonce") != request["required_nonce"]:
            error = "dpop_nonce_required"
        elif request.get("proof_jti_already_seen"):
            error = "dpop_replayed"
        expected = vector["expected"]
        if expected["valid"] != (error is None) or (error is not None and expected.get("error_code") != error):
            raise ValueError(f"DPoP vector {vector['id']} produced {error!r}, expected {expected}")


def validate_attestation_vectors(vector_set: dict[str, Any]) -> None:
    for vector in vector_set["vectors"]:
        canonical = json.dumps(vector["input"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        encoded = canonical.encode("utf-8")
        digest = hashlib.sha256(encoded).digest()
        digest_b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if canonical != vector["canonical_json"]:
            raise ValueError(f"attestation vector {vector['id']} canonical JSON mismatch")
        if encoded.hex() != vector["utf8_hex"]:
            raise ValueError(f"attestation vector {vector['id']} UTF-8 mismatch")
        if digest.hex() != vector["sha256_hex"] or digest_b64 != vector["sha256_base64url"]:
            raise ValueError(f"attestation vector {vector['id']} SHA-256 mismatch")


def validate_installation_family_vectors(vector_set: dict[str, Any]) -> None:
    family = vector_set["family"]
    root = vector_set["root_component"]
    root_claims = vector_set["root_session_claims"]
    if family["status"] != "active" or not root["is_root"] or root["status"] != "active":
        raise ValueError("installation-family vector must begin with one active root")
    root_expected = {
        "installation_family_id": family["id"],
        "client_component_id": root["id"],
        "component_definition_id": root["definition_id"],
        "component_kind": root["kind"],
        "component_is_root": True,
        "granted_features": root["granted_features"],
    }
    if any(root_claims.get(key) != value for key, value in root_expected.items()):
        raise ValueError("root component claims do not match the family fixture")
    if "parent_component_id" in root_claims or "delegation_id" in root_claims:
        raise ValueError("root component claims contain delegated provenance")

    child_ids: list[str] = []
    delegation_ids: list[str] = []
    public_keys: list[str] = []
    for vector in vector_set["provisioned_components"]:
        request = vector["request"]
        response = vector["response"]
        exchange = vector["session_exchange"]
        claims = vector["expected_session_claims"]
        trust = response["trust"]
        if response["installation_family_id"] != family["id"]:
            raise ValueError(f"component vector {vector['id']} crosses installation families")
        if exchange["request"] != {
            "component_id": response["component_id"],
            "refresh_grant": response["refresh_grant"],
        }:
            raise ValueError(f"component vector {vector['id']} does not consume its exact grant")
        expected_claims = {
            "installation_family_id": family["id"],
            "client_component_id": response["component_id"],
            "component_definition_id": request["component_definition_id"],
            "component_is_root": False,
            "granted_features": response["granted_features"],
            "trust_source": trust["source"],
            "parent_component_id": root["id"],
            "delegation_id": trust["delegation_id"],
        }
        if any(claims.get(key) != value for key, value in expected_claims.items()):
            raise ValueError(f"component vector {vector['id']} claims drift from provisioning")
        if request["requested_features"] != response["granted_features"]:
            raise ValueError(f"component vector {vector['id']} silently changes feature grants")
        if trust["parent_component_id"] != root["id"]:
            raise ValueError(f"component vector {vector['id']} has the wrong trust parent")
        verified = dt.datetime.fromisoformat(trust["verified_at"].replace("Z", "+00:00"))
        expires = dt.datetime.fromisoformat(trust["expires_at"].replace("Z", "+00:00"))
        refresh_expires = dt.datetime.fromisoformat(
            response["refresh_grant_expires_at"].replace("Z", "+00:00")
        )
        if expires <= verified or refresh_expires > expires:
            raise ValueError(f"component vector {vector['id']} outlives delegated trust")
        child_ids.append(response["component_id"])
        delegation_ids.append(trust["delegation_id"])
        public_keys.append(json.dumps(request["public_jwk"], sort_keys=True))
    if len(set(child_ids)) != 2 or root["id"] in child_ids:
        raise ValueError("component vectors must use two distinct non-root component IDs")
    if len(set(delegation_ids)) != 2 or len(set(public_keys)) != 2:
        raise ValueError("component vectors must use independent delegations and keys")

    component_revoke, family_revoke = vector_set["revocations"]
    if component_revoke["scope"] != "component" or component_revoke["target_id"] not in child_ids:
        raise ValueError("first revocation vector must target one delegated component")
    if component_revoke["expected_family_status"] != "active":
        raise ValueError("component revocation must preserve the family")
    component_states = {
        item["component_id"]: item["status"]
        for item in component_revoke["expected_components"]
    }
    sibling = next(value for value in child_ids if value != component_revoke["target_id"])
    if component_states != {
        root["id"]: "active",
        component_revoke["target_id"]: "revoked",
        sibling: "active",
    }:
        raise ValueError("component revocation vector does not preserve root and sibling isolation")
    if (
        family_revoke["scope"] != "family"
        or family_revoke["target_id"] != family["id"]
        or family_revoke["expected_family_status"] != "revoked"
    ):
        raise ValueError("second revocation vector must revoke the whole family")
    family_states = {
        item["component_id"]: item["status"]
        for item in family_revoke["expected_components"]
    }
    if family_states != {identifier: "revoked" for identifier in [root["id"], *child_ids]}:
        raise ValueError("family revocation vector must revoke every component")


def validate_contract_release_state(manifest: dict[str, Any]) -> None:
    status = manifest.get("contract_status")
    released_at = manifest.get("released_at")
    if status == "draft":
        if released_at is not None:
            raise ValueError("draft v1 contract must remain undated")
        return
    if status != "released" or not isinstance(released_at, str):
        raise ValueError("v1 contract release state is invalid")
    try:
        parsed = dt.datetime.strptime(released_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError:
        raise ValueError("released v1 contract must use canonical UTC time") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != released_at:
        raise ValueError("released v1 contract must use canonical UTC time")


def main() -> None:
    manifest_path = API / "protocol-version.json"
    manifest = load_document(manifest_path)
    contract_version = manifest["contract_version"]
    if contract_version != "1.0.0" or manifest["wire_protocol"] != {
        "current": 2,
        "supported": [1, 2],
        "minimum": 1,
    }:
        raise ValueError("unexpected contract or wire protocol version")
    validate_contract_release_state(manifest)

    client_path = API / "client.openapi.yaml"
    admin_path = API / "admin.openapi.yaml"
    client = load_document(client_path)
    admin = load_document(admin_path)
    validate_openapi(client_path, client, contract_version)
    validate_openapi(admin_path, admin, contract_version)
    validate_problem_operation_id_contract(client_path, client)
    validate_problem_operation_id_contract(admin_path, admin)
    expected_challenge_nonce = {
        "type": "string",
        "minLength": 43,
        "maxLength": 86,
        "pattern": "^[A-Za-z0-9_-]{43,86}$",
    }
    for challenge_name in ("SessionChallenge", "ComponentAttestationChallenge"):
        challenge_nonce = client["components"]["schemas"][challenge_name]["properties"][
            "challenge_nonce"
        ]
        if any(challenge_nonce.get(key) != value for key, value in expected_challenge_nonce.items()):
            raise ValueError(
                f"{challenge_name}.challenge_nonce must bound canonical unpadded base64url to 32..64 decoded bytes"
            )
    validate_admin_user_override_contract(admin_path, admin)
    validate_admin_administrator_contract(admin_path, admin)
    validate_admin_secret_contract(admin_path, admin)

    registry = load_document(API / "error-codes.yaml")
    if registry["contract_version"] != contract_version:
        raise ValueError("error registry contract version mismatch")
    operation_rule = registry.get("fields", {}).get("conditional", {}).get("operation_id", {})
    if operation_rule != {"required_for": ["operation_indeterminate"], "forbidden_otherwise": True}:
        raise ValueError("error registry operation_id conditional drift")
    for code, definition in registry["codes"].items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code):
            raise ValueError(f"invalid error code {code}")
        if not 400 <= definition["status"] <= 599 or not isinstance(definition["retryable"], bool):
            raise ValueError(f"invalid error definition for {code}")
    client_codes = set(client["components"]["schemas"]["Problem"]["properties"]["code"]["enum"])
    registry_codes = set(registry["codes"])
    if client_codes != registry_codes:
        raise ValueError(f"client Problem code drift: missing={sorted(registry_codes-client_codes)}, extra={sorted(client_codes-registry_codes)}")
    admin_code_ref = admin["components"]["schemas"]["Problem"]["properties"]["code"]["$ref"]
    _, admin_code_schema = resolve_ref(admin_path, admin_code_ref)
    admin_codes = set(admin_code_schema["enum"])
    if admin_codes != registry_codes:
        raise ValueError(f"admin Problem code drift: missing={sorted(registry_codes-admin_codes)}, extra={sorted(admin_codes-registry_codes)}")

    config_path = API / "config.schema.json"
    config_schema = load_document(config_path)
    if config_schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("configuration schema is not JSON Schema 2020-12")
    if config_schema.get("$id") != "https://latchway.dev/schemas/config/1.0.0/environment-config.schema.json":
        raise ValueError("configuration schema identity differs from the contract coordinate")
    walk_refs(config_path, config_schema)
    for index, example in enumerate(config_schema.get("examples", [])):
        errors = schema_errors(config_path, config_schema, example, f"config.examples[{index}]")
        if errors:
            raise ValueError("configuration example failed schema:\n" + "\n".join(errors))

    release_controls_schema_path = API / "github-release-controls.schema.json"
    release_controls_schema = load_document(release_controls_schema_path)
    if (
        release_controls_schema.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
        or release_controls_schema.get("$id")
        != "https://latchway.dev/schemas/github-release-controls.schema.json"
    ):
        raise ValueError("GitHub release controls schema identity drifted")
    walk_refs(release_controls_schema_path, release_controls_schema)
    release_controls = load_document(ROOT / ".github/release-controls.json")
    errors = schema_errors(
        release_controls_schema_path,
        release_controls_schema,
        release_controls,
        "github_release_controls",
    )
    if errors:
        raise ValueError("GitHub release controls failed schema:\n" + "\n".join(errors))

    release_schema_path = API / "release-evidence.schema.json"
    release_schema = load_document(release_schema_path)
    if (
        release_schema.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
        or release_schema.get("$id")
        != "https://latchway.dev/schemas/release-evidence.schema.json"
        or release_schema.get("type") != "object"
        or release_schema.get("additionalProperties") is not False
    ):
        raise ValueError("release evidence schema identity or strict root drifted")
    walk_refs(release_schema_path, release_schema)
    release_contract = manifest.get("release_evidence")
    expected_release_contract = {
        "schema_file": "release-evidence.schema.json",
        "schema_version": 1,
        "maximum_age_seconds": MAXIMUM_RELEASE_EVIDENCE_SECONDS,
        "maximum_window_seconds": MAXIMUM_RELEASE_EVIDENCE_SECONDS,
        "promotion_domains": PROMOTION_EVIDENCE_DOMAINS,
        "release_domains": RELEASE_EVIDENCE_DOMAINS,
    }
    if release_contract != expected_release_contract:
        raise ValueError("protocol manifest release evidence contract drifted")

    attestation_schema_path = API / "attestation-binding.schema.json"
    attestation_schema = load_document(attestation_schema_path)
    if attestation_schema.get("$id") != (
        "https://latchway.dev/schemas/protocol/1.0.0/attestation-binding-v1.schema.json"
    ):
        raise ValueError("attestation-binding schema identity differs from the contract coordinate")
    walk_refs(attestation_schema_path, attestation_schema)
    attestation_vector_schema_path = API / "test-vectors/attestation-binding/vector.schema.json"
    attestation_vector_schema = load_document(attestation_vector_schema_path)
    if attestation_vector_schema.get("$id") != (
        "https://latchway.dev/schemas/test-vectors/1.0.0/attestation-binding-vector-set.schema.json"
    ):
        raise ValueError("attestation vector schema identity differs from the contract coordinate")
    attestation_vectors = load_document(API / "test-vectors/attestation-binding/v1.json")
    errors = schema_errors(attestation_vector_schema_path, attestation_vector_schema, attestation_vectors, "attestation_vectors")
    if errors:
        raise ValueError("attestation vector schema failed:\n" + "\n".join(errors))
    validate_attestation_vectors(attestation_vectors)

    component_attestation_schema_path = API / "component-attestation-binding.schema.json"
    component_attestation_schema = load_document(component_attestation_schema_path)
    if component_attestation_schema.get("$id") != (
        "https://latchway.dev/schemas/protocol/1.0.0/component-attestation-binding-v2.schema.json"
    ):
        raise ValueError("component-attestation-binding schema identity differs from the contract coordinate")
    walk_refs(component_attestation_schema_path, component_attestation_schema)
    component_vector_schema_path = API / "test-vectors/component-attestation-binding/vector.schema.json"
    component_vector_schema = load_document(component_vector_schema_path)
    if component_vector_schema.get("$id") != (
        "https://latchway.dev/schemas/test-vectors/1.0.0/component-attestation-binding-vector-set.schema.json"
    ):
        raise ValueError("component attestation vector schema identity differs from the contract coordinate")
    component_vectors = load_document(API / "test-vectors/component-attestation-binding/v2.json")
    errors = schema_errors(
        component_vector_schema_path,
        component_vector_schema,
        component_vectors,
        "component_attestation_vectors",
    )
    if errors:
        raise ValueError("component attestation vector schema failed:\n" + "\n".join(errors))
    validate_attestation_vectors(component_vectors)

    dpop_vector_schema_path = API / "test-vectors/dpop/vector.schema.json"
    dpop_vector_schema = load_document(dpop_vector_schema_path)
    if dpop_vector_schema.get("$id") != (
        "https://latchway.dev/schemas/test-vectors/1.0.0/dpop-vector-set.schema.json"
    ):
        raise ValueError("DPoP vector schema identity differs from the contract coordinate")
    dpop_vectors = load_document(API / "test-vectors/dpop/v1.json")
    errors = schema_errors(dpop_vector_schema_path, dpop_vector_schema, dpop_vectors, "dpop_vectors")
    if errors:
        raise ValueError("DPoP vector schema failed:\n" + "\n".join(errors))
    validate_dpop_vectors(dpop_vectors)

    family_vector_schema_path = API / "test-vectors/installation-family/vector.schema.json"
    family_vector_schema = load_document(family_vector_schema_path)
    if family_vector_schema.get("$id") != (
        "https://latchway.dev/schemas/test-vectors/1.0.0/installation-family-v2-vector-set.schema.json"
    ):
        raise ValueError("installation-family vector schema identity differs from the contract coordinate")
    family_vectors = load_document(API / "test-vectors/installation-family/v2.json")
    errors = schema_errors(
        family_vector_schema_path,
        family_vector_schema,
        family_vectors,
        "installation_family_vectors",
    )
    if errors:
        raise ValueError("installation-family vector schema failed:\n" + "\n".join(errors))
    validate_installation_family_vectors(family_vectors)

    compatibility_schema_path = ROOT / "compatibility/frameworks.schema.json"
    compatibility_schema = load_document(compatibility_schema_path)
    compatibility_registry = load_document(ROOT / "compatibility/frameworks.yaml")
    walk_refs(compatibility_schema_path, compatibility_schema)
    errors = schema_errors(
        compatibility_schema_path,
        compatibility_schema,
        compatibility_registry,
        "framework_compatibility",
    )
    if errors:
        raise ValueError("framework compatibility schema failed:\n" + "\n".join(errors))

    required = set(manifest["bundle"]["required_entries"])
    actual = {
        "client.openapi.yaml",
        "admin.openapi.yaml",
        "config.schema.json",
        "attestation-binding.schema.json",
        "component-attestation-binding.schema.json",
        "release-evidence.schema.json",
        "error-codes.yaml",
        "protocol-version.json",
        "compatibility",
        "test-vectors",
        "SHA256SUMS",
    }
    if required != actual:
        raise ValueError(f"bundle manifest entries differ from builder: {sorted(required ^ actual)}")
    validate_framework_compatibility(check_generated=True)
    print("contract validation passed: OpenAPI structure/refs, registries, schemas/examples, GitHub release controls, release evidence, root/component attestation hashes, DPoP signatures/semantics, family/component wire-2 semantics, generated framework compatibility")


if __name__ == "__main__":
    main()
