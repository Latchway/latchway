#!/usr/bin/env python3
"""Reduce live Cloudflare responses into fail-closed deployment observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+@(sha256:[0-9a-f]{64})$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
EVIDENCE_ID = re.compile(r"^[1-9][0-9]{0,19}-[1-9][0-9]{0,3}$")
MAX_JSON_BYTES = 8 * 1024 * 1024
REQUIRED_RUNTIME_SECRETS = ("LATCHWAY_DATABASE_URL", "LATCHWAY_MASTER_KEY")
EVIDENCE_SECRET = "LATCHWAY_EVIDENCE_TOKEN"


class CaptureError(Exception):
    pass


def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureError("duplicate_json_key")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        data = path.read_bytes()
    except OSError:
        raise CaptureError("json_unreadable") from None
    if not data or len(data) > MAX_JSON_BYTES:
        raise CaptureError("json_size_invalid")
    try:
        return json.loads(data, object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CaptureError("json_invalid") from None


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise CaptureError("manifest_unreadable") from None


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def require_dict(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CaptureError(code)
    return value


def require_list(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise CaptureError(code)
    return value


def manifest_descriptor(path: Path, expected_digest: str) -> dict[str, Any]:
    if SHA256.fullmatch(expected_digest) is None or f"sha256:{file_sha256(path)}" != expected_digest:
        raise CaptureError("manifest_digest_mismatch")
    document = require_dict(load_json(path), "manifest_invalid")
    config = require_dict(document.get("config"), "manifest_config_invalid")
    layers = require_list(document.get("layers"), "manifest_layers_invalid")
    config_digest = config.get("digest")
    if not isinstance(config_digest, str) or SHA256.fullmatch(config_digest) is None:
        raise CaptureError("manifest_config_invalid")
    reduced_layers: list[dict[str, Any]] = []
    for layer in layers:
        item = require_dict(layer, "manifest_layer_invalid")
        digest, size = item.get("digest"), item.get("size")
        if (
            not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or size < 1
        ):
            raise CaptureError("manifest_layer_invalid")
        reduced_layers.append({"digest": digest, "size": size})
    return {"config_digest": config_digest, "layers": reduced_layers}


def contains_string(value: Any, expected: str) -> bool:
    if value == expected:
        return True
    if isinstance(value, dict):
        return any(contains_string(child, expected) for child in value.values())
    if isinstance(value, list):
        return any(contains_string(child, expected) for child in value)
    return False


def safe_provider_records(value: Any, code: str) -> list[dict[str, Any]]:
    records = require_list(value, code)
    if len(records) > 50:
        raise CaptureError(code)
    reduced: list[dict[str, Any]] = []
    for record in records:
        item = require_dict(record, code)
        serialized = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(serialized.encode()) > 256 * 1024:
            raise CaptureError(code)
        lowered = serialized.lower()
        if any(marker in lowered for marker in ('"password":', '"token":', '"secret_value":')):
            raise CaptureError("provider_secret_material_forbidden")
        reduced.append(item)
    return reduced


def select_application(value: Any, mirror_image: str) -> dict[str, Any]:
    applications = require_list(value, "cloudflare_applications_invalid")
    matching = [item for item in applications if isinstance(item, dict) and item.get("name") == "latchway"]
    if len(matching) != 1:
        raise CaptureError("cloudflare_application_not_unique")
    app = matching[0]
    identifier = app.get("id")
    if (
        not isinstance(identifier, str)
        or UUID.fullmatch(identifier) is None
        or app.get("state") not in ("active", "ready")
        or app.get("image") != mirror_image
        or type(app.get("instances")) is not int
        or app["instances"] < 1
        or type(app.get("version")) is not int
        or app["version"] < 1
        or not isinstance(app.get("updated_at"), str)
    ):
        raise CaptureError("cloudflare_application_not_ready")
    return {
        key: app[key]
        for key in ("id", "name", "state", "instances", "image", "version", "updated_at")
    }


def select_instance(value: Any, version: int) -> dict[str, Any]:
    instances = require_list(value, "cloudflare_instances_invalid")
    matching = [item for item in instances if isinstance(item, dict) and item.get("name") == "instance-0"]
    if len(matching) != 1:
        raise CaptureError("cloudflare_instance_not_unique")
    instance = matching[0]
    if (
        instance.get("state") != "running"
        or instance.get("version") != version
        or not isinstance(instance.get("id"), str)
        or not instance["id"]
        or not isinstance(instance.get("created"), str)
        or not instance["created"]
    ):
        raise CaptureError("cloudflare_instance_not_ready")
    return {
        key: instance.get(key)
        for key in ("id", "name", "state", "location", "version", "created")
    }


def secret_names(value: Any) -> set[str]:
    records = value.get("secrets") if isinstance(value, dict) else value
    if not isinstance(records, list):
        raise CaptureError("cloudflare_secrets_invalid")
    result = {
        item.get("name")
        for item in records
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    required = set(REQUIRED_RUNTIME_SECRETS) | {EVIDENCE_SECRET}
    if not required.issubset(result):
        raise CaptureError("cloudflare_secret_missing")
    return result


def build(args: argparse.Namespace) -> str:
    if ACCOUNT_ID.fullmatch(args.account_id) is None:
        raise CaptureError("cloudflare_account_identity_invalid")
    candidate = require_dict(load_json(args.candidate_manifest), "candidate_manifest_invalid")
    image = require_dict(candidate.get("image"), "candidate_image_invalid")
    platforms = require_dict(image.get("platforms"), "candidate_platforms_invalid")
    index_digest = image.get("index_digest")
    platform_digest = platforms.get("linux/amd64")
    mirror_match = IMAGE.fullmatch(args.mirror_image)
    if (
        image.get("repository") != "ghcr.io/latchway/latchway"
        or not isinstance(index_digest, str)
        or SHA256.fullmatch(index_digest) is None
        or not isinstance(platform_digest, str)
        or SHA256.fullmatch(platform_digest) is None
        or mirror_match is None
    ):
        raise CaptureError("candidate_image_invalid")
    mirror_digest = mirror_match.group(1)
    canonical = manifest_descriptor(args.canonical_manifest, platform_digest)
    mirror = manifest_descriptor(args.mirror_manifest, mirror_digest)
    if canonical != mirror:
        raise CaptureError("mirror_content_mismatch")

    whoami = load_json(args.whoami)
    if not contains_string(whoami, args.account_id):
        raise CaptureError("cloudflare_account_identity_mismatch")
    application = select_application(load_json(args.applications), args.mirror_image)
    before = select_instance(load_json(args.instances_before), application["version"])
    after = select_instance(load_json(args.instances_after), application["version"])
    before_resource = f"{before['id']}@{before['created']}"
    after_resource = f"{after['id']}@{after['created']}"
    if before_resource == after_resource:
        raise CaptureError("cloudflare_instance_not_replaced")

    migration = require_dict(load_json(args.migration), "cloudflare_migration_invalid")
    shutdown = require_dict(load_json(args.shutdown), "cloudflare_shutdown_invalid")
    status = require_dict(migration.get("status"), "cloudflare_migration_status_invalid")
    evidence_id = migration.get("evidence_id")
    command = migration.get("command")
    stop = require_dict(shutdown.get("stop"), "cloudflare_shutdown_stop_invalid")
    if (
        not isinstance(evidence_id, str)
        or EVIDENCE_ID.fullmatch(evidence_id) is None
        or shutdown.get("evidence_id") != evidence_id
        or command != ["/latchway", "--output", "json", "migrate", "status"]
        or migration.get("exit_code") != 0
        or status.get("up_to_date") is not True
        or status.get("current") != status.get("available")
        or not isinstance(status.get("current"), int)
        or status["current"] < 1
        or stop.get("evidence_id") != evidence_id
        or stop.get("signal") != "SIGTERM"
        or stop.get("reason") != "runtime_signal"
        or stop.get("exit_code") != 0
        or not isinstance(stop.get("requested_at"), str)
        or not isinstance(stop.get("stopped_at"), str)
    ):
        raise CaptureError("cloudflare_execution_invalid")

    deployments = safe_provider_records(load_json(args.deployments), "cloudflare_deployments_invalid")
    versions = safe_provider_records(load_json(args.versions), "cloudflare_versions_invalid")
    secret_names(load_json(args.secrets))
    output: Path = args.output_dir
    resource_id = application["id"]
    write_json(output / "identity.json", {
        "platform": "cloudflare_containers",
        "resource_id": resource_id,
        "observed_at": args.observed_at,
        "provider_response": {
            "account_id": args.account_id,
            "whoami_sha256": canonical_sha256(whoami),
            "wrangler_version": args.wrangler_version,
        },
    })
    write_json(output / "control_plane.json", {
        "platform": "cloudflare_containers",
        "worker": {
            "status": "ready",
            "resource_id": resource_id,
            "deployments": deployments,
            "versions": versions,
        },
        "container": {
            "application": application,
            "instances": [after],
            "canonical": {
                "index_digest": index_digest,
                "platform": "linux/amd64",
                "platform_digest": platform_digest,
                **canonical,
            },
            "mirror": {
                "image": args.mirror_image,
                "manifest_digest": mirror_digest,
                **mirror,
            },
        },
    })
    write_json(output / "migration.json", {
        "command": command,
        "status": status,
        "provider_execution": {
            "exit_code": 0,
            "evidence_id": evidence_id,
            "instance_name": "instance-0",
            "command": command,
            "reported_status": status,
        },
    })
    write_json(output / "secrets.json", {
        "required_names": list(REQUIRED_RUNTIME_SECRETS),
        "runtime_references": [
            {"name": name, "reference": "cloudflare-worker-secret"}
            for name in REQUIRED_RUNTIME_SECRETS
        ],
        "provider_resources": [
            {"resource_id": f"accounts/{args.account_id}/workers/scripts/latchway/secrets/{name}"}
            for name in REQUIRED_RUNTIME_SECRETS
        ],
    })
    write_json(output / "shutdown.json", {
        "method": "cloudflare_container_replacement",
        "started_at": args.shutdown_started,
        "finished_at": args.shutdown_finished,
        "signal": "SIGTERM",
        "platform_timeout_seconds": 900,
        "application_timeout_seconds": 30,
        "exit_code": stop["exit_code"],
        "readiness_restored": True,
        "evidence_id": evidence_id,
        "provider_reason": stop["reason"],
        "before": {"image_digest": mirror_digest, "resource_id": before_resource},
        "after": {"image_digest": mirror_digest, "resource_id": after_resource},
    })
    args.resource_id_output.write_text(resource_id + "\n", encoding="utf-8")
    return resource_id


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--canonical-manifest", type=Path, required=True)
    parser.add_argument("--mirror-manifest", type=Path, required=True)
    parser.add_argument("--mirror-image", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--whoami", type=Path, required=True)
    parser.add_argument("--applications", type=Path, required=True)
    parser.add_argument("--instances-before", type=Path, required=True)
    parser.add_argument("--instances-after", type=Path, required=True)
    parser.add_argument("--deployments", type=Path, required=True)
    parser.add_argument("--versions", type=Path, required=True)
    parser.add_argument("--secrets", type=Path, required=True)
    parser.add_argument("--migration", type=Path, required=True)
    parser.add_argument("--shutdown", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--shutdown-started", required=True)
    parser.add_argument("--shutdown-finished", required=True)
    parser.add_argument("--wrangler-version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--resource-id-output", type=Path, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        build(arguments())
    except CaptureError as error:
        print(f"Cloudflare capture failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
