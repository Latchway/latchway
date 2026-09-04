#!/usr/bin/env python3
"""Validate, seal, and aggregate fail-closed deployment evidence.

Local/static checks are intentionally separate from release evidence. A cloud
claim becomes eligible for the cross-repository release gate only after its raw
capture archive has been signed by the pinned GitHub Actions workflow and that
attestation has been verified against a supplied trusted root.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from typing import Any, Callable, Iterable, Mapping
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
GH_VERSION_PATH = Path(__file__).with_name("require-gh-version.py")
GH_VERSION_SPEC = importlib.util.spec_from_file_location(
    "latchway_deployment_require_gh_version", GH_VERSION_PATH
)
if GH_VERSION_SPEC is None or GH_VERSION_SPEC.loader is None:
    raise RuntimeError("GitHub CLI version policy cannot be loaded")
GH_VERSION = importlib.util.module_from_spec(GH_VERSION_SPEC)
GH_VERSION_SPEC.loader.exec_module(GH_VERSION)
PLATFORMS = ("compose", "cloud_run", "aws", "fly_io", "cloudflare_containers")
OBSERVATIONS = (
    "identity",
    "control_plane",
    "migration",
    "health",
    "readiness",
    "secrets",
    "shutdown",
)
REQUIRED_SECRET_NAMES = frozenset(("LATCHWAY_DATABASE_URL", "LATCHWAY_MASTER_KEY"))
# Prove target-database readiness, not the server's password policy: PostgreSQL
# may use loopback trust, while supplied credentials are checked under SCRAM.
COMPOSE_POSTGRES_HEALTHCHECK = (
    'result=$$(PGPASSWORD="$${POSTGRES_PASSWORD}" PGCONNECT_TIMEOUT=2 '
    'PGOPTIONS="-c statement_timeout=2000" psql -X -w -h 127.0.0.1 -p 5432 '
    '-U "$${POSTGRES_USER}" -d "$${POSTGRES_DB}" -At -v ON_ERROR_STOP=1 '
    '-c "SELECT 1" 2>/dev/null) && [ "$$result" = 1 ]'
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
RELEASE = re.compile(rf"^v{SEMVER}$")
OCI_IMAGE = re.compile(r"^ghcr\.io/latchway/latchway@sha256:([0-9a-f]{64})$")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
EVIDENCE_ID = re.compile(r"^[1-9][0-9]{0,19}-[1-9][0-9]{0,3}$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
WORKFLOW_REF = re.compile(
    r"^Latchway/latchway/\.github/workflows/deployment-evidence\.yml@refs/heads/main$"
)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_FILES = 64
MAX_TOTAL_EXTRACTED = 64 * 1024 * 1024
SIGNER_WORKFLOW = "github.com/Latchway/latchway/.github/workflows/deployment-evidence.yml"
WRANGLER_TOOLCHAIN_ROOT = ROOT / ".github/toolchains/wrangler"
WRANGLER_PACKAGE_JSON_SHA256 = "e65b3bedef41e581a85b006f4cf8ce769bb61a1f71c53af6ee4680cc4c25d839"
WRANGLER_PACKAGE_LOCK_SHA256 = "d506545cdc465df003f47903c17ffdff69bc88fe182b6b55a2313fe8d312f5a2"
WRANGLER_ALLOWED_PACKAGES_SHA256 = "1468b2214885fdd9f6013c1d636ecbe85e47c88989215383fffa5e3304a50217"
WRANGLER_PACKAGE_COUNT = 91
WRANGLER_INTEGRITY = "sha512-OzsiNgaI8i681L/+KnAKc+uEZ5D57xK5JuNvCOpRKICF4/5Q3Cu1oTGuUiT/f3GDUqQb3gzXNT0tfOHGMEtknw=="
NPM_REGISTRY_TARBALL = re.compile(r"^https://registry\.npmjs\.org/[^?#\s]+\.tgz$")
NPM_SHA512_INTEGRITY = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
DATABASE_POOL_FIELDS = (
    "aggregate_max_connections",
    "regular_max_connections",
    "completion_max_connections",
)
DATABASE_POOL_ENVIRONMENT_NAMES = (
    "LATCHWAY_DB_MAX_CONNECTIONS",
    "LATCHWAY_DB_COMPLETION_CONNECTIONS",
)
STANDARD_DATABASE_POOL = (20, 15, 5)
CLOUDFLARE_DATABASE_POOL = (5, 3, 2)
APPLICATION_READINESS_HEALTHCHECK_COMMAND = [
    "CMD",
    "/latchway",
    "--server",
    "http://127.0.0.1:8080",
    "--output",
    "json",
    "readiness",
]
CLOUD_RUN_STARTUP_PROBE = {
    "initialDelaySeconds": 1,
    "timeoutSeconds": 3,
    "periodSeconds": 3,
    "failureThreshold": 40,
    "httpGet": {"path": "/readyz", "port": 8080},
}
CLOUD_RUN_LIVENESS_PROBE = {
    "timeoutSeconds": 3,
    "periodSeconds": 15,
    "failureThreshold": 3,
    "httpGet": {"path": "/healthz", "port": 8080},
}
CLOUD_RUN_PROJECT_ID = "latchway"
CLOUD_RUN_REGION = "asia-southeast1"
CLOUD_RUN_SERVICE = "latchway"
CLOUD_RUN_MIGRATION_JOB = "latchway-migrate"
CLOUD_RUN_RUNTIME_SERVICE_ACCOUNT = "latchway-runtime@latchway.iam.gserviceaccount.com"
CLOUD_RUN_MIGRATOR_SERVICE_ACCOUNT = "latchway-migrator@latchway.iam.gserviceaccount.com"
CLOUD_RUN_CLOUD_SQL_CONNECTION_NAME = "latchway:asia-southeast1:latchway-postgres"
CLOUD_RUN_CLOUD_SQL_ANNOTATIONS = {
    "run.googleapis.com/cloudsql-instances": CLOUD_RUN_CLOUD_SQL_CONNECTION_NAME,
}
CLOUD_RUN_BASE_RUNTIME_ANNOTATIONS = {
    "autoscaling.knative.dev/minScale": "1",
    "autoscaling.knative.dev/maxScale": "3",
    "run.googleapis.com/cpu-throttling": "false",
    "run.googleapis.com/startup-cpu-boost": "true",
    "run.googleapis.com/execution-environment": "gen2",
}
CLOUD_RUN_RUNTIME_ANNOTATIONS = {
    **CLOUD_RUN_BASE_RUNTIME_ANNOTATIONS,
    **CLOUD_RUN_CLOUD_SQL_ANNOTATIONS,
}
CLOUD_RUN_NETWORK_PROFILE = {
    "mode": "cloud_sql_public_ip_connector",
    "ingress": "all",
    "invoker": "unauthenticated",
    "vpc_access": "none",
    "database_transport": "unix_socket",
    "cloud_sql_connection_name": CLOUD_RUN_CLOUD_SQL_CONNECTION_NAME,
    "cloud_sql_socket_path": f"/cloudsql/{CLOUD_RUN_CLOUD_SQL_CONNECTION_NAME}",
}
CLOUD_RUN_MIGRATION_RESOURCES = {"limits": {"cpu": "1", "memory": "512Mi"}}
CLOUD_RUN_CLOUD_SQL_NETWORK_ANNOTATIONS = {
    "run.googleapis.com/cloudsql-instances": "${CLOUD_SQL_CONNECTION_NAME}",
}
CLOUD_RUN_SECRET_REFERENCES = {
    "LATCHWAY_DATABASE_URL": "latchway-database-url",
    "LATCHWAY_MASTER_KEY": "latchway-master-key",
}
CLOUD_RUN_RUNTIME_ENVIRONMENT_NAMES = (
    "LATCHWAY_ROLE",
    "LATCHWAY_LOG_LEVEL",
    "LATCHWAY_MIGRATE_ON_START",
    "LATCHWAY_PUBLIC_ORIGIN",
    *CLOUD_RUN_SECRET_REFERENCES,
    "LATCHWAY_SHUTDOWN_TIMEOUT",
    *DATABASE_POOL_ENVIRONMENT_NAMES,
)
CANDIDATE_IMAGE_PLATFORMS = ("linux/amd64", "linux/arm64")


class EvidenceError(Exception):
    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


@dataclass
class Check:
    identifier: str
    status: str
    summary: str
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.identifier,
            "status": self.status,
            "summary": self.summary,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        if self.details:
            result["details"] = self.details
        return result


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate_json_member")
        result[key] = value
    return result


def read_json(path: Path, maximum: int = MAX_JSON_BYTES) -> Any:
    if not real_file(path):
        raise EvidenceError("artifact_not_regular_file", {"file": path.name})
    if path.stat().st_size > maximum:
        raise EvidenceError("artifact_too_large", {"file": path.name})
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=duplicate_rejecting_object
        )
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EvidenceError("artifact_json_invalid", {"file": path.name}) from None


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def real_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        raise EvidenceError("timestamp_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        raise EvidenceError("timestamp_invalid") from None


def timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


def connected_peer_address(response: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        peer = response.fp.raw._sock.getpeername()[0]
        return ipaddress.ip_address(peer)
    except (AttributeError, OSError, TypeError, ValueError):
        raise EvidenceError("http_peer_address_unavailable") from None


def observe_http(endpoint: str, output: Path, timeout: float) -> None:
    parsed_endpoint = urllib.parse.urlsplit(endpoint.rstrip("/"))
    if (
        parsed_endpoint.scheme not in ("http", "https")
        or not parsed_endpoint.hostname
        or parsed_endpoint.username
        or parsed_endpoint.password
        or parsed_endpoint.path not in ("", "/")
        or parsed_endpoint.query
        or parsed_endpoint.fragment
    ):
        raise EvidenceError("endpoint_origin_invalid")
    if parsed_endpoint.scheme == "http" and parsed_endpoint.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise EvidenceError("plaintext_remote_endpoint_forbidden")
    if parsed_endpoint.scheme == "https":
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(parsed_endpoint.hostname, parsed_endpoint.port or 443, type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError):
            raise EvidenceError("endpoint_dns_invalid") from None
        if not addresses or any(not address.is_global for address in addresses):
            raise EvidenceError("non_public_endpoint_forbidden")
    # Ignore ambient proxy variables and validate the connected peer, not only
    # the first DNS answer. This keeps a DNS rebind from reaching a private
    # runner address after the preflight check.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    output.mkdir(parents=True, exist_ok=True)
    for name, path in (("health", "/healthz"), ("readiness", "/readyz")):
        url = endpoint.rstrip("/") + path
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "latchway-deployment-evidence/1"},
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                peer = connected_peer_address(response)
                if parsed_endpoint.scheme == "https" and not peer.is_global:
                    raise EvidenceError("non_public_endpoint_forbidden")
                if parsed_endpoint.scheme == "http" and not peer.is_loopback:
                    raise EvidenceError("non_loopback_compose_endpoint_forbidden")
                status_code = response.status
                final_url = response.url
                payload = response.read(1024 * 1024 + 1)
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError("http_observation_failed", {"path": path}) from None
        if len(payload) > 1024 * 1024:
            raise EvidenceError("http_observation_too_large", {"path": path})
        try:
            body = json.loads(payload.decode("utf-8"), object_pairs_hook=duplicate_rejecting_object)
        except (UnicodeError, json.JSONDecodeError, EvidenceError):
            raise EvidenceError("http_observation_json_invalid", {"path": path}) from None
        if final_url != url:
            raise EvidenceError("http_redirect_forbidden", {"path": path})
        write_json(
            output / f"{name}.json",
            {
                "url": url,
                "status_code": status_code,
                "observed_at": timestamp_now(),
                "tls": parsed_endpoint.scheme == "https",
                "body": body,
            },
        )


def require_fields(value: Any, fields: Iterable[str], code: str) -> dict[str, Any]:
    required = set(fields)
    if not isinstance(value, dict) or set(value) != required:
        raise EvidenceError(code)
    return value


def nested(value: Any, *path: str) -> Any:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first_nested(value: Any, paths: Iterable[tuple[str, ...]]) -> Any:
    for path in paths:
        result = nested(value, *path)
        if result is not None:
            return result
    return None


def image_digest(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.search(r"@sha256:([0-9a-f]{64})$", value)
    if match:
        return match.group(1)
    match = re.fullmatch(r"sha256:([0-9a-f]{64})", value)
    return match.group(1) if match else None


def expected_digest(manifest: Mapping[str, Any]) -> str:
    match = OCI_IMAGE.fullmatch(str(manifest.get("oci_image_digest", "")))
    if match is None:
        raise EvidenceError("release_image_invalid")
    return match.group(1)


def cloud_run_candidate_platform_digest(
    candidate: Mapping[str, Any] | None,
    manifest: Mapping[str, Any],
) -> str | None:
    """Return the authenticated linux/amd64 child digest, when supplied.

    Cloud Run accepts an OCI index but executes linux/amd64. Depending on the
    provider response surface, RevisionStatus.imageDigest can identify either
    the submitted index or the selected platform manifest. A child digest is
    eligible only when it comes from the release candidate manifest already
    bound to this capture's commit, tag, repository, and index.
    """
    if candidate is None:
        return None
    image = candidate.get("image") if isinstance(candidate, Mapping) else None
    if (
        candidate.get("status") != "passed"
        or candidate.get("candidate_commit") != manifest.get("core_commit")
        or candidate.get("intended_tag") != manifest.get("core_release")
        or not isinstance(image, dict)
        or set(image) != {"repository", "index_digest", "platforms"}
    ):
        raise EvidenceError("cloud_run_candidate_image_invalid")
    platforms = image["platforms"]
    if (
        image.get("repository") != "ghcr.io/latchway/latchway"
        or not isinstance(image.get("index_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image["index_digest"]) is None
        or image["repository"] + "@" + image["index_digest"]
        != manifest.get("oci_image_digest")
        or not isinstance(platforms, dict)
        or set(platforms) != set(CANDIDATE_IMAGE_PLATFORMS)
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
            for value in platforms.values()
        )
        or len({image["index_digest"], *platforms.values()}) != 3
    ):
        raise EvidenceError("cloud_run_candidate_image_invalid")
    return platforms["linux/amd64"].removeprefix("sha256:")


def require_capture_time(value: Any, manifest: Mapping[str, Any]) -> datetime:
    observed = parse_time(value)
    started, finished = parse_time(manifest["started_at"]), parse_time(manifest["finished_at"])
    if observed < started or observed > finished:
        raise EvidenceError("observation_outside_capture_window")
    return observed


def run(arguments: list[str], *, cwd: Path = ROOT, timeout: int = 900) -> str:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C", "GIT_TERMINAL_PROMPT": "0"})
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvidenceError("command_failed", {"command": arguments[0]}) from None
    if result.returncode != 0:
        raise EvidenceError(
            "command_failed", {"command": arguments[0], "exit_code": result.returncode}
        )
    return result.stdout


def static_checks() -> list[Check]:
    checks: list[Check] = []

    def check(identifier: str, summary: str, operation: Callable[[], Mapping[str, Any]]) -> None:
        try:
            details = dict(operation())
        except EvidenceError as error:
            checks.append(Check(identifier, "failed", summary, error.code, error.details))
        except Exception:
            checks.append(Check(identifier, "failed", summary, "unexpected_validation_error"))
        else:
            checks.append(Check(identifier, "passed", summary, details=details))

    check("static.schema", "The deployment capture schema is strict JSON.", validate_schema)
    check("static.compose", "Release Compose has no source-build fallback.", validate_compose)
    check("static.cloud_run_yaml", "Cloud Run YAML separates service and migrations.", validate_cloud_run_yaml)
    check("static.cloud_run_terraform", "Cloud Run Terraform pins image and secret boundaries.", validate_cloud_run_terraform)
    check("static.aws_terraform", "AWS Terraform pins image, drain, health, and secret boundaries.", validate_aws_terraform)
    check("static.fly", "Fly config pins migration, health, and drain behavior.", validate_fly)
    check("static.cloudflare", "Cloudflare pins streaming, lifecycle, and protected live-evidence boundaries.", validate_cloudflare)
    check(
        "static.cloudflare_toolchain",
        "The source-free Wrangler toolchain has an exact registry-only npm closure.",
        validate_wrangler_toolchain,
    )
    check("static.workflow", "The live evidence workflow uses protected, pinned collectors.", validate_workflow)
    return checks


def validate_schema() -> Mapping[str, Any]:
    schema = read_json(ROOT / "deploy/evidence/platform-evidence.schema.json")
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("additionalProperties") is not False
        or set(nested(schema, "properties", "platform", "enum") or []) != set(PLATFORMS)
    ):
        raise EvidenceError("capture_schema_invalid")
    return {"platform_count": len(PLATFORMS)}


def yaml_as_json(path: Path) -> Any:
    try:
        import yaml  # type: ignore[import-not-found]

        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except ModuleNotFoundError:
        output = run(
            [
                "ruby",
                "-ryaml",
                "-rjson",
                "-e",
                "value=YAML.safe_load(File.read(ARGV[0]), aliases: false); puts JSON.generate(value)",
                str(path),
            ]
        )
        try:
            return json.loads(output, object_pairs_hook=duplicate_rejecting_object)
        except json.JSONDecodeError:
            raise EvidenceError("yaml_invalid", {"file": path.name}) from None
    except Exception:
        raise EvidenceError("yaml_invalid", {"file": path.name}) from None


def service_by_name(document: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    services = document.get("services")
    value = services.get(name) if isinstance(services, dict) else None
    if not isinstance(value, dict):
        raise EvidenceError("compose_service_missing", {"service": name})
    return value


def validate_compose() -> Mapping[str, Any]:
    document = yaml_as_json(ROOT / "deploy/compose/compose.release.yaml")
    if not isinstance(document, dict):
        raise EvidenceError("compose_invalid")
    gateway = service_by_name(document, "latchway")
    migrate = service_by_name(document, "migrate")
    postgres = service_by_name(document, "postgres")
    if postgres.get("image") != (
        "docker.io/library/postgres@sha256:"
        "d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
    ):
        raise EvidenceError("compose_postgres_image_not_pinned")
    if postgres.get("volumes") != ["postgres-data:/var/lib/postgresql"]:
        raise EvidenceError("compose_postgres_18_volume_layout_invalid")
    if postgres.get("healthcheck") != {
        "test": ["CMD-SHELL", COMPOSE_POSTGRES_HEALTHCHECK],
        "interval": "2s", "timeout": "5s", "retries": 30,
    }:
        raise EvidenceError("compose_postgres_authenticated_readiness_required")
    if "build" in gateway or "build" in migrate:
        raise EvidenceError("compose_build_fallback_forbidden")
    for service in (gateway, migrate):
        if not str(service.get("image", "")).startswith("${LATCHWAY_IMAGE:?"):
            raise EvidenceError("compose_release_image_not_required")
        if service.get("read_only") is not True or service.get("user") != "65532:65532":
            raise EvidenceError("compose_runtime_hardening_missing")
    if migrate.get("command") != ["migrate", "up"]:
        raise EvidenceError("compose_migration_command_invalid")
    condition = nested(gateway, "depends_on", "migrate", "condition")
    if condition != "service_completed_successfully":
        raise EvidenceError("compose_migration_dependency_invalid")
    environment = gateway.get("environment")
    if not isinstance(environment, dict) or not REQUIRED_SECRET_NAMES.issubset(environment):
        raise EvidenceError("compose_secret_injection_missing")
    if environment.get("LATCHWAY_MIGRATE_ON_START") != "false":
        raise EvidenceError("compose_startup_migration_not_disabled")
    if (
        environment.get("LATCHWAY_DB_MAX_CONNECTIONS")
        != "${LATCHWAY_DB_MAX_CONNECTIONS:-20}"
        or environment.get("LATCHWAY_DB_COMPLETION_CONNECTIONS")
        != "${LATCHWAY_DB_COMPLETION_CONNECTIONS:-5}"
    ):
        raise EvidenceError("compose_database_pool_partition_invalid")
    if environment.get("LATCHWAY_SHUTDOWN_TIMEOUT") != "30s" or gateway.get("stop_grace_period") != "35s":
        raise EvidenceError("compose_shutdown_budget_invalid")
    if gateway.get("healthcheck") != {
        "test": APPLICATION_READINESS_HEALTHCHECK_COMMAND,
        "interval": "5s",
        "timeout": "5s",
        "retries": 30,
        "start_period": "5s",
    }:
        raise EvidenceError("compose_serving_process_readiness_required")
    return {"services": sorted(document["services"])}


def cloud_run_containers(document: Mapping[str, Any]) -> list[Any]:
    value = first_nested(
        document,
        (
            ("spec", "template", "spec", "containers"),
            ("spec", "template", "spec", "template", "spec", "containers"),
        ),
    )
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        raise EvidenceError("cloud_run_containers_missing")
    return value


def env_map(container: Mapping[str, Any]) -> dict[str, Any]:
    values = container.get("env")
    if not isinstance(values, list):
        return {}
    result: dict[str, Any] = {}
    for item in values:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result[item["name"]] = item
    return result


def validate_cloud_run_startup_probe(container: Mapping[str, Any], code: str) -> None:
    if container.get("startupProbe") != CLOUD_RUN_STARTUP_PROBE:
        raise EvidenceError(code)


def validate_cloud_run_runtime_environment(
    container: Mapping[str, Any],
    endpoint: str,
    code: str,
) -> dict[str, Mapping[str, Any]]:
    environment = container.get("env")
    if (
        not isinstance(environment, list)
        or len(environment) != len(CLOUD_RUN_RUNTIME_ENVIRONMENT_NAMES)
        or any(not isinstance(item, dict) for item in environment)
        or [item.get("name") for item in environment]
        != list(CLOUD_RUN_RUNTIME_ENVIRONMENT_NAMES)
    ):
        raise EvidenceError(code)
    values = {item["name"]: item for item in environment}
    for name, expected_secret in CLOUD_RUN_SECRET_REFERENCES.items():
        item = values[name]
        if set(item) != {"name", "valueFrom"}:
            raise EvidenceError(code)
        reference = nested(item, "valueFrom", "secretKeyRef")
        if (
            not isinstance(reference, dict)
            or set(reference) != {"name", "key"}
            or reference.get("name") != expected_secret
            or not isinstance(reference.get("key"), str)
            or re.fullmatch(r"[1-9][0-9]*", reference["key"]) is None
        ):
            raise EvidenceError(code)
    for name in (
        "LATCHWAY_ROLE",
        "LATCHWAY_LOG_LEVEL",
        "LATCHWAY_MIGRATE_ON_START",
        "LATCHWAY_PUBLIC_ORIGIN",
        "LATCHWAY_SHUTDOWN_TIMEOUT",
        *DATABASE_POOL_ENVIRONMENT_NAMES,
    ):
        item = values[name]
        if set(item) != {"name", "value"} or not isinstance(item.get("value"), str):
            raise EvidenceError(code)
    if (
        values["LATCHWAY_ROLE"]["value"] != "all"
        or values["LATCHWAY_LOG_LEVEL"]["value"] != "info"
        or values["LATCHWAY_MIGRATE_ON_START"]["value"] != "false"
        or values["LATCHWAY_PUBLIC_ORIGIN"]["value"] != endpoint
        or values["LATCHWAY_SHUTDOWN_TIMEOUT"]["value"] != "8s"
    ):
        raise EvidenceError(code)
    return values


def validate_cloud_run_runtime_profile(
    spec: Any,
    annotations: Any,
    endpoint: str,
    code: str,
) -> Mapping[str, Any]:
    runtime = require_fields(
        spec,
        {"serviceAccountName", "containerConcurrency", "timeoutSeconds", "containers"},
        code,
    )
    if (
        annotations != CLOUD_RUN_RUNTIME_ANNOTATIONS
        or runtime["serviceAccountName"] != CLOUD_RUN_RUNTIME_SERVICE_ACCOUNT
        or type(runtime["containerConcurrency"]) is not int
        or runtime["containerConcurrency"] != 100
        or type(runtime["timeoutSeconds"]) is not int
        or runtime["timeoutSeconds"] != 3600
        or not isinstance(runtime["containers"], list)
        or len(runtime["containers"]) != 1
        or not isinstance(runtime["containers"][0], dict)
    ):
        raise EvidenceError(code)
    container = require_fields(
        runtime["containers"][0],
        {
            "name", "image", "command", "args", "ports", "resources", "env",
            "startupProbe", "livenessProbe",
        },
        code,
    )
    if (
        container["name"] != "latchway"
        or container["command"] != ["/latchway"]
        or container["args"] != ["serve", "--role", "all"]
        or container["ports"] != [{"name": "http1", "containerPort": 8080}]
        or container["resources"] != {"limits": {"cpu": "2", "memory": "2Gi"}}
        or container["startupProbe"] != CLOUD_RUN_STARTUP_PROBE
        or container["livenessProbe"] != CLOUD_RUN_LIVENESS_PROBE
    ):
        raise EvidenceError(code)
    environment = validate_cloud_run_runtime_environment(container, endpoint, code)
    return {
        "serviceAccountName": runtime["serviceAccountName"],
        "containerConcurrency": runtime["containerConcurrency"],
        "timeoutSeconds": runtime["timeoutSeconds"],
        "annotations": annotations,
        "container": {key: container[key] for key in container},
        "environment": environment,
    }


def validate_cloud_run_yaml() -> Mapping[str, Any]:
    service = yaml_as_json(ROOT / "deploy/cloud-run/service.yaml")
    job = yaml_as_json(ROOT / "deploy/cloud-run/migration-job.yaml")
    if not isinstance(service, dict) or not isinstance(job, dict):
        raise EvidenceError("cloud_run_yaml_invalid")
    service_container = cloud_run_containers(service)[0]
    job_container = cloud_run_containers(job)[0]
    if service_container.get("image") != "${LATCHWAY_IMAGE}" or job_container.get("image") != "${LATCHWAY_IMAGE}":
        raise EvidenceError("cloud_run_image_placeholder_invalid")
    template = nested(service, "spec", "template")
    runtime_spec = nested(template, "spec")
    annotations = nested(template, "metadata", "annotations")
    service_annotations = nested(service, "metadata", "annotations")
    job_annotations = nested(job, "spec", "template", "metadata", "annotations")
    if (
        not isinstance(runtime_spec, dict)
        or service_annotations != {
            "run.googleapis.com/ingress": "all",
            "run.googleapis.com/invoker-iam-disabled": "true",
        }
        or annotations != {
            **CLOUD_RUN_BASE_RUNTIME_ANNOTATIONS,
            **CLOUD_RUN_CLOUD_SQL_NETWORK_ANNOTATIONS,
        }
        or job_annotations != CLOUD_RUN_CLOUD_SQL_NETWORK_ANNOTATIONS
        or set(runtime_spec) != {
            "serviceAccountName", "containerConcurrency", "timeoutSeconds", "containers",
        }
        or runtime_spec.get("serviceAccountName") != "${RUNTIME_SERVICE_ACCOUNT}"
        or type(runtime_spec.get("containerConcurrency")) is not int
        or runtime_spec["containerConcurrency"] != 100
        or type(runtime_spec.get("timeoutSeconds")) is not int
        or runtime_spec["timeoutSeconds"] != 3600
        or service_container.get("command") != ["/latchway"]
        or service_container.get("args") != ["serve", "--role", "all"]
        or service_container.get("ports") != [{"name": "http1", "containerPort": 8080}]
        or service_container.get("resources") != {"limits": {"cpu": "2", "memory": "2Gi"}}
        or service_container.get("startupProbe") != CLOUD_RUN_STARTUP_PROBE
        or service_container.get("livenessProbe") != CLOUD_RUN_LIVENESS_PROBE
        or set(service_container) != {
            "name", "image", "command", "args", "ports", "resources", "env",
            "startupProbe", "livenessProbe",
        }
    ):
        raise EvidenceError("cloud_run_runtime_profile_invalid")
    environment = service_container.get("env")
    if (
        not isinstance(environment, list)
        or [item.get("name") for item in environment if isinstance(item, dict)]
        != list(CLOUD_RUN_RUNTIME_ENVIRONMENT_NAMES)
    ):
        raise EvidenceError("cloud_run_runtime_environment_invalid")
    by_name = env_map(service_container)
    expected_plain = {
        "LATCHWAY_ROLE": "all",
        "LATCHWAY_LOG_LEVEL": "info",
        "LATCHWAY_MIGRATE_ON_START": "false",
        "LATCHWAY_PUBLIC_ORIGIN": "${LATCHWAY_PUBLIC_ORIGIN}",
        "LATCHWAY_SHUTDOWN_TIMEOUT": "8s",
        "LATCHWAY_DB_MAX_CONNECTIONS": "20",
        "LATCHWAY_DB_COMPLETION_CONNECTIONS": "5",
    }
    if any(nested(by_name.get(name), "value") != value for name, value in expected_plain.items()):
        raise EvidenceError("cloud_run_runtime_environment_invalid")
    expected_versions = {
        "LATCHWAY_DATABASE_URL": ("latchway-database-url", "${DATABASE_SECRET_VERSION}"),
        "LATCHWAY_MASTER_KEY": ("latchway-master-key", "${MASTER_KEY_SECRET_VERSION}"),
    }
    for name, (secret, version) in expected_versions.items():
        reference = nested(by_name.get(name), "valueFrom", "secretKeyRef")
        if reference != {"name": secret, "key": version}:
            raise EvidenceError("cloud_run_runtime_secret_reference_invalid")
    job_outer = nested(job, "spec", "template", "spec")
    task_spec = nested(job_outer, "template", "spec")
    job_environment = job_container.get("env")
    if (
        not isinstance(job_outer, dict)
        or set(job_outer) != {"taskCount", "parallelism", "template"}
        or type(job_outer.get("taskCount")) is not int
        or job_outer["taskCount"] != 1
        or type(job_outer.get("parallelism")) is not int
        or job_outer["parallelism"] != 1
        or not isinstance(task_spec, dict)
        or set(task_spec) != {
            "serviceAccountName", "maxRetries", "timeoutSeconds", "containers",
        }
        or task_spec.get("serviceAccountName") != "${MIGRATOR_SERVICE_ACCOUNT}"
        or type(task_spec.get("maxRetries")) is not int
        or task_spec["maxRetries"] != 0
        or str(task_spec.get("timeoutSeconds")).rstrip("s") != "900"
        or job_container.get("name") != "latchway-migrate"
        or job_container.get("command") != ["/latchway"]
        or job_container.get("args") != ["migrate", "up"]
        or job_container.get("resources") != CLOUD_RUN_MIGRATION_RESOURCES
        or set(job_container) != {"name", "image", "command", "args", "resources", "env"}
        or job_environment != [{
            "name": "LATCHWAY_DATABASE_URL",
            "valueFrom": {"secretKeyRef": {
                "name": "latchway-database-url", "key": "${DATABASE_SECRET_VERSION}",
            }},
        }]
    ):
        raise EvidenceError("cloud_run_migration_profile_invalid")
    if "latest" in json.dumps({"service": service, "job": job}, sort_keys=True).lower():
        raise EvidenceError("cloud_run_unpinned_secret_reference")
    return {"service_api": service.get("apiVersion"), "job_api": job.get("apiVersion")}


def require_text(path: Path, fragments: Iterable[str], code: str) -> Mapping[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise EvidenceError(code) from None
    missing = [fragment for fragment in fragments if fragment not in text]
    if missing:
        raise EvidenceError(code, {"missing_count": len(missing), "file": path.name})
    return {"file": path.name, "bytes": len(text.encode())}


def validate_cloud_run_terraform() -> Mapping[str, Any]:
    main = ROOT / "deploy/cloud-run/terraform/main.tf"
    variables = ROOT / "deploy/cloud-run/terraform/variables.tf"
    outputs = ROOT / "deploy/cloud-run/terraform/outputs.tf"
    tfvars = ROOT / "deploy/cloud-run/terraform/terraform.tfvars.example"
    versions = ROOT / "deploy/cloud-run/terraform/versions.tf"
    require_text(
        main,
        (
            'resource "google_cloud_run_v2_service" "main"',
            'resource "google_cloud_run_v2_job" "migrate"',
            '"cloudresourcemanager.googleapis.com"',
            '"iam.googleapis.com"',
            'resource "google_service_account" "runtime"',
            'resource "google_service_account" "migrator"',
            "service_account = google_service_account.migrator.email",
            "google_secret_manager_secret_iam_member.migrator_database",
            "version = google_secret_manager_secret_version.database_url.version",
            "version = google_secret_manager_secret_version.master_key.version",
            "max_retries     = 0",
            'name    = "latchway-migrate"',
            'memory = "512Mi"',
            "depends_on = [google_project_service.required]",
            'args    = ["migrate", "up"]',
            'name  = "LATCHWAY_SHUTDOWN_TIMEOUT"',
            'value = "8s"',
            'name  = "LATCHWAY_DB_MAX_CONNECTIONS"',
            "value = tostring(var.db_connections_per_instance)",
            'name  = "LATCHWAY_DB_COMPLETION_CONNECTIONS"',
            "value = tostring(var.db_completion_connections_per_instance)",
            "var.db_completion_connections_per_instance < var.db_connections_per_instance",
            'name = "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN"',
            "var.inject_admin_bootstrap_token ? [1] : []",
            'path = "/readyz"',
            'path = "/healthz"',
            'execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"',
            "image   = var.service_image",
            "image   = var.migration_image",
            "edition           = var.database_edition",
            'revision = var.service_revision_name',
            "percent  = var.service_traffic_percent",
            'dynamic "traffic"',
            "var.service_image == var.migration_approved_service_image",
        ),
        "cloud_run_terraform_incomplete",
    )
    if 'version = "latest"' in main.read_text(encoding="utf-8"):
        raise EvidenceError("cloud_run_terraform_secret_version_unpinned")
    require_text(
        variables,
        (
            'regex("@sha256:[0-9a-f]{64}$", var.service_image)',
            'regex("@sha256:[0-9a-f]{64}$", var.migration_image)',
            'regex("@sha256:[0-9a-f]{64}$", var.migration_approved_service_image)',
            'variable "service_revision_name"',
            'variable "previous_service_revision_name"',
            'variable "service_traffic_percent"',
            'variable "database_edition"',
            'condition     = var.database_edition == "ENTERPRISE"',
            'variable "inject_admin_bootstrap_token"',
            'variable "migrate_on_start"',
            'variable "deploy_service"',
            'variable "db_connections_per_instance"',
            "floor(var.db_connections_per_instance) == var.db_connections_per_instance",
            'variable "db_completion_connections_per_instance"',
            "floor(var.db_completion_connections_per_instance) == var.db_completion_connections_per_instance",
            "default = 3",
        ),
        "cloud_run_variables_incomplete",
    )
    require_text(
        outputs,
        (
            'output "configured_steady_state_application_database_connections"',
            'output "configured_steady_state_regular_application_database_connections"',
            'output "configured_steady_state_completion_application_database_connections"',
            'output "maximum_application_database_connections"',
            'output "maximum_regular_application_database_connections"',
            'output "maximum_completion_application_database_connections"',
            "Configured steady-state aggregate application connection ceiling across max_instances Cloud Run service instances",
            "Configured steady-state regular-work connection ceiling across max_instances Cloud Run service instances",
            "Configured steady-state completion-reserved connection ceiling across max_instances Cloud Run service instances",
            "Compatibility alias for configured_steady_state_application_database_connections",
            "Compatibility alias for configured_steady_state_regular_application_database_connections",
            "Compatibility alias for configured_steady_state_completion_application_database_connections",
            "Rollout and provider overshoot are excluded.",
            "Despite the legacy maximum name, rollout and provider overshoot are excluded.",
            "var.max_instances * var.db_connections_per_instance",
            "var.max_instances * (var.db_connections_per_instance - var.db_completion_connections_per_instance)",
            "var.max_instances * var.db_completion_connections_per_instance",
        ),
        "cloud_run_outputs_incomplete",
    )
    require_text(
        tfvars,
        (
            "db_connections_per_instance            = 20",
            "db_completion_connections_per_instance = 5",
            "max_instances                          = 3",
            "inject_admin_bootstrap_token           = false",
            "migrate_on_start                       = false",
            "deploy_service                   = false",
        ),
        "cloud_run_tfvars_incomplete",
    )
    require_text(versions, ('backend "gcs" {}',), "cloud_run_backend_incomplete")
    return {"terraform_files": len(list(main.parent.glob("*.tf")))}


def validate_aws_terraform() -> Mapping[str, Any]:
    main = ROOT / "deploy/aws/terraform/main.tf"
    variables = ROOT / "deploy/aws/terraform/variables.tf"
    outputs = ROOT / "deploy/aws/terraform/outputs.tf"
    tfvars = ROOT / "deploy/aws/terraform/terraform.tfvars.example"
    require_text(
        main,
        (
            'resource "aws_ecs_service" "main"',
            'resource "aws_db_instance" "main"',
            'stopTimeout            = 35',
            'deregistration_delay = 60',
            '{ name = "LATCHWAY_SHUTDOWN_TIMEOUT", value = "30s" }',
            '{ name = "LATCHWAY_DB_MAX_CONNECTIONS", value = tostring(var.db_connections_per_task) }',
            '{ name = "LATCHWAY_DB_COMPLETION_CONNECTIONS", value = tostring(var.db_completion_connections_per_task) }',
            "var.db_completion_connections_per_task < var.db_connections_per_task",
            'command     = ["CMD", "/latchway", "--server", "http://127.0.0.1:8080", "--output", "json", "readiness"]',
            'path                = "/readyz"',
            "wait_for_steady_state = true",
            "assign_public_ip = false",
            "var.inject_admin_bootstrap_token ? [aws_secretsmanager_secret.admin_bootstrap.arn] : []",
        ),
        "aws_terraform_incomplete",
    )
    require_text(
        variables,
        (
            'regex("@sha256:[0-9a-f]{64}$", var.image)',
            'variable "migrate_on_start"',
            'variable "db_connections_per_task"',
            "floor(var.db_connections_per_task) == var.db_connections_per_task",
            'variable "db_completion_connections_per_task"',
            "floor(var.db_completion_connections_per_task) == var.db_completion_connections_per_task",
        ),
        "aws_variables_incomplete",
    )
    require_text(
        outputs,
        (
            'output "configured_steady_state_application_database_connections"',
            'output "configured_steady_state_regular_application_database_connections"',
            'output "configured_steady_state_completion_application_database_connections"',
            'output "maximum_application_database_connections"',
            'output "maximum_regular_application_database_connections"',
            'output "maximum_completion_application_database_connections"',
            "Configured steady-state aggregate application connection ceiling across maximum_tasks ECS tasks",
            "Configured steady-state regular-work connection ceiling across maximum_tasks ECS tasks",
            "Configured steady-state completion-reserved connection ceiling across maximum_tasks ECS tasks",
            "Compatibility alias for configured_steady_state_application_database_connections",
            "Compatibility alias for configured_steady_state_regular_application_database_connections",
            "Compatibility alias for configured_steady_state_completion_application_database_connections",
            "Rollout and provider overshoot are excluded.",
            "Despite the legacy maximum name, rollout and provider overshoot are excluded.",
            "var.maximum_tasks * var.db_connections_per_task",
            "var.maximum_tasks * (var.db_connections_per_task - var.db_completion_connections_per_task)",
            "var.maximum_tasks * var.db_completion_connections_per_task",
        ),
        "aws_outputs_incomplete",
    )
    require_text(
        tfvars,
        (
            "db_connections_per_task            = 20",
            "db_completion_connections_per_task = 5",
        ),
        "aws_tfvars_incomplete",
    )
    return {"terraform_files": len(list(main.parent.glob("*.tf")))}


def require_exact_keys(value: Any, expected: Iterable[str], code: str) -> dict[str, Any]:
    keys = set(expected)
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceError(code)
    return value


def validate_fly_document(document: Any) -> Mapping[str, Any]:
    root = require_exact_keys(
        document,
        (
            "app",
            "primary_region",
            "kill_signal",
            "kill_timeout",
            "build",
            "deploy",
            "env",
            "http_service",
            "vm",
        ),
        "fly_top_level_fields_invalid",
    )
    require_exact_keys(root["build"], ("dockerfile",), "fly_build_fields_invalid")
    require_exact_keys(
        root["deploy"],
        (
            "release_command",
            "release_command_timeout",
            "strategy",
            "max_unavailable",
            "wait_timeout",
        ),
        "fly_deploy_fields_invalid",
    )
    require_exact_keys(
        root["env"],
        (
            "PORT",
            "LATCHWAY_ROLE",
            "LATCHWAY_LOG_LEVEL",
            "LATCHWAY_MIGRATE_ON_START",
            "LATCHWAY_DB_MAX_CONNECTIONS",
            "LATCHWAY_DB_COMPLETION_CONNECTIONS",
            "LATCHWAY_SHUTDOWN_TIMEOUT",
        ),
        "fly_environment_fields_invalid",
    )
    service = require_exact_keys(
        root["http_service"],
        (
            "internal_port",
            "force_https",
            "auto_stop_machines",
            "auto_start_machines",
            "min_machines_running",
            "processes",
            "concurrency",
            "checks",
        ),
        "fly_http_service_fields_invalid",
    )
    require_exact_keys(
        service["concurrency"],
        ("type", "soft_limit", "hard_limit"),
        "fly_concurrency_fields_invalid",
    )
    checks = service["checks"]
    if not isinstance(checks, list) or len(checks) != 2:
        raise EvidenceError("fly_health_checks_invalid")
    for check in checks:
        require_exact_keys(
            check,
            ("grace_period", "interval", "method", "timeout", "path"),
            "fly_health_check_fields_invalid",
        )
    machines = root["vm"]
    if not isinstance(machines, list) or len(machines) != 1:
        raise EvidenceError("fly_vm_invalid")
    require_exact_keys(
        machines[0], ("memory", "cpu_kind", "cpus"), "fly_vm_fields_invalid"
    )
    if (
        root.get("app") != "replace-with-your-latchway-app"
        or root.get("primary_region") != "sin"
    ):
        raise EvidenceError("fly_identity_template_invalid")
    if nested(root, "build", "dockerfile") != "Dockerfile":
        raise EvidenceError("fly_build_invalid")
    if nested(document, "deploy", "release_command") != "/latchway migrate up":
        raise EvidenceError("fly_migration_command_invalid")
    if nested(document, "deploy", "release_command_timeout") != "15m":
        raise EvidenceError("fly_migration_timeout_invalid")
    if (
        nested(document, "deploy", "max_unavailable") != 1
        or nested(document, "deploy", "wait_timeout") != "10m"
    ):
        raise EvidenceError("fly_rollout_budget_invalid")
    if (
        document.get("kill_signal") != "SIGTERM"
        or document.get("kill_timeout") != "35s"
    ):
        raise EvidenceError("fly_shutdown_budget_invalid")
    if nested(document, "env", "LATCHWAY_SHUTDOWN_TIMEOUT") != "30s":
        raise EvidenceError("fly_app_shutdown_timeout_invalid")
    if nested(root, "deploy", "strategy") != "rolling":
        raise EvidenceError("fly_rollout_strategy_invalid")
    if (
        nested(root, "env", "PORT") != "8080"
        or nested(root, "env", "LATCHWAY_ROLE") != "all"
        or nested(root, "env", "LATCHWAY_LOG_LEVEL") != "info"
        or nested(root, "env", "LATCHWAY_MIGRATE_ON_START") != "false"
        or nested(root, "env", "LATCHWAY_DB_MAX_CONNECTIONS") != "20"
        or nested(root, "env", "LATCHWAY_DB_COMPLETION_CONNECTIONS") != "5"
    ):
        raise EvidenceError("fly_environment_invalid")
    if (
        nested(service, "internal_port") != 8080
        or nested(service, "force_https") is not True
        or nested(service, "auto_stop_machines") is not False
        or nested(service, "auto_start_machines") is not True
        or nested(service, "min_machines_running") != 2
        or nested(service, "processes") != ["app"]
    ):
        raise EvidenceError("fly_http_service_invalid")
    if (
        nested(service, "concurrency", "type") != "requests"
        or nested(service, "concurrency", "soft_limit") != 80
        or nested(service, "concurrency", "hard_limit") != 100
    ):
        raise EvidenceError("fly_concurrency_invalid")
    paths = {item["path"] for item in checks}
    if paths != {"/healthz", "/readyz"}:
        raise EvidenceError("fly_health_checks_invalid")
    if any(item["method"] != "GET" for item in checks):
        raise EvidenceError("fly_health_check_method_invalid")
    checks_by_path = {item["path"]: item for item in checks}
    if checks_by_path["/healthz"] != {
        "grace_period": "10s",
        "interval": "30s",
        "method": "GET",
        "timeout": "5s",
        "path": "/healthz",
    } or checks_by_path["/readyz"] != {
        "grace_period": "30s",
        "interval": "15s",
        "method": "GET",
        "timeout": "5s",
        "path": "/readyz",
    }:
        raise EvidenceError("fly_health_check_timing_invalid")
    if machines[0] != {"memory": "2gb", "cpu_kind": "shared", "cpus": 2}:
        raise EvidenceError("fly_vm_invalid")
    return {"health_paths": sorted(paths), "strict_offline_fields": True}


def validate_fly() -> Mapping[str, Any]:
    try:
        document = tomllib.loads(
            (ROOT / "deploy/fly/fly.toml").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise EvidenceError("fly_toml_invalid") from None
    result = validate_fly_document(document)
    require_text(
        ROOT / "scripts/validate-deployments.sh",
        (
            'if [[ -n "${FLY_API_TOKEN:-}" ]]',
            'FLY_APP is required when FLY_API_TOKEN is set',
            'flyctl config validate --strict --app "$FLY_APP" --config deploy/fly/fly.toml',
            'fly config validate --strict --app "$FLY_APP" --config deploy/fly/fly.toml',
        ),
        "fly_cli_validation_incomplete",
    )
    require_text(
        ROOT / "deploy/fly/README.md",
        (
            "python3 scripts/deployment-evidence.py static",
            'flyctl config validate --strict --app "$FLY_APP" --config deploy/fly/fly.toml',
        ),
        "fly_documentation_validation_incomplete",
    )
    return result


def validate_cloudflare() -> Mapping[str, Any]:
    configuration = ROOT / "deploy/cloudflare/wrangler.jsonc"
    container = ROOT / "deploy/cloudflare/src/container.ts"
    worker = ROOT / "deploy/cloudflare/src/index.ts"
    package = read_json(ROOT / "deploy/cloudflare/package.json")
    require_text(
        configuration,
        (
            '"image": "../../Dockerfile"',
            '"max_instances": 4',
            '"LATCHWAY_DB_MAX_CONNECTIONS": "5"',
            '"LATCHWAY_DB_COMPLETION_CONNECTIONS": "2"',
            '"LATCHWAY_SHUTDOWN_TIMEOUT": "30s"',
            '"rollout_step_percentage": [10, 50, 100]',
            '"rollout_active_grace_period": 35',
            '"observability": {',
        ),
        "cloudflare_configuration_incomplete",
    )
    require_text(
        container,
        (
            'const command = ["/latchway", "--output", "json", "migrate", "status"]',
            "this.ctx.container!.exec(command",
            'await this.stop("SIGTERM")',
            "MAX_EVIDENCE_OUTPUT_BYTES",
            'LATCHWAY_DB_MAX_CONNECTIONS: requiredString(',
            '"LATCHWAY_DB_MAX_CONNECTIONS"',
            'LATCHWAY_DB_COMPLETION_CONNECTIONS: requiredString(',
            '"LATCHWAY_DB_COMPLETION_CONNECTIONS"',
            "latchway:evidence:pending-stop",
            "params.exitCode",
        ),
        "cloudflare_container_evidence_incomplete",
    )
    require_text(
        worker,
        (
            '"/__latchway/cloudflare/evidence/migration"',
            '"/__latchway/cloudflare/evidence/shutdown"',
            'Reflect.get(env, "LATCHWAY_EVIDENCE_TOKEN")',
            'crypto.subtle.digest("SHA-256"',
            "crypto.subtle.timingSafeEqual(expectedDigest, providedDigest)",
            '"Cache-Control": "no-store"',
            'getByName("instance-0")',
        ),
        "cloudflare_worker_evidence_incomplete",
    )
    if nested(package, "devDependencies", "wrangler") != "4.127.1":
        raise EvidenceError("cloudflare_wrangler_not_pinned")
    return {"wrangler_version": "4.127.1", "instances": 4}


def validate_wrangler_lock_documents(
    package: Any, lock: Any, allowlist: Any
) -> Mapping[str, Any]:
    expected_package = {
        "name": "@latchway/trusted-wrangler-toolchain",
        "version": "1.0.0",
        "private": True,
        "description": "Exact source-free Wrangler toolchain used by deployment evidence.",
        "engines": {"node": "24.19.0"},
        "dependencies": {"wrangler": "4.127.1"},
    }
    if package != expected_package:
        raise EvidenceError("cloudflare_toolchain_package_invalid")
    if not isinstance(lock, dict) or set(lock) != {
        "name",
        "version",
        "lockfileVersion",
        "requires",
        "packages",
    }:
        raise EvidenceError("cloudflare_toolchain_lock_fields_invalid")
    packages = lock.get("packages")
    if (
        lock.get("name") != expected_package["name"]
        or lock.get("version") != expected_package["version"]
        or lock.get("lockfileVersion") != 3
        or lock.get("requires") is not True
        or not isinstance(packages, dict)
        or len(packages) != WRANGLER_PACKAGE_COUNT + 1
        or packages.get("")
        != {
            "name": expected_package["name"],
            "version": expected_package["version"],
            "dependencies": expected_package["dependencies"],
            "engines": expected_package["engines"],
        }
    ):
        raise EvidenceError("cloudflare_toolchain_lock_identity_invalid")

    allowed_packages: list[dict[str, str]] = []
    for path, value in packages.items():
        if path == "":
            continue
        if not isinstance(path, str):
            raise EvidenceError("cloudflare_toolchain_package_path_invalid")
        pure_path = PurePosixPath(path)
        if (
            not path.startswith("node_modules/")
            or pure_path.is_absolute()
            or any(part in ("", ".", "..") for part in pure_path.parts)
            or not isinstance(value, dict)
        ):
            raise EvidenceError("cloudflare_toolchain_package_path_invalid")
        version = value.get("version")
        resolved = value.get("resolved")
        integrity = value.get("integrity")
        if not isinstance(version, str) or not version:
            raise EvidenceError("cloudflare_toolchain_package_version_missing")
        if not isinstance(resolved, str) or NPM_REGISTRY_TARBALL.fullmatch(resolved) is None:
            raise EvidenceError("cloudflare_toolchain_package_registry_invalid", {"package": path})
        if not isinstance(integrity, str) or NPM_SHA512_INTEGRITY.fullmatch(integrity) is None:
            raise EvidenceError("cloudflare_toolchain_package_integrity_invalid", {"package": path})
        allowed_packages.append(
            {
                "path": path,
                "version": version,
                "resolved": resolved,
                "integrity": integrity,
            }
        )
    wrangler = packages.get("node_modules/wrangler")
    if (
        not isinstance(wrangler, dict)
        or wrangler.get("version") != "4.127.1"
        or wrangler.get("integrity") != WRANGLER_INTEGRITY
    ):
        raise EvidenceError("cloudflare_toolchain_wrangler_invalid")
    expected_allowlist = {
        "schema_version": 1,
        "kind": "latchway_trusted_npm_package_allowlist",
        "package_count": WRANGLER_PACKAGE_COUNT,
        "packages": sorted(allowed_packages, key=lambda item: item["path"]),
    }
    if allowlist != expected_allowlist:
        raise EvidenceError("cloudflare_toolchain_allowlist_mismatch")
    return {
        "wrangler_version": "4.127.1",
        "package_count": WRANGLER_PACKAGE_COUNT,
        "registry": "https://registry.npmjs.org",
    }


def validate_wrangler_toolchain() -> Mapping[str, Any]:
    package_path = WRANGLER_TOOLCHAIN_ROOT / "package.json"
    lock_path = WRANGLER_TOOLCHAIN_ROOT / "package-lock.json"
    allowlist_path = WRANGLER_TOOLCHAIN_ROOT / "allowed-packages.json"
    expected_hashes = {
        package_path: WRANGLER_PACKAGE_JSON_SHA256,
        lock_path: WRANGLER_PACKAGE_LOCK_SHA256,
        allowlist_path: WRANGLER_ALLOWED_PACKAGES_SHA256,
    }
    if any(not real_file(path) for path in expected_hashes):
        raise EvidenceError("cloudflare_toolchain_file_invalid")
    for path, expected in expected_hashes.items():
        if sha256_file(path) != expected:
            raise EvidenceError("cloudflare_toolchain_hash_mismatch", {"file": path.name})
    return validate_wrangler_lock_documents(
        read_json(package_path), read_json(lock_path), read_json(allowlist_path)
    )


def validate_workflow() -> Mapping[str, Any]:
    path = ROOT / ".github/workflows/deployment-evidence.yml"
    document = yaml_as_json(path)
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict) or set(jobs) != {
        "static",
        "authenticate",
        "cloudflare-toolchain-source",
        "trusted-cloudflare-tool",
        "prepare",
        "capture",
        "capture_compose",
        "finalize",
        "sign",
    }:
        raise EvidenceError("deployment_workflow_jobs_invalid")
    expected_toolchain_environment = {
        "TRUSTED_WRANGLER_PACKAGE_JSON_SHA256": WRANGLER_PACKAGE_JSON_SHA256,
        "TRUSTED_WRANGLER_PACKAGE_LOCK_SHA256": WRANGLER_PACKAGE_LOCK_SHA256,
        "TRUSTED_WRANGLER_ALLOWED_PACKAGES_SHA256": WRANGLER_ALLOWED_PACKAGES_SHA256,
        "TRUSTED_WRANGLER_PACKAGE_COUNT": str(WRANGLER_PACKAGE_COUNT),
    }
    if document.get("env") != expected_toolchain_environment:
        raise EvidenceError("deployment_wrangler_toolchain_pins_invalid")
    uses: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            raise EvidenceError("deployment_workflow_job_invalid")
        for step in job.get("steps", []):
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                uses.append(step["uses"])
    if not uses or any(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", item) is None for item in uses):
        raise EvidenceError("deployment_workflow_action_unpinned")
    authenticate = jobs.get("authenticate")
    cloudflare_toolchain_source = jobs.get("cloudflare-toolchain-source")
    trusted_cloudflare_tool = jobs.get("trusted-cloudflare-tool")
    prepare_job = jobs.get("prepare")
    capture_job = jobs.get("capture")
    compose_job = jobs.get("capture_compose")
    finalize_job = jobs.get("finalize")
    sign_job = jobs.get("sign")
    if any(
        not isinstance(item, dict)
        for item in (
            authenticate,
            cloudflare_toolchain_source,
            trusted_cloudflare_tool,
            prepare_job,
            capture_job,
            compose_job,
            finalize_job,
            sign_job,
        )
    ):
        raise EvidenceError("deployment_workflow_job_invalid")
    for name, job in (
        ("authenticate", authenticate),
        ("trusted_cloudflare_tool", trusted_cloudflare_tool),
        ("capture", capture_job),
        ("capture_compose", compose_job),
        ("sign", sign_job),
    ):
        if any(
            isinstance(step, dict)
            and str(step.get("uses", "")).startswith("actions/checkout@")
            for step in job.get("steps", [])
        ):
            raise EvidenceError(f"deployment_{name}_checkout_forbidden")
    if authenticate.get("environment") != "deployment-evidence-authentication":
        raise EvidenceError("deployment_authentication_environment_invalid")
    if cloudflare_toolchain_source.get("permissions") != {"contents": "read"}:
        raise EvidenceError("deployment_cloudflare_toolchain_source_permissions_invalid")
    if trusted_cloudflare_tool.get("permissions") != {}:
        raise EvidenceError("deployment_trusted_cloudflare_tool_permissions_invalid")
    if capture_job.get("environment") != "deployment-evidence-${{ inputs.platform }}":
        raise EvidenceError("deployment_capture_environment_invalid")
    if compose_job.get("environment") != "deployment-evidence-compose":
        raise EvidenceError("deployment_compose_environment_invalid")
    if finalize_job.get("environment") != "deployment-evidence-${{ inputs.platform }}":
        raise EvidenceError("deployment_finalize_environment_invalid")
    if sign_job.get("environment") != "deployment-evidence-signing":
        raise EvidenceError("deployment_signing_environment_invalid")
    for name, job in (
        ("prepare", prepare_job),
        ("trusted_cloudflare_tool", trusted_cloudflare_tool),
        ("capture", capture_job),
        ("capture_compose", compose_job),
        ("finalize", finalize_job),
    ):
        if any(
            permission in job.get("permissions", {})
            for permission in ("artifact-metadata", "attestations")
        ):
            raise EvidenceError(f"deployment_{name}_signing_permission_forbidden")
    if compose_job.get("permissions", {}).get("id-token") == "write":
        raise EvidenceError("deployment_compose_oidc_permission_forbidden")
    if capture_job.get("permissions", {}).get("id-token") != "write":
        raise EvidenceError("deployment_provider_oidc_permission_missing")
    prepare_text = json.dumps(prepare_job, sort_keys=True)
    if (
        "setup-flyctl" in prepare_text
        or "flyctl config validate" in prepare_text
        or "${{ secrets." in prepare_text
    ):
        raise EvidenceError("deployment_fly_credential_boundary_invalid")
    fly_validation_steps = [
        step
        for step in capture_job.get("steps", [])
        if isinstance(step, dict)
        and step.get("name")
        == "Validate Fly configuration against the authenticated platform"
    ]
    if len(fly_validation_steps) != 1:
        raise EvidenceError("deployment_fly_platform_validation_missing")
    fly_validation = fly_validation_steps[0]
    if (
        fly_validation.get("if") != "inputs.platform == 'fly_io'"
        or fly_validation.get("env")
        != {"FLY_API_TOKEN": "${{ secrets.FLY_API_TOKEN }}"}
        or fly_validation.get("run")
        != 'flyctl config validate --strict --app "$FLY_APP" --config "$RUNNER_TEMP/provider-inputs/fly.toml"'
    ):
        raise EvidenceError("deployment_fly_platform_validation_invalid")
    capture_text = json.dumps(capture_job, sort_keys=True)
    if any(
        fragment in capture_text
        for fragment in (
            "actions/checkout@",
            "docker compose",
            "npm ",
            "npx ",
            "pnpm ",
            "yarn ",
            "corepack ",
            "scripts/cloudflare-deployment-capture.py",
            "scripts/deployment-evidence.py",
            "scripts/release-candidate.py",
        )
    ):
        raise EvidenceError("deployment_oidc_candidate_execution_forbidden")
    cloudflare_capture_steps = [
        step
        for step in capture_job.get("steps", [])
        if isinstance(step, dict)
        and step.get("name")
        == "Capture Cloudflare Container image, migration, secret, and replacement evidence"
    ]
    if len(cloudflare_capture_steps) != 1:
        raise EvidenceError("deployment_cloudflare_capture_step_invalid")
    cloudflare_run = cloudflare_capture_steps[0].get("run")
    if not isinstance(cloudflare_run, str):
        raise EvidenceError("deployment_cloudflare_capture_step_invalid")
    required_cloudflare_discovery = (
        "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/containers/dash/applications",
        "cloudflare_application_per_page=100",
        "cloudflare_application_max_pages=100",
        "cloudflare_application_max_records=5000",
        "cloudflare_application_max_page_bytes=1048576",
        "cloudflare_application_max_output_bytes=8388608",
        "list_cloudflare_applications()",
        '--header @"$cloudflare_api_headers"',
        '--data-urlencode "page_token=$page_token"',
        ".result_info.next_page_token",
        "seen_page_token_hashes",
        'if .health.instances.failed > 0 then "degraded"',
        'elif .health.instances.starting > 0 or .health.instances.scheduling > 0 then "provisioning"',
        'elif .health.instances.active > 0 then "active"',
        "then .[0] | {name, image, state, id, version}",
        "list_cloudflare_applications /tmp/cloudflare-applications-before.json",
        "list_cloudflare_applications /tmp/cloudflare-applications.json",
    )
    if any(fragment not in cloudflare_run for fragment in required_cloudflare_discovery):
        raise EvidenceError("deployment_cloudflare_application_pagination_incomplete")
    if any(
        fragment in cloudflare_run
        for fragment in (
            '"${wrangler[@]}" containers list',
            '--header "Authorization: Bearer $CLOUDFLARE_API_TOKEN"',
        )
    ):
        raise EvidenceError("deployment_cloudflare_application_pagination_bypassed")
    cleanup_steps = [
        step
        for step in capture_job.get("steps", [])
        if isinstance(step, dict)
        and step.get("name") == "Remove any temporary Cloudflare registry credential"
    ]
    if len(cleanup_steps) != 1 or any(
        fragment not in str(cleanup_steps[0].get("run", ""))
        for fragment in (
            "$RUNNER_TEMP/cloudflare-container-api.headers",
            "$RUNNER_TEMP/cloudflare-applications-api-response.json",
            "$RUNNER_TEMP/cloudflare-applications-api-normalized.json",
            "$RUNNER_TEMP/cloudflare-applications-api-accumulator.json",
            "$RUNNER_TEMP/cloudflare-applications-api-combined.json",
        )
    ):
        raise EvidenceError("deployment_cloudflare_application_cleanup_invalid")
    toolchain_source_text = json.dumps(cloudflare_toolchain_source, sort_keys=True)
    if any(
        fragment in toolchain_source_text
        for fragment in (
            "inputs.candidate_commit",
            "provider-inputs",
            "scripts/",
            "secrets.",
            "id-token",
            "npm ",
            "npx ",
            "pnpm ",
            "yarn ",
            "corepack ",
        )
    ):
        raise EvidenceError("deployment_cloudflare_toolchain_source_boundary_invalid")
    for required_fragment in (
        "${{ github.sha }}",
        ".github/toolchains/wrangler/package.json",
        ".github/toolchains/wrangler/package-lock.json",
        ".github/toolchains/wrangler/allowed-packages.json",
        "sparse-checkout-cone-mode",
    ):
        if required_fragment not in toolchain_source_text:
            raise EvidenceError("deployment_cloudflare_toolchain_source_incomplete")
    trusted_tool_text = json.dumps(trusted_cloudflare_tool, sort_keys=True)
    if any(
        fragment in trusted_tool_text
        for fragment in (
            "actions/checkout@",
            "provider-inputs",
            "scripts/",
            "secrets.",
            "id-token",
        )
    ):
        raise EvidenceError("deployment_trusted_cloudflare_tool_boundary_invalid")
    if (
        "npm ci --ignore-scripts" not in trusted_tool_text
        or "WRANGLER_WRITE_LOGS" not in trusted_tool_text
        or "allowed-packages.json" not in trusted_tool_text
        or any(
            fragment in trusted_tool_text
            for fragment in (
                "npm install",
                "npm i ",
                "npm add",
                "npm update",
                "npm exec",
                "npx ",
                "pnpm ",
                "yarn ",
                "corepack ",
            )
        )
    ):
        raise EvidenceError("deployment_trusted_cloudflare_tool_integrity_invalid")
    compose_text = json.dumps(compose_job, sort_keys=True)
    if any(
        fragment in compose_text
        for fragment in (
            "docker/login-action",
            "provider-inputs/compose",
            "compose.review.yaml",
            "compose.release.yaml",
            "packages",
        )
    ):
        raise EvidenceError("deployment_compose_registry_boundary_invalid")
    if "pull_policy:\\\"never\\\"" not in compose_text or "preloaded-images.tar" not in compose_text:
        raise EvidenceError("deployment_compose_preloaded_images_missing")
    text = path.read_text(encoding="utf-8")
    required = (
        "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",
        "environment: deployment-evidence-${{ inputs.platform }}",
        "environment: deployment-evidence-authentication",
        "environment: deployment-evidence-signing",
        "Verify immutable prepublication candidate authority with no checkout",
        "Build the candidate Cloudflare Worker without provider or OIDC credentials",
        "Read only the committed Wrangler lock closure from the workflow revision",
        "Verify and isolate the exact committed Wrangler lock closure",
        "Build a lock-closed Wrangler distribution without candidate inputs",
        "Validate and unpack only the fixed-integrity Wrangler distribution",
        "npm ci --ignore-scripts --no-audit --no-fund",
        "TRUSTED_WRANGLER_PACKAGE_LOCK_SHA256",
        "TRUSTED_WRANGLER_ALLOWED_PACKAGES_SHA256",
        "WRANGLER_WRITE_LOGS: 'false'",
        '"${wrangler[@]}" deploy --no-bundle',
        "Import and bind exact images with an empty Docker credential store",
        "docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
        "Retain raw provider observations for fresh validation",
        "Normalize the pre-captured Cloudflare responses without provider credentials",
        "Bind, validate, and seal observations without provider credentials",
        "Download validated evidence on a fresh no-checkout signer",
        "name: latchway-candidate-${{ inputs.candidate_commit }}",
        "run-id: ${{ inputs.candidate_run_id }}",
        '--source-digest "$CANDIDATE_COMMIT"',
        "--source-ref refs/heads/main",
        "--core-commit \"$CANDIDATE_COMMIT\"",
        "--core-release \"$INTENDED_TAG\"",
        "cloudflare_containers",
        "scripts/cloudflare-deployment-capture.py",
        "CLOUDFLARE_API_TOKEN",
        "containers registries credentials registry.cloudflare.com",
        "/__latchway/cloudflare/evidence/migration",
        "/__latchway/cloudflare/evidence/shutdown",
        "version: '540.0.0'",
        "version: '0.4.89'",
        'flyctl config validate --strict --app "$FLY_APP" --config "$RUNNER_TEMP/provider-inputs/fly.toml"',
        "--args=--output,json,migrate,status",
        'test "$GCP_PROJECT" = "latchway"',
        'test "$GCP_REGION" = "asia-southeast1"',
        'test "$GCP_SERVICE" = "latchway"',
        'test "$GCP_MIGRATION_JOB" = "latchway-migrate"',
        'command:["--output","json","migrate","status"]',
        'LATCHWAY_DB_COMPLETION_CONNECTIONS: "2"',
        'healthcheck:{test:["CMD","/latchway","--server","http://127.0.0.1:8080","--output","json","readiness"],interval:"5s",timeout:"5s",retries:30,start_period:"5s"}',
        'LATCHWAY_DB_COMPLETION_CONNECTIONS:"${LATCHWAY_DB_COMPLETION_CONNECTIONS:-5}"',
        "Cloud Run probe is not the release profile",
        "Cloud Run runtime secret reference is not pinned",
        "Cloud Run desired and latest-ready runtime profiles differ",
        "Cloud Run latest-ready revision identity or readiness is invalid",
        "Cloud Run traffic is not exclusively bound to the latest-ready revision",
        "ECS database pool partition is not the release profile",
        "ECS task definition is not bound to the stable service deployment and tasks",
        "Fly database pool partition is not the release profile",
        "Compose database pool partition is not the release profile",
        "Cloudflare database pool partition is not the release profile",
        "Retain a strict allowlist, not Wrangler's historical records",
        "Cloudflare raw artifact must retain exactly one active deployment and version",
        "Cloudflare provider record contains forbidden secret material",
        '"active_version_id": active_version_id',
        '"database_pool": database_pool',
        "--signal SIGTERM --time 35",
        "up -d --wait --force-recreate --no-deps latchway",
        'test "$gateway_id" != "$before_gateway_id"',
        "/tmp/compose-provider-raw",
        "actions/attest@",
        "artifact-metadata: write",
        "id-token: write",
    )
    if any(fragment not in text for fragment in required):
        raise EvidenceError("deployment_workflow_incomplete")
    if (
        "deployment_environment:" in text
        or "internal/database/migrations" in text
        or "refs/tags/" in text
    ):
        raise EvidenceError("deployment_workflow_assertion_fallback_forbidden")
    return {"pinned_actions": len(uses), "protected_environment_prefix": "deployment-evidence-"}


def report(kind: str, checks: list[Check], **extra: Any) -> dict[str, Any]:
    passed = all(item.status == "passed" for item in checks)
    result = {
        "schema_version": 1,
        "kind": kind,
        "verdict": "passed" if passed else "failed",
        "checks": [item.as_json() for item in checks],
        "summary": {
            "passed": sum(item.status == "passed" for item in checks),
            "failed": sum(item.status == "failed" for item in checks),
        },
    }
    result.update(extra)
    return result


def write_junit(path: Path, name: str, checks: Iterable[Check]) -> None:
    values = list(checks)
    suite = ET.Element(
        "testsuite",
        name=name,
        tests=str(len(values)),
        failures=str(sum(item.status == "failed" for item in values)),
        errors="0",
        skipped="0",
    )
    for item in values:
        case = ET.SubElement(suite, "testcase", name=item.identifier, classname=name)
        if item.status == "failed":
            failure = ET.SubElement(case, "failure", message=item.reason or "failed")
            failure.text = json.dumps(item.details, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def build_bundle_sha256() -> str:
    with tempfile.TemporaryDirectory(prefix="latchway-deployment-contract-") as temporary:
        output = run(
            [sys.executable, "scripts/build-contract-bundle.py", "--output-directory", temporary]
        ).strip()
        digest = output.split(maxsplit=1)[0]
        if SHA256.fullmatch(digest) is None:
            raise EvidenceError("contract_bundle_digest_invalid")
        return digest


def make_manifest(args: argparse.Namespace) -> dict[str, Any]:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise EvidenceError("github_actions_required")
    environment = {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "ref": os.environ.get("GITHUB_REF"),
        "sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
        "environment": args.environment,
    }
    if environment["repository"] != "Latchway/latchway" or environment["runner_environment"] != "github-hosted":
        raise EvidenceError("collector_identity_invalid")
    if WORKFLOW_REF.fullmatch(str(environment["workflow_ref"] or "")) is None or environment["ref"] != "refs/heads/main":
        raise EvidenceError("collector_workflow_invalid")
    if not isinstance(environment["sha"], str) or COMMIT.fullmatch(environment["sha"]) is None:
        raise EvidenceError("collector_commit_invalid")
    if not isinstance(environment["run_id"], str) or re.fullmatch(r"[1-9]\d{0,19}", environment["run_id"]) is None:
        raise EvidenceError("collector_run_invalid")
    try:
        environment["run_attempt"] = int(str(environment["run_attempt"]))
    except ValueError:
        raise EvidenceError("collector_run_invalid") from None
    if not 1 <= environment["run_attempt"] <= 1000:
        raise EvidenceError("collector_run_invalid")
    if not RELEASE.fullmatch(args.core_release):
        raise EvidenceError("core_release_invalid")
    if not COMMIT.fullmatch(args.core_commit):
        raise EvidenceError("core_commit_invalid")
    if OCI_IMAGE.fullmatch(args.image) is None:
        raise EvidenceError("release_image_invalid")
    started, finished = parse_time(args.started_at), parse_time(args.finished_at)
    if finished <= started or finished - started > timedelta(hours=6):
        raise EvidenceError("capture_time_window_invalid")
    endpoint = urllib.parse.urlsplit(args.endpoint)
    if args.platform == "compose":
        if endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise EvidenceError("compose_endpoint_invalid")
    elif endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise EvidenceError("cloud_endpoint_invalid")
    if endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment:
        raise EvidenceError("endpoint_origin_invalid")
    if not args.provider_resource_id or len(args.provider_resource_id) > 1024 or any(ord(char) < 32 for char in args.provider_resource_id):
        raise EvidenceError("provider_resource_id_invalid")

    capture = args.capture_dir.resolve()
    observations: dict[str, Any] = {}
    for name in OBSERVATIONS:
        path = capture / f"{name}.json"
        read_json(path)
        observations[name] = {"path": path.name, "sha256": sha256_file(path)}
    manifest = {
        "schema_version": 1,
        "kind": "latchway_cloud_deployment_capture",
        "platform": args.platform,
        "started_at": args.started_at,
        "finished_at": args.finished_at,
        "core_commit": args.core_commit,
        "core_release": args.core_release,
        "contract_version": json.loads((ROOT / "api/protocol-version.json").read_text())["contract_version"],
        "bundle_sha256": build_bundle_sha256(),
        "oci_image_digest": args.image,
        "endpoint": args.endpoint.rstrip("/"),
        "provider_resource_id": args.provider_resource_id,
        "collector": environment,
        "observations": observations,
    }
    validate_manifest(manifest, capture)
    write_json(capture / "manifest.json", manifest)
    return manifest


def validate_manifest(value: Any, root: Path) -> dict[str, Any]:
    fields = {
        "schema_version", "kind", "platform", "started_at", "finished_at",
        "core_commit", "core_release", "contract_version", "bundle_sha256",
        "oci_image_digest", "endpoint", "provider_resource_id", "collector", "observations",
    }
    manifest = require_fields(value, fields, "capture_manifest_fields_invalid")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["kind"] != "latchway_cloud_deployment_capture"
    ):
        raise EvidenceError("capture_manifest_identity_invalid")
    if manifest["platform"] not in PLATFORMS:
        raise EvidenceError("capture_platform_invalid")
    if not isinstance(manifest["core_commit"], str) or COMMIT.fullmatch(manifest["core_commit"]) is None:
        raise EvidenceError("capture_commit_invalid")
    if not isinstance(manifest["core_release"], str) or RELEASE.fullmatch(manifest["core_release"]) is None:
        raise EvidenceError("capture_release_invalid")
    if not isinstance(manifest["contract_version"], str) or re.fullmatch(SEMVER, manifest["contract_version"]) is None:
        raise EvidenceError("capture_contract_invalid")
    if not isinstance(manifest["bundle_sha256"], str) or SHA256.fullmatch(manifest["bundle_sha256"]) is None:
        raise EvidenceError("capture_bundle_invalid")
    expected_digest(manifest)
    endpoint = urllib.parse.urlsplit(str(manifest["endpoint"]))
    if (
        not endpoint.hostname
        or endpoint.username
        or endpoint.password
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
        or (
            manifest["platform"] == "compose"
            and (endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "localhost", "::1"))
        )
        or (manifest["platform"] != "compose" and endpoint.scheme != "https")
    ):
        raise EvidenceError("capture_endpoint_invalid")
    started, finished = parse_time(manifest["started_at"]), parse_time(manifest["finished_at"])
    if finished <= started or finished - started > timedelta(hours=6):
        raise EvidenceError("capture_time_window_invalid")
    collector = require_fields(
        manifest["collector"],
        {"repository", "workflow_ref", "ref", "sha", "run_id", "run_attempt", "runner_environment", "environment"},
        "capture_collector_fields_invalid",
    )
    if (
        collector.get("repository") != "Latchway/latchway"
        or collector.get("runner_environment") != "github-hosted"
        or collector.get("ref") != "refs/heads/main"
        or WORKFLOW_REF.fullmatch(str(collector.get("workflow_ref", ""))) is None
        or not isinstance(collector.get("sha"), str)
        or COMMIT.fullmatch(collector["sha"]) is None
        or not isinstance(collector.get("run_id"), str)
        or re.fullmatch(r"[1-9]\d{0,19}", collector["run_id"]) is None
        or type(collector.get("run_attempt")) is not int
        or not 1 <= collector["run_attempt"] <= 1000
        or collector.get("environment") != f"deployment-evidence-{manifest['platform']}"
    ):
        raise EvidenceError("capture_collector_invalid")
    observations = require_fields(manifest["observations"], OBSERVATIONS, "capture_observations_invalid")
    seen: set[str] = set()
    for name in OBSERVATIONS:
        artifact = require_fields(observations[name], {"path", "sha256"}, "capture_artifact_invalid")
        relative, expected = artifact["path"], artifact["sha256"]
        if relative != f"{name}.json" or relative in seen or not isinstance(expected, str) or SHA256.fullmatch(expected) is None:
            raise EvidenceError("capture_artifact_invalid")
        seen.add(relative)
        path = root / relative
        if not real_file(path) or sha256_file(path) != expected:
            raise EvidenceError("capture_artifact_hash_mismatch", {"observation": name})
    return manifest


def validate_http_observation(value: Any, manifest: Mapping[str, Any], path: str) -> None:
    observation = require_fields(value, {"url", "status_code", "observed_at", "tls", "body"}, "http_observation_fields_invalid")
    if type(observation["status_code"]) is not int or observation["status_code"] != 200:
        raise EvidenceError("http_status_invalid", {"path": path})
    require_capture_time(observation["observed_at"], manifest)
    parsed = urllib.parse.urlsplit(str(observation["url"]))
    expected = urllib.parse.urlsplit(str(manifest["endpoint"]))
    if (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, path):
        raise EvidenceError("http_url_invalid", {"path": path})
    if manifest["platform"] != "compose" and observation["tls"] is not True:
        raise EvidenceError("http_tls_not_verified", {"path": path})
    body = observation["body"]
    if not isinstance(body, dict):
        raise EvidenceError("http_body_invalid", {"path": path})
    if path == "/healthz":
        if set(body) != {"status", "build"}:
            raise EvidenceError("health_response_invalid")
        build = body.get("build")
        if body.get("status") != "ok" or not isinstance(build, dict) or set(build) != {
            "version", "commit", "build_date", "contract_version", "protocol_version",
        }:
            raise EvidenceError("health_response_invalid")
        if (
            build.get("commit") != manifest["core_commit"]
            or build.get("version") != manifest["core_release"][1:]
            or build.get("contract_version") != manifest["contract_version"]
            or build.get("protocol_version") != expected_current_protocol_version()
        ):
            raise EvidenceError("health_build_identity_mismatch")
        try:
            parse_time(build.get("build_date"))
        except EvidenceError:
            raise EvidenceError("health_build_identity_mismatch") from None
    else:
        checks = body.get("checks")
        expected_checks = {
            "database", "schema", "active_configuration", "quota_completion_pool",
            "master_key", "signing_key", "worker_heartbeat",
        }
        if body.get("status") != "ready" or not isinstance(checks, dict) or set(checks) != expected_checks or any(checks[name] != "ok" for name in expected_checks):
            raise EvidenceError("readiness_response_invalid")


def validate_migration(value: Any) -> None:
    migration = require_fields(value, {"command", "status", "provider_execution"}, "migration_observation_fields_invalid")
    command = migration["command"]
    if not isinstance(command, list) or command[-2:] != ["migrate", "status"] or any(not isinstance(item, str) for item in command):
        raise EvidenceError("migration_command_invalid")
    status = migration["status"]
    if (
        not isinstance(status, dict)
        or status.get("up_to_date") is not True
        or type(status.get("current")) is not int
        or type(status.get("available")) is not int
        or status.get("current") != expected_current_schema_version()
        or status.get("available") != expected_current_schema_version()
    ):
        raise EvidenceError("migration_status_invalid")
    execution = migration["provider_execution"]
    if not isinstance(execution, dict) or execution.get("reported_status") != status:
        raise EvidenceError("migration_provider_execution_invalid")


def expected_current_protocol_version() -> str:
    document = read_json(ROOT / "api/protocol-version.json")
    wire = document.get("wire_protocol") if isinstance(document, dict) else None
    current = wire.get("current") if isinstance(wire, dict) else None
    if type(current) is not int or current < 1:
        raise EvidenceError("protocol_contract_invalid")
    return str(current)


def expected_current_schema_version() -> int:
    pattern = re.compile(r"^(\d{6})_[a-z0-9_]+[.]sql$")
    files = sorted((ROOT / "migrations").glob("*.sql"))
    versions: list[int] = []
    for path in files:
        match = pattern.fullmatch(path.name)
        if match is None or not real_file(path):
            raise EvidenceError("migration_catalog_invalid")
        versions.append(int(match.group(1)))
    if not versions or versions != list(range(1, versions[-1] + 1)):
        raise EvidenceError("migration_catalog_invalid")
    return versions[-1]


def validate_secrets(value: Any, control: Mapping[str, Any]) -> None:
    secrets = require_fields(value, {"required_names", "runtime_references", "provider_resources"}, "secret_observation_fields_invalid")
    names = secrets["required_names"]
    references = secrets["runtime_references"]
    resources = secrets["provider_resources"]
    if not isinstance(names, list) or set(names) != REQUIRED_SECRET_NAMES:
        raise EvidenceError("required_secret_names_invalid")
    if not isinstance(references, list) or not isinstance(resources, list):
        raise EvidenceError("secret_references_invalid")
    if any(
        not isinstance(item, dict)
        or set(item) != {"name", "reference"}
        or item.get("name") not in REQUIRED_SECRET_NAMES
        or not isinstance(item.get("reference"), str)
        or not 1 <= len(item["reference"]) <= 2048
        for item in references
    ):
        raise EvidenceError("secret_references_invalid")
    reference_names = [item["name"] for item in references]
    if set(reference_names) != REQUIRED_SECRET_NAMES or len(reference_names) != len(REQUIRED_SECRET_NAMES):
        raise EvidenceError("secret_runtime_reference_missing")
    if not resources and control.get("platform") != "compose":
        raise EvidenceError("secret_provider_resource_missing")
    if any(
        not isinstance(item, dict)
        or set(item) != {"resource_id"}
        or not isinstance(item.get("resource_id"), str)
        or not 1 <= len(item["resource_id"]) <= 2048
        for item in resources
    ):
        raise EvidenceError("secret_provider_resource_invalid")
    serialized = json.dumps(value, sort_keys=True).lower()
    for forbidden in ("secret_string", "secret_value", "plaintext", "database_url_value", "master_key_value"):
        if forbidden in serialized:
            raise EvidenceError("secret_material_field_forbidden")
    forbidden_keys = {"value", "secret", "secretdata", "secretstring", "password", "token", "plaintext"}

    def reject_material_keys(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = re.sub(r"[^a-z]", "", str(key).lower())
                if normalized in forbidden_keys:
                    raise EvidenceError("secret_material_field_forbidden")
                reject_material_keys(child)
        elif isinstance(item, list):
            for child in item:
                reject_material_keys(child)

    reject_material_keys(value)


def find_env(container: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for item in container.get("env", []) if isinstance(container.get("env"), list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result[item["name"]] = item
    return result


def validate_database_pool(
    value: Any,
    expected: tuple[int, int, int],
    code: str,
) -> dict[str, int]:
    pool = require_fields(value, DATABASE_POOL_FIELDS, code)
    aggregate = pool["aggregate_max_connections"]
    regular = pool["regular_max_connections"]
    completion = pool["completion_max_connections"]
    if (
        any(type(item) is not int for item in (aggregate, regular, completion))
        or not 2 <= aggregate <= 500
        or regular < 1
        or completion < 1
        or completion >= aggregate
        or regular + completion != aggregate
        or (aggregate, regular, completion) != expected
    ):
        raise EvidenceError(code)
    return {
        "aggregate_max_connections": aggregate,
        "regular_max_connections": regular,
        "completion_max_connections": completion,
    }


def database_pool_from_environment(
    environment: Any,
    expected: tuple[int, int, int],
    code: str,
) -> dict[str, int]:
    if not isinstance(environment, list):
        raise EvidenceError(code)
    selected = [
        item
        for item in environment
        if isinstance(item, dict)
        and item.get("name") in DATABASE_POOL_ENVIRONMENT_NAMES
    ]
    if (
        len(selected) != len(DATABASE_POOL_ENVIRONMENT_NAMES)
        or {item.get("name") for item in selected}
        != set(DATABASE_POOL_ENVIRONMENT_NAMES)
        or any(set(item) != {"name", "value"} for item in selected)
        or any(not isinstance(item.get("value"), str) for item in selected)
    ):
        raise EvidenceError(code)
    values = {item["name"]: item["value"] for item in selected}
    if any(re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", item) is None for item in values.values()):
        raise EvidenceError(code)
    aggregate = int(values["LATCHWAY_DB_MAX_CONNECTIONS"])
    completion = int(values["LATCHWAY_DB_COMPLETION_CONNECTIONS"])
    return validate_database_pool(
        {
            "aggregate_max_connections": aggregate,
            "regular_max_connections": aggregate - completion,
            "completion_max_connections": completion,
        },
        expected,
        code,
    )


def cloudflare_provider_database_pool(
    worker: Mapping[str, Any],
) -> dict[str, int]:
    code = "cloudflare_database_pool_invalid"
    active_version_id = worker.get("active_version_id")
    deployments = worker.get("deployments")
    versions = worker.get("versions")
    if (
        not isinstance(active_version_id, str)
        or UUID.fullmatch(active_version_id) is None
        or not isinstance(deployments, list)
        or len(deployments) != 1
        or not isinstance(versions, list)
        or len(versions) != 1
    ):
        raise EvidenceError(code)
    for records in (deployments, versions):
        if len(records) > 50:
            raise EvidenceError(code)
        for item in records:
            if not isinstance(item, dict):
                raise EvidenceError(code)
            serialized = json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            if len(serialized.encode()) > 256 * 1024 or any(
                marker in serialized.lower()
                for marker in ('"password":', '"token":', '"secret_value":')
            ):
                raise EvidenceError(code)
    deployment = deployments[0]
    version = versions[0]
    if (
        set(deployment) != {"id", "created_on", "versions"}
        or not isinstance(deployment.get("id"), str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", deployment["id"]) is None
        or not isinstance(deployment.get("created_on"), str)
        or RFC3339.fullmatch(deployment["created_on"]) is None
        or set(version) != {"id", "resources"}
    ):
        raise EvidenceError(code)
    try:
        parse_time(deployment["created_on"])
    except EvidenceError:
        raise EvidenceError(code) from None
    traffic = deployment["versions"]
    if (
        not isinstance(traffic, list)
        or len(traffic) != 1
        or not isinstance(traffic[0], dict)
        or set(traffic[0]) != {"version_id", "percentage"}
        or traffic[0].get("version_id") != active_version_id
        or type(traffic[0].get("percentage")) is not int
        or traffic[0]["percentage"] != 100
    ):
        raise EvidenceError(code)
    if version.get("id") != active_version_id:
        raise EvidenceError(code)
    resources = version["resources"]
    if not isinstance(resources, dict) or set(resources) != {"bindings"}:
        raise EvidenceError(code)
    selected = resources["bindings"]
    if (
        not isinstance(selected, list)
        or len(selected) != len(DATABASE_POOL_ENVIRONMENT_NAMES)
        or any(not isinstance(item, dict) for item in selected)
        or [item.get("name") for item in selected]
        != list(DATABASE_POOL_ENVIRONMENT_NAMES)
        or any(set(item) != {"name", "type", "text"} for item in selected)
        or any(item.get("type") != "plain_text" for item in selected)
        or any(not isinstance(item.get("text"), str) for item in selected)
    ):
        raise EvidenceError(code)
    return database_pool_from_environment(
        [{"name": item["name"], "value": item["text"]} for item in selected],
        CLOUDFLARE_DATABASE_POOL,
        code,
    )


def cloud_run_resource_identity(
    value: Any,
    collection: str,
    name: str,
    code: str,
) -> Mapping[str, Any]:
    metadata = require_fields(value, {"name", "selfLink", "uid", "location"}, code)
    suffix = f"/namespaces/{CLOUD_RUN_PROJECT_ID}/{collection}/{name}"
    if (
        metadata["name"] != name
        or metadata["location"] != CLOUD_RUN_REGION
        or not isinstance(metadata["uid"], str)
        or not metadata["uid"]
        or not isinstance(metadata["selfLink"], str)
        or not metadata["selfLink"].endswith(suffix)
    ):
        raise EvidenceError(code)
    return metadata


def validate_cloud_run_database_environment(
    value: Any,
    code: str,
) -> Mapping[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise EvidenceError(code)
    item = value[0]
    if set(item) != {"name", "valueFrom"} or item.get("name") != "LATCHWAY_DATABASE_URL":
        raise EvidenceError(code)
    reference = nested(item, "valueFrom", "secretKeyRef")
    if (
        not isinstance(reference, dict)
        or set(reference) != {"name", "key"}
        or reference.get("name") != CLOUD_RUN_SECRET_REFERENCES["LATCHWAY_DATABASE_URL"]
        or not isinstance(reference.get("key"), str)
        or re.fullmatch(r"[1-9][0-9]*", reference["key"]) is None
    ):
        raise EvidenceError(code)
    return item


def validate_cloud_run_rollout(value: Any, digest: str, revision_name: str) -> None:
    rollout = require_fields(
        value,
        {"method", "started_at", "finished_at", "readiness_restored", "before", "after"},
        "cloud_run_rollout_fields_invalid",
    )
    started, finished = parse_time(rollout["started_at"]), parse_time(rollout["finished_at"])
    if (
        rollout["method"] != "cloud_run_revision_rollout"
        or rollout["readiness_restored"] is not True
        or finished <= started
        or finished - started > timedelta(minutes=30)
    ):
        raise EvidenceError("cloud_run_rollout_invalid")
    phases = []
    for name in ("before", "after"):
        phase = require_fields(
            rollout[name], {"image_digest", "resource_id"},
            "cloud_run_rollout_phase_invalid",
        )
        if image_digest(phase["image_digest"]) != digest or not isinstance(phase["resource_id"], str) or not phase["resource_id"]:
            raise EvidenceError("cloud_run_rollout_phase_invalid")
        phases.append(phase)
    if phases[0]["resource_id"] == phases[1]["resource_id"] or phases[1]["resource_id"] != revision_name:
        raise EvidenceError("cloud_run_revision_not_replaced")


def validate_cloud_run(
    control: Mapping[str, Any],
    migration: Mapping[str, Any],
    shutdown: Mapping[str, Any],
    digest: str,
    platform_digest: str | None = None,
    endpoint: str | None = None,
) -> Mapping[str, Any]:
    value = require_fields(
        control,
        {
            "platform", "service", "revision", "migration_job",
            "database_pool", "network_profile",
        },
        "cloud_run_control_fields_invalid",
    )
    if (
        value["platform"] != "cloud_run"
        or not isinstance(endpoint, str)
        or value["network_profile"] != CLOUD_RUN_NETWORK_PROFILE
    ):
        raise EvidenceError("cloud_run_control_invalid")

    service = require_fields(
        value["service"], {"metadata", "spec", "status"},
        "cloud_run_service_fields_invalid",
    )
    service_metadata = cloud_run_resource_identity(
        service["metadata"], "services", CLOUD_RUN_SERVICE,
        "cloud_run_service_identity_invalid",
    )
    service_spec = require_fields(service["spec"], {"template"}, "cloud_run_service_spec_invalid")
    desired_template = require_fields(
        service_spec["template"], {"metadata", "spec"},
        "cloud_run_service_template_invalid",
    )
    desired_metadata = require_fields(
        desired_template["metadata"], {"annotations"},
        "cloud_run_desired_runtime_profile_invalid",
    )
    desired_profile = validate_cloud_run_runtime_profile(
        desired_template["spec"], desired_metadata["annotations"], endpoint,
        "cloud_run_desired_runtime_profile_invalid",
    )

    revision = require_fields(
        value["revision"], {"metadata", "spec", "status"},
        "cloud_run_revision_fields_invalid",
    )
    revision_metadata_raw = require_fields(
        revision["metadata"], {"name", "selfLink", "uid", "location", "annotations"},
        "cloud_run_revision_metadata_fields_invalid",
    )
    revision_name = revision_metadata_raw["name"]
    if not isinstance(revision_name, str) or not revision_name:
        raise EvidenceError("cloud_run_latest_ready_revision_identity_invalid")
    revision_metadata = cloud_run_resource_identity(
        {key: revision_metadata_raw[key] for key in ("name", "selfLink", "uid", "location")},
        "revisions", revision_name, "cloud_run_revision_metadata_fields_invalid",
    )
    revision_profile = validate_cloud_run_runtime_profile(
        revision["spec"], revision_metadata_raw["annotations"], endpoint,
        "cloud_run_revision_runtime_profile_invalid",
    )
    if desired_profile != revision_profile:
        raise EvidenceError("cloud_run_runtime_profile_mismatch")
    desired_container = desired_profile["container"]
    revision_container = revision_profile["container"]
    if image_digest(desired_container.get("image")) != digest:
        raise EvidenceError("cloud_run_image_digest_mismatch")

    service_status = require_fields(
        service["status"], {"conditions", "latestReadyRevisionName", "traffic", "url"},
        "cloud_run_service_status_fields_invalid",
    )
    if service_status["url"] != endpoint:
        raise EvidenceError("cloud_run_endpoint_binding_invalid")
    if service_status["latestReadyRevisionName"] != revision_name:
        raise EvidenceError("cloud_run_latest_ready_revision_identity_invalid")
    for conditions, code in (
        (service_status["conditions"], "cloud_run_service_not_ready"),
        (nested(revision, "status", "conditions"), "cloud_run_latest_ready_revision_not_ready"),
    ):
        if not isinstance(conditions, list) or not any(
            isinstance(item, dict) and item.get("type") == "Ready" and
            str(item.get("status")).lower() == "true" for item in conditions
        ):
            raise EvidenceError(code)
    traffic = service_status["traffic"]
    if (
        not isinstance(traffic, list)
        or len(traffic) != 1
        or not isinstance(traffic[0], dict)
        or set(traffic[0]) != {"revisionName", "percent"}
        or traffic[0].get("revisionName") != revision_name
        or type(traffic[0].get("percent")) is not int
        or traffic[0]["percent"] != 100
    ):
        raise EvidenceError("cloud_run_latest_ready_revision_traffic_invalid")

    revision_status = require_fields(
        revision["status"], {"conditions", "imageDigest"},
        "cloud_run_revision_status_fields_invalid",
    )
    resolved_digest = image_digest(revision_status["imageDigest"])
    allowed_resolved_digests = {digest}
    if platform_digest is not None:
        if SHA256.fullmatch(platform_digest) is None or platform_digest == digest:
            raise EvidenceError("cloud_run_candidate_image_invalid")
        allowed_resolved_digests.add(platform_digest)
    if image_digest(revision_container.get("image")) != digest or resolved_digest not in allowed_resolved_digests:
        raise EvidenceError("cloud_run_resolved_digest_mismatch")

    database_pool = validate_database_pool(
        value["database_pool"], STANDARD_DATABASE_POOL,
        "cloud_run_database_pool_invalid",
    )
    for profile in (desired_profile, revision_profile):
        if database_pool_from_environment(
            profile["container"].get("env"), STANDARD_DATABASE_POOL,
            "cloud_run_database_pool_invalid",
        ) != database_pool:
            raise EvidenceError("cloud_run_database_pool_invalid")

    migration_job = require_fields(
        value["migration_job"], {"metadata", "spec"},
        "cloud_run_migration_job_fields_invalid",
    )
    cloud_run_resource_identity(
        migration_job["metadata"], "jobs", CLOUD_RUN_MIGRATION_JOB,
        "cloud_run_migration_job_identity_invalid",
    )
    job_spec = require_fields(
        migration_job["spec"],
        {
            "executionTemplateAnnotations", "taskCount", "parallelism",
            "serviceAccountName", "timeoutSeconds", "maxRetries", "containers",
        },
        "cloud_run_migration_job_profile_invalid",
    )
    if (
        job_spec["executionTemplateAnnotations"] != CLOUD_RUN_CLOUD_SQL_ANNOTATIONS
        or type(job_spec["taskCount"]) is not int or job_spec["taskCount"] != 1
        or type(job_spec["parallelism"]) is not int or job_spec["parallelism"] != 1
        or job_spec["serviceAccountName"] != CLOUD_RUN_MIGRATOR_SERVICE_ACCOUNT
        or type(job_spec["timeoutSeconds"]) is not int or job_spec["timeoutSeconds"] != 900
        or type(job_spec["maxRetries"]) is not int or job_spec["maxRetries"] != 0
        or not isinstance(job_spec["containers"], list) or len(job_spec["containers"]) != 1
        or not isinstance(job_spec["containers"][0], dict)
    ):
        raise EvidenceError("cloud_run_migration_job_profile_invalid")
    job_container = require_fields(
        job_spec["containers"][0],
        {"name", "image", "command", "args", "resources", "env"},
        "cloud_run_migration_job_container_invalid",
    )
    expected_database_env = [desired_profile["environment"]["LATCHWAY_DATABASE_URL"]]
    if (
        job_container["name"] != "latchway-migrate"
        or image_digest(job_container["image"]) != digest
        or job_container["command"] != ["/latchway"]
        or job_container["args"] != ["migrate", "up"]
        or job_container["resources"] != CLOUD_RUN_MIGRATION_RESOURCES
        or job_container["env"] != expected_database_env
    ):
        raise EvidenceError("cloud_run_migration_job_container_invalid")
    validate_cloud_run_database_environment(
        job_container["env"], "cloud_run_migration_job_container_invalid",
    )

    execution = require_fields(
        migration.get("provider_execution"),
        {"metadata", "spec", "status", "reported_status", "log_record"},
        "cloud_run_migration_execution_failed",
    )
    execution_metadata_raw = require_fields(
        execution["metadata"],
        {"name", "selfLink", "uid", "location", "annotations"},
        "cloud_run_migration_execution_identity_invalid",
    )
    if execution_metadata_raw["annotations"] != CLOUD_RUN_CLOUD_SQL_ANNOTATIONS:
        raise EvidenceError("cloud_run_migration_execution_profile_invalid")
    execution_name = execution_metadata_raw["name"]
    if not isinstance(execution_name, str) or not execution_name:
        raise EvidenceError("cloud_run_migration_execution_identity_invalid")
    execution_metadata = cloud_run_resource_identity(
        {
            key: execution_metadata_raw[key]
            for key in ("name", "selfLink", "uid", "location")
        },
        "executions", execution_name,
        "cloud_run_migration_execution_identity_invalid",
    )
    execution_spec = require_fields(execution["spec"], {"containers"}, "cloud_run_migration_execution_profile_invalid")
    if not isinstance(execution_spec["containers"], list) or len(execution_spec["containers"]) != 1 or not isinstance(execution_spec["containers"][0], dict):
        raise EvidenceError("cloud_run_migration_execution_profile_invalid")
    execution_container = require_fields(
        execution_spec["containers"][0],
        {"name", "image", "command", "args", "resources", "env"},
        "cloud_run_migration_execution_profile_invalid",
    )
    if (
        execution_container["name"] != "latchway-migrate"
        or image_digest(execution_container["image"]) != digest
        or execution_container["command"] != ["/latchway"]
        or execution_container["args"] != ["--output", "json", "migrate", "status"]
        or execution_container["resources"] != CLOUD_RUN_MIGRATION_RESOURCES
        or execution_container["env"] != expected_database_env
    ):
        raise EvidenceError("cloud_run_migration_execution_profile_invalid")
    validate_cloud_run_database_environment(
        execution_container["env"], "cloud_run_migration_execution_profile_invalid",
    )
    execution_status = require_fields(
        execution["status"], {"conditions", "succeededCount", "failedCount", "completionTime"},
        "cloud_run_migration_execution_failed",
    )
    conditions = execution_status["conditions"]
    if (
        not isinstance(conditions, list)
        or not any(isinstance(item, dict) and item.get("type") == "Completed" and str(item.get("status")).lower() == "true" for item in conditions)
        or type(execution_status["succeededCount"]) is not int
        or execution_status["succeededCount"] != 1
        or type(execution_status["failedCount"]) is not int
        or execution_status["failedCount"] != 0
        or not isinstance(execution_status["completionTime"], str)
    ):
        raise EvidenceError("cloud_run_migration_execution_failed")
    parse_time(execution_status["completionTime"])
    log_record = execution["log_record"]
    if (
        execution["reported_status"] != migration.get("status")
        or not isinstance(log_record, dict)
        or not isinstance(log_record.get("insert_ids"), list)
        or not log_record["insert_ids"]
        or any(not isinstance(item, str) or not item for item in log_record["insert_ids"])
        or type(log_record.get("line_count")) is not int
        or log_record["line_count"] != len(log_record["insert_ids"])
        or log_record.get("execution_name") != execution_metadata["name"]
        or not isinstance(log_record.get("timestamp"), str)
    ):
        raise EvidenceError("cloud_run_migration_log_invalid")
    parse_time(log_record["timestamp"])

    assert resolved_digest is not None
    validate_cloud_run_rollout(shutdown, resolved_digest, revision_name)
    return {
        "resource": service_metadata["selfLink"],
        "digest": digest,
        "runtime_digest": resolved_digest,
        "database_pool": database_pool,
        "runtime_profile": "manual-v1-cloud-sql-connector-steady-state",
        "rollout": "provider_revision_replacement",
    }


def validate_aws(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "service", "task_definition", "tasks", "database_pool"}, "aws_control_fields_invalid")
    if value["platform"] != "aws" or not isinstance(value["service"], dict) or not isinstance(value["task_definition"], dict) or not isinstance(value["tasks"], list):
        raise EvidenceError("aws_control_invalid")
    task_definition = require_fields(
        value["task_definition"],
        {"taskDefinitionArn", "containerDefinitions"},
        "aws_task_definition_fields_invalid",
    )
    definition_arn = task_definition["taskDefinitionArn"]
    if (
        not isinstance(definition_arn, str)
        or not definition_arn.startswith("arn:")
        or ":task-definition/" not in definition_arn
    ):
        raise EvidenceError("aws_task_definition_arn_invalid")
    definitions = task_definition["containerDefinitions"]
    if not isinstance(definitions, list) or len(definitions) != 1 or not isinstance(definitions[0], dict):
        raise EvidenceError("aws_task_definition_invalid")
    container = definitions[0]
    if image_digest(container.get("image")) != digest or container.get("stopTimeout") != 35 or container.get("readonlyRootFilesystem") is not True:
        raise EvidenceError("aws_task_runtime_invalid")
    database_pool = validate_database_pool(
        value["database_pool"],
        STANDARD_DATABASE_POOL,
        "aws_database_pool_invalid",
    )
    if database_pool_from_environment(
        container.get("environment"),
        STANDARD_DATABASE_POOL,
        "aws_database_pool_invalid",
    ) != database_pool:
        raise EvidenceError("aws_database_pool_invalid")
    environment = {item.get("name"): item.get("value") for item in container.get("environment", []) if isinstance(item, dict)}
    if environment.get("LATCHWAY_SHUTDOWN_TIMEOUT") != "30s":
        raise EvidenceError("aws_shutdown_timeout_mismatch")
    secret_names = {item.get("name") for item in container.get("secrets", []) if isinstance(item, dict)}
    if not REQUIRED_SECRET_NAMES.issubset(secret_names):
        raise EvidenceError("aws_secret_reference_missing")
    service = require_fields(
        value["service"],
        {
            "serviceArn", "serviceName", "clusterArn", "status", "desiredCount",
            "runningCount", "taskDefinition", "deployments",
        },
        "aws_service_fields_invalid",
    )
    deployments = service["deployments"]
    if (
        service.get("status") != "ACTIVE"
        or type(service.get("desiredCount")) is not int
        or service.get("runningCount") != service.get("desiredCount")
        or service["desiredCount"] < 2
        or service.get("taskDefinition") != definition_arn
        or not isinstance(deployments, list)
        or len(deployments) != 1
        or not isinstance(deployments[0], dict)
        or set(deployments[0])
        != {"id", "status", "taskDefinition", "desiredCount", "pendingCount", "runningCount", "rolloutState"}
        or deployments[0].get("status") != "PRIMARY"
        or deployments[0].get("taskDefinition") != definition_arn
        or deployments[0].get("desiredCount") != service["desiredCount"]
        or deployments[0].get("runningCount") != service["desiredCount"]
        or deployments[0].get("pendingCount") != 0
        or deployments[0].get("rolloutState") != "COMPLETED"
        or len(value["tasks"]) != service["desiredCount"]
    ):
        raise EvidenceError("aws_service_not_stable")
    for task in value["tasks"]:
        containers = task.get("containers") if isinstance(task, dict) else None
        if (
            task.get("lastStatus") != "RUNNING"
            or task.get("taskDefinitionArn") != definition_arn
            or not isinstance(containers, list)
            or not containers
            or image_digest(containers[0].get("imageDigest")) != digest
        ):
            raise EvidenceError("aws_task_digest_mismatch")
    execution = migration.get("provider_execution")
    stopped = execution.get("stopped_task") if isinstance(execution, dict) else None
    containers = stopped.get("containers") if isinstance(stopped, dict) else None
    if (
        not isinstance(containers, list)
        or not containers
        or type(containers[0].get("exitCode")) is not int
        or containers[0]["exitCode"] != 0
        or image_digest(containers[0].get("imageDigest")) != digest
        or stopped.get("lastStatus") != "STOPPED"
        or stopped.get("taskDefinitionArn") != definition_arn
    ):
        raise EvidenceError("aws_migration_execution_failed")
    log_record = execution.get("log_record") if isinstance(execution, dict) else None
    if (
        not isinstance(log_record, dict)
        or not isinstance(log_record.get("log_stream"), str)
        or not log_record["log_stream"]
        or type(log_record.get("timestamp_ms")) is not int
        or type(log_record.get("ingestion_time_ms")) is not int
        or type(log_record.get("line_count")) is not int
        or not 1 <= log_record["line_count"] <= 100
        or log_record["timestamp_ms"] <= 0
        or log_record["ingestion_time_ms"] < log_record["timestamp_ms"]
    ):
        raise EvidenceError("aws_migration_log_invalid")
    validate_shutdown(shutdown, "ecs_task_replacement", 35, 30, digest)
    if nested(shutdown, "before", "resource_id") == nested(shutdown, "after", "resource_id"):
        raise EvidenceError("aws_task_not_replaced")
    return {
        "resource": service.get("serviceArn"),
        "digest": digest,
        "replicas": len(value["tasks"]),
        "database_pool": database_pool,
    }


def fly_machine_digest(machine: Mapping[str, Any]) -> str | None:
    return image_digest(first_nested(machine, (("image_ref", "digest"), ("imageRef", "digest"), ("config", "image"))))


def validate_fly_capture(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "app", "machines", "database_pool"}, "fly_control_fields_invalid")
    if value["platform"] != "fly_io" or not isinstance(value["app"], dict) or not isinstance(value["machines"], list) or len(value["machines"]) < 2:
        raise EvidenceError("fly_control_invalid")
    database_pool = validate_database_pool(
        value["database_pool"],
        STANDARD_DATABASE_POOL,
        "fly_database_pool_invalid",
    )
    for machine in value["machines"]:
        if not isinstance(machine, dict) or machine.get("state") != "started" or fly_machine_digest(machine) != digest:
            raise EvidenceError("fly_machine_digest_mismatch")
        if database_pool_from_environment(
            machine.get("environment"),
            STANDARD_DATABASE_POOL,
            "fly_database_pool_invalid",
        ) != database_pool:
            raise EvidenceError("fly_database_pool_invalid")
        checks = machine.get("checks")
        if isinstance(checks, list) and any(isinstance(item, dict) and item.get("status") not in ("passing", "success") for item in checks):
            raise EvidenceError("fly_machine_check_failed")
    execution = migration.get("provider_execution")
    machine_ids = {item.get("id") for item in value["machines"] if isinstance(item, dict)}
    if (
        not isinstance(execution, dict)
        or type(execution.get("exit_code")) is not int
        or execution["exit_code"] != 0
        or execution.get("machine_id") not in machine_ids
        or not isinstance(execution.get("stdout_sha256"), str)
        or SHA256.fullmatch(execution["stdout_sha256"]) is None
    ):
        raise EvidenceError("fly_migration_execution_failed")
    validate_shutdown(shutdown, "fly_machine_restart", 35, 30, digest)
    before_instance = nested(shutdown, "before", "resource_id")
    after_instance = nested(shutdown, "after", "resource_id")
    if not isinstance(before_instance, str) or not isinstance(after_instance, str) or before_instance == after_instance:
        raise EvidenceError("fly_machine_instance_not_replaced")
    return {
        "resource": value["app"].get("ID", value["app"].get("id")),
        "digest": digest,
        "replicas": len(value["machines"]),
        "database_pool": database_pool,
    }


def validate_compose_capture(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "project", "gateway", "image", "database_pool"}, "compose_control_fields_invalid")
    if value["platform"] != "compose" or not isinstance(value["gateway"], dict) or not isinstance(value["image"], dict):
        raise EvidenceError("compose_control_invalid")
    gateway = value["gateway"]
    gateway_id = gateway.get("Id")
    if (
        not isinstance(gateway_id, str)
        or not gateway_id
        or nested(gateway, "State", "Running") is not True
        or nested(gateway, "State", "Health", "Status") != "healthy"
    ):
        raise EvidenceError("compose_gateway_not_healthy")
    if nested(gateway, "Config", "Labels", "com.docker.compose.project") != value["project"]:
        raise EvidenceError("compose_project_identity_mismatch")
    if image_digest(nested(gateway, "Config", "Image")) != digest:
        digests = value["image"].get("RepoDigests")
        if not isinstance(digests, list) or digest not in {image_digest(item) for item in digests}:
            raise EvidenceError("compose_image_digest_mismatch")
    database_pool = validate_database_pool(
        value["database_pool"],
        STANDARD_DATABASE_POOL,
        "compose_database_pool_invalid",
    )
    if database_pool_from_environment(
        nested(gateway, "Config", "Env"),
        STANDARD_DATABASE_POOL,
        "compose_database_pool_invalid",
    ) != database_pool:
        raise EvidenceError("compose_database_pool_invalid")
    execution = migration.get("provider_execution")
    if (
        not isinstance(execution, dict)
        or type(execution.get("exit_code")) is not int
        or execution["exit_code"] != 0
        or type(execution.get("migration_container_exit_code")) is not int
        or execution["migration_container_exit_code"] != 0
    ):
        raise EvidenceError("compose_migration_execution_failed")
    validate_shutdown(shutdown, "compose_sigterm_restart", 35, 30, digest)
    before_id = nested(shutdown, "before", "resource_id")
    after_id = nested(shutdown, "after", "resource_id")
    if (
        not isinstance(before_id, str)
        or not before_id
        or not isinstance(after_id, str)
        or not after_id
        or before_id == after_id
        or after_id != gateway_id
        or before_id == value["project"]
    ):
        raise EvidenceError("compose_gateway_not_replaced")
    return {
        "resource": value["project"],
        "digest": digest,
        "database_pool": database_pool,
    }


def validate_cloudflare_capture(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "worker", "container", "database_pool"}, "cloudflare_control_fields_invalid")
    if value["platform"] != "cloudflare_containers" or not isinstance(value["worker"], dict) or not isinstance(value["container"], dict):
        raise EvidenceError("cloudflare_control_invalid")
    worker = require_fields(
        value["worker"],
        {"status", "resource_id", "active_version_id", "deployments", "versions"},
        "cloudflare_worker_fields_invalid",
    )
    container = require_fields(
        value["container"],
        {"application", "instances", "canonical", "mirror"},
        "cloudflare_container_fields_invalid",
    )
    application = require_fields(
        container["application"],
        {"id", "name", "state", "instances", "image", "version", "updated_at"},
        "cloudflare_application_fields_invalid",
    )
    canonical = require_fields(
        container["canonical"],
        {"index_digest", "platform", "platform_digest", "config_digest", "layers"},
        "cloudflare_canonical_image_fields_invalid",
    )
    mirror = require_fields(
        container["mirror"],
        {"image", "manifest_digest", "config_digest", "layers"},
        "cloudflare_mirror_image_fields_invalid",
    )
    database_pool = validate_database_pool(
        value["database_pool"],
        CLOUDFLARE_DATABASE_POOL,
        "cloudflare_database_pool_invalid",
    )
    if cloudflare_provider_database_pool(worker) != database_pool:
        raise EvidenceError("cloudflare_database_pool_invalid")
    if (
        worker["status"] != "ready"
        or worker["resource_id"] != application["id"]
        or not isinstance(worker["deployments"], list)
        or not worker["deployments"]
        or not isinstance(worker["versions"], list)
        or not worker["versions"]
        or application["name"] != "latchway"
        or application["state"] not in ("active", "ready")
        or not isinstance(application["id"], str)
        or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", application["id"]) is None
        or type(application["instances"]) is not int
        or application["instances"] < 1
        or type(application["version"]) is not int
        or application["version"] < 1
        or not isinstance(application["updated_at"], str)
        or canonical["index_digest"] != f"sha256:{digest}"
        or canonical["platform"] != "linux/amd64"
        or image_digest(canonical["platform_digest"]) is None
        or image_digest(canonical["config_digest"]) is None
        or image_digest(mirror["manifest_digest"]) is None
        or image_digest(mirror["config_digest"]) is None
        or image_digest(mirror["image"]) != image_digest(mirror["manifest_digest"])
        or image_digest(application["image"]) != image_digest(mirror["manifest_digest"])
        or canonical["config_digest"] != mirror["config_digest"]
        or canonical["layers"] != mirror["layers"]
        or not isinstance(canonical["layers"], list)
        or not canonical["layers"]
        or any(
            not isinstance(layer, dict)
            or set(layer) != {"digest", "size"}
            or image_digest(layer.get("digest")) is None
            or type(layer.get("size")) is not int
            or layer["size"] < 1
            for layer in canonical["layers"]
        )
    ):
        raise EvidenceError("cloudflare_deployment_invalid")
    instances = container["instances"]
    if (
        not isinstance(instances, list)
        or not instances
        or any(
            not isinstance(instance, dict)
            or set(instance) != {"id", "name", "state", "location", "version", "created"}
            or instance.get("state") != "running"
            or instance.get("version") != application["version"]
            or not isinstance(instance.get("id"), str)
            or not isinstance(instance.get("name"), str)
            or not isinstance(instance.get("created"), str)
            for instance in instances
        )
    ):
        raise EvidenceError("cloudflare_instances_not_ready")
    execution = migration.get("provider_execution")
    if (
        not isinstance(execution, dict)
        or set(execution) != {"exit_code", "evidence_id", "instance_name", "command", "reported_status"}
        or type(execution.get("exit_code")) is not int
        or execution["exit_code"] != 0
        or not isinstance(execution.get("evidence_id"), str)
        or EVIDENCE_ID.fullmatch(execution["evidence_id"]) is None
        or execution.get("instance_name") != "instance-0"
        or execution.get("command") != ["/latchway", "--output", "json", "migrate", "status"]
    ):
        raise EvidenceError("cloudflare_migration_execution_failed")
    mirror_digest = image_digest(mirror["manifest_digest"])
    if mirror_digest is None:
        raise EvidenceError("cloudflare_mirror_digest_invalid")
    validate_shutdown(
        shutdown,
        "cloudflare_container_replacement",
        900,
        30,
        mirror_digest,
        extra_fields={"evidence_id", "provider_reason"},
    )
    if (
        nested(shutdown, "before", "resource_id") == nested(shutdown, "after", "resource_id")
        or shutdown.get("evidence_id") != execution["evidence_id"]
        or shutdown.get("provider_reason") != "runtime_signal"
    ):
        raise EvidenceError("cloudflare_container_not_replaced")
    return {
        "resource": worker["resource_id"],
        "digest": digest,
        "runtime_digest": mirror_digest,
        "database_pool": database_pool,
    }


def validate_shutdown(
    value: Any,
    method: str,
    platform_timeout: int,
    app_timeout: int,
    digest: str,
    *,
    extra_fields: Iterable[str] = (),
) -> None:
    fields = {
        "method", "started_at", "finished_at", "signal",
        "platform_timeout_seconds", "application_timeout_seconds", "exit_code",
        "readiness_restored", "before", "after",
    }
    fields.update(extra_fields)
    shutdown = require_fields(
        value,
        fields,
        "shutdown_observation_fields_invalid",
    )
    started, finished = parse_time(shutdown["started_at"]), parse_time(shutdown["finished_at"])
    if (
        shutdown["method"] != method
        or shutdown["signal"] != "SIGTERM"
        or type(shutdown["platform_timeout_seconds"]) is not int
        or shutdown["platform_timeout_seconds"] != platform_timeout
        or type(shutdown["application_timeout_seconds"]) is not int
        or shutdown["application_timeout_seconds"] != app_timeout
        or type(shutdown["exit_code"]) is not int
        or shutdown["exit_code"] != 0
        or shutdown["readiness_restored"] is not True
        or finished <= started
        or finished - started > timedelta(minutes=30)
        or not isinstance(shutdown["before"], dict)
        or not isinstance(shutdown["after"], dict)
    ):
        raise EvidenceError("shutdown_observation_invalid")
    before_digest = image_digest(first_nested(shutdown["before"], (("image_digest",), ("image",), ("digest",))))
    after_digest = image_digest(first_nested(shutdown["after"], (("image_digest",), ("image",), ("digest",))))
    if before_digest != digest or after_digest != digest:
        raise EvidenceError("shutdown_image_digest_mismatch")


def validate_capture(
    root: Path,
    candidate_manifest: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[Check]]:
    manifest = validate_manifest(read_json(root / "manifest.json"), root)
    values = {name: read_json(root / manifest["observations"][name]["path"]) for name in OBSERVATIONS}
    checks: list[Check] = []

    def check(identifier: str, summary: str, operation: Callable[[], Mapping[str, Any] | None]) -> None:
        try:
            details = operation() or {}
        except EvidenceError as error:
            checks.append(Check(identifier, "failed", summary, error.code, error.details))
        except Exception:
            checks.append(Check(identifier, "failed", summary, "unexpected_validation_error"))
        else:
            checks.append(Check(identifier, "passed", summary, details=dict(details)))

    check("capture.identity", "The capture has an authenticated provider identity resource.", lambda: validate_identity(values["identity"], manifest))
    check("capture.health", "The release build answered the liveness endpoint.", lambda: validate_http_observation(values["health"], manifest, "/healthz"))
    check("capture.readiness", "Database, schema, configuration, quota completion capacity, keys, and worker are ready.", lambda: validate_http_observation(values["readiness"], manifest, "/readyz"))
    check("capture.migration", "The deployed image reports the current schema.", lambda: validate_migration(values["migration"]))
    check("capture.secrets", "Runtime secret references exist without captured secret values.", lambda: validate_secrets(values["secrets"], values["control_plane"]))
    validator = {
        "compose": validate_compose_capture,
        "cloud_run": validate_cloud_run,
        "aws": validate_aws,
        "fly_io": validate_fly_capture,
        "cloudflare_containers": validate_cloudflare_capture,
    }[manifest["platform"]]

    def validate_control_plane() -> Mapping[str, Any]:
        require_capture_time(values["shutdown"].get("started_at"), manifest)
        require_capture_time(values["shutdown"].get("finished_at"), manifest)
        arguments: list[Any] = [
            values["control_plane"],
            values["migration"],
            values["shutdown"],
            expected_digest(manifest),
        ]
        if manifest["platform"] == "cloud_run":
            arguments.append(
                cloud_run_candidate_platform_digest(candidate_manifest, manifest)
            )
            arguments.append(manifest["endpoint"])
        details = validator(*arguments)
        if details.get("resource") != manifest["provider_resource_id"]:
            raise EvidenceError("provider_control_plane_resource_mismatch")
        return details

    check(
        "capture.control_plane",
        "The provider serves the exact release digest and passed migration plus its platform lifecycle check.",
        validate_control_plane,
    )
    return manifest, checks


def validate_identity(value: Any, manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    identity = require_fields(value, {"platform", "resource_id", "observed_at", "provider_response"}, "identity_observation_fields_invalid")
    if identity["platform"] != manifest["platform"] or identity["resource_id"] != manifest["provider_resource_id"]:
        raise EvidenceError("provider_identity_mismatch")
    require_capture_time(identity["observed_at"], manifest)
    provider_response = identity["provider_response"]
    if not isinstance(provider_response, dict) or not provider_response:
        raise EvidenceError("provider_identity_response_invalid")
    if manifest["platform"] == "cloud_run":
        response = require_fields(
            provider_response,
            {"projectId", "projectNumber", "lifecycleState", "gcloud_version"},
            "cloud_run_provider_identity_invalid",
        )
        if (
            response["projectId"] != CLOUD_RUN_PROJECT_ID
            or not isinstance(response["projectNumber"], str)
            or re.fullmatch(r"[1-9][0-9]*", response["projectNumber"]) is None
            or response["lifecycleState"] != "ACTIVE"
            or not isinstance(response["gcloud_version"], dict)
            or not response["gcloud_version"]
            or not identity["resource_id"].endswith(
                f"/namespaces/{CLOUD_RUN_PROJECT_ID}/services/{CLOUD_RUN_SERVICE}"
            )
        ):
            raise EvidenceError("cloud_run_provider_identity_invalid")
    return {"resource_id_sha256": hashlib.sha256(identity["resource_id"].encode()).hexdigest()}


def normalized_tar_info(path: Path, name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def seal_capture(
    capture: Path,
    output: Path,
    candidate_manifest: Mapping[str, Any] | None = None,
) -> None:
    manifest, checks = validate_capture(capture, candidate_manifest)
    if any(item.status != "passed" for item in checks):
        raise EvidenceError("capture_validation_failed")
    allowed = {"manifest.json", *(f"{name}.json" for name in OBSERVATIONS)}
    actual = {path.name for path in capture.iterdir() if real_file(path)}
    if actual != allowed:
        raise EvidenceError("capture_file_set_invalid")
    if any(path.is_dir() or path.is_symlink() for path in capture.iterdir()):
        raise EvidenceError("capture_entry_unsafe")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name in sorted(allowed):
                    path = capture / name
                    info = normalized_tar_info(path, name)
                    with path.open("rb") as payload:
                        archive.addfile(info, payload)
    if output.stat().st_size > MAX_ARCHIVE_BYTES:
        raise EvidenceError("capture_archive_too_large")
    _ = manifest


def extract_capture(archive_path: Path, destination: Path) -> None:
    if not real_file(archive_path) or archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise EvidenceError("capture_archive_invalid")
    total = 0
    names: list[str] = []
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= MAX_ARCHIVE_FILES:
                raise EvidenceError("capture_archive_entry_count_invalid")
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    not member.isfile()
                    or path.as_posix() != member.name
                    or len(path.parts) != 1
                    or path.name in ("", ".", "..")
                    or member.uid != 0
                    or member.gid != 0
                    or member.mtime != 0
                    or member.mode != 0o644
                ):
                    raise EvidenceError("capture_archive_entry_unsafe")
                total += member.size
                if member.size > MAX_JSON_BYTES or total > MAX_TOTAL_EXTRACTED:
                    raise EvidenceError("capture_archive_payload_too_large")
                names.append(member.name)
            if names != sorted(names) or len(names) != len(set(names)):
                raise EvidenceError("capture_archive_not_deterministic")
            for member in members:
                source = archive.extractfile(member)
                if source is None:
                    raise EvidenceError("capture_archive_entry_missing")
                target = destination / member.name
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output)
    except EvidenceError:
        raise
    except (OSError, tarfile.TarError):
        raise EvidenceError("capture_archive_invalid") from None


def verify_attestation(archive: Path, bundle: Path, trusted_root: Path, manifest: Mapping[str, Any]) -> Any:
    if (
        not real_file(bundle)
        or not real_file(trusted_root)
        or bundle.stat().st_size > MAX_JSON_BYTES
        or trusted_root.stat().st_size > MAX_JSON_BYTES
    ):
        raise EvidenceError("attestation_material_missing")
    output = run(
        [
            "gh", "attestation", "verify", str(archive),
            "--repo", "Latchway/latchway",
            "--bundle", str(bundle),
            "--custom-trusted-root", str(trusted_root),
            "--signer-workflow", SIGNER_WORKFLOW,
            "--source-digest", manifest["collector"]["sha"],
            "--source-ref", "refs/heads/main",
            "--deny-self-hosted-runners",
            "--format", "json",
        ],
        timeout=120,
    )
    try:
        value = json.loads(output, object_pairs_hook=duplicate_rejecting_object)
    except (json.JSONDecodeError, EvidenceError):
        raise EvidenceError("attestation_verification_output_invalid") from None
    if not isinstance(value, list) or not value:
        raise EvidenceError("attestation_not_verified")
    return value


def safe_evidence_path(root: Path, path: Path) -> str:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        raise EvidenceError("evidence_path_unsafe") from None
    if not real_file(resolved) or not relative or any(part in ("", ".", "..") for part in PurePosixPath(relative).parts):
        raise EvidenceError("evidence_path_unsafe")
    return relative


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    root = args.evidence_root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise EvidenceError("evidence_root_invalid")
    coordinates = read_json(args.coordinates.resolve())
    expected_coordinate_fields = {"core", "javascript", "ios", "android", "react_native"}
    if not isinstance(coordinates, dict) or set(coordinates) != expected_coordinate_fields:
        raise EvidenceError("release_coordinates_invalid")
    for coordinate in coordinates.values():
        if not isinstance(coordinate, dict) or set(coordinate) != {"commit", "tag", "version"}:
            raise EvidenceError("release_coordinates_invalid")
        if COMMIT.fullmatch(str(coordinate["commit"])) is None or RELEASE.fullmatch(str(coordinate["tag"])) is None or re.fullmatch(SEMVER, str(coordinate["version"])) is None:
            raise EvidenceError("release_coordinates_invalid")
    core = coordinates["core"]
    if core["tag"] != args.core_release or core["commit"] != args.core_commit:
        raise EvidenceError("core_coordinates_mismatch")
    if OCI_IMAGE.fullmatch(args.image) is None or SHA256.fullmatch(args.bundle_sha256) is None or re.fullmatch(SEMVER, args.contract_version) is None:
        raise EvidenceError("release_identity_invalid")
    candidate_manifest = read_json(args.candidate_manifest.resolve())

    artifacts_dir = root / "artifacts/cloud-deployments"
    verification_summary: dict[str, Any] = {}
    started_values: list[datetime] = []
    finished_values: list[datetime] = []
    artifact_paths: list[Path] = []
    for platform in PLATFORMS:
        archive = artifacts_dir / f"{platform}.tar.gz"
        bundle = artifacts_dir / f"{platform}.attestation.json"
        with tempfile.TemporaryDirectory(prefix=f"latchway-{platform}-evidence-") as temporary:
            extracted = Path(temporary)
            extract_capture(archive, extracted)
            manifest, checks = validate_capture(extracted, candidate_manifest)
            if any(item.status != "passed" for item in checks):
                raise EvidenceError("platform_capture_failed", {"platform": platform})
            if (
                manifest["platform"] != platform
                or manifest["core_commit"] != args.core_commit
                or manifest["core_release"] != args.core_release
                or manifest["contract_version"] != args.contract_version
                or manifest["bundle_sha256"] != args.bundle_sha256
                or manifest["oci_image_digest"] != args.image
            ):
                raise EvidenceError("platform_capture_identity_mismatch", {"platform": platform})
            verified = verify_attestation(archive, bundle, args.trusted_root.resolve(), manifest)
            verification_summary[platform] = {
                "archive_sha256": sha256_file(archive),
                "bundle_sha256": sha256_file(bundle),
                "verified_attestations": len(verified),
                "workflow_run_id": manifest["collector"]["run_id"],
                "provider_resource_id_sha256": hashlib.sha256(manifest["provider_resource_id"].encode()).hexdigest(),
            }
            started_values.append(parse_time(manifest["started_at"]))
            finished_values.append(parse_time(manifest["finished_at"]))
        artifact_paths.extend((archive, bundle))

    started, finished = min(started_values), max(finished_values)
    if finished <= started or finished - started > timedelta(days=7):
        raise EvidenceError("aggregate_evidence_time_invalid")
    verification_path = artifacts_dir / "attestation-verification.json"
    write_json(
        verification_path,
        {
            "schema_version": 1,
            "kind": "latchway_deployment_attestation_verification",
            "trusted_root_sha256": sha256_file(args.trusted_root.resolve()),
            "platforms": verification_summary,
        },
    )
    artifact_paths.append(verification_path)
    artifacts = [
        {"path": safe_evidence_path(root, path), "sha256": sha256_file(path)}
        for path in sorted(artifact_paths, key=lambda item: item.name)
    ]
    result = {
        "schema_version": 1,
        "kind": "latchway_cross_repository_external_evidence",
        "domain": "cloud_deployments",
        "status": "passed",
        "started_at": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "finished_at": finished.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "core_commit": args.core_commit,
        "core_release": args.core_release,
        "contract_version": args.contract_version,
        "bundle_sha256": args.bundle_sha256,
        "oci_image_digest": args.image,
        "repositories": coordinates,
        "claims": {
            "compose_verified": True,
            "cloud_run_verified": True,
            "aws_verified": True,
            "fly_io_verified": True,
            "cloudflare_containers_verified": True,
        },
        "artifacts": artifacts,
    }
    write_json(root / "cloud_deployments.json", result)
    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    static = subcommands.add_parser("static", help="validate repository deployment assets")
    static.add_argument("--output", type=Path, required=True)
    static.add_argument("--junit", type=Path)

    manifest = subcommands.add_parser("make-manifest", help="bind raw observations to one GitHub-hosted capture")
    manifest.add_argument("--platform", choices=PLATFORMS, required=True)
    manifest.add_argument("--capture-dir", type=Path, required=True)
    manifest.add_argument("--started-at", required=True)
    manifest.add_argument("--finished-at", required=True)
    manifest.add_argument("--core-commit", required=True)
    manifest.add_argument("--core-release", required=True)
    manifest.add_argument("--image", required=True)
    manifest.add_argument("--endpoint", required=True)
    manifest.add_argument("--provider-resource-id", required=True)
    manifest.add_argument("--environment", required=True)

    validate = subcommands.add_parser("validate-capture", help="validate one raw capture directory")
    validate.add_argument("--capture-dir", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    validate.add_argument("--junit", type=Path)
    validate.add_argument("--candidate-manifest", type=Path)

    observe = subcommands.add_parser("observe-http", help="capture bounded liveness and readiness responses")
    observe.add_argument("--endpoint", required=True)
    observe.add_argument("--output-dir", type=Path, required=True)
    observe.add_argument("--timeout", type=float, default=10.0)

    seal = subcommands.add_parser("seal", help="write a deterministic capture archive")
    seal.add_argument("--capture-dir", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--candidate-manifest", type=Path)

    final = subcommands.add_parser("finalize", help="verify signed platform archives and emit cloud_deployments.json")
    final.add_argument("--evidence-root", type=Path, required=True)
    final.add_argument("--coordinates", type=Path, required=True)
    final.add_argument("--trusted-root", type=Path, required=True)
    final.add_argument("--core-commit", required=True)
    final.add_argument("--core-release", required=True)
    final.add_argument("--contract-version", required=True)
    final.add_argument("--bundle-sha256", required=True)
    final.add_argument("--image", required=True)
    final.add_argument("--candidate-manifest", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        if args.command == "static":
            checks = static_checks()
            value = report("latchway_deployment_static_evidence", checks, generated_at=timestamp_now())
            write_json(args.output, value)
            write_junit(args.junit or Path(str(args.output) + ".junit.xml"), "deployment-static", checks)
            return 0 if value["verdict"] == "passed" else 1
        if args.command == "make-manifest":
            make_manifest(args)
            return 0
        if args.command == "validate-capture":
            candidate_manifest = (
                read_json(args.candidate_manifest.resolve())
                if args.candidate_manifest is not None
                else None
            )
            manifest, checks = validate_capture(
                args.capture_dir.resolve(), candidate_manifest
            )
            value = report(
                "latchway_deployment_capture_validation",
                checks,
                platform=manifest["platform"],
                oci_image_digest=manifest["oci_image_digest"],
            )
            write_json(args.output, value)
            write_junit(args.junit or Path(str(args.output) + ".junit.xml"), "deployment-capture", checks)
            return 0 if value["verdict"] == "passed" else 1
        if args.command == "observe-http":
            if not 0 < args.timeout <= 30:
                raise EvidenceError("http_timeout_invalid")
            observe_http(args.endpoint, args.output_dir.resolve(), args.timeout)
            return 0
        if args.command == "seal":
            candidate_manifest = (
                read_json(args.candidate_manifest.resolve())
                if args.candidate_manifest is not None
                else None
            )
            seal_capture(
                args.capture_dir.resolve(), args.output.resolve(), candidate_manifest
            )
            return 0
        if args.command == "finalize":
            try:
                GH_VERSION.installed_version()
            except GH_VERSION.VersionError as error:
                raise EvidenceError(str(error)) from error
            finalize(args)
            return 0
    except EvidenceError as error:
        print(f"deployment evidence failed: {error.code}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
