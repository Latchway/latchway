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
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
RELEASE = re.compile(rf"^v{SEMVER}$")
OCI_IMAGE = re.compile(r"^ghcr\.io/latchway/latchway@sha256:([0-9a-f]{64})$")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
EVIDENCE_ID = re.compile(r"^[1-9][0-9]{0,19}-[1-9][0-9]{0,3}$")
WORKFLOW_REF = re.compile(
    r"^Latchway/latchway/\.github/workflows/deployment-evidence\.yml@refs/heads/main$"
)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_FILES = 64
MAX_TOTAL_EXTRACTED = 64 * 1024 * 1024
SIGNER_WORKFLOW = "github.com/Latchway/latchway/.github/workflows/deployment-evidence.yml"


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
    if environment.get("LATCHWAY_SHUTDOWN_TIMEOUT") != "30s" or gateway.get("stop_grace_period") != "35s":
        raise EvidenceError("compose_shutdown_budget_invalid")
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


def validate_cloud_run_yaml() -> Mapping[str, Any]:
    service = yaml_as_json(ROOT / "deploy/cloud-run/service.yaml")
    job = yaml_as_json(ROOT / "deploy/cloud-run/migration-job.yaml")
    if not isinstance(service, dict) or not isinstance(job, dict):
        raise EvidenceError("cloud_run_yaml_invalid")
    service_container = cloud_run_containers(service)[0]
    job_container = cloud_run_containers(job)[0]
    if service_container.get("image") != "${LATCHWAY_IMAGE}" or job_container.get("image") != "${LATCHWAY_IMAGE}":
        raise EvidenceError("cloud_run_image_placeholder_invalid")
    if job_container.get("args") != ["migrate", "up"]:
        raise EvidenceError("cloud_run_migration_command_invalid")
    environment = env_map(service_container)
    if nested(environment.get("LATCHWAY_DATABASE_URL"), "valueFrom", "secretKeyRef") is None:
        raise EvidenceError("cloud_run_database_secret_missing")
    if nested(environment.get("LATCHWAY_MASTER_KEY"), "valueFrom", "secretKeyRef") is None:
        raise EvidenceError("cloud_run_master_secret_missing")
    if nested(environment.get("LATCHWAY_ADMIN_BOOTSTRAP_TOKEN"), "valueFrom", "secretKeyRef") is None:
        raise EvidenceError("cloud_run_bootstrap_secret_missing")
    if nested(environment.get("LATCHWAY_SHUTDOWN_TIMEOUT"), "value") != "8s":
        raise EvidenceError("cloud_run_shutdown_budget_invalid")
    if nested(service_container, "startupProbe", "httpGet", "path") != "/readyz":
        raise EvidenceError("cloud_run_readiness_probe_missing")
    if nested(service_container, "livenessProbe", "httpGet", "path") != "/healthz":
        raise EvidenceError("cloud_run_liveness_probe_missing")
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
    require_text(
        main,
        (
            'resource "google_cloud_run_v2_service" "main"',
            'resource "google_cloud_run_v2_job" "migrate"',
            'args    = ["migrate", "up"]',
            'name  = "LATCHWAY_SHUTDOWN_TIMEOUT"',
            'value = "8s"',
            'name = "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN"',
            "var.inject_admin_bootstrap_token ? [1] : []",
            'path = "/readyz"',
            'path = "/healthz"',
        ),
        "cloud_run_terraform_incomplete",
    )
    require_text(
        variables,
        (
            'regex("@sha256:[0-9a-f]{64}$", var.image)',
            'variable "inject_admin_bootstrap_token"',
            'variable "migrate_on_start"',
        ),
        "cloud_run_variables_incomplete",
    )
    return {"terraform_files": len(list(main.parent.glob("*.tf")))}


def validate_aws_terraform() -> Mapping[str, Any]:
    main = ROOT / "deploy/aws/terraform/main.tf"
    variables = ROOT / "deploy/aws/terraform/variables.tf"
    require_text(
        main,
        (
            'resource "aws_ecs_service" "main"',
            'resource "aws_db_instance" "main"',
            'stopTimeout            = 35',
            'deregistration_delay = 60',
            '{ name = "LATCHWAY_SHUTDOWN_TIMEOUT", value = "30s" }',
            'path                = "/readyz"',
            "wait_for_steady_state = true",
            "assign_public_ip = false",
            "var.inject_admin_bootstrap_token ? [aws_secretsmanager_secret.admin_bootstrap.arn] : []",
        ),
        "aws_terraform_incomplete",
    )
    require_text(
        variables,
        ('regex("@sha256:[0-9a-f]{64}$", var.image)', 'variable "migrate_on_start"'),
        "aws_variables_incomplete",
    )
    return {"terraform_files": len(list(main.parent.glob("*.tf")))}


def validate_fly() -> Mapping[str, Any]:
    try:
        document = tomllib.loads((ROOT / "deploy/fly/fly.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise EvidenceError("fly_toml_invalid") from None
    if nested(document, "deploy", "release_command") != "/latchway migrate up":
        raise EvidenceError("fly_migration_command_invalid")
    if nested(document, "deploy", "release_command_timeout") != "15m":
        raise EvidenceError("fly_migration_timeout_invalid")
    if nested(document, "deploy", "max_unavailable") != 1 or nested(document, "deploy", "wait_timeout") != "10m":
        raise EvidenceError("fly_rollout_budget_invalid")
    if document.get("kill_signal") != "SIGTERM" or document.get("kill_timeout") != "35s":
        raise EvidenceError("fly_shutdown_budget_invalid")
    if nested(document, "env", "LATCHWAY_SHUTDOWN_TIMEOUT") != "30s":
        raise EvidenceError("fly_app_shutdown_timeout_invalid")
    checks = nested(document, "http_service", "checks")
    paths = {item.get("path") for item in checks if isinstance(item, dict)} if isinstance(checks, list) else set()
    if paths != {"/healthz", "/readyz"}:
        raise EvidenceError("fly_health_checks_invalid")
    return {"health_paths": sorted(paths)}


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
            '"Cache-Control": "no-store"',
            'getByName("instance-0")',
        ),
        "cloudflare_worker_evidence_incomplete",
    )
    if nested(package, "devDependencies", "wrangler") != "4.127.1":
        raise EvidenceError("cloudflare_wrangler_not_pinned")
    return {"wrangler_version": "4.127.1", "instances": 4}


def validate_workflow() -> Mapping[str, Any]:
    path = ROOT / ".github/workflows/deployment-evidence.yml"
    document = yaml_as_json(path)
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict) or set(jobs) != {"static", "capture"}:
        raise EvidenceError("deployment_workflow_jobs_invalid")
    uses: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            raise EvidenceError("deployment_workflow_job_invalid")
        for step in job.get("steps", []):
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                uses.append(step["uses"])
    if not uses or any(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", item) is None for item in uses):
        raise EvidenceError("deployment_workflow_action_unpinned")
    text = path.read_text(encoding="utf-8")
    required = (
        "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",
        "environment: deployment-evidence-${{ inputs.platform }}",
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
        "--args=--output,json,migrate,status",
        'command:["--output","json","migrate","status"]',
        "--signal SIGTERM --time 35",
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
    if manifest["schema_version"] != 1 or manifest["kind"] != "latchway_cloud_deployment_capture":
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
        or not isinstance(collector.get("run_attempt"), int)
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
    if observation["status_code"] != 200:
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
        build = body.get("build")
        if body.get("status") != "ok" or not isinstance(build, dict):
            raise EvidenceError("health_response_invalid")
        if (
            build.get("commit") != manifest["core_commit"]
            or build.get("version") != manifest["core_release"][1:]
            or build.get("contract_version") != manifest["contract_version"]
            or not isinstance(build.get("protocol_version"), str)
        ):
            raise EvidenceError("health_build_identity_mismatch")
    else:
        checks = body.get("checks")
        expected_checks = {"database", "schema", "active_configuration", "master_key", "signing_key", "worker_heartbeat"}
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
        or not isinstance(status.get("current"), int)
        or status.get("current") != status.get("available")
        or status["current"] < 1
    ):
        raise EvidenceError("migration_status_invalid")
    execution = migration["provider_execution"]
    if not isinstance(execution, dict) or execution.get("reported_status") != status:
        raise EvidenceError("migration_provider_execution_invalid")


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


def validate_cloud_run(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(
        control,
        {"platform", "service", "revision", "migration_job"},
        "cloud_run_control_fields_invalid",
    )
    if value["platform"] != "cloud_run":
        raise EvidenceError("cloud_run_control_invalid")
    service, revision, migration_job = value["service"], value["revision"], value["migration_job"]
    if not isinstance(service, dict) or not isinstance(revision, dict) or not isinstance(migration_job, dict):
        raise EvidenceError("cloud_run_control_invalid")
    container = cloud_run_containers(service)[0]
    if image_digest(container.get("image")) != digest:
        raise EvidenceError("cloud_run_image_digest_mismatch")
    observed = first_nested(revision, (("status", "imageDigest"), ("status", "image_digest")))
    if image_digest(observed) != digest:
        raise EvidenceError("cloud_run_resolved_digest_mismatch")
    if image_digest(cloud_run_containers(migration_job)[0].get("image")) != digest:
        raise EvidenceError("cloud_run_migration_image_digest_mismatch")
    env = find_env(container)
    if nested(env.get("LATCHWAY_SHUTDOWN_TIMEOUT"), "value") != "8s":
        raise EvidenceError("cloud_run_shutdown_timeout_mismatch")
    for name in REQUIRED_SECRET_NAMES:
        if first_nested(env.get(name), (("valueFrom", "secretKeyRef"), ("valueSource", "secretKeyRef"))) is None:
            raise EvidenceError("cloud_run_secret_reference_missing")
    execution = migration.get("provider_execution")
    conditions = first_nested(execution, (("status", "conditions"), ("conditions",)))
    if not isinstance(conditions, list) or not any(
        isinstance(item, dict) and item.get("type") in ("Completed", "Ready") and str(item.get("status")).lower() == "true"
        for item in conditions
    ):
        raise EvidenceError("cloud_run_migration_execution_failed")
    log_record = execution.get("log_record") if isinstance(execution, dict) else None
    execution_name = nested(execution, "metadata", "name")
    if (
        not isinstance(log_record, dict)
        or not isinstance(log_record.get("insert_ids"), list)
        or not log_record["insert_ids"]
        or any(not isinstance(item, str) or not item for item in log_record["insert_ids"])
        or log_record.get("line_count") != len(log_record["insert_ids"])
        or not isinstance(log_record.get("execution_name"), str)
        or not log_record["execution_name"]
        or not isinstance(log_record.get("timestamp"), str)
        or (isinstance(execution_name, str) and execution_name.rsplit("/", 1)[-1] != log_record["execution_name"])
    ):
        raise EvidenceError("cloud_run_migration_log_invalid")
    parse_time(log_record["timestamp"])
    validate_shutdown(shutdown, "cloud_run_revision_rollout", 10, 8, digest)
    if nested(shutdown, "before", "resource_id") == nested(shutdown, "after", "resource_id"):
        raise EvidenceError("cloud_run_revision_not_replaced")
    return {"resource": nested(service, "metadata", "selfLink"), "digest": digest}


def validate_aws(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "service", "task_definition", "tasks"}, "aws_control_fields_invalid")
    if value["platform"] != "aws" or not isinstance(value["service"], dict) or not isinstance(value["task_definition"], dict) or not isinstance(value["tasks"], list):
        raise EvidenceError("aws_control_invalid")
    definitions = value["task_definition"].get("containerDefinitions")
    if not isinstance(definitions, list) or len(definitions) != 1 or not isinstance(definitions[0], dict):
        raise EvidenceError("aws_task_definition_invalid")
    container = definitions[0]
    if image_digest(container.get("image")) != digest or container.get("stopTimeout") != 35 or container.get("readonlyRootFilesystem") is not True:
        raise EvidenceError("aws_task_runtime_invalid")
    environment = {item.get("name"): item.get("value") for item in container.get("environment", []) if isinstance(item, dict)}
    if environment.get("LATCHWAY_SHUTDOWN_TIMEOUT") != "30s":
        raise EvidenceError("aws_shutdown_timeout_mismatch")
    secret_names = {item.get("name") for item in container.get("secrets", []) if isinstance(item, dict)}
    if not REQUIRED_SECRET_NAMES.issubset(secret_names):
        raise EvidenceError("aws_secret_reference_missing")
    service = value["service"]
    if service.get("status") != "ACTIVE" or service.get("runningCount") != service.get("desiredCount") or int(service.get("desiredCount", 0)) < 2:
        raise EvidenceError("aws_service_not_stable")
    for task in value["tasks"]:
        containers = task.get("containers") if isinstance(task, dict) else None
        if task.get("lastStatus") != "RUNNING" or not isinstance(containers, list) or not containers or image_digest(containers[0].get("imageDigest")) != digest:
            raise EvidenceError("aws_task_digest_mismatch")
    execution = migration.get("provider_execution")
    stopped = execution.get("stopped_task") if isinstance(execution, dict) else None
    containers = stopped.get("containers") if isinstance(stopped, dict) else None
    if (
        not isinstance(containers, list)
        or not containers
        or containers[0].get("exitCode") != 0
        or image_digest(containers[0].get("imageDigest")) != digest
        or stopped.get("lastStatus") != "STOPPED"
    ):
        raise EvidenceError("aws_migration_execution_failed")
    log_record = execution.get("log_record") if isinstance(execution, dict) else None
    if (
        not isinstance(log_record, dict)
        or not isinstance(log_record.get("log_stream"), str)
        or not log_record["log_stream"]
        or not isinstance(log_record.get("timestamp_ms"), int)
        or not isinstance(log_record.get("ingestion_time_ms"), int)
        or not isinstance(log_record.get("line_count"), int)
        or not 1 <= log_record["line_count"] <= 100
        or log_record["timestamp_ms"] <= 0
        or log_record["ingestion_time_ms"] < log_record["timestamp_ms"]
    ):
        raise EvidenceError("aws_migration_log_invalid")
    validate_shutdown(shutdown, "ecs_task_replacement", 35, 30, digest)
    if nested(shutdown, "before", "resource_id") == nested(shutdown, "after", "resource_id"):
        raise EvidenceError("aws_task_not_replaced")
    return {"resource": service.get("serviceArn"), "digest": digest, "replicas": len(value["tasks"])}


def fly_machine_digest(machine: Mapping[str, Any]) -> str | None:
    return image_digest(first_nested(machine, (("image_ref", "digest"), ("imageRef", "digest"), ("config", "image"))))


def validate_fly_capture(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "app", "machines"}, "fly_control_fields_invalid")
    if value["platform"] != "fly_io" or not isinstance(value["app"], dict) or not isinstance(value["machines"], list) or len(value["machines"]) < 2:
        raise EvidenceError("fly_control_invalid")
    for machine in value["machines"]:
        if not isinstance(machine, dict) or machine.get("state") != "started" or fly_machine_digest(machine) != digest:
            raise EvidenceError("fly_machine_digest_mismatch")
        checks = machine.get("checks")
        if isinstance(checks, list) and any(isinstance(item, dict) and item.get("status") not in ("passing", "success") for item in checks):
            raise EvidenceError("fly_machine_check_failed")
    execution = migration.get("provider_execution")
    machine_ids = {item.get("id") for item in value["machines"] if isinstance(item, dict)}
    if (
        not isinstance(execution, dict)
        or execution.get("exit_code") != 0
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
    return {"resource": value["app"].get("ID", value["app"].get("id")), "digest": digest, "replicas": len(value["machines"])}


def validate_compose_capture(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "project", "gateway", "image"}, "compose_control_fields_invalid")
    if value["platform"] != "compose" or not isinstance(value["gateway"], dict) or not isinstance(value["image"], dict):
        raise EvidenceError("compose_control_invalid")
    gateway = value["gateway"]
    if nested(gateway, "State", "Running") is not True or nested(gateway, "State", "Health", "Status") != "healthy":
        raise EvidenceError("compose_gateway_not_healthy")
    if nested(gateway, "Config", "Labels", "com.docker.compose.project") != value["project"]:
        raise EvidenceError("compose_project_identity_mismatch")
    if image_digest(nested(gateway, "Config", "Image")) != digest:
        digests = value["image"].get("RepoDigests")
        if not isinstance(digests, list) or digest not in {image_digest(item) for item in digests}:
            raise EvidenceError("compose_image_digest_mismatch")
    execution = migration.get("provider_execution")
    if not isinstance(execution, dict) or execution.get("exit_code") != 0:
        raise EvidenceError("compose_migration_execution_failed")
    validate_shutdown(shutdown, "compose_sigterm_restart", 35, 30, digest)
    return {"resource": value["project"], "digest": digest}


def validate_cloudflare_capture(control: Mapping[str, Any], migration: Mapping[str, Any], shutdown: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
    value = require_fields(control, {"platform", "worker", "container"}, "cloudflare_control_fields_invalid")
    if value["platform"] != "cloudflare_containers" or not isinstance(value["worker"], dict) or not isinstance(value["container"], dict):
        raise EvidenceError("cloudflare_control_invalid")
    worker = require_fields(
        value["worker"],
        {"status", "resource_id", "deployments", "versions"},
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
            or not isinstance(layer.get("size"), int)
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
        or execution.get("exit_code") != 0
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
    return {"resource": worker["resource_id"], "digest": digest, "runtime_digest": mirror_digest}


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
        or shutdown["platform_timeout_seconds"] != platform_timeout
        or shutdown["application_timeout_seconds"] != app_timeout
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


def validate_capture(root: Path) -> tuple[dict[str, Any], list[Check]]:
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
    check("capture.readiness", "Database, schema, configuration, keys, and worker are ready.", lambda: validate_http_observation(values["readiness"], manifest, "/readyz"))
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
        details = validator(
            values["control_plane"],
            values["migration"],
            values["shutdown"],
            expected_digest(manifest),
        )
        if details.get("resource") != manifest["provider_resource_id"]:
            raise EvidenceError("provider_control_plane_resource_mismatch")
        return details

    check(
        "capture.control_plane",
        "The provider serves the exact release digest and passed migration and shutdown checks.",
        validate_control_plane,
    )
    return manifest, checks


def validate_identity(value: Any, manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    identity = require_fields(value, {"platform", "resource_id", "observed_at", "provider_response"}, "identity_observation_fields_invalid")
    if identity["platform"] != manifest["platform"] or identity["resource_id"] != manifest["provider_resource_id"]:
        raise EvidenceError("provider_identity_mismatch")
    require_capture_time(identity["observed_at"], manifest)
    if not isinstance(identity["provider_response"], dict) or not identity["provider_response"]:
        raise EvidenceError("provider_identity_response_invalid")
    return {"resource_id_sha256": hashlib.sha256(identity["resource_id"].encode()).hexdigest()}


def normalized_tar_info(path: Path, name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def seal_capture(capture: Path, output: Path) -> None:
    manifest, checks = validate_capture(capture)
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
            manifest, checks = validate_capture(extracted)
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

    observe = subcommands.add_parser("observe-http", help="capture bounded liveness and readiness responses")
    observe.add_argument("--endpoint", required=True)
    observe.add_argument("--output-dir", type=Path, required=True)
    observe.add_argument("--timeout", type=float, default=10.0)

    seal = subcommands.add_parser("seal", help="write a deterministic capture archive")
    seal.add_argument("--capture-dir", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)

    final = subcommands.add_parser("finalize", help="verify signed platform archives and emit cloud_deployments.json")
    final.add_argument("--evidence-root", type=Path, required=True)
    final.add_argument("--coordinates", type=Path, required=True)
    final.add_argument("--trusted-root", type=Path, required=True)
    final.add_argument("--core-commit", required=True)
    final.add_argument("--core-release", required=True)
    final.add_argument("--contract-version", required=True)
    final.add_argument("--bundle-sha256", required=True)
    final.add_argument("--image", required=True)
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
            manifest, checks = validate_capture(args.capture_dir.resolve())
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
            seal_capture(args.capture_dir.resolve(), args.output.resolve())
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
