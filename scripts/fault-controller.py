#!/usr/bin/env python3
"""Run the six release failure cases against one disposable Docker topology.

This controller owns fault injection, timing, bounded capture, and teardown. A
repository-built observer inside the isolated topology owns application-specific
traffic and database assertions. The controller never accepts target URLs or arbitrary
host commands: every Docker object name is derived from a run identifier and
must carry the matching disposable-run label on one internal-only network.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "tests/failure/matrix.json"
RUN_LABEL = "dev.latchway.failure.run"
ROLE_LABEL = "dev.latchway.failure.role"
DRIVER_PATH = "/tools/latchway-failure-driver"
MAXIMUM_COMMAND_OUTPUT = 1 << 20
MAXIMUM_PLAN_BYTES = 64 << 10
MAXIMUM_PHASE_BYTES = 512 << 10

SCENARIO_ACTIONS = {
    "live-process-kill-after-reservation": "docker_sigkill_api_after_reservation",
    "live-process-kill-during-stream": "docker_sigkill_api_during_stream",
    "live-database-outage-boundaries": "docker_postgresql_network_partition",
    "live-graceful-shutdown-and-drain": "docker_sigterm_drain",
    "live-upstream-and-client-disconnect": "fixture_disconnect_sequence",
    "live-config-and-key-rotation-across-api-replicas": "replicated_rotation_sequence",
}
SCENARIO_ASSERTIONS = {
    "live-process-kill-after-reservation": {
        "process_sigkill_observed",
        "reservation_was_durable_before_kill",
        "replacement_worker_reclaimed_reservation",
        "no_usage_recorded_for_undispatched_attempt",
        "hard_quota_not_overspent",
    },
    "live-process-kill-during-stream": {
        "sse_first_byte_observed_before_sigkill",
        "process_sigkill_observed",
        "replacement_api_and_worker_recovered",
        "reservation_settled_conservatively",
        "no_permanent_reservation",
        "hard_quota_not_overspent",
    },
    "live-database-outage-boundaries": {
        "database_network_cut_observed",
        "predispatch_outage_failed_closed",
        "no_upstream_dispatch_during_predispatch_outage",
        "settlement_outage_created_bounded_pending_usage",
        "worker_reconciled_pending_usage_after_restore",
        "no_permanent_reservation",
    },
    "live-graceful-shutdown-and-drain": {
        "sigterm_observed",
        "listener_rejected_new_work_during_drain",
        "nonstream_completed_or_terminated_within_drain_bound",
        "sse_completed_or_terminated_within_drain_bound",
        "process_exited_within_drain_bound",
        "no_permanent_reservation",
    },
    "live-upstream-and-client-disconnect": {
        "pre_response_upstream_disconnect_observed",
        "mid_sse_upstream_disconnect_observed",
        "downstream_client_cancel_observed",
        "one_terminal_attempt_per_case",
        "usage_provenance_bounded_per_case",
        "no_permanent_reservation",
    },
    "live-config-and-key-rotation-across-api-replicas": {
        "at_least_two_api_replicas_observed",
        "at_least_two_workers_observed",
        "load_balancer_routed_multiple_api_replicas",
        "configuration_revision_atomic_across_replicas",
        "signing_rotation_preserved_active_sessions",
        "jwks_rotation_converged",
    },
}

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{7,40}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
OBJECT_ID = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
OCI_REFERENCE = re.compile(
    r"^(?P<repository>ghcr\.io/latchway/latchway)@sha256:(?P<digest>[0-9a-f]{64})$"
)
POSTGRES_REFERENCE = re.compile(
    r"^docker\.io/library/postgres@sha256:[0-9a-f]{64}$"
)
OBSERVATION_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SENSITIVE_OBSERVATION_KEY = re.compile(
    r"(^|_)(password|secret|access_token|refresh_token|credential|cookie|authorization|private_key)($|_)"
)
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class ControllerError(RuntimeError):
    """A stable, non-secret fault-controller failure."""


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class BoundedRunner:
    """Execute argv without a shell while bounding time and combined output."""

    def run(
        self,
        argv: Sequence[str],
        *,
        label: str,
        timeout: float,
        check: bool = True,
        cwd: Path | None = None,
    ) -> CommandResult:
        if timeout <= 0 or timeout > 3600:
            raise ControllerError(f"{label}_timeout_invalid")
        process = subprocess.Popen(
            tuple(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout = bytearray()
        stderr = bytearray()
        output_exceeded = threading.Event()
        lock = threading.Lock()

        def kill_process() -> None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                return
            except OSError:
                pass
            try:
                process.kill()
            except OSError:
                pass

        def collect(stream: Any, destination: bytearray) -> None:
            try:
                while True:
                    chunk = stream.read(64 << 10)
                    if not chunk:
                        return
                    with lock:
                        if len(stdout) + len(stderr) + len(chunk) > MAXIMUM_COMMAND_OUTPUT:
                            output_exceeded.set()
                            kill_process()
                            return
                        destination.extend(chunk)
            finally:
                stream.close()

        threads = [
            threading.Thread(target=collect, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=collect, args=(process.stderr, stderr), daemon=True),
        ]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_process()
            process.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=10)
        if any(thread.is_alive() for thread in threads):
            raise ControllerError(f"{label}_collector_failed")
        if timed_out:
            raise ControllerError(f"{label}_timed_out")
        if output_exceeded.is_set():
            raise ControllerError(f"{label}_output_exceeded")
        result = CommandResult(bytes(stdout), bytes(stderr), process.returncode)
        if check and result.returncode != 0:
            raise ControllerError(f"{label}_failed_exit_{result.returncode}")
        return result


class Docker:
    def __init__(self, runner: BoundedRunner | Any, binary: str = "docker") -> None:
        self.runner = runner
        self.binary = binary

    def command(
        self,
        arguments: Sequence[str],
        *,
        label: str,
        timeout: float = 30,
        check: bool = True,
    ) -> CommandResult:
        return self.runner.run(
            (self.binary, *arguments), label=label, timeout=timeout, check=check
        )

    def text(
        self,
        arguments: Sequence[str],
        *,
        label: str,
        timeout: float = 30,
        check: bool = True,
    ) -> str:
        result = self.command(arguments, label=label, timeout=timeout, check=check)
        try:
            value = result.stdout.decode("utf-8", "strict").strip()
        except UnicodeDecodeError as error:
            raise ControllerError(f"{label}_output_invalid") from error
        if "\x00" in value:
            raise ControllerError(f"{label}_output_invalid")
        return value

    def network_exists(self, network: str) -> bool:
        result = self.command(
            ("network", "inspect", "--format", "{{.Name}}", network),
            label="inspect_network",
            check=False,
        )
        return result.returncode == 0

    def network_value(self, network: str, template: str, label: str) -> str:
        return self.text(
            ("network", "inspect", "--format", template, network), label=label
        )

    def container_exists(self, container: str) -> bool:
        result = self.command(
            ("inspect", "--format", "{{.Name}}", container),
            label="inspect_container",
            check=False,
        )
        return result.returncode == 0

    def container_value(self, container: str, template: str, label: str) -> str:
        return self.text(("inspect", "--format", template, container), label=label)

    def image_repo_digests(self, image_id: str) -> set[str]:
        value = self.text(
            ("image", "inspect", "--format", "{{json .RepoDigests}}", image_id),
            label="inspect_image_repo_digests",
        )
        decoded = decode_json(value.encode(), "image_repo_digests_invalid")
        if not isinstance(decoded, list) or not decoded or any(
            not isinstance(item, str) for item in decoded
        ):
            raise ControllerError("image_repo_digests_invalid")
        return set(decoded)

    def labeled_containers(self, run_id: str) -> set[str]:
        value = self.text(
            (
                "ps",
                "--filter",
                f"label={RUN_LABEL}={run_id}",
                "--format",
                "{{.Names}}",
            ),
            label="list_labeled_containers",
        )
        return {line for line in value.splitlines() if line}

    def attached_containers(self, network: str) -> set[str]:
        value = self.network_value(
            network,
            "{{range .Containers}}{{println .Name}}{{end}}",
            "inspect_network_containers",
        )
        return {line for line in value.splitlines() if line}

    def container_networks(self, container: str) -> set[str]:
        value = self.container_value(
            container,
            "{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}",
            "inspect_container_networks",
        )
        return {line for line in value.splitlines() if line}

    def label(self, container: str, key: str) -> str:
        return self.container_value(
            container, f'{{{{index .Config.Labels "{key}"}}}}', "inspect_container_label"
        )

    def running(self, container: str) -> bool:
        return self.container_value(
            container, "{{.State.Running}}", "inspect_container_state"
        ) == "true"

    def exit_code(self, container: str) -> int:
        value = self.container_value(
            container, "{{.State.ExitCode}}", "inspect_container_exit"
        )
        try:
            return int(value)
        except ValueError as error:
            raise ControllerError("container_exit_code_invalid") from error

    def kill(self, container: str, signal_name: str) -> None:
        self.command(
            ("kill", "--signal", signal_name, container),
            label=f"docker_{signal_name.lower()}",
        )

    def start(self, container: str) -> None:
        self.command(("start", container), label="docker_start")

    def disconnect(self, network: str, container: str) -> None:
        self.command(
            ("network", "disconnect", "--force", network, container),
            label="docker_network_disconnect",
        )

    def connect(self, network: str, container: str, ip_address: str) -> None:
        self.command(
            ("network", "connect", "--ip", ip_address, network, container),
            label="docker_network_connect",
        )

    def remove_containers(self, containers: Sequence[str]) -> None:
        self.command(("rm", "--force", *containers), label="docker_cleanup_containers")

    def remove_network(self, network: str) -> None:
        self.command(("network", "rm", network), label="docker_cleanup_network")

    def driver_phase(
        self, driver: str, scenario_id: str, phase: str, timeout: float
    ) -> Mapping[str, Any]:
        result = self.command(
            ("exec", driver, DRIVER_PATH, phase, scenario_id),
            label=f"driver_{scenario_id}_{phase}",
            timeout=timeout,
        )
        if len(result.stdout) == 0 or len(result.stdout) > MAXIMUM_PHASE_BYTES:
            raise ControllerError("driver_phase_output_invalid")
        return decode_phase(result.stdout, scenario_id, phase)


@dataclass(frozen=True)
class Plan:
    run_id: str
    api_replicas: int
    worker_replicas: int
    candidate_image_id: str
    postgres_image_id: str
    tools_image_id: str
    scenario_timeout_seconds: int
    overall_timeout_seconds: int
    drain_timeout_seconds: int

    @property
    def prefix(self) -> str:
        return f"latchway-failure-{self.run_id}"

    @property
    def network(self) -> str:
        return self.prefix

    @property
    def driver(self) -> str:
        return f"{self.prefix}-driver"

    @property
    def fixture(self) -> str:
        return f"{self.prefix}-fixture"

    @property
    def load_balancer(self) -> str:
        return f"{self.prefix}-load-balancer"

    @property
    def postgres(self) -> str:
        return f"{self.prefix}-postgres"

    @property
    def apis(self) -> tuple[str, ...]:
        return tuple(f"{self.prefix}-api-{index}" for index in range(1, self.api_replicas + 1))

    @property
    def workers(self) -> tuple[str, ...]:
        return tuple(
            f"{self.prefix}-worker-{index}" for index in range(1, self.worker_replicas + 1)
        )

    @property
    def roles(self) -> Mapping[str, str]:
        value = {
            self.driver: "driver",
            self.fixture: "fixture",
            self.load_balancer: "load-balancer",
            self.postgres: "postgres",
        }
        value.update({name: "api" for name in self.apis})
        value.update({name: "worker" for name in self.workers})
        return value


@dataclass(frozen=True)
class Identity:
    commit: str
    image: str
    platform_image: str
    postgres_image: str
    operator: str


@dataclass
class ScenarioCapture:
    scenario_id: str
    started_at: datetime
    finished_at: datetime | None = None
    assertions: list[Mapping[str, Any]] = field(default_factory=list)
    artifacts: list[Mapping[str, str]] = field(default_factory=list)
    events: list[Mapping[str, Any]] = field(default_factory=list)


def decode_json(payload: bytes, code: str) -> Any:
    def no_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ControllerError(code)
            value[key] = item
        return value

    try:
        return json.loads(payload, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError, ControllerError) as error:
        if isinstance(error, ControllerError):
            raise
        raise ControllerError(code) from error


def load_plan(path: Path) -> Plan:
    if not path.is_absolute():
        raise ControllerError("plan_path_must_be_absolute")
    try:
        info = path.lstat()
    except OSError as error:
        raise ControllerError("plan_unavailable") from error
    if path.is_symlink() or not path.is_file() or info.st_size <= 0 or info.st_size > MAXIMUM_PLAN_BYTES:
        raise ControllerError("plan_must_be_one_bounded_regular_file")
    value = decode_json(path.read_bytes(), "plan_json_invalid")
    keys = {
        "schema_version",
        "kind",
        "run_id",
        "api_replicas",
        "worker_replicas",
        "candidate_image_id",
        "postgres_image_id",
        "tools_image_id",
        "scenario_timeout_seconds",
        "overall_timeout_seconds",
        "drain_timeout_seconds",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ControllerError("plan_fields_invalid")
    if value["schema_version"] != 1 or value["kind"] != "latchway_disposable_fault_plan":
        raise ControllerError("plan_identity_invalid")
    if not isinstance(value["run_id"], str) or not NAME.fullmatch(value["run_id"]):
        raise ControllerError("plan_run_id_invalid")
    for key in ("api_replicas", "worker_replicas"):
        if not isinstance(value[key], int) or isinstance(value[key], bool) or not 2 <= value[key] <= 4:
            raise ControllerError("plan_replica_count_invalid")
    if not isinstance(value["candidate_image_id"], str) or not IMAGE_ID.fullmatch(value["candidate_image_id"]):
        raise ControllerError("plan_candidate_image_invalid")
    if not isinstance(value["postgres_image_id"], str) or not IMAGE_ID.fullmatch(value["postgres_image_id"]):
        raise ControllerError("plan_postgres_image_invalid")
    if not isinstance(value["tools_image_id"], str) or not IMAGE_ID.fullmatch(value["tools_image_id"]):
        raise ControllerError("plan_tools_image_invalid")
    if len({value["candidate_image_id"], value["postgres_image_id"], value["tools_image_id"]}) != 3:
        raise ControllerError("plan_image_identity_invalid")
    scenario_timeout = value["scenario_timeout_seconds"]
    overall_timeout = value["overall_timeout_seconds"]
    drain_timeout = value["drain_timeout_seconds"]
    if (
        not isinstance(scenario_timeout, int)
        or isinstance(scenario_timeout, bool)
        or not 30 <= scenario_timeout <= 600
        or not isinstance(overall_timeout, int)
        or isinstance(overall_timeout, bool)
        or not scenario_timeout * len(SCENARIO_ACTIONS) <= overall_timeout <= 3600
        or not isinstance(drain_timeout, int)
        or isinstance(drain_timeout, bool)
        or not 5 <= drain_timeout <= 120
        or drain_timeout >= scenario_timeout
    ):
        raise ControllerError("plan_timeout_invalid")
    plan = Plan(
        run_id=value["run_id"],
        api_replicas=value["api_replicas"],
        worker_replicas=value["worker_replicas"],
        candidate_image_id=value["candidate_image_id"],
        postgres_image_id=value["postgres_image_id"],
        tools_image_id=value["tools_image_id"],
        scenario_timeout_seconds=scenario_timeout,
        overall_timeout_seconds=overall_timeout,
        drain_timeout_seconds=drain_timeout,
    )
    if any(len(name) > 128 for name in (plan.network, *plan.roles)):
        raise ControllerError("plan_derived_name_invalid")
    return plan


def validate_matrix() -> None:
    value = decode_json(MATRIX.read_bytes(), "failure_matrix_invalid")
    if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("scenarios"), list):
        raise ControllerError("failure_matrix_invalid")
    observed: dict[str, str] = {}
    for scenario in value["scenarios"]:
        if not isinstance(scenario, dict) or scenario.get("kind") != "external":
            continue
        identifier = scenario.get("id")
        action = scenario.get("controller_action")
        if not isinstance(identifier, str) or not isinstance(action, str) or identifier in observed:
            raise ControllerError("failure_matrix_controller_actions_invalid")
        observed[identifier] = action
    if observed != SCENARIO_ACTIONS:
        raise ControllerError("failure_matrix_controller_actions_invalid")


def validate_identity(identity: Identity) -> None:
    if not COMMIT.fullmatch(identity.commit):
        raise ControllerError("candidate_commit_invalid")
    index = OCI_REFERENCE.fullmatch(identity.image)
    platform = OCI_REFERENCE.fullmatch(identity.platform_image)
    if index is None or platform is None or index.group("repository") != platform.group("repository") or identity.image == identity.platform_image:
        raise ControllerError("candidate_image_references_invalid")
    if not POSTGRES_REFERENCE.fullmatch(identity.postgres_image):
        raise ControllerError("postgres_image_reference_invalid")
    if not 1 <= len(identity.operator) <= 200 or any(character in identity.operator for character in "\r\n\x00"):
        raise ControllerError("operator_identity_invalid")


def prepare_output_directory(path: Path) -> None:
    if not path.is_absolute():
        raise ControllerError("output_directory_must_be_absolute")
    try:
        info = path.lstat()
    except OSError as error:
        raise ControllerError("output_directory_must_exist") from error
    if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
        raise ControllerError("output_directory_must_be_one_empty_real_directory")
    os.chmod(path, 0o700)


def validate_source(identity: Identity, runner: BoundedRunner) -> None:
    head = runner.run(
        ("git", "rev-parse", "--verify", "HEAD"),
        label="resolve_source_commit",
        timeout=10,
        cwd=ROOT,
    ).stdout.decode("ascii", "strict").strip()
    status = runner.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        label="resolve_source_status",
        timeout=10,
        cwd=ROOT,
    ).stdout
    if head != identity.commit or status.strip():
        raise ControllerError("controller_requires_exact_clean_candidate_checkout")


def validate_observation(value: Any, depth: int = 0) -> None:
    if depth > 5:
        raise ControllerError("driver_observation_invalid")
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if len(value) > 2048 or any(character in value for character in "\r\x00"):
            raise ControllerError("driver_observation_invalid")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise ControllerError("driver_observation_invalid")
        for item in value:
            validate_observation(item, depth + 1)
        return
    if isinstance(value, dict):
        if not value or len(value) > 256:
            raise ControllerError("driver_observation_invalid")
        for key, item in value.items():
            if not isinstance(key, str) or not OBSERVATION_KEY.fullmatch(key):
                raise ControllerError("driver_observation_invalid")
            if SENSITIVE_OBSERVATION_KEY.search(key):
                raise ControllerError("driver_observation_contains_sensitive_field")
            validate_observation(item, depth + 1)
        return
    raise ControllerError("driver_observation_invalid")


def decode_phase(payload: bytes, scenario_id: str, phase: str) -> Mapping[str, Any]:
    value = decode_json(payload, "driver_phase_json_invalid")
    expected = {"schema_version", "scenario_id", "phase", "status", "observations"}
    if phase == "verify":
        expected.add("assertions")
    if not isinstance(value, dict) or set(value) != expected:
        raise ControllerError("driver_phase_fields_invalid")
    if (
        value["schema_version"] != 1
        or value["scenario_id"] != scenario_id
        or value["phase"] != phase
        or value["status"] != "passed"
    ):
        raise ControllerError("driver_phase_identity_invalid")
    observations = value["observations"]
    validate_observation(observations)
    marker = {
        "prepare": "boundary_ready",
        "during_fault": "fault_observed",
        "inject": "fault_observed",
        "after_fault": "recovery_observed",
        "verify": "verification_complete",
    }.get(phase)
    if marker is None or observations.get(marker) is not True:
        raise ControllerError("driver_phase_marker_missing")
    if phase == "verify":
        assertions = value["assertions"]
        if not isinstance(assertions, list) or len(assertions) != len(SCENARIO_ASSERTIONS[scenario_id]):
            raise ControllerError("driver_assertions_invalid")
        names: set[str] = set()
        for assertion in assertions:
            if not isinstance(assertion, dict) or set(assertion) != {"name", "passed", "detail"}:
                raise ControllerError("driver_assertions_invalid")
            name = assertion["name"]
            detail = assertion["detail"]
            if (
                not isinstance(name, str)
                or name in names
                or assertion["passed"] is not True
                or not isinstance(detail, str)
                or not detail.strip()
                or len(detail) > 1000
                or any(character in detail for character in "\r\x00")
            ):
                raise ControllerError("driver_assertions_invalid")
            names.add(name)
        if names != SCENARIO_ASSERTIONS[scenario_id]:
            raise ControllerError("driver_assertions_invalid")
    return value


def now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


class Controller:
    def __init__(
        self,
        plan: Plan,
        identity: Identity,
        output: Path,
        docker: Docker,
    ) -> None:
        self.plan = plan
        self.identity = identity
        self.output = output
        self.docker = docker
        self.overall_deadline = time.monotonic() + plan.overall_timeout_seconds
        self.owned_containers: dict[str, str] = {}
        self.owned_network_id = ""
        self.postgres_network_ip = ""

    def remaining(self, scenario_deadline: float | None = None) -> float:
        deadline = self.overall_deadline
        if scenario_deadline is not None:
            deadline = min(deadline, scenario_deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ControllerError("fault_controller_deadline_exceeded")
        return remaining

    def validate_topology(self) -> None:
        plan = self.plan
        if not self.docker.network_exists(plan.network):
            raise ControllerError("disposable_network_missing")
        if self.docker.network_value(plan.network, "{{.Internal}}", "inspect_network_internal") != "true":
            raise ControllerError("disposable_network_not_internal")
        if self.docker.network_value(plan.network, "{{.Driver}}", "inspect_network_driver") != "bridge":
            raise ControllerError("disposable_network_driver_invalid")
        label = self.docker.network_value(
            plan.network, f'{{{{index .Labels "{RUN_LABEL}"}}}}', "inspect_network_label"
        )
        if label != plan.run_id:
            raise ControllerError("disposable_network_label_invalid")
        network_id = self.docker.network_value(
            plan.network, "{{.Id}}", "inspect_network_id"
        )
        if not OBJECT_ID.fullmatch(network_id):
            raise ControllerError("disposable_network_identity_invalid")
        self.owned_network_id = network_id
        expected = set(plan.roles)
        if self.docker.labeled_containers(plan.run_id) != expected or self.docker.attached_containers(plan.network) != expected:
            raise ControllerError("disposable_topology_container_set_invalid")
        if self.identity.platform_image not in self.docker.image_repo_digests(
            plan.candidate_image_id
        ):
            raise ControllerError("candidate_platform_digest_not_loaded")
        if self.identity.postgres_image not in self.docker.image_repo_digests(
            plan.postgres_image_id
        ):
            raise ControllerError("postgres_digest_not_loaded")
        for container, role in plan.roles.items():
            if not self.docker.container_exists(container):
                raise ControllerError("disposable_container_missing")
            if self.docker.label(container, RUN_LABEL) != plan.run_id or self.docker.label(container, ROLE_LABEL) != role:
                raise ControllerError("disposable_container_label_invalid")
            container_id = self.docker.container_value(
                container, "{{.Id}}", "inspect_container_id"
            )
            if not OBJECT_ID.fullmatch(container_id):
                raise ControllerError("disposable_container_identity_invalid")
            self.owned_containers[container] = container_id
            if not self.docker.running(container):
                raise ControllerError("disposable_container_not_running")
            if self.docker.container_networks(container) != {plan.network}:
                raise ControllerError("disposable_container_network_invalid")
            bindings = self.docker.container_value(
                container, "{{json .HostConfig.PortBindings}}", "inspect_container_ports"
            )
            if bindings not in ("null", "{}"):
                raise ControllerError("disposable_container_published_port")
            privileged = self.docker.container_value(
                container, "{{.HostConfig.Privileged}}", "inspect_container_privileged"
            )
            pid_mode = self.docker.container_value(
                container, "{{.HostConfig.PidMode}}", "inspect_container_pid_mode"
            )
            if privileged != "false" or pid_mode == "host":
                raise ControllerError("disposable_container_isolation_invalid")
            image_id = self.docker.container_value(container, "{{.Image}}", "inspect_container_image")
            if role in {"api", "worker"}:
                revision = self.docker.label(container, "org.opencontainers.image.revision")
                if image_id != plan.candidate_image_id or revision != self.identity.commit:
                    raise ControllerError("candidate_container_identity_invalid")
            if role == "postgres" and image_id != plan.postgres_image_id:
                raise ControllerError("postgres_container_identity_invalid")
            if role == "postgres":
                address = self.docker.container_value(
                    container,
                    f'{{{{(index .NetworkSettings.Networks "{plan.network}").IPAddress}}}}',
                    "inspect_postgres_network_address",
                )
                try:
                    parsed_address = ipaddress.ip_address(address)
                except ValueError as error:
                    raise ControllerError("postgres_network_address_invalid") from error
                if (
                    parsed_address.version != 4
                    or not any(parsed_address in network for network in RFC1918_NETWORKS)
                    or parsed_address.is_loopback
                    or parsed_address.is_unspecified
                    or parsed_address.is_multicast
                ):
                    raise ControllerError("postgres_network_address_invalid")
                self.postgres_network_ip = address
            if role in {"driver", "fixture", "load-balancer"}:
                revision = self.docker.label(container, "org.opencontainers.image.revision")
                if image_id != plan.tools_image_id or revision != self.identity.commit:
                    raise ControllerError("failure_tools_container_identity_invalid")

    def require_owned_container(self, container: str) -> None:
        expected_id = self.owned_containers.get(container)
        expected_role = self.plan.roles.get(container)
        if expected_id is None or expected_role is None or not self.docker.container_exists(container):
            raise ControllerError("disposable_container_ownership_lost")
        actual_id = self.docker.container_value(
            container, "{{.Id}}", "revalidate_container_id"
        )
        if (
            actual_id != expected_id
            or self.docker.label(container, RUN_LABEL) != self.plan.run_id
            or self.docker.label(container, ROLE_LABEL) != expected_role
        ):
            raise ControllerError("disposable_container_ownership_lost")

    def record_event(
        self, capture: ScenarioCapture, action: str, target: str, status: str, **details: Any
    ) -> None:
        event = {
            "observed_at": timestamp(now()),
            "action": action,
            "target": target,
            "status": status,
        }
        event.update(details)
        capture.events.append(event)

    def phase(
        self, capture: ScenarioCapture, phase: str, scenario_deadline: float
    ) -> Mapping[str, Any]:
        self.require_owned_container(self.plan.driver)
        document = self.docker.driver_phase(
            self.plan.driver,
            capture.scenario_id,
            phase,
            self.remaining(scenario_deadline),
        )
        relative = Path("artifacts") / capture.scenario_id / f"{phase}.json"
        path = self.output / relative
        write_json(path, document)
        capture.artifacts.append({"path": relative.as_posix(), "sha256": sha256_file(path)})
        self.record_event(capture, "driver_phase", self.plan.driver, "passed", phase=phase)
        return document

    def wait_stopped(self, container: str, deadline: float) -> int:
        while True:
            self.require_owned_container(container)
            if not self.docker.running(container):
                break
            if time.monotonic() >= deadline:
                raise ControllerError("container_did_not_stop_within_bound")
            time.sleep(0.25)
        self.require_owned_container(container)
        return self.docker.exit_code(container)

    def run_scenario(self, scenario_id: str) -> ScenarioCapture:
        capture = ScenarioCapture(scenario_id=scenario_id, started_at=now())
        deadline = min(
            self.overall_deadline,
            time.monotonic() + self.plan.scenario_timeout_seconds,
        )
        self.phase(capture, "prepare", deadline)
        action = SCENARIO_ACTIONS[scenario_id]
        if action in {
            "docker_sigkill_api_after_reservation",
            "docker_sigkill_api_during_stream",
        }:
            target = self.plan.apis[0 if action.endswith("after_reservation") else 1]
            self.require_owned_container(target)
            self.docker.kill(target, "KILL")
            exit_code = self.wait_stopped(target, min(deadline, time.monotonic() + 30))
            if exit_code != 137:
                raise ControllerError("sigkill_exit_code_invalid")
            self.record_event(capture, "docker_sigkill", target, "passed", exit_code=exit_code)
            self.require_owned_container(target)
            self.docker.start(target)
            if not self.docker.running(target):
                raise ControllerError("killed_api_did_not_restart")
            self.record_event(capture, "docker_start", target, "passed")
            self.phase(capture, "after_fault", deadline)
        elif action == "docker_postgresql_network_partition":
            disconnected = False
            try:
                self.require_owned_container(self.plan.postgres)
                self.docker.disconnect(self.plan.network, self.plan.postgres)
                disconnected = True
                if self.docker.container_networks(self.plan.postgres):
                    raise ControllerError("postgres_network_partition_not_observed")
                self.record_event(capture, "docker_network_disconnect", self.plan.postgres, "passed")
                self.phase(capture, "during_fault", deadline)
            finally:
                if disconnected:
                    self.require_owned_container(self.plan.postgres)
                    self.docker.connect(
                        self.plan.network,
                        self.plan.postgres,
                        self.postgres_network_ip,
                    )
            if self.docker.container_networks(self.plan.postgres) != {self.plan.network}:
                raise ControllerError("postgres_network_restore_not_observed")
            self.record_event(capture, "docker_network_connect", self.plan.postgres, "passed")
            self.phase(capture, "after_fault", deadline)
        elif action == "docker_sigterm_drain":
            target = self.plan.apis[0]
            drain_deadline = min(
                deadline,
                time.monotonic() + self.plan.drain_timeout_seconds,
            )
            self.require_owned_container(target)
            self.docker.kill(target, "TERM")
            self.record_event(capture, "docker_sigterm", target, "passed")
            self.phase(capture, "during_fault", deadline)
            if time.monotonic() >= drain_deadline:
                raise ControllerError("container_did_not_stop_within_bound")
            exit_code = self.wait_stopped(target, drain_deadline)
            self.record_event(capture, "docker_process_exit", target, "passed", exit_code=exit_code)
            self.require_owned_container(target)
            self.docker.start(target)
            if not self.docker.running(target):
                raise ControllerError("drained_api_did_not_restart")
            self.record_event(capture, "docker_start", target, "passed")
            self.phase(capture, "after_fault", deadline)
        elif action in {"fixture_disconnect_sequence", "replicated_rotation_sequence"}:
            self.phase(capture, "inject", deadline)
            self.phase(capture, "after_fault", deadline)
        else:
            raise ControllerError("controller_action_invalid")
        verified = self.phase(capture, "verify", deadline)
        capture.assertions = list(verified["assertions"])
        capture.finished_at = now()
        event_relative = Path("artifacts") / scenario_id / "fault-events.json"
        event_path = self.output / event_relative
        write_json(
            event_path,
            {
                "schema_version": 1,
                "kind": "latchway_fault_controller_events",
                "scenario_id": scenario_id,
                "controller_action": action,
                "events": capture.events,
            },
        )
        capture.artifacts.append(
            {"path": event_relative.as_posix(), "sha256": sha256_file(event_path)}
        )
        return capture

    def cleanup(self) -> None:
        errors: list[str] = []
        removable: list[str] = []
        for container in sorted(self.owned_containers, reverse=True):
            try:
                if not self.docker.container_exists(container):
                    continue
                if (
                    self.docker.container_value(
                        container, "{{.Id}}", "revalidate_cleanup_container_id"
                    )
                    != self.owned_containers[container]
                    or self.docker.label(container, RUN_LABEL) != self.plan.run_id
                    or self.docker.label(container, ROLE_LABEL)
                    != self.plan.roles[container]
                ):
                    errors.append("container_label_changed")
                    continue
                removable.append(container)
            except ControllerError:
                errors.append("container_revalidation_failed")
        if removable:
            try:
                self.docker.remove_containers(removable)
            except ControllerError:
                errors.append("container_removal_failed")
        if self.owned_network_id:
            try:
                if self.docker.network_exists(self.plan.network):
                    label = self.docker.network_value(
                        self.plan.network,
                        f'{{{{index .Labels "{RUN_LABEL}"}}}}',
                        "revalidate_network_label",
                    )
                    network_id = self.docker.network_value(
                        self.plan.network, "{{.Id}}", "revalidate_network_id"
                    )
                    if label != self.plan.run_id or network_id != self.owned_network_id:
                        errors.append("network_label_changed")
                    else:
                        self.docker.remove_network(self.plan.network)
            except ControllerError:
                errors.append("network_removal_failed")
        if errors:
            raise ControllerError("fault_controller_cleanup_failed:" + ",".join(sorted(set(errors))))

    def run(self) -> list[ScenarioCapture]:
        self.validate_topology()
        captures: list[ScenarioCapture] = []
        execution_error: ControllerError | None = None
        try:
            for scenario_id in SCENARIO_ACTIONS:
                self.remaining()
                captures.append(self.run_scenario(scenario_id))
        except ControllerError as error:
            execution_error = error
        cleanup_error: ControllerError | None = None
        try:
            self.cleanup()
        except ControllerError as error:
            cleanup_error = error
        if execution_error is not None:
            if cleanup_error is not None:
                raise ControllerError(f"{execution_error};{cleanup_error}") from execution_error
            raise execution_error
        if cleanup_error is not None:
            raise cleanup_error
        return captures


def emit_evidence(
    output: Path,
    plan: Plan,
    identity: Identity,
    captures: Sequence[ScenarioCapture],
    started_at: datetime,
) -> None:
    finished_at = now()
    summary = {
        "schema_version": 1,
        "kind": "latchway_fault_controller_run",
        "status": "passed",
        "run_id": plan.run_id,
        "commit": identity.commit,
        "started_at": timestamp(started_at),
        "finished_at": timestamp(finished_at),
        "network_internal": True,
        "api_replicas": plan.api_replicas,
        "worker_replicas": plan.worker_replicas,
        "candidate_image_id": plan.candidate_image_id,
        "postgres_image_id": plan.postgres_image_id,
        "tools_image_id": plan.tools_image_id,
        "scenario_ids": list(SCENARIO_ACTIONS),
        "cleanup": {"containers_removed": True, "network_removed": True},
    }
    summary_path = output / "controller-run.json"
    write_json(summary_path, summary)
    summary_artifact = {"path": "controller-run.json", "sha256": sha256_file(summary_path)}
    for capture in captures:
        if capture.finished_at is None or not capture.assertions:
            raise ControllerError("incomplete_scenario_capture")
        environment: dict[str, str] = {
            "image_digest": identity.image,
            "platform_image_digest": identity.platform_image,
            "platform": "linux/amd64",
            "postgresql": identity.postgres_image,
            "fault_tool": "latchway-fault-controller/v1 (Docker CLI)",
            "operator": identity.operator,
        }
        if capture.scenario_id == "live-config-and-key-rotation-across-api-replicas":
            environment.update(
                {
                    "api_replicas": str(plan.api_replicas),
                    "worker_replicas": str(plan.worker_replicas),
                    "load_balancer": plan.load_balancer,
                }
            )
        evidence = {
            "schema_version": 1,
            "scenario_id": capture.scenario_id,
            "status": "passed",
            "commit": identity.commit,
            "started_at": timestamp(capture.started_at),
            "finished_at": timestamp(capture.finished_at),
            "environment": environment,
            "assertions": capture.assertions,
            "artifacts": [*capture.artifacts, summary_artifact],
        }
        write_json(output / f"{capture.scenario_id}.json", evidence)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-disposable-target", action="store_true")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform-image", required=True)
    parser.add_argument("--postgres-image", required=True)
    parser.add_argument("--operator", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    if not arguments.acknowledge_disposable_target:
        raise ControllerError("explicit_disposable_target_acknowledgement_required")
    if os.geteuid() == 0:
        raise ControllerError("fault_controller_refuses_root")
    plan = load_plan(arguments.plan)
    identity = Identity(
        commit=arguments.commit,
        image=arguments.image,
        platform_image=arguments.platform_image,
        postgres_image=arguments.postgres_image,
        operator=arguments.operator,
    )
    validate_identity(identity)
    validate_matrix()
    prepare_output_directory(arguments.output_dir)
    runner = BoundedRunner()
    validate_source(identity, runner)
    started_at = now()
    captures = Controller(plan, identity, arguments.output_dir, Docker(runner)).run()
    emit_evidence(arguments.output_dir, plan, identity, captures, started_at)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ControllerError as error:
        print(f"fault controller failed: {error}", file=sys.stderr)
        raise SystemExit(1)
