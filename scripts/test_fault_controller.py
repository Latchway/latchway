#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("fault-controller.py")
SPEC = importlib.util.spec_from_file_location("fault_controller", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controller
SPEC.loader.exec_module(controller)


COMMIT = "c" * 40
INDEX = "ghcr.io/latchway/latchway@sha256:" + "a" * 64
PLATFORM = "ghcr.io/latchway/latchway@sha256:" + "b" * 64
POSTGRES = "docker.io/library/postgres@sha256:" + "d" * 64


def plan() -> controller.Plan:
    return controller.Plan(
        run_id="testrun01",
        api_replicas=2,
        worker_replicas=2,
        candidate_image_id="sha256:" + "e" * 64,
        postgres_image_id="sha256:" + "f" * 64,
        tools_image_id="sha256:" + "9" * 64,
        scenario_timeout_seconds=60,
        overall_timeout_seconds=360,
        drain_timeout_seconds=10,
    )


def identity() -> controller.Identity:
    return controller.Identity(
        commit=COMMIT,
        image=INDEX,
        platform_image=PLATFORM,
        postgres_image=POSTGRES,
        operator="protected workflow test",
    )


class FakeDocker:
    def __init__(self, value: controller.Plan) -> None:
        self.plan = value
        self.network_present = True
        self.present = set(value.roles)
        self.running_state = {name: True for name in value.roles}
        self.networks = {name: {value.network} for name in value.roles}
        self.exit_codes = {name: 0 for name in value.roles}
        self.calls: list[tuple[str, ...]] = []
        self.fail_phase: tuple[str, str] | None = None
        self.published_port = False
        self.candidate_repo_digests = {PLATFORM}
        self.container_ids = {
            name: f"{index:064x}" for index, name in enumerate(value.roles, start=1)
        }
        self.network_id = "8" * 64
        self.postgres_ip = "10.238.64.20"

    def network_exists(self, network: str) -> bool:
        return self.network_present and network == self.plan.network

    def network_value(self, network: str, template: str, label: str) -> str:
        if network != self.plan.network or not self.network_present:
            raise controller.ControllerError("network_missing")
        if ".Internal" in template:
            return "true"
        if ".Driver" in template:
            return "bridge"
        if template == "{{.Id}}":
            return self.network_id
        if controller.RUN_LABEL in template:
            return self.plan.run_id
        raise AssertionError((template, label))

    def container_exists(self, container: str) -> bool:
        return container in self.present

    def labeled_containers(self, run_id: str) -> set[str]:
        return set(self.present) if run_id == self.plan.run_id else set()

    def attached_containers(self, network: str) -> set[str]:
        return {name for name, networks in self.networks.items() if network in networks and name in self.present}

    def label(self, container: str, key: str) -> str:
        if key == controller.RUN_LABEL:
            return self.plan.run_id
        if key == controller.ROLE_LABEL:
            return self.plan.roles[container]
        if key == "org.opencontainers.image.revision":
            return COMMIT
        raise AssertionError(key)

    def running(self, container: str) -> bool:
        return self.running_state[container]

    def exit_code(self, container: str) -> int:
        return self.exit_codes[container]

    def container_networks(self, container: str) -> set[str]:
        return set(self.networks[container])

    def container_value(self, container: str, template: str, label: str) -> str:
        if "PortBindings" in template:
            return '{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"1"}]}' if self.published_port else "{}"
        if ".Privileged" in template:
            return "false"
        if ".PidMode" in template:
            return ""
        if template == "{{.Image}}":
            role = self.plan.roles[container]
            if role in {"api", "worker"}:
                return self.plan.candidate_image_id
            if role == "postgres":
                return self.plan.postgres_image_id
            return self.plan.tools_image_id
        if template == "{{.Id}}":
            return self.container_ids[container]
        if "IPAddress" in template and container == self.plan.postgres:
            return self.postgres_ip
        raise AssertionError((template, label))

    def image_repo_digests(self, image_id: str) -> set[str]:
        if image_id == self.plan.candidate_image_id:
            return set(self.candidate_repo_digests)
        if image_id == self.plan.postgres_image_id:
            return {POSTGRES}
        raise AssertionError(image_id)

    def kill(self, container: str, signal_name: str) -> None:
        self.calls.append(("kill", signal_name, container))
        self.running_state[container] = False
        self.exit_codes[container] = 137 if signal_name == "KILL" else 0

    def start(self, container: str) -> None:
        self.calls.append(("start", container))
        self.running_state[container] = True

    def disconnect(self, network: str, container: str) -> None:
        self.calls.append(("disconnect", network, container))
        self.networks[container].discard(network)

    def connect(self, network: str, container: str, ip_address: str) -> None:
        self.calls.append(("connect", network, container, ip_address))
        self.networks[container].add(network)

    def remove_containers(self, containers: tuple[str, ...] | list[str]) -> None:
        self.calls.append(("remove-containers", *containers))
        for name in containers:
            self.present.discard(name)
            self.networks[name].clear()

    def remove_network(self, network: str) -> None:
        self.calls.append(("remove-network", network))
        if any(network in networks for networks in self.networks.values()):
            raise controller.ControllerError("network_still_in_use")
        self.network_present = False

    def driver_phase(
        self, driver: str, scenario_id: str, phase: str, timeout: float
    ) -> dict:
        self.calls.append(("phase", scenario_id, phase))
        if self.fail_phase == (scenario_id, phase):
            raise controller.ControllerError("injected_driver_failure")
        marker = {
            "prepare": "boundary_ready",
            "during_fault": "fault_observed",
            "inject": "fault_observed",
            "after_fault": "recovery_observed",
            "verify": "verification_complete",
        }[phase]
        value = {
            "schema_version": 1,
            "scenario_id": scenario_id,
            "phase": phase,
            "status": "passed",
            "observations": {marker: True, "bounded_count": 1},
        }
        if phase == "verify":
            value["assertions"] = [
                {"name": name, "passed": True, "detail": f"machine check passed: {name}"}
                for name in sorted(controller.SCENARIO_ASSERTIONS[scenario_id])
            ]
        return value


class FaultControllerTests(unittest.TestCase):
    def test_committed_matrix_binds_all_six_fixed_actions(self) -> None:
        controller.validate_matrix()
        matrix = json.loads(controller.MATRIX.read_text(encoding="utf-8"))
        external = {
            item["id"]: item["controller_action"]
            for item in matrix["scenarios"]
            if item["kind"] == "external"
        }
        self.assertEqual(external, controller.SCENARIO_ACTIONS)

    def test_plan_is_strict_bounded_and_contains_no_target_coordinates(self) -> None:
        value = plan()
        payload = {
            "schema_version": 1,
            "kind": "latchway_disposable_fault_plan",
            **asdict(value),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = controller.load_plan(path)
            self.assertEqual(loaded, value)
            payload["gateway_url"] = "https://production.invalid"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(controller.ControllerError, "plan_fields_invalid"):
                controller.load_plan(path)

    def test_phase_protocol_rejects_missing_markers_and_arbitrary_assertions(self) -> None:
        scenario = "live-process-kill-after-reservation"
        value = {
            "schema_version": 1,
            "scenario_id": scenario,
            "phase": "prepare",
            "status": "passed",
            "observations": {"some_other_flag": True},
        }
        with self.assertRaisesRegex(controller.ControllerError, "driver_phase_marker_missing"):
            controller.decode_phase(json.dumps(value).encode(), scenario, "prepare")
        value.update(
            {
                "phase": "verify",
                "observations": {"verification_complete": True},
                "assertions": [{"name": "arbitrary_true", "passed": True, "detail": "not enough"}],
            }
        )
        with self.assertRaisesRegex(controller.ControllerError, "driver_assertions_invalid"):
            controller.decode_phase(json.dumps(value).encode(), scenario, "verify")

    def test_observations_allow_token_counts_but_reject_credentials(self) -> None:
        controller.validate_observation({"input_tokens": 11, "key_id": "kid_sha256"})
        with self.assertRaisesRegex(controller.ControllerError, "sensitive_field"):
            controller.validate_observation({"access_token": "must-not-be-captured"})

    def test_subprocess_runner_enforces_time_and_output_bounds(self) -> None:
        runner = controller.BoundedRunner()
        with self.assertRaisesRegex(controller.ControllerError, "timed_out"):
            runner.run(
                (sys.executable, "-c", "import time; time.sleep(2)"),
                label="bounded_timeout",
                timeout=0.05,
            )
        with self.assertRaisesRegex(controller.ControllerError, "output_exceeded"):
            runner.run(
                (
                    sys.executable,
                    "-c",
                    f"import os; os.write(1, b'x' * {controller.MAXIMUM_COMMAND_OUTPUT + 1})",
                ),
                label="bounded_output",
                timeout=5,
            )

    def test_controller_injects_every_fault_emits_existing_schema_and_tears_down(self) -> None:
        value = plan()
        fake = FakeDocker(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = controller.now()
            captures = controller.Controller(value, identity(), root, fake).run()
            controller.emit_evidence(root, value, identity(), captures, started)
            self.assertEqual({item.scenario_id for item in captures}, set(controller.SCENARIO_ACTIONS))
            self.assertFalse(fake.present)
            self.assertFalse(fake.network_present)
            self.assertIn(("kill", "KILL", value.apis[0]), fake.calls)
            self.assertIn(("kill", "KILL", value.apis[1]), fake.calls)
            self.assertIn(("disconnect", value.network, value.postgres), fake.calls)
            self.assertIn(
                ("connect", value.network, value.postgres, "10.238.64.20"),
                fake.calls,
            )
            self.assertIn(("kill", "TERM", value.apis[0]), fake.calls)
            for scenario_id, expected in controller.SCENARIO_ASSERTIONS.items():
                document = json.loads((root / f"{scenario_id}.json").read_text(encoding="utf-8"))
                self.assertEqual(document["status"], "passed")
                self.assertEqual({item["name"] for item in document["assertions"]}, expected)
                self.assertTrue(document["artifacts"])
                for artifact in document["artifacts"]:
                    path = root / artifact["path"]
                    self.assertTrue(path.is_file())
                    self.assertEqual(controller.sha256_file(path), artifact["sha256"])

    def test_driver_failure_still_removes_only_validated_disposable_topology(self) -> None:
        value = plan()
        fake = FakeDocker(value)
        fake.fail_phase = ("live-process-kill-during-stream", "prepare")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(controller.ControllerError, "injected_driver_failure"):
                controller.Controller(value, identity(), Path(temporary), fake).run()
        self.assertFalse(fake.present)
        self.assertFalse(fake.network_present)

    def test_topology_with_a_published_port_fails_before_fault_injection(self) -> None:
        value = plan()
        fake = FakeDocker(value)
        fake.published_port = True
        with tempfile.TemporaryDirectory() as temporary:
            instance = controller.Controller(value, identity(), Path(temporary), fake)
            with self.assertRaisesRegex(controller.ControllerError, "published_port"):
                instance.validate_topology()
        self.assertFalse(any(call[0] in {"kill", "disconnect", "phase"} for call in fake.calls))

    def test_topology_rejects_a_revision_label_without_the_authenticated_digest(self) -> None:
        value = plan()
        fake = FakeDocker(value)
        fake.candidate_repo_digests = {"ghcr.io/latchway/latchway@sha256:" + "1" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            instance = controller.Controller(value, identity(), Path(temporary), fake)
            with self.assertRaisesRegex(controller.ControllerError, "platform_digest_not_loaded"):
                instance.validate_topology()

    def test_topology_rejects_nonprivate_postgres_restore_coordinate(self) -> None:
        value = plan()
        fake = FakeDocker(value)
        fake.postgres_ip = "8.8.8.8"
        with tempfile.TemporaryDirectory() as temporary:
            instance = controller.Controller(value, identity(), Path(temporary), fake)
            with self.assertRaisesRegex(controller.ControllerError, "network_address_invalid"):
                instance.validate_topology()

    def test_controller_refuses_a_same_name_container_replacement_before_fault(self) -> None:
        value = plan()
        fake = FakeDocker(value)
        with tempfile.TemporaryDirectory() as temporary:
            instance = controller.Controller(value, identity(), Path(temporary), fake)
            instance.validate_topology()
            fake.container_ids[value.apis[0]] = "7" * 64
            with self.assertRaisesRegex(controller.ControllerError, "ownership_lost"):
                instance.run_scenario("live-process-kill-after-reservation")
        self.assertFalse(any(call[0] == "kill" for call in fake.calls))


if __name__ == "__main__":
    unittest.main()
