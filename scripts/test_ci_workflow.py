#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PNPM_SETUP = "pnpm/action-setup@d15e628ca66d93ee5f352c71671a7bc6a97af5c9"


def load_workflow(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path.name} is not an object")
    return value


class CIWorkflowTests(unittest.TestCase):
    def test_postgres_compatibility_matrix_uses_exact_images(self) -> None:
        workflow = load_workflow(WORKFLOWS / "ci.yml")
        rows = workflow["jobs"]["core"]["strategy"]["matrix"]["postgres"]
        self.assertEqual({row["major"] for row in rows}, {"15", "18"})
        for row in rows:
            self.assertRegex(
                row["image"],
                r"^docker\.io/library/postgres@sha256:[0-9a-f]{64}$",
            )

    def test_pull_requests_run_discovered_script_regressions_offline(self) -> None:
        workflow = load_workflow(WORKFLOWS / "ci.yml")
        triggers = workflow.get("on", workflow.get(True, {}))
        self.assertIn("pull_request", triggers)
        steps = workflow["jobs"]["contracts"]["steps"]
        step = next(
            step
            for step in steps
            if step.get("name") == "Validate repository script tooling offline"
        )
        self.assertNotIn("if", step)
        command = step["run"]
        self.assertEqual(command, "make test-scripts")
        self.assertNotIn("secrets.", command)
        self.assertNotIn("gh api", command)

        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("test-scripts:", makefile)
        self.assertIn(
            "$(PYTHON) -m unittest discover -s scripts -p 'test_*.py'",
            makefile,
        )

    def test_contracts_job_installs_and_runs_pinned_actionlint(self) -> None:
        workflow = load_workflow(WORKFLOWS / "ci.yml")
        steps = workflow["jobs"]["contracts"]["steps"]
        install_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Install pinned actionlint"
        )
        validate_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Validate GitHub workflows"
        )
        self.assertLess(install_index, validate_index)
        self.assertEqual(
            steps[install_index]["run"],
            "python3 scripts/install-actionlint.py",
        )
        self.assertEqual(steps[validate_index]["run"], "make check-workflows")

        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("check-workflows:", makefile)
        self.assertIn(
            "$(ACTIONLINT) -shellcheck= -pyflakes= -oneline .github/workflows/*.yml",
            makefile,
        )

    def test_pnpm_exists_before_setup_node_reads_its_cache(self) -> None:
        cached_setup_nodes = 0
        for path in sorted(WORKFLOWS.glob("*.yml")):
            workflow = load_workflow(path)
            for job_name, job in workflow["jobs"].items():
                steps = [step for step in job.get("steps", []) if isinstance(step, dict)]
                for index, step in enumerate(steps):
                    if not str(step.get("uses", "")).startswith("actions/setup-node@"):
                        continue
                    if step.get("with", {}).get("cache") != "pnpm":
                        continue
                    cached_setup_nodes += 1
                    self.assertGreater(index, 0, f"{path.name}:{job_name}")
                    package_manager = steps[index - 1]
                    self.assertEqual(
                        package_manager.get("uses"),
                        PNPM_SETUP,
                        f"{path.name}:{job_name}",
                    )
                    self.assertEqual(
                        package_manager.get("if"),
                        step.get("if"),
                        f"{path.name}:{job_name}",
                    )
                    self.assertEqual(
                        package_manager.get("with"),
                        {"version": "10.15.0", "run_install": False},
                        f"{path.name}:{job_name}",
                    )
        self.assertGreater(cached_setup_nodes, 0)

    def test_container_smoke_rejects_the_postgres_initialization_server(self) -> None:
        script = (ROOT / "scripts/container-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("postgres_required_ready_streak=5", script)
        self.assertIn(
            "docker inspect --format '{{.State.Running}}' \"$postgres\"",
            script,
        )
        self.assertIn("--env \"PGPASSWORD=${POSTGRES_PASSWORD}\"", script)
        self.assertIn("--host 127.0.0.1", script)
        self.assertIn("--command 'SELECT 1'", script)
        self.assertIn(
            "postgres_tcp_ready_streak=$((postgres_tcp_ready_streak + 1))",
            script,
        )
        self.assertGreaterEqual(script.count("postgres_tcp_ready_streak=0"), 2)
        self.assertNotIn(
            'docker exec "$postgres" pg_isready --username latchway',
            script,
        )

    def test_container_smoke_failure_dumps_gateway_and_postgres_logs(self) -> None:
        script = (ROOT / "scripts/container-smoke.sh").read_text(encoding="utf-8")
        self.assertIn('docker logs "$gateway" >&2 || true', script)
        self.assertIn('docker logs "$postgres" >&2 || true', script)

    def test_multiarch_image_gate_enforces_the_minimal_runtime_filesystem(self) -> None:
        workflow = load_workflow(WORKFLOWS / "ci.yml")
        image = workflow["jobs"]["image"]
        steps = [step for step in image["steps"] if isinstance(step, dict)]
        platforms = next(
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Verify both release platforms are present"
        )
        runtime = next(
            index
            for index, step in enumerate(steps)
            if step.get("name")
            == "Verify the exact minimal runtime filesystem on both platforms"
        )
        self.assertLess(platforms, runtime)
        self.assertEqual(
            steps[runtime]["run"],
            "python3 scripts/verify-runtime-image.py "
            "/tmp/latchway-multiarch.tar linux/amd64 linux/arm64",
        )

    def test_workflows_have_one_pinned_pnpm_bootstrap(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            self.assertNotIn(
                "corepack prepare pnpm",
                path.read_text(encoding="utf-8"),
                path.name,
            )

    def test_terraform_locks_cover_the_linux_amd64_ci_runner(self) -> None:
        expected = {
            ROOT / "deploy/cloud-run/terraform/.terraform.lock.hcl": (
                "h1:L3O+5UStRwh0MTseTQ7/IlOruySgkWvZJuLMrCs4/D4=",
                "h1:UlBuNVuCGJ39tTv2c5gz2NRZnQbXfbIWbTzWcth5o74=",
            ),
            ROOT / "deploy/aws/terraform/.terraform.lock.hcl": (
                "h1:lTKd2c1EunGxt2XROLgEeSXA2Jk+WiiG9BTcp+L/0xY=",
                "h1:UlBuNVuCGJ39tTv2c5gz2NRZnQbXfbIWbTzWcth5o74=",
            ),
        }
        for path, hashes in expected.items():
            lock = path.read_text(encoding="utf-8")
            for checksum in hashes:
                self.assertIn(f'"{checksum}"', lock, path)


class MakefileFormattingTests(unittest.TestCase):
    def test_fmt_checks_every_tracked_go_file_and_ignores_untracked_files(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("GOFMT ?= $(shell $(GO) env GOROOT)/bin/gofmt", makefile)
        self.assertIn("git ls-files -z -- '*.go' | xargs -0 $(GOFMT) -l", makefile)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            nested = repository / "nested"
            nested.mkdir()
            tracked = nested / "tracked.go"
            tracked.write_text(
                'package sample\n\nfunc Value(){println("tracked")}\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "add", "nested/tracked.go"],
                cwd=repository,
                check=True,
            )

            malformed = subprocess.run(
                ["make", "-f", str(ROOT / "Makefile"), "fmt"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(malformed.returncode, 0)
            self.assertIn("nested/tracked.go", malformed.stdout)

            subprocess.run(["gofmt", "-w", tracked], check=True)
            (repository / "untracked.go").write_text(
                'package sample\n\nfunc Other(){println("untracked")}\n',
                encoding="utf-8",
            )
            clean = subprocess.run(
                ["make", "-f", str(ROOT / "Makefile"), "fmt"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)


class LocalLoadPostgresReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "scripts/run-local-load-gates.sh").read_text(
            encoding="utf-8"
        )
        start = cls.source.index("postgres_query() (\n")
        end = cls.source.index("\npostgres_image_id=", start)
        cls.readiness = cls.source[start:end]
        cls.show = next(
            line for line in cls.source.splitlines()
            if line.startswith("postgres_observed_max_connections=")
        )
        start = cls.source.index("capture_postgres_startup_events() {\n")
        end = cls.source.index("\ncleanup() {", start)
        cls.diagnostics = cls.source[start:end]

    def run_probe(self, outcomes, *, show="ready", diagnostics=None):
        # Execute the production shell blocks with fake Docker responses. In
        # particular, the fake socket-only server accepts pg_isready but rejects
        # authenticated TCP SQL, matching the image initialization race.
        with tempfile.TemporaryDirectory(prefix="latchway-readiness-test-") as root:
            directory = Path(root)
            state_path = directory / "state.json"
            state_path.write_text(
                json.dumps({"probes": 0, "inspections": 0, "queries": [],
                            "invalid_connection": False, "pg_isready": 0,
                            "password_in_arguments": False,
                            "log_arguments": []}),
                encoding="utf-8",
            )
            mock = "#!" + sys.executable + r'''
import json, os, pathlib, sys
path = pathlib.Path(os.environ["MOCK_STATE"])
state = json.loads(path.read_text())
arguments = sys.argv[1:]
outcomes = json.loads(os.environ["MOCK_OUTCOMES"])
result = outcomes[min(state["probes"], len(outcomes) - 1)]
status = 0
if pathlib.Path(sys.argv[0]).name == "sleep":
    pass
elif arguments[0] == "inspect":
    state["inspections"] += 1
    if result == "missing_container":
        status = 1
    else:
        print("false" if result == "stopped" else "true")
elif arguments[0] == "logs":
    state["log_arguments"] = arguments
    sys.stdout.write(os.environ["MOCK_LOGS"])
elif arguments[0] == "exec":
    state["password_in_arguments"] = state["password_in_arguments"] or any(
        "load-readiness-test-password" in argument for argument in arguments)
    if "pg_isready" in arguments:
        state["pg_isready"] += 1
        print("accepting connections")
    else:
        command = arguments[arguments.index("--command") + 1]
        pairs = [("--host", "127.0.0.1"), ("--username", "latchway"),
                 ("--dbname", "latchway"), ("--set", "ON_ERROR_STOP=1")]
        valid = all(flag in arguments and arguments[arguments.index(flag)+1] == value
                    for flag, value in pairs)
        valid = valid and all(value in arguments for value in [
            "PGPASSWORD", "PGCONNECT_TIMEOUT=2",
            "PGOPTIONS=-c statement_timeout=2000", "--no-password", "--no-psqlrc"])
        valid = valid and os.environ.get("PGPASSWORD") == "load-readiness-test-password"
        state["invalid_connection"] = state["invalid_connection"] or not valid
        state["queries"].append(command)
        if not valid:
            status = 87
        elif command == "SELECT 1":
            state["probes"] += 1
            status = 0 if result == "ready" else 2
            if status == 0: print("1")
        elif command == "SHOW max_connections":
            status = 0 if os.environ["MOCK_SHOW"] == "ready" else 2
            if status == 0: print("100")
        else:
            status = 88
else:
    status = 89
path.write_text(json.dumps(state))
sys.exit(status)
'''
            for name in ("docker", "sleep"):
                executable = directory / name
                executable.write_text(mock, encoding="utf-8")
                executable.chmod(0o700)
            script = """set -eu
postgres=load-test-postgres
export POSTGRES_USER=latchway POSTGRES_DB=latchway
export POSTGRES_PASSWORD=load-readiness-test-password
export PGPASSWORD=caller-existing-password
"""
            if diagnostics is None:
                script += self.readiness + "\n" + self.show + "\n"
                script += 'test "$PGPASSWORD" = caller-existing-password\n'
                script += 'printf "ready=%s;max=%s\\n" "$postgres_ready" "$postgres_observed_max_connections"\n'
            else:
                script += self.diagnostics + "\ncapture_postgres_startup_events\n"
            completed = subprocess.run(
                ["/bin/sh", "-c", script],
                env={
                    **os.environ,
                    "PATH": str(directory) + os.pathsep + os.environ["PATH"],
                    "MOCK_STATE": str(state_path),
                    "MOCK_OUTCOMES": json.dumps(outcomes),
                    "MOCK_SHOW": show,
                    "MOCK_LOGS": diagnostics or "",
                },
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            return completed, json.loads(state_path.read_text(encoding="utf-8"))

    def test_socket_only_initialization_cannot_satisfy_readiness(self) -> None:
        result, state = self.run_probe(["socket_only", "socket_only"] + ["ready"] * 5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["probes"], 7)
        self.assertEqual(state["pg_isready"], 0)
        self.assertFalse(state["invalid_connection"])

    def test_absent_database_cannot_satisfy_readiness(self) -> None:
        result, state = self.run_probe(["missing_database"] * 2 + ["ready"] * 5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["probes"], 7)
        self.assertFalse(state["invalid_connection"])

    def test_failed_probe_resets_the_five_success_streak(self) -> None:
        result, state = self.run_probe(["ready"] * 4 + ["missing_database"] + ["ready"] * 5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["probes"], 10)

    def test_authentication_failure_exhausts_bounded_attempts(self) -> None:
        result, state = self.run_probe(["authentication_failed"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become ready for authenticated TCP queries", result.stderr)
        self.assertEqual(state["probes"], 90)
        self.assertFalse(state["invalid_connection"])
        self.assertNotIn("SHOW max_connections", state["queries"])

    def test_exited_container_stops_without_exhausting_attempts(self) -> None:
        result, state = self.run_probe(["ready", "stopped"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["probes"], 1)
        self.assertEqual(state["inspections"], 2)

    def test_missing_container_inspect_failure_stops_early(self) -> None:
        result, state = self.run_probe(["ready", "missing_container"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["probes"], 1)
        self.assertEqual(state["inspections"], 2)

    def test_password_is_not_in_arguments_and_caller_environment_is_preserved(self) -> None:
        result, state = self.run_probe(["ready"] * 5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(state["password_in_arguments"])
        self.assertFalse(state["invalid_connection"])

    def test_settings_query_uses_the_same_authenticated_tcp_path(self) -> None:
        result, state = self.run_probe(["ready"] * 5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "ready=true;max=100")
        self.assertEqual(state["queries"], ["SELECT 1"] * 5 + ["SHOW max_connections"])
        self.assertFalse(state["invalid_connection"])

    def test_failed_settings_query_remains_fatal(self) -> None:
        result, state = self.run_probe(["ready"] * 5, show="missing_database")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state["queries"][-1], "SHOW max_connections")
        self.assertNotIn("ready=true", result.stdout)

    def test_postgres_diagnostics_never_copy_raw_log_content(self) -> None:
        logs = "\n".join([
            "database system is ready to accept connections secret=sentinel-private-value",
            'FATAL:  database "latchway" does not exist',
            'FATAL:  password authentication failed for user "sentinel-private-value"',
            "DETAIL: SQL parameter bearer=sentinel-private-value",
            "FATAL: unknown secret-bearing error sentinel-private-value",
            "PostgreSQL init process complete; ready for start up.",
        ])
        result, state = self.run_probe(["ready"], diagnostics=logs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sentinel-private-value", result.stdout + result.stderr)
        self.assertNotIn("DETAIL", result.stdout)
        self.assertIn("postgres: expected database absent", result.stdout)
        self.assertIn("postgres: authentication failed", result.stdout)
        self.assertEqual(state["log_arguments"], ["logs", "--tail", "200", "load-test-postgres"])

    def test_postgres_diagnostics_have_a_byte_limit(self) -> None:
        logs = "x" * 32768 + "\ndatabase system is ready to accept connections\n"
        result, _ = self.run_probe(["ready"], diagnostics=logs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "postgres: no allowlisted event in bounded log tail")
        self.assertLess(len(result.stdout), 100)

    def test_cleanup_retains_only_sanitized_postgres_failure_events(self) -> None:
        self.assertIn(
            'if [ "$status" -ne 0 ] && docker inspect "$postgres" >/dev/null 2>&1; then',
            self.source,
        )
        self.assertIn(
            'capture_postgres_startup_events >"$evidence_dir/postgres-startup.log"',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
