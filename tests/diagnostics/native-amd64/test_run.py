"""Offline safety tests; no Docker daemon, database, network, or credentials."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("diagnostic", Path(__file__).with_name("run.py"))
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
TOOLING = "a" * 40
ENV = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Latchway/latchway", "GITHUB_EVENT_NAME": "workflow_dispatch",
       "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
       "GITHUB_RUN_ID": "12345678", "GITHUB_SHA": TOOLING}


def profile():
    statement = {k: 1 for k in ("calls", "rows", "shared_hit", "shared_read", "shared_dirtied", "shared_written", "temp_read",
                                "temp_written", "wal_records", "wal_fpi", "wal_bytes", "execution_ms", "read_ms", "write_ms")}
    statement.update(query_id="123", top_level=True)
    value = {"schema_version": 1, "advisory_only": True, "source_commit": d.BASE, "serial_requests": 200, "concurrent_requests": 200,
             "concurrency": 16, "pool_max_connections": 32, "calendar_buckets_per_phase": 4, "first_attempt_only": True,
             "exact_accounting_verified": True, "whole_lifecycle_includes_auth": False, "query_timing_is_client_wall": True,
             "batch_member_execution_time_available": False, "prepare_overlaps_query_or_batch": True,
             "batch_auto_prepare_is_not_reported_by_prepare_tracer": True, "warmup_requests_excluded": 16,
             "observer_overhead_present": True, "release_evidence": False, "phase_wall_ms": {"serial": 100, "concurrent": 50},
             "observations": [{"phase": "serial", "stage": "reserve", "category": "stage_inclusive", "label": "reserve",
                               "count": 200, "errors": 0, "no_rows": 0, "total_ms": 10, "mean_ms": .05, "p50_ms": .05, "p95_ms": .08, "max_ms": .1}],
             "server_phases": []}
    for phase in ("serial", "concurrent"):
        value["server_phases"].append({"phase": phase, "statements": [copy.deepcopy(statement)], "lock_samples": [], "wal_delta": [1] * 4,
                                       "io_delta": [1] * 8, "workload_cgroup_available": True,
                                       "workload_cgroup_delta": {k: 1 for k in d.CGROUP}, "stats_reset_or_evicted": False})
    return value


def raw_report():
    return b"ADVISORY_SQL_PROFILE=" + d.canonical(profile()) + b"\n"


class FakeRunner(d.Runner):
    def __init__(self, environment):
        super().__init__(environment)
        self.objects = {}
        self.commands = []
        self.fail_profile = False
        self.remove_failure = None

    def inspect(self, key):
        return self.objects.get(key)

    def call(self, argv, **kwargs):
        self.commands.append((argv, kwargs))
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            return 0, ((TOOLING if kwargs["cwd"] == self.repo else d.BASE) + "\n").encode()
        if argv[:3] == ["git", "diff", "--name-status"]:
            return 0, "".join("A\t" + p + "\n" for p in (*d.FILES, d.WORKFLOW)).encode()
        if argv[:2] == ["git", "ls-remote"]:
            return 0, (TOOLING + "\trefs/heads/main\n").encode()
        if argv[:2] == ["git", "clone"]:
            (Path(argv[-1]) / "internal/quota").mkdir(parents=True)
        if argv[:2] == ["docker", "info"]:
            return 0, b'{"cpu":4,"arch":"x86_64","os":"linux"}'
        if argv[:2] == ["docker", "build"]:
            self.objects["image"] = {"id": "1" * 64}
        if argv[:3] in (["docker", "network", "create"], ["docker", "volume", "create"]):
            self.objects[argv[1]] = {"id": ("2" if argv[1] == "network" else "3") * 64}
        if argv[:2] == ["docker", "create"]:
            key = "postgres" if argv[argv.index("--name") + 1] == self.paths["postgres"] else "tools"
            self.objects[key] = {"id": ("4" if key == "postgres" else "5") * 64}
        if argv[:2] == ["docker", "exec"]:
            return 0, b"1\n"
        if argv[:3] == ["docker", "start", "--attach"]:
            if self.fail_profile:
                return 1, b'private raw DB failure never retained\nADVISORY_PROGRESS={"phase":"serial","event":"work_complete","completed":200,"failed":2}\n'
            return 0, b"private discarded test chatter\n" + raw_report()
        if len(argv) > 2 and argv[0] == "docker" and argv[2] == "rm":
            for key, value in list(self.objects.items()):
                if argv[-1] in (value["id"], self.paths[key]):
                    if key == self.remove_failure:
                        raise d.Stopped("SYNTHETIC_REMOVE_FAILURE")
                    del self.objects[key]
        return 0, b""


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-advisory-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.environment = {**ENV, "RUNNER_TEMP": self.temporary.name}
        self.system = patch.object(d.platform, "system", return_value="Linux")
        self.machine = patch.object(d.platform, "machine", return_value="x86_64")
        self.system.start(); self.machine.start()
        self.addCleanup(self.system.stop); self.addCleanup(self.machine.stop)

    def runner(self):
        return FakeRunner(self.environment)

    def test_fixed_context(self):
        self.assertEqual(d.fixed_context(ENV), ("12345678-1", TOOLING))
        for field, value in {"GITHUB_RUN_ATTEMPT": "2", "GITHUB_REF": "refs/heads/other", "GITHUB_REPOSITORY": "foreign/repo",
                             "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_SHA": "main", "GITHUB_RUN_ID": "../../private"}.items():
            with self.subTest(field=field), self.assertRaises(d.Stopped):
                d.fixed_context({**ENV, field: value})

    def test_native_architecture_required(self):
        with patch.object(d.platform, "machine", return_value="aarch64"), self.assertRaises(d.Stopped):
            self.runner()

    def test_no_secret_inherited_environment(self):
        runner = FakeRunner({**self.environment, "GITHUB_TOKEN": "private", "DOCKER_HOST": "foreign", "PGPASSWORD": "private"})
        self.assertFalse({"GITHUB_TOKEN", "DOCKER_HOST", "PGPASSWORD"} & set(runner.env))

    def test_exact_diff(self):
        valid = "".join("A\t" + p + "\n" for p in (*d.FILES, d.WORKFLOW)).encode()
        d.validate_diff(valid)
        d.validate_diff(valid + b"M\tdocs/implementation/STATUS.md\n")
        for suffix in (b"M\tinternal/quota/store.go\n", b"A\tother.txt\n", b"R100\tx\ty\n", valid[:valid.index(b"\n") + 1]):
            with self.assertRaises(d.Stopped):
                d.validate_diff(valid + suffix)
        with self.assertRaises(d.Stopped):
            d.validate_diff(b"")

    def test_report_accepts_only_closed_schema(self):
        d.validate_profile(profile())
        for field, value in {"source_commit": "b" * 40, "release_evidence": True, "pool_max_connections": 64, "serial_requests": 201,
                             "raw_sql": "private", "advisory_only": 1}.items():
            candidate = profile(); candidate[field] = value
            with self.subTest(field=field), self.assertRaises(d.Stopped):
                d.validate_profile(candidate)

    def test_statement_sensitive_or_non_numeric_rejected(self):
        for field, value in {"query": "private SQL", "query_id": "raw-name", "execution_ms": float("nan"), "wal_bytes": -1, "calls": True}.items():
            candidate = profile(); candidate["server_phases"][0]["statements"][0][field] = value
            with self.subTest(field=field), self.assertRaises(d.Stopped):
                d.validate_profile(candidate)

    def test_query_ids_exact_int64(self):
        for value in ("0", "1", "-9223372036854775808", "9223372036854775807"):
            self.assertTrue(d.numeric_id(value))
        for value in ("01", "-0", "9223372036854775808", "private", True):
            self.assertFalse(d.numeric_id(value))

    def test_counter_and_observation_bounds(self):
        for mutate in (lambda v: v["observations"].extend(v["observations"] * 512),
                       lambda v: v["server_phases"][0]["statements"].extend(v["server_phases"][0]["statements"]),
                       lambda v: v["server_phases"][0].update(stats_reset_or_evicted=True),
                       lambda v: v["server_phases"][0]["workload_cgroup_delta"].update(private=3),
                       lambda v: v["observations"][0].update(label="private raw SQL"),
                       lambda v: v["observations"][0].update(sql_hash="not-a-hash")):
            candidate = profile(); mutate(candidate)
            with self.assertRaises(d.Stopped):
                d.validate_profile(candidate)

    def test_no_multiple_or_missing_report(self):
        self.assertEqual(d.extract_report(b"private\n" + raw_report()), profile())
        for raw in (b"private", raw_report() * 2, b"ADVISORY_SQL_PROFILE={\"private\":1}\n"):
            with self.assertRaises(d.Stopped):
                d.extract_report(raw)

    def test_json_duplicate_nonfinite_and_size_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"n":NaN}', b"x" * (d.MAX_OUTPUT + 1)):
            with self.assertRaises(d.Stopped):
                d.strict_json(raw)

    def test_progress_filters_raw_or_extra_fields(self):
        safe = {"phase": "serial", "event": "work_complete", "completed": 200, "failed": 2}
        raw = b"raw private\nADVISORY_PROGRESS=" + d.canonical(safe) + b"\nADVISORY_PROGRESS=" + d.canonical({**safe, "raw": "private"})
        self.assertEqual(d.extract_progress(raw), [safe])
        self.assertEqual(d.extract_progress(b"ADVISORY_PROGRESS=" + b"x" * 100), [])

    def test_success_one_sample_cleanup_and_no_credentials_argv(self):
        runner = self.runner()
        with patch.object(d.secrets, "token_urlsafe", return_value="synthetic-private-password"), patch("builtins.print"):
            self.assertEqual(runner.run(), 0)
        self.assertEqual(runner.objects, {})
        calls = [command for command, _ in runner.commands]
        self.assertEqual(sum(command[:3] == ["docker", "start", "--attach"] for command in calls), 1)
        self.assertNotIn("synthetic-private-password", json.dumps(calls))
        self.assertTrue(json.loads((runner.root / "cleanup.json").read_text())["cleanup_verified"])
        self.assertFalse((runner.root / "failure.json").exists())
        report = json.loads((runner.root / "report.json").read_text())
        self.assertEqual(report["tooling_commit"], TOOLING)
        self.assertNotIn("private", (runner.root / "report.json").read_text())
        with patch("builtins.print"):
            self.assertEqual(runner.cleanup_only(), 0)

    def test_failure_retains_only_fixed_progress_and_still_cleans(self):
        runner = self.runner(); runner.fail_profile = True
        with patch("builtins.print"):
            self.assertEqual(runner.run(), 2)
        failure = json.loads((runner.root / "failure.json").read_text())
        self.assertEqual(failure["stage"], "profile")
        self.assertEqual(failure["progress"][0]["failed"], 2)
        self.assertNotIn("private", json.dumps(failure))
        self.assertFalse((runner.root / "report.json").exists())
        self.assertEqual(runner.objects, {})

    def test_report_write_failure_still_has_fixed_receipt_and_cleanup(self):
        runner = self.runner()
        original = d.atomic_json
        def fail_report(path, value, **kwargs):
            if path.name == "report.json":
                raise OSError("synthetic raw filesystem message")
            return original(path, value, **kwargs)
        with patch.object(d, "atomic_json", side_effect=fail_report), patch("builtins.print"):
            self.assertEqual(runner.run(), 2)
        self.assertEqual(json.loads((runner.root / "failure.json").read_text())["stage"], "profile")
        self.assertNotIn("filesystem", (runner.root / "failure.json").read_text())
        self.assertEqual(runner.objects, {})

    def test_cleanup_unknown_not_success_but_other_targets_removed(self):
        runner = self.runner(); runner.remove_failure = "tools"
        with patch("builtins.print"):
            self.assertEqual(runner.run(), 2)
        receipt = json.loads((runner.root / "cleanup.json").read_text())
        self.assertFalse(receipt["cleanup_verified"])
        self.assertEqual(receipt["targets"]["tools"], "unresolved")
        self.assertEqual(set(runner.objects), {"tools"})

    def test_changed_identity_is_not_deleted(self):
        runner = self.runner()
        with patch("builtins.print"):
            runner.run()
        runner.objects["postgres"] = {"id": "f" * 64}
        runner.commands.clear()
        self.assertFalse(runner.cleanup())
        self.assertTrue(runner.objects.get("postgres"))
        self.assertFalse(any(c[:3] == ["docker", "container", "rm"] for c, _ in runner.commands))

    def test_ledger_target_forgery_and_symlink_refused(self):
        runner = self.runner()
        with patch("builtins.print"):
            runner.run()
        ledger = runner.root / "ownership.json"
        value = json.loads(ledger.read_text()); value["names"]["postgres"] = "foreign"
        d.atomic_json(ledger, value)
        with self.assertRaises(d.Stopped):
            runner.cleanup_only()
        original = runner.root / "original.json"; ledger.rename(original); ledger.symlink_to(original)
        with self.assertRaises(d.Stopped):
            runner.cleanup_only()

    def test_inspect_absence_requires_independent_empty_exact_inventory(self):
        runner = d.Runner(self.environment)
        with patch.object(runner, "call", side_effect=[(1, b""), (0, b"foreign-id")]), self.assertRaises(d.Stopped):
            runner.inspect("postgres")
        with patch.object(runner, "call", side_effect=[(1, b""), (0, b"")]) as call:
            self.assertIsNone(runner.inspect("postgres"))
        self.assertIn("name=^/lw-amd64-12345678-1-pg$", call.call_args_list[1].args[0])

    def test_inspect_refuses_foreign_labels_and_changed_caps(self):
        runner = d.Runner(self.environment)
        value = {"id": "1" * 64, "labels": {d.LABEL: runner.owner}, "image": d.PG_IMAGE, "running": False,
                 "nano_cpus": 4 * 10**9, "memory": 4 * 1024**3, "swap": 4 * 1024**3, "ports": None,
                 "network": runner.paths["network"], "readonly": False, "privileged": False, "pids_limit": 256}
        with patch.object(runner, "call", return_value=(0, d.canonical(value))):
            self.assertEqual(runner.inspect("postgres")["id"], value["id"])
        for field, replacement in (("labels", {d.LABEL: "foreign"}), ("nano_cpus", 8 * 10**9), ("ports", {"5432": [{"HostPort": "5432"}]}),
                                    ("network", "foreign"), ("privileged", True), ("pids_limit", 0)):
            with patch.object(runner, "call", return_value=(0, d.canonical({**value, field: replacement}))), self.assertRaises(d.Stopped):
                runner.inspect("postgres")

    def test_cli_success_system_exit_is_not_caught(self):
        # Execute the real entrypoint AST, replacing only main's implementation.
        code = "import ast,pathlib; p=pathlib.Path(" + repr(str(Path(d.__file__))) + "); tree=ast.parse(p.read_text()); "
        code += "target=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main'); target.body=[ast.Return(ast.Constant(0))]; "
        code += "ast.fix_missing_locations(tree); exec(compile(tree,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})"
        result = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_bounded_subprocess_suppresses_stderr(self):
        code, raw = d.bounded([sys.executable, "-c", "import sys;sys.stderr.write('private');print('safe')"], timeout=3)
        self.assertEqual((code, raw), (0, b"safe\n"))

    def test_bounded_subprocess_output_and_time_limits(self):
        for code in ("print('x'*10000)", "import time;time.sleep(20)", "import os,time;os.close(1);time.sleep(20)"):
            started = time.monotonic()
            with self.assertRaises(d.Stopped):
                d.bounded([sys.executable, "-c", code], timeout=.1, maximum=100)
            self.assertLess(time.monotonic() - started, 5)

    def test_selector_construction_failure_still_reaps_child(self):
        captured = []
        original = d.subprocess.Popen
        def start(*args, **kwargs):
            child = original(*args, **kwargs); captured.append(child); return child
        with patch.object(d.subprocess, "Popen", side_effect=start), patch.object(d.selectors, "DefaultSelector", side_effect=OSError("private")):
            with self.assertRaisesRegex(d.Stopped, "CHILD_INTERRUPTED"):
                d.bounded([sys.executable, "-c", "import time;time.sleep(20)"], timeout=1)
        self.assertIsNotNone(captured[0].poll())
        self.assertTrue(captured[0].stdout.closed)

    def test_selector_close_failure_fixed_and_child_reaped(self):
        selector = d.selectors.DefaultSelector()
        original = selector.close
        def broken_close():
            original(); raise OSError("private")
        with patch.object(d.selectors, "DefaultSelector", return_value=selector), patch.object(selector, "close", side_effect=broken_close):
            with self.assertRaisesRegex(d.Stopped, "CHILD_CLEANUP_UNCONFIRMED"):
                d.bounded([sys.executable, "-c", "print('safe')"], timeout=2)

    def test_templates_fixed_reset_and_no_raw_query_selection(self):
        directory = Path(d.__file__).parent
        observer = (directory / "advisory_database_test.go.in").read_text()
        self.assertIn("pg_stat_statements(showtext := false)", observer)
        self.assertEqual(observer.count('"SELECT public.pg_stat_statements_reset()"'), 1)
        self.assertIn("LIMIT 513", observer)
        self.assertIn("LIMIT 129", observer)
        docker = (directory / "Dockerfile").read_text()
        self.assertIn("TestAdvisory(ProfilerRedaction|DatabaseOfflineValidation)", docker)
        self.assertNotIn("--privileged", Path(d.__file__).read_text())


if __name__ == "__main__":
    unittest.main()
