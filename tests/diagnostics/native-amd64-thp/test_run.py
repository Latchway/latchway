"""Offline tests only: no Docker daemon, fixture, network, auth or real secrets."""
import copy
import datetime
import hashlib
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


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


d = module("thp_diagnostic", "run.py")
c = module("thp_collector", "collector.py")
TOOLING = "a"*40
ENV = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Latchway/latchway", "GITHUB_EVENT_NAME": "workflow_dispatch",
       "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
       "GITHUB_RUN_ID": "12345678", "GITHUB_SHA": TOOLING}


def load_report():
    start = datetime.datetime(2026, 9, 3, tzinfo=datetime.timezone.utc)
    gates = [{"name": name, "status": "passed", "started_at": start.isoformat().replace("+00:00", "Z"), "duration_ms": 60000, "metrics": {}} for name in d.GATES]
    gates[2]["metrics"] = {"samples": 1000, "p50_overhead_ms": 17}
    gates[2]["status"] = "failed"
    gates[2]["error"] = "synthetic private raw failure must not be retained"
    gates[3]["metrics"] = {"scheduled": 6000, "successful": 6000, "failed": 0, "target_rps": 100, "duration_seconds": 60}
    gates[4]["metrics"] = {"established": 500, "target_concurrency": 500, "premature_completions": 0, "hold_seconds": 60,
                           "plateau_slope_mib_per_minute": -1.5, "rss_samples": [
                               {"At": (start+datetime.timedelta(seconds=i)).isoformat().replace("+00:00", "Z"), "MiB": 200+i}
                               for i in range(61)]}
    return {"schema_version": 1, "kind": "latchway_load_evidence", "commit": d.BASE,
            "complete_suite": False, "load_targets_passed": False, "gates": gates,
            "metadata": {"private": "must not survive"}}


def memory_records():
    start = datetime.datetime(2026, 9, 3, tzinfo=datetime.timezone.utc)
    records = []
    for index, second in enumerate((10, 27, 45)):
        at = start + datetime.timedelta(seconds=second)
        sample = {key: 1 for key in c.FIELDS}
        sample.update(unix_nano=int(at.timestamp()*10**9), sequence=index+1, gogc_percent=100, gomemlimit_bytes=2**63-1)
        records.append({"kind": "process_memory", "at": at.isoformat(), "go_memory": {"status": "ok", "snapshot": sample},
                        "metrics": {"smaps_rollup": {"rss_bytes": 200, "pss_bytes": 190, "anon_huge_pages_bytes": 100},
                                    "status": {"vm_rss_bytes": 200, "rss_anon_bytes": 150, "rss_file_bytes": 50}},
                        "host_thp_controls": {"enabled": "always", "defrag": "madvise", "scan_sleep_millisecs": 10000, "max_ptes_none": 511}})
    return records


class Child:
    returncode = None
    pid = 123456
    def poll(self): return self.returncode
    def wait(self, timeout): self.returncode = 0; return 0


class FakeRunner(d.Runner):
    def __init__(self, environment):
        super().__init__(environment)
        self.objects = {}
        self.commands = []
        self.report = load_report()
        self.failure_key = None
        self.create_error = None
        self.memory = memory_records()
        self.runtime_projection = b"GOGC=100\nGODEBUG=madvdontneed=1,otherflag=0\n\n"
        self.fail_substage = None

    def inspect(self, key, cleanup=False):
        if self.stage == self.fail_substage and not cleanup:
            raise d.n.Stopped("CHILD_FAILED")
        return self.objects.get(key)

    def call(self, argv, **kwargs):
        self.remaining(kwargs.get("cleanup", False))
        if self.stage == self.fail_substage and not kwargs.get("cleanup", False):
            raise d.n.Stopped("CHILD_FAILED")
        self.commands.append((argv, kwargs))
        if argv[:3] == ["git", "rev-parse", "HEAD"]: return 0, (TOOLING+"\n").encode()
        if argv[:3] == ["git", "diff", "--name-status"]:
            return 0, "".join("A\t"+p+"\n" for p in (*d.FILES, *d.n.FILES, d.n.WORKFLOW)).encode()
        if argv[:2] == ["git", "ls-remote"]: return 0, (TOOLING+"\trefs/heads/main\n").encode()
        if argv[:2] == ["git", "clone"]: (Path(argv[-1])/"cmd/latchway").mkdir(parents=True)
        if argv[:2] == ["docker", "info"]: return 0, b'{"cpu":4,"arch":"x86_64","os":"linux"}'
        if argv[:2] == ["docker", "build"]:
            key = next(key for key, name in self.paths.items() if name == argv[argv.index("--tag")+1])
            self.objects[key] = {"id": "sha256:"+hashlib.sha256(key.encode()).hexdigest()}
        if argv[:3] == ["docker", "image", "inspect"]:
            if argv[-1] == d.n.PG_IMAGE: return 0, d.n.canonical({"id": "sha256:"+"b"*64, "os": "linux", "arch": "amd64"})
            return 0, self.runtime_projection
        if argv[:3] == ["docker", "container", "inspect"] and "LATCHWAY_DB_" in argv[-2]:
            return 0, b"matched\n"
        if argv[:3] in (["docker", "network", "create"], ["docker", "volume", "create"]):
            key = next(key for key, name in self.paths.items() if name == argv[-1])
            self.objects[key] = {"id": hashlib.sha256(key.encode()).hexdigest()}
        if argv[:2] == ["docker", "create"]:
            key = next(key for key, name in self.paths.items() if name == argv[argv.index("--name")+1])
            self.objects[key] = {"id": hashlib.sha256(key.encode()).hexdigest()}
            if key == self.create_error: raise d.n.Stopped("SYNTHETIC_AMBIGUOUS_CREATE")
        if argv[:2] == ["docker", "exec"]: return 0, b"100\n" if argv[-1] == "SHOW max_connections" else b"1\n"
        if argv[:3] == ["docker", "start", "--attach"] and argv[-1] in (self.paths["A_tools"], self.paths["B_tools"]):
            arm = "A" if argv[-1] == self.paths["A_tools"] else "B"
            d.n.atomic_json(self.root/"private"/arm/"output/load.json", self.report)
            (self.artifacts/(arm+"-runtime.jsonl")).write_bytes(b"\n".join(d.n.canonical(record) for record in self.memory)+b"\n")
            return 1, b""
        if len(argv) > 2 and argv[0] == "docker" and argv[2] == "rm":
            for key, value in list(self.objects.items()):
                if argv[-1] in (value["id"], self.paths[key]):
                    if key == self.failure_key: raise d.n.Stopped("SYNTHETIC_REMOVE_FAILED")
                    del self.objects[key]
        return 0, b""


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.environment = {**ENV, "RUNNER_TEMP": self.temp.name}
        self.platform = patch.multiple(d.n.platform, system=lambda: "Linux", machine=lambda: "x86_64")
        self.platform.start(); self.addCleanup(self.platform.stop)

    def runner(self, cls=FakeRunner):
        runner = cls(self.environment)
        self.addCleanup(runner.unlock)
        return runner

    def execute(self, runner):
        with patch.object(d.subprocess, "Popen", side_effect=lambda *a, **k: Child()), patch.object(d, "stop_child", return_value=True), patch.object(d.time, "sleep"):
            return runner.run()

    def initialized(self, runner):
        runner.root.mkdir(mode=0o700); runner.artifacts.mkdir(mode=0o700)
        runner.ledger = {"schema_version": 1, "owner": runner.owner, "source_commit": d.BASE, "tooling_commit": TOOLING,
                         "names": runner.paths, "t0_wall": time.time(), "t0_mono": time.monotonic(), "absent_before": [], "intents": [], "ids": {},
                         "postgres_image_id": None, "collectors": {"A": "not_started", "B": "not_started"}}
        runner.lock(create=True); runner.save()

    def test_complete_pair_preserves_workloads_and_environment_and_does_not_claim_release(self):
        runner = self.runner()
        self.assertEqual(self.execute(runner), 0)
        self.assertFalse(runner.objects)
        manifest = d.private_json(runner.artifacts/"manifest.json")
        self.assertFalse(manifest["release_evidence"])
        self.assertTrue(manifest["cleanup_verified"])
        self.assertTrue(manifest["workload_pair_complete"])
        self.assertTrue(manifest["memory_comparison_complete"])
        self.assertEqual(set(manifest["overlays_sha256"]), {Path(p).name for p in d.FILES})
        creates = [item for item in runner.commands if item[0][:2] == ["docker", "create"]]
        gateway = [item for item in creates if item[0][item[0].index("--name")+1] in (runner.paths["A_gateway"], runner.paths["B_gateway"])]
        a, b = (item[1]["env"].copy() for item in gateway)
        self.assertEqual(b.pop("GODEBUG"), "madvdontneed=1,otherflag=0,disablethp=1")
        self.assertEqual(a, b)
        self.assertEqual(a["LATCHWAY_DB_MAX_CONNECTIONS"], str(d.DB_POOL_MAX_CONNECTIONS))
        self.assertEqual(a["LATCHWAY_DB_COMPLETION_CONNECTIONS"], str(d.DB_COMPLETION_POOL_MAX_CONNECTIONS))
        self.assertEqual(
            d.DB_REGULAR_POOL_MAX_CONNECTIONS + d.DB_COMPLETION_POOL_MAX_CONNECTIONS,
            d.DB_POOL_MAX_CONNECTIONS,
        )
        self.assertEqual(gateway[0][0][-1], gateway[1][0][-1])
        for argv, kwargs in creates:
            for key, value in kwargs.get("env", {}).items():
                if key in ("LATCHWAY_MASTER_KEY", "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN", "POSTGRES_PASSWORD", "LATCHWAY_DATABASE_URL"):
                    self.assertNotIn(value, " ".join(argv))
        loads = [argv for argv, _ in creates if "/tools/latchway-load" in argv]
        self.assertEqual(len(loads), 2)
        self.assertTrue(all(argv[-1] == d.MODE for argv in loads))
        provisioners = [argv for argv, _ in creates if "/tools/latchway-load-provision" in argv]
        self.assertEqual(len(provisioners), 2)
        for argv in provisioners:
            self.assertEqual(argv[argv.index("-gateway-db-pool-max-connections") + 1], "32")
            self.assertEqual(argv[argv.index("-gateway-db-regular-pool-max-connections") + 1], "24")
            self.assertEqual(argv[argv.index("-gateway-db-completion-pool-max-connections") + 1], "8")
        for path in runner.artifacts.iterdir():
            content = path.read_text()
            self.assertNotIn("synthetic private raw failure", content)
            self.assertNotIn("must not survive", content)
        self.assertEqual(d.private_json(runner.artifacts/"A-load.json")["gates"][2]["status"], "failed")
        environment = d.private_json(runner.artifacts/"A-environment.json")
        self.assertEqual(environment["gateway_pool_max_connections"], 32)
        self.assertEqual(environment["gateway_regular_pool_max_connections"], 24)
        self.assertEqual(environment["gateway_completion_pool_max_connections"], 8)
        pool_inspections = [
            argv
            for argv, _ in runner.commands
            if argv[:3] == ["docker", "container", "inspect"]
            and "LATCHWAY_DB_" in argv[-2]
        ]
        self.assertEqual(len(pool_inspections), 4)

    def test_only_one_attempt_after_ambiguous_create_and_owned_target_cleaned(self):
        runner = self.runner(); runner.create_error = "A_gateway"
        self.assertEqual(self.execute(runner), 2)
        self.assertFalse(runner.objects)
        names = [argv[argv.index("--name")+1] for argv, _ in runner.commands if argv[:2] == ["docker", "create"]]
        self.assertEqual(names.count(runner.paths["A_gateway"]), 1)
        self.assertNotIn(runner.paths["B_gateway"], names)

    def test_preexisting_target_is_never_adopted_or_deleted(self):
        runner = self.runner(); runner.objects["gateway_image"] = {"id": "f"*64}
        self.assertEqual(self.execute(runner), 2)
        self.assertIn("gateway_image", runner.objects)
        self.assertNotIn("gateway_image", runner.ledger["intents"])

    def test_cleanup_failure_is_explicit_and_blocks_second_arm(self):
        runner = self.runner(); runner.failure_key = "A_gateway"
        self.assertEqual(self.execute(runner), 2)
        manifest = d.private_json(runner.artifacts/"manifest.json")
        self.assertFalse(manifest["cleanup_verified"])
        self.assertNotIn("B_gateway", runner.ledger["intents"])

    def test_exact_resource_names_survive_restart_without_clock_derived_targets(self):
        first = self.runner(); second = self.runner()
        self.assertEqual(first.paths, second.paths)
        self.initialized(first); first.unlock()
        self.assertEqual(second.cleanup_only(), 0)

    def test_cleanup_lock_refuses_live_producer(self):
        first = self.runner(); self.initialized(first)
        with self.assertRaises(d.n.Stopped): self.runner().cleanup_only()

    def test_cleanup_rejects_scope_or_future_clock_changes(self):
        runner = self.runner(); self.initialized(runner)
        baseline = copy.deepcopy(runner.ledger); runner.unlock()
        changes = (("owner", "other"), ("source_commit", "f"*40), ("t0_wall", time.time()+600), ("t0_mono", time.monotonic()+600), ("names", {}), ("intents", ["unknown"]))
        for key, value in changes:
            with self.subTest(key=key):
                ledger = copy.deepcopy(baseline); ledger[key] = value
                d.n.atomic_json(runner.root/"ownership.json", ledger)
                other = self.runner()
                with self.assertRaises(d.n.Stopped): other.cleanup_only()
                other.unlock()

    def test_restart_unknown_collector_does_not_guess_pid_or_claim_complete(self):
        runner = self.runner(); self.initialized(runner)
        runner.ledger["collectors"]["A"] = "started_or_unknown"; runner.save(); runner.unlock()
        with patch.object(d.os, "killpg") as kill:
            self.assertEqual(self.runner().cleanup_only(), 2)
            kill.assert_not_called()

    def test_stop_file_failure_cannot_skip_child_stop(self):
        runner = self.runner()
        with patch.object(Path, "touch", side_effect=OSError("private failure")):
            self.assertEqual(self.execute(runner), 0)
        self.assertEqual(runner.ledger["collectors"], {"A": "stopped", "B": "stopped"})

    def test_failed_collector_start_remains_unknown_but_containers_are_removed(self):
        runner = self.runner()
        with patch.object(d.subprocess, "Popen", side_effect=OSError("private failure")), patch.object(d.time, "sleep"):
            self.assertEqual(runner.run(), 2)
        self.assertFalse(runner.objects)
        self.assertEqual(runner.ledger["collectors"]["A"], "started_or_unknown")

    def test_global_wall_and_monotonic_deadline_and_cleanup_reserve(self):
        runner = self.runner(); self.initialized(runner)
        wall, mono = runner.ledger["t0_wall"], runner.ledger["t0_mono"]
        for forward in ("wall", "mono"):
            with self.subTest(clock=forward), patch.object(d.time, "time", return_value=wall+(1381 if forward == "wall" else 1)), patch.object(d.time, "monotonic", return_value=mono+(1381 if forward == "mono" else 1)):
                with self.assertRaises(d.n.Stopped): runner.remaining()
                self.assertGreater(runner.remaining(cleanup=True), 100)
        with patch.object(d.time, "time", return_value=wall+1496):
            with self.assertRaises(d.n.Stopped): runner.remaining(cleanup=True)

    def test_report_redaction_signed_slope_and_malformed_metrics(self):
        value = d.sanitized_load(load_report())
        self.assertEqual(value["gates"][-1]["metrics"]["plateau_slope_mib_per_minute"], -1.5)
        for key, bad in (("complete_suite", True), ("load_targets_passed", True), ("commit", "f"*40)):
            candidate = load_report(); candidate[key] = bad
            with self.assertRaises(d.n.Stopped): d.sanitized_load(candidate)
        for bad in ("private", True, float("nan"), float("inf")):
            candidate = load_report(); candidate["gates"][-1]["metrics"]["plateau_slope_mib_per_minute"] = bad
            with self.assertRaises(d.n.Stopped): d.sanitized_load(candidate)

    def test_incomplete_workload_or_held_interval_stops_pair(self):
        for change in ("scheduled", "held", "times"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                runner = FakeRunner({**self.environment, "RUNNER_TEMP": directory})
                self.addCleanup(runner.unlock)
                if change == "scheduled": runner.report["gates"][3]["metrics"]["scheduled"] = 5999
                elif change == "held": runner.report["gates"][-1]["metrics"]["established"] = 499
                else: runner.report["gates"][-1]["metrics"]["rss_samples"][-1]["At"] = "2026-09-03T00:00:01Z"
                self.assertEqual(self.execute(runner), 2)
                self.assertNotIn("B_gateway", runner.ledger["intents"])

    def test_debug_preservation_and_meaningful_baseline(self):
        self.assertEqual(d.merge_disable_thp(""), "disablethp=1")
        self.assertEqual(d.merge_disable_thp("a=1,disablethp=0,b=2"), "a=1,b=2,disablethp=1")
        for bad in ("disablethp=1", "a", "a=1,", "a=x\nTOKEN", "a=", "a=x=y"):
            with self.assertRaises(d.n.Stopped): d.merge_disable_thp(bad)

    def test_runtime_projection_accepts_actual_docker_empty_and_entry_newlines(self):
        for raw in (b"", b"\n", b"\n\n"):
            self.assertEqual(d.parse_runtime_environment(raw), {})
        self.assertEqual(d.parse_runtime_environment(b"GOGC=100\n\n"), {"GOGC": "100"})
        self.assertEqual(d.parse_runtime_environment(b"GODEBUG=a=1,b=2\nGOGC=100\nGOMEMLIMIT=2GiB\nGOMAXPROCS=2\n\n"),
                         {"GODEBUG": "a=1,b=2", "GOGC": "100", "GOMEMLIMIT": "2GiB", "GOMAXPROCS": "2"})
        self.assertEqual(d.parse_runtime_environment(b"GODEBUG=\n\n"), {"GODEBUG": ""})
        self.assertEqual(d.parse_runtime_environment(b"GOGC=100 \n\n"), {"GOGC": "100 "})
        self.assertEqual(d.parse_runtime_environment(b"GODEBUG="+b"x"*4096+b"\n\n"), {"GODEBUG": "x"*4096})

    def test_runtime_projection_rejects_duplicate_unknown_nonascii_or_malformed_lines(self):
        for raw in (b"GOGC=100\nGOGC=100\n\n", b"GOGC=100\n\nGOGC=50\n", b"PRIVATE=value\n", b"GOGC\n", b" \n", b"\t\n",
                    b"GOGC=100\r\n", b"GOGC=100\x00\n", b"GOGC=\xff\n", b"GODEBUG="+b"x"*4097+b"\n\n", b"\n"*8193, "GOGC=100"):
            with self.subTest(raw_type=type(raw).__name__, size=len(raw)), self.assertRaises(d.n.Stopped) as raised:
                d.parse_runtime_environment(raw)
            self.assertEqual(raised.exception.args, ("RUNTIME_ENV_SHAPE",))

    def test_empty_runtime_environment_now_completes_fake_pair(self):
        runner = self.runner(); runner.runtime_projection = b"\n"
        self.assertEqual(self.execute(runner), 0)
        self.assertEqual(runner.baseline_debug, "")
        self.assertEqual(runner.disabled_debug, "disablethp=1")

    def test_failure_receipt_only_allows_closed_stage_and_stopped_reason_enums(self):
        accepted = d.failure_receipt("runtime_environment_parse", d.n.Stopped("RUNTIME_ENV_SHAPE"))
        self.assertEqual(accepted["stage"], "runtime_environment_parse")
        self.assertEqual(accepted["reason"], "RUNTIME_ENV_SHAPE")
        for error in (ValueError("private payload"), d.n.Stopped("private payload"), d.n.Stopped("CHILD_FAILED", "private"),
                      RuntimeError("CHILD_FAILED"), d.n.Stopped({"private": "value"})):
            receipt = d.failure_receipt("private stage", error)
            self.assertEqual(receipt["stage"], "unclassified")
            self.assertEqual(receipt["reason"], "UNCLASSIFIED_REDACTED")
            self.assertNotIn("private", json.dumps(receipt))

    def test_source_failure_substages_survive_without_raw_dependency_output(self):
        for stage in ("source_identity", "native_host", "source_clone", "gateway_image_build", "gateway_image_validate", "tools_image_build",
                      "tools_image_validate", "postgres_image_pull", "postgres_image_validate", "runtime_environment_inspect"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                runner = FakeRunner({**self.environment, "RUNNER_TEMP": directory}); runner.fail_substage = stage
                try:
                    self.assertEqual(self.execute(runner), 2)
                    failure = d.private_json(runner.artifacts/"failure.json")
                    self.assertEqual((failure["stage"], failure["reason"]), (stage, "CHILD_FAILED"))
                finally:
                    runner.unlock()
        runner = self.runner(); runner.runtime_projection = b"UNKNOWN=private\n"
        self.assertEqual(self.execute(runner), 2)
        failure = d.private_json(runner.artifacts/"failure.json")
        self.assertEqual((failure["stage"], failure["reason"]), ("runtime_environment_parse", "RUNTIME_ENV_SHAPE"))
        self.assertNotIn("private", json.dumps(failure))

    def test_source_allowlist_excludes_any_product_or_policy_edit(self):
        raw = "".join("A\t"+p+"\n" for p in (*d.FILES, *d.n.FILES, d.n.WORKFLOW)).encode()
        d.validate_source_diff(raw)
        for extra in (b"M\tinternal/quota/store.go\n", b"M\tDockerfile\n", b"A\t.github/workflows/release.yml\n", raw):
            with self.assertRaises(d.n.Stopped): d.validate_source_diff(raw+extra)

    def test_missing_memory_is_inconclusive_not_a_workload_failure_or_success(self):
        runner = self.runner(); runner.memory = []
        self.assertEqual(self.execute(runner), 2)
        manifest = d.private_json(runner.artifacts/"manifest.json")
        self.assertTrue(manifest["workload_pair_complete"])
        self.assertFalse(manifest["memory_comparison_complete"])
        self.assertTrue(manifest["cleanup_verified"])

    def test_memory_requires_fresh_distinct_both_os_and_go_with_stable_controls(self):
        path = Path(self.temp.name)/"runtime.jsonl"
        samples = load_report()["gates"][-1]["metrics"]["rss_samples"]
        for change in ("stale", "os_missing", "controls", "repeat", "short", "runtime_change", "malformed"):
            with self.subTest(change=change):
                records = memory_records()
                if change == "stale": records[1]["go_memory"]["snapshot"]["unix_nano"] -= 11*10**9
                if change == "os_missing": del records[1]["metrics"]["smaps_rollup"]["anon_huge_pages_bytes"]
                if change == "controls": records[1]["host_thp_controls"]["enabled"] = "never"
                if change == "repeat": records[1]["go_memory"]["snapshot"]["sequence"] = 1
                if change == "short": records = records[:2]
                if change == "runtime_change": records[1]["go_memory"]["snapshot"]["gogc_percent"] = 50
                if change == "malformed": records[1]["go_memory"]["snapshot"]["heap_objects_bytes"] = "private"
                path.write_bytes(b"\n".join(d.n.canonical(record) for record in records)+b"\n")
                self.assertFalse(d.memory_observation(path, samples)["complete"])
        path.write_bytes(b"\n".join(d.n.canonical(record) for record in memory_records())+b"\n")
        result = d.memory_observation(path, samples)
        self.assertTrue(result["complete"]); self.assertEqual(result["span_seconds"], 35)

    def test_scope_inspector_rejects_foreign_label_changed_caps_or_cmd(self):
        runner = self.runner(d.Runner); self.initialized(runner)
        value = {"id": "sha256:"+"c"*64, "labels": {d.LABEL: runner.owner, d.LABEL+".target": "gateway_image", "org.opencontainers.image.revision": d.BASE},
                 "arch": "amd64", "os": "linux", "cmd": ["serve", "--role", "all"], "entrypoint": ["/latchway"], "user": "65532:65532"}
        with patch.object(runner, "call", return_value=(0, d.n.canonical(value))): self.assertIsNotNone(runner.inspect("gateway_image"))
        for key, wrong in (("cmd", ["serve"]), ("arch", "arm64"), ("labels", {})):
            candidate = copy.deepcopy(value); candidate[key] = wrong
            with patch.object(runner, "call", return_value=(0, d.n.canonical(candidate))), self.assertRaises(d.n.Stopped): runner.inspect("gateway_image")
        runner.ledger["ids"]["gateway_image"] = value["id"]
        container = {"id": "c"*64, "labels": {d.LABEL: runner.owner, d.LABEL+".target": "A_gateway"}, "image": value["id"],
                     "network": runner.paths["A_network"], "pid_mode": "", "cpu": 2*10**9, "memory": 2*1024**3, "swap": 2*1024**3,
                     "pids": 4096, "ports": None, "privileged": False, "readonly": True, "user": "65532:65532"}
        with patch.object(runner, "call", return_value=(0, d.n.canonical(container))): self.assertIsNotNone(runner.inspect("A_gateway"))
        for key, wrong in (("cpu", 3*10**9), ("memory", 4*1024**3), ("network", "host"), ("privileged", True), ("image", "sha256:"+"f"*64)):
            candidate = copy.deepcopy(container); candidate[key] = wrong
            with patch.object(runner, "call", return_value=(0, d.n.canonical(candidate))), self.assertRaises(d.n.Stopped): runner.inspect("A_gateway")

    def test_no_cleanup_after_identity_replacement_or_unconfirmed_absence(self):
        runner = self.runner(); self.initialized(runner)
        runner.ledger["intents"] = runner.ledger["absent_before"] = ["gateway_image"]
        runner.ledger["ids"]["gateway_image"] = "a"*64; runner.objects["gateway_image"] = {"id": "b"*64}
        self.assertFalse(runner.cleanup())
        self.assertIn("gateway_image", runner.objects)
        real = self.runner(d.Runner); real.ledger = runner.ledger
        with patch.object(real, "call", side_effect=[(1, b""), (0, b"existing")]), self.assertRaises(d.n.Stopped): real.inspect("gateway_image")

    def test_real_cli_default_is_offline_redacted_and_nonzero(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("run.py"))], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'{"status":"ADVISORY_STOPPED_REDACTED"}\n')
        self.assertEqual(result.stderr, b"")

    def test_main_success_not_caught_as_failure_and_unlocks(self):
        runner = self.runner()
        with patch.object(d.sys, "argv", ["run.py", "--run"]), patch.object(d, "Runner", return_value=runner), patch.object(runner, "run", return_value=0), patch.object(d.resource, "setrlimit"), patch.object(d.signal, "signal"), patch.object(runner, "unlock") as unlock:
            self.assertEqual(d.main(), 0); unlock.assert_called_once()

    def test_cleanup_child_escalates_only_its_group_and_reports_unknown_on_reap_failure(self):
        child = Child()
        with patch.object(child, "wait", side_effect=[subprocess.TimeoutExpired("synthetic", 2), 0]) as wait, patch.object(child, "poll", side_effect=[None, 0]), patch.object(d.os, "killpg") as kill:
            self.assertTrue(d.stop_child(child))
            self.assertEqual([call.args for call in kill.call_args_list], [(child.pid, d.signal.SIGTERM), (child.pid, d.signal.SIGKILL)])
            self.assertTrue(all(call.kwargs == {"timeout": 2} for call in wait.call_args_list))
        with patch.object(child, "wait", side_effect=subprocess.TimeoutExpired("synthetic", 2)), patch.object(child, "poll", return_value=None), patch.object(d.os, "killpg"):
            self.assertFalse(d.stop_child(child))

    def test_partial_failure_receipt_is_fixed_and_cleanup_survives_report_write_failure(self):
        runner = self.runner()
        atomic = d.n.atomic_json
        def write(path, value, **kwargs):
            if path.name == "A-load.json": raise OSError("synthetic private path or payload")
            return atomic(path, value, **kwargs)
        with patch.object(d.n, "atomic_json", side_effect=write): self.assertEqual(self.execute(runner), 2)
        self.assertFalse(runner.objects)
        failure = d.private_json(runner.artifacts/"failure.json")
        self.assertEqual(failure["stage"], "A_load")
        self.assertNotIn("synthetic", json.dumps(failure))

    def test_private_reports_refuse_symlink_and_size_overflow(self):
        target = Path(self.temp.name)/"target"
        target.write_bytes(b"{}")
        link = Path(self.temp.name)/"link"; link.symlink_to(target)
        with self.assertRaises(OSError): d.private_json(link)
        with self.assertRaises(d.n.Stopped): d.private_json(target, 1)


class CollectorTests(unittest.TestCase):
    def snapshot(self):
        value = {key: 1 for key in c.FIELDS}
        value.update(unix_nano=time.time_ns(), gomemlimit_bytes=2**63-1)
        return value

    def test_valid_snapshot_and_staleness_are_not_zero(self):
        value = self.snapshot()
        self.assertEqual(c.snapshot(d.n.canonical(value), value["unix_nano"])["status"], "ok")
        for now in (value["unix_nano"]+10**10+1, value["unix_nano"]-10**9-1):
            self.assertEqual(c.snapshot(d.n.canonical(value), now), {"status": "stale_or_clock_skew"})

    def test_malicious_missing_duplicate_and_nonfinite_data_are_discarded(self):
        value = self.snapshot()
        for raw in (b"x"*4097, b'{"schema":1,"schema":1}', b"[]", b'{"private":"secret"}', d.n.canonical({**value, "heap_objects_bytes": "secret"}),
                    d.n.canonical({**value, "sequence": 181}), d.n.canonical({**value, "schema": True}), d.n.canonical({**value, "raw_path": 1}), b'{"schema":NaN}'):
            result = c.snapshot(raw, value["unix_nano"])
            self.assertEqual(result, {"status": "invalid_response"})
            self.assertNotIn("secret", json.dumps(result))

    def test_snapshot_request_is_bounded_exact_same_uid_and_no_privilege(self):
        value = self.snapshot()
        with patch.object(c, "original", return_value={"kind": "process_memory"}), patch.object(c.base, "capture", return_value=("ok", d.n.canonical(value))) as capture:
            self.assertEqual(c.process_memory_sample("exact-tools")["go_memory"]["status"], "ok")
            argv = capture.call_args.args[0]
            self.assertEqual(argv, ["docker", "exec", "--user", "65532:65532", "exact-tools", "timeout", "-s", "KILL", "2", "cat", "/proc/1/root/tmp/latchway-advisory-memory.json"])
            self.assertEqual(capture.call_args.kwargs, {"limit": 4096, "timeout": 3})
        with patch.object(c, "original", return_value={}), patch.object(c.base, "capture", return_value=("failed", b"private")):
            self.assertEqual(c.process_memory_sample("exact-tools")["go_memory"], {"status": "unavailable"})

    def test_absolute_collector_deadline_required_and_bounded(self):
        now = time.time_ns()
        for extra in ([], ["--advisory-deadline-unix-ns", str(now-1)], ["--advisory-deadline-unix-ns", str(now+1501*10**9)], ["--advisory-deadline-unix-ns", "private"]):
            with patch.object(c.sys, "argv", ["collector.py", *extra]), patch.object(c.time, "time_ns", return_value=now), patch.object(c.base, "main") as main:
                self.assertEqual(c.main(), 2); main.assert_not_called()
        with patch.object(c.sys, "argv", ["collector.py", "--advisory-deadline-unix-ns", str(now+100*10**9)]), patch.object(c.time, "time_ns", return_value=now), patch.object(c.base, "collect") as collect:
            with patch.object(c.base, "main", side_effect=lambda: c.base.collect()): c.main()
            self.assertEqual(collect.call_args.kwargs["maximum_seconds"], 100)


if __name__ == "__main__":
    unittest.main()
