#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("load_runtime_diagnostics", ROOT / "scripts/load-runtime-diagnostics.py")
DIAGNOSTICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTICS)
SECRET = "sentinel-private-value"
POSTGRES = "latchway-load-postgres-1234-20260903060000"
GATEWAY = "latchway-load-gateway-1234-20260903060000"
TOOLS_RUNNER = "latchway-load-runner-1234-20260903060000"


def activity():
    return {"database": {name: 0 for name in DIAGNOSTICS.DATABASE_FIELDS}, "waits": []}


def lifecycle():
    return {name: [] for name in DIAGNOSTICS.ROW_SCHEMAS if name != "waits"}


class CaptureTests(unittest.TestCase):
    def test_output_has_a_real_byte_bound(self):
        status, data = DIAGNOSTICS.capture(
            [sys.executable, "-c", "import sys;sys.stdout.write('x'*1000000)"], limit=1024,
        )
        self.assertEqual(status, "truncated")
        self.assertEqual(len(data), 1024)

    def test_hung_process_has_a_real_time_bound(self):
        started = time.monotonic()
        status, data = DIAGNOSTICS.capture(
            [sys.executable, "-c", "import time;time.sleep(10)"], timeout=0.1,
        )
        self.assertEqual(status, "timeout")
        self.assertEqual(data, b"")
        self.assertLess(time.monotonic()-started, 2)

    def test_nonzero_command_does_not_become_a_successful_capture(self):
        status, _ = DIAGNOSTICS.capture([sys.executable, "-c", "raise SystemExit(7)"])
        self.assertEqual(status, "failed")

    def test_missing_command_returns_only_fixed_status(self):
        status, data = DIAGNOSTICS.capture(["/nonexistent/" + SECRET])
        self.assertEqual((status, data), ("unavailable", b""))

    def test_killed_child_reaping_is_also_bounded(self):
        read_descriptor, write_descriptor = os.pipe()
        os.close(write_descriptor)
        class StalledProcess:
            def __init__(self):
                self.stdout = os.fdopen(read_descriptor, "rb")
                self.wait_timeouts = []
                self.killed = False
            def poll(self):
                return None
            def kill(self):
                self.killed = True
            def wait(self, *, timeout):
                self.wait_timeouts.append(timeout)
                raise subprocess.TimeoutExpired(SECRET, timeout)
        process = StalledProcess()
        with patch.object(DIAGNOSTICS.subprocess, "Popen", return_value=process):
            status, output = DIAGNOSTICS.capture(["unused"])
        self.assertEqual(status, "reap_timeout")
        self.assertEqual(output, b"")
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_timeouts[-1], 1)
        self.assertTrue(all(0 < timeout <= 3 for timeout in process.wait_timeouts))


class DatabaseTests(unittest.TestCase):
    def test_both_queries_are_select_only_aggregates(self):
        for query in (DIAGNOSTICS.ACTIVITY_SQL, DIAGNOSTICS.LIFECYCLE_SQL):
            self.assertTrue(query.strip().startswith("SELECT json_build_object("))
            self.assertEqual(query.count(";"), 1)
            self.assertNotRegex(query, r"\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|CREATE)\b")
            self.assertNotRegex(query, r"\b(?:query|application_name|client_addr|usename|logical_request_id|session_grant_id)\b")
        self.assertIn("pid<>pg_backend_pid()", DIAGNOSTICS.ACTIVITY_SQL)

    def test_password_is_environment_only_and_caller_is_unchanged(self):
        with patch.dict(os.environ, {"POSTGRES_PASSWORD": SECRET, "PGPASSWORD": "existing-caller-password"}):
            with patch.object(DIAGNOSTICS, "capture", return_value=("ok", json.dumps(activity()).encode())) as captured:
                result = DIAGNOSTICS.database_sample(POSTGRES)
                self.assertEqual(os.environ["PGPASSWORD"], "existing-caller-password")
        arguments = captured.call_args.args[0]
        self.assertNotIn(SECRET, " ".join(arguments))
        self.assertEqual(captured.call_args.kwargs["environment"]["PGPASSWORD"], SECRET)
        self.assertIn("PGPASSWORD", arguments)
        self.assertIn("PGCONNECT_TIMEOUT=2", arguments)
        self.assertIn("PGOPTIONS=-c statement_timeout=500 -c default_transaction_read_only=on", arguments)
        for value in ("127.0.0.1", "--no-password", "--no-psqlrc", "ON_ERROR_STOP=1"):
            self.assertIn(value, arguments)
        self.assertEqual(result["status"], "ok")
        self.assertNotIn(SECRET, json.dumps(result))

    def test_failures_discard_raw_errors(self):
        for status in ("failed", "timeout", "truncated", "unavailable"):
            with patch.object(DIAGNOSTICS, "capture", return_value=(status, SECRET.encode())):
                result = DIAGNOSTICS.database_sample(POSTGRES)
            self.assertEqual(result["status"], status)
            self.assertNotIn("metrics", result)
            self.assertNotIn(SECRET, json.dumps(result))

    def test_invalid_success_response_has_only_fixed_error(self):
        for data in (SECRET.encode(), b"null", b"[]", b"{}", b'{"database":null}'):
            with patch.object(DIAGNOSTICS, "capture", return_value=("ok", data)):
                result = DIAGNOSTICS.database_sample(POSTGRES)
            self.assertEqual(result["status"], "invalid_response")
            self.assertNotIn(SECRET, json.dumps(result))

    def test_unknown_fields_labels_and_non_numeric_metrics_never_escape(self):
        value = activity()
        value[SECRET] = SECRET
        value["database"]["connections"] = SECRET
        value["database"]["commits"] = True
        value["database"]["rollbacks"] = -1
        value["database"]["temp_bytes"] = 2**100
        value["waits"] = [{"state": SECRET, "wait_type": SECRET, "wait_event": SECRET,
                           "connections": SECRET, "blocked": 2, "maximum_active_ms": 120,
                           "query": SECRET, "parameters": SECRET}]
        clean = DIAGNOSTICS.sanitize_metrics(value, lifecycle=False)
        self.assertNotIn(SECRET, json.dumps(clean))
        self.assertEqual(clean["waits"][0]["state"], "other")
        self.assertEqual(clean["waits"][0]["blocked"], 2)
        for field in ("connections", "commits", "rollbacks", "temp_bytes"):
            self.assertIsNone(clean["database"][field])

    def test_lifecycle_keeps_counts_but_never_identifiers(self):
        value = lifecycle()
        value["logical_requests"] = [{"status": "failed", "failure_code": "server_not_ready", "count": 42,
                                      "logical_request_id": SECRET}]
        value["reservations"] = [{"status": "pending", "count": 2, "oldest_pending_ms": 1250}]
        value["attempts"] = [{"status": "started", "first_byte": SECRET, "count": 2}]
        value["decision_failures"] = [{"stage": "quota_reserved", "outcome": "failed", "failure_code": SECRET, "count": 3}]
        clean = DIAGNOSTICS.sanitize_metrics(value, lifecycle=True)
        self.assertNotIn(SECRET, json.dumps(clean))
        self.assertEqual(clean["logical_requests"][0]["count"], 42)
        self.assertIsNone(clean["attempts"][0]["first_byte"])
        self.assertEqual(clean["decision_failures"][0]["failure_code"], "other")

    def test_oversized_row_inventory_is_rejected(self):
        value = activity()
        value["waits"] = [{}] * (DIAGNOSTICS.MAXIMUM_ROWS + 1)
        with self.assertRaises(ValueError):
            DIAGNOSTICS.sanitize_metrics(value, lifecycle=False)


class ResourceTests(unittest.TestCase):
    def test_container_capture_is_exactly_scoped_and_sanitized(self):
        rows = [
            {"name": POSTGRES, "cpu": "12.50%", "memory": "100MiB / 4GiB", "block_io": "1MB / 2MB", "pids": "32", "secret": SECRET},
            {"name": GATEWAY, "cpu": SECRET, "memory": SECRET, "block_io": SECRET, "pids": SECRET},
            {"name": SECRET, "cpu": "100%"},
        ]
        with patch.object(DIAGNOSTICS, "pressure_snapshot", return_value={}):
            with patch.object(DIAGNOSTICS, "capture", return_value=("ok", b"\n".join(json.dumps(row).encode() for row in rows))) as captured:
                result = DIAGNOSTICS.resource_sample(POSTGRES, GATEWAY)
        self.assertEqual(captured.call_args.args[0][-2:], [POSTGRES, GATEWAY])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(POSTGRES, json.dumps(result))
        self.assertEqual(set(result["containers"]), {"postgres", "gateway"})
        self.assertEqual(result["containers"]["postgres"]["cpu_percent"], 12.5)
        self.assertEqual(result["containers"]["postgres"]["memory_limit_bytes_approximate"], 4*1024**3)
        self.assertEqual(result["containers"]["postgres"]["block_write_bytes_approximate"], 2000000)
        self.assertIsNone(result["containers"]["gateway"]["cpu_percent"])

    def test_invalid_container_json_does_not_echo_dependency_contents(self):
        for data in (SECRET.encode(), b"null", b'{"name":[]}', b'{"name":"'+POSTGRES.encode()+b'","memory":null}'):
            with patch.object(DIAGNOSTICS, "pressure_snapshot", return_value={}):
                with patch.object(DIAGNOSTICS, "capture", return_value=("ok", data)):
                    result = DIAGNOSTICS.resource_sample(POSTGRES, GATEWAY)
            self.assertEqual(result["docker_status"], "invalid_response")
            self.assertNotIn(SECRET, json.dumps(result))

    def test_quantities_are_bounded_numeric_only(self):
        self.assertEqual(DIAGNOSTICS.byte_quantity("1.5MiB"), 1572864)
        for value in (None, SECRET, "-1B", "NaNB", "1e30B", "9"*1000+"TB"):
            self.assertIsNone(DIAGNOSTICS.byte_quantity(value))

    def test_pressure_has_fixed_fields_and_numeric_values(self):
        payload = b"some avg10=1.25 avg60=2.00 avg300=3.00 total=123\n" + SECRET.encode() + b"\nfull avg10=900 avg60=2 avg300=3 total=2\n"
        with patch.object(Path, "open", side_effect=lambda *args, **kwargs: io.BytesIO(payload)):
            result = DIAGNOSTICS.pressure_snapshot()
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["cpu"]["some"]["avg10"], 1.25)
        self.assertNotIn("full", result["cpu"])

    def test_host_metadata_does_not_echo_unknown_docker_fields(self):
        payload = json.dumps({"cpu_count": SECRET, "memory_bytes": 1234, "architecture": SECRET,
                              "hostname": SECRET, "environment": SECRET}).encode()
        with patch.object(DIAGNOSTICS, "cpu_model", return_value="Intel(R) Xeon(R)"):
            with patch.object(DIAGNOSTICS, "capture", return_value=("ok", payload)):
                result = DIAGNOSTICS.host_metadata(32, 24, 8)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["gateway_pool_max_connections"], 32)
        self.assertEqual(result["gateway_regular_pool_max_connections"], 24)
        self.assertEqual(result["gateway_completion_pool_max_connections"], 8)
        self.assertTrue(result["backend_count_is_not_pool_waiter_count"])
        self.assertEqual(result["docker"]["memory_bytes"], 1234)

    def test_host_metadata_rejects_incoherent_pool_partition(self):
        for partition in ((32, 0, 32), (32, 24, 0), (32, 25, 8), (1, 0, 1)):
            with self.subTest(partition=partition), self.assertRaises(ValueError):
                DIAGNOSTICS.host_metadata(*partition)


class LogTests(unittest.TestCase):
    def test_only_fixed_error_labels_are_retained(self):
        payload = ("\n".join([
            "2026-09-03 06:00:00.123 UTC [12] ERROR:  deadlock detected " + SECRET,
            "ERROR:  canceling statement due to statement timeout " + SECRET,
            "FATAL:  sorry, too many clients already " + SECRET,
            "ERROR:  " + SECRET,
            "DETAIL: ERROR: deadlock detected " + SECRET,
            "STATEMENT: select 'ERROR: deadlock detected " + SECRET + "'",
            "docker failed " + SECRET,
        ])).encode()
        with patch.object(DIAGNOSTICS, "capture", return_value=("truncated", payload)) as captured:
            result = DIAGNOSTICS.postgres_error_labels(POSTGRES)
        self.assertEqual(result["counts"], {"deadlock_detected": 1, "statement_timeout": 1, "too_many_connections": 1, "other_error": 1})
        self.assertEqual(result["status"], "truncated")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(captured.call_args.args[0], ["docker", "logs", "--tail", "2000", POSTGRES])
        self.assertEqual(captured.call_args.kwargs["limit"], DIAGNOSTICS.MAXIMUM_LOG_BYTES)

    def test_record_has_a_byte_bound(self):
        writer = io.StringIO()
        DIAGNOSTICS.write_record(writer, {"kind": "test", "value": "x"*DIAGNOSTICS.MAXIMUM_RECORD_BYTES})
        self.assertEqual(json.loads(writer.getvalue())["status"], "record_too_large")


class ProcessMemoryTests(unittest.TestCase):
    @staticmethod
    def payload():
        return (b"schema 1\nsmaps_rss_kib 4096\nsmaps_pss_kib 2048\n"
                b"smaps_anon_huge_pages_kib 2048\nstatus_vm_rss_kib 4096\n"
                b"status_rss_anon_kib 3072\nstatus_rss_file_kib 1024\n"
                b"enabled always\ndefrag defer+madvise\nscan_sleep_millisecs 10000\n"
                b"max_ptes_none 511\ncomplete 1\n")

    def test_same_uid_existing_runner_fixed_read_only_script_and_bounds(self):
        with patch.object(DIAGNOSTICS, "capture", return_value=("ok", self.payload())) as captured:
            result = DIAGNOSTICS.process_memory_sample(TOOLS_RUNNER)
        command = captured.call_args.args[0]
        self.assertEqual(command[:10], ["docker", "exec", "--user", "65532:65532", TOOLS_RUNNER,
                                      "timeout", "-s", "KILL", "2", "awk"])
        self.assertEqual(command[10], DIAGNOSTICS.PROCESS_MEMORY_AWK)
        self.assertEqual(captured.call_args.kwargs, {"limit": 2048, "timeout": 3})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["metrics"]["smaps_rollup"]["anon_huge_pages_bytes"], 2 * 1024**2)
        self.assertEqual(result["metrics"]["status"]["rss_file_bytes"], 1024**2)
        self.assertEqual(result["host_thp_controls"]["scan_sleep_millisecs"], 10000)
        self.assertEqual(result["host_thp_controls"]["defrag"], "defer+madvise")
        self.assertTrue(result["advisory_only"])
        self.assertTrue(result["thp_controls_are_metadata_not_causal_proof"])
        for forbidden in ("--privileged", "--cap-add", "--network", "GOGC", "GOMEMLIMIT", "disablethp"):
            self.assertNotIn(forbidden, command)
        self.assertNotIn(TOOLS_RUNNER, json.dumps(result))
        self.assertNotIn("/proc/", json.dumps(result))

    def test_malicious_raw_fields_and_duplicate_records_are_discarded(self):
        for payload in (SECRET.encode(), self.payload() + b"query " + SECRET.encode() + b"\n",
                        self.payload() + b"smaps_rss_kib 1\n", b"schema 1\n",
                        self.payload() + b"7f123400-7f123500 rw-p /private/path\n"):
            with patch.object(DIAGNOSTICS, "capture", return_value=("ok", payload)):
                result = DIAGNOSTICS.process_memory_sample(TOOLS_RUNNER)
            self.assertEqual(result["status"], "invalid_response")
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertNotIn("metrics", result)

    def test_non_numeric_and_unknown_enum_values_are_never_emitted(self):
        payload = self.payload().replace(b"4096", SECRET.encode()).replace(b"10000", b"-1")
        payload = payload.replace(b"always", SECRET.encode()).replace(b"defer+madvise", b"[unknown]")
        with patch.object(DIAGNOSTICS, "capture", return_value=("ok", payload)):
            result = DIAGNOSTICS.process_memory_sample(TOOLS_RUNNER)
        self.assertEqual(result["status"], "partial")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIsNone(result["metrics"]["smaps_rollup"]["rss_bytes"])
        self.assertIsNone(result["host_thp_controls"]["enabled"])
        self.assertIsNone(result["host_thp_controls"]["scan_sleep_millisecs"])

    def test_missing_or_denied_read_is_unavailable_not_zero(self):
        for capture_status in ("failed", "timeout", "truncated", "unavailable"):
            with patch.object(DIAGNOSTICS, "capture", return_value=(capture_status, SECRET.encode())):
                result = DIAGNOSTICS.process_memory_sample(TOOLS_RUNNER)
            self.assertEqual(result["status"], capture_status)
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertNotIn("metrics", result)
        with patch.object(DIAGNOSTICS, "capture", return_value=("ok", b"schema 1\ncomplete 1\n")):
            result = DIAGNOSTICS.process_memory_sample(TOOLS_RUNNER)
        self.assertEqual(result["status"], "unavailable")
        self.assertTrue(all(value is None for fields in result["metrics"].values() for value in fields.values()))

    def test_real_awk_filters_fixed_fixture_reads_before_capture(self):
        fixtures = {
            "/proc/1/smaps_rollup": "7f0000-7fffff rw-p /private/" + SECRET + "\nRss: 4096 kB\nPss: 2048 kB\nAnonHugePages: 2048 kB\n",
            "/proc/1/status": "Name:\t" + SECRET + "\nVmRSS: 4096 kB\nRssAnon: 3072 kB\nRssFile: 1024 kB\nUid: 65532\n",
            "/sys/kernel/mm/transparent_hugepage/enabled": "[always] madvise never\n",
            "/sys/kernel/mm/transparent_hugepage/defrag": "always defer [defer+madvise] madvise never\n",
            "/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs": "10000\n",
            "/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none": "511\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            script = DIAGNOSTICS.PROCESS_MEMORY_AWK
            for index, (source_path, contents) in enumerate(fixtures.items()):
                destination = Path(directory) / str(index)
                destination.write_text(contents)
                script = script.replace(source_path, str(destination))
            completed = subprocess.run(["awk", script], capture_output=True, timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(SECRET.encode(), completed.stdout)
        self.assertNotIn(b"/private", completed.stdout)
        self.assertIn(b"enabled always\n", completed.stdout)
        self.assertIn(b"defrag defer+madvise\n", completed.stdout)
        self.assertIn(b"scan_sleep_millisecs 10000\n", completed.stdout)
        with patch.object(DIAGNOSTICS, "capture", return_value=("ok", completed.stdout)):
            self.assertEqual(DIAGNOSTICS.process_memory_sample(TOOLS_RUNNER)["status"], "ok")

    def test_smaps_uses_only_existing_lifecycle_cadence(self):
        now = [0.0]
        def sleep(seconds): now[0] += seconds
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(DIAGNOSTICS.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(DIAGNOSTICS.time, "sleep", side_effect=sleep), \
             patch.object(DIAGNOSTICS, "host_metadata", return_value={"kind": "host"}), \
             patch.object(DIAGNOSTICS, "database_sample", return_value={"kind": "db"}), \
             patch.object(DIAGNOSTICS, "resource_sample", return_value={"kind": "resources"}) as resource_sample, \
             patch.object(DIAGNOSTICS, "process_memory_sample", return_value={"kind": "process_memory"}) as memory_sample, \
             patch.object(DIAGNOSTICS, "postgres_error_labels", return_value={"kind": "postgres_error_labels"}):
            DIAGNOSTICS.collect(io.StringIO(), POSTGRES, GATEWAY, Path(directory)/"stop", 32, 24, 8,
                                tools_runner=TOOLS_RUNNER, maximum_seconds=31)
        self.assertEqual(memory_sample.call_count, 3)  # T+0,15,30; never T+5 or T+10.
        self.assertEqual(resource_sample.call_count, memory_sample.call_count)
        self.assertTrue(all(call.args == (TOOLS_RUNNER,) for call in memory_sample.call_args_list))


class LifecycleTests(unittest.TestCase):
    def test_collector_has_a_time_bound_and_final_snapshot(self):
        now = [0.0]
        def sleep(seconds):
            now[0] += seconds
        writer = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            stop_file = Path(directory) / "stop"
            with patch.object(DIAGNOSTICS.time, "monotonic", side_effect=lambda: now[0]), patch.object(DIAGNOSTICS.time, "sleep", side_effect=sleep):
                with patch.object(DIAGNOSTICS, "host_metadata", return_value={"kind": "host"}), patch.object(DIAGNOSTICS, "database_sample", side_effect=lambda *args, lifecycle=False: {"kind": "lifecycle" if lifecycle else "database_activity"}), patch.object(DIAGNOSTICS, "resource_sample", return_value={"kind": "resources"}), patch.object(DIAGNOSTICS, "postgres_error_labels", return_value={"kind": "postgres_error_labels"}):
                    DIAGNOSTICS.collect(writer, POSTGRES, GATEWAY, stop_file, 32, 24, 8, maximum_seconds=11)
        records = [json.loads(line) for line in writer.getvalue().splitlines()]
        self.assertEqual(records[-1]["status"], "time_bound_reached")
        self.assertEqual(records[-1]["activity_samples"], 3)
        self.assertEqual([row["kind"] for row in records[-3:]], ["lifecycle", "postgres_error_labels", "collector"])

    def test_existing_stop_file_avoids_workload_sampling(self):
        writer = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            stop_file = Path(directory) / "stop"
            stop_file.touch()
            with patch.object(DIAGNOSTICS, "host_metadata", return_value={"kind": "host"}), patch.object(DIAGNOSTICS, "database_sample", return_value={"kind": "lifecycle"}) as sample, patch.object(DIAGNOSTICS, "postgres_error_labels", return_value={"kind": "postgres_error_labels"}):
                DIAGNOSTICS.collect(writer, POSTGRES, GATEWAY, stop_file, 32, 24, 8)
        self.assertEqual(sample.call_count, 1)
        self.assertTrue(sample.call_args.kwargs["lifecycle"])
        self.assertEqual(json.loads(writer.getvalue().splitlines()[-1])["status"], "stopped")

    def test_output_cannot_overwrite_existing_or_symlinked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing"
            existing.write_text(SECRET)
            link = root / "link"
            link.symlink_to(existing)
            for output in (existing, link):
                arguments = ["diagnostics", "--postgres", POSTGRES, "--gateway", GATEWAY,
                             "--tools-runner", TOOLS_RUNNER,
                             "--pool-max-connections", "32",
                             "--regular-pool-max-connections", "24",
                             "--completion-pool-max-connections", "8",
                             "--output", str(output), "--stop-file", str(root/"stop")]
                with patch.object(sys, "argv", arguments):
                    self.assertEqual(DIAGNOSTICS.main(), 1)
            self.assertEqual(existing.read_text(), SECRET)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "scripts/run-local-load-gates.sh").read_text()

    def test_source_cleanliness_gate_rejects_tracked_and_untracked_changes_without_leaking_names(self):
        start = self.source.index("require_clean_source_repository() {\n")
        end = self.source.index("\n}\n", start) + 2
        cleanliness_gate = self.source[start:end]

        for state in ("clean", "tracked", "untracked"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)
                subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
                tracked = repository / "tracked.txt"
                tracked.write_text("committed\n")
                subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
                subprocess.run(
                    [
                        "git", "-C", str(repository),
                        "-c", "user.name=Latchway Test",
                        "-c", "user.email=test@latchway.invalid",
                        "commit", "--quiet", "-m", "fixture",
                    ],
                    check=True,
                )
                if state == "tracked":
                    tracked.write_text("changed " + SECRET)
                elif state == "untracked":
                    (repository / (SECRET + ".txt")).write_text("untracked")

                script = "\n".join([
                    "set -eu",
                    "repository_root=" + shlex.quote(str(repository)),
                    cleanliness_gate,
                    "require_clean_source_repository",
                ])
                result = subprocess.run(
                    ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0 if state == "clean" else 2, result.stderr)
                self.assertNotIn(SECRET, result.stderr)

        invocation = self.source.index("\nrequire_clean_source_repository\n", end)
        self.assertLess(invocation, self.source.index('mkdir -p "$evidence_dir"'))
        self.assertLess(invocation, self.source.index("run_dir=$(mktemp"))
        self.assertLess(invocation, self.source.index("git clone --quiet --no-hardlinks"))

    def test_cleanup_preserves_success_and_failure_despite_collector_failure(self):
        start = self.source.index("cleanup() {\n")
        end = self.source.index("\ntrap cleanup EXIT HUP INT TERM", start)
        cleanup = self.source[start:end]
        for gate_status in (0, 23):
            with tempfile.TemporaryDirectory() as directory:
                script = "\n".join([
                    "set -eu", "docker() { return 0; }", "rm() { return 0; }",
                    "gateway=diagnostic-gateway", "fixture=diagnostic-fixture",
                    "postgres=diagnostic-postgres", "network_created=false",
                    "gateway_image_created=false", "tools_image_created=false",
                    "capture_postgres_startup_events() { return 0; }",
                    cleanup, "trap cleanup EXIT", "(exit 7) &", "diagnostics_pid=$!",
                    "exit " + str(gate_status),
                ])
                result = subprocess.run(["/bin/sh", "-c", script], env={**os.environ, "run_dir": directory, "evidence_dir": directory}, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, gate_status, result.stderr)
                record = json.loads((Path(directory)/"runtime-diagnostics.jsonl").read_text())
                self.assertEqual(record["status"], "unavailable")

    def test_stalled_collector_cannot_block_fixture_cleanup(self):
        start = self.source.index("cleanup() {\n")
        end = self.source.index("\ntrap cleanup EXIT HUP INT TERM", start)
        cleanup = self.source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            script = "\n".join([
                "set -eu", "docker() { return 0; }", "rm() { return 0; }",
                "kill() { return 0; }", "sleep() { return 0; }",
                "wait() { exit 99; }", "diagnostics_pid=12345",
                "gateway=diagnostic-gateway", "fixture=diagnostic-fixture",
                "postgres=diagnostic-postgres", "network_created=false",
                "gateway_image_created=false", "tools_image_created=false",
                "capture_postgres_startup_events() { return 0; }",
                cleanup, "trap cleanup EXIT", "exit 23",
            ])
            result = subprocess.run(["/bin/sh", "-c", script], env={**os.environ, "run_dir": directory, "evidence_dir": directory}, capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 23, result.stderr)
            record = json.loads((Path(directory)/"runtime-diagnostics.jsonl").read_text())
            self.assertEqual(record["status"], "stop_timeout")
        self.assertIn('"$diagnostics_stop_attempt" -lt 15', cleanup)
        self.assertIn('kill -TERM "$diagnostics_pid"', cleanup)
        self.assertIn('kill -KILL "$diagnostics_pid"', cleanup)

    def test_collector_starts_after_provision_and_stops_before_teardown(self):
        self.assertLess(self.source.index('cp "$run_dir/runtime/load-config.json"'), self.source.index('python3 "$run_dir/source/scripts/load-runtime-diagnostics.py"'))
        self.assertLess(self.source.index('wait "$diagnostics_pid"'), self.source.index('docker rm --force "$gateway"'))
        self.assertIn('--pool-max-connections "$gateway_db_pool_max_connections"', self.source)
        self.assertIn('--regular-pool-max-connections "$gateway_db_regular_pool_max_connections"', self.source)
        self.assertIn('--completion-pool-max-connections "$gateway_db_completion_pool_max_connections"', self.source)
        self.assertIn(
            "export LATCHWAY_DB_COMPLETION_CONNECTIONS=$gateway_db_completion_pool_max_connections",
            self.source,
        )
        self.assertIn("--env LATCHWAY_DB_COMPLETION_CONNECTIONS", self.source)
        self.assertIn("gateway_completion_pool_env=$(docker inspect", self.source)
        self.assertIn('--tools-runner "$tools_runner"', self.source)
        self.assertIn('--stop-file "$run_dir/runtime-diagnostics.stop" >/dev/null 2>&1 &', self.source)
        self.assertNotIn("-mode ", self.source)
        for value in ("--cpus 4", "--cpus 2", "--memory 4g", "--memory 2g",
                      "gateway_db_pool_max_connections=32",
                      "gateway_db_regular_pool_max_connections=24",
                      "gateway_db_completion_pool_max_connections=8",
                      "postgres_max_connections=100"):
            self.assertIn(value, self.source)

    def test_existing_runner_is_named_and_cleanup_requires_ownership(self):
        self.assertIn('tools_runner="latchway-load-runner-$suffix"', self.source)
        self.assertEqual(self.source.count('--name "$tools_runner"'), 1)
        self.assertIn('--label "dev.latchway.load-run=$suffix"', self.source)
        self.assertIn('refusing to reuse an existing load runner name', self.source)
        cleanup = self.source[self.source.index("cleanup() {\n"):self.source.index("\ntrap cleanup EXIT HUP INT TERM")]
        self.assertIn('.Config.Labels "dev.latchway.load-run"', cleanup)
        self.assertIn('= "$tools_image_id"', cleanup)
        self.assertIn('"${tools_runner_create_intended:-false}" = true', cleanup)
        self.assertIn('docker rm --force "$tools_runner"', cleanup)
        self.assertIn('--pid "container:$gateway"', self.source)

    def test_runner_cleanup_skips_preexisting_or_mismatching_ownership(self):
        cleanup = self.source[self.source.index("cleanup() {\n"):self.source.index("\ntrap cleanup EXIT HUP INT TERM")]
        for intended, matching_label, expected in (("false", True, False), ("true", False, False), ("true", True, True)):
            with tempfile.TemporaryDirectory() as directory:
                script = "\n".join([
                    "set -eu", "rm() { return 0; }",
                    "docker() { if [ \"$1\" = inspect ] && [ \"${2:-}\" = --format ]; then case \"$3\" in *'.Image'*) printf '%s\\n' \"$tools_image_id\";; *) printf '%s\\n' \"$observed_label\";; esac; elif [ \"$1\" = rm ] && [ \"${3:-}\" = \"$tools_runner\" ]; then printf '%s\\n' runner_removed >> \"$removal_receipt\"; fi; return 0; }",
                    "gateway=diagnostic-gateway", "fixture=diagnostic-fixture", "postgres=diagnostic-postgres",
                    "tools_runner=diagnostic-runner", "tools_image_id=sha256:synthetic-tools-image",
                    "suffix=owned-suffix", "diagnostics_pid=", "network_created=false",
                    "gateway_image_created=false", "tools_image_created=false",
                    "tools_runner_create_intended=" + intended,
                    "observed_label=" + ("owned-suffix" if matching_label else "other-run"),
                    "capture_postgres_startup_events() { return 0; }", cleanup,
                    "trap cleanup EXIT", "exit 23",
                ])
                receipt = Path(directory)/"removal"
                result = subprocess.run(["/bin/sh", "-c", script], env={**os.environ, "run_dir": directory,
                                        "evidence_dir": directory, "removal_receipt": str(receipt)},
                                        capture_output=True, text=True, timeout=2)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(receipt.exists(), expected)

    def test_candidate_runs_the_new_regressions(self):
        self.assertIn("scripts/test_load_runtime_diagnostics.py", (ROOT/".github/workflows/release.yml").read_text())

    def test_cleanup_removes_only_the_exact_postgres_anonymous_volume(self):
        self.assertIn('docker rm --force --volumes "$postgres" >/dev/null 2>&1', self.source)
        self.assertEqual(self.source.count("--volumes"), 1)
        self.assertNotIn("docker volume prune", self.source)
        self.assertNotIn("docker system prune", self.source)


if __name__ == "__main__":
    unittest.main()
