#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
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
                result = DIAGNOSTICS.host_metadata(32)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["gateway_pool_max_connections"], 32)
        self.assertTrue(result["backend_count_is_not_pool_waiter_count"])
        self.assertEqual(result["docker"]["memory_bytes"], 1234)


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
                    DIAGNOSTICS.collect(writer, POSTGRES, GATEWAY, stop_file, 32, maximum_seconds=11)
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
                DIAGNOSTICS.collect(writer, POSTGRES, GATEWAY, stop_file, 32)
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
                             "--pool-max-connections", "32", "--output", str(output), "--stop-file", str(root/"stop")]
                with patch.object(sys, "argv", arguments):
                    self.assertEqual(DIAGNOSTICS.main(), 1)
            self.assertEqual(existing.read_text(), SECRET)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "scripts/run-local-load-gates.sh").read_text()

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
        self.assertIn('--stop-file "$run_dir/runtime-diagnostics.stop" >/dev/null 2>&1 &', self.source)
        self.assertNotIn("-mode ", self.source)
        for value in ("--cpus 4", "--cpus 2", "--memory 4g", "--memory 2g",
                      "gateway_db_pool_max_connections=32", "postgres_max_connections=100"):
            self.assertIn(value, self.source)

    def test_candidate_runs_the_new_regressions(self):
        self.assertIn("scripts/test_load_runtime_diagnostics.py", (ROOT/".github/workflows/release.yml").read_text())

    def test_cleanup_removes_only_the_exact_postgres_anonymous_volume(self):
        self.assertIn('docker rm --force --volumes "$postgres" >/dev/null 2>&1', self.source)
        self.assertEqual(self.source.count("--volumes"), 1)
        self.assertNotIn("docker volume prune", self.source)
        self.assertNotIn("docker system prune", self.source)


if __name__ == "__main__":
    unittest.main()
