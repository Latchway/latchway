#!/usr/bin/env python3
"""Bounded, advisory diagnostics for the isolated load fixture, never release gates.

Only enum labels and numeric aggregates cross the capture boundary. PostgreSQL
query text, parameters, identifiers and raw dependency errors are never emitted.
Database counters include this read-only collector; backend samples exclude it.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import time


INTERVAL_SECONDS = 5
LIFECYCLE_EVERY = 3
MAXIMUM_SECONDS = 15 * 60
MAXIMUM_RECORD_BYTES = 65536
MAXIMUM_LOG_BYTES = 262144
MAXIMUM_ROWS = 128
INTEGER_MAXIMUM = 2**63 - 1

STATES = {"active", "idle", "idle in transaction", "idle in transaction (aborted)"}
WAIT_TYPES = {"Activity", "BufferPin", "Client", "Extension", "IO", "IPC", "Lock", "LWLock", "Timeout"}
WAIT_EVENTS = {
    "transactionid", "tuple", "relation", "extend", "ClientRead", "ClientWrite",
    "DataFileRead", "DataFileWrite", "BufferContent", "BufferMapping", "BufferIO",
    "WALWrite", "WALSync", "WALInsert", "WALBufMapping", "WALInitWrite",
    "WalWrite", "WalSync", "WalInsert", "WalInitWrite", "ProcArray", "SyncRep",
    "LockManager", "PgSleep",
}
LOGICAL_STATES = {"authenticated", "reserved", "dispatched", "streaming", "succeeded", "failed", "cancelled", "denied"}
RESERVATION_STATES = {"pending", "settled", "released", "expired"}
ATTEMPT_STATES = {"started", "succeeded", "failed", "cancelled", "timed_out"}
OUTCOMES = {"failed", "denied", "cancelled"}
STAGES = {
    "identity_verified", "client_trust_verified", "client_context_validated",
    "configuration_loaded", "request_inspected", "policy_evaluated",
    "route_selected", "quota_rule_evaluated", "quota_reserved", "lifecycle_recovered",
}
FAILURE_CODES = {
    "server_not_ready", "quota_state_unavailable", "upstream_timeout",
    "upstream_unavailable", "upstream_protocol_error", "request_cancelled",
    "client_cancelled", "reservation_expired", "quota_exceeded", "configuration_invalid",
}

# Advisory metadata, not runtime tuning or proof that THP caused an RSS change.
# Kernel documentation: admin-guide/mm/transhuge.html and filesystems/proc.html.
THP_ENABLED = {"always", "madvise", "never"}
THP_DEFRAG = THP_ENABLED | {"defer", "defer+madvise"}
PROCESS_MEMORY_FIELDS = {
    "smaps_rss_kib": ("smaps_rollup", "rss_bytes"),
    "smaps_pss_kib": ("smaps_rollup", "pss_bytes"),
    "smaps_anon_huge_pages_kib": ("smaps_rollup", "anon_huge_pages_bytes"),
    "status_vm_rss_kib": ("status", "vm_rss_bytes"),
    "status_rss_anon_kib": ("status", "rss_anon_bytes"),
    "status_rss_file_kib": ("status", "rss_file_bytes"),
}
THP_INTEGER_FIELDS = {"scan_sleep_millisecs", "max_ptes_none"}
PROCESS_MEMORY_CAPTURE_BYTES = 2048
PROCESS_MEMORY_AWK = r'''
function discard_proc(path) {
    if (path == "/proc/1/smaps_rollup") {
        delete values["smaps_rss_kib"]; delete values["smaps_pss_kib"]; delete values["smaps_anon_huge_pages_kib"]
    }
    if (path == "/proc/1/status") {
        delete values["status_vm_rss_kib"]; delete values["status_rss_anon_kib"]; delete values["status_rss_file_kib"]
    }
}
function bounded_read(path, lines, bytes, line, status, first) {
    lines = bytes = 0
    while ((status = (getline line < path)) > 0) {
        bytes += length(line) + 1
        if (++lines > 256 || bytes > 16384) { discard_proc(path); close(path); return "" }
        if (path == "/proc/1/smaps_rollup" && line ~ /^(Rss|Pss|AnonHugePages):[ \t]+[0-9]+[ \t]+kB$/) {
            split(line, a, /[ \t]+/)
            if (a[1] == "Rss:") values["smaps_rss_kib"] = a[2]
            if (a[1] == "Pss:") values["smaps_pss_kib"] = a[2]
            if (a[1] == "AnonHugePages:") values["smaps_anon_huge_pages_kib"] = a[2]
        }
        if (path == "/proc/1/status" && line ~ /^(VmRSS|RssAnon|RssFile):[ \t]+[0-9]+[ \t]+kB$/) {
            split(line, a, /[ \t]+/)
            if (a[1] == "VmRSS:") values["status_vm_rss_kib"] = a[2]
            if (a[1] == "RssAnon:") values["status_rss_anon_kib"] = a[2]
            if (a[1] == "RssFile:") values["status_rss_file_kib"] = a[2]
        }
        # Only one short selected enum or integer from these fixed sysfs files.
        if (path != "/proc/1/smaps_rollup" && path != "/proc/1/status" && lines == 1 && length(line) <= 256)
            first = line
    }
    close(path)
    if (status < 0) discard_proc(path)
    return status < 0 || (path != "/proc/1/smaps_rollup" && path != "/proc/1/status" && lines != 1) ? "" : first
}
function selected(line, allowed, count, i, tokens, candidate, found, choice) {
    count = split(line, tokens, /[ \t]+/); found = 0
    for (i = 1; i <= count; i++) {
        if (tokens[i] ~ /^\[[a-z+]+\]$/) {
            candidate = substr(tokens[i], 2, length(tokens[i]) - 2)
            if (candidate !~ allowed) return ""
            found++; choice = candidate
        } else if (tokens[i] != "" && tokens[i] !~ allowed) return ""
    }
    return found == 1 ? choice : ""
}
BEGIN {
    bounded_read("/proc/1/smaps_rollup")
    bounded_read("/proc/1/status")
    enabled = selected(bounded_read("/sys/kernel/mm/transparent_hugepage/enabled"), "^(always|madvise|never)$")
    defrag = selected(bounded_read("/sys/kernel/mm/transparent_hugepage/defrag"), "^(always|defer|defer[+]madvise|madvise|never)$")
    scan = bounded_read("/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs")
    none = bounded_read("/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none")
    print "schema 1"
    for (key in values) print key " " values[key]
    if (enabled != "") print "enabled " enabled
    if (defrag != "") print "defrag " defrag
    if (scan ~ /^[0-9]+$/) print "scan_sleep_millisecs " scan
    if (none ~ /^[0-9]+$/) print "max_ptes_none " none
    print "complete 1"
}
'''


def sql_enum(column: str, allowed: set[str]) -> str:
    # All arguments are module-owned constants, never CLI or database values.
    values = ",".join("'" + value + "'" for value in sorted(allowed))
    return f"CASE WHEN {column} IN ({values}) THEN {column} WHEN {column} IS NULL THEN 'none' ELSE 'other' END"


ACTIVITY_SQL = f"""
SELECT json_build_object(
 'database', (SELECT json_build_object(
   'connections',numbackends,'deadlocks',deadlocks,'commits',xact_commit,
   'rollbacks',xact_rollback,'conflicts',conflicts,'temp_files',temp_files,'temp_bytes',temp_bytes
 ) FROM pg_stat_database WHERE datname=current_database()),
 'waits', (SELECT coalesce(json_agg(row),'[]'::json) FROM (
   SELECT {sql_enum('state', STATES)} AS state,
          {sql_enum('wait_event_type', WAIT_TYPES)} AS wait_type,
          {sql_enum('wait_event', WAIT_EVENTS)} AS wait_event,
          count(*) AS connections,
          count(*) FILTER (WHERE cardinality(pg_blocking_pids(pid))>0) AS blocked,
          coalesce(greatest(0,round((max(extract(epoch FROM clock_timestamp()-query_start))
            FILTER (WHERE state='active'))*1000)),0)::bigint AS maximum_active_ms
   FROM pg_stat_activity
   WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'
   GROUP BY 1,2,3 ORDER BY 1,2,3
 ) AS row)
);
"""

LIFECYCLE_SQL = f"""
SELECT json_build_object(
 'logical_requests', (SELECT coalesce(json_agg(row),'[]'::json) FROM (
   SELECT {sql_enum('status', LOGICAL_STATES)} AS status,
          {sql_enum('failure_code', FAILURE_CODES)} AS failure_code,
          count(*) AS count FROM logical_requests GROUP BY 1,2 ORDER BY 1,2
 ) AS row),
 'reservations', (SELECT coalesce(json_agg(row),'[]'::json) FROM (
   SELECT {sql_enum('status', RESERVATION_STATES)} AS status, count(*) AS count,
          CASE WHEN status='pending' THEN greatest(0,round(max(extract(epoch FROM clock_timestamp()-created_at))*1000)) ELSE 0 END::bigint AS oldest_pending_ms
   FROM quota_reservations GROUP BY 1,status ORDER BY 1
 ) AS row),
 'attempts', (SELECT coalesce(json_agg(row),'[]'::json) FROM (
   SELECT {sql_enum('status', ATTEMPT_STATES)} AS status,
          (first_byte_at IS NOT NULL) AS first_byte, count(*) AS count
   FROM upstream_attempts GROUP BY 1,2 ORDER BY 1,2
 ) AS row),
 'decision_failures', (SELECT coalesce(json_agg(row),'[]'::json) FROM (
   SELECT {sql_enum('stage', STAGES)} AS stage,
          {sql_enum('outcome', OUTCOMES)} AS outcome,
          {sql_enum('failure_code', FAILURE_CODES)} AS failure_code,
          count(*) AS count
   FROM logical_request_decision_stages WHERE outcome<>'succeeded'
   GROUP BY 1,2,3 ORDER BY 1,2,3
 ) AS row)
);
"""


def capture(arguments: list[str], *, environment=None, limit=MAXIMUM_RECORD_BYTES, timeout=3):
    """Capture at most limit bytes; errors and partial output never become logs."""
    output = bytearray()
    status = "unavailable"
    try:
        process = subprocess.Popen(arguments, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, close_fds=True)
    except OSError:
        return status, b""
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                if not selector.select(remaining):
                    status = "timeout"
                    break
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    status = "ok" if process.wait(timeout=max(0.01, deadline-time.monotonic())) == 0 else "failed"
                    break
                output.extend(chunk)
                if len(output) > limit:
                    status = "truncated"
                    break
    except (OSError, subprocess.TimeoutExpired):
        status = "unavailable"
    finally:
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            status = "reap_timeout"
        except OSError:
            status = "unavailable"
        process.stdout.close()
    return status, bytes(output[:limit])


def integer(value):
    return value if type(value) is int and 0 <= value <= INTEGER_MAXIMUM else None


def label(value, allowed):
    return value if isinstance(value, str) and value in allowed | {"none", "other"} else "other"


ROW_SCHEMAS = {
    "waits": {"state": STATES, "wait_type": WAIT_TYPES, "wait_event": WAIT_EVENTS,
              "connections": int, "blocked": int, "maximum_active_ms": int},
    "logical_requests": {"status": LOGICAL_STATES, "failure_code": FAILURE_CODES, "count": int},
    "reservations": {"status": RESERVATION_STATES, "count": int, "oldest_pending_ms": int},
    "attempts": {"status": ATTEMPT_STATES, "first_byte": bool, "count": int},
    "decision_failures": {"stage": STAGES, "outcome": OUTCOMES, "failure_code": FAILURE_CODES, "count": int},
}
DATABASE_FIELDS = {"connections", "deadlocks", "commits", "rollbacks", "conflicts", "temp_files", "temp_bytes"}


def sanitize_metrics(value, *, lifecycle):
    if not isinstance(value, dict):
        raise ValueError("invalid diagnostics")
    result = {}
    if not lifecycle:
        database = value.get("database")
        if not isinstance(database, dict):
            raise ValueError("invalid diagnostics")
        result["database"] = {key: integer(database.get(key)) for key in sorted(DATABASE_FIELDS)}
    selected = set(ROW_SCHEMAS) - {"waits"} if lifecycle else {"waits"}
    for key in sorted(selected):
        rows = value.get(key)
        if not isinstance(rows, list) or len(rows) > MAXIMUM_ROWS:
            raise ValueError("invalid diagnostics")
        result[key] = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("invalid diagnostics")
            clean = {}
            for field, kind in ROW_SCHEMAS[key].items():
                candidate = row.get(field)
                if kind is int:
                    clean[field] = integer(candidate)
                elif kind is bool:
                    clean[field] = candidate if type(candidate) is bool else None
                else:
                    clean[field] = label(candidate, kind)
            result[key].append(clean)
    return result


def database_sample(postgres: str, *, lifecycle=False):
    environment = dict(os.environ)
    environment["PGPASSWORD"] = environment.get("POSTGRES_PASSWORD", "")
    arguments = ["docker", "exec", "--user", "postgres", "--env", "PGPASSWORD",
        "--env", "PGCONNECT_TIMEOUT=2", "--env", "PGAPPNAME=latchway-load-diagnostics",
        "--env", "PGOPTIONS=-c statement_timeout=500 -c default_transaction_read_only=on",
        postgres, "psql", "--host", "127.0.0.1", "--username", "latchway", "--dbname", "latchway",
        "--no-password", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align",
        "--command", LIFECYCLE_SQL if lifecycle else ACTIVITY_SQL]
    started = time.monotonic()
    status, output = capture(arguments, environment=environment)
    record = {"kind": "lifecycle" if lifecycle else "database_activity", "status": status}
    if status == "ok":
        try:
            record["metrics"] = sanitize_metrics(json.loads(output), lifecycle=lifecycle)
        except (ValueError, UnicodeError):
            record["status"] = "invalid_response"
    record["duration_ms"] = round((time.monotonic()-started)*1000)
    return record


CPU_MODEL = re.compile(r"^(?:Intel|AMD|Apple|ARM|Ampere|Neoverse|QEMU)[A-Za-z0-9 .()+_@/-]{0,150}$")
ARCHITECTURES = {"x86_64", "amd64", "aarch64", "arm64"}


def cpu_model():
    try:
        with Path("/proc/cpuinfo").open("rb") as reader:
            contents = reader.read(65536).decode("ascii", "replace")
        for line in contents.splitlines():
            field, separator, value = line.partition(":")
            if separator and field.strip() == "model name" and CPU_MODEL.fullmatch(value.strip()):
                return value.strip()
    except OSError:
        pass
    status, output = capture(["sysctl", "-n", "machdep.cpu.brand_string"], limit=256, timeout=1)
    value = output.decode("ascii", "replace").strip()
    return value if status == "ok" and CPU_MODEL.fullmatch(value) else None


def valid_pool_partition(pool_maximum, regular_pool_maximum, completion_pool_maximum):
    return (
        all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (pool_maximum, regular_pool_maximum, completion_pool_maximum)
        )
        and 2 <= pool_maximum <= 500
        and regular_pool_maximum >= 1
        and completion_pool_maximum >= 1
        and regular_pool_maximum == pool_maximum - completion_pool_maximum
    )


def host_metadata(pool_maximum, regular_pool_maximum, completion_pool_maximum):
    if not valid_pool_partition(pool_maximum, regular_pool_maximum, completion_pool_maximum):
        raise ValueError("invalid gateway database pool partition")
    memory = None
    try:
        memory = integer(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError):
        pass
    affinity = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    result = {"kind": "host", "cpu_model": cpu_model(), "logical_cpu_count": integer(os.cpu_count()),
              "affinity_cpu_count": integer(affinity), "memory_bytes": memory,
              "architecture": label(os.uname().machine, ARCHITECTURES),
              "gateway_pool_max_connections": pool_maximum,
              "gateway_regular_pool_max_connections": regular_pool_maximum,
              "gateway_completion_pool_max_connections": completion_pool_maximum,
              "backend_count_is_not_pool_waiter_count": True,
              "database_counters_include_collector": True,
              "postgres_error_labels_may_include_collector_timeouts": True}
    template = '{"cpu_count":{{json .NCPU}},"memory_bytes":{{json .MemTotal}},"architecture":{{json .Architecture}}}'
    status, output = capture(["docker", "info", "--format", template], limit=1024)
    result["docker_status"] = status
    if status == "ok":
        try:
            value = json.loads(output)
            result["docker"] = {"cpu_count": integer(value.get("cpu_count")),
                                "memory_bytes": integer(value.get("memory_bytes")),
                                "architecture": label(value.get("architecture"), ARCHITECTURES)}
        except (ValueError, AttributeError):
            result["docker_status"] = "invalid_response"
    return result


def pressure_snapshot():
    result = {}
    for resource in ("cpu", "memory", "io"):
        try:
            with Path(f"/proc/pressure/{resource}").open("rb") as reader:
                lines = reader.read(2048).decode("ascii").splitlines()
            categories = {}
            for line in lines:
                match = re.fullmatch(r"(some|full) avg10=([0-9.]+) avg60=([0-9.]+) avg300=([0-9.]+) total=([0-9]+)", line)
                if match is None:
                    continue
                values = [float(value) for value in match.group(2, 3, 4)]
                if all(math.isfinite(value) and 0 <= value <= 100 for value in values):
                    categories[match[1]] = dict(zip(("avg10", "avg60", "avg300"), values))
                    categories[match[1]]["total_us"] = integer(int(match[5]))
            result[resource] = categories
        except (OSError, UnicodeError, ValueError):
            result[resource] = None
    return result


def byte_quantity(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|MB|GB|TB|KiB|MiB|GiB|TiB)", value.strip())
    if match is None:
        return None
    scales = {"B": 1, "kB": 1000, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
              "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    quantity = float(match[1]) * scales[match[2]]
    return integer(round(quantity)) if math.isfinite(quantity) else None


def resource_sample(postgres, gateway):
    result = {"kind": "resources", "host_pressure": pressure_snapshot()}
    try:
        loads = os.getloadavg()
        result["host_load_average"] = [value if math.isfinite(value) and 0 <= value <= 1e9 else None for value in loads]
    except OSError:
        result["host_load_average"] = None
    template = '{"name":{{json .Name}},"cpu":{{json .CPUPerc}},"memory":{{json .MemUsage}},"block_io":{{json .BlockIO}},"pids":{{json .PIDs}}}'
    status, output = capture(["docker", "stats", "--no-stream", "--format", template, postgres, gateway], limit=4096)
    result["docker_status"] = status
    result["containers"] = {}
    if status != "ok":
        return result
    roles = {postgres: "postgres", gateway: "gateway"}
    try:
        for line in output.splitlines():
            row = json.loads(line)
            role = roles.get(row.get("name"))
            if role is None:
                continue
            cpu = row.get("cpu")
            cpu_match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)%", cpu) if isinstance(cpu, str) else None
            cpu_percent = float(cpu_match[1]) if cpu_match else None
            memory = row.get("memory", "").split(" / ")
            block = row.get("block_io", "").split(" / ")
            pids = row.get("pids")
            result["containers"][role] = {
                "cpu_percent": cpu_percent if cpu_percent is not None and math.isfinite(cpu_percent) and cpu_percent <= 1e6 else None,
                "memory_used_bytes_approximate": byte_quantity(memory[0]) if len(memory) == 2 else None,
                "memory_limit_bytes_approximate": byte_quantity(memory[1]) if len(memory) == 2 else None,
                "block_read_bytes_approximate": byte_quantity(block[0]) if len(block) == 2 else None,
                "block_write_bytes_approximate": byte_quantity(block[1]) if len(block) == 2 else None,
                "pids": integer(int(pids)) if isinstance(pids, str) and re.fullmatch(r"[0-9]{1,10}", pids) else None,
            }
    except (ValueError, AttributeError, TypeError):
        result["docker_status"] = "invalid_response"
        result["containers"] = {}
    return result


def process_memory_sample(tools_runner):
    """Same-UID read in the existing runner's gateway PID namespace, no privilege."""
    started = time.monotonic()
    arguments = ["docker", "exec", "--user", "65532:65532", tools_runner,
                 "timeout", "-s", "KILL", "2", "awk", PROCESS_MEMORY_AWK]
    status, output = capture(arguments, limit=PROCESS_MEMORY_CAPTURE_BYTES, timeout=3)
    result = {"kind": "process_memory", "status": status, "advisory_only": True,
              "smaps_read_can_add_sampling_overhead": True,
              "thp_controls_are_metadata_not_causal_proof": True}
    if status == "ok":
        try:
            # Strict second boundary: even a malicious dependency cannot append
            # unknown keys, raw mappings, strings, or duplicate observations.
            fields = {}
            for line in output.decode("ascii").splitlines():
                parts = line.split(" ")
                if len(parts) != 2 or not parts[0] or parts[0] in fields:
                    raise ValueError("invalid process diagnostics")
                fields[parts[0]] = parts[1]
            allowed = set(PROCESS_MEMORY_FIELDS) | THP_INTEGER_FIELDS | {"enabled", "defrag", "schema", "complete"}
            if set(fields) - allowed or fields.pop("schema", None) != "1" or fields.pop("complete", None) != "1":
                raise ValueError("invalid process diagnostics")
            metrics = {"smaps_rollup": {}, "status": {}}
            for key, (group, field) in PROCESS_MEMORY_FIELDS.items():
                raw = fields.get(key)
                number = int(raw) if isinstance(raw, str) and re.fullmatch(r"[0-9]{1,19}", raw) else None
                metrics[group][field] = integer(number * 1024) if number is not None else None
            thp = {}
            for key in sorted(THP_INTEGER_FIELDS):
                raw = fields.get(key)
                thp[key] = integer(int(raw)) if isinstance(raw, str) and re.fullmatch(r"[0-9]{1,19}", raw) else None
            thp["enabled"] = fields.get("enabled") if fields.get("enabled") in THP_ENABLED else None
            thp["defrag"] = fields.get("defrag") if fields.get("defrag") in THP_DEFRAG else None
            result["metrics"], result["host_thp_controls"] = metrics, thp
            values = [value for group in metrics.values() for value in group.values()] + list(thp.values())
            result["status"] = "ok" if all(value is not None for value in values) else "partial" if any(value is not None for value in values) else "unavailable"
        except (ValueError, UnicodeError):
            result["status"] = "invalid_response"
    result["duration_ms"] = round((time.monotonic()-started)*1000)
    return result


PG_ERROR_PREFIX = re.compile(rb"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ [A-Za-z0-9+:/-]+ \[[0-9]+\] )?(?:ERROR|FATAL):\s+")
PG_ERROR_LABELS = {
    b"deadlock detected": "deadlock_detected",
    b"could not serialize access": "serialization_failure",
    b"canceling statement due to statement timeout": "statement_timeout",
    b"canceling statement due to lock timeout": "lock_timeout",
    b"canceling statement due to user request": "cancel_requested",
    b"remaining connection slots are reserved": "connection_slots_reserved",
    b"sorry, too many clients already": "too_many_connections",
    b"out of shared memory": "out_of_shared_memory",
    b"could not write": "write_failed",
    b"could not fsync": "fsync_failed",
    b"duplicate key value violates unique constraint": "duplicate_key",
}


def postgres_error_labels(postgres):
    status, output = capture(["docker", "logs", "--tail", "2000", postgres], limit=MAXIMUM_LOG_BYTES)
    counts = {}
    for line in output.splitlines():
        match = PG_ERROR_PREFIX.match(line)
        if match is None:
            continue
        message = line[match.end():]
        category = next((category for prefix, category in PG_ERROR_LABELS.items() if message.startswith(prefix)), "other_error")
        counts[category] = counts.get(category, 0) + 1
    return {"kind": "postgres_error_labels", "status": status,
            "tail_lines_limit": 2000, "capture_bytes_limit": MAXIMUM_LOG_BYTES, "counts": counts}


def write_record(writer, record):
    record["at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    encoded = json.dumps(record, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > MAXIMUM_RECORD_BYTES:
        encoded = '{"kind":"collector","status":"record_too_large"}'
    writer.write(encoded + "\n")
    writer.flush()


def collect(writer, postgres, gateway, stop_file, pool_maximum, regular_pool_maximum,
            completion_pool_maximum, *, tools_runner=None, maximum_seconds=MAXIMUM_SECONDS):
    write_record(writer, host_metadata(pool_maximum, regular_pool_maximum, completion_pool_maximum))
    deadline = time.monotonic() + maximum_seconds
    index = 0
    while time.monotonic() < deadline and not stop_file.exists():
        write_record(writer, database_sample(postgres))
        if index % LIFECYCLE_EVERY == 0:
            write_record(writer, database_sample(postgres, lifecycle=True))
            write_record(writer, resource_sample(postgres, gateway))
            if tools_runner is not None and time.monotonic() < deadline and not stop_file.exists():
                # smaps walks page tables: never sample it at the 5s SQL cadence.
                write_record(writer, process_memory_sample(tools_runner))
        index += 1
        until = min(deadline, time.monotonic() + INTERVAL_SECONDS)
        while time.monotonic() < until and not stop_file.exists():
            time.sleep(min(0.1, max(0, until-time.monotonic())))
    # Final lifecycle counts are read before the shell removes the fixture.
    write_record(writer, database_sample(postgres, lifecycle=True))
    write_record(writer, postgres_error_labels(postgres))
    write_record(writer, {"kind": "collector", "status": "stopped" if stop_file.exists() else "time_bound_reached",
                          "activity_samples": index})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres", required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--tools-runner", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--pool-max-connections", type=int, required=True)
    parser.add_argument("--regular-pool-max-connections", type=int, required=True)
    parser.add_argument("--completion-pool-max-connections", type=int, required=True)
    args = parser.parse_args()
    if (not re.fullmatch(r"latchway-load-postgres-[0-9]+-[0-9]{14}", args.postgres)
            or not re.fullmatch(r"latchway-load-gateway-[0-9]+-[0-9]{14}", args.gateway)
            or args.tools_runner != "latchway-load-runner-" + args.postgres.removeprefix("latchway-load-postgres-")
            or args.gateway != "latchway-load-gateway-" + args.postgres.removeprefix("latchway-load-postgres-")
            or not args.output.is_absolute() or not args.stop_file.is_absolute()
            or not valid_pool_partition(
                args.pool_max_connections,
                args.regular_pool_max_connections,
                args.completion_pool_max_connections,
            )):
        return 2
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as writer:
            collect(
                writer, args.postgres, args.gateway, args.stop_file,
                args.pool_max_connections, args.regular_pool_max_connections,
                args.completion_pool_max_connections, tools_runner=args.tools_runner,
            )
    except (OSError, ValueError):
        # The launcher retains the gate status and records a fixed unavailable
        # marker. Never copy dependency exceptions, argv or environment values.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
