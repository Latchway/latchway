#!/usr/bin/env python3
"""One fixed GitHub-native-AMD64 advisory sample; never release evidence.

Only --run creates this run's labeled disposable Docker resources. --cleanup
rechecks its bounded non-secret ownership ledger and removes only those targets.
No existing database/container is adopted. Credentials stay in process memory and
Docker environment, never argv, logs, host files, or retained artifacts.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

BASE = "568f4f6950acec79c65ca59b3f829d7612242a11"
PG_IMAGE = "docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
LABEL = "dev.latchway.native-amd64-diagnostic"
DIRECTORY = "tests/diagnostics/native-amd64/"
FILES = tuple(DIRECTORY + name for name in ("Dockerfile", "run.py", "test_run.py", "README.md",
                                          "advisory_sql_profile_test.go.in", "advisory_database_test.go.in"))
WORKFLOW = ".github/workflows/native-amd64-diagnostic.yml"
ALLOWED = {*FILES, WORKFLOW, "docs/implementation/STATUS.md"}
CGROUP = {"usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec"}
MAX_OUTPUT = 2 * 1024 * 1024


class Stopped(Exception):
    pass


def need(value, code):
    if not value:
        raise Stopped(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def strict_json(raw):
    need(type(raw) is bytes and len(raw) <= MAX_OUTPUT, "JSON_SIZE")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "JSON_DUPLICATE")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Stopped("JSON_NONFINITE")))
    except Exception:
        raise Stopped("JSON_INVALID") from None


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def integer(value, maximum=10**15):
    return type(value) is int and 0 <= value <= maximum


def numeric(value, maximum=10**15):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def numeric_id(value):
    if not matches(value, r"0|-?[1-9][0-9]{0,18}"):
        return False
    return -(2**63) <= int(value) < 2**63


def bounded(argv, *, env=None, timeout=15, maximum=MAX_OUTPUT, cwd=None, accepted=(0,), discard=False):
    """Drain bounded stdout, discard stderr, terminate only this child process group."""
    process = None
    selector = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL if discard else subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        selector = selectors.DefaultSelector()
        if process.stdout is not None:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
        while process.poll() is None or selector.get_map():
            need(time.monotonic() < deadline, "CHILD_TIMEOUT")
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    need(len(output) + len(chunk) <= maximum, "CHILD_OUTPUT_BOUND")
                    output.extend(chunk)
            if not selector.get_map() and process.poll() is None:
                time.sleep(0.02)
        need(process.returncode in accepted, "CHILD_FAILED")
        return process.returncode, bytes(output)
    except Stopped:
        failure = sys.exc_info()[1]
        failure.captured = bytes(output)
        raise
    except BaseException:
        raise Stopped("CHILD_INTERRUPTED") from None
    finally:
        cleanup_failed = False
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        cleanup_failed = True
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except BaseException:
                    cleanup_failed = True
        if selector is not None:
            try:
                selector.close()
            except BaseException:
                cleanup_failed = True
        if cleanup_failed:
            raise Stopped("CHILD_CLEANUP_UNCONFIRMED") from None


def fixed_context(environment):
    required = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Latchway/latchway",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                "GITHUB_RUN_ATTEMPT": "1", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
    need(all(environment.get(k) == v for k, v in required.items()), "GITHUB_CONTEXT")
    need(matches(environment.get("GITHUB_RUN_ID"), r"[1-9][0-9]{0,19}"), "RUN_ID")
    need(matches(environment.get("GITHUB_SHA"), r"[0-9a-f]{40}"), "TOOLING_SHA")
    return environment["GITHUB_RUN_ID"] + "-1", environment["GITHUB_SHA"]


def validate_diff(raw):
    need(type(raw) is bytes and len(raw) <= 16384, "SOURCE_DIFF_SIZE")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise Stopped("SOURCE_DIFF_ENCODING") from None
    seen = set()
    for line in lines:
        fields = line.split("\t")
        need(len(fields) == 2 and fields[1] in ALLOWED and fields[1] not in seen, "SOURCE_DIFF_SCOPE")
        need(fields[0] == ("M" if fields[1] == "docs/implementation/STATUS.md" else "A"), "SOURCE_DIFF_KIND")
        seen.add(fields[1])
    need(set(FILES) | {WORKFLOW} <= seen, "DIAGNOSTIC_FILES_REQUIRED")


def validate_profile(value):
    expected = {"schema_version": 1, "advisory_only": True, "source_commit": BASE, "serial_requests": 200,
                "concurrent_requests": 200, "concurrency": 16, "pool_max_connections": 32, "calendar_buckets_per_phase": 4,
                "first_attempt_only": True, "exact_accounting_verified": True, "whole_lifecycle_includes_auth": False,
                "query_timing_is_client_wall": True, "batch_member_execution_time_available": False,
                "prepare_overlaps_query_or_batch": True, "batch_auto_prepare_is_not_reported_by_prepare_tracer": True,
                "warmup_requests_excluded": 16, "observer_overhead_present": True, "release_evidence": False}
    need(type(value) is dict and set(value) == set(expected) | {"phase_wall_ms", "observations", "server_phases"}, "REPORT_FIELDS")
    need(all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()), "REPORT_IDENTITY")
    need(type(value["phase_wall_ms"]) is dict and set(value["phase_wall_ms"]) == {"serial", "concurrent"} and
         all(numeric(v, 120000) for v in value["phase_wall_ms"].values()), "PHASE_WALL")
    observations = value["observations"]
    need(type(observations) is list and 1 <= len(observations) <= 512, "OBSERVATION_BOUND")
    labels = {"materialize_quota_bucket", "find_quota_bucket_id", "lock_quota_bucket", "reserve_calendar_bucket", "insert_quota_reservation",
              "insert_quota_reservation_entry", "lock_quota_reservation", "lock_logical_request", "lock_upstream_attempts", "lock_reservation_entries",
              "lock_private_reservation_entries", "lock_shared_reservation_entries_and_buckets", "lock_concurrency_leases", "lock_attempt_quota_entries",
              "count_initial_settlement_usage", "count_attempt_usage", "mark_initial_attempt_first_byte", "mark_initial_logical_streaming",
              "settle_initial_calendar_buckets", "settle_initial_reservation_entries", "settle_initial_attempt_quota_entries", "insert_initial_attempt_usage",
              "complete_initial_attempt", "insert_initial_logical_usage", "complete_initial_logical_request", "complete_initial_reservation",
              "transaction_timestamp", "statement_timestamp", "begin_transaction", "commit_transaction", "rollback_transaction", "other_static_sql"}
    labels |= {"cached_" + label for label in tuple(labels)} | {"batch_first_" + label for label in tuple(labels)}
    labels |= {"reserve", "begin", "mark", "settle", "lifecycle", "pool_acquire", "other_batch"}
    for item in observations:
        timed = {"total_ms", "mean_ms", "p50_ms", "p95_ms", "max_ms"}
        required = {"phase", "stage", "category", "label", "count", "errors", "no_rows"}
        need(type(item) is dict and required <= set(item) <= required | timed | {"sql_hash"}, "OBSERVATION_FIELDS")
        need(item["phase"] in ("serial", "concurrent") and item["stage"] in ("reserve", "begin", "mark", "settle", "lifecycle") and
             item["category"] in ("stage_inclusive", "query", "batch", "pool_acquire", "prepare_inclusive_overlap", "batch_member_count_only", "batch_queued_count_only") and
             type(item["label"]) is str and item["label"] in labels, "OBSERVATION_ENUM")
        need(all(integer(item[k], 10000) for k in ("count", "errors", "no_rows")), "OBSERVATION_COUNT")
        need("sql_hash" not in item or matches(item["sql_hash"], r"[0-9a-f]{64}"), "STATIC_SQL_HASH")
        need(all(numeric(item[k], 120000000) for k in timed & set(item)), "OBSERVATION_TIME")
    phases = value["server_phases"]
    need(type(phases) is list and len(phases) == 2, "SERVER_PHASES")
    for name, phase in zip(("serial", "concurrent"), phases):
        validate_server_phase(phase, name)
    return value


def validate_server_phase(phase, name):
    fields = {"phase", "statements", "lock_samples", "wal_delta", "io_delta", "workload_cgroup_delta", "workload_cgroup_available", "stats_reset_or_evicted"}
    need(type(phase) is dict and set(phase) == fields and phase["phase"] == name and phase["stats_reset_or_evicted"] is False, "SERVER_PHASE_FIELDS")
    statements = phase["statements"]
    need(type(statements) is list and 1 <= len(statements) <= 512, "STATEMENT_BOUND")
    integers = {"calls", "rows", "shared_hit", "shared_read", "shared_dirtied", "shared_written", "temp_read", "temp_written", "wal_records", "wal_fpi", "wal_bytes"}
    decimals = {"execution_ms", "read_ms", "write_ms"}
    seen = set()
    for item in statements:
        need(type(item) is dict and set(item) == integers | decimals | {"query_id", "top_level"}, "STATEMENT_FIELDS")
        need(numeric_id(item["query_id"]) and type(item["top_level"]) is bool and all(integer(item[k]) for k in integers) and
             all(numeric(item[k]) for k in decimals), "STATEMENT_VALUES")
        identity = (item["query_id"], item["top_level"])
        need(identity not in seen, "STATEMENT_DUPLICATE")
        seen.add(identity)
    samples = phase["lock_samples"]
    need(type(samples) is list and len(samples) <= 120, "LOCK_SAMPLE_BOUND")
    for sample in samples:
        need(type(sample) is dict and set(sample) == {"elapsed_ms", "duration_ms", "status", "locks"} and
             integer(sample["elapsed_ms"], 125000) and integer(sample["duration_ms"], 3000) and
             sample["status"] in ("ok", "unavailable") and type(sample["locks"]) is list and len(sample["locks"]) <= 128, "LOCK_SAMPLE_SHAPE")
        need(sample["status"] == "ok" or not sample["locks"], "LOCK_UNAVAILABLE")
        for item in sample["locks"]:
            enums = {"waiter_state": {"active", "idle", "idle in transaction", "other"}, "blocker_state": {"active", "idle", "idle in transaction", "other"},
                     "wait_type": {"Lock", "LWLock", "IO", "Client", "other"}, "wait_event": {"tuple", "transactionid", "WALWrite", "WALInsert", "WalSync", "WalWrite", "ClientRead", "ClientWrite", "other"},
                     "relation_class": {"quota_buckets", "quota_reservations", "quota_reservation_entries", "logical_requests", "upstream_attempts", "upstream_attempt_quota_entries", "concurrency_leases", "usage_records", "session_grants", "installations", "application_users", "none", "other"},
                     "lock_type": {"tuple", "transactionid", "none"}, "lock_mode": {"AccessShareLock", "RowShareLock", "RowExclusiveLock", "ShareUpdateExclusiveLock", "ShareLock", "ShareRowExclusiveLock", "ExclusiveLock", "AccessExclusiveLock", "SIReadLock", "none"}}
            need(type(item) is dict and set(item) == set(enums) | {"waiter_query_id", "blocker_query_id", "granted", "connections", "waiter_age_ms", "blocker_age_ms"}, "LOCK_FIELDS")
            need(all(type(item[k]) is str and item[k] in allowed for k, allowed in enums.items()) and numeric_id(item["waiter_query_id"]) and
                 numeric_id(item["blocker_query_id"]) and type(item["granted"]) is bool and integer(item["connections"], 32) and item["connections"] >= 1 and
                 numeric(item["waiter_age_ms"]) and numeric(item["blocker_age_ms"]), "LOCK_VALUES")
    need(type(phase["wal_delta"]) is list and len(phase["wal_delta"]) == 4 and all(integer(v) for v in phase["wal_delta"]), "WAL_VALUES")
    need(type(phase["io_delta"]) is list and len(phase["io_delta"]) == 8 and all(numeric(v) for v in phase["io_delta"]), "IO_VALUES")
    available, counters = phase["workload_cgroup_available"], phase["workload_cgroup_delta"]
    need(type(available) is bool and type(counters) is dict and set(counters) == (CGROUP if available else set()) and
         all(integer(v) for v in counters.values()), "CGROUP_VALUES")


def extract_report(raw):
    prefix = b"ADVISORY_SQL_PROFILE="
    matches_ = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    need(len(matches_) == 1, "SINGLE_REPORT_REQUIRED")
    return validate_profile(strict_json(matches_[0]))


def extract_progress(raw):
    result = []
    for line in raw.splitlines():
        if not line.startswith(b"ADVISORY_PROGRESS="):
            continue
        try:
            item = strict_json(line[len(b"ADVISORY_PROGRESS="):])
            need(type(item) is dict and set(item) == {"phase", "event", "completed", "failed"}, "PROGRESS_FIELDS")
            need(item["phase"] in ("setup", "warmup", "serial", "concurrent") and
                 item["event"] in ("started", "work_complete", "snapshot_complete", "accounting_verified") and
                 integer(item["completed"], 200) and integer(item["failed"], 200), "PROGRESS_VALUES")
            if len(result) < 16:
                result.append(item)
        except (Stopped, KeyError, TypeError):
            continue
    return result


def atomic_json(path, value, exclusive=False):
    encoded = canonical(value) + b"\n"
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    else:
        temporary = path.with_suffix(".next")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Runner:
    def __init__(self, environment):
        self.owner, self.tooling = fixed_context(environment)
        need(platform.system() == "Linux" and platform.machine() == "x86_64", "NATIVE_AMD64_REQUIRED")
        self.repo = Path(__file__).resolve().parents[3]
        temporary = Path(environment["RUNNER_TEMP"]).resolve()
        need(temporary.is_dir() and not temporary.is_symlink(), "RUNNER_TEMP")
        self.root = temporary / ("latchway-native-amd64-" + self.owner)
        self.paths = {"network": "lw-amd64-" + self.owner, "postgres": "lw-amd64-" + self.owner + "-pg",
                      "tools": "lw-amd64-" + self.owner + "-tools", "image": "latchway-amd64-diagnostic:" + self.owner,
                      "volume": "lw-amd64-" + self.owner + "-data"}
        self.env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
        self.ledger = None

    def call(self, argv, **kwargs):
        return bounded(argv, env=kwargs.pop("env", self.env), **kwargs)

    def inspect(self, key):
        formats = {"volume": '{"id":{{json .Name}},"labels":{{json .Labels}},"created":{{json .CreatedAt}}}',
                   "network": '{"id":{{json .Id}},"labels":{{json .Labels}},"internal":{{json .Internal}}}',
                   "image": '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"architecture":{{json .Architecture}},"os":{{json .Os}}}',
                   "postgres": '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"image":{{json .Config.Image}},"running":{{json .State.Running}},"nano_cpus":{{json .HostConfig.NanoCpus}},"memory":{{json .HostConfig.Memory}},"swap":{{json .HostConfig.MemorySwap}},"ports":{{json .HostConfig.PortBindings}},"network":{{json .HostConfig.NetworkMode}},"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"pids_limit":{{json .HostConfig.PidsLimit}}}',
                   "tools": '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"image":{{json .Config.Image}},"running":{{json .State.Running}},"nano_cpus":{{json .HostConfig.NanoCpus}},"memory":{{json .HostConfig.Memory}},"swap":{{json .HostConfig.MemorySwap}},"ports":{{json .HostConfig.PortBindings}},"network":{{json .HostConfig.NetworkMode}},"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"pids_limit":{{json .HostConfig.PidsLimit}}}'}
        kind = key if key in ("network", "image", "volume") else "container"
        code, raw = self.call(["docker", kind, "inspect", "--format", formats[key], self.paths[key]], accepted=(0, 1))
        if code == 1:
            # Independently confirm the exact target is absent, not merely that
            # inspect failed. No project/daemon-wide inventory is requested.
            filter_value = "reference=" + self.paths[key] if key == "image" else "name=^" + ("/" if kind == "container" else "") + self.paths[key] + "$"
            command = ["docker", kind, "ls", "--filter", filter_value, "--format", "{{.ID}}" if kind != "volume" else "{{.Name}}"]
            if kind == "container":
                command.append("--all")
            need(self.call(command, maximum=256)[1].strip() == b"", "TARGET_ABSENCE_UNCONFIRMED")
            return None
        result = strict_json(raw)
        need(type(result) is dict and type(result.get("labels")) is dict and result["labels"].get(LABEL) == self.owner and
             (result.get("id") == self.paths[key] if key == "volume" else matches(result.get("id"), r"(?:sha256:)?[0-9a-f]{64}")), "OWNED_IDENTITY_REQUIRED")
        if key == "volume":
            need(matches(result.get("created"), r"[0-9T:.+Z-]{20,40}"), "VOLUME_CREATION_IDENTITY")
            # Docker volumes have no separate immutable UID. Bind the fresh
            # exact name AND provider creation timestamp in the receipt.
            result["id"] = hashlib.sha256((result["id"] + "\n" + result["created"]).encode("ascii")).hexdigest()
        elif key == "network":
            need(result["internal"] is True, "NETWORK_NOT_INTERNAL")
        elif key == "image":
            need(result["architecture"] == "amd64" and result["os"] == "linux" and
                 result["labels"].get("dev.latchway.native-amd64-tooling") == self.tooling, "IMAGE_PROVENANCE")
        else:
            cpu, memory, image = (4, 4, PG_IMAGE) if key == "postgres" else (2, 2, self.paths["image"])
            need(result["nano_cpus"] == cpu * 10**9 and result["memory"] == memory * 1024**3 and result["swap"] == memory * 1024**3 and
                 result["image"] == image and result["ports"] in ({}, None) and result["network"] == self.paths["network"] and
                 result["privileged"] is False and result["readonly"] is (key == "tools") and result["pids_limit"] == (256 if key == "postgres" else 128), "CONTAINER_SCOPE")
        return result

    def save(self):
        atomic_json(self.root / "ownership.json", self.ledger)

    def intent(self, key):
        need(key not in self.ledger["intents"], "RESOURCE_NO_REPEAT")
        self.ledger["intents"].append(key); self.save()

    def observed(self, key):
        result = self.inspect(key)
        need(result is not None, "CREATED_TARGET_NOT_OBSERVED")
        self.ledger["ids"][key] = result["id"]; self.save()

    def cleanup(self):
        results = {}
        for key in ("tools", "postgres", "volume", "image", "network"):
            if key not in self.ledger["intents"]:
                results[key] = "not_created"; continue
            try:
                current = self.inspect(key)
                if current is None:
                    results[key] = "absent"; continue
                saved = self.ledger["ids"].get(key)
                need(saved is None or saved == current["id"], "CLEANUP_IDENTITY_CHANGED")
                if saved is None:
                    # Unique run/attempt name, durable absent-before + intent, exact
                    # labels/caps/provenance; persist reconciled identity first.
                    self.ledger["ids"][key] = current["id"]; self.save()
                if key in ("tools", "postgres"):
                    self.call(["docker", "container", "rm", "--force", "--volumes", current["id"]], timeout=20)
                elif key == "volume":
                    self.call(["docker", "volume", "rm", self.paths[key]], timeout=20)
                else:
                    self.call(["docker", key, "rm", current["id"]], timeout=20)
                need(self.inspect(key) is None, "CLEANUP_ABSENCE_UNCONFIRMED")
                results[key] = "removed_and_absent"
            except BaseException:
                results[key] = "unresolved"
        complete = all(v != "unresolved" for v in results.values())
        atomic_json(self.root / "cleanup.json", {"schema_version": 1, "advisory_only": True, "source_commit": BASE,
                    "tooling_commit": self.tooling, "owner": self.owner, "targets": results, "cleanup_verified": complete})
        return complete

    def run(self):
        self.root.mkdir(mode=0o700)
        atomic_json(self.root / "started.json", {"source_commit": BASE, "tooling_commit": self.tooling, "owner": self.owner}, exclusive=True)
        self.ledger = {"schema_version": 1, "owner": self.owner, "source_commit": BASE, "tooling_commit": self.tooling,
                       "names": self.paths, "absent_before": [], "intents": [], "ids": {}}
        atomic_json(self.root / "ownership.json", self.ledger, exclusive=True)
        complete, outcome, stage, raw = False, "DIAGNOSTIC_STOPPED", "source_proof", b""
        try:
            need(self.call(["git", "rev-parse", "HEAD"], cwd=self.repo)[1].decode().strip() == self.tooling, "TOOLING_CHECKOUT")
            self.call(["git", "diff", "--exit-code", "HEAD"], cwd=self.repo)
            validate_diff(self.call(["git", "diff", "--name-status", "--no-renames", BASE, self.tooling], cwd=self.repo)[1])
            remote = self.call(["git", "ls-remote", "--exit-code", "https://github.com/Latchway/latchway.git", "refs/heads/main"], timeout=20)[1]
            need(remote.decode().strip() == self.tooling + "\trefs/heads/main", "MAIN_MOVED")
            docker = strict_json(self.call(["docker", "info", "--format", '{"cpu":{{json .NCPU}},"arch":{{json .Architecture}},"os":{{json .OSType}}}'])[1])
            need(docker == {"cpu": 4, "arch": "x86_64", "os": "linux"}, "NATIVE_DOCKER_SCOPE")
            for key in self.paths:
                need(self.inspect(key) is None, "PREEXISTING_TARGET")
                self.ledger["absent_before"].append(key); self.save()
            source = self.root / "source"
            self.call(["git", "clone", "--no-hardlinks", "--no-checkout", str(self.repo), str(source)], timeout=60)
            self.call(["git", "checkout", "--detach", BASE], cwd=source)
            need(self.call(["git", "rev-parse", "HEAD"], cwd=source)[1].decode().strip() == BASE, "SOURCE_CHECKOUT")
            self.call(["git", "diff", "--exit-code", "HEAD"], cwd=source)
            for name in ("advisory_sql_profile_test.go", "advisory_database_test.go"):
                raw = (self.repo / DIRECTORY / (name + ".in")).read_bytes()
                need(0 < len(raw) <= 65536, "TEMPLATE_SIZE")
                target = source / "internal/quota" / name
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
            self.intent("image")
            stage = "image_build"
            self.call(["docker", "build", "--platform=linux/amd64", "--file", str(self.repo / DIRECTORY / "Dockerfile"),
                       "--build-arg", "DIAGNOSTIC_OWNER=" + self.owner, "--build-arg", "TOOLING_COMMIT=" + self.tooling,
                       "--tag", self.paths["image"], str(source)], timeout=600, discard=True)
            self.observed("image")
            stage = "fixture_creation"
            self.call(["docker", "pull", "--platform=linux/amd64", PG_IMAGE], timeout=180, discard=True)
            self.intent("network")
            self.call(["docker", "network", "create", "--internal", "--label", LABEL + "=" + self.owner, self.paths["network"]])
            self.observed("network")
            self.intent("volume")
            self.call(["docker", "volume", "create", "--label", LABEL + "=" + self.owner, self.paths["volume"]])
            self.observed("volume")
            password = secrets.token_urlsafe(36)
            pg_env = {**self.env, "POSTGRES_PASSWORD": password}
            self.intent("postgres")
            self.call(["docker", "create", "--platform=linux/amd64", "--name", self.paths["postgres"], "--label", LABEL + "=" + self.owner,
                       "--network", self.paths["network"], "--network-alias", "postgres", "--cpus=4", "--memory=4g", "--memory-swap=4g", "--pids-limit=256",
                       "--mount", "type=volume,src=" + self.paths["volume"] + ",dst=/var/lib/postgresql",
                       "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER=latchway", "--env", "POSTGRES_DB=latchway", PG_IMAGE,
                       "postgres", "-c", "max_connections=100", "-c", "shared_preload_libraries=pg_stat_statements", "-c", "compute_query_id=on",
                       "-c", "pg_stat_statements.track=all", "-c", "pg_stat_statements.track_utility=off", "-c", "pg_stat_statements.save=off",
                       "-c", "track_io_timing=on", "-c", "track_wal_io_timing=on", "-c", "log_statement=none", "-c", "log_min_error_statement=panic"], env=pg_env)
            del pg_env
            self.observed("postgres")
            self.call(["docker", "start", self.paths["postgres"]])
            ready_env = {**self.env, "PGPASSWORD": password}
            stage = "database_readiness"
            ready = False
            for _ in range(60):
                code, raw = self.call(["docker", "exec", "--env", "PGPASSWORD", self.paths["postgres"], "psql", "--host=127.0.0.1", "--username=latchway",
                                      "--dbname=latchway", "--no-psqlrc", "--tuples-only", "--no-align", "--command", "SELECT 1"], env=ready_env, accepted=(0, 1, 2), timeout=3, maximum=128)
                if code == 0 and raw.strip() == b"1":
                    ready = True; break
                time.sleep(1)
            del ready_env
            need(ready, "DATABASE_NOT_READY")
            self.intent("tools")
            stage = "workload_creation"
            tools_env = {**self.env, "LATCHWAY_TEST_DATABASE_URL": "postgres://latchway:" + password + "@postgres:5432/latchway?sslmode=disable"}
            del password
            self.call(["docker", "create", "--platform=linux/amd64", "--name", self.paths["tools"], "--label", LABEL + "=" + self.owner,
                       "--network", self.paths["network"], "--cpus=2", "--memory=2g", "--memory-swap=2g", "--pids-limit=128", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                       "--env", "LATCHWAY_TEST_DATABASE_URL", "--env", "LATCHWAY_ADVISORY_SQL_PROFILE=1", "--env", "LATCHWAY_ADVISORY_SOURCE_COMMIT=" + BASE,
                       self.paths["image"], "-test.run=^TestAdvisoryQuotaSQLProfile$", "-test.count=1", "-test.timeout=140s", "-test.v"], env=tools_env)
            del tools_env
            self.observed("tools")
            atomic_json(self.root / "environment.json", {"schema_version": 1, "advisory_only": True, "release_evidence": False,
                        "source_commit": BASE, "tooling_commit": self.tooling, "owner": self.owner, "native_architecture": "amd64", "os": "linux",
                        "host_cpu_count": 4, "postgres_image": PG_IMAGE, "postgres_cpu": 4, "postgres_memory_bytes": 4 * 1024**3,
                        "workload_cpu": 2, "workload_memory_bytes": 2 * 1024**3, "pool_max_connections": 32,
                        "postgres_max_connections": 100, "internal_network": True, "published_ports": False,
                        "measurement_settings": {"pg_stat_statements": True, "track_io_timing": True, "track_wal_io_timing": True,
                                                 "observer_session_tracking": False, "initial_statement_reset_after_warmup": True}})
            stage = "profile"
            code, raw = self.call(["docker", "start", "--attach", self.paths["tools"]], timeout=155, accepted=(0, 1, 2))
            need(code == 0, "PROFILE_FAILED")
            report = extract_report(raw)
            raw = b""
            report["tooling_commit"] = self.tooling
            report["profiler_sha256"] = hashlib.sha256((self.repo / DIRECTORY / "advisory_sql_profile_test.go.in").read_bytes()).hexdigest()
            report["observer_sha256"] = hashlib.sha256((self.repo / DIRECTORY / "advisory_database_test.go.in").read_bytes()).hexdigest()
            atomic_json(self.root / "report.json", report, exclusive=True)
            outcome = "ADVISORY_SAMPLE_COMPLETE_NOT_RELEASE_EVIDENCE"
        except BaseException as error:
            outcome = "ADVISORY_SAMPLE_STOPPED_REDACTED_NO_REPEAT"
            captured = getattr(error, "captured", raw)
            atomic_json(self.root / "failure.json", {"schema_version": 1, "advisory_only": True, "release_evidence": False,
                        "source_commit": BASE, "tooling_commit": self.tooling, "stage": stage, "status": "stopped_no_repeat",
                        "progress": extract_progress(captured if type(captured) is bytes else b"")})
        finally:
            complete = self.cleanup()
        print(json.dumps({"status": outcome, "cleanup_verified": complete, "advisory_only": True, "source_commit": BASE, "tooling_commit": self.tooling}))
        return 0 if complete and outcome == "ADVISORY_SAMPLE_COMPLETE_NOT_RELEASE_EVIDENCE" else 2

    def cleanup_only(self):
        info = self.root.lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(), "LEDGER_DIRECTORY")
        path = self.root / "ownership.json"
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and info.st_size <= 16384, "LEDGER_FILE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            need(opened.st_ino == info.st_ino and opened.st_dev == info.st_dev, "LEDGER_CHANGED")
            value = strict_json(stream.read(16385))
        need(type(value) is dict and set(value) == {"schema_version", "owner", "source_commit", "tooling_commit", "names", "absent_before", "intents", "ids"} and
             value["schema_version"] == 1 and value["owner"] == self.owner and value["source_commit"] == BASE and value["tooling_commit"] == self.tooling and value["names"] == self.paths,
             "LEDGER_SCOPE")
        need(type(value["absent_before"]) is list and type(value["intents"]) is list and type(value["ids"]) is dict and
             len(set(value["absent_before"])) == len(value["absent_before"]) and set(value["absent_before"]) <= set(self.paths) and
             len(set(value["intents"])) == len(value["intents"]) and set(value["intents"]) <= set(value["absent_before"]) and
             set(value["ids"]) <= set(value["intents"]) and all(matches(v, r"(?:sha256:)?[0-9a-f]{64}") for v in value["ids"].values()), "LEDGER_TARGETS")
        self.ledger = value
        complete = self.cleanup()
        print(json.dumps({"status": "OWNED_CLEANUP_CHECKED", "cleanup_verified": complete, "advisory_only": True}))
        return 0 if complete else 2


def main():
    need(sys.argv[1:] in (["--run"], ["--cleanup"]), "EXPLICIT_MODE_REQUIRED")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def stop(signum, frame):
        raise Stopped("INTERRUPTED")
    signal.signal(signal.SIGTERM, stop)
    runner = Runner(os.environ)
    return runner.run() if sys.argv[1] == "--run" else runner.cleanup_only()


if __name__ == "__main__":
    try:
        result = main()
    except BaseException:
        print('{"status":"ADVISORY_STOPPED_REDACTED"}')
        result = 2
    sys.exit(result)
