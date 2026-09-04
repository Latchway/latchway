#!/usr/bin/env python3
"""Fixed two-arm actual-gateway diagnostic. No release claim or automatic repeats."""
import base64
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[3]
NATIVE = REPO / "tests/diagnostics/native-amd64/run.py"
NATIVE_SHA = "bd0e73a18faceb643a0aa921324f2e02f04786415a45118308f86b3ee06b6086"
if hashlib.sha256(NATIVE.read_bytes()).hexdigest() != NATIVE_SHA:
    raise RuntimeError("NATIVE_HELPER_CHANGED")
SPEC = importlib.util.spec_from_file_location("reviewed_native_helper", NATIVE)
n = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(n)
COLLECTOR_SPEC = importlib.util.spec_from_file_location("private_memory_collector", Path(__file__).with_name("collector.py"))
c = importlib.util.module_from_spec(COLLECTOR_SPEC)
COLLECTOR_SPEC.loader.exec_module(c)
BASE = n.BASE
DIRECTORY = "tests/diagnostics/native-amd64-thp/"
FILES = tuple(DIRECTORY + name for name in ("run.py", "test_run.py", "collector.py", "README.md", "advisory_memory.go.in", "advisory_memory_test.go.in"))
LABEL = "dev.latchway.sse-thp-pair"
MODE = "preflight,idle,overhead,nonstream,streams"
ARM_SECONDS = 450
TOTAL_SECONDS = 1500
CLEANUP_SECONDS = 120
CHILD_STOP_RESERVE = 5
SUBNET = "10.239.170.0/24"
PG_IP = "10.239.170.20"
FIXTURE_IP = "10.239.170.10"
GATES = ("preflight", "idle_memory", "gateway_overhead", "non_stream_100_rps", "sse_500_concurrent_memory")
DB_POOL_MAX_CONNECTIONS = 32
DB_REGULAR_POOL_MAX_CONNECTIONS = 24
DB_COMPLETION_POOL_MAX_CONNECTIONS = 8
if DB_REGULAR_POOL_MAX_CONNECTIONS != DB_POOL_MAX_CONNECTIONS - DB_COMPLETION_POOL_MAX_CONNECTIONS:
    raise RuntimeError("DB_POOL_PARTITION_CHANGED")
RUNTIME_KEYS = {"GODEBUG", "GOGC", "GOMEMLIMIT", "GOMAXPROCS"}
FAILURE_STAGES = {"initialization", "source_identity", "native_host", "source_clone", "sampler_overlay",
                  "gateway_image_build", "gateway_image_validate", "tools_image_build", "tools_image_validate",
                  "postgres_image_pull", "postgres_image_validate", "runtime_environment_inspect", "runtime_environment_parse",
                  "runtime_environment_validate", "A_fixture", "A_load", "B_fixture", "B_load"}
FAILURE_REASONS = {"CHILD_TIMEOUT", "CHILD_OUTPUT_BOUND", "CHILD_FAILED", "CHILD_INTERRUPTED", "CHILD_CLEANUP_UNCONFIRMED",
                   "TOOLING_CHECKOUT", "MAIN_MOVED", "NATIVE_HOST_REQUIRED", "PRODUCT_SOURCE_CHANGED", "DIFF_BOUND", "TOOLING_FILES_MISSING",
                   "OVERLAY_BOUND", "NO_ADOPTION_OR_REPEAT", "CREATE_UNCONFIRMED", "TARGET_OWNERSHIP", "IMAGE_PLATFORM_SOURCE",
                   "SAMPLER_EXACT_ACTIVATION", "ABSENCE_UNCONFIRMED", "TARGET_ID", "VOLUME_IDENTITY", "INTERNAL_NETWORK", "CONTAINER_SCOPE",
                   "FORWARD_DEADLINE", "CLEANUP_DEADLINE", "ARM_HEADROOM_REQUIRED", "RUNTIME_ENV_SHAPE", "BASELINE_ALREADY_DISABLED",
                   "PINNED_POSTGRES_PLATFORM", "ARM_CLEANUP_UNCONFIRMED", "POSTGRES_NOT_READY_OR_CONFIG_CHANGED",
                   "PRECONDITION_INCOMPLETE", "PRECONDITION_WORKLOAD_CHANGED", "HELD_STREAM_OBSERVATION_INCOMPLETE", "HELD_STREAM_SAMPLE_TIMES",
                   "SUBSET_REPORT_IDENTITY", "SUBSET_GATES", "SUBSET_GATE_SHAPE", "SUBSET_METRICS", "SUBSET_NUMERIC", "RSS_SAMPLES",
                   "PRIVATE_FILE_SHAPE", "PRIVATE_FILE_BOUND", "JSON_SIZE", "JSON_INVALID", "INTERRUPTED"}


def failure_receipt(stage, error):
    reason = error.args[0] if isinstance(error, n.Stopped) and len(error.args) == 1 else None
    return {"schema_version": 1, "status": "stopped_no_repeat", "advisory_only": True, "release_evidence": False,
            "stage": stage if type(stage) is str and stage in FAILURE_STAGES else "unclassified",
            "reason": reason if type(reason) is str and reason in FAILURE_REASONS else "UNCLASSIFIED_REDACTED"}


def parse_runtime_environment(raw):
    n.need(type(raw) is bytes and len(raw) <= 8192, "RUNTIME_ENV_SHAPE")
    try:
        lines = raw.decode("ascii").split("\n")
    except UnicodeError:
        raise n.Stopped("RUNTIME_ENV_SHAPE") from None
    runtime = {}
    for line in lines:
        # Docker appends a newline after the template, including an empty
        # result; println within the template adds per-entry newlines too.
        # Ignore empty lines only. Never strip or reinterpret a setting value.
        if line == "":
            continue
        n.need("=" in line and all(32 <= ord(char) <= 126 for char in line), "RUNTIME_ENV_SHAPE")
        key, value = line.split("=", 1)
        n.need(key in RUNTIME_KEYS and key not in runtime and len(value) <= 4096, "RUNTIME_ENV_SHAPE")
        runtime[key] = value
    return runtime


def timestamp(value):
    return n.matches(value, r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z")


def merge_disable_thp(value):
    n.need(type(value) is str and len(value) <= 4096 and (not value or n.matches(value, r"[A-Za-z0-9_.=,/-]+")), "RUNTIME_ENV_SHAPE")
    parts = value.split(",") if value else []
    n.need(all(part.count("=") == 1 and all(part.split("=")) for part in parts), "RUNTIME_ENV_SHAPE")
    # Preserve every other setting in its original order and value. A baseline
    # already disabling THP is not a meaningful default-vs-disabled comparison.
    n.need(all(part.split("=", 1)[1] == "0" for part in parts if part.startswith("disablethp=")), "BASELINE_ALREADY_DISABLED")
    return ",".join([part for part in parts if not part.startswith("disablethp=")] + ["disablethp=1"])


def validate_source_diff(raw):
    n.need(type(raw) is bytes and len(raw) <= 32768, "DIFF_BOUND")
    allowed = n.ALLOWED | set(FILES) | {".github/workflows/native-amd64-thp.yml"}
    seen = set()
    for line in raw.decode("ascii").splitlines():
        fields = line.split("\t")
        n.need(len(fields) == 2 and fields[1] in allowed and fields[1] not in seen, "PRODUCT_SOURCE_CHANGED")
        n.need(fields[0] == ("M" if fields[1] == "docs/implementation/STATUS.md" else "A"), "PRODUCT_SOURCE_CHANGED")
        seen.add(fields[1])
    n.need(set(FILES) | set(n.FILES) | {n.WORKFLOW} <= seen, "TOOLING_FILES_MISSING")


def private_json(path, maximum=n.MAX_OUTPUT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        n.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size <= maximum, "PRIVATE_FILE_SHAPE")
        raw = stream.read(maximum + 1)
    n.need(len(raw) <= maximum, "PRIVATE_FILE_BOUND")
    return n.strict_json(raw)


def sanitized_load(value):
    n.need(type(value) is dict and value.get("schema_version") == 1 and value.get("kind") == "latchway_load_evidence" and
           value.get("commit") == BASE and value.get("complete_suite") is False and value.get("load_targets_passed") is False, "SUBSET_REPORT_IDENTITY")
    gates = value.get("gates")
    n.need(type(gates) is list and 1 <= len(gates) <= 5, "SUBSET_GATES")
    numeric_fields = {"maximum_rss_mib", "samples", "p50_overhead_ms", "p95_overhead_ms", "p99_overhead_ms", "scheduled", "successful", "failed",
                      "target_rps", "duration_seconds", "maximum_request_start_lag_ms", "maximum_scheduler_lag_ms", "completion_elapsed_seconds",
                      "p50_e2e_ms", "p95_e2e_ms", "p99_e2e_ms", "baseline_rss_mib", "peak_rss_mib", "growth_mib", "established", "target_concurrency",
                      "premature_completions", "hold_seconds", "plateau_slope_mib_per_minute", "growth_target_mib", "slope_target_mib_per_minute"}
    output = []
    for expected, gate in zip(GATES, gates):
        n.need(type(gate) is dict and gate.get("name") == expected and gate.get("status") in ("passed", "failed") and
               n.integer(gate.get("duration_ms"), 900000) and timestamp(gate.get("started_at")), "SUBSET_GATE_SHAPE")
        metrics = gate.get("metrics", {})
        n.need(type(metrics) is dict, "SUBSET_METRICS")
        retained = {key: metrics[key] for key in numeric_fields & set(metrics)}
        n.need(all(n.numeric(abs(v) if key == "plateau_slope_mib_per_minute" and type(v) in (int, float) else v, 10**12)
                   for key, v in retained.items()), "SUBSET_NUMERIC")
        if "rss_samples" in metrics:
            samples = metrics["rss_samples"]
            n.need(type(samples) is list and len(samples) <= 62 and all(type(s) is dict and set(s) == {"At", "MiB"} and
                   timestamp(s["At"]) and n.numeric(s["MiB"], 4096) for s in samples), "RSS_SAMPLES")
            retained["rss_samples"] = samples
        output.append({"name": expected, "status": gate["status"], "started_at": gate["started_at"], "duration_ms": gate["duration_ms"],
                       "error_present": "error" in gate, "metrics": retained})
    return {"schema_version": 1, "advisory_only": True, "release_evidence": False, "source_commit": BASE,
            "complete_suite": False, "load_targets_passed": False, "gates": output}


def memory_observation(path, rss_samples):
    """Closed summary only; availability is separate from workload completion."""
    unavailable = {"complete": False, "status": "unavailable_or_insufficient", "fresh_go_and_os_samples": 0, "span_seconds": 0}
    try:
        start = datetime.datetime.fromisoformat(rss_samples[0]["At"]).timestamp()
        end = datetime.datetime.fromisoformat(rss_samples[-1]["At"]).timestamp()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            n.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size <= 8*1024**2, "MEMORY_FILE_BOUND")
            raw = stream.read(8*1024**2+1)
        n.need(len(raw) <= 8*1024**2 and len(raw.splitlines()) <= 1024, "MEMORY_RECORD_BOUND")
        observations = []
        for line in raw.splitlines():
            n.need(0 < len(line) <= 65536, "MEMORY_RECORD_BOUND")
            record = n.strict_json(line)
            if type(record) is not dict or record.get("kind") != "process_memory": continue
            at = datetime.datetime.fromisoformat(record["at"]).timestamp()
            # OS capture can precede record emission by up to the two 3s
            # captures. Exclude the edge instead of pretending simultaneity.
            if not start+6 <= at <= end: continue
            go = record.get("go_memory", {})
            if type(go) is not dict or go.get("status") != "ok": continue
            validated = c.snapshot(n.canonical(go.get("snapshot")), int(at*10**9))
            if validated["status"] != "ok": continue
            sample = validated["snapshot"]
            if not start*10**9 <= sample["unix_nano"] <= end*10**9: continue
            metrics = record.get("metrics", {})
            n.need(type(metrics) is dict, "MEMORY_METRICS")
            required = {"smaps_rollup": {"rss_bytes", "pss_bytes", "anon_huge_pages_bytes"}, "status": {"vm_rss_bytes", "rss_anon_bytes", "rss_file_bytes"}}
            if any(type(metrics.get(group)) is not dict or not fields <= set(metrics[group]) or
                   not all(n.integer(metrics[group][field], 4*1024**3) for field in fields) for group, fields in required.items()): continue
            controls = record.get("host_thp_controls", {})
            if (type(controls) is not dict or set(controls) != {"enabled", "defrag", "scan_sleep_millisecs", "max_ptes_none"} or
                controls["enabled"] not in c.base.THP_ENABLED or controls["defrag"] not in c.base.THP_DEFRAG or
                not all(n.integer(controls[key]) for key in ("scan_sleep_millisecs", "max_ptes_none"))): continue
            observations.append((at, sample["sequence"], sample["unix_nano"], controls, sample["gogc_percent"], sample["gomemlimit_bytes"]))
        if not observations: return unavailable
        ordered = all(a[0] < b[0] and a[1] < b[1] and a[2] < b[2] for a, b in zip(observations, observations[1:]))
        stable = all(item[3:] == observations[0][3:] for item in observations)
        span = observations[-1][0] - observations[0][0]
        complete = ordered and stable and len(observations) >= 3 and span >= 30
        return {"complete": complete, "status": "observed_not_causal_proof" if complete else "unavailable_or_insufficient",
                "fresh_go_and_os_samples": len(observations), "span_seconds": max(0, span), "host_and_runtime_controls_stable": stable,
                "host_thp_controls": observations[0][3], "gogc_percent": observations[0][4], "gomemlimit_bytes": observations[0][5]}
    except (OSError, ValueError, TypeError, KeyError, IndexError, n.Stopped):
        return unavailable


def stop_child(process):
    if process is None:
        return True
    try:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        return process.poll() is not None
    except BaseException:
        return False


class Runner(n.Runner):
    def __init__(self, environment):
        super().__init__(environment)
        self.root = Path(environment["RUNNER_TEMP"]).resolve() / ("latchway-sse-thp-" + self.owner)
        self.artifacts = self.root / "artifacts"
        self.source = self.root / "private/source"
        self.paths = {"gateway_image": "latchway-sse-thp-gateway:" + self.owner, "tools_image": "latchway-sse-thp-tools:" + self.owner}
        # Names deliberately satisfy the unchanged original collector's scope.
        # Compatibility suffix only, not an observed timestamp. The globally
        # unique GitHub run ID makes exact cleanup names restart-deterministic.
        stamp = "20000101000000"
        for arm, digit in (("A", "0"), ("B", "1")):
            suffix = environment["GITHUB_RUN_ID"] + digit + "-" + stamp
            for kind, prefix in (("network", "network"), ("volume", "data"), ("postgres", "postgres"), ("fixture", "fixture"),
                                 ("gateway", "gateway"), ("provisioner", "provisioner"), ("tools", "runner")):
                self.paths[arm + "_" + kind] = "latchway-load-" + prefix + "-" + suffix
        self.collector = None
        self.stage = "initialization"
        self.collector_stopped = True
        self.lock_fd = None
        self.observations = {}

    def remaining(self, cleanup=False):
        budget = TOTAL_SECONDS - CHILD_STOP_RESERVE if cleanup else TOTAL_SECONDS - CLEANUP_SECONDS
        available = min(self.ledger["t0_wall"] + budget - time.time(), self.ledger["t0_mono"] + budget - time.monotonic())
        n.need(available > 0, "CLEANUP_DEADLINE" if cleanup else "FORWARD_DEADLINE")
        return available

    def lock(self, create=False):
        flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if create else 0)
        fd = os.open(self.root / "producer.lock", flags, 0o600)
        try:
            info = os.fstat(fd)
            n.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and info.st_nlink == 1, "LOCK_SCOPE")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise n.Stopped("PRODUCER_ACTIVE_OR_LOCK_UNAVAILABLE") from None
        self.lock_fd = fd

    def unlock(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def stop_collector(self, arm):
        # No guessed PID recovery. An interrupted spawn/ack window is unknown;
        # cleanup can still remove verified Docker resources independently.
        if self.collector is not None and stop_child(self.collector):
            self.collector = None
            self.ledger["collectors"][arm] = "stopped"
            self.save()
        self.collector_stopped = all(state in ("not_started", "stopped") for state in self.ledger["collectors"].values())

    def call(self, argv, **kwargs):
        cleanup = kwargs.pop("cleanup", False)
        if self.ledger is not None:
            kwargs["timeout"] = min(kwargs.get("timeout", 15), self.remaining(cleanup))
        return n.bounded(argv, env=kwargs.pop("env", self.env), **kwargs)

    def save(self):
        n.atomic_json(self.root / "ownership.json", self.ledger)

    def target(self, key):
        if key.endswith("_image"):
            return None, "image"
        return tuple(key.split("_", 1))

    def inspect(self, key, cleanup=False):
        arm, target = self.target(key)
        kind = target if target in ("network", "volume", "image") else "container"
        formats = {
            "image": '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"arch":{{json .Architecture}},"os":{{json .Os}},"cmd":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}}}',
            "network": '{"id":{{json .Id}},"labels":{{json .Labels}},"internal":{{json .Internal}},"ipam":{{json .IPAM.Config}}}',
            "volume": '{"id":{{json .Name}},"created":{{json .CreatedAt}},"labels":{{json .Labels}},"driver":{{json .Driver}},"options":{{json .Options}}}',
            "container": '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"image":{{json .Image}},"network":{{json .HostConfig.NetworkMode}},"pid_mode":{{json .HostConfig.PidMode}},"cpu":{{json .HostConfig.NanoCpus}},"memory":{{json .HostConfig.Memory}},"swap":{{json .HostConfig.MemorySwap}},"pids":{{json .HostConfig.PidsLimit}},"ports":{{json .HostConfig.PortBindings}},"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"user":{{json .Config.User}}}'
        }
        code, raw = self.call(["docker", kind, "inspect", "--format", formats[kind], self.paths[key]], accepted=(0, 1), timeout=3, cleanup=cleanup)
        if code == 1:
            expression = "reference=" + self.paths[key] if kind == "image" else "name=^" + ("/" if kind == "container" else "") + self.paths[key] + "$"
            args = ["docker", kind, "ls", "--filter", expression, "--format", "{{.Name}}" if kind == "volume" else "{{.ID}}"]
            if kind == "container": args.append("--all")
            n.need(self.call(args, maximum=256, timeout=3, cleanup=cleanup)[1].strip() == b"", "ABSENCE_UNCONFIRMED")
            return None
        value = n.strict_json(raw)
        n.need(type(value) is dict and type(value.get("labels")) is dict and value["labels"].get(LABEL) == self.owner and
               value["labels"].get(LABEL + ".target") == key, "TARGET_OWNERSHIP")
        if kind == "volume":
            n.need(value["id"] == self.paths[key] and n.matches(value["created"], r"[0-9T:.+Z-]{20,40}") and value["driver"] == "local" and value["options"] in (None, {}), "VOLUME_IDENTITY")
            value["id"] = hashlib.sha256((value["id"] + "\n" + value["created"]).encode()).hexdigest()
        else:
            n.need(n.matches(value["id"], r"(?:sha256:)?[0-9a-f]{64}"), "TARGET_ID")
        if kind == "image":
            n.need(value["arch"] == "amd64" and value["os"] == "linux" and value["labels"].get("org.opencontainers.image.revision") == BASE, "IMAGE_PLATFORM_SOURCE")
            if key == "gateway_image":
                n.need(value["cmd"] == ["serve", "--role", "all"] and value["entrypoint"] == ["/latchway"] and value["user"] == "65532:65532", "SAMPLER_EXACT_ACTIVATION")
        elif kind == "network":
            n.need(value["internal"] is True and type(value["ipam"]) is list and len(value["ipam"]) == 1 and value["ipam"][0].get("Subnet") == SUBNET, "INTERNAL_NETWORK")
        elif kind == "container":
            expected_image = self.ledger["ids"].get("gateway_image" if target == "gateway" else "tools_image")
            if target == "postgres": expected_image = self.ledger["postgres_image_id"]
            network = self.paths[arm + "_network"]
            if target in ("tools", "provisioner"):
                network = "container:" + self.ledger["ids"][arm + "_gateway"]
            expected_pid = network if target == "tools" else ""
            cpu, memory, pids = (4, 4, 2048) if target == "postgres" else (2, 2, 4096) if target == "gateway" else (0, 0, 1024) if target == "fixture" else (0, 0, 0)
            user = "" if target == "postgres" else "65532:65532" if target == "gateway" else str(os.getuid()) + ":" + str(os.getgid())
            n.need(value["image"] == expected_image and value["network"] == network and value["pid_mode"] == expected_pid and
                   value["cpu"] == cpu*10**9 and value["memory"] == memory*1024**3 and value["swap"] == memory*1024**3 and
                   value["pids"] in ((None, 0) if pids == 0 else (pids,)) and value["ports"] in (None, {}) and value["privileged"] is False and
                   value["readonly"] is (target != "postgres") and value["user"] == user, "CONTAINER_SCOPE")
        return value

    def intent(self, key):
        self.remaining()
        n.need(key not in self.ledger["intents"] and self.inspect(key) is None, "NO_ADOPTION_OR_REPEAT")
        self.ledger["absent_before"].append(key)
        self.ledger["intents"].append(key)
        self.save()

    def labels(self, key):
        return ["--label", LABEL + "=" + self.owner, "--label", LABEL + ".target=" + key]

    def observe(self, key):
        value = self.inspect(key)
        n.need(value is not None, "CREATE_UNCONFIRMED")
        self.ledger["ids"][key] = value["id"]
        self.save()

    def create(self, key, options, image, arguments=(), environment=None):
        self.intent(key)
        self.call(["docker", "create", "--platform=linux/amd64", "--name", self.paths[key], *self.labels(key), *options, image, *arguments],
                  env=self.env if environment is None else environment, timeout=15, maximum=256)
        self.observe(key)

    def verify_gateway_pool_environment(self, arm):
        expected = (
            "LATCHWAY_DB_MAX_CONNECTIONS=" + str(DB_POOL_MAX_CONNECTIONS),
            "LATCHWAY_DB_COMPLETION_CONNECTIONS=" + str(DB_COMPLETION_POOL_MAX_CONNECTIONS),
        )
        for setting in expected:
            template = '{{range .Config.Env}}{{if eq . "' + setting + '"}}{{println "matched"}}{{end}}{{end}}'
            raw = self.call(
                ["docker", "container", "inspect", "--format", template, self.paths[arm + "_gateway"]],
                maximum=64,
            )[1]
            n.need(raw.strip() == b"matched", "CONTAINER_SCOPE")

    def remove(self, key):
        value = self.inspect(key, cleanup=True)
        if value is None: return "absent"
        n.need(self.ledger["ids"].get(key, value["id"]) == value["id"], "CLEANUP_IDENTITY_CHANGED")
        if key not in self.ledger["ids"]:
            self.ledger["ids"][key] = value["id"]; self.save()
        _, target = self.target(key)
        kind = target if target in ("image", "volume", "network") else "container"
        argument = self.paths[key] if kind == "volume" else value["id"]
        options = ["--force", "--volumes"] if kind == "container" else []
        self.call(["docker", kind, "rm", *options, argument], timeout=5, cleanup=True, maximum=256)
        n.need(self.inspect(key, cleanup=True) is None, "DELETE_UNCONFIRMED")
        return "removed_and_absent"

    def cleanup(self, arm=None):
        keys = []
        for selected in ((arm,) if arm is not None else ("B", "A")):
            keys.extend(selected + "_" + name for name in ("tools", "provisioner", "gateway", "fixture", "postgres", "volume", "network"))
        if arm is None: keys.extend(("tools_image", "gateway_image"))
        results = {}
        for key in keys:
            if key not in self.ledger["intents"]:
                results[key] = "not_created"; continue
            try: results[key] = self.remove(key)
            except BaseException: results[key] = "unresolved"
        complete = self.collector_stopped and all(v != "unresolved" for v in results.values())
        n.atomic_json(self.artifacts / ((arm + "-cleanup.json") if arm else "cleanup.json"),
                      {"schema_version": 1, "advisory_only": True, "targets": results, "collector_stopped": self.collector_stopped, "cleanup_verified": complete})
        return complete

    def prepare(self):
        self.stage = "source_identity"
        n.need(self.call(["git", "rev-parse", "HEAD"], cwd=REPO)[1].decode().strip() == self.tooling, "TOOLING_CHECKOUT")
        self.call(["git", "diff", "--exit-code", "HEAD"], cwd=REPO)
        validate_source_diff(self.call(["git", "diff", "--name-status", "--no-renames", BASE, self.tooling], cwd=REPO)[1])
        remote = self.call(["git", "ls-remote", "--exit-code", "https://github.com/Latchway/latchway.git", "refs/heads/main"], timeout=20)[1]
        n.need(remote.decode().strip() == self.tooling + "\trefs/heads/main", "MAIN_MOVED")
        self.stage = "native_host"
        info = n.strict_json(self.call(["docker", "info", "--format", '{"cpu":{{json .NCPU}},"arch":{{json .Architecture}},"os":{{json .OSType}}}'])[1])
        n.need(info == {"cpu": 4, "arch": "x86_64", "os": "linux"} and os.getuid() != 0, "NATIVE_HOST_REQUIRED")
        self.stage = "source_clone"
        self.call(["git", "clone", "--no-hardlinks", "--no-checkout", str(REPO), str(self.source)], timeout=30)
        self.call(["git", "checkout", "--detach", BASE], cwd=self.source)
        self.call(["git", "diff", "--exit-code", "HEAD"], cwd=self.source)
        self.stage = "sampler_overlay"
        for name in ("advisory_memory.go", "advisory_memory_test.go"):
            raw = (REPO / DIRECTORY / (name + ".in")).read_bytes()
            n.need(0 < len(raw) <= 32768, "OVERLAY_BOUND")
            fd = os.open(self.source / "cmd/latchway" / name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream: stream.write(raw)
        for key, dockerfile, timeout in (("gateway_image", "Dockerfile", 480), ("tools_image", "tests/load/Dockerfile", 180)):
            self.stage = key + "_build"
            self.intent(key)
            self.call(["docker", "build", "--platform=linux/amd64", "--file", str(self.source / dockerfile), "--build-arg", "COMMIT=" + BASE,
                       *self.labels(key), "--tag", self.paths[key], str(self.source)], timeout=timeout, discard=True)
            self.stage = key + "_validate"
            self.observe(key)
        self.stage = "postgres_image_pull"
        self.call(["docker", "pull", "--platform=linux/amd64", n.PG_IMAGE], timeout=120, discard=True)
        self.stage = "postgres_image_validate"
        raw = self.call(["docker", "image", "inspect", "--format", '{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}}}', n.PG_IMAGE])[1]
        info = n.strict_json(raw)
        n.need(info.get("os") == "linux" and info.get("arch") == "amd64" and n.matches(info.get("id"), r"sha256:[0-9a-f]{64}"), "PINNED_POSTGRES_PLATFORM")
        self.ledger["postgres_image_id"] = info["id"]; self.save()
        # Only these four non-secret runtime variables are inspected. Image
        # configuration is otherwise preserved by running the immutable image.
        template = '{{range .Config.Env}}{{$k := index (split . "=") 0}}{{if or (eq $k "GODEBUG") (eq $k "GOGC") (eq $k "GOMEMLIMIT") (eq $k "GOMAXPROCS")}}{{println .}}{{end}}{{end}}'
        self.stage = "runtime_environment_inspect"
        raw = self.call(["docker", "image", "inspect", "--format", template, self.ledger["ids"]["gateway_image"]], maximum=8192)[1]
        self.stage = "runtime_environment_parse"
        runtime = parse_runtime_environment(raw)
        self.stage = "runtime_environment_validate"
        self.baseline_debug = runtime.get("GODEBUG", "")
        self.disabled_debug = merge_disable_thp(self.baseline_debug)
        self.runtime_env_hash = hashlib.sha256(n.canonical(runtime)).hexdigest()

    def arm(self, arm, shared):
        self.stage = arm + "_fixture"
        n.need(self.remaining() >= ARM_SECONDS + 45, "ARM_HEADROOM_REQUIRED")
        root = self.root / "private" / arm
        root.mkdir(mode=0o700)
        runtime = root / "runtime"; runtime.mkdir(mode=0o700)
        output = root / "output"; output.mkdir(mode=0o700)
        key = arm + "_network"; self.intent(key)
        self.call(["docker", "network", "create", "--internal", "--subnet", SUBNET, *self.labels(key), self.paths[key]], maximum=256)
        self.observe(key)
        key = arm + "_volume"; self.intent(key)
        self.call(["docker", "volume", "create", *self.labels(key), self.paths[key]], maximum=256); self.observe(key)
        network = self.paths[arm + "_network"]
        pg_env = {**self.env, "POSTGRES_DB": "latchway", "POSTGRES_USER": "latchway", "POSTGRES_PASSWORD": shared["postgres"]}
        self.create(arm + "_postgres", ["--network", network, "--ip", PG_IP, "--cpus=4", "--memory=4g", "--memory-swap=4g", "--pids-limit=2048",
                    "--security-opt", "no-new-privileges:true", "--mount", "type=volume,src=" + self.paths[arm + "_volume"] + ",dst=/var/lib/postgresql",
                    "--env", "POSTGRES_DB", "--env", "POSTGRES_USER", "--env", "POSTGRES_PASSWORD"],
                    n.PG_IMAGE, ("-c", "max_connections=100"), pg_env)
        self.call(["docker", "start", self.paths[arm + "_postgres"]], maximum=256)
        pg_env = {**self.env, "PGPASSWORD": shared["postgres"]}
        prefix = ["docker", "exec", "--user", "postgres", "--env", "PGPASSWORD", "--env", "PGCONNECT_TIMEOUT=2", "--env", "PGOPTIONS=-c statement_timeout=2000",
                  self.paths[arm + "_postgres"], "psql", "--host", "127.0.0.1", "--username", "latchway", "--dbname", "latchway", "--no-password", "--no-psqlrc",
                  "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--command"]
        streak = 0
        for _ in range(90):
            code, raw = self.call([*prefix, "SELECT 1"], env=pg_env, accepted=(0, 1, 2), timeout=3, maximum=128)
            streak = streak + 1 if code == 0 and raw.strip() == b"1" else 0
            if streak == 5: break
            self.remaining(); time.sleep(1)
        n.need(streak == 5 and self.call([*prefix, "SHOW max_connections"], env=pg_env, maximum=128)[1].strip() == b"100", "POSTGRES_NOT_READY_OR_CONFIG_CHANGED")
        tools_user = str(os.getuid()) + ":" + str(os.getgid())
        common = ["--user", tools_user, "--read-only", "--tmpfs", "/tmp:size=16m,mode=1777", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
        fixture_env = {**self.env, "LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN": shared["fixture"]}
        self.create(arm + "_fixture", ["--network", network, "--ip", FIXTURE_IP, *common, "--pids-limit=1024", "--env", "LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN"],
                    self.ledger["ids"]["tools_image"], ("/tools/latchway-load-fixture", "-listen", FIXTURE_IP + ":19090", "-stream-hold", "150s", "-acknowledge-isolated-container-network"), fixture_env)
        self.call(["docker", "start", self.paths[arm + "_fixture"]], maximum=256)
        gateway = {"LATCHWAY_DATABASE_URL": "postgres://latchway:" + shared["postgres"] + "@" + PG_IP + ":5432/latchway?sslmode=disable",
                   "LATCHWAY_MASTER_KEY": shared["master"], "LATCHWAY_PUBLIC_ORIGIN": "http://127.0.0.1:8080", "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN": shared["bootstrap"],
                   "LATCHWAY_ROLE": "all", "LATCHWAY_LOG_LEVEL": "info", "LATCHWAY_MIGRATE_ON_START": "true",
                   "LATCHWAY_DB_MAX_CONNECTIONS": str(DB_POOL_MAX_CONNECTIONS),
                   "LATCHWAY_DB_COMPLETION_CONNECTIONS": str(DB_COMPLETION_POOL_MAX_CONNECTIONS), "LATCHWAY_SHUTDOWN_TIMEOUT": "30s"}
        # Same dictionary and immutable image in both arms. No inherited image
        # environment setting is erased. Only B overrides the exact GODEBUG key.
        if arm == "B": gateway["GODEBUG"] = self.disabled_debug
        options = ["--network", network, "--cpus=2", "--memory=2g", "--memory-swap=2g", "--pids-limit=4096", "--read-only", "--tmpfs", "/tmp:size=32m,mode=1777",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
        for name in gateway: options.extend(("--env", name))
        self.create(arm + "_gateway", options, self.ledger["ids"]["gateway_image"], environment={**self.env, **gateway})
        self.call(["docker", "start", self.paths[arm + "_gateway"]], maximum=256)
        self.verify_gateway_pool_environment(arm)
        gateway_namespace = "container:" + self.ledger["ids"][arm + "_gateway"]
        provision_env = {**self.env, "LATCHWAY_LOAD_BOOTSTRAP_TOKEN": shared["bootstrap"], "LATCHWAY_LOAD_ADMIN_PASSWORD": shared["admin"]}
        provision_args = ("/tools/latchway-load-provision", "-gateway-url", "http://127.0.0.1:8080", "-upstream-base-url", "http://" + FIXTURE_IP + ":19090/v1",
                          "-output-dir", "/evidence/runtime", "-local-docker-image-id", self.ledger["ids"]["gateway_image"], "-commit", BASE,
                          "-postgres-identity", "PostgreSQL 18.6 Alpine local Docker image " + self.ledger["postgres_image_id"], "-postgres-network", "same internal-only Docker bridge; PostgreSQL address " + PG_IP,
                          "-postgres-cpu-millicores", "4000", "-postgres-memory-bytes", "4294967296", "-postgres-memory-swap-bytes", "4294967296", "-postgres-max-connections", "100",
                          "-gateway-db-pool-max-connections", str(DB_POOL_MAX_CONNECTIONS),
                          "-gateway-db-regular-pool-max-connections", str(DB_REGULAR_POOL_MAX_CONNECTIONS),
                          "-gateway-db-completion-pool-max-connections", str(DB_COMPLETION_POOL_MAX_CONNECTIONS))
        self.create(arm + "_provisioner", ["--network", gateway_namespace, *common, "--env", "LATCHWAY_LOAD_BOOTSTRAP_TOKEN", "--env", "LATCHWAY_LOAD_ADMIN_PASSWORD",
                    "--volume", str(runtime) + ":/evidence/runtime"], self.ledger["ids"]["tools_image"], provision_args, provision_env)
        self.call(["docker", "start", "--attach", self.paths[arm + "_provisioner"]], timeout=90, discard=True)
        self.remove(arm + "_provisioner")
        # Generated credentials stay in this private mode0700 directory. They
        # are consumed by the unchanged tool, never copied into artifacts.
        options = ["--network", gateway_namespace, "--pid", gateway_namespace, "--user", tools_user, "--read-only", "--tmpfs", "/tmp:size=32m,mode=1777",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--env-file", str(runtime / "load.env"), "--env", "GIT_CONFIG_COUNT=1",
                   "--env", "GIT_CONFIG_KEY_0=safe.directory", "--env", "GIT_CONFIG_VALUE_0=/src", "--volume", str(self.source) + ":/src:ro",
                   "--volume", str(runtime) + ":/evidence/runtime:ro", "--volume", str(output) + ":/evidence/output", "--workdir", "/src"]
        self.create(arm + "_tools", options, self.ledger["ids"]["tools_image"],
                    ("/tools/latchway-load", "-acknowledge-load", "-config", "/evidence/runtime/load-config.json", "-output", "/evidence/output/load.json", "-mode", MODE))
        stop_file = root / "collector.stop"
        self.remaining()
        self.ledger["collectors"][arm] = "started_or_unknown"; self.save()
        self.collector_stopped = False
        self.collector = subprocess.Popen([sys.executable, str(REPO / DIRECTORY / "collector.py"), "--postgres", self.paths[arm + "_postgres"],
                         "--gateway", self.paths[arm + "_gateway"], "--tools-runner", self.paths[arm + "_tools"], "--pool-max-connections", str(DB_POOL_MAX_CONNECTIONS),
                         "--regular-pool-max-connections", str(DB_REGULAR_POOL_MAX_CONNECTIONS),
                         "--completion-pool-max-connections", str(DB_COMPLETION_POOL_MAX_CONNECTIONS),
                         "--output", str(self.artifacts / (arm + "-runtime.jsonl")), "--stop-file", str(stop_file),
                         "--advisory-deadline-unix-ns", str(int((self.ledger["t0_wall"] + TOTAL_SECONDS - CLEANUP_SECONDS - 30) * 10**9))],
                         env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.stage = arm + "_load"
        try:
            code, _ = self.call(["docker", "start", "--attach", self.paths[arm + "_tools"]], timeout=ARM_SECONDS, accepted=(0, 1, 2), discard=True)
        finally:
            try:
                stop_file.touch(mode=0o600, exist_ok=False)
                self.collector.wait(timeout=5)
            except BaseException:
                pass
            finally:
                self.stop_collector(arm)
        report = sanitized_load(private_json(output / "load.json"))
        report["tooling_commit"] = self.tooling; report["arm"] = arm; report["original_load_exit_code"] = code
        n.atomic_json(self.artifacts / (arm + "-load.json"), report)
        n.need(len(report["gates"]) == 5, "PRECONDITION_INCOMPLETE")
        overhead = report["gates"][2]["metrics"]
        nonstream = report["gates"][3]["metrics"]
        n.need(overhead.get("samples") == 1000 and nonstream.get("scheduled") == 6000 and nonstream.get("target_rps") == 100 and
               nonstream.get("duration_seconds") == 60, "PRECONDITION_WORKLOAD_CHANGED")
        metrics = report["gates"][-1]["metrics"]
        n.need(metrics.get("established") == 500 and metrics.get("premature_completions") == 0 and metrics.get("hold_seconds") == 60 and
               metrics.get("target_concurrency") == 500 and len(metrics.get("rss_samples", [])) >= 59, "HELD_STREAM_OBSERVATION_INCOMPLETE")
        times = [datetime.datetime.fromisoformat(sample["At"]) for sample in metrics["rss_samples"]]
        n.need(all(a < b for a, b in zip(times, times[1:])) and 58 <= (times[-1]-times[0]).total_seconds() <= 62, "HELD_STREAM_SAMPLE_TIMES")
        self.observations[arm] = memory_observation(self.artifacts / (arm + "-runtime.jsonl"), metrics["rss_samples"])
        n.atomic_json(self.artifacts / (arm + "-environment.json"), {"schema_version": 1, "advisory_only": True, "release_evidence": False, "arm": arm,
                      "source_commit": BASE, "tooling_commit": self.tooling, "gateway_image_id": self.ledger["ids"]["gateway_image"], "tools_image_id": self.ledger["ids"]["tools_image"],
                      "postgres_image": n.PG_IMAGE, "gateway_cpus": 2, "gateway_memory_bytes": 2147483648, "postgres_cpus": 4, "postgres_memory_bytes": 4294967296,
                      "postgres_max_connections": 100, "gateway_pool_max_connections": DB_POOL_MAX_CONNECTIONS,
                      "gateway_regular_pool_max_connections": DB_REGULAR_POOL_MAX_CONNECTIONS,
                      "gateway_completion_pool_max_connections": DB_COMPLETION_POOL_MAX_CONNECTIONS,
                      "original_image_runtime_environment_sha256": self.runtime_env_hash,
                      "other_runtime_environment_preserved": True, "disablethp_override": arm == "B", "mode": MODE, "memory_observation": self.observations[arm]})

    def run(self):
        self.root.mkdir(mode=0o700); self.artifacts.mkdir(mode=0o700); (self.root / "private").mkdir(mode=0o700)
        self.lock(create=True)
        self.ledger = {"schema_version": 1, "owner": self.owner, "source_commit": BASE, "tooling_commit": self.tooling, "names": self.paths,
                       "t0_wall": time.time(), "t0_mono": time.monotonic(), "absent_before": [], "intents": [], "ids": {}, "postgres_image_id": None,
                       "collectors": {"A": "not_started", "B": "not_started"}}
        n.atomic_json(self.root / "ownership.json", self.ledger, exclusive=True)
        outcome = "stopped_no_repeat"
        try:
            self.prepare()
            shared = {"postgres": secrets.token_hex(32), "fixture": secrets.token_hex(32), "master": base64.b64encode(secrets.token_bytes(32)).decode(),
                      "bootstrap": secrets.token_hex(32), "admin": base64.b64encode(secrets.token_bytes(36)).decode()}
            for arm in ("A", "B"):
                try: self.arm(arm, shared)
                finally:
                    self.stop_collector(arm)
                    n.need(self.cleanup(arm), "ARM_CLEANUP_UNCONFIRMED")
            shared.clear()
            outcome = "pair_observed_not_release_evidence"
        except BaseException as error:
            n.atomic_json(self.artifacts / "failure.json", failure_receipt(self.stage, error))
        finally:
            clean = self.cleanup()
        workload_complete = outcome == "pair_observed_not_release_evidence"
        memory_complete = workload_complete and all(self.observations[arm]["complete"] for arm in ("A", "B"))
        if memory_complete:
            memory_complete = all(self.observations["A"][key] == self.observations["B"][key] for key in ("host_thp_controls", "gogc_percent", "gomemlimit_bytes"))
        if workload_complete:
            outcome = "memory_pair_observed_not_release_evidence" if memory_complete else "workload_pair_complete_memory_inconclusive"
        hashes = {Path(path).name: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in FILES}
        n.atomic_json(self.artifacts / "manifest.json", {"schema_version": 1, "status": outcome, "advisory_only": True, "release_evidence": False,
                      "source_commit": BASE, "tooling_commit": self.tooling, "overlays_sha256": hashes, "native_helper_sha256": NATIVE_SHA,
                      "maximum_total_seconds": TOTAL_SECONDS, "cleanup_reserve_seconds": CLEANUP_SECONDS, "elapsed_seconds": time.monotonic()-self.ledger["t0_mono"],
                      "cleanup_verified": clean, "workload_pair_complete": workload_complete, "memory_comparison_complete": memory_complete,
                      "interpretation": "one_pair_no_automatic_repetition"})
        print(json.dumps({"status": outcome, "advisory_only": True, "cleanup_verified": clean}))
        return 0 if clean and memory_complete else 2

    def cleanup_only(self):
        for directory in (self.root, self.artifacts):
            info = directory.lstat()
            n.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(), "LEDGER_DIRECTORY")
        self.lock()
        info = (self.root / "ownership.json").lstat()
        n.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, "LEDGER_MODE")
        value = private_json(self.root / "ownership.json", 16384)
        expected = {"schema_version", "owner", "source_commit", "tooling_commit", "names", "t0_wall", "t0_mono", "absent_before", "intents", "ids", "postgres_image_id", "collectors"}
        n.need(type(value) is dict and set(value) == expected and value["schema_version"] == 1 and value["owner"] == self.owner and
               value["source_commit"] == BASE and value["tooling_commit"] == self.tooling and value["names"] == self.paths, "LEDGER_SCOPE")
        n.need(all(n.numeric(value[key]) for key in ("t0_wall", "t0_mono")) and value["t0_wall"] <= time.time() and value["t0_mono"] <= time.monotonic(), "LEDGER_CLOCK")
        n.need(type(value["absent_before"]) is list and type(value["intents"]) is list and type(value["ids"]) is dict and
               all(type(key) is str for key in value["absent_before"] + value["intents"]) and
               len(set(value["absent_before"])) == len(value["absent_before"]) and set(value["absent_before"]) <= set(self.paths) and
               value["intents"] == value["absent_before"] and set(value["ids"]) <= set(value["intents"]) and
               all(n.matches(item, r"(?:sha256:)?[0-9a-f]{64}") for item in value["ids"].values()), "LEDGER_TARGETS")
        n.need(value["postgres_image_id"] is None or n.matches(value["postgres_image_id"], r"sha256:[0-9a-f]{64}"), "LEDGER_POSTGRES_IMAGE")
        n.need(type(value["collectors"]) is dict and set(value["collectors"]) == {"A", "B"} and
               all(state in ("not_started", "started_or_unknown", "stopped") for state in value["collectors"].values()), "LEDGER_COLLECTOR")
        self.ledger = value
        self.collector_stopped = all(state in ("not_started", "stopped") for state in value["collectors"].values())
        complete = self.cleanup()
        print(json.dumps({"status": "OWNED_CLEANUP_CHECKED", "cleanup_verified": complete, "advisory_only": True}))
        return 0 if complete else 2


def main():
    n.need(sys.argv[1:] in (["--run"], ["--cleanup"]), "EXPLICIT_MODE_REQUIRED")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(n.Stopped("INTERRUPTED")))
    runner = Runner(os.environ)
    try:
        return runner.run() if sys.argv[1] == "--run" else runner.cleanup_only()
    finally:
        runner.unlock()


if __name__ == "__main__":
    try: result = main()
    except BaseException:
        print('{"status":"ADVISORY_STOPPED_REDACTED"}')
        result = 2
    raise SystemExit(result)
