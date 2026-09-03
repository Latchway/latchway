"""Narrow private extension of the reviewed load collector; no new service."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
BASE_COLLECTOR = ROOT / "scripts/load-runtime-diagnostics.py"
EXPECTED_SHA = "76213e8540d9a8eb2252f93e60902dfaa039a93d98c587cb0c37b534c66f30d5"
if hashlib.sha256(BASE_COLLECTOR.read_bytes()).hexdigest() != EXPECTED_SHA:
    raise RuntimeError("COLLECTOR_SOURCE_CHANGED")
SPEC = importlib.util.spec_from_file_location("base_memory_collector", BASE_COLLECTOR)
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

FIELDS = {"schema", "sequence", "unix_nano", "elapsed_nano", "heap_objects_bytes", "heap_free_bytes", "heap_released_bytes",
          "heap_unused_bytes", "heap_stacks_bytes", "runtime_total_bytes", "heap_live_last_gc_bytes", "gc_cycles",
          "heap_allocated_total_bytes", "heap_freed_total_bytes", "goroutines", "gogc_percent", "gomemlimit_bytes"}


def snapshot(raw, now_ns):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("DUPLICATE")
            value[key] = item
        return value
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise ValueError("SIZE")
        value = json.loads(raw, object_pairs_hook=pairs)
        if type(value) is not dict or set(value) != FIELDS or any(type(n) is not int or not 0 <= n < 2**63 for n in value.values()):
            raise ValueError("SCHEMA")
        if value["schema"] != 1 or not 1 <= value["sequence"] <= 180 or value["elapsed_nano"] > 15*60*10**9:
            raise ValueError("SCOPE")
        age = now_ns - value["unix_nano"]
        if not -10**9 <= age <= 10*10**9:
            return {"status": "stale_or_clock_skew"}
        return {"status": "ok", "snapshot": value, "age_nano": age}
    except (ValueError, TypeError, UnicodeError):
        return {"status": "invalid_response"}


original = base.process_memory_sample


def process_memory_sample(tools_runner):
    result = original(tools_runner)
    started = time.monotonic()
    status, raw = base.capture(["docker", "exec", "--user", "65532:65532", tools_runner,
                                "timeout", "-s", "KILL", "2", "cat", "/proc/1/root/tmp/latchway-advisory-memory.json"],
                               limit=4096, timeout=3)
    result["go_memory"] = snapshot(raw, time.time_ns()) if status == "ok" else {"status": "unavailable"}
    result["go_sample_duration_ms"] = int((time.monotonic() - started) * 1000)
    result["go_sampler_adds_observation_overhead"] = True
    return result


base.process_memory_sample = process_memory_sample


def main():
    # A lost launcher cannot leave this observer running without a wall bound.
    # Keep the existing collector cadence and capture limits unchanged.
    if len(sys.argv) < 3 or sys.argv[-2] != "--advisory-deadline-unix-ns":
        return 2
    try:
        deadline = int(sys.argv[-1])
        remaining = (deadline - time.time_ns()) / 10**9
        if not 0 < remaining <= 1500:
            return 2
    except (ValueError, OverflowError):
        return 2
    del sys.argv[-2:]
    collect = base.collect
    def bounded_collect(*args, **kwargs):
        kwargs["maximum_seconds"] = min(900, remaining)
        return collect(*args, **kwargs)
    base.collect = bounded_collect
    return base.main()

if __name__ == "__main__":
    try:
        result = main()
    except BaseException:
        result = 2
    raise SystemExit(result)
