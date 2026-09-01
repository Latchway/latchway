#!/usr/bin/env python3
"""Emit a bounded machine-readable observation for a scheduled framework run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
REPOSITORY = re.compile(r"^latchway(?:-[a-z0-9-]+)?$")


def observation(
    repository: str,
    profile: str,
    outcome: str,
    report: Path,
    source_commit: str,
    versions: list[str],
    run_url: str,
) -> dict[str, object]:
    if REPOSITORY.fullmatch(repository) is None:
        raise ValueError("repository is invalid")
    if profile not in {"minimum", "latest", "registry-exact", "newest-compatible"}:
        raise ValueError("profile is invalid")
    if outcome not in {"success", "failure"}:
        raise ValueError("outcome is invalid")
    if COMMIT.fullmatch(source_commit) is None:
        raise ValueError("source commit must be a full lowercase SHA-1")
    raw = report.read_bytes()
    parsed_versions: dict[str, str] = {}
    for coordinate in versions:
        name, separator, value = coordinate.partition("=")
        if separator != "=" or NAME.fullmatch(name) is None or not value or len(value) > 128:
            raise ValueError(f"invalid version coordinate: {coordinate!r}")
        if name in parsed_versions:
            raise ValueError(f"duplicate version coordinate: {name}")
        parsed_versions[name] = value
    if not run_url.startswith("https://github.com/") or len(run_url) > 300:
        raise ValueError("run URL is invalid")
    return {
        "schema_version": 1,
        "kind": "latchway_framework_compatibility_observation",
        "repository": repository,
        "source_commit": source_commit,
        "profile": profile,
        "outcome": outcome,
        "framework_report_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_versions": dict(sorted(parsed_versions.items())),
        "run_url": run_url,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--run-url", default=(
        f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
        f"{os.environ.get('GITHUB_RUN_ID', '')}/attempts/{os.environ.get('GITHUB_RUN_ATTEMPT', '')}"
    ))
    parser.add_argument("--version", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    value = observation(
        arguments.repository,
        arguments.profile,
        arguments.outcome,
        arguments.report,
        arguments.source_commit,
        arguments.version,
        arguments.run_url,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
