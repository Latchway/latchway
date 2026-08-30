#!/usr/bin/env python3
"""Validate immutable Latchway release-candidate source before publication.

This preflight deliberately does not validate promotion evidence. Candidate
creation and stable promotion are separate workflows: this command proves that
the checked-out source is a coherent, untagged release candidate, while the
promotion workflow verifies independently produced, attested evidence before it
creates any public release coordinate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORE_VERSION = (
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
)
CANDIDATE_TAG = re.compile(
    rf"^v{CORE_VERSION}(?:-rc\.(?:[1-9][0-9]*))?$"
)
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAXIMUM_CANDIDATE_AGE = timedelta(days=7)


class PreflightError(Exception):
    """A stable, redaction-safe release-preflight failure."""


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightError("git_command_failed") from None
    if check and result.returncode != 0:
        raise PreflightError("git_command_failed")
    return result


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise PreflightError("release_metadata_invalid") from None
    if not isinstance(value, dict):
        raise PreflightError("release_metadata_invalid")
    return value


def require_match(pattern: str, contents: str, code: str) -> str:
    match = re.search(pattern, contents, flags=re.MULTILINE)
    if match is None:
        raise PreflightError(code)
    return match.group(1)


def parse_released_at(value: Any, now: datetime) -> datetime:
    if not isinstance(value, str) or CANONICAL_UTC.fullmatch(value) is None:
        raise PreflightError("contract_released_at_invalid")
    try:
        released_at = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise PreflightError("contract_released_at_invalid") from None
    if released_at > now:
        raise PreflightError("contract_released_at_in_future")
    if now - released_at > MAXIMUM_CANDIDATE_AGE:
        raise PreflightError("contract_release_window_expired")
    return released_at


def validate_candidate(tag: str, commit: str, now: datetime) -> dict[str, Any]:
    if CANDIDATE_TAG.fullmatch(tag) is None:
        raise PreflightError("release_tag_not_canonical")
    if COMMIT.fullmatch(commit) is None:
        raise PreflightError("candidate_commit_not_canonical")
    version = tag[1:]

    if git("status", "--porcelain=v1", "--untracked-files=all").stdout:
        raise PreflightError("dirty_worktree")
    head = git("rev-parse", "--verify", "HEAD").stdout.strip()
    if head != commit:
        raise PreflightError("candidate_commit_not_at_head")
    existing_tag = git(
        "show-ref", "--verify", "--quiet", f"refs/tags/{tag}", check=False
    )
    if existing_tag.returncode not in (0, 1):
        raise PreflightError("git_command_failed")
    if existing_tag.returncode == 0:
        raise PreflightError("candidate_tag_already_exists")

    console = read_json(ROOT / "web/console/package.json")
    if console.get("version") != version:
        raise PreflightError("console_version_mismatch")

    try:
        buildinfo = (ROOT / "internal/buildinfo/buildinfo.go").read_text(
            encoding="utf-8"
        )
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise PreflightError("release_metadata_invalid") from None
    build_version = require_match(
        r'^\s*Version\s*=\s*"([^"]+)"', buildinfo, "build_version_missing"
    )
    contract_constant = require_match(
        r'^\s*ContractVersion\s*=\s*"([^"]+)"',
        buildinfo,
        "contract_version_missing",
    )
    if build_version != version:
        raise PreflightError("binary_version_mismatch")

    manifest = read_json(ROOT / "api/protocol-version.json")
    if manifest.get("contract_version") != contract_constant:
        raise PreflightError("contract_version_mismatch")
    if manifest.get("contract_status") != "released":
        raise PreflightError("contract_not_released")
    released_at = parse_released_at(manifest.get("released_at"), now)
    bundle = manifest.get("bundle")
    if not isinstance(bundle, dict) or bundle.get("file_name") != (
        f"latchway-contract-{contract_constant}.tar.gz"
    ):
        raise PreflightError("contract_bundle_name_mismatch")

    if (
        re.search(
            rf"^## \[{re.escape(version)}\](?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?$",
            changelog,
            re.MULTILINE,
        )
        is None
    ):
        raise PreflightError("release_changelog_entry_missing")

    return {
        "schema_version": 1,
        "kind": "latchway_release_candidate_preflight",
        "status": "passed",
        "candidate_commit": commit,
        "intended_tag": tag,
        "version": version,
        "contract_version": contract_constant,
        "contract_released_at": released_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="validate an untagged release candidate",
    )
    parser.add_argument("--commit", required=True, help="exact candidate Git commit")
    parser.add_argument("tag", help="intended v-prefixed semantic release tag")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if not arguments.candidate:
        print(
            "release preflight failed: --candidate is required; stable promotion "
            "must use the promotion evidence workflow",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_candidate(
            arguments.tag,
            arguments.commit,
            datetime.now(timezone.utc),
        )
    except PreflightError as error:
        print(f"release preflight failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
