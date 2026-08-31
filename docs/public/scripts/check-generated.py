#!/usr/bin/env python3
"""Verify generated public references in the canonical tree or docs mirror."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


PUBLIC_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = PUBLIC_ROOT.parents[1]
MANIFEST = PUBLIC_ROOT / "config/generated-reference.json"
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"generated reference validation failed: {message}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_keys(value: Any, expected: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{location} must contain exactly {sorted(expected)}")
    return value


def checked_path(root: Path, relative: Any, location: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        fail(f"{location}.path must be a nonempty relative path")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{location}.path escapes its root")
    if not resolved.is_file():
        fail(f"{location}.path is missing: {relative}")
    return resolved


def check_entries(entries: Any, root: Path, location: str) -> int:
    if not isinstance(entries, list) or not entries:
        fail(f"{location} must be a nonempty list")
    paths: list[str] = []
    for index, raw in enumerate(entries):
        entry = exact_keys(raw, {"path", "sha256"}, f"{location}[{index}]")
        path = checked_path(root, entry["path"], f"{location}[{index}]")
        expected = entry["sha256"]
        if not isinstance(expected, str) or DIGEST.fullmatch(expected) is None:
            fail(f"{location}[{index}].sha256 is invalid")
        if digest(path) != expected:
            fail(f"{location}[{index}] digest differs: {entry['path']}")
        paths.append(entry["path"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail(f"{location} paths must be sorted and unique")
    return len(paths)


def main() -> int:
    try:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {MANIFEST}: {error}")
    manifest = exact_keys(
        value,
        {"format", "generator", "sources", "outputs"},
        "manifest",
    )
    if manifest["format"] != 1 or manifest["generator"] != "scripts/public_reference.py":
        fail("manifest coordinate is unsupported")
    output_count = check_entries(manifest["outputs"], PUBLIC_ROOT, "outputs")

    generator = CORE_ROOT / manifest["generator"]
    if generator.is_file():
        source_count = check_entries(manifest["sources"], CORE_ROOT, "sources")
        completed = subprocess.run(
            [sys.executable, str(generator), "--check-generated"],
            cwd=CORE_ROOT,
            check=False,
        )
        if completed.returncode != 0:
            fail("canonical generator reported drift")
        print(
            f"generated public reference manifest valid: {source_count} sources, "
            f"{output_count} outputs"
        )
        return 0

    # A generated latchway-docs mirror intentionally has no core contracts or
    # generator. Its fail-closed source manifest authenticates this verifier and
    # manifest; this local gate still proves that no generated output drifted.
    print(f"generated public reference mirror valid: {output_count} outputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
