#!/usr/bin/env python3
"""Safely synchronize the canonical public docs into a deployment mirror.

The mirror manifest records only files owned by this synchronizer. Files such as
the mirror repository's .git directory and workflows are intentionally outside
that ownership boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


MANIFEST_NAME = ".latchway-docs-source.json"
IGNORED_PARTS = {".git", "__pycache__", "node_modules"}
IGNORED_NAMES = {".DS_Store", MANIFEST_NAME}
ASSISTANT_PATH = ".mintlify/Assistant.md"
SKILLS_PREFIX = ".mintlify/skills/"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_files(source: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        relative_text = relative.as_posix()
        if ".mintlify" in relative.parts:
            is_assistant = relative_text == ASSISTANT_PATH
            is_skill_resource = relative_text.startswith(SKILLS_PREFIX)
            if not (is_assistant or is_skill_resource):
                continue
        if path.name in IGNORED_NAMES:
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ValueError(f"source contains a symlink: {relative}")
        if path.is_file():
            files[relative_text] = path
    return files


def read_manifest(target: Path) -> dict[str, str] | None:
    path = target / MANIFEST_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if data.get("format") != 1 or not isinstance(data.get("files"), dict):
        raise ValueError(f"unsupported manifest format in {path}")
    files = data["files"]
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in files.items()):
        raise ValueError(f"invalid file table in {path}")
    return files


def source_commit(source: Path) -> str | None:
    """Return the local source revision without contacting a remote."""
    repository = Path(__file__).resolve().parents[1]
    try:
        source.resolve().relative_to(repository.resolve())
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    if result.returncode != 0 or len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def file_table(files: dict[str, Path]) -> dict[str, str]:
    return {relative: sha256(path) for relative, path in files.items()}


def file_table_sha256(files: dict[str, str]) -> str:
    encoded = (json.dumps(files, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def manifest_payload(files: dict[str, Path], commit: str | None) -> str:
    hashes = file_table(files)
    payload = {
        "format": 1,
        "source": "latchway/docs/public",
        "source_commit": commit,
        "source_tree_sha256": file_table_sha256(hashes),
        "files": hashes,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_manifest(target: Path, payload: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{MANIFEST_NAME}.", dir=target)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(temporary_name, target / MANIFEST_NAME)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def initialize(source: Path, target: Path, files: dict[str, Path]) -> int:
    if (target / MANIFEST_NAME).exists():
        print(f"error: {target / MANIFEST_NAME} already exists", file=sys.stderr)
        return 2
    mismatches: list[str] = []
    missing: list[str] = []
    for relative, source_path in files.items():
        target_path = target / relative
        if not target_path.exists():
            missing.append(relative)
        elif not target_path.is_file() or sha256(target_path) != sha256(source_path):
            mismatches.append(relative)
    if mismatches or missing:
        for relative in mismatches:
            print(f"conflict: mirror differs from canonical source: {relative}", file=sys.stderr)
        for relative in missing:
            print(f"conflict: mirror is missing canonical source file: {relative}", file=sys.stderr)
        print("initialization is non-mutating unless the existing mirror already matches", file=sys.stderr)
        return 2
    write_manifest(target, manifest_payload(files, source_commit(source)))
    print(f"initialized {target / MANIFEST_NAME} with {len(files)} owned files")
    return 0


def preflight_write(
    target: Path, files: dict[str, Path], old_files: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    copies: list[str] = []
    removals: list[str] = []
    conflicts: list[str] = []
    for relative, source_path in files.items():
        target_path = target / relative
        source_hash = sha256(source_path)
        if not target_path.exists():
            copies.append(relative)
            continue
        if not target_path.is_file() or target_path.is_symlink():
            conflicts.append(f"owned path is not a regular file: {relative}")
            continue
        target_hash = sha256(target_path)
        if target_hash == source_hash:
            continue
        if old_files.get(relative) == target_hash:
            copies.append(relative)
        else:
            conflicts.append(f"mirror has an unowned edit: {relative}")
    for relative, old_hash in old_files.items():
        if relative in files:
            continue
        target_path = target / relative
        if not target_path.exists():
            continue
        if target_path.is_file() and not target_path.is_symlink() and sha256(target_path) == old_hash:
            removals.append(relative)
        else:
            conflicts.append(f"stale owned file has an unowned edit: {relative}")
    return copies, removals, conflicts


def write(source: Path, target: Path, files: dict[str, Path], old_files: dict[str, str] | None) -> int:
    if old_files is None:
        print(f"error: initialize {target / MANIFEST_NAME} before writing", file=sys.stderr)
        return 2
    copies, removals, conflicts = preflight_write(target, files, old_files)
    if conflicts:
        for conflict in conflicts:
            print(f"conflict: {conflict}", file=sys.stderr)
        print("no mirror files were changed", file=sys.stderr)
        return 2
    for relative in copies:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(files[relative], destination)
    for relative in removals:
        destination = target / relative
        destination.unlink()
        parent = destination.parent
        while parent != target and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent
    write_manifest(target, manifest_payload(files, source_commit(source)))
    print(f"synchronized {len(files)} files ({len(copies)} copied, {len(removals)} removed)")
    return 0


def check(target: Path, files: dict[str, Path], old_files: dict[str, str] | None) -> int:
    if old_files is None:
        print(f"error: mirror manifest is missing: {target / MANIFEST_NAME}", file=sys.stderr)
        return 1
    expected = {relative: sha256(path) for relative, path in files.items()}
    problems: list[str] = []
    if old_files != expected:
        problems.append("manifest does not describe the current canonical source")
    for relative, expected_hash in expected.items():
        target_path = target / relative
        if not target_path.is_file() or target_path.is_symlink():
            problems.append(f"mirror file is missing: {relative}")
        elif sha256(target_path) != expected_hash:
            problems.append(f"mirror file differs: {relative}")
    for relative in old_files.keys() - expected.keys():
        if (target / relative).exists():
            problems.append(f"stale owned mirror file remains: {relative}")
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(f"mirror matches {len(files)} canonical public-doc files")
    return 0


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=repository_root / "docs" / "public")
    parser.add_argument("--target", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initialize", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    arguments = parser.parse_args()

    source = arguments.source.resolve()
    target = arguments.target.resolve()
    if not source.is_dir():
        parser.error(f"source is not a directory: {source}")
    if source == target:
        parser.error("source and target must be different directories")
    try:
        files = source_files(source)
        old_files = read_manifest(target)
        if arguments.initialize:
            return initialize(source, target, files)
        if arguments.write:
            return write(source, target, files, old_files)
        return check(target, files, old_files)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
