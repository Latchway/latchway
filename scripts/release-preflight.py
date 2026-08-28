#!/usr/bin/env python3
"""Reject a release tag unless versioned source and release evidence agree."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^v(?P<version>0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"$"
)


def fail(message: str) -> None:
    raise SystemExit(f"release preflight failed: {message}")


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def require_match(pattern: str, contents: str, label: str) -> str:
    match = re.search(pattern, contents, flags=re.MULTILINE)
    if match is None:
        fail(f"could not read {label}")
    return match.group(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: release-preflight.py vMAJOR.MINOR.PATCH[-PRERELEASE]")
    tag = sys.argv[1]
    match = SEMVER.fullmatch(tag)
    if match is None:
        fail(f"{tag!r} is not a canonical v-prefixed semantic version")
    version = tag[1:]

    if git("status", "--porcelain"):
        fail("the repository has uncommitted or untracked files")
    if git("rev-parse", f"refs/tags/{tag}^{{commit}}") != git("rev-parse", "HEAD"):
        fail(f"tag {tag} does not resolve to HEAD")
    if git("cat-file", "-t", f"refs/tags/{tag}") != "tag":
        fail("release tags must be annotated (signing is performed by the release operator)")

    console = json.loads((ROOT / "web/console/package.json").read_text())
    if console.get("version") != version:
        fail(
            "web/console/package.json version "
            f"{console.get('version')!r} does not equal {version!r}"
        )

    buildinfo = (ROOT / "internal/buildinfo/buildinfo.go").read_text()
    build_version = require_match(r'^\s*Version\s*=\s*"([^"]+)"', buildinfo, "build version")
    contract_constant = require_match(
        r'^\s*ContractVersion\s*=\s*"([^"]+)"', buildinfo, "contract version"
    )
    if build_version != version:
        fail(f"default binary version {build_version!r} does not equal {version!r}")

    manifest = json.loads((ROOT / "api/protocol-version.json").read_text())
    if manifest.get("contract_version") != contract_constant:
        fail("buildinfo and api/protocol-version.json contract versions disagree")

    changelog = (ROOT / "CHANGELOG.md").read_text()
    if re.search(rf"^## \[{re.escape(version)}\](?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?$", changelog, re.MULTILINE) is None:
        fail(f"CHANGELOG.md has no release section for {version}")

    print(
        json.dumps(
            {
                "status": "ok",
                "tag": tag,
                "version": version,
                "contract_version": contract_constant,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
