#!/usr/bin/env python3
"""Reject GitHub CLI releases with known attestation/release verification flaws."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys


MINIMUM = (2, 97, 0)
VERSION = re.compile(r"^gh version (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\s|$)")


class VersionError(Exception):
    """A stable GitHub CLI version-policy failure."""


def parse_version(output: str) -> tuple[int, int, int]:
    first = output.splitlines()[0] if output.splitlines() else ""
    match = VERSION.match(first)
    if match is None:
        raise VersionError("github_cli_version_invalid")
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def require_version(output: str) -> tuple[int, int, int]:
    version = parse_version(output)
    if version < MINIMUM:
        raise VersionError("github_cli_version_vulnerable")
    return version


def installed_version() -> tuple[int, int, int]:
    executable = shutil.which("gh")
    if executable is None:
        raise VersionError("github_cli_unavailable")
    try:
        result = subprocess.run(
            (executable, "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise VersionError("github_cli_unavailable") from None
    if result.returncode != 0 or result.stderr:
        raise VersionError("github_cli_version_invalid")
    return require_version(result.stdout)


def main() -> int:
    try:
        version = installed_version()
    except VersionError as error:
        print(f"GitHub CLI version rejected: {error}", file=sys.stderr)
        return 1
    else:
        print(".".join(str(value) for value in version))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
