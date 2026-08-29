#!/usr/bin/env python3
"""Authorize one monotonic stable OCI moving-alias transition."""

from __future__ import annotations

import argparse
import json
import re
import sys


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ALIAS = re.compile(r"^(?:latest|0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$")


class TransitionError(Exception):
    """A stable OCI alias-transition policy failure."""


def version(value: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(value)
    if match is None:
        raise TransitionError("oci_alias_version_invalid")
    return tuple(int(item) for item in match.groups())  # type: ignore[return-value]


def expected_aliases(candidate: str) -> tuple[str, str, str]:
    major, minor, _ = version(candidate)
    return f"{major}.{minor}", str(major), "latest"


def authorize(alias: str, current: str, candidate: str) -> str:
    if ALIAS.fullmatch(alias) is None:
        raise TransitionError("oci_alias_name_invalid")
    current_key = version(current)
    candidate_key = version(candidate)
    if alias not in expected_aliases(candidate):
        raise TransitionError("oci_alias_scope_invalid")
    if alias != "latest":
        parts = tuple(int(item) for item in alias.split("."))
        if current_key[: len(parts)] != parts:
            raise TransitionError("oci_alias_current_scope_invalid")
    if current_key == candidate_key:
        return "already_current"
    if current_key > candidate_key:
        raise TransitionError("oci_alias_rollback_rejected")
    return "advance"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--current-version", required=True)
    parser.add_argument("--candidate-version", required=True)
    arguments = parser.parse_args()
    try:
        action = authorize(arguments.alias, arguments.current_version, arguments.candidate_version)
    except TransitionError as error:
        print(f"OCI alias transition rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"action": action, "alias": arguments.alias}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
