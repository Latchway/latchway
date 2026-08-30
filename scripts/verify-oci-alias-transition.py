#!/usr/bin/env python3
"""Authorize one monotonic stable OCI moving-alias transition."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ALIAS = re.compile(r"^(?:latest|0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


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


def authorize_plan(
    candidate: str,
    aliases: Mapping[str, Any],
    stable_predecessors: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    expected = expected_aliases(candidate)
    if set(aliases) != set(expected):
        raise TransitionError("oci_alias_plan_scope_invalid")
    if stable_predecessors is None:
        stable_predecessors = {}
    if not isinstance(stable_predecessors, Mapping):
        raise TransitionError("oci_alias_predecessor_scope_invalid")
    candidate_key = version(candidate)
    for prior_version, state in stable_predecessors.items():
        if (
            not isinstance(prior_version, str)
            or not isinstance(state, dict)
            or set(state) != {"commit", "finalized"}
            or COMMIT.fullmatch(str(state.get("commit"))) is None
            or state.get("finalized") is not True
        ):
            raise TransitionError("oci_alias_predecessor_state_invalid")
        if version(prior_version) >= candidate_key:
            raise TransitionError("oci_alias_predecessor_order_invalid")
    actions: dict[str, str] = {}
    for alias in expected:
        state = aliases.get(alias)
        if state is None:
            actions[alias] = "create"
            continue
        if not isinstance(state, dict) or set(state) != {
            "current_version",
            "predecessor_finalized",
        }:
            raise TransitionError("oci_alias_plan_state_invalid")
        current = state.get("current_version")
        finalized = state.get("predecessor_finalized")
        if not isinstance(current, str) or not isinstance(finalized, bool):
            raise TransitionError("oci_alias_plan_state_invalid")
        action = authorize(alias, current, candidate)
        if action == "advance" and finalized is not True:
            raise TransitionError("oci_alias_predecessor_unfinalized")
        actions[alias] = action
    return actions


def load_plan(path: Path) -> Mapping[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= 65536:
            raise TransitionError("oci_alias_plan_invalid")
        value = json.loads(path.read_bytes())
    except TransitionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise TransitionError("oci_alias_plan_invalid") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"aliases", "stable_predecessors"}
        or not isinstance(value["aliases"], dict)
        or not isinstance(value["stable_predecessors"], dict)
    ):
        raise TransitionError("oci_alias_plan_invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alias")
    parser.add_argument("--current-version")
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--plan", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.plan is None:
            if arguments.alias is None or arguments.current_version is None:
                raise TransitionError("oci_alias_arguments_invalid")
            result: Any = {
                "action": authorize(
                    arguments.alias,
                    arguments.current_version,
                    arguments.candidate_version,
                ),
                "alias": arguments.alias,
            }
        else:
            if arguments.alias is not None or arguments.current_version is not None:
                raise TransitionError("oci_alias_arguments_invalid")
            plan = load_plan(arguments.plan)
            result = {
                "actions": authorize_plan(
                    arguments.candidate_version,
                    plan["aliases"],
                    plan["stable_predecessors"],
                ),
                "candidate_version": arguments.candidate_version,
            }
    except TransitionError as error:
        print(f"OCI alias transition rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
