#!/usr/bin/env python3
"""Require a written PR-body reason whenever docs-not-required is applied."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any


LABEL = "docs-not-required"
REASON = re.compile(r"(?im)^Docs-Not-Required-Reason:[ \t]*(?P<reason>[^\r\n]*)$")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
PLACEHOLDERS = {"n/a", "na", "none", "not applicable", "not required", "todo", "tbd", "-"}
MAXIMUM_EVENT_BYTES = 2 * 1024 * 1024


class PolicyError(ValueError):
    """The pull request does not satisfy the documentation disposition policy."""


def rejecting_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_event(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PolicyError(f"cannot inspect GitHub event: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise PolicyError("GitHub event must be a regular file")
    if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_EVENT_BYTES:
        raise PolicyError("GitHub event size is outside policy")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=rejecting_object_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"GitHub event is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError("GitHub event root must be an object")
    return value


def pull_request_fields(event: dict[str, Any]) -> tuple[set[str], str]:
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        raise PolicyError("event does not contain a pull_request object")
    body = pull_request.get("body")
    if body is None:
        body = ""
    if not isinstance(body, str):
        raise PolicyError("pull_request.body must be a string or null")
    labels_value = pull_request.get("labels")
    if not isinstance(labels_value, list):
        raise PolicyError("pull_request.labels must be an array")
    labels: set[str] = set()
    for label in labels_value:
        if not isinstance(label, dict) or not isinstance(label.get("name"), str):
            raise PolicyError("pull_request label is malformed")
        labels.add(label["name"].strip().casefold())
    return labels, body


def validate_event(event: dict[str, Any]) -> str | None:
    labels, body = pull_request_fields(event)
    if LABEL not in labels:
        return None
    match = REASON.search(body)
    if match is None:
        raise PolicyError(
            f"{LABEL} requires a Docs-Not-Required-Reason line in the pull request body"
        )
    reason = HTML_COMMENT.sub("", match.group("reason")).strip()
    normalized = reason.casefold().rstrip(".")
    if (
        len(reason) < 15
        or normalized in PLACEHOLDERS
        or "<" in reason
        or ">" in reason
        or re.search(r"[A-Za-z]", reason) is None
    ):
        raise PolicyError(f"{LABEL} reason is empty or placeholder text")
    return reason


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        reason = validate_event(load_event(arguments.event))
    except PolicyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if reason is None:
        print("documentation PR policy passed: docs-not-required is absent")
    else:
        print("documentation PR policy passed: written docs-not-required reason present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
