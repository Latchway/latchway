#!/usr/bin/env python3
"""Parse one bounded `gh api --include` response and retain its ETag/body."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


MAXIMUM = 32 * 1024 * 1024
STATUS = re.compile(rb"^HTTP/(?:1\.[01]|2(?:\.0)?) ([1-5][0-9]{2})(?: |$)")
ETAG = re.compile(r'^(?:W/)?"[!#-~]{1,512}"$')


class SnapshotError(Exception):
    pass


def read(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= MAXIMUM:
            raise SnapshotError("snapshot_input_invalid")
        return path.read_bytes()
    except SnapshotError:
        raise
    except OSError:
        raise SnapshotError("snapshot_input_invalid") from None


def parse(payload: bytes, expected_status: int) -> tuple[str | None, bytes]:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in payload else b"\n\n"
    blocks = payload.split(separator)
    if len(blocks) < 2:
        raise SnapshotError("snapshot_headers_invalid")
    headers, body = blocks[-2], blocks[-1]
    lines = headers.replace(b"\r", b"").splitlines()
    if not lines or (match := STATUS.match(lines[0])) is None:
        raise SnapshotError("snapshot_status_invalid")
    if int(match.group(1)) != expected_status:
        raise SnapshotError("snapshot_status_mismatch")
    values: dict[str, list[str]] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise SnapshotError("snapshot_headers_invalid")
        raw_name, raw_value = line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.strip().decode("ascii")
        except UnicodeDecodeError:
            raise SnapshotError("snapshot_headers_invalid") from None
        values.setdefault(name, []).append(value)
    etags = values.get("etag", [])
    etag = etags[0] if len(etags) == 1 else None
    if expected_status == 200:
        if etag is None or ETAG.fullmatch(etag) is None or not body:
            raise SnapshotError("snapshot_etag_invalid")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SnapshotError("snapshot_body_invalid") from None
        if not isinstance(value, dict):
            raise SnapshotError("snapshot_body_invalid")
    elif expected_status == 304:
        if body.strip():
            raise SnapshotError("snapshot_304_body_invalid")
    return etag, body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--expected-status", type=int, choices=(200, 304), required=True)
    parser.add_argument("--body-output", type=Path)
    parser.add_argument("--etag-output", type=Path)
    arguments = parser.parse_args()
    try:
        etag, body = parse(read(arguments.response), arguments.expected_status)
        if arguments.body_output is not None:
            if arguments.expected_status != 200 or arguments.body_output.exists():
                raise SnapshotError("snapshot_output_invalid")
            arguments.body_output.write_bytes(body)
        if arguments.etag_output is not None:
            if etag is None or arguments.etag_output.exists():
                raise SnapshotError("snapshot_output_invalid")
            arguments.etag_output.write_text(etag + "\n", encoding="ascii")
    except (OSError, SnapshotError) as error:
        print(f"GitHub API snapshot rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
