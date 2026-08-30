#!/usr/bin/env python3
"""Verify the complete byte closure of a prior immutable evidence release."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping


COMMIT = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CHECKSUM = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
REPORT_HASH = re.compile(
    r"^\| `([A-Za-z0-9][A-Za-z0-9._-]{0,127})` \| `([0-9a-f]{64})` \|$"
)
MAXIMUM_FILE_BYTES = 1024 * 1024 * 1024
EXPECTED = frozenset(
    {
        "COMPLETION_REPORT.attestation.sigstore.json",
        "COMPLETION_REPORT.md",
        "SHA256SUMS",
        "latchway-cross-repository-release.attestation.sigstore.json",
        "latchway-cross-repository-release.json",
        "latchway-product-release-attestation.json",
        "latchway-public-registry-byte-proof.json",
        "latchway-publication-state.json",
        "latchway-release-evidence-v1.tar.gz",
    }
)
DURABLE = EXPECTED - {
    "COMPLETION_REPORT.attestation.sigstore.json",
    "COMPLETION_REPORT.md",
    "SHA256SUMS",
}


class EvidenceError(Exception):
    """A stable prior-final-evidence validation failure."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("final_evidence_duplicate_json_key")
        result[key] = value
    return result


def read(path: Path, maximum: int = MAXIMUM_FILE_BYTES) -> bytes:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or not 1 <= metadata.st_size <= maximum
        ):
            raise EvidenceError("final_evidence_file_invalid")
        return path.read_bytes()
    except EvidenceError:
        raise
    except OSError:
        raise EvidenceError("final_evidence_file_invalid") from None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAXIMUM_FILE_BYTES
        ):
            raise EvidenceError("final_evidence_file_invalid")
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except EvidenceError:
        raise
    except OSError:
        raise EvidenceError("final_evidence_file_invalid") from None
    return digest.hexdigest()


def release_assets(release: Mapping[str, Any]) -> dict[str, tuple[int, str]]:
    assets = release.get("assets")
    if not isinstance(assets, list) or len(assets) != len(EXPECTED):
        raise EvidenceError("final_evidence_release_assets_invalid")
    result: dict[str, tuple[int, str]] = {}
    for asset in assets:
        if (
            not isinstance(asset, dict)
            or not isinstance(asset.get("name"), str)
            or asset["name"] in result
            or not isinstance(asset.get("size"), int)
            or isinstance(asset.get("size"), bool)
            or asset["size"] < 1
            or not isinstance(asset.get("digest"), str)
            or DIGEST.fullmatch(asset["digest"]) is None
        ):
            raise EvidenceError("final_evidence_release_assets_invalid")
        result[asset["name"]] = (asset["size"], asset["digest"].removeprefix("sha256:"))
    if set(result) != EXPECTED:
        raise EvidenceError("final_evidence_release_assets_invalid")
    return result


def validate(directory: Path, release: Mapping[str, Any], commit: str, tag: str) -> dict[str, str]:
    if COMMIT.fullmatch(commit) is None or TAG.fullmatch(tag) is None:
        raise EvidenceError("final_evidence_identity_invalid")
    try:
        if directory.is_symlink() or not directory.is_dir():
            raise EvidenceError("final_evidence_directory_invalid")
        entries = list(directory.iterdir())
    except EvidenceError:
        raise
    except OSError:
        raise EvidenceError("final_evidence_directory_invalid") from None
    if {item.name for item in entries} != EXPECTED or len(entries) != len(EXPECTED):
        raise EvidenceError("final_evidence_file_set_invalid")
    assets = release_assets(release)
    hashes: dict[str, str] = {}
    for name in sorted(EXPECTED):
        path = directory / name
        digest = sha256(path)
        hashes[name] = digest
        if path.stat().st_size != assets[name][0] or digest != assets[name][1]:
            raise EvidenceError("final_evidence_release_digest_mismatch")

    try:
        checksum_lines = read(directory / "SHA256SUMS", 64 * 1024).decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise EvidenceError("final_evidence_checksum_invalid") from None
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        match = CHECKSUM.fullmatch(line)
        if match is None or match.group(2) in checksums:
            raise EvidenceError("final_evidence_checksum_invalid")
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != EXPECTED - {"SHA256SUMS"}:
        raise EvidenceError("final_evidence_checksum_invalid")
    if any(hashes[name] != digest for name, digest in checksums.items()):
        raise EvidenceError("final_evidence_checksum_mismatch")

    try:
        report = read(directory / "COMPLETION_REPORT.md", 32 * 1024 * 1024).decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceError("final_evidence_report_invalid") from None
    identity = f"| Core repository commit and tag | `{commit}` / `{tag}` |"
    evidence_target = f"Evidence publication target: [`evidence/{tag}`]"
    if report.count(identity) != 1 or report.count(evidence_target) != 1:
        raise EvidenceError("final_evidence_report_identity_mismatch")
    retained: dict[str, str] = {}
    for line in report.splitlines():
        match = REPORT_HASH.fullmatch(line)
        if match is None or match.group(1) not in DURABLE:
            continue
        if match.group(1) in retained:
            raise EvidenceError("final_evidence_report_assets_invalid")
        retained[match.group(1)] = match.group(2)
    if set(retained) != DURABLE:
        raise EvidenceError("final_evidence_report_assets_invalid")
    if any(hashes[name] != digest for name, digest in retained.items()):
        raise EvidenceError("final_evidence_report_asset_mismatch")
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--release-tag", required=True)
    arguments = parser.parse_args()
    try:
        release = json.loads(
            read(arguments.release, 32 * 1024 * 1024), object_pairs_hook=strict_object
        )
        if not isinstance(release, dict):
            raise EvidenceError("final_evidence_release_invalid")
        validate(
            arguments.directory,
            release,
            arguments.candidate_commit,
            arguments.release_tag,
        )
    except (EvidenceError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"Final evidence release rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
