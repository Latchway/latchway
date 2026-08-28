#!/usr/bin/env python3
"""Verify that an OCI archive contains every required release platform."""

from __future__ import annotations

import argparse
import json
import tarfile
from collections.abc import Iterable


OCI_INDEX = "application/vnd.oci.image.index.v1+json"


def blob_path(digest: str) -> str:
    algorithm, separator, value = digest.partition(":")
    if separator != ":" or algorithm != "sha256" or len(value) != 64:
        raise ValueError(f"unsupported OCI digest: {digest!r}")
    return f"blobs/{algorithm}/{value}"


def collect_platforms(
    archive: tarfile.TarFile,
    document: dict[str, object],
) -> set[str]:
    platforms: set[str] = set()
    manifests = document.get("manifests", [])
    if not isinstance(manifests, list):
        raise ValueError("OCI manifests must be a list")

    for raw_descriptor in manifests:
        if not isinstance(raw_descriptor, dict):
            raise ValueError("OCI descriptor must be an object")
        descriptor: dict[str, object] = raw_descriptor
        platform = descriptor.get("platform")
        if isinstance(platform, dict):
            operating_system = platform.get("os")
            architecture = platform.get("architecture")
            if (
                isinstance(operating_system, str)
                and isinstance(architecture, str)
                and operating_system != "unknown"
                and architecture != "unknown"
            ):
                platforms.add(f"{operating_system}/{architecture}")

        if descriptor.get("mediaType") == OCI_INDEX:
            digest = descriptor.get("digest")
            if not isinstance(digest, str):
                raise ValueError("nested OCI index is missing its digest")
            extracted = archive.extractfile(blob_path(digest))
            if extracted is None:
                raise ValueError(f"OCI index blob is missing: {digest}")
            nested = json.load(extracted)
            if not isinstance(nested, dict):
                raise ValueError("nested OCI index must be an object")
            platforms.update(collect_platforms(archive, nested))
    return platforms


def required_platforms(values: Iterable[str]) -> set[str]:
    required = set(values)
    invalid = sorted(value for value in required if value.count("/") != 1)
    if invalid:
        raise ValueError(f"invalid required platforms: {', '.join(invalid)}")
    return required


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", help="OCI archive produced by docker buildx")
    parser.add_argument(
        "platform",
        nargs="+",
        help="required os/architecture values, for example linux/amd64",
    )
    args = parser.parse_args()

    with tarfile.open(args.archive) as archive:
        extracted = archive.extractfile("index.json")
        if extracted is None:
            raise ValueError("OCI archive is missing index.json")
        index = json.load(extracted)
        if not isinstance(index, dict):
            raise ValueError("OCI index must be an object")
        actual = collect_platforms(archive, index)

    required = required_platforms(args.platform)
    missing = required - actual
    if missing:
        raise SystemExit(
            "OCI archive is missing required platforms: " + ", ".join(sorted(missing))
        )
    print("verified OCI platforms: " + ", ".join(sorted(actual)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
