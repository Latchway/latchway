#!/usr/bin/env python3
"""Resolve exact platform-child digests from a published OCI index."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PLATFORM = re.compile(r"[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9]+)?\Z")
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def resolve_platform_digests(
    document: Mapping[str, Any], required: Iterable[str]
) -> dict[str, str]:
    if document.get("schemaVersion") != 2:
        raise ValueError("OCI index schemaVersion must be 2")
    if document.get("mediaType") not in INDEX_MEDIA_TYPES:
        raise ValueError("OCI index mediaType is unsupported")
    manifests = document.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("OCI index manifests must be an array")

    required_platforms = list(required)
    if len(required_platforms) != len(set(required_platforms)):
        raise ValueError("required OCI platforms must be unique")
    if not required_platforms or any(
        not isinstance(value, str) or PLATFORM.fullmatch(value) is None
        for value in required_platforms
    ):
        raise ValueError("required OCI platform is invalid")

    resolved: dict[str, str] = {}
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise ValueError("OCI manifest descriptor must be an object")
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            continue
        operating_system = platform.get("os")
        architecture = platform.get("architecture")
        variant = platform.get("variant")
        if not isinstance(operating_system, str) or not isinstance(
            architecture, str
        ):
            continue
        if operating_system == "unknown" or architecture == "unknown":
            continue
        name = f"{operating_system}/{architecture}"
        if variant is not None:
            if not isinstance(variant, str) or not variant:
                raise ValueError("OCI platform variant is invalid")
        if name not in required_platforms:
            continue

        if descriptor.get("mediaType") not in MANIFEST_MEDIA_TYPES:
            raise ValueError(f"OCI platform {name} has an unsupported mediaType")
        digest = descriptor.get("digest")
        size = descriptor.get("size")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ValueError(f"OCI platform {name} has an invalid digest")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"OCI platform {name} has an invalid descriptor size")
        if name in resolved:
            raise ValueError(f"OCI platform {name} is duplicated")
        resolved[name] = digest

    missing = [name for name in required_platforms if name not in resolved]
    if missing:
        raise ValueError("OCI index is missing required platforms: " + ", ".join(missing))
    return {name: resolved[name] for name in required_platforms}


def output_key(platform: str) -> str:
    return platform.replace("/", "_").replace("-", "_")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("index", type=Path, help="raw OCI index JSON")
    parser.add_argument("platform", nargs="+", help="required os/architecture")
    args = parser.parse_args()

    document = json.loads(args.index.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("OCI index must be an object")
    resolved = resolve_platform_digests(document, args.platform)
    for platform, digest in resolved.items():
        print(f"{output_key(platform)}={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
