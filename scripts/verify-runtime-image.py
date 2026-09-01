#!/usr/bin/env python3
"""Verify the exact filesystem and runtime configuration of a Latchway image.

The verifier accepts either a Docker ``image save`` archive or an OCI layout
archive.  It inspects image layers directly instead of exporting a container,
so daemon-injected files cannot hide an unexpected build artifact and a file
deleted by a later whiteout is still rejected.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


OCI_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_LAYER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_LAYER_MEMBERS = 64


@dataclass(frozen=True)
class ExpectedEntry:
    kind: str
    mode: int
    minimum_size: int = 0
    maximum_size: int = 0


EXPECTED_ROOTFS: dict[str, ExpectedEntry] = {
    "latchway": ExpectedEntry("file", 0o555, 1024 * 1024, 256 * 1024 * 1024),
    "etc": ExpectedEntry("directory", 0o755),
    "etc/ssl": ExpectedEntry("directory", 0o755),
    "etc/ssl/certs": ExpectedEntry("directory", 0o755),
    "etc/ssl/certs/ca-certificates.crt": ExpectedEntry(
        "file", 0o644, 1024, 8 * 1024 * 1024
    ),
    "licenses": ExpectedEntry("directory", 0o755),
    "licenses/latchway": ExpectedEntry("directory", 0o755),
    "licenses/latchway/LICENSE": ExpectedEntry("file", 0o644, 1024, 1024 * 1024),
    "licenses/latchway/NOTICE": ExpectedEntry("file", 0o644, 1, 1024 * 1024),
}
EXPECTED_LABELS = {
    "org.opencontainers.image.created",
    "org.opencontainers.image.description",
    "org.opencontainers.image.licenses",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.source",
    "org.opencontainers.image.title",
    "org.opencontainers.image.version",
}
EXPECTED_ENVIRONMENT = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
]


class VerificationError(ValueError):
    pass


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate JSON member")
        result[key] = value
    return result


def read_json_bytes(value: bytes, label: str) -> Any:
    if not value or len(value) > MAX_JSON_BYTES:
        raise VerificationError(f"{label} has an invalid size")
    try:
        return json.loads(
            value.decode("utf-8"), object_pairs_hook=duplicate_rejecting_object
        )
    except VerificationError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise VerificationError(f"{label} is not strict UTF-8 JSON") from None


def normalized_name(name: str) -> str:
    value = name.removeprefix("./").rstrip("/")
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise VerificationError("archive contains an unsafe path")
    return path.as_posix()


class ImageArchive:
    def __init__(self, path: str) -> None:
        try:
            self.archive = tarfile.open(path, mode="r:*")
        except (OSError, tarfile.TarError):
            raise VerificationError("image archive is unreadable") from None
        members = self.archive.getmembers()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise VerificationError("image archive member count is invalid")
        self.members: dict[str, tarfile.TarInfo] = {}
        for member in members:
            name = normalized_name(member.name)
            if name in self.members:
                raise VerificationError("image archive contains a duplicate path")
            if not (member.isfile() or member.isdir()):
                raise VerificationError("image archive contains a non-file member")
            self.members[name] = member

    def close(self) -> None:
        self.archive.close()

    def contains(self, name: str) -> bool:
        return name in self.members

    def read(self, name: str, maximum: int = MAX_LAYER_BYTES) -> bytes:
        member = self.members.get(name)
        if member is None or not member.isfile() or member.size <= 0 or member.size > maximum:
            raise VerificationError(f"image archive member is invalid: {name}")
        source = self.archive.extractfile(member)
        if source is None:
            raise VerificationError(f"image archive member is unreadable: {name}")
        value = source.read(maximum + 1)
        if len(value) != member.size or len(value) > maximum:
            raise VerificationError(f"image archive member changed size: {name}")
        return value

    def json(self, name: str) -> Any:
        return read_json_bytes(self.read(name, MAX_JSON_BYTES), name)

    def blob(self, descriptor: Mapping[str, Any]) -> bytes:
        digest = descriptor.get("digest")
        size = descriptor.get("size")
        if (
            not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > MAX_LAYER_BYTES
        ):
            raise VerificationError("OCI descriptor identity is invalid")
        path = f"blobs/sha256/{digest.removeprefix('sha256:')}"
        value = self.read(path, MAX_LAYER_BYTES)
        if len(value) != size or hashlib.sha256(value).hexdigest() != digest.removeprefix(
            "sha256:"
        ):
            raise VerificationError("OCI descriptor digest or size does not match")
        return value


def verify_config(value: Any, platform: str, layer_count: int) -> list[str]:
    if not isinstance(value, dict):
        raise VerificationError("image configuration is not an object")
    operating_system, architecture = platform.split("/", 1)
    if value.get("os") != operating_system or value.get("architecture") != architecture:
        raise VerificationError(f"image configuration does not match {platform}")
    rootfs = value.get("rootfs")
    if (
        not isinstance(rootfs, dict)
        or rootfs.get("type") != "layers"
        or not isinstance(rootfs.get("diff_ids"), list)
        or len(rootfs["diff_ids"]) != layer_count
        or not all(isinstance(item, str) and SHA256.fullmatch(item) for item in rootfs["diff_ids"])
    ):
        raise VerificationError("image rootfs configuration is invalid")
    config = value.get("config")
    if not isinstance(config, dict):
        raise VerificationError("runtime configuration is missing")
    if config.get("User") != "65532:65532":
        raise VerificationError("runtime user is not the fixed non-root identity")
    if config.get("Entrypoint") != ["/latchway"]:
        raise VerificationError("runtime entrypoint is invalid")
    if config.get("Cmd") != ["serve", "--role", "all"]:
        raise VerificationError("runtime command is invalid")
    if config.get("ExposedPorts") != {"8080/tcp": {}}:
        raise VerificationError("runtime exposed-port contract is invalid")
    if config.get("Env") != EXPECTED_ENVIRONMENT:
        raise VerificationError("runtime environment contains an unexpected value")
    if config.get("WorkingDir") not in {None, "", "/"}:
        raise VerificationError("runtime working directory is invalid")
    for forbidden in ("Healthcheck", "OnBuild", "Volumes"):
        forbidden_value = config.get(forbidden)
        if forbidden_value is not None and forbidden_value != ():
            raise VerificationError(f"runtime configuration contains {forbidden}")
    labels = config.get("Labels")
    if not isinstance(labels, dict) or set(labels) != EXPECTED_LABELS:
        raise VerificationError("runtime OCI labels are incomplete or contain extras")
    if labels.get("org.opencontainers.image.title") != "Latchway":
        raise VerificationError("runtime title label is invalid")
    if labels.get("org.opencontainers.image.licenses") != "Apache-2.0":
        raise VerificationError("runtime license label is invalid")
    if labels.get("org.opencontainers.image.source") != "https://github.com/Latchway/latchway":
        raise VerificationError("runtime source label is invalid")
    for label in EXPECTED_LABELS:
        if not isinstance(labels[label], str) or not labels[label]:
            raise VerificationError("runtime OCI label is empty")
    return list(rootfs["diff_ids"])


def uncompressed_layer(value: bytes, media_type: str | None) -> bytes:
    if media_type is not None and media_type not in LAYER_MEDIA_TYPES:
        raise VerificationError("image uses an unsupported layer media type")
    if value.startswith(b"\x1f\x8b"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(value), mode="rb") as source:
                uncompressed = source.read(MAX_LAYER_BYTES + 1)
        except (OSError, EOFError):
            raise VerificationError("image layer gzip stream is invalid") from None
        if len(uncompressed) > MAX_LAYER_BYTES:
            raise VerificationError("uncompressed image layer is too large")
        return uncompressed
    return value


def verify_layers(layers: Iterable[tuple[bytes, str | None]]) -> list[str]:
    observed: dict[str, tuple[ExpectedEntry, bytes]] = {}
    diff_ids: list[str] = []
    for raw, media_type in layers:
        payload = uncompressed_layer(raw, media_type)
        diff_ids.append("sha256:" + hashlib.sha256(payload).hexdigest())
        try:
            layer = tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
            members = layer.getmembers()
        except tarfile.TarError:
            raise VerificationError("image layer is not a strict tar archive") from None
        if not members or len(members) > MAX_LAYER_MEMBERS:
            raise VerificationError("image layer member count is invalid")
        for member in members:
            name = normalized_name(member.name)
            expected = EXPECTED_ROOTFS.get(name)
            if expected is None:
                raise VerificationError(f"unexpected runtime image path: {name}")
            if name in observed:
                raise VerificationError(f"runtime image path is overwritten: {name}")
            if member.uid != 0 or member.gid != 0:
                raise VerificationError(f"runtime image path has an unexpected owner: {name}")
            if member.mode & 0o7777 != expected.mode:
                raise VerificationError(f"runtime image path has an unexpected mode: {name}")
            if expected.kind == "directory":
                if not member.isdir() or member.size != 0:
                    raise VerificationError(f"runtime image directory is invalid: {name}")
                content = b""
            else:
                if (
                    not member.isfile()
                    or member.size < expected.minimum_size
                    or member.size > expected.maximum_size
                ):
                    raise VerificationError(f"runtime image file size is invalid: {name}")
                source = layer.extractfile(member)
                if source is None:
                    raise VerificationError(f"runtime image file is unreadable: {name}")
                content = source.read(expected.maximum_size + 1)
                if len(content) != member.size:
                    raise VerificationError(f"runtime image file changed size: {name}")
            observed[name] = (expected, content)
        layer.close()
    if set(observed) != set(EXPECTED_ROOTFS):
        missing = ", ".join(sorted(set(EXPECTED_ROOTFS) - set(observed)))
        raise VerificationError(f"runtime image paths are incomplete: {missing}")
    if not observed["latchway"][1].startswith(b"\x7fELF"):
        raise VerificationError("runtime latchway binary is not ELF")
    if b"-----BEGIN CERTIFICATE-----" not in observed[
        "etc/ssl/certs/ca-certificates.crt"
    ][1]:
        raise VerificationError("runtime CA bundle is invalid")
    if b"Apache License" not in observed["licenses/latchway/LICENSE"][1]:
        raise VerificationError("runtime license file is invalid")
    if b"Latchway" not in observed["licenses/latchway/NOTICE"][1]:
        raise VerificationError("runtime notice file is invalid")
    return diff_ids


def verify_docker_archive(archive: ImageArchive, required: set[str]) -> set[str]:
    manifest = archive.json("manifest.json")
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        raise VerificationError("Docker image archive must contain exactly one image")
    record = manifest[0]
    config_path = record.get("Config")
    layer_paths = record.get("Layers")
    if (
        not isinstance(config_path, str)
        or not isinstance(layer_paths, list)
        or not layer_paths
        or not all(isinstance(item, str) for item in layer_paths)
    ):
        raise VerificationError("Docker image manifest is invalid")
    config = read_json_bytes(archive.read(config_path, MAX_JSON_BYTES), config_path)
    if not isinstance(config, dict):
        raise VerificationError("Docker image configuration is invalid")
    platform = f"{config.get('os')}/{config.get('architecture')}"
    if required != {platform}:
        raise VerificationError("Docker image archive platform set does not match")
    expected_diff_ids = verify_config(config, platform, len(layer_paths))
    actual_diff_ids = verify_layers((archive.read(path), None) for path in layer_paths)
    if actual_diff_ids != expected_diff_ids:
        raise VerificationError("Docker image layer diff IDs do not match the configuration")
    return {platform}


def collect_oci_manifests(
    archive: ImageArchive,
    document: Any,
    inherited_platform: str | None = None,
) -> list[tuple[str, Mapping[str, Any]]]:
    if not isinstance(document, dict) or not isinstance(document.get("manifests"), list):
        raise VerificationError("OCI index is invalid")
    result: list[tuple[str, Mapping[str, Any]]] = []
    for descriptor in document["manifests"]:
        if not isinstance(descriptor, dict):
            raise VerificationError("OCI index descriptor is invalid")
        media_type = descriptor.get("mediaType")
        platform_value = descriptor.get("platform")
        platform = inherited_platform
        if isinstance(platform_value, dict):
            operating_system = platform_value.get("os")
            architecture = platform_value.get("architecture")
            if isinstance(operating_system, str) and isinstance(architecture, str):
                if operating_system == "unknown" or architecture == "unknown":
                    continue
                platform = f"{operating_system}/{architecture}"
        payload = archive.blob(descriptor)
        nested = read_json_bytes(payload, "OCI descriptor")
        if media_type in OCI_INDEX_MEDIA_TYPES:
            result.extend(collect_oci_manifests(archive, nested, platform))
        elif media_type in OCI_MANIFEST_MEDIA_TYPES:
            if platform is None:
                raise VerificationError("OCI image manifest has no concrete platform")
            if not isinstance(nested, dict):
                raise VerificationError("OCI image manifest is invalid")
            result.append((platform, nested))
        else:
            raise VerificationError("OCI index contains an unsupported descriptor")
    return result


def verify_oci_archive(archive: ImageArchive, required: set[str]) -> set[str]:
    index = archive.json("index.json")
    manifests = collect_oci_manifests(archive, index)
    by_platform: dict[str, Mapping[str, Any]] = {}
    for platform, manifest in manifests:
        if platform in by_platform:
            raise VerificationError(f"OCI archive repeats platform {platform}")
        by_platform[platform] = manifest
    if set(by_platform) != required:
        raise VerificationError("OCI image archive platform set does not match")
    for platform, manifest in sorted(by_platform.items()):
        config_descriptor = manifest.get("config")
        layer_descriptors = manifest.get("layers")
        if (
            not isinstance(config_descriptor, dict)
            or config_descriptor.get("mediaType")
            not in {
                "application/vnd.oci.image.config.v1+json",
                "application/vnd.docker.container.image.v1+json",
            }
            or not isinstance(layer_descriptors, list)
            or not layer_descriptors
            or not all(isinstance(item, dict) for item in layer_descriptors)
        ):
            raise VerificationError("OCI image manifest is incomplete")
        config = read_json_bytes(archive.blob(config_descriptor), "OCI image configuration")
        expected_diff_ids = verify_config(config, platform, len(layer_descriptors))
        actual_diff_ids = verify_layers(
            (archive.blob(descriptor), descriptor.get("mediaType"))
            for descriptor in layer_descriptors
        )
        if actual_diff_ids != expected_diff_ids:
            raise VerificationError("OCI image layer diff IDs do not match the configuration")
    return set(by_platform)


def required_platforms(values: Iterable[str]) -> set[str]:
    result = set(values)
    if not result or any(re.fullmatch(r"linux/(?:amd64|arm64)", item) is None for item in result):
        raise VerificationError("required platform set is invalid")
    return result


def verify(path: str, platforms: Iterable[str]) -> set[str]:
    required = required_platforms(platforms)
    archive = ImageArchive(path)
    try:
        if archive.contains("manifest.json"):
            return verify_docker_archive(archive, required)
        if archive.contains("oci-layout") and archive.contains("index.json"):
            return verify_oci_archive(archive, required)
        raise VerificationError("archive is neither a Docker image save nor an OCI layout")
    finally:
        archive.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", help="Docker image-save or OCI-layout tar archive")
    parser.add_argument(
        "platform",
        nargs="+",
        help="exact expected platform set, for example linux/amd64 linux/arm64",
    )
    arguments = parser.parse_args()
    platforms = verify(arguments.archive, arguments.platform)
    print(
        "verified minimal Latchway runtime image: "
        + ", ".join(sorted(platforms))
        + f"; {len(EXPECTED_ROOTFS)} exact filesystem entries"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"runtime image verification failed: {error}") from None
