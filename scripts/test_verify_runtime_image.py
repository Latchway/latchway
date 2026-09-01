#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_runtime_image", ROOT / "scripts/verify-runtime-image.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def tar_bytes(entries: list[tuple[str, bytes | None, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content, mode in entries:
            value = tarfile.TarInfo(name)
            value.mode = mode
            value.uid = 0
            value.gid = 0
            value.mtime = 1
            if content is None:
                value.type = tarfile.DIRTYPE
                archive.addfile(value)
            else:
                value.size = len(content)
                archive.addfile(value, io.BytesIO(content))
    return output.getvalue()


def layers(extra: tuple[str, bytes, int] | None = None) -> list[bytes]:
    binary = b"\x7fELF" + b"\x00" * (1024 * 1024)
    first = tar_bytes([("latchway", binary, 0o555)])
    second = tar_bytes(
        [
            ("etc", None, 0o755),
            ("etc/ssl", None, 0o755),
            ("etc/ssl/certs", None, 0o755),
            (
                "etc/ssl/certs/ca-certificates.crt",
                b"-----BEGIN CERTIFICATE-----\nfixture\n" + b"x" * 1024,
                0o644,
            ),
        ]
    )
    license_entries: list[tuple[str, bytes | None, int]] = [
        ("licenses", None, 0o755),
        ("licenses/latchway", None, 0o755),
        ("licenses/latchway/LICENSE", b"Apache License\n" + b"x" * 1024, 0o644),
        ("licenses/latchway/NOTICE", b"Latchway\n", 0o644),
    ]
    if extra is not None:
        license_entries.append(extra)
    return [first, second, tar_bytes(license_entries)]


def image_config(platform: str, image_layers: list[bytes]) -> dict:
    operating_system, architecture = platform.split("/", 1)
    return {
        "architecture": architecture,
        "os": operating_system,
        "config": {
            "User": "65532:65532",
            "ExposedPorts": {"8080/tcp": {}},
            "Env": list(MODULE.EXPECTED_ENVIRONMENT),
            "Entrypoint": ["/latchway"],
            "Cmd": ["serve", "--role", "all"],
            "WorkingDir": "/",
            "Labels": {
                "org.opencontainers.image.created": "2026-09-01T00:00:00Z",
                "org.opencontainers.image.description": "fixture",
                "org.opencontainers.image.licenses": "Apache-2.0",
                "org.opencontainers.image.revision": "1" * 40,
                "org.opencontainers.image.source": "https://github.com/Latchway/latchway",
                "org.opencontainers.image.title": "Latchway",
                "org.opencontainers.image.version": "1.0.0",
            },
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [
                "sha256:" + hashlib.sha256(layer).hexdigest() for layer in image_layers
            ],
        },
    }


def add_bytes(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    info.mode = 0o644
    info.mtime = 1
    archive.addfile(info, io.BytesIO(value))


def docker_archive(path: Path, *, extra=None, mutate_config=None, duplicate_binary=False) -> None:
    image_layers = layers(extra)
    if duplicate_binary:
        image_layers.append(tar_bytes([("latchway", b"\x7fELF" + b"x" * (1024 * 1024), 0o555)]))
    config = image_config("linux/amd64", image_layers)
    if mutate_config is not None:
        mutate_config(config)
    config_bytes = json.dumps(config).encode()
    manifest = [
        {
            "Config": "config.json",
            "RepoTags": ["latchway:test"],
            "Layers": [f"layer-{index}.tar" for index in range(len(image_layers))],
        }
    ]
    with tarfile.open(path, mode="w") as archive:
        add_bytes(archive, "manifest.json", json.dumps(manifest).encode())
        add_bytes(archive, "config.json", config_bytes)
        for index, layer in enumerate(image_layers):
            add_bytes(archive, f"layer-{index}.tar", layer)


def descriptor(value: bytes, media_type: str) -> dict:
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(value).hexdigest(),
        "size": len(value),
    }


def oci_archive(path: Path) -> None:
    blobs: dict[str, bytes] = {}
    manifests = []
    for platform in ("linux/amd64", "linux/arm64"):
        uncompressed_layers = layers()
        image_layers = [gzip.compress(value, mtime=0) for value in uncompressed_layers]
        layer_descriptors = []
        for layer in image_layers:
            layer_descriptor = descriptor(
                layer, "application/vnd.oci.image.layer.v1.tar+gzip"
            )
            blobs[layer_descriptor["digest"]] = layer
            layer_descriptors.append(layer_descriptor)
        config = json.dumps(
            image_config(platform, uncompressed_layers), sort_keys=True
        ).encode()
        config_descriptor = descriptor(
            config, "application/vnd.oci.image.config.v1+json"
        )
        blobs[config_descriptor["digest"]] = config
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": config_descriptor,
                "layers": layer_descriptors,
            },
            sort_keys=True,
        ).encode()
        manifest_descriptor = descriptor(
            manifest, "application/vnd.oci.image.manifest.v1+json"
        )
        operating_system, architecture = platform.split("/", 1)
        manifest_descriptor["platform"] = {
            "os": operating_system,
            "architecture": architecture,
        }
        blobs[manifest_descriptor["digest"]] = manifest
        manifests.append(manifest_descriptor)
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": manifests,
        },
        sort_keys=True,
    ).encode()
    with tarfile.open(path, mode="w") as archive:
        add_bytes(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add_bytes(archive, "index.json", index)
        for digest, value in blobs.items():
            add_bytes(archive, "blobs/sha256/" + digest.removeprefix("sha256:"), value)


class RuntimeImageTests(unittest.TestCase):
    def test_accepts_exact_docker_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            docker_archive(path)
            self.assertEqual(MODULE.verify(str(path), ["linux/amd64"]), {"linux/amd64"})

    def test_accepts_exact_multiarch_oci_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            oci_archive(path)
            self.assertEqual(
                MODULE.verify(str(path), ["linux/amd64", "linux/arm64"]),
                {"linux/amd64", "linux/arm64"},
            )

    def test_rejects_tool_source_or_cache_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            docker_archive(path, extra=("usr/bin/node", b"node", 0o755))
            with self.assertRaisesRegex(MODULE.VerificationError, "unexpected runtime image path"):
                MODULE.verify(str(path), ["linux/amd64"])

    def test_rejects_credential_bearing_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            docker_archive(
                path,
                mutate_config=lambda value: value["config"]["Env"].append(
                    "LATCHWAY_MASTER_KEY=forbidden"
                ),
            )
            with self.assertRaisesRegex(MODULE.VerificationError, "runtime environment"):
                MODULE.verify(str(path), ["linux/amd64"])

    def test_rejects_layer_diff_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            docker_archive(
                path,
                mutate_config=lambda value: value["rootfs"]["diff_ids"].__setitem__(
                    0, "sha256:" + "0" * 64
                ),
            )
            with self.assertRaisesRegex(MODULE.VerificationError, "diff IDs"):
                MODULE.verify(str(path), ["linux/amd64"])

    def test_rejects_overwritten_files_even_when_final_path_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            docker_archive(path, duplicate_binary=True)
            with self.assertRaisesRegex(MODULE.VerificationError, "is overwritten"):
                MODULE.verify(str(path), ["linux/amd64"])

    def test_rejects_platform_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            docker_archive(path)
            with self.assertRaisesRegex(MODULE.VerificationError, "platform set"):
                MODULE.verify(str(path), ["linux/arm64"])


if __name__ == "__main__":
    unittest.main()
