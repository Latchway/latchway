#!/usr/bin/env python3
"""Tests for the fail-closed SDK documentation bundle importer."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("docs_sdk_bundle.py")
SPEC = importlib.util.spec_from_file_location("latchway_docs_sdk_bundle", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("SDK documentation bundle module cannot be loaded")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
MIRROR_SCRIPT = MODULE.ROOT / "docs" / "public" / "scripts" / "check-sdk-bundles.py"
MIRROR_SPEC = importlib.util.spec_from_file_location(
    "latchway_public_sdk_bundle_check",
    MIRROR_SCRIPT,
)
if MIRROR_SPEC is None or MIRROR_SPEC.loader is None:
    raise RuntimeError("public SDK bundle checker module cannot be loaded")
MIRROR = importlib.util.module_from_spec(MIRROR_SPEC)
MIRROR_SPEC.loader.exec_module(MIRROR)


class SDKDocumentationBundleTests(unittest.TestCase):
    def archive(self, sdk: str = "js") -> bytes:
        return (
            MODULE.ROOT
            / "docs"
            / "sdk-bundles"
            / sdk
            / f"docs-bundle-{MODULE.VERSION}.tar.gz"
        ).read_bytes()

    @staticmethod
    def repack(
        members: dict[str, bytes],
        epoch: int,
        *,
        rename: dict[str, str] | None = None,
        symlink: str | None = None,
        trailing: bytes = b"",
    ) -> bytes:
        rename = rename or {}
        output = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                rows = sorted((rename.get(name, name), name, data) for name, data in members.items())
                for output_name, original_name, data in rows:
                    info = tarfile.TarInfo(f"docs-bundle-{MODULE.VERSION}/{output_name}")
                    info.mode = 0o644
                    info.mtime = epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    if original_name == symlink:
                        info.type = tarfile.SYMTYPE
                        info.linkname = "target"
                        info.size = 0
                        archive.addfile(info)
                    else:
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
        return output.getvalue() + trailing

    @staticmethod
    def compress_tar(payload: bytes, epoch: int) -> bytes:
        output = io.BytesIO()
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=output,
            mtime=epoch,
            compresslevel=9,
        ) as compressed:
            compressed.write(payload)
        return output.getvalue()

    def test_checked_in_lock_archives_and_generated_outputs_are_exact_and_idempotent(self) -> None:
        locked = MODULE.load_locked_bundles(require_complete=True)
        self.assertEqual([entry["id"] for entry, _ in locked], sorted(MODULE.SDK_SPECS))
        first = MODULE.render_outputs(locked)
        second = MODULE.render_outputs(MODULE.load_locked_bundles(require_complete=True))
        self.assertEqual(first, second)
        MODULE.check_generated()
        for entry, result in locked:
            self.assertEqual(result["manifest"]["release"]["commit"], entry["commit"])
            self.assertEqual(hashlib.sha256(self.archive(entry["id"])).hexdigest(), entry["archive_sha256"])

    def test_traversal_links_checksum_tampering_duplicate_json_and_trailing_gzip_are_rejected(self) -> None:
        raw = self.archive()
        members, epoch = MODULE.archive_members(raw, MODULE.VERSION)
        source_name = "quickstart/firebase-app-check.ts"

        traversal = self.repack(
            members, epoch, rename={source_name: "quickstart/../../escape.ts"}
        )
        with self.assertRaisesRegex(MODULE.BundleError, "unsafe archive member"):
            MODULE.validate_bundle("js", MODULE.VERSION, traversal)

        linked = self.repack(members, epoch, symlink=source_name)
        with self.assertRaisesRegex(MODULE.BundleError, "canonical USTAR|metadata is non-canonical"):
            MODULE.validate_bundle("js", MODULE.VERSION, linked)

        changed = dict(members)
        changed[source_name] += b"\n// unowned drift\n"
        with self.assertRaisesRegex(MODULE.BundleError, "manifest payload record is invalid"):
            MODULE.validate_bundle("js", MODULE.VERSION, self.repack(changed, epoch))

        duplicate = dict(members)
        duplicate["bundle-manifest.json"] = duplicate["bundle-manifest.json"].replace(
            b'{\n  "archive":', b'{\n  "archive": "docs-bundle-1.0.0.tar.gz",\n  "archive":', 1
        )
        with self.assertRaisesRegex(MODULE.BundleError, "duplicate JSON key"):
            MODULE.validate_bundle("js", MODULE.VERSION, self.repack(duplicate, epoch))

        with self.assertRaisesRegex(MODULE.BundleError, "trailing, concatenated"):
            MODULE.validate_bundle("js", MODULE.VERSION, raw + b"trailing")

    def test_noncanonical_ustar_header_and_padding_are_rejected(self) -> None:
        raw = self.archive()
        tar_bytes, epoch = MODULE.decompress_archive(raw)

        padded = self.compress_tar(tar_bytes + b"\0" * 10240, epoch)
        with self.assertRaisesRegex(MODULE.BundleError, "USTAR terminator"):
            MODULE.validate_bundle("js", MODULE.VERSION, padded)

        changed = bytearray(tar_bytes)
        changed[100:108] = b"0000644 "
        changed[148:156] = b"        "
        checksum = sum(changed[:512])
        changed[148:156] = f"{checksum:06o}\0 ".encode("ascii")
        alternate_header = self.compress_tar(bytes(changed), epoch)
        with self.assertRaisesRegex(MODULE.BundleError, "canonical USTAR"):
            MODULE.validate_bundle("js", MODULE.VERSION, alternate_header)

        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            member = next(item for item in archive.getmembers() if item.size % 512)
        changed = bytearray(tar_bytes)
        changed[member.offset_data + member.size] = 1
        alternate_padding = self.compress_tar(bytes(changed), epoch)
        with self.assertRaisesRegex(MODULE.BundleError, "payload padding"):
            MODULE.validate_bundle("js", MODULE.VERSION, alternate_padding)

    def test_manifest_and_catalog_provenance_must_close_exactly(self) -> None:
        raw = self.archive()
        members, epoch = MODULE.archive_members(raw, MODULE.VERSION)
        manifest = json.loads(members["bundle-manifest.json"])
        manifest["repository"] = "https://github.com/example/substitution"
        changed = dict(members)
        changed["bundle-manifest.json"] = MODULE.json_bytes(manifest)
        changed["SHA256SUMS"] = b"".join(
            f"{MODULE.sha256(changed[name])}  {name}\n".encode("ascii")
            for name in sorted(changed)
            if name != "SHA256SUMS"
        )
        with self.assertRaisesRegex(MODULE.BundleError, "identity or release binding"):
            MODULE.validate_bundle("js", MODULE.VERSION, self.repack(changed, epoch))

        catalog = json.loads(members["supported-versions.json"])
        catalog["versions"][0]["source"]["region"]["start_line"] += 1
        changed = dict(members)
        changed["supported-versions.json"] = MODULE.json_bytes(catalog)
        record = next(item for item in manifest_for(members)["files"] if item["path"] == "supported-versions.json")
        record["bytes"] = len(changed["supported-versions.json"])
        record["sha256"] = MODULE.sha256(changed["supported-versions.json"])
        changed["bundle-manifest.json"] = MODULE.json_bytes(manifest_for(members, replacement=record))
        changed["SHA256SUMS"] = b"".join(
            f"{MODULE.sha256(changed[name])}  {name}\n".encode("ascii")
            for name in sorted(changed)
            if name != "SHA256SUMS"
        )
        with self.assertRaisesRegex(MODULE.BundleError, "provenance does not close"):
            MODULE.validate_bundle("js", MODULE.VERSION, self.repack(changed, epoch))

    def test_local_source_hash_and_checked_out_commit_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "docs@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Docs Test"], cwd=root, check=True)
            source = root / "example.ts"
            source.write_text("export const value = 1;\n", encoding="utf-8")
            subprocess.run(["git", "add", "example.ts"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=root, check=True)
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True,
                stdout=subprocess.PIPE, text=True, encoding="utf-8",
            ).stdout.strip()
            raw = source.read_bytes()
            provenance = [{
                "file": "example.ts",
                "region": {"start_line": 1, "end_line": 1},
                "source_sha256": MODULE.sha256(raw),
                "region_sha256": MODULE.sha256(raw),
            }]
            MODULE.verify_repository_sources(root, commit, provenance)
            source.write_text("export const value = 2;\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.BundleError, "provenance hash differs"):
                MODULE.verify_repository_sources(root, commit, provenance)
            with self.assertRaisesRegex(MODULE.BundleError, "does not equal checked-out HEAD"):
                MODULE.verify_repository_sources(root, "f" * 40, provenance)

    def test_managed_writes_reject_symlink_files_and_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_bytes(b"outside generated data\n")
            link = root / "generated.json"
            link.symlink_to(target)

            with self.assertRaisesRegex(MODULE.BundleError, "regular file"):
                MODULE.atomic_write(link, b"replacement\n", root)
            self.assertEqual(target.read_bytes(), b"outside generated data\n")
            with self.assertRaisesRegex(MODULE.BundleError, "regular non-symlink"):
                MODULE.read_regular_bytes(link, "fixture", 1024)

            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(MODULE.BundleError, "parent is unsafe"):
                MODULE.atomic_write(linked_parent / "output.json", b"{}\n", root)
            self.assertFalse((real_parent / "output.json").exists())

    def test_public_mirror_rejects_forged_payload_and_sdk_identity(self) -> None:
        source_root = MODULE.PUBLIC_ROOT
        manifest = json.loads(MODULE.GENERATED_MANIFEST.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            public_root = Path(directory) / "public"
            for output in manifest["outputs"]:
                source = source_root / output["path"]
                destination = public_root / output["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            manifest_path = public_root / "config" / "generated-sdk-bundles.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_bytes(MODULE.json_bytes(manifest))

            with (
                mock.patch.object(MIRROR, "PUBLIC_ROOT", public_root),
                mock.patch.object(MIRROR, "MANIFEST", manifest_path),
                mock.patch.object(MIRROR, "CORE_ROOT", Path(directory) / "no-core"),
            ):
                self.assertEqual(MIRROR.main(), 0)

                forged_identity = json.loads(manifest_path.read_text(encoding="utf-8"))
                forged_identity["bundles"][0]["repository"] = (
                    "https://github.com/example/substitution"
                )
                manifest_path.write_bytes(MODULE.json_bytes(forged_identity))
                with self.assertRaisesRegex(SystemExit, "invalid release coordinate"):
                    MIRROR.main()

                forged_payload = json.loads(MODULE.json_bytes(manifest))
                record = next(
                    item
                    for bundle in forged_payload["bundles"]
                    if bundle["id"] == "js"
                    for item in bundle["files"]
                    if item["payload_path"] == "frameworks/openai.ts"
                )
                generated = public_root / record["generated_path"]
                data = generated.read_bytes() + b"\n// forged payload\n"
                generated.write_bytes(data)
                record["generated_sha256"] = MODULE.sha256(data)
                output = next(
                    item
                    for item in forged_payload["outputs"]
                    if item["path"] == record["generated_path"]
                )
                output["bytes"] = len(data)
                output["sha256"] = MODULE.sha256(data)
                manifest_path.write_bytes(MODULE.json_bytes(forged_payload))
                with self.assertRaisesRegex(SystemExit, "payload differs"):
                    MIRROR.main()


def manifest_for(members: dict[str, bytes], replacement: dict | None = None) -> dict:
    manifest = json.loads(members["bundle-manifest.json"])
    if replacement is not None:
        manifest["files"] = [
            replacement if item["path"] == replacement["path"] else item
            for item in manifest["files"]
        ]
    return manifest


if __name__ == "__main__":
    unittest.main()
