#!/usr/bin/env python3
"""Verify and import reproducible SDK documentation bundles.

The SDK repositories own source examples and API catalogs.  This module is the
only supported path from their release bundles into the public documentation
tree; generated files must never be copied or edited by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, Mapping
import zlib


ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "docs" / "sdk-bundles.lock"
PUBLIC_ROOT = ROOT / "docs" / "public"
SCHEMA = "latchway.sdk-documentation-bundle.v1"
LOCK_SCHEMA = "latchway.sdk-documentation-lock.v1"
GENERATED_SCHEMA = "latchway.generated-sdk-documentation.v1"
VERSION = "1.0.0"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 64
MAX_METADATA_BYTES = 4 * 1024 * 1024


class BundleError(RuntimeError):
    """A bundle, lock, source, or generated output violated the contract."""


SDK_SPECS: Mapping[str, Mapping[str, Any]] = {
    "js": {
        "repository": "https://github.com/Latchway/latchway-js",
        "package": "@latchway/client",
        "directory": "latchway-js",
        "required_documents": {
            "quickstart/firebase-app-check.ts": "quickstart",
            "quickstart/vanilla-development-helper.ts": "quickstart",
            "quickstart/vanilla-development-client.ts": "quickstart",
            "quickstart/vanilla-streaming-fetch.ts": "quickstart",
            "frameworks/openai.ts": "framework",
            "frameworks/vercel-ai.ts": "framework",
            "frameworks/langchain.ts": "framework",
        },
    },
    "ios": {
        "repository": "https://github.com/Latchway/latchway-ios-sdk",
        "package": "Latchway",
        "directory": "latchway-ios-sdk",
        "required_documents": {
            "quickstart/url-session.swift": "quickstart",
            "quickstart/app-extension-component.swift": "quickstart",
            "frameworks/swift-openai.swift": "framework",
            "frameworks/foundation-models.swift": "framework",
        },
    },
    "android": {
        "repository": "https://github.com/Latchway/latchway-android",
        "package": "dev.latchway",
        "directory": "latchway-android",
        "required_documents": {
            "quickstart/basic-client.kt": "quickstart",
            "quickstart/firebase-auth.kt": "quickstart",
            "frameworks/retrofit.kt": "framework",
            "frameworks/openai-kotlin.kt": "framework",
            "frameworks/langchain4j.kt": "framework",
            "frameworks/koog.kt": "framework",
        },
    },
    "react-native": {
        "repository": "https://github.com/Latchway/latchway-react-native-sdk",
        "package": "@latchway/react-native",
        "directory": "latchway-react-native-sdk",
        "required_documents": {
            "quickstart/create-client.tsx": "quickstart",
            "quickstart/streaming-fetch.tsx": "quickstart",
            "frameworks/react-native-consumers.ts": "framework",
        },
    },
}

CATALOG_KINDS = {
    "errors.json": "errors",
    "examples.json": "examples",
    "public-symbols.json": "public_symbols",
    "supported-versions.json": "supported_versions",
}
COMMON_KINDS = {**CATALOG_KINDS, "release-notes.md": "release_notes"}
MANAGED_ROOTS = (
    PUBLIC_ROOT / "snippets" / "generated",
    PUBLIC_ROOT / "config" / "sdk-bundles",
    PUBLIC_ROOT / "reference" / "sdk-bundles",
)
GENERATED_MANIFEST = PUBLIC_ROOT / "config" / "generated-sdk-bundles.json"
GENERATED_OVERVIEW = PUBLIC_ROOT / "reference" / "sdk-bundles.mdx"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_archive(path: Path) -> bytes:
    try:
        mode = path.lstat().st_mode
        size = path.stat().st_size
    except FileNotFoundError as error:
        raise BundleError(f"SDK documentation archive is missing: {path}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise BundleError(f"SDK documentation archive must be a regular non-symlink file: {path}")
    if size < 18 or size > MAX_ARCHIVE_BYTES:
        raise BundleError(f"SDK documentation archive size is invalid: {path}")
    with path.open("rb") as handle:
        raw = handle.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) != size:
        raise BundleError(f"SDK documentation archive changed while it was read: {path}")
    return raw


def read_regular_bytes(path: Path, label: str, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise BundleError(f"{label} is missing: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BundleError(f"{label} must be a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise BundleError(f"{label} size is invalid: {path}")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) != metadata.st_size:
        raise BundleError(f"{label} changed while it was read: {path}")
    return raw


def validate_destination(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise BundleError(f"managed destination escapes its root: {path}") from error
    try:
        root_mode = root.lstat().st_mode
    except FileNotFoundError as error:
        raise BundleError(f"managed destination root is missing: {root}") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise BundleError(f"managed destination root is unsafe: {root}")
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise BundleError(f"managed destination parent is unsafe: {current}")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise BundleError(f"managed destination is not a regular file: {path}")
    return True


def atomic_write(path: Path, data: bytes, root: Path) -> None:
    exists = validate_destination(path, root)
    if exists and path.read_bytes() == data:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_destination(path, root)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            handle.write(data)
            temporary = Path(handle.name)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def load_json(data: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BundleError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                BundleError(f"{label} contains non-finite JSON number {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"{label} is not canonical UTF-8 JSON") from error


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BundleError(f"{label} has an invalid field set")
    return value


def safe_relative(value: Any, label: str = "path") -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "//" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise BundleError(f"{label} must be a canonical printable POSIX path")
    path = PurePosixPath(value)
    if path.as_posix() != value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"unsafe {label}: {value}")
    return path


def decompress_archive(raw: bytes) -> tuple[bytes, int]:
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise BundleError("documentation bundle exceeds the archive size limit")
    if len(raw) < 18 or raw[:4] != b"\x1f\x8b\x08\x00" or raw[8:10] != b"\x02\xff":
        raise BundleError("documentation bundle has a non-canonical gzip header")
    epoch = int.from_bytes(raw[4:8], "little")
    decompressor = zlib.decompressobj(wbits=31)
    try:
        payload = decompressor.decompress(raw, MAX_TAR_BYTES + 1)
        if len(payload) > MAX_TAR_BYTES or decompressor.unconsumed_tail:
            raise BundleError("documentation bundle exceeds the decompressed size limit")
        payload += decompressor.flush(MAX_TAR_BYTES - len(payload) + 1)
    except zlib.error as error:
        raise BundleError("documentation bundle gzip stream is invalid") from error
    if (
        len(payload) > MAX_TAR_BYTES
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise BundleError("documentation bundle has trailing, concatenated, or oversized gzip data")
    if not payload or len(payload) % 10240 != 0:
        raise BundleError("documentation bundle is not a canonically padded USTAR archive")
    return payload, epoch


def archive_members(raw: bytes, version: str) -> tuple[dict[str, bytes], int]:
    tar_bytes, gzip_epoch = decompress_archive(raw)
    root = f"docs-bundle-{version}"
    files: dict[str, bytes] = {}
    latest_payload_end = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:")
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise BundleError("documentation bundle member count is invalid")
        names = [member.name for member in members]
        if names != sorted(names) or len(names) != len(set(names)):
            raise BundleError("documentation bundle members must be unique and bytewise sorted")
        for member in members:
            candidate = safe_relative(member.name, "archive member")
            if len(candidate.parts) < 2 or candidate.parts[0] != root:
                raise BundleError(f"archive member is outside {root}: {member.name}")
            relative = "/".join(candidate.parts[1:])
            safe_relative(relative, "archive member path")
            header = tar_bytes[member.offset : member.offset + 512]
            canonical = tarfile.TarInfo(member.name)
            canonical.size = member.size
            canonical.mode = 0o644
            canonical.uid = canonical.gid = 0
            canonical.mtime = gzip_epoch
            canonical.type = tarfile.REGTYPE
            canonical.uname = canonical.gname = ""
            try:
                canonical_header = canonical.tobuf(
                    format=tarfile.USTAR_FORMAT,
                    encoding="utf-8",
                    errors="strict",
                )
            except (UnicodeError, ValueError) as error:
                raise BundleError(
                    f"archive member cannot be represented canonically: {member.name}"
                ) from error
            if (
                len(header) != 512
                or header != canonical_header
                or header[257:263] != b"ustar\x00"
                or header[263:265] != b"00"
                or header[156:157] != b"0"
                or any(header[345:500])
            ):
                raise BundleError(f"archive member is not canonical USTAR: {member.name}")
            if (
                not member.isfile()
                or member.issym()
                or member.islnk()
                or member.size < 0
                or member.size > MAX_MEMBER_BYTES
                or member.mode != 0o644
                or member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.pax_headers
                or member.mtime != gzip_epoch
            ):
                raise BundleError(f"archive member metadata is non-canonical: {member.name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise BundleError(f"archive member is unreadable: {member.name}")
            data = handle.read(MAX_MEMBER_BYTES + 1)
            if len(data) != member.size:
                raise BundleError(f"archive member length is invalid: {member.name}")
            padded_end = member.offset_data + ((member.size + 511) // 512) * 512
            if any(tar_bytes[member.offset_data + member.size : padded_end]):
                raise BundleError(
                    f"archive member payload padding is non-canonical: {member.name}"
                )
            files[relative] = data
            latest_payload_end = max(latest_payload_end, padded_end)
    except (tarfile.TarError, OSError) as error:
        raise BundleError("documentation bundle is not a valid USTAR archive") from error
    finally:
        try:
            archive.close()
        except UnboundLocalError:
            pass
    canonical_size = ((latest_payload_end + 1024 + 10239) // 10240) * 10240
    if (
        latest_payload_end <= 0
        or len(tar_bytes) != canonical_size
        or len(tar_bytes) - latest_payload_end < 1024
        or any(tar_bytes[latest_payload_end:])
    ):
        raise BundleError("documentation bundle has a non-zero or missing USTAR terminator")
    return files, gzip_epoch


def validate_source(value: Any, *, repository: str, release: str, commit: str, label: str) -> dict[str, Any]:
    source = exact_keys(
        value,
        {"repository", "release", "commit", "file", "region", "source_sha256", "region_sha256"},
        label,
    )
    region = exact_keys(source["region"], {"start_line", "end_line"}, f"{label}.region")
    start, end = region["start_line"], region["end_line"]
    if (
        source["repository"] != repository
        or source["release"] != release
        or source["commit"] != commit
        or not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 1
        or end < start
        or SHA256.fullmatch(str(source["source_sha256"])) is None
        or SHA256.fullmatch(str(source["region_sha256"])) is None
    ):
        raise BundleError(f"{label} is not bound to the SDK release source")
    safe_relative(source["file"], f"{label}.file")
    return source


def validate_catalog(path: str, raw: bytes, provenance: list[dict[str, Any]]) -> None:
    value = load_json(raw, path)
    if json_bytes(value) != raw:
        raise BundleError(f"{path} is not canonical sorted JSON")
    collection_by_path = {
        "errors.json": "errors",
        "examples.json": "examples",
        "public-symbols.json": "symbols",
        "supported-versions.json": "versions",
    }
    collection = collection_by_path[path]
    exact_keys(value, {"schema_version", collection}, path)
    rows = value[collection]
    if value["schema_version"] != 1 or not isinstance(rows, list) or not rows:
        raise BundleError(f"{path} catalog is empty or has an unsupported schema")
    row_sources: list[Any] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or "source" not in row or not isinstance(row.get("name"), str) or not row["name"]:
            raise BundleError(f"{path} row {index} is invalid")
        if path in {"errors.json", "public-symbols.json"}:
            exact_keys(row, {"name", "source"}, f"{path}[{index}]")
        elif path == "examples.json":
            exact_keys(row, {"name", "kind", "source"}, f"{path}[{index}]")
            if not isinstance(row["kind"], str) or not row["kind"]:
                raise BundleError(f"{path} row {index} has an invalid kind")
        else:
            exact_keys(row, {"name", "version", "source"}, f"{path}[{index}]")
            if not isinstance(row["version"], str) or not row["version"]:
                raise BundleError(f"{path} row {index} has an invalid version")
        row_sources.append(row["source"])
    if row_sources != provenance:
        raise BundleError(f"{path} provenance does not close over its catalog rows")


def validate_bundle(sdk: str, version: str, raw: bytes, repository_path: Path | None = None) -> dict[str, Any]:
    if sdk not in SDK_SPECS or version != VERSION:
        raise BundleError(f"unsupported SDK documentation coordinate: {sdk}@{version}")
    spec = SDK_SPECS[sdk]
    members, epoch = archive_members(raw, version)
    required = {**COMMON_KINDS, **spec["required_documents"]}
    expected_members = set(required) | {"bundle-manifest.json", "SHA256SUMS"}
    if set(members) != expected_members:
        missing = sorted(expected_members - set(members))
        extra = sorted(set(members) - expected_members)
        raise BundleError(f"{sdk} bundle member closure differs (missing={missing}, extra={extra})")

    manifest_raw = members["bundle-manifest.json"]
    manifest = load_json(manifest_raw, "bundle-manifest.json")
    if json_bytes(manifest) != manifest_raw:
        raise BundleError("bundle-manifest.json is not canonical sorted JSON")
    exact_keys(
        manifest,
        {
            "schema_version", "archive", "bundle_root", "repository", "package",
            "release", "source_date_epoch", "source_tree_clean", "generator", "files",
        },
        "bundle-manifest.json",
    )
    release = exact_keys(manifest["release"], {"version", "tag", "commit"}, "manifest.release")
    generator = exact_keys(manifest["generator"], {"file", "sha256"}, "manifest.generator")
    commit = release["commit"]
    if (
        manifest["schema_version"] != SCHEMA
        or manifest["archive"] != f"docs-bundle-{version}.tar.gz"
        or manifest["bundle_root"] != f"docs-bundle-{version}"
        or manifest["repository"] != spec["repository"]
        or manifest["package"] != spec["package"]
        or release != {"version": version, "tag": f"v{version}", "commit": commit}
        or not isinstance(commit, str)
        or COMMIT.fullmatch(commit) is None
        or not isinstance(manifest["source_tree_clean"], bool)
        or not isinstance(manifest["source_date_epoch"], int)
        or isinstance(manifest["source_date_epoch"], bool)
        or manifest["source_date_epoch"] != epoch
        or manifest["source_date_epoch"] < 0
        or generator["file"] != "scripts/build_docs_bundle.py"
        or SHA256.fullmatch(str(generator["sha256"])) is None
    ):
        raise BundleError("bundle manifest identity or release binding is invalid")
    safe_relative(generator["file"], "manifest.generator.file")

    records = manifest["files"]
    if not isinstance(records, list) or [item.get("path") for item in records if isinstance(item, dict)] != sorted(required):
        raise BundleError("bundle manifest files must exactly match the sorted payload closure")
    all_sources: list[dict[str, Any]] = []
    for index, record_value in enumerate(records):
        record = exact_keys(record_value, {"path", "kind", "bytes", "sha256", "provenance"}, f"manifest.files[{index}]")
        path = str(safe_relative(record["path"], f"manifest.files[{index}].path"))
        payload = members.get(path)
        sources = record["provenance"]
        if (
            payload is None
            or record["kind"] != required.get(path)
            or not isinstance(record["bytes"], int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] != len(payload)
            or record["sha256"] != sha256(payload)
            or not isinstance(sources, list)
            or not sources
        ):
            raise BundleError(f"manifest payload record is invalid: {path}")
        validated = [
            validate_source(
                source,
                repository=spec["repository"],
                release=f"v{version}",
                commit=commit,
                label=f"manifest.files[{index}].provenance[{source_index}]",
            )
            for source_index, source in enumerate(sources)
        ]
        if path in spec["required_documents"] or path == "release-notes.md":
            if len(validated) != 1:
                raise BundleError(f"source document must have one exact provenance region: {path}")
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise BundleError(f"source document is not UTF-8: {path}") from error
        if path in CATALOG_KINDS:
            validate_catalog(path, payload, validated)
        all_sources.extend(validated)

    expected_sums = b"".join(
        f"{sha256(members[name])}  {name}\n".encode("ascii")
        for name in sorted(members)
        if name != "SHA256SUMS"
    )
    if members["SHA256SUMS"] != expected_sums:
        raise BundleError("SHA256SUMS does not exactly close over the bundle members")

    if repository_path is not None:
        verify_repository_sources(repository_path, commit, all_sources)
        generator_bytes = regular_source(repository_path, generator["file"]).read_bytes()
        if sha256(generator_bytes) != generator["sha256"]:
            raise BundleError("SDK bundle generator hash differs from the checked-out source")
        if manifest["source_tree_clean"]:
            try:
                dirty = subprocess.run(
                    ["git", "status", "--porcelain", "--untracked-files=all"],
                    cwd=repository_path,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                ).stdout
            except subprocess.CalledProcessError as error:
                raise BundleError("SDK source cleanliness cannot be verified") from error
            if dirty:
                raise BundleError(
                    "bundle claims a clean SDK source tree but the checkout is dirty"
                )
    return {
        "archive_bytes": len(raw),
        "archive_sha256": sha256(raw),
        "manifest": manifest,
        "manifest_sha256": sha256(manifest_raw),
        "members": members,
    }


def regular_source(root: Path, relative: str) -> Path:
    safe_relative(relative, "source path")
    root = root.resolve()
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as error:
            raise BundleError(f"SDK source file is absent: {relative}") from error
        if stat.S_ISLNK(mode):
            raise BundleError(f"SDK source path contains a symlink: {relative}")
    if not stat.S_ISREG(current.lstat().st_mode) or not current.resolve().is_relative_to(root):
        raise BundleError(f"SDK source is not a regular in-repository file: {relative}")
    return current


def verify_repository_sources(repository: Path, commit: str, sources: list[dict[str, Any]]) -> None:
    if not repository.is_dir():
        raise BundleError(f"SDK repository does not exist: {repository}")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise BundleError(f"SDK repository has no readable Git HEAD: {repository}") from error
    if head != commit:
        raise BundleError(f"SDK bundle commit {commit} does not equal checked-out HEAD {head}")
    cached: dict[str, tuple[bytes, list[bytes]]] = {}
    for source in sources:
        relative = source["file"]
        if relative not in cached:
            raw = regular_source(repository, relative).read_bytes()
            try:
                lines = raw.decode("utf-8").splitlines(keepends=True)
            except UnicodeDecodeError as error:
                raise BundleError(f"SDK source is not UTF-8: {relative}") from error
            cached[relative] = (raw, [line.encode("utf-8") for line in lines])
        raw, lines = cached[relative]
        start, end = source["region"]["start_line"], source["region"]["end_line"]
        if end > len(lines):
            raise BundleError(f"SDK source region exceeds {relative}")
        region = b"".join(lines[start - 1 : end])
        if sha256(raw) != source["source_sha256"] or sha256(region) != source["region_sha256"]:
            raise BundleError(f"SDK source provenance hash differs at {relative}:{start}-{end}")


def lock_entry(sdk: str, result: Mapping[str, Any]) -> dict[str, Any]:
    manifest = result["manifest"]
    return {
        "archive": f"docs/sdk-bundles/{sdk}/docs-bundle-{VERSION}.tar.gz",
        "archive_bytes": result["archive_bytes"],
        "archive_sha256": result["archive_sha256"],
        "commit": manifest["release"]["commit"],
        "generator_sha256": manifest["generator"]["sha256"],
        "id": sdk,
        "manifest_sha256": result["manifest_sha256"],
        "package": manifest["package"],
        "release": manifest["release"]["tag"],
        "repository": manifest["repository"],
        "source_date_epoch": manifest["source_date_epoch"],
        "source_tree_clean": manifest["source_tree_clean"],
        "version": manifest["release"]["version"],
    }


def read_lock(require_complete: bool) -> dict[str, Any]:
    try:
        LOCK_PATH.lstat()
    except FileNotFoundError:
        if require_complete:
            raise BundleError("docs/sdk-bundles.lock is missing")
        return {"bundle_schema_version": SCHEMA, "bundles": [], "schema_version": LOCK_SCHEMA}
    raw = read_regular_bytes(LOCK_PATH, "docs/sdk-bundles.lock", MAX_METADATA_BYTES)
    value = load_json(raw, "docs/sdk-bundles.lock")
    if json_bytes(value) != raw:
        raise BundleError("docs/sdk-bundles.lock is not canonical sorted JSON")
    exact_keys(value, {"schema_version", "bundle_schema_version", "bundles"}, "docs/sdk-bundles.lock")
    entries = value["bundles"]
    if value["schema_version"] != LOCK_SCHEMA or value["bundle_schema_version"] != SCHEMA or not isinstance(entries, list):
        raise BundleError("docs/sdk-bundles.lock has an unsupported schema")
    expected_keys = {
        "id", "repository", "package", "version", "release", "commit", "archive",
        "archive_bytes", "archive_sha256", "manifest_sha256", "generator_sha256",
        "source_date_epoch", "source_tree_clean",
    }
    ids: list[str] = []
    for index, entry_value in enumerate(entries):
        entry = exact_keys(entry_value, expected_keys, f"lock.bundles[{index}]")
        sdk = entry["id"]
        if sdk not in SDK_SPECS or entry["repository"] != SDK_SPECS[sdk]["repository"] or entry["package"] != SDK_SPECS[sdk]["package"]:
            raise BundleError(f"lock.bundles[{index}] has an invalid SDK identity")
        if (
            entry["version"] != VERSION
            or entry["release"] != f"v{VERSION}"
            or COMMIT.fullmatch(str(entry["commit"])) is None
            or entry["archive"] != f"docs/sdk-bundles/{sdk}/docs-bundle-{VERSION}.tar.gz"
            or not isinstance(entry["archive_bytes"], int)
            or isinstance(entry["archive_bytes"], bool)
            or entry["archive_bytes"] <= 0
            or any(SHA256.fullmatch(str(entry[key])) is None for key in ("archive_sha256", "manifest_sha256", "generator_sha256"))
            or not isinstance(entry["source_date_epoch"], int)
            or isinstance(entry["source_date_epoch"], bool)
            or entry["source_date_epoch"] < 0
            or not isinstance(entry["source_tree_clean"], bool)
        ):
            raise BundleError(f"lock.bundles[{index}] is invalid")
        ids.append(sdk)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise BundleError("locked SDK bundle IDs must be unique and sorted")
    if require_complete and set(ids) != set(SDK_SPECS):
        raise BundleError("docs/sdk-bundles.lock must contain exactly the four v1 SDKs")
    return value


def provenance_header(source: Mapping[str, Any], archive_sha256: str) -> bytes:
    region = source["region"]
    return (
        "// Generated by scripts/docs-sync-sdk; DO NOT EDIT.\n"
        f"// Source repository: {source['repository']}\n"
        f"// Source release: {source['release']}\n"
        f"// Source commit: {source['commit']}\n"
        f"// Source file: {source['file']}\n"
        f"// Source region: L{region['start_line']}-L{region['end_line']}\n"
        f"// Bundle SHA-256: {archive_sha256}\n\n"
    ).encode("utf-8")


def mdx_fence(path: str, body: str) -> str:
    language = Path(path).suffix.lstrip(".")
    language = {"tsx": "tsx", "ts": "typescript", "swift": "swift", "kt": "kotlin"}.get(language, "text")
    fence = "```"
    while fence in body:
        fence += "`"
    return f"{fence}{language}\n{body.rstrip()}\n{fence}\n"


def render_mdx_snippet(
    path: str,
    body: bytes,
    source: Mapping[str, Any],
    entry: Mapping[str, Any],
) -> bytes:
    region = source["region"]
    if entry["source_tree_clean"]:
        source_note = (
            f"Generated from [{source['file']}]({source['repository']}/blob/{source['commit']}/"
            f"{source['file']}#L{region['start_line']}-L{region['end_line']}) at "
            f"release `{source['release']}`. Bundle SHA-256: `{entry['archive_sha256']}`."
        )
    else:
        source_note = (
            f"Generated from working-tree source `{source['file']}:L{region['start_line']}-"
            f"L{region['end_line']}` for release candidate `{source['release']}` and recorded "
            f"commit `{source['commit']}`. The dirty bundle does not claim that this region is "
            f"already at that commit. Bundle SHA-256: `{entry['archive_sha256']}`."
        )
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleError(f"SDK snippet payload is not UTF-8: {path}") from error
    return (
        "<Info>\n  " + source_note + "\n</Info>\n\n" + mdx_fence(path, text)
    ).encode("utf-8")


def render_sdk_page(sdk: str, entry: Mapping[str, Any], result: Mapping[str, Any]) -> bytes:
    manifest, members = result["manifest"], result["members"]
    title = {"js": "JavaScript SDK", "ios": "iOS SDK", "android": "Android SDK", "react-native": "React Native SDK"}[sdk]
    versions = load_json(members["supported-versions.json"], f"{sdk}/supported-versions.json")["versions"]
    lines = [
        "---", f'title: "{title} source bundle"',
        f'description: "Generated, version-bound examples and compatibility metadata for {title} {VERSION}."',
        "---", "", "<Warning>",
        "  This page proves the checked-in source bundle and its provenance. It does not claim",
        "  that the package or protected external release evidence has been published.",
        "</Warning>", "", "## Bundle identity", "",
        "| Field | Value |", "| --- | --- |",
        f"| Package | `{manifest['package']}` |",
        f"| Release | `{manifest['release']['tag']}` |",
        f"| Commit | `{manifest['release']['commit']}` |",
        f"| Source tree clean | `{'yes' if manifest['source_tree_clean'] else 'no'}` |",
        f"| Bundle SHA-256 | `{entry['archive_sha256']}` |", "", "## Supported versions", "",
        "| Dependency or platform | Tested version | Source |", "| --- | --- | --- |",
    ]
    for item in versions:
        source = item["source"]
        lines.append(
            f"| {item['name']} | `{item['version']}` | `{source['file']}:L{source['region']['start_line']}-L{source['region']['end_line']}` |"
        )
    record_by_path = {record["path"]: record for record in manifest["files"]}
    lines.extend(["", "## Version-bound examples", ""])
    for path in sorted(SDK_SPECS[sdk]["required_documents"]):
        source = record_by_path[path]["provenance"][0]
        if manifest["source_tree_clean"]:
            source_note = (
                f"Source: [{source['file']}]({source['repository']}/blob/{source['commit']}/"
                f"{source['file']}#L{source['region']['start_line']}-L{source['region']['end_line']})"
            )
        else:
            source_note = (
                f"Working-tree source: `{source['file']}:L{source['region']['start_line']}-"
                f"L{source['region']['end_line']}`. The bundle records candidate commit "
                f"`{source['commit']}`, but does not claim that this dirty source region is "
                "already present at that commit."
            )
        lines.extend([
            f"### `{path}`", "",
            source_note,
            "", mdx_fence(path, members[path].decode("utf-8")).rstrip(), "",
        ])
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def render_outputs(locked: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[Path, bytes]:
    outputs: dict[Path, bytes] = {}
    manifest_bundles: list[dict[str, Any]] = []
    overview_rows: list[str] = []
    for entry, result in locked:
        sdk, manifest, members = entry["id"], result["manifest"], result["members"]
        files: list[dict[str, Any]] = []
        for record in manifest["files"]:
            path = record["path"]
            if record["kind"] in {"quickstart", "framework"}:
                source = record["provenance"][0]
                destination = PUBLIC_ROOT / "snippets" / "generated" / sdk / path
                data = provenance_header(source, entry["archive_sha256"]) + members[path]
                outputs[destination] = data
                snippet_destination = destination.with_name(destination.name + ".mdx")
                snippet_data = render_mdx_snippet(path, members[path], source, entry)
                outputs[snippet_destination] = snippet_data
                files.append({
                    "generated_path": destination.relative_to(PUBLIC_ROOT).as_posix(),
                    "generated_sha256": sha256(data),
                    "kind": record["kind"],
                    "payload_path": path,
                    "payload_sha256": record["sha256"],
                    "provenance": record["provenance"],
                    "snippet_path": snippet_destination.relative_to(PUBLIC_ROOT).as_posix(),
                    "snippet_sha256": sha256(snippet_data),
                })
        for path in sorted(CATALOG_KINDS):
            destination = PUBLIC_ROOT / "config" / "sdk-bundles" / sdk / path
            outputs[destination] = members[path]
        page = PUBLIC_ROOT / "reference" / "sdk-bundles" / f"{sdk}.mdx"
        outputs[page] = render_sdk_page(sdk, entry, result)
        manifest_bundles.append({
            "archive": entry["archive"],
            "archive_sha256": entry["archive_sha256"],
            "commit": entry["commit"],
            "files": files,
            "id": sdk,
            "package": entry["package"],
            "release": entry["release"],
            "repository": entry["repository"],
            "source_date_epoch": entry["source_date_epoch"],
            "source_tree_clean": entry["source_tree_clean"],
            "version": entry["version"],
        })
        overview_rows.append(
            f"| [{sdk}](/reference/sdk-bundles/{sdk}) | `{entry['package']}` | "
            f"`{entry['release']}` | `{'yes' if entry['source_tree_clean'] else 'no'}` | "
            f"`{entry['commit']}` | `{entry['archive_sha256']}` |"
        )
    overview = [
        "---", 'title: "SDK documentation bundles"',
        'description: "Trace generated SDK examples and API catalogs to versioned source bundles and exact provenance."',
        "---", "", "SDK quickstarts and framework examples are imported only through",
        "`scripts/docs-sync-sdk`. Every generated source file identifies the SDK repository,",
        "release, commit, file, and exact line region. CI verifies the archive, manifest,",
        "checksums, lock, provenance, and generated output before documentation can merge.", "",
        "<Warning>", "  A checked-in source bundle is not evidence that its registry package or GitHub",
        "  release is public. See [Release status](/release-status) for protected external gates.",
        "</Warning>", "", "| SDK | Package | Release | Source tree clean | Commit | Bundle SHA-256 |",
        "| --- | --- | --- | --- | --- | --- |", *overview_rows, "", "## Update a bundle", "",
        "Run the source repository's bundle producer, then import the exact coordinate:", "",
        "```shell", "scripts/docs-sync-sdk ios 1.0.0", "scripts/docs-sync-sdk android 1.0.0",
        "scripts/docs-sync-sdk js 1.0.0", "scripts/docs-sync-sdk react-native 1.0.0", "```", "",
        "The command rejects archive traversal, links, non-canonical metadata, unknown files,",
        "checksum or manifest drift, source hash drift, and a commit that differs from the",
        "checked-out SDK repository. `scripts/docs-sync-sdk --check` is read-only.", "",
    ]
    outputs[GENERATED_OVERVIEW] = "\n".join(overview).encode("utf-8")
    output_rows = [
        {"bytes": len(data), "path": path.relative_to(PUBLIC_ROOT).as_posix(), "sha256": sha256(data)}
        for path, data in sorted(outputs.items(), key=lambda item: item[0].as_posix())
    ]
    generated = {
        "bundles": manifest_bundles,
        "generator": "scripts/docs_sdk_bundle.py",
        "lock_sha256": sha256(json_bytes({"bundle_schema_version": SCHEMA, "bundles": [entry for entry, _ in locked], "schema_version": LOCK_SCHEMA})),
        "outputs": output_rows,
        "schema_version": GENERATED_SCHEMA,
    }
    outputs[GENERATED_MANIFEST] = json_bytes(generated)
    return outputs


def load_locked_bundles(require_complete: bool = True) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    lock = read_lock(require_complete=require_complete)
    result: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for entry in lock["bundles"]:
        archive = ROOT / entry["archive"]
        raw = read_archive(archive)
        verified = validate_bundle(entry["id"], entry["version"], raw)
        expected = lock_entry(entry["id"], verified)
        if expected != entry:
            raise BundleError(f"locked metadata differs from archive: {entry['id']}")
        result.append((entry, verified))
    return result


def managed_existing() -> set[Path]:
    result: set[Path] = set()
    for root in MANAGED_ROOTS:
        if root.exists():
            if root.is_symlink() or not root.is_dir():
                raise BundleError(f"managed SDK documentation root is unsafe: {root}")
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise BundleError(f"managed SDK documentation contains a symlink: {path}")
                if path.is_file():
                    result.add(path)
    for path in (GENERATED_MANIFEST, GENERATED_OVERVIEW):
        if validate_destination(path, PUBLIC_ROOT):
            result.add(path)
    return result


def check_generated() -> None:
    locked = load_locked_bundles(require_complete=True)
    expected = render_outputs(locked)
    actual = managed_existing()
    if actual != set(expected):
        missing = sorted(path.relative_to(ROOT).as_posix() for path in set(expected) - actual)
        extra = sorted(path.relative_to(ROOT).as_posix() for path in actual - set(expected))
        raise BundleError(f"generated SDK documentation closure differs (missing={missing}, extra={extra})")
    changed = [path.relative_to(ROOT).as_posix() for path, data in expected.items() if path.read_bytes() != data]
    if changed:
        raise BundleError(f"generated SDK documentation drifted: {sorted(changed)}")


def write_generated() -> None:
    locked = load_locked_bundles(require_complete=True)
    expected = render_outputs(locked)
    for path, data in expected.items():
        atomic_write(path, data, PUBLIC_ROOT)
    for path in sorted(managed_existing() - set(expected), reverse=True):
        path.unlink()
    for root in MANAGED_ROOTS:
        if root.exists():
            for directory in sorted((path for path in root.rglob("*") if path.is_dir()), reverse=True):
                try:
                    directory.rmdir()
                except OSError:
                    pass


def sync_one(sdk: str, version: str, archive: Path, repository: Path) -> None:
    if sdk not in SDK_SPECS or version != VERSION:
        raise BundleError(f"unsupported SDK documentation coordinate: {sdk}@{version}")
    raw = read_archive(archive)
    verified = validate_bundle(sdk, version, raw, repository.resolve())
    lock = read_lock(require_complete=False)
    entries = {entry["id"]: entry for entry in lock["bundles"]}
    entry = lock_entry(sdk, verified)
    destination = ROOT / entry["archive"]
    atomic_write(destination, raw, ROOT)
    entries[sdk] = entry
    lock = {"bundle_schema_version": SCHEMA, "bundles": [entries[key] for key in sorted(entries)], "schema_version": LOCK_SCHEMA}
    atomic_write(LOCK_PATH, json_bytes(lock), ROOT)


def sync_all() -> None:
    candidates: list[tuple[str, bytes, dict[str, Any]]] = []
    for sdk in sorted(SDK_SPECS):
        repository = default_repository(sdk)
        archive = repository / ".artifacts" / f"docs-bundle-{VERSION}.tar.gz"
        raw = read_archive(archive)
        verified = validate_bundle(sdk, VERSION, raw, repository.resolve())
        candidates.append((sdk, raw, lock_entry(sdk, verified)))

    for sdk, raw, entry in candidates:
        atomic_write(ROOT / entry["archive"], raw, ROOT)
    lock = {
        "bundle_schema_version": SCHEMA,
        "bundles": [entry for _, _, entry in candidates],
        "schema_version": LOCK_SCHEMA,
    }
    atomic_write(LOCK_PATH, json_bytes(lock), ROOT)


def default_repository(sdk: str) -> Path:
    return ROOT.parent / SDK_SPECS[sdk]["directory"]


def command(arguments: argparse.Namespace) -> None:
    if arguments.check:
        check_generated()
        print("SDK documentation bundles and generated outputs are current")
        return
    if arguments.all:
        sync_all()
        write_generated()
        check_generated()
        print("imported all SDK documentation bundles")
        return
    if arguments.sdk is None or arguments.version is None:
        raise BundleError("specify <sdk> <version>, --all, or --check")
    repository = arguments.repository or default_repository(arguments.sdk)
    archive = arguments.archive or repository / ".artifacts" / f"docs-bundle-{arguments.version}.tar.gz"
    sync_one(arguments.sdk, arguments.version, archive, repository)
    if set(entry["id"] for entry in read_lock(require_complete=False)["bundles"]) == set(SDK_SPECS):
        write_generated()
        check_generated()
    print(f"imported {arguments.sdk} SDK documentation bundle {arguments.version}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk", nargs="?", choices=sorted(SDK_SPECS))
    parser.add_argument("version", nargs="?")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.check and (arguments.all or arguments.sdk or arguments.version or arguments.archive or arguments.repository):
        parser.error("--check cannot be combined with synchronization arguments")
    if arguments.all and (arguments.sdk or arguments.version or arguments.archive or arguments.repository):
        parser.error("--all cannot be combined with per-SDK arguments")
    try:
        command(arguments)
    except (BundleError, OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(2, f"SDK documentation bundle rejected: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
