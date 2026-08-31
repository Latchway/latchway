#!/usr/bin/env python3
"""Verify generated SDK documentation in the canonical tree or docs mirror."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any


PUBLIC_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = PUBLIC_ROOT.parents[1]
MANIFEST = PUBLIC_ROOT / "config" / "generated-sdk-bundles.json"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SCHEMA = "latchway.generated-sdk-documentation.v1"
SDK_IDS = {"android", "ios", "js", "react-native"}
SDK_SPECS = {
    "android": {
        "repository": "https://github.com/Latchway/latchway-android",
        "package": "dev.latchway",
        "documents": {
            "frameworks/koog.kt",
            "frameworks/langchain4j.kt",
            "frameworks/openai-kotlin.kt",
            "frameworks/retrofit.kt",
            "quickstart/basic-client.kt",
            "quickstart/firebase-auth.kt",
        },
    },
    "ios": {
        "repository": "https://github.com/Latchway/latchway-ios-sdk",
        "package": "Latchway",
        "documents": {
            "frameworks/foundation-models.swift",
            "frameworks/swift-openai.swift",
            "quickstart/app-extension-component.swift",
            "quickstart/url-session.swift",
        },
    },
    "js": {
        "repository": "https://github.com/Latchway/latchway-js",
        "package": "@latchway/client",
        "documents": {
            "frameworks/langchain.ts",
            "frameworks/openai.ts",
            "frameworks/vercel-ai.ts",
            "quickstart/firebase-app-check.ts",
            "quickstart/vanilla-development-helper.ts",
            "quickstart/vanilla-development-client.ts",
            "quickstart/vanilla-streaming-fetch.ts",
        },
    },
    "react-native": {
        "repository": "https://github.com/Latchway/latchway-react-native-sdk",
        "package": "@latchway/react-native",
        "documents": {
            "frameworks/react-native-consumers.ts",
            "quickstart/create-client.tsx",
            "quickstart/streaming-fetch.tsx",
        },
    },
}
CATALOGS = {"errors.json", "examples.json", "public-symbols.json", "supported-versions.json"}


def fail(message: str) -> None:
    raise SystemExit(f"generated SDK documentation validation failed: {message}")


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has an invalid field set")
    return value


def safe_file(relative: Any, label: str) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or "//" in relative
        or any(ord(character) < 32 or ord(character) == 127 for character in relative)
    ):
        fail(f"{label} is not a canonical relative path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or pure.as_posix() != relative or any(part in {"", ".", ".."} for part in pure.parts):
        fail(f"{label} is unsafe")
    path = PUBLIC_ROOT / relative
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing or a symlink: {relative}")
    try:
        path.resolve().relative_to(PUBLIC_ROOT.resolve())
    except ValueError:
        fail(f"{label} escapes the public root")
    return path


def safe_relative(relative: Any, label: str) -> str:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or "//" in relative
        or any(ord(character) < 32 or ord(character) == 127 for character in relative)
    ):
        fail(f"{label} is not a canonical relative path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or pure.as_posix() != relative or any(
        part in {"", ".", ".."} for part in pure.parts
    ):
        fail(f"{label} is unsafe")
    return relative


def mdx_fence(path: str, body: str) -> str:
    suffix = Path(path).suffix.lstrip(".")
    language = {"tsx": "tsx", "ts": "typescript", "swift": "swift", "kt": "kotlin"}.get(
        suffix, "text"
    )
    fence = "```"
    while fence in body:
        fence += "`"
    return f"{fence}{language}\n{body.rstrip()}\n{fence}\n"


def rendered_snippet(
    payload_path: str,
    payload: bytes,
    source: dict[str, Any],
    bundle: dict[str, Any],
) -> bytes:
    try:
        body = payload.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"generated snippet payload is not UTF-8: {payload_path}")
    region = source["region"]
    if bundle["source_tree_clean"]:
        note = (
            f"Generated from [{source['file']}]({source['repository']}/blob/{source['commit']}/"
            f"{source['file']}#L{region['start_line']}-L{region['end_line']}) at "
            f"release `{source['release']}`. Bundle SHA-256: `{bundle['archive_sha256']}`."
        )
    else:
        note = (
            f"Generated from working-tree source `{source['file']}:L{region['start_line']}-"
            f"L{region['end_line']}` for release candidate `{source['release']}` and recorded "
            f"commit `{source['commit']}`. The dirty bundle does not claim that this region is "
            f"already at that commit. Bundle SHA-256: `{bundle['archive_sha256']}`."
        )
    return ("<Info>\n  " + note + "\n</Info>\n\n" + mdx_fence(payload_path, body)).encode(
        "utf-8"
    )


def main() -> int:
    try:
        manifest_path = safe_file(
            MANIFEST.relative_to(PUBLIC_ROOT).as_posix(),
            "generated manifest",
        )
        raw = manifest_path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read the generated manifest: {error}")
    if (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8") != raw:
        fail("generated manifest is not canonical sorted JSON")
    manifest = exact_keys(value, {"schema_version", "generator", "lock_sha256", "bundles", "outputs"}, "manifest")
    if manifest["schema_version"] != SCHEMA or manifest["generator"] != "scripts/docs_sdk_bundle.py" or DIGEST.fullmatch(str(manifest["lock_sha256"])) is None:
        fail("generated manifest coordinate is unsupported")

    bundles = manifest["bundles"]
    if not isinstance(bundles, list) or [item.get("id") for item in bundles if isinstance(item, dict)] != sorted(SDK_IDS):
        fail("generated manifest must contain exactly the four sorted SDKs")
    documented: set[str] = set()
    required_outputs: set[str] = {"reference/sdk-bundles.mdx"}
    for bundle_index, raw_bundle in enumerate(bundles):
        bundle = exact_keys(
            raw_bundle,
            {
                "id", "repository", "package", "version", "release", "commit",
                "archive", "archive_sha256", "source_date_epoch",
                "source_tree_clean", "files",
            },
            f"bundles[{bundle_index}]",
        )
        sdk = bundle["id"]
        spec = SDK_SPECS[sdk]
        if (
            bundle["repository"] != spec["repository"]
            or bundle["package"] != spec["package"]
            or bundle["version"] != "1.0.0"
            or bundle["release"] != "v1.0.0"
            or COMMIT.fullmatch(str(bundle["commit"])) is None
            or DIGEST.fullmatch(str(bundle["archive_sha256"])) is None
            or not isinstance(bundle["source_date_epoch"], int)
            or isinstance(bundle["source_date_epoch"], bool)
            or bundle["source_date_epoch"] < 0
            or not isinstance(bundle["source_tree_clean"], bool)
            or bundle["archive"]
            != f"docs/sdk-bundles/{sdk}/docs-bundle-1.0.0.tar.gz"
        ):
            fail(f"bundles[{bundle_index}] has an invalid release coordinate")
        files = bundle["files"]
        if not isinstance(files, list) or not files:
            fail(f"bundles[{bundle_index}].files is empty")
        paths: list[str] = []
        payload_paths: list[str] = []
        for file_index, raw_file in enumerate(files):
            record = exact_keys(
                raw_file,
                {
                    "generated_path", "generated_sha256", "kind", "payload_path",
                    "payload_sha256", "provenance", "snippet_path",
                    "snippet_sha256",
                },
                f"bundles[{bundle_index}].files[{file_index}]",
            )
            payload_path = safe_relative(
                record["payload_path"],
                f"bundles[{bundle_index}].files[{file_index}].payload_path",
            )
            expected_generated = f"snippets/generated/{sdk}/{payload_path}"
            expected_snippet = expected_generated + ".mdx"
            if (
                payload_path not in spec["documents"]
                or record["kind"]
                != ("quickstart" if payload_path.startswith("quickstart/") else "framework")
                or record["generated_path"] != expected_generated
                or record["snippet_path"] != expected_snippet
            ):
                fail(f"generated snippet coordinate differs: {payload_path}")
            path = safe_file(
                record["generated_path"],
                f"bundles[{bundle_index}].files[{file_index}].generated_path",
            )
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != record["generated_sha256"] or any(DIGEST.fullmatch(str(record[key])) is None for key in ("generated_sha256", "payload_sha256")):
                fail(f"generated snippet digest differs: {record['generated_path']}")
            provenance = record["provenance"]
            if not isinstance(provenance, list) or len(provenance) != 1:
                fail(f"generated snippet has invalid provenance: {record['generated_path']}")
            source = exact_keys(
                provenance[0],
                {"repository", "release", "commit", "file", "region", "source_sha256", "region_sha256"},
                f"bundles[{bundle_index}].files[{file_index}].provenance[0]",
            )
            region = exact_keys(source["region"], {"start_line", "end_line"}, "source.region")
            if (
                source["repository"] != bundle["repository"]
                or source["release"] != bundle["release"]
                or source["commit"] != bundle["commit"]
                or safe_relative(source["file"], "source.file") != source["file"]
                or not isinstance(region["start_line"], int)
                or isinstance(region["start_line"], bool)
                or not isinstance(region["end_line"], int)
                or isinstance(region["end_line"], bool)
                or region["start_line"] < 1
                or region["end_line"] < region["start_line"]
                or DIGEST.fullmatch(str(source["source_sha256"])) is None
                or DIGEST.fullmatch(str(source["region_sha256"])) is None
            ):
                fail(f"generated snippet provenance differs: {record['generated_path']}")
            expected_header = (
                "// Generated by scripts/docs-sync-sdk; DO NOT EDIT.\n"
                f"// Source repository: {source['repository']}\n"
                f"// Source release: {source['release']}\n"
                f"// Source commit: {source['commit']}\n"
                f"// Source file: {source['file']}\n"
                f"// Source region: L{region['start_line']}-L{region['end_line']}\n"
                f"// Bundle SHA-256: {bundle['archive_sha256']}\n\n"
            ).encode("utf-8")
            if not data.startswith(expected_header):
                fail(f"generated snippet provenance header differs: {record['generated_path']}")
            payload = data[len(expected_header) :]
            if hashlib.sha256(payload).hexdigest() != record["payload_sha256"]:
                fail(f"generated snippet payload differs: {record['generated_path']}")
            snippet = safe_file(
                record["snippet_path"],
                f"bundles[{bundle_index}].files[{file_index}].snippet_path",
            )
            if (
                DIGEST.fullmatch(str(record["snippet_sha256"])) is None
                or hashlib.sha256(snippet.read_bytes()).hexdigest()
                != record["snippet_sha256"]
                or snippet.read_bytes()
                != rendered_snippet(payload_path, payload, source, bundle)
            ):
                fail(f"rendered snippet digest differs: {record['snippet_path']}")
            paths.append(record["generated_path"])
            paths.append(record["snippet_path"])
            payload_paths.append(payload_path)
            documented.add(record["generated_path"])
            documented.add(record["snippet_path"])
            required_outputs.add(record["generated_path"])
            required_outputs.add(record["snippet_path"])
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            fail(f"bundles[{bundle_index}].files paths must be sorted and unique")
        if payload_paths != sorted(spec["documents"]):
            fail(f"bundles[{bundle_index}].files does not match the required SDK documents")
        required_outputs.add(f"reference/sdk-bundles/{sdk}.mdx")
        required_outputs.update(
            f"config/sdk-bundles/{sdk}/{catalog}" for catalog in CATALOGS
        )

    outputs = manifest["outputs"]
    if not isinstance(outputs, list) or not outputs:
        fail("outputs must be a nonempty list")
    output_paths: list[str] = []
    for index, raw_output in enumerate(outputs):
        output = exact_keys(raw_output, {"path", "bytes", "sha256"}, f"outputs[{index}]")
        path = safe_file(output["path"], f"outputs[{index}].path")
        data = path.read_bytes()
        if not isinstance(output["bytes"], int) or isinstance(output["bytes"], bool) or output["bytes"] != len(data) or DIGEST.fullmatch(str(output["sha256"])) is None or hashlib.sha256(data).hexdigest() != output["sha256"]:
            fail(f"generated output digest or size differs: {output['path']}")
        output_paths.append(output["path"])
    if output_paths != sorted(output_paths) or len(output_paths) != len(set(output_paths)):
        fail("output paths must be sorted and unique")
    if set(output_paths) != required_outputs:
        fail("output paths do not match the exact generated SDK documentation closure")
    if not documented.issubset(set(output_paths)):
        fail("one or more generated snippets are outside the output closure")

    managed: set[str] = {"config/generated-sdk-bundles.json", "reference/sdk-bundles.mdx"}
    for relative in ("snippets/generated", "config/sdk-bundles", "reference/sdk-bundles"):
        root = PUBLIC_ROOT / relative
        if root.is_symlink() or not root.is_dir():
            fail(f"managed root is missing or a symlink: {relative}")
        for path in root.rglob("*"):
            if path.is_symlink():
                fail(f"managed root contains a symlink: {path}")
            if path.is_file():
                managed.add(path.relative_to(PUBLIC_ROOT).as_posix())
    if managed != set(output_paths) | {"config/generated-sdk-bundles.json"}:
        fail("generated SDK documentation contains missing or unreferenced output")

    canonical = CORE_ROOT / "scripts" / "docs-sync-sdk"
    if canonical.is_file():
        completed = subprocess.run([sys.executable, str(canonical), "--check"], cwd=CORE_ROOT, check=False)
        if completed.returncode != 0:
            fail("canonical bundle importer reported drift")
        print(f"generated SDK documentation valid: {len(bundles)} bundles, {len(outputs)} outputs")
    else:
        print(f"generated SDK documentation mirror valid: {len(bundles)} bundles, {len(outputs)} outputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
