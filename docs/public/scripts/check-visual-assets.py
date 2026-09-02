#!/usr/bin/env python3
"""Verify the deterministic, accessible public-documentation SVG baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any
import xml.etree.ElementTree as ET


MANIFEST = "config/visual-assets.json"
EXPECTED_PURPOSES = {
    "homepage-architecture",
    "installation-family-overview",
    "trust-boundary-overview",
    "feature-routing-overview",
}
SVG_NAMESPACE = "http://www.w3.org/2000/svg"
UNSAFE_ELEMENTS = {"a", "foreignObject", "iframe", "image", "script", "use"}
MAXIMUM_SVG_BYTES = 512 * 1024
HEX_64 = re.compile(r"[0-9a-f]{64}")
VIEW_BOX = re.compile(r"0 0 [1-9][0-9]{1,4} [1-9][0-9]{1,4}")


class VisualError(ValueError):
    """The visual baseline or one of its assets is invalid."""


def rejecting_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VisualError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def regular_file(root: Path, relative: str, maximum: int | None = None) -> Path:
    posix = PurePosixPath(relative)
    if (
        posix.is_absolute()
        or posix.as_posix() != relative
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise VisualError(f"non-canonical path: {relative!r}")
    path = root.joinpath(*posix.parts)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VisualError(f"cannot inspect {relative}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise VisualError(f"visual path is not a regular file: {relative}")
    if maximum is not None and (metadata.st_size <= 0 or metadata.st_size > maximum):
        raise VisualError(f"visual asset size is outside policy: {relative}")
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise VisualError(f"visual path escapes the documentation root: {relative}") from error
    return path


def local_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def validate_svg(path: Path, relative: str) -> None:
    try:
        payload = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise VisualError(f"cannot read SVG {relative}: {error}") from error
    if "<!DOCTYPE" in payload.upper() or "<!ENTITY" in payload.upper():
        raise VisualError(f"SVG declarations are forbidden: {relative}")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise VisualError(f"SVG is not well-formed: {relative}: {error}") from error
    if root.tag != f"{{{SVG_NAMESPACE}}}svg":
        raise VisualError(f"SVG root namespace is invalid: {relative}")
    if root.get("role") != "img" or not VIEW_BOX.fullmatch(root.get("viewBox", "")):
        raise VisualError(f"SVG role or responsive viewBox is invalid: {relative}")
    if root.get("width") is not None or root.get("height") is not None:
        raise VisualError(f"SVG must remain responsive without fixed dimensions: {relative}")

    direct = {local_name(child.tag): child for child in root}
    title = direct.get("title")
    description = direct.get("desc")
    if title is None or description is None:
        raise VisualError(f"SVG must have direct title and desc elements: {relative}")
    title_id = title.get("id", "")
    description_id = description.get("id", "")
    if (
        not title_id
        or not description_id
        or title_id == description_id
        or root.get("aria-labelledby") != f"{title_id} {description_id}"
        or not "".join(title.itertext()).strip()
        or len("".join(description.itertext()).strip()) < 40
    ):
        raise VisualError(f"SVG accessible name and description are invalid: {relative}")

    styles = "\n".join(
        "".join(element.itertext())
        for element in root.iter()
        if local_name(element.tag) == "style"
    )
    if (
        "prefers-color-scheme: dark" not in styles
        or "forced-colors: active" not in styles
    ):
        raise VisualError(f"SVG adaptive color policies are missing: {relative}")

    identifiers: set[str] = set()
    for element in root.iter():
        name = local_name(element.tag)
        if name in UNSAFE_ELEMENTS:
            raise VisualError(f"unsafe SVG element {name}: {relative}")
        identifier = element.get("id")
        if identifier:
            if identifier in identifiers:
                raise VisualError(f"duplicate SVG id {identifier}: {relative}")
            identifiers.add(identifier)
        for attribute, value in element.attrib.items():
            attribute_name = local_name(attribute)
            if attribute_name.lower().startswith("on") or attribute_name == "href":
                raise VisualError(f"unsafe SVG attribute {attribute_name}: {relative}")
            if "url(" in value and not re.fullmatch(r"url\(#[A-Za-z0-9_-]+\)", value):
                raise VisualError(f"external SVG URL is forbidden: {relative}")


def load_manifest(root: Path) -> list[dict[str, str]]:
    path = regular_file(root, MANIFEST)
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=rejecting_object_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VisualError(f"cannot read visual manifest: {error}") from error
    if not isinstance(payload, dict) or set(payload) != {"format", "visuals"}:
        raise VisualError("visual manifest has unsupported fields")
    if type(payload["format"]) is not int or payload["format"] != 1:
        raise VisualError("visual manifest format must be 1")
    visuals = payload["visuals"]
    if not isinstance(visuals, list) or not visuals:
        raise VisualError("visual manifest must contain visuals")
    return visuals


def verify(root: Path) -> int:
    root = root.resolve(strict=True)
    visuals = load_manifest(root)
    expected_fields = {"alt", "asset", "page", "purpose", "sha256"}
    assets: set[str] = set()
    pages: set[str] = set()
    purposes: set[str] = set()
    previous = ""

    for index, visual in enumerate(visuals):
        if not isinstance(visual, dict) or set(visual) != expected_fields:
            raise VisualError(f"visuals[{index}] has unsupported fields")
        if not all(isinstance(value, str) for value in visual.values()):
            raise VisualError(f"visuals[{index}] fields must be strings")
        asset = visual["asset"]
        page = visual["page"]
        purpose = visual["purpose"]
        alt = visual["alt"]
        if asset <= previous:
            raise VisualError("visual manifest must be sorted by asset")
        previous = asset
        if not asset.startswith("assets/") or not asset.endswith(".svg"):
            raise VisualError(f"unsupported visual asset path: {asset}")
        if not page.endswith(".mdx") or page in pages or asset in assets or purpose in purposes:
            raise VisualError(f"duplicate or unsupported visual coordinate: {asset}")
        if purpose not in EXPECTED_PURPOSES or len(alt) < 40 or '"' in alt:
            raise VisualError(f"visual purpose or alt text is invalid: {asset}")
        if HEX_64.fullmatch(visual["sha256"]) is None:
            raise VisualError(f"visual digest is invalid: {asset}")

        asset_path = regular_file(root, asset, MAXIMUM_SVG_BYTES)
        if digest(asset_path) != visual["sha256"]:
            raise VisualError(f"visual digest differs from baseline: {asset}")
        validate_svg(asset_path, asset)

        page_path = regular_file(root, page)
        page_text = page_path.read_text(encoding="utf-8")
        image = re.compile(
            rf'<img\s+[^>]*src="/{re.escape(asset)}"[^>]*alt="{re.escape(alt)}"[^>]*/>',
            re.DOTALL,
        )
        if len(image.findall(page_text)) != 1:
            raise VisualError(f"visual must have one exact accessible page use: {asset}")
        frame = re.compile(
            rf'<Frame\s+caption="[^"]+">.*?src="/{re.escape(asset)}".*?</Frame>',
            re.DOTALL,
        )
        if frame.search(page_text) is None:
            raise VisualError(f"visual must be wrapped in a captioned Frame: {asset}")
        assets.add(asset)
        pages.add(page)
        purposes.add(purpose)

    actual_assets = {
        path.relative_to(root).as_posix()
        for path in (root / "assets").rglob("*.svg")
        if path.is_file()
    }
    if actual_assets != assets:
        raise VisualError("visual manifest does not close over every public SVG")
    if purposes != EXPECTED_PURPOSES:
        raise VisualError("visual manifest does not cover the four required diagram purposes")
    print(f"visual asset baseline passed: {len(assets)} accessible adaptive SVGs")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        return verify(arguments.root)
    except (OSError, UnicodeDecodeError, VisualError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
