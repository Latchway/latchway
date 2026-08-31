#!/usr/bin/env python3
"""Validate effective metadata and P0 page-template invariants for public MDX."""

from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

import yaml


REQUIRED_FIELDS = {
    "title",
    "description",
    "icon",
    "audience",
    "pageType",
    "serverVersion",
    "sdkVersion",
    "lastVerified",
    "owner",
}
OVERLAY_FIELDS = REQUIRED_FIELDS - {"title", "description"}
GENERATED_SDK_ROUTES = {
    "reference/sdk-bundles",
    "reference/sdk-bundles/android",
    "reference/sdk-bundles/ios",
    "reference/sdk-bundles/js",
    "reference/sdk-bundles/react-native",
}
AUDIENCES = {
    "client-android",
    "client-ios",
    "client-react-native",
    "client-web",
    "community",
    "mixed",
    "operator",
    "reference",
    "security",
}
PAGE_TYPES = {"tutorial", "how-to", "concept", "reference", "troubleshooting", "runbook"}
SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
TOKEN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
GOLDEN_ROUTES = {
    "operate/quickstart": "operator",
    "clients/ios/quickstart": "client-ios",
    "clients/android/quickstart": "client-android",
    "clients/web/quickstart": "client-web",
    "clients/react-native/quickstart": "client-react-native",
}
GOLDEN_HEADINGS = (
    "## Outcome",
    "## Before you start",
    "## What you will build",
    "## Procedure",
    "## Verification",
    "## What Latchway established",
    "## Production next step",
    "## Troubleshooting",
)
GOLDEN_TEMPLATE_MARKERS = (
    "**Expected time:**",
    "**Mode:**",
    "**Coordinates:**",
)
STEP_BLOCK = re.compile(r'<Step title="[^"]+">(?P<body>.*?)</Step>', re.DOTALL)
WEB_ROUTES = {
    "clients/web/index",
    "clients/web/quickstart",
    "clients/web/installation",
    "clients/web/authentication",
    "clients/web/send-a-request",
    "clients/web/streaming",
    "clients/web/webcrypto-dpop",
    "clients/web/browser-trust",
    "clients/web/firebase-app-check",
    "clients/web/turnstile",
    "clients/web/origins-and-cors",
    "clients/web/content-security-policy",
    "clients/web/session-storage",
    "clients/web/multiple-tabs",
    "clients/web/browser-vs-node",
    "clients/web/server-rendering",
    "clients/web/react",
    "clients/web/nextjs",
    "clients/web/vite",
    "clients/web/errors",
    "clients/web/troubleshooting",
    "clients/web/production-checklist",
}
IOS_ROUTES = {
    "clients/ios/index",
    "clients/ios/quickstart",
    "clients/ios/installation",
    "clients/ios/authentication",
    "clients/ios/app-attest",
    "clients/ios/send-a-request",
    "clients/ios/streaming",
    "clients/ios/framework-integrations",
    "clients/ios/app-extensions",
    "clients/ios/error-handling",
    "clients/ios/production-checklist",
}
ANDROID_ROUTES = {
    "clients/android/index",
    "clients/android/quickstart",
    "clients/android/installation",
    "clients/android/authentication",
    "clients/android/play-integrity",
    "clients/android/okhttp",
    "clients/android/retrofit",
    "clients/android/streaming",
    "clients/android/background-execution",
    "clients/android/error-handling",
    "clients/android/production-checklist",
}
REACT_NATIVE_ROUTES = {
    "clients/react-native/index",
    "clients/react-native/quickstart",
    "clients/react-native/installation",
    "clients/react-native/ios-native-setup",
    "clients/react-native/android-native-setup",
    "clients/react-native/authentication",
    "clients/react-native/send-a-request",
    "clients/react-native/streaming",
    "clients/react-native/framework-integrations",
    "clients/react-native/app-extensions",
    "clients/react-native/error-handling",
    "clients/react-native/production-checklist",
}
CUSTOM_COMPONENTS = {
    "BrowserTrustStack",
    "CompatibilityMatrix",
    "ConfigDiff",
    "QuotaPreview",
    "SecurityGuarantee",
    "SetupPath",
    "TrustPath",
}


class MetadataError(ValueError):
    """The public metadata registry or one MDX page is invalid."""


class UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise MetadataError(f"duplicate frontmatter key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def page_files(root: Path) -> dict[str, Path]:
    return {
        path.relative_to(root).with_suffix("").as_posix(): path
        for path in root.rglob("*.mdx")
        if path.relative_to(root).parts[0] != "snippets"
        and not any(part.startswith(".") for part in path.relative_to(root).parts)
    }


def parse_frontmatter(path: Path) -> tuple[Mapping[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise MetadataError(f"missing frontmatter: {path}")
    closing = text.find("\n---\n", 4)
    if closing == -1:
        raise MetadataError(f"unterminated frontmatter: {path}")
    try:
        value = yaml.load(text[4:closing], Loader=UniqueLoader)
    except yaml.YAMLError as error:
        raise MetadataError(f"invalid frontmatter in {path}: {error}") from error
    if not isinstance(value, dict):
        raise MetadataError(f"frontmatter must be an object: {path}")
    return value, text[closing + 5 :]


def load_overlay(path: Path) -> Mapping[str, Mapping[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_json_unique)
    except (OSError, json.JSONDecodeError) as error:
        raise MetadataError(f"cannot load generated metadata overlay: {error}") from error
    if not isinstance(value, dict):
        raise MetadataError("generated metadata overlay must be an object")
    for route, fields in value.items():
        if not isinstance(route, str) or not isinstance(fields, dict) or set(fields) != OVERLAY_FIELDS:
            raise MetadataError(f"generated metadata overlay entry is invalid: {route}")
    return value


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MetadataError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def effective_metadata(route: str, physical: Mapping[str, Any], overlay: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    supplemental = overlay.get(route, {})
    conflicts = {key for key in supplemental if key in physical and physical[key] != supplemental[key]}
    if conflicts:
        raise MetadataError(f"physical and generated metadata conflict for {route}: {sorted(conflicts)}")
    return {**supplemental, **physical}


def validate_fields(route: str, fields: Mapping[str, Any], today: date) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_FIELDS - set(fields))
    if missing:
        return [f"{route} lacks effective metadata: {', '.join(missing)}"]
    for key in REQUIRED_FIELDS:
        if not isinstance(fields[key], str) or not fields[key].strip() or fields[key] != fields[key].strip():
            errors.append(f"{route} metadata {key} must be a nonempty trimmed string")
    if errors:
        return errors
    if fields["audience"] not in AUDIENCES:
        errors.append(f"{route} has unsupported audience {fields['audience']!r}")
    if fields["pageType"] not in PAGE_TYPES:
        errors.append(f"{route} has unsupported pageType {fields['pageType']!r}")
    if SEMVER.fullmatch(fields["serverVersion"]) is None:
        errors.append(f"{route} serverVersion must be exact SemVer")
    if fields["sdkVersion"] != "not-applicable" and SEMVER.fullmatch(fields["sdkVersion"]) is None:
        errors.append(f"{route} sdkVersion must be exact SemVer or not-applicable")
    if TOKEN.fullmatch(fields["owner"]) is None:
        errors.append(f"{route} owner must be a stable lowercase token")
    if TOKEN.fullmatch(fields["icon"]) is None:
        errors.append(f"{route} icon must be a stable lowercase token")
    try:
        verified = date.fromisoformat(fields["lastVerified"])
        if verified > today:
            errors.append(f"{route} lastVerified is in the future")
        elif (today - verified).days > 183:
            errors.append(f"{route} lastVerified is more than 183 days old")
    except ValueError:
        errors.append(f"{route} lastVerified must be YYYY-MM-DD")
    return errors


def validate_golden_body(route: str, body: str) -> list[str]:
    errors: list[str] = []
    for heading in GOLDEN_HEADINGS:
        if heading not in body:
            errors.append(f"golden journey {route} lacks heading: {heading}")
    for marker in GOLDEN_TEMPLATE_MARKERS:
        if marker not in body:
            errors.append(f"golden journey {route} lacks visible template field: {marker}")
    steps = list(STEP_BLOCK.finditer(body))
    if not steps:
        errors.append(f"golden journey {route} has no procedural Steps")
    for index, step in enumerate(steps, start=1):
        step_body = step.group("body")
        if "Expected result:" not in step_body:
            errors.append(f"golden journey {route} step {index} lacks an expected result")
        if "Diagnostic:" not in step_body:
            errors.append(f"golden journey {route} step {index} lacks a diagnostic")
    return errors


def validate_repository(root: Path, *, today: date | None = None) -> list[str]:
    root = root.resolve()
    files = page_files(root)
    overlay = load_overlay(root / "config/generated-page-metadata.json")
    errors: list[str] = []
    if set(overlay) != GENERATED_SDK_ROUTES:
        errors.append(
            "generated metadata overlay must name only the five SDK-bundle routes; "
            f"found {sorted(overlay)}"
        )
    if set(overlay) - set(files):
        errors.append(f"metadata overlay names missing routes: {sorted(set(overlay) - set(files))}")
    for route in sorted(files):
        try:
            physical, body = parse_frontmatter(files[route])
            fields = effective_metadata(route, physical, overlay)
            errors.extend(validate_fields(route, fields, today or date.today()))
            if route in overlay and set(physical) != {"title", "description"}:
                errors.append(
                    f"generated SDK route must leave rich fields to the deterministic overlay: {route}"
                )
            if route not in overlay and set(physical) & REQUIRED_FIELDS != REQUIRED_FIELDS:
                errors.append(f"authored route must carry full physical metadata: {route}")
            if route in GOLDEN_ROUTES:
                if fields.get("pageType") != "tutorial" or fields.get("audience") != GOLDEN_ROUTES[route]:
                    errors.append(f"golden journey metadata is invalid: {route}")
                errors.extend(validate_golden_body(route, body))
                if route != "operate/quickstart" and "<Prompt" not in body:
                    errors.append(f"golden client journey lacks a versioned Prompt: {route}")
        except (MetadataError, KeyError) as error:
            errors.append(f"cannot resolve metadata for {route}: {error}")
    for label, required_routes in (
        ("iOS", IOS_ROUTES),
        ("Android", ANDROID_ROUTES),
        ("Web", WEB_ROUTES),
        ("React Native", REACT_NATIVE_ROUTES),
    ):
        missing_routes = sorted(required_routes - set(files))
        if missing_routes:
            errors.append(f"first-class {label} route set is incomplete: {missing_routes}")
    component_names = {path.stem for path in (root / "components").glob("*.jsx")}
    missing_components = sorted(CUSTOM_COMPONENTS - component_names)
    if missing_components:
        errors.append(f"custom component set is incomplete: {missing_components}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate_repository(args.root)
    if errors:
        print("public documentation metadata failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"public documentation metadata passed: {len(page_files(args.root.resolve()))} routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
