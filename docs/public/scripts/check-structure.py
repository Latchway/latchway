#!/usr/bin/env python3
"""Validate repository-local invariants for the Latchway Mintlify source."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


EXPECTED_TABS = ["Start", "Build", "Operate", "Security", "Reference", "Community"]
REQUIRED_PAGES = {
    "start/architecture-at-a-glance",
    "start/choose-an-integration",
    "start/concepts",
    "concepts/installation-families",
    "concepts/client-components",
    "concepts/trust-provenance",
    "build/app-extensions/overview",
    "build/app-extensions/widgetkit",
    "build/app-extensions/share-extension",
    "build/app-extensions/keychain-access-groups",
    "build/app-extensions/containing-app-provisioning",
    "build/app-extensions/direct-attestation-step-up",
    "integrations/overview",
    "integrations/raw-http",
    "integrations/openai-js",
    "integrations/vercel-ai-sdk",
    "integrations/langchain-js",
    "integrations/foundation-models",
    "integrations/macpaw-openai",
    "integrations/okhttp",
    "integrations/react-native",
    "operate/installation-families/overview",
    "operate/installation-families/component-limits",
    "operate/installation-families/revocation",
    "operate/installation-families/troubleshooting",
    "security/delegated-components",
    "reference/compatibility",
    "community/agent-resources",
}
INTEGRATION_PAGES = {
    "integrations/raw-http",
    "integrations/openai-js",
    "integrations/vercel-ai-sdk",
    "integrations/langchain-js",
    "integrations/foundation-models",
    "integrations/macpaw-openai",
    "integrations/okhttp",
    "integrations/react-native",
}
INTEGRATION_SECTIONS = [
    "What this integration does",
    "Supported framework versions",
    "Supported Latchway versions",
    "Security level",
    "Install packages",
    "Create the Latchway client",
    "Bind a feature",
    "Create the framework client",
    "Send a non-streaming request",
    "Send a streaming request",
    "Use tools",
    "Use structured output",
    "Handle cancellation",
    "Handle quota failures",
    "Handle session renewal",
    "Known limitations",
    "Verify the integration",
    "Troubleshooting",
    "Compatibility matrix",
]
CAPABILITY_TERMS = [
    "Full DPoP",
    "Private key remains native",
    "Streaming",
    "Cancellation",
    "App extensions",
    "Structured output",
    "Tool calls",
    "Protocol",
]
PRE_RELEASE_PAGES = {
    page
    for page in REQUIRED_PAGES
    if page.startswith(("concepts/", "build/app-extensions/", "integrations/", "operate/", "security/"))
}


def load_json(path: Path, errors: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot parse {path}: {error}")
        return None


def resolve_refs(value: Any, root: Path, from_file: Path, chain: tuple[Path, ...], errors: list[str]) -> Any:
    if isinstance(value, dict) and isinstance(value.get("$ref"), str):
        referenced = (from_file.parent / value["$ref"]).resolve()
        try:
            referenced.relative_to(root)
        except ValueError:
            errors.append(f"configuration reference escapes the public root: {value['$ref']}")
            return None
        if referenced in chain:
            errors.append(f"circular configuration reference: {referenced}")
            return None
        loaded = load_json(referenced, errors)
        resolved = resolve_refs(loaded, root, referenced, chain + (referenced,), errors)
        if isinstance(resolved, dict):
            for key, sibling in value.items():
                if key != "$ref":
                    resolved[key] = resolve_refs(sibling, root, from_file, chain, errors)
        return resolved
    if isinstance(value, dict):
        return {
            key: resolve_refs(child, root, from_file, chain, errors)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [resolve_refs(child, root, from_file, chain, errors) for child in value]
    return value


def collect_pages(value: Any) -> list[str]:
    pages: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "pages" and isinstance(child, list):
                pages.extend(page for page in child if isinstance(page, str))
            else:
                pages.extend(collect_pages(child))
    elif isinstance(value, list):
        for child in value:
            pages.extend(collect_pages(child))
    return pages


def frontmatter(path: Path, errors: list[str]) -> tuple[str, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        errors.append(f"missing YAML frontmatter: {path}")
        return "", ""
    closing = text.find("\n---\n", 4)
    if closing == -1:
        errors.append(f"unterminated YAML frontmatter: {path}")
        return "", ""
    block = text[4:closing]
    values: dict[str, str] = {}
    for key in ("title", "description"):
        match = re.search(rf"(?m)^{key}:\s*[\"']?(.+?)[\"']?\s*$", block)
        if not match:
            errors.append(f"missing {key} frontmatter: {path}")
            values[key] = ""
        else:
            values[key] = match.group(1).strip().strip('"\'')
    return values["title"], values["description"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    errors: list[str] = []

    required_files = [
        "docs.json",
        "config/navigation.json",
        "config/redirects.json",
        "config/versions.json",
        ".mintlify/Assistant.md",
        "AGENTS.md",
        "llms.txt",
        "skill.md",
        "skills/latchway/SKILL.md",
    ]
    for relative in required_files:
        if not (root / relative).is_file():
            errors.append(f"required public-doc file is missing: {relative}")

    docs_path = root / "docs.json"
    raw_docs = load_json(docs_path, errors)
    resolved_docs = resolve_refs(raw_docs, root, docs_path, (docs_path,), errors)
    if not isinstance(resolved_docs, dict):
        resolved_docs = {}

    navigation = resolved_docs.get("navigation", {})
    tabs = navigation.get("tabs", []) if isinstance(navigation, dict) else []
    tab_names = [tab.get("tab") for tab in tabs if isinstance(tab, dict)]
    if tab_names != EXPECTED_TABS:
        errors.append(f"navigation tabs must be exactly {EXPECTED_TABS}; found {tab_names}")

    nav_pages = collect_pages(navigation)
    duplicate_nav = sorted({page for page in nav_pages if nav_pages.count(page) > 1})
    if duplicate_nav:
        errors.append(f"pages occur more than once in navigation: {', '.join(duplicate_nav)}")
    nav_set = set(nav_pages)

    files_by_route = {
        path.relative_to(root).with_suffix("").as_posix(): path
        for path in root.rglob("*.mdx")
        if not any(part.startswith(".") for part in path.relative_to(root).parts)
    }
    for route in sorted(nav_set - files_by_route.keys()):
        errors.append(f"navigation references a missing page: {route}")
    for route in sorted(files_by_route.keys() - nav_set):
        errors.append(f"public MDX page is not referenced in navigation: {route}")
    for route in sorted(REQUIRED_PAGES - files_by_route.keys()):
        errors.append(f"required foundation page is missing: {route}")

    seen_titles: dict[str, str] = {}
    seen_descriptions: dict[str, str] = {}
    for route, path in sorted(files_by_route.items()):
        title, description = frontmatter(path, errors)
        for kind, value, seen in (
            ("title", title, seen_titles),
            ("description", description, seen_descriptions),
        ):
            normalized = value.casefold()
            if normalized and normalized in seen:
                errors.append(f"duplicate {kind}: {route} and {seen[normalized]}")
            elif normalized:
                seen[normalized] = route

    markdown = resolved_docs.get("markdown", {})
    instructions = markdown.get("instructions", "") if isinstance(markdown, dict) else ""
    instruction_text = " ".join(instructions) if isinstance(instructions, list) else str(instructions)
    for phrase in (
        "Never recommend placing an upstream provider API key",
        "Distinguish authentication, attestation, authorization, and DPoP",
        "Prefer feature IDs over physical model names",
        "State the relevant Latchway server and SDK versions",
        "Never describe a delegated client component as directly attested",
    ):
        if phrase not in instruction_text:
            errors.append(f"markdown instructions are missing required guidance: {phrase}")

    versions = navigation.get("global", {}).get("versions", []) if isinstance(navigation, dict) else []
    if not (
        isinstance(versions, list)
        and len(versions) == 1
        and versions[0].get("version") == "Pre-release"
        and versions[0].get("default") is True
        and versions[0].get("href") == "/release-status"
    ):
        errors.append("version navigation must expose one default Pre-release entry")

    redirects = resolved_docs.get("redirects", [])
    redirect_sources: set[str] = set()
    if not isinstance(redirects, list):
        errors.append("redirects must resolve to a list")
    else:
        for redirect in redirects:
            if not isinstance(redirect, dict):
                errors.append("redirect entry must be an object")
                continue
            source = redirect.get("source")
            destination = redirect.get("destination")
            if source in redirect_sources:
                errors.append(f"duplicate redirect source: {source}")
            redirect_sources.add(source)
            if not isinstance(destination, str) or destination.lstrip("/") not in files_by_route:
                errors.append(f"redirect destination is not a public page: {destination}")

    for route in sorted(PRE_RELEASE_PAGES & files_by_route.keys()):
        text = files_by_route[route].read_text(encoding="utf-8").casefold()
        if "pre-release" not in text and "not supported by the current" not in text:
            errors.append(f"target-contract page lacks a pre-release caveat: {route}")

    for route in sorted(INTEGRATION_PAGES & files_by_route.keys()):
        text = files_by_route[route].read_text(encoding="utf-8")
        for index, section in enumerate(INTEGRATION_SECTIONS, start=1):
            if f"## {index}. {section}" not in text:
                errors.append(f"integration page lacks section {index} ({section}): {route}")
        for term in CAPABILITY_TERMS:
            if term not in text:
                errors.append(f"integration page lacks capability statement ({term}): {route}")

    installation_text = "\n".join(
        files_by_route[route].read_text(encoding="utf-8")
        for route in (
            "concepts/installation-families",
            "concepts/client-components",
            "concepts/trust-provenance",
        )
        if route in files_by_route
    )
    normalized_installation_text = re.sub(r"[\s>#*`]+", " ", installation_text).casefold()
    for phrase in (
        "independent P-256 key",
        "rotating refresh token",
        "delegated component independently completed App Attest",
        "family revocation",
    ):
        if phrase.casefold() not in normalized_installation_text:
            errors.append(f"Installation Family concepts lack required invariant: {phrase}")

    mermaid_count = sum(
        path.read_text(encoding="utf-8").count("```mermaid")
        for path in files_by_route.values()
    )
    if mermaid_count < 4:
        errors.append(f"foundation requires at least four repository-native diagrams; found {mermaid_count}")

    forbidden_roots = {"implementation", "adr", "engineering", "internal"}
    for forbidden in forbidden_roots:
        if (root / forbidden).exists():
            errors.append(f"internal material is inside the public publish root: {forbidden}")

    if errors:
        print("public documentation structure failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        f"public documentation structure passed: {len(files_by_route)} pages, "
        f"{len(nav_pages)} navigation entries, {mermaid_count} Mermaid diagrams"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
