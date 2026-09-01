#!/usr/bin/env python3
"""Validate repository-local invariants for the Latchway Mintlify source."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


EXPECTED_TABS = ["Get started", "Client SDKs", "Operate", "Security", "Reference", "Community"]
GOLDEN_PAGES = {
    "operate/quickstart",
    "clients/ios/quickstart",
    "clients/android/quickstart",
    "clients/web/quickstart",
    "clients/react-native/quickstart",
}
WEB_PAGES = {
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
    "clients/web/xss-and-key-invalidation",
    "clients/web/browser-storage-reset",
    "clients/web/multiple-tabs",
    "clients/web/browser-vs-node",
    "clients/web/server-rendering",
    "clients/web/service-workers",
    "clients/web/react",
    "clients/web/nextjs",
    "clients/web/vite",
    "clients/web/errors",
    "clients/web/troubleshooting",
    "clients/web/production-checklist",
}
IOS_PAGES = {
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
ANDROID_PAGES = {
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
REACT_NATIVE_PAGES = {
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
SKILL_NAMES = {
    "install-latchway",
    "deploy-latchway",
    "configure-upstream",
    "configure-firebase",
    "configure-app-attest",
    "configure-play-integrity",
    "integrate-ios",
    "integrate-android",
    "integrate-web",
    "integrate-react-native",
    "create-feature",
    "create-limit-plan",
    "troubleshoot-request",
}
COMPONENT_USES = {
    "BrowserTrustStack": "clients/web/browser-trust",
    "CompatibilityMatrix": "reference/compatibility",
    "ConfigDiff": "administration/configuration",
    "QuotaPreview": "concepts/routing-and-quotas",
    "SecurityGuarantee": "concepts/security-and-privacy",
    "SetupPath": "index",
    "TrustPath": "concepts/client-components",
}
FRAMEWORK_SNIPPETS = {
    "integrations/koog-android": "/snippets/generated/android/frameworks/koog.kt.mdx",
    "integrations/swift-openai": "/snippets/generated/ios/frameworks/swift-openai.swift.mdx",
}
REQUIRED_PAGES = {
    "clients/choose-an-sdk",
    "clients/authentication-providers",
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
    "integrations/swift-openai",
    "integrations/macpaw-openai",
    "integrations/okhttp",
    "integrations/koog-android",
    "integrations/react-native",
    "operate/installation-families/overview",
    "operate/installation-families/component-limits",
    "operate/installation-families/revocation",
    "operate/installation-families/troubleshooting",
    "security/delegated-components",
    "security/threat-model",
    "security/incident-response",
    "administration/users",
    "administration/overrides",
    "administration/audit-log",
    "operations/rollbacks",
    "operations/scaling",
    "operations/disaster-recovery",
    "reference/environment-variables",
    "reference/metrics",
    "reference/audit-event-types",
    "reference/admin-api",
    "reference/errors",
    "reference/config-schema",
    "reference/cel-policy-context",
    "reference/compatibility",
    "reference/sdk-bundles",
    "reference/sdk-bundles/android",
    "reference/sdk-bundles/ios",
    "reference/sdk-bundles/js",
    "reference/sdk-bundles/react-native",
    "community/architecture",
    "community/adrs",
    "community/governance",
    "community/security-reporting",
    "community/roadmap",
    "community/agent-resources",
} | GOLDEN_PAGES | WEB_PAGES | IOS_PAGES | ANDROID_PAGES | REACT_NATIVE_PAGES
INTEGRATION_PAGES = {
    "integrations/raw-http",
    "integrations/openai-js",
    "integrations/vercel-ai-sdk",
    "integrations/langchain-js",
    "integrations/foundation-models",
    "integrations/swift-openai",
    "integrations/macpaw-openai",
    "integrations/okhttp",
    "integrations/koog-android",
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
CANONICAL_DIAGRAMS = {
    "Latchway in one picture": (
        "start/architecture-at-a-glance",
        ("Untrusted client", "Latchway boundary", "PostgreSQL", "upstream"),
    ),
    "Control plane versus data plane": (
        "start/architecture-at-a-glance",
        ("Data plane", "Control plane", "Admin API", "PostgreSQL"),
    ),
    "Identity, attestation, and DPoP": (
        "concepts/identity-and-attestation",
        ("Identity token", "Attestation", "DPoP", "Authorize feature policy"),
    ),
    "Session bootstrap sequence": (
        "concepts/identity-and-attestation",
        ("sequenceDiagram", "Session challenge", "component public key", "PostgreSQL"),
    ),
    "Protected AI request sequence": (
        "concepts/security-boundary",
        ("sequenceDiagram", "fresh DPoP proof", "Reserve replay key", "Settle usage"),
    ),
    "Reserve-execute-settle quota lifecycle": (
        "concepts/routing-and-quotas",
        ("Trusted preflight estimate", "Reserve atomically", "without open transaction", "Settle actual charge"),
    ),
    "Feature routing": (
        "concepts/routing-and-quotas",
        ("Feature ID", "Active immutable configuration", "physical model", "fallback"),
    ),
    "Installation Family hierarchy": (
        "concepts/installation-families",
        ("Installation Family", "directly attested", "delegated trust", "DPoP key"),
    ),
    "Delegated component provisioning": (
        "build/app-extensions/containing-app-provisioning",
        ("sequenceDiagram", "single-use delegation", "component-key possession", "Component-scoped session"),
    ),
    "Root revocation propagation": (
        "operate/installation-families/revocation",
        ("Revoke root", "delegation", "refresh chain", "Revoke Widget only"),
    ),
    "Framework-transparent integration": (
        "integrations/overview",
        ("Existing AI framework", "authenticated transport", "application feature", "Server-selected upstream"),
    ),
    "PostgreSQL-only deployment": (
        "operations/deployment",
        ("API replica", "Worker replica", "Migration job", "only required external service"),
    ),
}
DIAGRAM_CAPTIONS = (
    "What this establishes",
    "What this does not establish",
    "What causes the relationship to expire",
)
MERMAID_BLOCK = re.compile(r"```mermaid\s*\n(?P<body>.*?)\n```", re.DOTALL)
LLMS_LINK = re.compile(
    r"\[[^\]]+\]\(https://docs\.latchway\.dev/(?P<route>[a-z0-9][a-z0-9_./-]*)\.md\)"
)
PRE_RELEASE_PAGES = {
    page
    for page in REQUIRED_PAGES
    if page.startswith(("concepts/", "build/app-extensions/", "integrations/", "operate/", "security/"))
}
FACTUAL_PAGE_GUARDS: dict[str, dict[str, tuple[str, ...]]] = {
    "operations/rollbacks": {
        "required": (
            "before routing any production traffic",
            "latchway_migrate_on_start=false",
        ),
        "forbidden": (
            "previous binary declares the current schema compatible",
            "use the previous immutable digest only when its declared schema range",
        ),
    },
    "operations/upgrades": {
        "required": (
            "the binary has no declared schema range",
            "against an isolated copy of the current database",
        ),
        "forbidden": ("confirm that binary's declared schema range includes",),
    },
    "operations/disaster-recovery": {
        "required": ("passes isolated current-schema proof",),
        "forbidden": ("route to a schema-compatible previous digest",),
    },
    "security/threat-model": {
        "required": ("same-origin indexeddb", "accepted browser residual risk"),
        "forbidden": ("plaintext persistence or telemetry",),
    },
    "administration/users": {
        "required": (
            "normalization bounds claim names",
            "normal bounded expiry",
        ),
        "forbidden": ("reads safe normalized claims",),
    },
    "administration/overrides": {
        "required": (
            "same immutable row and override id",
            "repeating an identical effective override must return the same override id",
        ),
        "forbidden": (
            "replacement revokes the previous row and creates a new immutable record",
        ),
    },
    "clients/web/browser-storage-reset": {
        "required": (
            "server diagnostics expose the active installation id, not a component id",
        ),
        "forbidden": ("component: diagnostics.server.installation.id",),
    },
    "reference/environment-variables": {
        "required": ("serve --role worker", "has no http listener or scrape endpoint"),
        "forbidden": ("metrics are always exposed at /metrics",),
    },
    "reference/metrics": {
        "required": (
            "creates no http listener in version 1",
            "its process-local observations therefore have no scrape endpoint",
        ),
    },
    "operations/scaling": {
        "required": ("a worker-only process has no http listener",),
    },
    "operations/key-rotation": {
        "required": (
            "no admin api or cli operation to force signing-key rotation",
            "scheduled rotation is therefore not emergency containment",
        ),
    },
    "security/incident-response": {
        "required": (
            "api-token-authenticated cli revocation is self-only",
            "there is no admin api or cli emergency-rotation operation",
        ),
        "forbidden": ("follow the emergency path in key rotation",),
    },
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
    required_files.extend(
        f".mintlify/skills/{name}/SKILL.md" for name in sorted(SKILL_NAMES)
    )
    required_files.extend(
        f"components/{name}.jsx" for name in sorted(COMPONENT_USES)
    )
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

    client_tab = next(
        (tab for tab in tabs if isinstance(tab, dict) and tab.get("tab") == "Client SDKs"),
        None,
    )
    client_groups = client_tab.get("groups", []) if isinstance(client_tab, dict) else []
    if not client_groups or client_groups[0] != {
        "group": "Choose an SDK",
        "pages": ["clients/choose-an-sdk"],
    }:
        errors.append("Client SDK navigation must begin with the Choose an SDK route")
    if {
        "group": "Authentication providers",
        "pages": ["clients/authentication-providers"],
    } not in client_groups:
        errors.append("Client SDK navigation must expose the Authentication providers route")

    navbar = resolved_docs.get("navbar", {})
    navbar_links = navbar.get("links", []) if isinstance(navbar, dict) else []
    link_coordinates = {
        (item.get("label"), item.get("href"))
        for item in navbar_links
        if isinstance(item, dict)
    }
    if link_coordinates != {
        ("GitHub", "https://github.com/Latchway/latchway"),
        ("Status", "/release-status"),
        ("Changelog", "https://github.com/Latchway/latchway/releases"),
    }:
        errors.append("navbar must expose the exact GitHub, Status, and Changelog links")
    primary = navbar.get("primary", {}) if isinstance(navbar, dict) else {}
    if primary != {"type": "button", "label": "Console", "href": "/administration/console"}:
        errors.append("navbar primary action must link to the Console documentation")

    nav_pages = collect_pages(navigation)
    duplicate_nav = sorted({page for page in nav_pages if nav_pages.count(page) > 1})
    if duplicate_nav:
        errors.append(f"pages occur more than once in navigation: {', '.join(duplicate_nav)}")
    nav_set = set(nav_pages)

    files_by_route = {
        path.relative_to(root).with_suffix("").as_posix(): path
        for path in root.rglob("*.mdx")
        if not any(part.startswith(".") for part in path.relative_to(root).parts)
        and path.relative_to(root).parts[0] != "snippets"
    }
    for route in sorted(nav_set - files_by_route.keys()):
        errors.append(f"navigation references a missing page: {route}")
    for route in sorted(files_by_route.keys() - nav_set):
        errors.append(f"public MDX page is not referenced in navigation: {route}")
    for route in sorted(REQUIRED_PAGES - files_by_route.keys()):
        errors.append(f"required foundation page is missing: {route}")

    for component, route in COMPONENT_USES.items():
        page = files_by_route.get(route)
        if page is not None and f"<{component}" not in page.read_text(encoding="utf-8"):
            errors.append(f"custom component {component} is not rendered on {route}")

    setup_path = root / "components/SetupPath.jsx"
    if setup_path.is_file():
        setup_text = setup_path.read_text(encoding="utf-8")
        for phrase in (
            'firebase: ["Firebase", "/clients/authentication-providers#firebase"]',
            '"cloud-run": ["Google Cloud Run source template (provider proof open)"',
            "[role, platform, authentication, integration, deployment, webFramework, webTrust]",
            'const STORAGE_KEY = "latchway.docs.setup-preferences.v1"',
            "new URLSearchParams(window.location.search)",
            "window.localStorage.setItem(STORAGE_KEY",
            "navigator.clipboard.writeText",
            'consoleHref("/requests"',
            'consoleHref("/features"',
            'consoleHref("/limit-plans"',
            'consoleHref("/route-simulator"',
        ):
            if phrase not in setup_text:
                errors.append(f"SetupPath selector is not wired to a truthful result: {phrase}")
        allowlist_match = re.search(
            r"const SAFE_URL_FIELDS = \{(?P<body>.*?)\n\};",
            setup_text,
            re.DOTALL,
        )
        if not allowlist_match:
            errors.append("SetupPath lacks an explicit URL-personalization allowlist")
        else:
            allowlist = allowlist_match.group("body")
            for parameter in (
                "lw_gateway",
                "lw_console",
                "lw_application_id",
                "lw_application_slug",
                "lw_environment",
                "lw_feature",
                "lw_component_definition",
                "lw_sdk_version",
                "lw_server_version",
            ):
                if f'"{parameter}"' not in allowlist:
                    errors.append(f"SetupPath safe URL allowlist lacks {parameter}")
            for forbidden in ("token", "secret", "credential", "proof", "evidence", "requestBody"):
                if re.search(rf"(?m)^\s*[A-Za-z0-9_]*{forbidden}[A-Za-z0-9_]*\s*:", allowlist, re.IGNORECASE):
                    errors.append(f"SetupPath URL allowlist contains forbidden field class: {forbidden}")
        for guard in ("url.username", "url.password", "url.search", "url.hash"):
            if guard not in setup_text:
                errors.append(f"SetupPath public-origin validation lacks guard: {guard}")

    for route, platform in (
        ("clients/ios/quickstart", "ios"),
        ("clients/android/quickstart", "android"),
        ("clients/react-native/quickstart", "react-native"),
    ):
        page = files_by_route.get(route)
        if page is not None:
            text = page.read_text(encoding="utf-8")
            if f'<SetupCoordinates platform="{platform}" />' not in text:
                errors.append(f"native first-run path lacks safe coordinates: {route}")

    homepage = files_by_route.get("index")
    if homepage is not None:
        homepage_text = homepage.read_text(encoding="utf-8")
        for snippet in (
            "/snippets/generated/ios/quickstart/url-session.swift.mdx",
            "/snippets/generated/android/quickstart/basic-client.kt.mdx",
            "/snippets/generated/js/quickstart/vanilla-streaming-fetch.ts.mdx",
            "/snippets/generated/react-native/quickstart/streaming-fetch.tsx.mdx",
        ):
            if snippet not in homepage_text:
                errors.append(f"homepage preview is not source-provenanced: {snippet}")

    android_quickstart = files_by_route.get("clients/android/quickstart")
    if android_quickstart is not None:
        android_text = android_quickstart.read_text(encoding="utf-8")
        for stale_handwritten_example in ("OkHttpClient.Builder()", "http.newCall(request).execute()"):
            if stale_handwritten_example in android_text:
                errors.append(
                    "Android quickstart contains a handwritten transport example instead "
                    f"of SDK-owned provenance: {stale_handwritten_example}"
                )

    foundation_page = files_by_route.get("integrations/foundation-models")
    if foundation_page is not None:
        foundation_text = foundation_page.read_text(encoding="utf-8")
        for current_claim in ("pre-release experimental", "exact `27.0.0`", "Nine iOS 27.0 simulator tests"):
            if current_claim not in foundation_text:
                errors.append(f"Foundation Models page lacks current generated status: {current_claim}")
    choose_page = files_by_route.get("start/choose-an-integration")
    if choose_page is not None and "Foundation Models remains planned" in choose_page.read_text(encoding="utf-8"):
        errors.append("integration chooser still calls the experimental Foundation Models source seam planned")

    for route, snippet in FRAMEWORK_SNIPPETS.items():
        page = files_by_route.get(route)
        if page is not None and snippet not in page.read_text(encoding="utf-8"):
            errors.append(f"framework guide is not source-provenanced: {route} must import {snippet}")

    origins_page = files_by_route.get("clients/web/origins-and-cors")
    if origins_page is not None:
        origins_text = origins_page.read_text(encoding="utf-8")
        if "clientOrigins:" in origins_text:
            errors.append("Web origin guide uses nonexistent clientOrigins configuration")
        for field in ("attestationPolicies:", "web:", "allowedOrigins:"):
            if field not in origins_text:
                errors.append(f"Web origin guide lacks canonical configuration path: {field}")

    for route, guards in FACTUAL_PAGE_GUARDS.items():
        page = files_by_route.get(route)
        if page is None:
            continue
        normalized_text = " ".join(page.read_text(encoding="utf-8").casefold().split())
        for phrase in guards.get("required", ()):
            if phrase.casefold() not in normalized_text:
                errors.append(f"factual documentation guard is missing on {route}: {phrase}")
        for phrase in guards.get("forbidden", ()):
            if phrase.casefold() in normalized_text:
                errors.append(f"factual documentation guard is violated on {route}: {phrase}")

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

    api = resolved_docs.get("api", {})
    playground = api.get("playground", {}) if isinstance(api, dict) else {}
    if playground != {"display": "none", "proxy": False}:
        errors.append(
            "public API playground must be disabled with proxying off; "
            "Client API DPoP and production Admin credentials cannot use a public request builder"
        )

    llms_path = root / "llms.txt"
    if llms_path.is_file():
        llms_text = llms_path.read_text(encoding="utf-8")
        if not llms_text.startswith("# Latchway public documentation\n\n> "):
            errors.append("llms.txt must start with a title and blockquote outcome summary")
        llms_routes = [match.group("route") for match in LLMS_LINK.finditer(llms_text)]
        duplicate_llms_routes = sorted(
            {route for route in llms_routes if llms_routes.count(route) > 1}
        )
        if duplicate_llms_routes:
            errors.append(f"llms.txt repeats routes: {', '.join(duplicate_llms_routes)}")
        llms_required = GOLDEN_PAGES | {
            "index",
            "release-status",
            "reference/client-api",
            "reference/admin-api",
            "reference/errors",
            "community/agent-resources",
        }
        for route in sorted(llms_required - set(llms_routes)):
            errors.append(f"llms.txt omits required retrieval route: {route}")
        for route in sorted(set(llms_routes) - files_by_route.keys() - {"skill"}):
            errors.append(f"llms.txt references a missing Markdown route: {route}")
        if re.search(r"(?m)^\s*-\s+/(?!/)\S+", llms_text):
            errors.append("llms.txt contains a bare route instead of a descriptive Markdown link")

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
            if not isinstance(source, str) or not source.startswith("/") or "?" in source or "#" in source:
                errors.append(f"redirect source is not a canonical path: {source}")
            if source in redirect_sources:
                errors.append(f"duplicate redirect source: {source}")
            redirect_sources.add(source)
            if redirect.get("permanent") is not True:
                errors.append(f"redirect must be permanent: {source}")
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

    diagrams: list[tuple[str, str]] = []
    for route, path in sorted(files_by_route.items()):
        text = path.read_text(encoding="utf-8")
        matches = list(MERMAID_BLOCK.finditer(text))
        for match in matches:
            body = match.group("body")
            title_match = re.search(r"(?m)^\s*accTitle:\s*(.+?)\s*$", body)
            description_match = re.search(r"(?m)^\s*accDescr:\s*(.+?)\s*$", body)
            if not title_match:
                errors.append(f"Mermaid diagram lacks accTitle: {route}")
                continue
            title = title_match.group(1).strip()
            diagrams.append((title, route))
            if not description_match or len(description_match.group(1).strip()) < 40:
                errors.append(f"canonical diagram lacks a useful accDescr: {title} ({route})")

            expected = CANONICAL_DIAGRAMS.get(title)
            if expected is None:
                errors.append(f"unexpected canonical diagram: {title} ({route})")
                continue
            expected_route, semantic_terms = expected
            if route != expected_route:
                errors.append(
                    f"canonical diagram is on the wrong page: {title} must be in "
                    f"{expected_route}, found {route}"
                )
            if route not in nav_set:
                errors.append(f"canonical diagram page is absent from navigation: {route}")
            preceding = text[: match.start()].rstrip()
            if not preceding.endswith(f"## {title}"):
                errors.append(f"canonical diagram must immediately follow its level-two heading: {title}")
            normalized_body = body.casefold()
            for term in semantic_terms:
                if term.casefold() not in normalized_body:
                    errors.append(f"canonical diagram lacks required semantic ({term}): {title}")

            following = text[match.end() :]
            next_level_two = re.search(r"(?m)^##\s+", following)
            caption_region = following[: next_level_two.start()] if next_level_two else following
            caption_matches: list[re.Match[str]] = []
            for caption in DIAGRAM_CAPTIONS:
                heading = rf"(?m)^### {re.escape(caption)}\s*$"
                caption_match = re.search(heading, caption_region)
                if not caption_match:
                    errors.append(f"canonical diagram lacks trust caption ({caption}): {title}")
                else:
                    caption_matches.append(caption_match)
            if len(caption_matches) == len(DIAGRAM_CAPTIONS):
                if [item.start() for item in caption_matches] != sorted(
                    item.start() for item in caption_matches
                ):
                    errors.append(f"canonical diagram trust captions are out of order: {title}")
                for index, caption_match in enumerate(caption_matches):
                    body_end = (
                        caption_matches[index + 1].start()
                        if index + 1 < len(caption_matches)
                        else len(caption_region)
                    )
                    caption_body = re.sub(
                        r"[\s>#*`]+", " ", caption_region[caption_match.end() : body_end]
                    ).strip()
                    if len(caption_body) < 40:
                        errors.append(
                            f"canonical diagram trust caption lacks an explanation "
                            f"({DIAGRAM_CAPTIONS[index]}): {title}"
                        )

    mermaid_count = len(diagrams)
    if mermaid_count != len(CANONICAL_DIAGRAMS):
        errors.append(
            f"foundation requires exactly {len(CANONICAL_DIAGRAMS)} canonical diagrams; "
            f"found {mermaid_count}"
        )
    diagram_titles = [title for title, _ in diagrams]
    duplicate_diagrams = sorted({title for title in diagram_titles if diagram_titles.count(title) > 1})
    if duplicate_diagrams:
        errors.append(f"canonical diagrams occur more than once: {', '.join(duplicate_diagrams)}")
    missing_diagrams = sorted(CANONICAL_DIAGRAMS.keys() - set(diagram_titles))
    if missing_diagrams:
        errors.append(f"canonical diagrams are missing: {', '.join(missing_diagrams)}")

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
