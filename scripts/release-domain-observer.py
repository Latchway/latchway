#!/usr/bin/env python3
"""Run fixed external checks and emit candidate-bound machine observations.

This command is deliberately usable only by the protected observation
workflow.  It has no generic command or uploaded-result mode: every subprocess
and every accepted output shape is selected by the domain in this source file.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Sequence
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
import zipfile


SCRIPT = Path(__file__).with_name("release-domain-evidence.py")
SPEC = importlib.util.spec_from_file_location("latchway_release_domain_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release-domain evidence module cannot be loaded")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)

RELEASE_ATTESTATION_SCRIPT = Path(__file__).with_name(
    "verify-github-release-attestation.py"
)
RELEASE_ATTESTATION_SPEC = importlib.util.spec_from_file_location(
    "latchway_github_release_attestation", RELEASE_ATTESTATION_SCRIPT
)
if RELEASE_ATTESTATION_SPEC is None or RELEASE_ATTESTATION_SPEC.loader is None:
    raise RuntimeError("release-attestation verifier cannot be loaded")
RELEASE_ATTESTATION = importlib.util.module_from_spec(RELEASE_ATTESTATION_SPEC)
RELEASE_ATTESTATION_SPEC.loader.exec_module(RELEASE_ATTESTATION)

MINTLIFY_PROOF_SCRIPT = Path(__file__).with_name("mintlify-production-proof.py")
MINTLIFY_PROOF_SPEC = importlib.util.spec_from_file_location(
    "latchway_mintlify_production_proof", MINTLIFY_PROOF_SCRIPT
)
if MINTLIFY_PROOF_SPEC is None or MINTLIFY_PROOF_SPEC.loader is None:
    raise RuntimeError("Mintlify production-proof validator cannot be loaded")
MINTLIFY_PROOF = importlib.util.module_from_spec(MINTLIFY_PROOF_SPEC)
MINTLIFY_PROOF_SPEC.loader.exec_module(MINTLIFY_PROOF)

GITHUB_AUTHORITY_DOMAINS = frozenset(
    {"supply_chain", "public_tags", "public_registries"}
)
# Exact public-registry closure at GitHub's 64-asset release bound:
# JavaScript 230 + React Native 245 + iOS 21 + Android 31 + documentation 7
# + anonymous public OCI 7. This counts manifest rows; the authority manifest
# itself is the 542nd file.
MAXIMUM_AUTHORITY_FILES = 541
MAXIMUM_AUTHORITY_BYTES = 128 * 1024 * 1024
MAXIMUM_AUTHORITY_WINDOW = EVIDENCE.timedelta(hours=2)
FORBIDDEN_CANDIDATE_CREDENTIAL_ENV = frozenset(
    {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "LATCHWAY_ADMIN_API_TOKEN",
        "LATCHWAY_LIVE_SDK_ATTESTATION_TOKEN",
        "LATCHWAY_LIVE_SDK_FIREBASE_APP_CHECK_TOKEN",
        "LATCHWAY_LIVE_SDK_IDENTITY_TOKEN",
        "LATCHWAY_LIVE_SDK_TURNSTILE_TOKEN",
        "LATCHWAY_ONE_TIME_LIVE_SDK_GRANT",
        "ONE_TIME_GRANT",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    }
)

REPOSITORY_NAMES = {
    "core": "latchway",
    "javascript": "latchway-js",
    "ios": "latchway-ios-sdk",
    "android": "latchway-android",
    "react_native": "latchway-react-native-sdk",
}
NPM_ADOPTION_ASSET = re.compile(
    r"^npm-release-adoption-[1-9][0-9]*-[1-9][0-9]*\.json$"
)
JAVASCRIPT_NPM_PACKAGES: tuple[tuple[str, str], ...] = (
    ("client", "@latchway/client"),
    ("openai", "@latchway/openai"),
    ("vercel-ai", "@latchway/vercel-ai"),
    ("langchain", "@latchway/langchain"),
)
JAVASCRIPT_NPM_ADOPTION_ASSET = re.compile(
    r"^npm-release-adoption-(client|openai|vercel-ai|langchain)-"
    r"([1-9][0-9]*)-([1-9][0-9]*)\.json$"
)
JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS = (
    "package-evidence.json",
    "release-candidate-evidence.json",
    "publish-input-evidence.json",
    "post-publish-evidence.json",
    "npm-registry-evidence-manifest.json",
    "build-reproducibility.json",
    "contract-evidence.json",
    "dependency-vulnerability-scan.json",
    "tag-evidence.json",
)
JAVASCRIPT_NPM_AGGREGATE_ASSETS = (
    *JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS,
    "SHA256SUMS",
)
SINGLE_MAINTAINER_JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS = (
    "package-evidence.json",
    "release-candidate-evidence.json",
    "post-publish-evidence.json",
    "npm-registry-evidence-manifest.json",
    "build-reproducibility.json",
    "contract-evidence.json",
    "dependency-vulnerability-scan.json",
    "core-release-gate.json",
    "latchway-single-maintainer-v1-intent.json",
    "single-maintainer-npm-adoption.json",
)
SINGLE_MAINTAINER_JAVASCRIPT_NPM_AGGREGATE_ASSETS = (
    *SINGLE_MAINTAINER_JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS,
    "SHA256SUMS",
)
STRICT_RELEASE_WORKFLOW = ".github/workflows/release.yml"
SINGLE_MAINTAINER_RELEASE_WORKFLOW = (
    ".github/workflows/single-maintainer-release.yml"
)
JAVASCRIPT_RETAINED_TARBALL = re.compile(
    r"^latchway-(client|openai|vercel-ai|langchain)-"
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.tgz$"
)
MAXIMUM_RETAINED_NPM_TARBALL_BYTES = 10 * 1024 * 1024
JAVASCRIPT_OSV_SCANNER_COMMIT = "b56b5191101d5f27d4787d5583d8d01e9518a7af"
CONTRACT_LOCK_LINE = re.compile(
    r"([a-z][a-z0-9_]*):[ \t]*(?:\"([^\"\r\n]*)\"|([^\s#][^\r\n]*?))[ \t]*"
)
IOS_COCOAPODS_SUBSPECS = frozenset(
    {"AppAttest", "AppExtensions", "Core", "FirebaseAuth"}
)
COCOAPODS_FORBIDDEN_HOOKS = frozenset(
    {"prepare_command", "script_phase", "script_phases"}
)


def expected_source_attested_release_assets(
    repository_id: str,
    version: str,
    release_names: Sequence[str],
    release_profile: str | None = None,
) -> set[str]:
    """Return the exact released subjects the production observer must verify."""
    names = set(release_names)
    if release_profile == EVIDENCE.SINGLE_MAINTAINER_PROFILE:
        return names
    if release_profile is not None:
        raise ObservationError("release_profile_invalid")
    if repository_id in {"javascript", "android"}:
        return names
    if repository_id == "react_native":
        return names - {f"latchway-react-native-{version}.tgz.sha256"}
    if repository_id == "ios":
        return names - {f"latchway-ios-sdk-{version}.tar.gz.sha256"}
    raise ObservationError("release_asset_attestation_repository_invalid")


PROVIDER_CHECKS = {
    "provider.openrouter.non-streaming": "non_streaming",
    "provider.openrouter.streaming": "streaming",
    "provider.openrouter.usage": "usage",
    "provider.openrouter.output-clamp": "output_clamp",
    "provider.openrouter.error-normalization": "error_normalization",
}


def valid_npm_adoption_mode(
    mode: Any,
    adoption_run_id: Any,
    adoption_run_attempt: Any,
    provenance_run_id: Any,
    provenance_run_attempt: Any,
) -> bool:
    """Require retry adoption records to identify whether they did the publish."""
    return (
        isinstance(mode, str)
        and mode in {"published", "adopted_existing"}
        and (mode == "published")
        == (
            adoption_run_id == provenance_run_id
            and adoption_run_attempt == provenance_run_attempt
        )
    )


def javascript_npm_tarball_digest(payload: bytes) -> dict[str, Any]:
    sha512_digest = hashlib.sha512(payload).digest()
    return {
        "bytes": len(payload),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "sha512": sha512_digest.hex(),
        "integrity": "sha512-" + base64.b64encode(sha512_digest).decode("ascii"),
    }


def validate_javascript_sha256sums(
    payload: bytes, package_items: Any, version: str
) -> dict[str, Any]:
    if not isinstance(package_items, list) or len(package_items) != 4:
        raise ObservationError("registry_npm_checksums_invalid")
    entries: list[dict[str, str]] = []
    lines: list[str] = []
    for index, (package_id, package) in enumerate(JAVASCRIPT_NPM_PACKAGES):
        item = package_items[index]
        name = f"latchway-{package_id}-{version}.tgz"
        sha256 = item.get("sha256") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or item.get("id") != package_id
            or item.get("package") != package
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            raise ObservationError("registry_npm_checksums_invalid")
        entries.append({"name": name, "sha256": sha256})
        lines.append(f"{sha256}  {name}")
    expected = ("\n".join(sorted(lines)) + "\n").encode("ascii")
    if payload != expected:
        raise ObservationError("registry_npm_checksums_invalid")
    return {
        "schema_version": 1,
        "algorithm": "sha256",
        "file": "SHA256SUMS",
        "file_sha256": hashlib.sha256(payload).hexdigest(),
        "entries": sorted(entries, key=lambda item: item["name"]),
    }


def validate_javascript_supporting_evidence(
    documents: Mapping[str, Any],
    coordinate: Mapping[str, str],
    *,
    require_tag_evidence: bool = True,
) -> None:
    tag = documents.get("tag-evidence.json")
    vulnerability = documents.get("dependency-vulnerability-scan.json")
    scanner = vulnerability.get("scanner") if isinstance(vulnerability, dict) else None
    if require_tag_evidence and (
        not isinstance(tag, dict)
        or set(tag) != {"schema_version", "tag", "version", "commit", "annotated"}
        or tag.get("schema_version") != 1
        or tag.get("tag") != coordinate.get("tag")
        or tag.get("version") != coordinate.get("version")
        or tag.get("commit") != coordinate.get("commit")
        or tag.get("annotated") is not True
    ):
        raise ObservationError("registry_npm_tag_evidence_invalid")
    if (
        not isinstance(vulnerability, dict)
        or set(vulnerability)
        != {
            "schema_version", "scanner", "source_commit", "inventory_sha256",
            "database_sha256", "package_count", "vulnerability_count",
            "blocking_vulnerability_count", "policy", "status",
        }
        or vulnerability.get("schema_version")
        != "latchway.dependency-vulnerability-scan.v1"
        or not isinstance(scanner, dict)
        or set(scanner) != {"name", "version", "commit", "mode"}
        or scanner
        != {
            "name": "OSV-Scanner",
            "version": "2.4.0",
            "commit": JAVASCRIPT_OSV_SCANNER_COMMIT,
            "mode": "offline",
        }
        or vulnerability.get("source_commit") != coordinate.get("commit")
        or re.fullmatch(
            r"[0-9a-f]{64}", str(vulnerability.get("inventory_sha256"))
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(vulnerability.get("database_sha256"))
        )
        is None
        or not isinstance(vulnerability.get("package_count"), int)
        or isinstance(vulnerability.get("package_count"), bool)
        or vulnerability["package_count"] < 1
        or not isinstance(vulnerability.get("vulnerability_count"), int)
        or isinstance(vulnerability.get("vulnerability_count"), bool)
        or vulnerability["vulnerability_count"] < 0
        or vulnerability.get("blocking_vulnerability_count") != 0
        or vulnerability.get("policy")
        != "block-critical-high-and-unknown-severity"
        or vulnerability.get("status") != "passed"
    ):
        raise ObservationError("registry_npm_vulnerability_evidence_invalid")


def parse_contract_lock_payload(payload: bytes) -> dict[str, str]:
    try:
        contents = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ObservationError("registry_npm_contract_source_invalid") from None
    values: dict[str, str] = {}
    for line in contents.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = CONTRACT_LOCK_LINE.fullmatch(line)
        if match is None or match.group(1) in values:
            raise ObservationError("registry_npm_contract_source_invalid")
        values[match.group(1)] = (
            match.group(2) if match.group(2) is not None else match.group(3)
        )
    wire_fields = {"wire_protocol", "wire_protocol_version"} & values.keys()
    required = {
        "contract_version", "core_release", "core_commit", "bundle_sha256",
        "minimum_server_version", "maximum_tested_server_version",
    }
    if (
        set(values) - (required | {"wire_protocol", "wire_protocol_version"})
        or not required.issubset(values)
        or len(wire_fields) != 1
        or not valid_commit(values.get("core_commit"))
        or re.fullmatch(r"[0-9a-f]{64}", values.get("bundle_sha256", "")) is None
    ):
        raise ObservationError("registry_npm_contract_source_invalid")
    values["wire_protocol"] = values.pop(next(iter(wire_fields)))
    return values


SDK_BEHAVIOR_KEYS = {
    "sdk.behavior.dpop-vectors": "dpop_vectors",
    "sdk.behavior.error-mapping": "error_mapping",
    "sdk.behavior.session-refresh": "session_refresh",
    "sdk.behavior.installation-revocation": "installation_revocation",
    "sdk.behavior.streaming": "streaming",
    "sdk.behavior.quota-snapshots": "quota_snapshots",
    "sdk.behavior.protocol-version-rejection": "protocol_version_rejection",
}
LIVE_SDK_JAVASCRIPT_PROVIDERS: Mapping[str, Mapping[str, str]] = {
    "firebase_app_check": {
        "observation": "sdk.javascript.firebase-app-check.release-image",
        "audience": "firebase-app-check",
        "runner_slug": "firebase",
    },
    "turnstile": {
        "observation": "sdk.javascript.turnstile.release-image",
        "audience": "turnstile",
        "runner_slug": "turnstile",
    },
}
LIVE_SDK_JAVASCRIPT_CONFIGURATION_KEYS = frozenset(
    {
        "LATCHWAY_LIVE_SDK_ENVIRONMENT",
        "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE",
    }
)
LIVE_SDK_LEGACY_CREDENTIAL_ENV = frozenset(
    {
        "LATCHWAY_LIVE_SDK_ATTESTATION_TOKEN",
        "LATCHWAY_LIVE_SDK_FIREBASE_APP_CHECK_TOKEN",
        "LATCHWAY_LIVE_SDK_IDENTITY_TOKEN",
        "LATCHWAY_LIVE_SDK_TURNSTILE_TOKEN",
        "LATCHWAY_ONE_TIME_LIVE_SDK_GRANT",
        "ONE_TIME_GRANT",
    }
)
LIVE_SDK_ISOLATION_SUBJECTS = (
    "collector-lease.json",
    "collector-lease.sig",
    "collector-teardown.json",
    "collector-teardown.sig",
    "execution.json",
    "gateway-consumption-receipt.json",
    "gateway-consumption-receipt.sig",
    "gateway-receipt-public-key.pem",
    "harness-manifest.json",
    "report.json",
)
LIVE_SDK_ISOLATION_FILES = frozenset(
    {"ISOLATION_SHA256SUMS", *LIVE_SDK_ISOLATION_SUBJECTS}
)
LIVE_SDK_ISOLATION_SIGNATURES = frozenset(
    {
        "collector-lease.sig",
        "collector-teardown.sig",
        "gateway-consumption-receipt.sig",
    }
)
LIVE_PROVIDER_ISOLATION_PATHS: Mapping[str, str] = {
    "manifest.json": "manifest.json",
    "health.json": "health.json",
    "self-test.json": "self-test.json",
    "collector-lease.json": "collector-isolation/collector-lease.json",
    "collector-lease.sig": "collector-isolation/collector-lease.sig",
    "collector-trust-root.pem": "collector-isolation/collector-trust-root.pem",
    "grant-consumption-receipt.json": "collector-isolation/grant-consumption-receipt.json",
    "grant-consumption-receipt.sig": "collector-isolation/grant-consumption-receipt.sig",
    "collector-teardown.json": "collector-isolation/collector-teardown.json",
    "collector-teardown.sig": "collector-isolation/collector-teardown.sig",
}
LIVE_PROVIDER_ISOLATION_SIGNATURES = frozenset(
    {
        "collector-lease.sig",
        "grant-consumption-receipt.sig",
        "collector-teardown.sig",
    }
)
RETAINED_INPUT_CONTAINERS: Mapping[str, tuple[str, str]] = {
    "physical_device_receipt": (
        "latchway_retained_physical_device_receipt",
        "physical-receipt.json",
    ),
    "live_sdk_collector_isolation": (
        "latchway_retained_live_sdk_collector_isolation",
        "collector-isolation.json",
    ),
    "live_provider_collector_isolation": (
        "latchway_retained_live_provider_collector_isolation",
        "live-provider-isolation.json",
    ),
    "mintlify_production_evidence": (
        "latchway_retained_mintlify_production_evidence",
        "mintlify-production-evidence.json",
    ),
}
LIVE_SDK_JAVASCRIPT_TESTS = (
    "dpop_authorized_request",
    "dpop_replay_rejected",
    "tampered_dpop_rejected",
    "canonical_error_mapping",
    "session_refresh_rotation",
    "protocol_version_rejection",
    "streamed_request",
    "quota",
    "installation_revocation",
)
LIVE_SDK_COMMON_PHYSICAL_TESTS = frozenset(
    {
        "physical_device",
        "identifier_pins",
        "dpop_authorized_request",
        "dpop_replay_rejected",
        "tampered_dpop_rejected",
        "streamed_request",
        "quota",
        "canonical_error_mapping",
        "session_refresh_rotation",
        "installation_revocation",
        "protocol_version_rejection",
    }
)
IOS_COMPONENT_OBSERVATION_VERSION = "latchway.ios-component-observation.v2"
IOS_COMPONENT_TESTS = frozenset(
    {
        "component_candidate_identities",
        "widget_delegated_request",
        "share_delegated_request",
        "action_delegated_request",
        "component_key_isolation",
        "component_session_isolation",
        "component_sibling_denied",
        "component_keychain_sibling_denied",
        "component_refresh_race",
        "component_no_host_process",
        "component_background_execution",
        "component_host_termination",
        "component_no_user_presence",
    }
)
LIVE_SDK_RECEIPTS: Mapping[str, Mapping[str, Any]] = {
    "ios": {
        "repository_id": "ios",
        "repository": "Latchway/latchway-ios-sdk",
        "workflow": ".github/workflows/physical-app-attest.yml",
        "artifact_prefix": "app-attest-physical",
        "run_prefix": "app-attest",
        "platform": "ios_app_attest",
        "observation": "sdk.ios.release-image",
        "profile": "app-attest-profile.json",
        "evidence": "app-attest-evidence.json",
        "component_observation": "component-observation.json",
        "mapped_error_type": "swift_latchway_problem",
        "tests": LIVE_SDK_COMMON_PHYSICAL_TESTS
        | IOS_COMPONENT_TESTS
        | {
            "app_attest_supported",
            "secure_enclave_key",
            "app_attest_registration",
            "session_created",
            "app_attest_assertion",
        },
        "manifest": frozenset(
            {
                "app-attest-evidence.json",
                "app-attest-junit.xml",
                "app-attest-observation.json",
                "app-attest-profile.json",
                "app-attest-validation.json",
                "component-observation.json",
                "gateway-client-policy.json",
                "gateway-deployment-public-key.pem",
                "gateway-deployment-statement.json",
                "gateway-deployment-statement.sig",
                "gateway-deployment-verification.json",
                "device-inventory.json",
            }
        ),
    },
    "android": {
        "repository_id": "android",
        "repository": "Latchway/latchway-android",
        "workflow": ".github/workflows/physical-play-integrity.yml",
        "artifact_prefix": "play-integrity-physical",
        "run_prefix": "play-integrity",
        "platform": "android_play_integrity",
        "observation": "sdk.android.release-image",
        "profile": "play-integrity-profile.json",
        "evidence": "play-integrity-evidence.json",
        "mapped_error_type": "kotlin_latchway_exception",
        "tests": LIVE_SDK_COMMON_PHYSICAL_TESTS
        | {
            "play_install_source",
            "play_integrity_standard_request",
            "hardware_backed_key",
            "session_created",
        },
        "manifest": frozenset(
            {
                "device-inventory.json",
                "gateway-client-policy.json",
                "gateway-deployment-public-key.pem",
                "gateway-deployment-statement.json",
                "gateway-deployment-statement.sig",
                "gateway-deployment-verification.json",
                "installed-apk-set.sha256",
                "play-integrity-evidence.json",
                "play-integrity-junit.xml",
                "play-integrity-observation.json",
                "play-integrity-profile.json",
                "play-integrity-validation.json",
            }
        ),
    },
    "react_native_ios": {
        "repository_id": "react_native",
        "repository": "Latchway/latchway-react-native-sdk",
        "workflow": ".github/workflows/physical-device-evidence.yml",
        "artifact_prefix": "react-native-ios-physical",
        "run_prefix": "rn-ios",
        "platform": "react_native_ios_app_attest",
        "observation": "sdk.react-native-ios.release-image",
        "profile": "react-native-ios-profile.json",
        "evidence": "react-native-ios-evidence.json",
        "mapped_error_type": "react_native_latchway_error",
        "tests": LIVE_SDK_COMMON_PHYSICAL_TESTS
        | {
            "native_evidence_linked",
            "react_native_bridge",
            "app_attest_session",
            "secure_enclave_key",
        },
        "manifest": frozenset(
            {
                "device-inventory.json",
                "gateway-client-policy.json",
                "gateway-deployment-public-key.pem",
                "gateway-deployment-statement.json",
                "gateway-deployment-statement.sig",
                "gateway-deployment-verification.json",
                "linked-ios-native-evidence.json",
                "linked-ios-native-profile.json",
                "react-native-ios-collection.json",
                "react-native-ios-evidence.json",
                "react-native-ios-junit.xml",
                "react-native-ios-observation.json",
                "react-native-ios-profile.json",
                "react-native-ios-run.json",
                "react-native-ios-validation.json",
            }
        ),
    },
    "react_native_android": {
        "repository_id": "react_native",
        "repository": "Latchway/latchway-react-native-sdk",
        "workflow": ".github/workflows/physical-device-evidence.yml",
        "artifact_prefix": "react-native-android-physical",
        "run_prefix": "rn-android",
        "platform": "react_native_android_play_integrity",
        "observation": "sdk.react-native-android.release-image",
        "profile": "react-native-android-profile.json",
        "evidence": "react-native-android-evidence.json",
        "mapped_error_type": "react_native_latchway_error",
        "tests": LIVE_SDK_COMMON_PHYSICAL_TESTS
        | {
            "native_evidence_linked",
            "react_native_bridge",
            "play_integrity_session",
            "hardware_backed_key",
        },
        "manifest": frozenset(
            {
                "device-inventory.json",
                "gateway-client-policy.json",
                "gateway-deployment-public-key.pem",
                "gateway-deployment-statement.json",
                "gateway-deployment-statement.sig",
                "gateway-deployment-verification.json",
                "installed-apk-set.sha256",
                "linked-android-native-evidence.json",
                "linked-android-native-profile.json",
                "react-native-android-collection.json",
                "react-native-android-evidence.json",
                "react-native-android-junit.xml",
                "react-native-android-observation.json",
                "react-native-android-profile.json",
                "react-native-android-run.json",
                "react-native-android-validation.json",
            }
        ),
    },
}
SAFE_ENVIRONMENT_KEYS = (
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "CI",
    "DEVELOPER_DIR",
    "JAVA_HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TMPDIR",
)
ALLOWED_ENVIRONMENT_OVERRIDES = frozenset(
    (
        "GH_TOKEN",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "GCM_INTERACTIVE",
        "LATCHWAY_CENTRAL_EXPECTED_REPOSITORY",
        "LATCHWAY_COCOAPODS_EXPECTED_ARCHIVE",
        "LATCHWAY_CENTRAL_SIGNING_FINGERPRINT",
        "LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY",
        "LATCHWAY_RELEASE_VERSION",
        "NPM_CONFIG_PROVENANCE",
        "NPM_CONFIG_USERCONFIG",
    )
)


class ObservationError(EVIDENCE.EvidenceError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def load_output(payload: bytes, code: str) -> Any:
    EVIDENCE.scan_safe(payload)
    try:
        return json.loads(
            payload,
            object_pairs_hook=EVIDENCE.strict_object,
            parse_constant=EVIDENCE.reject_nonfinite,
        )
    except (EVIDENCE.EvidenceError, UnicodeDecodeError, json.JSONDecodeError):
        raise ObservationError(code) from None


def nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def verify_javascript_reproducibility_archive_inputs(
    reproducibility: Any,
    release_assets: Mapping[str, Mapping[str, Any]],
    version: str,
    package_evidence: Any | None = None,
    javascript_root: Path | None = None,
) -> dict[str, Any]:
    """Recompute the producer aggregate over exact dist bytes in npm archives."""
    rows = reproducibility.get("files") if isinstance(reproducibility, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ObservationError("registry_npm_reproducibility_invalid")
    row_paths = [item.get("path") for item in rows if isinstance(item, dict)]
    if len(row_paths) != len(rows) or any(
        not isinstance(path, str) for path in row_paths
    ):
        raise ObservationError("registry_npm_reproducibility_invalid")

    payloads: dict[str, bytes] = {}
    maximum_dist_bytes = EVIDENCE.MAXIMUM_RAW_BYTES
    total_bytes = 0
    evidence_packages = (
        package_evidence.get("packages")
        if isinstance(package_evidence, dict)
        else None
    )
    if package_evidence is not None and (
        not isinstance(evidence_packages, list) or len(evidence_packages) != 4
    ):
        raise ObservationError("registry_npm_reproducibility_invalid")
    source_lock: bytes | None = None
    if javascript_root is not None:
        try:
            source_lock = EVIDENCE.read_bytes(
                javascript_root / "contract.lock", EVIDENCE.MAXIMUM_RESULT_BYTES
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("registry_npm_reproducibility_invalid") from None
    for package_index, (package_id, package) in enumerate(JAVASCRIPT_NPM_PACKAGES):
        tarball_name = f"latchway-{package_id}-{version}.tgz"
        entry = release_assets.get(tarball_name)
        archive_payload = entry.get("bytes") if isinstance(entry, Mapping) else None
        if not isinstance(archive_payload, bytes):
            raise ObservationError("registry_npm_reproducibility_invalid")
        archive_entries: list[str] = []
        archive_payloads: dict[str, bytes] = {}
        unpacked_bytes = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r:gz") as archive:
                for member in archive.getmembers():
                    raw_name = member.name
                    relative = PurePosixPath(raw_name)
                    if (
                        not raw_name
                        or raw_name.startswith("/")
                        or "\\" in raw_name
                        or relative.as_posix() != raw_name
                        or any(part in ("", ".", "..") for part in relative.parts)
                    ):
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    if (
                        raw_name in archive_payloads
                        or not member.isfile()
                        or member.size < 0
                        or member.size > 8 * 1024 * 1024
                    ):
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    archive_entries.append(raw_name)
                    if len(archive_entries) > 512:
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    unpacked_bytes += member.size
                    if unpacked_bytes > 25 * 1024 * 1024:
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    payload = extracted.read(member.size + 1)
                    if len(payload) != member.size:
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    archive_payloads[raw_name] = payload
                    if raw_name.startswith("package/dist/"):
                        repository_path = raw_name.removeprefix("package/")
                        if package_id != "client":
                            repository_path = (
                                f"packages/{package_id}/{repository_path}"
                            )
                        if repository_path in payloads or member.size < 1:
                            raise ObservationError(
                                "registry_npm_reproducibility_invalid"
                            )
                        total_bytes += member.size
                        if total_bytes > maximum_dist_bytes:
                            raise ObservationError(
                                "registry_npm_reproducibility_invalid"
                            )
                        payloads[repository_path] = payload
        except ObservationError:
            raise
        except (tarfile.TarError, EOFError, OSError):
            raise ObservationError("registry_npm_reproducibility_invalid") from None

        if len(set(archive_entries)) != len(archive_entries):
            raise ObservationError("registry_npm_reproducibility_invalid")
        if evidence_packages is not None:
            reviewed = evidence_packages[package_index]
            if (
                not isinstance(reviewed, dict)
                or reviewed.get("id") != package_id
                or reviewed.get("package") != package
                or reviewed.get("entries") != sorted(archive_entries)
                or reviewed.get("unpacked_bytes") != unpacked_bytes
            ):
                raise ObservationError("registry_npm_reproducibility_invalid")
            manifest_payload = archive_payloads.get("package/package.json")
            try:
                manifest = json.loads(
                    manifest_payload.decode("utf-8")
                    if isinstance(manifest_payload, bytes)
                    else "",
                    object_pairs_hook=EVIDENCE.strict_object,
                    parse_constant=EVIDENCE.reject_nonfinite,
                )
            except (
                EVIDENCE.EvidenceError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
                raise ObservationError(
                    "registry_npm_reproducibility_invalid"
                ) from None
            published_peers = reviewed.get("published_peer_dependencies")
            if (
                not isinstance(manifest, dict)
                or manifest.get("name") != package
                or manifest.get("version") != version
                or not isinstance(published_peers, dict)
                or (manifest.get("peerDependencies") or {}) != published_peers
                or (
                    package_id != "client"
                    and published_peers.get("@latchway/client") != f"^{version}"
                )
                or (
                    package_id == "client"
                    and source_lock is not None
                    and archive_payloads.get("package/contract.lock") != source_lock
                )
            ):
                raise ObservationError("registry_npm_reproducibility_invalid")
            if javascript_root is not None:
                source_manifest_path = (
                    javascript_root / "package.json"
                    if package_id == "client"
                    else javascript_root / "packages" / package_id / "package.json"
                )
                try:
                    source_manifest = EVIDENCE.read_json(
                        source_manifest_path, EVIDENCE.MAXIMUM_RESULT_BYTES
                    )
                except EVIDENCE.EvidenceError:
                    raise ObservationError(
                        "registry_npm_reproducibility_invalid"
                    ) from None
                source_peers = source_manifest.get("peerDependencies") or {}
                if (
                    source_manifest.get("name") != package
                    or source_manifest.get("version") != version
                    or not isinstance(source_peers, dict)
                ):
                    raise ObservationError("registry_npm_reproducibility_invalid")
                expected_published_peers: dict[str, str] = {}
                release_names = {item[1] for item in JAVASCRIPT_NPM_PACKAGES}
                for name, requirement in source_peers.items():
                    if not isinstance(name, str) or not isinstance(requirement, str):
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    if not requirement.startswith("workspace:"):
                        expected_published_peers[name] = requirement
                        continue
                    if name not in release_names:
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    selector = requirement.removeprefix("workspace:")
                    replacements = {
                        "^": f"^{version}",
                        "~": f"~{version}",
                        "*": version,
                    }
                    if selector not in replacements:
                        raise ObservationError(
                            "registry_npm_reproducibility_invalid"
                        )
                    expected_published_peers[name] = replacements[selector]
                if expected_published_peers != published_peers:
                    raise ObservationError("registry_npm_reproducibility_invalid")

        expected = {
            str(item.get("path"))
            for item in rows
            if isinstance(item, dict) and item.get("package") == package
        }
        prefix = (
            "dist/"
            if package_id == "client"
            else f"packages/{package_id}/dist/"
        )
        observed = {path for path in payloads if path.startswith(prefix)}
        if observed != expected:
            raise ObservationError("registry_npm_reproducibility_invalid")

    aggregate = hashlib.sha256()
    for item in rows:
        path = item.get("path") if isinstance(item, dict) else None
        payload = payloads.get(str(path))
        if (
            payload is None
            or item.get("bytes") != len(payload)
            or item.get("sha256") != hashlib.sha256(payload).hexdigest()
        ):
            raise ObservationError("registry_npm_reproducibility_invalid")
        aggregate.update(str(path).encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(payload)
        aggregate.update(b"\0")
    aggregate_sha256 = aggregate.hexdigest()
    if reproducibility.get("sha256") != aggregate_sha256:
        raise ObservationError("registry_npm_reproducibility_invalid")
    return {
        "schema_version": 1,
        "algorithm": "sha256",
        "inputs": "ordered-release-tarball-dist-file-bytes",
        "archive_regular_file_closure_verified": package_evidence is not None,
        "source_manifests_and_peer_translation_verified": javascript_root
        is not None,
        "independent_source_rebuild_performed": False,
        "file_count": len(rows),
        "bytes": total_bytes,
        "sha256": aggregate_sha256,
    }


def valid_sha512_integrity(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        decoded = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 64


def valid_commit(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def command_environment(
    additions: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the complete allowlisted environment for an observation command."""
    environment = {
        name: os.environ[name]
        for name in SAFE_ENVIRONMENT_KEYS
        if os.environ.get(name)
    }
    temporary_home = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
    if not temporary_home:
        temporary_home = tempfile.gettempdir()
    environment.update(
        {
            "HOME": temporary_home,
            "GH_PROMPT_DISABLED": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
        }
    )
    if additions is not None:
        if set(additions) - ALLOWED_ENVIRONMENT_OVERRIDES:
            raise ObservationError("observation_environment_invalid")
        if any(
            not isinstance(value, str) or not value or "\x00" in value
            for value in additions.values()
        ):
            raise ObservationError("observation_environment_invalid")
        environment.update(additions)
    return environment


def repository_state(path: Path) -> tuple[str, bytes]:
    executable = shutil.which("git")
    if executable is None:
        raise ObservationError("repository_verifier_unavailable")
    results: list[subprocess.CompletedProcess[bytes]] = []
    for arguments in (
        ("-C", str(path), "rev-parse", "--verify", "HEAD"),
        ("-C", str(path), "status", "--porcelain=v1", "--untracked-files=all"),
    ):
        try:
            results.append(
                subprocess.run(
                    (executable, *arguments),
                    check=False,
                    capture_output=True,
                    timeout=30,
                    env=command_environment(),
                )
            )
        except (OSError, subprocess.SubprocessError):
            raise ObservationError("repository_verification_failed") from None
    if any(result.returncode != 0 for result in results):
        raise ObservationError("repository_verification_failed")
    try:
        head = results[0].stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        raise ObservationError("repository_verification_failed") from None
    return head, results[1].stdout


class Observer:
    def __init__(
        self,
        *,
        domain: str,
        source: Path,
        candidate: Path,
        output: Path,
        repositories: Mapping[str, Path],
        live_sdk_receipts: Mapping[str, Path] | None = None,
        live_sdk_runs: Mapping[str, tuple[str, str]] | None = None,
        live_sdk_authority: Path | None = None,
        javascript_captures: Mapping[str, Path] | None = None,
        live_provider_capture: Path | None = None,
        github_authority: Path | None = None,
        now: datetime,
        release_profile: str | None = None,
    ):
        EVIDENCE.protected_context()
        if any(os.environ.get(name) for name in FORBIDDEN_CANDIDATE_CREDENTIAL_ENV):
            raise ObservationError("candidate_credentials_present")
        if domain not in EVIDENCE.CLAIM_REQUIREMENTS:
            raise ObservationError("domain_invalid")
        if release_profile is not None and (
            release_profile != EVIDENCE.SINGLE_MAINTAINER_PROFILE
            or domain not in {"public_tags", "public_registries"}
        ):
            raise ObservationError("release_profile_domain_invalid")
        # public_tags deliberately keeps the same closed claim set while the
        # profile records which immutable producer contract was accepted.
        evidence_release_profile = release_profile
        try:
            EVIDENCE.claim_requirements(domain, evidence_release_profile)
        except EVIDENCE.EvidenceError as error:
            raise ObservationError(str(error)) from None
        if not output.is_absolute() or output.exists() or output.is_symlink():
            raise ObservationError("observation_output_invalid")
        self.domain = domain
        self.release_profile = release_profile
        self.evidence_release_profile = evidence_release_profile
        self.source = source
        self.candidate_path = candidate
        self.output = output
        self.repositories = dict(repositories)
        self.live_sdk_receipts = dict(live_sdk_receipts or {})
        self.live_sdk_runs = dict(live_sdk_runs or {})
        self.live_sdk_authority = live_sdk_authority
        self.javascript_captures = dict(javascript_captures or {})
        self.live_provider_capture = live_provider_capture
        self.github_authority = github_authority
        self._github_authority_entries: dict[str, dict[str, Any]] = {}
        self._github_authority_used: set[str] = set()
        self._github_authority_manifest_sha256: str | None = None
        self.now = now
        self.identity, self.candidate, self.candidate_created = EVIDENCE.identity_from_inputs(
            source, candidate, now
        )
        try:
            source_document = EVIDENCE.read_json(source)
            self.documentation = MINTLIFY_PROOF.validate_documentation_coordinate(
                source_document.get("documentation"), self.identity["core_commit"]
            )
        except (EVIDENCE.EvidenceError, MINTLIFY_PROOF.ProofError):
            raise ObservationError("documentation_source_coordinate_invalid") from None
        self.input_hashes = {
            "source": EVIDENCE.sha256_file(source, EVIDENCE.MAXIMUM_RESULT_BYTES),
            "candidate": EVIDENCE.sha256_file(
                candidate, EVIDENCE.MAXIMUM_RESULT_BYTES
            ),
        }
        self._validate_repositories()
        if self.domain in GITHUB_AUTHORITY_DOMAINS:
            self._validate_github_authority_directory()
        self.output.mkdir(parents=True, mode=0o700)

    def _validate_repositories(self) -> None:
        if set(self.repositories) != set(REPOSITORY_NAMES):
            raise ObservationError("repository_set_invalid")
        coordinates = self.identity.get("repositories")
        if not isinstance(coordinates, dict) or set(coordinates) != set(REPOSITORY_NAMES):
            raise ObservationError("repository_set_invalid")
        for repository_id in REPOSITORY_NAMES:
            root = self.repositories[repository_id]
            if (
                not root.is_absolute()
                or not root.is_dir()
                or root.is_symlink()
            ):
                raise ObservationError("repository_checkout_invalid")
            expected = coordinates[repository_id].get("commit")
            head, status = repository_state(root)
            if head != expected:
                raise ObservationError("repository_commit_mismatch")
            if status:
                raise ObservationError("repository_checkout_dirty")

    def _validate_github_authority_directory(self) -> None:
        root = self.github_authority
        if (
            root is None
            or not root.is_absolute()
            or not root.is_dir()
            or root.is_symlink()
        ):
            raise ObservationError("github_authority_directory_invalid")
        manifest_path = root / "manifest.json"
        try:
            manifest_sha256 = EVIDENCE.sha256_file(
                manifest_path, EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            manifest = EVIDENCE.read_json(manifest_path)
        except EVIDENCE.EvidenceError:
            raise ObservationError("github_authority_manifest_invalid") from None
        if (
            set(manifest)
            != {
                "schema_version",
                "kind",
                "domain",
                "candidate",
                "source_sha256",
                "candidate_sha256",
                "started_at",
                "finished_at",
                "files",
            }
            or manifest.get("schema_version") != 1
            or manifest.get("kind") != "latchway_github_authority"
            or manifest.get("domain") != self.domain
            or manifest.get("candidate") != self.identity
            or manifest.get("source_sha256") != self.input_hashes["source"]
            or manifest.get("candidate_sha256") != self.input_hashes["candidate"]
        ):
            raise ObservationError("github_authority_manifest_invalid")
        try:
            started = EVIDENCE.parse_time(
                manifest.get("started_at"), "github_authority_time_invalid"
            )
            finished = EVIDENCE.parse_time(
                manifest.get("finished_at"), "github_authority_time_invalid"
            )
        except EVIDENCE.EvidenceError as error:
            raise ObservationError(str(error)) from None
        if (
            started < self.candidate_created
            or finished <= started
            or finished > self.now
            or finished - started > MAXIMUM_AUTHORITY_WINDOW
        ):
            raise ObservationError("github_authority_time_invalid")
        files = manifest.get("files")
        if (
            not isinstance(files, list)
            or not 1 <= len(files) <= MAXIMUM_AUTHORITY_FILES
        ):
            raise ObservationError("github_authority_file_set_invalid")
        entries: dict[str, dict[str, Any]] = {}
        total = 0
        for item in files:
            if not isinstance(item, dict) or set(item) != {
                "path",
                "bytes",
                "sha256",
                "started_at",
                "finished_at",
            }:
                raise ObservationError("github_authority_file_set_invalid")
            relative = item.get("path")
            size = item.get("bytes")
            digest = item.get("sha256")
            if (
                not EVIDENCE.safe_relative(relative)
                or relative == "manifest.json"
                or relative in entries
                or not isinstance(size, int)
                or isinstance(size, bool)
                or not 1 <= size <= EVIDENCE.MAXIMUM_RAW_BYTES
                or not isinstance(digest, str)
                or EVIDENCE.SHA256.fullmatch(digest) is None
            ):
                raise ObservationError("github_authority_file_set_invalid")
            try:
                item_started = EVIDENCE.parse_time(
                    item.get("started_at"), "github_authority_time_invalid"
                )
                item_finished = EVIDENCE.parse_time(
                    item.get("finished_at"), "github_authority_time_invalid"
                )
                path = EVIDENCE.resolve_inside(root, relative)
            except EVIDENCE.EvidenceError as error:
                raise ObservationError(str(error)) from None
            if (
                item_started < started
                or item_finished <= item_started
                or item_finished > finished
                or item_finished - item_started > MAXIMUM_AUTHORITY_WINDOW
                or path.stat().st_size != size
                or EVIDENCE.sha256_file(path, EVIDENCE.MAXIMUM_RAW_BYTES) != digest
            ):
                raise ObservationError("github_authority_file_invalid")
            entries[relative] = {
                **item,
                "path_object": path,
                "started": item_started,
                "finished": item_finished,
            }
            total += size
        actual: set[str] = set()
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ObservationError("github_authority_contains_symlink")
            if path.is_file():
                actual.add(path.relative_to(root).as_posix())
        if actual != {"manifest.json", *entries} or total > MAXIMUM_AUTHORITY_BYTES:
            raise ObservationError("github_authority_file_set_invalid")
        self._github_authority_entries = entries
        self._github_authority_used = set()
        try:
            final_manifest_sha256 = EVIDENCE.sha256_file(
                manifest_path, EVIDENCE.MAXIMUM_RESULT_BYTES
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("github_authority_manifest_invalid") from None
        if final_manifest_sha256 != manifest_sha256:
            raise ObservationError("github_authority_manifest_changed")
        self._github_authority_manifest_sha256 = manifest_sha256

    def _github_authority_file(
        self, relative: str, *, maximum: int = EVIDENCE.MAXIMUM_RAW_BYTES
    ) -> tuple[bytes, datetime, datetime]:
        entry = self._github_authority_entries.get(relative)
        if entry is None:
            raise ObservationError("github_authority_file_missing")
        try:
            payload = EVIDENCE.read_bytes(entry["path_object"], maximum)
        except EVIDENCE.EvidenceError:
            raise ObservationError("github_authority_file_invalid") from None
        if hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise ObservationError("github_authority_file_changed")
        self._github_authority_used.add(relative)
        return payload, entry["started"], entry["finished"]

    def _github_authority_json(
        self, relative: str, code: str
    ) -> tuple[Any, datetime, datetime]:
        payload, started, finished = self._github_authority_file(
            relative, maximum=EVIDENCE.MAXIMUM_RESULT_BYTES
        )
        return load_output(payload, code), started, finished

    def _validate_github_authority_consumed(self) -> None:
        if self.domain not in GITHUB_AUTHORITY_DOMAINS:
            return
        if self._github_authority_used != set(self._github_authority_entries):
            raise ObservationError("github_authority_file_set_invalid")
        root = self.github_authority
        if (
            root is None
            or not root.is_absolute()
            or not root.is_dir()
            or root.is_symlink()
        ):
            raise ObservationError("github_authority_directory_invalid")
        actual: set[str] = set()
        try:
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ObservationError("github_authority_contains_symlink")
                if path.is_file():
                    actual.add(path.relative_to(root).as_posix())
            if actual != {"manifest.json", *self._github_authority_entries}:
                raise ObservationError("github_authority_file_set_invalid")
            if (
                self._github_authority_manifest_sha256 is None
                or EVIDENCE.sha256_file(
                    root / "manifest.json", EVIDENCE.MAXIMUM_RESULT_BYTES
                )
                != self._github_authority_manifest_sha256
            ):
                raise ObservationError("github_authority_manifest_changed")
            for entry in self._github_authority_entries.values():
                path = entry["path_object"]
                if (
                    path.stat().st_size != entry["bytes"]
                    or EVIDENCE.sha256_file(path, EVIDENCE.MAXIMUM_RAW_BYTES)
                    != entry["sha256"]
                ):
                    raise ObservationError("github_authority_file_changed")
        except ObservationError:
            raise
        except (EVIDENCE.EvidenceError, OSError):
            raise ObservationError("github_authority_file_changed") from None

    @staticmethod
    def _execute_command(
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        timeout: int = 20 * 60,
    ) -> tuple[bytes, datetime, datetime]:
        if not command or not isinstance(command[0], str):
            raise ObservationError("observation_command_invalid")
        executable = shutil.which(command[0])
        if executable is None:
            raise ObservationError("observation_tool_unavailable")
        invocation = (executable, *command[1:])
        started = datetime.now(timezone.utc).replace(microsecond=0)
        try:
            result = subprocess.run(
                invocation,
                cwd=cwd,
                env=command_environment(environment),
                check=False,
                capture_output=True,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            raise ObservationError("observation_command_failed") from None
        finished = datetime.now(timezone.utc).replace(microsecond=0)
        if finished <= started:
            finished = started + EVIDENCE.timedelta(seconds=1)
        if result.returncode != 0:
            raise ObservationError("observation_command_failed")
        payload = result.stdout
        if not payload:
            raise ObservationError("observation_output_empty")
        EVIDENCE.scan_safe(payload)
        return payload, started, finished

    def run_command(
        self,
        observation: str,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        validate=None,
        version: str = "system",
        timeout: int = 20 * 60,
    ) -> bytes:
        if observation not in EVIDENCE.OBSERVATION_TOOLS:
            raise ObservationError("observation_invalid")
        payload, started, finished = self._execute_command(
            command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
        if validate is not None:
            validate(payload)
        self.emit(
            observation,
            payload,
            started=started,
            finished=finished,
            version=version,
            invocation=command,
            cwd=cwd,
        )
        return payload

    def emit(
        self,
        observation: str,
        payload: bytes,
        *,
        started: datetime,
        finished: datetime,
        version: str,
        invocation: Sequence[str],
        cwd: Path | None = None,
        retained_inputs: Mapping[str, bytes] | None = None,
        retained_input_kind: str = "physical_device_receipt",
        raw_artifacts: Mapping[str, bytes] | None = None,
    ) -> None:
        if observation not in EVIDENCE.expected_observations(
            self.domain, getattr(self, "evidence_release_profile", None)
        ):
            raise ObservationError("observation_invalid")
        EVIDENCE.scan_safe(payload)
        slug = observation.replace(".", "-")
        relative = f"artifacts/{slug}/tool-output.json"
        artifacts = [
            {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
        ]
        retained = retained_inputs or {}
        container = RETAINED_INPUT_CONTAINERS.get(retained_input_kind)
        if len(retained) > 64 or (retained and container is None):
            raise ObservationError("observation_retained_input_set_invalid")
        retained_files: list[dict[str, str]] = []
        for name, retained_payload in sorted(retained.items()):
            if (
                not isinstance(name, str)
                or EVIDENCE.ARTIFACT_NAME.fullmatch(name) is None
                or not isinstance(retained_payload, bytes)
            ):
                raise ObservationError("observation_retained_input_set_invalid")
            if (
                retained_input_kind == "live_sdk_collector_isolation"
                and name in LIVE_SDK_ISOLATION_SIGNATURES
            ) or (
                retained_input_kind == "live_provider_collector_isolation"
                and name in LIVE_PROVIDER_ISOLATION_SIGNATURES
            ):
                if not 1 <= len(retained_payload) <= 16 * 1024:
                    raise ObservationError("observation_retained_input_set_invalid")
            else:
                EVIDENCE.scan_safe(retained_payload)
            retained_files.append(
                {
                    "name": name,
                    "sha256": hashlib.sha256(retained_payload).hexdigest(),
                    "content_base64": base64.b64encode(retained_payload).decode("ascii"),
                }
            )
        if retained_files:
            assert container is not None
            retained_payload = canonical_json(
                {
                    "schema_version": 1,
                    "kind": container[0],
                    "observation": observation,
                    "files": retained_files,
                }
            )
            EVIDENCE.scan_safe(retained_payload)
            retained_relative = f"artifacts/{slug}/{container[1]}"
            artifacts.append(
                {
                    "path": retained_relative,
                    "sha256": hashlib.sha256(retained_payload).hexdigest(),
                }
            )
        raw = raw_artifacts or {}
        if len(raw) > 4:
            raise ObservationError("observation_raw_artifact_set_invalid")
        raw_files: list[tuple[str, str, bytes]] = []
        for name, raw_payload in sorted(raw.items()):
            if (
                observation != "registry.npm.javascript"
                or not isinstance(name, str)
                or JAVASCRIPT_RETAINED_TARBALL.fullmatch(name) is None
                or not isinstance(raw_payload, bytes)
                or not 1 <= len(raw_payload) <= MAXIMUM_RETAINED_NPM_TARBALL_BYTES
            ):
                raise ObservationError("observation_raw_artifact_set_invalid")
            raw_relative = f"artifacts/{slug}/{name}"
            raw_files.append((name, raw_relative, raw_payload))
            artifacts.append(
                {
                    "path": raw_relative,
                    "sha256": hashlib.sha256(raw_payload).hexdigest(),
                }
            )
        # Validate and construct every output before the first filesystem
        # mutation so an invalid retained receipt cannot leave a partial
        # machine-result directory behind.
        write_bytes(self.output / relative, payload)
        if retained_files:
            write_bytes(self.output / retained_relative, retained_payload)
        for _, raw_relative, raw_payload in raw_files:
            write_bytes(self.output / raw_relative, raw_payload)
        descriptor = {
            "tool": EVIDENCE.OBSERVATION_TOOLS[observation],
            "argv": [Path(invocation[0]).name, *invocation[1:]],
            "working_repository": self._repository_id_for_path(cwd),
        }
        result = {
            "schema_version": 1,
            "kind": "latchway_release_machine_result",
            "domain": self.domain,
            "observation": observation,
            "started_at": EVIDENCE.format_time(started),
            "finished_at": EVIDENCE.format_time(finished),
            "candidate": self.identity,
            "tool": {
                "name": EVIDENCE.OBSERVATION_TOOLS[observation],
                "version": version if EVIDENCE.TOOL_VALUE.fullmatch(version) else "system",
                "invocation_sha256": hashlib.sha256(canonical_json(descriptor)).hexdigest(),
            },
            "exit_code": 0,
            "artifacts": artifacts,
        }
        EVIDENCE.write_exclusive(self.output / EVIDENCE.result_name(observation), result)

    def emit_existing(
        self, observation: str, source: Path, *, version: str, validate
    ) -> None:
        payload = EVIDENCE.read_bytes(source)
        validate(payload)
        started = datetime.now(timezone.utc).replace(microsecond=0)
        finished = started + EVIDENCE.timedelta(seconds=1)
        self.emit(
            observation,
            payload,
            started=started,
            finished=finished,
            version=version,
            invocation=(EVIDENCE.OBSERVATION_TOOLS[observation], "verify", source.name),
        )

    def _repository_id_for_path(self, cwd: Path | None) -> str:
        if cwd is not None:
            try:
                resolved = cwd.resolve(strict=True)
            except OSError:
                return "unknown"
            for repository_id, root in self.repositories.items():
                try:
                    if resolved == root.resolve(strict=True):
                        return repository_id
                except OSError:
                    continue
        return "core"

    def observe(self) -> None:
        getattr(self, f"observe_{self.domain}")()
        self._validate_github_authority_consumed()
        self._validate_repositories()
        if (
            EVIDENCE.sha256_file(self.source, EVIDENCE.MAXIMUM_RESULT_BYTES)
            != self.input_hashes["source"]
            or EVIDENCE.sha256_file(
                self.candidate_path, EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            != self.input_hashes["candidate"]
        ):
            raise ObservationError("observation_identity_changed")
        actual = {path.name for path in self.output.glob("*.json")}
        expected = {
            EVIDENCE.result_name(item)
            for item in EVIDENCE.expected_observations(
                self.domain, getattr(self, "evidence_release_profile", None)
            )
        }
        if actual != expected:
            raise ObservationError("observation_set_incomplete")

    def observe_live_provider(self) -> None:
        capture = self._load_live_provider_capture()
        base_url = capture["gateway_origin"]
        health = capture["files"]["health.json"]
        self_test = capture["files"]["self-test.json"]
        self._validate_gateway_identity(health["payload"], self.identity)
        states = self._validate_provider_result(self_test["payload"])
        self.emit(
            "provider.gateway-identity",
            health["payload"],
            started=health["started"],
            finished=health["finished"],
            version="https-v1",
            invocation=("https", "GET", f"{base_url}/healthz"),
            retained_inputs=capture["retained_inputs"],
            retained_input_kind="live_provider_collector_isolation",
        )
        request_digest = capture["request_sha256"]
        invocation = (
            "https",
            "POST",
            f"{base_url}/admin/v1/self-tests",
            f"request-sha256:{request_digest}",
        )
        for observation, check in PROVIDER_CHECKS.items():
            if states.get(check) != "passed":
                raise ObservationError("live_provider_check_missing")
            self.emit(
                observation,
                self_test["payload"],
                started=self_test["started"],
                finished=self_test["finished"],
                version="admin-api-v1",
                invocation=invocation,
            )
        # Re-open the complete sealed closure after output production so even a
        # concurrent post-read mutation cannot survive validation.
        confirmed = self._load_live_provider_capture()
        if confirmed["manifest_sha256"] != capture["manifest_sha256"]:
            raise ObservationError("live_provider_capture_changed")

    def _load_live_provider_capture(self) -> dict[str, Any]:
        root = self.live_provider_capture
        if (
            root is None
            or not root.is_absolute()
            or not root.is_dir()
            or root.is_symlink()
        ):
            raise ObservationError("live_provider_capture_invalid")
        actual: set[str] = set()
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ObservationError("live_provider_capture_symlink")
            if path.is_file():
                actual.add(path.relative_to(root).as_posix())
        if actual != {
            "manifest.json",
            "health.json",
            "self-test.json",
            "collector-isolation/collector-lease.json",
            "collector-isolation/collector-lease.sig",
            "collector-isolation/collector-trust-root.pem",
            "collector-isolation/grant-consumption-receipt.json",
            "collector-isolation/grant-consumption-receipt.sig",
            "collector-isolation/collector-teardown.json",
            "collector-isolation/collector-teardown.sig",
        }:
            raise ObservationError("live_provider_capture_file_set_invalid")
        try:
            manifest_sha256 = EVIDENCE.sha256_file(
                root / "manifest.json", EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            manifest = EVIDENCE.read_json(root / "manifest.json")
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_provider_capture_invalid") from None
        if (
            set(manifest)
            != {
                "schema_version",
                "kind",
                "candidate",
                "source_sha256",
                "candidate_sha256",
                "gateway_origin",
                "request",
                "request_sha256",
                "started_at",
                "finished_at",
                "collector_isolation",
                "files",
            }
            or manifest.get("schema_version") != 1
            or manifest.get("kind") != "latchway_live_provider_capture"
            or manifest.get("candidate") != self.identity
            or manifest.get("source_sha256") != self.input_hashes["source"]
            or manifest.get("candidate_sha256") != self.input_hashes["candidate"]
        ):
            raise ObservationError("live_provider_capture_invalid")
        base_url = manifest.get("gateway_origin")
        if not isinstance(base_url, str):
            raise ObservationError("live_provider_gateway_invalid")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ObservationError("live_provider_gateway_invalid")
        request = manifest.get("request")
        if (
            not isinstance(request, dict)
            or set(request)
            != {"kind", "environment_id", "upstream", "model", "max_cost_nano_usd"}
            or request.get("kind") != "openrouter"
            or any(
                not isinstance(request.get(name), str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request[name])
                is None
                for name in ("environment_id", "upstream", "model")
            )
            or not isinstance(request.get("max_cost_nano_usd"), int)
            or isinstance(request.get("max_cost_nano_usd"), bool)
            or not 1 <= request["max_cost_nano_usd"] <= 100_000_000
            or manifest.get("request_sha256")
            != hashlib.sha256(canonical_json(request)).hexdigest()
        ):
            raise ObservationError("live_provider_cost_bound_invalid")
        try:
            started = EVIDENCE.parse_time(
                manifest.get("started_at"), "live_provider_capture_time_invalid"
            )
            finished = EVIDENCE.parse_time(
                manifest.get("finished_at"), "live_provider_capture_time_invalid"
            )
        except EVIDENCE.EvidenceError as error:
            raise ObservationError(str(error)) from None
        if (
            started < self.candidate_created
            or finished <= started
            or finished > self.now
            or finished - started > EVIDENCE.timedelta(minutes=10)
        ):
            raise ObservationError("live_provider_capture_time_invalid")
        self._validate_live_provider_isolation(root, manifest, started, finished)
        file_rows = manifest.get("files")
        if not isinstance(file_rows, list) or len(file_rows) != 2:
            raise ObservationError("live_provider_capture_file_set_invalid")
        by_name: dict[str, dict[str, Any]] = {}
        for row in file_rows:
            if not isinstance(row, dict) or set(row) != {
                "path",
                "bytes",
                "sha256",
                "status_code",
                "started_at",
                "finished_at",
            }:
                raise ObservationError("live_provider_capture_file_set_invalid")
            name = row.get("path")
            expected_status = {"health.json": 200, "self-test.json": 202}.get(name)
            if (
                expected_status is None
                or name in by_name
                or row.get("status_code") != expected_status
                or not isinstance(row.get("bytes"), int)
                or isinstance(row.get("bytes"), bool)
                or not 1 <= row["bytes"] <= EVIDENCE.MAXIMUM_RESULT_BYTES
                or not isinstance(row.get("sha256"), str)
                or EVIDENCE.SHA256.fullmatch(row["sha256"]) is None
            ):
                raise ObservationError("live_provider_capture_file_set_invalid")
            try:
                item_started = EVIDENCE.parse_time(
                    row.get("started_at"), "live_provider_capture_time_invalid"
                )
                item_finished = EVIDENCE.parse_time(
                    row.get("finished_at"), "live_provider_capture_time_invalid"
                )
                payload = EVIDENCE.read_bytes(
                    root / name, EVIDENCE.MAXIMUM_RESULT_BYTES
                )
            except EVIDENCE.EvidenceError as error:
                raise ObservationError(str(error)) from None
            if (
                item_started < started
                or item_finished <= item_started
                or item_finished > finished
                or item_finished - item_started > EVIDENCE.timedelta(minutes=5)
                or len(payload) != row["bytes"]
                or hashlib.sha256(payload).hexdigest() != row["sha256"]
            ):
                raise ObservationError("live_provider_capture_file_invalid")
            load_output(payload, "live_provider_capture_response_invalid")
            by_name[name] = {
                "payload": payload,
                "started": item_started,
                "finished": item_finished,
            }
        if set(by_name) != {"health.json", "self-test.json"}:
            raise ObservationError("live_provider_capture_file_set_invalid")
        try:
            final_manifest_sha256 = EVIDENCE.sha256_file(
                root / "manifest.json", EVIDENCE.MAXIMUM_RESULT_BYTES
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_provider_capture_invalid") from None
        if final_manifest_sha256 != manifest_sha256:
            raise ObservationError("live_provider_capture_changed")
        try:
            retained_inputs = {
                name: EVIDENCE.read_bytes(root / relative)
                for name, relative in LIVE_PROVIDER_ISOLATION_PATHS.items()
            }
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_provider_capture_changed") from None
        return {
            "gateway_origin": base_url.rstrip("/"),
            "request_sha256": manifest["request_sha256"],
            "manifest_sha256": manifest_sha256,
            "files": by_name,
            "retained_inputs": retained_inputs,
        }

    def _validate_live_provider_isolation(
        self,
        root: Path,
        manifest: Mapping[str, Any],
        started: datetime,
        finished: datetime,
    ) -> None:
        code = "live_provider_collector_isolation_invalid"
        isolation = manifest.get("collector_isolation")
        expected_hashes = {
            "lease_sha256": "collector-lease.json",
            "lease_signature_sha256": "collector-lease.sig",
            "trust_root_sha256": "collector-trust-root.pem",
            "receipt_sha256": "grant-consumption-receipt.json",
            "receipt_signature_sha256": "grant-consumption-receipt.sig",
            "teardown_sha256": "collector-teardown.json",
            "teardown_signature_sha256": "collector-teardown.sig",
        }
        if (
            not isinstance(isolation, dict)
            or set(isolation) != {"schema_version", *expected_hashes}
            or isolation.get("schema_version")
            != "latchway.live-provider-collector-isolation.v1"
        ):
            raise ObservationError(code)
        isolation_root = root / "collector-isolation"
        payloads: dict[str, bytes] = {}
        try:
            for field, name in expected_hashes.items():
                payload = EVIDENCE.read_bytes(isolation_root / name, 2 * 1024 * 1024)
                if (
                    not isinstance(isolation.get(field), str)
                    or EVIDENCE.SHA256.fullmatch(isolation[field]) is None
                    or hashlib.sha256(payload).hexdigest() != isolation[field]
                ):
                    raise ObservationError(code)
                payloads[name] = payload
            lease = EVIDENCE.read_json(isolation_root / "collector-lease.json")
            receipt = EVIDENCE.read_json(
                isolation_root / "grant-consumption-receipt.json"
            )
            teardown = EVIDENCE.read_json(isolation_root / "collector-teardown.json")
        except EVIDENCE.EvidenceError:
            raise ObservationError(code) from None

        for name in (
            "collector-lease.sig",
            "grant-consumption-receipt.sig",
            "collector-teardown.sig",
        ):
            if not 8 <= len(payloads[name]) <= 4096:
                raise ObservationError(code)
        try:
            trust_root = payloads["collector-trust-root.pem"].decode("ascii")
        except UnicodeDecodeError:
            raise ObservationError(code) from None
        if (
            "PRIVATE KEY" in trust_root
            or re.fullmatch(
                r"-----BEGIN PUBLIC KEY-----\n"
                r"[A-Za-z0-9+/=\n]+"
                r"-----END PUBLIC KEY-----\n?",
                trust_root,
            )
            is None
        ):
            raise ObservationError(code)

        workflow = lease.get("workflow") if isinstance(lease, dict) else None
        runner = lease.get("runner") if isinstance(lease, dict) else None
        grant = lease.get("grant") if isinstance(lease, dict) else None
        candidate = lease.get("candidate") if isinstance(lease, dict) else None
        gateway = lease.get("gateway") if isinstance(lease, dict) else None
        core_commit = self.identity["core_commit"]
        request_sha256 = manifest.get("request_sha256")
        if (
            not isinstance(lease, dict)
            or set(lease)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "workflow",
                "runner",
                "credentials",
                "supervisor",
                "grant",
                "candidate",
                "gateway",
                "issued_at_unix",
                "expires_at_unix",
            }
            or lease.get("schema_version")
            != "latchway.live-provider-collector-lease.v1"
            or lease.get("repository") != EVIDENCE.REPOSITORY
            or lease.get("core_commit") != core_commit
            or not isinstance(workflow, dict)
            or set(workflow) != {"run_id", "run_attempt", "job", "audience"}
            or EVIDENCE.RUN_ID.fullmatch(str(workflow.get("run_id"))) is None
            or re.fullmatch(r"[1-9][0-9]{0,5}", str(workflow.get("run_attempt")))
            is None
            or workflow.get("job") != "live_provider_capture"
            or workflow.get("audience") != "latchway-live-provider/self-test"
            or not isinstance(workflow.get("run_id"), str)
            or not isinstance(workflow.get("run_attempt"), str)
            or not isinstance(runner, dict)
            or set(runner)
            != {
                "name",
                "ephemeral",
                "jit",
                "max_jobs",
                "fresh_boot",
                "clean_workspace",
                "repository_scope",
                "destroy_after_job",
                "image_digest",
                "boot_id_sha256",
            }
            or runner.get("name")
            != f"latchway-live-provider-{workflow.get('run_id')}-{workflow.get('run_attempt')}"
            or runner.get("ephemeral") is not True
            or runner.get("jit") is not True
            or runner.get("max_jobs") != 1
            or runner.get("fresh_boot") is not True
            or runner.get("clean_workspace") is not True
            or runner.get("repository_scope") != EVIDENCE.REPOSITORY
            or runner.get("destroy_after_job") is not True
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(runner.get("image_digest")))
            is None
            or EVIDENCE.SHA256.fullmatch(str(runner.get("boot_id_sha256"))) is None
            or lease.get("credentials")
            != {
                "long_lived": False,
                "organization": False,
                "administration": False,
                "registry": False,
                "oidc": False,
            }
            or lease.get("supervisor")
            != {
                "private_key_isolated": True,
                "caller_supplied_claims_accepted": False,
                "gateway_egress_only": True,
                "dns_pinned": True,
                "tls_verified": True,
                "grant_issuer_independent": True,
                "one_use_verification": True,
                "out_of_band_watchdog": True,
            }
            or not isinstance(grant, dict)
            or set(grant)
            != {
                "audience",
                "core_commit",
                "run_id",
                "run_attempt",
                "sha256",
                "scope",
                "single_use",
                "revocable",
                "jti_sha256",
                "request_sha256",
                "issued_at_unix",
                "expires_at_unix",
            }
            or grant.get("audience") != "latchway-live-provider/self-test"
            or grant.get("core_commit") != core_commit
            or grant.get("run_id") != workflow["run_id"]
            or grant.get("run_attempt") != workflow["run_attempt"]
            or grant.get("scope") != "run_self_tests"
            or grant.get("single_use") is not True
            or grant.get("revocable") is not True
            or EVIDENCE.SHA256.fullmatch(str(grant.get("sha256"))) is None
            or EVIDENCE.SHA256.fullmatch(str(grant.get("jti_sha256"))) is None
            or grant.get("request_sha256") != request_sha256
            or not isinstance(candidate, dict)
            or candidate
            != {
                "source_report_sha256": self.input_hashes["source"],
                "candidate_manifest_sha256": self.input_hashes["candidate"],
            }
            or gateway != {"origin": manifest.get("gateway_origin")}
        ):
            raise ObservationError(code)
        numeric = (
            lease.get("issued_at_unix"),
            lease.get("expires_at_unix"),
            grant.get("issued_at_unix"),
            grant.get("expires_at_unix"),
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in numeric):
            raise ObservationError(code)
        lease_issued, lease_expires, grant_issued, grant_expires = numeric
        if (
            lease_issued < int(self.candidate_created.timestamp())
            or lease_issued > int(started.timestamp())
            or lease_expires < int(started.timestamp())
            or not 1 <= lease_expires - lease_issued <= 600
            or grant_issued < lease_issued
            or grant_issued > int(started.timestamp())
            or grant_expires < int(finished.timestamp())
            or grant_expires > lease_expires
            or not 1 <= grant_expires - grant_issued <= 300
        ):
            raise ObservationError(code)

        if (
            not isinstance(receipt, dict)
            or set(receipt)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "run_id",
                "run_attempt",
                "audience",
                "scope",
                "grant_sha256",
                "jti_sha256",
                "single_use",
                "consumption_count",
                "consumed",
                "revoked",
                "request_sha256",
                "health_sha256",
                "self_test_sha256",
                "consumed_at_unix",
            }
            or receipt.get("schema_version")
            != "latchway.live-provider-grant-consumption.v1"
            or receipt.get("repository") != EVIDENCE.REPOSITORY
            or receipt.get("core_commit") != core_commit
            or receipt.get("run_id") != workflow["run_id"]
            or receipt.get("run_attempt") != workflow["run_attempt"]
            or receipt.get("audience") != workflow["audience"]
            or receipt.get("scope") != "run_self_tests"
            or receipt.get("grant_sha256") != grant["sha256"]
            or receipt.get("jti_sha256") != grant["jti_sha256"]
            or receipt.get("single_use") is not True
            or receipt.get("consumption_count") != 1
            or receipt.get("consumed") is not True
            or receipt.get("revoked") is not True
            or receipt.get("request_sha256") != request_sha256
            or receipt.get("health_sha256")
            != hashlib.sha256(EVIDENCE.read_bytes(root / "health.json")).hexdigest()
            or receipt.get("self_test_sha256")
            != hashlib.sha256(EVIDENCE.read_bytes(root / "self-test.json")).hexdigest()
            or not isinstance(receipt.get("consumed_at_unix"), int)
            or isinstance(receipt.get("consumed_at_unix"), bool)
            or not int(started.timestamp())
            <= receipt["consumed_at_unix"]
            <= int(finished.timestamp())
        ):
            raise ObservationError(code)

        teardown_workflow = (
            teardown.get("workflow") if isinstance(teardown, dict) else None
        )
        teardown_runner = teardown.get("runner") if isinstance(teardown, dict) else None
        if (
            not isinstance(teardown, dict)
            or set(teardown)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "workflow",
                "runner",
                "grant",
                "network",
                "receipt_verified",
                "evidence_eligible",
                "lease_sha256",
                "receipt_sha256",
                "health_sha256",
                "self_test_sha256",
            }
            or teardown.get("schema_version")
            != "latchway.live-provider-collector-teardown.v1"
            or teardown.get("repository") != EVIDENCE.REPOSITORY
            or teardown.get("core_commit") != core_commit
            or teardown_workflow != workflow
            or not isinstance(teardown_runner, dict)
            or set(teardown_runner)
            != {
                "name",
                "deregistered",
                "accepts_more_jobs",
                "destroy_scheduled",
                "destroy_deadline_unix",
            }
            or teardown_runner.get("name") != runner["name"]
            or teardown_runner.get("deregistered") is not True
            or teardown_runner.get("accepts_more_jobs") is not False
            or teardown_runner.get("destroy_scheduled") is not True
            or not isinstance(teardown_runner.get("destroy_deadline_unix"), int)
            or isinstance(teardown_runner.get("destroy_deadline_unix"), bool)
            or not int(finished.timestamp())
            <= teardown_runner["destroy_deadline_unix"]
            <= int(finished.timestamp()) + 600
            or teardown.get("grant")
            != {
                "single_use": True,
                "consumption_count": 1,
                "zeroized": True,
                "revoked": True,
            }
            or teardown.get("network")
            != {
                "gateway_egress_only": True,
                "dns_pinned": True,
                "tls_verified": True,
            }
            or teardown.get("receipt_verified") is not True
            or teardown.get("evidence_eligible") is not True
            or teardown.get("lease_sha256") != isolation["lease_sha256"]
            or teardown.get("receipt_sha256") != isolation["receipt_sha256"]
            or teardown.get("health_sha256") != receipt["health_sha256"]
            or teardown.get("self_test_sha256") != receipt["self_test_sha256"]
        ):
            raise ObservationError(code)

    @staticmethod
    def _validate_gateway_identity(
        payload: bytes, identity: Mapping[str, Any]
    ) -> None:
        value = load_output(payload, "live_provider_gateway_identity_invalid")
        build = value.get("build") if isinstance(value, dict) else None
        core = identity.get("repositories", {}).get("core", {})
        if (
            not isinstance(value, dict)
            or value.get("status") != "ok"
            or not isinstance(build, dict)
            or build.get("version") != core.get("version")
            or build.get("commit") != identity.get("core_commit")
            or build.get("contract_version") != identity.get("contract_version")
            or str(build.get("protocol_version")) != "2"
        ):
            raise ObservationError("live_provider_gateway_identity_invalid")

    @staticmethod
    def _validate_provider_result(payload: bytes) -> dict[str, str]:
        document = load_output(payload, "live_provider_result_invalid")
        if (
            not isinstance(document, dict)
            or document.get("kind") != "openrouter"
            or document.get("state") != "passed"
        ):
            raise ObservationError("live_provider_result_invalid")
        checks = document.get("checks")
        if not isinstance(checks, list):
            raise ObservationError("live_provider_result_invalid")
        states: dict[str, str] = {}
        for item in checks:
            if (
                not isinstance(item, dict)
                or set(item) - {"name", "state", "safe_detail"}
                or not isinstance(item.get("name"), str)
                or not isinstance(item.get("state"), str)
                or item["name"] in states
            ):
                raise ObservationError("live_provider_result_invalid")
            states[item["name"]] = item["state"]
        if any(states.get(name) != "passed" for name in PROVIDER_CHECKS.values()):
            raise ObservationError("live_provider_check_missing")
        return states

    def observe_supply_chain(self) -> None:
        image = self.identity["oci_image_digest"]
        index_digest = self.candidate["image"]["index_digest"]
        inspect_command = (
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            "--raw",
            image,
        )
        payload = self.run_command(
            "supply.oci-index",
            inspect_command,
            validate=lambda raw: self._validate_index(
                raw, index_digest, self.candidate["image"]["platforms"]
            ),
        )
        for observation in (
            "supply.platform.amd64",
            "supply.platform.arm64",
        ):
            self.emit(
                observation,
                payload,
                started=datetime.now(timezone.utc).replace(microsecond=0),
                finished=datetime.now(timezone.utc).replace(microsecond=0) + EVIDENCE.timedelta(seconds=1),
                version="system",
                invocation=inspect_command,
            )

        candidate_root = self.candidate_path.parent
        for observation, name, key in (
            ("supply.vulnerability.amd64", "latchway-linux-amd64-vulnerability.json", "Vulnerabilities"),
            ("supply.vulnerability.arm64", "latchway-linux-arm64-vulnerability.json", "Vulnerabilities"),
            ("supply.license.amd64", "latchway-linux-amd64-license.json", "Licenses"),
            ("supply.license.arm64", "latchway-linux-arm64-license.json", "Licenses"),
        ):
            self.emit_existing(
                observation,
                candidate_root / name,
                version="1.0.0",
                validate=lambda raw, result_key=key: self._validate_trivy(
                    raw, result_key
                ),
            )
        for observation, name in (
            ("supply.sbom.amd64", "latchway-linux-amd64.spdx.json"),
            ("supply.sbom.arm64", "latchway-linux-arm64.spdx.json"),
        ):
            self.emit_existing(
                observation,
                candidate_root / name,
                version="1.0.0",
                validate=self._validate_spdx,
            )

        for architecture in ("amd64", "arm64"):
            digest = self.candidate["image"]["platforms"][f"linux/{architecture}"]
            sbom = load_output(
                EVIDENCE.read_bytes(
                    candidate_root / f"latchway-linux-{architecture}.spdx.json"
                ),
                "spdx_invalid",
            )
            attestation, started, finished = self._github_authority_file(
                f"supply-chain/github-spdx-{architecture}.json"
            )
            self._validate_github_attestation(
                attestation,
                predicate_type="https://spdx.dev/Document/v2.3",
                digest=digest,
                code="github_spdx_attestation_invalid",
                expected_predicate=sbom,
            )
            self.emit(
                f"supply.github-spdx.{architecture}",
                attestation,
                started=started,
                finished=finished,
                version="github-cli-v2",
                invocation=(
                    "gh",
                    "attestation",
                    "verify",
                    f"oci://{self.candidate['image']['repository']}@{digest}",
                    "--repo",
                    EVIDENCE.REPOSITORY,
                    "--signer-workflow",
                    f"{EVIDENCE.REPOSITORY}/{EVIDENCE.CANDIDATE_WORKFLOW}",
                    "--source-digest",
                    self.identity["core_commit"],
                    "--signer-digest",
                    self.identity["core_commit"],
                    "--source-ref",
                    "refs/heads/main",
                    "--deny-self-hosted-runners",
                    "--bundle-from-oci",
                    "--predicate-type",
                    "https://spdx.dev/Document/v2.3",
                    "--format",
                    "json",
                ),
            )

        certificate = "https://github.com/Latchway/latchway/.github/workflows/release.yml@refs/heads/main"
        self.run_command(
            "supply.cosign-signature",
            (
                "cosign", "verify", "--output", "json",
                "--certificate-identity", certificate,
                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-sha", self.identity["core_commit"],
                image,
            ),
            validate=lambda payload: self._validate_cosign(payload, image, "cosign_result_invalid"),
        )
        provenance, started, finished = self._github_authority_file(
            "supply-chain/github-provenance.json",
            maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
        )
        self._validate_github_attestation(
            provenance,
            predicate_type="https://slsa.dev/provenance/v1",
            digest=index_digest,
            code="provenance_result_invalid",
        )
        self.emit(
            "supply.github-provenance",
            provenance,
            started=started,
            finished=finished,
            version="github-cli-v2",
            invocation=(
                "gh",
                "attestation",
                "verify",
                f"oci://{image}",
                "--repo",
                EVIDENCE.REPOSITORY,
                "--signer-workflow",
                f"{EVIDENCE.REPOSITORY}/{EVIDENCE.CANDIDATE_WORKFLOW}",
                "--source-digest",
                self.identity["core_commit"],
                "--signer-digest",
                self.identity["core_commit"],
                "--source-ref",
                "refs/heads/main",
                "--deny-self-hosted-runners",
                "--bundle-from-oci",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--format",
                "json",
            ),
        )

    @staticmethod
    def _validate_index(
        payload: bytes,
        index_digest: str,
        platforms: Mapping[str, str],
    ) -> None:
        raw_hashes = {
            hashlib.sha256(payload).hexdigest(),
            hashlib.sha256(payload.removesuffix(b"\n")).hexdigest(),
        }
        if index_digest.removeprefix("sha256:") not in raw_hashes:
            raise ObservationError("oci_index_digest_mismatch")
        value = load_output(payload, "oci_index_invalid")
        manifests = value.get("manifests") if isinstance(value, dict) else None
        if not isinstance(manifests, list):
            raise ObservationError("oci_index_invalid")
        observed: dict[str, str] = {}
        for entry in manifests:
            platform = entry.get("platform") if isinstance(entry, dict) else None
            if not isinstance(platform, dict):
                raise ObservationError("oci_platforms_mismatch")
            os_name = platform.get("os")
            architecture = platform.get("architecture")
            name = f"{os_name}/{architecture}"
            digest = entry.get("digest") if isinstance(entry, dict) else None
            if name in observed or not isinstance(digest, str):
                raise ObservationError("oci_platforms_mismatch")
            observed[name] = digest
        # Registry attestations are OCI referrers to these subjects. They do not
        # rewrite the immutable two-platform subject index with synthetic
        # `unknown/unknown` descriptors.
        if len(manifests) != len(platforms) or observed != dict(platforms):
            raise ObservationError("oci_platforms_mismatch")

    @staticmethod
    def _validate_trivy(payload: bytes, result_key: str) -> None:
        value = load_output(payload, "trivy_result_invalid")
        if (
            result_key not in ("Vulnerabilities", "Licenses")
            or not isinstance(value, dict)
            or not isinstance(value.get("Results"), list)
        ):
            raise ObservationError("trivy_result_invalid")
        findings = [
            item
            for result in value["Results"]
            if isinstance(result, dict)
            for item in result.get(result_key, []) or []
            if isinstance(item, dict)
            and item.get("Severity") in ("HIGH", "CRITICAL")
        ]
        if findings:
            raise ObservationError("trivy_policy_failed")

    @staticmethod
    def _validate_spdx(payload: bytes) -> None:
        value = load_output(payload, "spdx_invalid")
        if (
            not isinstance(value, dict)
            or not str(value.get("spdxVersion", "")).startswith("SPDX-")
            or not isinstance(value.get("packages"), list)
            or not value["packages"]
        ):
            raise ObservationError("spdx_invalid")

    @staticmethod
    def _require_nonempty_list(payload: bytes, code: str) -> None:
        value = load_output(payload, code)
        if not isinstance(value, list) or not value:
            raise ObservationError(code)

    @staticmethod
    def _validate_github_attestation(
        payload: bytes,
        *,
        predicate_type: str,
        digest: str,
        code: str,
        expected_predicate: Any | None = None,
    ) -> None:
        value = load_output(payload, code)
        expected_digest = digest.removeprefix("sha256:")
        if not isinstance(value, list) or not value:
            raise ObservationError(code)
        exact_predicate_found = expected_predicate is None
        for item in value:
            statement = nested(item, "verificationResult", "statement")
            subjects = statement.get("subject") if isinstance(statement, dict) else None
            if (
                not isinstance(statement, dict)
                or statement.get("predicateType") != predicate_type
                or not isinstance(subjects, list)
                or not any(
                    isinstance(subject, dict)
                    and nested(subject, "digest", "sha256") == expected_digest
                    for subject in subjects
                )
            ):
                raise ObservationError(code)
            if statement.get("predicate") == expected_predicate:
                exact_predicate_found = True
        if not exact_predicate_found:
            raise ObservationError(code)

    @staticmethod
    def _validate_cosign(payload: bytes, image: str, code: str) -> None:
        value = load_output(payload, code)
        digest = image.rsplit("@", 1)[-1]
        repository = image.split("@", 1)[0]
        if not isinstance(value, list) or not value:
            raise ObservationError(code)
        matching = [
            item
            for item in value
            if isinstance(item, dict)
            and nested(item, "critical", "image", "docker-manifest-digest")
            == digest
            and nested(item, "critical", "identity", "docker-reference")
            == repository
        ]
        if not matching:
            raise ObservationError(code)

    def observe_public_tags(self) -> None:
        promotion_sha256: str | None = None
        sdk_titles = {
            "javascript": "JavaScript SDK",
            "ios": "iOS SDK",
            "android": "Android SDK",
            "react_native": "React Native SDK",
        }
        core_tag = self.identity["repositories"]["core"]["tag"]
        for repository_id in ("core", "javascript", "ios", "android", "react_native"):
            coordinate = self.identity["repositories"][repository_id]
            repository = f"Latchway/{REPOSITORY_NAMES[repository_id]}"
            tag = coordinate["tag"]
            root = f"public-tags/{repository_id}"
            ref_payload, ref_started, ref_finished = self._github_authority_file(
                f"{root}/tag-ref.json", maximum=EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            ref = self._validate_tag_ref(ref_payload, tag)
            tag_payload, tag_started, tag_finished = self._github_authority_file(
                f"{root}/tag-object.json", maximum=EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            tag_object = self._validate_tag_object(
                tag_payload, tag, coordinate["commit"]
            )
            release_payload, release_started, release_finished = (
                self._github_authority_file(
                    f"{root}/release.json", maximum=EVIDENCE.MAXIMUM_RESULT_BYTES
                )
            )
            expected_assets, adoption_required = self._expected_release_assets(
                repository_id,
                coordinate["version"],
                getattr(self, "release_profile", None),
            )
            message = tag_object.get("message")
            if getattr(self, "release_profile", None) is None:
                if repository_id == "core":
                    match = re.fullmatch(
                        re.escape(
                            f"Latchway {tag}\n\nPromotion evidence SHA-256: "
                        )
                        + r"([0-9a-f]{64})",
                        message if isinstance(message, str) else "",
                    )
                    if match is None:
                        raise ObservationError("public_tag_message_mismatch")
                    promotion_sha256 = match.group(1)
                else:
                    if promotion_sha256 is None:
                        raise ObservationError("public_tag_message_mismatch")
                    expected_message = (
                        f"{sdk_titles[repository_id]} {tag}\n\n"
                        f"Core promotion: {core_tag}\n"
                        f"Promotion evidence SHA-256: {promotion_sha256}"
                    )
                    if message != expected_message:
                        raise ObservationError("public_tag_message_mismatch")
                release = self._validate_release(
                    release_payload,
                    tag,
                    expected_assets=expected_assets,
                    adoption_required=adoption_required,
                    expected_name=(
                        f"Latchway {tag}" if repository_id == "core" else None
                    ),
                    expected_body=(
                        f"Immutable Latchway product release {tag}.\n\n"
                        f"Candidate commit: {coordinate['commit']}\n"
                        f"Promotion evidence SHA-256: {promotion_sha256}"
                        if repository_id == "core"
                        else None
                    ),
                )
            else:
                # First close the immutable asset set so that the iOS, Android,
                # and React Native intent digest can be derived from the exact
                # release metadata rather than accepted as an unbound string.
                release = self._validate_release(
                    release_payload,
                    tag,
                    expected_assets=expected_assets,
                    adoption_required=adoption_required,
                    single_adoption_per_key=True,
                )
                expected_message, expected_name, expected_body = (
                    self._single_maintainer_release_contract(
                        repository_id, coordinate, release, message
                    )
                )
                if message != expected_message:
                    raise ObservationError("public_tag_message_mismatch")
                release = self._validate_release(
                    release_payload,
                    tag,
                    expected_assets=expected_assets,
                    adoption_required=adoption_required,
                    single_adoption_per_key=True,
                    expected_name=expected_name,
                    expected_body=expected_body,
                )
            combined = canonical_json({"ref": ref, "tag": tag_object})
            observation = f"publication.annotated-tag.{repository_id}"
            self.emit(
                observation,
                combined,
                started=min(ref_started, tag_started),
                finished=max(ref_finished, tag_finished),
                version="github-cli-v2",
                invocation=("gh", "api", repository, "annotated-tag", tag),
            )
            release_attestation, attestation_started, attestation_finished = (
                self._release_attestation_from_authority(
                    repository_id,
                    repository,
                    tag,
                    ref["object"]["sha"],
                    release,
                )
            )
            retained_release_proof = canonical_json(
                {
                    "schema_version": 1,
                    "kind": "latchway_immutable_github_release_proof",
                    "repository": repository,
                    "tag": tag,
                    "release": release,
                    # Preserve the canonical validated signed bundle projection,
                    # excluding nondeterministic CLI transport/diagnostic fields.
                    "release_attestation": {
                        "sha256": hashlib.sha256(release_attestation).hexdigest(),
                        "content_base64": base64.b64encode(release_attestation).decode(
                            "ascii"
                        ),
                    },
                }
            )
            observation = f"publication.github-release.{repository_id}"
            self.emit(
                observation,
                retained_release_proof,
                started=min(release_started, attestation_started),
                finished=max(release_finished, attestation_finished),
                version="github-cli-v2",
                invocation=("gh", "release", "verify", tag, "--repo", repository),
            )

    def _single_maintainer_release_contract(
        self,
        repository_id: str,
        coordinate: Mapping[str, str],
        release: Mapping[str, Any],
        observed_message: Any,
    ) -> tuple[str, str, str]:
        if getattr(self, "release_profile", None) != EVIDENCE.SINGLE_MAINTAINER_PROFILE:
            raise ObservationError("release_profile_invalid")
        tag = coordinate["tag"]
        version = coordinate["version"]
        if repository_id == "core":
            image = self.identity["oci_image_digest"]
            message = "\n".join(
                (
                    f"Latchway {tag}",
                    "",
                    "Release profile: single_maintainer_v1",
                    f"Candidate commit: {coordinate['commit']}",
                    f"Image: {image}",
                )
            )
            body = "\n".join(
                (
                    f"Latchway {tag} core release.",
                    "",
                    "Release profile: single_maintainer_v1",
                    "Profile status: incomplete until every required public package and registry check passes.",
                    "Authenticated profile-wide publication readiness is not claimed by this core-only record.",
                    f"Candidate commit: {coordinate['commit']}",
                    f"Image: {image}",
                    "Required deployment evidence: Docker Compose and Google Cloud Run passed for this exact image.",
                    "",
                    "Deferred evidence remains unverified. This release is not release-qualified, fully evidence-gated, or independently reviewed.",
                )
            )
            return message, f"Latchway {tag} — single_maintainer_v1", body
        if repository_id == "javascript":
            tag_prefix = (
                "Latchway JavaScript SDKs v1.0.0\n\n"
                "Release profile: single_maintainer_v1\n"
                "Assurance: deferred; not release-qualified or independently reviewed\n"
            )
            body_prefix = "\n".join(
                (
                    "Published with the `single_maintainer_v1` profile.",
                    "",
                    "The exact public Latchway core v1.0.0 release, including Docker Compose and Google Cloud Run evidence, was verified before this transaction began.",
                    "npm archives are accepted only with byte-identical registry data, registry signatures, and provenance bound to this repository, workflow, source commit, and main ref.",
                    "External platform/device/provider evidence and independent human review remain deferred.",
                    "This release is not `release_qualified`, fully evidence-gated, or independently reviewed.",
                    "",
                )
            ) + "\n"
            source = (
                observed_message
                if isinstance(observed_message, str)
                else release.get("body")
            )
            prefix = tag_prefix if isinstance(observed_message, str) else body_prefix
            match = re.fullmatch(
                re.escape(
                    prefix
                    + "Transaction owner: https://github.com/Latchway/latchway-js/actions/runs/"
                )
                + r"([1-9][0-9]{0,15})\nTransaction ID: ([0-9a-f]{64})",
                source if isinstance(source, str) else "",
            )
            if match is None or int(match.group(1)) > 9_007_199_254_740_991:
                raise ObservationError("public_tag_message_mismatch")
            run_id = int(match.group(1))
            transaction_id = hashlib.sha256(
                "\0".join(
                    (
                        "Latchway/latchway-js",
                        SINGLE_MAINTAINER_RELEASE_WORKFLOW,
                        str(run_id),
                        coordinate["commit"],
                        tag,
                    )
                ).encode("utf-8")
            ).hexdigest()
            if match.group(2) != transaction_id:
                raise ObservationError("public_tag_message_mismatch")
            owner_url = (
                "https://github.com/Latchway/latchway-js/actions/runs/"
                f"{run_id}"
            )
            message = "\n".join(
                (
                    "Latchway JavaScript SDKs v1.0.0",
                    "",
                    "Release profile: single_maintainer_v1",
                    "Assurance: deferred; not release-qualified or independently reviewed",
                    f"Transaction owner: {owner_url}",
                    f"Transaction ID: {transaction_id}",
                )
            )
            body = (
                body_prefix
                + f"Transaction owner: {owner_url}\n"
                + f"Transaction ID: {transaction_id}"
            )
            return (
                message,
                f"Latchway JavaScript SDKs {version} — single-maintainer v1",
                body,
            )
        sdk = {
            "ios": "iOS",
            "android": "Android",
            "react_native": "React Native",
        }.get(repository_id)
        if sdk is None:
            raise ObservationError("github_release_repository_invalid")
        intent_digest = self._release_asset_sha256(
            release, "latchway-single-maintainer-v1-intent.json"
        )
        message = "\n".join(
            (
                f"Latchway {sdk} SDK {tag}",
                "",
                "Release profile: single_maintainer_v1",
                "Assurance: deferred; not release-qualified or independently reviewed",
                f"Maintainer intent SHA-256: {intent_digest}",
            )
        )
        if repository_id == "android":
            body = "\n".join(
                (
                    "Published with the `single_maintainer_v1` profile.",
                    "",
                    "The Maven Central bytes, OpenPGP signatures, deterministic source artifacts, pinned-core conformance, and GitHub provenance in this release were verified by automation. Independent human review and external platform/device/provider evidence are deferred. Docker Compose and GCP Cloud Run evidence remain required by the global v1 profile.",
                    "",
                    "This release is not `release_qualified`, fully evidence-gated, or independently reviewed.",
                )
            )
        else:
            body = (
                "Published with the `single_maintainer_v1` profile. External "
                "platform/device/provider evidence and independent human review "
                "are deferred. This release is not `release_qualified`, fully "
                "evidence-gated, or independently reviewed.\n"
            )
        return message, f"Latchway {sdk} SDK {version} — single-maintainer v1", body

    @staticmethod
    def _release_asset_sha256(release: Mapping[str, Any], name: str) -> str:
        assets = release.get("assets")
        matches = (
            [
                item
                for item in assets
                if isinstance(item, dict) and item.get("name") == name
            ]
            if isinstance(assets, list)
            else []
        )
        digest = matches[0].get("digest") if len(matches) == 1 else None
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise ObservationError("github_release_asset_set_invalid")
        return digest.removeprefix("sha256:")

    @staticmethod
    def _validate_tag_ref(payload: bytes, tag: str) -> dict[str, Any]:
        value = load_output(payload, "public_tag_ref_invalid")
        if (
            not isinstance(value, dict)
            or value.get("ref") != f"refs/tags/{tag}"
            or nested(value, "object", "type") != "tag"
            or not valid_commit(nested(value, "object", "sha"))
        ):
            raise ObservationError("public_tag_not_annotated")
        return value

    @staticmethod
    def _validate_tag_object(
        payload: bytes, tag: str, commit: str
    ) -> dict[str, Any]:
        value = load_output(payload, "public_tag_object_invalid")
        if (
            not isinstance(value, dict)
            or value.get("tag") != tag
            or nested(value, "object", "type") != "commit"
            or nested(value, "object", "sha") != commit
        ):
            raise ObservationError("public_tag_target_mismatch")
        return value

    @staticmethod
    def _expected_release_assets(
        repository_id: str,
        version: str,
        release_profile: str | None = None,
    ) -> tuple[set[str], frozenset[str]]:
        if release_profile == EVIDENCE.SINGLE_MAINTAINER_PROFILE:
            if repository_id == "core":
                return {
                    "SHA256SUMS",
                    "cloud_run.attestation.json",
                    "cloud_run.tar.gz",
                    "compose.attestation.json",
                    "compose.tar.gz",
                    "latchway-candidate.attestation.sigstore.json",
                    "latchway-candidate.json",
                    "latchway-contract.tar.gz",
                    "latchway-linux-amd64-license.json",
                    "latchway-linux-amd64-vulnerability.json",
                    "latchway-linux-amd64.spdx.json",
                    "latchway-linux-arm64-license.json",
                    "latchway-linux-arm64-vulnerability.json",
                    "latchway-linux-arm64.spdx.json",
                    "latchway-single-maintainer-v1.json",
                }, frozenset()
            if repository_id == "javascript":
                fixed = {
                    *(
                        f"latchway-{package_id}-{version}.tgz"
                        for package_id, _ in JAVASCRIPT_NPM_PACKAGES
                    ),
                    f"docs-bundle-{version}.tar.gz",
                    "SHA256SUMS",
                    "build-reproducibility.json",
                    "contract-evidence.json",
                    "core-release-gate.json",
                    "dependency-vulnerability-scan.json",
                    "latchway-single-maintainer-v1-intent.json",
                    "package-evidence.json",
                    "post-publish-evidence.json",
                    "release-candidate-evidence.json",
                    "npm-registry-evidence-manifest.json",
                    "single-maintainer-npm-adoption.json",
                }
                for package_id, _ in JAVASCRIPT_NPM_PACKAGES:
                    fixed.update(
                        {
                            f"npm-{package_id}-registry-version.json",
                            f"npm-{package_id}-registry-view.json",
                            f"npm-{package_id}-attestations.json",
                            f"npm-{package_id}-audit-signatures.json",
                        }
                    )
                if len(fixed) != 32:
                    raise ObservationError("github_release_asset_set_invalid")
                return fixed, frozenset()
            if repository_id == "react_native":
                return {
                    f"latchway-react-native-{version}.tgz",
                    f"latchway-react-native-{version}.tgz.sha256",
                    f"docs-bundle-{version}.tar.gz",
                    "package-evidence.json",
                    "build-reproducibility.json",
                    "latchway-single-maintainer-v1-intent.json",
                    "npm-registry-version.json",
                    "npm-registry-view.json",
                    "npm-attestations.json",
                    "npm-audit-signatures.json",
                    "npm-registry-evidence-manifest.json",
                    "post-publish-evidence.json",
                }, frozenset({""})
            if repository_id == "ios":
                archive = f"latchway-ios-sdk-{version}.tar.gz"
                return {
                    "SHA256SUMS",
                    archive,
                    f"{archive}.sha256",
                    f"docs-bundle-{version}.tar.gz",
                    "cocoapods-published-podspec.json",
                    "cocoapods-reviewed-podspec.json",
                    "cocoapods-release-evidence.json",
                    "dependency-vulnerability-scan.json",
                    "ios-registry-candidate.json",
                    "latchway-single-maintainer-v1-intent.json",
                }, frozenset()
            if repository_id == "android":
                return {
                    f"latchway-android-{version}-maven-repository.zip",
                    f"latchway-android-{version}-central-portal.zip",
                    f"docs-bundle-{version}.tar.gz",
                    "SHA256SUMS",
                    "android-dependency-vulnerability-scan.json",
                    "github-release-tag-binding.json",
                    "latchway-maven-signing-public-key.asc",
                    "latchway-single-maintainer-v1-intent.json",
                    "maven-central-upload-intent.json",
                    "maven-central-deployment.json",
                    "maven-central-deployment-status.json",
                    "maven-central-release-evidence.json",
                    "pinned-core-conformance.tar.gz",
                    "single-maintainer-release-evidence.json",
                }, frozenset()
            raise ObservationError("github_release_repository_invalid")
        if release_profile is not None:
            raise ObservationError("release_profile_invalid")
        if repository_id == "core":
            return {
                "latchway-cross-repository-promotion.json",
                "latchway-cross-repository-promotion.attestation.sigstore.json",
                "latchway-candidate.json",
                "latchway-candidate.attestation.sigstore.json",
                "latchway-contract.tar.gz",
                "latchway-linux-amd64.spdx.json",
                "latchway-linux-arm64.spdx.json",
                "latchway-linux-amd64-vulnerability.json",
                "latchway-linux-arm64-vulnerability.json",
                "latchway-linux-amd64-license.json",
                "latchway-linux-arm64-license.json",
                "security-summary.json",
                "security-summary.attestation.sigstore.json",
                "oci-alias-promotion.json",
            }, frozenset()
        if repository_id == "javascript":
            fixed = {
                *(f"latchway-{package_id}-{version}.tgz" for package_id, _ in JAVASCRIPT_NPM_PACKAGES),
                f"docs-bundle-{version}.tar.gz",
                "SHA256SUMS",
                "build-reproducibility.json",
                "contract-evidence.json",
                "dependency-vulnerability-scan.json",
                "package-evidence.json",
                "post-publish-evidence.json",
                "publish-input-evidence.json",
                "release-candidate-evidence.json",
                "tag-evidence.json",
                "npm-registry-evidence-manifest.json",
            }
            for package_id, _ in JAVASCRIPT_NPM_PACKAGES:
                fixed.update(
                    {
                        f"npm-{package_id}-registry-version.json",
                        f"npm-{package_id}-registry-view.json",
                        f"npm-{package_id}-attestations.json",
                        f"npm-{package_id}-audit-signatures.json",
                    }
                )
            if len(fixed) != 31:
                raise ObservationError("github_release_asset_set_invalid")
            return fixed, frozenset(package_id for package_id, _ in JAVASCRIPT_NPM_PACKAGES)
        if repository_id == "react_native":
            return {
                f"latchway-react-native-{version}.tgz",
                f"latchway-react-native-{version}.tgz.sha256",
                f"docs-bundle-{version}.tar.gz",
                "package-evidence.json",
                "build-reproducibility.json",
                "published-dependency-evidence.json",
                "npm-registry-version.json",
                "npm-registry-view.json",
                "npm-attestations.json",
                "npm-audit-signatures.json",
                "npm-registry-evidence-manifest.json",
                "post-publish-evidence.json",
            }, frozenset({""})
        if repository_id == "ios":
            archive = f"latchway-ios-sdk-{version}.tar.gz"
            return {
                archive,
                f"{archive}.sha256",
                f"docs-bundle-{version}.tar.gz",
                "cocoapods-published-podspec.json",
                "cocoapods-reviewed-podspec.json",
                "cocoapods-release-evidence.json",
                "cocoapods-release-evidence.SHA256SUMS",
            }, frozenset()
        if repository_id == "android":
            return {
                f"latchway-android-{version}-maven-repository.zip",
                f"latchway-android-{version}-central-portal.zip",
                f"docs-bundle-{version}.tar.gz",
                "SHA256SUMS",
                "github-release-tag-binding.json",
                "latchway-maven-signing-public-key.asc",
                "maven-central-upload-intent.json",
                "maven-central-deployment.json",
                "maven-central-deployment-status.json",
                "maven-central-release-evidence.json",
            }, frozenset()
        raise ObservationError("github_release_repository_invalid")

    @staticmethod
    def _validate_release(
        payload: bytes,
        tag: str,
        *,
        expected_assets: set[str] | None = None,
        adoption_required: frozenset[str] = frozenset(),
        expected_name: str | None = None,
        expected_body: str | None = None,
        single_adoption_per_key: bool = False,
    ) -> dict[str, Any]:
        value = load_output(payload, "github_release_invalid")
        if (
            not isinstance(value, dict)
            or value.get("tag_name") != tag
            or value.get("draft") is not False
            or value.get("prerelease") is not False
            or value.get("immutable") is not True
            or not isinstance(value.get("id"), int)
            or isinstance(value.get("id"), bool)
            or value["id"] < 1
            or (expected_name is not None and value.get("name") != expected_name)
            or (expected_body is not None and value.get("body") != expected_body)
        ):
            raise ObservationError("github_release_invalid")
        if expected_assets is not None:
            assets = value.get("assets")
            if not isinstance(assets, list):
                raise ObservationError("github_release_asset_set_invalid")
            names: set[str] = set()
            adoptions: dict[str, set[str]] = {}
            for asset in assets:
                name = asset.get("name") if isinstance(asset, dict) else None
                digest = asset.get("digest") if isinstance(asset, dict) else None
                size = asset.get("size") if isinstance(asset, dict) else None
                identifier = asset.get("id") if isinstance(asset, dict) else None
                if (
                    not isinstance(name, str)
                    or name in names
                    or not isinstance(digest, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                    or not isinstance(size, int)
                    or isinstance(size, bool)
                    or not 1 <= size <= EVIDENCE.MAXIMUM_RAW_BYTES
                    or not isinstance(identifier, int)
                    or isinstance(identifier, bool)
                    or identifier < 1
                ):
                    raise ObservationError("github_release_asset_set_invalid")
                names.add(name)
                package_adoption = JAVASCRIPT_NPM_ADOPTION_ASSET.fullmatch(name)
                if package_adoption is not None:
                    adoptions.setdefault(package_adoption.group(1), set()).add(name)
                elif NPM_ADOPTION_ASSET.fullmatch(name):
                    adoptions.setdefault("", set()).add(name)
                elif name not in expected_assets:
                    raise ObservationError("github_release_asset_set_invalid")
            if (
                not expected_assets.issubset(names)
                or set(adoptions) != set(adoption_required)
                or any(not values for values in adoptions.values())
                or (
                    single_adoption_per_key
                    and any(len(values) != 1 for values in adoptions.values())
                )
            ):
                raise ObservationError("github_release_asset_set_invalid")
        return value

    def _release_attestation_from_authority(
        self,
        repository_id: str,
        repository: str,
        tag: str,
        ref_sha: str,
        release: Mapping[str, Any],
    ) -> tuple[bytes, datetime, datetime]:
        payload, started, finished = self._github_authority_file(
            f"public-tags/{repository_id}/release-attestation.json",
            maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
        )
        try:
            normalized = RELEASE_ATTESTATION.validate_bytes(
                payload,
                repository=repository,
                tag=tag,
                ref_sha=ref_sha,
                release=release,
            )
        except RELEASE_ATTESTATION.AttestationError:
            raise ObservationError("github_release_attestation_invalid") from None
        return canonical_json(normalized), started, finished

    def observe_public_registries(self) -> None:
        if self.release_profile is None:
            self._observe_documentation_production()
        image = self.identity["oci_image_digest"]
        cosign_payload, oci_started, oci_finished = self._github_authority_file(
            "public-registries/oci/cosign.json",
            maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
        )
        self._validate_cosign(cosign_payload, image, "registry_oci_invalid")
        core = self.identity["repositories"]["core"]
        references: dict[str, dict[str, str]] = {}
        for tag in self._oci_release_tags(core["version"]):
            reference = f"ghcr.io/latchway/latchway:{tag}"
            raw, started, finished = self._github_authority_file(
                f"public-registries/oci/index-{tag}.json",
                maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
            )
            self._validate_index(
                raw,
                self.candidate["image"]["index_digest"],
                self.candidate["image"]["platforms"],
            )
            references[tag] = {
                "reference": reference,
                "digest": self.candidate["image"]["index_digest"],
            }
            if started < oci_started:
                oci_started = started
            if finished > oci_finished:
                oci_finished = finished
        children: dict[str, dict[str, Any]] = {}
        for architecture in ("amd64", "arm64"):
            digest = self.candidate["image"]["platforms"][f"linux/{architecture}"]
            payload, started, finished = self._github_authority_file(
                f"public-registries/oci/child-{architecture}.json",
                maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
            )
            children[f"linux/{architecture}"] = self._validate_public_child_inspection(
                payload,
                architecture=architecture,
                reference=f"ghcr.io/latchway/latchway@{digest}",
                commit=self.identity["core_commit"],
                version=core["version"],
            )
            if started < oci_started:
                oci_started = started
            if finished > oci_finished:
                oci_finished = finished
        oci_proof = {
            "schema_version": 1,
            "registry": "ghcr",
            "repository": "ghcr.io/latchway/latchway",
            "version": core["version"],
            "source_commit": self.identity["core_commit"],
            "index_digest": self.candidate["image"]["index_digest"],
            "immutable_version_reference": f"ghcr.io/latchway/latchway:{core['version']}",
            "moving_aliases": list(self._oci_release_tags(core["version"])[1:]),
            "references": references,
            "anonymous_platform_pulls": children,
            "signature_verification": load_output(
                cosign_payload, "registry_oci_invalid"
            ),
        }
        self.emit(
            "registry.oci",
            canonical_json(oci_proof),
            started=oci_started,
            finished=oci_finished,
            version="github-authority-v1",
            invocation=("github-authority", "verify-public-oci"),
        )
        javascript = self.identity["repositories"]["javascript"]
        self._observe_javascript_npm_set(javascript)
        react_native = self.identity["repositories"]["react_native"]
        self._observe_npm_bytes(
            "registry.npm.react-native",
            "@latchway/react-native",
            "react_native",
            react_native,
        )
        ios = self.identity["repositories"]["ios"]
        self._observe_swift_registry(ios)
        _, ios_assets = self._release_asset_set("ios")
        ios_archive_name = f"latchway-ios-sdk-{ios['version']}.tar.gz"
        ios_archive = ios_assets[ios_archive_name]["bytes"]
        ios_asset = ios_assets[ios_archive_name]["metadata"]
        ios_checksum = ios_assets[f"{ios_archive_name}.sha256"]["bytes"]
        self._validate_exact_checksum_file(
            ios_checksum, {ios_archive_name: ios_archive}
        )
        ios_archive_path = Path(tempfile.mkdtemp(prefix="latchway-ios-reviewed-")) / ios_archive_name
        ios_archive_path.write_bytes(ios_archive)
        ios_attestation = self._verify_release_asset_attestation(
            ios_archive_path, "ios", ios
        )
        ios_source_attestations = {ios_archive_name: ios_attestation}
        expected_ios_attestations = expected_source_attested_release_assets(
            "ios",
            ios["version"],
            ios_assets,
            getattr(self, "release_profile", None),
        )
        for name in sorted(expected_ios_attestations - {ios_archive_name}):
            path = ios_archive_path.parent / name
            path.write_bytes(ios_assets[name]["bytes"])
            ios_source_attestations[name] = self._verify_release_asset_attestation(
                path, "ios", ios
            )
        if set(ios_source_attestations) != expected_ios_attestations:
            raise ObservationError("release_asset_attestation_set_invalid")
        if getattr(self, "release_profile", None) is None:
            self._validate_exact_checksum_file(
                ios_assets["cocoapods-release-evidence.SHA256SUMS"]["bytes"],
                {
                    name: ios_assets[name]["bytes"]
                    for name in (
                        "cocoapods-published-podspec.json",
                        "cocoapods-reviewed-podspec.json",
                        "cocoapods-release-evidence.json",
                    )
                },
            )
        else:
            self._validate_exact_checksum_file(
                ios_assets["SHA256SUMS"]["bytes"],
                {
                    name: ios_assets[name]["bytes"]
                    for name in ios_assets
                    if name != "SHA256SUMS"
                },
            )
        published_spec = ios_assets["cocoapods-published-podspec.json"]["bytes"]
        reviewed_spec = ios_assets["cocoapods-reviewed-podspec.json"]["bytes"]
        published_spec_value = self._validate_cocoapods_spec(published_spec, ios)
        reviewed_spec_value = self._validate_cocoapods_spec(reviewed_spec, ios)
        if published_spec_value != reviewed_spec_value:
            raise ObservationError("registry_cocoapods_spec_mismatch")
        cocoa_command = (
            str(self.repositories["ios"] / "scripts/verify-cocoapods-release.sh"),
            ios["version"],
        )
        cocoa_payload, cocoa_started, cocoa_finished = self._execute_command(
            cocoa_command,
            cwd=self.repositories["ios"],
            environment={"LATCHWAY_COCOAPODS_EXPECTED_ARCHIVE": str(ios_archive_path)},
        )
        self._validate_cocoapods_proof(cocoa_payload, ios, ios_asset)
        live_cocoa = load_output(cocoa_payload, "registry_cocoapods_proof_invalid")
        cocoa = load_output(
            ios_assets["cocoapods-release-evidence.json"]["bytes"],
            "registry_cocoapods_proof_invalid",
        )
        self._validate_cocoapods_proof(canonical_json(cocoa), ios, ios_asset)
        if live_cocoa != cocoa:
            raise ObservationError("registry_cocoapods_retained_proof_changed")
        if (
            cocoa.get("published_spec_sha256")
            != hashlib.sha256(published_spec).hexdigest()
            or cocoa.get("reviewed_spec_sha256")
            != hashlib.sha256(reviewed_spec).hexdigest()
        ):
            raise ObservationError("registry_cocoapods_spec_mismatch")
        live_podspec = self._download_https(
            cocoa.get("registry_url"),
            allowed_hosts={"cdn.cocoapods.org"},
            maximum=2 * 1024 * 1024,
        )
        if live_podspec != published_spec:
            raise ObservationError("registry_cocoapods_live_bytes_changed")
        cocoa["release_asset_attestation_verification"] = ios_attestation
        cocoa["release_asset_source_attestations"] = ios_source_attestations
        cocoa["immutable_release_asset_verifications"] = {
            name: ios_assets[name]["immutable_release_verification"]
            for name in sorted(ios_assets)
        }
        cocoa["retained_release_assets"] = {
            name: self._retained_asset_envelope(name, ios_assets[name])
            for name in sorted(ios_assets)
        }
        cocoa["independent_live_verification"] = live_cocoa
        cocoa["compatibility"] = self._derive_ios_compatibility()
        self.emit(
            "registry.cocoapods",
            canonical_json(cocoa),
            started=cocoa_started,
            finished=cocoa_finished,
            version="system",
            invocation=cocoa_command,
            cwd=self.repositories["ios"],
        )
        android = self.identity["repositories"]["android"]
        _, android_assets = self._release_asset_set("android")
        android_archive_name = f"latchway-android-{android['version']}-maven-repository.zip"
        android_archive = android_assets[android_archive_name]["bytes"]
        android_checksum = android_assets["SHA256SUMS"]["bytes"]
        android_public_key = android_assets[
            "latchway-maven-signing-public-key.asc"
        ]["bytes"]
        android_public_key_asset = android_assets[
            "latchway-maven-signing-public-key.asc"
        ]["metadata"]
        self._validate_exact_checksum_file(
            android_checksum,
            {
                name: android_assets[name]["bytes"]
                for name in android_assets
                if name != "SHA256SUMS"
            },
        )
        android_root = Path(tempfile.mkdtemp(prefix="latchway-android-reviewed-"))
        android_archive_path = android_root / android_archive_name
        android_archive_path.write_bytes(android_archive)
        android_attestation = self._verify_release_asset_attestation(
            android_archive_path, "android", android
        )
        android_source_attestations = {android_archive_name: android_attestation}
        for name in sorted(android_assets):
            if name == android_archive_name:
                continue
            path = android_root / name
            path.write_bytes(android_assets[name]["bytes"])
            android_source_attestations[name] = self._verify_release_asset_attestation(
                path, "android", android
            )
        if set(android_source_attestations) != expected_source_attested_release_assets(
            "android",
            android["version"],
            android_assets,
            getattr(self, "release_profile", None),
        ):
            raise ObservationError("release_asset_attestation_set_invalid")
        self._extract_reviewed_zip(android_archive, android_root)
        android_public_key_path = android_root / "latchway-maven-signing-public-key.asc"
        android_public_key_path.write_bytes(android_public_key)
        signing_fingerprint = os.environ.get("LATCHWAY_MAVEN_SIGNING_FINGERPRINT", "")
        if re.fullmatch(r"[0-9A-F]{40}", signing_fingerprint) is None:
            raise ObservationError("maven_signing_fingerprint_invalid")
        self._validate_android_release_documents(android_assets, android)
        maven_command = (
            str(self.repositories["android"] / "scripts/verify-central-release.sh"),
            android["version"],
        )
        maven_payload, maven_started, maven_finished = self._execute_command(
            maven_command,
            cwd=self.repositories["android"],
            environment={
                "LATCHWAY_RELEASE_VERSION": android["version"],
                "LATCHWAY_CENTRAL_EXPECTED_REPOSITORY": str(android_root),
                "LATCHWAY_CENTRAL_SIGNING_FINGERPRINT": signing_fingerprint,
                "LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY": str(android_public_key_path),
                "LATCHWAY_CENTRAL_UPLOAD_INTENT": str(
                    android_root / "maven-central-upload-intent.json"
                ),
                "LATCHWAY_CENTRAL_DEPLOYMENT_RECORD": str(
                    android_root / "maven-central-deployment.json"
                ),
                "LATCHWAY_CENTRAL_DEPLOYMENT_STATUS": str(
                    android_root / "maven-central-deployment-status.json"
                ),
                "LATCHWAY_CENTRAL_REQUIRE_DEPLOYMENT_EVIDENCE": "true",
            },
        )
        self._validate_maven_proof(
            maven_payload,
            android,
            signing_fingerprint,
            str(android_public_key_asset["digest"]).removeprefix("sha256:"),
        )
        live_maven = load_output(maven_payload, "registry_maven_proof_invalid")
        maven = load_output(
            android_assets["maven-central-release-evidence.json"]["bytes"],
            "registry_maven_proof_invalid",
        )
        self._validate_maven_proof(
            canonical_json(maven),
            android,
            signing_fingerprint,
            str(android_public_key_asset["digest"]).removeprefix("sha256:"),
        )
        if live_maven != maven:
            raise ObservationError("registry_maven_retained_proof_changed")
        maven["release_asset_attestation_verification"] = android_attestation
        maven["release_asset_source_attestations"] = android_source_attestations
        maven["immutable_release_asset_verifications"] = {
            name: android_assets[name]["immutable_release_verification"]
            for name in sorted(android_assets)
        }
        maven["retained_release_assets"] = {
            name: self._retained_asset_envelope(name, android_assets[name])
            for name in sorted(android_assets)
        }
        maven["independent_live_verification"] = live_maven
        maven["compatibility"] = self._derive_android_compatibility()
        self.emit(
            "registry.maven-central",
            canonical_json(maven),
            started=maven_started,
            finished=maven_finished,
            version="system",
            invocation=maven_command,
            cwd=self.repositories["android"],
        )

    @staticmethod
    def _validate_public_child_inspection(
        payload: bytes,
        *,
        architecture: str,
        reference: str,
        commit: str,
        version: str,
    ) -> dict[str, Any]:
        value = load_output(payload, "registry_oci_child_invalid")
        item = value[0] if isinstance(value, list) and len(value) == 1 else None
        labels = nested(item, "Config", "Labels") if isinstance(item, dict) else None
        repo_digests = item.get("RepoDigests") if isinstance(item, dict) else None
        layers = nested(item, "RootFS", "Layers") if isinstance(item, dict) else None
        image_id = item.get("Id") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or item.get("Os") != "linux"
            or item.get("Architecture") != architecture
            or not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.source")
            != "https://github.com/Latchway/latchway"
            or labels.get("org.opencontainers.image.revision") != commit
            or labels.get("org.opencontainers.image.version") != version
            or not isinstance(repo_digests, list)
            or reference not in repo_digests
            or not isinstance(layers, list)
            or not layers
            or any(
                not isinstance(layer, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", layer) is None
                for layer in layers
            )
            or not isinstance(image_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        ):
            raise ObservationError("registry_oci_child_invalid")
        return {
            "reference": reference,
            "image_id": image_id,
            "rootfs_layers": layers,
        }

    def _observe_documentation_production(self) -> None:
        root = "public-registries/documentation"
        limits = {
            MINTLIFY_PROOF.EVIDENCE_FILE: 8 * 1024 * 1024,
            MINTLIFY_PROOF.CHECKSUM_FILE: 512,
            MINTLIFY_PROOF.ATTESTATION_FILE: 2 * 1024 * 1024,
            "run.json": EVIDENCE.MAXIMUM_RESULT_BYTES,
            "workflow.json": EVIDENCE.MAXIMUM_RESULT_BYTES,
            "artifact.json": EVIDENCE.MAXIMUM_RESULT_BYTES,
            "attestation-verification.json": EVIDENCE.MAXIMUM_RESULT_BYTES,
        }
        payloads: dict[str, bytes] = {}
        intervals: list[tuple[datetime, datetime]] = []
        for name in sorted(MINTLIFY_PROOF.RETAINED_FILES):
            payload, started, finished = self._github_authority_file(
                f"{root}/{name}", maximum=limits[name]
            )
            payloads[name] = payload
            intervals.append((started, finished))
        try:
            evidence = MINTLIFY_PROOF.load_json(
                payloads[MINTLIFY_PROOF.EVIDENCE_FILE],
                "mintlify_evidence_json_invalid",
            )
            workflow = evidence.get("workflow")
            if not isinstance(workflow, dict):
                raise MINTLIFY_PROOF.ProofError("mintlify_workflow_identity_invalid")
            run_id = MINTLIFY_PROOF.positive_integer(
                workflow.get("run_id"), "mintlify_workflow_identity_invalid"
            )
            run_attempt = MINTLIFY_PROOF.positive_integer(
                workflow.get("run_attempt"), "mintlify_workflow_identity_invalid"
            )
            proof = MINTLIFY_PROOF.build_proof(
                documentation=self.documentation,
                evidence_payload=payloads[MINTLIFY_PROOF.EVIDENCE_FILE],
                checksum_payload=payloads[MINTLIFY_PROOF.CHECKSUM_FILE],
                attestation_bundle_payload=payloads[MINTLIFY_PROOF.ATTESTATION_FILE],
                run_payload=payloads["run.json"],
                workflow_payload=payloads["workflow.json"],
                artifact_payload=payloads["artifact.json"],
                attestation_verification_payload=payloads[
                    "attestation-verification.json"
                ],
                expected_run_id=run_id,
                expected_run_attempt=run_attempt,
                now=self.now,
            )
        except MINTLIFY_PROOF.ProofError as error:
            raise ObservationError(str(error)) from None
        self.emit(
            "registry.documentation-production",
            canonical_json(proof),
            started=min(started for started, _ in intervals),
            finished=max(finished for _, finished in intervals),
            version="core-v1",
            invocation=(
                "latchway-mintlify-production-validator",
                "verify",
                MINTLIFY_PROOF.EVIDENCE_FILE,
            ),
            retained_inputs=payloads,
            retained_input_kind="mintlify_production_evidence",
        )

    @staticmethod
    def _oci_release_tags(version: str) -> tuple[str, ...]:
        match = re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
            version,
        )
        if match is None:
            raise ObservationError("registry_oci_version_invalid")
        if "-" in version:
            return (version,)
        major, minor, _ = match.groups()
        return version, f"{major}.{minor}", major, "latest"

    def _verify_release_asset_attestation(
        self, path: Path, repository_id: str, coordinate: Mapping[str, str]
    ) -> Any:
        if repository_id not in REPOSITORY_NAMES or (
            coordinate != self.identity["repositories"][repository_id]
        ):
            raise ObservationError("release_asset_attestation_invalid")
        payload, _, _ = self._github_authority_file(
            f"public-registries/{repository_id}/attestations/{path.name}.json",
            maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
        )
        value = load_output(payload, "release_asset_attestation_invalid")
        if not isinstance(value, list) or not value:
            raise ObservationError("release_asset_attestation_invalid")
        return value

    def _publication_workflow(self) -> str:
        profile = getattr(self, "release_profile", None)
        if profile is None:
            return STRICT_RELEASE_WORKFLOW
        if profile == EVIDENCE.SINGLE_MAINTAINER_PROFILE:
            return SINGLE_MAINTAINER_RELEASE_WORKFLOW
        raise ObservationError("release_profile_invalid")

    def _publication_event(self) -> str:
        return (
            "workflow_dispatch"
            if self._publication_workflow() == SINGLE_MAINTAINER_RELEASE_WORKFLOW
            else "repository_dispatch"
        )

    def _javascript_aggregate_json_assets(self) -> tuple[str, ...]:
        return (
            SINGLE_MAINTAINER_JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS
            if getattr(self, "release_profile", None)
            == EVIDENCE.SINGLE_MAINTAINER_PROFILE
            else JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS
        )

    def _javascript_aggregate_assets(self) -> tuple[str, ...]:
        return (
            SINGLE_MAINTAINER_JAVASCRIPT_NPM_AGGREGATE_ASSETS
            if getattr(self, "release_profile", None)
            == EVIDENCE.SINGLE_MAINTAINER_PROFILE
            else JAVASCRIPT_NPM_AGGREGATE_ASSETS
        )

    @staticmethod
    def _javascript_npm_evidence_names(package_id: str) -> tuple[str, ...]:
        if package_id not in {item[0] for item in JAVASCRIPT_NPM_PACKAGES}:
            raise ObservationError("registry_npm_package_set_invalid")
        return tuple(
            f"npm-{package_id}-{suffix}.json"
            for suffix in (
                "registry-version",
                "registry-view",
                "attestations",
                "audit-signatures",
            )
        )

    def _verify_javascript_contract_source(
        self, contract_evidence: Any, coordinate: Mapping[str, str]
    ) -> dict[str, Any]:
        javascript_root = self.repositories.get("javascript")
        if (
            not isinstance(javascript_root, Path)
            or not javascript_root.is_absolute()
            or not javascript_root.is_dir()
            or javascript_root.is_symlink()
        ):
            raise ObservationError("registry_npm_contract_source_invalid")
        try:
            lock_payload = EVIDENCE.read_bytes(
                javascript_root / "contract.lock", EVIDENCE.MAXIMUM_RESULT_BYTES
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("registry_npm_contract_source_invalid") from None
        lock = parse_contract_lock_payload(lock_payload)
        fixture_root = javascript_root / "test" / "fixtures" / "contract"
        if (
            not fixture_root.is_dir()
            or fixture_root.is_symlink()
            or any(path.is_symlink() or not path.is_file() for path in fixture_root.iterdir())
        ):
            raise ObservationError("registry_npm_contract_source_invalid")
        fixture_paths = sorted(fixture_root.iterdir(), key=lambda path: path.name)
        if not 1 <= len(fixture_paths) <= 64 or any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", path.name) is None
            for path in fixture_paths
        ):
            raise ObservationError("registry_npm_contract_source_invalid")
        fixtures: list[dict[str, str]] = []
        try:
            for path in fixture_paths:
                payload = EVIDENCE.read_bytes(path, EVIDENCE.MAXIMUM_RESULT_BYTES)
                fixtures.append(
                    {"name": path.name, "sha256": hashlib.sha256(payload).hexdigest()}
                )
        except EVIDENCE.EvidenceError:
            raise ObservationError("registry_npm_contract_source_invalid") from None
        wire = lock.get("wire_protocol")
        if (
            not isinstance(contract_evidence, dict)
            or set(contract_evidence)
            != {
                "schema_version", "contract_version", "core_release",
                "core_commit", "bundle_sha256", "wire_protocol_version",
                "contract_lock_sha256", "fixtures",
            }
            or contract_evidence.get("schema_version") != 1
            or contract_evidence.get("contract_version")
            != self.identity.get("contract_version")
            or contract_evidence.get("contract_version")
            != lock.get("contract_version")
            or contract_evidence.get("core_release") != self.identity.get("core_release")
            or contract_evidence.get("core_release") != lock.get("core_release")
            or contract_evidence.get("core_commit") != lock.get("core_commit")
            or contract_evidence.get("bundle_sha256") != self.identity.get("bundle_sha256")
            or contract_evidence.get("bundle_sha256") != lock.get("bundle_sha256")
            or not isinstance(contract_evidence.get("wire_protocol_version"), int)
            or isinstance(contract_evidence.get("wire_protocol_version"), bool)
            or str(contract_evidence["wire_protocol_version"]) != wire
            or contract_evidence.get("contract_lock_sha256")
            != hashlib.sha256(lock_payload).hexdigest()
            or contract_evidence.get("fixtures") != fixtures
            or coordinate.get("commit")
            != self.identity.get("repositories", {}).get("javascript", {}).get("commit")
        ):
            raise ObservationError("registry_npm_contract_source_invalid")
        return {
            "schema_version": 1,
            "source_repository_commit": coordinate["commit"],
            "contract_version": contract_evidence["contract_version"],
            "core_release": contract_evidence["core_release"],
            "core_commit": contract_evidence["core_commit"],
            "bundle_sha256": contract_evidence["bundle_sha256"],
            "wire_protocol_version": contract_evidence["wire_protocol_version"],
            "contract_lock_sha256": contract_evidence["contract_lock_sha256"],
            "fixture_count": len(fixtures),
            "fixture_set_sha256": hashlib.sha256(canonical_json(fixtures)).hexdigest(),
        }

    def _validate_javascript_npm_aggregate(
        self,
        coordinate: Mapping[str, str],
        release_assets: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        names = [package for _, package in JAVASCRIPT_NPM_PACKAGES]
        version = coordinate["version"]
        documents = {
            name: load_output(
                release_assets[name]["bytes"], "registry_npm_package_set_invalid"
            )
            for name in self._javascript_aggregate_json_assets()
        }
        package_evidence = documents["package-evidence.json"]
        candidate = documents["release-candidate-evidence.json"]
        publish_input = documents.get("publish-input-evidence.json")
        post_publish = documents["post-publish-evidence.json"]
        manifest = documents["npm-registry-evidence-manifest.json"]
        reproducibility = documents["build-reproducibility.json"]
        single_maintainer = (
            getattr(self, "release_profile", None)
            == EVIDENCE.SINGLE_MAINTAINER_PROFILE
        )
        validate_javascript_supporting_evidence(
            documents,
            coordinate,
            require_tag_evidence=not single_maintainer,
        )
        repository_url = "https://github.com/Latchway/latchway-js"
        workflow_path = self._publication_workflow()
        source = {
            "repository": repository_url,
            "commit": coordinate["commit"],
            "workflow": workflow_path,
            "ref": "refs/heads/main",
        }
        gates = [
            "workflow-policy",
            "contract-lock",
            "release-policy",
            "lint",
            "typecheck",
            "clean-build",
            "unit-tests",
            "offline-release-tests",
            "examples",
            "exports",
            "web-browser-and-bundler-conformance",
            "build-reproducibility",
            "package-conformance",
        ]
        package_items = (
            package_evidence.get("packages")
            if isinstance(package_evidence, dict)
            else None
        )
        consumer = package_evidence.get("consumer") if isinstance(package_evidence, dict) else None
        if (
            not isinstance(package_evidence, dict)
            or set(package_evidence)
            != {"schema_version", "kind", "version", "package_count", "publish_order", "packages", "consumer"}
            or package_evidence.get("schema_version") != 2
            or package_evidence.get("kind") != "latchway_npm_package_set_evidence"
            or package_evidence.get("version") != version
            or package_evidence.get("package_count") != 4
            or package_evidence.get("publish_order") != names
            or not isinstance(package_items, list)
            or len(package_items) != 4
            or not isinstance(consumer, dict)
            or set(consumer) != {"package_count", "packages", "node_esm", "typescript", "peer_source"}
            or consumer.get("package_count") != 4
            or consumer.get("node_esm") is not True
            or consumer.get("typescript") is not True
            or consumer.get("peer_source") != "reviewed"
            or not isinstance(consumer.get("packages"), list)
            or len(consumer["packages"]) != 4
            or any(not isinstance(item, dict) or set(item) != {"name", "version"} for item in consumer["packages"])
            or [item["name"] for item in consumer["packages"]] != names
            or any(item["version"] != version for item in consumer["packages"])
        ):
            raise ObservationError("registry_npm_package_set_invalid")
        candidate_gates = candidate.get("gates") if isinstance(candidate, dict) else None
        if (
            not isinstance(candidate, dict)
            or set(candidate)
            != {"schema_version", "package_count", "packages", "version", "source_commit", "worktree_clean", "stable_version", "node", "pnpm", "gates"}
            or candidate.get("schema_version") != 2
            or candidate.get("package_count") != 4
            or candidate.get("packages") != names
            or candidate.get("version") != version
            or candidate.get("source_commit") != coordinate["commit"]
            or candidate.get("worktree_clean") is not True
            or candidate.get("stable_version") is not True
            or candidate.get("node") != "v24.19.0"
            or candidate.get("pnpm") != "10.15.0"
            or not isinstance(candidate_gates, list)
            or [item.get("name") for item in candidate_gates if isinstance(item, dict)] != gates
            or any(
                not isinstance(item, dict)
                or set(item) != {"name", "status", "duration_ms"}
                or item.get("status") != "passed"
                or not isinstance(item.get("duration_ms"), int)
                or isinstance(item.get("duration_ms"), bool)
                or item["duration_ms"] < 0
                for item in candidate_gates
            )
        ):
            raise ObservationError("registry_npm_release_candidate_invalid")
        if single_maintainer and isinstance(package_items, list):
            publish_packages = [
                {
                    key: item.get(key)
                    for key in (
                        "id", "package", "version", "tarball", "bytes",
                        "sha1", "sha256", "sha512", "integrity",
                    )
                }
                for item in package_items
                if isinstance(item, dict)
            ]
            publish_consumer = None
        else:
            publish_packages = (
                publish_input.get("packages")
                if isinstance(publish_input, dict)
                else None
            )
            publish_consumer = (
                publish_input.get("consumer")
                if isinstance(publish_input, dict)
                else None
            )
        if not single_maintainer and (
            not isinstance(publish_input, dict)
            or set(publish_input)
            != {"schema_version", "kind", "version", "source_commit", "release_tag", "package_count", "publish_order", "packages", "verified_job_evidence", "package_evidence", "checksums", "consumer"}
            or publish_input.get("schema_version") != 2
            or publish_input.get("kind") != "latchway_npm_publish_input_evidence"
            or publish_input.get("version") != version
            or publish_input.get("source_commit") != coordinate["commit"]
            or publish_input.get("release_tag") != coordinate["tag"]
            or publish_input.get("package_count") != 4
            or publish_input.get("publish_order") != names
            or publish_input.get("verified_job_evidence") is not True
            or not isinstance(publish_packages, list)
            or len(publish_packages) != 4
            or not isinstance(publish_consumer, dict)
            or set(publish_consumer) != {"package_count", "packages", "node_esm", "typescript", "peer_source"}
            or publish_consumer.get("package_count") != 4
            or publish_consumer.get("node_esm") is not True
            or publish_consumer.get("typescript") is not False
            or publish_consumer.get("peer_source") != "registry"
            or not isinstance(publish_consumer.get("packages"), list)
            or len(publish_consumer["packages"]) != 4
            or any(not isinstance(item, dict) or set(item) != {"name", "version"} for item in publish_consumer["packages"])
            or [item["name"] for item in publish_consumer["packages"]] != names
            or any(item["version"] != version for item in publish_consumer["packages"])
            or not isinstance(publish_input.get("package_evidence"), dict)
            or set(publish_input["package_evidence"]) != {"file", "sha256"}
            or nested(publish_input, "package_evidence", "file") != "package-evidence.json"
            or nested(publish_input, "package_evidence", "sha256")
            != hashlib.sha256(release_assets["package-evidence.json"]["bytes"]).hexdigest()
            or not isinstance(publish_input.get("checksums"), dict)
            or set(publish_input["checksums"]) != {"file", "sha256"}
            or nested(publish_input, "checksums", "file") != "SHA256SUMS"
            or nested(publish_input, "checksums", "sha256")
            != hashlib.sha256(release_assets["SHA256SUMS"]["bytes"]).hexdigest()
        ):
            raise ObservationError("registry_npm_publish_input_invalid")
        manifest_packages = manifest.get("packages") if isinstance(manifest, dict) else None
        if (
            not isinstance(manifest, dict)
            or set(manifest)
            != {"schema_version", "kind", "version", "package_count", "publish_order", "packages"}
            or manifest.get("schema_version") != 2
            or manifest.get("kind")
            != "latchway_npm_registry_package_set_evidence_manifest"
            or manifest.get("version") != version
            or manifest.get("package_count") != 4
            or manifest.get("publish_order") != names
            or not isinstance(manifest_packages, list)
            or len(manifest_packages) != 4
        ):
            raise ObservationError("registry_npm_registry_manifest_invalid")
        post_packages = post_publish.get("packages") if isinstance(post_publish, dict) else None
        reproducibility_files = (
            reproducibility.get("files")
            if isinstance(reproducibility, dict)
            else None
        )
        reproducibility_prefixes = {
            package: ("dist/" if package_id == "client" else f"packages/{package_id}/dist/")
            for package_id, package in JAVASCRIPT_NPM_PACKAGES
        }
        manifest_bytes = release_assets["npm-registry-evidence-manifest.json"]["bytes"]
        if (
            not isinstance(post_publish, dict)
            or set(post_publish)
            != {"schema_version", "kind", "version", "package_count", "publish_order", "source", "release_tag", "registry", "packages", "evidence_manifest"}
            or post_publish.get("schema_version") != 3
            or post_publish.get("kind")
            != "latchway_npm_package_set_publication_evidence"
            or post_publish.get("version") != version
            or post_publish.get("package_count") != 4
            or post_publish.get("publish_order") != names
            or post_publish.get("source") != source
            or post_publish.get("release_tag") != coordinate["tag"]
            or post_publish.get("registry") != "https://registry.npmjs.org/"
            or not isinstance(post_packages, list)
            or len(post_packages) != 4
            or post_publish.get("evidence_manifest")
            != {
                "file": "npm-registry-evidence-manifest.json",
                "bytes": len(manifest_bytes),
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            }
        ):
            raise ObservationError("registry_npm_post_publish_invalid")
        if (
            not isinstance(reproducibility, dict)
            or set(reproducibility) != {"schema_version", "identical", "package_count", "sha256", "files"}
            or reproducibility.get("schema_version") != 1
            or reproducibility.get("identical") is not True
            or reproducibility.get("package_count") != 4
            or re.fullmatch(r"[0-9a-f]{64}", str(reproducibility.get("sha256"))) is None
            or not isinstance(reproducibility_files, list)
            or not reproducibility_files
            or any(
                not isinstance(item, dict)
                or set(item) != {"package", "path", "bytes", "sha256"}
                or item.get("package") not in names
                or not isinstance(item.get("path"), str)
                or not item["path"].startswith(
                    reproducibility_prefixes.get(item.get("package"), "\0")
                )
                or "\\" in item["path"]
                or ".." in item["path"].split("/")
                or not isinstance(item.get("bytes"), int)
                or isinstance(item.get("bytes"), bool)
                or item["bytes"] < 1
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
                for item in reproducibility_files
            )
            or len({item["path"] for item in reproducibility_files})
            != len(reproducibility_files)
            or {item["package"] for item in reproducibility_files} != set(names)
            or [
                (item["package"], item["path"])
                for item in reproducibility_files
            ]
            != sorted(
                (
                    (item["package"], item["path"])
                    for item in reproducibility_files
                ),
                key=lambda item: (names.index(item[0]), item[1]),
            )
        ):
            raise ObservationError("registry_npm_reproducibility_invalid")

        if not isinstance(publish_packages, list) or len(publish_packages) != 4:
            raise ObservationError("registry_npm_publish_input_invalid")

        normalized: list[dict[str, Any]] = []
        for index, (package_id, package) in enumerate(JAVASCRIPT_NPM_PACKAGES):
            item = package_items[index]
            published = publish_packages[index]
            manifest_item = manifest_packages[index]
            post_item = post_packages[index]
            tarball_name = f"latchway-{package_id}-{version}.tgz"
            if (
                not isinstance(item, dict)
                or set(item)
                != {"id", "package", "version", "tarball", "bytes", "sha1", "sha256", "sha512", "integrity", "double_pack_byte_identical", "archive_allowlist_verified", "archive_regular_files_only", "credential_scan", "entries", "unpacked_bytes", "published_peer_dependencies"}
                or item.get("id") != package_id
                or item.get("package") != package
                or item.get("version") != version
                or item.get("tarball") != tarball_name
                or not isinstance(item.get("bytes"), int)
                or isinstance(item.get("bytes"), bool)
                or item["bytes"] < 1
                or re.fullmatch(r"[0-9a-f]{40}", str(item.get("sha1"))) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
                or re.fullmatch(r"[0-9a-f]{128}", str(item.get("sha512"))) is None
                or not valid_sha512_integrity(item.get("integrity"))
                or item.get("double_pack_byte_identical") is not True
                or item.get("archive_allowlist_verified") is not True
                or item.get("archive_regular_files_only") is not True
                or item.get("credential_scan") != "passed"
                or not isinstance(item.get("entries"), list)
                or not item["entries"]
                or item["entries"] != sorted(set(item["entries"]))
                or any(
                    not isinstance(entry, str)
                    or re.fullmatch(
                        r"package/(?:[A-Za-z0-9@._+-]+/)*[A-Za-z0-9@._+-]+",
                        entry,
                    )
                    is None
                    for entry in item["entries"]
                )
                or not isinstance(item.get("unpacked_bytes"), int)
                or isinstance(item.get("unpacked_bytes"), bool)
                or not 1 <= item["unpacked_bytes"] <= 25 * 1024 * 1024
                or not isinstance(item.get("published_peer_dependencies"), dict)
                or any(
                    not isinstance(name, str)
                    or not name
                    or not isinstance(requirement, str)
                    or not requirement
                    for name, requirement in item[
                        "published_peer_dependencies"
                    ].items()
                )
            ):
                raise ObservationError("registry_npm_package_set_invalid")
            tarball = {
                "name": tarball_name,
                "bytes": item["bytes"],
                "sha256": item["sha256"],
                "sha512": item["sha512"],
                "integrity": item["integrity"],
            }
            if (
                not isinstance(published, dict)
                or set(published) != {"id", "package", "version", "tarball", "bytes", "sha1", "sha256", "sha512", "integrity"}
                or published.get("id") != package_id
                or published.get("package") != package
                or published.get("version") != version
                or published.get("tarball") != tarball_name
                or any(published.get(field) != item.get(field) for field in ("bytes", "sha1", "sha256", "sha512", "integrity"))
                or not isinstance(manifest_item, dict)
                or set(manifest_item) != {"id", "package", "version", "tarball", "evidence"}
                or manifest_item.get("id") != package_id
                or manifest_item.get("package") != package
                or manifest_item.get("version") != version
                or manifest_item.get("tarball") != tarball
                or not isinstance(manifest_item.get("evidence"), list)
                or not isinstance(post_item, dict)
                or set(post_item) != {"id", "package", "version", "publication_mode", "tarball", "trusted_publisher", "registry_signature_verification", "clean_consumer", "retained_outputs"}
                or post_item.get("id") != package_id
                or post_item.get("package") != package
                or post_item.get("version") != version
                or post_item.get("publication_mode") != "published"
                or nested(post_item, "tarball", "name") != tarball_name
                or any(nested(post_item, "tarball", field) != tarball[field] for field in ("bytes", "sha256", "sha512", "integrity"))
                or nested(post_item, "tarball", "registry_bytes_sha256") != item["sha256"]
            ):
                raise ObservationError("registry_npm_package_set_invalid")
            evidence_names = set(self._javascript_npm_evidence_names(package_id))
            evidence_by_name = {
                entry.get("name"): entry
                for entry in manifest_item["evidence"]
                if isinstance(entry, dict)
            }
            retained_outputs = post_item.get("retained_outputs")
            if (
                len(evidence_by_name) != 4
                or set(evidence_by_name) != evidence_names
                or not isinstance(retained_outputs, dict)
                or set(retained_outputs) != evidence_names
            ):
                raise ObservationError("registry_npm_registry_manifest_invalid")
            for evidence_name in evidence_names:
                payload = release_assets[evidence_name]["bytes"]
                reference = {
                    "name": evidence_name,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                if evidence_by_name[evidence_name] != reference or retained_outputs[evidence_name] != {
                    "bytes": reference["bytes"],
                    "sha256": reference["sha256"],
                }:
                    raise ObservationError("registry_npm_registry_manifest_invalid")
            normalized.append(
                {
                    "id": package_id,
                    "package": package,
                    "evidence": item,
                    "manifest": manifest_item,
                    "post_publish": post_item,
                }
            )
        checksum_verification = validate_javascript_sha256sums(
            release_assets["SHA256SUMS"]["bytes"], package_items, version
        )
        return {
            "documents": documents,
            "packages": normalized,
            "checksum_verification": checksum_verification,
        }

    def _observe_javascript_npm_set(
        self, coordinate: Mapping[str, str]
    ) -> None:
        _, release_assets = self._release_asset_set("javascript")
        aggregate = self._validate_javascript_npm_aggregate(coordinate, release_assets)
        aggregate_documents = aggregate["documents"]
        contract_source_verification = self._verify_javascript_contract_source(
            aggregate_documents["contract-evidence.json"], coordinate
        )
        reproducibility_verification = (
            verify_javascript_reproducibility_archive_inputs(
                aggregate_documents["build-reproducibility.json"],
                release_assets,
                coordinate["version"],
                aggregate_documents["package-evidence.json"],
                self.repositories["javascript"],
            )
        )
        source_attestations: dict[str, Any] = {}
        attestation_root = Path(
            tempfile.mkdtemp(prefix="latchway-javascript-release-attestations-")
        )
        for name in sorted(release_assets):
            path = attestation_root / name
            path.write_bytes(release_assets[name]["bytes"])
            source_attestations[name] = self._verify_release_asset_attestation(
                path, "javascript", coordinate
            )
        if set(source_attestations) != expected_source_attested_release_assets(
            "javascript",
            coordinate["version"],
            release_assets,
            getattr(self, "release_profile", None),
        ):
            raise ObservationError("release_asset_attestation_set_invalid")
        package_proofs: list[dict[str, Any]] = []
        starts: list[datetime] = []
        for package_item in aggregate["packages"]:
            package_id = package_item["id"]
            package = package_item["package"]
            evidence = package_item["evidence"]
            metadata_payload, started, _ = self._execute_command(
                (
                    "npm", "view", f"{package}@{coordinate['version']}", "--json",
                    "--include-attestations", "--registry=https://registry.npmjs.org/",
                ),
                environment={
                    "NPM_CONFIG_USERCONFIG": os.devnull,
                    "NPM_CONFIG_PROVENANCE": "false",
                },
            )
            starts.append(started)
            self._validate_npm(metadata_payload, package, coordinate)
            metadata = load_output(metadata_payload, "registry_npm_invalid")
            tarball_name = evidence["tarball"]
            reviewed_bytes = release_assets[tarball_name]["bytes"]
            digests = javascript_npm_tarball_digest(reviewed_bytes)
            sha1 = digests["sha1"]
            sha256 = digests["sha256"]
            sha512 = digests["sha512"]
            integrity = digests["integrity"]
            registry_bytes = self._download_https(
                nested(metadata, "dist", "tarball"),
                allowed_hosts={"registry.npmjs.org"},
                maximum=10 * 1024 * 1024,
            )
            if (
                registry_bytes != reviewed_bytes
                or nested(metadata, "dist", "integrity") != integrity
                or evidence.get("bytes") != digests["bytes"]
                or evidence.get("sha1") != sha1
                or evidence.get("sha256") != sha256
                or evidence.get("sha512") != sha512
                or evidence.get("integrity") != integrity
            ):
                raise ObservationError("registry_npm_byte_proof_invalid")
            registry_evidence = self._validate_javascript_npm_package_evidence(
                package_id,
                package,
                coordinate,
                evidence,
                package_item["manifest"],
                package_item["post_publish"],
                metadata,
                metadata_payload,
                release_assets,
            )
            package_proofs.append(
                {
                    "id": package_id,
                    "package": package,
                    "version": coordinate["version"],
                    "registry_tarball_url": nested(metadata, "dist", "tarball"),
                    "registry_integrity": nested(metadata, "dist", "integrity"),
                    "tarball": tarball_name,
                    "bytes": len(reviewed_bytes),
                    "sha1": sha1,
                    "sha256": sha256,
                    "sha512": sha512,
                    "integrity": integrity,
                    "registry_tarball_byte_identical": True,
                    "provenance": registry_evidence["provenance"],
                    "registry_evidence": registry_evidence["retained"],
                    "independent_live_registry_evidence": registry_evidence["live"],
                    "adoptions": registry_evidence["adoptions"],
                }
            )
        retained_aggregates = {
            name: self._retained_asset_envelope(name, release_assets[name])
            for name in self._javascript_aggregate_assets()
        }
        proof = {
            "schema_version": 2,
            "kind": "latchway_npm_package_set_registry_proof",
            "registry": "npm",
            "version": coordinate["version"],
            "source_commit": coordinate["commit"],
            "release_tag": coordinate["tag"],
            "package_count": 4,
            "publish_order": [package for _, package in JAVASCRIPT_NPM_PACKAGES],
            "packages": package_proofs,
            "reviewed_aggregate_evidence": aggregate_documents,
            "checksum_verification": aggregate["checksum_verification"],
            "contract_source_verification": contract_source_verification,
            "reproducibility_archive_verification": reproducibility_verification,
            "retained_aggregate_evidence": retained_aggregates,
            "release_asset_set": {
                name: release_assets[name]["metadata"] for name in sorted(release_assets)
            },
            "immutable_release_asset_verifications": {
                name: release_assets[name]["immutable_release_verification"]
                for name in sorted(release_assets)
            },
            "release_asset_attestation_verifications": source_attestations,
            "compatibility": self._derive_npm_compatibility("javascript"),
        }
        finished = datetime.now(timezone.utc).replace(microsecond=0)
        started = min(starts)
        if finished <= started:
            finished = started + EVIDENCE.timedelta(seconds=1)
        self.emit(
            "registry.npm.javascript",
            canonical_json(proof),
            started=started,
            finished=finished,
            version="core-v2",
            invocation=("npm", "view", "@latchway/{client,openai,vercel-ai,langchain}", "--json", "--include-attestations", "and-download"),
            cwd=self.repositories["javascript"],
            raw_artifacts={
                f"latchway-{package_id}-{coordinate['version']}.tgz":
                    release_assets[
                        f"latchway-{package_id}-{coordinate['version']}.tgz"
                    ]["bytes"]
                for package_id, _ in JAVASCRIPT_NPM_PACKAGES
            },
        )

    def _observe_npm_bytes(
        self,
        observation: str,
        package: str,
        repository_id: str,
        coordinate: Mapping[str, str],
    ) -> None:
        _, release_assets = self._release_asset_set(repository_id)
        metadata_payload, started, _ = self._execute_command(
            (
                "npm", "view", f"{package}@{coordinate['version']}", "--json",
                "--include-attestations", "--registry=https://registry.npmjs.org/",
            ),
            environment={
                "NPM_CONFIG_USERCONFIG": os.devnull,
                "NPM_CONFIG_PROVENANCE": "false",
            },
        )
        self._validate_npm(metadata_payload, package, coordinate)
        metadata = load_output(metadata_payload, "registry_npm_invalid")
        package_evidence_bytes = release_assets["package-evidence.json"]["bytes"]
        package_evidence_asset = release_assets["package-evidence.json"]["metadata"]
        reproducibility_bytes = release_assets["build-reproducibility.json"]["bytes"]
        reproducibility_asset = release_assets["build-reproducibility.json"]["metadata"]
        docs_bundle_name = f"docs-bundle-{coordinate['version']}.tar.gz"
        docs_bundle_bytes = release_assets[docs_bundle_name]["bytes"]
        docs_bundle_asset = release_assets[docs_bundle_name]["metadata"]
        package_evidence = load_output(package_evidence_bytes, "registry_npm_package_evidence_invalid")
        reproducibility = load_output(reproducibility_bytes, "registry_npm_reproducibility_invalid")
        published_dependencies: dict[str, Any] | None = None
        dependency_evidence_bytes: bytes | None = None
        dependency_evidence_asset: Mapping[str, Any] | None = None
        if (
            repository_id == "react_native"
            and "published-dependency-evidence.json" in release_assets
        ):
            dependency_evidence_bytes = release_assets[
                "published-dependency-evidence.json"
            ]["bytes"]
            dependency_evidence_asset = release_assets[
                "published-dependency-evidence.json"
            ]["metadata"]
            published_dependencies = self._validate_rn_published_dependencies(
                dependency_evidence_bytes
            )
        elif (
            repository_id == "react_native"
            and getattr(self, "release_profile", None) is None
        ):
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        tarball_name = package_evidence.get("tarball") if isinstance(package_evidence, dict) else None
        if not isinstance(tarball_name, str) or re.fullmatch(r"[A-Za-z0-9._-]+\.tgz", tarball_name) is None:
            raise ObservationError("registry_npm_package_evidence_invalid")
        if tarball_name not in release_assets:
            raise ObservationError("registry_npm_package_evidence_invalid")
        reviewed_bytes = release_assets[tarball_name]["bytes"]
        reviewed_asset = release_assets[tarball_name]["metadata"]
        reviewed_root = Path(tempfile.mkdtemp(prefix="latchway-npm-reviewed-"))
        reviewed_paths = {
            tarball_name: reviewed_root / tarball_name,
            "package-evidence.json": reviewed_root / "package-evidence.json",
            "build-reproducibility.json": reviewed_root / "build-reproducibility.json",
            docs_bundle_name: reviewed_root / docs_bundle_name,
        }
        if (
            repository_id == "react_native"
            and getattr(self, "release_profile", None)
            == EVIDENCE.SINGLE_MAINTAINER_PROFILE
        ):
            for name in (
                f"latchway-react-native-{coordinate['version']}.tgz.sha256",
                "latchway-single-maintainer-v1-intent.json",
            ):
                reviewed_paths[name] = reviewed_root / name
        if dependency_evidence_bytes is not None:
            reviewed_paths["published-dependency-evidence.json"] = (
                reviewed_root / "published-dependency-evidence.json"
            )
        for name, path in reviewed_paths.items():
            path.write_bytes(release_assets[name]["bytes"])
        asset_attestations = {
            name: self._verify_release_asset_attestation(path, repository_id, coordinate)
            for name, path in reviewed_paths.items()
        }
        registry_bytes = self._download_https(
            nested(metadata, "dist", "tarball"),
            allowed_hosts={"registry.npmjs.org"},
            maximum=10 * 1024 * 1024,
        )
        sha256 = hashlib.sha256(reviewed_bytes).hexdigest()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(reviewed_bytes).digest()).decode("ascii")
        if (
            registry_bytes != reviewed_bytes
            or nested(metadata, "dist", "integrity") != integrity
            or package_evidence.get("schema_version") != 1
            or package_evidence.get("package") != package
            or package_evidence.get("version") != coordinate["version"]
            or package_evidence.get("sha256") != sha256
            or package_evidence.get("integrity") != integrity
            or package_evidence.get("double_pack_byte_identical") is not True
            or reproducibility.get("schema_version") != 1
            or reproducibility.get("identical") is not True
            or not isinstance(reproducibility.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", reproducibility["sha256"]) is None
        ):
            raise ObservationError("registry_npm_byte_proof_invalid")
        registry_evidence = self._validate_npm_release_evidence(
            package,
            repository_id,
            coordinate,
            package_evidence,
            metadata,
            metadata_payload,
            release_assets,
        )
        retained_source_attestations = registry_evidence["retained"].get(
            "source_attestation_verifications"
        )
        if (
            not isinstance(retained_source_attestations, dict)
            or set(asset_attestations) | set(retained_source_attestations)
            != expected_source_attested_release_assets(
                repository_id,
                coordinate["version"],
                release_assets,
                getattr(self, "release_profile", None),
            )
        ):
            raise ObservationError("release_asset_attestation_set_invalid")
        provenance = registry_evidence["provenance"]
        proof = {
            "schema_version": 1,
            "registry": "npm",
            "package": package,
            "version": coordinate["version"],
            "source_commit": coordinate["commit"],
            "registry_tarball_url": nested(metadata, "dist", "tarball"),
            "registry_integrity": nested(metadata, "dist", "integrity"),
            "tarball": tarball_name,
            "bytes": len(reviewed_bytes),
            "sha256": sha256,
            "integrity": integrity,
            "registry_tarball_byte_identical": True,
            "provenance": provenance,
            "registry_evidence": registry_evidence["retained"],
            "independent_live_registry_evidence": registry_evidence["live"],
            "adoptions": registry_evidence["adoptions"],
            "reviewed_package_evidence": package_evidence,
            "reviewed_build_reproducibility": reproducibility,
            "release_asset_digests": {
                tarball_name: reviewed_asset["digest"],
                "package-evidence.json": package_evidence_asset["digest"],
                "build-reproducibility.json": reproducibility_asset["digest"],
                docs_bundle_name: docs_bundle_asset["digest"],
            },
            "release_asset_attestation_verifications": asset_attestations,
            "immutable_release_asset_verifications": {
                name: release_assets[name]["immutable_release_verification"]
                for name in sorted(release_assets)
            },
            "release_asset_set": {
                name: release_assets[name]["metadata"]
                for name in sorted(release_assets)
            },
            "compatibility": self._derive_npm_compatibility(repository_id),
        }
        if published_dependencies is not None and dependency_evidence_asset is not None:
            proof["reviewed_published_dependency_evidence"] = published_dependencies
            proof["release_asset_digests"]["published-dependency-evidence.json"] = (
                dependency_evidence_asset["digest"]
            )
        if (
            repository_id == "react_native"
            and getattr(self, "release_profile", None)
            == EVIDENCE.SINGLE_MAINTAINER_PROFILE
        ):
            for name in (
                f"latchway-react-native-{coordinate['version']}.tgz.sha256",
                "latchway-single-maintainer-v1-intent.json",
            ):
                proof["release_asset_digests"][name] = release_assets[name][
                    "metadata"
                ]["digest"]
        finished = datetime.now(timezone.utc).replace(microsecond=0)
        if finished <= started:
            finished = started + EVIDENCE.timedelta(seconds=1)
        self.emit(
            observation,
            canonical_json(proof),
            started=started,
            finished=finished,
            version="system",
            invocation=("npm", "view", f"{package}@{coordinate['version']}", "--json", "--include-attestations", "and-download"),
            cwd=self.repositories[repository_id],
        )

    def _validate_rn_published_dependencies(self, payload: bytes) -> dict[str, Any]:
        value = load_output(payload, "registry_npm_dependency_evidence_invalid")
        dependencies = value.get("dependencies") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "kind", "dependencies"}
            or value.get("schema_version") != 1
            or value.get("kind")
            != "latchway_react_native_published_dependency_evidence"
            or not isinstance(dependencies, dict)
            or set(dependencies) != {"core", "javascript", "ios", "android"}
        ):
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        core = self.identity["repositories"]["core"]
        if dependencies["core"] != {
            "repository": "https://github.com/Latchway/latchway",
            "source_commit": core["commit"],
            "release_tag": core["tag"],
        }:
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        for repository_id in ("javascript", "ios", "android"):
            self._validate_rn_dependency_summary(
                dependencies[repository_id], repository_id
            )
        return value

    def _validate_rn_dependency_summary(
        self, value: Any, repository_id: str
    ) -> None:
        coordinate = self.identity["repositories"][repository_id]
        expected_assets, adoption_required = self._expected_release_assets(
            repository_id,
            coordinate["version"],
            getattr(self, "release_profile", None),
        )
        if not isinstance(value, dict) or set(value) != {
            "repository",
            "release_tag",
            "source_commit",
            "github_release_immutable",
            "github_release_attestation",
            "release_assets",
            "public_registry",
        }:
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        assets = value.get("release_assets")
        registry = value.get("public_registry")
        names = set(assets) if isinstance(assets, dict) else set()
        if repository_id == "javascript":
            adoptions = {
                name
                for name in names
                if JAVASCRIPT_NPM_ADOPTION_ASSET.fullmatch(name)
            }
            adoption_ids = {
                match.group(1)
                for name in adoptions
                if (match := JAVASCRIPT_NPM_ADOPTION_ASSET.fullmatch(name))
                is not None
            }
        else:
            adoptions = {name for name in names if NPM_ADOPTION_ASSET.fullmatch(name)}
            adoption_ids = {""} if adoptions else set()
        if (
            value.get("repository")
            != f"https://github.com/Latchway/{REPOSITORY_NAMES[repository_id]}"
            or value.get("release_tag") != coordinate["tag"]
            or value.get("source_commit") != coordinate["commit"]
            or value.get("github_release_immutable") is not True
            or not value.get("github_release_attestation")
            or not isinstance(assets, dict)
            or not expected_assets.issubset(names)
            or names - expected_assets != adoptions
            or set(adoption_required) != adoption_ids
            or not isinstance(registry, dict)
        ):
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        for name, asset in assets.items():
            if (
                not isinstance(asset, dict)
                or set(asset) != {"bytes", "sha256", "immutable_attestation"}
                or not isinstance(asset.get("bytes"), int)
                or isinstance(asset.get("bytes"), bool)
                or asset["bytes"] < 1
                or re.fullmatch(r"[0-9a-f]{64}", str(asset.get("sha256"))) is None
                or not asset.get("immutable_attestation")
            ):
                raise ObservationError("registry_npm_dependency_evidence_invalid")
        expected_registry = {
            "javascript": "npm",
            "ios": "cocoapods",
            "android": "maven_central",
        }[repository_id]
        if registry.get("registry") != expected_registry:
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        if repository_id == "javascript" and (
            not valid_sha512_integrity(registry.get("integrity"))
            or re.fullmatch(r"[0-9a-f]{64}", str(registry.get("tarball_sha256")))
            is None
            or not isinstance(registry.get("provenance_run_id"), int)
            or not isinstance(registry.get("provenance_run_attempt"), int)
        ):
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        if repository_id == "ios" and any(
            re.fullmatch(r"[0-9a-f]{64}", str(registry.get(name))) is None
            for name in ("source_archive_sha256", "published_spec_sha256")
        ):
            raise ObservationError("registry_npm_dependency_evidence_invalid")
        if repository_id == "android" and (
            re.fullmatch(
                r"[0-9a-f]{64}", str(registry.get("repository_archive_sha256"))
            )
            is None
            or re.fullmatch(r"[0-9A-F]{40}", str(registry.get("signing_fingerprint")))
            is None
        ):
            raise ObservationError("registry_npm_dependency_evidence_invalid")

    @staticmethod
    def _retained_asset_envelope(
        name: str, entry: Mapping[str, Any]
    ) -> dict[str, Any]:
        payload = entry.get("bytes")
        metadata = entry.get("metadata")
        if not isinstance(payload, bytes) or not isinstance(metadata, dict):
            raise ObservationError("registry_npm_release_evidence_invalid")
        result = {
            "name": name,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "release_digest": metadata.get("digest"),
        }
        if len(payload) <= EVIDENCE.MAXIMUM_RESULT_BYTES:
            EVIDENCE.scan_safe(payload)
            result["content_base64"] = base64.b64encode(payload).decode("ascii")
        return result

    def _validate_npm_release_evidence(
        self,
        package: str,
        repository_id: str,
        coordinate: Mapping[str, str],
        package_evidence: Mapping[str, Any],
        metadata: Mapping[str, Any],
        live_view_payload: bytes,
        release_assets: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        raw_names = {
            "npm-registry-version.json",
            "npm-registry-view.json",
            "npm-attestations.json",
            "npm-audit-signatures.json",
            "npm-registry-evidence-manifest.json",
            "post-publish-evidence.json",
        }
        adoption_names = sorted(
            name for name in release_assets if NPM_ADOPTION_ASSET.fullmatch(name)
        )
        if not raw_names.issubset(release_assets) or not adoption_names:
            raise ObservationError("registry_npm_release_evidence_invalid")
        retained = {
            name: self._retained_asset_envelope(name, release_assets[name])
            for name in sorted(raw_names)
        }
        retained_values = {
            name: load_output(
                release_assets[name]["bytes"],
                "registry_npm_release_evidence_invalid",
            )
            for name in raw_names
        }
        manifest = retained_values["npm-registry-evidence-manifest.json"]
        evidence = manifest.get("evidence") if isinstance(manifest, dict) else None
        expected_evidence_names = {
            "npm-registry-version.json",
            "npm-registry-view.json",
            "npm-attestations.json",
            "npm-audit-signatures.json",
        }
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {
                "schema_version", "kind", "package", "version", "tarball", "evidence"
            }
            or manifest.get("schema_version") != 1
            or manifest.get("kind") != "latchway_npm_registry_evidence_manifest"
            or manifest.get("package") != package
            or manifest.get("version") != coordinate["version"]
            or manifest.get("tarball") != {
                "name": package_evidence.get("tarball"),
                "bytes": package_evidence.get("bytes"),
                "sha256": package_evidence.get("sha256"),
                "sha512": package_evidence.get("sha512"),
                "integrity": package_evidence.get("integrity"),
            }
            or not isinstance(evidence, list)
            or len(evidence) != len(expected_evidence_names)
        ):
            raise ObservationError("registry_npm_release_evidence_invalid")
        by_name: dict[str, Mapping[str, Any]] = {}
        for item in evidence:
            if (
                not isinstance(item, dict)
                or set(item) != {"name", "bytes", "sha256"}
                or item.get("name") in by_name
            ):
                raise ObservationError("registry_npm_release_evidence_invalid")
            by_name[str(item.get("name"))] = item
        if set(by_name) != expected_evidence_names:
            raise ObservationError("registry_npm_release_evidence_invalid")
        for name in expected_evidence_names:
            payload = release_assets[name]["bytes"]
            if by_name[name] != {
                "name": name,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }:
                raise ObservationError("registry_npm_release_evidence_invalid")
        registry_version = retained_values["npm-registry-version.json"]
        registry_view = retained_values["npm-registry-view.json"]
        for document in (registry_version, registry_view, metadata):
            self._validate_npm(canonical_json(document), package, coordinate)
            if nested(document, "dist", "integrity") != package_evidence.get("integrity"):
                raise ObservationError("registry_npm_release_evidence_invalid")
        if registry_view != metadata:
            raise ObservationError("registry_npm_registry_view_changed")
        retained_audit = retained_values["npm-audit-signatures.json"]
        if not isinstance(retained_audit, dict) or "error" in retained_audit:
            raise ObservationError("registry_npm_release_evidence_invalid")
        post = retained_values["post-publish-evidence.json"]
        repository = f"Latchway/{REPOSITORY_NAMES[repository_id]}"
        repository_url = f"https://github.com/{repository}"
        workflow_path = self._publication_workflow()
        if (
            not isinstance(post, dict)
            or post.get("schema_version") != 2
            or post.get("kind") != "latchway_npm_publication_evidence"
            or post.get("package") != package
            or post.get("version") != coordinate["version"]
            or post.get("release_tag") != coordinate["tag"]
            or post.get("registry") != "https://registry.npmjs.org/"
            or nested(post, "source", "repository") != repository_url
            or nested(post, "source", "commit") != coordinate["commit"]
            or nested(post, "source", "workflow") != workflow_path
            or nested(post, "source", "ref") != "refs/heads/main"
            or nested(post, "evidence_manifest", "sha256")
            != hashlib.sha256(release_assets["npm-registry-evidence-manifest.json"]["bytes"]).hexdigest()
        ):
            raise ObservationError("registry_npm_release_evidence_invalid")
        provenance, live = self._validate_npm_provenance(
            package,
            repository_id,
            coordinate,
            package_evidence,
            metadata,
            release_assets["npm-attestations.json"]["bytes"],
            release_assets["npm-audit-signatures.json"]["bytes"],
        )
        source_attestations: dict[str, Any] = {}
        for name in sorted(raw_names | set(adoption_names)):
            path = Path(tempfile.mkdtemp(prefix="latchway-npm-source-attestation-")) / name
            path.write_bytes(release_assets[name]["bytes"])
            source_attestations[name] = self._verify_release_asset_attestation(
                path, repository_id, coordinate
            )
        adoptions: list[dict[str, Any]] = []
        successful_adoption = False
        manifest_sha256 = hashlib.sha256(
            release_assets["npm-registry-evidence-manifest.json"]["bytes"]
        ).hexdigest()
        for name in adoption_names:
            record = load_output(
                release_assets[name]["bytes"], "registry_npm_adoption_invalid"
            )
            match = NPM_ADOPTION_ASSET.fullmatch(name)
            source = record.get("source") if isinstance(record, dict) else None
            origin = record.get("provenance") if isinstance(record, dict) else None
            adoption = record.get("adoption") if isinstance(record, dict) else None
            if (
                match is None
                or not isinstance(record, dict)
                or record.get("schema_version") != 1
                or record.get("kind") != "latchway_npm_release_adoption"
                or record.get("package") != package
                or record.get("version") != coordinate["version"]
                or record.get("release_tag") != coordinate["tag"]
                or record.get("tarball") != manifest.get("tarball")
                or source != {
                    "repository": repository_url,
                    "commit": coordinate["commit"],
                    "workflow": workflow_path,
                    "ref": "refs/heads/main",
                }
                or origin != {
                    "repository": repository_url,
                    "commit": coordinate["commit"],
                    "workflow": workflow_path,
                    "ref": "refs/heads/main",
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    "run_id": provenance["run_id"],
                    "run_attempt": provenance["run_attempt"],
                    "invocation_id": provenance["invocation_id"],
                }
                or not isinstance(adoption, dict)
                or str(adoption.get("run_id")) != name.split("-")[-2]
                or str(adoption.get("run_attempt")) != name.split("-")[-1].removesuffix(".json")
                or adoption.get("repository") != repository_url
                or adoption.get("commit") != coordinate["commit"]
                or adoption.get("workflow") != workflow_path
                or adoption.get("ref") != "refs/heads/main"
                or not valid_npm_adoption_mode(
                    adoption.get("mode"),
                    int(match.group(1)),
                    int(match.group(2)),
                    provenance["run_id"],
                    provenance["run_attempt"],
                )
                or record.get("registry_evidence_manifest") != {
                    "file": "npm-registry-evidence-manifest.json",
                    "sha256": manifest_sha256,
                }
            ):
                raise ObservationError("registry_npm_adoption_invalid")
            run_id, run_attempt = adoption["run_id"], adoption["run_attempt"]
            run = self._github_run_from_authority(
                repository_id, run_id, run_attempt
            )
            self._validate_npm_workflow_run(
                run, repository, coordinate["commit"], run_id, run_attempt,
                conclusions={"success"},
            )
            successful_adoption = True
            adoptions.append({
                "asset": self._retained_asset_envelope(name, release_assets[name]),
                "record": record,
                "authenticated_run": run,
            })
        if not successful_adoption:
            raise ObservationError("registry_npm_adoption_invalid")
        retained["source_attestation_verifications"] = source_attestations
        return {
            "provenance": provenance,
            "retained": retained,
            "live": {
                **live,
                "npm_view": {
                    "sha256": hashlib.sha256(live_view_payload).hexdigest(),
                    "content_base64": base64.b64encode(live_view_payload).decode("ascii"),
                },
            },
            "adoptions": adoptions,
        }

    def _validate_javascript_npm_package_evidence(
        self,
        package_id: str,
        package: str,
        coordinate: Mapping[str, str],
        package_evidence: Mapping[str, Any],
        manifest_entry: Mapping[str, Any],
        post_entry: Mapping[str, Any],
        metadata: Mapping[str, Any],
        live_view_payload: bytes,
        release_assets: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        raw_names = set(self._javascript_npm_evidence_names(package_id))
        single_maintainer = (
            getattr(self, "release_profile", None)
            == EVIDENCE.SINGLE_MAINTAINER_PROFILE
        )
        adoption_names = sorted(
            name
            for name in release_assets
            if (
                (match := JAVASCRIPT_NPM_ADOPTION_ASSET.fullmatch(name))
                is not None
                and match.group(1) == package_id
            )
        )
        if (
            not raw_names.issubset(release_assets)
            or (not single_maintainer and not adoption_names)
            or (
                single_maintainer
                and "single-maintainer-npm-adoption.json" not in release_assets
            )
        ):
            raise ObservationError("registry_npm_release_evidence_invalid")
        retained = {
            name: self._retained_asset_envelope(name, release_assets[name])
            for name in sorted(raw_names)
        }
        values = {
            name: load_output(
                release_assets[name]["bytes"],
                "registry_npm_release_evidence_invalid",
            )
            for name in raw_names
        }
        registry_version_name = f"npm-{package_id}-registry-version.json"
        registry_view_name = f"npm-{package_id}-registry-view.json"
        attestations_name = f"npm-{package_id}-attestations.json"
        audit_name = f"npm-{package_id}-audit-signatures.json"
        for document in (values[registry_version_name], values[registry_view_name], metadata):
            self._validate_npm(canonical_json(document), package, coordinate)
            if (
                nested(document, "dist", "integrity")
                != package_evidence.get("integrity")
            ):
                raise ObservationError("registry_npm_release_evidence_invalid")
        if values[registry_view_name] != metadata:
            raise ObservationError("registry_npm_registry_view_changed")
        retained_audit = values[audit_name]
        if not isinstance(retained_audit, dict) or "error" in retained_audit:
            raise ObservationError("registry_npm_release_evidence_invalid")
        provenance, live = self._validate_npm_provenance(
            package,
            "javascript",
            coordinate,
            package_evidence,
            metadata,
            release_assets[attestations_name]["bytes"],
            release_assets[audit_name]["bytes"],
        )
        evidence_references = {
            name: {
                "bytes": len(release_assets[name]["bytes"]),
                "sha256": hashlib.sha256(release_assets[name]["bytes"]).hexdigest(),
            }
            for name in raw_names
        }
        clean_consumer = post_entry.get("clean_consumer")
        if (
            post_entry.get("trusted_publisher")
            != {
                "provider": "github",
                "provenance_predicate_type": "https://slsa.dev/provenance/v1",
                "provenance_origin": {
                    "invocation_id": provenance["invocation_id"],
                    "run_id": provenance["run_id"],
                    "run_attempt": provenance["run_attempt"],
                },
                "sigstore_bundle": {
                    "file": attestations_name,
                    **evidence_references[attestations_name],
                },
            }
            or post_entry.get("registry_signature_verification")
            != {
                "command": "npm audit signatures --json --registry=https://registry.npmjs.org/",
                "output": {
                    "file": audit_name,
                    **evidence_references[audit_name],
                },
            }
            or post_entry.get("retained_outputs") != evidence_references
            or not isinstance(clean_consumer, dict)
            or set(clean_consumer)
            != {
                "isolated_directory",
                "install_scripts",
                "exact_package_version",
                "matching_client_version",
                "external_peer_dependencies",
                "node_esm",
                "registry_signatures",
            }
            or clean_consumer.get("isolated_directory") is not True
            or clean_consumer.get("install_scripts") != "disabled"
            or clean_consumer.get("exact_package_version") != coordinate["version"]
            or clean_consumer.get("matching_client_version")
            != (None if package_id == "client" else coordinate["version"])
            or clean_consumer.get("node_esm") is not True
            or clean_consumer.get("registry_signatures") is not True
            or not isinstance(clean_consumer.get("external_peer_dependencies"), dict)
            or any(
                not isinstance(name, str)
                or not name
                or not isinstance(requirement, str)
                or not requirement
                for name, requirement in clean_consumer[
                    "external_peer_dependencies"
                ].items()
            )
        ):
            raise ObservationError("registry_npm_post_publish_invalid")
        repository = "Latchway/latchway-js"
        repository_url = f"https://github.com/{repository}"
        workflow_path = self._publication_workflow()
        source_binding = {
            "repository": repository_url,
            "commit": coordinate["commit"],
            "workflow": workflow_path,
            "ref": "refs/heads/main",
        }
        manifest_sha256 = hashlib.sha256(
            release_assets["npm-registry-evidence-manifest.json"]["bytes"]
        ).hexdigest()
        if single_maintainer:
            adoption = self._validate_javascript_single_maintainer_adoption(
                release_assets,
                coordinate,
                package,
                post_entry,
                provenance,
            )
            return {
                "provenance": provenance,
                "retained": retained,
                "live": {
                    **live,
                    "npm_view": {
                        "sha256": hashlib.sha256(live_view_payload).hexdigest(),
                        "content_base64": base64.b64encode(
                            live_view_payload
                        ).decode("ascii"),
                    },
                },
                "adoptions": [adoption],
            }
        adoptions: list[dict[str, Any]] = []
        for name in adoption_names:
            record = load_output(
                release_assets[name]["bytes"], "registry_npm_adoption_invalid"
            )
            match = JAVASCRIPT_NPM_ADOPTION_ASSET.fullmatch(name)
            adoption = record.get("adoption") if isinstance(record, dict) else None
            expected_tarball = {
                "name": package_evidence.get("tarball"),
                "bytes": package_evidence.get("bytes"),
                "sha256": package_evidence.get("sha256"),
                "sha512": package_evidence.get("sha512"),
                "integrity": package_evidence.get("integrity"),
            }
            expected_origin = {
                **source_binding,
                "predicate_type": "https://slsa.dev/provenance/v1",
                "run_id": provenance["run_id"],
                "run_attempt": provenance["run_attempt"],
                "invocation_id": provenance["invocation_id"],
            }
            if (
                match is None
                or not isinstance(record, dict)
                or set(record)
                != {
                    "schema_version",
                    "kind",
                    "package",
                    "version",
                    "release_tag",
                    "tarball",
                    "source",
                    "provenance",
                    "adoption",
                    "registry_evidence_manifest",
                }
                or record.get("schema_version") != 1
                or record.get("kind") != "latchway_npm_release_adoption"
                or record.get("package") != package
                or record.get("version") != coordinate["version"]
                or record.get("release_tag") != coordinate["tag"]
                or record.get("tarball") != expected_tarball
                or record.get("source") != source_binding
                or record.get("provenance") != expected_origin
                or not isinstance(adoption, dict)
                or not valid_npm_adoption_mode(
                    adoption.get("mode"),
                    int(match.group(2)),
                    int(match.group(3)),
                    provenance["run_id"],
                    provenance["run_attempt"],
                )
                or adoption
                != {
                    **source_binding,
                    "run_id": int(match.group(2)),
                    "run_attempt": int(match.group(3)),
                    "mode": adoption.get("mode"),
                }
                or record.get("registry_evidence_manifest")
                != {
                    "file": "npm-registry-evidence-manifest.json",
                    "sha256": manifest_sha256,
                }
            ):
                raise ObservationError("registry_npm_adoption_invalid")
            run_id, run_attempt = adoption["run_id"], adoption["run_attempt"]
            run = self._github_run_from_authority(
                "javascript", run_id, run_attempt
            )
            self._validate_npm_workflow_run(
                run,
                repository,
                coordinate["commit"],
                run_id,
                run_attempt,
                conclusions={"success"},
            )
            adoptions.append(
                {
                    "asset": self._retained_asset_envelope(
                        name, release_assets[name]
                    ),
                    "record": record,
                    "authenticated_run": run,
                }
            )
        return {
            "provenance": provenance,
            "retained": retained,
            "live": {
                **live,
                "npm_view": {
                    "sha256": hashlib.sha256(live_view_payload).hexdigest(),
                    "content_base64": base64.b64encode(live_view_payload).decode(
                        "ascii"
                    ),
                },
            },
            "adoptions": adoptions,
        }

    def _validate_javascript_single_maintainer_adoption(
        self,
        release_assets: Mapping[str, Mapping[str, Any]],
        coordinate: Mapping[str, str],
        package: str,
        post_entry: Mapping[str, Any],
        provenance: Mapping[str, Any],
    ) -> dict[str, Any]:
        name = "single-maintainer-npm-adoption.json"
        record = load_output(
            release_assets[name]["bytes"], "registry_npm_adoption_invalid"
        )
        transaction = record.get("transaction") if isinstance(record, dict) else None
        source = record.get("source") if isinstance(record, dict) else None
        packages = record.get("packages") if isinstance(record, dict) else None
        owner = transaction.get("owner_run_id") if isinstance(transaction, dict) else None
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "schema_version", "kind", "transaction", "source",
                "release_tag", "packages",
            }
            or record.get("schema_version") != 1
            or record.get("kind") != "latchway_single_maintainer_npm_adoption"
            or source
            != {
                "repository": "https://github.com/Latchway/latchway-js",
                "commit": coordinate["commit"],
                "workflow": SINGLE_MAINTAINER_RELEASE_WORKFLOW,
                "ref": "refs/heads/main",
            }
            or record.get("release_tag") != coordinate["tag"]
            or not isinstance(transaction, dict)
            or set(transaction)
            != {
                "id", "owner_repository", "owner_workflow", "owner_run_id"
            }
            or transaction.get("owner_repository") != "Latchway/latchway-js"
            or transaction.get("owner_workflow")
            != SINGLE_MAINTAINER_RELEASE_WORKFLOW
            or not isinstance(owner, int)
            or isinstance(owner, bool)
            or not 1 <= owner <= 9_007_199_254_740_991
            or transaction.get("id")
            != hashlib.sha256(
                "\0".join(
                    (
                        "Latchway/latchway-js",
                        SINGLE_MAINTAINER_RELEASE_WORKFLOW,
                        str(owner),
                        coordinate["commit"],
                        coordinate["tag"],
                    )
                ).encode("utf-8")
            ).hexdigest()
            or not isinstance(packages, list)
            or len(packages) != len(JAVASCRIPT_NPM_PACKAGES)
        ):
            raise ObservationError("registry_npm_adoption_invalid")
        owner_run = self._github_owner_run_from_authority("javascript", owner)
        owner_attempt = owner_run.get("run_attempt")
        if (
            not isinstance(owner_attempt, int)
            or isinstance(owner_attempt, bool)
            or owner_attempt < 1
        ):
            raise ObservationError("registry_npm_adoption_invalid")
        self._validate_npm_workflow_run(
            owner_run,
            "Latchway/latchway-js",
            coordinate["commit"],
            owner,
            owner_attempt,
            conclusions={"success"},
        )
        by_package = {
            item.get("package"): item for item in packages if isinstance(item, dict)
        }
        if set(by_package) != {item[1] for item in JAVASCRIPT_NPM_PACKAGES}:
            raise ObservationError("registry_npm_adoption_invalid")
        item = by_package.get(package)
        expected_mode = (
            "transaction_publication"
            if provenance.get("run_id") == owner
            else "verified_existing"
        )
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "package", "version", "tarball", "provenance", "mode",
                "attestation", "signature_verification",
            }
            or item.get("version") != coordinate["version"]
            or item.get("tarball") != post_entry.get("tarball")
            or item.get("provenance")
            != nested(post_entry, "trusted_publisher", "provenance_origin")
            or item.get("provenance")
            != {
                "invocation_id": provenance.get("invocation_id"),
                "run_id": provenance.get("run_id"),
                "run_attempt": provenance.get("run_attempt"),
            }
            or item.get("mode") != expected_mode
            or item.get("attestation")
            != nested(post_entry, "trusted_publisher", "sigstore_bundle")
            or item.get("signature_verification")
            != nested(post_entry, "registry_signature_verification", "output")
        ):
            raise ObservationError("registry_npm_adoption_invalid")
        return {
            "asset": self._retained_asset_envelope(name, release_assets[name]),
            "record": record,
            "package": item,
            "authenticated_owner_run": owner_run,
        }

    def _validate_npm_workflow_run(
        self,
        run: Mapping[str, Any],
        repository: str,
        commit: str,
        run_id: int,
        run_attempt: int,
        *,
        conclusions: set[str],
    ) -> None:
        if (
            run.get("id") != run_id
            or run.get("run_attempt") != run_attempt
            or run.get("event") != self._publication_event()
            or run.get("status") != "completed"
            or run.get("conclusion") not in conclusions
            or run.get("head_sha") != commit
            or run.get("head_branch") != "main"
            or run.get("path") != self._publication_workflow()
            or nested(run, "repository", "full_name") != repository
        ):
            raise ObservationError("registry_npm_provenance_run_invalid")

    def _derive_npm_compatibility(self, repository_id: str) -> dict[str, Any]:
        try:
            package = load_output(
                EVIDENCE.read_bytes(
                    self.repositories[repository_id] / "package.json",
                    EVIDENCE.MAXIMUM_RESULT_BYTES,
                ),
                "sdk_compatibility_invalid",
            )
        except OSError:
            raise ObservationError("sdk_compatibility_invalid") from None
        node = nested(package, "engines", "node")
        if not isinstance(node, str) or re.fullmatch(r">=([1-9][0-9]*\.[0-9]+\.[0-9]+)", node) is None:
            raise ObservationError("sdk_compatibility_invalid")
        result: dict[str, Any] = {"minimum_node": node.removeprefix(">=")}
        if repository_id == "react_native":
            react_native = nested(package, "peerDependencies", "react-native")
            try:
                podspec = (
                    self.repositories[repository_id] / "LatchwayReactNative.podspec"
                ).read_text(encoding="utf-8")
                gradle = (
                    self.repositories[repository_id] / "android/build.gradle.kts"
                ).read_text(encoding="utf-8")
            except OSError:
                raise ObservationError("sdk_compatibility_invalid") from None
            ios_match = re.search(
                r'spec\.platforms\s*=\s*\{\s*ios:\s*"([0-9]+\.[0-9]+)"\s*\}',
                podspec,
            )
            android_match = re.search(r"\bminSdk\s*=\s*([1-9][0-9]*)\b", gradle)
            if (
                not isinstance(react_native, str)
                or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]+\.x", react_native) is None
                or ios_match is None
                or android_match is None
            ):
                raise ObservationError("sdk_compatibility_invalid")
            result.update(
                react_native=react_native,
                minimum_ios=ios_match.group(1),
                minimum_android_api=int(android_match.group(1)),
            )
        return result

    def _derive_ios_compatibility(self) -> dict[str, Any]:
        try:
            package = (self.repositories["ios"] / "Package.swift").read_text(
                encoding="utf-8"
            )
            podspec = (self.repositories["ios"] / "Latchway.podspec").read_text(
                encoding="utf-8"
            )
        except OSError:
            raise ObservationError("sdk_compatibility_invalid") from None
        package_match = re.search(r"\.iOS\(\.v([1-9][0-9]*)\)", package)
        pod_match = re.search(
            r"spec\.ios\.deployment_target\s*=\s*'([0-9]+\.[0-9]+)'", podspec
        )
        if (
            package_match is None
            or pod_match is None
            or pod_match.group(1) != f"{package_match.group(1)}.0"
        ):
            raise ObservationError("sdk_compatibility_invalid")
        return {"minimum_ios": pod_match.group(1)}

    def _derive_android_compatibility(self) -> dict[str, Any]:
        values: set[int] = set()
        for module in (
            "latchway-core",
            "latchway-okhttp",
            "latchway-play-integrity",
            "latchway-firebase-auth",
        ):
            try:
                text = (
                    self.repositories["android"] / module / "build.gradle.kts"
                ).read_text(encoding="utf-8")
            except OSError:
                raise ObservationError("sdk_compatibility_invalid") from None
            match = re.search(r"\bminSdk\s*=\s*([1-9][0-9]*)\b", text)
            if match is None:
                raise ObservationError("sdk_compatibility_invalid")
            values.add(int(match.group(1)))
        if len(values) != 1:
            raise ObservationError("sdk_compatibility_invalid")
        return {"minimum_android_api": values.pop()}

    def _validate_npm_provenance(
        self,
        package: str,
        repository_id: str,
        coordinate: Mapping[str, str],
        package_evidence: Mapping[str, Any],
        metadata: Mapping[str, Any],
        retained_attestations: bytes,
        retained_audit_signatures: bytes,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        url = nested(metadata, "dist", "attestations", "url")
        payload = self._download_https(
            url, allowed_hosts={"registry.npmjs.org"}, maximum=5 * 1024 * 1024
        )
        if payload != retained_attestations:
            raise ObservationError("registry_npm_attestations_changed")
        response = load_output(payload, "registry_npm_attestations_invalid")
        attestations = response.get("attestations") if isinstance(response, dict) else None
        if not isinstance(attestations, list):
            raise ObservationError("registry_npm_attestations_invalid")
        types = {
            "https://slsa.dev/provenance/v1": "provenance",
            "https://github.com/npm/attestation/tree/main/specs/publish/v0.1": "publish",
        }
        selected: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for predicate_type, label in types.items():
            matches = [item for item in attestations if isinstance(item, dict) and item.get("predicateType") == predicate_type]
            if len(matches) != 1:
                raise ObservationError("registry_npm_attestations_invalid")
            envelope = nested(matches[0], "bundle", "dsseEnvelope")
            encoded = envelope.get("payload") if isinstance(envelope, dict) else None
            if (
                not isinstance(encoded, str)
                or envelope.get("payloadType") != "application/vnd.in-toto+json"
                or not isinstance(envelope.get("signatures"), list)
                or not envelope["signatures"]
            ):
                raise ObservationError("registry_npm_attestations_invalid")
            try:
                statement = load_output(base64.b64decode(encoded, validate=True), "registry_npm_attestations_invalid")
            except (binascii.Error, ValueError):
                raise ObservationError("registry_npm_attestations_invalid") from None
            selected[label] = (matches[0], statement)
        expected_purl = f"pkg:npm/{quote(package.split('/')[0], safe='')}/{package.split('/')[1]}@{coordinate['version']}"
        expected_sha512 = package_evidence.get("sha512")
        for label, (_, statement) in selected.items():
            subject = statement.get("subject")
            expected_type = "https://in-toto.io/Statement/v1" if label == "provenance" else "https://in-toto.io/Statement/v0.1"
            if (
                statement.get("_type") != expected_type
                or not isinstance(subject, list)
                or len(subject) != 1
                or subject[0].get("name") != expected_purl
                or nested(subject[0], "digest", "sha512") != expected_sha512
            ):
                raise ObservationError("registry_npm_attestations_invalid")
        provenance_attestation, statement = selected["provenance"]
        repository = f"Latchway/{REPOSITORY_NAMES[repository_id]}"
        repository_url = f"https://github.com/{repository}"
        workflow_path = self._publication_workflow()
        workflow_event = self._publication_event()
        workflow = nested(statement, "predicate", "buildDefinition", "externalParameters", "workflow")
        resolved = nested(statement, "predicate", "buildDefinition", "resolvedDependencies")
        github = nested(statement, "predicate", "buildDefinition", "internalParameters", "github")
        invocation = nested(statement, "predicate", "runDetails", "metadata", "invocationId")
        match = re.fullmatch(
            re.escape(f"{repository_url}/actions/runs/") + r"([1-9]\d*)/attempts/([1-9]\d*)",
            invocation if isinstance(invocation, str) else "",
        )
        if (
            not isinstance(workflow, dict)
            or workflow.get("repository") != repository_url
            or workflow.get("ref") != "refs/heads/main"
            or workflow.get("path") != workflow_path
            or not isinstance(resolved, list)
            or not any(nested(item, "digest", "gitCommit") == coordinate["commit"] for item in resolved if isinstance(item, dict))
            or nested(github, "event_name") != workflow_event
            or match is None
        ):
            raise ObservationError("registry_npm_provenance_binding_invalid")
        run_id, run_attempt = (int(value) for value in match.groups())
        run = self._github_run_from_authority(
            repository_id, run_id, run_attempt
        )
        self._validate_npm_workflow_run(
            run,
            repository,
            coordinate["commit"],
            run_id,
            run_attempt,
            conclusions={"success", "failure", "cancelled", "timed_out"},
        )
        certificate = nested(provenance_attestation, "bundle", "verificationMaterial", "certificate", "rawBytes")
        try:
            certificate_bytes = base64.b64decode(certificate, validate=True) if isinstance(certificate, str) else b""
        except (binascii.Error, ValueError):
            raise ObservationError("registry_npm_provenance_certificate_invalid") from None
        certificate_path = Path(tempfile.mkdtemp(prefix="latchway-npm-cert-")) / "certificate.der"
        certificate_path.write_bytes(certificate_bytes)
        san, _, _ = self._execute_command(
            ("openssl", "x509", "-inform", "DER", "-in", str(certificate_path), "-noout", "-ext", "subjectAltName")
        )
        expected_identity = f"URI:{repository_url}/{workflow_path}@refs/heads/main"
        if expected_identity.encode("utf-8") not in san:
            raise ObservationError("registry_npm_provenance_certificate_invalid")
        publish = selected["publish"][1]
        if (
            nested(publish, "predicate", "name") != package
            or nested(publish, "predicate", "version") != coordinate["version"]
            or nested(publish, "predicate", "registry") != "https://registry.npmjs.org"
        ):
            raise ObservationError("registry_npm_publish_attestation_invalid")
        audit_root = Path(tempfile.mkdtemp(prefix="latchway-npm-audit-"))
        (audit_root / "package.json").write_text(
            json.dumps({"name": "latchway-proof", "version": "0.0.0", "private": True, "dependencies": {package: coordinate["version"]}}),
            encoding="utf-8",
        )
        environment = command_environment({"NPM_CONFIG_USERCONFIG": os.devnull})
        audit_payload = b""
        for command in (
            ("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact"),
            ("npm", "audit", "signatures", "--json", "--registry=https://registry.npmjs.org/"),
        ):
            executable = shutil.which(command[0])
            if executable is None:
                raise ObservationError("observation_tool_unavailable")
            result = subprocess.run((executable, *command[1:]), cwd=audit_root, env=environment, capture_output=True, timeout=180)
            if result.returncode != 0:
                raise ObservationError("registry_npm_signature_audit_failed")
            if command[1:3] == ("audit", "signatures"):
                audit_payload = result.stdout
        audit = load_output(audit_payload, "registry_npm_signature_audit_failed")
        retained_audit = load_output(
            retained_audit_signatures, "registry_npm_signature_audit_failed"
        )
        if (
            not isinstance(audit, dict)
            or "error" in audit
            or audit != retained_audit
        ):
            raise ObservationError("registry_npm_signature_audit_failed")
        provenance = {
            "attestations_sha256": hashlib.sha256(payload).hexdigest(),
            "attestations_content_base64": base64.b64encode(payload).decode("ascii"),
            "source_repository": repository,
            "source_commit": coordinate["commit"],
            "workflow": workflow_path,
            "workflow_ref": "refs/heads/main",
            "invocation_id": invocation,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_conclusion": run.get("conclusion"),
            "certificate_identity": expected_identity,
            "authenticated_run": run,
        }
        live = {
            "npm_attestations": {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "content_base64": base64.b64encode(payload).decode("ascii"),
            },
            "npm_audit_signatures": {
                "sha256": hashlib.sha256(audit_payload).hexdigest(),
                "content_base64": base64.b64encode(audit_payload).decode("ascii"),
            },
        }
        return provenance, live

    def _github_run_from_authority(
        self, repository_id: str, run_id: int, run_attempt: int
    ) -> dict[str, Any]:
        if (
            repository_id not in ("javascript", "react_native")
            or not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or run_id < 1
            or not isinstance(run_attempt, int)
            or isinstance(run_attempt, bool)
            or run_attempt < 1
        ):
            raise ObservationError("registry_npm_provenance_run_invalid")
        value, _, _ = self._github_authority_json(
            f"public-registries/{repository_id}/runs/{run_id}-{run_attempt}.json",
            "registry_npm_provenance_run_invalid",
        )
        if not isinstance(value, dict):
            raise ObservationError("registry_npm_provenance_run_invalid")
        return value

    def _github_owner_run_from_authority(
        self, repository_id: str, run_id: int
    ) -> dict[str, Any]:
        if (
            repository_id != "javascript"
            or not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or not 1 <= run_id <= 9_007_199_254_740_991
        ):
            raise ObservationError("registry_npm_adoption_invalid")
        value, _, _ = self._github_authority_json(
            f"public-registries/{repository_id}/runs/owner-{run_id}.json",
            "registry_npm_adoption_invalid",
        )
        if not isinstance(value, dict):
            raise ObservationError("registry_npm_adoption_invalid")
        return value

    def _release_asset_set(
        self, repository_id: str
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        coordinate = self.identity["repositories"][repository_id]
        root = f"public-registries/{repository_id}"
        release_payload, _, _ = self._github_authority_file(
            f"{root}/release.json", maximum=EVIDENCE.MAXIMUM_RESULT_BYTES
        )
        expected_assets, adoption_required = self._expected_release_assets(
            repository_id,
            coordinate["version"],
            getattr(self, "release_profile", None),
        )
        release = self._validate_release(
            release_payload,
            coordinate["tag"],
            expected_assets=expected_assets,
            adoption_required=adoption_required,
            single_adoption_per_key=(
                getattr(self, "release_profile", None)
                == EVIDENCE.SINGLE_MAINTAINER_PROFILE
            ),
        )
        if getattr(self, "release_profile", None) is not None:
            _, expected_name, expected_body = self._single_maintainer_release_contract(
                repository_id, coordinate, release, None
            )
            release = self._validate_release(
                release_payload,
                coordinate["tag"],
                expected_assets=expected_assets,
                adoption_required=adoption_required,
                single_adoption_per_key=True,
                expected_name=expected_name,
                expected_body=expected_body,
            )
        assets = release.get("assets")
        if not isinstance(assets, list):
            raise ObservationError("github_release_asset_invalid")
        downloaded: dict[str, dict[str, Any]] = {}
        for asset in assets:
            name = asset["name"]
            payload, _, _ = self._github_authority_file(f"{root}/assets/{name}")
            if (
                len(payload) != asset["size"]
                or f"sha256:{hashlib.sha256(payload).hexdigest()}"
                != asset["digest"]
            ):
                raise ObservationError("github_release_asset_digest_mismatch")
            immutable_payload, _, _ = self._github_authority_file(
                f"{root}/immutable/{name}.json",
                maximum=EVIDENCE.MAXIMUM_RESULT_BYTES,
            )
            immutable_value = load_output(
                immutable_payload, "github_release_asset_attestation_invalid"
            )
            if not isinstance(immutable_value, dict) or not immutable_value:
                raise ObservationError("github_release_asset_attestation_invalid")
            immutable_verification = {
                "sha256": hashlib.sha256(immutable_payload).hexdigest(),
                "content_base64": base64.b64encode(immutable_payload).decode("ascii"),
            }
            downloaded[name] = {
                "bytes": payload,
                "metadata": {
                    "name": name,
                    "digest": asset["digest"],
                    "size": asset["size"],
                },
                "immutable_release_verification": immutable_verification,
            }
        return release, downloaded

    def _release_asset_bytes(self, repository_id: str, name: str) -> tuple[bytes, dict[str, Any]]:
        _, assets = self._release_asset_set(repository_id)
        if name not in assets:
            raise ObservationError("github_release_asset_invalid")
        return assets[name]["bytes"], assets[name]["metadata"]

    @staticmethod
    def _download_https(url: Any, *, allowed_hosts: set[str], maximum: int) -> bytes:
        if not isinstance(url, str):
            raise ObservationError("registry_download_url_invalid")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in allowed_hosts or parsed.username or parsed.password:
            raise ObservationError("registry_download_url_invalid")
        try:
            with urlopen(Request(url, headers={"Accept": "application/octet-stream"}), timeout=60) as response:
                final = urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname not in allowed_hosts:
                    raise ObservationError("registry_download_redirect_invalid")
                payload = response.read(maximum + 1)
        except ObservationError:
            raise
        except Exception:
            raise ObservationError("registry_download_failed") from None
        if not 1 <= len(payload) <= maximum:
            raise ObservationError("registry_download_size_invalid")
        return payload

    @staticmethod
    def _validate_checksum_file(payload: bytes, expected_name: str, expected_bytes: bytes) -> None:
        Observer._validate_exact_checksum_file(
            payload, {expected_name: expected_bytes}, allow_additional=True
        )

    @staticmethod
    def _validate_exact_checksum_file(
        payload: bytes,
        expected: Mapping[str, bytes],
        *,
        allow_additional: bool = False,
    ) -> None:
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            raise ObservationError("release_checksum_invalid") from None
        entries: dict[str, str] = {}
        for line in text.splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
            if match is None or match.group(2) in entries:
                raise ObservationError("release_checksum_invalid")
            entries[match.group(2)] = match.group(1)
        expected_entries = {
            name: hashlib.sha256(value).hexdigest() for name, value in expected.items()
        }
        if (allow_additional and any(entries.get(name) != digest for name, digest in expected_entries.items())) or (
            not allow_additional and entries != expected_entries
        ):
            raise ObservationError("release_checksum_invalid")

    @staticmethod
    def _extract_reviewed_zip(payload: bytes, destination: Path) -> None:
        archive = destination / "reviewed.zip"
        archive.write_bytes(payload)
        try:
            with zipfile.ZipFile(archive) as value:
                members = value.infolist()
                if not members or len(members) > 512:
                    raise ObservationError("reviewed_maven_archive_invalid")
                seen: set[str] = set()
                total = 0
                for member in members:
                    path = Path(member.filename)
                    normalized = PurePosixPath(member.filename).as_posix()
                    mode = (member.external_attr >> 16) & 0o170000
                    total += member.file_size
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or member.is_dir()
                        or normalized in seen
                        or mode == stat.S_IFLNK
                        or member.file_size > EVIDENCE.MAXIMUM_RAW_BYTES
                        or total > 128 * 1024 * 1024
                    ):
                        raise ObservationError("reviewed_maven_archive_invalid")
                    seen.add(normalized)
                value.extractall(destination)
        except (OSError, zipfile.BadZipFile):
            raise ObservationError("reviewed_maven_archive_invalid") from None
        archive.unlink()
        if not (destination / "dev" / "latchway").is_dir():
            raise ObservationError("reviewed_maven_archive_invalid")

    @staticmethod
    def _validate_cocoapods_spec(
        payload: bytes, coordinate: Mapping[str, str]
    ) -> dict[str, Any]:
        value = load_output(payload, "registry_cocoapods_spec_invalid")
        source = value.get("source") if isinstance(value, dict) else None
        subspecs = value.get("subspecs") if isinstance(value, dict) else None
        names = (
            [item.get("name") for item in subspecs if isinstance(item, dict)]
            if isinstance(subspecs, list)
            else []
        )

        def contains_forbidden_hook(item: Any) -> bool:
            if isinstance(item, dict):
                return bool(COCOAPODS_FORBIDDEN_HOOKS.intersection(item)) or any(
                    contains_forbidden_hook(child) for child in item.values()
                )
            if isinstance(item, list):
                return any(contains_forbidden_hook(child) for child in item)
            return False

        if (
            not isinstance(value, dict)
            or value.get("name") != "Latchway"
            or value.get("version") != coordinate["version"]
            or source
            != {
                "git": "https://github.com/Latchway/latchway-ios-sdk.git",
                "tag": coordinate["tag"],
            }
            or not isinstance(subspecs, list)
            or len(names) != len(subspecs)
            or any(not isinstance(name, str) for name in names)
            or len(names) != len(set(names))
            or set(names) != IOS_COCOAPODS_SUBSPECS
            or contains_forbidden_hook(value)
        ):
            raise ObservationError("registry_cocoapods_spec_invalid")
        return value

    @staticmethod
    def _validate_cocoapods_proof(payload: bytes, coordinate: Mapping[str, str], asset: Mapping[str, Any]) -> None:
        value = load_output(payload, "registry_cocoapods_proof_invalid")
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version", "kind", "status", "registry", "package",
                "version", "published_spec_sha256",
                "reviewed_source_archive_sha256",
                "published_spec_equals_reviewed_podspec",
                "reviewed_source_archive_equals_release_tag",
                "reviewed_spec_sha256", "source_commit", "source_tag",
                "registry_url", "source",
            }
            or value.get("schema_version") != 1
            or value.get("kind") != "latchway_cocoapods_release_evidence"
            or value.get("status") != "passed"
            or value.get("registry") != "cocoapods"
            or value.get("package") != "Latchway"
            or value.get("version") != coordinate["version"]
            or value.get("published_spec_equals_reviewed_podspec") is not True
            or value.get("reviewed_source_archive_equals_release_tag") is not True
            or value.get("reviewed_source_archive_sha256") != str(asset["digest"]).removeprefix("sha256:")
            or EVIDENCE.SHA256.fullmatch(str(value.get("published_spec_sha256"))) is None
            or EVIDENCE.SHA256.fullmatch(str(value.get("reviewed_spec_sha256"))) is None
            or value.get("source_commit") != coordinate["commit"]
            or value.get("source_tag") != coordinate["tag"]
            or value.get("source")
            != {
                "git": "https://github.com/Latchway/latchway-ios-sdk.git",
                "tag": coordinate["tag"],
            }
            or not isinstance(value.get("registry_url"), str)
        ):
            raise ObservationError("registry_cocoapods_proof_invalid")

    @staticmethod
    def _validate_maven_proof(
        payload: bytes,
        coordinate: Mapping[str, str],
        signing_fingerprint: str,
        public_key_sha256: str,
    ) -> None:
        value = load_output(payload, "registry_maven_proof_invalid")
        files = value.get("files") if isinstance(value, dict) else None
        version = coordinate["version"]
        expected_paths = {
            f"{module}/{version}/{module}-{version}{suffix}"
            for module in (
                "latchway-core",
                "latchway-okhttp",
                "latchway-play-integrity",
                "latchway-firebase-auth",
                "latchway-bom",
            )
            for suffix in (
                (".pom", ".module", "-sources.jar", "-javadoc.jar")
                if module == "latchway-bom"
                else (".pom", ".module", "-sources.jar", "-javadoc.jar", ".aar")
            )
        }
        checksum_algorithms = {
            "md5": 32,
            "sha1": 40,
            "sha256": 64,
            "sha512": 128,
        }
        expected_manifest_paths = {
            derived
            for path in expected_paths
            for derived in (
                path,
                f"{path}.asc",
                *(f"{path}.{algorithm}" for algorithm in checksum_algorithms),
            )
        }
        public_manifest = value.get("public_manifest")
        deployment = value.get("deployment")
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version", "registry", "namespace", "version",
                "reviewed_repository", "primary_artifacts_byte_identical",
                "checksum_files_byte_identical", "signature_files_present",
                "signatures_cryptographically_verified", "signing_fingerprint",
                "reviewed_public_key_sha256", "deployment", "public_manifest",
                "public_manifest_sha256", "files",
            }
            or value.get("schema_version") != 2
            or value.get("registry") != "maven_central"
            or value.get("namespace") != "dev.latchway"
            or value.get("version") != coordinate["version"]
            or value.get("reviewed_repository") is not True
            or value.get("primary_artifacts_byte_identical") is not True
            or value.get("checksum_files_byte_identical") is not True
            or value.get("signature_files_present") is not True
            or value.get("signatures_cryptographically_verified") is not True
            or value.get("signing_fingerprint") != signing_fingerprint
            or value.get("reviewed_public_key_sha256") != public_key_sha256
            or not isinstance(files, list)
            or {item.get("path") for item in files if isinstance(item, dict)} != expected_paths
            or len(files) != len(expected_paths)
            or not isinstance(public_manifest, list)
            or len(public_manifest) != len(expected_manifest_paths)
            or public_manifest
            != sorted(
                public_manifest,
                key=lambda item: item.get("path", "") if isinstance(item, dict) else "",
            )
            or not isinstance(deployment, dict)
            or set(deployment)
            != {
                "intent_sha256", "record_sha256", "status_sha256", "record_kind",
                "record", "status",
            }
        ):
            raise ObservationError("registry_maven_proof_invalid")

        manifest_by_path: dict[str, Mapping[str, Any]] = {}
        for item in public_manifest:
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "bytes", "sha256"}
                or item.get("path") not in expected_manifest_paths
                or item["path"] in manifest_by_path
                or not isinstance(item.get("bytes"), int)
                or isinstance(item.get("bytes"), bool)
                or item["bytes"] < 1
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
            ):
                raise ObservationError("registry_maven_proof_invalid")
            manifest_by_path[item["path"]] = item
        if (
            set(manifest_by_path) != expected_manifest_paths
            or value.get("public_manifest_sha256")
            != hashlib.sha256(canonical_json(public_manifest)).hexdigest()
        ):
            raise ObservationError("registry_maven_proof_invalid")

        file_keys = {
            "path", "sha256", "bytes", "signature_sha256", "signature_bytes",
            "signature_armored", "gpg_status", "checksums",
            "checksums_byte_identical",
        }
        gpg_keys = {
            "schema_version", "primary_fingerprint", "signing_fingerprint",
            "public_key_algorithm", "hash_algorithm", "status_lines",
        }
        for item in files:
            if not isinstance(item, dict) or set(item) != file_keys:
                raise ObservationError("registry_maven_proof_invalid")
            path = item.get("path")
            signature = item.get("signature_armored")
            checksums = item.get("checksums")
            gpg_status = item.get("gpg_status")
            try:
                signature_bytes = signature.encode("ascii") if isinstance(signature, str) else b""
            except UnicodeEncodeError:
                raise ObservationError("registry_maven_proof_invalid") from None
            if (
                path not in expected_paths
                or not isinstance(item.get("bytes"), int)
                or isinstance(item.get("bytes"), bool)
                or item["bytes"] < 1
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
                or not isinstance(item.get("signature_bytes"), int)
                or isinstance(item.get("signature_bytes"), bool)
                or not 1 <= item["signature_bytes"] <= 65536
                or item["signature_bytes"] != len(signature_bytes)
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("signature_sha256"))) is None
                or not isinstance(signature, str)
                or not signature.startswith("-----BEGIN PGP SIGNATURE-----")
                or hashlib.sha256(signature_bytes).hexdigest()
                != item.get("signature_sha256")
                or item.get("checksums_byte_identical") is not True
                or not isinstance(checksums, list)
                or [entry.get("algorithm") for entry in checksums if isinstance(entry, dict)]
                != list(checksum_algorithms)
                or len(checksums) != len(checksum_algorithms)
                or not isinstance(gpg_status, dict)
                or set(gpg_status) != gpg_keys
                or gpg_status.get("schema_version") != 1
                or gpg_status.get("primary_fingerprint") != signing_fingerprint
                or re.fullmatch(
                    r"[0-9A-F]{40}", str(gpg_status.get("signing_fingerprint"))
                )
                is None
                or gpg_status.get("public_key_algorithm")
                not in {"1", "3", "19", "22", "27"}
                or gpg_status.get("hash_algorithm") != "10"
                or not isinstance(gpg_status.get("status_lines"), list)
                or not gpg_status["status_lines"]
                or any(
                    not isinstance(line, str) or not line.startswith("[GNUPG:]")
                    for line in gpg_status["status_lines"]
                )
                or manifest_by_path[path].get("bytes") != item["bytes"]
                or manifest_by_path[path].get("sha256") != item["sha256"]
                or manifest_by_path[f"{path}.asc"].get("bytes")
                != item["signature_bytes"]
                or manifest_by_path[f"{path}.asc"].get("sha256")
                != item["signature_sha256"]
            ):
                raise ObservationError("registry_maven_proof_invalid")
            for checksum in checksums:
                algorithm = checksum.get("algorithm") if isinstance(checksum, dict) else None
                expected_length = checksum_algorithms.get(str(algorithm))
                checksum_path = f"{path}.{algorithm}"
                if (
                    not isinstance(checksum, dict)
                    or set(checksum)
                    != {"algorithm", "path", "bytes", "sha256", "published_digest"}
                    or checksum.get("path") != checksum_path
                    or not isinstance(checksum.get("bytes"), int)
                    or isinstance(checksum.get("bytes"), bool)
                    or not 1 <= checksum["bytes"] <= 256
                    or re.fullmatch(r"[0-9a-f]{64}", str(checksum.get("sha256"))) is None
                    or expected_length is None
                    or re.fullmatch(
                        rf"[0-9a-f]{{{expected_length}}}",
                        str(checksum.get("published_digest")),
                    )
                    is None
                    or manifest_by_path[checksum_path].get("bytes") != checksum["bytes"]
                    or manifest_by_path[checksum_path].get("sha256") != checksum["sha256"]
                ):
                    raise ObservationError("registry_maven_proof_invalid")

    @staticmethod
    def _validate_android_release_documents(
        assets: Mapping[str, Mapping[str, Any]], coordinate: Mapping[str, str]
    ) -> None:
        def document(name: str) -> Mapping[str, Any]:
            value = load_output(
                assets[name]["bytes"], "registry_maven_deployment_evidence_invalid"
            )
            if not isinstance(value, dict):
                raise ObservationError("registry_maven_deployment_evidence_invalid")
            return value

        intent = document("maven-central-upload-intent.json")
        deployment = document("maven-central-deployment.json")
        status = document("maven-central-deployment-status.json")
        proof = document("maven-central-release-evidence.json")
        tag_binding = document("github-release-tag-binding.json")
        purls = sorted(
            f"pkg:maven/dev.latchway/{module}@{coordinate['version']}"
            for module in (
                "latchway-core",
                "latchway-okhttp",
                "latchway-play-integrity",
                "latchway-firebase-auth",
                "latchway-bom",
            )
        )
        intent_sha = hashlib.sha256(
            assets["maven-central-upload-intent.json"]["bytes"]
        ).hexdigest()
        deployment_sha = hashlib.sha256(
            assets["maven-central-deployment.json"]["bytes"]
        ).hexdigest()
        status_sha = hashlib.sha256(
            assets["maven-central-deployment-status.json"]["bytes"]
        ).hexdigest()
        portal_sha = hashlib.sha256(
            assets[
                f"latchway-android-{coordinate['version']}-central-portal.zip"
            ]["bytes"]
        ).hexdigest()
        expected_deployment_name = (
            f"latchway-android-v{coordinate['version']}-"
            f"{coordinate['commit'][:12]}-{portal_sha}"
        )
        intent_keys = {
            "schema", "repository", "source_commit", "release_tag", "version",
            "namespace", "deployment_name", "publishing_type",
            "reviewed_repository_archive_sha256",
            "reviewed_repository_manifest_sha256", "reviewed_repository_file_count",
            "reviewed_portal_bundle_sha256", "reviewed_portal_bundle_file_count",
            "reviewed_public_key_sha256", "expected_purls", "authorization",
        }
        deployment_keys = {
            "schema", "intent_sha256", "deployment_name", "publishing_type",
            "namespace", "version", "source_commit", "expected_purls",
            "reviewed_portal_bundle_sha256", "record_kind", "deployment_id",
            "public_manifest_sha256",
        }
        status_keys = {
            "schema", "intent_sha256", "record_sha256", "record_kind",
            "deployment_id", "deployment_name", "deployment_state", "purls",
            "public_manifest_sha256",
        }
        record_kind = deployment.get("record_kind")
        public_manifest = deployment.get("public_manifest_sha256")
        proof_deployment = proof.get("deployment")
        proof_keys = {
            "schema_version", "registry", "namespace", "version",
            "reviewed_repository", "primary_artifacts_byte_identical",
            "checksum_files_byte_identical", "signature_files_present",
            "signatures_cryptographically_verified", "signing_fingerprint",
            "reviewed_public_key_sha256", "deployment", "public_manifest",
            "public_manifest_sha256", "files",
        }
        proof_deployment_keys = {
            "intent_sha256", "record_sha256", "status_sha256", "record_kind",
            "record", "status",
        }
        deployment_kind_valid = (
            record_kind == "portal_deployment"
            and re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                str(deployment.get("deployment_id")),
                re.IGNORECASE,
            )
            is not None
            and public_manifest is None
        ) or (
            record_kind == "public_registry_adoption"
            and deployment.get("deployment_id") is None
            and re.fullmatch(r"[0-9a-f]{64}", str(public_manifest)) is not None
        )
        if (
            set(intent) != intent_keys
            or intent.get("schema") != "latchway.maven-central-upload-intent.v2"
            or intent.get("repository") != "Latchway/latchway-android"
            or intent.get("source_commit") != coordinate["commit"]
            or intent.get("release_tag") != coordinate["tag"]
            or intent.get("version") != coordinate["version"]
            or intent.get("namespace") != "dev.latchway"
            or intent.get("publishing_type") != "user_managed"
            or intent.get("authorization") != "recoverable_exact_upload"
            or intent.get("reviewed_repository_archive_sha256")
            != hashlib.sha256(
                assets[
                    f"latchway-android-{coordinate['version']}-maven-repository.zip"
                ]["bytes"]
            ).hexdigest()
            or intent.get("reviewed_portal_bundle_sha256")
            != portal_sha
            or intent.get("reviewed_public_key_sha256")
            != hashlib.sha256(
                assets["latchway-maven-signing-public-key.asc"]["bytes"]
            ).hexdigest()
            or intent.get("deployment_name") != expected_deployment_name
            or not isinstance(intent.get("reviewed_repository_manifest_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", intent["reviewed_repository_manifest_sha256"]
            ) is None
            or intent.get("reviewed_repository_file_count") != 120
            or intent.get("reviewed_portal_bundle_file_count") != 144
            or sorted(intent.get("expected_purls", [])) != purls
            or set(tag_binding)
            != {
                "schema",
                "tag",
                "tag_object_sha",
                "commit",
                "message_sha256",
            }
            or tag_binding.get("schema")
            != "latchway.github-release-tag-binding.v1"
            or tag_binding.get("tag") != coordinate["tag"]
            or tag_binding.get("commit") != coordinate["commit"]
            or re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                str(tag_binding.get("tag_object_sha")),
            ) is None
            or re.fullmatch(
                r"[0-9a-f]{64}", str(tag_binding.get("message_sha256"))
            )
            is None
            or set(deployment) != deployment_keys
            or deployment.get("schema") != "latchway.maven-central-deployment.v2"
            or deployment.get("intent_sha256") != intent_sha
            or deployment.get("deployment_name") != expected_deployment_name
            or deployment.get("publishing_type") != "user_managed"
            or deployment.get("namespace") != "dev.latchway"
            or deployment.get("source_commit") != coordinate["commit"]
            or deployment.get("version") != coordinate["version"]
            or sorted(deployment.get("expected_purls", [])) != purls
            or deployment.get("reviewed_portal_bundle_sha256") != portal_sha
            or not deployment_kind_valid
            or set(status) != status_keys
            or status.get("schema")
            != "latchway.maven-central-deployment-status.v2"
            or status.get("intent_sha256") != intent_sha
            or status.get("record_sha256") != deployment_sha
            or status.get("record_kind") != record_kind
            or status.get("deployment_id") != deployment.get("deployment_id")
            or status.get("deployment_name") != expected_deployment_name
            or status.get("deployment_state") != "PUBLISHED"
            or sorted(status.get("purls", [])) != purls
            or status.get("public_manifest_sha256") != public_manifest
            or set(proof) != proof_keys
            or proof.get("schema_version") != 2
            or proof.get("registry") != "maven_central"
            or proof.get("namespace") != "dev.latchway"
            or proof.get("version") != coordinate["version"]
            or not isinstance(proof_deployment, dict)
            or set(proof_deployment) != proof_deployment_keys
            or nested(proof, "deployment", "intent_sha256") != intent_sha
            or nested(proof, "deployment", "record_sha256") != deployment_sha
            or nested(proof, "deployment", "status_sha256") != status_sha
            or nested(proof, "deployment", "record_kind") != record_kind
            or nested(proof, "deployment", "record") != deployment
            or nested(proof, "deployment", "status") != status
            or (
                record_kind == "public_registry_adoption"
                and public_manifest != proof.get("public_manifest_sha256")
            )
        ):
            raise ObservationError("registry_maven_deployment_evidence_invalid")

    @staticmethod
    def _validate_npm(payload: bytes, package: str, coordinate: Mapping[str, str]) -> None:
        value = load_output(payload, "registry_npm_invalid")
        integrity = nested(value, "dist", "integrity")
        if (
            not isinstance(value, dict)
            or value.get("name") != package
            or value.get("version") != coordinate["version"]
            or not valid_sha512_integrity(integrity)
        ):
            raise ObservationError("registry_npm_invalid")

    def _observe_swift_registry(self, coordinate: Mapping[str, str]) -> None:
        executable = shutil.which("swift")
        if executable is None:
            raise ObservationError("observation_tool_unavailable")
        root = Path(tempfile.mkdtemp(prefix="latchway-swift-registry-"))
        package = root / "Package.swift"
        package.write_text(
            "// swift-tools-version: 6.0\n"
            "import PackageDescription\n"
            "let package = Package(\n"
            "  name: \"LatchwayRegistryEvidence\",\n"
            "  dependencies: [.package(url: \"https://github.com/Latchway/latchway-ios-sdk.git\", exact: \""
            + coordinate["version"]
            + "\")],\n"
            "  targets: [.executableTarget(name: \"Evidence\", dependencies: [.product(name: \"Latchway\", package: \"latchway-ios-sdk\")])]\n"
            ")\n",
            encoding="utf-8",
        )
        source = root / "Sources" / "Evidence" / "main.swift"
        source.parent.mkdir(parents=True)
        source.write_text("import Latchway\n", encoding="utf-8")
        started = datetime.now(timezone.utc).replace(microsecond=0)
        result = subprocess.run(
            (executable, "package", "resolve", "--package-path", str(root)),
            check=False,
            capture_output=True,
            timeout=10 * 60,
            env=command_environment(),
        )
        finished = datetime.now(timezone.utc).replace(microsecond=0)
        if finished <= started:
            finished = started + EVIDENCE.timedelta(seconds=1)
        resolved = root / "Package.resolved"
        if result.returncode != 0 or not resolved.is_file():
            raise ObservationError("swift_registry_resolution_failed")
        payload = EVIDENCE.read_bytes(resolved)
        self._validate_swift_resolution(payload, coordinate)
        self.emit(
            "registry.swift",
            payload,
            started=started,
            finished=finished,
            version="system",
            invocation=("swift", "package", "resolve", "latchway-ios-sdk", coordinate["version"]),
        )

    @staticmethod
    def _validate_swift_resolution(
        payload: bytes, coordinate: Mapping[str, str]
    ) -> None:
        value = load_output(payload, "swift_registry_resolution_invalid")
        pins = value.get("pins") if isinstance(value, dict) else None
        matches = [
            pin
            for pin in pins or []
            if isinstance(pin, dict)
            and pin.get("identity") == "latchway-ios-sdk"
            and pin.get("kind") == "remoteSourceControl"
            and pin.get("location")
            == "https://github.com/Latchway/latchway-ios-sdk.git"
            and pin.get("state")
            == {
                "revision": coordinate["commit"],
                "version": coordinate["version"],
            }
        ]
        if not isinstance(pins, list) or len(matches) != 1:
            raise ObservationError("swift_registry_resolution_invalid")

    def observe_live_sdk_conformance(self) -> None:
        self._observe_sdk_conformance(include_javascript=True)

    def observe_physical_devices(self) -> None:
        self._observe_sdk_conformance(include_javascript=False)

    def _observe_sdk_conformance(self, *, include_javascript: bool) -> None:
        gateway, token, javascript_environment, runs = self._live_sdk_configuration(
            require_javascript=include_javascript
        )

        run_cache: dict[tuple[str, int, int], tuple[datetime, datetime]] = {}
        receipts: dict[str, dict[str, Any]] = {}
        for receipt_id, policy in LIVE_SDK_RECEIPTS.items():
            run_key = "react_native" if receipt_id.startswith("react_native_") else receipt_id
            run_id, run_attempt = runs[run_key]
            coordinate = self.identity["repositories"][policy["repository_id"]]
            cache_key = (policy["repository"], run_id, run_attempt)
            if cache_key not in run_cache:
                metadata = (
                    self._load_live_sdk_authority(f"{run_key.replace('_', '-')}-run.json")
                    if self.live_sdk_authority is not None
                    else self._github_api(
                        f"repos/{policy['repository']}/actions/runs/{run_id}/attempts/{run_attempt}",
                        token,
                    )
                )
                run_cache[cache_key] = self._validate_sdk_run_metadata(
                    metadata,
                    repository=policy["repository"],
                    workflow=policy["workflow"],
                    commit=coordinate["commit"],
                    run_id=run_id,
                    run_attempt=run_attempt,
                    candidate_created=self.candidate_created,
                    now=self.now,
                )
            workflow_started, workflow_finished = run_cache[cache_key]
            artifact_name = (
                f"{policy['artifact_prefix']}-{run_id}-{run_attempt}"
            )
            artifact = (
                self._load_live_sdk_authority(f"{receipt_id.replace('_', '-')}-artifact.json")
                if self.live_sdk_authority is not None
                else self._github_api(
                    f"repos/{policy['repository']}/actions/runs/{run_id}/artifacts"
                    f"?name={artifact_name}&per_page=100",
                    token,
                )
            )
            self._validate_sdk_artifact_metadata(
                artifact,
                repository=policy["repository"],
                commit=coordinate["commit"],
                run_id=run_id,
                name=artifact_name,
            )
            receipt = self._load_physical_receipt(
                self.live_sdk_receipts[receipt_id], policy
            )
            if self.live_sdk_authority is not None:
                self._validate_physical_attestation_authority(receipt_id, policy)
            else:
                self._verify_physical_attestations(
                    receipt,
                    policy=policy,
                    commit=coordinate["commit"],
                    token=token,
                )
            self._rerun_physical_validator(
                receipt,
                policy=policy,
                commit=coordinate["commit"],
                expected_run=f"{policy['run_prefix']}-{run_id}-{run_attempt}",
            )
            profile, evidence, summary, started, finished = (
                self._validate_physical_receipt(
                    receipt,
                    policy=policy,
                    gateway=gateway,
                    run_id=run_id,
                    run_attempt=run_attempt,
                    artifact_name=artifact_name,
                    workflow_started=workflow_started,
                    workflow_finished=workflow_finished,
                )
            )
            self._rerun_gateway_deployment_validator(
                receipt,
                policy=policy,
                profile=profile,
            )
            receipts[receipt_id] = {
                "receipt": receipt,
                "profile": profile,
                "evidence": evidence,
                "summary": summary,
                "started": started,
                "finished": finished,
            }

        self._validate_common_gateway_binding(
            receipts,
            gateway,
            javascript_environment if include_javascript else None,
        )
        self._validate_react_native_links(receipts)
        platform_records = {}
        for receipt_id, item in receipts.items():
            policy = LIVE_SDK_RECEIPTS[receipt_id]
            platform_records[policy["observation"]] = {
                "summary": item["summary"],
                "started": item["started"],
                "finished": item["finished"],
                "version": self.identity["repositories"][policy["repository_id"]][
                    "version"
                ],
                "invocation": (
                    "python3",
                    "scripts/device-evidence.py",
                    "verify",
                    policy["profile"],
                    policy["evidence"],
                ),
                "cwd": self.repositories[policy["repository_id"]],
                # Retain the exact, already secret-scanned physical receipt
                # bytes as hash-bound machine-result inputs. Actions artifacts
                # are transport, not the durable release record.
                "retained_inputs": item["receipt"]["payloads"],
            }

        if include_javascript:
            javascript_isolations: dict[str, dict[str, Any]] = {}
            for provider, provider_policy in LIVE_SDK_JAVASCRIPT_PROVIDERS.items():
                (
                    javascript_payload,
                    javascript_started,
                    javascript_finished,
                    javascript_isolation,
                ) = self._load_javascript_capture(
                    provider,
                    gateway=gateway,
                    environment=javascript_environment[
                        "LATCHWAY_LIVE_SDK_ENVIRONMENT"
                    ],
                )
                javascript_report = self._validate_javascript_report(
                    javascript_payload,
                    self.identity,
                    gateway,
                    expected_provider=provider,
                )
                javascript_summary = self._platform_summary(
                    platform="javascript",
                    repository="Latchway/latchway-js",
                    workflow="scripts/live-conformance.mjs",
                    run_id=None,
                    run_attempt=None,
                    artifact_name=None,
                    profile=None,
                    evidence=javascript_report,
                    receipt_hashes={},
                    attestation_provider=provider,
                )
                platform_records[provider_policy["observation"]] = {
                    "summary": javascript_summary,
                    "started": javascript_started,
                    "finished": javascript_finished,
                    "version": self.identity["repositories"]["javascript"]["version"],
                    "invocation": (
                        "latchway-live-sdk-collector",
                        "validate-isolation",
                        provider,
                    ),
                    "cwd": self.repositories["javascript"],
                    "retained_inputs": javascript_isolation["payloads"],
                    "retained_input_kind": "live_sdk_collector_isolation",
                }
                javascript_isolations[provider] = javascript_isolation
            self._validate_javascript_isolation_pair(javascript_isolations)

        for observation, item in platform_records.items():
            self.emit(
                observation,
                canonical_json(item["summary"]),
                started=item["started"],
                finished=item["finished"],
                version=item["version"],
                invocation=item["invocation"],
                cwd=item["cwd"],
                retained_inputs=item.get("retained_inputs"),
                retained_input_kind=item.get(
                    "retained_input_kind", "physical_device_receipt"
                ),
            )

        if not include_javascript:
            return

        earliest = min(item["started"] for item in platform_records.values())
        latest = max(item["finished"] for item in platform_records.values())
        platform_summaries = [
            platform_records[observation]["summary"]
            for observation in sorted(platform_records)
        ]
        for observation, behavior in SDK_BEHAVIOR_KEYS.items():
            payload = self._behavior_summary(
                behavior, platform_summaries, self.identity
            )
            self.emit(
                observation,
                canonical_json(payload),
                started=earliest,
                finished=latest,
                version="1.0.0",
                invocation=("latchway-live-sdk-harness", "derive", behavior),
            )

    def _live_sdk_configuration(
        self, *, require_javascript: bool,
    ) -> tuple[str, str, dict[str, str], dict[str, tuple[int, int]]]:
        # Some unit fixtures construct a deliberately bare observer without
        # invoking __init__. Preserve the online defaults for those fixtures.
        if not hasattr(self, "live_sdk_authority"):
            self.live_sdk_authority = None
        if not hasattr(self, "javascript_captures"):
            self.javascript_captures = {}
        if any(os.environ.get(name) for name in LIVE_SDK_LEGACY_CREDENTIAL_ENV):
            raise ObservationError("live_sdk_javascript_credentials_present")
        if (
            set(self.live_sdk_receipts) != set(LIVE_SDK_RECEIPTS)
            or set(self.live_sdk_runs) != {"ios", "android", "react_native"}
        ):
            raise ObservationError("live_sdk_receipt_configuration_missing")
        for path in self.live_sdk_receipts.values():
            if not path.is_absolute() or not path.is_dir() or path.is_symlink():
                raise ObservationError("live_sdk_receipt_directory_invalid")
        parsed_runs: dict[str, tuple[int, int]] = {}
        for name, values in self.live_sdk_runs.items():
            if (
                not isinstance(values, tuple)
                or len(values) != 2
                or not isinstance(values[0], str)
                or not isinstance(values[1], str)
                or EVIDENCE.RUN_ID.fullmatch(values[0]) is None
                or re.fullmatch(r"[1-9][0-9]{0,5}", values[1]) is None
            ):
                raise ObservationError("live_sdk_run_identity_invalid")
            parsed_runs[name] = (int(values[0]), int(values[1]))

        if self.live_sdk_authority is not None:
            self._validate_live_sdk_authority_directory()
        required = {"LATCHWAY_BASE_URL"}
        if self.live_sdk_authority is None:
            required.add("GH_TOKEN")
        if require_javascript:
            required |= set(LIVE_SDK_JAVASCRIPT_CONFIGURATION_KEYS)
        if require_javascript and set(self.javascript_captures) != set(LIVE_SDK_JAVASCRIPT_PROVIDERS):
            raise ObservationError("live_sdk_javascript_capture_configuration_invalid")
        if not require_javascript and self.javascript_captures:
            raise ObservationError("live_sdk_javascript_capture_configuration_invalid")
        if any(not os.environ.get(name) for name in required):
            raise ObservationError("live_sdk_configuration_missing")
        gateway = os.environ["LATCHWAY_BASE_URL"].rstrip("/")
        parsed = urlsplit(gateway)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ObservationError("live_sdk_gateway_invalid")
        if require_javascript:
            javascript_environment = {
                key: os.environ[key]
                for key in sorted(LIVE_SDK_JAVASCRIPT_CONFIGURATION_KEYS)
            }
        else:
            javascript_environment = {}
        return gateway, os.environ.get("GH_TOKEN", ""), javascript_environment, parsed_runs

    @staticmethod
    def _physical_authority_files() -> set[str]:
        files = {"ios-run.json", "android-run.json", "react-native-run.json"}
        for receipt_id, policy in LIVE_SDK_RECEIPTS.items():
            slug = receipt_id.replace("_", "-")
            files.add(f"{slug}-artifact.json")
            for subject in (policy["profile"], policy["evidence"], "SHA256SUMS"):
                subject_slug = subject.lower().replace(".", "-")
                files.add(f"{slug}-{subject_slug}-attestation.json")
        return files

    def _validate_live_sdk_authority_directory(self) -> None:
        root = self.live_sdk_authority
        if root is None:
            return
        if not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ObservationError("live_sdk_authority_directory_invalid")
        try:
            children = list(root.iterdir())
        except OSError:
            raise ObservationError("live_sdk_authority_directory_invalid") from None
        if (
            {child.name for child in children} != self._physical_authority_files()
            or any(not child.is_file() or child.is_symlink() for child in children)
        ):
            raise ObservationError("live_sdk_authority_file_set_invalid")

    def _load_live_sdk_authority(self, name: str) -> Any:
        root = self.live_sdk_authority
        if root is None or name not in self._physical_authority_files():
            raise ObservationError("live_sdk_authority_file_invalid")
        try:
            payload = EVIDENCE.read_bytes(root / name, EVIDENCE.MAXIMUM_RESULT_BYTES)
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_sdk_authority_file_invalid") from None
        return load_output(payload, "live_sdk_authority_file_invalid")

    def _validate_physical_attestation_authority(
        self, receipt_id: str, policy: Mapping[str, Any]
    ) -> None:
        slug = receipt_id.replace("_", "-")
        for subject in (policy["profile"], policy["evidence"], "SHA256SUMS"):
            subject_slug = subject.lower().replace(".", "-")
            result = self._load_live_sdk_authority(
                f"{slug}-{subject_slug}-attestation.json"
            )
            if not isinstance(result, list) or not result:
                raise ObservationError("live_sdk_attestation_invalid")

    def _load_javascript_capture(
        self,
        provider: str,
        *,
        gateway: str,
        environment: str,
    ) -> tuple[bytes, datetime, datetime, dict[str, Any]]:
        path = self.javascript_captures.get(provider)
        if (
            provider not in LIVE_SDK_JAVASCRIPT_PROVIDERS
            or path is None
            or not path.is_absolute()
            or not path.is_file()
            or path.is_symlink()
        ):
            raise ObservationError("live_sdk_javascript_capture_invalid")
        try:
            capture_payload = EVIDENCE.read_bytes(
                path, EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            value = load_output(
                capture_payload,
                "live_sdk_javascript_capture_invalid",
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_sdk_javascript_capture_invalid") from None
        if (
            not isinstance(value, dict)
            or set(value) != {
                "schema_version",
                "kind",
                "attestation_provider",
                "started_at",
                "finished_at",
                "report",
                "collector_isolation",
            }
            or value.get("schema_version") != 1
            or isinstance(value.get("schema_version"), bool)
            or value.get("kind") != "latchway_live_javascript_capture"
            or value.get("attestation_provider") != provider
            or not isinstance(value.get("report"), dict)
            or not isinstance(value.get("collector_isolation"), dict)
        ):
            raise ObservationError("live_sdk_javascript_capture_invalid")
        try:
            started = EVIDENCE.parse_time(
                value.get("started_at"), "live_sdk_javascript_capture_invalid"
            )
            finished = EVIDENCE.parse_time(
                value.get("finished_at"), "live_sdk_javascript_capture_invalid"
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_sdk_javascript_capture_invalid") from None
        if (
            started < self.candidate_created
            or started >= finished
            or finished > self.now
            or self.now - finished > EVIDENCE.MAXIMUM_AGE
            or finished - started > EVIDENCE.timedelta(minutes=30)
        ):
            raise ObservationError("live_sdk_javascript_capture_invalid")
        isolation = self._validate_javascript_isolation(
            path=path,
            provider=provider,
            capture=value,
            capture_payload=capture_payload,
            started=started,
            finished=finished,
            gateway=gateway,
            environment=environment,
        )
        return canonical_json(value["report"]), started, finished, isolation

    def _validate_javascript_isolation(
        self,
        *,
        path: Path,
        provider: str,
        capture: Mapping[str, Any],
        capture_payload: bytes,
        started: datetime,
        finished: datetime,
        gateway: str,
        environment: str,
    ) -> dict[str, Any]:
        code = "live_sdk_javascript_isolation_invalid"
        policy = LIVE_SDK_JAVASCRIPT_PROVIDERS[provider]
        root = path.parent / f"{provider}-isolation"
        if not root.is_dir() or root.is_symlink():
            raise ObservationError(code)
        try:
            children = list(root.iterdir())
        except OSError:
            raise ObservationError(code) from None
        if (
            {child.name for child in children} != LIVE_SDK_ISOLATION_FILES
            or any(not child.is_file() or child.is_symlink() for child in children)
        ):
            raise ObservationError(code)

        payloads: dict[str, bytes] = {}
        total = 0
        for child in children:
            maximum = (
                16 * 1024
                if child.name in LIVE_SDK_ISOLATION_SIGNATURES
                else EVIDENCE.MAXIMUM_RESULT_BYTES
            )
            try:
                payload = EVIDENCE.read_bytes(child, maximum)
                if child.name not in LIVE_SDK_ISOLATION_SIGNATURES:
                    EVIDENCE.scan_safe(payload)
            except EVIDENCE.EvidenceError:
                raise ObservationError(code) from None
            total += len(payload)
            if total > EVIDENCE.MAXIMUM_DOMAIN_BYTES:
                raise ObservationError(code)
            payloads[child.name] = payload

        checksum_payload = payloads["ISOLATION_SHA256SUMS"]
        try:
            checksum_text = checksum_payload.decode("ascii")
        except UnicodeDecodeError:
            raise ObservationError(code) from None
        if not checksum_text.endswith("\n"):
            raise ObservationError(code)
        checksums: dict[str, str] = {}
        for line in checksum_text.splitlines():
            match = re.fullmatch(
                r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})",
                line,
            )
            if match is None or match.group(2) in checksums:
                raise ObservationError(code)
            checksums[match.group(2)] = match.group(1)
        if tuple(checksums) != LIVE_SDK_ISOLATION_SUBJECTS:
            raise ObservationError(code)
        if any(
            hashlib.sha256(payloads[name]).hexdigest() != digest
            for name, digest in checksums.items()
        ):
            raise ObservationError(code)

        values = {
            name: load_output(payloads[name], code)
            for name in (
                "collector-lease.json",
                "collector-teardown.json",
                "execution.json",
                "gateway-consumption-receipt.json",
                "harness-manifest.json",
                "report.json",
            )
        }
        lease = values["collector-lease.json"]
        teardown = values["collector-teardown.json"]
        execution = values["execution.json"]
        receipt = values["gateway-consumption-receipt.json"]
        harness = values["harness-manifest.json"]
        report = values["report.json"]
        collector = capture["collector_isolation"]
        identity = self.identity
        core_commit = identity["core_commit"]
        javascript_commit = identity["repositories"]["javascript"]["commit"]

        if (
            set(collector)
            != {
                "schema_version",
                "lease_sha256",
                "teardown_sha256",
                "gateway_receipt_sha256",
                "harness_manifest_sha256",
                "report_sha256",
            }
            or collector.get("schema_version")
            != "latchway.live-sdk-collector-isolation.v1"
            or collector.get("lease_sha256")
            != hashlib.sha256(payloads["collector-lease.json"]).hexdigest()
            or collector.get("teardown_sha256")
            != hashlib.sha256(payloads["collector-teardown.json"]).hexdigest()
            or collector.get("gateway_receipt_sha256")
            != hashlib.sha256(
                payloads["gateway-consumption-receipt.json"]
            ).hexdigest()
            or collector.get("harness_manifest_sha256")
            != hashlib.sha256(payloads["harness-manifest.json"]).hexdigest()
            or collector.get("report_sha256")
            != hashlib.sha256(payloads["report.json"]).hexdigest()
            or report != capture["report"]
        ):
            raise ObservationError(code)

        if (
            not isinstance(execution, dict)
            or set(execution) != {"started_at_unix", "finished_at_unix"}
            or any(
                not isinstance(execution.get(name), int)
                or isinstance(execution.get(name), bool)
                for name in ("started_at_unix", "finished_at_unix")
            )
        ):
            raise ObservationError(code)
        execution_started = execution["started_at_unix"]
        execution_finished = execution["finished_at_unix"]
        try:
            execution_started_time = datetime.fromtimestamp(
                execution_started, tz=timezone.utc
            )
            execution_finished_time = datetime.fromtimestamp(
                execution_finished, tz=timezone.utc
            )
        except (OverflowError, OSError, ValueError):
            raise ObservationError(code) from None
        if (
            execution_started >= execution_finished
            or execution_started_time != started
            or execution_finished_time != finished
            or capture.get("started_at") != EVIDENCE.format_time(started)
            or capture.get("finished_at") != EVIDENCE.format_time(finished)
        ):
            raise ObservationError(code)

        workflow = lease.get("workflow") if isinstance(lease, dict) else None
        runner = lease.get("runner") if isinstance(lease, dict) else None
        grant = lease.get("grant") if isinstance(lease, dict) else None
        candidate = lease.get("candidate") if isinstance(lease, dict) else None
        lease_gateway = lease.get("gateway") if isinstance(lease, dict) else None
        if (
            not isinstance(lease, dict)
            or set(lease)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "javascript_commit",
                "workflow",
                "runner",
                "credentials",
                "supervisor",
                "grant",
                "candidate",
                "gateway",
                "issued_at_unix",
                "expires_at_unix",
            }
            or lease.get("schema_version")
            != "latchway.live-sdk-collector-lease.v1"
            or lease.get("repository") != EVIDENCE.REPOSITORY
            or lease.get("core_commit") != core_commit
            or lease.get("javascript_commit") != javascript_commit
            or not isinstance(workflow, dict)
            or set(workflow) != {"run_id", "run_attempt", "job", "audience"}
            or EVIDENCE.RUN_ID.fullmatch(str(workflow.get("run_id"))) is None
            or re.fullmatch(r"[1-9][0-9]{0,5}", str(workflow.get("run_attempt")))
            is None
            or workflow.get("job") != "javascript_collect"
            or workflow.get("audience") != policy["audience"]
            or not isinstance(workflow.get("run_id"), str)
            or not isinstance(workflow.get("run_attempt"), str)
            or not isinstance(runner, dict)
            or set(runner)
            != {
                "name",
                "ephemeral",
                "jit",
                "max_jobs",
                "fresh_boot",
                "clean_workspace",
                "repository_scope",
                "destroy_after_job",
                "image_digest",
                "boot_id_sha256",
            }
            or runner.get("name")
            != (
                f"latchway-live-sdk-{policy['runner_slug']}-"
                f"{workflow.get('run_id')}-{workflow.get('run_attempt')}"
            )
            or runner.get("ephemeral") is not True
            or runner.get("jit") is not True
            or not isinstance(runner.get("max_jobs"), int)
            or isinstance(runner.get("max_jobs"), bool)
            or runner.get("max_jobs") != 1
            or runner.get("fresh_boot") is not True
            or runner.get("clean_workspace") is not True
            or runner.get("repository_scope") != EVIDENCE.REPOSITORY
            or runner.get("destroy_after_job") is not True
            or not isinstance(runner.get("image_digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", runner["image_digest"])
            is None
            or not isinstance(runner.get("boot_id_sha256"), str)
            or EVIDENCE.SHA256.fullmatch(runner["boot_id_sha256"]) is None
            or not isinstance(lease.get("credentials"), dict)
            or set(lease["credentials"])
            != {
                "long_lived",
                "organization",
                "administration",
                "registry",
                "oidc",
            }
            or any(value is not False for value in lease["credentials"].values())
            or not isinstance(lease.get("supervisor"), dict)
            or set(lease["supervisor"])
            != {
                "private_key_isolated",
                "caller_supplied_claims_accepted",
                "gateway_egress_only",
                "dns_pinned",
                "tls_verified",
                "gateway_run_receipt_verification",
                "one_use_invocation",
            }
            or lease["supervisor"].get("private_key_isolated") is not True
            or lease["supervisor"].get("caller_supplied_claims_accepted")
            is not False
            or any(
                lease["supervisor"].get(name) is not True
                for name in (
                    "gateway_egress_only",
                    "dns_pinned",
                    "tls_verified",
                    "gateway_run_receipt_verification",
                    "one_use_invocation",
                )
            )
            or not isinstance(grant, dict)
            or set(grant)
            != {
                "audience",
                "core_commit",
                "javascript_commit",
                "run_id",
                "run_attempt",
                "provider",
                "sha256",
                "single_use",
                "jti_sha256",
                "request_sha256",
            }
            or grant.get("audience") != f"latchway-live-sdk/{provider}"
            or grant.get("core_commit") != core_commit
            or grant.get("javascript_commit") != javascript_commit
            or grant.get("run_id") != workflow.get("run_id")
            or grant.get("run_attempt") != workflow.get("run_attempt")
            or grant.get("provider") != provider
            or grant.get("single_use") is not True
            or not isinstance(grant.get("sha256"), str)
            or EVIDENCE.SHA256.fullmatch(grant["sha256"]) is None
            or not isinstance(grant.get("jti_sha256"), str)
            or EVIDENCE.SHA256.fullmatch(grant["jti_sha256"]) is None
            or not isinstance(grant.get("request_sha256"), str)
            or EVIDENCE.SHA256.fullmatch(grant["request_sha256"]) is None
            or not isinstance(candidate, dict)
            or set(candidate)
            != {
                "harness_archive_sha256",
                "harness_manifest_sha256",
                "source_report_sha256",
                "candidate_manifest_sha256",
            }
            or not isinstance(candidate.get("harness_archive_sha256"), str)
            or EVIDENCE.SHA256.fullmatch(candidate["harness_archive_sha256"])
            is None
            or candidate.get("harness_manifest_sha256")
            != hashlib.sha256(payloads["harness-manifest.json"]).hexdigest()
            or candidate.get("source_report_sha256")
            != self.input_hashes["source"]
            or candidate.get("candidate_manifest_sha256")
            != self.input_hashes["candidate"]
            or not isinstance(lease_gateway, dict)
            or set(lease_gateway) != {"origin", "application_id", "environment"}
            or lease_gateway.get("origin") != gateway
            or lease_gateway.get("environment") != environment
            or not isinstance(lease_gateway.get("application_id"), str)
            or not 1 <= len(lease_gateway["application_id"]) <= 256
            or any(character.isspace() for character in lease_gateway["application_id"])
            or not isinstance(lease.get("issued_at_unix"), int)
            or isinstance(lease.get("issued_at_unix"), bool)
            or not isinstance(lease.get("expires_at_unix"), int)
            or isinstance(lease.get("expires_at_unix"), bool)
            or lease["issued_at_unix"]
            < int(self.candidate_created.timestamp())
            or lease["issued_at_unix"] > execution_started
            or lease["expires_at_unix"] < execution_started
            or not 1 <= lease["expires_at_unix"] - lease["issued_at_unix"] <= 300
        ):
            raise ObservationError(code)

        harness_workflow = harness.get("workflow") if isinstance(harness, dict) else None
        if (
            not isinstance(harness, dict)
            or set(harness)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "javascript_commit",
                "workflow",
                "source_archive_sha256",
                "harness_archive_sha256",
                "harness_bytes",
            }
            or harness.get("schema_version") != "latchway.live-sdk-harness.v1"
            or harness.get("repository") != "Latchway/latchway-js"
            or harness.get("core_commit") != core_commit
            or harness.get("javascript_commit") != javascript_commit
            or harness_workflow
            != {
                "run_id": workflow["run_id"],
                "run_attempt": workflow["run_attempt"],
            }
            or not isinstance(harness.get("source_archive_sha256"), str)
            or EVIDENCE.SHA256.fullmatch(harness["source_archive_sha256"]) is None
            or harness.get("harness_archive_sha256")
            != candidate["harness_archive_sha256"]
            or not isinstance(harness.get("harness_bytes"), int)
            or isinstance(harness.get("harness_bytes"), bool)
            or not 1 <= harness["harness_bytes"] <= 512 * 1024 * 1024
        ):
            raise ObservationError(code)

        if (
            not isinstance(receipt, dict)
            or set(receipt)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "javascript_commit",
                "run_id",
                "run_attempt",
                "provider",
                "grant_sha256",
                "jti_sha256",
                "single_use",
                "consumption_count",
                "consumed",
                "report_sha256",
                "request_sha256",
                "consumed_at_unix",
            }
            or receipt.get("schema_version")
            != "latchway.live-sdk-gateway-consumption.v1"
            or receipt.get("repository") != EVIDENCE.REPOSITORY
            or receipt.get("core_commit") != core_commit
            or receipt.get("javascript_commit") != javascript_commit
            or receipt.get("run_id") != workflow["run_id"]
            or receipt.get("run_attempt") != workflow["run_attempt"]
            or receipt.get("provider") != provider
            or receipt.get("grant_sha256") != grant["sha256"]
            or receipt.get("jti_sha256") != grant["jti_sha256"]
            or receipt.get("single_use") is not True
            or not isinstance(receipt.get("consumption_count"), int)
            or isinstance(receipt.get("consumption_count"), bool)
            or receipt.get("consumption_count") != 1
            or receipt.get("consumed") is not True
            or receipt.get("report_sha256") != collector["report_sha256"]
            or receipt.get("request_sha256") != grant["request_sha256"]
            or not isinstance(receipt.get("consumed_at_unix"), int)
            or isinstance(receipt.get("consumed_at_unix"), bool)
            or not execution_started
            <= receipt["consumed_at_unix"]
            <= execution_finished
        ):
            raise ObservationError(code)

        teardown_workflow = (
            teardown.get("workflow") if isinstance(teardown, dict) else None
        )
        teardown_runner = teardown.get("runner") if isinstance(teardown, dict) else None
        if (
            not isinstance(teardown, dict)
            or set(teardown)
            != {
                "schema_version",
                "repository",
                "core_commit",
                "javascript_commit",
                "workflow",
                "provider",
                "runner",
                "grant",
                "network",
                "gateway_receipt_verified",
                "evidence_eligible",
                "lease_sha256",
                "gateway_receipt_sha256",
                "report_sha256",
            }
            or teardown.get("schema_version")
            != "latchway.live-sdk-collector-teardown.v1"
            or teardown.get("repository") != EVIDENCE.REPOSITORY
            or teardown.get("core_commit") != core_commit
            or teardown.get("javascript_commit") != javascript_commit
            or teardown_workflow != workflow
            or teardown.get("provider") != provider
            or not isinstance(teardown_runner, dict)
            or set(teardown_runner)
            != {
                "name",
                "deregistered",
                "accepts_more_jobs",
                "destroy_scheduled",
                "destroy_deadline_unix",
            }
            or teardown_runner.get("name") != runner["name"]
            or teardown_runner.get("deregistered") is not True
            or teardown_runner.get("accepts_more_jobs") is not False
            or teardown_runner.get("destroy_scheduled") is not True
            or not isinstance(teardown_runner.get("destroy_deadline_unix"), int)
            or isinstance(teardown_runner.get("destroy_deadline_unix"), bool)
            or not execution_finished
            <= teardown_runner["destroy_deadline_unix"]
            <= execution_finished + 600
            or not isinstance(teardown.get("grant"), dict)
            or set(teardown["grant"])
            != {"single_use", "consumption_count", "zeroized", "revoked"}
            or teardown["grant"].get("single_use") is not True
            or not isinstance(teardown["grant"].get("consumption_count"), int)
            or isinstance(teardown["grant"].get("consumption_count"), bool)
            or teardown["grant"].get("consumption_count") != 1
            or teardown["grant"].get("zeroized") is not True
            or teardown["grant"].get("revoked") is not True
            or not isinstance(teardown.get("network"), dict)
            or set(teardown["network"])
            != {"gateway_egress_only", "dns_pinned", "tls_verified"}
            or any(value is not True for value in teardown["network"].values())
            or teardown.get("gateway_receipt_verified") is not True
            or teardown.get("evidence_eligible") is not True
            or teardown.get("lease_sha256") != collector["lease_sha256"]
            or teardown.get("gateway_receipt_sha256")
            != collector["gateway_receipt_sha256"]
            or teardown.get("report_sha256") != collector["report_sha256"]
        ):
            raise ObservationError(code)

        public_key = payloads["gateway-receipt-public-key.pem"]
        try:
            public_key_text = public_key.decode("ascii")
        except UnicodeDecodeError:
            raise ObservationError(code) from None
        if (
            "PRIVATE KEY" in public_key_text
            or re.fullmatch(
                r"-----BEGIN PUBLIC KEY-----\n"
                r"[A-Za-z0-9+/=\n]+"
                r"-----END PUBLIC KEY-----\n?",
                public_key_text,
            )
            is None
        ):
            raise ObservationError(code)

        retained = {"capture.json": capture_payload, **payloads}
        return {
            "payloads": retained,
            "workflow": (workflow["run_id"], workflow["run_attempt"]),
            "grant_sha256": grant["sha256"],
            "jti_sha256": grant["jti_sha256"],
            "runner_name": runner["name"],
            "harness_manifest": payloads["harness-manifest.json"],
            "gateway_public_key": public_key,
        }

    @staticmethod
    def _validate_javascript_isolation_pair(
        isolations: Mapping[str, Mapping[str, Any]],
    ) -> None:
        if set(isolations) != set(LIVE_SDK_JAVASCRIPT_PROVIDERS):
            raise ObservationError("live_sdk_javascript_isolation_pair_invalid")
        firebase = isolations["firebase_app_check"]
        turnstile = isolations["turnstile"]
        if (
            firebase.get("workflow") != turnstile.get("workflow")
            or firebase.get("harness_manifest")
            != turnstile.get("harness_manifest")
            or firebase.get("gateway_public_key")
            != turnstile.get("gateway_public_key")
            or firebase.get("grant_sha256") == turnstile.get("grant_sha256")
            or firebase.get("jti_sha256") == turnstile.get("jti_sha256")
            or firebase.get("runner_name") == turnstile.get("runner_name")
        ):
            raise ObservationError("live_sdk_javascript_isolation_pair_invalid")

    def _github_api(self, endpoint: str, token: str) -> Any:
        payload, _, _ = self._execute_command(
            (
                "gh",
                "api",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "X-GitHub-Api-Version: 2022-11-28",
                endpoint,
            ),
            environment={"GH_TOKEN": token},
            timeout=60,
        )
        return load_output(payload, "live_sdk_github_metadata_invalid")

    @staticmethod
    def _validate_sdk_run_metadata(
        value: Any,
        *,
        repository: str,
        workflow: str,
        commit: str,
        run_id: int,
        run_attempt: int,
        candidate_created: datetime,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), int)
            or isinstance(value.get("id"), bool)
            or value["id"] != run_id
            or not isinstance(value.get("run_attempt"), int)
            or isinstance(value.get("run_attempt"), bool)
            or value["run_attempt"] != run_attempt
            or value.get("event") != "workflow_dispatch"
            or value.get("status") != "completed"
            or value.get("conclusion") != "success"
            or value.get("head_sha") != commit
            or value.get("head_branch") != "main"
            or value.get("path") != workflow
            or nested(value, "repository", "full_name") != repository
            or nested(value, "head_repository", "full_name") != repository
        ):
            raise ObservationError("live_sdk_run_metadata_invalid")
        try:
            created = EVIDENCE.parse_time(
                value.get("created_at"), "live_sdk_run_metadata_invalid"
            )
            started = EVIDENCE.parse_time(
                value.get("run_started_at"), "live_sdk_run_metadata_invalid"
            )
            finished = EVIDENCE.parse_time(
                value.get("updated_at"), "live_sdk_run_metadata_invalid"
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_sdk_run_metadata_invalid") from None
        if (
            created < candidate_created
            or created > started
            or started >= finished
            or finished > now
            or now - finished > EVIDENCE.MAXIMUM_AGE
            or finished - started > EVIDENCE.timedelta(hours=2)
        ):
            raise ObservationError("live_sdk_run_metadata_invalid")
        return started, finished

    @staticmethod
    def _validate_sdk_artifact_metadata(
        value: Any,
        *,
        repository: str,
        commit: str,
        run_id: int,
        name: str,
    ) -> None:
        artifacts = value.get("artifacts") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("total_count"), int)
            or isinstance(value.get("total_count"), bool)
            or value["total_count"] != 1
            or not isinstance(artifacts, list)
            or len(artifacts) != 1
        ):
            raise ObservationError("live_sdk_artifact_metadata_invalid")
        artifact = artifacts[0]
        download = artifact.get("archive_download_url") if isinstance(artifact, dict) else None
        if (
            not isinstance(artifact, dict)
            or artifact.get("name") != name
            or artifact.get("expired") is not False
            or not isinstance(artifact.get("id"), int)
            or isinstance(artifact.get("id"), bool)
            or artifact["id"] < 1
            or not isinstance(artifact.get("size_in_bytes"), int)
            or isinstance(artifact.get("size_in_bytes"), bool)
            or not 1 <= artifact["size_in_bytes"] <= EVIDENCE.MAXIMUM_DOMAIN_BYTES
            or not isinstance(nested(artifact, "workflow_run", "id"), int)
            or isinstance(nested(artifact, "workflow_run", "id"), bool)
            or nested(artifact, "workflow_run", "id") != run_id
            or nested(artifact, "workflow_run", "head_sha") != commit
            or not isinstance(download, str)
            or download
            != (
                f"https://api.github.com/repos/{repository}/actions/artifacts/"
                f"{artifact['id']}/zip"
            )
        ):
            raise ObservationError("live_sdk_artifact_metadata_invalid")

    @staticmethod
    def _parse_checksum_manifest(payload: bytes, expected: set[str]) -> dict[str, str]:
        EVIDENCE.scan_safe(payload)
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            raise ObservationError("live_sdk_checksum_manifest_invalid") from None
        if not text.endswith("\n"):
            raise ObservationError("live_sdk_checksum_manifest_invalid")
        checksums: dict[str, str] = {}
        for line in text.splitlines():
            match = re.fullmatch(
                r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})", line
            )
            if match is None or match.group(2) in checksums:
                raise ObservationError("live_sdk_checksum_manifest_invalid")
            checksums[match.group(2)] = match.group(1)
        if set(checksums) != expected:
            raise ObservationError("live_sdk_checksum_manifest_invalid")
        return checksums

    def _load_physical_receipt(
        self, root: Path, policy: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected_manifest = set(policy["manifest"])
        expected_files = expected_manifest | {
            "SHA256SUMS",
            "github-attestation.sigstore.json",
        }
        try:
            children = list(root.iterdir())
        except OSError:
            raise ObservationError("live_sdk_receipt_directory_invalid") from None
        if {child.name for child in children} != expected_files:
            raise ObservationError("live_sdk_receipt_file_set_invalid")
        payloads: dict[str, bytes] = {}
        total_bytes = 0
        for child in children:
            try:
                child.relative_to(root)
            except ValueError:
                raise ObservationError("live_sdk_receipt_file_invalid") from None
            try:
                payload = EVIDENCE.read_bytes(child, EVIDENCE.MAXIMUM_RAW_BYTES)
                EVIDENCE.scan_safe(payload)
            except EVIDENCE.EvidenceError:
                raise ObservationError("live_sdk_receipt_file_invalid") from None
            total_bytes += len(payload)
            if total_bytes > EVIDENCE.MAXIMUM_DOMAIN_BYTES:
                raise ObservationError("live_sdk_receipt_file_invalid")
            payloads[child.name] = payload
        checksums = self._parse_checksum_manifest(
            payloads["SHA256SUMS"], expected_manifest
        )
        for name, expected in checksums.items():
            if hashlib.sha256(payloads[name]).hexdigest() != expected:
                raise ObservationError("live_sdk_receipt_checksum_mismatch")
        return {
            "root": root,
            "payloads": payloads,
            "checksums": checksums,
            "initial_hashes": {
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in payloads.items()
            },
        }

    def _verify_physical_attestations(
        self,
        receipt: Mapping[str, Any],
        *,
        policy: Mapping[str, Any],
        commit: str,
        token: str,
    ) -> None:
        root = receipt["root"]
        bundle = root / "github-attestation.sigstore.json"
        for subject_name in (policy["profile"], policy["evidence"], "SHA256SUMS"):
            payload, _, _ = self._execute_command(
                (
                    "gh",
                    "attestation",
                    "verify",
                    str(root / subject_name),
                    "--bundle",
                    str(bundle),
                    "--repo",
                    policy["repository"],
                    "--signer-workflow",
                    f"{policy['repository']}/{policy['workflow']}",
                    "--source-digest",
                    commit,
                    "--signer-digest",
                    commit,
                    "--source-ref",
                    "refs/heads/main",
                    "--format",
                    "json",
                ),
                environment={"GH_TOKEN": token},
                timeout=120,
            )
            result = load_output(payload, "live_sdk_attestation_invalid")
            if not isinstance(result, list) or not result:
                raise ObservationError("live_sdk_attestation_invalid")

    def _rerun_physical_validator(
        self,
        receipt: Mapping[str, Any],
        *,
        policy: Mapping[str, Any],
        commit: str,
        expected_run: str,
    ) -> None:
        repository = self.repositories[policy["repository_id"]]
        with tempfile.TemporaryDirectory(
            prefix="latchway-live-sdk-validator-",
            dir=os.environ.get("RUNNER_TEMP") or None,
        ) as temporary:
            temporary_root = Path(temporary)
            summary_path = temporary_root / "summary.json"
            command = (
                "python3",
                str(repository / "scripts" / "device-evidence.py"),
                "verify",
                "--schema",
                str(repository / "Conformance" / "physical-device-evidence.schema.json"),
                "--profile",
                str(receipt["root"] / policy["profile"]),
                "--evidence",
                str(receipt["root"] / policy["evidence"]),
                "--junit",
                str(temporary_root / "junit.xml"),
                "--summary",
                str(summary_path),
            )
            if "component_observation" in policy:
                command += (
                    "--component-observation",
                    str(receipt["root"] / policy["component_observation"]),
                )
            self._execute_command(
                command, cwd=repository, timeout=120
            )
            summary = load_output(
                EVIDENCE.read_bytes(summary_path),
                "live_sdk_validator_summary_invalid",
            )
            evidence_hash = hashlib.sha256(
                receipt["payloads"][policy["evidence"]]
            ).hexdigest()
            if (
                not isinstance(summary, dict)
                or summary.get("valid") is not True
                or summary.get("errors") != []
                or summary.get("platform") != policy["platform"]
                or summary.get("source_commit") != commit
                or summary.get("run_id") != expected_run
                or summary.get("evidence_sha256") != evidence_hash
            ):
                raise ObservationError("live_sdk_validator_summary_invalid")
        self._ensure_receipt_unchanged(receipt)

    def _rerun_gateway_deployment_validator(
        self,
        receipt: Mapping[str, Any],
        *,
        policy: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> None:
        repository = self.repositories[policy["repository_id"]]
        pins = profile["expected_pins"]
        root = receipt["root"]
        command = (
            "python3",
            str(repository / "scripts" / "verify-gateway-deployment.py"),
            "--statement",
            str(root / "gateway-deployment-statement.json"),
            "--signature",
            str(root / "gateway-deployment-statement.sig"),
            "--public-key",
            str(root / "gateway-deployment-public-key.pem"),
            "--public-key-sha256",
            pins["gateway_deployment_public_key_sha256"],
            "--client-policy",
            str(root / "gateway-client-policy.json"),
            "--key-id",
            pins["gateway_deployment_key_id"],
            "--gateway-origin",
            pins["gateway_origin"],
            "--environment",
            pins["gateway_environment"],
            "--core-commit",
            self.identity["core_commit"],
            "--contract-version",
            self.identity["contract_version"],
            "--contract-bundle-sha256",
            self.identity["bundle_sha256"],
            "--gateway-image-digest",
            self.candidate["image"]["index_digest"],
            "--gateway-configuration-sha256",
            pins["gateway_configuration_sha256"],
        )
        payload, _, _ = self._execute_command(
            command,
            cwd=repository,
            timeout=120,
        )
        if payload != receipt["payloads"]["gateway-deployment-verification.json"]:
            raise ObservationError("live_sdk_gateway_verification_invalid")
        self._ensure_receipt_unchanged(receipt)

    @staticmethod
    def _ensure_receipt_unchanged(receipt: Mapping[str, Any]) -> None:
        root = receipt["root"]
        try:
            names = {path.name for path in root.iterdir()}
        except OSError:
            raise ObservationError("live_sdk_receipt_changed") from None
        if names != set(receipt["initial_hashes"]):
            raise ObservationError("live_sdk_receipt_changed")
        for name, expected in receipt["initial_hashes"].items():
            try:
                actual = EVIDENCE.sha256_file(
                    root / name, EVIDENCE.MAXIMUM_RAW_BYTES
                )
            except EVIDENCE.EvidenceError:
                raise ObservationError("live_sdk_receipt_changed") from None
            if actual != expected:
                raise ObservationError("live_sdk_receipt_changed")

    def _validate_physical_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        policy: Mapping[str, Any],
        gateway: str,
        run_id: int,
        run_attempt: int,
        artifact_name: str,
        workflow_started: datetime,
        workflow_finished: datetime,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        datetime,
        datetime,
    ]:
        profile = load_output(
            receipt["payloads"][policy["profile"]],
            "live_sdk_profile_invalid",
        )
        evidence = load_output(
            receipt["payloads"][policy["evidence"]],
            "live_sdk_evidence_invalid",
        )
        coordinate = self.identity["repositories"][policy["repository_id"]]
        source = profile.get("source") if isinstance(profile, dict) else None
        expected_pins = profile.get("expected_pins") if isinstance(profile, dict) else None
        image_digest = self.candidate["image"]["index_digest"]
        expected_source = {
            "commit": coordinate["commit"],
            "core_commit": self.identity["core_commit"],
            "sdk_version": coordinate["version"],
            "contract_version": self.identity["contract_version"],
            "contract_bundle_sha256": self.identity["bundle_sha256"],
            "gateway_image_digest": image_digest,
            "gateway_origin": gateway,
        }
        if (
            not isinstance(profile, dict)
            or profile.get("platform") != policy["platform"]
            or profile.get("repository") != policy["repository"]
            or not isinstance(source, dict)
            or source.get("worktree_clean") is not True
            or any(source.get(key) != value for key, value in expected_source.items())
            or not isinstance(expected_pins, dict)
            or expected_pins.get("source_commit") != coordinate["commit"]
            or expected_pins.get("core_commit") != self.identity["core_commit"]
            or expected_pins.get("contract_bundle_sha256")
            != self.identity["bundle_sha256"]
            or expected_pins.get("gateway_image_digest") != image_digest
            or expected_pins.get("gateway_origin") != gateway
        ):
            raise ObservationError("live_sdk_profile_identity_invalid")
        expected_run = f"{policy['run_prefix']}-{run_id}-{run_attempt}"
        try:
            evidence_started = EVIDENCE.parse_time(
                nested(evidence, "run", "started_at"),
                "live_sdk_evidence_time_invalid",
            )
            evidence_finished = EVIDENCE.parse_time(
                nested(evidence, "run", "completed_at"),
                "live_sdk_evidence_time_invalid",
            )
            evidence_generated = EVIDENCE.parse_time(
                evidence.get("generated_at") if isinstance(evidence, dict) else None,
                "live_sdk_evidence_time_invalid",
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_sdk_evidence_time_invalid") from None
        if (
            workflow_started > evidence_started
            or evidence_started < self.candidate_created
            or evidence_started >= evidence_finished
            or evidence_finished > evidence_generated
            or evidence_generated > workflow_finished
            or workflow_finished > self.now
            or evidence_finished - evidence_started > EVIDENCE.timedelta(hours=2)
            or evidence_generated - evidence_finished > EVIDENCE.timedelta(hours=1)
            or self.now - workflow_finished > EVIDENCE.MAXIMUM_AGE
        ):
            raise ObservationError("live_sdk_evidence_time_invalid")
        if (
            not isinstance(evidence, dict)
            or evidence.get("platform") != policy["platform"]
            or evidence.get("release_eligible") is not True
            or evidence.get("source") != source
            or nested(evidence, "run", "id") != expected_run
            or nested(evidence, "run", "mode") != "release"
            or nested(evidence, "device", "physical") is not True
            or nested(evidence, "device", "simulator") is not False
            or nested(evidence, "device", "emulator") is not False
            or nested(evidence, "device", "testing") is not False
            or nested(evidence, "device", "debugger_attached") is not False
            or nested(evidence, "provider", "environment") != "production"
            or nested(evidence, "provider", "request_hash_bound") is not True
        ):
            raise ObservationError("live_sdk_evidence_identity_invalid")
        component_name = policy.get("component_observation")
        if component_name is not None:
            component_observation = load_output(
                receipt["payloads"][component_name],
                "live_sdk_component_observation_invalid",
            )
            self._validate_ios_component_observation(
                component_observation,
                evidence=evidence,
                expected_pins=expected_pins,
                raw_sha256=hashlib.sha256(
                    receipt["payloads"][component_name]
                ).hexdigest(),
            )
        self._validate_concrete_tests(
            evidence.get("tests"),
            expected=set(policy["tests"]),
            mapped_error_type=policy["mapped_error_type"],
            javascript=False,
        )
        summary = self._platform_summary(
            platform=policy["platform"],
            repository=policy["repository"],
            workflow=policy["workflow"],
            run_id=run_id,
            run_attempt=run_attempt,
            artifact_name=artifact_name,
            profile=profile,
            evidence=evidence,
            receipt_hashes=receipt["initial_hashes"],
        )
        return profile, evidence, summary, evidence_started, evidence_generated

    @staticmethod
    def _validate_ios_component_observation(
        value: Any,
        *,
        evidence: Mapping[str, Any],
        expected_pins: Mapping[str, Any],
        raw_sha256: str,
    ) -> None:
        required = {
            "schema_version", "platform", "run_id", "started_at", "completed_at",
            "runtime", "tests",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ObservationError("live_sdk_component_observation_invalid")
        try:
            started = EVIDENCE.parse_time(
                value["started_at"], "live_sdk_component_observation_invalid"
            )
            completed = EVIDENCE.parse_time(
                value["completed_at"], "live_sdk_component_observation_invalid"
            )
            run_started = EVIDENCE.parse_time(
                nested(evidence, "run", "started_at"),
                "live_sdk_component_observation_invalid",
            )
            run_completed = EVIDENCE.parse_time(
                nested(evidence, "run", "completed_at"),
                "live_sdk_component_observation_invalid",
            )
        except EVIDENCE.EvidenceError:
            raise ObservationError("live_sdk_component_observation_invalid") from None
        runtime = value["runtime"]
        tests = value["tests"]
        evidence_tests = [
            item for item in evidence.get("tests", [])
            if isinstance(item, dict)
            and item.get("id") in IOS_COMPONENT_TESTS
        ]
        component_tests = (
            {
                item.get("id"): item
                for item in tests
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            }
            if isinstance(tests, list)
            else {}
        )
        if (
            value["schema_version"] != IOS_COMPONENT_OBSERVATION_VERSION
            or value["platform"] != "ios_app_attest"
            or value["run_id"] != nested(evidence, "run", "id")
            or started < run_started
            or completed < started
            or completed > run_completed
            or completed - started > EVIDENCE.timedelta(hours=2)
            or runtime != evidence.get("component_runtime")
            or tests != evidence_tests
            or not isinstance(tests, list)
            or len(component_tests) != len(tests)
            or set(component_tests) != IOS_COMPONENT_TESTS
            or any(
                test.get("status") != "passed"
                for test in component_tests.values()
            )
            or nested(evidence, "artifacts", "component_observation_sha256")
            != raw_sha256
        ):
            raise ObservationError("live_sdk_component_observation_invalid")

        if not isinstance(runtime, dict) or set(runtime) != {
            "identities", "widget_delegated_execution", "share_delegated_execution",
            "delegated_execution", "sibling_denial", "keychain_sibling_denial",
            "component_refresh_race", "lifecycle",
        }:
            raise ObservationError("live_sdk_component_runtime_invalid")
        identities = runtime["identities"]
        identity_fields = {
            "role", "kind", "definition_id", "bundle_identifier", "binary_sha256",
            "attestation_mode", "principal_id_sha256", "dpop_key_id_sha256",
            "session_id_sha256",
        }
        if not isinstance(identities, list) or len(identities) != 4:
            raise ObservationError("live_sdk_component_runtime_invalid")
        by_role: dict[str, Mapping[str, Any]] = {}
        for identity in identities:
            if (
                not isinstance(identity, dict)
                or set(identity) != identity_fields
                or not isinstance(identity.get("role"), str)
                or identity["role"] in by_role
            ):
                raise ObservationError("live_sdk_component_runtime_invalid")
            by_role[identity["role"]] = identity
        role_policy = {
            "host": ("main_app", "host_bundle_identifier", "host_definition_id", "host_binary_sha256"),
            "widget": ("widget", "widget_bundle_identifier", "widget_definition_id", "widget_binary_sha256"),
            "share": ("share_extension", "share_bundle_identifier", "share_definition_id", "share_binary_sha256"),
            "action": ("action_extension", "action_bundle_identifier", "action_definition_id", "action_binary_sha256"),
        }
        if set(by_role) != set(role_policy):
            raise ObservationError("live_sdk_component_runtime_invalid")
        for role, (kind, bundle_pin, definition_pin, binary_pin) in role_policy.items():
            identity = by_role[role]
            if (
                identity["kind"] != kind
                or identity["bundle_identifier"] != expected_pins.get(bundle_pin)
                or identity["definition_id"] != expected_pins.get(definition_pin)
                or identity["binary_sha256"] != expected_pins.get(binary_pin)
                or identity["attestation_mode"]
                != ("root_app_attest" if role == "host" else "delegated_only")
                or any(
                    EVIDENCE.SHA256.fullmatch(str(identity[field])) is None
                    for field in (
                        "binary_sha256", "principal_id_sha256",
                        "dpop_key_id_sha256", "session_id_sha256",
                    )
                )
            ):
                raise ObservationError("live_sdk_component_runtime_invalid")
        for field in ("principal_id_sha256", "dpop_key_id_sha256", "session_id_sha256"):
            if len({identity[field] for identity in identities}) != 4:
                raise ObservationError("live_sdk_component_runtime_invalid")

        request_id = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
        execution_fields = {
            "role", "definition_id", "component_id_sha256", "dpop_key_id_sha256",
            "session_id_sha256", "trust_source", "http_status", "request_id",
        }
        execution_policy = {
            "widget": "widget_delegated_execution",
            "share": "share_delegated_execution",
            "action": "delegated_execution",
        }
        execution_request_ids: list[str] = []
        for role, field in execution_policy.items():
            identity = by_role[role]
            execution = runtime[field]
            if (
                not isinstance(execution, dict)
                or set(execution) != execution_fields
                or execution["role"] != role
                or execution["definition_id"] != identity["definition_id"]
                or execution["component_id_sha256"] != identity["principal_id_sha256"]
                or execution["dpop_key_id_sha256"] != identity["dpop_key_id_sha256"]
                or execution["session_id_sha256"] != identity["session_id_sha256"]
                or execution["trust_source"] != "delegated_from_attested_root"
                or isinstance(execution["http_status"], bool)
                or not isinstance(execution["http_status"], int)
                or not 200 <= execution["http_status"] <= 299
                or request_id.fullmatch(str(execution["request_id"])) is None
            ):
                raise ObservationError("live_sdk_component_delegated_execution_invalid")
            execution_test = component_tests[f"{role}_delegated_request"]
            if (
                execution_test.get("http_status") != execution["http_status"]
                or execution_test.get("request_id") != execution["request_id"]
            ):
                raise ObservationError("live_sdk_component_delegated_execution_invalid")
            execution_request_ids.append(execution["request_id"])
        if len(set(execution_request_ids)) != len(execution_request_ids):
            raise ObservationError("live_sdk_component_delegated_execution_invalid")

        action = by_role["action"]
        denial = runtime["sibling_denial"]
        denial_fields = {
            "requesting_role", "credential_role", "credential_session_id_sha256",
            "http_status", "error_code", "request_id",
        }
        if not isinstance(denial, dict) or set(denial) != denial_fields:
            raise ObservationError("live_sdk_component_sibling_denial_invalid")
        sibling = by_role.get(str(denial.get("credential_role")), {})
        if (
            denial["requesting_role"] != "action"
            or denial["credential_role"] not in {"widget", "share"}
            or denial["credential_session_id_sha256"] != sibling.get("session_id_sha256")
            or denial["credential_session_id_sha256"] == action["session_id_sha256"]
            or denial["http_status"] != 401
            or denial["error_code"] != "component_key_invalid"
            or request_id.fullmatch(str(denial["request_id"])) is None
        ):
            raise ObservationError("live_sdk_component_sibling_denial_invalid")
        denial_test = next(
            (item for item in tests if item.get("id") == "component_sibling_denied"),
            {},
        )
        if any(denial_test.get(field) != denial[field] for field in (
            "http_status", "error_code", "request_id",
        )):
            raise ObservationError("live_sdk_component_sibling_denial_invalid")

        keychain_denial = runtime["keychain_sibling_denial"]
        keychain_fields = {
            "requesting_role", "target_role", "target_key_id_sha256", "operation",
            "os_status", "os_status_name", "key_material_returned",
        }
        if (
            not isinstance(keychain_denial, dict)
            or set(keychain_denial) != keychain_fields
        ):
            raise ObservationError("live_sdk_component_keychain_denial_invalid")
        target_role = keychain_denial.get("target_role")
        target = by_role.get(str(target_role), {})
        keychain_test = component_tests["component_keychain_sibling_denied"]
        if (
            keychain_denial["requesting_role"] != "action"
            or not isinstance(target_role, str)
            or target_role not in {"widget", "share"}
            or keychain_denial["target_key_id_sha256"] != target.get("dpop_key_id_sha256")
            or keychain_denial["target_key_id_sha256"] == action["dpop_key_id_sha256"]
            or keychain_denial["operation"] != "SecItemCopyMatching"
            or keychain_denial["os_status"] != -34018
            or keychain_denial["os_status_name"] != "errSecMissingEntitlement"
            or keychain_denial["key_material_returned"] is not False
            or keychain_test.get("os_status") != keychain_denial["os_status"]
            or keychain_test.get("os_status_name") != keychain_denial["os_status_name"]
        ):
            raise ObservationError("live_sdk_component_keychain_denial_invalid")

        race = runtime["component_refresh_race"]
        race_fields = {
            "role", "component_id_sha256", "dpop_key_id_sha256",
            "session_id_before_sha256", "old_credential_sha256",
            "requests_started_concurrently", "overlap_observed", "requests",
            "session_id_after_sha256", "results_identical",
        }
        race_request_fields = {
            "request_id", "http_status", "access_credential_sha256",
            "refresh_credential_sha256", "session_id_sha256",
        }
        if not isinstance(race, dict) or set(race) != race_fields:
            raise ObservationError("live_sdk_component_refresh_race_invalid")
        race_role = race.get("role")
        race_identity = by_role.get(str(race_role), {})
        race_requests = race.get("requests")
        if (
            not isinstance(race_role, str)
            or race_role not in {"widget", "share", "action"}
            or race["component_id_sha256"] != race_identity.get("principal_id_sha256")
            or race["dpop_key_id_sha256"] != race_identity.get("dpop_key_id_sha256")
            or race["session_id_after_sha256"] != race_identity.get("session_id_sha256")
            or EVIDENCE.SHA256.fullmatch(str(race["session_id_before_sha256"])) is None
            or race["session_id_before_sha256"] == race["session_id_after_sha256"]
            or EVIDENCE.SHA256.fullmatch(str(race["old_credential_sha256"])) is None
            or race["requests_started_concurrently"] is not True
            or race["overlap_observed"] is not True
            or race["results_identical"] is not True
            or not isinstance(race_requests, list)
            or len(race_requests) != 2
        ):
            raise ObservationError("live_sdk_component_refresh_race_invalid")
        for request in race_requests:
            if (
                not isinstance(request, dict)
                or set(request) != race_request_fields
                or request_id.fullmatch(str(request.get("request_id", ""))) is None
                or isinstance(request.get("http_status"), bool)
                or not isinstance(request.get("http_status"), int)
                or not 200 <= request["http_status"] <= 299
                or any(
                    EVIDENCE.SHA256.fullmatch(str(request.get(field, ""))) is None
                    for field in (
                        "access_credential_sha256", "refresh_credential_sha256",
                        "session_id_sha256",
                    )
                )
            ):
                raise ObservationError("live_sdk_component_refresh_race_invalid")
        if (
            race_requests[0]["request_id"] == race_requests[1]["request_id"]
            or race_requests[0]["access_credential_sha256"]
            != race_requests[1]["access_credential_sha256"]
            or race_requests[0]["refresh_credential_sha256"]
            != race_requests[1]["refresh_credential_sha256"]
            or race_requests[0]["session_id_sha256"]
            != race_requests[1]["session_id_sha256"]
            or race_requests[0]["session_id_sha256"] != race["session_id_after_sha256"]
            or race_requests[0]["refresh_credential_sha256"] == race["old_credential_sha256"]
        ):
            raise ObservationError("live_sdk_component_refresh_race_invalid")
        race_test = component_tests["component_refresh_race"]
        if (
            race_test.get("concurrent_request_count") != 2
            or race_test.get("credential_before_sha256") != race["old_credential_sha256"]
            or race_test.get("credential_after_sha256")
            != race_requests[0]["refresh_credential_sha256"]
        ):
            raise ObservationError("live_sdk_component_refresh_race_invalid")

        if runtime["lifecycle"] != {
            "host_process_running_during_action_request": False,
            "background_execution_observed": True,
            "host_termination_observed": True,
            "user_presence_prompt_observed": False,
        }:
            raise ObservationError("live_sdk_component_lifecycle_invalid")

    @staticmethod
    def _validate_concrete_tests(
        value: Any,
        *,
        expected: set[str],
        mapped_error_type: str,
        javascript: bool,
    ) -> dict[str, dict[str, Any]]:
        if not isinstance(value, list):
            raise ObservationError("live_sdk_test_set_invalid")
        tests: dict[str, dict[str, Any]] = {}
        for test in value:
            if (
                not isinstance(test, dict)
                or not isinstance(test.get("id"), str)
                or test["id"] in tests
                or test.get("status") != "passed"
            ):
                raise ObservationError("live_sdk_test_set_invalid")
            tests[test["id"]] = test
        if set(tests) != expected:
            raise ObservationError("live_sdk_test_set_invalid")
        request_id = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
        negative = {
            "dpop_replay_rejected": (401, "dpop_replayed"),
            "tampered_dpop_rejected": (401, "dpop_invalid"),
            "canonical_error_mapping": (404, "feature_not_found"),
            "installation_revocation": (403, "installation_revoked"),
            "protocol_version_rejection": (426, "protocol_version_unsupported"),
        }
        if "component_sibling_denied" in expected:
            negative["component_sibling_denied"] = (
                401,
                "component_key_invalid",
            )
        for identifier, (status, code) in negative.items():
            test = tests.get(identifier, {})
            if (
                test.get("http_status") != status
                or test.get("error_code") != code
                or request_id.fullmatch(str(test.get("request_id", ""))) is None
            ):
                raise ObservationError("live_sdk_concrete_behavior_invalid")
        if (
            tests["canonical_error_mapping"].get("mapped_error_type")
            != mapped_error_type
            or tests["protocol_version_rejection"].get("protocol_version_sent")
            != 0
        ):
            raise ObservationError("live_sdk_concrete_behavior_invalid")
        rotation = tests["session_refresh_rotation"]
        hashes = (
            rotation.get("credential_before_sha256"),
            rotation.get("credential_after_sha256"),
            rotation.get("installation_before_sha256"),
            rotation.get("installation_after_sha256"),
        )
        if (
            any(EVIDENCE.SHA256.fullmatch(str(item)) is None for item in hashes)
            or hashes[0] == hashes[1]
            or hashes[2] != hashes[3]
        ):
            raise ObservationError("live_sdk_concrete_behavior_invalid")
        authorized = tests["dpop_authorized_request"]
        streamed = tests["streamed_request"]
        if (
            not isinstance(authorized.get("http_status"), int)
            or not 200 <= authorized["http_status"] < 300
            or request_id.fullmatch(str(authorized.get("request_id", ""))) is None
            or not isinstance(streamed.get("http_status"), int)
            or not 200 <= streamed["http_status"] < 300
            or request_id.fullmatch(str(streamed.get("request_id", ""))) is None
        ):
            raise ObservationError("live_sdk_concrete_behavior_invalid")
        if javascript:
            quota = tests["quota"]
            if (
                not isinstance(streamed.get("byte_count"), int)
                or isinstance(streamed.get("byte_count"), bool)
                or not 1 <= streamed["byte_count"] <= 1_048_576
                or not isinstance(quota.get("limit_count"), int)
                or isinstance(quota.get("limit_count"), bool)
                or quota["limit_count"] < 1
                or not isinstance(quota.get("metrics"), list)
                or not quota["metrics"]
                or any(not isinstance(item, str) or not item for item in quota["metrics"])
            ):
                raise ObservationError("live_sdk_concrete_behavior_invalid")
        return tests

    @staticmethod
    def _validate_common_gateway_binding(
        receipts: Mapping[str, Mapping[str, Any]],
        gateway: str,
        javascript_environment: Mapping[str, str] | None,
    ) -> None:
        keys = (
            "gateway_image_digest",
            "gateway_configuration_sha256",
            "gateway_origin",
            "gateway_environment",
            "gateway_deployment_key_id",
            "gateway_deployment_statement_sha256",
            "gateway_deployment_public_key_sha256",
            "error_mapping_feature",
        )
        bindings = []
        for item in receipts.values():
            pins = item["profile"].get("expected_pins")
            if not isinstance(pins, dict) or any(not pins.get(key) for key in keys):
                raise ObservationError("live_sdk_gateway_binding_invalid")
            bindings.append(tuple(pins[key] for key in keys))
        if not bindings or any(binding != bindings[0] for binding in bindings[1:]) or bindings[0][2] != gateway:
            raise ObservationError("live_sdk_gateway_binding_invalid")
        if javascript_environment is not None and (
            bindings[0][3]
            != javascript_environment["LATCHWAY_LIVE_SDK_ENVIRONMENT"]
            or bindings[0][7]
            != javascript_environment["LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE"]
        ):
            raise ObservationError("live_sdk_gateway_binding_invalid")

    @staticmethod
    def _validate_react_native_links(
        receipts: Mapping[str, Mapping[str, Any]]
    ) -> None:
        links = (
            (
                "react_native_ios",
                "ios",
                "linked-ios-native-profile.json",
                "linked-ios-native-evidence.json",
            ),
            (
                "react_native_android",
                "android",
                "linked-android-native-profile.json",
                "linked-android-native-evidence.json",
            ),
        )
        for react_native, native, linked_profile, linked_evidence in links:
            rn = receipts[react_native]
            source = receipts[native]
            rn_payloads = rn["receipt"]["payloads"]
            source_payloads = source["receipt"]["payloads"]
            native_policy = LIVE_SDK_RECEIPTS[native]
            if (
                rn_payloads[linked_profile] != source_payloads[native_policy["profile"]]
                or rn_payloads[linked_evidence]
                != source_payloads[native_policy["evidence"]]
                or nested(rn["profile"], "expected_pins", "native_evidence_sha256")
                != hashlib.sha256(rn_payloads[linked_evidence]).hexdigest()
                or nested(rn["profile"], "expected_pins", "native_sdk_version")
                != nested(source["profile"], "source", "sdk_version")
            ):
                raise ObservationError("live_sdk_native_link_invalid")

    @classmethod
    def _validate_javascript_report(
        cls,
        payload: bytes,
        identity: Mapping[str, Any],
        gateway: str,
        *,
        expected_provider: str,
    ) -> dict[str, Any]:
        report = load_output(payload, "live_sdk_javascript_report_invalid")
        build = nested(report, "gateway", "build")
        if (
            not isinstance(report, dict)
            or set(report)
            != {
                "schema_version",
                "kind",
                "platform",
                "attestation_provider",
                "candidate",
                "gateway",
                "tests",
                "redaction",
            }
            or report.get("schema_version") != 1
            or report.get("kind") != "latchway_live_javascript_observation"
            or report.get("platform") != "javascript"
            or expected_provider not in LIVE_SDK_JAVASCRIPT_PROVIDERS
            or report.get("attestation_provider") != expected_provider
            or report.get("candidate") != identity
            or nested(report, "gateway", "origin") != gateway
            or nested(report, "gateway", "status") != "ok"
            or not isinstance(build, dict)
            or build.get("commit") != identity["core_commit"]
            or build.get("version") != identity["repositories"]["core"]["version"]
            or build.get("contract_version") != identity["contract_version"]
            or str(build.get("protocol_version")) != "2"
            or not isinstance(report.get("redaction"), dict)
            or any(value is not False for value in report["redaction"].values())
        ):
            raise ObservationError("live_sdk_javascript_report_invalid")
        cls._validate_concrete_tests(
            report.get("tests"),
            expected=set(LIVE_SDK_JAVASCRIPT_TESTS),
            mapped_error_type="javascript_latchway_error",
            javascript=True,
        )
        return report

    def _platform_summary(
        self,
        *,
        platform: str,
        repository: str,
        workflow: str,
        run_id: int | None,
        run_attempt: int | None,
        artifact_name: str | None,
        profile: Mapping[str, Any] | None,
        evidence: Mapping[str, Any],
        receipt_hashes: Mapping[str, str],
        attestation_provider: str | None = None,
    ) -> dict[str, Any]:
        tests = evidence.get("tests")
        concrete = [
            self._redacted_test_record(test)
            for test in tests
            if isinstance(test, dict) and test.get("id") in self._behavior_test_ids()
        ]
        source = (
            profile.get("source", {}) if profile is not None else {
                "commit": self.identity["repositories"]["javascript"]["commit"],
                "core_commit": self.identity["core_commit"],
                "sdk_version": self.identity["repositories"]["javascript"]["version"],
                "contract_version": self.identity["contract_version"],
                "contract_bundle_sha256": self.identity["bundle_sha256"],
                "gateway_image_digest": self.candidate["image"]["index_digest"],
                "gateway_origin": nested(evidence, "gateway", "origin"),
            }
        )
        summary = {
            "schema_version": 1,
            "kind": "latchway_live_sdk_validated_platform",
            "platform": platform,
            "candidate": self.identity,
            "producer": {
                "repository": repository,
                "workflow": workflow,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "artifact_name": artifact_name,
            },
            "source": {
                key: source.get(key)
                for key in (
                    "commit",
                    "core_commit",
                    "sdk_version",
                    "contract_version",
                    "contract_bundle_sha256",
                    "gateway_image_digest",
                    "gateway_configuration_sha256",
                    "gateway_origin",
                )
                if source.get(key) is not None
            },
            "receipt_sha256": dict(sorted(receipt_hashes.items())),
            "concrete_tests": sorted(concrete, key=lambda item: item["id"]),
        }
        if attestation_provider is not None:
            if (
                platform != "javascript"
                or attestation_provider not in LIVE_SDK_JAVASCRIPT_PROVIDERS
                or evidence.get("attestation_provider") != attestation_provider
            ):
                raise ObservationError("live_sdk_javascript_provider_invalid")
            summary["attestation_provider"] = attestation_provider
        EVIDENCE.scan_safe(canonical_json(summary))
        return summary

    @staticmethod
    def _behavior_test_ids() -> frozenset[str]:
        return frozenset(
            {
                "dpop_authorized_request",
                "dpop_replay_rejected",
                "tampered_dpop_rejected",
                "canonical_error_mapping",
                "session_refresh_rotation",
                "installation_revocation",
                "streamed_request",
                "quota",
                "protocol_version_rejection",
            }
        ) | IOS_COMPONENT_TESTS

    @staticmethod
    def _redacted_test_record(test: Mapping[str, Any]) -> dict[str, Any]:
        safe_fields = (
            "id",
            "http_status",
            "error_code",
            "mapped_error_type",
            "credential_before_sha256",
            "credential_after_sha256",
            "installation_before_sha256",
            "installation_after_sha256",
            "protocol_version_sent",
            "os_status",
            "os_status_name",
            "concurrent_request_count",
            "byte_count",
            "feature",
            "limit_count",
            "metrics",
        )
        value = {key: test[key] for key in safe_fields if key in test}
        request_id = test.get("request_id")
        if isinstance(request_id, str):
            value["request_id_sha256"] = hashlib.sha256(
                request_id.encode("utf-8")
            ).hexdigest()
        value["record_sha256"] = hashlib.sha256(canonical_json(test)).hexdigest()
        return value

    @classmethod
    def _behavior_summary(
        cls,
        behavior: str,
        platform_summaries: Sequence[Mapping[str, Any]],
        identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        mapping = {
            "dpop_vectors": {
                "dpop_authorized_request",
                "dpop_replay_rejected",
                "tampered_dpop_rejected",
            },
            "error_mapping": {"canonical_error_mapping"},
            "session_refresh": {"session_refresh_rotation"},
            "installation_revocation": {"installation_revocation"},
            "streaming": {"streamed_request"},
            "quota_snapshots": {"quota"},
            "protocol_version_rejection": {"protocol_version_rejection"},
        }
        selected = []
        for platform in platform_summaries:
            tests = [
                test
                for test in platform["concrete_tests"]
                if test.get("id") in mapping[behavior]
            ]
            if {test.get("id") for test in tests} != mapping[behavior]:
                raise ObservationError("live_sdk_behavior_set_invalid")
            selected_platform = {
                "platform": platform["platform"],
                "producer": platform["producer"],
                "tests": tests,
            }
            if "attestation_provider" in platform:
                selected_platform["attestation_provider"] = platform[
                    "attestation_provider"
                ]
            selected.append(selected_platform)
        javascript_providers = [
            platform.get("attestation_provider")
            for platform in platform_summaries
            if platform.get("platform") == "javascript"
        ]
        native_provider_fields = [
            platform
            for platform in platform_summaries
            if platform.get("platform") != "javascript"
            and "attestation_provider" in platform
        ]
        if (
            len(selected)
            != len(LIVE_SDK_RECEIPTS) + len(LIVE_SDK_JAVASCRIPT_PROVIDERS)
            or len(javascript_providers) != len(LIVE_SDK_JAVASCRIPT_PROVIDERS)
            or set(javascript_providers) != set(LIVE_SDK_JAVASCRIPT_PROVIDERS)
            or native_provider_fields
        ):
            raise ObservationError("live_sdk_behavior_set_invalid")
        result = {
            "schema_version": 1,
            "kind": "latchway_live_sdk_validated_behavior",
            "behavior": behavior,
            "candidate": identity,
            "platforms": selected,
        }
        EVIDENCE.scan_safe(canonical_json(result))
        return result

def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--domain", choices=tuple(EVIDENCE.CLAIM_REQUIREMENTS), required=True)
    value.add_argument(
        "--release-profile", choices=(EVIDENCE.SINGLE_MAINTAINER_PROFILE,)
    )
    value.add_argument("--source-conformance", type=Path, required=True)
    value.add_argument("--candidate-manifest", type=Path, required=True)
    value.add_argument("--output-directory", type=Path, required=True)
    for repository_id in REPOSITORY_NAMES:
        value.add_argument(f"--{repository_id.replace('_', '-')}-repo", type=Path, required=True)
    for receipt_id in LIVE_SDK_RECEIPTS:
        value.add_argument(
            f"--{receipt_id.replace('_', '-')}-receipt-directory", type=Path
        )
    for run_id in ("ios", "android", "react_native"):
        option = run_id.replace("_", "-")
        value.add_argument(f"--{option}-run-id")
        value.add_argument(f"--{option}-run-attempt")
    value.add_argument("--physical-authority-directory", type=Path)
    value.add_argument("--javascript-firebase-app-check-capture", type=Path)
    value.add_argument("--javascript-turnstile-capture", type=Path)
    value.add_argument("--live-provider-capture-directory", type=Path)
    value.add_argument("--github-authority-directory", type=Path)
    return value


def main() -> int:
    arguments = parser().parse_args()
    repositories = {
        repository_id: getattr(arguments, f"{repository_id}_repo")
        for repository_id in REPOSITORY_NAMES
    }
    live_sdk_receipts = {
        receipt_id: getattr(arguments, f"{receipt_id}_receipt_directory")
        for receipt_id in LIVE_SDK_RECEIPTS
        if getattr(arguments, f"{receipt_id}_receipt_directory") is not None
    }
    live_sdk_runs = {
        run_id: (
            getattr(arguments, f"{run_id}_run_id"),
            getattr(arguments, f"{run_id}_run_attempt"),
        )
        for run_id in ("ios", "android", "react_native")
        if getattr(arguments, f"{run_id}_run_id") is not None
        or getattr(arguments, f"{run_id}_run_attempt") is not None
    }
    javascript_captures = {
        provider: getattr(
            arguments, f"javascript_{provider.replace('-', '_')}_capture"
        )
        for provider in LIVE_SDK_JAVASCRIPT_PROVIDERS
        if getattr(
            arguments, f"javascript_{provider.replace('-', '_')}_capture"
        ) is not None
    }
    try:
        observer = Observer(
            domain=arguments.domain,
            source=arguments.source_conformance,
            candidate=arguments.candidate_manifest,
            output=arguments.output_directory,
            repositories=repositories,
            live_sdk_receipts=live_sdk_receipts,
            live_sdk_runs=live_sdk_runs,
            live_sdk_authority=arguments.physical_authority_directory,
            javascript_captures=javascript_captures,
            live_provider_capture=arguments.live_provider_capture_directory,
            github_authority=arguments.github_authority_directory,
            release_profile=arguments.release_profile,
            now=datetime.now(timezone.utc).replace(microsecond=0),
        )
        observer.observe()
    except (ObservationError, EVIDENCE.EvidenceError, OSError) as error:
        code = (
            str(error)
            if isinstance(error, (ObservationError, EVIDENCE.EvidenceError))
            else "observation_io_failed"
        )
        print(f"release domain observation rejected: {code}", file=sys.stderr)
        return 1
    summary = {
        "domain": arguments.domain,
        "observations": len(
            EVIDENCE.expected_observations(
                arguments.domain,
                arguments.release_profile,
            )
        ),
    }
    if arguments.release_profile is not None:
        summary["release_profile"] = arguments.release_profile
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
