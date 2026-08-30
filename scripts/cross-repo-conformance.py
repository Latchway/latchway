#!/usr/bin/env python3
"""Produce fail-closed cross-repository source and release evidence.

This command is intentionally offline. It proves facts about exact local Git
checkouts and validates separately captured external evidence, but it never
queries a registry, creates a tag, publishes an artifact, or contacts a device
or deployment.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Mapping
import xml.etree.ElementTree as ET


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_BUNDLE_ENTRIES = 4096
MAXIMUM_EVIDENCE_AGE = timedelta(days=7)
MAXIMUM_EVIDENCE_SECONDS = int(MAXIMUM_EVIDENCE_AGE.total_seconds())

REPOSITORY_IDS = ("core", "javascript", "ios", "android", "react_native")
DEFAULT_REPOSITORY_NAMES = {
    "core": "latchway",
    "javascript": "latchway-js",
    "ios": "latchway-ios-sdk",
    "android": "latchway-android",
    "react_native": "latchway-react-native-sdk",
}
SDK_FIXTURES = {
    "javascript": "test/fixtures/contract",
    "ios": "Tests/ConformanceTests/Fixtures",
    "android": "latchway-core/src/test/resources/contract",
    "react_native": "test/fixtures/contract",
}
FIXTURE_MEMBERS = {
    "attestation-binding-v1.json": "test-vectors/attestation-binding/v1.json",
    "dpop-v1.json": "test-vectors/dpop/v1.json",
    "protocol-version.json": "protocol-version.json",
}
FIXED_CONTRACT_FILES = (
    "admin.openapi.yaml",
    "attestation-binding.schema.json",
    "client.openapi.yaml",
    "config.schema.json",
    "error-codes.yaml",
    "protocol-version.json",
    "release-evidence.schema.json",
)
REQUIRED_SDK_KINDS = frozenset(("ios", "android", "javascript", "react-native"))

SEMVER_PATTERN = (
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SEMVER = re.compile(rf"^{SEMVER_PATTERN}$")
RELEASE_TAG = re.compile(rf"^v{SEMVER_PATTERN}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OCI_IMAGE_DIGEST = re.compile(
    r"^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$"
)
MAXIMUM_TESTED = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.x$")
LOCK_LINE = re.compile(
    r'^([a-z0-9_]+):\s*(?:"([^"]*)"|([^#\s]+))\s*(?:#.*)?$'
)
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64}) {2}([^\r\n]+)$")
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

EXTERNAL_DOMAINS: Mapping[str, tuple[str, ...]] = {
    "live_sdk_conformance": (
        "javascript_against_release_image",
        "ios_against_release_image",
        "android_against_release_image",
        "react_native_ios_against_release_image",
        "react_native_android_against_release_image",
        "dpop_vectors",
        "error_mapping",
        "session_refresh",
        "installation_revocation",
        "streaming",
        "quota_snapshots",
        "protocol_version_rejection",
    ),
    "public_tags": (
        "remote_annotated_tags_verified",
        "github_releases_verified",
    ),
    "public_registries": (
        "oci_digest_verified",
        "npm_javascript_verified",
        "npm_react_native_verified",
        "swift_package_verified",
        "cocoapods_verified",
        "maven_central_verified",
    ),
    "physical_devices": (
        "app_attest_production_verified",
        "play_integrity_play_distributed_verified",
        "react_native_ios_verified",
        "react_native_android_verified",
    ),
    "live_provider": (
        "openrouter_nonstreaming_verified",
        "openrouter_streaming_verified",
        "usage_verified",
        "output_clamp_verified",
        "error_normalization_verified",
    ),
    "cloud_deployments": (
        "compose_verified",
        "cloud_run_verified",
        "aws_verified",
        "fly_io_verified",
        "cloudflare_containers_verified",
    ),
    "operational_resilience": (
        "v1_load_targets_verified",
        "live_failure_injection_verified",
        "multi_replica_verified",
        "backup_restore_drill_verified",
        "previous_candidate_upgrade_rollback_verified",
    ),
    "supply_chain": (
        "multi_arch_image_verified",
        "vulnerability_scan_verified",
        "license_scan_verified",
        "sbom_verified",
        "signature_verified",
        "provenance_verified",
    ),
}
PUBLICATION_DOMAINS = frozenset(("public_tags", "public_registries"))
PROMOTION_DOMAINS = tuple(
    domain for domain in EXTERNAL_DOMAINS if domain not in PUBLICATION_DOMAINS
)
RELEASE_DOMAINS = tuple(EXTERNAL_DOMAINS)

CHECK_SUMMARIES = {
    "source.repository_layout": "All five explicit repository roots are distinct local Git checkouts.",
    "source.clean_worktrees": "All five source worktrees are clean, including untracked files.",
    "source.core_contract": "Core contract and build declarations are internally consistent.",
    "source.contract_bundle": "Two core contract bundles are byte-identical and internally complete.",
    "source.contract_locks": "Every SDK lock names one immutable ancestor contract checkpoint, contract, wire version, server range, and bundle hash.",
    "source.generated_fixtures": "Every SDK fixture is byte-identical to the generated core bundle member.",
    "source.package_versions": "Public package names and source version declarations agree.",
    "source.react_native_pins": "React Native dependencies pin the exact local JavaScript, iOS, and Android sources.",
    "promotion.local_preconditions": "The released contract and every intended source coordinate are valid before publication.",
    "promotion.evidence_window": "All required evidence is fresh and belongs to one bounded candidate window.",
    "release.local_preconditions": "All local release coordinates, clean trees, and annotated tags are valid.",
}


class VerificationError(Exception):
    """A redaction-safe verification failure."""

    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


@dataclass
class Check:
    identifier: str
    domain: str
    required: bool
    status: str
    summary: str
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.identifier,
            "domain": self.domain,
            "required": self.required,
            "status": self.status,
            "summary": self.summary,
        }
        if self.reason is not None:
            value["reason"] = self.reason
        if self.details:
            value["details"] = self.details
        return value


@dataclass(frozen=True)
class Configuration:
    scope: str
    repositories: Mapping[str, Path]
    release_tag: str | None
    oci_image_digest: str | None
    external_evidence_dir: Path | None


class Evaluator:
    def __init__(self, configuration: Configuration):
        self.configuration = configuration
        self.checks: list[Check] = []
        self.state: dict[str, Any] = {}
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def evaluate(self) -> dict[str, Any]:
        self._run("source.repository_layout", "local_source", True, self._repository_layout)
        self._run("source.clean_worktrees", "local_source", True, self._clean_worktrees)
        self._run("source.core_contract", "local_source", True, self._core_contract)
        self._run("source.contract_bundle", "local_source", True, self._contract_bundle)
        self._run("source.contract_locks", "local_source", True, self._contract_locks)
        self._run("source.generated_fixtures", "local_source", True, self._generated_fixtures)
        self._run("source.package_versions", "local_source", True, self._package_versions)
        self._run("source.react_native_pins", "local_source", True, self._react_native_pins)

        promotion_requested = self.configuration.scope in ("promotion", "release")
        release_required = self.configuration.scope == "release"
        if promotion_requested:
            self._run(
                "promotion.local_preconditions",
                "local_promotion",
                True,
                self._local_promotion_preconditions,
            )
        else:
            self._unverified(
                "promotion.local_preconditions",
                "local_promotion",
                False,
                "promotion_scope_not_requested",
            )
        if release_required:
            self._run(
                "release.local_preconditions",
                "local_release",
                True,
                self._local_release_preconditions,
            )
        else:
            self._unverified(
                "release.local_preconditions",
                "local_release",
                False,
                "release_scope_not_requested",
            )

        for domain in EXTERNAL_DOMAINS:
            identifier = f"external.{domain}"
            required = release_required or (
                self.configuration.scope == "promotion" and domain in PROMOTION_DOMAINS
            )
            if required:
                self._verify_external_domain(identifier, domain)
            else:
                self._unverified(
                    identifier,
                    domain,
                    False,
                    "external_evidence_not_required_by_scope",
                )

        if promotion_requested:
            self._run(
                "promotion.evidence_window",
                "local_promotion",
                True,
                self._validate_evidence_window,
            )
        else:
            self._unverified(
                "promotion.evidence_window",
                "local_promotion",
                False,
                "promotion_scope_not_requested",
            )

        required_passed = all(
            check.status == "passed" for check in self.checks if check.required
        )
        source_passed = all(
            check.status == "passed"
            for check in self.checks
            if check.domain == "local_source"
        )
        promotion_required_checks = [
            check
            for check in self.checks
            if check.domain == "local_source"
            or check.domain == "local_promotion"
            or check.domain in PROMOTION_DOMAINS
        ]
        promotion_ready = promotion_requested and all(
            check.status == "passed" for check in promotion_required_checks
        )
        release_ready = release_required and required_passed
        report: dict[str, Any] = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_conformance_evidence",
            "scope": self.configuration.scope,
            "verdict": "passed" if required_passed else "failed",
            "source_conformance_passed": source_passed,
            "promotion_ready": promotion_ready,
            "release_ready": release_ready,
            "contract": self._contract_summary(),
            "repositories": self._repository_summary(),
            "evidence_window": self.state.get("evidence_window"),
            "evidence_domains": self._domain_summary(),
            "checks": [check.as_json() for check in self.checks],
        }
        return report

    def _run(
        self,
        identifier: str,
        domain: str,
        required: bool,
        operation: Callable[[], Mapping[str, Any] | None],
    ) -> None:
        try:
            details = dict(operation() or {})
        except VerificationError as error:
            self.checks.append(
                Check(
                    identifier,
                    domain,
                    required,
                    "failed",
                    CHECK_SUMMARIES.get(identifier, "Required evidence is valid."),
                    error.code,
                    error.details,
                )
            )
        except Exception:
            self.checks.append(
                Check(
                    identifier,
                    domain,
                    required,
                    "failed",
                    CHECK_SUMMARIES.get(identifier, "Required evidence is valid."),
                    "internal_verification_error",
                )
            )
        else:
            self.checks.append(
                Check(
                    identifier,
                    domain,
                    required,
                    "passed",
                    CHECK_SUMMARIES.get(identifier, "Required evidence is valid."),
                    details=details,
                )
            )

    def _unverified(
        self,
        identifier: str,
        domain: str,
        required: bool,
        reason: str,
    ) -> None:
        self.checks.append(
            Check(
                identifier,
                domain,
                required,
                "unverified",
                external_summary(domain)
                if identifier.startswith("external.")
                else CHECK_SUMMARIES[identifier],
                reason,
            )
        )

    def _repository_layout(self) -> Mapping[str, Any]:
        resolved: dict[str, Path] = {}
        commits: dict[str, str] = {}
        for repository_id in REPOSITORY_IDS:
            root = self.configuration.repositories[repository_id]
            try:
                metadata = root.lstat()
            except OSError:
                raise VerificationError(
                    "repository_missing", {"repository": repository_id}
                ) from None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise VerificationError(
                    "repository_root_not_real_directory", {"repository": repository_id}
                )
            root = root.resolve()
            if root in resolved.values():
                raise VerificationError("repository_roots_not_distinct")
            try:
                top_level = Path(git(root, "rev-parse", "--show-toplevel")).resolve()
                commit = git(root, "rev-parse", "--verify", "HEAD")
            except VerificationError:
                raise VerificationError(
                    "repository_not_git_checkout", {"repository": repository_id}
                ) from None
            if top_level != root or COMMIT.fullmatch(commit) is None:
                raise VerificationError(
                    "repository_identity_invalid", {"repository": repository_id}
                )
            resolved[repository_id] = root
            commits[repository_id] = commit
        self.state["repositories"] = resolved
        self.state["commits"] = commits
        return {"repository_count": len(resolved)}

    def _clean_worktrees(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        dirty: dict[str, int] = {}
        for repository_id in REPOSITORY_IDS:
            output = git(
                repositories[repository_id],
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            )
            if output:
                dirty[repository_id] = len(output.splitlines())
        if dirty:
            raise VerificationError(
                "dirty_worktrees",
                {
                    "repositories": sorted(dirty),
                    "entry_counts": {key: dirty[key] for key in sorted(dirty)},
                },
            )
        return {"clean_repository_count": len(REPOSITORY_IDS)}

    def _core_contract(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        core = repositories["core"]
        manifest = read_json(core / "api/protocol-version.json")
        if manifest.get("manifest_version") != 1:
            raise VerificationError("unsupported_contract_manifest")
        contract_version = manifest.get("contract_version")
        wire = nested(manifest, "wire_protocol", "current")
        bundle_name = nested(manifest, "bundle", "file_name")
        sdk_kinds = manifest.get("sdk_kinds")
        if not isinstance(contract_version, str) or SEMVER.fullmatch(contract_version) is None:
            raise VerificationError("invalid_contract_version")
        if not isinstance(wire, int) or isinstance(wire, bool) or wire < 1:
            raise VerificationError("invalid_wire_protocol")
        if bundle_name != f"latchway-contract-{contract_version}.tar.gz":
            raise VerificationError("invalid_contract_bundle_name")
        if not isinstance(sdk_kinds, list) or not REQUIRED_SDK_KINDS.issubset(
            {value for value in sdk_kinds if isinstance(value, str)}
        ):
            raise VerificationError("contract_sdk_kinds_incomplete")
        status_value = manifest.get("contract_status")
        if status_value not in ("draft", "released"):
            raise VerificationError("invalid_contract_status")
        released_at = manifest.get("released_at")
        if status_value == "draft":
            if released_at is not None:
                raise VerificationError("draft_contract_has_release_timestamp")
        else:
            parse_timestamp(released_at, "contract_released_at_invalid")
        expected_release_evidence = {
            "schema_file": "release-evidence.schema.json",
            "schema_version": 1,
            "maximum_age_seconds": MAXIMUM_EVIDENCE_SECONDS,
            "maximum_window_seconds": MAXIMUM_EVIDENCE_SECONDS,
            "promotion_domains": list(PROMOTION_DOMAINS),
            "release_domains": list(RELEASE_DOMAINS),
        }
        if manifest.get("release_evidence") != expected_release_evidence:
            raise VerificationError("release_evidence_contract_mismatch")

        buildinfo = read_text(core / "internal/buildinfo/buildinfo.go")
        core_version = require_match(
            buildinfo, r'^\s*Version\s*=\s*"([^"]+)"', "core_version"
        )
        build_contract = require_match(
            buildinfo,
            r'^\s*ContractVersion\s*=\s*"([^"]+)"',
            "core_contract_version",
        )
        build_protocol = require_match(
            buildinfo,
            r'^\s*ProtocolVersion\s*=\s*"([^"]+)"',
            "core_protocol_version",
        )
        console = read_json(core / "web/console/package.json")
        console_version = console.get("version")
        if SEMVER.fullmatch(core_version) is None:
            raise VerificationError("invalid_core_version")
        if build_contract != contract_version or build_protocol != str(wire):
            raise VerificationError("core_build_contract_mismatch")
        if console.get("name") != "@latchway/admin-console" or not isinstance(
            console_version, str
        ):
            raise VerificationError("invalid_console_package")
        if console_version != core_version:
            raise VerificationError("core_console_version_mismatch")

        dockerfile = read_text(core / "Dockerfile")
        docker_version_declarations = tuple(
            match.group(1)
            for match in re.finditer(
                r"^[ \t]*(?i:ARG)[ \t]+VERSION(?:[ \t]*=[ \t]*([^\r\n]*?))?[ \t]*$",
                dockerfile,
                flags=re.MULTILINE,
            )
        )
        if not docker_version_declarations or any(
            value is None or not value for value in docker_version_declarations
        ):
            raise VerificationError("core_docker_version_default_missing")
        if any(value != core_version for value in docker_version_declarations):
            raise VerificationError("core_docker_version_mismatch")

        self.state["manifest"] = manifest
        self.state["contract_version"] = contract_version
        self.state["wire_protocol"] = wire
        self.state["bundle_name"] = bundle_name
        self.state["core_version"] = core_version
        self.state["contract_status"] = status_value
        self.state["released_at"] = released_at
        return {
            "contract_version": contract_version,
            "wire_protocol": wire,
            "contract_status": status_value,
            "core_version": core_version,
            "docker_version_default_count": len(docker_version_declarations),
        }

    def _contract_bundle(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        bundle_name = self._required_state("bundle_name")
        core = repositories["core"]
        builder = core / "scripts/build-contract-bundle.py"
        if not is_real_file(builder):
            raise VerificationError("contract_bundle_builder_missing")

        with tempfile.TemporaryDirectory(prefix="latchway-cross-repo-") as temporary:
            temporary_root = Path(temporary)
            archives: list[Path] = []
            for index in (1, 2):
                output = temporary_root / f"build-{index}"
                output.mkdir(mode=0o700)
                run_bundle_builder(core, builder, output)
                archive = output / bundle_name
                if not is_real_file(archive):
                    raise VerificationError("contract_bundle_not_generated")
                if archive.stat().st_size > MAX_BUNDLE_BYTES:
                    raise VerificationError("contract_bundle_too_large")
                archives.append(archive)
            first = archives[0].read_bytes()
            second = archives[1].read_bytes()
            if first != second:
                raise VerificationError("contract_bundle_not_reproducible")
            bundle_hash = sha256_bytes(first)
            members = validate_bundle(core, archives[0])

        self.state["bundle_sha256"] = bundle_hash
        self.state["bundle_members"] = members
        return {
            "bundle_sha256": bundle_hash,
            "member_count": len(members),
            "byte_reproducible": True,
        }

    def _contract_locks(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        commits = self._required_state("commits")
        contract_version = self._required_state("contract_version")
        core_version = self._required_state("core_version").split("-", 1)[0]
        wire = self._required_state("wire_protocol")
        bundle_hash = self._required_state("bundle_sha256")
        canonical: dict[str, str] | None = None
        locks: dict[str, dict[str, str]] = {}
        for repository_id in REPOSITORY_IDS[1:]:
            parsed = parse_contract_lock(repositories[repository_id] / "contract.lock")
            normalized = dict(parsed)
            wire_key = (
                "wire_protocol"
                if "wire_protocol" in normalized
                else "wire_protocol_version"
            )
            normalized["wire_protocol"] = normalized.pop(wire_key)
            if canonical is None:
                canonical = normalized
            elif normalized != canonical:
                raise VerificationError(
                    "sdk_contract_locks_disagree", {"repository": repository_id}
                )
            locks[repository_id] = normalized
        assert canonical is not None

        contract_source_commit = canonical.get("core_commit")
        core = repositories["core"]
        try:
            git(core, "cat-file", "-e", f"{contract_source_commit}^{{commit}}")
        except VerificationError:
            raise VerificationError("sdk_locked_contract_source_unavailable") from None
        try:
            git(
                core,
                "merge-base",
                "--is-ancestor",
                str(contract_source_commit),
                commits["core"],
            )
        except VerificationError:
            raise VerificationError("sdk_locked_contract_source_not_ancestor") from None
        try:
            git(
                core,
                "diff",
                "--exit-code",
                "--no-ext-diff",
                str(contract_source_commit),
                commits["core"],
                "--",
                "api",
            )
        except VerificationError:
            raise VerificationError("sdk_locked_contract_source_drift") from None

        expected = {
            "contract_version": contract_version,
            "bundle_sha256": bundle_hash,
            "wire_protocol": str(wire),
        }
        mismatched = sorted(
            field for field, value in expected.items() if canonical.get(field) != value
        )
        if mismatched:
            raise VerificationError(
                "sdk_lock_does_not_match_core", {"fields": mismatched}
            )
        core_release = canonical.get("core_release")
        minimum = canonical.get("minimum_server_version")
        maximum = canonical.get("maximum_tested_server_version")
        if core_release != "unreleased" and (
            not isinstance(core_release, str) or RELEASE_TAG.fullmatch(core_release) is None
        ):
            raise VerificationError("invalid_locked_core_release")
        if not isinstance(minimum, str) or SEMVER.fullmatch(minimum) is None:
            raise VerificationError("invalid_minimum_server_version")
        if semver_key(minimum) > semver_key(core_version):
            raise VerificationError("minimum_server_version_exceeds_core")
        maximum_match = MAXIMUM_TESTED.fullmatch(maximum or "")
        if maximum_match is None:
            raise VerificationError("invalid_maximum_tested_server_version")
        core_parts = core_version.split(".")
        if core_parts[:2] != list(maximum_match.groups()):
            raise VerificationError("maximum_tested_server_series_mismatch")

        self.state["locks"] = locks
        self.state["core_release"] = core_release
        self.state["contract_source_commit"] = contract_source_commit
        return {
            "lock_count": len(locks),
            "core_release": core_release,
            "contract_source_commit": contract_source_commit,
            "minimum_server_version": minimum,
            "maximum_tested_server_version": maximum,
        }

    def _generated_fixtures(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        members = self._required_state("bundle_members")
        fixture_hashes: dict[str, str] = {}
        for fixture_name, bundle_member in FIXTURE_MEMBERS.items():
            canonical = members.get(bundle_member)
            if canonical is None:
                raise VerificationError(
                    "bundle_fixture_missing", {"fixture": fixture_name}
                )
            fixture_hashes[fixture_name] = sha256_bytes(canonical)
            for repository_id, fixture_root in SDK_FIXTURES.items():
                path = repositories[repository_id] / fixture_root / fixture_name
                if not is_real_file(path) or read_bytes(path) != canonical:
                    raise VerificationError(
                        "sdk_fixture_mismatch",
                        {"repository": repository_id, "fixture": fixture_name},
                    )
        self.state["fixture_hashes"] = fixture_hashes
        return {
            "fixture_count_per_sdk": len(FIXTURE_MEMBERS),
            "sdk_count": len(SDK_FIXTURES),
            "fixture_sha256": fixture_hashes,
        }

    def _package_versions(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        contract_version = self._required_state("contract_version")
        wire = self._required_state("wire_protocol")
        versions: dict[str, str] = {"core": self._required_state("core_version")}

        javascript_package = read_json(repositories["javascript"] / "package.json")
        javascript_source = read_text(repositories["javascript"] / "src/version.ts")
        javascript_version = require_string(javascript_package, "version", "javascript_version")
        if javascript_package.get("name") != "@latchway/client":
            raise VerificationError("javascript_package_name_mismatch")
        require_version_source(
            javascript_source,
            javascript_version,
            contract_version,
            wire,
            "javascript",
        )
        versions["javascript"] = javascript_version

        ios_source = read_text(
            repositories["ios"] / "Sources/Latchway/LatchwayVersion.swift"
        )
        ios_version = require_match(ios_source, r'\bsdk\s*=\s*"([^"]+)"', "ios_version")
        if require_match(
            ios_source, r'\bcontract\s*=\s*"([^"]+)"', "ios_contract"
        ) != contract_version or int(
            require_match(
                ios_source, r'\bprotocolVersion\s*=\s*(\d+)', "ios_protocol"
            )
        ) != wire:
            raise VerificationError("ios_contract_constants_mismatch")
        package_swift = read_text(repositories["ios"] / "Package.swift")
        if re.search(r'\bname:\s*"Latchway"', package_swift) is None:
            raise VerificationError("ios_swift_package_name_mismatch")
        podspec = read_text(repositories["ios"] / "Latchway.podspec")
        pod_version = require_match(
            podspec, r"spec\.version\s*=\s*['\"]([^'\"]+)['\"]", "ios_pod_version"
        )
        if pod_version != ios_version or "tag: \"v#{spec.version}\"" not in podspec:
            raise VerificationError("ios_package_version_mismatch")
        versions["ios"] = ios_version

        android_source = read_text(
            repositories["android"]
            / "latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt"
        )
        android_version = require_match(
            android_source,
            r'LATCHWAY_SDK_VERSION:\s*String\s*=\s*"([^"]+)"',
            "android_version",
        )
        if require_match(
            android_source,
            r'LATCHWAY_CONTRACT_VERSION:\s*String\s*=\s*"([^"]+)"',
            "android_contract",
        ) != contract_version or int(
            require_match(
                android_source,
                r"LATCHWAY_PROTOCOL_VERSION:\s*Int\s*=\s*(\d+)",
                "android_protocol",
            )
        ) != wire:
            raise VerificationError("android_contract_constants_mismatch")
        android_build = read_text(repositories["android"] / "build.gradle.kts")
        default_android_version = require_match(
            android_build,
            r'\.orElse\("([^"]+)"\)\s*\.get\(\)',
            "android_default_version",
        )
        if default_android_version not in (
            android_version,
            f"{android_version}-SNAPSHOT",
        ):
            raise VerificationError("android_package_version_mismatch")
        for artifact in (
            "latchway-core",
            "latchway-okhttp",
            "latchway-play-integrity",
            "latchway-firebase-auth",
            "latchway-bom",
        ):
            if f'path = ":{artifact}"' not in android_build:
                raise VerificationError(
                    "android_publication_missing", {"artifact": artifact}
                )
        versions["android"] = android_version

        react_native_package = read_json(repositories["react_native"] / "package.json")
        react_native_source = read_text(
            repositories["react_native"] / "src/version.ts"
        )
        react_native_version = require_string(
            react_native_package, "version", "react_native_version"
        )
        if react_native_package.get("name") != "@latchway/react-native":
            raise VerificationError("react_native_package_name_mismatch")
        require_version_source(
            react_native_source,
            react_native_version,
            contract_version,
            wire,
            "react_native",
        )
        react_native_android = read_text(
            repositories["react_native"] / "android/build.gradle.kts"
        )
        if require_match(
            react_native_android,
            r'^version\s*=\s*"([^"]+)"',
            "react_native_android_version",
        ) != react_native_version:
            raise VerificationError("react_native_bridge_version_mismatch")
        versions["react_native"] = react_native_version

        for repository_id, version in versions.items():
            if SEMVER.fullmatch(version) is None:
                raise VerificationError(
                    "invalid_package_version", {"repository": repository_id}
                )
        self.state["versions"] = versions
        self.state["intended_tags"] = {
            repository_id: f"v{version}"
            for repository_id, version in versions.items()
        }
        return {"versions": versions}

    def _react_native_pins(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        commits = self._required_state("commits")
        versions = self._required_state("versions")
        fixture_hashes = self._required_state("fixture_hashes")
        compatibility = read_json(
            repositories["react_native"] / "release-compatibility.json"
        )
        if compatibility.get("schema_version") != 1:
            raise VerificationError("unsupported_react_native_compatibility_schema")
        contract = compatibility.get("contract")
        if not isinstance(contract, dict):
            raise VerificationError("react_native_contract_pin_missing")
        expected_contract = {
            "version": self._required_state("contract_version"),
            "wire_protocol": self._required_state("wire_protocol"),
            "core_commit": self._required_state("contract_source_commit"),
            "bundle_sha256": self._required_state("bundle_sha256"),
            "fixtures": fixture_hashes,
        }
        for key, value in expected_contract.items():
            if contract.get(key) != value:
                raise VerificationError(
                    "react_native_contract_pin_mismatch", {"field": key}
                )

        package = read_json(repositories["react_native"] / "package.json")
        react_native = compatibility.get("react_native")
        javascript = compatibility.get("javascript")
        ios = compatibility.get("ios")
        android = compatibility.get("android")
        if not all(isinstance(value, dict) for value in (react_native, javascript, ios, android)):
            raise VerificationError("react_native_dependency_pin_missing")
        if (
            react_native.get("package") != "@latchway/react-native"
            or react_native.get("version") != versions["react_native"]
        ):
            raise VerificationError("react_native_self_pin_mismatch")
        if (
            javascript.get("package") != "@latchway/client"
            or javascript.get("version") != versions["javascript"]
            or javascript.get("source_commit") != commits["javascript"]
            or nested(package, "dependencies", "@latchway/client")
            != versions["javascript"]
        ):
            raise VerificationError("react_native_javascript_pin_mismatch")
        if ios.get("version") != versions["ios"] or ios.get("source_commit") != commits["ios"]:
            raise VerificationError("react_native_ios_pin_mismatch")
        if (
            android.get("version") != versions["android"]
            or android.get("source_commit") != commits["android"]
        ):
            raise VerificationError("react_native_android_pin_mismatch")

        podspec = read_text(repositories["react_native"] / "LatchwayReactNative.podspec")
        ios_pod = ios.get("pod")
        if not isinstance(ios_pod, str) or (
            f'spec.dependency "{ios_pod}", "{versions["ios"]}"' not in podspec
        ):
            raise VerificationError("react_native_pod_source_pin_mismatch")
        android_build = read_text(
            repositories["react_native"] / "android/build.gradle.kts"
        )
        android_group = android.get("group")
        artifacts = android.get("artifacts")
        if not isinstance(android_group, str) or not isinstance(artifacts, list) or not artifacts:
            raise VerificationError("react_native_android_coordinates_invalid")
        for artifact in artifacts:
            if not isinstance(artifact, str) or (
                f'implementation("{android_group}:{artifact}:{versions["android"]}")'
                not in android_build
            ):
                raise VerificationError("react_native_android_source_pin_mismatch")

        expected_repositories = {
            "javascript": "https://github.com/Latchway/latchway-js.git",
            "ios": "https://github.com/Latchway/latchway-ios-sdk.git",
            "android": "https://github.com/Latchway/latchway-android.git",
        }
        for repository_id, expected in expected_repositories.items():
            metadata = compatibility[repository_id]
            if normalize_repository(metadata.get("repository")) != normalize_repository(expected):
                raise VerificationError(
                    "react_native_repository_pin_mismatch",
                    {"repository": repository_id},
                )
        if normalize_repository(contract.get("repository")) != normalize_repository(
            "https://github.com/Latchway/latchway.git"
        ):
            raise VerificationError("react_native_core_repository_pin_mismatch")

        self.state["compatibility"] = compatibility
        return {
            "pinned_source_commits": {
                repository_id: commits[repository_id]
                for repository_id in ("javascript", "ios", "android")
            }
        }

    def _local_promotion_preconditions(self) -> Mapping[str, Any]:
        repositories = self._required_state("repositories")
        versions = self._required_state("versions")
        intended_tags = self._required_state("intended_tags")
        manifest = self._required_state("manifest")
        release_tag = self.configuration.release_tag
        if release_tag is None:
            raise VerificationError("release_tag_required")
        if RELEASE_TAG.fullmatch(release_tag) is None:
            raise VerificationError("release_tag_not_canonical")
        if release_tag != intended_tags["core"]:
            raise VerificationError("core_release_tag_version_mismatch")
        if self._required_state("core_release") != release_tag:
            raise VerificationError("sdk_locks_do_not_name_core_release")
        if manifest.get("contract_status") != "released":
            raise VerificationError("contract_not_marked_released")
        released_at = parse_timestamp(
            manifest.get("released_at"), "contract_released_at_invalid"
        )
        if released_at > self.now:
            raise VerificationError("contract_released_at_in_future")
        if self.now - released_at > MAXIMUM_EVIDENCE_AGE:
            raise VerificationError("contract_released_at_stale")
        image_digest = self.configuration.oci_image_digest
        if (
            not isinstance(image_digest, str)
            or OCI_IMAGE_DIGEST.fullmatch(image_digest) is None
        ):
            raise VerificationError("candidate_oci_image_digest_invalid")

        for repository_id in REPOSITORY_IDS:
            root = repositories[repository_id]
            changelog = read_text(root / "CHANGELOG.md")
            version = versions[repository_id]
            if re.search(
                rf"^## \[{re.escape(version)}\](?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?$",
                changelog,
                flags=re.MULTILINE,
            ) is None:
                raise VerificationError(
                    "release_changelog_entry_missing", {"repository": repository_id}
                )
            forbidden = forbidden_tracked_files(root)
            if forbidden:
                raise VerificationError(
                    "forbidden_release_files_tracked",
                    {"repository": repository_id, "count": len(forbidden)},
                )
        self.state["contract_released_at"] = released_at
        self.state["oci_image_digest"] = image_digest
        self.state["promotion_preconditions_passed"] = True
        return {
            "intended_tags": intended_tags,
            "contract_released_at": manifest["released_at"],
            "oci_image_digest": image_digest,
        }

    def _local_release_preconditions(self) -> Mapping[str, Any]:
        self._required_state("promotion_preconditions_passed")
        repositories = self._required_state("repositories")
        commits = self._required_state("commits")
        intended_tags = self._required_state("intended_tags")
        for repository_id in REPOSITORY_IDS:
            root = repositories[repository_id]
            tag = intended_tags[repository_id]
            try:
                object_type = git(root, "cat-file", "-t", f"refs/tags/{tag}")
                target = git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}")
            except VerificationError:
                raise VerificationError(
                    "release_tag_missing", {"repository": repository_id}
                ) from None
            if object_type != "tag":
                raise VerificationError(
                    "release_tag_not_annotated", {"repository": repository_id}
                )
            if target != commits[repository_id]:
                raise VerificationError(
                    "release_tag_not_at_head", {"repository": repository_id}
                )
        self.state["verified_release_tags"] = intended_tags
        return {
            "tags": intended_tags,
            "annotated_tag_count": len(intended_tags),
        }

    def _verify_external_domain(self, identifier: str, domain: str) -> None:
        evidence_root = self.configuration.external_evidence_dir
        if evidence_root is None:
            self._unverified(
                identifier, domain, True, "external_evidence_directory_not_supplied"
            )
            return
        try:
            root_metadata = evidence_root.lstat()
            if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
                raise VerificationError("external_evidence_directory_invalid")
        except OSError:
            self._unverified(
                identifier, domain, True, "external_evidence_directory_missing"
            )
            return
        document_path = evidence_root / f"{domain}.json"
        if not document_path.exists():
            self._unverified(identifier, domain, True, "external_evidence_missing")
            return

        def verify() -> Mapping[str, Any]:
            document = validate_external_document(
                evidence_root.resolve(),
                document_path,
                domain,
                EXTERNAL_DOMAINS[domain],
                self._external_coordinates(),
                self._required_state("contract_version"),
                self._required_state("bundle_sha256"),
                self._required_state("commits")["core"],
                self.configuration.release_tag,
                self._required_state("contract_released_at"),
                self.now,
                self._required_state("oci_image_digest"),
            )
            external_evidence = self.state.setdefault("external_evidence", {})
            external_evidence[domain] = document
            return document

        self._run(identifier, domain, True, verify)

    def _external_coordinates(self) -> Mapping[str, Mapping[str, str]]:
        commits = self._required_state("commits")
        versions = self._required_state("versions")
        tags = self._required_state("intended_tags")
        return {
            repository_id: {
                "commit": commits[repository_id],
                "tag": tags[repository_id],
                "version": versions[repository_id],
            }
            for repository_id in REPOSITORY_IDS
        }

    def _validate_evidence_window(self) -> Mapping[str, Any]:
        evidence = self._required_state("external_evidence")
        required_domains = (
            RELEASE_DOMAINS
            if self.configuration.scope == "release"
            else PROMOTION_DOMAINS
        )
        if any(domain not in evidence for domain in required_domains):
            raise VerificationError("prerequisite_evidence_failed")
        started = [
            parse_timestamp(evidence[domain]["started_at"], "external_evidence_time_invalid")
            for domain in required_domains
        ]
        finished = [
            parse_timestamp(evidence[domain]["finished_at"], "external_evidence_time_invalid")
            for domain in required_domains
        ]
        earliest = min(started)
        latest = max(finished)
        if latest - earliest > MAXIMUM_EVIDENCE_AGE:
            raise VerificationError("external_evidence_window_too_wide")
        window = {
            "started_at": format_timestamp(earliest),
            "finished_at": format_timestamp(latest),
            "maximum_age_seconds": MAXIMUM_EVIDENCE_SECONDS,
        }
        self.state["evidence_window"] = window
        return window

    def _required_state(self, key: str) -> Any:
        if key not in self.state:
            raise VerificationError("prerequisite_evidence_failed")
        return self.state[key]

    def _contract_summary(self) -> Mapping[str, Any]:
        return {
            "version": self.state.get("contract_version"),
            "status": self.state.get("contract_status"),
            "released_at": self.state.get("released_at"),
            "wire_protocol": self.state.get("wire_protocol"),
            "bundle_file_name": self.state.get("bundle_name"),
            "bundle_sha256": self.state.get("bundle_sha256"),
            "core_release": self.state.get("core_release"),
            "oci_image_digest": self.state.get("oci_image_digest"),
        }

    def _repository_summary(self) -> list[Mapping[str, Any]]:
        commits = self.state.get("commits", {})
        versions = self.state.get("versions", {})
        tags = self.state.get("intended_tags", {})
        return [
            {
                "id": repository_id,
                "commit": commits.get(repository_id),
                "version": versions.get(repository_id),
                "intended_tag": tags.get(repository_id),
            }
            for repository_id in REPOSITORY_IDS
        ]

    def _domain_summary(self) -> list[Mapping[str, Any]]:
        order = [
            "local_source",
            "local_promotion",
            "local_release",
            *EXTERNAL_DOMAINS.keys(),
        ]
        external_evidence = self.state.get("external_evidence", {})
        result: list[Mapping[str, Any]] = []
        for domain in order:
            checks = [check for check in self.checks if check.domain == domain]
            if not checks:
                continue
            if any(check.status == "failed" for check in checks):
                status_value = "failed"
            elif all(check.status == "passed" for check in checks):
                status_value = "passed"
            else:
                status_value = "unverified"
            evidence = external_evidence.get(domain, {})
            result.append(
                {
                    "id": domain,
                    "required": any(check.required for check in checks),
                    "status": status_value,
                    "started_at": evidence.get("started_at"),
                    "finished_at": evidence.get("finished_at"),
                    "document_sha256": evidence.get("document_sha256"),
                    "oci_image_digest": evidence.get("oci_image_digest"),
                    "artifact_sha256": evidence.get("artifact_sha256", []),
                }
            )
        return result


def external_summary(domain: str) -> str:
    labels = {
        "live_sdk_conformance": "All SDKs passed live behavior against the exact release image.",
        "public_tags": "Remote annotated tags and GitHub releases were independently verified.",
        "public_registries": "OCI, npm, Swift/CocoaPods, and Maven artifacts were independently verified.",
        "physical_devices": "Production App Attest and Play Integrity flows passed on required physical distributions.",
        "live_provider": "The bounded live-provider conformance suite passed.",
        "cloud_deployments": "Compose and every claimed cloud deployment passed release-image smoke tests.",
        "operational_resilience": "Load, destructive failure, replica, recovery, and released upgrade gates passed.",
        "supply_chain": "The multi-architecture image, scans, SBOM, signature, and provenance were verified.",
    }
    return labels[domain]


def git(root: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise VerificationError("git_command_failed") from None
    if result.returncode != 0:
        raise VerificationError("git_command_failed")
    return result.stdout.rstrip("\n")


def run_bundle_builder(core: Path, builder: Path, output: Path) -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        result = subprocess.run(
            [sys.executable, str(builder), "--output-directory", str(output)],
            cwd=core,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise VerificationError("contract_bundle_builder_failed") from None
    if result.returncode != 0:
        raise VerificationError("contract_bundle_builder_failed")


def validate_bundle(core: Path, archive: Path) -> dict[str, bytes]:
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            entries = bundle.getmembers()
            if not entries or len(entries) > MAX_BUNDLE_ENTRIES:
                raise VerificationError("contract_bundle_entry_count_invalid")
            names: set[str] = set()
            payloads: dict[str, bytes] = {}
            total_size = 0
            for entry in entries:
                if entry.name in names or not safe_archive_name(entry.name):
                    raise VerificationError("contract_bundle_path_invalid")
                names.add(entry.name)
                if entry.isdir():
                    continue
                if not entry.isfile() or entry.size < 0 or entry.size > MAX_TEXT_BYTES:
                    raise VerificationError("contract_bundle_member_invalid")
                total_size += entry.size
                if total_size > MAX_BUNDLE_BYTES:
                    raise VerificationError("contract_bundle_payload_too_large")
                extracted = bundle.extractfile(entry)
                if extracted is None:
                    raise VerificationError("contract_bundle_member_unreadable")
                payloads[entry.name] = extracted.read(MAX_TEXT_BYTES + 1)
                if len(payloads[entry.name]) != entry.size:
                    raise VerificationError("contract_bundle_member_size_mismatch")
    except VerificationError:
        raise
    except (OSError, tarfile.TarError):
        raise VerificationError("contract_bundle_archive_invalid") from None

    expected_paths: dict[str, Path] = {
        name: core / "api" / name for name in FIXED_CONTRACT_FILES
    }
    vectors = core / "api/test-vectors"
    if not vectors.is_dir() or vectors.is_symlink():
        raise VerificationError("core_test_vectors_missing")
    for path in sorted(vectors.rglob("*")):
        if path.is_symlink():
            raise VerificationError("core_test_vector_symlink")
        if path.is_file():
            expected_paths[path.relative_to(core / "api").as_posix()] = path
    expected_payload_names = set(expected_paths)
    if set(payloads) != expected_payload_names | {"SHA256SUMS"}:
        raise VerificationError("contract_bundle_members_do_not_match_core")
    for name, path in expected_paths.items():
        if not is_real_file(path) or payloads[name] != read_bytes(path):
            raise VerificationError("contract_bundle_member_does_not_match_core")

    checksum_bytes = payloads["SHA256SUMS"]
    try:
        checksum_text = checksum_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise VerificationError("contract_bundle_checksums_invalid") from None
    if not checksum_text.endswith("\n"):
        raise VerificationError("contract_bundle_checksums_invalid")
    checksums: dict[str, str] = {}
    for line in checksum_text.rstrip("\n").split("\n"):
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None or match.group(2) in checksums:
            raise VerificationError("contract_bundle_checksums_invalid")
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != expected_payload_names:
        raise VerificationError("contract_bundle_checksums_incomplete")
    for name in sorted(expected_payload_names):
        if checksums[name] != sha256_bytes(payloads[name]):
            raise VerificationError("contract_bundle_checksum_mismatch")
    return payloads


def safe_archive_name(value: str) -> bool:
    if "\\" in value or value.startswith("/") or value.endswith("//"):
        return False
    path = PurePosixPath(value)
    return bool(value) and path.as_posix() == value and not any(
        part in ("", ".", "..") for part in path.parts
    )


def parse_contract_lock(path: Path) -> dict[str, str]:
    contents = read_text(path)
    values: dict[str, str] = {}
    for line in contents.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = LOCK_LINE.fullmatch(line)
        if match is None:
            raise VerificationError("contract_lock_syntax_invalid")
        key = match.group(1)
        if key in values:
            raise VerificationError("contract_lock_duplicate_field")
        values[key] = match.group(2) if match.group(2) is not None else match.group(3)
    wire_fields = {"wire_protocol", "wire_protocol_version"} & values.keys()
    required = {
        "contract_version",
        "core_release",
        "core_commit",
        "bundle_sha256",
        "minimum_server_version",
        "maximum_tested_server_version",
    }
    allowed = required | {"wire_protocol", "wire_protocol_version"}
    if set(values) - allowed or not required.issubset(values) or len(wire_fields) != 1:
        raise VerificationError("contract_lock_fields_invalid")
    if COMMIT.fullmatch(values["core_commit"]) is None or SHA256.fullmatch(
        values["bundle_sha256"]
    ) is None:
        raise VerificationError("contract_lock_digest_invalid")
    return values


def validate_external_document(
    evidence_root: Path,
    document_path: Path,
    domain: str,
    required_claims: tuple[str, ...],
    coordinates: Mapping[str, Mapping[str, str]],
    contract_version: str,
    bundle_sha256: str,
    core_commit: str,
    core_release: str | None,
    contract_released_at: datetime,
    now: datetime,
    expected_oci_image_digest: str,
) -> Mapping[str, Any]:
    if not is_real_file(document_path) or document_path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise VerificationError("external_evidence_document_invalid")
    document = read_json(document_path, maximum_bytes=MAX_EVIDENCE_BYTES)
    expected_fields = {
        "schema_version",
        "kind",
        "domain",
        "status",
        "started_at",
        "finished_at",
        "core_commit",
        "core_release",
        "contract_version",
        "bundle_sha256",
        "oci_image_digest",
        "repositories",
        "claims",
        "artifacts",
    }
    if set(document) != expected_fields:
        raise VerificationError("external_evidence_fields_invalid")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "latchway_cross_repository_external_evidence"
        or document.get("domain") != domain
        or document.get("status") != "passed"
        or document.get("core_commit") != core_commit
        or document.get("core_release") != core_release
        or document.get("contract_version") != contract_version
        or document.get("bundle_sha256") != bundle_sha256
    ):
        raise VerificationError("external_evidence_identity_mismatch")
    image_digest = document.get("oci_image_digest")
    if not isinstance(image_digest, str) or OCI_IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise VerificationError("external_evidence_oci_digest_invalid")
    if image_digest != expected_oci_image_digest:
        raise VerificationError("external_evidence_oci_digest_mismatch")
    started = parse_timestamp(document.get("started_at"), "external_evidence_time_invalid")
    finished = parse_timestamp(document.get("finished_at"), "external_evidence_time_invalid")
    if finished <= started or finished - started > MAXIMUM_EVIDENCE_AGE:
        raise VerificationError("external_evidence_time_invalid")
    if started < contract_released_at:
        raise VerificationError("external_evidence_precedes_contract_release")
    if finished > now:
        raise VerificationError("external_evidence_time_in_future")
    if now - finished > MAXIMUM_EVIDENCE_AGE:
        raise VerificationError("external_evidence_stale")
    if document.get("repositories") != coordinates:
        raise VerificationError("external_evidence_repository_mismatch")
    claims = document.get("claims")
    if not isinstance(claims, dict) or set(claims) != set(required_claims):
        raise VerificationError("external_evidence_claims_invalid")
    if any(claims[claim] is not True for claim in required_claims):
        raise VerificationError("external_evidence_claim_failed")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 64:
        raise VerificationError("external_evidence_artifacts_invalid")
    seen: set[str] = set()
    hashes: list[str] = []
    total_size = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise VerificationError("external_evidence_artifacts_invalid")
        relative = artifact.get("path")
        expected_hash = artifact.get("sha256")
        if (
            not isinstance(relative, str)
            or not safe_relative_path(relative)
            or relative in seen
            or not isinstance(expected_hash, str)
            or SHA256.fullmatch(expected_hash) is None
        ):
            raise VerificationError("external_evidence_artifacts_invalid")
        seen.add(relative)
        artifact_path = evidence_root / PurePosixPath(relative)
        if has_symlink_component(evidence_root, PurePosixPath(relative)):
            raise VerificationError("external_evidence_artifact_unsafe")
        if not is_real_file(artifact_path):
            raise VerificationError("external_evidence_artifact_missing")
        try:
            resolved = artifact_path.resolve(strict=True)
            resolved.relative_to(evidence_root)
        except (OSError, ValueError):
            raise VerificationError("external_evidence_artifact_unsafe") from None
        size = resolved.stat().st_size
        total_size += size
        if size > MAX_ARTIFACT_BYTES or total_size > MAX_ARTIFACT_BYTES:
            raise VerificationError("external_evidence_artifact_too_large")
        actual_hash = sha256_file(resolved)
        if actual_hash != expected_hash:
            raise VerificationError("external_evidence_artifact_hash_mismatch")
        hashes.append(actual_hash)
    return {
        "document_sha256": sha256_file(document_path),
        "oci_image_digest": image_digest,
        "started_at": format_timestamp(started),
        "finished_at": format_timestamp(finished),
        "artifact_count": len(artifacts),
        "artifact_sha256": sorted(hashes),
    }


def safe_relative_path(value: str) -> bool:
    if not value or "\\" in value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return path.as_posix() == value and not any(
        part in ("", ".", "..") for part in path.parts
    )


def has_symlink_component(root: Path, relative: PurePosixPath) -> bool:
    current = root
    for part in relative.parts:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except OSError:
            return False
    return False


def semver_key(value: str) -> tuple[int, int, int, int]:
    core, separator, _ = value.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    # A stable release sorts after a prerelease with the same numeric core.
    return major, minor, patch, 1 if not separator else 0


def parse_timestamp(value: Any, error_code: str) -> datetime:
    if not isinstance(value, str) or CANONICAL_UTC.fullmatch(value) is None:
        raise VerificationError(error_code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise VerificationError(error_code) from None
    if parsed.tzinfo != timezone.utc:
        raise VerificationError(error_code)
    return parsed


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def forbidden_tracked_files(root: Path) -> list[str]:
    output = git(root, "ls-files", "-z")
    forbidden = re.compile(
        r"(^|/)(?:\.env(?:\.[^/]*)?|Pods|DerivedData|\.build|\.gradle|"
        r"\.artifacts|node_modules|build)(?:/|$)|"
        r"\.(?:jks|keystore|p8|p12|cer|mobileprovision)$"
    )
    result = []
    for path in output.split("\0"):
        if path and forbidden.search(path) and not re.search(r"(^|/)\.env\.example$", path):
            result.append(path)
    return result


def require_version_source(
    contents: str,
    version: str,
    contract_version: str,
    protocol: int,
    label: str,
) -> None:
    if (
        require_match(contents, r'SDK_VERSION\s*=\s*"([^"]+)"', f"{label}_version")
        != version
        or require_match(
            contents, r'CONTRACT_VERSION\s*=\s*"([^"]+)"', f"{label}_contract"
        )
        != contract_version
        or int(
            require_match(
                contents, r"PROTOCOL_VERSION\s*=\s*(\d+)", f"{label}_protocol"
            )
        )
        != protocol
    ):
        raise VerificationError(f"{label}_version_constants_mismatch")


def normalize_repository(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value.removeprefix("git+").removesuffix(".git").lower()


def nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def require_string(value: Mapping[str, Any], key: str, error_code: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise VerificationError(error_code)
    return result


def require_match(contents: str, expression: str, error_code: str) -> str:
    match = re.search(expression, contents, flags=re.MULTILINE)
    if match is None or not match.group(1):
        raise VerificationError(error_code)
    return match.group(1)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("json_duplicate_key")
        result[key] = value
    return result


def read_json(path: Path, maximum_bytes: int = MAX_TEXT_BYTES) -> dict[str, Any]:
    try:
        contents = read_bytes(path, maximum_bytes).decode("utf-8")
        value = json.loads(contents, object_pairs_hook=strict_object)
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VerificationError("json_document_invalid") from None
    if not isinstance(value, dict):
        raise VerificationError("json_root_not_object")
    return value


def schema_pointer(document: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise VerificationError("release_evidence_schema_reference_invalid")
    current: Any = document
    for encoded in reference[2:].split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            raise VerificationError("release_evidence_schema_reference_invalid")
        current = current[key]
    if not isinstance(current, dict):
        raise VerificationError("release_evidence_schema_reference_invalid")
    return current


def schema_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise VerificationError("release_evidence_schema_type_invalid")


def schema_format_matches(value: str, format_name: str) -> bool:
    if format_name != "date-time":
        raise VerificationError("release_evidence_schema_format_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return "T" in value and parsed.tzinfo is not None


def release_schema_errors(
    root: Mapping[str, Any],
    schema: Mapping[str, Any],
    value: Any,
    location: str = "$",
) -> list[str]:
    errors: list[str] = []
    reference = schema.get("$ref")
    if isinstance(reference, str):
        errors.extend(
            release_schema_errors(root, schema_pointer(root, reference), value, location)
        )
    for subschema in schema.get("allOf", []):
        errors.extend(release_schema_errors(root, subschema, value, location))
    if "anyOf" in schema:
        outcomes = [
            release_schema_errors(root, subschema, value, location)
            for subschema in schema["anyOf"]
        ]
        if all(outcome for outcome in outcomes):
            errors.append(f"{location}:anyOf")
    if "oneOf" in schema:
        matches = sum(
            not release_schema_errors(root, subschema, value, location)
            for subschema in schema["oneOf"]
        )
        if matches != 1:
            errors.append(f"{location}:oneOf")
    condition = schema.get("if")
    if isinstance(condition, dict):
        branch = schema.get("then", {}) if not release_schema_errors(
            root, condition, value, location
        ) else schema.get("else", {})
        errors.extend(release_schema_errors(root, branch, value, location))

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(schema_type_matches(value, candidate) for candidate in allowed):
            return errors + [f"{location}:type"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}:const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{location}:enum")

    if isinstance(value, dict):
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{location}:required")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties")
        for key, child in value.items():
            if key in properties:
                errors.extend(
                    release_schema_errors(
                        root, properties[key], child, f"{location}.{key}"
                    )
                )
            elif additional is False:
                errors.append(f"{location}:additionalProperties")
            elif isinstance(additional, dict):
                errors.extend(
                    release_schema_errors(
                        root, additional, child, f"{location}.{key}"
                    )
                )
        if len(value) < schema.get("minProperties", 0):
            errors.append(f"{location}:minProperties")
        maximum_properties = schema.get("maxProperties")
        if isinstance(maximum_properties, int) and len(value) > maximum_properties:
            errors.append(f"{location}:maxProperties")
        property_names = schema.get("propertyNames")
        if isinstance(property_names, dict):
            for key in value:
                errors.extend(
                    release_schema_errors(
                        root, property_names, key, f"{location}.propertyName"
                    )
                )

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{location}:minItems")
        maximum_items = schema.get("maxItems")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            errors.append(f"{location}:maxItems")
        if schema.get("uniqueItems") is True:
            encoded = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{location}:uniqueItems")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, child in enumerate(value):
                errors.extend(
                    release_schema_errors(
                        root, items, child, f"{location}[{index}]"
                    )
                )

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{location}:minLength")
        maximum_length = schema.get("maxLength")
        if isinstance(maximum_length, int) and len(value) > maximum_length:
            errors.append(f"{location}:maxLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            errors.append(f"{location}:pattern")
        format_name = schema.get("format")
        if isinstance(format_name, str) and not schema_format_matches(value, format_name):
            errors.append(f"{location}:format")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{location}:minimum")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and value > maximum:
            errors.append(f"{location}:maximum")
    return errors


def validate_release_report(report: Mapping[str, Any], schema_path: Path) -> None:
    schema = read_json(schema_path, maximum_bytes=MAX_EVIDENCE_BYTES)
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != "https://latchway.dev/schemas/release-evidence.schema.json"
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        raise VerificationError("release_evidence_schema_invalid")
    errors = release_schema_errors(schema, schema, report)
    if errors:
        raise VerificationError(
            "release_evidence_report_schema_invalid", {"error_count": len(errors)}
        )


def read_text(path: Path, maximum_bytes: int = MAX_TEXT_BYTES) -> str:
    try:
        return read_bytes(path, maximum_bytes).decode("utf-8")
    except UnicodeDecodeError:
        raise VerificationError("source_file_not_utf8") from None


def read_bytes(path: Path, maximum_bytes: int = MAX_TEXT_BYTES) -> bytes:
    if not is_real_file(path):
        raise VerificationError("required_source_file_missing")
    try:
        if path.stat().st_size > maximum_bytes:
            raise VerificationError("source_file_too_large")
        with path.open("rb") as source:
            value = source.read(maximum_bytes + 1)
    except OSError:
        raise VerificationError("required_source_file_unreadable") from None
    if len(value) > maximum_bytes:
        raise VerificationError("source_file_too_large")
    return value


def is_real_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, report: Mapping[str, Any]) -> None:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write(path, payload)


def write_junit(path: Path, report: Mapping[str, Any]) -> None:
    checks = report["checks"]
    failures = sum(
        1
        for check in checks
        if check["status"] == "failed"
        or (check["required"] and check["status"] != "passed")
    )
    skipped = sum(
        1
        for check in checks
        if not check["required"] and check["status"] == "unverified"
    )
    suite = ET.Element(
        "testsuite",
        {
            "name": "latchway-cross-repository-conformance",
            "tests": str(len(checks)),
            "failures": str(failures),
            "errors": "0",
            "skipped": str(skipped),
        },
    )
    properties = ET.SubElement(suite, "properties")
    for name in (
        "scope",
        "source_conformance_passed",
        "promotion_ready",
        "release_ready",
    ):
        ET.SubElement(
            properties,
            "property",
            {"name": name, "value": str(report[name]).lower()},
        )
    for check in checks:
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": check["domain"], "name": check["id"]},
        )
        if check["status"] == "failed" or (
            check["required"] and check["status"] != "passed"
        ):
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "message": check.get("reason", "required_evidence_not_passed"),
                    "type": "verification",
                },
            )
            failure.text = check["summary"]
        elif check["status"] == "unverified":
            ET.SubElement(
                case,
                "skipped",
                {"message": check.get("reason", "not_requested")},
            )
    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    payload = ET.tostring(suite, encoding="utf-8", xml_declaration=True) + b"\n"
    atomic_write(path, payload)


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def ensure_output_outside_repositories(
    output: Path, junit: Path, repositories: Mapping[str, Path]
) -> None:
    for candidate in (output, junit):
        resolved_candidate = candidate.resolve(strict=False)
        for repository_id, repository in repositories.items():
            try:
                resolved_candidate.relative_to(repository.resolve())
            except ValueError:
                continue
            raise VerificationError(
                "evidence_output_inside_source_repository",
                {"repository": repository_id},
            )


def repository_paths(arguments: argparse.Namespace) -> dict[str, Path]:
    workspace = arguments.workspace_root.resolve()
    configured = {
        "core": arguments.core_repo,
        "javascript": arguments.javascript_repo,
        "ios": arguments.ios_repo,
        "android": arguments.android_repo,
        "react_native": arguments.react_native_repo,
    }
    return {
        repository_id: (
            configured[repository_id]
            if configured[repository_id] is not None
            else workspace / DEFAULT_REPOSITORY_NAMES[repository_id]
        ).absolute()
        for repository_id in REPOSITORY_IDS
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope", choices=("source", "promotion", "release"), default="source"
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=SCRIPT_ROOT.parent,
        help="directory containing the five repositories",
    )
    parser.add_argument("--core-repo", type=Path)
    parser.add_argument("--javascript-repo", type=Path)
    parser.add_argument("--ios-repo", type=Path)
    parser.add_argument("--android-repo", type=Path)
    parser.add_argument("--react-native-repo", type=Path)
    parser.add_argument(
        "--release-tag",
        help="intended core tag; required in promotion/release scope and verified as annotated in release scope",
    )
    parser.add_argument(
        "--oci-image-digest",
        help="exact immutable ghcr.io/latchway/latchway candidate digest; required in promotion/release scope",
    )
    parser.add_argument(
        "--external-evidence-dir",
        type=Path,
        help="promotion/release directory containing fixed external evidence documents",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--junit-output",
        type=Path,
        help="JUnit path (default: <output>.junit.xml)",
    )
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.scope == "source" and (
        arguments.release_tag is not None
        or arguments.oci_image_digest is not None
        or arguments.external_evidence_dir is not None
    ):
        build_parser().error(
            "--release-tag, --oci-image-digest, and --external-evidence-dir are valid only in promotion/release scope"
        )
    repositories = repository_paths(arguments)
    output = arguments.output.absolute()
    junit = (
        arguments.junit_output.absolute()
        if arguments.junit_output is not None
        else Path(f"{output}.junit.xml")
    )
    try:
        ensure_output_outside_repositories(output, junit, repositories)
    except VerificationError as error:
        print(f"cross-repository conformance failed: {error.code}", file=sys.stderr)
        return 2

    configuration = Configuration(
        scope=arguments.scope,
        repositories=repositories,
        release_tag=arguments.release_tag,
        oci_image_digest=arguments.oci_image_digest,
        external_evidence_dir=(
            arguments.external_evidence_dir.absolute()
            if arguments.external_evidence_dir is not None
            else None
        ),
    )
    report = Evaluator(configuration).evaluate()
    try:
        validate_release_report(
            report,
            repositories["core"] / "api/release-evidence.schema.json",
        )
        write_json(output, report)
        write_junit(junit, report)
    except VerificationError as error:
        print(f"cross-repository conformance failed: {error.code}", file=sys.stderr)
        return 2
    except OSError:
        print("cross-repository conformance failed: evidence_write_failed", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
