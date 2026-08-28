#!/usr/bin/env python3
"""Tests for the offline cross-repository evidence orchestrator."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


CORE_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = CORE_ROOT / "scripts/cross-repo-conformance.py"
BUILDER = CORE_ROOT / "scripts/build-contract-bundle.py"


class SyntheticWorkspace:
    version = "1.0.0"
    contract_version = "1.0.0"
    wire_protocol = 1
    core_release = "v1.0.0"
    oci_image_digest = (
        "ghcr.io/latchway/latchway@sha256:"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    def __init__(self, root: Path):
        self.root = root
        self.repositories = {
            "core": root / "latchway",
            "javascript": root / "latchway-js",
            "ios": root / "latchway-ios-sdk",
            "android": root / "latchway-android",
            "react_native": root / "latchway-react-native-sdk",
        }
        self.commits: dict[str, str] = {}
        self.bundle_sha256 = ""
        self.fixture_sha256: dict[str, str] = {}

    def create(self) -> None:
        self._create_core()
        self._create_javascript()
        self._create_ios()
        self._create_android()
        self._create_react_native()
        for repository_id, repository in self.repositories.items():
            self.git(repository, "tag", "-a", self.core_release, "-m", "Release 1.0.0")
            self.commits[repository_id] = self.git(repository, "rev-parse", "HEAD")

    def _create_core(self) -> None:
        root = self.repositories["core"]
        manifest = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "manifest_version": 1,
            "contract_version": self.contract_version,
            "contract_status": "released",
            "wire_protocol": {"current": 1, "supported": [1], "minimum": 1},
            "bundle": {
                "file_name": "latchway-contract-1.0.0.tar.gz",
                "required_entries": [
                    "client.openapi.yaml",
                    "admin.openapi.yaml",
                    "config.schema.json",
                    "attestation-binding.schema.json",
                    "error-codes.yaml",
                    "protocol-version.json",
                    "test-vectors",
                    "SHA256SUMS",
                ],
            },
            "sdk_kinds": ["ios", "android", "javascript", "react-native"],
            "released_at": "2026-08-29T00:00:00Z",
        }
        self.write_json(root / "api/protocol-version.json", manifest)
        for relative, contents in {
            "api/admin.openapi.yaml": "openapi: 3.1.0\ninfo: {title: admin, version: 1.0.0}\n",
            "api/client.openapi.yaml": "openapi: 3.1.0\ninfo: {title: client, version: 1.0.0}\n",
            "api/config.schema.json": '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n',
            "api/attestation-binding.schema.json": '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n',
            "api/error-codes.yaml": "errors: []\n",
            "api/test-vectors/dpop/v1.json": '{"schema_version":1,"vectors":[]}\n',
            "api/test-vectors/dpop/vector.schema.json": '{"type":"object"}\n',
            "api/test-vectors/attestation-binding/v1.json": '{"schema_version":1,"vectors":[]}\n',
            "api/test-vectors/attestation-binding/vector.schema.json": '{"type":"object"}\n',
            "internal/buildinfo/buildinfo.go": (
                'package buildinfo\n\nvar (\n\tVersion = "1.0.0"\n)\n\n'
                'const (\n\tContractVersion = "1.0.0"\n\tProtocolVersion = "1"\n)\n'
            ),
            "CHANGELOG.md": "# Changelog\n\n## [1.0.0] - 2026-08-29\n\n- Release.\n",
        }.items():
            self.write(root / relative, contents)
        self.write_json(
            root / "web/console/package.json",
            {"name": "@latchway/admin-console", "version": "1.0.0", "private": True},
        )
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BUILDER, root / "scripts/build-contract-bundle.py")

        with tempfile.TemporaryDirectory(prefix="latchway-test-bundle-") as temporary:
            subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts/build-contract-bundle.py"),
                    "--output-directory",
                    temporary,
                ],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            archive = Path(temporary) / "latchway-contract-1.0.0.tar.gz"
            self.bundle_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.fixture_sha256 = {
            "attestation-binding-v1.json": self.sha256(
                root / "api/test-vectors/attestation-binding/v1.json"
            ),
            "dpop-v1.json": self.sha256(root / "api/test-vectors/dpop/v1.json"),
            "protocol-version.json": self.sha256(root / "api/protocol-version.json"),
        }
        self.init_and_commit(root)
        self.commits["core"] = self.git(root, "rev-parse", "HEAD")

    def _create_javascript(self) -> None:
        root = self.repositories["javascript"]
        self.write(root / "contract.lock", self.lock("wire_protocol_version"))
        self.write_json(
            root / "package.json",
            {
                "name": "@latchway/client",
                "version": self.version,
                "dependencies": {},
                "repository": {
                    "url": "git+https://github.com/Latchway/latchway-js.git"
                },
            },
        )
        self.write(
            root / "src/version.ts",
            'export const SDK_VERSION = "1.0.0";\n'
            'export const CONTRACT_VERSION = "1.0.0";\n'
            "export const PROTOCOL_VERSION = 1;\n"
            'export const SDK_KIND = "javascript";\n',
        )
        self.copy_fixtures(root / "test/fixtures/contract")
        self.write(root / "CHANGELOG.md", "# Changelog\n\n## [1.0.0]\n\n- Release.\n")
        self.init_and_commit(root)
        self.commits["javascript"] = self.git(root, "rev-parse", "HEAD")

    def _create_ios(self) -> None:
        root = self.repositories["ios"]
        self.write(root / "contract.lock", self.lock("wire_protocol"))
        self.write(
            root / "Package.swift",
            '// swift-tools-version: 6.2\nimport PackageDescription\n'
            'let package = Package(name: "Latchway")\n',
        )
        self.write(
            root / "Sources/Latchway/LatchwayVersion.swift",
            'public enum LatchwayVersion {\n'
            '  public static let sdk = "1.0.0"\n'
            '  public static let contract = "1.0.0"\n'
            "  public static let protocolVersion = 1\n"
            "}\n",
        )
        self.write(
            root / "Latchway.podspec",
            "Pod::Spec.new do |spec|\n"
            "  spec.name = 'Latchway'\n"
            "  spec.version = '1.0.0'\n"
            '  spec.source = { git: "https://github.com/Latchway/latchway-ios-sdk.git", tag: "v#{spec.version}" }\n'
            "end\n",
        )
        self.copy_fixtures(root / "Tests/ConformanceTests/Fixtures")
        self.write(root / "CHANGELOG.md", "# Changelog\n\n## [1.0.0]\n\n- Release.\n")
        self.init_and_commit(root)
        self.commits["ios"] = self.git(root, "rev-parse", "HEAD")

    def _create_android(self) -> None:
        root = self.repositories["android"]
        self.write(root / "contract.lock", self.lock("wire_protocol"))
        self.write(
            root / "latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt",
            'public const val LATCHWAY_SDK_VERSION: String = "1.0.0"\n'
            'public const val LATCHWAY_CONTRACT_VERSION: String = "1.0.0"\n'
            "public const val LATCHWAY_PROTOCOL_VERSION: Int = 1\n",
        )
        modules = "\n".join(
            f'    PublishedModule(path = ":{artifact}"),'
            for artifact in (
                "latchway-core",
                "latchway-okhttp",
                "latchway-play-integrity",
                "latchway-firebase-auth",
                "latchway-bom",
            )
        )
        self.write(
            root / "build.gradle.kts",
            "data class PublishedModule(val path: String)\n"
            "val releaseVersion = providers.gradleProperty(\"latchway.version\")\n"
            '    .orElse("1.0.0-SNAPSHOT")\n'
            "    .get()\n"
            "val publishedModules = listOf(\n"
            f"{modules}\n"
            ")\n",
        )
        self.copy_fixtures(root / "latchway-core/src/test/resources/contract")
        self.write(root / "CHANGELOG.md", "# Changelog\n\n## [1.0.0]\n\n- Release.\n")
        self.init_and_commit(root)
        self.commits["android"] = self.git(root, "rev-parse", "HEAD")

    def _create_react_native(self) -> None:
        root = self.repositories["react_native"]
        self.write(root / "contract.lock", self.lock("wire_protocol"))
        self.write_json(
            root / "package.json",
            {
                "name": "@latchway/react-native",
                "version": self.version,
                "dependencies": {"@latchway/client": self.version},
                "repository": {
                    "url": "git+https://github.com/Latchway/latchway-react-native-sdk.git"
                },
            },
        )
        self.write(
            root / "src/version.ts",
            'export const SDK_VERSION = "1.0.0";\n'
            'export const CONTRACT_VERSION = "1.0.0";\n'
            "export const PROTOCOL_VERSION = 1;\n"
            'export const SDK_KIND = "react-native";\n',
        )
        self.write(
            root / "android/build.gradle.kts",
            'version = "1.0.0"\n'
            'dependencies {\n  implementation("dev.latchway:latchway-okhttp:1.0.0")\n'
            '  implementation("dev.latchway:latchway-play-integrity:1.0.0")\n}\n',
        )
        self.write(
            root / "LatchwayReactNative.podspec",
            'spec.dependency "Latchway/AppAttest", "1.0.0"\n',
        )
        self.copy_fixtures(root / "test/fixtures/contract")
        self.write_json(
            root / "release-compatibility.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "schema_version": 1,
                "contract": {
                    "version": self.contract_version,
                    "wire_protocol": self.wire_protocol,
                    "repository": "https://github.com/Latchway/latchway.git",
                    "core_commit": self.commits["core"],
                    "bundle_sha256": self.bundle_sha256,
                    "fixtures": self.fixture_sha256,
                },
                "react_native": {
                    "package": "@latchway/react-native",
                    "version": self.version,
                },
                "javascript": {
                    "package": "@latchway/client",
                    "version": self.version,
                    "repository": "https://github.com/Latchway/latchway-js.git",
                    "source_commit": self.commits["javascript"],
                },
                "ios": {
                    "pod": "Latchway/AppAttest",
                    "version": self.version,
                    "repository": "https://github.com/Latchway/latchway-ios-sdk.git",
                    "source_commit": self.commits["ios"],
                },
                "android": {
                    "group": "dev.latchway",
                    "artifacts": ["latchway-okhttp", "latchway-play-integrity"],
                    "version": self.version,
                    "repository": "https://github.com/Latchway/latchway-android.git",
                    "source_commit": self.commits["android"],
                },
            },
        )
        self.write(root / "CHANGELOG.md", "# Changelog\n\n## [1.0.0]\n\n- Release.\n")
        self.init_and_commit(root)
        self.commits["react_native"] = self.git(root, "rev-parse", "HEAD")

    def create_external_evidence(self, root: Path) -> None:
        coordinates = {
            repository_id: {
                "commit": self.commits[repository_id],
                "tag": self.core_release,
                "version": self.version,
            }
            for repository_id in self.repositories
        }
        for domain, claims in EXTERNAL_CLAIMS.items():
            artifact = root / "artifacts" / f"{domain}.txt"
            self.write(artifact, f"bounded {domain} evidence\n")
            document = {
                "schema_version": 1,
                "kind": "latchway_cross_repository_external_evidence",
                "domain": domain,
                "status": "passed",
                "started_at": "2026-08-29T00:00:00Z",
                "finished_at": "2026-08-29T00:10:00Z",
                "core_commit": self.commits["core"],
                "core_release": self.core_release,
                "contract_version": self.contract_version,
                "bundle_sha256": self.bundle_sha256,
                "oci_image_digest": self.oci_image_digest,
                "repositories": coordinates,
                "claims": {claim: True for claim in claims},
                "artifacts": [
                    {
                        "path": f"artifacts/{domain}.txt",
                        "sha256": self.sha256(artifact),
                    }
                ],
            }
            self.write_json(root / f"{domain}.json", document)

    def lock(self, wire_field: str) -> str:
        return (
            f"contract_version: {self.contract_version}\n"
            f"{wire_field}: {self.wire_protocol}\n"
            f"core_release: {self.core_release}\n"
            f"core_commit: {self.commits['core']}\n"
            f'bundle_sha256: "{self.bundle_sha256}"\n'
            f"minimum_server_version: {self.contract_version}\n"
            "maximum_tested_server_version: 1.0.x\n"
        )

    def copy_fixtures(self, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        core = self.repositories["core"] / "api"
        shutil.copyfile(
            core / "test-vectors/attestation-binding/v1.json",
            destination / "attestation-binding-v1.json",
        )
        shutil.copyfile(
            core / "test-vectors/dpop/v1.json", destination / "dpop-v1.json"
        )
        shutil.copyfile(
            core / "protocol-version.json", destination / "protocol-version.json"
        )

    def init_and_commit(self, root: Path) -> None:
        self.git(root, "init", "--initial-branch=main")
        self.git(root, "config", "user.name", "Latchway test")
        self.git(root, "config", "user.email", "test@latchway.invalid")
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "test: fixture")

    @staticmethod
    def git(root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    @staticmethod
    def write(path: Path, contents: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    @classmethod
    def write_json(cls, path: Path, value: object) -> None:
        cls.write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()


EXTERNAL_CLAIMS = {
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
    "public_tags": ("remote_annotated_tags_verified", "github_releases_verified"),
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
        "released_version_upgrade_rollback_verified",
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


class CrossRepositoryConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-cross-repo-test-")
        self.root = Path(self.temporary.name)
        self.workspace = SyntheticWorkspace(self.root / "workspace")
        self.workspace.create()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_gate(
        self,
        name: str,
        *,
        scope: str = "source",
        external: Path | None = None,
        output: Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object], Path, Path]:
        output = output or self.root / "reports" / f"{name}.json"
        junit = self.root / "reports" / f"{name}.xml"
        command = [
            sys.executable,
            str(SCRIPT),
            "--workspace-root",
            str(self.workspace.root),
            "--scope",
            scope,
            "--output",
            str(output),
            "--junit-output",
            str(junit),
        ]
        if scope == "release":
            command.extend(["--release-tag", self.workspace.core_release])
            if external is not None:
                command.extend(["--external-evidence-dir", str(external)])
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        report = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
        return result, report, output, junit

    def test_source_scope_passes_without_claiming_external_evidence(self) -> None:
        result, report, _, junit = self.run_gate("source-pass")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["verdict"], "passed")
        self.assertTrue(report["source_conformance_passed"])
        self.assertFalse(report["release_ready"])
        external = [
            domain
            for domain in report["evidence_domains"]
            if domain["id"] not in ("local_source", "local_release")
        ]
        self.assertTrue(external)
        self.assertTrue(all(domain["status"] == "unverified" for domain in external))
        self.assertIn(
            f'skipped="{len(EXTERNAL_CLAIMS) + 1}"',
            junit.read_text(encoding="utf-8"),
        )

    def test_source_scope_is_byte_deterministic_and_redaction_safe(self) -> None:
        first_result, _, first_json, first_junit = self.run_gate("first")
        second_result, _, second_json, second_junit = self.run_gate("second")
        self.assertEqual(first_result.returncode, 0)
        self.assertEqual(second_result.returncode, 0)
        self.assertEqual(first_json.read_bytes(), second_json.read_bytes())
        self.assertEqual(first_junit.read_bytes(), second_junit.read_bytes())

        secret = "provider-token-must-not-appear"
        (self.workspace.repositories["javascript"] / secret).write_text(
            "sensitive", encoding="utf-8"
        )
        result, report, output, junit = self.run_gate("dirty-redaction")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["verdict"], "failed")
        combined = output.read_text(encoding="utf-8") + junit.read_text(encoding="utf-8")
        self.assertNotIn(secret, combined)
        dirty = next(
            check for check in report["checks"] if check["id"] == "source.clean_worktrees"
        )
        self.assertEqual(dirty["reason"], "dirty_worktrees")

    def test_lock_and_generated_fixture_drift_fail_closed(self) -> None:
        lock = self.workspace.repositories["ios"] / "contract.lock"
        lock.write_text(
            lock.read_text(encoding="utf-8").replace(self.workspace.bundle_sha256, "0" * 64),
            encoding="utf-8",
        )
        fixture = (
            self.workspace.repositories["android"]
            / "latchway-core/src/test/resources/contract/dpop-v1.json"
        )
        fixture.write_text('{"tampered":true}\n', encoding="utf-8")
        result, report, _, _ = self.run_gate("drift")
        self.assertEqual(result.returncode, 1)
        reasons = {check.get("reason") for check in report["checks"]}
        self.assertIn("sdk_contract_locks_disagree", reasons)
        self.assertIn("sdk_fixture_mismatch", reasons)

    def test_release_scope_requires_every_external_domain(self) -> None:
        result, report, _, junit = self.run_gate("release-missing", scope="release")
        self.assertEqual(result.returncode, 1)
        self.assertTrue(report["source_conformance_passed"])
        self.assertFalse(report["release_ready"])
        external = [
            check for check in report["checks"] if check["id"].startswith("external.")
        ]
        self.assertEqual(len(external), len(EXTERNAL_CLAIMS))
        self.assertTrue(all(check["required"] for check in external))
        self.assertTrue(all(check["status"] == "unverified" for check in external))
        self.assertIn(f'failures="{len(EXTERNAL_CLAIMS)}"', junit.read_text(encoding="utf-8"))

    def test_release_scope_accepts_only_hash_bound_external_evidence(self) -> None:
        evidence = self.root / "external"
        self.workspace.create_external_evidence(evidence)
        result, report, _, _ = self.run_gate(
            "release-pass", scope="release", external=evidence
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["verdict"], "passed")
        self.assertTrue(report["release_ready"])

        artifact = evidence / "artifacts/physical_devices.txt"
        artifact.write_text("changed after sign-off\n", encoding="utf-8")
        result, report, _, _ = self.run_gate(
            "release-tamper", scope="release", external=evidence
        )
        self.assertEqual(result.returncode, 1)
        physical = next(
            check for check in report["checks"] if check["id"] == "external.physical_devices"
        )
        self.assertEqual(physical["reason"], "external_evidence_artifact_hash_mismatch")

    def test_release_scope_rejects_cross_domain_oci_digest_substitution(self) -> None:
        evidence = self.root / "external"
        self.workspace.create_external_evidence(evidence)
        supply_chain_path = evidence / "supply_chain.json"
        supply_chain = json.loads(supply_chain_path.read_text(encoding="utf-8"))
        supply_chain["oci_image_digest"] = (
            "ghcr.io/latchway/latchway@sha256:"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        SyntheticWorkspace.write_json(supply_chain_path, supply_chain)
        result, report, _, _ = self.run_gate(
            "release-image-substitution", scope="release", external=evidence
        )
        self.assertEqual(result.returncode, 1)
        supply_chain_check = next(
            check for check in report["checks"] if check["id"] == "external.supply_chain"
        )
        self.assertEqual(
            supply_chain_check["reason"], "external_evidence_oci_digest_mismatch"
        )

    def test_evidence_output_inside_source_checkout_is_rejected(self) -> None:
        output = self.workspace.repositories["core"] / "evidence.json"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--workspace-root",
                str(self.workspace.root),
                "--output",
                str(output),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertIn("evidence_output_inside_source_repository", result.stderr)


if __name__ == "__main__":
    unittest.main()
