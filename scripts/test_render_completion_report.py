#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/render-completion-report.py"
SPEC = importlib.util.spec_from_file_location("render_completion_report", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load completion report renderer")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


COMMIT = "a" * 40
HASH = "b" * 64
DOCUMENT_HASH = "c" * 64
TAG = "v1.0.0"
OCI = f"ghcr.io/latchway/latchway@sha256:{HASH}"


class RenderCompletionReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-final-report-")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        (self.repository / "migrations").mkdir(parents=True)
        (self.repository / "migrations/000001_first.sql").write_text("select 1;\n")
        (self.repository / "migrations/000002_second.sql").write_text("select 2;\n")
        versions = {
            "core": "1.0.0",
            "javascript": "1.0.0",
            "ios": "1.0.0",
            "android": "1.0.0",
            "react_native": "1.0.0",
        }
        commits = {
            "core": COMMIT,
            "javascript": "1" * 40,
            "ios": "2" * 40,
            "android": "3" * 40,
            "react_native": "4" * 40,
        }
        self.repositories = [
            {
                "id": identifier,
                "commit": commits[identifier],
                "version": versions[identifier],
                "intended_tag": f"v{versions[identifier]}",
            }
            for identifier in MODULE.REPOSITORY_IDS
        ]
        self.candidate = {
            "schema_version": 1,
            "kind": "latchway_release_candidate",
            "status": "passed",
            "created_at": "2026-08-29T01:00:00Z",
            "candidate_commit": COMMIT,
            "intended_tag": TAG,
            "version": "1.0.0",
            "contract": {
                "version": "0.5.1",
                "status": "released",
                "released_at": "2026-08-29T00:00:00Z",
                "bundle_file_name": "latchway-contract-0.5.1.tar.gz",
                "bundle_sha256": HASH,
            },
            "image": {
                "repository": "ghcr.io/latchway/latchway",
                "index_digest": f"sha256:{HASH}",
                "platforms": {
                    "linux/amd64": f"sha256:{'d' * 64}",
                    "linux/arm64": f"sha256:{'e' * 64}",
                },
            },
            "artifacts": [
                {"path": "latchway-contract.tar.gz", "sha256": HASH},
                {"path": "latchway-linux-amd64.spdx.json", "sha256": "f" * 64},
            ],
        }
        self.security = {
            "schema_version": 1,
            "kind": "latchway_candidate_security_evidence",
            "automated_gate": "passed",
            "candidate": {
                "commit": COMMIT,
                "intended_tag": TAG,
                "version": "1.0.0",
                "contract": {"version": "0.5.1", "bundle_sha256": HASH},
                "image": {
                    "repository": "ghcr.io/latchway/latchway",
                    "index_digest": f"sha256:{HASH}",
                },
            },
            "checks": [
                {
                    "id": "source_race",
                    "status": "passed",
                    "tool": {"name": "go", "version": "go1.27.0"},
                },
                {
                    "id": "image_vulnerability",
                    "status": "passed",
                    "tool": {"name": "trivy", "version": "v0.74.0"},
                },
            ],
        }
        domains = [
            {"id": identifier, "required": True, "status": "passed"}
            for identifier in MODULE.LOCAL_DOMAINS
        ]
        domains.extend(
            {
                "id": identifier,
                "required": True,
                "status": "passed",
                "started_at": "2026-08-29T01:00:00Z",
                "finished_at": "2026-08-29T01:01:00Z",
                "document_sha256": DOCUMENT_HASH,
                "oci_image_digest": OCI,
                "artifact_sha256": [HASH],
            }
            for identifier in MODULE.EXTERNAL_DOMAINS
        )
        self.conformance = {
            "schema_version": 1,
            "kind": "latchway_cross_repository_conformance_evidence",
            "scope": "release",
            "verdict": "passed",
            "source_conformance_passed": True,
            "promotion_ready": True,
            "release_ready": True,
            "contract": {
                "version": "0.5.1",
                "status": "released",
                "released_at": "2026-08-29T00:00:00Z",
                "wire_protocol": 1,
                "bundle_file_name": "latchway-contract-0.5.1.tar.gz",
                "bundle_sha256": HASH,
                "core_release": TAG,
                "oci_image_digest": OCI,
            },
            "repositories": self.repositories,
            "evidence_window": {
                "started_at": "2026-08-29T01:00:00Z",
                "finished_at": "2026-08-29T01:01:00Z",
            },
            "evidence_domains": domains,
            "checks": [
                {
                    "id": "source.core_contract",
                    "domain": "local_source",
                    "required": True,
                    "status": "passed",
                    "summary": "contract valid",
                },
                {
                    "id": "external.public_registries",
                    "domain": "public_registries",
                    "required": True,
                    "status": "passed",
                    "summary": "registries valid",
                },
            ],
        }
        self.publication = {
            "schema_version": 1,
            "kind": "latchway_public_release_state",
            "repository": "Latchway/latchway",
            "core_commit": COMMIT,
            "core_tag": TAG,
            "tag_object_sha": "9" * 40,
            "github_release": {
                "id": 42,
                "url": f"https://github.com/Latchway/latchway/releases/tag/{TAG}",
                "tag_name": TAG,
                "draft": False,
                "prerelease": False,
                "published_at": "2026-08-29T02:00:00Z",
            },
            "oci_image_digest": OCI,
            "registries": MODULE.canonical_registries(self.repositories, OCI),
        }
        self.paths = {}
        for name in ("candidate", "security", "conformance", "publication"):
            path = self.root / f"{name}.json"
            path.write_text(
                json.dumps(getattr(self, name), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.paths[name] = path
        self.durable_assets = {}
        for name in (
            "latchway-cross-repository-release.json",
            "latchway-cross-repository-release.attestation.sigstore.json",
            "latchway-publication-state.json",
            "latchway-release-evidence-v1.tar.gz",
        ):
            path = self.root / name
            path.write_bytes((name + "\n").encode("utf-8"))
            self.durable_assets[name] = path

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def render(self) -> str:
        return MODULE.render(
            candidate_path=self.paths["candidate"],
            security_path=self.paths["security"],
            conformance_path=self.paths["conformance"],
            publication_path=self.paths["publication"],
            repository=self.repository,
            commit=COMMIT,
            tag=TAG,
            durable_assets=self.durable_assets,
        )

    def rewrite(self, name: str, value: dict) -> None:
        self.paths[name].write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_renders_deterministic_complete_release_record(self) -> None:
        first = self.render()
        second = self.render()
        self.assertEqual(first, second)
        for value in (
            COMMIT,
            TAG,
            OCI,
            "Database schema | `2`",
            "@latchway/client@1.0.0",
            "dev.latchway:latchway-bom:1.0.0",
            "`operational_resilience` | `passed`",
            "`physical_devices` | `passed`",
            "`public_registries` | `passed`",
            "source_race",
            "Release-scope cross-repository report",
            "latchway-release-evidence-v1.tar.gz",
        ):
            self.assertIn(value, first)

    def test_rejects_non_release_or_failed_public_registry_proof(self) -> None:
        document = copy.deepcopy(self.conformance)
        next(
            item
            for item in document["evidence_domains"]
            if item["id"] == "public_registries"
        )["status"] = "failed"
        self.rewrite("conformance", document)
        with self.assertRaisesRegex(MODULE.ReportError, "required_domain_not_passed"):
            self.render()

    def test_rejects_sdk_coordinate_substitution(self) -> None:
        document = copy.deepcopy(self.publication)
        document["registries"]["npm_javascript"] = "@latchway/client@9.9.9"
        self.rewrite("publication", document)
        with self.assertRaisesRegex(MODULE.ReportError, "registry_coordinates_mismatch"):
            self.render()

    def test_rejects_candidate_digest_substitution(self) -> None:
        document = copy.deepcopy(self.conformance)
        document["contract"]["oci_image_digest"] = (
            "ghcr.io/latchway/latchway@sha256:" + "0" * 64
        )
        self.rewrite("conformance", document)
        with self.assertRaisesRegex(MODULE.ReportError, "conformance_contract_mismatch"):
            self.render()

    def test_rejects_failed_security_check(self) -> None:
        document = copy.deepcopy(self.security)
        document["checks"][0]["status"] = "failed"
        self.rewrite("security", document)
        with self.assertRaisesRegex(MODULE.ReportError, "security_checks_invalid"):
            self.render()

    def test_rejects_noncontiguous_database_schema(self) -> None:
        (self.repository / "migrations/000002_second.sql").unlink()
        (self.repository / "migrations/000003_third.sql").write_text("select 3;\n")
        with self.assertRaisesRegex(MODULE.ReportError, "migration_sequence_invalid"):
            self.render()

    def test_rejects_duplicate_json_keys(self) -> None:
        self.paths["publication"].write_text(
            '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(MODULE.ReportError, "json_duplicate_key"):
            self.render()


if __name__ == "__main__":
    unittest.main()
