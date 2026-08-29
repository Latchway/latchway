#!/usr/bin/env python3

from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile
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
        (self.repository / "docs/release").mkdir(parents=True)
        shutil.copyfile(
            ROOT / "docs/release/final-report-metadata.json",
            self.repository / "docs/release/final-report-metadata.json",
        )
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
        self.race_log = (
            b'{"Action":"pass","Package":"github.com/latchway/latchway/internal/localverify",'
            b'"Test":"TestRunPostgreSQLV1Vertical","Elapsed":1}\n'
        )
        self.race_result = {
            "schema_version": 1,
            "kind": "latchway_security_command_result",
            "check": "source_race",
            "candidate_commit": COMMIT,
            "started_at": "2026-08-29T00:01:00Z",
            "finished_at": "2026-08-29T00:02:00Z",
            "tool": {"name": "go", "version": "go1.27.0"},
            "argv": ["go", "test", "-race", "-json", "-count=1", "./..."],
            "execution_context": {
                "postgresql_enabled": True,
                "fuzz_time": None,
                "fuzz_parallel": None,
            },
            "exit_code": 0,
            "log": {
                "path": "source-race.log",
                "sha256": hashlib.sha256(self.race_log).hexdigest(),
            },
        }
        race_result_bytes = (
            json.dumps(self.race_result, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
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
                    "id": identifier,
                    "status": "passed",
                    "tool": {
                        "name": "go" if identifier.startswith("source_") else "trivy",
                        "version": "go1.27.0" if identifier.startswith("source_") else "v0.74.0",
                    },
                }
                for identifier in sorted(MODULE.REQUIRED_SECURITY_CHECKS)
            ],
            "raw_evidence": [
                {
                    "path": "raw/source-race.log",
                    "sha256": hashlib.sha256(self.race_log).hexdigest(),
                },
                {
                    "path": "raw/source-race.result.json",
                    "sha256": hashlib.sha256(race_result_bytes).hexdigest(),
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
                    "id": identifier,
                    "domain": domain,
                    "required": True,
                    "status": "passed",
                    "summary": "validated release evidence",
                }
                for identifier, domain in MODULE.REQUIRED_CONFORMANCE_CHECKS.items()
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
                "immutable": True,
                "published_at": "2026-08-29T02:00:00Z",
                "release_attestation_sha256": "",
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
            "latchway-product-release-attestation.json",
        ):
            path = self.root / name
            path.write_bytes((name + "\n").encode("utf-8"))
            self.durable_assets[name] = path
        product_attestation = self.durable_assets[
            "latchway-product-release-attestation.json"
        ]
        self.publication["github_release"]["release_attestation_sha256"] = (
            hashlib.sha256(product_attestation.read_bytes()).hexdigest()
        )
        self.rewrite("publication", self.publication)
        self.build_durable_evidence()

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
            evidence_tag=f"evidence/{TAG}",
            durable_evidence_root=self.durable_evidence_root,
            durable_assets=self.durable_assets,
        )

    def rewrite(self, name: str, value: dict) -> None:
        self.paths[name].write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def build_durable_evidence(self) -> None:
        self.durable_evidence_root = self.root / "latchway-release-evidence-v1"
        candidate_root = self.durable_evidence_root / "candidate"
        security_root = self.durable_evidence_root / "security"
        external = self.durable_evidence_root / "external/latchway-external-evidence"
        source_root = self.durable_evidence_root / "source"
        candidate_root.mkdir(parents=True)
        (security_root / "raw").mkdir(parents=True)
        external.mkdir(parents=True)
        source_root.mkdir(parents=True)
        shutil.copyfile(
            self.repository / "docs/release/final-report-metadata.json",
            source_root / "final-report-metadata.json",
        )
        shutil.copyfile(self.paths["candidate"], candidate_root / "latchway-candidate.json")
        shutil.copyfile(self.paths["candidate"], security_root / "latchway-candidate.json")
        shutil.copyfile(self.paths["security"], security_root / "security-summary.json")
        (candidate_root / "latchway-candidate.attestation.sigstore.json").write_text(
            '{"bundle":"candidate"}\n', encoding="utf-8"
        )
        (security_root / "security-summary.attestation.sigstore.json").write_text(
            '{"bundle":"security"}\n', encoding="utf-8"
        )
        (security_root / "raw/source-race.log").write_bytes(self.race_log)
        self.write_json(
            security_root / "raw/source-race.result.json", self.race_result
        )

        coordinates = {
            item["id"]: {
                "commit": item["commit"],
                "tag": item["intended_tag"],
                "version": item["version"],
            }
            for item in self.repositories
        }
        domain_documents: dict[str, dict] = {}
        for domain in MODULE.EXTERNAL_DOMAINS:
            artifacts: list[dict[str, str]] = []
            proof = external / f"artifacts/{domain.replace('_', '-')}/proof.json"
            self.write_json(proof, {"domain": domain, "passed": True})
            artifacts.append(
                {"path": proof.relative_to(external).as_posix(), "sha256": hashlib.sha256(proof.read_bytes()).hexdigest()}
            )
            if domain == "physical_devices":
                artifacts = self.build_physical_domain_artifacts(external)
            document = {
                "schema_version": 1,
                "kind": "latchway_cross_repository_external_evidence",
                "domain": domain,
                "status": "passed",
                "started_at": "2026-08-29T01:00:00Z",
                "finished_at": "2026-08-29T01:01:00Z",
                "core_commit": COMMIT,
                "core_release": TAG,
                "contract_version": "0.5.1",
                "bundle_sha256": HASH,
                "oci_image_digest": OCI,
                "repositories": coordinates,
                "claims": {claim: True for claim in MODULE.REQUIRED_EXTERNAL_CLAIMS[domain]},
                "artifacts": artifacts,
            }
            domain_path = external / f"{domain}.json"
            self.write_json(domain_path, document)
            (external / f"{domain}.attestation.sigstore.json").write_text(
                json.dumps({"bundle": domain}) + "\n", encoding="utf-8"
            )
            domain_documents[domain] = document

        for domain in self.conformance["evidence_domains"]:
            identifier = domain["id"]
            if identifier not in MODULE.EXTERNAL_DOMAINS:
                continue
            document_path = external / f"{identifier}.json"
            domain["document_sha256"] = hashlib.sha256(document_path.read_bytes()).hexdigest()
            domain["artifact_sha256"] = sorted(
                item["sha256"] for item in domain_documents[identifier]["artifacts"]
            )
        self.rewrite("conformance", self.conformance)

        aggregate_files = []
        for path in sorted(external.rglob("*")):
            if path.is_file():
                aggregate_files.append(
                    {
                        "path": path.relative_to(external).as_posix(),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
        manifest = {
            "schema_version": 1,
            "kind": "latchway_external_evidence_aggregate",
            "scope": "release",
            "candidate_commit": COMMIT,
            "domains": list(MODULE.EXTERNAL_DOMAINS),
            "identity": {"core_commit": COMMIT},
            "files": aggregate_files,
        }
        self.write_json(external / "aggregate-manifest.json", manifest)
        (external / "aggregate-manifest.attestation.sigstore.json").write_text(
            '{"bundle":"aggregate"}\n', encoding="utf-8"
        )
        archive = self.durable_assets["latchway-release-evidence-v1.tar.gz"]
        with tarfile.open(archive, mode="w:gz") as bundle:
            bundle.add(
                self.durable_evidence_root,
                arcname="latchway-release-evidence-v1",
            )

    def build_physical_domain_artifacts(self, external: Path) -> list[dict[str, str]]:
        artifacts: list[dict[str, str]] = []
        for observation, required_names in MODULE.PHYSICAL_OBSERVATIONS.items():
            slug = observation.replace(".", "-")
            files = {
                "SHA256SUMS": b"receipt checksums\n",
                "github-attestation.sigstore.json": b'{"bundle":"physical"}\n',
                "device-inventory.json": b'{"physical":true}\n',
                "gateway-deployment-verification.json": b'{"valid":true}\n',
                required_names[0]: b'{"profile":true}\n',
                required_names[1]: b'{"evidence":true}\n',
            }
            hashes = {
                name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()
            }
            envelope = {
                "schema_version": 1,
                "kind": "latchway_retained_physical_device_receipt",
                "observation": observation,
                "files": [
                    {
                        "name": name,
                        "sha256": hashes[name],
                        "content_base64": base64.b64encode(files[name]).decode("ascii"),
                    }
                    for name in sorted(files)
                ],
            }
            summary = {"observation": observation, "receipt_sha256": hashes}
            result_original = f"artifacts/{slug}/physical-receipt.json"
            receipt_relative = f"artifacts/physical-devices/artifacts--{slug}--physical-receipt.json"
            summary_relative = f"artifacts/physical-devices/artifacts--{slug}--tool-output.json"
            result_relative = f"artifacts/physical-devices/result-{slug}.json"
            self.write_json(external / receipt_relative, envelope)
            self.write_json(external / summary_relative, summary)
            receipt_hash = hashlib.sha256((external / receipt_relative).read_bytes()).hexdigest()
            self.write_json(
                external / result_relative,
                {
                    "observation": observation,
                    "artifacts": [
                        {"path": f"artifacts/{slug}/tool-output.json", "sha256": hashlib.sha256((external / summary_relative).read_bytes()).hexdigest()},
                        {"path": result_original, "sha256": receipt_hash},
                    ],
                },
            )
            for relative in (receipt_relative, summary_relative, result_relative):
                path = external / relative
                artifacts.append(
                    {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                )
        return sorted(artifacts, key=lambda item: item["path"])

    def test_renders_deterministic_complete_release_record(self) -> None:
        first = self.render()
        second = self.render()
        self.assertEqual(first, second)
        for value in (
            COMMIT,
            TAG,
            OCI,
            "Database schema version | `2`",
            "@latchway/client@1.0.0",
            "dev.latchway:latchway-bom:1.0.0",
            "`operational_resilience` | `passed`",
            "`physical_devices` | `passed`",
            "`public_registries` | `passed`",
            "source_race",
            "Release-scope cross-repository report",
            "latchway-release-evidence-v1.tar.gz",
            "## Release artifacts",
            "## Test evidence",
            "## Compatibility matrix",
            "## Security statement",
            "## Operational proof",
            "## Remaining work",
            "exact redacted security inputs",
            "exact physical-device receipt files",
            "evidence/v1.0.0",
            "does not claim that evidence release already exists",
        ):
            self.assertIn(value, first)
        section_positions = [
            first.index(f"## {name}")
            for name in (
                "Release artifacts",
                "Test evidence",
                "Compatibility matrix",
                "Security statement",
                "Operational proof",
                "Remaining work",
            )
        ]
        self.assertEqual(section_positions, sorted(section_positions))

    def test_rejects_incomplete_section_evidence(self) -> None:
        document = copy.deepcopy(self.conformance)
        document["checks"] = document["checks"][:-1]
        self.rewrite("conformance", document)
        with self.assertRaisesRegex(MODULE.ReportError, "checks_incomplete"):
            self.render()

        self.rewrite("conformance", self.conformance)
        security = copy.deepcopy(self.security)
        security["checks"] = security["checks"][:-1]
        self.rewrite("security", security)
        with self.assertRaisesRegex(MODULE.ReportError, "security_checks_incomplete"):
            self.render()

    def test_rejects_unclassified_or_unfinished_remaining_work(self) -> None:
        path = self.repository / "docs/release/final-report-metadata.json"
        metadata = json.loads(path.read_text(encoding="utf-8"))
        metadata["remaining_work"][0]["description"] = "Pending version 1 requirement"
        self.write_json(path, metadata)
        with self.assertRaisesRegex(MODULE.ReportError, "remaining_work_invalid"):
            self.render()

    def test_rejects_tampered_durable_security_or_physical_raw_bytes(self) -> None:
        security_raw = self.durable_evidence_root / "security/raw/source-race.log"
        security_raw.write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ReportError, "durable_security_raw_invalid"):
            self.render()

        security_raw.write_bytes(self.race_log)
        receipt = next(
            self.durable_evidence_root.glob(
                "external/latchway-external-evidence/artifacts/physical-devices/*physical-receipt.json"
            )
        )
        receipt.write_text('{"substituted":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ReportError,
            "durable_(?:aggregate|domain)|physical_receipts",
        ):
            self.render()

    def test_rejects_archive_that_does_not_match_validated_tree(self) -> None:
        archive = self.durable_assets["latchway-release-evidence-v1.tar.gz"]
        archive.write_bytes(b"not a release evidence archive\n")
        with self.assertRaisesRegex(MODULE.ReportError, "durable_archive_invalid"):
            self.render()

    def test_rejects_mutable_product_release_or_unbound_release_attestation(self) -> None:
        document = copy.deepcopy(self.publication)
        document["github_release"]["immutable"] = False
        self.rewrite("publication", document)
        with self.assertRaisesRegex(MODULE.ReportError, "github_release_invalid"):
            self.render()

        self.rewrite("publication", self.publication)
        self.durable_assets["latchway-product-release-attestation.json"].write_text(
            '{"substituted":true}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            MODULE.ReportError, "product_attestation_mismatch"
        ):
            self.render()

    def test_rejects_security_run_without_passing_vertical_configuration_proof(self) -> None:
        raw = self.durable_evidence_root / "security/raw"
        log = b'{"Action":"skip","Package":"github.com/latchway/latchway/internal/localverify","Test":"TestRunPostgreSQLV1Vertical"}\n'
        (raw / "source-race.log").write_bytes(log)
        result = copy.deepcopy(self.race_result)
        result["log"]["sha256"] = hashlib.sha256(log).hexdigest()
        self.write_json(raw / "source-race.result.json", result)
        security = copy.deepcopy(self.security)
        hashes = {
            "raw/source-race.log": hashlib.sha256(log).hexdigest(),
            "raw/source-race.result.json": hashlib.sha256(
                (raw / "source-race.result.json").read_bytes()
            ).hexdigest(),
        }
        for item in security["raw_evidence"]:
            item["sha256"] = hashes[item["path"]]
        self.rewrite("security", security)
        self.write_json(
            self.durable_evidence_root / "security/security-summary.json", security
        )
        with self.assertRaisesRegex(
            MODULE.ReportError, "configuration_proof_invalid"
        ):
            self.render()

    def test_rejects_unbound_report_metadata_copy_or_evidence_tag(self) -> None:
        retained = self.durable_evidence_root / "source/final-report-metadata.json"
        retained.write_text('{"substituted":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ReportError, "durable_evidence_identity_mismatch"
        ):
            self.render()
        with self.assertRaisesRegex(MODULE.ReportError, "evidence_tag_invalid"):
            MODULE.render(
                candidate_path=self.paths["candidate"],
                security_path=self.paths["security"],
                conformance_path=self.paths["conformance"],
                publication_path=self.paths["publication"],
                repository=self.repository,
                commit=COMMIT,
                tag=TAG,
                evidence_tag="evidence/v1.0.1",
                durable_evidence_root=self.durable_evidence_root,
                durable_assets=self.durable_assets,
            )

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
