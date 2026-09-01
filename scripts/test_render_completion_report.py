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
PROMOTION_HASH = "7" * 64
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
        self.documentation = {
            "repository": "https://github.com/Latchway/latchway-docs.git",
            "commit": "5" * 40,
            "canonical_core_commit": COMMIT,
            "source_commit": COMMIT,
            "source_manifest_sha256": "6" * 64,
            "source_tree_sha256": "8" * 64,
            "owned_file_count": 308,
        }
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
            "started_at": "2026-08-29T01:01:00Z",
            "finished_at": "2026-08-29T01:02:00Z",
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
        reviewer = {
            "identity": "urn:security-reviewer:example-audit-firm",
            "organization": "Example Audit Firm",
            "github_login": "example-auditor",
            "independent_from": "Latchway",
            "control": "separately_controlled",
        }
        producer = {
            "repository": "ExternalSecurity/latchway-review",
            "workflow_path": ".github/workflows/independent-security-review.yml",
            "run_id": 81234,
            "run_attempt": 2,
            "source_commit": "9" * 40,
        }
        findings = {
            "total": {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "informational": 4,
            },
            "unresolved": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 2,
                "informational": 4,
            },
        }
        review_results: list[dict[str, object]] = []
        self.review_files: dict[str, bytes] = {}
        for identifier in sorted(MODULE.REQUIRED_INDEPENDENT_REVIEWS):
            accepted_risks = sorted(
                [
                    {
                        "id": f"{identifier}.{severity}-{index + 1}",
                        "severity": severity,
                        "summary": f"Retained {severity} fixture risk {index + 1}",
                        "acceptance_rationale": (
                            "The independent reviewer documented this bounded residual "
                            "risk for explicit release review."
                        ),
                    }
                    for severity in ("medium", "low", "informational")
                    for index in range(findings["unresolved"][severity])
                ],
                key=lambda risk: risk["id"],
            )
            receipt = {
                "schema_version": 1,
                "kind": "latchway_independent_security_review_result",
                "id": identifier,
                "status": "passed",
                "candidate_commit": COMMIT,
                "reviewer": reviewer,
                "started_at": "2026-08-29T01:00:10Z",
                "finished_at": "2026-08-29T01:00:20Z",
                "findings": findings,
                "accepted_risks": accepted_risks,
            }
            payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
            relative = f"independent-review/reviews/{identifier}.json"
            self.review_files[relative] = payload
            review_results.append(
                {
                    "id": identifier,
                    "status": "passed",
                    "started_at": receipt["started_at"],
                    "finished_at": receipt["finished_at"],
                    "findings": findings,
                    "accepted_risks": accepted_risks,
                    "artifact": {
                        "path": f"reviews/{identifier}.json",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    },
                }
            )
        review_report = {
            "schema_version": 1,
            "kind": "latchway_independent_security_review",
            "status": "passed",
            "review_window": {
                "started_at": "2026-08-29T01:00:05Z",
                "finished_at": "2026-08-29T01:00:30Z",
                "maximum_age_seconds": 604800,
            },
            "candidate": {
                "commit": COMMIT,
                "intended_tag": TAG,
                "version": "1.0.0",
                "contract": {
                    "version": "0.5.1",
                    "bundle_file_name": "latchway-contract-0.5.1.tar.gz",
                    "bundle_sha256": HASH,
                },
                "image": self.candidate["image"],
            },
            "reviewer": reviewer,
            "producer": producer,
            "reviews": review_results,
        }
        review_report_payload = (
            json.dumps(review_report, indent=2, sort_keys=True) + "\n"
        ).encode()
        review_report_hash = hashlib.sha256(review_report_payload).hexdigest()
        self.review_files[
            "independent-review/independent-security-review.json"
        ] = review_report_payload
        fixed_review_documents = {
            "independent-review/independent-security-review.attestation.sigstore.json": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"
            },
            "independent-review/producer-verification.json": {
                "schema_version": 1,
                "kind": "latchway_independent_security_review_producer_verification",
                "repository": producer["repository"],
                "workflow_path": producer["workflow_path"],
                "run_id": producer["run_id"],
                "run_attempt": producer["run_attempt"],
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "head_sha": producer["source_commit"],
                "head_branch": "main",
            },
            "independent-review/attestation-verification.json": {
                "schema_version": 1,
                "kind": "latchway_independent_security_review_attestation_verification",
                "repository": producer["repository"],
                "signer_workflow": f"{producer['repository']}/{producer['workflow_path']}",
                "source_digest": producer["source_commit"],
                "source_ref": "refs/heads/main",
                "subject_sha256": review_report_hash,
                "hosted_runner": True,
                "verified": True,
            },
        }
        for relative, document in fixed_review_documents.items():
            self.review_files[relative] = (
                json.dumps(document, indent=2, sort_keys=True) + "\n"
            ).encode()
        self.promotion_files = {
            "promotion-conformance/latchway-cross-repository.json": (
                json.dumps(
                    {"kind": "latchway_cross_repository_conformance_evidence"},
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            "promotion-conformance/latchway-cross-repository.attestation.sigstore.json": b'{"bundle":"promotion"}\n',
            "promotion-conformance/producer-verification.json": b'{"verified":"producer"}\n',
            "promotion-conformance/attestation-verification.json": b'{"verified":"attestation"}\n',
        }
        promotion_report_hash = hashlib.sha256(
            self.promotion_files[
                "promotion-conformance/latchway-cross-repository.json"
            ]
        ).hexdigest()
        self.security = {
            "schema_version": 2,
            "kind": "latchway_candidate_security_evidence",
            "automated_gate": "passed",
            "independent_review_gate": "passed",
            "candidate": {
                "commit": COMMIT,
                "intended_tag": TAG,
                "version": "1.0.0",
                "candidate_created_at": "2026-08-29T01:00:00Z",
                "contract": {"version": "0.5.1", "bundle_sha256": HASH},
                "image": {
                    "repository": "ghcr.io/latchway/latchway",
                    "index_digest": f"sha256:{HASH}",
                    "platforms": self.candidate["image"]["platforms"],
                },
            },
            "evidence_window": {
                "started_at": "2026-08-29T01:01:00Z",
                "finished_at": "2026-08-29T01:03:00Z",
                "maximum_age_seconds": 604800,
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
            "review_authority": {
                "reviewer": reviewer,
                "producer": producer,
                "report_sha256": review_report_hash,
            },
            "promotion_conformance": {
                "scope": "promotion",
                "run_id": 71234,
                "run_attempt": 3,
                "report_sha256": promotion_report_hash,
                "repositories": self.repositories,
            },
            "independent_reviews": review_results,
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
            "review_evidence": [
                {"path": path, "sha256": hashlib.sha256(payload).hexdigest()}
                for path, payload in sorted(self.review_files.items())
            ],
            "promotion_evidence": [
                {"path": path, "sha256": hashlib.sha256(payload).hexdigest()}
                for path, payload in sorted(self.promotion_files.items())
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
                "started_at": (
                    "2026-08-29T02:01:00Z"
                    if identifier in {"public_tags", "public_registries"}
                    else "2026-08-29T01:00:00Z"
                ),
                "finished_at": (
                    "2026-08-29T02:02:00Z"
                    if identifier in {"public_tags", "public_registries"}
                    else "2026-08-29T01:01:00Z"
                ),
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
            "documentation": self.documentation,
            "evidence_window": {
                "started_at": "2026-08-29T01:00:00Z",
                "finished_at": "2026-08-29T02:02:00Z",
                "maximum_age_seconds": 604800,
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
            "promotion_evidence_sha256": PROMOTION_HASH,
            "github_release": {
                "id": 42,
                "url": f"https://github.com/Latchway/latchway/releases/tag/{TAG}",
                "tag_name": TAG,
                "name": f"Latchway {TAG}",
                "body": (
                    f"Immutable Latchway product release {TAG}.\n\n"
                    f"Candidate commit: {COMMIT}\n"
                    "Promotion evidence SHA-256: "
                ),
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "published_at": "2026-08-29T02:00:00Z",
                "release_attestation_sha256": "",
                "assets": [
                    {
                        "id": index + 1,
                        "name": name,
                        "size": 1,
                        "digest": f"sha256:{index:064x}",
                    }
                    for index, name in enumerate(
                        sorted(MODULE.CORE_PRODUCT_RELEASE_ASSETS), start=1
                    )
                ],
            },
            "oci_image_digest": OCI,
            "oci_aliases": MODULE.canonical_oci_aliases(
                self.repositories, self.candidate["image"]
            ),
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
        self.publication["github_release"]["body"] += PROMOTION_HASH
        for asset in self.publication["github_release"]["assets"]:
            if asset["name"] == "latchway-cross-repository-promotion.json":
                asset["digest"] = "sha256:" + PROMOTION_HASH
        self.rewrite("publication", self.publication)

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
        for relative, payload in self.review_files.items():
            destination = security_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
        for relative, payload in self.promotion_files.items():
            destination = security_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)

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
            if domain == "public_registries":
                compatibility_proofs = {
                    "artifacts--registry-npm-javascript--tool-output.json": {
                        "registry": "npm",
                        "package": "@latchway/client",
                        "compatibility": {"minimum_node": "24.19.0"},
                    },
                    "artifacts--registry-npm-react-native--tool-output.json": {
                        "registry": "npm",
                        "package": "@latchway/react-native",
                        "compatibility": {
                            "minimum_node": "24.19.0",
                            "react_native": "0.82.x",
                            "minimum_ios": "15.0",
                            "minimum_android_api": 24,
                        },
                    },
                    "artifacts--registry-cocoapods--tool-output.json": {
                        "registry": "cocoapods",
                        "compatibility": {"minimum_ios": "15.0"},
                    },
                    "artifacts--registry-maven-central--tool-output.json": {
                        "registry": "maven_central",
                        "compatibility": {"minimum_android_api": 23},
                    },
                }
                for name, value in compatibility_proofs.items():
                    path = external / f"artifacts/public-registries/{name}"
                    self.write_json(path, value)
                    artifacts.append(
                        {
                            "path": path.relative_to(external).as_posix(),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        }
                    )
            started_at = (
                "2026-08-29T02:01:00Z"
                if domain in {"public_tags", "public_registries"}
                else "2026-08-29T01:00:00Z"
            )
            finished_at = (
                "2026-08-29T02:02:00Z"
                if domain in {"public_tags", "public_registries"}
                else "2026-08-29T01:01:00Z"
            )
            document = {
                "schema_version": 1,
                "kind": "latchway_cross_repository_external_evidence",
                "domain": domain,
                "status": "passed",
                "started_at": started_at,
                "finished_at": finished_at,
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
            "Independent security review gate",
            "Independently accepted lower-severity risks",
            "independent_p0_p2_review",
            "Acceptance rationale",
            "all `8` independent security reviews passed",
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

        self.rewrite("security", self.security)
        security = copy.deepcopy(self.security)
        security["independent_reviews"] = security["independent_reviews"][:-1]
        self.rewrite("security", security)
        with self.assertRaisesRegex(MODULE.ReportError, "security_reviews_incomplete"):
            self.render()

        self.rewrite("security", self.security)
        security = copy.deepcopy(self.security)
        security["independent_reviews"][0]["findings"]["total"]["high"] = 2
        security["independent_reviews"][0]["findings"]["unresolved"]["high"] = 1
        self.rewrite("security", security)
        with self.assertRaisesRegex(MODULE.ReportError, "findings_unresolved"):
            self.render()

    def test_requires_exact_sdk_documentation_bundle_conformance(self) -> None:
        identifier = "source.sdk_documentation_bundles"
        self.assertEqual(
            MODULE.REQUIRED_CONFORMANCE_CHECKS.get(identifier),
            "local_source",
        )
        document = copy.deepcopy(self.conformance)
        document["checks"] = [
            check for check in document["checks"] if check["id"] != identifier
        ]
        self.rewrite("conformance", document)
        with self.assertRaisesRegex(MODULE.ReportError, "checks_incomplete"):
            self.render()

    def test_rejects_incomplete_accepted_risk_documentation(self) -> None:
        security = copy.deepcopy(self.security)
        security["independent_reviews"][0]["accepted_risks"] = security[
            "independent_reviews"
        ][0]["accepted_risks"][:-1]
        self.rewrite("security", security)
        with self.assertRaisesRegex(MODULE.ReportError, "accepted_risks_incomplete"):
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

    def test_rejects_tampered_durable_independent_review(self) -> None:
        review = self.durable_evidence_root / (
            "security/independent-review/reviews/ssrf_review.json"
        )
        review.write_text('{"substituted":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ReportError, "durable_security_review_invalid"
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

    def test_rejects_impossible_or_reversed_evidence_times(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["created_at"] = "2026-02-30T01:00:00Z"
        self.rewrite("candidate", candidate)
        with self.assertRaisesRegex(MODULE.ReportError, "candidate_identity_mismatch"):
            self.render()

        self.rewrite("candidate", self.candidate)
        conformance = copy.deepcopy(self.conformance)
        domain = next(
            item
            for item in conformance["evidence_domains"]
            if item["id"] == "live_provider"
        )
        domain["started_at"] = "2026-08-29T01:02:00Z"
        domain["finished_at"] = "2026-08-29T01:01:00Z"
        self.rewrite("conformance", conformance)
        with self.assertRaisesRegex(MODULE.ReportError, "domain_proof_invalid"):
            self.render()

    def test_rejects_public_registry_evidence_that_predates_publication(self) -> None:
        conformance = copy.deepcopy(self.conformance)
        for domain in conformance["evidence_domains"]:
            if domain["id"] in {"public_tags", "public_registries"}:
                domain["started_at"] = "2026-08-29T01:50:00Z"
                domain["finished_at"] = "2026-08-29T01:55:00Z"
        conformance["evidence_window"]["finished_at"] = "2026-08-29T01:55:00Z"
        self.rewrite("conformance", conformance)
        with self.assertRaisesRegex(
            MODULE.ReportError, "post_publication_evidence_invalid"
        ):
            self.render()

    def test_rejects_unproved_compatibility_or_security_prose(self) -> None:
        metadata_path = self.repository / "docs/release/final-report-metadata.json"
        retained_path = (
            self.durable_evidence_root / "source/final-report-metadata.json"
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["compatibility"]["minimum_platform_versions"][
            "javascript_sdk"
        ] = "Node.js 99.0.0"
        self.write_json(metadata_path, metadata)
        self.write_json(retained_path, metadata)
        with self.assertRaisesRegex(
            MODULE.ReportError, "compatibility_metadata_mismatch"
        ):
            self.render()

        canonical = json.loads(
            (ROOT / "docs/release/final-report-metadata.json").read_text(
                encoding="utf-8"
            )
        )
        canonical["security_statement"]["prompt_logging_defaults"] = (
            "Prompts may be logged."
        )
        self.write_json(metadata_path, canonical)
        with self.assertRaisesRegex(MODULE.ReportError, "security_metadata_mismatch"):
            self.render()

    def test_rejects_product_release_asset_set_substitution(self) -> None:
        publication = copy.deepcopy(self.publication)
        publication["github_release"]["assets"].append(
            {
                "id": 999,
                "name": "unexpected.txt",
                "size": 1,
                "digest": "sha256:" + "a" * 64,
            }
        )
        self.rewrite("publication", publication)
        with self.assertRaisesRegex(
            MODULE.ReportError, "github_release_assets_invalid"
        ):
            self.render()

        publication = copy.deepcopy(self.publication)
        publication["promotion_evidence_sha256"] = "f" * 64
        publication["github_release"]["body"] = (
            f"Immutable Latchway product release {TAG}.\n\n"
            f"Candidate commit: {COMMIT}\n"
            f"Promotion evidence SHA-256: {'f' * 64}"
        )
        self.rewrite("publication", publication)
        with self.assertRaisesRegex(MODULE.ReportError, "promotion_hash_invalid"):
            self.render()

    def test_rejects_oci_moving_alias_drift(self) -> None:
        publication = copy.deepcopy(self.publication)
        publication["oci_aliases"]["references"]["latest"]["digest"] = (
            "sha256:" + "f" * 64
        )
        self.rewrite("publication", publication)
        with self.assertRaisesRegex(MODULE.ReportError, "oci_aliases_invalid"):
            self.render()


if __name__ == "__main__":
    unittest.main()
