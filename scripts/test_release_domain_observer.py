#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime, timezone
import base64
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
from typing import Mapping
import unittest
from unittest import mock
import zipfile


SCRIPT = Path(__file__).with_name("release-domain-observer.py")
SPEC = importlib.util.spec_from_file_location("release_domain_observer", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

FIXTURE_SCRIPT = Path(__file__).with_name("test_release_domain_evidence.py")
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "release_domain_evidence_fixture", FIXTURE_SCRIPT
)
assert FIXTURE_SPEC is not None and FIXTURE_SPEC.loader is not None
FIXTURE_MODULE = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(FIXTURE_MODULE)

PUBLIC_PROOF_FIXTURE_SCRIPT = Path(__file__).with_name(
    "test_verify_public_registry_proof.py"
)
PUBLIC_PROOF_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "public_registry_proof_fixture_for_observer", PUBLIC_PROOF_FIXTURE_SCRIPT
)
assert (
    PUBLIC_PROOF_FIXTURE_SPEC is not None
    and PUBLIC_PROOF_FIXTURE_SPEC.loader is not None
)
PUBLIC_PROOF_FIXTURE_MODULE = importlib.util.module_from_spec(
    PUBLIC_PROOF_FIXTURE_SPEC
)
PUBLIC_PROOF_FIXTURE_SPEC.loader.exec_module(PUBLIC_PROOF_FIXTURE_MODULE)


def canonical_maven_file_rows(
    version: str, fingerprint: str
) -> tuple[list[dict], list[dict], str]:
    signature = (
        "-----BEGIN PGP SIGNATURE-----\n"
        "test\n"
        "-----END PGP SIGNATURE-----\n"
    )
    signature_bytes = signature.encode("ascii")
    signature_sha256 = hashlib.sha256(signature_bytes).hexdigest()
    checksum_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
    expected_paths = sorted(
        {
            f"{module}/{version}/{module}-{version}{suffix}"
            for module in (
                "latchway-core", "latchway-okhttp", "latchway-play-integrity",
                "latchway-firebase-auth", "latchway-bom",
            )
            for suffix in (
                (".pom", ".module", "-sources.jar", "-javadoc.jar")
                if module == "latchway-bom"
                else (".pom", ".module", "-sources.jar", "-javadoc.jar", ".aar")
            )
        }
    )
    files: list[dict] = []
    manifest: list[dict] = []
    for path in expected_paths:
        artifact = path.encode("utf-8")
        artifact_sha256 = hashlib.sha256(artifact).hexdigest()
        checksums = []
        for algorithm, length in checksum_lengths.items():
            published_digest = hashlib.sha512(
                f"{algorithm}:{path}".encode()
            ).hexdigest()[:length]
            checksum_bytes = f"{published_digest}\n".encode("ascii")
            checksums.append(
                {
                    "algorithm": algorithm,
                    "path": f"{path}.{algorithm}",
                    "bytes": len(checksum_bytes),
                    "sha256": hashlib.sha256(checksum_bytes).hexdigest(),
                    "published_digest": published_digest,
                }
            )
        files.append(
            {
                "path": path,
                "sha256": artifact_sha256,
                "bytes": len(artifact),
                "signature_sha256": signature_sha256,
                "signature_bytes": len(signature_bytes),
                "signature_armored": signature,
                "gpg_status": {
                    "schema_version": 1,
                    "primary_fingerprint": fingerprint,
                    "signing_fingerprint": fingerprint,
                    "public_key_algorithm": "1",
                    "hash_algorithm": "10",
                    "status_lines": ["[GNUPG:] VALIDSIG test"],
                },
                "checksums": checksums,
                "checksums_byte_identical": True,
            }
        )
        manifest.extend(
            [
                {"path": path, "bytes": len(artifact), "sha256": artifact_sha256},
                {
                    "path": f"{path}.asc",
                    "bytes": len(signature_bytes),
                    "sha256": signature_sha256,
                },
                *(
                    {
                        "path": checksum["path"],
                        "bytes": checksum["bytes"],
                        "sha256": checksum["sha256"],
                    }
                    for checksum in checksums
                ),
            ]
        )
    manifest.sort(key=lambda item: item["path"])
    manifest_sha256 = hashlib.sha256(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    ).hexdigest()
    return files, manifest, manifest_sha256


class ReleaseDomainObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="latchway-release-observer-"
        )
        self.root = Path(self.temporary.name)
        self.candidate_created = datetime(
            2026, 8, 29, 9, 0, tzinfo=timezone.utc
        )
        self.workflow_started = datetime(
            2026, 8, 29, 9, 55, tzinfo=timezone.utc
        )
        self.workflow_finished = datetime(
            2026, 8, 29, 10, 15, tzinfo=timezone.utc
        )
        self.now = datetime(2026, 8, 29, 10, 30, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def bare_observer(self, domain: str = "live_provider") -> MODULE.Observer:
        observer = object.__new__(MODULE.Observer)
        observer.domain = domain
        observer.release_profile = None
        observer.evidence_release_profile = None
        observer.output = self.root / "raw"
        observer.output.mkdir(exist_ok=True)
        observer.repositories = {}
        observer.live_sdk_receipts = {}
        observer.live_sdk_runs = {}
        observer.live_provider_capture = None
        observer.github_authority = None
        observer._github_authority_entries = {}
        observer._github_authority_used = set()
        commits = {
            "core": "a" * 40,
            "javascript": "b" * 40,
            "ios": "c" * 40,
            "android": "d" * 40,
            "react_native": "e" * 40,
        }
        observer.identity = {
            "core_commit": "a" * 40,
            "core_release": "v1.0.0",
            "contract_version": "0.5.1",
            "bundle_sha256": "b" * 64,
            "oci_image_digest": "ghcr.io/latchway/latchway@sha256:" + "c" * 64,
            "repositories": {
                repository: {
                    "commit": commit,
                    "tag": "v1.0.0",
                    "version": "1.0.0",
                }
                for repository, commit in commits.items()
            },
        }
        observer.candidate = {"image": {"index_digest": "sha256:" + "c" * 64}}
        observer.candidate_created = self.candidate_created
        observer.input_hashes = {"source": "1" * 64, "candidate": "2" * 64}
        observer.now = self.now
        return observer

    def live_provider_capture_fixture(
        self, observer: MODULE.Observer, name: str
    ) -> Path:
        root = self.root / name
        root.mkdir()
        health = MODULE.canonical_json(
            {
                "status": "ok",
                "build": {
                    "version": "1.0.0",
                    "commit": "a" * 40,
                    "contract_version": "0.5.1",
                    "protocol_version": "2",
                },
            }
        )
        self_test = MODULE.canonical_json(
            {
                "kind": "openrouter",
                "state": "passed",
                "checks": [
                    {"name": check, "state": "passed"}
                    for check in MODULE.PROVIDER_CHECKS.values()
                ],
            }
        )
        (root / "health.json").write_bytes(health)
        (root / "self-test.json").write_bytes(self_test)
        request = {
            "kind": "openrouter",
            "environment_id": "env_00000000000000000000000000",
            "upstream": "openrouter",
            "model": "canary",
            "max_cost_nano_usd": 10_000_000,
        }
        request_sha256 = hashlib.sha256(MODULE.canonical_json(request)).hexdigest()
        isolation_root = root / "collector-isolation"
        isolation_root.mkdir()
        run_id = "123456"
        run_attempt = "2"
        started_unix = int(self.workflow_started.timestamp())
        finished_unix = int(
            datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc).timestamp()
        )
        grant_sha256 = "3" * 64
        jti_sha256 = "4" * 64
        workflow = {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": "live_provider_capture",
            "audience": "latchway-live-provider/self-test",
        }
        lease = {
            "schema_version": "latchway.live-provider-collector-lease.v1",
            "repository": MODULE.EVIDENCE.REPOSITORY,
            "core_commit": observer.identity["core_commit"],
            "workflow": workflow,
            "runner": {
                "name": f"latchway-live-provider-{run_id}-{run_attempt}",
                "ephemeral": True,
                "jit": True,
                "max_jobs": 1,
                "fresh_boot": True,
                "clean_workspace": True,
                "repository_scope": MODULE.EVIDENCE.REPOSITORY,
                "destroy_after_job": True,
                "image_digest": "sha256:" + "5" * 64,
                "boot_id_sha256": "6" * 64,
            },
            "credentials": {
                "long_lived": False,
                "organization": False,
                "administration": False,
                "registry": False,
                "oidc": False,
            },
            "supervisor": {
                "private_key_isolated": True,
                "caller_supplied_claims_accepted": False,
                "gateway_egress_only": True,
                "dns_pinned": True,
                "tls_verified": True,
                "grant_issuer_independent": True,
                "one_use_verification": True,
                "out_of_band_watchdog": True,
            },
            "grant": {
                "audience": "latchway-live-provider/self-test",
                "core_commit": observer.identity["core_commit"],
                "run_id": run_id,
                "run_attempt": run_attempt,
                "sha256": grant_sha256,
                "scope": "run_self_tests",
                "single_use": True,
                "revocable": True,
                "jti_sha256": jti_sha256,
                "request_sha256": request_sha256,
                "issued_at_unix": started_unix,
                "expires_at_unix": finished_unix,
            },
            "candidate": {
                "source_report_sha256": observer.input_hashes["source"],
                "candidate_manifest_sha256": observer.input_hashes["candidate"],
            },
            "gateway": {"origin": "https://gateway.example.test"},
            "issued_at_unix": started_unix - 60,
            "expires_at_unix": finished_unix + 240,
        }
        lease_payload = MODULE.canonical_json(lease)
        (isolation_root / "collector-lease.json").write_bytes(lease_payload)
        (isolation_root / "collector-lease.sig").write_bytes(b"lease-signature")
        (isolation_root / "collector-trust-root.pem").write_text(
            "-----BEGIN PUBLIC KEY-----\nQUJDREVGR0g=\n-----END PUBLIC KEY-----\n",
            encoding="ascii",
        )
        health_sha256 = hashlib.sha256(health).hexdigest()
        self_test_sha256 = hashlib.sha256(self_test).hexdigest()
        receipt = {
            "schema_version": "latchway.live-provider-grant-consumption.v1",
            "repository": MODULE.EVIDENCE.REPOSITORY,
            "core_commit": observer.identity["core_commit"],
            "run_id": run_id,
            "run_attempt": run_attempt,
            "audience": "latchway-live-provider/self-test",
            "scope": "run_self_tests",
            "grant_sha256": grant_sha256,
            "jti_sha256": jti_sha256,
            "single_use": True,
            "consumption_count": 1,
            "consumed": True,
            "revoked": True,
            "request_sha256": request_sha256,
            "health_sha256": health_sha256,
            "self_test_sha256": self_test_sha256,
            "consumed_at_unix": started_unix + 180,
        }
        receipt_payload = MODULE.canonical_json(receipt)
        (isolation_root / "grant-consumption-receipt.json").write_bytes(
            receipt_payload
        )
        (isolation_root / "grant-consumption-receipt.sig").write_bytes(
            b"receipt-signature"
        )
        teardown = {
            "schema_version": "latchway.live-provider-collector-teardown.v1",
            "repository": MODULE.EVIDENCE.REPOSITORY,
            "core_commit": observer.identity["core_commit"],
            "workflow": workflow,
            "runner": {
                "name": f"latchway-live-provider-{run_id}-{run_attempt}",
                "deregistered": True,
                "accepts_more_jobs": False,
                "destroy_scheduled": True,
                "destroy_deadline_unix": finished_unix + 300,
            },
            "grant": {
                "single_use": True,
                "consumption_count": 1,
                "zeroized": True,
                "revoked": True,
            },
            "network": {
                "gateway_egress_only": True,
                "dns_pinned": True,
                "tls_verified": True,
            },
            "receipt_verified": True,
            "evidence_eligible": True,
            "lease_sha256": hashlib.sha256(lease_payload).hexdigest(),
            "receipt_sha256": hashlib.sha256(receipt_payload).hexdigest(),
            "health_sha256": health_sha256,
            "self_test_sha256": self_test_sha256,
        }
        (isolation_root / "collector-teardown.json").write_bytes(
            MODULE.canonical_json(teardown)
        )
        (isolation_root / "collector-teardown.sig").write_bytes(
            b"teardown-signature"
        )
        rows = []
        for path, payload, status, started, finished in (
            (
                "health.json",
                health,
                200,
                "2026-08-29T09:55:00Z",
                "2026-08-29T09:56:00Z",
            ),
            (
                "self-test.json",
                self_test,
                202,
                "2026-08-29T09:56:00Z",
                "2026-08-29T10:00:00Z",
            ),
        ):
            rows.append(
                {
                    "path": path,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "status_code": status,
                    "started_at": started,
                    "finished_at": finished,
                }
            )
        manifest = {
            "schema_version": 1,
            "kind": "latchway_live_provider_capture",
            "candidate": observer.identity,
            "source_sha256": observer.input_hashes["source"],
            "candidate_sha256": observer.input_hashes["candidate"],
            "gateway_origin": "https://gateway.example.test",
            "request": request,
            "request_sha256": request_sha256,
            "started_at": "2026-08-29T09:55:00Z",
            "finished_at": "2026-08-29T10:00:00Z",
            "collector_isolation": {
                "schema_version": "latchway.live-provider-collector-isolation.v1",
                "lease_sha256": hashlib.sha256(
                    (isolation_root / "collector-lease.json").read_bytes()
                ).hexdigest(),
                "lease_signature_sha256": hashlib.sha256(
                    (isolation_root / "collector-lease.sig").read_bytes()
                ).hexdigest(),
                "trust_root_sha256": hashlib.sha256(
                    (isolation_root / "collector-trust-root.pem").read_bytes()
                ).hexdigest(),
                "receipt_sha256": hashlib.sha256(
                    (isolation_root / "grant-consumption-receipt.json").read_bytes()
                ).hexdigest(),
                "receipt_signature_sha256": hashlib.sha256(
                    (isolation_root / "grant-consumption-receipt.sig").read_bytes()
                ).hexdigest(),
                "teardown_sha256": hashlib.sha256(
                    (isolation_root / "collector-teardown.json").read_bytes()
                ).hexdigest(),
                "teardown_signature_sha256": hashlib.sha256(
                    (isolation_root / "collector-teardown.sig").read_bytes()
                ).hexdigest(),
            },
            "files": rows,
        }
        (root / "manifest.json").write_bytes(MODULE.canonical_json(manifest))
        return root

    def javascript_isolation_fixture(
        self,
        observer: MODULE.Observer,
        provider: str,
        *,
        report: dict | None = None,
    ) -> Path:
        policy = MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS[provider]
        capture = self.root / f"{provider}.json"
        isolation = self.root / f"{provider}-isolation"
        isolation.mkdir()
        started = int(self.workflow_started.timestamp())
        finished = int(self.workflow_finished.timestamp())
        run_id = "123456"
        run_attempt = "2"
        provider_index = list(MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS).index(provider)
        grant_sha256 = str(3 + provider_index) * 64
        jti_sha256 = str(5 + provider_index) * 64
        request_sha256 = str(7 + provider_index) * 64
        harness_archive_sha256 = "9" * 64
        report_value = report or {"redacted": True, "provider": provider}
        report_payload = MODULE.canonical_json(report_value)
        harness = {
            "schema_version": "latchway.live-sdk-harness.v1",
            "repository": "Latchway/latchway-js",
            "core_commit": observer.identity["core_commit"],
            "javascript_commit": observer.identity["repositories"]["javascript"][
                "commit"
            ],
            "workflow": {"run_id": run_id, "run_attempt": run_attempt},
            "source_archive_sha256": "8" * 64,
            "harness_archive_sha256": harness_archive_sha256,
            "harness_bytes": 4096,
        }
        harness_payload = MODULE.canonical_json(harness)
        runner_name = (
            f"latchway-live-sdk-{policy['runner_slug']}-{run_id}-{run_attempt}"
        )
        workflow = {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": "javascript_collect",
            "audience": policy["audience"],
        }
        lease = {
            "schema_version": "latchway.live-sdk-collector-lease.v1",
            "repository": "Latchway/latchway",
            "core_commit": observer.identity["core_commit"],
            "javascript_commit": observer.identity["repositories"]["javascript"][
                "commit"
            ],
            "workflow": workflow,
            "runner": {
                "name": runner_name,
                "ephemeral": True,
                "jit": True,
                "max_jobs": 1,
                "fresh_boot": True,
                "clean_workspace": True,
                "repository_scope": "Latchway/latchway",
                "destroy_after_job": True,
                "image_digest": "sha256:" + "a" * 64,
                "boot_id_sha256": "b" * 64,
            },
            "credentials": {
                "long_lived": False,
                "organization": False,
                "administration": False,
                "registry": False,
                "oidc": False,
            },
            "supervisor": {
                "private_key_isolated": True,
                "caller_supplied_claims_accepted": False,
                "gateway_egress_only": True,
                "dns_pinned": True,
                "tls_verified": True,
                "gateway_run_receipt_verification": True,
                "one_use_invocation": True,
            },
            "grant": {
                "audience": f"latchway-live-sdk/{provider}",
                "core_commit": observer.identity["core_commit"],
                "javascript_commit": observer.identity["repositories"][
                    "javascript"
                ]["commit"],
                "run_id": run_id,
                "run_attempt": run_attempt,
                "provider": provider,
                "sha256": grant_sha256,
                "single_use": True,
                "jti_sha256": jti_sha256,
                "request_sha256": request_sha256,
            },
            "candidate": {
                "harness_archive_sha256": harness_archive_sha256,
                "harness_manifest_sha256": hashlib.sha256(
                    harness_payload
                ).hexdigest(),
                "source_report_sha256": observer.input_hashes["source"],
                "candidate_manifest_sha256": observer.input_hashes["candidate"],
            },
            "gateway": {
                "origin": "https://gateway.example.test",
                "application_id": "app_00000000000000000000000000",
                "environment": "production",
            },
            "issued_at_unix": started - 30,
            "expires_at_unix": started + 270,
        }
        lease_payload = MODULE.canonical_json(lease)
        execution_payload = MODULE.canonical_json(
            {"started_at_unix": started, "finished_at_unix": finished}
        )
        receipt = {
            "schema_version": "latchway.live-sdk-gateway-consumption.v1",
            "repository": "Latchway/latchway",
            "core_commit": observer.identity["core_commit"],
            "javascript_commit": observer.identity["repositories"]["javascript"][
                "commit"
            ],
            "run_id": run_id,
            "run_attempt": run_attempt,
            "provider": provider,
            "grant_sha256": grant_sha256,
            "jti_sha256": jti_sha256,
            "single_use": True,
            "consumption_count": 1,
            "consumed": True,
            "report_sha256": hashlib.sha256(report_payload).hexdigest(),
            "request_sha256": request_sha256,
            "consumed_at_unix": started + 30,
        }
        receipt_payload = MODULE.canonical_json(receipt)
        teardown = {
            "schema_version": "latchway.live-sdk-collector-teardown.v1",
            "repository": "Latchway/latchway",
            "core_commit": observer.identity["core_commit"],
            "javascript_commit": observer.identity["repositories"]["javascript"][
                "commit"
            ],
            "workflow": workflow,
            "provider": provider,
            "runner": {
                "name": runner_name,
                "deregistered": True,
                "accepts_more_jobs": False,
                "destroy_scheduled": True,
                "destroy_deadline_unix": finished + 300,
            },
            "grant": {
                "single_use": True,
                "consumption_count": 1,
                "zeroized": True,
                "revoked": True,
            },
            "network": {
                "gateway_egress_only": True,
                "dns_pinned": True,
                "tls_verified": True,
            },
            "gateway_receipt_verified": True,
            "evidence_eligible": True,
            "lease_sha256": hashlib.sha256(lease_payload).hexdigest(),
            "gateway_receipt_sha256": hashlib.sha256(receipt_payload).hexdigest(),
            "report_sha256": hashlib.sha256(report_payload).hexdigest(),
        }
        payloads = {
            "collector-lease.json": lease_payload,
            "collector-lease.sig": b"\x00\xffcollector-lease-signature",
            "collector-teardown.json": MODULE.canonical_json(teardown),
            "collector-teardown.sig": b"\x00\xffcollector-teardown-signature",
            "execution.json": execution_payload,
            "gateway-consumption-receipt.json": receipt_payload,
            "gateway-consumption-receipt.sig": b"\x00\xffgateway-signature",
            "gateway-receipt-public-key.pem": (
                b"-----BEGIN PUBLIC KEY-----\n"
                b"dGVzdC1wdWJsaWMta2V5Cg==\n"
                b"-----END PUBLIC KEY-----\n"
            ),
            "harness-manifest.json": harness_payload,
            "report.json": report_payload,
        }
        for name, payload in payloads.items():
            (isolation / name).write_bytes(payload)
        checksum_payload = "".join(
            f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
            for name in MODULE.LIVE_SDK_ISOLATION_SUBJECTS
        ).encode("ascii")
        (isolation / "ISOLATION_SHA256SUMS").write_bytes(checksum_payload)
        collector = {
            "schema_version": "latchway.live-sdk-collector-isolation.v1",
            "lease_sha256": hashlib.sha256(lease_payload).hexdigest(),
            "teardown_sha256": hashlib.sha256(
                payloads["collector-teardown.json"]
            ).hexdigest(),
            "gateway_receipt_sha256": hashlib.sha256(receipt_payload).hexdigest(),
            "harness_manifest_sha256": hashlib.sha256(harness_payload).hexdigest(),
            "report_sha256": hashlib.sha256(report_payload).hexdigest(),
        }
        capture.write_bytes(
            MODULE.canonical_json(
                {
                    "schema_version": 1,
                    "kind": "latchway_live_javascript_capture",
                    "attestation_provider": provider,
                    "started_at": MODULE.EVIDENCE.format_time(
                        self.workflow_started
                    ),
                    "finished_at": MODULE.EVIDENCE.format_time(
                        self.workflow_finished
                    ),
                    "report": report_value,
                    "collector_isolation": collector,
                }
            )
        )
        return capture

    def github_authority_fixture(
        self,
        observer: MODULE.Observer,
        name: str,
        files: dict[str, bytes],
    ) -> Path:
        root = self.root / name
        root.mkdir()
        rows = []
        for relative, payload in sorted(files.items()):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            rows.append(
                {
                    "path": relative,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "started_at": "2026-08-29T09:55:00Z",
                    "finished_at": "2026-08-29T09:56:00Z",
                }
            )
        manifest = {
            "schema_version": 1,
            "kind": "latchway_github_authority",
            "domain": observer.domain,
            "candidate": observer.identity,
            "source_sha256": observer.input_hashes["source"],
            "candidate_sha256": observer.input_hashes["candidate"],
            "started_at": "2026-08-29T09:55:00Z",
            "finished_at": "2026-08-29T10:00:00Z",
            "files": rows,
        }
        (root / "manifest.json").write_bytes(MODULE.canonical_json(manifest))
        return root

    def test_public_tags_validate_core_first_independent_of_json_key_order(self) -> None:
        observer = self.bare_observer("public_tags")
        observer.identity["repositories"] = {
            key: observer.identity["repositories"][key]
            for key in ("android", "react_native", "ios", "javascript", "core")
        }
        promotion_hash = "f" * 64
        titles = {
            "javascript": "JavaScript SDK",
            "ios": "iOS SDK",
            "android": "Android SDK",
            "react_native": "React Native SDK",
        }
        responses = []
        release_id = 10
        for repository_id in ("core", "javascript", "ios", "android", "react_native"):
            coordinate = observer.identity["repositories"][repository_id]
            expected_assets, adoption_required = observer._expected_release_assets(
                repository_id, coordinate["version"]
            )
            names = sorted(expected_assets)
            for package_id in sorted(adoption_required):
                middle = f"-{package_id}" if package_id else ""
                names.append(f"npm-release-adoption{middle}-123-1.json")
            assets = [
                {
                    "id": index + 1,
                    "name": name,
                    "size": 1,
                    "digest": "sha256:" + f"{index + 1:064x}",
                }
                for index, name in enumerate(names)
            ]
            responses.extend((
                (json.dumps({"ref": "refs/tags/v1.0.0", "object": {"type": "tag", "sha": "f" * 40}}).encode(), self.workflow_started, self.workflow_finished),
                (json.dumps({
                    "tag": "v1.0.0",
                    "object": {"type": "commit", "sha": coordinate["commit"]},
                    "message": (
                        f"Latchway v1.0.0\n\nPromotion evidence SHA-256: {promotion_hash}"
                        if repository_id == "core"
                        else f"{titles[repository_id]} v1.0.0\n\nCore promotion: v1.0.0\nPromotion evidence SHA-256: {promotion_hash}"
                    ),
                }).encode(), self.workflow_started, self.workflow_finished),
                (json.dumps({
                    "id": release_id,
                    "tag_name": "v1.0.0",
                    "name": (
                        "Latchway v1.0.0" if repository_id == "core" else "SDK v1.0.0"
                    ),
                    "body": (
                        "Immutable Latchway product release v1.0.0.\n\n"
                        f"Candidate commit: {coordinate['commit']}\n"
                        f"Promotion evidence SHA-256: {promotion_hash}"
                        if repository_id == "core"
                        else "Immutable SDK release."
                    ),
                    "draft": False,
                    "prerelease": False,
                    "immutable": True,
                    "assets": assets,
                }).encode(), self.workflow_started, self.workflow_finished),
            ))
            release_id += 1
        attestation = b'{"verification":"passed"}\n'
        with mock.patch.object(observer, "_github_authority_file", side_effect=responses), mock.patch.object(
            observer,
            "_release_attestation_from_authority",
            return_value=(attestation, self.workflow_started, self.workflow_finished),
        ), mock.patch.object(observer, "emit") as emit:
            observer.observe_public_tags()
        release_calls = [
            call
            for call in emit.call_args_list
            if call.args[0].startswith("publication.github-release.")
        ]
        self.assertEqual(len(release_calls), 5)
        proof = json.loads(release_calls[0].args[1])
        self.assertEqual(proof["release"]["immutable"], True)
        self.assertEqual(
            base64.b64decode(
                proof["release_attestation"]["content_base64"], validate=True
            ),
            attestation,
        )
        self.assertEqual(
            proof["release_attestation"]["sha256"],
            hashlib.sha256(attestation).hexdigest(),
        )

    def selected_public_tag_responses(
        self, observer: MODULE.Observer
    ) -> list[tuple[bytes, datetime, datetime]]:
        responses: list[tuple[bytes, datetime, datetime]] = []
        for release_id, repository_id in enumerate(
            ("core", "javascript", "ios", "android", "react_native"),
            start=10,
        ):
            coordinate = observer.identity["repositories"][repository_id]
            expected_assets, adoption_required = observer._expected_release_assets(
                repository_id,
                coordinate["version"],
                MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE,
            )
            names = sorted(expected_assets)
            for package_id in sorted(adoption_required):
                middle = f"-{package_id}" if package_id else ""
                names.append(f"npm-release-adoption{middle}-123-1.json")
            assets = [
                {
                    "id": index + 1,
                    "name": name,
                    "size": 1,
                    "digest": "sha256:" + f"{index + 1:064x}",
                }
                for index, name in enumerate(names)
            ]
            intent_sha256 = next(
                (
                    asset["digest"].removeprefix("sha256:")
                    for asset in assets
                    if asset["name"]
                    == "latchway-single-maintainer-v1-intent.json"
                ),
                None,
            )
            tag = coordinate["tag"]
            version = coordinate["version"]
            if repository_id == "core":
                image = observer.identity["oci_image_digest"]
                message = (
                    f"Latchway {tag}\n\n"
                    "Release profile: single_maintainer_v1\n"
                    f"Candidate commit: {coordinate['commit']}\n"
                    f"Image: {image}"
                )
                title = f"Latchway {tag} — single_maintainer_v1"
                body = (
                    f"Latchway {tag} core release.\n\n"
                    "Release profile: single_maintainer_v1\n"
                    "Profile status: incomplete until every required public package and registry check passes.\n"
                    "Authenticated profile-wide publication readiness is not claimed by this core-only record.\n"
                    f"Candidate commit: {coordinate['commit']}\n"
                    f"Image: {image}\n"
                    "Required deployment evidence: Docker Compose and Google Cloud Run passed for this exact image.\n\n"
                    "Deferred evidence remains unverified. This release is not release-qualified, fully evidence-gated, or independently reviewed."
                )
            elif repository_id == "javascript":
                run_id = 123
                transaction_id = hashlib.sha256(
                    "\0".join(
                        (
                            "Latchway/latchway-js",
                            ".github/workflows/single-maintainer-release.yml",
                            str(run_id),
                            coordinate["commit"],
                            tag,
                        )
                    ).encode()
                ).hexdigest()
                owner = (
                    "https://github.com/Latchway/latchway-js/actions/runs/123"
                )
                message = (
                    "Latchway JavaScript SDKs v1.0.0\n\n"
                    "Release profile: single_maintainer_v1\n"
                    "Assurance: deferred; not release-qualified or independently reviewed\n"
                    f"Transaction owner: {owner}\n"
                    f"Transaction ID: {transaction_id}"
                )
                title = (
                    "Latchway JavaScript SDKs 1.0.0 — single-maintainer v1"
                )
                body = (
                    "Published with the `single_maintainer_v1` profile.\n\n"
                    "The exact public Latchway core v1.0.0 release, including Docker Compose and Google Cloud Run evidence, was verified before this transaction began.\n"
                    "npm archives are accepted only with byte-identical registry data, registry signatures, and provenance bound to this repository, workflow, source commit, and main ref.\n"
                    "External platform/device/provider evidence and independent human review remain deferred.\n"
                    "This release is not `release_qualified`, fully evidence-gated, or independently reviewed.\n\n"
                    f"Transaction owner: {owner}\n"
                    f"Transaction ID: {transaction_id}"
                )
            else:
                self.assertIsNotNone(intent_sha256)
                sdk = {
                    "ios": "iOS",
                    "android": "Android",
                    "react_native": "React Native",
                }[repository_id]
                message = (
                    f"Latchway {sdk} SDK {tag}\n\n"
                    "Release profile: single_maintainer_v1\n"
                    "Assurance: deferred; not release-qualified or independently reviewed\n"
                    f"Maintainer intent SHA-256: {intent_sha256}"
                )
                title = f"Latchway {sdk} SDK {version} — single-maintainer v1"
                if repository_id == "android":
                    body = (
                        "Published with the `single_maintainer_v1` profile.\n\n"
                        "The Maven Central bytes, OpenPGP signatures, deterministic source artifacts, pinned-core conformance, and GitHub provenance in this release were verified by automation. Independent human review and external platform/device/provider evidence are deferred. Docker Compose and GCP Cloud Run evidence remain required by the global v1 profile.\n\n"
                        "This release is not `release_qualified`, fully evidence-gated, or independently reviewed."
                    )
                else:
                    body = (
                        "Published with the `single_maintainer_v1` profile. External platform/device/provider evidence and independent human review are deferred. This release is not `release_qualified`, fully evidence-gated, or independently reviewed.\n"
                    )
            responses.extend(
                (
                    (
                        json.dumps(
                            {
                                "ref": f"refs/tags/{tag}",
                                "object": {"type": "tag", "sha": "f" * 40},
                            }
                        ).encode(),
                        self.workflow_started,
                        self.workflow_finished,
                    ),
                    (
                        json.dumps(
                            {
                                "tag": tag,
                                "object": {
                                    "type": "commit",
                                    "sha": coordinate["commit"],
                                },
                                "message": message,
                            }
                        ).encode(),
                        self.workflow_started,
                        self.workflow_finished,
                    ),
                    (
                        json.dumps(
                            {
                                "id": release_id,
                                "tag_name": tag,
                                "name": title,
                                "body": body,
                                "draft": False,
                                "prerelease": False,
                                "immutable": True,
                                "assets": assets,
                            }
                        ).encode(),
                        self.workflow_started,
                        self.workflow_finished,
                    ),
                )
            )
        return responses

    def test_single_maintainer_public_tags_validate_exact_five_repo_surface(self) -> None:
        observer = self.bare_observer("public_tags")
        observer.release_profile = MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        observer.evidence_release_profile = MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        responses = self.selected_public_tag_responses(observer)
        attestation = b'{"verification":"passed"}\n'
        with mock.patch.object(
            observer, "_github_authority_file", side_effect=responses
        ), mock.patch.object(
            observer,
            "_release_attestation_from_authority",
            return_value=(
                attestation,
                self.workflow_started,
                self.workflow_finished,
            ),
        ), mock.patch.object(observer, "emit") as emit:
            observer.observe_public_tags()
        self.assertEqual(emit.call_count, 10)

    def test_single_maintainer_public_tags_reject_tag_body_and_asset_drift(self) -> None:
        for mutation in ("tag", "body", "asset"):
            observer = self.bare_observer("public_tags")
            observer.release_profile = MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
            observer.evidence_release_profile = (
                MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
            )
            responses = self.selected_public_tag_responses(observer)
            payload, started, finished = responses[2]
            core_release = json.loads(payload)
            if mutation == "tag":
                tag_payload, tag_started, tag_finished = responses[1]
                tag_object = json.loads(tag_payload)
                tag_object["message"] += "\nextra"
                responses[1] = (
                    json.dumps(tag_object).encode(), tag_started, tag_finished
                )
            elif mutation == "body":
                core_release["body"] += "\nextra"
                responses[2] = (
                    json.dumps(core_release).encode(), started, finished
                )
            else:
                core_release["assets"].append(
                    {
                        "id": 999,
                        "name": "unexpected.txt",
                        "size": 1,
                        "digest": "sha256:" + "9" * 64,
                    }
                )
                responses[2] = (
                    json.dumps(core_release).encode(), started, finished
                )
            with self.subTest(mutation=mutation), mock.patch.object(
                observer, "_github_authority_file", side_effect=responses
            ), self.assertRaisesRegex(
                MODULE.ObservationError,
                "public_tag_message_mismatch|github_release_invalid|github_release_asset_set_invalid",
            ):
                observer.observe_public_tags()

    def test_single_maintainer_react_native_rejects_multiple_adoptions(
        self,
    ) -> None:
        observer = self.bare_observer("public_tags")
        observer.release_profile = MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        observer.evidence_release_profile = MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        responses = self.selected_public_tag_responses(observer)
        payload, started, finished = responses[14]
        release = json.loads(payload)
        release["assets"].append(
            {
                "id": 999,
                "name": "npm-release-adoption-124-1.json",
                "size": 1,
                "digest": "sha256:" + "9" * 64,
            }
        )
        responses[14] = (json.dumps(release).encode(), started, finished)
        with mock.patch.object(
            observer, "_github_authority_file", side_effect=responses
        ), mock.patch.object(
            observer,
            "_release_attestation_from_authority",
            return_value=(
                b'{"verification":"passed"}\n',
                self.workflow_started,
                self.workflow_finished,
            ),
        ), self.assertRaisesRegex(
            MODULE.ObservationError, "github_release_asset_set_invalid"
        ):
            observer.observe_public_tags()

    def test_reviewed_zip_rejects_duplicate_and_symlink_members(self) -> None:
        for mode in ("duplicate", "symlink"):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                if mode == "duplicate":
                    with self.assertWarns(UserWarning):
                        archive.writestr("dev/latchway/file.pom", b"one")
                        archive.writestr("dev/latchway/file.pom", b"two")
                else:
                    member = zipfile.ZipInfo("dev/latchway/link.pom")
                    member.create_system = 3
                    member.external_attr = 0o120777 << 16
                    archive.writestr(member, b"target")
            with self.subTest(mode=mode), self.assertRaisesRegex(
                MODULE.ObservationError, "reviewed_maven_archive_invalid"
            ):
                destination = self.root / mode
                destination.mkdir()
                MODULE.Observer._extract_reviewed_zip(stream.getvalue(), destination)

    def concrete_tests(self, receipt_id: str, *, javascript: bool = False) -> list[dict]:
        if javascript:
            names = set(MODULE.LIVE_SDK_JAVASCRIPT_TESTS)
            mapped = "javascript_latchway_error"
        else:
            policy = MODULE.LIVE_SDK_RECEIPTS[receipt_id]
            names = set(policy["tests"])
            mapped = policy["mapped_error_type"]
        tests = [
            {"id": name, "status": "passed", "duration_ms": 1}
            for name in sorted(names)
        ]
        by_id = {item["id"]: item for item in tests}
        by_id["dpop_authorized_request"].update(
            http_status=200, request_id="request-authorized-1234"
        )
        by_id["dpop_replay_rejected"].update(
            http_status=401,
            error_code="dpop_replayed",
            request_id="request-replay-1234",
        )
        by_id["tampered_dpop_rejected"].update(
            http_status=401,
            error_code="dpop_invalid",
            request_id="request-tamper-1234",
        )
        by_id["canonical_error_mapping"].update(
            http_status=404,
            error_code="feature_not_found",
            request_id="request-mapping-1234",
            mapped_error_type=mapped,
        )
        by_id["session_refresh_rotation"].update(
            credential_before_sha256="1" * 64,
            credential_after_sha256="2" * 64,
            installation_before_sha256="3" * 64,
            installation_after_sha256="3" * 64,
        )
        by_id["installation_revocation"].update(
            http_status=403,
            error_code="installation_revoked",
            request_id="request-revoked-1234",
        )
        by_id["protocol_version_rejection"].update(
            http_status=426,
            error_code="protocol_version_unsupported",
            request_id="request-protocol-1234",
            protocol_version_sent=0,
        )
        by_id["streamed_request"].update(
            http_status=200, request_id="request-stream-1234"
        )
        if "component_sibling_denied" in by_id:
            by_id["component_sibling_denied"].update(
                http_status=401,
                error_code="component_key_invalid",
                request_id="request-sibling-1234",
            )
            for role in ("widget", "share", "action"):
                by_id[f"{role}_delegated_request"].update(
                    http_status=200,
                    request_id=f"request-{role}-1234",
                )
            by_id["component_keychain_sibling_denied"].update(
                os_status=-34018,
                os_status_name="errSecMissingEntitlement",
            )
            by_id["component_refresh_race"].update(
                concurrent_request_count=2,
                credential_before_sha256="8" * 64,
                credential_after_sha256="a" * 64,
            )
        if javascript:
            by_id["streamed_request"]["byte_count"] = 128
            by_id["quota"].update(
                feature="chat", limit_count=1, metrics=["requests"]
            )
        return tests

    def ios_component_case(
        self, expected_pins: Mapping[str, str], run_id: str
    ) -> dict:
        values = {
            "host": ("main_app", "c", "0", "4"),
            "widget": ("widget", "d", "1", "5"),
            "share": ("share_extension", "e", "2", "6"),
            "action": ("action_extension", "f", "3", "7"),
        }
        identities = [
            {
                "role": role,
                "kind": kind,
                "definition_id": expected_pins[f"{role}_definition_id"],
                "bundle_identifier": expected_pins[f"{role}_bundle_identifier"],
                "binary_sha256": expected_pins[f"{role}_binary_sha256"],
                "attestation_mode": (
                    "root_app_attest" if role == "host" else "delegated_only"
                ),
                "principal_id_sha256": principal * 64,
                "dpop_key_id_sha256": key * 64,
                "session_id_sha256": session * 64,
            }
            for role, (kind, principal, key, session) in values.items()
        ]
        tests = [
            item
            for item in self.concrete_tests("ios")
            if item["id"] in MODULE.IOS_COMPONENT_TESTS
        ]
        return {
            "schema_version": MODULE.IOS_COMPONENT_OBSERVATION_VERSION,
            "platform": "ios_app_attest",
            "run_id": run_id,
            "started_at": "2026-08-29T10:01:00Z",
            "completed_at": "2026-08-29T10:04:00Z",
            "runtime": {
                "identities": identities,
                "widget_delegated_execution": {
                    "role": "widget",
                    "definition_id": expected_pins["widget_definition_id"],
                    "component_id_sha256": "d" * 64,
                    "dpop_key_id_sha256": "1" * 64,
                    "session_id_sha256": "5" * 64,
                    "trust_source": "delegated_from_attested_root",
                    "http_status": 200,
                    "request_id": "request-widget-1234",
                },
                "share_delegated_execution": {
                    "role": "share",
                    "definition_id": expected_pins["share_definition_id"],
                    "component_id_sha256": "e" * 64,
                    "dpop_key_id_sha256": "2" * 64,
                    "session_id_sha256": "6" * 64,
                    "trust_source": "delegated_from_attested_root",
                    "http_status": 200,
                    "request_id": "request-share-1234",
                },
                "delegated_execution": {
                    "role": "action",
                    "definition_id": expected_pins["action_definition_id"],
                    "component_id_sha256": "f" * 64,
                    "dpop_key_id_sha256": "3" * 64,
                    "session_id_sha256": "7" * 64,
                    "trust_source": "delegated_from_attested_root",
                    "http_status": 200,
                    "request_id": "request-action-1234",
                },
                "sibling_denial": {
                    "requesting_role": "action",
                    "credential_role": "share",
                    "credential_session_id_sha256": "6" * 64,
                    "http_status": 401,
                    "error_code": "component_key_invalid",
                    "request_id": "request-sibling-1234",
                },
                "keychain_sibling_denial": {
                    "requesting_role": "action",
                    "target_role": "share",
                    "target_key_id_sha256": "2" * 64,
                    "operation": "SecItemCopyMatching",
                    "os_status": -34018,
                    "os_status_name": "errSecMissingEntitlement",
                    "key_material_returned": False,
                },
                "component_refresh_race": {
                    "role": "action",
                    "component_id_sha256": "f" * 64,
                    "dpop_key_id_sha256": "3" * 64,
                    "session_id_before_sha256": "8" * 64,
                    "old_credential_sha256": "8" * 64,
                    "requests_started_concurrently": True,
                    "overlap_observed": True,
                    "requests": [
                        {
                            "request_id": "request-refresh-race-a",
                            "http_status": 200,
                            "access_credential_sha256": "9" * 64,
                            "refresh_credential_sha256": "a" * 64,
                            "session_id_sha256": "7" * 64,
                        },
                        {
                            "request_id": "request-refresh-race-b",
                            "http_status": 200,
                            "access_credential_sha256": "9" * 64,
                            "refresh_credential_sha256": "a" * 64,
                            "session_id_sha256": "7" * 64,
                        },
                    ],
                    "session_id_after_sha256": "7" * 64,
                    "results_identical": True,
                },
                "lifecycle": {
                    "host_process_running_during_action_request": False,
                    "background_execution_observed": True,
                    "host_termination_observed": True,
                    "user_presence_prompt_observed": False,
                },
            },
            "tests": tests,
        }

    def physical_case(self, receipt_id: str) -> tuple[dict, dict]:
        observer = self.bare_observer("live_sdk_conformance")
        policy = MODULE.LIVE_SDK_RECEIPTS[receipt_id]
        coordinate = observer.identity["repositories"][policy["repository_id"]]
        source = {
            "commit": coordinate["commit"],
            "core_commit": observer.identity["core_commit"],
            "worktree_clean": True,
            "sdk_version": coordinate["version"],
            "contract_version": observer.identity["contract_version"],
            "contract_bundle_sha256": observer.identity["bundle_sha256"],
            "gateway_image_digest": observer.candidate["image"]["index_digest"],
            "gateway_configuration_sha256": "4" * 64,
            "gateway_origin": "https://gateway.example.test",
            "gateway_deployment_key_id": "gateway-key-1",
            "gateway_deployment_statement_sha256": "5" * 64,
            "gateway_deployment_public_key_sha256": "6" * 64,
        }
        expected_pins = {
            "source_commit": coordinate["commit"],
            "core_commit": observer.identity["core_commit"],
            "contract_bundle_sha256": observer.identity["bundle_sha256"],
            "gateway_image_digest": observer.candidate["image"]["index_digest"],
            "gateway_configuration_sha256": "4" * 64,
            "gateway_origin": "https://gateway.example.test",
            "gateway_environment": "production",
            "gateway_deployment_key_id": "gateway-key-1",
            "gateway_deployment_statement_sha256": "5" * 64,
            "gateway_deployment_public_key_sha256": "6" * 64,
            "error_mapping_feature": "missing_feature",
        }
        if receipt_id.startswith("react_native_"):
            expected_pins.update(native_sdk_version="1.0.0", native_evidence_sha256="7" * 64)
        if receipt_id == "ios":
            expected_pins.update(
                host_bundle_identifier="dev.latchway.conformance",
                widget_bundle_identifier="dev.latchway.conformance.widget",
                share_bundle_identifier="dev.latchway.conformance.share",
                action_bundle_identifier="dev.latchway.conformance.action",
                host_definition_id="host_app",
                widget_definition_id="home_widget",
                share_definition_id="share_sheet",
                action_definition_id="background_action",
                host_binary_sha256="9" * 64,
                widget_binary_sha256="a" * 64,
                share_binary_sha256="b" * 64,
                action_binary_sha256="c" * 64,
            )
        profile = {
            "platform": policy["platform"],
            "repository": policy["repository"],
            "source": source,
            "expected_pins": expected_pins,
        }
        evidence = {
            "platform": policy["platform"],
            "release_eligible": True,
            "source": source,
            "run": {
                "id": f"{policy['run_prefix']}-12345-2",
                "mode": "release",
                "started_at": "2026-08-29T10:00:00Z",
                "completed_at": "2026-08-29T10:05:00Z",
            },
            "generated_at": "2026-08-29T10:06:00Z",
            "device": {
                "physical": True,
                "simulator": False,
                "emulator": False,
                "testing": False,
                "debugger_attached": False,
            },
            "provider": {"environment": "production", "request_hash_bound": True},
            "tests": self.concrete_tests(receipt_id),
        }
        if receipt_id == "ios":
            component = self.ios_component_case(
                expected_pins, evidence["run"]["id"]
            )
            component_payload = json.dumps(component).encode()
            evidence["component_runtime"] = component["runtime"]
            evidence["artifacts"] = {
                "component_observation_sha256": hashlib.sha256(
                    component_payload
                ).hexdigest()
            }
        return profile, evidence

    def receipt_directory(self, receipt_id: str) -> Path:
        policy = MODULE.LIVE_SDK_RECEIPTS[receipt_id]
        root = self.root / f"receipt-{receipt_id}"
        root.mkdir()
        checksums = []
        for name in sorted(policy["manifest"]):
            payload = (
                b"<testsuite/>\n"
                if name.endswith(".xml")
                else b"signature\n"
                if name.endswith(".sig") or name.endswith(".pem")
                else b"artifact-hash\n"
                if name.endswith(".sha256")
                else b'{}\n'
            )
            (root / name).write_bytes(payload)
            checksums.append(f"{hashlib.sha256(payload).hexdigest()}  {name}\n")
        (root / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
        (root / "github-attestation.sigstore.json").write_text("{}\n", encoding="utf-8")
        return root

    def test_constructor_rejects_unprotected_context_before_parsing_inputs(self) -> None:
        with (
            mock.patch.object(
                MODULE.EVIDENCE,
                "protected_context",
                side_effect=MODULE.EVIDENCE.EvidenceError(
                    "protected_workflow_required"
                ),
            ),
            mock.patch.object(MODULE.EVIDENCE, "identity_from_inputs") as identity,
        ):
            with self.assertRaisesRegex(
                MODULE.EVIDENCE.EvidenceError, "protected_workflow_required"
            ):
                MODULE.Observer(
                    domain="live_provider",
                    source=self.root / "source.json",
                    candidate=self.root / "candidate.json",
                    output=self.root / "output",
                    repositories={},
                    now=datetime.now(timezone.utc),
                )
        identity.assert_not_called()

    def test_constructor_rejects_github_admin_and_oidc_credentials_before_parsing_inputs(self) -> None:
        for name in sorted(MODULE.FORBIDDEN_CANDIDATE_CREDENTIAL_ENV):
            with (
                self.subTest(name=name),
                mock.patch.dict(os.environ, {name: "must-not-reach-candidate"}, clear=True),
                mock.patch.object(MODULE.EVIDENCE, "protected_context", return_value={}),
                mock.patch.object(MODULE.EVIDENCE, "identity_from_inputs") as identity,
                self.assertRaisesRegex(
                    MODULE.ObservationError, "candidate_credentials_present"
                ),
            ):
                MODULE.Observer(
                    domain="live_provider",
                    source=self.root / "source.json",
                    candidate=self.root / "candidate.json",
                    output=self.root / f"output-{name.lower()}",
                    repositories={},
                    now=datetime.now(timezone.utc),
                )
            identity.assert_not_called()

    def test_cli_contract_exposes_only_explicit_offline_privileged_captures(self) -> None:
        options = {
            option
            for action in MODULE.parser()._actions
            for option in action.option_strings
        }
        self.assertIn("--live-provider-capture-directory", options)
        self.assertIn("--github-authority-directory", options)
        for removed in (
            "--api-token-env",
            "--server",
            "--server-owned",
            "--upstream",
            "--model",
            "--max-cost-nano-usd",
        ):
            self.assertNotIn(removed, options)
        self.assertNotIn(
            "LATCHWAY_ADMIN_API_TOKEN", MODULE.ALLOWED_ENVIRONMENT_OVERRIDES
        )

    def test_repository_checkouts_bind_every_exact_source_commit_and_clean_tree(self) -> None:
        fixture = FIXTURE_MODULE.EvidenceFixture(
            self.root / "fixture", "live_provider"
        )
        repositories: dict[str, Path] = {}
        for repository_id in MODULE.REPOSITORY_NAMES:
            repositories[repository_id] = self.root / repository_id
            repositories[repository_id].mkdir()

        def substituted(path: Path) -> tuple[str, bytes]:
            repository_id = path.name
            commit = fixture.identity["repositories"][repository_id]["commit"]
            if repository_id == "javascript":
                commit = "f" * 40
            return commit, b""

        with (
            mock.patch.object(MODULE.EVIDENCE, "protected_context", return_value={}),
            mock.patch.object(MODULE, "repository_state", side_effect=substituted),
        ):
            with self.assertRaisesRegex(
                MODULE.ObservationError, "repository_commit_mismatch"
            ):
                MODULE.Observer(
                    domain="live_provider",
                    source=fixture.source,
                    candidate=fixture.candidate,
                    output=self.root / "substituted-output",
                    repositories=repositories,
                    now=fixture.now,
                )
        self.assertFalse((self.root / "substituted-output").exists())

        def dirty(path: Path) -> tuple[str, bytes]:
            repository_id = path.name
            commit = fixture.identity["repositories"][repository_id]["commit"]
            return commit, b"?? injected-script.sh\x00" if repository_id == "ios" else b""

        with (
            mock.patch.object(MODULE.EVIDENCE, "protected_context", return_value={}),
            mock.patch.object(MODULE, "repository_state", side_effect=dirty),
        ):
            with self.assertRaisesRegex(
                MODULE.ObservationError, "repository_checkout_dirty"
            ):
                MODULE.Observer(
                    domain="live_provider",
                    source=fixture.source,
                    candidate=fixture.candidate,
                    output=self.root / "dirty-output",
                    repositories=repositories,
                    now=fixture.now,
                )

    def test_repository_verifier_runs_only_head_and_clean_tree_commands(self) -> None:
        completed = [
            subprocess.CompletedProcess([], 0, b"a" * 40 + b"\n", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
        runner = mock.Mock(side_effect=completed)
        environment = {
            "PATH": "/usr/bin",
            "RUNNER_TEMP": str(self.root),
            "AWS_SECRET_ACCESS_KEY": "must-not-propagate",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/git"),
            mock.patch.object(MODULE.subprocess, "run", runner),
        ):
            head, status = MODULE.repository_state(self.root)
        self.assertEqual(head, "a" * 40)
        self.assertEqual(status, b"")
        self.assertEqual(runner.call_count, 2)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(
            commands,
            [
                (
                    "/usr/bin/git",
                    "-C",
                    str(self.root),
                    "rev-parse",
                    "--verify",
                    "HEAD",
                ),
                (
                    "/usr/bin/git",
                    "-C",
                    str(self.root),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                ),
            ],
        )
        for call in runner.call_args_list:
            command_env = call.kwargs["env"]
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", command_env)
            self.assertEqual(command_env["HOME"], str(self.root))
            self.assertEqual(command_env["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_command_runner_uses_one_exact_subprocess_and_allowlisted_environment(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b'{"records":1}\n', stderr=b""
        )
        runner = mock.Mock(return_value=completed)
        environment = {
            "PATH": "/usr/bin",
            "RUNNER_TEMP": str(self.root),
            "UNEXPECTED_SECRET": "do-not-copy",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(
                MODULE.shutil, "which", return_value="/usr/bin/fixed-tool"
            ),
            mock.patch.object(MODULE.subprocess, "run", runner),
        ):
            payload, _, _ = MODULE.Observer._execute_command(
                ("fixed-tool", "verify", "--format", "json")
            )
        self.assertEqual(payload, completed.stdout)
        runner.assert_called_once()
        call = runner.call_args
        self.assertEqual(
            call.args[0],
            ("/usr/bin/fixed-tool", "verify", "--format", "json"),
        )
        self.assertNotIn("UNEXPECTED_SECRET", call.kwargs["env"])
        self.assertEqual(call.kwargs["env"]["HOME"], str(self.root))

    def test_command_runner_rejects_empty_nonzero_malformed_and_secret_output(self) -> None:
        cases = (
            (0, b"", "observation_output_empty", None),
            (7, b'{"error":"safe"}\n', "observation_command_failed", None),
            (0, b"not-json\n", "malformed", "json"),
            (
                0,
                b'{"authorization":"Bearer abcdefghijklmnopqrstuvwxyz"}\n',
                "raw_result_contains_secret",
                None,
            ),
        )
        for returncode, stdout, error, validator in cases:
            with self.subTest(error=error):
                observer = self.bare_observer()
                completed = subprocess.CompletedProcess(
                    args=[], returncode=returncode, stdout=stdout, stderr=b"ignored"
                )
                validate = (
                    (lambda payload: MODULE.load_output(payload, "malformed"))
                    if validator == "json"
                    else None
                )
                with (
                    mock.patch.object(
                        MODULE.shutil, "which", return_value="/usr/bin/fixed-tool"
                    ),
                    mock.patch.object(
                        MODULE.subprocess, "run", return_value=completed
                    ) as runner,
                    mock.patch.object(observer, "emit") as emit,
                ):
                    with self.assertRaisesRegex(Exception, error):
                        observer.run_command(
                            "provider.openrouter.non-streaming",
                            ("fixed-tool", "verify"),
                            validate=validate,
                        )
                runner.assert_called_once()
                emit.assert_not_called()

    def test_live_provider_consumes_only_the_offline_health_and_self_test_capture(self) -> None:
        observer = self.bare_observer()
        health_payload = json.dumps(
            {
                "status": "ok",
                "build": {
                    "version": "1.0.0",
                    "commit": "a" * 40,
                    "contract_version": "0.5.1",
                    "protocol_version": "2",
                },
            }
        ).encode()
        result = {
            "kind": "openrouter",
            "state": "passed",
            "checks": [
                {"name": name, "state": "passed"}
                for name in MODULE.PROVIDER_CHECKS.values()
            ],
        }
        self_test_payload = json.dumps(result).encode()
        capture = {
            "gateway_origin": "https://gateway.example.test",
            "request_sha256": "9" * 64,
            "manifest_sha256": "8" * 64,
            "retained_inputs": {"manifest.json": b"{}\n"},
            "files": {
                "health.json": {
                    "payload": health_payload,
                    "started": self.workflow_started,
                    "finished": self.workflow_started.replace(minute=56),
                },
                "self-test.json": {
                    "payload": self_test_payload,
                    "started": self.workflow_started.replace(minute=56),
                    "finished": self.workflow_started.replace(minute=57),
                },
            },
        }
        with (
            mock.patch.object(observer, "_load_live_provider_capture", return_value=capture),
            mock.patch.object(observer, "_execute_command") as execute,
            mock.patch.object(observer, "run_command") as run_command,
            mock.patch.object(observer, "emit") as emit,
        ):
            observer.observe_live_provider()
        execute.assert_not_called()
        run_command.assert_not_called()
        self.assertEqual(emit.call_count, len(MODULE.PROVIDER_CHECKS) + 1)
        self.assertEqual(emit.call_args_list[0].args[0], "provider.gateway-identity")
        self.assertEqual(emit.call_args_list[0].args[1], health_payload)
        self.assertEqual(
            emit.call_args_list[0].kwargs["retained_input_kind"],
            "live_provider_collector_isolation",
        )
        self.assertEqual(
            emit.call_args_list[0].kwargs["retained_inputs"],
            capture["retained_inputs"],
        )
        command = emit.call_args_list[1].kwargs["invocation"]
        self.assertEqual(
            command,
            (
                "https",
                "POST",
                "https://gateway.example.test/admin/v1/self-tests",
                "request-sha256:" + "9" * 64,
            ),
        )

        changed_capture = {**capture, "manifest_sha256": "7" * 64}
        with (
            mock.patch.object(
                observer,
                "_load_live_provider_capture",
                side_effect=(capture, changed_capture),
            ),
            mock.patch.object(observer, "emit"),
            self.assertRaisesRegex(
                MODULE.ObservationError, "live_provider_capture_changed"
            ),
        ):
            observer.observe_live_provider()

    def test_live_provider_validators_reject_identity_and_check_tampering(self) -> None:
        observer = self.bare_observer()
        identity = observer.identity
        health = {
            "status": "ok",
            "build": {
                "version": "1.0.0",
                "commit": "a" * 40,
                "contract_version": "0.5.1",
                "protocol_version": "2",
            },
        }
        MODULE.Observer._validate_gateway_identity(
            json.dumps(health).encode(), identity
        )
        health["build"]["commit"] = "f" * 40
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_gateway_identity_invalid"
        ):
            MODULE.Observer._validate_gateway_identity(
                json.dumps(health).encode(), identity
            )

        result = {
            "kind": "openrouter",
            "state": "passed",
            "checks": [
                {"name": name, "state": "passed"}
                for name in MODULE.PROVIDER_CHECKS.values()
            ],
        }
        MODULE.Observer._validate_provider_result(json.dumps(result).encode())
        result["checks"][0]["state"] = "failed"
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_check_missing"
        ):
            MODULE.Observer._validate_provider_result(json.dumps(result).encode())

    def test_live_provider_observation_retains_the_signed_collector_closure(self) -> None:
        observer = self.bare_observer("live_provider")
        observer.live_provider_capture = self.live_provider_capture_fixture(
            observer, "provider-retained-closure"
        )

        observer.observe_live_provider()

        result = json.loads(
            (observer.output / "provider-gateway-identity.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            [row["path"] for row in result["artifacts"]],
            [
                "artifacts/provider-gateway-identity/tool-output.json",
                "artifacts/provider-gateway-identity/live-provider-isolation.json",
            ],
        )
        retained = json.loads(
            (
                observer.output
                / "artifacts/provider-gateway-identity/live-provider-isolation.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            retained["kind"],
            "latchway_retained_live_provider_collector_isolation",
        )
        self.assertEqual(
            {row["name"] for row in retained["files"]},
            set(MODULE.LIVE_PROVIDER_ISOLATION_PATHS),
        )

    def test_live_provider_capture_rejects_missing_extra_symlink_hash_time_and_coordinate_mutations(self) -> None:
        observer = self.bare_observer("live_provider")
        valid = self.live_provider_capture_fixture(observer, "provider-valid")
        observer.live_provider_capture = valid
        capture = observer._load_live_provider_capture()
        self.assertEqual(capture["gateway_origin"], "https://gateway.example.test")
        self.assertEqual(
            set(capture["retained_inputs"]),
            set(MODULE.LIVE_PROVIDER_ISOLATION_PATHS),
        )

        missing = self.live_provider_capture_fixture(observer, "provider-missing")
        (missing / "health.json").unlink()
        observer.live_provider_capture = missing
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_capture_file_set_invalid"
        ):
            observer._load_live_provider_capture()

        extra = self.live_provider_capture_fixture(observer, "provider-extra")
        (extra / "unexpected.json").write_text("{}\n", encoding="utf-8")
        observer.live_provider_capture = extra
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_capture_file_set_invalid"
        ):
            observer._load_live_provider_capture()

        linked = self.live_provider_capture_fixture(observer, "provider-symlink")
        (linked / "link.json").symlink_to(linked / "health.json")
        observer.live_provider_capture = linked
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_capture_symlink"
        ):
            observer._load_live_provider_capture()

        changed = self.live_provider_capture_fixture(observer, "provider-hash")
        (changed / "health.json").write_text('{"tampered":true}\n', encoding="utf-8")
        observer.live_provider_capture = changed
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_collector_isolation_invalid"
        ):
            observer._load_live_provider_capture()

        invalid_time = self.live_provider_capture_fixture(observer, "provider-time")
        manifest = json.loads(
            (invalid_time / "manifest.json").read_text(encoding="utf-8")
        )
        manifest["files"][0]["finished_at"] = manifest["files"][0]["started_at"]
        (invalid_time / "manifest.json").write_bytes(MODULE.canonical_json(manifest))
        observer.live_provider_capture = invalid_time
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_capture_file_invalid"
        ):
            observer._load_live_provider_capture()

        coordinate = self.live_provider_capture_fixture(observer, "provider-coordinate")
        manifest = json.loads((coordinate / "manifest.json").read_text(encoding="utf-8"))
        manifest["candidate"]["core_commit"] = "f" * 40
        (coordinate / "manifest.json").write_bytes(MODULE.canonical_json(manifest))
        observer.live_provider_capture = coordinate
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_provider_capture_invalid"
        ):
            observer._load_live_provider_capture()

    def test_github_authority_rejects_closure_hash_time_coordinate_run_and_attestation_mutations(self) -> None:
        observer = self.bare_observer("public_registries")
        run = {
            "id": 123,
            "run_attempt": 2,
            "event": "repository_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "b" * 40,
            "head_branch": "main",
            "path": ".github/workflows/release.yml",
            "repository": {"full_name": "Latchway/latchway-js"},
        }
        attestation = [{"verificationResult": {"signature": {"verified": True}}}]
        files = {
            "public-registries/javascript/runs/123-2.json": MODULE.canonical_json(run),
            "public-registries/javascript/attestations/package-evidence.json.json": MODULE.canonical_json(attestation),
        }
        valid = self.github_authority_fixture(observer, "github-valid", files)
        observer.github_authority = valid
        observer._validate_github_authority_directory()
        authenticated_run = observer._github_run_from_authority("javascript", 123, 2)
        observer._validate_npm_workflow_run(
            authenticated_run,
            "Latchway/latchway-js",
            "b" * 40,
            123,
            2,
            conclusions={"success"},
        )
        subject = self.root / "package-evidence.json"
        subject.write_text("{}\n", encoding="utf-8")
        self.assertEqual(
            observer._verify_release_asset_attestation(
                subject,
                "javascript",
                observer.identity["repositories"]["javascript"],
            ),
            attestation,
        )
        observer._validate_github_authority_consumed()

        changed_after_read = self.github_authority_fixture(
            observer, "github-changed-after-read", files
        )
        observer.github_authority = changed_after_read
        observer._validate_github_authority_directory()
        for relative in files:
            observer._github_authority_file(relative)
        (
            changed_after_read
            / "public-registries/javascript/runs/123-2.json"
        ).write_text('{"tampered":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "github_authority_file_changed"
        ):
            observer._validate_github_authority_consumed()

        for mutation in (
            "missing",
            "extra",
            "symlink",
            "hash",
            "time",
            "coordinate",
        ):
            changed = self.github_authority_fixture(
                observer, f"github-{mutation}", files
            )
            if mutation == "missing":
                (changed / "public-registries/javascript/runs/123-2.json").unlink()
            elif mutation == "extra":
                (changed / "extra.json").write_text("{}\n", encoding="utf-8")
            elif mutation == "symlink":
                (changed / "link.json").symlink_to(changed / "manifest.json")
            elif mutation == "hash":
                (changed / "public-registries/javascript/runs/123-2.json").write_text(
                    '{"tampered":true}\n', encoding="utf-8"
                )
            elif mutation == "time":
                manifest = json.loads(
                    (changed / "manifest.json").read_text(encoding="utf-8")
                )
                manifest["files"][0]["finished_at"] = manifest["files"][0][
                    "started_at"
                ]
                (changed / "manifest.json").write_bytes(
                    MODULE.canonical_json(manifest)
                )
            else:
                manifest = json.loads(
                    (changed / "manifest.json").read_text(encoding="utf-8")
                )
                manifest["candidate"]["repositories"]["javascript"]["commit"] = "f" * 40
                (changed / "manifest.json").write_bytes(
                    MODULE.canonical_json(manifest)
                )
            observer.github_authority = changed
            with self.subTest(mutation=mutation), self.assertRaises(
                MODULE.ObservationError
            ):
                observer._validate_github_authority_directory()

        bad_run = dict(run)
        bad_run["event"] = "push"
        invalid_run = self.github_authority_fixture(
            observer,
            "github-run-mutation",
            {
                "public-registries/javascript/runs/123-2.json": MODULE.canonical_json(
                    bad_run
                )
            },
        )
        observer.github_authority = invalid_run
        observer._validate_github_authority_directory()
        with self.assertRaisesRegex(
            MODULE.ObservationError, "registry_npm_provenance_run_invalid"
        ):
            observer._validate_npm_workflow_run(
                observer._github_run_from_authority("javascript", 123, 2),
                "Latchway/latchway-js",
                "b" * 40,
                123,
                2,
                conclusions={"success"},
            )

        invalid_attestation = self.github_authority_fixture(
            observer,
            "github-attestation-mutation",
            {
                "public-registries/javascript/attestations/package-evidence.json.json": b"{}\n"
            },
        )
        observer.github_authority = invalid_attestation
        observer._validate_github_authority_directory()
        with self.assertRaisesRegex(
            MODULE.ObservationError, "release_asset_attestation_invalid"
        ):
            observer._verify_release_asset_attestation(
                subject,
                "javascript",
                observer.identity["repositories"]["javascript"],
            )

    def test_github_authority_file_bound_accepts_exact_schema_maximum_only(self) -> None:
        observer = self.bare_observer("public_registries")
        self.assertEqual(MODULE.MAXIMUM_AUTHORITY_FILES, 541)
        maximum_files = {
            f"boundary/{index:03d}.json": b"{}\n"
            for index in range(MODULE.MAXIMUM_AUTHORITY_FILES)
        }
        accepted = self.github_authority_fixture(
            observer, "github-authority-boundary-accepted", maximum_files
        )
        observer.github_authority = accepted
        observer._validate_github_authority_directory()

        rejected = self.github_authority_fixture(
            observer,
            "github-authority-boundary-rejected",
            {
                **maximum_files,
                f"boundary/{MODULE.MAXIMUM_AUTHORITY_FILES:03d}.json": b"{}\n",
            },
        )
        observer.github_authority = rejected
        with self.assertRaisesRegex(
            MODULE.ObservationError, "github_authority_file_set_invalid"
        ):
            observer._validate_github_authority_directory()

    def test_collector_observer_and_final_verifier_share_exact_attestation_sets(self) -> None:
        version = "1.0.0"
        javascript_fixed, _ = (
            PUBLIC_PROOF_FIXTURE_MODULE.MODULE.expected_npm_release_assets(
                "@latchway/client", version
            )
        )
        react_native_fixed, _ = (
            PUBLIC_PROOF_FIXTURE_MODULE.MODULE.expected_npm_release_assets(
                "@latchway/react-native", version
            )
        )
        release_names = {
            "javascript": javascript_fixed
            | {
                f"npm-release-adoption-{package_id}-10-1.json"
                for package_id, _ in MODULE.JAVASCRIPT_NPM_PACKAGES
            },
            "react_native": react_native_fixed
            | {"npm-release-adoption-10-1.json"},
            "ios": {
                f"latchway-ios-sdk-{version}.tar.gz",
                f"latchway-ios-sdk-{version}.tar.gz.sha256",
                f"docs-bundle-{version}.tar.gz",
                "cocoapods-published-podspec.json",
                "cocoapods-reviewed-podspec.json",
                "cocoapods-release-evidence.json",
                "cocoapods-release-evidence.SHA256SUMS",
            },
            "android": {
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
            },
        }
        expected: dict[str, set[str]] = {}
        verifier = PUBLIC_PROOF_FIXTURE_MODULE.MODULE
        for repository_id, names in release_names.items():
            observer_names = MODULE.expected_source_attested_release_assets(
                repository_id, version, names
            )
            verifier_names = verifier.expected_source_attested_release_assets(
                repository_id, version, names
            )
            self.assertEqual(observer_names, verifier_names)
            expected[repository_id] = observer_names

        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/release-domain-observations.yml"
        ).read_text(encoding="utf-8")
        start = workflow.index("            requires_subject_attestation() {")
        end = workflow.index("            for id in javascript", start)
        function = textwrap.dedent(workflow[start:end])
        candidates = [
            f"{repository_id}:{name}"
            for repository_id, names in release_names.items()
            for name in sorted(names)
        ]
        command = subprocess.run(
            [
                "bash",
                "-c",
                (
                    "set -Eeuo pipefail\n"
                    + function
                    + '\nfor value in "$@"; do\n'
                    + '  id=${value%%:*}; name=${value#*:}\n'
                    + '  if requires_subject_attestation "$id" "$name"; then printf "%s\\n" "$value"; fi\n'
                    + "done\n"
                ),
                "collector-attestations",
                *candidates,
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        captured = set(command.stdout.splitlines())
        self.assertEqual(
            captured,
            {
                f"{repository_id}:{name}"
                for repository_id, names in expected.items()
                for name in names
            },
        )
        self.assertIn("ios:docs-bundle-1.0.0.tar.gz", captured)
        self.assertIn("react_native:docs-bundle-1.0.0.tar.gz", captured)

    def test_github_authority_cap_matches_exact_worst_case_arithmetic(self) -> None:
        # Per repository: release metadata + asset bytes + immutable verification
        # + source attestation verification + distinct provenance/adoption runs.
        javascript = 1 + 64 + 64 + 64 + (4 + (64 - 31))
        react_native = 1 + 64 + 64 + 63 + (1 + (64 - 12))
        ios = 1 + 7 + 7 + 6
        android = 1 + 10 + 10 + 10
        documentation = 7
        public_oci = 7
        self.assertEqual(
            (javascript, react_native, ios, android, documentation, public_oci),
            (230, 245, 21, 31, 7, 7),
        )
        self.assertEqual(
            MODULE.MAXIMUM_AUTHORITY_FILES,
            javascript
            + react_native
            + ios
            + android
            + documentation
            + public_oci,
        )

    def test_supply_chain_validators_reject_digest_scan_sbom_and_signature_tampering(self) -> None:
        platforms = {
            "linux/amd64": "sha256:" + "2" * 64,
            "linux/arm64": "sha256:" + "3" * 64,
        }
        index = {
            "manifests": [
                {
                    "digest": digest,
                    "platform": {
                        "os": "linux",
                        "architecture": name.split("/", 1)[1],
                    },
                }
                for name, digest in platforms.items()
            ]
        }
        payload = json.dumps(index, separators=(",", ":")).encode()
        MODULE.Observer._validate_index(
            payload, "sha256:" + hashlib.sha256(payload).hexdigest(), platforms
        )
        extra = copy.deepcopy(index)
        extra["manifests"].append(
            {
                "digest": "sha256:" + "7" * 64,
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": next(iter(platforms.values())),
                },
            }
        )
        extra_payload = json.dumps(extra, separators=(",", ":")).encode()
        with self.assertRaisesRegex(MODULE.ObservationError, "oci_platforms_mismatch"):
            MODULE.Observer._validate_index(
                extra_payload,
                "sha256:" + hashlib.sha256(extra_payload).hexdigest(),
                platforms,
            )
        index["manifests"][0]["digest"] = "sha256:" + "9" * 64
        tampered = json.dumps(index, separators=(",", ":")).encode()
        with self.assertRaisesRegex(MODULE.ObservationError, "oci_platforms_mismatch"):
            MODULE.Observer._validate_index(
                tampered,
                "sha256:" + hashlib.sha256(tampered).hexdigest(),
                platforms,
            )

        MODULE.Observer._validate_trivy(b'{"Results":[]}', "Vulnerabilities")
        with self.assertRaisesRegex(MODULE.ObservationError, "trivy_policy_failed"):
            MODULE.Observer._validate_trivy(
                b'{"Results":[{"Vulnerabilities":[{"Severity":"CRITICAL"}]}]}',
                "Vulnerabilities",
            )
        MODULE.Observer._validate_spdx(
            b'{"spdxVersion":"SPDX-2.3","packages":[{"name":"latchway"}]}'
        )
        with self.assertRaisesRegex(MODULE.ObservationError, "spdx_invalid"):
            MODULE.Observer._validate_spdx(
                b'{"spdxVersion":"SPDX-2.3","packages":[]}'
            )

        expected_spdx = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "latchway"}],
        }

        def github_spdx(predicate: dict, digest: str = "2" * 64) -> dict:
            return {
                "verificationResult": {
                    "statement": {
                        "predicateType": "https://spdx.dev/Document/v2.3",
                        "subject": [{"digest": {"sha256": digest}}],
                        "predicate": predicate,
                    }
                }
            }

        historical_and_current = MODULE.canonical_json(
            [
                github_spdx({"spdxVersion": "SPDX-2.3", "packages": [{"name": "old"}]}),
                github_spdx(expected_spdx),
            ]
        )
        MODULE.Observer._validate_github_attestation(
            historical_and_current,
            predicate_type="https://spdx.dev/Document/v2.3",
            digest=platforms["linux/amd64"],
            code="github_spdx_attestation_invalid",
            expected_predicate=expected_spdx,
        )
        with self.assertRaisesRegex(
            MODULE.ObservationError, "github_spdx_attestation_invalid"
        ):
            MODULE.Observer._validate_github_attestation(
                MODULE.canonical_json([github_spdx({"packages": [{"name": "old"}]})]),
                predicate_type="https://spdx.dev/Document/v2.3",
                digest=platforms["linux/amd64"],
                code="github_spdx_attestation_invalid",
                expected_predicate=expected_spdx,
            )
        with self.assertRaisesRegex(
            MODULE.ObservationError, "github_spdx_attestation_invalid"
        ):
            MODULE.Observer._validate_github_attestation(
                MODULE.canonical_json([github_spdx(expected_spdx, "9" * 64)]),
                predicate_type="https://spdx.dev/Document/v2.3",
                digest=platforms["linux/amd64"],
                code="github_spdx_attestation_invalid",
                expected_predicate=expected_spdx,
            )

        public_reference = "ghcr.io/latchway/latchway@" + platforms["linux/amd64"]
        public_child = [
            {
                "Id": "sha256:" + "4" * 64,
                "Os": "linux",
                "Architecture": "amd64",
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.source": "https://github.com/Latchway/latchway",
                        "org.opencontainers.image.revision": "a" * 40,
                        "org.opencontainers.image.version": "1.0.0",
                    }
                },
                "RepoDigests": [public_reference],
                "RootFS": {"Layers": ["sha256:" + "5" * 64]},
            }
        ]
        MODULE.Observer._validate_public_child_inspection(
            MODULE.canonical_json(public_child),
            architecture="amd64",
            reference=public_reference,
            commit="a" * 40,
            version="1.0.0",
        )
        for mutation in ("Architecture", "RepoDigests", "RootFS"):
            changed = copy.deepcopy(public_child)
            if mutation == "Architecture":
                changed[0][mutation] = "arm64"
            elif mutation == "RepoDigests":
                changed[0][mutation] = []
            else:
                changed[0][mutation] = {"Layers": []}
            with self.subTest(public_child_mutation=mutation), self.assertRaisesRegex(
                MODULE.ObservationError, "registry_oci_child_invalid"
            ):
                MODULE.Observer._validate_public_child_inspection(
                    MODULE.canonical_json(changed),
                    architecture="amd64",
                    reference=public_reference,
                    commit="a" * 40,
                    version="1.0.0",
                )

        image = "ghcr.io/latchway/latchway@sha256:" + "a" * 64
        cosign = [
            {
                "critical": {
                    "identity": {"docker-reference": "ghcr.io/latchway/latchway"},
                    "image": {"docker-manifest-digest": "sha256:" + "a" * 64},
                }
            }
        ]
        MODULE.Observer._validate_cosign(json.dumps(cosign).encode(), image, "invalid")
        cosign[0]["critical"]["image"]["docker-manifest-digest"] = (
            "sha256:" + "b" * 64
        )
        with self.assertRaisesRegex(MODULE.ObservationError, "invalid"):
            MODULE.Observer._validate_cosign(
                json.dumps(cosign).encode(), image, "invalid"
            )
        with self.assertRaisesRegex(MODULE.ObservationError, "provenance_invalid"):
            MODULE.Observer._require_nonempty_list(b"[]", "provenance_invalid")

    def test_public_tag_validators_reject_target_and_release_tampering(self) -> None:
        tag = "v1.0.0"
        commit = "a" * 40
        reference = {
            "ref": f"refs/tags/{tag}",
            "object": {"type": "tag", "sha": "b" * 40},
        }
        MODULE.Observer._validate_tag_ref(json.dumps(reference).encode(), tag)
        tag_object = {
            "tag": tag,
            "object": {"type": "commit", "sha": commit},
        }
        MODULE.Observer._validate_tag_object(
            json.dumps(tag_object).encode(), tag, commit
        )
        tag_object["object"]["sha"] = "f" * 40
        with self.assertRaisesRegex(
            MODULE.ObservationError, "public_tag_target_mismatch"
        ):
            MODULE.Observer._validate_tag_object(
                json.dumps(tag_object).encode(), tag, commit
            )
        release = {
            "id": 42,
            "tag_name": tag,
            "draft": False,
            "prerelease": False,
            "immutable": True,
        }
        MODULE.Observer._validate_release(json.dumps(release).encode(), tag)
        exact = {
            **release,
            "name": "Latchway v1.0.0",
            "body": "pinned body",
        }
        MODULE.Observer._validate_release(
            json.dumps(exact).encode(), tag,
            expected_name="Latchway v1.0.0", expected_body="pinned body",
        )
        exact["body"] = "attacker-controlled notes"
        with self.assertRaisesRegex(MODULE.ObservationError, "github_release_invalid"):
            MODULE.Observer._validate_release(
                json.dumps(exact).encode(), tag,
                expected_name="Latchway v1.0.0", expected_body="pinned body",
            )
        release["prerelease"] = True
        with self.assertRaisesRegex(MODULE.ObservationError, "github_release_invalid"):
            MODULE.Observer._validate_release(json.dumps(release).encode(), tag)
        release["prerelease"] = False
        release["immutable"] = False
        with self.assertRaisesRegex(MODULE.ObservationError, "github_release_invalid"):
            MODULE.Observer._validate_release(json.dumps(release).encode(), tag)

    def test_release_attestation_is_consumed_only_from_offline_authority(self) -> None:
        observer = self.bare_observer("public_tags")
        retained = b'{"verified":true}\n'
        authority = self.github_authority_fixture(
            observer,
            "public-tag-attestation",
            {"public-tags/core/release-attestation.json": retained},
        )
        observer.github_authority = authority
        observer._validate_github_authority_directory()
        release = {
            "id": 42,
            "tag_name": "v1.0.0",
            "draft": False,
            "immutable": True,
            "assets": [],
        }
        with mock.patch.object(
            MODULE.RELEASE_ATTESTATION,
            "validate_bytes",
            return_value={"status": "passed"},
        ) as validate:
            payload, started, finished = observer._release_attestation_from_authority(
                "core",
                "Latchway/latchway", "v1.0.0", "f" * 40, release
            )
        self.assertEqual(payload, MODULE.canonical_json({"status": "passed"}))
        self.assertEqual(started, self.workflow_started)
        self.assertEqual(finished, self.workflow_started.replace(minute=56))
        validate.assert_called_once_with(
            retained,
            repository="Latchway/latchway",
            tag="v1.0.0",
            ref_sha="f" * 40,
            release=release,
        )
        observer._validate_github_authority_consumed()

        rejected_authority = self.github_authority_fixture(
            observer,
            "public-tag-attestation-rejected",
            {"public-tags/core/release-attestation.json": b"{}\n"},
        )
        observer.github_authority = rejected_authority
        observer._validate_github_authority_directory()
        with mock.patch.object(
            MODULE.RELEASE_ATTESTATION,
            "validate_bytes",
            side_effect=MODULE.RELEASE_ATTESTATION.AttestationError(
                "release_attestation_invalid"
            ),
        ), self.assertRaisesRegex(
            MODULE.ObservationError, "github_release_attestation_invalid"
        ):
            observer._release_attestation_from_authority(
                "core",
                "Latchway/latchway", "v1.0.0", "f" * 40, release
            )

    def test_public_registry_validators_reject_coordinate_tampering(self) -> None:
        coordinate = {"version": "1.0.0", "commit": "a" * 40}
        npm = {
            "name": "@latchway/client",
            "version": "1.0.0",
            "dist": {
                "integrity": "sha512-"
                + base64.b64encode(b"published-archive".ljust(64, b"x")).decode()
            },
        }
        MODULE.Observer._validate_npm(
            json.dumps(npm).encode(), "@latchway/client", coordinate
        )
        npm["version"] = "1.0.1"
        with self.assertRaisesRegex(MODULE.ObservationError, "registry_npm_invalid"):
            MODULE.Observer._validate_npm(
                json.dumps(npm).encode(), "@latchway/client", coordinate
            )
        swift = {
            "pins": [
                {
                    "identity": "latchway-ios-sdk",
                    "kind": "remoteSourceControl",
                    "location": "https://github.com/Latchway/latchway-ios-sdk.git",
                    "state": {
                        "version": coordinate["version"],
                        "revision": coordinate["commit"],
                    },
                }
            ]
        }
        MODULE.Observer._validate_swift_resolution(
            json.dumps(swift).encode(), coordinate
        )
        swift["pins"][0]["state"]["revision"] = "c" * 40
        with self.assertRaisesRegex(
            MODULE.ObservationError, "swift_registry_resolution_invalid"
        ):
            MODULE.Observer._validate_swift_resolution(
                json.dumps(swift).encode(), coordinate
            )

    def test_javascript_aggregate_rejects_retry_variant_and_reordered_reproducibility(self) -> None:
        fixture = PUBLIC_PROOF_FIXTURE_MODULE.PublicRegistryProofTests(
            methodName="runTest"
        )
        proof, coordinate, _ = fixture.javascript_npm_set_proof()
        release_assets: dict[str, dict[str, bytes]] = {
            "SHA256SUMS": {"bytes": b"checksums"}
        }
        for name, envelope in proof["retained_aggregate_evidence"].items():
            release_assets[name] = {
                "bytes": base64.b64decode(envelope["content_base64"], validate=True)
            }
        for package_proof in proof["packages"]:
            for name, envelope in package_proof["registry_evidence"].items():
                release_assets[name] = {
                    "bytes": base64.b64decode(
                        envelope["content_base64"], validate=True
                    )
                }
        observer = self.bare_observer()
        observer._validate_javascript_npm_aggregate(coordinate, release_assets)

        for mutation in (
            "retry-variant",
            "reordered-reproducibility",
            "failed-vulnerability-scan",
            "unannotated-tag",
            "changed-checksums",
        ):
            changed = copy.deepcopy(release_assets)
            if mutation == "retry-variant":
                document = json.loads(
                    changed["post-publish-evidence.json"]["bytes"]
                )
                document["packages"][0]["publication_mode"] = "adopted_existing"
                changed["post-publish-evidence.json"]["bytes"] = (
                    json.dumps(document, indent=2, sort_keys=True) + "\n"
                ).encode()
            elif mutation == "reordered-reproducibility":
                document = json.loads(
                    changed["build-reproducibility.json"]["bytes"]
                )
                document["files"][0], document["files"][1] = (
                    document["files"][1],
                    document["files"][0],
                )
                changed["build-reproducibility.json"]["bytes"] = (
                    json.dumps(document, indent=2, sort_keys=True) + "\n"
                ).encode()
            elif mutation == "failed-vulnerability-scan":
                document = json.loads(
                    changed["dependency-vulnerability-scan.json"]["bytes"]
                )
                document["status"] = "failed"
                changed["dependency-vulnerability-scan.json"]["bytes"] = (
                    json.dumps(document, indent=2, sort_keys=True) + "\n"
                ).encode()
            elif mutation == "unannotated-tag":
                document = json.loads(changed["tag-evidence.json"]["bytes"])
                document["annotated"] = False
                changed["tag-evidence.json"]["bytes"] = (
                    json.dumps(document, indent=2, sort_keys=True) + "\n"
                ).encode()
            else:
                changed["SHA256SUMS"]["bytes"] = b"0" * 64 + b"  wrong.tgz\n"
            with self.subTest(mutation=mutation), self.assertRaises(
                MODULE.ObservationError
            ):
                observer._validate_javascript_npm_aggregate(
                    coordinate, changed
                )

    def test_javascript_reproducibility_hash_is_recomputed_from_archive_bytes(self) -> None:
        release_assets: dict[str, dict[str, bytes]] = {}
        javascript_root = self.root / "javascript-reproducibility-source"
        javascript_root.mkdir()
        contract_lock = b"contract_version: 1.0.0\n"
        (javascript_root / "contract.lock").write_bytes(contract_lock)
        files = []
        package_items = []
        aggregate = hashlib.sha256()
        for index, (package_id, package) in enumerate(
            MODULE.JAVASCRIPT_NPM_PACKAGES, 1
        ):
            payload = f"export const package{index} = true;\n".encode()
            repository_path = (
                "dist/index.js"
                if package_id == "client"
                else f"packages/{package_id}/dist/index.js"
            )
            aggregate.update(repository_path.encode())
            aggregate.update(b"\0")
            aggregate.update(payload)
            aggregate.update(b"\0")
            files.append(
                {
                    "package": package,
                    "path": repository_path,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            package_root = (
                javascript_root
                if package_id == "client"
                else javascript_root / "packages" / package_id
            )
            package_root.mkdir(parents=True, exist_ok=True)
            source_peers = (
                {} if package_id == "client" else {"@latchway/client": "workspace:^"}
            )
            published_peers = (
                {} if package_id == "client" else {"@latchway/client": "^1.0.0"}
            )
            (package_root / "package.json").write_text(
                json.dumps(
                    {
                        "name": package,
                        "version": "1.0.0",
                        "peerDependencies": source_peers,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            packaged_manifest = (
                json.dumps(
                    {
                        "name": package,
                        "version": "1.0.0",
                        "peerDependencies": published_peers,
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            archive_files = {
                "package/dist/index.js": payload,
                "package/package.json": packaged_manifest,
            }
            if package_id == "client":
                archive_files["package/contract.lock"] = contract_lock
            archive_bytes = io.BytesIO()
            with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
                for name, archive_payload in sorted(archive_files.items()):
                    member = tarfile.TarInfo(name)
                    member.size = len(archive_payload)
                    archive.addfile(member, io.BytesIO(archive_payload))
            release_assets[f"latchway-{package_id}-1.0.0.tgz"] = {
                "bytes": archive_bytes.getvalue()
            }
            package_items.append(
                {
                    "id": package_id,
                    "package": package,
                    "entries": sorted(archive_files),
                    "unpacked_bytes": sum(len(item) for item in archive_files.values()),
                    "published_peer_dependencies": published_peers,
                }
            )
        reproducibility = {
            "schema_version": 1,
            "identical": True,
            "package_count": 4,
            "sha256": aggregate.hexdigest(),
            "files": files,
        }
        verification = MODULE.verify_javascript_reproducibility_archive_inputs(
            reproducibility,
            release_assets,
            "1.0.0",
            {"packages": package_items},
            javascript_root,
        )
        self.assertEqual(verification["sha256"], aggregate.hexdigest())
        self.assertEqual(verification["file_count"], 4)
        self.assertEqual(
            verification["bytes"], sum(item["bytes"] for item in files)
        )

        arbitrary_hash = copy.deepcopy(reproducibility)
        arbitrary_hash["sha256"] = "f" * 64
        with self.assertRaisesRegex(
            MODULE.ObservationError, "registry_npm_reproducibility_invalid"
        ):
            MODULE.verify_javascript_reproducibility_archive_inputs(
                arbitrary_hash,
                release_assets,
                "1.0.0",
                {"packages": package_items},
                javascript_root,
            )

        changed_manifest = json.loads(
            (javascript_root / "packages" / "openai" / "package.json").read_text()
        )
        changed_manifest["peerDependencies"]["@latchway/client"] = "workspace:~"
        (javascript_root / "packages" / "openai" / "package.json").write_text(
            json.dumps(changed_manifest) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            MODULE.ObservationError, "registry_npm_reproducibility_invalid"
        ):
            MODULE.verify_javascript_reproducibility_archive_inputs(
                reproducibility,
                release_assets,
                "1.0.0",
                {"packages": package_items},
                javascript_root,
            )

        digest = MODULE.javascript_npm_tarball_digest(
            release_assets["latchway-client-1.0.0.tgz"]["bytes"]
        )
        self.assertEqual(
            digest["sha1"],
            hashlib.sha1(
                release_assets["latchway-client-1.0.0.tgz"]["bytes"]
            ).hexdigest(),
        )

    def test_javascript_contract_evidence_is_bound_to_locked_source_files(self) -> None:
        observer = self.bare_observer("public_registries")
        javascript = self.root / "javascript-contract-source"
        fixtures = javascript / "test" / "fixtures" / "contract"
        fixtures.mkdir(parents=True)
        fixture_payload = b'{"wire":2}\n'
        (fixtures / "protocol-version.json").write_bytes(fixture_payload)
        lock_payload = (
            "contract_version: 0.5.1\n"
            "wire_protocol: 2\n"
            "core_release: v1.0.0\n"
            f"core_commit: {'c' * 40}\n"
            f'bundle_sha256: "{'b' * 64}"\n'
            "minimum_server_version: 1.0.0\n"
            "maximum_tested_server_version: 1.0.x\n"
        ).encode()
        (javascript / "contract.lock").write_bytes(lock_payload)
        observer.repositories["javascript"] = javascript
        coordinate = observer.identity["repositories"]["javascript"]
        evidence = {
            "schema_version": 1,
            "contract_version": "0.5.1",
            "core_release": "v1.0.0",
            "core_commit": "c" * 40,
            "bundle_sha256": "b" * 64,
            "wire_protocol_version": 2,
            "contract_lock_sha256": hashlib.sha256(lock_payload).hexdigest(),
            "fixtures": [
                {
                    "name": "protocol-version.json",
                    "sha256": hashlib.sha256(fixture_payload).hexdigest(),
                }
            ],
        }
        verification = observer._verify_javascript_contract_source(
            evidence, coordinate
        )
        self.assertEqual(verification["fixture_count"], 1)
        for mutation in ("evidence", "fixture"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(evidence)
                if mutation == "evidence":
                    changed["bundle_sha256"] = "0" * 64
                else:
                    (fixtures / "protocol-version.json").write_bytes(b"changed\n")
                with self.assertRaisesRegex(
                    MODULE.ObservationError, "registry_npm_contract_source_invalid"
                ):
                    observer._verify_javascript_contract_source(
                        changed, coordinate
                    )
                (fixtures / "protocol-version.json").write_bytes(fixture_payload)

    def test_javascript_adoption_mode_is_exactly_bound_to_origin_attempt(self) -> None:
        valid = MODULE.valid_npm_adoption_mode
        self.assertTrue(valid("published", 101, 1, 101, 1))
        self.assertTrue(valid("adopted_existing", 201, 2, 101, 1))
        for mode, run_id, run_attempt, origin_id, origin_attempt in (
            ("published", 201, 2, 101, 1),
            ("adopted_existing", 101, 1, 101, 1),
            ("unexpected", 201, 2, 101, 1),
            ({"published": True}, 101, 1, 101, 1),
        ):
            with self.subTest(mode=mode):
                self.assertFalse(
                    valid(mode, run_id, run_attempt, origin_id, origin_attempt)
                )

    def test_documentation_observer_retains_exact_raw_authority_closure(self) -> None:
        mintlify_fixture_path = Path(__file__).with_name(
            "test_mintlify_production_proof.py"
        )
        mintlify_spec = importlib.util.spec_from_file_location(
            "mintlify_fixture_for_observer", mintlify_fixture_path
        )
        assert mintlify_spec is not None and mintlify_spec.loader is not None
        mintlify_module = importlib.util.module_from_spec(mintlify_spec)
        mintlify_spec.loader.exec_module(mintlify_module)
        fixture = mintlify_module.MintlifyProductionProofTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        inputs = fixture.inputs()
        payloads = {
            MODULE.MINTLIFY_PROOF.EVIDENCE_FILE: inputs["evidence_payload"],
            MODULE.MINTLIFY_PROOF.CHECKSUM_FILE: inputs["checksum_payload"],
            MODULE.MINTLIFY_PROOF.ATTESTATION_FILE: inputs[
                "attestation_bundle_payload"
            ],
            "run.json": inputs["run_payload"],
            "workflow.json": inputs["workflow_payload"],
            "artifact.json": inputs["artifact_payload"],
            "attestation-verification.json": inputs[
                "attestation_verification_payload"
            ],
        }
        observer = self.bare_observer("public_registries")
        observer.documentation = fixture.documentation
        observer.now = fixture.now

        def authority(relative: str, *, maximum: int):
            name = Path(relative).name
            payload = payloads[name]
            self.assertLessEqual(len(payload), maximum)
            return payload, fixture.now, fixture.now

        with (
            mock.patch.object(
                observer, "_github_authority_file", side_effect=authority
            ),
            mock.patch.object(observer, "emit") as emit,
        ):
            observer._observe_documentation_production()
        emit.assert_called_once()
        call = emit.call_args
        self.assertEqual(call.args[0], "registry.documentation-production")
        self.assertEqual(call.kwargs["retained_inputs"], payloads)
        self.assertEqual(
            call.kwargs["retained_input_kind"],
            "mintlify_production_evidence",
        )
        proof = json.loads(call.args[1])
        self.assertEqual(
            proof["kind"], "latchway_mintlify_production_release_proof"
        )

    def test_cocoapods_spec_requires_every_reviewed_subspec_and_no_hooks(self) -> None:
        coordinate = {
            "version": "1.0.0",
            "tag": "v1.0.0",
            "commit": "a" * 40,
        }
        spec = {
            "name": "Latchway",
            "version": "1.0.0",
            "source": {
                "git": "https://github.com/Latchway/latchway-ios-sdk.git",
                "tag": "v1.0.0",
            },
            "subspecs": [
                {"name": name, "source_files": f"Sources/{name}/**/*.swift"}
                for name in ("Core", "AppAttest", "AppExtensions", "FirebaseAuth")
            ],
        }
        self.assertEqual(
            MODULE.Observer._validate_cocoapods_spec(
                json.dumps(spec).encode(), coordinate
            ),
            spec,
        )
        mutations = []
        missing_extensions = copy.deepcopy(spec)
        missing_extensions["subspecs"] = [
            item
            for item in missing_extensions["subspecs"]
            if item["name"] != "AppExtensions"
        ]
        mutations.append(missing_extensions)
        duplicate_core = copy.deepcopy(spec)
        duplicate_core["subspecs"].append({"name": "Core"})
        mutations.append(duplicate_core)
        injected_hook = copy.deepcopy(spec)
        injected_hook["subspecs"][0]["script_phase"] = {"script": "unreviewed"}
        mutations.append(injected_hook)
        wrong_source = copy.deepcopy(spec)
        wrong_source["source"]["tag"] = "v1.0.1"
        mutations.append(wrong_source)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                MODULE.ObservationError, "registry_cocoapods_spec_invalid"
            ):
                MODULE.Observer._validate_cocoapods_spec(
                    json.dumps(mutation).encode(), coordinate
                )

        archive_sha256 = "b" * 64
        proof = {
            "schema_version": 1,
            "kind": "latchway_cocoapods_release_evidence",
            "status": "passed",
            "registry": "cocoapods",
            "package": "Latchway",
            "version": "1.0.0",
            "published_spec_sha256": "c" * 64,
            "reviewed_source_archive_sha256": archive_sha256,
            "published_spec_equals_reviewed_podspec": True,
            "reviewed_source_archive_equals_release_tag": True,
            "reviewed_spec_sha256": "d" * 64,
            "source_commit": "a" * 40,
            "source_tag": "v1.0.0",
            "registry_url": "https://cdn.cocoapods.org/Specs/0/0/0/Latchway/1.0.0/Latchway.podspec.json",
            "source": spec["source"],
        }
        MODULE.Observer._validate_cocoapods_proof(
            json.dumps(proof).encode(),
            coordinate,
            {"digest": f"sha256:{archive_sha256}"},
        )
        for field, replacement in (
            ("source_commit", "e" * 40),
            ("status", "registry_only"),
            ("reviewed_spec_sha256", "not-a-hash"),
        ):
            tampered = copy.deepcopy(proof)
            tampered[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                MODULE.ObservationError, "registry_cocoapods_proof_invalid"
            ):
                MODULE.Observer._validate_cocoapods_proof(
                    json.dumps(tampered).encode(),
                    coordinate,
                    {"digest": f"sha256:{archive_sha256}"},
                )

    def test_npm_provenance_origin_may_fail_but_adoption_must_succeed(self) -> None:
        observer = self.bare_observer("public_registries")
        run = {
            "id": 41,
            "run_attempt": 1,
            "event": "repository_dispatch",
            "status": "completed",
            "conclusion": "failure",
            "head_sha": "a" * 40,
            "head_branch": "main",
            "path": ".github/workflows/release.yml",
            "repository": {"full_name": "Latchway/latchway-js"},
        }
        observer._validate_npm_workflow_run(
            run,
            "Latchway/latchway-js",
            "a" * 40,
            41,
            1,
            conclusions={"success", "failure", "cancelled", "timed_out"},
        )
        with self.assertRaisesRegex(
            MODULE.ObservationError, "registry_npm_provenance_run_invalid"
        ):
            observer._validate_npm_workflow_run(
                run,
                "Latchway/latchway-js",
                "a" * 40,
                41,
                1,
                conclusions={"success"},
            )
        run["conclusion"] = "success"
        observer._validate_npm_workflow_run(
            run,
            "Latchway/latchway-js",
            "a" * 40,
            41,
            1,
            conclusions={"success"},
        )

    def test_single_maintainer_npm_run_requires_selected_workflow_and_event(
        self,
    ) -> None:
        observer = self.bare_observer("public_registries")
        observer.release_profile = MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        run = {
            "id": 41,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
            "head_branch": "main",
            "path": ".github/workflows/single-maintainer-release.yml",
            "repository": {"full_name": "Latchway/latchway-js"},
        }
        observer._validate_npm_workflow_run(
            run,
            "Latchway/latchway-js",
            "a" * 40,
            41,
            1,
            conclusions={"success"},
        )
        with mock.patch.object(
            observer,
            "_github_authority_json",
            return_value=(run, self.workflow_started, self.workflow_finished),
        ) as authority:
            self.assertEqual(
                observer._github_owner_run_from_authority("javascript", 41),
                run,
            )
        authority.assert_called_once_with(
            "public-registries/javascript/runs/owner-41.json",
            "registry_npm_adoption_invalid",
        )
        for field, value in (
            ("event", "repository_dispatch"),
            ("path", ".github/workflows/release.yml"),
        ):
            tampered = copy.deepcopy(run)
            tampered[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                MODULE.ObservationError,
                "registry_npm_provenance_run_invalid",
            ):
                observer._validate_npm_workflow_run(
                    tampered,
                    "Latchway/latchway-js",
                    "a" * 40,
                    41,
                    1,
                    conclusions={"success"},
                )

    def test_exact_sdk_release_asset_sets_reject_unknown_missing_and_no_adoption(self) -> None:
        expected, adoption_required = MODULE.Observer._expected_release_assets(
            "javascript", "1.0.0"
        )
        self.assertEqual(len(expected), 31)
        self.assertEqual(
            adoption_required, frozenset({"client", "openai", "vercel-ai", "langchain"})
        )
        for package_id in adoption_required:
            self.assertTrue(
                {
                    f"latchway-{package_id}-1.0.0.tgz",
                    f"npm-{package_id}-registry-version.json",
                    f"npm-{package_id}-registry-view.json",
                    f"npm-{package_id}-attestations.json",
                    f"npm-{package_id}-audit-signatures.json",
                }.issubset(expected)
            )
        names = sorted(expected) + [
            f"npm-release-adoption-{package_id}-7-2.json"
            for package_id in sorted(adoption_required)
        ]
        release = {
            "id": 42,
            "tag_name": "v1.0.0",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": [
                {"id": index + 1, "name": name, "size": 1, "digest": "sha256:" + f"{index + 1:064x}"}
                for index, name in enumerate(names)
            ],
        }
        MODULE.Observer._validate_release(
            json.dumps(release).encode(), "v1.0.0",
            expected_assets=expected, adoption_required=adoption_required,
        )
        for mutation in (
            "unknown", "missing", "missing-docs", "no-adoption", "missing-adoption-id"
        ):
            changed = copy.deepcopy(release)
            if mutation == "unknown":
                changed["assets"].append({"id": 99, "name": "evil.json", "size": 1, "digest": "sha256:" + "f" * 64})
            elif mutation == "missing":
                changed["assets"] = [item for item in changed["assets"] if item["name"] != "package-evidence.json"]
            elif mutation == "missing-docs":
                changed["assets"] = [
                    item for item in changed["assets"]
                    if item["name"] != "docs-bundle-1.0.0.tar.gz"
                ]
            elif mutation == "no-adoption":
                changed["assets"] = [item for item in changed["assets"] if not item["name"].startswith("npm-release-adoption-")]
            else:
                changed["assets"] = [
                    item
                    for item in changed["assets"]
                    if not item["name"].startswith("npm-release-adoption-openai-")
                ]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                MODULE.ObservationError, "github_release_asset_set_invalid"
            ):
                MODULE.Observer._validate_release(
                    json.dumps(changed).encode(), "v1.0.0",
                    expected_assets=expected, adoption_required=adoption_required,
                )

    def test_single_maintainer_release_asset_closures_are_exact(self) -> None:
        expected_counts = {
            "core": 15,
            "javascript": 32,
            "ios": 10,
            "android": 14,
            "react_native": 12,
        }
        for repository_id, count in expected_counts.items():
            expected, adoption_required = MODULE.Observer._expected_release_assets(
                repository_id,
                "1.0.0",
                MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE,
            )
            with self.subTest(repository_id=repository_id):
                self.assertEqual(len(expected), count)
                self.assertEqual(
                    MODULE.expected_source_attested_release_assets(
                        repository_id,
                        "1.0.0",
                        sorted(expected),
                        MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE,
                    ),
                    expected,
                )
                if repository_id in {"core", "javascript", "ios", "android"}:
                    self.assertIn("SHA256SUMS", expected)
                self.assertEqual(
                    adoption_required,
                    frozenset({""})
                    if repository_id == "react_native"
                    else frozenset(),
                )
        javascript, _ = MODULE.Observer._expected_release_assets(
            "javascript", "1.0.0", MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        )
        self.assertIn("single-maintainer-npm-adoption.json", javascript)
        self.assertNotIn("publish-input-evidence.json", javascript)
        ios, _ = MODULE.Observer._expected_release_assets(
            "ios", "1.0.0", MODULE.EVIDENCE.SINGLE_MAINTAINER_PROFILE
        )
        self.assertIn("ios-registry-candidate.json", ios)
        self.assertNotIn("cocoapods-release-evidence.SHA256SUMS", ios)

    def test_every_sdk_release_requires_the_versioned_documentation_bundle(self) -> None:
        for repository_id in ("javascript", "ios", "android", "react_native"):
            expected, adoption_required = MODULE.Observer._expected_release_assets(
                repository_id, "1.0.0"
            )
            self.assertIn("docs-bundle-1.0.0.tar.gz", expected)
            names = sorted(expected)
            for package_id in sorted(adoption_required):
                middle = f"-{package_id}" if package_id else ""
                names.append(f"npm-release-adoption{middle}-8-1.json")
            release = {
                "id": 81,
                "tag_name": "v1.0.0",
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [
                    {
                        "id": index + 1,
                        "name": name,
                        "size": 1,
                        "digest": "sha256:" + f"{index + 1:064x}",
                    }
                    for index, name in enumerate(names)
                    if name != "docs-bundle-1.0.0.tar.gz"
                ],
            }
            with self.subTest(repository_id=repository_id), self.assertRaisesRegex(
                MODULE.ObservationError, "github_release_asset_set_invalid"
            ):
                MODULE.Observer._validate_release(
                    json.dumps(release).encode(),
                    "v1.0.0",
                    expected_assets=expected,
                    adoption_required=adoption_required,
                )

    def test_android_release_schema_tracks_canonical_portal_assets_and_intent(self) -> None:
        version = "1.0.0"
        coordinate = {
            "version": version,
            "tag": "v1.0.0",
            "commit": "d" * 40,
        }
        expected, adoption_required = MODULE.Observer._expected_release_assets(
            "android", version
        )
        self.assertFalse(adoption_required)
        self.assertEqual(
            expected,
            {
                "latchway-android-1.0.0-maven-repository.zip",
                "latchway-android-1.0.0-central-portal.zip",
                "docs-bundle-1.0.0.tar.gz",
                "SHA256SUMS",
                "github-release-tag-binding.json",
                "latchway-maven-signing-public-key.asc",
                "maven-central-upload-intent.json",
                "maven-central-deployment.json",
                "maven-central-deployment-status.json",
                "maven-central-release-evidence.json",
            },
        )
        repository_archive = b"reviewed repository"
        portal_archive = b"signed portal bundle"
        public_key = b"public key"
        portal_sha = hashlib.sha256(portal_archive).hexdigest()
        deployment_name = (
            f"latchway-android-v{version}-{coordinate['commit'][:12]}-{portal_sha}"
        )
        purls = sorted(
            f"pkg:maven/dev.latchway/{module}@{version}"
            for module in (
                "latchway-core",
                "latchway-okhttp",
                "latchway-play-integrity",
                "latchway-firebase-auth",
                "latchway-bom",
            )
        )
        intent = {
            "schema": "latchway.maven-central-upload-intent.v2",
            "repository": "Latchway/latchway-android",
            "source_commit": coordinate["commit"],
            "release_tag": coordinate["tag"],
            "version": version,
            "namespace": "dev.latchway",
            "deployment_name": deployment_name,
            "publishing_type": "user_managed",
            "authorization": "recoverable_exact_upload",
            "reviewed_repository_archive_sha256": hashlib.sha256(
                repository_archive
            ).hexdigest(),
            "reviewed_portal_bundle_sha256": hashlib.sha256(
                portal_archive
            ).hexdigest(),
            "reviewed_repository_manifest_sha256": "a" * 64,
            "reviewed_repository_file_count": 120,
            "reviewed_portal_bundle_file_count": 144,
            "reviewed_public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "expected_purls": purls,
        }

        def encoded(value: object) -> bytes:
            return (json.dumps(value, sort_keys=True) + "\n").encode()

        intent_bytes = encoded(intent)
        deployment = {
            "schema": "latchway.maven-central-deployment.v2",
            "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
            "deployment_name": deployment_name,
            "publishing_type": "user_managed",
            "namespace": "dev.latchway",
            "source_commit": coordinate["commit"],
            "version": version,
            "expected_purls": purls,
            "reviewed_portal_bundle_sha256": portal_sha,
            "record_kind": "portal_deployment",
            "deployment_id": "38570f16-da32-4c14-bd2e-c1acc0782365",
            "public_manifest_sha256": None,
        }
        deployment_bytes = encoded(deployment)
        status = {
            "schema": "latchway.maven-central-deployment-status.v2",
            "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
            "record_sha256": hashlib.sha256(deployment_bytes).hexdigest(),
            "record_kind": "portal_deployment",
            "deployment_id": deployment["deployment_id"],
            "deployment_name": deployment_name,
            "deployment_state": "PUBLISHED",
            "purls": purls,
            "public_manifest_sha256": None,
        }
        status_bytes = encoded(status)
        files, public_manifest, public_manifest_sha256 = canonical_maven_file_rows(
            version, "A" * 40
        )
        proof = {
            "schema_version": 2,
            "registry": "maven_central",
            "namespace": "dev.latchway",
            "version": version,
            "reviewed_repository": True,
            "primary_artifacts_byte_identical": True,
            "checksum_files_byte_identical": True,
            "signature_files_present": True,
            "signatures_cryptographically_verified": True,
            "signing_fingerprint": "A" * 40,
            "reviewed_public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "deployment": {
                "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
                "record_sha256": hashlib.sha256(deployment_bytes).hexdigest(),
                "status_sha256": hashlib.sha256(status_bytes).hexdigest(),
                "record_kind": "portal_deployment",
                "record": deployment,
                "status": status,
            },
            "public_manifest": public_manifest,
            "public_manifest_sha256": public_manifest_sha256,
            "files": files,
        }
        tag_binding = {
            "schema": "latchway.github-release-tag-binding.v1",
            "tag": coordinate["tag"],
            "tag_object_sha": "e" * 40,
            "commit": coordinate["commit"],
            "message_sha256": "f" * 64,
        }
        assets = {
            "latchway-android-1.0.0-maven-repository.zip": {
                "bytes": repository_archive
            },
            "latchway-android-1.0.0-central-portal.zip": {
                "bytes": portal_archive
            },
            "docs-bundle-1.0.0.tar.gz": {"bytes": b"documentation bundle"},
            "latchway-maven-signing-public-key.asc": {"bytes": public_key},
            "maven-central-upload-intent.json": {"bytes": intent_bytes},
            "maven-central-deployment.json": {"bytes": deployment_bytes},
            "maven-central-deployment-status.json": {"bytes": status_bytes},
            "maven-central-release-evidence.json": {"bytes": encoded(proof)},
            "github-release-tag-binding.json": {"bytes": encoded(tag_binding)},
        }
        MODULE.Observer._validate_android_release_documents(assets, coordinate)
        MODULE.Observer._validate_maven_proof(
            encoded(proof),
            coordinate,
            "A" * 40,
            hashlib.sha256(public_key).hexdigest(),
        )

        mutations = []
        legacy_assets = copy.deepcopy(assets)
        legacy = copy.deepcopy(intent)
        legacy["publishing_type"] = "automatic"
        legacy["authorization"] = "single_upload_only"
        legacy_assets["maven-central-upload-intent.json"]["bytes"] = encoded(legacy)
        mutations.append(legacy_assets)

        extra_intent_assets = copy.deepcopy(assets)
        extra_intent = copy.deepcopy(intent)
        extra_intent["unreviewed"] = True
        extra_intent_assets["maven-central-upload-intent.json"]["bytes"] = encoded(
            extra_intent
        )
        mutations.append(extra_intent_assets)

        missing_status_assets = copy.deepcopy(assets)
        missing_status = copy.deepcopy(status)
        missing_status.pop("deployment_name")
        missing_status_assets["maven-central-deployment-status.json"]["bytes"] = encoded(
            missing_status
        )
        mutations.append(missing_status_assets)

        wrong_kind_assets = copy.deepcopy(assets)
        wrong_kind = copy.deepcopy(deployment)
        wrong_kind["record_kind"] = "unreviewed"
        wrong_kind_assets["maven-central-deployment.json"]["bytes"] = encoded(wrong_kind)
        mutations.append(wrong_kind_assets)

        extra_proof_deployment_assets = copy.deepcopy(assets)
        extra_proof_deployment = copy.deepcopy(proof)
        extra_proof_deployment["deployment"]["unreviewed"] = True
        extra_proof_deployment_assets["maven-central-release-evidence.json"][
            "bytes"
        ] = encoded(extra_proof_deployment)
        mutations.append(extra_proof_deployment_assets)

        missing_proof_deployment_assets = copy.deepcopy(assets)
        missing_proof_deployment = copy.deepcopy(proof)
        missing_proof_deployment["deployment"].pop("status_sha256")
        missing_proof_deployment_assets["maven-central-release-evidence.json"][
            "bytes"
        ] = encoded(missing_proof_deployment)
        mutations.append(missing_proof_deployment_assets)

        adoption_assets = copy.deepcopy(assets)
        adoption = copy.deepcopy(deployment)
        adoption["record_kind"] = "public_registry_adoption"
        adoption["deployment_id"] = None
        adoption["public_manifest_sha256"] = "b" * 64
        adoption_bytes = encoded(adoption)
        adoption_status = copy.deepcopy(status)
        adoption_status["record_sha256"] = hashlib.sha256(adoption_bytes).hexdigest()
        adoption_status["record_kind"] = "public_registry_adoption"
        adoption_status["deployment_id"] = None
        adoption_status["public_manifest_sha256"] = "b" * 64
        adoption_status_bytes = encoded(adoption_status)
        adoption_proof = copy.deepcopy(proof)
        adoption_proof["deployment"] = {
            "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
            "record_sha256": hashlib.sha256(adoption_bytes).hexdigest(),
            "status_sha256": hashlib.sha256(adoption_status_bytes).hexdigest(),
            "record_kind": "public_registry_adoption",
            "record": adoption,
            "status": adoption_status,
        }
        adoption_assets["maven-central-deployment.json"]["bytes"] = adoption_bytes
        adoption_assets["maven-central-deployment-status.json"]["bytes"] = (
            adoption_status_bytes
        )
        adoption_assets["maven-central-release-evidence.json"]["bytes"] = encoded(
            adoption_proof
        )
        mutations.append(adoption_assets)

        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaisesRegex(
                MODULE.ObservationError, "registry_maven_deployment_evidence_invalid"
            ):
                MODULE.Observer._validate_android_release_documents(changed, coordinate)

    def test_android_observer_replays_with_complete_deployment_evidence(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for name in (
            "LATCHWAY_CENTRAL_UPLOAD_INTENT",
            "LATCHWAY_CENTRAL_DEPLOYMENT_RECORD",
            "LATCHWAY_CENTRAL_DEPLOYMENT_STATUS",
        ):
            self.assertIn(f'"{name}"', source)
        self.assertIn('"LATCHWAY_CENTRAL_REQUIRE_DEPLOYMENT_EVIDENCE": "true"', source)

    def test_live_sdk_run_and_artifact_metadata_reject_every_substitution(self) -> None:
        metadata = {
            "id": 12345,
            "run_attempt": 2,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "c" * 40,
            "head_branch": "main",
            "path": ".github/workflows/physical-app-attest.yml",
            "created_at": "2026-08-29T09:54:00Z",
            "run_started_at": "2026-08-29T09:55:00Z",
            "updated_at": "2026-08-29T10:15:00Z",
            "repository": {"full_name": "Latchway/latchway-ios-sdk"},
            "head_repository": {"full_name": "Latchway/latchway-ios-sdk"},
        }
        arguments = {
            "repository": "Latchway/latchway-ios-sdk",
            "workflow": ".github/workflows/physical-app-attest.yml",
            "commit": "c" * 40,
            "run_id": 12345,
            "run_attempt": 2,
            "candidate_created": self.candidate_created,
            "now": self.now,
        }
        self.assertEqual(
            MODULE.Observer._validate_sdk_run_metadata(metadata, **arguments),
            (self.workflow_started, self.workflow_finished),
        )
        substitutions = (
            ("id", 99999),
            ("id", True),
            ("run_attempt", 1),
            ("run_attempt", True),
            ("event", "push"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("head_sha", "f" * 40),
            ("head_branch", "feature"),
            ("path", ".github/workflows/ci.yml"),
            ("created_at", "2026-08-29T08:59:59Z"),
            ("updated_at", "2026-08-29T10:31:00Z"),
        )
        for key, value in substitutions:
            with self.subTest(key=key):
                changed = copy.deepcopy(metadata)
                changed[key] = value
                with self.assertRaisesRegex(
                    MODULE.ObservationError, "live_sdk_run_metadata_invalid"
                ):
                    MODULE.Observer._validate_sdk_run_metadata(changed, **arguments)
        changed = copy.deepcopy(metadata)
        changed["repository"]["full_name"] = "attacker/repository"
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_run_metadata_invalid"
        ):
            MODULE.Observer._validate_sdk_run_metadata(changed, **arguments)

        artifact_name = "app-attest-physical-12345-2"
        artifact = {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 88,
                    "name": artifact_name,
                    "expired": False,
                    "size_in_bytes": 4096,
                    "archive_download_url": "https://api.github.com/repos/Latchway/latchway-ios-sdk/actions/artifacts/88/zip",
                    "workflow_run": {"id": 12345, "head_sha": "c" * 40},
                }
            ],
        }
        artifact_arguments = {
            "repository": "Latchway/latchway-ios-sdk",
            "commit": "c" * 40,
            "run_id": 12345,
            "name": artifact_name,
        }
        MODULE.Observer._validate_sdk_artifact_metadata(artifact, **artifact_arguments)
        for key, value in (
            ("name", "injected"),
            ("expired", True),
            ("archive_download_url", "https://example.test/injected.zip"),
            (
                "archive_download_url",
                "https://api.github.com/repos/Latchway/latchway-ios-sdk/actions/artifacts/999/zip",
            ),
        ):
            with self.subTest(artifact=key):
                changed = copy.deepcopy(artifact)
                changed["artifacts"][0][key] = value
                with self.assertRaisesRegex(
                    MODULE.ObservationError, "live_sdk_artifact_metadata_invalid"
                ):
                    MODULE.Observer._validate_sdk_artifact_metadata(
                        changed, **artifact_arguments
                    )
        for key, value in (("total_count", True), ("id", True), ("size_in_bytes", True)):
            with self.subTest(artifact_type=key):
                changed = copy.deepcopy(artifact)
                if key == "total_count":
                    changed[key] = value
                else:
                    changed["artifacts"][0][key] = value
                with self.assertRaisesRegex(
                    MODULE.ObservationError, "live_sdk_artifact_metadata_invalid"
                ):
                    MODULE.Observer._validate_sdk_artifact_metadata(
                        changed, **artifact_arguments
                    )

    def test_live_sdk_github_and_attestation_commands_are_exact_and_secret_bounded(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        now = datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc)
        runner = mock.Mock(return_value=(b'[{}]\n', now, now.replace(minute=1)))
        with mock.patch.object(observer, "_execute_command", runner):
            self.assertEqual(
                observer._github_api(
                    "repos/Latchway/latchway-ios-sdk/actions/runs/12345",
                    "cross-repo-token",
                ),
                [{}],
            )
        command = runner.call_args.args[0]
        self.assertEqual(command[0:4], ("gh", "api", "--method", "GET"))
        self.assertEqual(
            command[-1], "repos/Latchway/latchway-ios-sdk/actions/runs/12345"
        )
        self.assertNotIn("cross-repo-token", command)
        self.assertEqual(
            runner.call_args.kwargs["environment"], {"GH_TOKEN": "cross-repo-token"}
        )

        receipt = {"root": self.receipt_directory("ios")}
        runner.reset_mock()
        with mock.patch.object(observer, "_execute_command", runner):
            observer._verify_physical_attestations(
                receipt,
                policy=MODULE.LIVE_SDK_RECEIPTS["ios"],
                commit="c" * 40,
                token="cross-repo-token",
            )
        self.assertEqual(runner.call_count, 3)
        for call in runner.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:3], ("gh", "attestation", "verify"))
            self.assertIn("Latchway/latchway-ios-sdk/.github/workflows/physical-app-attest.yml", command)
            self.assertEqual(command.count("c" * 40), 2)
            self.assertIn("refs/heads/main", command)
            self.assertNotIn("--deny-self-hosted-runners", command)
            self.assertNotIn("cross-repo-token", command)
            self.assertEqual(
                call.kwargs["environment"], {"GH_TOKEN": "cross-repo-token"}
            )

    def test_live_sdk_reruns_exact_gateway_deployment_verifier(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        observer.repositories = {"ios": self.root / "latchway-ios-sdk"}
        observer.repositories["ios"].mkdir()
        profile, _ = self.physical_case("ios")
        root = self.receipt_directory("ios")
        receipt = observer._load_physical_receipt(
            root, MODULE.LIVE_SDK_RECEIPTS["ios"]
        )
        retained = receipt["payloads"]["gateway-deployment-verification.json"]
        runner = mock.Mock(
            return_value=(retained, self.workflow_started, self.workflow_finished)
        )
        with mock.patch.object(observer, "_execute_command", runner):
            observer._rerun_gateway_deployment_validator(
                receipt,
                policy=MODULE.LIVE_SDK_RECEIPTS["ios"],
                profile=profile,
            )
        runner.assert_called_once()
        command = runner.call_args.args[0]
        self.assertEqual(command[0], "python3")
        self.assertEqual(
            command[1],
            str(
                observer.repositories["ios"]
                / "scripts"
                / "verify-gateway-deployment.py"
            ),
        )
        for flag, expected in (
            ("--public-key-sha256", "6" * 64),
            ("--key-id", "gateway-key-1"),
            ("--gateway-origin", "https://gateway.example.test"),
            ("--environment", "production"),
            ("--core-commit", "a" * 40),
            ("--contract-version", "0.5.1"),
            ("--contract-bundle-sha256", "b" * 64),
            ("--gateway-image-digest", "sha256:" + "c" * 64),
            ("--gateway-configuration-sha256", "4" * 64),
        ):
            self.assertEqual(command[command.index(flag) + 1], expected)

        with mock.patch.object(
            observer,
            "_execute_command",
            return_value=(b'{"valid":false}\n', self.workflow_started, self.workflow_finished),
        ):
            with self.assertRaisesRegex(
                MODULE.ObservationError, "live_sdk_gateway_verification_invalid"
            ):
                observer._rerun_gateway_deployment_validator(
                    receipt,
                    policy=MODULE.LIVE_SDK_RECEIPTS["ios"],
                    profile=profile,
                )

    def test_live_sdk_receipt_requires_exact_files_and_hashes(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        root = self.receipt_directory("ios")
        receipt = observer._load_physical_receipt(
            root, MODULE.LIVE_SDK_RECEIPTS["ios"]
        )
        self.assertEqual(
            set(receipt["checksums"]),
            set(MODULE.LIVE_SDK_RECEIPTS["ios"]["manifest"]),
        )
        with mock.patch.object(MODULE.EVIDENCE, "MAXIMUM_DOMAIN_BYTES", 8):
            with self.assertRaisesRegex(
                MODULE.ObservationError, "live_sdk_receipt_file_invalid"
            ):
                observer._load_physical_receipt(
                    root, MODULE.LIVE_SDK_RECEIPTS["ios"]
                )
        target = root / "app-attest-evidence.json"
        target.write_text('{"tampered":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_receipt_checksum_mismatch"
        ):
            observer._load_physical_receipt(
                root, MODULE.LIVE_SDK_RECEIPTS["ios"]
            )
        (root / "unexpected.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_receipt_file_set_invalid"
        ):
            observer._load_physical_receipt(
                root, MODULE.LIVE_SDK_RECEIPTS["ios"]
            )

    def test_physical_machine_result_retains_exact_hash_bound_receipt_bytes(self) -> None:
        observer = self.bare_observer("physical_devices")
        observation = "sdk.ios.release-image"
        retained = {
            "SHA256SUMS": b"checksums\n",
            "github-attestation.sigstore.json": b'{"bundle":"verified"}\n',
            "app-attest-profile.json": b'{"profile":true}\n',
            "app-attest-evidence.json": b'{"evidence":true}\n',
        }
        hashes = {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in retained.items()
        }
        observer.emit(
            observation,
            MODULE.canonical_json({"receipt_sha256": hashes}),
            started=self.workflow_started,
            finished=self.workflow_finished,
            version="1.0.0",
            invocation=("python3", "scripts/device-evidence.py", "verify"),
            retained_inputs=retained,
        )
        result_path = observer.output / MODULE.EVIDENCE.result_name(observation)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(len(result["artifacts"]), 2)
        retained_entry = next(
            item
            for item in result["artifacts"]
            if item["path"].endswith("physical-receipt.json")
        )
        envelope_path = observer.output / retained_entry["path"]
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        self.assertEqual(envelope["observation"], observation)
        self.assertEqual(
            {
                item["name"]: base64.b64decode(item["content_base64"], validate=True)
                for item in envelope["files"]
            },
            retained,
        )
        envelope_path.write_text('{"substituted":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.EVIDENCE.EvidenceError, "result_artifact_hash_mismatch"
        ):
            MODULE.EVIDENCE.validate_result(
                result_path,
                observer.output,
                "physical_devices",
                observation,
                observer.identity,
                self.candidate_created,
                self.now,
            )

    def test_javascript_machine_result_retains_four_exact_scanned_tarballs(self) -> None:
        observer = self.bare_observer("public_registries")

        def npm_tarball(payload: bytes) -> bytes:
            buffer = io.BytesIO()
            with tarfile.open(
                fileobj=buffer, mode="w:gz", format=tarfile.USTAR_FORMAT
            ) as archive:
                member = tarfile.TarInfo("package/dist/index.js")
                member.mode = 0o644
                member.uid = member.gid = member.mtime = 0
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            return buffer.getvalue()

        tarballs = {
            f"latchway-{package_id}-1.0.0.tgz": npm_tarball(
                f"export const id = {package_id!r};\n".encode()
            )
            for package_id, _ in MODULE.JAVASCRIPT_NPM_PACKAGES
        }
        observer.emit(
            "registry.npm.javascript",
            MODULE.canonical_json({"proof": "fixture"}),
            started=self.workflow_started,
            finished=self.workflow_finished,
            version="core-v2",
            invocation=("npm", "view", "fixture"),
            raw_artifacts=tarballs,
        )
        result_path = observer.output / MODULE.EVIDENCE.result_name(
            "registry.npm.javascript"
        )
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(len(result["artifacts"]), 5)
        for name, payload in tarballs.items():
            path = observer.output / f"artifacts/registry-npm-javascript/{name}"
            self.assertEqual(path.read_bytes(), payload)
        MODULE.EVIDENCE.validate_result(
            result_path,
            observer.output,
            "public_registries",
            "registry.npm.javascript",
            observer.identity,
            self.candidate_created,
            self.now,
        )
        with self.assertRaisesRegex(
            MODULE.EVIDENCE.EvidenceError, "raw_result_contains_secret"
        ):
            MODULE.EVIDENCE.scan_npm_tarball_safe(
                npm_tarball(b"authorization: Bearer definitely-secret-token\n")
            )

        boundary_payload = tarballs["latchway-client-1.0.0.tgz"]
        accepted = self.bare_observer("public_registries")
        accepted.output = self.root / "raw-tarball-boundary-accepted"
        accepted.output.mkdir()
        with mock.patch.object(
            MODULE,
            "MAXIMUM_RETAINED_NPM_TARBALL_BYTES",
            len(boundary_payload),
        ):
            accepted.emit(
                "registry.npm.javascript",
                MODULE.canonical_json({"proof": "boundary"}),
                started=self.workflow_started,
                finished=self.workflow_finished,
                version="core-v2",
                invocation=("npm", "view", "fixture"),
                raw_artifacts={
                    "latchway-client-1.0.0.tgz": boundary_payload
                },
            )
        rejected = self.bare_observer("public_registries")
        rejected.output = self.root / "raw-tarball-boundary-rejected"
        rejected.output.mkdir()
        with (
            mock.patch.object(
                MODULE,
                "MAXIMUM_RETAINED_NPM_TARBALL_BYTES",
                len(boundary_payload) - 1,
            ),
            self.assertRaisesRegex(
                MODULE.ObservationError, "observation_raw_artifact_set_invalid"
            ),
        ):
            rejected.emit(
                "registry.npm.javascript",
                MODULE.canonical_json({"proof": "boundary"}),
                started=self.workflow_started,
                finished=self.workflow_finished,
                version="core-v2",
                invocation=("npm", "view", "fixture"),
                raw_artifacts={
                    "latchway-client-1.0.0.tgz": boundary_payload
                },
            )
        self.assertEqual(list(rejected.output.rglob("*")), [])

    def test_invalid_retained_receipt_is_rejected_before_any_output(self) -> None:
        observer = self.bare_observer("physical_devices")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "observation_retained_input_set_invalid"
        ):
            observer.emit(
                "sdk.ios.release-image",
                MODULE.canonical_json({"receipt_sha256": {}}),
                started=self.workflow_started,
                finished=self.workflow_finished,
                version="1.0.0",
                invocation=("python3", "scripts/device-evidence.py", "verify"),
                retained_inputs={"../escape.json": b"not written\n"},
            )
        self.assertEqual(list(observer.output.rglob("*")), [])

    def test_live_sdk_configuration_rejects_incomplete_or_malformed_receipt_identity(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        observer.live_sdk_receipts = {
            receipt_id: self.root for receipt_id in MODULE.LIVE_SDK_RECEIPTS
        }
        observer.live_sdk_runs = {
            "ios": ("12345", "2"),
            "android": ("12346", "1"),
        }
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_receipt_configuration_missing"
        ):
            observer._live_sdk_configuration(require_javascript=False)

        observer.live_sdk_runs["react_native"] = (None, "1")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_run_identity_invalid"
        ):
            observer._live_sdk_configuration(require_javascript=False)

    def test_live_sdk_configuration_requires_both_isolated_captures_and_rejects_legacy_credentials(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        observer.live_sdk_receipts = {
            receipt_id: self.root for receipt_id in MODULE.LIVE_SDK_RECEIPTS
        }
        observer.live_sdk_runs = {
            "ios": ("12345", "2"),
            "android": ("12346", "1"),
            "react_native": ("12347", "3"),
        }
        observer.javascript_captures = {
            "firebase_app_check": self.root / "firebase_app_check.json",
        }
        environment = {
            "GH_TOKEN": "github-token",
            "LATCHWAY_BASE_URL": "https://gateway.example.test",
            "LATCHWAY_LIVE_SDK_ENVIRONMENT": "production",
            "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE": "missing_feature",
        }
        with mock.patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(
            MODULE.ObservationError,
            "live_sdk_javascript_capture_configuration_invalid",
        ):
            observer._live_sdk_configuration(require_javascript=True)

        observer.javascript_captures["turnstile"] = self.root / "turnstile.json"
        with mock.patch.dict(os.environ, environment, clear=True):
            gateway, token, javascript_environment, runs = (
                observer._live_sdk_configuration(require_javascript=True)
            )
        self.assertEqual(gateway, "https://gateway.example.test")
        self.assertEqual(token, "github-token")
        self.assertEqual(
            set(javascript_environment),
            set(MODULE.LIVE_SDK_JAVASCRIPT_CONFIGURATION_KEYS),
        )
        self.assertEqual(set(runs), {"ios", "android", "react_native"})

        for legacy_name in MODULE.LIVE_SDK_LEGACY_CREDENTIAL_ENV:
            with self.subTest(legacy_name=legacy_name):
                legacy = {**environment, legacy_name: "reusable-secret"}
                with mock.patch.dict(
                    os.environ, legacy, clear=True
                ), self.assertRaisesRegex(
                    MODULE.ObservationError,
                    "live_sdk_javascript_credentials_present",
                ):
                    observer._live_sdk_configuration(require_javascript=True)

    def test_offline_sdk_configuration_needs_no_cross_repo_or_provider_secret(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        observer.live_sdk_receipts = {
            receipt_id: self.root for receipt_id in MODULE.LIVE_SDK_RECEIPTS
        }
        observer.live_sdk_runs = {
            "ios": ("12345", "2"),
            "android": ("12346", "1"),
            "react_native": ("12347", "3"),
        }
        authority = self.root / "authority"
        authority.mkdir()
        for name in observer._physical_authority_files():
            value = [{}] if name.endswith("-attestation.json") else {}
            (authority / name).write_text(json.dumps(value) + "\n", encoding="utf-8")
        observer.live_sdk_authority = authority
        observer.javascript_captures = {
            provider: self.root / f"{provider}.json"
            for provider in MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS
        }
        with mock.patch.dict(
            os.environ,
            {
                "LATCHWAY_BASE_URL": "https://gateway.example.test",
                "LATCHWAY_LIVE_SDK_ENVIRONMENT": "production",
                "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE": "missing_feature",
            },
            clear=True,
        ):
            gateway, token, javascript_environment, runs = (
                observer._live_sdk_configuration(require_javascript=True)
            )
        self.assertEqual(gateway, "https://gateway.example.test")
        self.assertEqual(token, "")
        self.assertEqual(
            javascript_environment,
            {
                "LATCHWAY_LIVE_SDK_ENVIRONMENT": "production",
                "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE": "missing_feature",
            },
        )
        self.assertEqual(set(runs), {"ios", "android", "react_native"})

    def test_offline_javascript_capture_is_strictly_bound_to_one_use_isolation(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        path = self.javascript_isolation_fixture(
            observer, "firebase_app_check"
        )
        observer.javascript_captures = {"firebase_app_check": path}
        payload, started, finished, isolation = observer._load_javascript_capture(
            "firebase_app_check",
            gateway="https://gateway.example.test",
            environment="production",
        )
        self.assertEqual(
            json.loads(payload),
            {"redacted": True, "provider": "firebase_app_check"},
        )
        self.assertLess(started, finished)
        self.assertEqual(
            set(isolation["payloads"]),
            {"capture.json", *MODULE.LIVE_SDK_ISOLATION_FILES},
        )

        value = json.loads(path.read_text(encoding="utf-8"))
        value["attestation_provider"] = "turnstile"
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_capture_invalid"
        ):
            observer._load_javascript_capture(
                "firebase_app_check",
                gateway="https://gateway.example.test",
                environment="production",
            )

    def test_javascript_isolation_rejects_closure_hash_schema_and_binding_mutations(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        path = self.javascript_isolation_fixture(observer, "firebase_app_check")
        observer.javascript_captures = {"firebase_app_check": path}

        def load() -> None:
            observer._load_javascript_capture(
                "firebase_app_check",
                gateway="https://gateway.example.test",
                environment="production",
            )

        isolation = path.parent / "firebase_app_check-isolation"
        extra = isolation / "extra.json"
        extra.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_isolation_invalid"
        ):
            load()
        extra.unlink()

        checksum = isolation / "ISOLATION_SHA256SUMS"
        original_checksum = checksum.read_bytes()
        checksum.write_bytes(original_checksum.replace(b"a", b"b", 1))
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_isolation_invalid"
        ):
            load()
        checksum.write_bytes(original_checksum)

        lease_path = isolation / "collector-lease.json"
        original_lease = lease_path.read_bytes()
        lease = json.loads(original_lease)
        lease["grant"]["single_use"] = False
        lease_path.write_bytes(MODULE.canonical_json(lease))
        checksum.write_bytes(
            original_checksum.replace(
                hashlib.sha256(original_lease).hexdigest().encode(),
                hashlib.sha256(lease_path.read_bytes()).hexdigest().encode(),
                1,
            )
        )
        capture = json.loads(path.read_text(encoding="utf-8"))
        capture["collector_isolation"]["lease_sha256"] = hashlib.sha256(
            lease_path.read_bytes()
        ).hexdigest()
        path.write_bytes(MODULE.canonical_json(capture))
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_isolation_invalid"
        ):
            load()

    def test_javascript_isolation_pair_and_retention_bind_every_file(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        captures = {
            provider: self.javascript_isolation_fixture(observer, provider)
            for provider in MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS
        }
        observer.javascript_captures = captures
        isolations = {}
        for provider in MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS:
            payload, started, finished, isolation = observer._load_javascript_capture(
                provider,
                gateway="https://gateway.example.test",
                environment="production",
            )
            isolations[provider] = isolation
            observer.emit(
                MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS[provider]["observation"],
                payload,
                started=started,
                finished=finished,
                version="1.0.0",
                invocation=("latchway-live-sdk-collector", "validate-isolation", provider),
                retained_inputs=isolation["payloads"],
                retained_input_kind="live_sdk_collector_isolation",
            )
            slug = MODULE.LIVE_SDK_JAVASCRIPT_PROVIDERS[provider][
                "observation"
            ].replace(".", "-")
            retained_path = (
                observer.output / "artifacts" / slug / "collector-isolation.json"
            )
            retained = json.loads(retained_path.read_text(encoding="utf-8"))
            self.assertEqual(
                retained["kind"],
                "latchway_retained_live_sdk_collector_isolation",
            )
            retained_files = {item["name"]: item for item in retained["files"]}
            self.assertEqual(set(retained_files), set(isolation["payloads"]))
            for name, source in isolation["payloads"].items():
                self.assertEqual(
                    retained_files[name]["sha256"], hashlib.sha256(source).hexdigest()
                )
                self.assertEqual(
                    base64.b64decode(
                        retained_files[name]["content_base64"], validate=True
                    ),
                    source,
                )
        observer._validate_javascript_isolation_pair(isolations)

        changed = copy.deepcopy(isolations)
        changed["turnstile"]["jti_sha256"] = isolations["firebase_app_check"][
            "jti_sha256"
        ]
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_isolation_pair_invalid"
        ):
            observer._validate_javascript_isolation_pair(changed)

    def test_live_sdk_physical_receipt_rejects_candidate_and_behavior_tampering(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        policy = MODULE.LIVE_SDK_RECEIPTS["ios"]
        profile, evidence = self.physical_case("ios")
        component = self.ios_component_case(
            profile["expected_pins"], evidence["run"]["id"]
        )
        receipt = {
            "payloads": {
                policy["profile"]: json.dumps(profile).encode(),
                policy["evidence"]: json.dumps(evidence).encode(),
                policy["component_observation"]: json.dumps(component).encode(),
            },
            "initial_hashes": {"SHA256SUMS": "8" * 64},
        }
        _, _, summary, started, finished = observer._validate_physical_receipt(
            receipt,
            policy=policy,
            gateway="https://gateway.example.test",
            run_id=12345,
            run_attempt=2,
            artifact_name="app-attest-physical-12345-2",
            workflow_started=self.workflow_started,
            workflow_finished=self.workflow_finished,
        )
        self.assertEqual(summary["candidate"], observer.identity)
        self.assertEqual(started.isoformat(), "2026-08-29T10:00:00+00:00")
        self.assertEqual(finished.isoformat(), "2026-08-29T10:06:00+00:00")
        self.assertNotIn("passed", json.dumps(summary))

        changed_profile = copy.deepcopy(profile)
        changed_profile["source"]["commit"] = "f" * 40
        changed_evidence = copy.deepcopy(evidence)
        changed_evidence["source"] = changed_profile["source"]
        changed = copy.deepcopy(receipt)
        changed["payloads"][policy["profile"]] = json.dumps(changed_profile).encode()
        changed["payloads"][policy["evidence"]] = json.dumps(changed_evidence).encode()
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_profile_identity_invalid"
        ):
            observer._validate_physical_receipt(
                changed,
                policy=policy,
                gateway="https://gateway.example.test",
                run_id=12345,
                run_attempt=2,
                artifact_name="app-attest-physical-12345-2",
                workflow_started=self.workflow_started,
                workflow_finished=self.workflow_finished,
            )

        for test_id, key, value in (
            ("canonical_error_mapping", "mapped_error_type", "generic_error"),
            ("session_refresh_rotation", "credential_after_sha256", "1" * 64),
            ("installation_revocation", "error_code", "session_revoked"),
            ("protocol_version_rejection", "protocol_version_sent", 1),
        ):
            with self.subTest(test_id=test_id):
                changed_evidence = copy.deepcopy(evidence)
                next(
                    item for item in changed_evidence["tests"] if item["id"] == test_id
                )[key] = value
                changed = copy.deepcopy(receipt)
                changed["payloads"][policy["evidence"]] = json.dumps(
                    changed_evidence
                ).encode()
                with self.assertRaisesRegex(
                    MODULE.ObservationError, "live_sdk_concrete_behavior_invalid"
                ):
                    observer._validate_physical_receipt(
                        changed,
                        policy=policy,
                        gateway="https://gateway.example.test",
                        run_id=12345,
                        run_attempt=2,
                        artifact_name="app-attest-physical-12345-2",
                        workflow_started=self.workflow_started,
                        workflow_finished=self.workflow_finished,
                    )

        for field, value in (
            ("started_at", "2026-08-29T08:59:59Z"),
            ("completed_at", "2026-08-29T10:16:00Z"),
        ):
            with self.subTest(time_field=field):
                changed_evidence = copy.deepcopy(evidence)
                changed_evidence["run"][field] = value
                if field == "completed_at":
                    changed_evidence["generated_at"] = value
                changed = copy.deepcopy(receipt)
                changed["payloads"][policy["evidence"]] = json.dumps(
                    changed_evidence
                ).encode()
                with self.assertRaisesRegex(
                    MODULE.ObservationError, "live_sdk_evidence_time_invalid"
                ):
                    observer._validate_physical_receipt(
                        changed,
                        policy=policy,
                        gateway="https://gateway.example.test",
                        run_id=12345,
                        run_attempt=2,
                        artifact_name="app-attest-physical-12345-2",
                        workflow_started=self.workflow_started,
                        workflow_finished=self.workflow_finished,
                    )

    def test_ios_component_observer_rejects_delegation_keychain_race_and_lifecycle_tampering(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        policy = MODULE.LIVE_SDK_RECEIPTS["ios"]
        profile, evidence = self.physical_case("ios")
        component = self.ios_component_case(
            profile["expected_pins"], evidence["run"]["id"]
        )
        component["schema_version"] = "latchway.ios-component-observation.v1"
        component_payload = json.dumps(component).encode()
        evidence["artifacts"]["component_observation_sha256"] = hashlib.sha256(
            component_payload
        ).hexdigest()
        receipt = {
            "payloads": {
                policy["profile"]: json.dumps(profile).encode(),
                policy["evidence"]: json.dumps(evidence).encode(),
                policy["component_observation"]: component_payload,
            },
            "initial_hashes": {"SHA256SUMS": "8" * 64},
        }
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_component_observation_invalid"
        ):
            observer._validate_physical_receipt(
                receipt,
                policy=policy,
                gateway="https://gateway.example.test",
                run_id=12345,
                run_attempt=2,
                artifact_name="app-attest-physical-12345-2",
                workflow_started=self.workflow_started,
                workflow_finished=self.workflow_finished,
            )

        mutations = (
            (
                "live_sdk_component_runtime_invalid",
                lambda runtime: runtime["identities"][3].__setitem__(
                    "bundle_identifier", "dev.latchway.conformance.other"
                ),
            ),
            (
                "live_sdk_component_runtime_invalid",
                lambda runtime: runtime["identities"][3].__setitem__(
                    "attestation_mode", "root_app_attest"
                ),
            ),
            (
                "live_sdk_component_runtime_invalid",
                lambda runtime: runtime["identities"][3].__setitem__(
                    "dpop_key_id_sha256",
                    runtime["identities"][0]["dpop_key_id_sha256"],
                ),
            ),
            (
                "live_sdk_component_runtime_invalid",
                lambda runtime: runtime.pop("widget_delegated_execution"),
            ),
            (
                "live_sdk_component_delegated_execution_invalid",
                lambda runtime: runtime["widget_delegated_execution"].__setitem__(
                    "http_status", 401
                ),
            ),
            (
                "live_sdk_component_delegated_execution_invalid",
                lambda runtime: runtime["share_delegated_execution"].__setitem__(
                    "request_id", runtime["widget_delegated_execution"]["request_id"]
                ),
            ),
            (
                "live_sdk_component_delegated_execution_invalid",
                lambda runtime: runtime["delegated_execution"].__setitem__(
                    "trust_source", "delegated_identity_only"
                ),
            ),
            (
                "live_sdk_component_sibling_denial_invalid",
                lambda runtime: runtime["sibling_denial"].__setitem__(
                    "credential_session_id_sha256",
                    runtime["identities"][3]["session_id_sha256"],
                ),
            ),
            (
                "live_sdk_component_keychain_denial_invalid",
                lambda runtime: runtime["keychain_sibling_denial"].__setitem__(
                    "os_status", -25300
                ),
            ),
            (
                "live_sdk_component_keychain_denial_invalid",
                lambda runtime: runtime["keychain_sibling_denial"].__setitem__(
                    "target_key_id_sha256", runtime["identities"][3]["dpop_key_id_sha256"]
                ),
            ),
            (
                "live_sdk_component_keychain_denial_invalid",
                lambda runtime: runtime["keychain_sibling_denial"].__setitem__(
                    "key_material_returned", True
                ),
            ),
            (
                "live_sdk_component_refresh_race_invalid",
                lambda runtime: runtime["component_refresh_race"].__setitem__(
                    "requests_started_concurrently", False
                ),
            ),
            (
                "live_sdk_component_refresh_race_invalid",
                lambda runtime: runtime["component_refresh_race"]["requests"][1].__setitem__(
                    "request_id", "request-refresh-race-a"
                ),
            ),
            (
                "live_sdk_component_refresh_race_invalid",
                lambda runtime: runtime["component_refresh_race"]["requests"][1].__setitem__(
                    "access_credential_sha256", "b" * 64
                ),
            ),
            (
                "live_sdk_component_refresh_race_invalid",
                lambda runtime: runtime["component_refresh_race"].__setitem__(
                    "session_id_before_sha256", "7" * 64
                ),
            ),
            (
                "live_sdk_component_lifecycle_invalid",
                lambda runtime: runtime["lifecycle"].__setitem__(
                    "host_process_running_during_action_request", True
                ),
            ),
            (
                "live_sdk_component_lifecycle_invalid",
                lambda runtime: runtime["lifecycle"].__setitem__(
                    "background_execution_observed", False
                ),
            ),
            (
                "live_sdk_component_lifecycle_invalid",
                lambda runtime: runtime["lifecycle"].__setitem__(
                    "host_termination_observed", False
                ),
            ),
            (
                "live_sdk_component_lifecycle_invalid",
                lambda runtime: runtime["lifecycle"].__setitem__(
                    "user_presence_prompt_observed", True
                ),
            ),
        )
        for expected_error, mutate in mutations:
            with self.subTest(expected_error=expected_error):
                profile, evidence = self.physical_case("ios")
                component = self.ios_component_case(
                    profile["expected_pins"], evidence["run"]["id"]
                )
                mutate(component["runtime"])
                evidence["component_runtime"] = copy.deepcopy(component["runtime"])
                component_payload = json.dumps(component).encode()
                evidence["artifacts"]["component_observation_sha256"] = hashlib.sha256(
                    component_payload
                ).hexdigest()
                receipt = {
                    "payloads": {
                        policy["profile"]: json.dumps(profile).encode(),
                        policy["evidence"]: json.dumps(evidence).encode(),
                        policy["component_observation"]: component_payload,
                    },
                    "initial_hashes": {"SHA256SUMS": "8" * 64},
                }
                with self.assertRaisesRegex(MODULE.ObservationError, expected_error):
                    observer._validate_physical_receipt(
                        receipt,
                        policy=policy,
                        gateway="https://gateway.example.test",
                        run_id=12345,
                        run_attempt=2,
                        artifact_name="app-attest-physical-12345-2",
                        workflow_started=self.workflow_started,
                        workflow_finished=self.workflow_finished,
                    )

    def test_live_sdk_javascript_report_rejects_identity_behavior_and_secret_tampering(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        report = {
            "schema_version": 1,
            "kind": "latchway_live_javascript_observation",
            "platform": "javascript",
            "attestation_provider": "firebase_app_check",
            "candidate": observer.identity,
            "gateway": {
                "origin": "https://gateway.example.test",
                "status": "ok",
                "build": {
                    "version": "1.0.0",
                    "commit": "a" * 40,
                    "build_date": "2026-08-29T10:00:00Z",
                    "contract_version": "0.5.1",
                    "protocol_version": "2",
                },
            },
            "tests": self.concrete_tests("ios", javascript=True),
            "redaction": {
                "identity_token_recorded": False,
                "attestation_token_recorded": False,
                "access_token_recorded": False,
                "refresh_token_recorded": False,
                "dpop_proof_recorded": False,
                "private_key_recorded": False,
            },
        }
        MODULE.Observer._validate_javascript_report(
            json.dumps(report).encode(),
            observer.identity,
            "https://gateway.example.test",
            expected_provider="firebase_app_check",
        )
        changed = copy.deepcopy(report)
        changed["candidate"]["core_commit"] = "f" * 40
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_report_invalid"
        ):
            MODULE.Observer._validate_javascript_report(
                json.dumps(changed).encode(),
                observer.identity,
                "https://gateway.example.test",
                expected_provider="firebase_app_check",
            )
        changed = copy.deepcopy(report)
        next(item for item in changed["tests"] if item["id"] == "quota")[
            "limit_count"
        ] = 0
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_concrete_behavior_invalid"
        ):
            MODULE.Observer._validate_javascript_report(
                json.dumps(changed).encode(),
                observer.identity,
                "https://gateway.example.test",
                expected_provider="firebase_app_check",
            )
        changed = copy.deepcopy(report)
        changed["gateway"]["build"]["build_date"] = "api_key=secret-value"
        with self.assertRaisesRegex(Exception, "raw_result_contains_secret"):
            MODULE.Observer._validate_javascript_report(
                json.dumps(changed).encode(),
                observer.identity,
                "https://gateway.example.test",
                expected_provider="firebase_app_check",
            )
        changed = copy.deepcopy(report)
        changed["attestation_provider"] = "turnstile"
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_javascript_report_invalid"
        ):
            MODULE.Observer._validate_javascript_report(
                json.dumps(changed).encode(),
                observer.identity,
                "https://gateway.example.test",
                expected_provider="firebase_app_check",
            )

    def test_live_sdk_react_native_links_are_exact_bytes_and_candidate_native_versions(self) -> None:
        native_ios_profile, _ = self.physical_case("ios")
        native_android_profile, _ = self.physical_case("android")
        rn_ios_profile, _ = self.physical_case("react_native_ios")
        rn_android_profile, _ = self.physical_case("react_native_android")
        ios_profile_bytes = json.dumps(native_ios_profile, sort_keys=True).encode()
        android_profile_bytes = json.dumps(native_android_profile, sort_keys=True).encode()
        ios_evidence_bytes = b'{"native":"ios"}\n'
        android_evidence_bytes = b'{"native":"android"}\n'
        rn_ios_profile["expected_pins"]["native_evidence_sha256"] = hashlib.sha256(
            ios_evidence_bytes
        ).hexdigest()
        rn_android_profile["expected_pins"]["native_evidence_sha256"] = hashlib.sha256(
            android_evidence_bytes
        ).hexdigest()
        receipts = {
            "ios": {
                "profile": native_ios_profile,
                "receipt": {
                    "payloads": {
                        "app-attest-profile.json": ios_profile_bytes,
                        "app-attest-evidence.json": ios_evidence_bytes,
                    }
                },
            },
            "android": {
                "profile": native_android_profile,
                "receipt": {
                    "payloads": {
                        "play-integrity-profile.json": android_profile_bytes,
                        "play-integrity-evidence.json": android_evidence_bytes,
                    }
                },
            },
            "react_native_ios": {
                "profile": rn_ios_profile,
                "receipt": {
                    "payloads": {
                        "linked-ios-native-profile.json": ios_profile_bytes,
                        "linked-ios-native-evidence.json": ios_evidence_bytes,
                    }
                },
            },
            "react_native_android": {
                "profile": rn_android_profile,
                "receipt": {
                    "payloads": {
                        "linked-android-native-profile.json": android_profile_bytes,
                        "linked-android-native-evidence.json": android_evidence_bytes,
                    }
                },
            },
        }
        MODULE.Observer._validate_react_native_links(receipts)
        receipts["react_native_ios"]["receipt"]["payloads"][
            "linked-ios-native-evidence.json"
        ] = b'{"native":"substituted"}\n'
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_native_link_invalid"
        ):
            MODULE.Observer._validate_react_native_links(receipts)

    def test_live_sdk_behavior_derivation_requires_both_web_providers_and_four_physical_sets(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        platforms = []
        specifications = (
            ("javascript", "firebase_app_check", None),
            ("javascript", "turnstile", None),
            ("ios_app_attest", None, "ios"),
            ("android_play_integrity", None, "android"),
            ("react_native_ios_app_attest", None, "react_native_ios"),
            ("react_native_android_play_integrity", None, "react_native_android"),
        )
        for index, (platform, provider, receipt_id) in enumerate(specifications):
            javascript = provider is not None
            tests = self.concrete_tests(
                receipt_id or "ios",
                javascript=javascript,
            )
            summary = {
                "platform": platform,
                "producer": {"repository": f"repository-{index}"},
                "concrete_tests": [
                    MODULE.Observer._redacted_test_record(item)
                    for item in tests
                    if item["id"] in observer._behavior_test_ids()
                ],
            }
            if provider is not None:
                summary["attestation_provider"] = provider
            platforms.append(summary)
        result = MODULE.Observer._behavior_summary(
            "session_refresh", platforms, observer.identity
        )
        self.assertEqual(len(result["platforms"]), 6)
        self.assertEqual(
            {
                item.get("attestation_provider")
                for item in result["platforms"]
                if item["platform"] == "javascript"
            },
            {"firebase_app_check", "turnstile"},
        )
        self.assertNotIn("passed", json.dumps(result))
        platforms[5]["concrete_tests"] = [
            item
            for item in platforms[5]["concrete_tests"]
            if item["id"] != "session_refresh_rotation"
        ]
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_behavior_set_invalid"
        ):
            MODULE.Observer._behavior_summary(
                "session_refresh", platforms, observer.identity
            )

        platforms[5]["concrete_tests"] = [
            MODULE.Observer._redacted_test_record(item)
            for item in self.concrete_tests("react_native_android")
            if item["id"] in observer._behavior_test_ids()
        ]
        platforms[1]["attestation_provider"] = "firebase_app_check"
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_behavior_set_invalid"
        ):
            MODULE.Observer._behavior_summary(
                "session_refresh", platforms, observer.identity
            )

    def test_observe_rejects_incomplete_result_set(self) -> None:
        observer = self.bare_observer()
        observer.source = self.root / "source.json"
        observer.candidate_path = self.root / "candidate.json"
        observer.input_hashes = {"source": "a" * 64, "candidate": "a" * 64}
        observer.observe_live_provider = mock.Mock()
        with (
            mock.patch.object(observer, "_validate_repositories"),
            mock.patch.object(MODULE.EVIDENCE, "sha256_file", return_value="a" * 64),
        ):
            with self.assertRaisesRegex(
                MODULE.ObservationError, "observation_set_incomplete"
            ):
                observer.observe()


if __name__ == "__main__":
    unittest.main()
