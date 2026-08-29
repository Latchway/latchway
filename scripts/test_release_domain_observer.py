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
import tempfile
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
        observer.output = self.root / "raw"
        observer.output.mkdir(exist_ok=True)
        observer.repositories = {}
        observer.live_sdk_receipts = {}
        observer.live_sdk_runs = {}
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
        observer.now = self.now
        return observer

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
        for repository_id in ("core", "javascript", "ios", "android", "react_native"):
            coordinate = observer.identity["repositories"][repository_id]
            responses.extend((
                json.dumps({"ref": "refs/tags/v1.0.0", "object": {"type": "tag", "sha": "f" * 40}}).encode(),
                json.dumps({
                    "tag": "v1.0.0",
                    "object": {"type": "commit", "sha": coordinate["commit"]},
                    "message": (
                        f"Latchway v1.0.0\n\nPromotion evidence SHA-256: {promotion_hash}"
                        if repository_id == "core"
                        else f"{titles[repository_id]} v1.0.0\n\nCore promotion: v1.0.0\nPromotion evidence SHA-256: {promotion_hash}"
                    ),
                }).encode(),
                json.dumps({"tag_name": "v1.0.0", "draft": False, "prerelease": False}).encode(),
            ))
        with mock.patch.object(observer, "_gh_json", side_effect=responses), mock.patch.object(observer, "emit"):
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
        tests = [{"id": name, "status": "passed"} for name in sorted(names)]
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
        if javascript:
            by_id["streamed_request"]["byte_count"] = 128
            by_id["quota"].update(
                feature="chat", limit_count=1, metrics=["requests"]
            )
        return tests

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

    def test_live_provider_selects_health_and_self_test_commands_without_token_argv(self) -> None:
        observer = self.bare_observer()
        result = {
            "kind": "openrouter",
            "state": "passed",
            "checks": [
                {"name": name, "state": "passed"}
                for name in MODULE.PROVIDER_CHECKS.values()
            ],
        }
        environment = {
            "LATCHWAY_BASE_URL": "https://gateway.example.test",
            "LATCHWAY_ADMIN_API_TOKEN": "admin-token-value",
            "LATCHWAY_PROVIDER_ENVIRONMENT_ID": "env_00000000000000000000000000",
            "LATCHWAY_PROVIDER_UPSTREAM_ID": "ups_00000000000000000000000000",
            "LATCHWAY_PROVIDER_MODEL_ID": "mdl_00000000000000000000000000",
            "LATCHWAY_CLI_PATH": "/runner/latchway",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(MODULE.shutil, "which", return_value="/runner/latchway"),
            mock.patch.object(observer, "run_command", return_value=b"{}") as health,
            mock.patch.object(
                observer,
                "_execute_command",
                return_value=(
                    json.dumps(result).encode(),
                    datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
                    datetime(2026, 8, 29, 10, 1, tzinfo=timezone.utc),
                ),
            ) as execute,
            mock.patch.object(observer, "emit") as emit,
        ):
            observer.observe_live_provider()
        health_command = health.call_args.args[1]
        self.assertEqual(health.call_args.args[0], "provider.gateway-identity")
        self.assertEqual(health_command[-1], "https://gateway.example.test/healthz")
        command = execute.call_args.args[0]
        self.assertEqual(
            command[:6],
            (
                "/runner/latchway",
                "--output",
                "json",
                "--base-url",
                "https://gateway.example.test",
                "verify",
            ),
        )
        self.assertIn("--api-token-env", command)
        self.assertNotIn("admin-token-value", command)
        self.assertEqual(
            execute.call_args.kwargs["environment"],
            {"LATCHWAY_ADMIN_API_TOKEN": "admin-token-value"},
        )
        self.assertEqual(emit.call_count, len(MODULE.PROVIDER_CHECKS))

    def test_live_provider_validators_reject_identity_and_check_tampering(self) -> None:
        observer = self.bare_observer()
        identity = observer.identity
        health = {
            "status": "ok",
            "build": {
                "version": "1.0.0",
                "commit": "a" * 40,
                "contract_version": "0.5.1",
                "protocol_version": "1",
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
            + [
                {
                    "digest": "sha256:" + str(index + 7) * 64,
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": digest,
                    },
                }
                for index, digest in enumerate(platforms.values())
            ]
        }
        payload = json.dumps(index, separators=(",", ":")).encode()
        MODULE.Observer._validate_index(
            payload, "sha256:" + hashlib.sha256(payload).hexdigest(), platforms
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
        release = {"tag_name": tag, "draft": False, "prerelease": False}
        MODULE.Observer._validate_release(json.dumps(release).encode(), tag)
        release["prerelease"] = True
        with self.assertRaisesRegex(MODULE.ObservationError, "github_release_invalid"):
            MODULE.Observer._validate_release(json.dumps(release).encode(), tag)

    def test_public_registry_validators_reject_coordinate_tampering(self) -> None:
        coordinate = {"version": "1.0.0", "commit": "a" * 40}
        npm = {
            "name": "@latchway/client",
            "version": "1.0.0",
            "gitHead": "a" * 40,
            "dist": {
                "integrity": "sha512-"
                + base64.b64encode(b"published-archive".ljust(64, b"x")).decode()
            },
        }
        MODULE.Observer._validate_npm(
            json.dumps(npm).encode(), "@latchway/client", coordinate
        )
        npm["gitHead"] = "b" * 40
        with self.assertRaisesRegex(MODULE.ObservationError, "registry_npm_invalid"):
            MODULE.Observer._validate_npm(
                json.dumps(npm).encode(), "@latchway/client", coordinate
            )
        swift = {
            "pins": [
                {
                    "identity": "latchway-ios-sdk",
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

    def test_live_sdk_physical_receipt_rejects_candidate_and_behavior_tampering(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        policy = MODULE.LIVE_SDK_RECEIPTS["ios"]
        profile, evidence = self.physical_case("ios")
        receipt = {
            "payloads": {
                policy["profile"]: json.dumps(profile).encode(),
                policy["evidence"]: json.dumps(evidence).encode(),
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

    def test_live_sdk_javascript_report_rejects_identity_behavior_and_secret_tampering(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        report = {
            "schema_version": 1,
            "kind": "latchway_live_javascript_observation",
            "platform": "javascript",
            "candidate": observer.identity,
            "gateway": {
                "origin": "https://gateway.example.test",
                "status": "ok",
                "build": {
                    "version": "1.0.0",
                    "commit": "a" * 40,
                    "build_date": "2026-08-29T10:00:00Z",
                    "contract_version": "0.5.1",
                    "protocol_version": "1",
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
            )
        changed = copy.deepcopy(report)
        changed["gateway"]["build"]["build_date"] = "api_key=secret-value"
        with self.assertRaisesRegex(Exception, "raw_result_contains_secret"):
            MODULE.Observer._validate_javascript_report(
                json.dumps(changed).encode(),
                observer.identity,
                "https://gateway.example.test",
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

    def test_live_sdk_behavior_derivation_requires_all_five_concrete_sets(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        platforms = []
        for index, platform in enumerate(
            (
                "javascript",
                "ios_app_attest",
                "android_play_integrity",
                "react_native_ios_app_attest",
                "react_native_android_play_integrity",
            )
        ):
            tests = self.concrete_tests(
                "ios" if index == 0 else tuple(MODULE.LIVE_SDK_RECEIPTS)[index - 1],
                javascript=index == 0,
            )
            platforms.append(
                {
                    "platform": platform,
                    "producer": {"repository": f"repository-{index}"},
                    "concrete_tests": [
                        MODULE.Observer._redacted_test_record(item)
                        for item in tests
                        if item["id"] in observer._behavior_test_ids()
                    ],
                }
            )
        result = MODULE.Observer._behavior_summary(
            "session_refresh", platforms, observer.identity
        )
        self.assertEqual(len(result["platforms"]), 5)
        self.assertNotIn("passed", json.dumps(result))
        platforms[4]["concrete_tests"] = [
            item
            for item in platforms[4]["concrete_tests"]
            if item["id"] != "session_refresh_rotation"
        ]
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
