#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def bare_observer(self, domain: str = "live_provider") -> MODULE.Observer:
        observer = object.__new__(MODULE.Observer)
        observer.domain = domain
        observer.output = self.root / "raw"
        observer.output.mkdir(exist_ok=True)
        observer.repositories = {}
        observer.identity = {
            "core_commit": "a" * 40,
            "core_release": "v1.0.0",
            "contract_version": "0.5.1",
            "bundle_sha256": "b" * 64,
            "oci_image_digest": "ghcr.io/latchway/latchway@sha256:" + "c" * 64,
            "repositories": {
                "core": {
                    "commit": "a" * 40,
                    "tag": "v1.0.0",
                    "version": "1.0.0",
                }
            },
        }
        return observer

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

    def test_live_sdk_report_validator_rejects_identity_and_behavior_tampering(self) -> None:
        observer = self.bare_observer("live_sdk_conformance")
        observation = "sdk.javascript.release-image"
        report = {
            "candidate": observer.identity,
            "platform_observation": observation,
            "behaviors": {
                key: True for key in MODULE.SDK_BEHAVIOR_KEYS.values()
            },
        }
        MODULE.Observer._validate_sdk_report(
            json.dumps(report).encode(), observation, observer.identity
        )
        report["candidate"] = {**observer.identity, "core_commit": "f" * 40}
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_report_identity_invalid"
        ):
            MODULE.Observer._validate_sdk_report(
                json.dumps(report).encode(), observation, observer.identity
            )
        report["candidate"] = observer.identity
        report["behaviors"]["streaming"] = False
        with self.assertRaisesRegex(MODULE.ObservationError, "live_sdk_behavior_missing"):
            MODULE.Observer._validate_sdk_report(
                json.dumps(report).encode(), observation, observer.identity
            )
        with self.assertRaisesRegex(
            MODULE.ObservationError, "live_sdk_external_receipts_required"
        ):
            observer.observe_live_sdk_conformance()

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
