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
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
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

GH_VERSION_SCRIPT = Path(__file__).with_name("require-gh-version.py")
GH_VERSION_SPEC = importlib.util.spec_from_file_location(
    "latchway_require_gh_version", GH_VERSION_SCRIPT
)
if GH_VERSION_SPEC is None or GH_VERSION_SPEC.loader is None:
    raise RuntimeError("GitHub CLI version policy cannot be loaded")
GH_VERSION = importlib.util.module_from_spec(GH_VERSION_SPEC)
GH_VERSION_SPEC.loader.exec_module(GH_VERSION)

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
PROVIDER_CHECKS = {
    "provider.openrouter.non-streaming": "non_streaming",
    "provider.openrouter.streaming": "streaming",
    "provider.openrouter.usage": "usage",
    "provider.openrouter.output-clamp": "output_clamp",
    "provider.openrouter.error-normalization": "error_normalization",
}
SDK_BEHAVIOR_KEYS = {
    "sdk.behavior.dpop-vectors": "dpop_vectors",
    "sdk.behavior.error-mapping": "error_mapping",
    "sdk.behavior.session-refresh": "session_refresh",
    "sdk.behavior.installation-revocation": "installation_revocation",
    "sdk.behavior.streaming": "streaming",
    "sdk.behavior.quota-snapshots": "quota_snapshots",
    "sdk.behavior.protocol-version-rejection": "protocol_version_rejection",
}
LIVE_SDK_ENVIRONMENT_KEYS = frozenset(
    {
        "LATCHWAY_LIVE_SDK_APPLICATION_ID",
        "LATCHWAY_LIVE_SDK_FEATURE",
        "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE",
        "LATCHWAY_LIVE_SDK_ATTESTATION_PROVIDER",
        "LATCHWAY_LIVE_SDK_ENVIRONMENT",
        "LATCHWAY_LIVE_SDK_IDENTITY_PROVIDER",
        "LATCHWAY_LIVE_SDK_MODEL",
        "LATCHWAY_LIVE_SDK_IDENTITY_TOKEN",
        "LATCHWAY_LIVE_SDK_ATTESTATION_TOKEN",
    }
)
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
        "mapped_error_type": "swift_latchway_problem",
        "tests": LIVE_SDK_COMMON_PHYSICAL_TESTS
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
        "LATCHWAY_ADMIN_API_TOKEN",
        "LATCHWAY_CENTRAL_EXPECTED_REPOSITORY",
        "LATCHWAY_COCOAPODS_EXPECTED_ARCHIVE",
        "LATCHWAY_CENTRAL_SIGNING_FINGERPRINT",
        "LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY",
        "LATCHWAY_RELEASE_VERSION",
        "NPM_CONFIG_PROVENANCE",
        "NPM_CONFIG_USERCONFIG",
    )
) | LIVE_SDK_ENVIRONMENT_KEYS


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
        now: datetime,
    ):
        EVIDENCE.protected_context()
        if domain not in EVIDENCE.CLAIM_REQUIREMENTS:
            raise ObservationError("domain_invalid")
        if not output.is_absolute() or output.exists() or output.is_symlink():
            raise ObservationError("observation_output_invalid")
        self.domain = domain
        self.source = source
        self.candidate_path = candidate
        self.output = output
        self.repositories = dict(repositories)
        self.live_sdk_receipts = dict(live_sdk_receipts or {})
        self.live_sdk_runs = dict(live_sdk_runs or {})
        self.now = now
        self.identity, self.candidate, self.candidate_created = EVIDENCE.identity_from_inputs(
            source, candidate, now
        )
        self.input_hashes = {
            "source": EVIDENCE.sha256_file(source, EVIDENCE.MAXIMUM_RESULT_BYTES),
            "candidate": EVIDENCE.sha256_file(
                candidate, EVIDENCE.MAXIMUM_RESULT_BYTES
            ),
        }
        self._validate_repositories()
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
    ) -> None:
        if observation not in EVIDENCE.expected_observations(self.domain):
            raise ObservationError("observation_invalid")
        EVIDENCE.scan_safe(payload)
        slug = observation.replace(".", "-")
        relative = f"artifacts/{slug}/tool-output.json"
        artifacts = [
            {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
        ]
        retained = retained_inputs or {}
        if len(retained) > 64:
            raise ObservationError("observation_retained_input_set_invalid")
        retained_files: list[dict[str, str]] = []
        for name, retained_payload in sorted(retained.items()):
            if (
                not isinstance(name, str)
                or EVIDENCE.ARTIFACT_NAME.fullmatch(name) is None
                or not isinstance(retained_payload, bytes)
            ):
                raise ObservationError("observation_retained_input_set_invalid")
            EVIDENCE.scan_safe(retained_payload)
            retained_files.append(
                {
                    "name": name,
                    "sha256": hashlib.sha256(retained_payload).hexdigest(),
                    "content_base64": base64.b64encode(retained_payload).decode("ascii"),
                }
            )
        if retained_files:
            retained_payload = canonical_json(
                {
                    "schema_version": 1,
                    "kind": "latchway_retained_physical_device_receipt",
                    "observation": observation,
                    "files": retained_files,
                }
            )
            EVIDENCE.scan_safe(retained_payload)
            retained_relative = f"artifacts/{slug}/physical-receipt.json"
            artifacts.append(
                {
                    "path": retained_relative,
                    "sha256": hashlib.sha256(retained_payload).hexdigest(),
                }
            )
        # Validate and construct every output before the first filesystem
        # mutation so an invalid retained receipt cannot leave a partial
        # machine-result directory behind.
        write_bytes(self.output / relative, payload)
        if retained_files:
            write_bytes(self.output / retained_relative, retained_payload)
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
        expected = {EVIDENCE.result_name(item) for item in EVIDENCE.expected_observations(self.domain)}
        if actual != expected:
            raise ObservationError("observation_set_incomplete")

    def observe_live_provider(self) -> None:
        required = {
            "LATCHWAY_BASE_URL",
            "LATCHWAY_ADMIN_API_TOKEN",
            "LATCHWAY_PROVIDER_ENVIRONMENT_ID",
            "LATCHWAY_PROVIDER_UPSTREAM_ID",
            "LATCHWAY_PROVIDER_MODEL_ID",
        }
        if any(not os.environ.get(name) for name in required):
            raise ObservationError("live_provider_configuration_missing")
        base_url = os.environ["LATCHWAY_BASE_URL"].rstrip("/")
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
        max_cost = (
            os.environ.get("LATCHWAY_PROVIDER_MAX_COST_NANO_USD") or "10000000"
        )
        if (
            not max_cost.isascii()
            or not max_cost.isdigit()
            or not 1 <= int(max_cost) <= 100_000_000
        ):
            raise ObservationError("live_provider_cost_bound_invalid")
        self.run_command(
            "provider.gateway-identity",
            (
                "curl",
                "--fail-with-body",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "30",
                f"{base_url}/healthz",
            ),
            validate=lambda payload: self._validate_gateway_identity(
                payload, self.identity
            ),
            timeout=60,
        )
        executable = os.environ.get("LATCHWAY_CLI_PATH", "latchway")
        command = (
            executable,
            "--output", "json",
            "--base-url", base_url,
            "verify", "openrouter",
            "--api-token-env", "LATCHWAY_ADMIN_API_TOKEN",
            "--environment", os.environ["LATCHWAY_PROVIDER_ENVIRONMENT_ID"],
            "--upstream", os.environ["LATCHWAY_PROVIDER_UPSTREAM_ID"],
            "--model", os.environ["LATCHWAY_PROVIDER_MODEL_ID"],
            "--max-cost-nano-usd", max_cost,
        )
        payload, started, finished = self._execute_command(
            command,
            environment={
                "LATCHWAY_ADMIN_API_TOKEN": os.environ["LATCHWAY_ADMIN_API_TOKEN"]
            },
            timeout=120,
        )
        states = self._validate_provider_result(payload)
        for observation, check in PROVIDER_CHECKS.items():
            if states.get(check) != "passed":
                raise ObservationError("live_provider_check_missing")
            self.emit(
                observation,
                payload,
                started=started,
                finished=finished,
                version="1.0.0",
                invocation=command,
            )

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
            or str(build.get("protocol_version")) != "1"
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
        self.run_command(
            "supply.github-provenance",
            (
                "gh", "attestation", "verify", f"oci://{image}",
                "--repo", EVIDENCE.REPOSITORY,
                "--signer-workflow", f"{EVIDENCE.REPOSITORY}/{EVIDENCE.CANDIDATE_WORKFLOW}",
                "--source-digest", self.identity["core_commit"],
                "--signer-digest", self.identity["core_commit"],
                "--source-ref", "refs/heads/main",
                "--deny-self-hosted-runners", "--format", "json",
            ),
            environment={"GH_TOKEN": self._github_token()},
            validate=lambda payload: self._require_nonempty_list(payload, "provenance_result_invalid"),
        )

    @staticmethod
    def _github_token() -> str:
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise ObservationError("github_authentication_missing")
        return token

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
        attested: set[str] = set()
        for entry in manifests:
            platform = entry.get("platform") if isinstance(entry, dict) else None
            if not isinstance(platform, dict):
                raise ObservationError("oci_platforms_mismatch")
            os_name = platform.get("os")
            architecture = platform.get("architecture")
            if os_name == "unknown" and architecture == "unknown":
                subject = nested(
                    entry, "annotations", "vnd.docker.reference.digest"
                )
                if (
                    nested(entry, "annotations", "vnd.docker.reference.type")
                    != "attestation-manifest"
                    or subject not in platforms.values()
                    or subject in attested
                ):
                    raise ObservationError("oci_attestation_manifest_invalid")
                attested.add(subject)
                continue
            name = f"{os_name}/{architecture}"
            digest = entry.get("digest") if isinstance(entry, dict) else None
            if name in observed or not isinstance(digest, str):
                raise ObservationError("oci_platforms_mismatch")
            observed[name] = digest
        if observed != dict(platforms) or attested != set(platforms.values()):
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
            ref_payload = self._gh_json(("api", f"repos/{repository}/git/ref/tags/{tag}"))
            ref = self._validate_tag_ref(ref_payload, tag)
            tag_payload = self._gh_json(("api", f"repos/{repository}/git/tags/{ref['object']['sha']}"))
            tag_object = self._validate_tag_object(
                tag_payload, tag, coordinate["commit"]
            )
            message = tag_object.get("message")
            if repository_id == "core":
                match = re.fullmatch(
                    re.escape(f"Latchway {tag}\n\nPromotion evidence SHA-256: ")
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
            combined = canonical_json({"ref": ref, "tag": tag_object})
            observation = f"publication.annotated-tag.{repository_id}"
            now = datetime.now(timezone.utc).replace(microsecond=0)
            self.emit(
                observation,
                combined,
                started=now,
                finished=now + EVIDENCE.timedelta(seconds=1),
                version="system",
                invocation=("gh", "api", repository, "annotated-tag", tag),
            )

            release_payload = self._gh_json(
                (
                    "api",
                    "-H",
                    "X-GitHub-Api-Version: 2026-03-10",
                    f"repos/{repository}/releases/tags/{tag}",
                )
            )
            expected_assets, adoption_required = self._expected_release_assets(
                repository_id, coordinate["version"]
            )
            release = self._validate_release(
                release_payload,
                tag,
                expected_assets=expected_assets,
                adoption_required=adoption_required,
                expected_name=(f"Latchway {tag}" if repository_id == "core" else None),
                expected_body=(
                    f"Immutable Latchway product release {tag}.\n\n"
                    f"Candidate commit: {coordinate['commit']}\n"
                    f"Promotion evidence SHA-256: {promotion_sha256}"
                    if repository_id == "core"
                    else None
                ),
            )
            release_attestation = self._verify_release_attestation(
                repository,
                tag,
                ref["object"]["sha"],
                release,
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
            now = datetime.now(timezone.utc).replace(microsecond=0)
            self.emit(
                observation,
                retained_release_proof,
                started=now,
                finished=now + EVIDENCE.timedelta(seconds=1),
                version="system",
                invocation=("gh", "release", "verify", tag, "--repo", repository),
            )

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
        repository_id: str, version: str
    ) -> tuple[set[str], bool]:
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
            }, False
        if repository_id == "javascript":
            return {
                f"latchway-client-{version}.tgz",
                "SHA256SUMS",
                "build-reproducibility.json",
                "contract-evidence.json",
                "package-evidence.json",
                "post-publish-evidence.json",
                "publish-input-evidence.json",
                "release-candidate-evidence.json",
                "tag-evidence.json",
                "npm-registry-version.json",
                "npm-registry-view.json",
                "npm-attestations.json",
                "npm-audit-signatures.json",
                "npm-registry-evidence-manifest.json",
            }, True
        if repository_id == "react_native":
            return {
                f"latchway-react-native-{version}.tgz",
                f"latchway-react-native-{version}.tgz.sha256",
                "package-evidence.json",
                "build-reproducibility.json",
                "published-dependency-evidence.json",
                "npm-registry-version.json",
                "npm-registry-view.json",
                "npm-attestations.json",
                "npm-audit-signatures.json",
                "npm-registry-evidence-manifest.json",
                "post-publish-evidence.json",
            }, True
        if repository_id == "ios":
            archive = f"latchway-ios-sdk-{version}.tar.gz"
            return {
                archive,
                f"{archive}.sha256",
                "cocoapods-published-podspec.json",
                "cocoapods-reviewed-podspec.json",
                "cocoapods-release-evidence.json",
                "cocoapods-release-evidence.SHA256SUMS",
            }, False
        if repository_id == "android":
            return {
                f"latchway-android-{version}-maven-repository.zip",
                f"latchway-android-{version}-central-portal.zip",
                "SHA256SUMS",
                "github-release-tag-binding.json",
                "latchway-maven-signing-public-key.asc",
                "maven-central-upload-intent.json",
                "maven-central-deployment.json",
                "maven-central-deployment-status.json",
                "maven-central-release-evidence.json",
            }, False
        raise ObservationError("github_release_repository_invalid")

    @staticmethod
    def _validate_release(
        payload: bytes,
        tag: str,
        *,
        expected_assets: set[str] | None = None,
        adoption_required: bool = False,
        expected_name: str | None = None,
        expected_body: str | None = None,
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
            adoptions: set[str] = set()
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
                if NPM_ADOPTION_ASSET.fullmatch(name):
                    adoptions.add(name)
                elif name not in expected_assets:
                    raise ObservationError("github_release_asset_set_invalid")
            if not expected_assets.issubset(names) or (
                adoption_required and not adoptions
            ) or (not adoption_required and adoptions):
                raise ObservationError("github_release_asset_set_invalid")
        return value

    def _verify_release_attestation(
        self,
        repository: str,
        tag: str,
        ref_sha: str,
        release: Mapping[str, Any],
    ) -> bytes:
        executable = shutil.which("gh")
        if executable is None:
            raise ObservationError("observation_tool_unavailable")
        result = subprocess.run(
            (
                executable,
                "release",
                "verify",
                tag,
                "--repo",
                repository,
                "--format",
                "json",
            ),
            check=False,
            capture_output=True,
            timeout=60,
            env=command_environment({"GH_TOKEN": self._github_token()}),
        )
        if (
            result.returncode != 0
            or not result.stdout
            or len(result.stdout) > EVIDENCE.MAXIMUM_RESULT_BYTES
        ):
            raise ObservationError("github_release_attestation_invalid")
        EVIDENCE.scan_safe(result.stdout)
        value = load_output(result.stdout, "github_release_attestation_invalid")
        if not isinstance(value, dict) or not value:
            raise ObservationError("github_release_attestation_invalid")
        try:
            normalized = RELEASE_ATTESTATION.validate_bytes(
                result.stdout,
                repository=repository,
                tag=tag,
                ref_sha=ref_sha,
                release=release,
            )
        except RELEASE_ATTESTATION.AttestationError:
            raise ObservationError("github_release_attestation_invalid") from None
        return canonical_json(normalized)

    def _gh_json(self, arguments: Sequence[str]) -> bytes:
        executable = shutil.which("gh")
        token = self._github_token()
        if executable is None:
            raise ObservationError("observation_tool_unavailable")
        result = subprocess.run(
            (executable, *arguments),
            check=False,
            capture_output=True,
            timeout=60,
            env=command_environment({"GH_TOKEN": token}),
        )
        if result.returncode != 0 or not result.stdout:
            raise ObservationError("github_api_failed")
        EVIDENCE.scan_safe(result.stdout)
        return result.stdout

    def observe_public_registries(self) -> None:
        image = self.identity["oci_image_digest"]
        cosign_command = (
            "cosign", "verify", "--output", "json",
            "--certificate-identity", "https://github.com/Latchway/latchway/.github/workflows/release.yml@refs/heads/main",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-sha", self.identity["core_commit"],
            image,
        )
        cosign_payload, oci_started, oci_finished = self._execute_command(
            cosign_command
        )
        self._validate_cosign(cosign_payload, image, "registry_oci_invalid")
        core = self.identity["repositories"]["core"]
        references: dict[str, dict[str, str]] = {}
        for tag in self._oci_release_tags(core["version"]):
            reference = f"ghcr.io/latchway/latchway:{tag}"
            raw, _, finished = self._execute_command(
                ("docker", "buildx", "imagetools", "inspect", "--raw", reference)
            )
            hashes = {
                hashlib.sha256(raw).hexdigest(),
                hashlib.sha256(raw.removesuffix(b"\n")).hexdigest(),
            }
            if self.candidate["image"]["index_digest"].removeprefix("sha256:") not in hashes:
                raise ObservationError("registry_oci_alias_digest_mismatch")
            references[tag] = {
                "reference": reference,
                "digest": self.candidate["image"]["index_digest"],
            }
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
            "signature_verification": load_output(
                cosign_payload, "registry_oci_invalid"
            ),
        }
        self.emit(
            "registry.oci",
            canonical_json(oci_proof),
            started=oci_started,
            finished=oci_finished,
            version="system",
            invocation=cosign_command,
        )
        for observation, package, repository_id in (
            ("registry.npm.javascript", "@latchway/client", "javascript"),
            ("registry.npm.react-native", "@latchway/react-native", "react_native"),
        ):
            coordinate = self.identity["repositories"][repository_id]
            self._observe_npm_bytes(observation, package, repository_id, coordinate)
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
        for name in (
            "cocoapods-published-podspec.json",
            "cocoapods-reviewed-podspec.json",
            "cocoapods-release-evidence.json",
            "cocoapods-release-evidence.SHA256SUMS",
        ):
            path = ios_archive_path.parent / name
            path.write_bytes(ios_assets[name]["bytes"])
            ios_source_attestations[name] = self._verify_release_asset_attestation(
                path, "ios", ios
            )
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
        published_spec = ios_assets["cocoapods-published-podspec.json"]["bytes"]
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
        repository = f"Latchway/{REPOSITORY_NAMES[repository_id]}"
        payload, _, _ = self._execute_command(
            (
                "gh", "attestation", "verify", str(path),
                "--repo", repository,
                "--signer-workflow", f"{repository}/.github/workflows/release.yml",
                "--source-digest", coordinate["commit"],
                "--signer-digest", coordinate["commit"],
                "--source-ref", "refs/heads/main",
                "--deny-self-hosted-runners",
                "--format", "json",
            ),
            environment={"GH_TOKEN": self._github_token()},
            timeout=120,
        )
        value = load_output(payload, "release_asset_attestation_invalid")
        if not value:
            raise ObservationError("release_asset_attestation_invalid")
        return value

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
        package_evidence = load_output(package_evidence_bytes, "registry_npm_package_evidence_invalid")
        reproducibility = load_output(reproducibility_bytes, "registry_npm_reproducibility_invalid")
        published_dependencies: dict[str, Any] | None = None
        dependency_evidence_bytes: bytes | None = None
        dependency_evidence_asset: Mapping[str, Any] | None = None
        if repository_id == "react_native":
            dependency_evidence_bytes = release_assets[
                "published-dependency-evidence.json"
            ]["bytes"]
            dependency_evidence_asset = release_assets[
                "published-dependency-evidence.json"
            ]["metadata"]
            published_dependencies = self._validate_rn_published_dependencies(
                dependency_evidence_bytes
            )
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
        }
        if dependency_evidence_bytes is not None:
            reviewed_paths["published-dependency-evidence.json"] = (
                reviewed_root / "published-dependency-evidence.json"
            )
        reviewed_paths[tarball_name].write_bytes(reviewed_bytes)
        reviewed_paths["package-evidence.json"].write_bytes(package_evidence_bytes)
        reviewed_paths["build-reproducibility.json"].write_bytes(reproducibility_bytes)
        if dependency_evidence_bytes is not None:
            reviewed_paths["published-dependency-evidence.json"].write_bytes(
                dependency_evidence_bytes
            )
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
            repository_id, coordinate["version"]
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
        adoptions = {name for name in names if NPM_ADOPTION_ASSET.fullmatch(name)}
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
            or adoption_required != bool(adoptions)
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
            or nested(post, "source", "workflow") != ".github/workflows/release.yml"
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
                    "workflow": ".github/workflows/release.yml",
                    "ref": "refs/heads/main",
                }
                or origin != {
                    "repository": repository_url,
                    "commit": coordinate["commit"],
                    "workflow": ".github/workflows/release.yml",
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
                or adoption.get("workflow") != ".github/workflows/release.yml"
                or adoption.get("ref") != "refs/heads/main"
                or adoption.get("mode") not in {"published", "adopted_existing"}
                or record.get("registry_evidence_manifest") != {
                    "file": "npm-registry-evidence-manifest.json",
                    "sha256": manifest_sha256,
                }
            ):
                raise ObservationError("registry_npm_adoption_invalid")
            run_id, run_attempt = adoption["run_id"], adoption["run_attempt"]
            run = self._github_api(
                f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}",
                self._github_token(),
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

    @staticmethod
    def _validate_npm_workflow_run(
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
            or run.get("event") != "repository_dispatch"
            or run.get("status") != "completed"
            or run.get("conclusion") not in conclusions
            or run.get("head_sha") != commit
            or run.get("head_branch") != "main"
            or run.get("path") != ".github/workflows/release.yml"
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
            or workflow.get("path") != ".github/workflows/release.yml"
            or not isinstance(resolved, list)
            or not any(nested(item, "digest", "gitCommit") == coordinate["commit"] for item in resolved if isinstance(item, dict))
            or nested(github, "event_name") != "repository_dispatch"
            or match is None
        ):
            raise ObservationError("registry_npm_provenance_binding_invalid")
        run_id, run_attempt = (int(value) for value in match.groups())
        run = self._github_api(
            f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}", self._github_token()
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
        expected_identity = f"URI:{repository_url}/.github/workflows/release.yml@refs/heads/main"
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
            "workflow": ".github/workflows/release.yml",
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

    def _release_asset_set(
        self, repository_id: str
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        coordinate = self.identity["repositories"][repository_id]
        repository = f"Latchway/{REPOSITORY_NAMES[repository_id]}"
        release_payload = self._gh_json(
            (
                "api",
                "-H",
                "X-GitHub-Api-Version: 2026-03-10",
                f"repos/{repository}/releases/tags/{coordinate['tag']}",
            )
        )
        expected_assets, adoption_required = self._expected_release_assets(
            repository_id, coordinate["version"]
        )
        release = self._validate_release(
            release_payload,
            coordinate["tag"],
            expected_assets=expected_assets,
            adoption_required=adoption_required,
        )
        assets = release.get("assets")
        if not isinstance(assets, list):
            raise ObservationError("github_release_asset_invalid")
        downloaded: dict[str, dict[str, Any]] = {}
        for asset in assets:
            name = asset["name"]
            payload = self._download_release_asset(repository, asset)
            path = Path(tempfile.mkdtemp(prefix="latchway-release-asset-")) / name
            path.write_bytes(payload)
            immutable_verification = self._verify_immutable_release_asset(
                path, repository, coordinate["tag"]
            )
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

    def _download_release_asset(
        self, repository: str, asset: Mapping[str, Any]
    ) -> bytes:
        name = asset.get("name")
        identifier, size, digest = asset.get("id"), asset.get("size"), asset.get("digest")
        if (
            not isinstance(name, str)
            or
            not isinstance(identifier, int)
            or isinstance(identifier, bool)
            or identifier < 1
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= EVIDENCE.MAXIMUM_RAW_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise ObservationError("github_release_asset_invalid")
        executable = shutil.which("gh")
        if executable is None:
            raise ObservationError("observation_tool_unavailable")
        result = subprocess.run(
            (executable, "api", "-H", "Accept: application/octet-stream", f"repos/{repository}/releases/assets/{identifier}"),
            check=False,
            capture_output=True,
            timeout=120,
            env=command_environment({"GH_TOKEN": self._github_token()}),
        )
        if result.returncode != 0 or len(result.stdout) != size or f"sha256:{hashlib.sha256(result.stdout).hexdigest()}" != digest:
            raise ObservationError("github_release_asset_digest_mismatch")
        return result.stdout

    def _release_asset_bytes(self, repository_id: str, name: str) -> tuple[bytes, dict[str, Any]]:
        _, assets = self._release_asset_set(repository_id)
        if name not in assets:
            raise ObservationError("github_release_asset_invalid")
        return assets[name]["bytes"], assets[name]["metadata"]

    def _verify_immutable_release_asset(
        self, path: Path, repository: str, tag: str
    ) -> dict[str, Any]:
        payload, _, _ = self._execute_command(
            (
                "gh", "release", "verify-asset", tag, str(path),
                "--repo", repository, "--format", "json",
            ),
            environment={"GH_TOKEN": self._github_token()},
            timeout=120,
        )
        value = load_output(payload, "github_release_asset_attestation_invalid")
        if not isinstance(value, dict) or not value:
            raise ObservationError("github_release_asset_attestation_invalid")
        return {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "content_base64": base64.b64encode(payload).decode("ascii"),
        }

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
    def _validate_cocoapods_proof(payload: bytes, coordinate: Mapping[str, str], asset: Mapping[str, Any]) -> None:
        value = load_output(payload, "registry_cocoapods_proof_invalid")
        if (
            value.get("schema_version") != 1
            or value.get("registry") != "cocoapods"
            or value.get("version") != coordinate["version"]
            or value.get("published_spec_equals_reviewed_podspec") is not True
            or value.get("reviewed_source_archive_equals_release_tag") is not True
            or value.get("reviewed_source_archive_sha256") != str(asset["digest"]).removeprefix("sha256:")
            or nested(value, "source", "tag") != coordinate["tag"]
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
        if (
            value.get("schema_version") != 2
            or value.get("registry") != "maven_central"
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
            or any(
                not isinstance(item, dict)
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(item.get("signature_sha256"))) is None
                or not isinstance(item.get("signature_armored"), str)
                or not item["signature_armored"].startswith("-----BEGIN PGP SIGNATURE-----")
                or hashlib.sha256(item["signature_armored"].encode("ascii")).hexdigest()
                != item.get("signature_sha256")
                or item.get("checksums_byte_identical") is not True
                for item in files
            )
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
        if (
            intent.get("schema") != "latchway.maven-central-upload-intent.v1"
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
            != hashlib.sha256(
                assets[
                    f"latchway-android-{coordinate['version']}-central-portal.zip"
                ]["bytes"]
            ).hexdigest()
            or intent.get("reviewed_public_key_sha256")
            != hashlib.sha256(
                assets["latchway-maven-signing-public-key.asc"]["bytes"]
            ).hexdigest()
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
            or not valid_commit(tag_binding.get("tag_object_sha"))
            or re.fullmatch(
                r"[0-9a-f]{64}", str(tag_binding.get("message_sha256"))
            )
            is None
            or deployment.get("schema") != "latchway.maven-central-deployment.v1"
            or deployment.get("intent_sha256") != intent_sha
            or deployment.get("source_commit") != coordinate["commit"]
            or deployment.get("version") != coordinate["version"]
            or sorted(deployment.get("expected_purls", [])) != purls
            or status.get("schema")
            != "latchway.maven-central-deployment-status.v1"
            or status.get("intent_sha256") != intent_sha
            or status.get("record_sha256") != deployment_sha
            or status.get("deployment_id") != deployment.get("deployment_id")
            or status.get("deployment_state") != "PUBLISHED"
            or sorted(status.get("purls", [])) != purls
            or nested(proof, "deployment", "intent_sha256") != intent_sha
            or nested(proof, "deployment", "record_sha256") != deployment_sha
            or nested(proof, "deployment", "status_sha256") != status_sha
            or nested(proof, "deployment", "record") != deployment
            or nested(proof, "deployment", "status") != status
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
            and nested(pin, "state", "version") == coordinate["version"]
            and nested(pin, "state", "revision") == coordinate["commit"]
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
                metadata = self._github_api(
                    f"repos/{policy['repository']}/actions/runs/{run_id}/attempts/{run_attempt}", token
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
            artifact = self._github_api(
                f"repos/{policy['repository']}/actions/runs/{run_id}/artifacts"
                f"?name={artifact_name}&per_page=100",
                token,
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
            javascript_payload, javascript_started, javascript_finished = (
                self._run_javascript_live_harness(
                    gateway=gateway, environment=javascript_environment
                )
            )
            javascript_report = self._validate_javascript_report(
                javascript_payload, self.identity, gateway
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
            )
            platform_records["sdk.javascript.release-image"] = {
                "summary": javascript_summary,
                "started": javascript_started,
                "finished": javascript_finished,
                "version": self.identity["repositories"]["javascript"]["version"],
                "invocation": (
                    "node",
                    "scripts/live-conformance.mjs",
                    "--candidate-manifest",
                    "candidate-manifest.json",
                    "--gateway",
                    gateway,
                ),
                "cwd": self.repositories["javascript"],
            }

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

        required = {"GH_TOKEN", "LATCHWAY_BASE_URL"}
        if require_javascript:
            required |= set(LIVE_SDK_ENVIRONMENT_KEYS)
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
        javascript_environment = (
            {key: os.environ[key] for key in sorted(LIVE_SDK_ENVIRONMENT_KEYS)}
            if require_javascript
            else {}
        )
        return gateway, os.environ["GH_TOKEN"], javascript_environment, parsed_runs

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

    def _run_javascript_live_harness(
        self, *, gateway: str, environment: Mapping[str, str]
    ) -> tuple[bytes, datetime, datetime]:
        repository = self.repositories["javascript"]
        with tempfile.TemporaryDirectory(
            prefix="latchway-live-javascript-",
            dir=os.environ.get("RUNNER_TEMP") or None,
        ) as temporary:
            manifest = Path(temporary) / "candidate-manifest.json"
            write_bytes(
                manifest,
                canonical_json(
                    {
                        "schema_version": 1,
                        "kind": "latchway_live_sdk_candidate",
                        "candidate": self.identity,
                        "gateway_origin": gateway,
                    }
                ),
            )
            return self._execute_command(
                (
                    "node",
                    str(repository / "scripts" / "live-conformance.mjs"),
                    "--candidate-manifest",
                    str(manifest),
                    "--gateway",
                    gateway,
                ),
                cwd=repository,
                environment=environment,
                timeout=20 * 60,
            )

    @classmethod
    def _validate_javascript_report(
        cls, payload: bytes, identity: Mapping[str, Any], gateway: str
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
                "candidate",
                "gateway",
                "tests",
                "redaction",
            }
            or report.get("schema_version") != 1
            or report.get("kind") != "latchway_live_javascript_observation"
            or report.get("platform") != "javascript"
            or report.get("candidate") != identity
            or nested(report, "gateway", "origin") != gateway
            or nested(report, "gateway", "status") != "ok"
            or not isinstance(build, dict)
            or build.get("commit") != identity["core_commit"]
            or build.get("version") != identity["repositories"]["core"]["version"]
            or build.get("contract_version") != identity["contract_version"]
            or str(build.get("protocol_version")) != "1"
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
        )

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
            selected.append(
                {
                    "platform": platform["platform"],
                    "producer": platform["producer"],
                    "tests": tests,
                }
            )
        if len(selected) != 5:
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
    return value


def require_github_cli() -> tuple[int, int, int]:
    """Fail closed before the observer uses GitHub release/attestation commands."""
    try:
        return GH_VERSION.installed_version()
    except GH_VERSION.VersionError as error:
        raise ObservationError(str(error)) from error


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
    try:
        require_github_cli()
        observer = Observer(
            domain=arguments.domain,
            source=arguments.source_conformance,
            candidate=arguments.candidate_manifest,
            output=arguments.output_directory,
            repositories=repositories,
            live_sdk_receipts=live_sdk_receipts,
            live_sdk_runs=live_sdk_runs,
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
    print(json.dumps({"domain": arguments.domain, "observations": len(EVIDENCE.expected_observations(arguments.domain))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
