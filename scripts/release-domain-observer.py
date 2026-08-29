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
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


SCRIPT = Path(__file__).with_name("release-domain-evidence.py")
SPEC = importlib.util.spec_from_file_location("latchway_release_domain_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release-domain evidence module cannot be loaded")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)

REPOSITORY_NAMES = {
    "core": "latchway",
    "javascript": "latchway-js",
    "ios": "latchway-ios-sdk",
    "android": "latchway-android",
    "react_native": "latchway-react-native-sdk",
}
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
    ) -> None:
        if observation not in EVIDENCE.expected_observations(self.domain):
            raise ObservationError("observation_invalid")
        EVIDENCE.scan_safe(payload)
        slug = observation.replace(".", "-")
        relative = f"artifacts/{slug}/tool-output.json"
        artifact = self.output / relative
        write_bytes(artifact, payload)
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
            "artifacts": [{"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}],
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
        for repository_id, coordinate in self.identity["repositories"].items():
            repository = f"Latchway/{REPOSITORY_NAMES[repository_id]}"
            tag = coordinate["tag"]
            ref_payload = self._gh_json(("api", f"repos/{repository}/git/ref/tags/{tag}"))
            ref = self._validate_tag_ref(ref_payload, tag)
            tag_payload = self._gh_json(("api", f"repos/{repository}/git/tags/{ref['object']['sha']}"))
            tag_object = self._validate_tag_object(
                tag_payload, tag, coordinate["commit"]
            )
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

            release_payload = self._gh_json(("api", f"repos/{repository}/releases/tags/{tag}"))
            self._validate_release(release_payload, tag)
            observation = f"publication.github-release.{repository_id}"
            now = datetime.now(timezone.utc).replace(microsecond=0)
            self.emit(
                observation,
                release_payload,
                started=now,
                finished=now + EVIDENCE.timedelta(seconds=1),
                version="system",
                invocation=("gh", "api", repository, "release", tag),
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
    def _validate_release(payload: bytes, tag: str) -> dict[str, Any]:
        value = load_output(payload, "github_release_invalid")
        if (
            not isinstance(value, dict)
            or value.get("tag_name") != tag
            or value.get("draft") is not False
            or value.get("prerelease") is not False
        ):
            raise ObservationError("github_release_invalid")
        return value

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
        self.run_command(
            "registry.oci",
            (
                "cosign", "verify", "--output", "json",
                "--certificate-identity", "https://github.com/Latchway/latchway/.github/workflows/release.yml@refs/heads/main",
                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-sha", self.identity["core_commit"],
                image,
            ),
            validate=lambda payload: self._validate_cosign(payload, image, "registry_oci_invalid"),
        )
        for observation, package, repository_id in (
            ("registry.npm.javascript", "@latchway/client", "javascript"),
            ("registry.npm.react-native", "@latchway/react-native", "react_native"),
        ):
            coordinate = self.identity["repositories"][repository_id]
            self.run_command(
                observation,
                ("npm", "view", f"{package}@{coordinate['version']}", "--json"),
                environment={
                    "NPM_CONFIG_USERCONFIG": os.devnull,
                    "NPM_CONFIG_PROVENANCE": "false",
                },
                validate=lambda payload, package=package, coordinate=coordinate: self._validate_npm(payload, package, coordinate),
            )
        ios = self.identity["repositories"]["ios"]
        self._observe_swift_registry(ios)
        self.run_command(
            "registry.cocoapods",
            (str(self.repositories["ios"] / "scripts/verify-cocoapods-release.sh"), ios["version"]),
            cwd=self.repositories["ios"],
        )
        android = self.identity["repositories"]["android"]
        self.run_command(
            "registry.maven-central",
            (str(self.repositories["android"] / "scripts/verify-central-release.sh"), android["version"]),
            cwd=self.repositories["android"],
            environment={"LATCHWAY_RELEASE_VERSION": android["version"]},
        )

    @staticmethod
    def _validate_npm(payload: bytes, package: str, coordinate: Mapping[str, str]) -> None:
        value = load_output(payload, "registry_npm_invalid")
        integrity = nested(value, "dist", "integrity")
        if (
            not isinstance(value, dict)
            or value.get("name") != package
            or value.get("version") != coordinate["version"]
            or value.get("gitHead") != coordinate["commit"]
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
        # Native and React Native release-image observations must come from the
        # SDK repositories' protected self-hosted physical workflows.  The
        # core hosted observer intentionally cannot substitute a simulator or
        # fixture for those receipts.  A separate consumer is required to
        # authenticate and merge those exact SDK attestations with a real JS
        # live run before this domain can be finalized.
        raise ObservationError("live_sdk_external_receipts_required")

    @staticmethod
    def _validate_sdk_report(
        payload: bytes,
        observation: str,
        identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        report = load_output(payload, "live_sdk_report_invalid")
        if not isinstance(report, dict):
            raise ObservationError("live_sdk_report_invalid")
        if (
            report.get("candidate") != identity
            or report.get("platform_observation") != observation
            or not isinstance(report.get("behaviors"), dict)
        ):
            raise ObservationError("live_sdk_report_identity_invalid")
        if set(report["behaviors"]) != set(SDK_BEHAVIOR_KEYS.values()):
            raise ObservationError("live_sdk_behavior_set_invalid")
        if any(value is not True for value in report["behaviors"].values()):
            raise ObservationError("live_sdk_behavior_missing")
        return report


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--domain", choices=tuple(EVIDENCE.CLAIM_REQUIREMENTS), required=True)
    value.add_argument("--source-conformance", type=Path, required=True)
    value.add_argument("--candidate-manifest", type=Path, required=True)
    value.add_argument("--output-directory", type=Path, required=True)
    for repository_id in REPOSITORY_NAMES:
        value.add_argument(f"--{repository_id.replace('_', '-')}-repo", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    repositories = {
        repository_id: getattr(arguments, f"{repository_id}_repo")
        for repository_id in REPOSITORY_NAMES
    }
    try:
        observer = Observer(
            domain=arguments.domain,
            source=arguments.source_conformance,
            candidate=arguments.candidate_manifest,
            output=arguments.output_directory,
            repositories=repositories,
            now=datetime.now(timezone.utc).replace(microsecond=0),
        )
        observer.observe()
    except (ObservationError, EVIDENCE.EvidenceError, OSError) as error:
        code = str(error) if isinstance(error, EVIDENCE.EvidenceError) else "observation_io_failed"
        print(f"release domain observation rejected: {code}", file=sys.stderr)
        return 1
    print(json.dumps({"domain": arguments.domain, "observations": len(EVIDENCE.expected_observations(arguments.domain))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
