#!/usr/bin/env python3
"""Close exact v1 core and deployment evidence for a single-maintainer release.

This tool deliberately does not verify Sigstore signatures.  The protected
workflow verifies the candidate and deployment attestations with ``gh`` before
and after this deterministic, semantic closure check.  The resulting record is
only a core-publication gate; it never claims that the complete release profile
or the stronger strict release gate passed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
TAG = "v1.0.0"
VERSION = "1.0.0"
PROFILE = "single_maintainer_v1"
IMAGE_REPOSITORY = "ghcr.io/latchway/latchway"
PROFILE_ENVIRONMENT_POLICY_IDS = {
    "release_evidence_signing": (
        "latchway-release-profile-v1:latchway:single_maintainer_v1:"
        "release-evidence-signing"
    ),
    "release_image_publishing": (
        "latchway-release-profile-v1:latchway:single_maintainer_v1:"
        "release-image-publishing"
    ),
}
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
MAXIMUM_JSON_BYTES = 8 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 32 * 1024 * 1024
CAPTURE_FILES = (
    "control_plane.json",
    "health.json",
    "identity.json",
    "manifest.json",
    "migration.json",
    "readiness.json",
    "secrets.json",
    "shutdown.json",
)
SIGNED_CAPTURE_FILES = tuple(sorted((*CAPTURE_FILES, "latchway-deployment-binding.json")))
DEPLOYMENT_ASSET_FILES = {
    "compose": ("compose.tar.gz", "compose.attestation.json"),
    "cloud_run": ("cloud_run.tar.gz", "cloud_run.attestation.json"),
}
RAW_CAPTURE_FILES = tuple(
    sorted(
        (
            "latchway-deployment-started-at",
            "latchway-provider-resource-id",
            "latchway-deployment-capture/control_plane.json",
            "latchway-deployment-capture/identity.json",
            "latchway-deployment-capture/migration.json",
            "latchway-deployment-capture/secrets.json",
            "latchway-deployment-capture/shutdown.json",
        )
    )
)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CANDIDATE = load_module(
    "latchway_single_maintainer_candidate",
    Path(__file__).with_name("release-candidate.py"),
)
DEPLOYMENT = load_module(
    "latchway_single_maintainer_deployment",
    Path(__file__).with_name("deployment-evidence.py"),
)
RELEASE_PROFILE = load_module(
    "latchway_single_maintainer_profile",
    Path(__file__).with_name("release-profile.py"),
)


class ReleaseError(Exception):
    """A stable, redaction-safe single-maintainer release failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("json_duplicate_member")
        result[key] = value
    return result


def read_json(path: Path, maximum: int = MAXIMUM_JSON_BYTES) -> dict[str, Any]:
    require_regular_file(path, maximum)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except ReleaseError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseError("json_document_invalid") from None
    if not isinstance(value, dict):
        raise ReleaseError("json_document_invalid")
    return value


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def require_regular_file(path: Path, maximum: int) -> int:
    try:
        value = path.lstat()
    except OSError:
        raise ReleaseError("required_file_missing") from None
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_size <= 0
        or value.st_size > maximum
    ):
        raise ReleaseError("required_file_unsafe")
    return value.st_size


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, maximum: int = MAXIMUM_ARCHIVE_BYTES) -> str:
    require_regular_file(path, maximum)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_directory(root: Path, names: Iterable[str], code: str) -> None:
    expected = set(names)
    try:
        entries = list(root.iterdir())
    except OSError:
        raise ReleaseError(code) from None
    if {item.name for item in entries} != expected:
        raise ReleaseError(code)
    if any(item.is_symlink() or not item.is_file() for item in entries):
        raise ReleaseError(code)


def require_exact_fields(value: Any, names: Iterable[str], code: str) -> dict[str, Any]:
    expected = set(names)
    if not isinstance(value, dict) or set(value) != expected:
        raise ReleaseError(code)
    return value


def require_run(value: str, code: str) -> str:
    if RUN_ID.fullmatch(value) is None:
        raise ReleaseError(code)
    return value


def validate_scan(path: Path, field: str, code: str) -> None:
    value = read_json(path)
    results = value.get("Results")
    if (
        not isinstance(value.get("SchemaVersion"), int)
        or value["SchemaVersion"] < 2
        or not isinstance(results, list)
    ):
        raise ReleaseError(code)
    for result in results:
        if not isinstance(result, dict):
            raise ReleaseError(code)
        findings = result.get(field, [])
        if not isinstance(findings, list):
            raise ReleaseError(code)
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("Severity") in {
                "HIGH",
                "CRITICAL",
            }:
                raise ReleaseError(code)


def validate_sbom(path: Path, code: str) -> None:
    value = read_json(path)
    packages = value.get("packages")
    creation = value.get("creationInfo")
    if (
        value.get("spdxVersion") != "SPDX-2.3"
        or not isinstance(value.get("SPDXID"), str)
        or not value["SPDXID"].startswith("SPDXRef-")
        or not isinstance(value.get("documentNamespace"), str)
        or not value["documentNamespace"]
        or not isinstance(creation, dict)
        or not isinstance(creation.get("created"), str)
        or not creation["created"]
        or not isinstance(packages, list)
        or not packages
    ):
        raise ReleaseError(code)
    for package in packages:
        if (
            not isinstance(package, dict)
            or not isinstance(package.get("SPDXID"), str)
            or not package["SPDXID"].startswith("SPDXRef-")
            or not isinstance(package.get("name"), str)
            or not package["name"]
        ):
            raise ReleaseError(code)


def verify_candidate_directory(
    root: Path, commit: str, now: datetime
) -> dict[str, Any]:
    expected = {
        "latchway-candidate.json",
        "latchway-candidate.attestation.sigstore.json",
        *CANDIDATE.ARTIFACT_NAMES,
    }
    require_exact_directory(root, expected, "candidate_artifact_closure_invalid")
    if COMMIT.fullmatch(commit) is None:
        raise ReleaseError("candidate_commit_invalid")
    try:
        manifest = CANDIDATE.verify_manifest(
            root / "latchway-candidate.json",
            expected_commit=commit,
            expected_tag=TAG,
            expected_image=IMAGE_REPOSITORY,
            now=now,
        )
    except CANDIDATE.CandidateError as error:
        raise ReleaseError(str(error)) from error
    read_json(root / "latchway-candidate.attestation.sigstore.json")
    for architecture in ("amd64", "arm64"):
        validate_scan(
            root / f"latchway-linux-{architecture}-vulnerability.json",
            "Vulnerabilities",
            "candidate_vulnerability_scan_invalid",
        )
        validate_scan(
            root / f"latchway-linux-{architecture}-license.json",
            "Licenses",
            "candidate_license_scan_invalid",
        )
        validate_sbom(
            root / f"latchway-linux-{architecture}.spdx.json",
            "candidate_sbom_invalid",
        )
    return manifest


def read_archive(path: Path) -> tuple[dict[str, bytes], bytes]:
    require_regular_file(path, MAXIMUM_ARCHIVE_BYTES)
    archive_bytes = path.read_bytes()
    if archive_bytes[:8] != bytes.fromhex("1f8b080000000000"):
        raise ReleaseError("deployment_archive_not_deterministic")
    values: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != list(SIGNED_CAPTURE_FILES):
                raise ReleaseError("deployment_archive_closure_invalid")
            for member in members:
                relative = PurePosixPath(member.name)
                if (
                    not member.isfile()
                    or relative.as_posix() != member.name
                    or len(relative.parts) != 1
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mode != 0o644
                    or member.mtime != 0
                    or member.size <= 0
                    or member.size > MAXIMUM_JSON_BYTES
                ):
                    raise ReleaseError("deployment_archive_entry_unsafe")
                total += member.size
                if total > MAXIMUM_ARCHIVE_BYTES:
                    raise ReleaseError("deployment_archive_too_large")
                source = archive.extractfile(member)
                if source is None:
                    raise ReleaseError("deployment_archive_entry_missing")
                payload = source.read(MAXIMUM_JSON_BYTES + 1)
                if len(payload) != member.size:
                    raise ReleaseError("deployment_archive_entry_size_invalid")
                values[member.name] = payload
    except ReleaseError:
        raise
    except (OSError, tarfile.TarError):
        raise ReleaseError("deployment_archive_invalid") from None
    return values, archive_bytes


def deterministic_capture_archive(values: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name in CAPTURE_FILES:
                payload = values[name]
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def decode_json_bytes(value: bytes, code: str) -> dict[str, Any]:
    try:
        document = json.loads(value.decode("utf-8"), object_pairs_hook=strict_object)
    except ReleaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseError(code) from None
    if not isinstance(document, dict):
        raise ReleaseError(code)
    return document


def validate_capture_binding(
    values: Mapping[str, bytes],
    *,
    platform: str,
    commit: str,
    run_id: str,
    run_attempt: str,
    image: str,
    bundle_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = decode_json_bytes(values["manifest.json"], "deployment_manifest_invalid")
    binding = decode_json_bytes(
        values["latchway-deployment-binding.json"], "deployment_binding_invalid"
    )
    collector = {
        "repository": "Latchway/latchway",
        "workflow_ref": (
            "Latchway/latchway/.github/workflows/deployment-evidence.yml@refs/heads/main"
        ),
        "ref": "refs/heads/main",
        "sha": commit,
        "run_id": run_id,
        "run_attempt": int(run_attempt),
        "runner_environment": "github-hosted",
        "environment": f"deployment-evidence-{platform}",
    }
    manifest_fields = {
        "schema_version",
        "kind",
        "platform",
        "started_at",
        "finished_at",
        "core_commit",
        "core_release",
        "contract_version",
        "bundle_sha256",
        "oci_image_digest",
        "endpoint",
        "provider_resource_id",
        "collector",
        "observations",
    }
    require_exact_fields(manifest, manifest_fields, "deployment_manifest_fields_invalid")
    if (
        manifest["schema_version"] != 1
        or manifest["kind"] != "latchway_cloud_deployment_capture"
        or manifest["platform"] != platform
        or manifest["core_commit"] != commit
        or manifest["core_release"] != TAG
        or manifest["contract_version"] != VERSION
        or manifest["bundle_sha256"] != bundle_sha256
        or manifest["oci_image_digest"] != image
        or manifest["collector"] != collector
    ):
        raise ReleaseError("deployment_manifest_identity_mismatch")
    expected_observations = {
        name.removesuffix(".json"): {
            "path": name,
            "sha256": sha256_bytes(values[name]),
        }
        for name in CAPTURE_FILES
        if name != "manifest.json"
    }
    if manifest["observations"] != expected_observations:
        raise ReleaseError("deployment_observation_binding_invalid")

    binding_fields = {
        "schema_version",
        "kind",
        "platform",
        "candidate_commit",
        "core_release",
        "contract_version",
        "bundle_sha256",
        "oci_image_digest",
        "endpoint",
        "provider_resource_id",
        "collector",
        "candidate_archive",
        "raw_capture",
    }
    require_exact_fields(binding, binding_fields, "deployment_binding_fields_invalid")
    if (
        binding["schema_version"] != 1
        or binding["kind"] != "latchway_authenticated_deployment_capture"
        or binding["platform"] != platform
        or binding["candidate_commit"] != commit
        or binding["core_release"] != TAG
        or binding["contract_version"] != VERSION
        or binding["bundle_sha256"] != bundle_sha256
        or binding["oci_image_digest"] != image
        or binding["endpoint"] != manifest["endpoint"]
        or binding["provider_resource_id"] != manifest["provider_resource_id"]
        or binding["collector"] != collector
    ):
        raise ReleaseError("deployment_binding_identity_mismatch")

    unsigned_bytes = deterministic_capture_archive(values)
    expected_entries = [
        {
            "path": name,
            "sha256": sha256_bytes(values[name]),
            "size_bytes": len(values[name]),
        }
        for name in CAPTURE_FILES
    ]
    expected_archive = {
        "sha256": sha256_bytes(unsigned_bytes),
        "size_bytes": len(unsigned_bytes),
        "entries": expected_entries,
    }
    if binding["candidate_archive"] != expected_archive:
        raise ReleaseError("deployment_unsigned_archive_binding_invalid")
    raw = require_exact_fields(
        binding["raw_capture"], {"artifact", "files"}, "deployment_raw_binding_invalid"
    )
    if raw["artifact"] != (
        f"latchway-deployment-raw-{platform}-{commit}-{run_id}-{run_attempt}"
    ):
        raise ReleaseError("deployment_raw_artifact_identity_mismatch")
    raw_files = raw["files"]
    if not isinstance(raw_files, list) or len(raw_files) != len(RAW_CAPTURE_FILES):
        raise ReleaseError("deployment_raw_file_closure_invalid")
    observed_names: list[str] = []
    for item in raw_files:
        require_exact_fields(
            item, {"path", "sha256", "size_bytes"}, "deployment_raw_file_invalid"
        )
        path = item["path"]
        if (
            not isinstance(path, str)
            or PurePosixPath(path).as_posix() != path
            or any(part in ("", ".", "..") for part in PurePosixPath(path).parts)
            or not isinstance(item["sha256"], str)
            or SHA256.fullmatch(item["sha256"]) is None
            or not isinstance(item["size_bytes"], int)
            or isinstance(item["size_bytes"], bool)
            or not 0 < item["size_bytes"] <= MAXIMUM_JSON_BYTES
        ):
            raise ReleaseError("deployment_raw_file_invalid")
        observed_names.append(path)
    if tuple(sorted(observed_names)) != RAW_CAPTURE_FILES or len(set(observed_names)) != len(
        observed_names
    ):
        raise ReleaseError("deployment_raw_file_closure_invalid")
    return manifest, binding


def validate_deployment_capture(
    archive: Path,
    attestation: Path,
    *,
    platform: str,
    commit: str,
    run_id: str,
    run_attempt: str,
    image: str,
    bundle_sha256: str,
) -> dict[str, Any]:
    if platform not in DEPLOYMENT_ASSET_FILES:
        raise ReleaseError("deployment_platform_invalid")
    require_run(run_id, "deployment_run_id_invalid")
    require_run(run_attempt, "deployment_run_attempt_invalid")
    read_json(attestation)
    values, archive_bytes = read_archive(archive)
    manifest, _ = validate_capture_binding(
        values,
        platform=platform,
        commit=commit,
        run_id=run_id,
        run_attempt=run_attempt,
        image=image,
        bundle_sha256=bundle_sha256,
    )
    # Re-run the canonical platform validators over exact extracted bytes.  A
    # private temporary directory avoids trusting tar paths or archive.extract.
    import tempfile

    with tempfile.TemporaryDirectory(prefix=f"latchway-{platform}-release-") as temporary:
        root = Path(temporary)
        for name in CAPTURE_FILES:
            (root / name).write_bytes(values[name])
        try:
            verified_manifest, checks = DEPLOYMENT.validate_capture(root)
        except DEPLOYMENT.EvidenceError as error:
            raise ReleaseError(error.code) from error
        if verified_manifest != manifest or any(item.status != "passed" for item in checks):
            raise ReleaseError("deployment_capture_validation_failed")
    return {
        "platform": platform,
        "run_id": run_id,
        "run_attempt": int(run_attempt),
        "endpoint": manifest["endpoint"],
        "provider_resource_id": manifest["provider_resource_id"],
        "archive_sha256": sha256_bytes(archive_bytes),
        "attestation_sha256": sha256_file(attestation, MAXIMUM_JSON_BYTES),
    }


def release_title() -> str:
    return f"Latchway {TAG} — {PROFILE}"


def release_body(commit: str, image: str) -> str:
    return "\n".join(
        (
            f"Latchway {TAG} core release.",
            "",
            f"Release profile: {PROFILE}",
            "Profile status: incomplete until every required public package and registry check passes.",
            "Authenticated profile-wide publication readiness is not claimed by this core-only record.",
            f"Candidate commit: {commit}",
            f"Image: {image}",
            "Required deployment evidence: Docker Compose and Google Cloud Run passed for this exact image.",
            "",
            "Deferred evidence remains unverified. This release is not release-qualified, fully evidence-gated, or independently reviewed.",
        )
    )


def tag_message(commit: str, image: str) -> str:
    return "\n".join(
        (
            f"Latchway {TAG}",
            "",
            f"Release profile: {PROFILE}",
            f"Candidate commit: {commit}",
            f"Image: {image}",
        )
    )


def asset_entry(path: Path) -> dict[str, Any]:
    return {"path": path.name, "sha256": sha256_file(path)}


def copy_asset(source: Path, destination: Path) -> Path:
    require_regular_file(source, MAXIMUM_ARCHIVE_BYTES)
    target = destination / source.name
    if target.exists():
        raise ReleaseError("handoff_asset_collision")
    shutil.copyfile(source, target)
    target.chmod(0o600)
    return target


def policy_profile() -> dict[str, Any]:
    try:
        policy = RELEASE_PROFILE.validate_policy()
    except RELEASE_PROFILE.ProfileError as error:
        raise ReleaseError(error.code) from error
    profile = policy["profiles"][PROFILE]
    if profile["status_claim"] != "v1_profile_projection_passed_with_deferred_assurance":
        raise ReleaseError("single_maintainer_profile_identity_invalid")
    return profile


def prepare_handoff(args: argparse.Namespace, now: datetime) -> dict[str, Any]:
    if COMMIT.fullmatch(args.candidate_commit) is None:
        raise ReleaseError("candidate_commit_invalid")
    for value, code in (
        (args.candidate_run_id, "candidate_run_id_invalid"),
        (args.candidate_run_attempt, "candidate_run_attempt_invalid"),
        (args.compose_run_id, "compose_run_id_invalid"),
        (args.compose_run_attempt, "compose_run_attempt_invalid"),
        (args.cloud_run_run_id, "cloud_run_run_id_invalid"),
        (args.cloud_run_run_attempt, "cloud_run_run_attempt_invalid"),
    ):
        require_run(value, code)
    manifest = verify_candidate_directory(args.candidate_dir, args.candidate_commit, now)
    image = f"{IMAGE_REPOSITORY}@{manifest['image']['index_digest']}"
    bundle_sha256 = manifest["contract"]["bundle_sha256"]
    deployment_roots = {
        "compose": (args.compose_dir, args.compose_run_id, args.compose_run_attempt),
        "cloud_run": (
            args.cloud_run_dir,
            args.cloud_run_run_id,
            args.cloud_run_run_attempt,
        ),
    }
    deployments: dict[str, Any] = {}
    for platform, (root, run_id, run_attempt) in deployment_roots.items():
        expected = {
            f"{platform}.tar.gz",
            f"{platform}.attestation.json",
            "latchway-deployment-validation.json",
            "latchway-deployment-validation.json.junit.xml",
        }
        require_exact_directory(root, expected, "deployment_artifact_closure_invalid")
        diagnostic = read_json(root / "latchway-deployment-validation.json")
        if (
            diagnostic.get("verdict") != "passed"
            or diagnostic.get("platform") != platform
            or diagnostic.get("oci_image_digest") != image
        ):
            raise ReleaseError("deployment_diagnostic_invalid")
        require_regular_file(
            root / "latchway-deployment-validation.json.junit.xml", 1024 * 1024
        )
        deployments[platform] = validate_deployment_capture(
            root / f"{platform}.tar.gz",
            root / f"{platform}.attestation.json",
            platform=platform,
            commit=args.candidate_commit,
            run_id=run_id,
            run_attempt=run_attempt,
            image=image,
            bundle_sha256=bundle_sha256,
        )

    output = args.output_directory
    output.mkdir(parents=True, exist_ok=False)
    copied: list[Path] = []
    for name in sorted(
        {
            "latchway-candidate.json",
            "latchway-candidate.attestation.sigstore.json",
            *CANDIDATE.ARTIFACT_NAMES,
        }
    ):
        copied.append(copy_asset(args.candidate_dir / name, output))
    for platform, (root, _, _) in deployment_roots.items():
        for name in DEPLOYMENT_ASSET_FILES[platform]:
            copied.append(copy_asset(root / name, output))
    assets = [asset_entry(path) for path in sorted(copied, key=lambda item: item.name)]
    profile = policy_profile()
    record = {
        "schema_version": 1,
        "kind": "latchway_single_maintainer_v1_core_release",
        "profile": PROFILE,
        "profile_status": "incomplete",
        "core_publication_gate": "passed",
        "candidate_commit": args.candidate_commit,
        "tag": TAG,
        "version": VERSION,
        "image": {
            "repository": IMAGE_REPOSITORY,
            "index_digest": manifest["image"]["index_digest"],
            "coordinate": image,
            "platforms": manifest["image"]["platforms"],
        },
        "release_policy": {
            "mode": PROFILE,
            "independent_reviewer_required": False,
            "strict_full_controls_satisfied": False,
            "environment_policy_ids": PROFILE_ENVIRONMENT_POLICY_IDS,
        },
        "candidate_run": {
            "run_id": args.candidate_run_id,
            "run_attempt": int(args.candidate_run_attempt),
        },
        "deployment_evidence": deployments,
        "supply_chain": {
            "multi_arch_image_verified": True,
            "vulnerability_scan_verified": True,
            "license_scan_verified": True,
            "sbom_verified": True,
            "signature_verified": True,
            "provenance_verified": True,
        },
        "github_release": {
            "title": release_title(),
            "body": release_body(args.candidate_commit, image),
            "tag_message": tag_message(args.candidate_commit, image),
        },
        "claims": {
            "release_qualified": False,
            "fully_evidence_gated": False,
            "independently_reviewed": False,
        },
        "deferred_evidence": profile["deferred_evidence"],
        "assets": assets,
    }
    write_json(output / "latchway-single-maintainer-v1.json", record)
    hashed = sorted((*copied, output / "latchway-single-maintainer-v1.json"), key=lambda item: item.name)
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in hashed),
        encoding="utf-8",
    )
    return record


def verify_record_shape(
    record: dict[str, Any], args: argparse.Namespace, manifest: Mapping[str, Any]
) -> None:
    expected_fields = {
        "schema_version",
        "kind",
        "profile",
        "profile_status",
        "core_publication_gate",
        "candidate_commit",
        "tag",
        "version",
        "image",
        "release_policy",
        "candidate_run",
        "deployment_evidence",
        "supply_chain",
        "github_release",
        "claims",
        "deferred_evidence",
        "assets",
    }
    require_exact_fields(record, expected_fields, "release_record_fields_invalid")
    image = f"{IMAGE_REPOSITORY}@{manifest['image']['index_digest']}"
    profile = policy_profile()
    if (
        record["schema_version"] != 1
        or record["kind"] != "latchway_single_maintainer_v1_core_release"
        or record["profile"] != PROFILE
        or record["profile_status"] != "incomplete"
        or record["core_publication_gate"] != "passed"
        or record["candidate_commit"] != args.candidate_commit
        or record["tag"] != TAG
        or record["version"] != VERSION
        or record["image"]
        != {
            "repository": IMAGE_REPOSITORY,
            "index_digest": manifest["image"]["index_digest"],
            "coordinate": image,
            "platforms": manifest["image"]["platforms"],
        }
        or record["release_policy"]
        != {
            "mode": PROFILE,
            "independent_reviewer_required": False,
            "strict_full_controls_satisfied": False,
            "environment_policy_ids": PROFILE_ENVIRONMENT_POLICY_IDS,
        }
        or record["candidate_run"]
        != {
            "run_id": args.candidate_run_id,
            "run_attempt": int(args.candidate_run_attempt),
        }
        or record["supply_chain"]
        != {
            "multi_arch_image_verified": True,
            "vulnerability_scan_verified": True,
            "license_scan_verified": True,
            "sbom_verified": True,
            "signature_verified": True,
            "provenance_verified": True,
        }
        or record["github_release"]
        != {
            "title": release_title(),
            "body": release_body(args.candidate_commit, image),
            "tag_message": tag_message(args.candidate_commit, image),
        }
        or record["claims"]
        != {
            "release_qualified": False,
            "fully_evidence_gated": False,
            "independently_reviewed": False,
        }
        or record["deferred_evidence"] != profile["deferred_evidence"]
    ):
        raise ReleaseError("release_record_identity_invalid")


def verify_checksums(root: Path, expected_names: set[str]) -> None:
    sums_path = root / "SHA256SUMS"
    require_regular_file(sums_path, 1024 * 1024)
    try:
        lines = sums_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        raise ReleaseError("handoff_checksums_invalid") from None
    observed: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})", line)
        if match is None or match.group(2) in observed:
            raise ReleaseError("handoff_checksums_invalid")
        observed[match.group(2)] = match.group(1)
    if set(observed) != expected_names or list(observed) != sorted(observed):
        raise ReleaseError("handoff_checksums_invalid")
    for name, digest in observed.items():
        if sha256_file(root / name) != digest:
            raise ReleaseError("handoff_checksum_mismatch")


def verify_handoff(args: argparse.Namespace, now: datetime) -> dict[str, Any]:
    root = args.handoff_directory
    evidence_names = {
        "latchway-candidate.json",
        "latchway-candidate.attestation.sigstore.json",
        *CANDIDATE.ARTIFACT_NAMES,
        *(name for pair in DEPLOYMENT_ASSET_FILES.values() for name in pair),
    }
    expected = {"SHA256SUMS", "latchway-single-maintainer-v1.json", *evidence_names}
    require_exact_directory(root, expected, "handoff_artifact_closure_invalid")
    verify_checksums(root, expected - {"SHA256SUMS"})

    # Candidate validation expects a closed directory, so bind only its fixed
    # assets in a private temporary view rather than relaxing its closure.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="latchway-release-candidate-") as temporary:
        candidate_root = Path(temporary)
        for name in {
            "latchway-candidate.json",
            "latchway-candidate.attestation.sigstore.json",
            *CANDIDATE.ARTIFACT_NAMES,
        }:
            shutil.copyfile(root / name, candidate_root / name)
        manifest = verify_candidate_directory(candidate_root, args.candidate_commit, now)
    image = f"{IMAGE_REPOSITORY}@{manifest['image']['index_digest']}"
    bundle_sha256 = manifest["contract"]["bundle_sha256"]
    expected_deployments: dict[str, Any] = {}
    for platform, run_id, run_attempt in (
        ("compose", args.compose_run_id, args.compose_run_attempt),
        ("cloud_run", args.cloud_run_run_id, args.cloud_run_run_attempt),
    ):
        expected_deployments[platform] = validate_deployment_capture(
            root / f"{platform}.tar.gz",
            root / f"{platform}.attestation.json",
            platform=platform,
            commit=args.candidate_commit,
            run_id=run_id,
            run_attempt=run_attempt,
            image=image,
            bundle_sha256=bundle_sha256,
        )
    record = read_json(root / "latchway-single-maintainer-v1.json")
    verify_record_shape(record, args, manifest)
    if record["deployment_evidence"] != expected_deployments:
        raise ReleaseError("release_record_deployment_evidence_invalid")
    assets = record["assets"]
    if not isinstance(assets, list) or len(assets) != len(evidence_names):
        raise ReleaseError("release_record_assets_invalid")
    observed: dict[str, str] = {}
    for item in assets:
        require_exact_fields(item, {"path", "sha256"}, "release_record_asset_invalid")
        name = item["path"]
        digest = item["sha256"]
        if (
            not isinstance(name, str)
            or SAFE_FILE.fullmatch(name) is None
            or name in observed
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or sha256_file(root / name) != digest
        ):
            raise ReleaseError("release_record_asset_invalid")
        observed[name] = digest
    if set(observed) != evidence_names or list(observed) != sorted(observed):
        raise ReleaseError("release_record_assets_invalid")
    return record


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-run-id", required=True)
    parser.add_argument("--candidate-run-attempt", required=True)
    parser.add_argument("--compose-run-id", required=True)
    parser.add_argument("--compose-run-attempt", required=True)
    parser.add_argument("--cloud-run-run-id", required=True)
    parser.add_argument("--cloud-run-run-attempt", required=True)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="verify inputs and build the closed mutation handoff")
    common_arguments(prepare)
    prepare.add_argument("--candidate-dir", type=Path, required=True)
    prepare.add_argument("--compose-dir", type=Path, required=True)
    prepare.add_argument("--cloud-run-dir", type=Path, required=True)
    prepare.add_argument("--output-directory", type=Path, required=True)
    verify = commands.add_parser("verify-handoff", help="revalidate an exact closed handoff")
    common_arguments(verify)
    verify.add_argument("--handoff-directory", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if args.command == "prepare":
            record = prepare_handoff(args, now)
        else:
            record = verify_handoff(args, now)
    except (ReleaseError, OSError) as error:
        code = error.code if isinstance(error, ReleaseError) else "release_io_failed"
        print(f"single-maintainer release failed: {code}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
