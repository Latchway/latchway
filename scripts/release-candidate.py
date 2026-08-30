#!/usr/bin/env python3
"""Create or verify the hash-bound manifest for an immutable OCI candidate."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CORE_VERSION = (
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
)
TAG = re.compile(rf"^v{CORE_VERSION}(?:-rc\.(?:[1-9][0-9]*))?$")
IMAGE = re.compile(r"^ghcr\.io/latchway/latchway$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAXIMUM_AGE = timedelta(days=7)
PLATFORMS = ("linux/amd64", "linux/arm64")
ARTIFACT_NAMES = (
    "latchway-contract.tar.gz",
    "latchway-linux-amd64.spdx.json",
    "latchway-linux-arm64.spdx.json",
    "latchway-linux-amd64-vulnerability.json",
    "latchway-linux-arm64-vulnerability.json",
    "latchway-linux-amd64-license.json",
    "latchway-linux-arm64-license.json",
)


class CandidateError(Exception):
    """A stable, redaction-safe candidate-manifest failure."""


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise CandidateError("candidate_artifact_missing")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    def strict(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CandidateError("candidate_json_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict
        )
    except CandidateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise CandidateError("candidate_json_invalid") from None
    if not isinstance(value, dict):
        raise CandidateError("candidate_json_invalid")
    return value


def parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or CANONICAL_UTC.fullmatch(value) is None:
        raise CandidateError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise CandidateError(code) from None


def validate_identity(commit: str, tag: str, image: str) -> None:
    if COMMIT.fullmatch(commit) is None:
        raise CandidateError("candidate_commit_invalid")
    if TAG.fullmatch(tag) is None:
        raise CandidateError("candidate_tag_invalid")
    if IMAGE.fullmatch(image) is None:
        raise CandidateError("candidate_image_repository_invalid")


def build_manifest(
    *,
    commit: str,
    tag: str,
    image: str,
    index_digest: str,
    platform_digests: Mapping[str, str],
    artifacts: Mapping[str, Path],
    now: datetime,
) -> dict[str, Any]:
    validate_identity(commit, tag, image)
    if DIGEST.fullmatch(index_digest) is None or set(platform_digests) != set(
        PLATFORMS
    ):
        raise CandidateError("candidate_image_digest_invalid")
    if any(DIGEST.fullmatch(platform_digests[name]) is None for name in PLATFORMS):
        raise CandidateError("candidate_image_digest_invalid")
    if len(set(platform_digests.values())) != len(PLATFORMS):
        raise CandidateError("candidate_platform_digests_not_distinct")
    if set(artifacts) != set(ARTIFACT_NAMES):
        raise CandidateError("candidate_artifact_set_invalid")

    protocol = load_json(ROOT / "api/protocol-version.json")
    contract_version = protocol.get("contract_version")
    released_at_value = protocol.get("released_at")
    released_at = parse_time(released_at_value, "contract_released_at_invalid")
    bundle = protocol.get("bundle")
    if (
        protocol.get("contract_status") != "released"
        or not isinstance(contract_version, str)
        or not isinstance(bundle, dict)
        or bundle.get("file_name") != f"latchway-contract-{contract_version}.tar.gz"
    ):
        raise CandidateError("candidate_contract_not_released")
    if released_at > now or now - released_at > MAXIMUM_AGE:
        raise CandidateError("candidate_contract_time_invalid")
    if tag[1:] != load_json(ROOT / "web/console/package.json").get("version"):
        raise CandidateError("candidate_version_mismatch")

    artifact_entries = [
        {"path": name, "sha256": sha256_file(artifacts[name])}
        for name in ARTIFACT_NAMES
    ]
    contract_entry = next(
        entry for entry in artifact_entries if entry["path"] == "latchway-contract.tar.gz"
    )
    return {
        "schema_version": 1,
        "kind": "latchway_release_candidate",
        "status": "passed",
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidate_commit": commit,
        "intended_tag": tag,
        "version": tag[1:],
        "contract": {
            "version": contract_version,
            "status": "released",
            "released_at": released_at_value,
            "bundle_file_name": bundle["file_name"],
            "bundle_sha256": contract_entry["sha256"],
        },
        "image": {
            "repository": image,
            "index_digest": index_digest,
            "platforms": {
                platform: platform_digests[platform] for platform in PLATFORMS
            },
        },
        "artifacts": artifact_entries,
    }


def safe_artifact_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return path.as_posix() == value and len(path.parts) == 1 and path.name == value


def verify_manifest(
    path: Path,
    *,
    expected_commit: str,
    expected_tag: str,
    expected_image: str,
    now: datetime,
) -> dict[str, Any]:
    validate_identity(expected_commit, expected_tag, expected_image)
    document = load_json(path)
    expected_fields = {
        "schema_version",
        "kind",
        "status",
        "created_at",
        "candidate_commit",
        "intended_tag",
        "version",
        "contract",
        "image",
        "artifacts",
    }
    if set(document) != expected_fields:
        raise CandidateError("candidate_manifest_fields_invalid")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "latchway_release_candidate"
        or document.get("status") != "passed"
        or document.get("candidate_commit") != expected_commit
        or document.get("intended_tag") != expected_tag
        or document.get("version") != expected_tag[1:]
    ):
        raise CandidateError("candidate_manifest_identity_mismatch")

    created_at = parse_time(document.get("created_at"), "candidate_created_at_invalid")
    if created_at > now or now - created_at > MAXIMUM_AGE:
        raise CandidateError("candidate_created_at_invalid")
    contract = document.get("contract")
    if not isinstance(contract, dict) or set(contract) != {
        "version",
        "status",
        "released_at",
        "bundle_file_name",
        "bundle_sha256",
    }:
        raise CandidateError("candidate_contract_invalid")
    released_at = parse_time(contract.get("released_at"), "contract_released_at_invalid")
    version = contract.get("version")
    if (
        contract.get("status") != "released"
        or not isinstance(version, str)
        or contract.get("bundle_file_name") != f"latchway-contract-{version}.tar.gz"
        or not isinstance(contract.get("bundle_sha256"), str)
        or SHA256.fullmatch(contract["bundle_sha256"]) is None
        or released_at > created_at
        or now - released_at > MAXIMUM_AGE
    ):
        raise CandidateError("candidate_contract_invalid")

    image = document.get("image")
    if not isinstance(image, dict) or set(image) != {
        "repository",
        "index_digest",
        "platforms",
    }:
        raise CandidateError("candidate_image_invalid")
    platforms = image.get("platforms")
    if (
        image.get("repository") != expected_image
        or not isinstance(image.get("index_digest"), str)
        or DIGEST.fullmatch(image["index_digest"]) is None
        or not isinstance(platforms, dict)
        or set(platforms) != set(PLATFORMS)
        or any(not isinstance(value, str) or DIGEST.fullmatch(value) is None for value in platforms.values())
        or len(set(platforms.values())) != len(PLATFORMS)
    ):
        raise CandidateError("candidate_image_invalid")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_NAMES):
        raise CandidateError("candidate_artifacts_invalid")
    artifact_root = path.resolve().parent
    seen: set[str] = set()
    hashes: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise CandidateError("candidate_artifacts_invalid")
        relative = artifact.get("path")
        expected_hash = artifact.get("sha256")
        if (
            not safe_artifact_path(relative)
            or relative in seen
            or not isinstance(expected_hash, str)
            or SHA256.fullmatch(expected_hash) is None
        ):
            raise CandidateError("candidate_artifacts_invalid")
        seen.add(relative)
        artifact_path = artifact_root / relative
        if sha256_file(artifact_path) != expected_hash:
            raise CandidateError("candidate_artifact_hash_mismatch")
        hashes[relative] = expected_hash
    if seen != set(ARTIFACT_NAMES):
        raise CandidateError("candidate_artifact_set_invalid")
    if hashes["latchway-contract.tar.gz"] != contract["bundle_sha256"]:
        raise CandidateError("candidate_contract_bundle_hash_mismatch")
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--create", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--image", default="ghcr.io/latchway/latchway")
    parser.add_argument("--index-digest")
    parser.add_argument("--amd64-digest")
    parser.add_argument("--arm64-digest")
    parser.add_argument("--contract-bundle", type=Path)
    parser.add_argument("--sbom-amd64", type=Path)
    parser.add_argument("--sbom-arm64", type=Path)
    parser.add_argument("--vulnerability-amd64", type=Path)
    parser.add_argument("--vulnerability-arm64", type=Path)
    parser.add_argument("--license-amd64", type=Path)
    parser.add_argument("--license-arm64", type=Path)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if arguments.create:
            required = (
                arguments.index_digest,
                arguments.amd64_digest,
                arguments.arm64_digest,
                arguments.contract_bundle,
                arguments.sbom_amd64,
                arguments.sbom_arm64,
                arguments.vulnerability_amd64,
                arguments.vulnerability_arm64,
                arguments.license_amd64,
                arguments.license_arm64,
            )
            if any(value is None for value in required):
                raise CandidateError("candidate_create_arguments_missing")
            document = build_manifest(
                commit=arguments.commit,
                tag=arguments.tag,
                image=arguments.image,
                index_digest=arguments.index_digest,
                platform_digests={
                    "linux/amd64": arguments.amd64_digest,
                    "linux/arm64": arguments.arm64_digest,
                },
                artifacts={
                    "latchway-contract.tar.gz": arguments.contract_bundle,
                    "latchway-linux-amd64.spdx.json": arguments.sbom_amd64,
                    "latchway-linux-arm64.spdx.json": arguments.sbom_arm64,
                    "latchway-linux-amd64-vulnerability.json": arguments.vulnerability_amd64,
                    "latchway-linux-arm64-vulnerability.json": arguments.vulnerability_arm64,
                    "latchway-linux-amd64-license.json": arguments.license_amd64,
                    "latchway-linux-arm64-license.json": arguments.license_arm64,
                },
                now=now,
            )
            arguments.manifest.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        else:
            document = verify_manifest(
                arguments.manifest,
                expected_commit=arguments.commit,
                expected_tag=arguments.tag,
                expected_image=arguments.image,
                now=now,
            )
    except (CandidateError, OSError) as error:
        code = str(error) if isinstance(error, CandidateError) else "candidate_write_failed"
        print(f"release candidate failed: {code}", file=sys.stderr)
        return 1
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
