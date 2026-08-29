#!/usr/bin/env python3
"""Independently validate byte-bound public registry proof in release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
MAXIMUM = 32 * 1024 * 1024


class ProofError(Exception):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofError("json_duplicate_key")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= MAXIMUM:
            raise ProofError("proof_file_invalid")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except ProofError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ProofError("proof_json_invalid") from None
    if not isinstance(value, dict):
        raise ProofError("proof_json_invalid")
    return value


def safe_path(root: Path, raw: Any) -> Path:
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\\" in raw:
        raise ProofError("proof_path_invalid")
    relative = PurePosixPath(raw)
    if relative.as_posix() != raw or any(part in ("", ".", "..") for part in relative.parts):
        raise ProofError("proof_path_invalid")
    try:
        resolved_root = root.resolve(strict=True)
        path = (resolved_root / Path(*relative.parts)).resolve(strict=True)
        path.relative_to(resolved_root)
    except (OSError, ValueError):
        raise ProofError("proof_path_invalid") from None
    if path.is_symlink() or not path.is_file():
        raise ProofError("proof_path_invalid")
    return path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def exact_artifact(document: dict[str, Any], suffix: str) -> dict[str, str]:
    artifacts = document.get("artifacts")
    matches = [item for item in artifacts if isinstance(item, dict) and str(item.get("path", "")).endswith(suffix)] if isinstance(artifacts, list) else []
    if len(matches) != 1 or set(matches[0]) != {"path", "sha256"}:
        raise ProofError("registry_proof_artifact_missing")
    return matches[0]


def require_hash(value: Any) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ProofError("registry_proof_hash_invalid")
    return value


def validate_npm(value: dict[str, Any], package: str, coordinate: dict[str, Any]) -> None:
    evidence = value.get("reviewed_package_evidence")
    reproducibility = value.get("reviewed_build_reproducibility")
    provenance = value.get("provenance")
    if (
        value.get("schema_version") != 1
        or value.get("registry") != "npm"
        or value.get("package") != package
        or value.get("version") != coordinate.get("version")
        or value.get("source_commit") != coordinate.get("commit")
        or value.get("registry_tarball_byte_identical") is not True
        or value.get("registry_signatures_verified") is not True
        or not isinstance(evidence, dict)
        or evidence.get("schema_version") != 1
        or evidence.get("package") != package
        or evidence.get("version") != coordinate.get("version")
        or evidence.get("sha256") != value.get("sha256")
        or evidence.get("integrity") != value.get("integrity")
        or evidence.get("double_pack_byte_identical") is not True
        or not isinstance(reproducibility, dict)
        or reproducibility.get("schema_version") != 1
        or reproducibility.get("identical") is not True
        or not isinstance(provenance, dict)
        or provenance.get("source_commit") != coordinate.get("commit")
        or provenance.get("workflow") != ".github/workflows/release.yml"
        or provenance.get("workflow_ref") != "refs/heads/main"
        or provenance.get("npm_signature_audit") != "passed"
        or not isinstance(provenance.get("run_id"), int)
        or isinstance(provenance.get("run_id"), bool)
        or provenance["run_id"] < 1
        or not isinstance(provenance.get("run_attempt"), int)
        or isinstance(provenance.get("run_attempt"), bool)
        or provenance["run_attempt"] < 1
        or not isinstance(provenance.get("attestations"), dict)
    ):
        raise ProofError("npm_byte_proof_invalid")
    require_hash(value.get("sha256"))
    require_hash(reproducibility.get("sha256"))
    require_hash(provenance.get("attestations_sha256"))
    normalized_attestations = (
        json.dumps(provenance["attestations"], indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if hashlib.sha256(normalized_attestations).hexdigest() != provenance["attestations_sha256"]:
        raise ProofError("npm_attestation_document_hash_invalid")
    if value.get("registry_integrity") != value.get("integrity") or not str(value.get("integrity", "")).startswith("sha512-"):
        raise ProofError("npm_integrity_proof_invalid")
    assets = value.get("release_asset_digests")
    attestations = value.get("release_asset_attestation_verifications")
    expected_asset_names = {
        str(evidence.get("tarball")),
        "package-evidence.json",
        "build-reproducibility.json",
    }
    if not isinstance(assets, dict) or set(assets) != expected_asset_names or any(
        not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
        for item in assets.values()
    ) or assets.get(evidence.get("tarball")) != f"sha256:{value.get('sha256')}":
        raise ProofError("npm_release_asset_proof_invalid")
    if (
        not isinstance(attestations, dict)
        or set(attestations) != expected_asset_names
        or any(not verification for verification in attestations.values())
    ):
        raise ProofError("npm_release_asset_attestation_invalid")


def expected_maven_paths(version: str) -> set[str]:
    return {
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


def validate_maven(maven: dict[str, Any], version: str) -> None:
    files = maven.get("files") if isinstance(maven, dict) else None
    expected_paths = expected_maven_paths(version)
    if (
        maven.get("schema_version") != 1
        or maven.get("registry") != "maven_central"
        or maven.get("version") != version
        or maven.get("reviewed_repository") is not True
        or maven.get("primary_artifacts_byte_identical") is not True
        or maven.get("checksum_files_byte_identical") is not True
        or maven.get("signature_files_present") is not True
        or maven.get("signatures_cryptographically_verified") is not True
        or not maven.get("release_asset_attestation_verification")
        or re.fullmatch(r"[0-9A-F]{40}", str(maven.get("signing_fingerprint", ""))) is None
        or SHA256.fullmatch(str(maven.get("reviewed_public_key_sha256", ""))) is None
        or not isinstance(files, list)
        or len(files) != len(expected_paths)
        or {item.get("path") for item in files if isinstance(item, dict)} != expected_paths
        or any(
            not isinstance(item, dict)
            or item.get("checksums_byte_identical") is not True
            or not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or item["bytes"] < 1
            or SHA256.fullmatch(str(item.get("sha256", ""))) is None
            or SHA256.fullmatch(str(item.get("signature_sha256", ""))) is None
            or not isinstance(item.get("signature_armored"), str)
            or not item["signature_armored"].startswith("-----BEGIN PGP SIGNATURE-----")
            or hashlib.sha256(item["signature_armored"].encode("ascii")).hexdigest()
            != item.get("signature_sha256")
            for item in files
        )
    ):
        raise ProofError("maven_byte_proof_invalid")


def validate(root: Path, candidate_commit: str, release_tag: str) -> dict[str, Any]:
    if COMMIT.fullmatch(candidate_commit) is None or TAG.fullmatch(release_tag) is None:
        raise ProofError("expected_identity_invalid")
    manifest = read_json(root / "aggregate-manifest.json")
    document = read_json(root / "public_registries.json")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "latchway_external_evidence_aggregate"
        or manifest.get("scope") != "release"
        or manifest.get("candidate_commit") != candidate_commit
        or "public_registries" not in manifest.get("domains", [])
        or document.get("schema_version") != 1
        or document.get("kind") != "latchway_cross_repository_external_evidence"
        or document.get("domain") != "public_registries"
        or document.get("status") != "passed"
        or document.get("core_commit") != candidate_commit
        or document.get("core_release") != release_tag
        or not isinstance(document.get("repositories"), dict)
        or not isinstance(document.get("claims"), dict)
        or not all(value is True for value in document["claims"].values())
    ):
        raise ProofError("registry_domain_identity_invalid")
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list) or not manifest_files:
        raise ProofError("aggregate_file_manifest_invalid")
    manifest_hashes: dict[str, str] = {}
    for item in manifest_files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ProofError("aggregate_file_manifest_invalid")
        raw_path, expected = item["path"], require_hash(item["sha256"])
        if raw_path in manifest_hashes:
            raise ProofError("aggregate_file_manifest_invalid")
        path = safe_path(root, raw_path)
        if digest(path) != expected:
            raise ProofError("aggregate_file_hash_mismatch")
        manifest_hashes[raw_path] = expected
    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    expected_files = set(manifest_hashes) | {
        "aggregate-manifest.json",
        "aggregate-manifest.attestation.sigstore.json",
    }
    if actual_files != expected_files or any(path.is_symlink() for path in root.rglob("*")):
        raise ProofError("aggregate_tree_not_exact")
    proofs: dict[str, dict[str, Any]] = {}
    suffixes = {
        "javascript": "artifacts--registry-npm-javascript--tool-output.json",
        "react_native": "artifacts--registry-npm-react-native--tool-output.json",
        "ios": "artifacts--registry-cocoapods--tool-output.json",
        "android": "artifacts--registry-maven-central--tool-output.json",
    }
    for name, suffix in suffixes.items():
        artifact = exact_artifact(document, suffix)
        path = safe_path(root, artifact["path"])
        expected = require_hash(artifact["sha256"])
        if digest(path) != expected or manifest_hashes.get(artifact["path"]) != expected:
            raise ProofError("registry_proof_artifact_hash_mismatch")
        proofs[name] = read_json(path)
    repositories = document["repositories"]
    validate_npm(proofs["javascript"], "@latchway/client", repositories["javascript"])
    validate_npm(proofs["react_native"], "@latchway/react-native", repositories["react_native"])
    cocoa = proofs["ios"]
    if (
        cocoa.get("schema_version") != 1
        or cocoa.get("registry") != "cocoapods"
        or cocoa.get("version") != repositories["ios"].get("version")
        or cocoa.get("published_spec_equals_reviewed_podspec") is not True
        or cocoa.get("reviewed_source_archive_equals_release_tag") is not True
        or not cocoa.get("release_asset_attestation_verification")
        or cocoa.get("source", {}).get("tag") != repositories["ios"].get("tag")
    ):
        raise ProofError("cocoapods_byte_proof_invalid")
    require_hash(cocoa.get("published_spec_sha256"))
    require_hash(cocoa.get("reviewed_source_archive_sha256"))
    maven = proofs["android"]
    android_version = repositories["android"].get("version")
    if not isinstance(android_version, str):
        raise ProofError("maven_byte_proof_invalid")
    validate_maven(maven, android_version)
    return {
        "schema_version": 1,
        "kind": "latchway_public_registry_byte_proof_verification",
        "candidate_commit": candidate_commit,
        "release_tag": release_tag,
        "status": "passed",
        "proofs": {
            name: {"path": exact_artifact(document, suffixes[name])["path"], "sha256": digest(safe_path(root, exact_artifact(document, suffixes[name])["path"]))}
            for name in sorted(suffixes)
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = validate(arguments.evidence_root, arguments.candidate_commit, arguments.release_tag)
        if arguments.output.exists() or arguments.output.is_symlink():
            raise ProofError("output_exists")
        arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ProofError) as error:
        print(f"public registry proof rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
