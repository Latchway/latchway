#!/usr/bin/env python3
"""Independently validate byte-bound public registry proof in release evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping


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


def decode_retained(envelope: Any, expected_name: str) -> bytes:
    if (
        not isinstance(envelope, dict)
        or envelope.get("name") != expected_name
        or not isinstance(envelope.get("bytes"), int)
        or isinstance(envelope.get("bytes"), bool)
        or not 1 <= envelope["bytes"] <= MAXIMUM
        or require_hash(envelope.get("sha256")) is None
        or envelope.get("release_digest") != f"sha256:{envelope['sha256']}"
        or not isinstance(envelope.get("content_base64"), str)
    ):
        raise ProofError("retained_registry_evidence_invalid")
    try:
        payload = base64.b64decode(envelope["content_base64"], validate=True)
    except (binascii.Error, ValueError):
        raise ProofError("retained_registry_evidence_invalid") from None
    if len(payload) != envelope["bytes"] or hashlib.sha256(payload).hexdigest() != envelope["sha256"]:
        raise ProofError("retained_registry_evidence_invalid")
    return payload


def load_retained_json(envelope: Any, expected_name: str) -> dict[str, Any]:
    try:
        value = json.loads(
            decode_retained(envelope, expected_name).decode("utf-8"),
            object_pairs_hook=strict_object,
        )
    except ProofError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProofError("retained_registry_evidence_invalid") from None
    if not isinstance(value, dict):
        raise ProofError("retained_registry_evidence_invalid")
    return value


def expected_npm_release_assets(package: str, version: str) -> tuple[set[str], str]:
    if package == "@latchway/client":
        tarball = f"latchway-client-{version}.tgz"
        return {
            tarball, "SHA256SUMS", "build-reproducibility.json", "contract-evidence.json",
            "package-evidence.json", "post-publish-evidence.json", "publish-input-evidence.json",
            "release-candidate-evidence.json", "tag-evidence.json", "npm-registry-version.json",
            "npm-registry-view.json", "npm-attestations.json", "npm-audit-signatures.json",
            "npm-registry-evidence-manifest.json",
        }, tarball
    if package == "@latchway/react-native":
        tarball = f"latchway-react-native-{version}.tgz"
        return {
            tarball, f"{tarball}.sha256", "package-evidence.json", "build-reproducibility.json",
            "published-dependency-evidence.json", "npm-registry-version.json",
            "npm-registry-view.json", "npm-attestations.json", "npm-audit-signatures.json",
            "npm-registry-evidence-manifest.json", "post-publish-evidence.json",
        }, tarball
    raise ProofError("npm_package_invalid")


def validate_rn_published_dependencies(
    value: Any, repositories: Mapping[str, Mapping[str, Any]]
) -> None:
    dependencies = value.get("dependencies") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "kind", "dependencies"}
        or value.get("schema_version") != 1
        or value.get("kind") != "latchway_react_native_published_dependency_evidence"
        or not isinstance(dependencies, dict)
        or set(dependencies) != {"core", "javascript", "ios", "android"}
    ):
        raise ProofError("rn_dependency_evidence_invalid")
    core = repositories.get("core", {})
    if dependencies["core"] != {
        "repository": "https://github.com/Latchway/latchway",
        "source_commit": core.get("commit"),
        "release_tag": core.get("tag"),
    }:
        raise ProofError("rn_dependency_evidence_invalid")
    names_by_id = {
        "javascript": "latchway-js",
        "ios": "latchway-ios-sdk",
        "android": "latchway-android",
    }
    for repository_id, repository_name in names_by_id.items():
        coordinate = repositories.get(repository_id, {})
        summary = dependencies.get(repository_id)
        if not isinstance(summary, dict) or set(summary) != {
            "repository", "release_tag", "source_commit",
            "github_release_immutable", "github_release_attestation",
            "release_assets", "public_registry",
        }:
            raise ProofError("rn_dependency_evidence_invalid")
        assets = summary.get("release_assets")
        registry = summary.get("public_registry")
        version = coordinate.get("version")
        if (
            not isinstance(assets, dict)
            or not isinstance(registry, dict)
            or not isinstance(version, str)
        ):
            raise ProofError("rn_dependency_evidence_invalid")
        if repository_id == "javascript":
            fixed, _ = expected_npm_release_assets("@latchway/client", version)
            adoptions = {
                name for name in assets
                if re.fullmatch(r"npm-release-adoption-[1-9][0-9]*-[1-9][0-9]*\.json", name)
            }
            exact_names = fixed | adoptions
            if not adoptions:
                raise ProofError("rn_dependency_evidence_invalid")
        elif repository_id == "ios":
            archive = f"latchway-ios-sdk-{version}.tar.gz"
            exact_names = {
                archive, f"{archive}.sha256", "cocoapods-published-podspec.json",
                "cocoapods-reviewed-podspec.json", "cocoapods-release-evidence.json",
                "cocoapods-release-evidence.SHA256SUMS",
            }
        else:
            exact_names = {
                f"latchway-android-{version}-maven-repository.zip",
                f"latchway-android-{version}-central-portal.zip",
                "SHA256SUMS", "github-release-tag-binding.json",
                "latchway-maven-signing-public-key.asc",
                "maven-central-upload-intent.json", "maven-central-deployment.json",
                "maven-central-deployment-status.json",
                "maven-central-release-evidence.json",
            }
        if (
            summary.get("repository") != f"https://github.com/Latchway/{repository_name}"
            or summary.get("release_tag") != coordinate.get("tag")
            or summary.get("source_commit") != coordinate.get("commit")
            or summary.get("github_release_immutable") is not True
            or not summary.get("github_release_attestation")
            or set(assets) != exact_names
        ):
            raise ProofError("rn_dependency_evidence_invalid")
        for asset in assets.values():
            if (
                not isinstance(asset, dict)
                or set(asset) != {"bytes", "sha256", "immutable_attestation"}
                or not isinstance(asset.get("bytes"), int)
                or isinstance(asset.get("bytes"), bool)
                or asset["bytes"] < 1
                or SHA256.fullmatch(str(asset.get("sha256"))) is None
                or not asset.get("immutable_attestation")
            ):
                raise ProofError("rn_dependency_evidence_invalid")
        expected_registry = {
            "javascript": "npm", "ios": "cocoapods", "android": "maven_central"
        }[repository_id]
        if registry.get("registry") != expected_registry:
            raise ProofError("rn_dependency_evidence_invalid")
        if repository_id == "javascript" and (
            not str(registry.get("integrity", "")).startswith("sha512-")
            or SHA256.fullmatch(str(registry.get("tarball_sha256"))) is None
            or not isinstance(registry.get("provenance_run_id"), int)
            or not isinstance(registry.get("provenance_run_attempt"), int)
        ):
            raise ProofError("rn_dependency_evidence_invalid")
        if repository_id == "ios" and any(
            SHA256.fullmatch(str(registry.get(name))) is None
            for name in ("source_archive_sha256", "published_spec_sha256")
        ):
            raise ProofError("rn_dependency_evidence_invalid")
        if repository_id == "android" and (
            SHA256.fullmatch(str(registry.get("repository_archive_sha256"))) is None
            or re.fullmatch(r"[0-9A-F]{40}", str(registry.get("signing_fingerprint"))) is None
        ):
            raise ProofError("rn_dependency_evidence_invalid")


def validate_oci(value: Any, coordinate: Mapping[str, Any]) -> None:
    version = coordinate.get("version")
    commit = coordinate.get("commit")
    if not isinstance(version, str) or re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version
    ) is None:
        raise ProofError("oci_alias_proof_invalid")
    major, minor, _ = version.split(".")
    tags = (version, f"{major}.{minor}", major, "latest")
    digest_value = value.get("index_digest") if isinstance(value, dict) else None
    references = value.get("references") if isinstance(value, dict) else None
    signature = value.get("signature_verification") if isinstance(value, dict) else None
    expected_references = {
        tag: {"reference": f"ghcr.io/latchway/latchway:{tag}", "digest": digest_value}
        for tag in tags
    }
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("registry") != "ghcr"
        or value.get("repository") != "ghcr.io/latchway/latchway"
        or value.get("version") != version
        or value.get("source_commit") != commit
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest_value)) is None
        or value.get("immutable_version_reference") != f"ghcr.io/latchway/latchway:{version}"
        or value.get("moving_aliases") != list(tags[1:])
        or references != expected_references
        or not isinstance(signature, list)
        or not signature
    ):
        raise ProofError("oci_alias_proof_invalid")
    for item in signature:
        critical = item.get("critical") if isinstance(item, dict) else None
        if (
            not isinstance(critical, dict)
            or critical.get("identity", {}).get("docker-reference")
            != "ghcr.io/latchway/latchway"
            or critical.get("image", {}).get("docker-manifest-digest") != digest_value
        ):
            raise ProofError("oci_alias_proof_invalid")


def validate_retained_release_set(
    value: Mapping[str, Any],
    expected_names: set[str],
    *,
    source_attested_names: set[str],
) -> None:
    retained = value.get("retained_release_assets")
    immutable = value.get("immutable_release_asset_verifications")
    source = value.get("release_asset_source_attestations")
    if (
        not isinstance(retained, dict)
        or set(retained) != expected_names
        or not isinstance(immutable, dict)
        or set(immutable) != expected_names
        or any(not isinstance(item, dict) or not item for item in immutable.values())
        or not isinstance(source, dict)
        or set(source) != source_attested_names
        or any(not item for item in source.values())
    ):
        raise ProofError("sdk_release_asset_set_invalid")
    for name, envelope in retained.items():
        if (
            not isinstance(envelope, dict)
            or envelope.get("name") != name
            or not isinstance(envelope.get("bytes"), int)
            or isinstance(envelope.get("bytes"), bool)
            or envelope["bytes"] < 1
            or SHA256.fullmatch(str(envelope.get("sha256"))) is None
            or envelope.get("release_digest") != f"sha256:{envelope['sha256']}"
        ):
            raise ProofError("sdk_release_asset_set_invalid")
        if "content_base64" in envelope:
            decode_retained(envelope, name)


def validate_npm(value: dict[str, Any], package: str, coordinate: dict[str, Any]) -> None:
    evidence = value.get("reviewed_package_evidence")
    reproducibility = value.get("reviewed_build_reproducibility")
    provenance = value.get("provenance")
    retained = value.get("registry_evidence")
    live = value.get("independent_live_registry_evidence")
    adoptions = value.get("adoptions")
    release_set = value.get("release_asset_set")
    immutable_verifications = value.get("immutable_release_asset_verifications")
    expected_fixed, expected_tarball = expected_npm_release_assets(
        package, str(coordinate.get("version"))
    )
    if (
        value.get("schema_version") != 1
        or value.get("registry") != "npm"
        or value.get("package") != package
        or value.get("version") != coordinate.get("version")
        or value.get("source_commit") != coordinate.get("commit")
        or value.get("registry_tarball_byte_identical") is not True
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
        or not isinstance(provenance.get("invocation_id"), str)
        or provenance.get("run_conclusion") not in {"success", "failure", "cancelled", "timed_out"}
        or not isinstance(provenance.get("run_id"), int)
        or isinstance(provenance.get("run_id"), bool)
        or provenance["run_id"] < 1
        or not isinstance(provenance.get("run_attempt"), int)
        or isinstance(provenance.get("run_attempt"), bool)
        or provenance["run_attempt"] < 1
        or not isinstance(provenance.get("authenticated_run"), dict)
        or not isinstance(provenance.get("attestations_content_base64"), str)
        or not isinstance(retained, dict)
        or not isinstance(live, dict)
        or not isinstance(adoptions, list)
        or not adoptions
    ):
        raise ProofError("npm_byte_proof_invalid")
    require_hash(value.get("sha256"))
    require_hash(reproducibility.get("sha256"))
    require_hash(provenance.get("attestations_sha256"))
    try:
        provenance_attestations = base64.b64decode(
            provenance["attestations_content_base64"], validate=True
        )
    except (binascii.Error, ValueError):
        raise ProofError("npm_attestation_document_hash_invalid") from None
    if hashlib.sha256(provenance_attestations).hexdigest() != provenance["attestations_sha256"]:
        raise ProofError("npm_attestation_document_hash_invalid")
    if value.get("registry_integrity") != value.get("integrity") or not str(value.get("integrity", "")).startswith("sha512-"):
        raise ProofError("npm_integrity_proof_invalid")
    raw_names = {
        "npm-registry-version.json", "npm-registry-view.json", "npm-attestations.json",
        "npm-audit-signatures.json", "npm-registry-evidence-manifest.json", "post-publish-evidence.json",
    }
    if set(retained) != raw_names | {"source_attestation_verifications"}:
        raise ProofError("retained_registry_evidence_invalid")
    retained_documents = {
        name: load_retained_json(retained[name], name) for name in raw_names
    }
    if decode_retained(retained["npm-attestations.json"], "npm-attestations.json") != provenance_attestations:
        raise ProofError("npm_attestation_document_hash_invalid")
    manifest = retained_documents["npm-registry-evidence-manifest.json"]
    manifest_evidence = manifest.get("evidence") if isinstance(manifest, dict) else None
    evidence_names = {
        "npm-registry-version.json", "npm-registry-view.json",
        "npm-attestations.json", "npm-audit-signatures.json",
    }
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "latchway_npm_registry_evidence_manifest"
        or manifest.get("package") != package
        or manifest.get("version") != coordinate.get("version")
        or manifest.get("tarball", {}).get("name") != expected_tarball
        or manifest.get("tarball", {}).get("sha256") != value.get("sha256")
        or manifest.get("tarball", {}).get("integrity") != value.get("integrity")
        or not isinstance(manifest_evidence, list)
        or len(manifest_evidence) != len(evidence_names)
    ):
        raise ProofError("npm_registry_manifest_invalid")
    manifest_by_name = {
        item.get("name"): item for item in manifest_evidence if isinstance(item, dict)
    }
    if set(manifest_by_name) != evidence_names:
        raise ProofError("npm_registry_manifest_invalid")
    for name in evidence_names:
        envelope = retained[name]
        if manifest_by_name[name] != {
            "name": name, "bytes": envelope["bytes"], "sha256": envelope["sha256"]
        }:
            raise ProofError("npm_registry_manifest_invalid")
    for name in ("npm-registry-version.json", "npm-registry-view.json"):
        document = retained_documents[name]
        if (
            document.get("name") != package
            or document.get("version") != coordinate.get("version")
            or document.get("dist", {}).get("integrity") != value.get("integrity")
        ):
            raise ProofError("npm_retained_metadata_invalid")
    if "error" in retained_documents["npm-audit-signatures.json"]:
        raise ProofError("npm_signature_evidence_invalid")
    live_documents: dict[str, dict[str, Any]] = {}
    for name in ("npm_attestations", "npm_audit_signatures", "npm_view"):
        envelope = live.get(name)
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"sha256", "content_base64"}
            or SHA256.fullmatch(str(envelope.get("sha256"))) is None
            or not isinstance(envelope.get("content_base64"), str)
        ):
            raise ProofError("npm_live_evidence_invalid")
        try:
            payload = base64.b64decode(envelope["content_base64"], validate=True)
            document = json.loads(payload, object_pairs_hook=strict_object)
        except (binascii.Error, ValueError, json.JSONDecodeError):
            raise ProofError("npm_live_evidence_invalid") from None
        if not isinstance(document, dict) or hashlib.sha256(payload).hexdigest() != envelope["sha256"]:
            raise ProofError("npm_live_evidence_invalid")
        if name == "npm_audit_signatures" and "error" in document:
            raise ProofError("npm_signature_evidence_invalid")
        live_documents[name] = document
    if live["npm_attestations"]["sha256"] != retained["npm-attestations.json"]["sha256"]:
        raise ProofError("npm_attestations_changed")
    if (
        live_documents["npm_view"]
        != retained_documents["npm-registry-view.json"]
        or live_documents["npm_audit_signatures"]
        != retained_documents["npm-audit-signatures.json"]
    ):
        raise ProofError("npm_registry_evidence_changed")
    observed_release_names = set(release_set) if isinstance(release_set, dict) else set()
    adoption_names = observed_release_names - expected_fixed
    source_verifications = retained.get("source_attestation_verifications")
    if (
        not expected_fixed.issubset(observed_release_names)
        or not adoption_names
        or any(re.fullmatch(r"npm-release-adoption-[1-9][0-9]*-[1-9][0-9]*\.json", name) is None for name in adoption_names)
        or not isinstance(immutable_verifications, dict)
        or set(immutable_verifications) != observed_release_names
        or any(not isinstance(item, dict) or not item for item in immutable_verifications.values())
        or not isinstance(source_verifications, dict)
        or set(source_verifications) != raw_names | adoption_names
        or any(not item for item in source_verifications.values())
    ):
        raise ProofError("npm_release_asset_set_invalid")
    for name, metadata in release_set.items():
        if (
            not isinstance(metadata, dict)
            or metadata.get("name") != name
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(metadata.get("digest"))) is None
            or not isinstance(metadata.get("size"), int)
            or isinstance(metadata.get("size"), bool)
            or metadata["size"] < 1
        ):
            raise ProofError("npm_release_asset_set_invalid")
    if len(adoptions) != len(adoption_names):
        raise ProofError("npm_adoption_proof_invalid")
    repository_name = (
        "latchway-js"
        if package == "@latchway/client"
        else "latchway-react-native-sdk"
    )
    repository = f"Latchway/{repository_name}"
    repository_url = f"https://github.com/{repository}"
    source_binding = {
        "repository": repository_url,
        "commit": coordinate.get("commit"),
        "workflow": ".github/workflows/release.yml",
        "ref": "refs/heads/main",
    }
    authenticated_origin = provenance.get("authenticated_run")
    if (
        provenance.get("source_repository") != repository
        or not isinstance(authenticated_origin, dict)
        or authenticated_origin.get("id") != provenance.get("run_id")
        or authenticated_origin.get("run_attempt") != provenance.get("run_attempt")
        or authenticated_origin.get("event") != "repository_dispatch"
        or authenticated_origin.get("status") != "completed"
        or authenticated_origin.get("conclusion")
        not in {"success", "failure", "cancelled", "timed_out"}
        or authenticated_origin.get("head_sha") != coordinate.get("commit")
        or authenticated_origin.get("head_branch") != "main"
        or authenticated_origin.get("path") != ".github/workflows/release.yml"
        or authenticated_origin.get("repository", {}).get("full_name") != repository
    ):
        raise ProofError("npm_provenance_run_invalid")
    seen_adoptions: set[str] = set()
    for item in adoptions:
        if not isinstance(item, dict) or set(item) != {"asset", "record", "authenticated_run"}:
            raise ProofError("npm_adoption_proof_invalid")
        record = item["record"]
        asset_name = item["asset"].get("name") if isinstance(item["asset"], dict) else None
        run = item["authenticated_run"]
        adoption = record.get("adoption") if isinstance(record, dict) else None
        origin = record.get("provenance") if isinstance(record, dict) else None
        adoption_payload = decode_retained(item["asset"], str(asset_name))
        try:
            retained_record = json.loads(
                adoption_payload, object_pairs_hook=strict_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProofError("npm_adoption_proof_invalid") from None
        match = re.fullmatch(
            r"npm-release-adoption-([1-9][0-9]*)-([1-9][0-9]*)\.json",
            str(asset_name),
        )
        expected_origin = {
            **source_binding,
            "predicate_type": "https://slsa.dev/provenance/v1",
            "run_id": provenance.get("run_id"),
            "run_attempt": provenance.get("run_attempt"),
            "invocation_id": provenance.get("invocation_id"),
        }
        if (
            asset_name not in adoption_names
            or asset_name in seen_adoptions
            or retained_record != record
            or match is None
            or not isinstance(record, dict)
            or set(record)
            != {
                "schema_version",
                "kind",
                "package",
                "version",
                "release_tag",
                "tarball",
                "source",
                "provenance",
                "adoption",
                "registry_evidence_manifest",
            }
            or record.get("schema_version") != 1
            or record.get("kind") != "latchway_npm_release_adoption"
            or record.get("package") != package
            or record.get("version") != coordinate.get("version")
            or record.get("release_tag") != coordinate.get("tag")
            or record.get("tarball") != manifest.get("tarball")
            or record.get("source") != source_binding
            or not isinstance(adoption, dict)
            or adoption.get("mode") not in {"published", "adopted_existing"}
            or adoption
            != {
                **source_binding,
                "run_id": int(match.group(1)) if match is not None else None,
                "run_attempt": int(match.group(2)) if match is not None else None,
                "mode": adoption.get("mode") if isinstance(adoption, dict) else None,
            }
            or origin != expected_origin
            or record.get("registry_evidence_manifest")
            != {
                "file": "npm-registry-evidence-manifest.json",
                "sha256": retained["npm-registry-evidence-manifest.json"]["sha256"],
            }
            or not isinstance(run, dict)
            or run.get("event") != "repository_dispatch"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("head_sha") != coordinate.get("commit")
            or run.get("head_branch") != "main"
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("repository", {}).get("full_name") != repository
            or run.get("run_attempt") != adoption.get("run_attempt")
            or run.get("id") != adoption.get("run_id")
        ):
            raise ProofError("npm_adoption_proof_invalid")
        seen_adoptions.add(str(asset_name))
        if release_set[asset_name]["digest"] != item["asset"]["release_digest"]:
            raise ProofError("npm_adoption_proof_invalid")
    assets = value.get("release_asset_digests")
    attestations = value.get("release_asset_attestation_verifications")
    expected_asset_names = {
        str(evidence.get("tarball")),
        "package-evidence.json",
        "build-reproducibility.json",
    }
    if package == "@latchway/react-native":
        expected_asset_names.add("published-dependency-evidence.json")
    if not isinstance(assets, dict) or set(assets) != expected_asset_names or any(
        not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
        for item in assets.values()
    ) or assets.get(evidence.get("tarball")) != f"sha256:{value.get('sha256')}":
        raise ProofError("npm_release_asset_proof_invalid")
    if release_set.get(expected_tarball, {}).get("digest") != f"sha256:{value.get('sha256')}":
        raise ProofError("npm_release_asset_proof_invalid")
    if any(
        release_set.get(name, {}).get("digest") != digest
        for name, digest in assets.items()
    ):
        raise ProofError("npm_release_asset_proof_invalid")
    expected_compatibility = (
        {"minimum_node": "24.19.0"}
        if package == "@latchway/client"
        else {
            "minimum_node": "24.19.0",
            "react_native": "0.82.x",
            "minimum_ios": "15.0",
            "minimum_android_api": 24,
        }
    )
    if value.get("compatibility") != expected_compatibility:
        raise ProofError("npm_compatibility_proof_invalid")
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


def validate_maven_file_closure(maven: Mapping[str, Any], version: str) -> None:
    expected_paths = expected_maven_paths(version)
    checksum_algorithms = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha512": 128,
    }
    expected_manifest_paths = {
        derived
        for path in expected_paths
        for derived in (
            path,
            f"{path}.asc",
            *(f"{path}.{algorithm}" for algorithm in checksum_algorithms),
        )
    }
    files = maven.get("files")
    public_manifest = maven.get("public_manifest")
    deployment = maven.get("deployment")
    if (
        not isinstance(files, list)
        or len(files) != len(expected_paths)
        or {item.get("path") for item in files if isinstance(item, dict)}
        != expected_paths
        or not isinstance(public_manifest, list)
        or len(public_manifest) != len(expected_manifest_paths)
        or public_manifest
        != sorted(
            public_manifest,
            key=lambda item: item.get("path", "") if isinstance(item, dict) else "",
        )
        or not isinstance(deployment, dict)
        or set(deployment)
        != {
            "intent_sha256", "record_sha256", "status_sha256", "record_kind",
            "record", "status",
        }
    ):
        raise ProofError("maven_byte_proof_invalid")

    manifest_by_path: dict[str, Mapping[str, Any]] = {}
    for item in public_manifest:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "bytes", "sha256"}
            or item.get("path") not in expected_manifest_paths
            or item["path"] in manifest_by_path
            or not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or item["bytes"] < 1
            or SHA256.fullmatch(str(item.get("sha256"))) is None
        ):
            raise ProofError("maven_byte_proof_invalid")
        manifest_by_path[item["path"]] = item
    encoded_manifest = (
        json.dumps(public_manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if (
        set(manifest_by_path) != expected_manifest_paths
        or maven.get("public_manifest_sha256")
        != hashlib.sha256(encoded_manifest).hexdigest()
    ):
        raise ProofError("maven_byte_proof_invalid")

    file_keys = {
        "path", "sha256", "bytes", "signature_sha256", "signature_bytes",
        "signature_armored", "gpg_status", "checksums",
        "checksums_byte_identical",
    }
    gpg_keys = {
        "schema_version", "primary_fingerprint", "signing_fingerprint",
        "public_key_algorithm", "hash_algorithm", "status_lines",
    }
    primary_fingerprint = maven.get("signing_fingerprint")
    for item in files:
        if not isinstance(item, dict) or set(item) != file_keys:
            raise ProofError("maven_byte_proof_invalid")
        path = item.get("path")
        signature = item.get("signature_armored")
        checksums = item.get("checksums")
        gpg_status = item.get("gpg_status")
        try:
            signature_bytes = signature.encode("ascii") if isinstance(signature, str) else b""
        except UnicodeEncodeError:
            raise ProofError("maven_byte_proof_invalid") from None
        if (
            path not in expected_paths
            or not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or item["bytes"] < 1
            or SHA256.fullmatch(str(item.get("sha256"))) is None
            or not isinstance(item.get("signature_bytes"), int)
            or isinstance(item.get("signature_bytes"), bool)
            or not 1 <= item["signature_bytes"] <= 65536
            or item["signature_bytes"] != len(signature_bytes)
            or SHA256.fullmatch(str(item.get("signature_sha256"))) is None
            or not isinstance(signature, str)
            or not signature.startswith("-----BEGIN PGP SIGNATURE-----")
            or hashlib.sha256(signature_bytes).hexdigest()
            != item.get("signature_sha256")
            or item.get("checksums_byte_identical") is not True
            or not isinstance(checksums, list)
            or [entry.get("algorithm") for entry in checksums if isinstance(entry, dict)]
            != list(checksum_algorithms)
            or len(checksums) != len(checksum_algorithms)
            or not isinstance(gpg_status, dict)
            or set(gpg_status) != gpg_keys
            or gpg_status.get("schema_version") != 1
            or gpg_status.get("primary_fingerprint") != primary_fingerprint
            or re.fullmatch(
                r"[0-9A-F]{40}", str(gpg_status.get("signing_fingerprint"))
            )
            is None
            or gpg_status.get("public_key_algorithm")
            not in {"1", "3", "19", "22", "27"}
            or gpg_status.get("hash_algorithm") != "10"
            or not isinstance(gpg_status.get("status_lines"), list)
            or not gpg_status["status_lines"]
            or any(
                not isinstance(line, str) or not line.startswith("[GNUPG:]")
                for line in gpg_status["status_lines"]
            )
            or manifest_by_path[path].get("bytes") != item["bytes"]
            or manifest_by_path[path].get("sha256") != item["sha256"]
            or manifest_by_path[f"{path}.asc"].get("bytes")
            != item["signature_bytes"]
            or manifest_by_path[f"{path}.asc"].get("sha256")
            != item["signature_sha256"]
        ):
            raise ProofError("maven_byte_proof_invalid")
        for checksum in checksums:
            algorithm = checksum.get("algorithm") if isinstance(checksum, dict) else None
            expected_length = checksum_algorithms.get(str(algorithm))
            checksum_path = f"{path}.{algorithm}"
            if (
                not isinstance(checksum, dict)
                or set(checksum)
                != {"algorithm", "path", "bytes", "sha256", "published_digest"}
                or checksum.get("path") != checksum_path
                or not isinstance(checksum.get("bytes"), int)
                or isinstance(checksum.get("bytes"), bool)
                or not 1 <= checksum["bytes"] <= 256
                or SHA256.fullmatch(str(checksum.get("sha256"))) is None
                or expected_length is None
                or re.fullmatch(
                    rf"[0-9a-f]{{{expected_length}}}",
                    str(checksum.get("published_digest")),
                )
                is None
                or manifest_by_path[checksum_path].get("bytes") != checksum["bytes"]
                or manifest_by_path[checksum_path].get("sha256") != checksum["sha256"]
            ):
                raise ProofError("maven_byte_proof_invalid")


def validate_maven(
    maven: dict[str, Any], coordinate: Mapping[str, Any]
) -> None:
    version = coordinate.get("version")
    if not isinstance(version, str):
        raise ProofError("maven_byte_proof_invalid")
    files = maven.get("files") if isinstance(maven, dict) else None
    expected_paths = expected_maven_paths(version)
    base_keys = {
        "schema_version", "registry", "namespace", "version",
        "reviewed_repository", "primary_artifacts_byte_identical",
        "checksum_files_byte_identical", "signature_files_present",
        "signatures_cryptographically_verified", "signing_fingerprint",
        "reviewed_public_key_sha256", "deployment", "public_manifest",
        "public_manifest_sha256", "files",
    }
    additions = {
        "release_asset_attestation_verification",
        "release_asset_source_attestations",
        "immutable_release_asset_verifications",
        "retained_release_assets",
        "independent_live_verification",
        "compatibility",
    }
    if (
        set(maven) != base_keys | additions
        or maven.get("schema_version") != 2
        or maven.get("registry") != "maven_central"
        or maven.get("namespace") != "dev.latchway"
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
    validate_maven_file_closure(maven, version)
    archive_name = f"latchway-android-{version}-maven-repository.zip"
    portal_name = f"latchway-android-{version}-central-portal.zip"
    expected_assets = {
        archive_name,
        portal_name,
        "SHA256SUMS",
        "github-release-tag-binding.json",
        "latchway-maven-signing-public-key.asc",
        "maven-central-upload-intent.json",
        "maven-central-deployment.json",
        "maven-central-deployment-status.json",
        "maven-central-release-evidence.json",
    }
    validate_retained_release_set(
        maven, expected_assets, source_attested_names=expected_assets
    )
    retained = maven["retained_release_assets"]
    checksum_bytes = decode_retained(retained["SHA256SUMS"], "SHA256SUMS")
    try:
        lines = checksum_bytes.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise ProofError("maven_release_checksum_invalid") from None
    checksums: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) in checksums:
            raise ProofError("maven_release_checksum_invalid")
        checksums[match.group(2)] = match.group(1)
    expected_checksum_names = expected_assets - {"SHA256SUMS"}
    if set(checksums) != expected_checksum_names or any(
        checksums[name] != retained[name]["sha256"] for name in expected_checksum_names
    ):
        raise ProofError("maven_release_checksum_invalid")
    intent = load_retained_json(retained["maven-central-upload-intent.json"], "maven-central-upload-intent.json")
    deployment = load_retained_json(retained["maven-central-deployment.json"], "maven-central-deployment.json")
    status = load_retained_json(retained["maven-central-deployment-status.json"], "maven-central-deployment-status.json")
    retained_proof = load_retained_json(retained["maven-central-release-evidence.json"], "maven-central-release-evidence.json")
    tag_binding = load_retained_json(
        retained["github-release-tag-binding.json"],
        "github-release-tag-binding.json",
    )
    expected_purls = sorted(
        f"pkg:maven/dev.latchway/{module}@{version}"
        for module in (
            "latchway-core",
            "latchway-okhttp",
            "latchway-play-integrity",
            "latchway-firebase-auth",
            "latchway-bom",
        )
    )
    portal_sha = retained[portal_name]["sha256"]
    expected_deployment_name = (
        f"latchway-android-v{version}-{str(coordinate.get('commit'))[:12]}-{portal_sha}"
    )
    intent_keys = {
        "schema", "repository", "source_commit", "release_tag", "version",
        "namespace", "deployment_name", "publishing_type",
        "reviewed_repository_archive_sha256",
        "reviewed_repository_manifest_sha256", "reviewed_repository_file_count",
        "reviewed_portal_bundle_sha256", "reviewed_portal_bundle_file_count",
        "reviewed_public_key_sha256", "expected_purls", "authorization",
    }
    deployment_keys = {
        "schema", "intent_sha256", "deployment_name", "publishing_type",
        "namespace", "version", "source_commit", "expected_purls",
        "reviewed_portal_bundle_sha256", "record_kind", "deployment_id",
        "public_manifest_sha256",
    }
    status_keys = {
        "schema", "intent_sha256", "record_sha256", "record_kind",
        "deployment_id", "deployment_name", "deployment_state", "purls",
        "public_manifest_sha256",
    }
    record_kind = deployment.get("record_kind")
    public_manifest = deployment.get("public_manifest_sha256")
    deployment_kind_valid = (
        record_kind == "portal_deployment"
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            str(deployment.get("deployment_id")),
            re.IGNORECASE,
        )
        is not None
        and public_manifest is None
    ) or (
        record_kind == "public_registry_adoption"
        and deployment.get("deployment_id") is None
        and SHA256.fullmatch(str(public_manifest)) is not None
    )
    if (
        set(intent) != intent_keys
        or intent.get("schema") != "latchway.maven-central-upload-intent.v2"
        or intent.get("repository") != "Latchway/latchway-android"
        or intent.get("source_commit") != coordinate.get("commit")
        or intent.get("release_tag") != coordinate.get("tag")
        or intent.get("version") != version
        or intent.get("namespace") != "dev.latchway"
        or intent.get("publishing_type") != "user_managed"
        or intent.get("authorization") != "recoverable_exact_upload"
        or intent.get("reviewed_repository_archive_sha256")
        != retained[archive_name]["sha256"]
        or intent.get("reviewed_portal_bundle_sha256")
        != retained[portal_name]["sha256"]
        or intent.get("reviewed_public_key_sha256")
        != retained["latchway-maven-signing-public-key.asc"]["sha256"]
        or maven.get("reviewed_public_key_sha256")
        != retained["latchway-maven-signing-public-key.asc"]["sha256"]
        or intent.get("deployment_name") != expected_deployment_name
        or SHA256.fullmatch(
            str(intent.get("reviewed_repository_manifest_sha256"))
        ) is None
        or intent.get("reviewed_repository_file_count") != 120
        or intent.get("reviewed_portal_bundle_file_count") != 144
        or sorted(intent.get("expected_purls", [])) != expected_purls
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
        or tag_binding.get("tag") != coordinate.get("tag")
        or tag_binding.get("commit") != coordinate.get("commit")
        or re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
            str(tag_binding.get("tag_object_sha")),
        ) is None
        or SHA256.fullmatch(str(tag_binding.get("message_sha256"))) is None
        or set(deployment) != deployment_keys
        or deployment.get("schema") != "latchway.maven-central-deployment.v2"
        or deployment.get("intent_sha256") != retained["maven-central-upload-intent.json"]["sha256"]
        or deployment.get("deployment_name") != expected_deployment_name
        or deployment.get("publishing_type") != "user_managed"
        or deployment.get("namespace") != "dev.latchway"
        or deployment.get("version") != version
        or deployment.get("source_commit") != coordinate.get("commit")
        or sorted(deployment.get("expected_purls", [])) != expected_purls
        or deployment.get("reviewed_portal_bundle_sha256") != portal_sha
        or not deployment_kind_valid
        or set(status) != status_keys
        or status.get("schema") != "latchway.maven-central-deployment-status.v2"
        or status.get("intent_sha256") != retained["maven-central-upload-intent.json"]["sha256"]
        or status.get("record_sha256") != retained["maven-central-deployment.json"]["sha256"]
        or status.get("record_kind") != record_kind
        or status.get("deployment_id") != deployment.get("deployment_id")
        or status.get("deployment_name") != expected_deployment_name
        or status.get("deployment_state") != "PUBLISHED"
        or sorted(status.get("purls", [])) != expected_purls
        or status.get("public_manifest_sha256") != public_manifest
        or not isinstance(retained_proof.get("deployment"), dict)
        or set(retained_proof["deployment"])
        != {
            "intent_sha256", "record_sha256", "status_sha256", "record_kind",
            "record", "status",
        }
        or retained_proof.get("deployment", {}).get("intent_sha256") != retained["maven-central-upload-intent.json"]["sha256"]
        or retained_proof.get("deployment", {}).get("record_sha256") != retained["maven-central-deployment.json"]["sha256"]
        or retained_proof.get("deployment", {}).get("status_sha256") != retained["maven-central-deployment-status.json"]["sha256"]
        or retained_proof.get("deployment", {}).get("record_kind") != record_kind
        or retained_proof.get("deployment", {}).get("record") != deployment
        or retained_proof.get("deployment", {}).get("status") != status
        or (
            record_kind == "public_registry_adoption"
            and public_manifest != retained_proof.get("public_manifest_sha256")
        )
    ):
        raise ProofError("maven_deployment_binding_invalid")
    original = {key: value for key, value in maven.items() if key not in additions}
    if retained_proof != original or maven.get("independent_live_verification") != original:
        raise ProofError("maven_retained_proof_changed")
    if maven.get("compatibility") != {"minimum_android_api": 23}:
        raise ProofError("maven_compatibility_proof_invalid")


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
        "oci": "artifacts--registry-oci--tool-output.json",
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
    validate_oci(proofs["oci"], repositories["core"])
    validate_npm(proofs["javascript"], "@latchway/client", repositories["javascript"])
    validate_npm(proofs["react_native"], "@latchway/react-native", repositories["react_native"])
    validate_rn_published_dependencies(
        proofs["react_native"].get("reviewed_published_dependency_evidence"),
        repositories,
    )
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
    ios_version = repositories["ios"].get("version")
    if not isinstance(ios_version, str):
        raise ProofError("cocoapods_byte_proof_invalid")
    ios_archive = f"latchway-ios-sdk-{ios_version}.tar.gz"
    ios_assets = {
        ios_archive,
        f"{ios_archive}.sha256",
        "cocoapods-published-podspec.json",
        "cocoapods-reviewed-podspec.json",
        "cocoapods-release-evidence.json",
        "cocoapods-release-evidence.SHA256SUMS",
    }
    validate_retained_release_set(
        cocoa,
        ios_assets,
        source_attested_names=ios_assets - {f"{ios_archive}.sha256"},
    )
    retained_ios = cocoa["retained_release_assets"]
    if decode_retained(retained_ios[f"{ios_archive}.sha256"], f"{ios_archive}.sha256") != (
        f"{retained_ios[ios_archive]['sha256']}  {ios_archive}\n".encode("ascii")
    ):
        raise ProofError("cocoapods_release_checksum_invalid")
    evidence_sums = decode_retained(
        retained_ios["cocoapods-release-evidence.SHA256SUMS"],
        "cocoapods-release-evidence.SHA256SUMS",
    ).decode("ascii").splitlines()
    expected_cocoa_sums = {
        "cocoapods-published-podspec.json",
        "cocoapods-reviewed-podspec.json",
        "cocoapods-release-evidence.json",
    }
    parsed_cocoa_sums: dict[str, str] = {}
    for line in evidence_sums:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) in parsed_cocoa_sums:
            raise ProofError("cocoapods_release_checksum_invalid")
        parsed_cocoa_sums[match.group(2)] = match.group(1)
    if set(parsed_cocoa_sums) != expected_cocoa_sums or any(
        parsed_cocoa_sums[name] != retained_ios[name]["sha256"]
        for name in expected_cocoa_sums
    ):
        raise ProofError("cocoapods_release_checksum_invalid")
    retained_cocoa = load_retained_json(
        retained_ios["cocoapods-release-evidence.json"],
        "cocoapods-release-evidence.json",
    )
    cocoa_additions = {
        "release_asset_attestation_verification",
        "release_asset_source_attestations",
        "immutable_release_asset_verifications",
        "retained_release_assets",
        "independent_live_verification",
        "compatibility",
    }
    original_cocoa = {key: value for key, value in cocoa.items() if key not in cocoa_additions}
    if (
        retained_cocoa != original_cocoa
        or cocoa.get("independent_live_verification") != original_cocoa
        or cocoa.get("compatibility") != {"minimum_ios": "15.0"}
    ):
        raise ProofError("cocoapods_retained_proof_changed")
    maven = proofs["android"]
    android_version = repositories["android"].get("version")
    if not isinstance(android_version, str):
        raise ProofError("maven_byte_proof_invalid")
    validate_maven(maven, repositories["android"])
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
