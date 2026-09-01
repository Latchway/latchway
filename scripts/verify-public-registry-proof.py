#!/usr/bin/env python3
"""Independently validate byte-bound public registry proof in release evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
from typing import Any, Mapping


MINTLIFY_PATH = Path(__file__).with_name("mintlify-production-proof.py")
MINTLIFY_SPEC = importlib.util.spec_from_file_location(
    "latchway_public_registry_mintlify_proof", MINTLIFY_PATH
)
if MINTLIFY_SPEC is None or MINTLIFY_SPEC.loader is None:
    raise RuntimeError("Mintlify production-proof validator cannot be loaded")
MINTLIFY = importlib.util.module_from_spec(MINTLIFY_SPEC)
MINTLIFY_SPEC.loader.exec_module(MINTLIFY)

SOURCE_PATH = Path(__file__).with_name("operational-resilience-evidence.py")
SOURCE_SPEC = importlib.util.spec_from_file_location(
    "latchway_public_registry_source_evidence", SOURCE_PATH
)
if SOURCE_SPEC is None or SOURCE_SPEC.loader is None:
    raise RuntimeError("source-conformance validator cannot be loaded")
SOURCE = importlib.util.module_from_spec(SOURCE_SPEC)
SOURCE_SPEC.loader.exec_module(SOURCE)


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
MAXIMUM = 32 * 1024 * 1024
MAXIMUM_RETAINED_NPM_TARBALL_BYTES = 10 * 1024 * 1024
IOS_COCOAPODS_SUBSPECS = frozenset(
    {"AppAttest", "AppExtensions", "Core", "FirebaseAuth"}
)
COCOAPODS_FORBIDDEN_HOOKS = frozenset(
    {"prepare_command", "script_phase", "script_phases"}
)
JAVASCRIPT_NPM_PACKAGES: tuple[tuple[str, str], ...] = (
    ("client", "@latchway/client"),
    ("openai", "@latchway/openai"),
    ("vercel-ai", "@latchway/vercel-ai"),
    ("langchain", "@latchway/langchain"),
)
JAVASCRIPT_NPM_ADOPTION = re.compile(
    r"^npm-release-adoption-(client|openai|vercel-ai|langchain)-"
    r"([1-9][0-9]*)-([1-9][0-9]*)\.json$"
)
JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS = frozenset(
    {
        "package-evidence.json",
        "release-candidate-evidence.json",
        "publish-input-evidence.json",
        "post-publish-evidence.json",
        "npm-registry-evidence-manifest.json",
        "build-reproducibility.json",
        "contract-evidence.json",
        "dependency-vulnerability-scan.json",
        "tag-evidence.json",
    }
)
JAVASCRIPT_NPM_AGGREGATE_ASSETS = (
    JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS | {"SHA256SUMS"}
)
JAVASCRIPT_OSV_SCANNER_COMMIT = "b56b5191101d5f27d4787d5583d8d01e9518a7af"


class ProofError(Exception):
    pass


def expected_source_attested_release_assets(
    repository_id: str, version: str, release_names: Any
) -> set[str]:
    """Return the exact released subjects the production verifier must require."""
    names = set(release_names)
    if repository_id in {"javascript", "android"}:
        return names
    if repository_id == "react_native":
        return names - {f"latchway-react-native-{version}.tgz.sha256"}
    if repository_id == "ios":
        return names - {f"latchway-ios-sdk-{version}.tar.gz.sha256"}
    raise ProofError("release_asset_attestation_repository_invalid")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def valid_npm_adoption_mode(
    mode: Any,
    adoption_run_id: Any,
    adoption_run_attempt: Any,
    provenance_run_id: Any,
    provenance_run_attempt: Any,
) -> bool:
    """Require retry adoption records to identify whether they did the publish."""
    return (
        isinstance(mode, str)
        and mode in {"published", "adopted_existing"}
        and (mode == "published")
        == (
            adoption_run_id == provenance_run_id
            and adoption_run_attempt == provenance_run_attempt
        )
    )


def validate_javascript_reproducibility_archive_verification(
    reproducibility: Any, verification: Any
) -> None:
    rows = reproducibility.get("files") if isinstance(reproducibility, dict) else None
    if (
        not isinstance(rows, list)
        or not rows
        or not isinstance(verification, dict)
        or verification
        != {
            "schema_version": 1,
            "algorithm": "sha256",
            "inputs": "ordered-release-tarball-dist-file-bytes",
            "archive_regular_file_closure_verified": True,
            "source_manifests_and_peer_translation_verified": True,
            "independent_source_rebuild_performed": False,
            "file_count": len(rows),
            "bytes": sum(
                item.get("bytes", 0) if isinstance(item, dict) else 0
                for item in rows
            ),
            "sha256": reproducibility.get("sha256"),
        }
    ):
        raise ProofError("npm_reproducibility_archive_verification_invalid")


def validate_javascript_reproducibility_tarballs(
    value: Mapping[str, Any],
    coordinate: Mapping[str, Any],
    retained_tarballs: Mapping[str, bytes],
) -> None:
    """Recompute the ordered dist-byte aggregate from four retained npm archives."""
    version = coordinate.get("version")
    aggregate = value.get("reviewed_aggregate_evidence")
    release_set = value.get("release_asset_set")
    package_proofs = value.get("packages")
    package_evidence = (
        aggregate.get("package-evidence.json")
        if isinstance(aggregate, Mapping)
        else None
    )
    reproducibility = (
        aggregate.get("build-reproducibility.json")
        if isinstance(aggregate, Mapping)
        else None
    )
    contract = (
        aggregate.get("contract-evidence.json")
        if isinstance(aggregate, Mapping)
        else None
    )
    reviewed_packages = (
        package_evidence.get("packages")
        if isinstance(package_evidence, Mapping)
        else None
    )
    rows = reproducibility.get("files") if isinstance(reproducibility, Mapping) else None
    expected_names = {
        f"latchway-{package_id}-{version}.tgz"
        for package_id, _ in JAVASCRIPT_NPM_PACKAGES
    }
    if (
        not isinstance(version, str)
        or set(retained_tarballs) != expected_names
        or not isinstance(release_set, Mapping)
        or not isinstance(package_proofs, list)
        or len(package_proofs) != len(JAVASCRIPT_NPM_PACKAGES)
        or not isinstance(reviewed_packages, list)
        or len(reviewed_packages) != len(JAVASCRIPT_NPM_PACKAGES)
        or not isinstance(rows, list)
        or not rows
        or not isinstance(contract, Mapping)
        or SHA256.fullmatch(str(contract.get("contract_lock_sha256"))) is None
    ):
        raise ProofError("npm_reproducibility_retained_tarballs_invalid")

    dist_payloads: dict[str, bytes] = {}
    total_dist_bytes = 0
    for index, (package_id, package) in enumerate(JAVASCRIPT_NPM_PACKAGES):
        name = f"latchway-{package_id}-{version}.tgz"
        payload = retained_tarballs.get(name)
        reviewed = reviewed_packages[index]
        package_proof = package_proofs[index]
        if (
            not isinstance(payload, bytes)
            or not 1 <= len(payload) <= MAXIMUM_RETAINED_NPM_TARBALL_BYTES
            or not isinstance(reviewed, Mapping)
            or not isinstance(package_proof, Mapping)
        ):
            raise ProofError("npm_reproducibility_retained_tarballs_invalid")
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()
        sha512 = hashlib.sha512(payload).hexdigest()
        integrity = "sha512-" + base64.b64encode(
            hashlib.sha512(payload).digest()
        ).decode("ascii")
        metadata = release_set.get(name)
        if (
            not isinstance(metadata, Mapping)
            or metadata.get("name") != name
            or metadata.get("size") != len(payload)
            or metadata.get("digest") != f"sha256:{sha256}"
            or reviewed.get("tarball") != name
            or reviewed.get("bytes") != len(payload)
            or reviewed.get("sha1") != sha1
            or reviewed.get("sha256") != sha256
            or reviewed.get("sha512") != sha512
            or reviewed.get("integrity") != integrity
            or package_proof.get("tarball") != name
            or package_proof.get("bytes") != len(payload)
            or package_proof.get("sha1") != sha1
            or package_proof.get("sha256") != sha256
            or package_proof.get("sha512") != sha512
            or package_proof.get("integrity") != integrity
        ):
            raise ProofError("npm_reproducibility_retained_tarballs_invalid")

        entries: list[str] = []
        archive_payloads: dict[str, bytes] = {}
        unpacked_bytes = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                for member in archive.getmembers():
                    raw_name = member.name
                    relative = PurePosixPath(raw_name)
                    if (
                        not raw_name
                        or raw_name.startswith("/")
                        or "\\" in raw_name
                        or relative.as_posix() != raw_name
                        or any(part in ("", ".", "..") for part in relative.parts)
                        or raw_name in archive_payloads
                        or not member.isfile()
                        or member.size < 0
                        or member.size > 8 * 1024 * 1024
                    ):
                        raise ProofError(
                            "npm_reproducibility_retained_tarballs_invalid"
                        )
                    entries.append(raw_name)
                    if len(entries) > 512:
                        raise ProofError(
                            "npm_reproducibility_retained_tarballs_invalid"
                        )
                    unpacked_bytes += member.size
                    if unpacked_bytes > 25 * 1024 * 1024:
                        raise ProofError(
                            "npm_reproducibility_retained_tarballs_invalid"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ProofError(
                            "npm_reproducibility_retained_tarballs_invalid"
                        )
                    member_payload = extracted.read(member.size + 1)
                    if len(member_payload) != member.size:
                        raise ProofError(
                            "npm_reproducibility_retained_tarballs_invalid"
                        )
                    archive_payloads[raw_name] = member_payload
                    if raw_name.startswith("package/dist/"):
                        repository_path = raw_name.removeprefix("package/")
                        if package_id != "client":
                            repository_path = f"packages/{package_id}/{repository_path}"
                        if repository_path in dist_payloads or member.size < 1:
                            raise ProofError(
                                "npm_reproducibility_retained_tarballs_invalid"
                            )
                        total_dist_bytes += member.size
                        if total_dist_bytes > MAXIMUM:
                            raise ProofError(
                                "npm_reproducibility_retained_tarballs_invalid"
                            )
                        dist_payloads[repository_path] = member_payload
        except ProofError:
            raise
        except (tarfile.TarError, EOFError, OSError):
            raise ProofError("npm_reproducibility_retained_tarballs_invalid") from None

        manifest_payload = archive_payloads.get("package/package.json")
        try:
            manifest = json.loads(
                manifest_payload.decode("utf-8")
                if isinstance(manifest_payload, bytes)
                else "",
                object_pairs_hook=strict_object,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ProofError("npm_reproducibility_retained_tarballs_invalid")
                ),
            )
        except ProofError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProofError("npm_reproducibility_retained_tarballs_invalid") from None
        published_peers = reviewed.get("published_peer_dependencies")
        if (
            sorted(entries) != reviewed.get("entries")
            or unpacked_bytes != reviewed.get("unpacked_bytes")
            or not isinstance(manifest, dict)
            or manifest.get("name") != package
            or manifest.get("version") != version
            or not isinstance(published_peers, dict)
            or (manifest.get("peerDependencies") or {}) != published_peers
            or (
                package_id != "client"
                and published_peers.get("@latchway/client") != f"^{version}"
            )
            or (
                package_id == "client"
                and hashlib.sha256(
                    archive_payloads.get("package/contract.lock", b"")
                ).hexdigest()
                != contract.get("contract_lock_sha256")
            )
        ):
            raise ProofError("npm_reproducibility_retained_tarballs_invalid")
        prefix = "dist/" if package_id == "client" else f"packages/{package_id}/dist/"
        expected_paths = {
            item.get("path")
            for item in rows
            if isinstance(item, Mapping) and item.get("package") == package
        }
        if {path for path in dist_payloads if path.startswith(prefix)} != expected_paths:
            raise ProofError("npm_reproducibility_retained_tarballs_invalid")

    aggregate_digest = hashlib.sha256()
    for item in rows:
        path = item.get("path") if isinstance(item, Mapping) else None
        payload = dist_payloads.get(str(path))
        if (
            payload is None
            or item.get("bytes") != len(payload)
            or item.get("sha256") != hashlib.sha256(payload).hexdigest()
        ):
            raise ProofError("npm_reproducibility_retained_tarballs_invalid")
        aggregate_digest.update(str(path).encode("utf-8"))
        aggregate_digest.update(b"\0")
        aggregate_digest.update(payload)
        aggregate_digest.update(b"\0")
    recomputed = aggregate_digest.hexdigest()
    if (
        reproducibility.get("sha256") != recomputed
        or value.get("reproducibility_archive_verification", {}).get("sha256")
        != recomputed
        or value.get("reproducibility_archive_verification", {}).get("bytes")
        != total_dist_bytes
    ):
        raise ProofError("npm_reproducibility_retained_tarballs_invalid")


def validate_javascript_supporting_evidence(
    aggregate: Mapping[str, Any], coordinate: Mapping[str, Any]
) -> None:
    tag = aggregate.get("tag-evidence.json")
    vulnerability = aggregate.get("dependency-vulnerability-scan.json")
    scanner = vulnerability.get("scanner") if isinstance(vulnerability, dict) else None
    if (
        not isinstance(tag, dict)
        or set(tag) != {"schema_version", "tag", "version", "commit", "annotated"}
        or tag.get("schema_version") != 1
        or tag.get("tag") != coordinate.get("tag")
        or tag.get("version") != coordinate.get("version")
        or tag.get("commit") != coordinate.get("commit")
        or tag.get("annotated") is not True
    ):
        raise ProofError("npm_tag_evidence_invalid")
    if (
        not isinstance(vulnerability, dict)
        or set(vulnerability)
        != {
            "schema_version", "scanner", "source_commit", "inventory_sha256",
            "database_sha256", "package_count", "vulnerability_count",
            "blocking_vulnerability_count", "policy", "status",
        }
        or vulnerability.get("schema_version")
        != "latchway.dependency-vulnerability-scan.v1"
        or scanner
        != {
            "name": "OSV-Scanner",
            "version": "2.4.0",
            "commit": JAVASCRIPT_OSV_SCANNER_COMMIT,
            "mode": "offline",
        }
        or vulnerability.get("source_commit") != coordinate.get("commit")
        or SHA256.fullmatch(str(vulnerability.get("inventory_sha256"))) is None
        or SHA256.fullmatch(str(vulnerability.get("database_sha256"))) is None
        or not isinstance(vulnerability.get("package_count"), int)
        or isinstance(vulnerability.get("package_count"), bool)
        or vulnerability["package_count"] < 1
        or not isinstance(vulnerability.get("vulnerability_count"), int)
        or isinstance(vulnerability.get("vulnerability_count"), bool)
        or vulnerability["vulnerability_count"] < 0
        or vulnerability.get("blocking_vulnerability_count") != 0
        or vulnerability.get("policy")
        != "block-critical-high-and-unknown-severity"
        or vulnerability.get("status") != "passed"
    ):
        raise ProofError("npm_vulnerability_evidence_invalid")


def validate_javascript_contract_source_verification(
    contract: Any,
    verification: Any,
    coordinate: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> None:
    fixtures = contract.get("fixtures") if isinstance(contract, dict) else None
    if (
        not isinstance(contract, dict)
        or set(contract)
        != {
            "schema_version", "contract_version", "core_release", "core_commit",
            "bundle_sha256", "wire_protocol_version", "contract_lock_sha256",
            "fixtures",
        }
        or contract.get("schema_version") != 1
        or contract.get("contract_version") != authority.get("contract_version")
        or contract.get("core_release") != authority.get("core_release")
        or contract.get("core_commit") != authority.get("core_commit")
        or contract.get("bundle_sha256") != authority.get("bundle_sha256")
        or contract.get("wire_protocol_version")
        != authority.get("wire_protocol_version")
        or SHA256.fullmatch(str(contract.get("contract_lock_sha256"))) is None
        or not isinstance(fixtures, list)
        or not 1 <= len(fixtures) <= 64
        or any(
            not isinstance(item, dict)
            or set(item) != {"name", "sha256"}
            or not isinstance(item.get("name"), str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item["name"])
            is None
            or SHA256.fullmatch(str(item.get("sha256"))) is None
            for item in fixtures
        )
        or fixtures != sorted(fixtures, key=lambda item: item["name"])
        or len({item["name"] for item in fixtures}) != len(fixtures)
        or fixtures != authority.get("fixtures")
        or verification
        != {
            "schema_version": 1,
            "source_repository_commit": coordinate.get("commit"),
            "contract_version": contract.get("contract_version"),
            "core_release": contract.get("core_release"),
            "core_commit": contract.get("core_commit"),
            "bundle_sha256": contract.get("bundle_sha256"),
            "wire_protocol_version": contract.get("wire_protocol_version"),
            "contract_lock_sha256": contract.get("contract_lock_sha256"),
            "fixture_count": len(fixtures) if isinstance(fixtures, list) else 0,
            "fixture_set_sha256": hashlib.sha256(canonical_json(fixtures)).hexdigest()
            if isinstance(fixtures, list)
            else "",
        }
    ):
        raise ProofError("npm_contract_source_verification_invalid")


def javascript_contract_authority(source: Mapping[str, Any]) -> dict[str, Any]:
    document = source.get("document")
    contract = source.get("contract")
    checks = document.get("checks") if isinstance(document, dict) else None
    selected = {
        identifier: [
            check
            for check in checks
            if isinstance(check, dict) and check.get("id") == identifier
        ]
        if isinstance(checks, list)
        else []
        for identifier in ("source.contract_locks", "source.generated_fixtures")
    }
    if any(len(matches) != 1 for matches in selected.values()):
        raise ProofError("npm_contract_source_authority_invalid")
    lock = selected["source.contract_locks"][0].get("details")
    generated = selected["source.generated_fixtures"][0].get("details")
    fixture_hashes = (
        generated.get("fixture_sha256") if isinstance(generated, dict) else None
    )
    if (
        not isinstance(contract, dict)
        or not isinstance(lock, dict)
        or set(lock)
        != {
            "lock_count", "core_release", "contract_source_commit",
            "minimum_server_version", "maximum_tested_server_version",
        }
        or not isinstance(lock.get("lock_count"), int)
        or isinstance(lock.get("lock_count"), bool)
        or lock["lock_count"] < 1
        or lock.get("core_release") != contract.get("core_release")
        or COMMIT.fullmatch(str(lock.get("contract_source_commit"))) is None
        or not isinstance(generated, dict)
        or set(generated)
        != {"fixture_count_per_sdk", "sdk_count", "fixture_sha256"}
        or generated.get("sdk_count") != 4
        or not isinstance(fixture_hashes, dict)
        or generated.get("fixture_count_per_sdk") != len(fixture_hashes)
        or not 1 <= len(fixture_hashes) <= 64
        or any(
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None
            or SHA256.fullmatch(str(sha256)) is None
            for name, sha256 in fixture_hashes.items()
        )
    ):
        raise ProofError("npm_contract_source_authority_invalid")
    return {
        "contract_version": contract.get("version"),
        "core_release": contract.get("core_release"),
        "core_commit": lock.get("contract_source_commit"),
        "bundle_sha256": contract.get("bundle_sha256"),
        "wire_protocol_version": contract.get("wire_protocol"),
        "fixtures": [
            {"name": name, "sha256": fixture_hashes[name]}
            for name in sorted(fixture_hashes)
        ],
    }


def validate_javascript_checksum_verification(
    envelope: Any, verification: Any, package_items: Any, version: Any
) -> None:
    if not isinstance(package_items, list) or len(package_items) != 4:
        raise ProofError("npm_checksum_verification_invalid")
    entries: list[dict[str, str]] = []
    lines: list[str] = []
    for index, (package_id, package) in enumerate(JAVASCRIPT_NPM_PACKAGES):
        item = package_items[index]
        name = f"latchway-{package_id}-{version}.tgz"
        sha256 = item.get("sha256") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or item.get("id") != package_id
            or item.get("package") != package
            or SHA256.fullmatch(str(sha256)) is None
        ):
            raise ProofError("npm_checksum_verification_invalid")
        entries.append({"name": name, "sha256": sha256})
        lines.append(f"{sha256}  {name}")
    expected = ("\n".join(sorted(lines)) + "\n").encode("ascii")
    payload = decode_retained(envelope, "SHA256SUMS")
    if (
        payload != expected
        or verification
        != {
            "schema_version": 1,
            "algorithm": "sha256",
            "file": "SHA256SUMS",
            "file_sha256": hashlib.sha256(payload).hexdigest(),
            "entries": sorted(entries, key=lambda item: item["name"]),
        }
    ):
        raise ProofError("npm_checksum_verification_invalid")


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


def read_binary(path: Path, maximum: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= maximum:
            raise ProofError("proof_file_invalid")
        return path.read_bytes()
    except ProofError:
        raise
    except OSError:
        raise ProofError("proof_file_invalid") from None


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


def exact_artifact(document: Mapping[str, Any], suffix: str) -> dict[str, str]:
    artifacts = document.get("artifacts")
    matches = [item for item in artifacts if isinstance(item, dict) and str(item.get("path", "")).endswith(suffix)] if isinstance(artifacts, list) else []
    if len(matches) != 1 or set(matches[0]) != {"path", "sha256"}:
        raise ProofError("registry_proof_artifact_missing")
    return matches[0]


def require_hash(value: Any) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ProofError("registry_proof_hash_invalid")
    return value


def load_javascript_retained_tarballs(
    root: Path,
    document: Mapping[str, Any],
    manifest_hashes: Mapping[str, str],
    version: str,
) -> dict[str, bytes]:
    expected_suffixes = {
        f"artifacts--registry-npm-javascript--latchway-{package_id}-{version}.tgz"
        for package_id, _ in JAVASCRIPT_NPM_PACKAGES
    }
    artifacts = document.get("artifacts")
    observed_suffixes = {
        str(item.get("path", "")).rsplit("/", 1)[-1]
        for item in artifacts
        if isinstance(item, dict)
        and "artifacts--registry-npm-javascript--latchway-"
        in str(item.get("path", ""))
        and str(item.get("path", "")).endswith(".tgz")
    } if isinstance(artifacts, list) else set()
    if observed_suffixes != expected_suffixes:
        raise ProofError("npm_reproducibility_retained_tarballs_invalid")
    retained: dict[str, bytes] = {}
    for package_id, _ in JAVASCRIPT_NPM_PACKAGES:
        name = f"latchway-{package_id}-{version}.tgz"
        artifact = exact_artifact(
            document, f"artifacts--registry-npm-javascript--{name}"
        )
        path = safe_path(root, artifact["path"])
        expected = require_hash(artifact["sha256"])
        if digest(path) != expected or manifest_hashes.get(artifact["path"]) != expected:
            raise ProofError("npm_reproducibility_retained_tarballs_invalid")
        retained[name] = read_binary(path, MAXIMUM_RETAINED_NPM_TARBALL_BYTES)
    return retained


def nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, Mapping):
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


def validate_mintlify_retained_container(
    value: Any,
    proof: Mapping[str, Any],
    *,
    now: datetime,
) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "kind", "observation", "files"}
        or value.get("schema_version") != 1
        or value.get("kind") != "latchway_retained_mintlify_production_evidence"
        or value.get("observation") != "registry.documentation-production"
        or not isinstance(value.get("files"), list)
        or len(value["files"]) != len(MINTLIFY.RETAINED_FILES)
    ):
        raise ProofError("mintlify_retained_input_container_invalid")
    payloads: dict[str, bytes] = {}
    for item in value["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "sha256", "content_base64"}
            or not isinstance(item.get("name"), str)
            or item["name"] in payloads
            or SHA256.fullmatch(str(item.get("sha256"))) is None
            or not isinstance(item.get("content_base64"), str)
        ):
            raise ProofError("mintlify_retained_input_container_invalid")
        try:
            payload = base64.b64decode(item["content_base64"], validate=True)
        except (binascii.Error, ValueError):
            raise ProofError("mintlify_retained_input_container_invalid") from None
        if (
            not 1 <= len(payload) <= MAXIMUM
            or hashlib.sha256(payload).hexdigest() != item["sha256"]
        ):
            raise ProofError("mintlify_retained_input_container_invalid")
        payloads[item["name"]] = payload
    if set(payloads) != set(MINTLIFY.RETAINED_FILES):
        raise ProofError("mintlify_retained_input_container_invalid")
    if [item["name"] for item in value["files"]] != sorted(
        MINTLIFY.RETAINED_FILES
    ):
        raise ProofError("mintlify_retained_input_container_invalid")
    run = nested(proof, "authority", "run")
    if not isinstance(run, dict):
        raise ProofError("mintlify_retained_input_container_invalid")
    try:
        recomputed = MINTLIFY.build_proof(
            documentation=proof.get("documentation"),
            evidence_payload=payloads[MINTLIFY.EVIDENCE_FILE],
            checksum_payload=payloads[MINTLIFY.CHECKSUM_FILE],
            attestation_bundle_payload=payloads[MINTLIFY.ATTESTATION_FILE],
            run_payload=payloads["run.json"],
            workflow_payload=payloads["workflow.json"],
            artifact_payload=payloads["artifact.json"],
            attestation_verification_payload=payloads[
                "attestation-verification.json"
            ],
            expected_run_id=run.get("id"),
            expected_run_attempt=run.get("run_attempt"),
            now=now,
        )
    except MINTLIFY.ProofError as error:
        raise ProofError(str(error)) from None
    if recomputed != proof:
        raise ProofError("mintlify_retained_input_container_invalid")


def validate_cocoapods_spec(
    value: Any, coordinate: Mapping[str, Any]
) -> None:
    source = value.get("source") if isinstance(value, dict) else None
    subspecs = value.get("subspecs") if isinstance(value, dict) else None
    names = (
        [item.get("name") for item in subspecs if isinstance(item, dict)]
        if isinstance(subspecs, list)
        else []
    )

    def contains_forbidden_hook(item: Any) -> bool:
        if isinstance(item, dict):
            return bool(COCOAPODS_FORBIDDEN_HOOKS.intersection(item)) or any(
                contains_forbidden_hook(child) for child in item.values()
            )
        if isinstance(item, list):
            return any(contains_forbidden_hook(child) for child in item)
        return False

    if (
        not isinstance(value, dict)
        or value.get("name") != "Latchway"
        or value.get("version") != coordinate.get("version")
        or source
        != {
            "git": "https://github.com/Latchway/latchway-ios-sdk.git",
            "tag": coordinate.get("tag"),
        }
        or not isinstance(subspecs, list)
        or len(names) != len(subspecs)
        or any(not isinstance(name, str) for name in names)
        or len(names) != len(set(names))
        or set(names) != IOS_COCOAPODS_SUBSPECS
        or contains_forbidden_hook(value)
    ):
        raise ProofError("cocoapods_spec_invalid")


def validate_swift_resolution(
    value: Any, coordinate: Mapping[str, Any]
) -> None:
    pins = value.get("pins") if isinstance(value, dict) else None
    if not isinstance(pins, list):
        raise ProofError("swift_registry_resolution_invalid")
    matches = [
        pin
        for pin in pins
        if isinstance(pin, dict)
        and pin.get("identity") == "latchway-ios-sdk"
        and pin.get("kind") == "remoteSourceControl"
        and pin.get("location")
        == "https://github.com/Latchway/latchway-ios-sdk.git"
        and pin.get("state")
        == {
            "revision": coordinate.get("commit"),
            "version": coordinate.get("version"),
        }
    ]
    if len(matches) != 1:
        raise ProofError("swift_registry_resolution_invalid")


def expected_npm_release_assets(package: str, version: str) -> tuple[set[str], str]:
    if package == "@latchway/client":
        tarball = f"latchway-client-{version}.tgz"
        fixed = {
            *(f"latchway-{package_id}-{version}.tgz" for package_id, _ in JAVASCRIPT_NPM_PACKAGES),
            f"docs-bundle-{version}.tar.gz",
            "SHA256SUMS",
            "build-reproducibility.json",
            "contract-evidence.json",
            "dependency-vulnerability-scan.json",
            "package-evidence.json",
            "post-publish-evidence.json",
            "publish-input-evidence.json",
            "release-candidate-evidence.json",
            "tag-evidence.json",
            "npm-registry-evidence-manifest.json",
        }
        for package_id, _ in JAVASCRIPT_NPM_PACKAGES:
            fixed.update(
                {
                    f"npm-{package_id}-registry-version.json",
                    f"npm-{package_id}-registry-view.json",
                    f"npm-{package_id}-attestations.json",
                    f"npm-{package_id}-audit-signatures.json",
                }
            )
        if len(fixed) != 31:
            raise ProofError("npm_release_asset_set_invalid")
        return fixed, tarball
    if package == "@latchway/react-native":
        tarball = f"latchway-react-native-{version}.tgz"
        return {
            tarball, f"{tarball}.sha256", f"docs-bundle-{version}.tar.gz", "package-evidence.json", "build-reproducibility.json",
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
                if JAVASCRIPT_NPM_ADOPTION.fullmatch(name)
            }
            exact_names = fixed | adoptions
            adoption_ids = {
                match.group(1)
                for name in adoptions
                if (match := JAVASCRIPT_NPM_ADOPTION.fullmatch(name)) is not None
            }
            if adoption_ids != {package_id for package_id, _ in JAVASCRIPT_NPM_PACKAGES}:
                raise ProofError("rn_dependency_evidence_invalid")
        elif repository_id == "ios":
            archive = f"latchway-ios-sdk-{version}.tar.gz"
            exact_names = {
                archive, f"{archive}.sha256", "cocoapods-published-podspec.json",
                "cocoapods-reviewed-podspec.json", "cocoapods-release-evidence.json",
                "cocoapods-release-evidence.SHA256SUMS", f"docs-bundle-{version}.tar.gz",
            }
        else:
            exact_names = {
                f"latchway-android-{version}-maven-repository.zip",
                f"latchway-android-{version}-central-portal.zip",
                f"docs-bundle-{version}.tar.gz",
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
            or not valid_npm_adoption_mode(
                adoption.get("mode"),
                int(match.group(1)) if match is not None else None,
                int(match.group(2)) if match is not None else None,
                provenance.get("run_id"),
                provenance.get("run_attempt"),
            )
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
        f"docs-bundle-{coordinate.get('version')}.tar.gz",
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
        or (
            package == "@latchway/react-native"
            and (
                not isinstance(source_verifications, dict)
                or set(attestations) | set(source_verifications)
                != expected_source_attested_release_assets(
                    "react_native", str(coordinate.get("version")), release_set
                )
            )
        )
    ):
        raise ProofError("npm_release_asset_attestation_invalid")


def validate_javascript_npm_set(
    value: dict[str, Any],
    coordinate: dict[str, Any],
    contract_authority: Mapping[str, Any],
    retained_tarballs: Mapping[str, bytes],
) -> None:
    order = [package for _, package in JAVASCRIPT_NPM_PACKAGES]
    version = coordinate.get("version")
    fixed, _ = expected_npm_release_assets("@latchway/client", str(version))
    packages = value.get("packages")
    aggregate = value.get("reviewed_aggregate_evidence")
    retained_aggregate = value.get("retained_aggregate_evidence")
    release_set = value.get("release_asset_set")
    immutable = value.get("immutable_release_asset_verifications")
    attestations = value.get("release_asset_attestation_verifications")
    reproducibility_verification = value.get(
        "reproducibility_archive_verification"
    )
    checksum_verification = value.get("checksum_verification")
    contract_source_verification = value.get("contract_source_verification")
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version", "kind", "registry", "version", "source_commit",
            "release_tag", "package_count", "publish_order", "packages",
            "reviewed_aggregate_evidence", "retained_aggregate_evidence",
            "checksum_verification", "contract_source_verification",
            "reproducibility_archive_verification",
            "release_asset_set", "immutable_release_asset_verifications",
            "release_asset_attestation_verifications", "compatibility",
        }
        or value.get("schema_version") != 2
        or value.get("kind") != "latchway_npm_package_set_registry_proof"
        or value.get("registry") != "npm"
        or value.get("version") != version
        or value.get("source_commit") != coordinate.get("commit")
        or value.get("release_tag") != coordinate.get("tag")
        or value.get("package_count") != 4
        or value.get("publish_order") != order
        or not isinstance(packages, list)
        or len(packages) != 4
        or not isinstance(aggregate, dict)
        or not isinstance(retained_aggregate, dict)
        or not isinstance(release_set, dict)
        or not isinstance(immutable, dict)
        or not isinstance(attestations, dict)
        or value.get("compatibility") != {"minimum_node": "24.19.0"}
    ):
        raise ProofError("npm_package_set_proof_invalid")
    if (
        set(aggregate) != JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS
        or set(retained_aggregate) != JAVASCRIPT_NPM_AGGREGATE_ASSETS
    ):
        raise ProofError("npm_aggregate_evidence_invalid")
    for name in JAVASCRIPT_NPM_AGGREGATE_JSON_ASSETS:
        if load_retained_json(retained_aggregate[name], name) != aggregate[name]:
            raise ProofError("npm_aggregate_evidence_invalid")
    observed_names = set(release_set)
    adoption_names = observed_names - fixed
    adoption_ids = {
        match.group(1)
        for name in adoption_names
        if (match := JAVASCRIPT_NPM_ADOPTION.fullmatch(name)) is not None
    }
    if (
        not fixed.issubset(observed_names)
        or len(fixed) != 31
        or any(JAVASCRIPT_NPM_ADOPTION.fullmatch(name) is None for name in adoption_names)
        or adoption_ids != {package_id for package_id, _ in JAVASCRIPT_NPM_PACKAGES}
        or set(immutable) != observed_names
        or set(attestations)
        != expected_source_attested_release_assets(
            "javascript", str(version), observed_names
        )
        or any(not isinstance(item, dict) or not item for item in immutable.values())
        or any(not verification for verification in attestations.values())
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
    for name, envelope in retained_aggregate.items():
        if (
            release_set[name]["digest"] != envelope.get("release_digest")
            or release_set[name]["size"] != envelope.get("bytes")
        ):
            raise ProofError("npm_aggregate_evidence_invalid")

    package_evidence = aggregate["package-evidence.json"]
    candidate = aggregate["release-candidate-evidence.json"]
    publish_input = aggregate["publish-input-evidence.json"]
    post = aggregate["post-publish-evidence.json"]
    manifest = aggregate["npm-registry-evidence-manifest.json"]
    reproducibility = aggregate["build-reproducibility.json"]
    contract = aggregate["contract-evidence.json"]
    source_binding = {
        "repository": "https://github.com/Latchway/latchway-js",
        "commit": coordinate.get("commit"),
        "workflow": ".github/workflows/release.yml",
        "ref": "refs/heads/main",
    }
    gates = [
        "workflow-policy", "contract-lock", "release-policy", "lint", "typecheck",
        "clean-build", "unit-tests", "offline-release-tests", "examples", "exports",
        "web-browser-and-bundler-conformance", "build-reproducibility",
        "package-conformance",
    ]
    package_items = package_evidence.get("packages") if isinstance(package_evidence, dict) else None
    candidate_gates = candidate.get("gates") if isinstance(candidate, dict) else None
    publish_packages = publish_input.get("packages") if isinstance(publish_input, dict) else None
    manifest_packages = manifest.get("packages") if isinstance(manifest, dict) else None
    post_packages = post.get("packages") if isinstance(post, dict) else None
    reproducibility_files = (
        reproducibility.get("files") if isinstance(reproducibility, dict) else None
    )
    reproducibility_prefixes = {
        package: ("dist/" if package_id == "client" else f"packages/{package_id}/dist/")
        for package_id, package in JAVASCRIPT_NPM_PACKAGES
    }
    if (
        not isinstance(package_evidence, dict)
        or set(package_evidence)
        != {"schema_version", "kind", "version", "package_count", "publish_order", "packages", "consumer"}
        or package_evidence.get("schema_version") != 2
        or package_evidence.get("kind") != "latchway_npm_package_set_evidence"
        or package_evidence.get("version") != version
        or package_evidence.get("package_count") != 4
        or package_evidence.get("publish_order") != order
        or not isinstance(package_items, list)
        or len(package_items) != 4
        or not isinstance(package_evidence.get("consumer"), dict)
        or set(package_evidence["consumer"]) != {"package_count", "packages", "node_esm", "typescript", "peer_source"}
        or nested(package_evidence, "consumer", "package_count") != 4
        or nested(package_evidence, "consumer", "node_esm") is not True
        or nested(package_evidence, "consumer", "typescript") is not True
        or nested(package_evidence, "consumer", "peer_source") != "reviewed"
        or not isinstance(package_evidence["consumer"].get("packages"), list)
        or len(package_evidence["consumer"]["packages"]) != 4
        or any(not isinstance(item, dict) or set(item) != {"name", "version"} for item in package_evidence["consumer"]["packages"])
        or [item["name"] for item in package_evidence["consumer"]["packages"]] != order
        or any(item["version"] != version for item in package_evidence["consumer"]["packages"])
        or not isinstance(candidate, dict)
        or set(candidate)
        != {"schema_version", "package_count", "packages", "version", "source_commit", "worktree_clean", "stable_version", "node", "pnpm", "gates"}
        or candidate.get("schema_version") != 2
        or candidate.get("package_count") != 4
        or candidate.get("packages") != order
        or candidate.get("version") != version
        or candidate.get("source_commit") != coordinate.get("commit")
        or candidate.get("worktree_clean") is not True
        or candidate.get("stable_version") is not True
        or candidate.get("node") != "v24.19.0"
        or candidate.get("pnpm") != "10.15.0"
        or not isinstance(candidate_gates, list)
        or [item.get("name") for item in candidate_gates if isinstance(item, dict)] != gates
        or any(
            not isinstance(item, dict)
            or set(item) != {"name", "status", "duration_ms"}
            or item.get("status") != "passed"
            or not isinstance(item.get("duration_ms"), int)
            or isinstance(item.get("duration_ms"), bool)
            or item["duration_ms"] < 0
            for item in candidate_gates
        )
        or not isinstance(publish_input, dict)
        or set(publish_input)
        != {"schema_version", "kind", "version", "source_commit", "release_tag", "package_count", "publish_order", "packages", "verified_job_evidence", "package_evidence", "checksums", "consumer"}
        or publish_input.get("schema_version") != 2
        or publish_input.get("kind") != "latchway_npm_publish_input_evidence"
        or publish_input.get("version") != version
        or publish_input.get("source_commit") != coordinate.get("commit")
        or publish_input.get("release_tag") != coordinate.get("tag")
        or publish_input.get("package_count") != 4
        or publish_input.get("publish_order") != order
        or publish_input.get("verified_job_evidence") is not True
        or not isinstance(publish_packages, list)
        or len(publish_packages) != 4
        or not isinstance(publish_input.get("consumer"), dict)
        or set(publish_input["consumer"]) != {"package_count", "packages", "node_esm", "typescript", "peer_source"}
        or nested(publish_input, "consumer", "package_count") != 4
        or nested(publish_input, "consumer", "node_esm") is not True
        or nested(publish_input, "consumer", "typescript") is not False
        or nested(publish_input, "consumer", "peer_source") != "registry"
        or not isinstance(publish_input["consumer"].get("packages"), list)
        or len(publish_input["consumer"]["packages"]) != 4
        or any(not isinstance(item, dict) or set(item) != {"name", "version"} for item in publish_input["consumer"]["packages"])
        or [item["name"] for item in publish_input["consumer"]["packages"]] != order
        or any(item["version"] != version for item in publish_input["consumer"]["packages"])
        or not isinstance(publish_input.get("package_evidence"), dict)
        or set(publish_input["package_evidence"]) != {"file", "sha256"}
        or nested(publish_input, "package_evidence", "file") != "package-evidence.json"
        or nested(publish_input, "package_evidence", "sha256")
        != release_set["package-evidence.json"]["digest"].removeprefix("sha256:")
        or not isinstance(publish_input.get("checksums"), dict)
        or set(publish_input["checksums"]) != {"file", "sha256"}
        or nested(publish_input, "checksums", "file") != "SHA256SUMS"
        or nested(publish_input, "checksums", "sha256")
        != release_set["SHA256SUMS"]["digest"].removeprefix("sha256:")
        or not isinstance(manifest, dict)
        or set(manifest)
        != {"schema_version", "kind", "version", "package_count", "publish_order", "packages"}
        or manifest.get("schema_version") != 2
        or manifest.get("kind") != "latchway_npm_registry_package_set_evidence_manifest"
        or manifest.get("version") != version
        or manifest.get("package_count") != 4
        or manifest.get("publish_order") != order
        or not isinstance(manifest_packages, list)
        or len(manifest_packages) != 4
        or not isinstance(post, dict)
        or set(post)
        != {"schema_version", "kind", "version", "package_count", "publish_order", "source", "release_tag", "registry", "packages", "evidence_manifest"}
        or post.get("schema_version") != 3
        or post.get("kind") != "latchway_npm_package_set_publication_evidence"
        or post.get("version") != version
        or post.get("package_count") != 4
        or post.get("publish_order") != order
        or post.get("source") != source_binding
        or post.get("release_tag") != coordinate.get("tag")
        or post.get("registry") != "https://registry.npmjs.org/"
        or not isinstance(post_packages, list)
        or len(post_packages) != 4
        or post.get("evidence_manifest")
        != {
            "file": "npm-registry-evidence-manifest.json",
            "bytes": retained_aggregate["npm-registry-evidence-manifest.json"]["bytes"],
            "sha256": retained_aggregate["npm-registry-evidence-manifest.json"]["sha256"],
        }
        or not isinstance(reproducibility, dict)
        or set(reproducibility) != {"schema_version", "identical", "package_count", "sha256", "files"}
        or reproducibility.get("schema_version") != 1
        or reproducibility.get("identical") is not True
        or reproducibility.get("package_count") != 4
        or SHA256.fullmatch(str(reproducibility.get("sha256"))) is None
        or not isinstance(reproducibility_files, list)
        or not reproducibility_files
        or any(
            not isinstance(item, dict)
            or set(item) != {"package", "path", "bytes", "sha256"}
            or item.get("package") not in order
            or not isinstance(item.get("path"), str)
            or not item["path"].startswith(
                reproducibility_prefixes.get(item.get("package"), "\0")
            )
            or "\\" in item["path"]
            or ".." in item["path"].split("/")
            or not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or item["bytes"] < 1
            or SHA256.fullmatch(str(item.get("sha256"))) is None
            for item in reproducibility_files
        )
        or len({item["path"] for item in reproducibility_files})
        != len(reproducibility_files)
        or {item["package"] for item in reproducibility_files} != set(order)
        or [(item["package"], item["path"]) for item in reproducibility_files]
        != sorted(
            ((item["package"], item["path"]) for item in reproducibility_files),
            key=lambda item: (order.index(item[0]), item[1]),
        )
    ):
        raise ProofError("npm_aggregate_evidence_invalid")
    validate_javascript_reproducibility_archive_verification(
        reproducibility, reproducibility_verification
    )
    validate_javascript_reproducibility_tarballs(
        value, coordinate, retained_tarballs
    )
    validate_javascript_supporting_evidence(aggregate, coordinate)
    validate_javascript_contract_source_verification(
        contract, contract_source_verification, coordinate, contract_authority
    )
    validate_javascript_checksum_verification(
        retained_aggregate["SHA256SUMS"],
        checksum_verification,
        package_items,
        version,
    )

    all_seen_adoptions: set[str] = set()
    for index, (package_id, package) in enumerate(JAVASCRIPT_NPM_PACKAGES):
        proof = packages[index]
        reviewed = package_items[index]
        published = publish_packages[index]
        manifest_item = manifest_packages[index]
        post_item = post_packages[index]
        tarball_name = f"latchway-{package_id}-{version}.tgz"
        tarball = {
            "name": tarball_name,
            "bytes": reviewed.get("bytes") if isinstance(reviewed, dict) else None,
            "sha256": reviewed.get("sha256") if isinstance(reviewed, dict) else None,
            "sha512": reviewed.get("sha512") if isinstance(reviewed, dict) else None,
            "integrity": reviewed.get("integrity") if isinstance(reviewed, dict) else None,
        }
        if (
            not isinstance(reviewed, dict)
            or set(reviewed)
            != {"id", "package", "version", "tarball", "bytes", "sha1", "sha256", "sha512", "integrity", "double_pack_byte_identical", "archive_allowlist_verified", "archive_regular_files_only", "credential_scan", "entries", "unpacked_bytes", "published_peer_dependencies"}
            or reviewed.get("id") != package_id
            or reviewed.get("package") != package
            or reviewed.get("version") != version
            or reviewed.get("tarball") != tarball_name
            or not isinstance(reviewed.get("bytes"), int)
            or isinstance(reviewed.get("bytes"), bool)
            or reviewed["bytes"] < 1
            or re.fullmatch(r"[0-9a-f]{40}", str(reviewed.get("sha1"))) is None
            or SHA256.fullmatch(str(reviewed.get("sha256"))) is None
            or re.fullmatch(r"[0-9a-f]{128}", str(reviewed.get("sha512"))) is None
            or not valid_sha512_integrity(reviewed.get("integrity"))
            or reviewed.get("double_pack_byte_identical") is not True
            or reviewed.get("archive_allowlist_verified") is not True
            or reviewed.get("archive_regular_files_only") is not True
            or reviewed.get("credential_scan") != "passed"
            or not isinstance(reviewed.get("entries"), list)
            or not reviewed["entries"]
            or reviewed["entries"] != sorted(set(reviewed["entries"]))
            or any(
                not isinstance(entry, str)
                or re.fullmatch(
                    r"package/(?:[A-Za-z0-9@._+-]+/)*[A-Za-z0-9@._+-]+",
                    entry,
                )
                is None
                for entry in reviewed["entries"]
            )
            or not isinstance(reviewed.get("unpacked_bytes"), int)
            or isinstance(reviewed.get("unpacked_bytes"), bool)
            or not 1 <= reviewed["unpacked_bytes"] <= 25 * 1024 * 1024
            or not isinstance(reviewed.get("published_peer_dependencies"), dict)
            or any(
                not isinstance(name, str)
                or not name
                or not isinstance(requirement, str)
                or not requirement
                for name, requirement in reviewed[
                    "published_peer_dependencies"
                ].items()
            )
            or not isinstance(published, dict)
            or set(published) != {"id", "package", "version", "tarball", "bytes", "sha1", "sha256", "sha512", "integrity"}
            or published.get("id") != package_id
            or published.get("package") != package
            or published.get("version") != version
            or published.get("tarball") != tarball_name
            or any(published.get(field) != reviewed.get(field) for field in ("bytes", "sha1", "sha256", "sha512", "integrity"))
            or not isinstance(manifest_item, dict)
            or set(manifest_item) != {"id", "package", "version", "tarball", "evidence"}
            or manifest_item.get("id") != package_id
            or manifest_item.get("package") != package
            or manifest_item.get("version") != version
            or manifest_item.get("tarball") != tarball
            or not isinstance(post_item, dict)
            or set(post_item) != {"id", "package", "version", "publication_mode", "tarball", "trusted_publisher", "registry_signature_verification", "clean_consumer", "retained_outputs"}
            or post_item.get("id") != package_id
            or post_item.get("package") != package
            or post_item.get("version") != version
            or post_item.get("publication_mode") != "published"
            or nested(post_item, "tarball", "name") != tarball_name
            or any(nested(post_item, "tarball", field) != tarball[field] for field in ("bytes", "sha256", "sha512", "integrity"))
            or nested(post_item, "tarball", "registry_bytes_sha256") != reviewed.get("sha256")
            or release_set[tarball_name]["size"] != reviewed.get("bytes")
        ):
            raise ProofError("npm_package_set_order_invalid")
        _validate_javascript_npm_package_proof(
            proof,
            package_id=package_id,
            package=package,
            coordinate=coordinate,
            reviewed=reviewed,
            manifest_item=manifest_item,
            post_item=post_item,
            release_set=release_set,
            adoption_names=adoption_names,
            manifest_sha256=retained_aggregate["npm-registry-evidence-manifest.json"]["sha256"],
            all_seen_adoptions=all_seen_adoptions,
        )
    if all_seen_adoptions != adoption_names:
        raise ProofError("npm_adoption_proof_invalid")


def _validate_javascript_npm_package_proof(
    value: Any,
    *,
    package_id: str,
    package: str,
    coordinate: Mapping[str, Any],
    reviewed: Mapping[str, Any],
    manifest_item: Mapping[str, Any],
    post_item: Mapping[str, Any],
    release_set: Mapping[str, Mapping[str, Any]],
    adoption_names: set[str],
    manifest_sha256: str,
    all_seen_adoptions: set[str],
) -> None:
    retained = value.get("registry_evidence") if isinstance(value, dict) else None
    live = value.get("independent_live_registry_evidence") if isinstance(value, dict) else None
    provenance = value.get("provenance") if isinstance(value, dict) else None
    adoptions = value.get("adoptions") if isinstance(value, dict) else None
    raw_names = {
        f"npm-{package_id}-registry-version.json",
        f"npm-{package_id}-registry-view.json",
        f"npm-{package_id}-attestations.json",
        f"npm-{package_id}-audit-signatures.json",
    }
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "id", "package", "version", "registry_tarball_url",
            "registry_integrity", "tarball", "bytes", "sha1", "sha256", "sha512",
            "integrity", "registry_tarball_byte_identical", "provenance",
            "registry_evidence", "independent_live_registry_evidence",
            "adoptions",
        }
        or value.get("id") != package_id
        or value.get("package") != package
        or value.get("version") != coordinate.get("version")
        or value.get("tarball") != reviewed.get("tarball")
        or value.get("bytes") != reviewed.get("bytes")
        or value.get("sha1") != reviewed.get("sha1")
        or value.get("sha256") != reviewed.get("sha256")
        or value.get("sha512") != reviewed.get("sha512")
        or value.get("integrity") != reviewed.get("integrity")
        or value.get("registry_integrity") != reviewed.get("integrity")
        or value.get("registry_tarball_byte_identical") is not True
        or release_set.get(str(reviewed.get("tarball")), {}).get("digest")
        != f"sha256:{reviewed.get('sha256')}"
        or not isinstance(retained, dict)
        or set(retained) != raw_names
        or not isinstance(live, dict)
        or set(live) != {"npm_attestations", "npm_audit_signatures", "npm_view"}
        or not isinstance(provenance, dict)
        or not isinstance(adoptions, list)
        or not adoptions
    ):
        raise ProofError("npm_package_proof_invalid")
    retained_docs = {name: load_retained_json(retained[name], name) for name in raw_names}
    manifest_evidence = manifest_item.get("evidence")
    evidence_by_name = {
        item.get("name"): item
        for item in manifest_evidence
        if isinstance(item, dict)
    } if isinstance(manifest_evidence, list) else {}
    post_outputs = post_item.get("retained_outputs")
    if set(evidence_by_name) != raw_names or not isinstance(post_outputs, dict) or set(post_outputs) != raw_names:
        raise ProofError("npm_registry_manifest_invalid")
    for name in raw_names:
        reference = {"name": name, "bytes": retained[name]["bytes"], "sha256": retained[name]["sha256"]}
        if (
            evidence_by_name[name] != reference
            or post_outputs[name] != {"bytes": reference["bytes"], "sha256": reference["sha256"]}
            or release_set[name]["digest"] != retained[name]["release_digest"]
            or release_set[name]["size"] != retained[name]["bytes"]
        ):
            raise ProofError("npm_registry_manifest_invalid")
    version_name = f"npm-{package_id}-registry-version.json"
    view_name = f"npm-{package_id}-registry-view.json"
    attestation_name = f"npm-{package_id}-attestations.json"
    audit_name = f"npm-{package_id}-audit-signatures.json"
    for name in (version_name, view_name):
        document = retained_docs[name]
        if (
            document.get("name") != package
            or document.get("version") != coordinate.get("version")
            or nested(document, "dist", "integrity") != reviewed.get("integrity")
            or nested(document, "dist", "tarball")
            != value.get("registry_tarball_url")
        ):
            raise ProofError("npm_retained_metadata_invalid")
    if "error" in retained_docs[audit_name]:
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
        live_documents[name] = document
    if (
        live["npm_attestations"]["sha256"] != retained[attestation_name]["sha256"]
        or live_documents["npm_view"] != retained_docs[view_name]
        or live_documents["npm_audit_signatures"] != retained_docs[audit_name]
    ):
        raise ProofError("npm_registry_evidence_changed")
    try:
        provenance_bytes = base64.b64decode(provenance.get("attestations_content_base64", ""), validate=True)
    except (binascii.Error, ValueError):
        raise ProofError("npm_attestation_document_hash_invalid") from None
    run = provenance.get("authenticated_run")
    repository = "Latchway/latchway-js"
    expected_invocation = (
        f"https://github.com/{repository}/actions/runs/"
        f"{provenance.get('run_id')}/attempts/{provenance.get('run_attempt')}"
    )
    if (
        set(provenance)
        != {
            "attestations_sha256", "attestations_content_base64",
            "source_repository", "source_commit", "workflow", "workflow_ref",
            "invocation_id", "run_id", "run_attempt", "run_conclusion",
            "certificate_identity", "authenticated_run",
        }
        or hashlib.sha256(provenance_bytes).hexdigest()
        != provenance.get("attestations_sha256")
        or provenance.get("attestations_sha256") != retained[attestation_name]["sha256"]
        or provenance.get("source_repository") != repository
        or provenance.get("source_commit") != coordinate.get("commit")
        or provenance.get("workflow") != ".github/workflows/release.yml"
        or provenance.get("workflow_ref") != "refs/heads/main"
        or provenance.get("invocation_id") != expected_invocation
        or provenance.get("certificate_identity")
        != (
            "URI:https://github.com/Latchway/latchway-js/"
            ".github/workflows/release.yml@refs/heads/main"
        )
        or not isinstance(provenance.get("run_id"), int)
        or isinstance(provenance.get("run_id"), bool)
        or provenance["run_id"] < 1
        or not isinstance(provenance.get("run_attempt"), int)
        or isinstance(provenance.get("run_attempt"), bool)
        or provenance["run_attempt"] < 1
        or provenance.get("run_conclusion") not in {"success", "failure", "cancelled", "timed_out"}
        or not isinstance(run, dict)
        or run.get("id") != provenance.get("run_id")
        or run.get("run_attempt") != provenance.get("run_attempt")
        or run.get("event") != "repository_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != provenance.get("run_conclusion")
        or run.get("head_sha") != coordinate.get("commit")
        or run.get("head_branch") != "main"
        or run.get("path") != ".github/workflows/release.yml"
        or nested(run, "repository", "full_name") != repository
    ):
        raise ProofError("npm_provenance_run_invalid")
    evidence_references = {
        name: {"bytes": retained[name]["bytes"], "sha256": retained[name]["sha256"]}
        for name in raw_names
    }
    origin = {
        "invocation_id": provenance.get("invocation_id"),
        "run_id": provenance.get("run_id"),
        "run_attempt": provenance.get("run_attempt"),
    }
    if (
        nested(post_item, "trusted_publisher", "provider") != "github"
        or nested(post_item, "trusted_publisher", "provenance_predicate_type") != "https://slsa.dev/provenance/v1"
        or nested(post_item, "trusted_publisher", "provenance_origin") != origin
        or nested(post_item, "trusted_publisher", "sigstore_bundle")
        != {"file": attestation_name, **evidence_references[attestation_name]}
        or post_item.get("registry_signature_verification")
        != {
            "command": "npm audit signatures --json --registry=https://registry.npmjs.org/",
            "output": {"file": audit_name, **evidence_references[audit_name]},
        }
        or post_item.get("retained_outputs") != evidence_references
        or not isinstance(post_item.get("clean_consumer"), dict)
        or set(post_item["clean_consumer"])
        != {
            "isolated_directory", "install_scripts", "exact_package_version",
            "matching_client_version", "external_peer_dependencies", "node_esm",
            "registry_signatures",
        }
        or nested(post_item, "clean_consumer", "isolated_directory") is not True
        or nested(post_item, "clean_consumer", "install_scripts") != "disabled"
        or nested(post_item, "clean_consumer", "exact_package_version") != coordinate.get("version")
        or nested(post_item, "clean_consumer", "matching_client_version")
        != (None if package_id == "client" else coordinate.get("version"))
        or nested(post_item, "clean_consumer", "node_esm") is not True
        or nested(post_item, "clean_consumer", "registry_signatures") is not True
        or not isinstance(
            nested(post_item, "clean_consumer", "external_peer_dependencies"),
            dict,
        )
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(requirement, str)
            or not requirement
            for name, requirement in nested(
                post_item, "clean_consumer", "external_peer_dependencies"
            ).items()
        )
    ):
        raise ProofError("npm_post_publish_binding_invalid")
    package_adoptions = {
        name
        for name in adoption_names
        if (match := JAVASCRIPT_NPM_ADOPTION.fullmatch(name)) is not None
        and match.group(1) == package_id
    }
    if len(adoptions) != len(package_adoptions):
        raise ProofError("npm_adoption_proof_invalid")
    source = {
        "repository": "https://github.com/Latchway/latchway-js",
        "commit": coordinate.get("commit"),
        "workflow": ".github/workflows/release.yml",
        "ref": "refs/heads/main",
    }
    for item in adoptions:
        if not isinstance(item, dict) or set(item) != {"asset", "record", "authenticated_run"}:
            raise ProofError("npm_adoption_proof_invalid")
        record = item["record"]
        envelope = item["asset"]
        name = envelope.get("name") if isinstance(envelope, dict) else None
        match = JAVASCRIPT_NPM_ADOPTION.fullmatch(str(name))
        adoption = record.get("adoption") if isinstance(record, dict) else None
        run = item["authenticated_run"]
        if (
            name not in package_adoptions
            or name in all_seen_adoptions
            or match is None
            or match.group(1) != package_id
            or load_retained_json(envelope, str(name)) != record
            or not isinstance(record, dict)
            or set(record)
            != {"schema_version", "kind", "package", "version", "release_tag", "tarball", "source", "provenance", "adoption", "registry_evidence_manifest"}
            or record.get("schema_version") != 1
            or record.get("kind") != "latchway_npm_release_adoption"
            or record.get("package") != package
            or record.get("version") != coordinate.get("version")
            or record.get("release_tag") != coordinate.get("tag")
            or record.get("tarball")
            != {
                "name": reviewed.get("tarball"), "bytes": reviewed.get("bytes"),
                "sha256": reviewed.get("sha256"), "sha512": reviewed.get("sha512"),
                "integrity": reviewed.get("integrity"),
            }
            or record.get("source") != source
            or record.get("provenance")
            != {
                **source,
                "predicate_type": "https://slsa.dev/provenance/v1",
                **origin,
            }
            or not isinstance(adoption, dict)
            or not valid_npm_adoption_mode(
                adoption.get("mode"),
                int(match.group(2)),
                int(match.group(3)),
                provenance.get("run_id"),
                provenance.get("run_attempt"),
            )
            or adoption
            != {
                **source,
                "run_id": int(match.group(2)),
                "run_attempt": int(match.group(3)),
                "mode": adoption.get("mode"),
            }
            or record.get("registry_evidence_manifest")
            != {"file": "npm-registry-evidence-manifest.json", "sha256": manifest_sha256}
            or not isinstance(run, dict)
            or run.get("id") != adoption.get("run_id")
            or run.get("run_attempt") != adoption.get("run_attempt")
            or run.get("event") != "repository_dispatch"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("head_sha") != coordinate.get("commit")
            or run.get("head_branch") != "main"
            or run.get("path") != ".github/workflows/release.yml"
            or nested(run, "repository", "full_name") != repository
            or release_set[str(name)]["digest"] != envelope.get("release_digest")
            or release_set[str(name)]["size"] != envelope.get("bytes")
        ):
            raise ProofError("npm_adoption_proof_invalid")
        all_seen_adoptions.add(str(name))


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
        f"docs-bundle-{version}.tar.gz",
        "SHA256SUMS",
        "github-release-tag-binding.json",
        "latchway-maven-signing-public-key.asc",
        "maven-central-upload-intent.json",
        "maven-central-deployment.json",
        "maven-central-deployment-status.json",
        "maven-central-release-evidence.json",
    }
    validate_retained_release_set(
        maven,
        expected_assets,
        source_attested_names=expected_source_attested_release_assets(
            "android", version, expected_assets
        ),
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
        or document.get("claims")
        != {
            "cocoapods_verified": True,
            "documentation_production_verified": True,
            "maven_central_verified": True,
            "npm_javascript_verified": True,
            "npm_react_native_verified": True,
            "oci_digest_verified": True,
            "swift_package_verified": True,
        }
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
        "swift": "artifacts--registry-swift--tool-output.json",
        "ios": "artifacts--registry-cocoapods--tool-output.json",
        "android": "artifacts--registry-maven-central--tool-output.json",
        "documentation": "artifacts--registry-documentation-production--tool-output.json",
        "documentation_inputs": "artifacts--registry-documentation-production--mintlify-production-evidence.json",
    }
    for name, suffix in suffixes.items():
        artifact = exact_artifact(document, suffix)
        path = safe_path(root, artifact["path"])
        expected = require_hash(artifact["sha256"])
        if digest(path) != expected or manifest_hashes.get(artifact["path"]) != expected:
            raise ProofError("registry_proof_artifact_hash_mismatch")
        proofs[name] = read_json(path)
    repositories = document["repositories"]
    javascript_version = repositories.get("javascript", {}).get("version")
    if not isinstance(javascript_version, str):
        raise ProofError("npm_reproducibility_retained_tarballs_invalid")
    retained_javascript_tarballs = load_javascript_retained_tarballs(
        root, document, manifest_hashes, javascript_version
    )
    verification_now = datetime.now(timezone.utc).replace(microsecond=0)
    source_artifact = exact_artifact(
        document, "artifacts/public-registries/source-conformance.json"
    )
    source_path = safe_path(root, source_artifact["path"])
    source_sha256 = require_hash(source_artifact["sha256"])
    if (
        digest(source_path) != source_sha256
        or manifest_hashes.get(source_artifact["path"]) != source_sha256
    ):
        raise ProofError("source_conformance_artifact_hash_mismatch")
    try:
        source = SOURCE.validate_source(source_path, verification_now)
    except SOURCE.EvidenceError as error:
        raise ProofError(str(error)) from None
    if (
        source.get("repositories") != repositories
        or document.get("core_commit")
        != source.get("repositories", {}).get("core", {}).get("commit")
        or document.get("core_release") != source.get("contract", {}).get("core_release")
        or document.get("contract_version") != source.get("contract", {}).get("version")
        or document.get("bundle_sha256") != source.get("contract", {}).get("bundle_sha256")
    ):
        raise ProofError("source_conformance_identity_mismatch")
    contract_authority = javascript_contract_authority(source)
    try:
        MINTLIFY.validate_retained_proof(
            proofs["documentation"],
            candidate_commit,
            now=verification_now,
        )
    except MINTLIFY.ProofError as error:
        raise ProofError(str(error)) from None
    validate_mintlify_retained_container(
        proofs["documentation_inputs"],
        proofs["documentation"],
        now=verification_now,
    )
    validate_oci(proofs["oci"], repositories["core"])
    validate_javascript_npm_set(
        proofs["javascript"], repositories["javascript"], contract_authority,
        retained_javascript_tarballs,
    )
    validate_npm(proofs["react_native"], "@latchway/react-native", repositories["react_native"])
    validate_rn_published_dependencies(
        proofs["react_native"].get("reviewed_published_dependency_evidence"),
        repositories,
    )
    validate_swift_resolution(proofs["swift"], repositories["ios"])
    cocoa = proofs["ios"]
    cocoa_source = cocoa.get("source") if isinstance(cocoa, dict) else None
    if (
        not isinstance(cocoa, dict)
        or cocoa.get("schema_version") != 1
        or cocoa.get("kind") != "latchway_cocoapods_release_evidence"
        or cocoa.get("status") != "passed"
        or cocoa.get("registry") != "cocoapods"
        or cocoa.get("package") != "Latchway"
        or cocoa.get("version") != repositories["ios"].get("version")
        or cocoa.get("published_spec_equals_reviewed_podspec") is not True
        or cocoa.get("reviewed_source_archive_equals_release_tag") is not True
        or not cocoa.get("release_asset_attestation_verification")
        or cocoa.get("source_commit") != repositories["ios"].get("commit")
        or cocoa.get("source_tag") != repositories["ios"].get("tag")
        or cocoa_source
        != {
            "git": "https://github.com/Latchway/latchway-ios-sdk.git",
            "tag": repositories["ios"].get("tag"),
        }
    ):
        raise ProofError("cocoapods_byte_proof_invalid")
    require_hash(cocoa.get("published_spec_sha256"))
    require_hash(cocoa.get("reviewed_spec_sha256"))
    require_hash(cocoa.get("reviewed_source_archive_sha256"))
    ios_version = repositories["ios"].get("version")
    if not isinstance(ios_version, str):
        raise ProofError("cocoapods_byte_proof_invalid")
    ios_archive = f"latchway-ios-sdk-{ios_version}.tar.gz"
    ios_assets = {
        ios_archive,
        f"{ios_archive}.sha256",
        f"docs-bundle-{ios_version}.tar.gz",
        "cocoapods-published-podspec.json",
        "cocoapods-reviewed-podspec.json",
        "cocoapods-release-evidence.json",
        "cocoapods-release-evidence.SHA256SUMS",
    }
    validate_retained_release_set(
        cocoa,
        ios_assets,
        source_attested_names=expected_source_attested_release_assets(
            "ios", ios_version, ios_assets
        ),
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
    published_spec = load_retained_json(
        retained_ios["cocoapods-published-podspec.json"],
        "cocoapods-published-podspec.json",
    )
    reviewed_spec = load_retained_json(
        retained_ios["cocoapods-reviewed-podspec.json"],
        "cocoapods-reviewed-podspec.json",
    )
    validate_cocoapods_spec(published_spec, repositories["ios"])
    validate_cocoapods_spec(reviewed_spec, repositories["ios"])
    if (
        published_spec != reviewed_spec
        or cocoa.get("published_spec_sha256")
        != retained_ios["cocoapods-published-podspec.json"]["sha256"]
        or cocoa.get("reviewed_spec_sha256")
        != retained_ios["cocoapods-reviewed-podspec.json"]["sha256"]
        or cocoa.get("reviewed_source_archive_sha256")
        != retained_ios[ios_archive]["sha256"]
    ):
        raise ProofError("cocoapods_spec_invalid")
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
