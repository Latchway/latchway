#!/usr/bin/env python3
"""Merge independently attested release-domain directories without trust loss.

The protected workflow verifies each domain document's GitHub attestation
before invoking this offline copier. This program then enforces the exact
domain set, candidate identity, artifact hashes, safe paths, and collision-free
union consumed by cross-repository conformance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tempfile
from typing import Any


COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAXIMUM_JSON_BYTES = 2 * 1024 * 1024
MAXIMUM_FILE_BYTES = 128 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 768 * 1024 * 1024
MAXIMUM_FILES = 8192

PROMOTION_DOMAINS = (
    "live_sdk_conformance",
    "physical_devices",
    "live_provider",
    "cloud_deployments",
    "operational_resilience",
    "supply_chain",
)
RELEASE_DOMAINS = PROMOTION_DOMAINS + ("public_tags", "public_registries")


class AggregateError(Exception):
    """Stable redaction-safe aggregate rejection."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AggregateError("json_duplicate_key")
        value[key] = item
    return value


def read_json(path: Path) -> dict[str, Any]:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAXIMUM_JSON_BYTES:
            raise AggregateError("domain_document_invalid")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except AggregateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise AggregateError("domain_document_invalid") from None
    if not isinstance(value, dict):
        raise AggregateError("domain_document_invalid")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise AggregateError("domain_artifact_unreadable") from None
    return digest.hexdigest()


def safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise AggregateError("domain_artifact_path_invalid")
    path = PurePosixPath(value)
    if path.as_posix() != value or any(part in ("", ".", "..") for part in path.parts):
        raise AggregateError("domain_artifact_path_invalid")
    return path


def resolve_regular(root: Path, relative: PurePosixPath) -> Path:
    try:
        root = root.resolve(strict=True)
        path = (root / Path(*relative.parts)).resolve(strict=True)
        path.relative_to(root)
    except (OSError, ValueError):
        raise AggregateError("domain_artifact_path_invalid") from None
    if not path.is_file() or path.is_symlink():
        raise AggregateError("domain_artifact_invalid")
    return path


def validate_domain(root: Path, domain: str, candidate_commit: str) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise AggregateError("domain_directory_invalid")
    document = read_json(root / f"{domain}.json")
    required = {
        "schema_version", "kind", "domain", "status", "started_at", "finished_at",
        "core_commit", "core_release", "contract_version", "bundle_sha256",
        "oci_image_digest", "repositories", "claims", "artifacts",
    }
    if set(document) != required:
        raise AggregateError("domain_document_fields_invalid")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "latchway_cross_repository_external_evidence"
        or document.get("domain") != domain
        or document.get("status") != "passed"
        or document.get("core_commit") != candidate_commit
        or SHA256.fullmatch(str(document.get("bundle_sha256", ""))) is None
    ):
        raise AggregateError("domain_document_identity_mismatch")
    bundle = root / f"{domain}.attestation.sigstore.json"
    if not bundle.is_file() or bundle.is_symlink() or bundle.stat().st_size > MAXIMUM_JSON_BYTES:
        raise AggregateError("domain_attestation_missing")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > MAXIMUM_FILES:
        raise AggregateError("domain_artifacts_invalid")
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise AggregateError("domain_artifacts_invalid")
        relative = safe_relative(item["path"])
        serialized = relative.as_posix()
        expected = item["sha256"]
        if serialized in seen or not isinstance(expected, str) or SHA256.fullmatch(expected) is None:
            raise AggregateError("domain_artifacts_invalid")
        seen.add(serialized)
        path = resolve_regular(root, relative)
        if path.stat().st_size > MAXIMUM_FILE_BYTES or sha256_file(path) != expected:
            raise AggregateError("domain_artifact_hash_mismatch")
    return document


def enumerate_tree(root: Path) -> list[tuple[PurePosixPath, Path]]:
    result: list[tuple[PurePosixPath, Path]] = []
    root_resolved = root.resolve(strict=True)
    for current, directories, files in os.walk(root_resolved, followlinks=False):
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                raise AggregateError("domain_tree_symlink")
        for name in files:
            source = current_path / name
            if source.is_symlink() or not source.is_file():
                raise AggregateError("domain_tree_invalid")
            relative = PurePosixPath(source.relative_to(root_resolved).as_posix())
            safe_relative(relative.as_posix())
            result.append((relative, source))
            if len(result) > MAXIMUM_FILES:
                raise AggregateError("aggregate_file_count_exceeded")
    return sorted(result, key=lambda item: item[0].as_posix())


def aggregate(
    *, scope: str, candidate_commit: str, inputs: dict[str, Path], output: Path,
) -> dict[str, Any]:
    required = PROMOTION_DOMAINS if scope == "promotion" else RELEASE_DOMAINS
    if scope not in ("promotion", "release") or COMMIT.fullmatch(candidate_commit) is None:
        raise AggregateError("aggregate_identity_invalid")
    if set(inputs) != set(required):
        raise AggregateError("aggregate_domain_set_invalid")
    if output.exists() or output.is_symlink() or output.parent.is_symlink():
        raise AggregateError("aggregate_output_invalid")

    documents = {
        domain: validate_domain(inputs[domain].resolve(), domain, candidate_commit)
        for domain in required
    }
    identity = {
        key: documents[required[0]][key]
        for key in (
            "core_commit", "core_release", "contract_version", "bundle_sha256",
            "oci_image_digest", "repositories",
        )
    }
    for document in documents.values():
        if any(document[key] != value for key, value in identity.items()):
            raise AggregateError("aggregate_domain_identity_mismatch")

    staging_parent = output.parent.resolve()
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".latchway-evidence-", dir=staging_parent))
    hashes: dict[str, str] = {}
    total = 0
    try:
        for domain in required:
            for relative, source in enumerate_tree(inputs[domain]):
                serialized = relative.as_posix()
                digest = sha256_file(source)
                size = source.stat().st_size
                total += size
                if total > MAXIMUM_TOTAL_BYTES:
                    raise AggregateError("aggregate_size_exceeded")
                destination = staging / Path(*relative.parts)
                if destination.exists():
                    if hashes.get(serialized) != digest:
                        raise AggregateError("aggregate_path_collision")
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                destination.chmod(0o600)
                if sha256_file(destination) != digest:
                    raise AggregateError("aggregate_copy_changed")
                hashes[serialized] = digest
        manifest = {
            "schema_version": 1,
            "kind": "latchway_external_evidence_aggregate",
            "scope": scope,
            "candidate_commit": candidate_commit,
            "domains": list(required),
            "identity": identity,
            "files": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(hashes.items())
            ],
        }
        manifest_path = staging / "aggregate-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        manifest_path.chmod(0o600)
        os.replace(staging, output)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parse_input(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("input must be DOMAIN=PATH")
    domain, raw_path = value.split("=", 1)
    if domain not in RELEASE_DOMAINS or not raw_path:
        raise argparse.ArgumentTypeError("input domain or path is invalid")
    return domain, Path(raw_path)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--scope", choices=("promotion", "release"), required=True)
    value.add_argument("--candidate-commit", required=True)
    value.add_argument("--input", action="append", type=parse_input, required=True)
    value.add_argument("--output-directory", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    inputs: dict[str, Path] = {}
    for domain, path in arguments.input:
        if domain in inputs:
            print("aggregate release evidence rejected: aggregate_domain_set_invalid", file=sys.stderr)
            return 1
        inputs[domain] = path
    try:
        result = aggregate(
            scope=arguments.scope,
            candidate_commit=arguments.candidate_commit,
            inputs=inputs,
            output=arguments.output_directory,
        )
    except (AggregateError, OSError) as error:
        code = str(error) if isinstance(error, AggregateError) else "aggregate_io_failed"
        print(f"aggregate release evidence rejected: {code}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
