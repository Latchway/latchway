#!/usr/bin/env python3
"""Validate GitHub's immutable-release attestation against live release state."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAXIMUM = 16 * 1024 * 1024


class AttestationError(Exception):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("duplicate_json_key")
        result[key] = value
    return result


def load_json_bytes(payload: bytes, code: str) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=strict_object)
    except AttestationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AttestationError(code) from None


def read_bytes(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= MAXIMUM:
            raise AttestationError("input_file_invalid")
        return path.read_bytes()
    except AttestationError:
        raise
    except OSError:
        raise AttestationError("input_file_invalid") from None


def release_assets(release: Mapping[str, Any]) -> dict[str, str]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise AttestationError("release_assets_invalid")
    result: dict[str, str] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise AttestationError("release_assets_invalid")
        name, digest = asset.get("name"), asset.get("digest")
        if (
            not isinstance(name, str)
            or not name
            or name in result
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or SHA256.fullmatch(digest.removeprefix("sha256:")) is None
        ):
            raise AttestationError("release_assets_invalid")
        result[name] = digest.removeprefix("sha256:")
    return result


def validate_bytes(
    payload: bytes,
    *,
    repository: str,
    tag: str,
    ref_sha: str,
    release: Mapping[str, Any],
) -> dict[str, Any]:
    if REPOSITORY.fullmatch(repository) is None or SHA1.fullmatch(ref_sha) is None:
        raise AttestationError("expected_identity_invalid")
    release_id = release.get("id")
    if (
        not isinstance(release_id, int)
        or isinstance(release_id, bool)
        or release_id < 1
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("immutable") is not True
    ):
        raise AttestationError("release_state_invalid")
    expected_assets = release_assets(release)
    result = load_json_bytes(payload, "attestation_json_invalid")
    if not isinstance(result, dict) or set(result) != {"attestation", "verificationResult"}:
        raise AttestationError("attestation_result_invalid")
    attestation = result.get("attestation")
    verification = result.get("verificationResult")
    if (
        not isinstance(attestation, dict)
        or attestation.get("initiator") != "github"
        or not isinstance(verification, dict)
        or not verification
    ):
        raise AttestationError("attestation_result_invalid")
    bundle = attestation.get("bundle")
    envelope = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
    encoded = envelope.get("payload") if isinstance(envelope, dict) else None
    if (
        not isinstance(encoded, str)
        or envelope.get("payloadType") != "application/vnd.in-toto+json"
        or not isinstance(envelope.get("signatures"), list)
        or len(envelope["signatures"]) != 1
    ):
        raise AttestationError("attestation_bundle_invalid")
    try:
        statement_bytes = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise AttestationError("attestation_statement_invalid") from None
    statement = load_json_bytes(statement_bytes, "attestation_statement_invalid")
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    subjects = statement.get("subject") if isinstance(statement, dict) else None
    purl = f"pkg:github/{repository}@{tag}"
    if (
        not isinstance(statement, dict)
        or statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != "https://in-toto.io/attestation/release/v0.2"
        or not isinstance(predicate, dict)
        or str(predicate.get("databaseId")) != str(release_id)
        or predicate.get("purl") != purl
        or predicate.get("repository") != repository
        or predicate.get("tag") != tag
        or not isinstance(subjects, list)
        or len(subjects) != len(expected_assets) + 1
    ):
        raise AttestationError("attestation_statement_binding_invalid")
    release_subjects = [item for item in subjects if isinstance(item, dict) and item.get("uri") == purl]
    if len(release_subjects) != 1 or release_subjects[0].get("digest") != {"sha1": ref_sha}:
        raise AttestationError("attestation_ref_binding_invalid")
    observed_assets: dict[str, str] = {}
    for subject in subjects:
        if subject is release_subjects[0]:
            continue
        if not isinstance(subject, dict) or set(subject) != {"name", "digest"}:
            raise AttestationError("attestation_asset_binding_invalid")
        name, digest = subject.get("name"), subject.get("digest")
        if (
            not isinstance(name, str)
            or name in observed_assets
            or not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or SHA256.fullmatch(str(digest.get("sha256"))) is None
        ):
            raise AttestationError("attestation_asset_binding_invalid")
        observed_assets[name] = digest["sha256"]
    if observed_assets != expected_assets:
        raise AttestationError("attestation_asset_set_mismatch")
    return {
        "schema_version": 1,
        "kind": "latchway_github_release_attestation_verification",
        "repository": repository,
        "tag": tag,
        "ref_sha": ref_sha,
        "release_id": release_id,
        # Preserve the signed bundle itself, but deliberately exclude the CLI's
        # nondeterministic verificationResult and transport URL wrapper.
        "attestation_bundle": bundle,
        "assets": [
            {"name": name, "sha256": expected_assets[name]}
            for name in sorted(expected_assets)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--ref-sha", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        release = load_json_bytes(read_bytes(arguments.release), "release_json_invalid")
        if not isinstance(release, dict):
            raise AttestationError("release_json_invalid")
        result = validate_bytes(
            read_bytes(arguments.attestation),
            repository=arguments.repository,
            tag=arguments.tag,
            ref_sha=arguments.ref_sha,
            release=release,
        )
        if arguments.output is not None:
            if arguments.output.exists() or arguments.output.is_symlink():
                raise AttestationError("output_exists")
            arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (AttestationError, OSError) as error:
        print(f"GitHub release attestation rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
