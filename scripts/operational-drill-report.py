#!/usr/bin/env python3
"""Seal raw isolated Docker observations into backup and upgrade drill reports."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Iterable


MODULE_PATH = Path(__file__).with_name("operational-resilience-evidence.py")
SPEC = importlib.util.spec_from_file_location("operational_resilience_evidence", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load operational evidence validator")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


class DrillError(Exception):
    """A stable drill-observation failure."""


def read(path: Path) -> dict[str, Any]:
    try:
        return EVIDENCE.read_json(path)
    except EVIDENCE.EvidenceError as error:
        raise DrillError(str(error)) from None


def validate_state(path: Path) -> dict[str, Any]:
    value = read(path)
    if set(value) != {
        "database_identity_sha256",
        "state_fingerprint_sha256",
        "row_counts",
    }:
        raise DrillError("drill_state_fields_invalid")
    if (
        EVIDENCE.SHA256.fullmatch(str(value["database_identity_sha256"])) is None
        or EVIDENCE.SHA256.fullmatch(str(value["state_fingerprint_sha256"])) is None
        or not isinstance(value["row_counts"], dict)
        or set(value["row_counts"])
        != {"organizations", "applications", "environments"}
        or any(
            not isinstance(count, int) or isinstance(count, bool) or count != 1
            for count in value["row_counts"].values()
        )
    ):
        raise DrillError("drill_state_invalid")
    return value


def validate_capture_identity(
    root: Path,
    *,
    commit: str,
    previous_candidate_commit: str,
    previous_candidate_version: str,
    previous_candidate_tag: str,
    previous_candidate_image: str,
    previous_candidate_platform_image: str,
    candidate_image: str,
    candidate_platform_image: str,
    postgres_image: str,
) -> tuple[str, str, dict[str, Any]]:
    try:
        value = EVIDENCE.validate_image_inspection(
            root / "image-inspection.json",
            commit=commit,
            candidate_image=candidate_image,
            candidate_platform_image=candidate_platform_image,
            previous_candidate_commit=previous_candidate_commit,
            previous_candidate_version=previous_candidate_version,
            previous_candidate_tag=previous_candidate_tag,
            previous_candidate_image=previous_candidate_image,
            previous_candidate_platform_image=previous_candidate_platform_image,
            postgres_image=postgres_image,
        )
    except EVIDENCE.EvidenceError as error:
        raise DrillError(str(error)) from None
    return (
        value["source_database_identity_sha256"],
        value["restore_database_identity_sha256"],
        value,
    )


def observation(root: Path, name: str) -> dict[str, Any]:
    return read(root / name)


def artifacts(root: Path, names: Iterable[str]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for name in sorted(set(names)):
        path = root / name
        try:
            digest = EVIDENCE.sha256_file(path)
        except EVIDENCE.EvidenceError as error:
            raise DrillError(str(error)) from None
        result.append({"path": name, "sha256": digest})
    return result


def runtime_stage(root: Path, prefix: str, image: str) -> dict[str, Any]:
    state = validate_state(root / f"{prefix}-state.json")
    return {
        "image": image,
        "version": observation(root, f"{prefix}-version.json"),
        "migration": observation(root, f"{prefix}-migration.json"),
        "doctor": observation(root, f"{prefix}-doctor.json"),
        "health": observation(root, f"{prefix}-health.json"),
        "readiness": observation(root, f"{prefix}-readiness.json"),
        "state_fingerprint_sha256": state["state_fingerprint_sha256"],
        "row_counts": state["row_counts"],
    }


def build_reports(
    *,
    root: Path,
    commit: str,
    previous_candidate_commit: str,
    previous_candidate_version: str,
    previous_candidate_tag: str,
    previous_candidate_image: str,
    previous_candidate_platform_image: str,
    candidate_image: str,
    candidate_platform_image: str,
    postgres_image: str,
    started_at: str,
    finished_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        EVIDENCE.COMMIT.fullmatch(commit) is None
        or EVIDENCE.COMMIT.fullmatch(previous_candidate_commit) is None
        or previous_candidate_commit == commit
        or EVIDENCE.SEMVER.fullmatch(previous_candidate_version) is None
        or previous_candidate_tag != "v" + previous_candidate_version
        or EVIDENCE.TAG.fullmatch(previous_candidate_tag) is None
        or EVIDENCE.OCI.fullmatch(previous_candidate_image) is None
        or EVIDENCE.OCI.fullmatch(previous_candidate_platform_image) is None
        or EVIDENCE.OCI.fullmatch(candidate_image) is None
        or EVIDENCE.OCI.fullmatch(candidate_platform_image) is None
        or len(
            {
                previous_candidate_image,
                previous_candidate_platform_image,
                candidate_image,
                candidate_platform_image,
            }
        )
        != 4
        or EVIDENCE.POSTGRES_OCI.fullmatch(postgres_image) is None
    ):
        raise DrillError("drill_coordinates_invalid")
    started = EVIDENCE.parse_time(started_at, "drill_time_invalid")
    finished = EVIDENCE.parse_time(finished_at, "drill_time_invalid")
    if finished <= started or finished - started > EVIDENCE.MAXIMUM_AGE:
        raise DrillError("drill_time_invalid")
    source_identity, restore_identity, inspection = validate_capture_identity(
        root,
        commit=commit,
        previous_candidate_commit=previous_candidate_commit,
        previous_candidate_version=previous_candidate_version,
        previous_candidate_tag=previous_candidate_tag,
        previous_candidate_image=previous_candidate_image,
        previous_candidate_platform_image=previous_candidate_platform_image,
        candidate_image=candidate_image,
        candidate_platform_image=candidate_platform_image,
        postgres_image=postgres_image,
    )
    source_state = validate_state(root / "previous-state.json")
    restore_state = validate_state(root / "restore-state.json")
    if (
        source_state["database_identity_sha256"] != source_identity
        or restore_state["database_identity_sha256"] != restore_identity
    ):
        raise DrillError("drill_database_identity_mismatch")

    backup_names = (
        "image-inspection.json",
        "previous-version.json",
        "previous-migration.json",
        "previous-doctor.json",
        "previous-health.json",
        "previous-readiness.json",
        "previous-state.json",
        "backup.dump",
        "restore-migration.json",
        "restore-doctor.json",
        "restore-health.json",
        "restore-readiness.json",
        "restore-state.json",
    )
    backup_path = root / "backup.dump"
    backup_digest = EVIDENCE.sha256_file(backup_path)
    previous_version = observation(root, "previous-version.json")
    try:
        previous_version = EVIDENCE.validate_version(
            previous_version, "drill_previous_version_invalid"
        )
    except EVIDENCE.EvidenceError as error:
        raise DrillError(str(error)) from None
    if (
        previous_version["version"] != inspection["previous_candidate_version"]
        or previous_version["commit"] != inspection["previous_candidate_revision"]
    ):
        raise DrillError("drill_previous_version_mismatch")
    previous_migration = observation(root, "previous-migration.json")
    previous_doctor = observation(root, "previous-doctor.json")
    restore_migration = observation(root, "restore-migration.json")
    restore_doctor = observation(root, "restore-doctor.json")
    backup = {
        "schema_version": 1,
        "kind": "latchway_backup_restore_drill",
        "status": "passed",
        "core_commit": commit,
        "previous_candidate_commit": previous_candidate_commit,
        "previous_candidate_intended_tag": previous_candidate_tag,
        "previous_candidate_oci_reference": previous_candidate_image,
        "previous_candidate_platform_oci_reference": previous_candidate_platform_image,
        "candidate_oci_reference": candidate_image,
        "candidate_platform_oci_reference": candidate_platform_image,
        "postgres_oci_reference": postgres_image,
        "started_at": started_at,
        "finished_at": finished_at,
        "isolation": {
            "network_internal": True,
            "source_database_container_fresh": True,
            "restore_database_container_fresh": True,
            "production_targeted": False,
        },
        "source": {
            "database_identity_sha256": source_identity,
            "image": previous_candidate_platform_image,
            "version": previous_version,
            "migration": previous_migration,
            "doctor": previous_doctor,
            "health": observation(root, "previous-health.json"),
            "readiness": observation(root, "previous-readiness.json"),
            "state_fingerprint_sha256": source_state["state_fingerprint_sha256"],
            "row_counts": source_state["row_counts"],
        },
        "backup": {
            "format": "postgresql-custom",
            "artifact_path": "backup.dump",
            "sha256": backup_digest,
            "size_bytes": backup_path.stat().st_size,
        },
        "restore": {
            "database_identity_sha256": restore_identity,
            "image": previous_candidate_platform_image,
            "version": previous_version,
            "migration": restore_migration,
            "doctor": restore_doctor,
            "health": observation(root, "restore-health.json"),
            "readiness": observation(root, "restore-readiness.json"),
            "state_fingerprint_sha256": restore_state["state_fingerprint_sha256"],
            "row_counts": restore_state["row_counts"],
        },
        "assertions": {name: True for name in sorted(EVIDENCE.BACKUP_ASSERTIONS)},
        "artifacts": artifacts(root, backup_names),
    }

    upgrade_names = (
        "image-inspection.json",
        "previous-version.json",
        "previous-migration.json",
        "previous-doctor.json",
        "previous-health.json",
        "previous-readiness.json",
        "previous-state.json",
        "candidate-version.json",
        "candidate-migration.json",
        "candidate-doctor.json",
        "candidate-health.json",
        "candidate-readiness.json",
        "candidate-state.json",
        "rollback-version.json",
        "rollback-migration.json",
        "rollback-doctor.json",
        "rollback-health.json",
        "rollback-readiness.json",
        "rollback-state.json",
    )
    upgrade = {
        "schema_version": 1,
        "kind": "latchway_upgrade_application_rollback_drill",
        "status": "passed",
        "core_commit": commit,
        "previous_candidate_commit": previous_candidate_commit,
        "previous_candidate_intended_tag": previous_candidate_tag,
        "previous_candidate_oci_reference": previous_candidate_image,
        "previous_candidate_platform_oci_reference": previous_candidate_platform_image,
        "candidate_oci_reference": candidate_image,
        "candidate_platform_oci_reference": candidate_platform_image,
        "postgres_oci_reference": postgres_image,
        "started_at": started_at,
        "finished_at": finished_at,
        "previous_before": runtime_stage(
            root, "previous", previous_candidate_platform_image
        ),
        "candidate_after": runtime_stage(root, "candidate", candidate_platform_image),
        "previous_rollback": runtime_stage(
            root, "rollback", previous_candidate_platform_image
        ),
        "assertions": {name: True for name in sorted(EVIDENCE.UPGRADE_ASSERTIONS)},
        "artifacts": artifacts(root, upgrade_names),
    }

    # Run the same semantic validators as the finalizer before writing either
    # report. Temporary paths let artifact references retain their fixed root.
    EVIDENCE.write_json(root / ".backup-report.check.json", backup)
    EVIDENCE.write_json(root / ".upgrade-report.check.json", upgrade)
    try:
        candidate_version = EVIDENCE.validate_version(
            upgrade["candidate_after"]["version"],
            "drill_candidate_version_invalid",
        )
        candidate_build_time = EVIDENCE.parse_build_time(
            candidate_version["build_date"], "drill_candidate_version_invalid"
        )
        if candidate_build_time > started:
            raise EVIDENCE.EvidenceError("drill_candidate_version_invalid")
        EVIDENCE.validate_backup(
            root / ".backup-report.check.json",
            commit=commit,
            candidate_image=candidate_image,
            candidate_platform_image=candidate_platform_image,
            previous_candidate_commit=previous_candidate_commit,
            previous_candidate_version=previous_candidate_version,
            previous_candidate_tag=previous_candidate_tag,
            previous_candidate_image=previous_candidate_image,
            previous_candidate_platform_image=previous_candidate_platform_image,
            contract_version=candidate_version["contract_version"],
            wire_protocol=candidate_version["protocol_version"],
            released_at=started,
            now=finished,
        )
        EVIDENCE.validate_upgrade(
            root / ".upgrade-report.check.json",
            commit=commit,
            core_version=candidate_version["version"],
            contract_version=candidate_version["contract_version"],
            wire_protocol=candidate_version["protocol_version"],
            candidate_image=candidate_image,
            candidate_platform_image=candidate_platform_image,
            previous_candidate_commit=previous_candidate_commit,
            previous_candidate_version=previous_candidate_version,
            previous_candidate_tag=previous_candidate_tag,
            previous_candidate_image=previous_candidate_image,
            previous_candidate_platform_image=previous_candidate_platform_image,
            postgres_image=postgres_image,
            released_at=candidate_build_time,
            now=finished,
        )
    except EVIDENCE.EvidenceError as error:
        raise DrillError(str(error)) from None
    finally:
        (root / ".backup-report.check.json").unlink(missing_ok=True)
        (root / ".upgrade-report.check.json").unlink(missing_ok=True)
    return backup, upgrade


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--evidence-directory", type=Path, required=True)
    value.add_argument("--core-commit", required=True)
    value.add_argument("--previous-candidate-commit", required=True)
    value.add_argument("--previous-candidate-version", required=True)
    value.add_argument("--previous-candidate-tag", required=True)
    value.add_argument("--previous-candidate-image", required=True)
    value.add_argument("--previous-candidate-platform-image", required=True)
    value.add_argument("--candidate-image", required=True)
    value.add_argument("--candidate-platform-image", required=True)
    value.add_argument("--postgres-image", required=True)
    value.add_argument("--started-at", required=True)
    value.add_argument("--finished-at", required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        backup, upgrade = build_reports(
            root=arguments.evidence_directory,
            commit=arguments.core_commit,
            previous_candidate_commit=arguments.previous_candidate_commit,
            previous_candidate_version=arguments.previous_candidate_version,
            previous_candidate_tag=arguments.previous_candidate_tag,
            previous_candidate_image=arguments.previous_candidate_image,
            previous_candidate_platform_image=arguments.previous_candidate_platform_image,
            candidate_image=arguments.candidate_image,
            candidate_platform_image=arguments.candidate_platform_image,
            postgres_image=arguments.postgres_image,
            started_at=arguments.started_at,
            finished_at=arguments.finished_at,
        )
        EVIDENCE.write_json(arguments.evidence_directory / "backup-restore.json", backup)
        EVIDENCE.write_json(arguments.evidence_directory / "upgrade-rollback.json", upgrade)
    except (DrillError, EVIDENCE.EvidenceError, OSError) as error:
        code = str(error) if not isinstance(error, OSError) else "drill_report_write_failed"
        print(f"operational drill report failed: {code}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "passed",
                "backup_restore": "backup-restore.json",
                "upgrade_rollback": "upgrade-rollback.json",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
