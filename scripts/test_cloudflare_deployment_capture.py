#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest


SCRIPT = Path(__file__).with_name("cloudflare-deployment-capture.py")
SPEC = importlib.util.spec_from_file_location("cloudflare_capture", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def read(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class CloudflareCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.index = "sha256:" + "a" * 64
        self.config = "sha256:" + "b" * 64
        self.layer = "sha256:" + "c" * 64
        manifest = {"schemaVersion": 2, "config": {"digest": self.config}, "layers": [{"digest": self.layer, "size": 10}]}
        raw = json.dumps(manifest, sort_keys=True).encode()
        self.platform = "sha256:" + __import__("hashlib").sha256(raw).hexdigest()
        self.mirror = self.platform
        (self.root / "canonical.json").write_bytes(raw)
        (self.root / "mirror.json").write_bytes(raw)
        write(self.root / "candidate.json", {"image": {"repository": "ghcr.io/latchway/latchway", "index_digest": self.index, "platforms": {"linux/amd64": self.platform}}})
        self.app_id = "12345678-abcd-1234-abcd-123456789abc"
        self.mirror_image = f"registry.cloudflare.com/account/latchway@{self.mirror}"
        write(self.root / "whoami.json", {"accounts": [{"id": "f" * 32}]})
        write(self.root / "apps.json", [{"id": self.app_id, "name": "latchway", "state": "active", "instances": 1, "image": self.mirror_image, "version": 7, "updated_at": "2026-08-29T01:00:00Z", "created_at": "2026-08-29T00:00:00Z"}])
        before = {"id": "durable", "name": "instance-0", "state": "running", "location": "sin01", "version": 7, "created": "2026-08-29T01:00:30Z"}
        write(self.root / "before.json", [before])
        write(self.root / "after.json", [{**before, "created": "2026-08-29T01:01:30Z"}])
        self.active_version_id = "87654321-abcd-1234-abcd-123456789abc"
        write(self.root / "deployments.json", [{
            "id": "deployment",
            "created_on": "2026-08-29T01:00:00Z",
            "versions": [{"version_id": self.active_version_id, "percentage": 100}],
        }])
        write(self.root / "versions.json", [{
            "id": self.active_version_id,
            "resources": {"bindings": [
                {"name": "LATCHWAY_DB_MAX_CONNECTIONS", "type": "plain_text", "text": "5"},
                {"name": "LATCHWAY_DB_COMPLETION_CONNECTIONS", "type": "plain_text", "text": "2"},
            ]},
        }])
        write(self.root / "secrets.json", [{"name": name} for name in (*capture.REQUIRED_RUNTIME_SECRETS, capture.EVIDENCE_SECRET)])
        status = {"current": 16, "available": 16, "up_to_date": True}
        command = ["/latchway", "--output", "json", "migrate", "status"]
        write(self.root / "migration.json", {"evidence_id": "123-1", "command": command, "exit_code": 0, "status": status})
        write(self.root / "shutdown.json", {"evidence_id": "123-1", "before": {"status": "healthy"}, "stop": {"evidence_id": "123-1", "requested_at": "2026-08-29T01:01:00Z", "stopped_at": "2026-08-29T01:01:10Z", "signal": "SIGTERM", "reason": "runtime_signal", "exit_code": 0}})

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def args(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            candidate_manifest=self.root / "candidate.json", canonical_manifest=self.root / "canonical.json",
            mirror_manifest=self.root / "mirror.json", mirror_image=self.mirror_image, account_id="f" * 32,
            whoami=self.root / "whoami.json", applications=self.root / "apps.json",
            instances_before=self.root / "before.json", instances_after=self.root / "after.json",
            deployments=self.root / "deployments.json", versions=self.root / "versions.json",
            secrets=self.root / "secrets.json", migration=self.root / "migration.json", shutdown=self.root / "shutdown.json",
            observed_at="2026-08-29T01:02:00Z", shutdown_started="2026-08-29T01:01:00Z",
            shutdown_finished="2026-08-29T01:02:00Z", wrangler_version="4.127.1",
            output_dir=self.root / "out", resource_id_output=self.root / "resource-id",
        )

    def test_builds_content_equivalent_provider_capture(self) -> None:
        self.assertEqual(capture.build(self.args()), self.app_id)
        control = json.loads((self.root / "out/control_plane.json").read_text())
        self.assertEqual(control["container"]["canonical"]["index_digest"], self.index)
        self.assertEqual(control["container"]["mirror"]["manifest_digest"], self.mirror)
        self.assertEqual(control["worker"]["active_version_id"], self.active_version_id)
        self.assertEqual(control["database_pool"], {
            "aggregate_max_connections": 5,
            "regular_max_connections": 3,
            "completion_max_connections": 2,
        })

    def test_rejects_mirror_with_different_layers(self) -> None:
        write(self.root / "mirror.json", {"schemaVersion": 2, "config": {"digest": self.config}, "layers": [{"digest": "sha256:" + "d" * 64, "size": 10}]})
        args = self.args()
        args.mirror_image = "registry.cloudflare.com/account/latchway@sha256:" + capture.file_sha256(self.root / "mirror.json")
        with self.assertRaisesRegex(capture.CaptureError, "mirror_content_mismatch"):
            capture.build(args)

    def test_rejects_unreplaced_instance(self) -> None:
        (self.root / "after.json").write_bytes((self.root / "before.json").read_bytes())
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_instance_not_replaced"):
            capture.build(self.args())

    def test_rejects_coherent_but_wrong_database_pool_profile(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["resources"]["bindings"][0]["text"] = "6"
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_boolean_migration_schema_versions(self) -> None:
        migration = read(self.root / "migration.json")
        assert isinstance(migration, dict)
        migration["status"] = {"current": True, "available": True, "up_to_date": True}
        write(self.root / "migration.json", migration)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_execution_invalid"):
            capture.build(self.args())

    def test_rejects_duplicate_database_pool_binding(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["resources"]["bindings"].append({
            "name": "LATCHWAY_DB_MAX_CONNECTIONS",
            "type": "plain_text",
            "text": "5",
        })
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_non_plain_text_database_pool_binding(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["resources"]["bindings"][1]["type"] = "secret_text"
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_database_pool_outside_range(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["resources"]["bindings"][1]["text"] = "0"
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_ambiguous_active_deployment(self) -> None:
        deployments = read(self.root / "deployments.json")
        assert isinstance(deployments, list)
        deployments[0]["versions"].append({
            "version_id": "11111111-abcd-1234-abcd-123456789abc",
            "percentage": 0,
        })
        write(self.root / "deployments.json", deployments)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_provider_record_secret_material(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["password"] = "must-not-enter-evidence"
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "provider_secret_material_forbidden"):
            capture.build(self.args())

    def test_rejects_non_allowlisted_active_version_fields(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["metadata"] = {"created_on": "2026-08-29T00:59:00Z"}
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_noncanonical_pool_binding_order(self) -> None:
        versions = read(self.root / "versions.json")
        assert isinstance(versions, list)
        versions[0]["resources"]["bindings"].reverse()
        write(self.root / "versions.json", versions)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_database_pool_invalid"):
            capture.build(self.args())

    def test_rejects_retained_historical_deployment_record(self) -> None:
        deployments = read(self.root / "deployments.json")
        assert isinstance(deployments, list)
        deployments.append({
            **deployments[0],
            "id": "second-deployment",
        })
        write(self.root / "deployments.json", deployments)
        with self.assertRaisesRegex(capture.CaptureError, "cloudflare_deployments_invalid"):
            capture.build(self.args())


if __name__ == "__main__":
    unittest.main()
