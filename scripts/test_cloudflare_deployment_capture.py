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
        write(self.root / "deployments.json", [{"id": "deployment"}])
        write(self.root / "versions.json", [{"id": "version"}])
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


if __name__ == "__main__":
    unittest.main()
