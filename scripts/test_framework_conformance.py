from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.framework_conformance import ConformanceError, load_manifest, load_registry, validate_report


ROOT = Path(__file__).resolve().parents[1]


class FrameworkConformanceTests(unittest.TestCase):
    def test_canonical_manifest_is_valid_and_stable(self) -> None:
        cases, digest = load_manifest(ROOT / "conformance/framework-cases.json")
        self.assertEqual(len(cases), 27)
        self.assertEqual(cases[0]["id"], "FW-AUTH-001")
        self.assertEqual(cases[-1]["id"], "FW-LC-003")
        self.assertEqual(len(digest), 64)

    def test_report_requires_every_case_and_exact_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "conformance").mkdir()
            evidence = directory / "Tests/example.test"
            evidence.parent.mkdir()
            evidence.write_text("case\n", encoding="utf-8")
            manifest = directory / "manifest.json"
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "cases": [
                    {"id": "FW-AUTH-001", "category": "authentication", "title": "binds metadata"},
                ],
            }), encoding="utf-8")
            cases, digest = load_manifest(manifest)
            report = directory / "conformance/report.json"
            report.write_text(json.dumps({
                "schema_version": 1,
                "manifest_sha256": digest,
                "repository": "latchway-ios-sdk",
                "integrations": [{
                    "id": "swift-openai",
                    "support": "experimental",
                    "pass": {
                        "FW-AUTH-001": ["Tests/example.test#case"],
                    },
                    "not_applicable": [],
                }],
            }), encoding="utf-8")
            validate_report(report, cases, digest)

            changed_digest = hashlib.sha256(manifest.read_bytes() + b"\n").hexdigest()
            value = json.loads(report.read_text(encoding="utf-8"))
            value["manifest_sha256"] = changed_digest
            report.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "canonical manifest"):
                validate_report(report, cases, digest)

            value["manifest_sha256"] = digest
            value["integrations"][0]["pass"]["FW-AUTH-001"] = ["Tests/example.test#missing"]
            report.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "fragment is not present"):
                validate_report(report, cases, digest)

    def test_registry_binds_ownership_support_and_capability_claims(self) -> None:
        registry = load_registry(ROOT / "compatibility/frameworks.yaml")
        self.assertEqual(registry["swift-openai"]["repository"], "latchway-ios-sdk")
        self.assertIs(registry["swift-openai"]["capabilities"]["chat_completions"], True)
        self.assertEqual(registry["swift-openai"]["capabilities"]["tools"], "conditional")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "Conformance").mkdir()
            evidence = directory / "Tests/evidence.swift"
            evidence.parent.mkdir()
            evidence.write_text("evidence\n", encoding="utf-8")
            manifest = directory / "manifest.json"
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "cases": [
                    {"id": "FW-REQ-002", "category": "request", "title": "chat"},
                ],
            }), encoding="utf-8")
            cases, digest = load_manifest(manifest)
            report = directory / "Conformance/framework-report.json"
            report.write_text(json.dumps({
                "schema_version": 1,
                "manifest_sha256": digest,
                "repository": "latchway-ios-sdk",
                "integrations": [{
                    "id": "swift-openai",
                    "support": "experimental",
                    "pass": {},
                    "not_applicable": [{
                        "case_ids": ["FW-REQ-002"],
                        "reason": "not proven",
                        "evidence": ["Tests/evidence.swift"],
                    }],
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "chat_completions=true"):
                validate_report(report, cases, digest, registry)


if __name__ == "__main__":
    unittest.main()
