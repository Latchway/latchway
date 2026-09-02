from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.framework_conformance import ConformanceError, load_manifest, load_registry, validate_report


ROOT = Path(__file__).resolve().parents[1]


class FrameworkConformanceTests(unittest.TestCase):
    def test_report_schema_matches_v2_validator_vocabulary(self) -> None:
        case_schema = json.loads(
            (ROOT / "conformance/framework-cases.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(case_schema["properties"]["schema_version"]["const"], 2)
        self.assertIn("suites", case_schema["required"])
        common_suite = case_schema["properties"]["suites"]["properties"]["addendum_common_v1"]
        self.assertEqual(
            common_suite["items"]["properties"]["not_applicable"]["enum"],
            ["forbidden", "evidence_required"],
        )

        schema = json.loads((ROOT / "conformance/framework-report.schema.json").read_text(encoding="utf-8"))
        integration = schema["properties"]["integrations"]["items"]
        self.assertEqual(schema["properties"]["schema_version"]["const"], 2)
        self.assertEqual(
            integration["properties"]["support"]["enum"],
            ["supported", "experimental", "unsupported"],
        )
        self.assertIn("pending", integration["required"])
        pending = integration["properties"]["pending"]["items"]
        self.assertFalse(pending["additionalProperties"])
        self.assertEqual(
            pending["required"],
            ["case_ids", "reason", "blocker", "evidence"],
        )
        self.assertEqual(
            pending["properties"]["blocker"]["enum"],
            ["local", "hosted", "protected_device", "upstream"],
        )
        unsupported_branch = integration["allOf"][0]
        self.assertIn("unsupported_evidence", unsupported_branch["then"]["properties"])
        self.assertFalse(unsupported_branch["else"]["properties"]["unsupported_evidence"])
        self.assertEqual(
            integration["allOf"][1]["then"]["properties"]["pending"]["type"],
            "array",
        )

    def test_canonical_manifest_is_valid_and_stable(self) -> None:
        cases, digest = load_manifest(ROOT / "conformance/framework-cases.json")
        self.assertEqual(len(cases), 58)
        self.assertEqual(cases[0]["id"], "FW-AUTH-001")
        self.assertEqual(cases[-1]["id"], "FW-SEC-106")
        common = {case["id"]: case.get("common_not_applicable") for case in cases if "common_not_applicable" in case}
        self.assertEqual(len(common), 31)
        self.assertEqual(common["FW-AUTH-101"], "forbidden")
        self.assertEqual(common["FW-SEC-106"], "evidence_required")
        self.assertEqual(len(digest), 64)

    def test_common_suite_requires_exact_case_evidence_and_explicit_pending_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "Conformance").mkdir()
            evidence = directory / "Tests/evidence.swift"
            evidence.parent.mkdir()
            evidence.write_text("func bootstrap() {}\n// platform limitation\n", encoding="utf-8")
            catalog = directory / "Conformance/common-framework-evidence.json"
            catalog.write_text(json.dumps({
                "schema_version": 1,
                "cases": {"FW-AUTH-101": ["Tests/evidence.swift#bootstrap"]},
            }), encoding="utf-8")
            manifest = directory / "manifest.json"
            manifest.write_text(json.dumps({
                "schema_version": 2,
                "suites": {"addendum_common_v1": [
                    {"case_id": "FW-AUTH-101", "not_applicable": "forbidden"},
                    {"case_id": "FW-SEC-106", "not_applicable": "evidence_required"},
                ]},
                "cases": [
                    {"id": "FW-AUTH-101", "category": "authentication", "title": "bootstrap"},
                    {"id": "FW-SEC-106", "category": "security", "title": "bridge"},
                ],
            }), encoding="utf-8")
            cases, digest = load_manifest(manifest)
            report = directory / "Conformance/framework-report.json"
            value = {
                "schema_version": 2,
                "manifest_sha256": digest,
                "repository": "latchway-ios-sdk",
                "integrations": [{
                    "id": "swift-openai",
                    "support": "experimental",
                    "pass": {"FW-AUTH-101": ["Conformance/common-framework-evidence.json#FW-AUTH-101"]},
                    "not_applicable": [{
                        "case_ids": ["FW-SEC-106"],
                        "reason": "This is not a React Native integration.",
                        "evidence": ["Tests/evidence.swift"],
                    }],
                    "pending": [],
                }],
            }
            report.write_text(json.dumps(value), encoding="utf-8")
            validate_report(report, cases, digest)

            catalog.write_text(json.dumps({
                "schema_version": 1,
                "cases": {
                    "FW-AUTH-101": ["Conformance/common-framework-evidence.json#FW-AUTH-101"],
                },
            }), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "cannot self-reference"):
                validate_report(report, cases, digest)

            nested_catalog = directory / "Tests/common-framework-evidence.json"
            nested_catalog.write_text('{"FW-AUTH-101":"bootstrap"}\n', encoding="utf-8")
            catalog.write_text(json.dumps({
                "schema_version": 1,
                "cases": {
                    "FW-AUTH-101": ["Tests/common-framework-evidence.json#FW-AUTH-101"],
                },
            }), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "cannot reference another catalog"):
                validate_report(report, cases, digest)

            documentation = directory / "docs/evidence.md"
            documentation.parent.mkdir()
            documentation.write_text("bootstrap\n", encoding="utf-8")
            catalog.write_text(json.dumps({
                "schema_version": 1,
                "cases": {"FW-AUTH-101": ["docs/evidence.md#bootstrap"]},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "under a test path"):
                validate_report(report, cases, digest)

            nested = directory / "nested/tests/repository"
            (nested / "Conformance").mkdir(parents=True)
            (nested / "docs").mkdir()
            (nested / "docs/evidence.md").write_text("bootstrap\n", encoding="utf-8")
            (nested / "Conformance/common-framework-evidence.json").write_text(json.dumps({
                "schema_version": 1,
                "cases": {"FW-AUTH-101": ["docs/evidence.md#bootstrap"]},
            }), encoding="utf-8")
            nested_report = nested / "Conformance/framework-report.json"
            nested_report.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "under a test path"):
                validate_report(nested_report, cases, digest)

            misplaced = directory / "Other/common-framework-evidence.json"
            misplaced.parent.mkdir()
            misplaced.write_text(json.dumps({
                "schema_version": 1,
                "cases": {"FW-AUTH-101": ["Tests/evidence.swift#bootstrap"]},
            }), encoding="utf-8")
            value["integrations"][0]["pass"] = {
                "FW-AUTH-101": ["Other/common-framework-evidence.json#FW-AUTH-101"],
            }
            report.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "must use Conformance"):
                validate_report(report, cases, digest)

            catalog.write_text(json.dumps({
                "schema_version": 1,
                "cases": {"FW-AUTH-101": ["Tests/evidence.swift#bootstrap"]},
            }), encoding="utf-8")

            value["integrations"][0]["pass"] = {}
            value["integrations"][0]["not_applicable"][0]["case_ids"] = ["FW-AUTH-101", "FW-SEC-106"]
            report.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "required common case"):
                validate_report(report, cases, digest)

            value["integrations"][0]["not_applicable"][0]["case_ids"] = ["FW-SEC-106"]
            value["integrations"][0]["pending"] = [{
                "case_ids": ["FW-AUTH-101"],
                "reason": "Hosted replay rejection is not available locally.",
                "blocker": "hosted",
                "evidence": ["Tests/evidence.swift"],
            }]
            value["integrations"][0]["support"] = "supported"
            report.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "supported integration"):
                validate_report(report, cases, digest)

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

    def test_common_na_is_bound_to_registry_claims_and_native_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "Conformance").mkdir()
            evidence = directory / "Tests/evidence.swift"
            evidence.parent.mkdir()
            evidence.write_text("bounded evidence\n", encoding="utf-8")

            def validate_na(
                case_id: str,
                integration_id: str,
                repository: str,
                ecosystem: str,
                capabilities: dict[str, object],
            ) -> None:
                manifest = directory / "manifest.json"
                manifest.write_text(json.dumps({
                    "schema_version": 2,
                    "suites": {"addendum_common_v1": [{
                        "case_id": case_id,
                        "not_applicable": "evidence_required",
                    }]},
                    "cases": [{
                        "id": case_id,
                        "category": "security" if "SEC" in case_id else "request",
                        "title": "bounded case",
                    }],
                }), encoding="utf-8")
                cases, digest = load_manifest(manifest)
                report = directory / "Conformance/framework-report.json"
                report.write_text(json.dumps({
                    "schema_version": 2,
                    "manifest_sha256": digest,
                    "repository": repository,
                    "integrations": [{
                        "id": integration_id,
                        "support": "experimental",
                        "pass": {},
                        "not_applicable": [{
                            "case_ids": [case_id],
                            "reason": "The conditional surface is absent.",
                            "evidence": ["Tests/evidence.swift"],
                        }],
                        "pending": [],
                    }],
                }), encoding="utf-8")
                registry = {integration_id: {
                    "ecosystem": ecosystem,
                    "support": "experimental",
                    "repository": repository,
                    "capabilities": capabilities,
                }}
                validate_report(report, cases, digest, registry)

            validate_na(
                "FW-REQ-105", "swift-openai", "latchway-ios-sdk", "apple",
                {"cancellation": "conditional"},
            )
            with self.assertRaisesRegex(ConformanceError, "cancellation=true"):
                validate_na(
                    "FW-REQ-105", "swift-openai", "latchway-ios-sdk", "apple",
                    {"cancellation": True},
                )
            with self.assertRaisesRegex(ConformanceError, "native integration"):
                validate_na(
                    "FW-SEC-105", "swift-openai", "latchway-ios-sdk", "apple", {},
                )
            with self.assertRaisesRegex(ConformanceError, "react-native-fetch"):
                validate_na(
                    "FW-SEC-106", "react-native-fetch", "latchway-react-native-sdk",
                    "react_native", {},
                )

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
