from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import yaml

from scripts import framework_compatibility as compatibility


class FrameworkCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = compatibility.load_registry(
            compatibility.DEFAULT_REGISTRY,
            compatibility.DEFAULT_SCHEMA,
        )

    def write_registry(self, directory: Path, value: object) -> Path:
        path = directory / "frameworks.yaml"
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
        return path

    def assert_registry_error(self, value: object, message: str) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write_registry(Path(raw_directory), value)
            with self.assertRaisesRegex(compatibility.RegistryError, message):
                compatibility.load_registry(path, compatibility.DEFAULT_SCHEMA)

    def test_repository_registry_and_generated_table_are_current(self) -> None:
        validated = compatibility.validate_repository(check_generated=True)
        self.assertEqual(len(validated["frameworks"]), 8)
        support = {item["id"]: item["support"] for item in validated["frameworks"]}
        self.assertEqual(support["foundation-models"], "planned")
        self.assertEqual(support["macpaw-openai"], "unsupported")
        self.assertTrue(
            all(
                support[identifier] == "experimental"
                for identifier in (
                    "android-okhttp",
                    "langchain-js",
                    "openai-js",
                    "react-native-fetch",
                    "swift-openai",
                    "vercel-ai-sdk",
                )
            )
        )
        self.assertEqual(
            [item["id"] for item in validated["frameworks"]],
            [
                "android-okhttp",
                "foundation-models",
                "langchain-js",
                "macpaw-openai",
                "openai-js",
                "react-native-fetch",
                "swift-openai",
                "vercel-ai-sdk",
            ],
        )
        vercel = next(
            item for item in validated["frameworks"] if item["id"] == "vercel-ai-sdk"
        )
        self.assertEqual(vercel["latchway_package"], "@latchway/vercel-ai")

    def test_client_openapi_uses_exact_registry_ids(self) -> None:
        openapi = yaml.safe_load(
            (compatibility.ROOT / "api/client.openapi.yaml").read_text(encoding="utf-8")
        )
        declared = openapi["components"]["parameters"]["Framework"]["schema"]["enum"]
        self.assertEqual(declared, [item["id"] for item in self.registry["frameworks"]])
        protocol = json.loads(
            (compatibility.ROOT / "api/protocol-version.json").read_text(encoding="utf-8")
        )
        self.assertEqual(protocol["standard_headers"]["framework"], "X-Latchway-Framework")
        self.assertEqual(
            protocol["standard_headers"]["framework_version"],
            "X-Latchway-Framework-Version",
        )

    def test_schema_closes_root_framework_capability_and_security_objects(self) -> None:
        schema = json.loads(compatibility.DEFAULT_SCHEMA.read_text(encoding="utf-8"))
        framework = schema["$defs"]["framework"]
        self.assertIs(schema["additionalProperties"], False)
        self.assertIs(framework["additionalProperties"], False)
        self.assertIs(framework["properties"]["capabilities"]["additionalProperties"], False)
        self.assertIs(framework["properties"]["security"]["additionalProperties"], False)
        self.assertIs(framework["properties"]["tested"]["additionalProperties"], False)

    def test_unknown_framework_field_is_rejected(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"][0]["claim_without_evidence"] = True
        self.assert_registry_error(value, "fields differ")

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "frameworks.yaml"
            path.write_text("schema_version: 1\nschema_version: 1\nframeworks: []\n", encoding="utf-8")
            with self.assertRaisesRegex(compatibility.RegistryError, "duplicate YAML key"):
                compatibility.load_registry(path, compatibility.DEFAULT_SCHEMA)

    def test_duplicate_id_is_rejected(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"].insert(1, deepcopy(value["frameworks"][0]))
        self.assert_registry_error(value, "framework ids must be unique")

    def test_boolean_schema_version_is_rejected(self) -> None:
        value = deepcopy(self.registry)
        value["schema_version"] = True
        self.assert_registry_error(value, "schema_version must be 1")

    def test_registry_must_be_sorted(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"][0], value["frameworks"][1] = (
            value["frameworks"][1],
            value["frameworks"][0],
        )
        self.assert_registry_error(value, "sorted by id")

    def test_support_claim_requires_pinned_versions(self) -> None:
        value = deepcopy(self.registry)
        item = next(
            candidate
            for candidate in value["frameworks"]
            if candidate["support"] == "planned"
        )
        item["support"] = "supported"
        self.assert_registry_error(value, "must be a pinned version")

    def test_planned_entry_cannot_publish_tested_range(self) -> None:
        value = deepcopy(self.registry)
        item = next(
            candidate
            for candidate in value["frameworks"]
            if candidate["support"] == "planned"
        )
        item["tested"] = {"minimum": "1.0.0", "latest": "1.1.0"}
        self.assert_registry_error(value, "forbidden while support is planned")

    def test_unsupported_entry_records_the_exact_assessed_version(self) -> None:
        item = next(
            candidate
            for candidate in self.registry["frameworks"]
            if candidate["id"] == "macpaw-openai"
        )
        self.assertEqual(item["support"], "unsupported")
        self.assertEqual(item["tested"], {"minimum": "0.5.1", "latest": "0.5.1"})

    def test_minimum_cannot_exceed_latest(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"][0]["tested"] = {"minimum": "6.0.0", "latest": "5.9.9"}
        self.assert_registry_error(value, "minimum exceeds latest")

    def test_experimental_claim_requires_tested_security(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"][0]["security"]["dpop"] = "not_tested"
        self.assert_registry_error(value, "security must be tested")

    def test_supported_claim_cannot_leave_capability_planned(self) -> None:
        value = deepcopy(self.registry)
        item = next(
            candidate
            for candidate in value["frameworks"]
            if candidate["support"] == "planned"
        )
        item["support"] = "supported"
        item["tested"] = {"minimum": "27.0.0", "latest": "27.0.0"}
        item["security"] = {"dpop": "full", "native_key_isolation": "full"}
        self.assert_registry_error(value, "cannot remain planned")

    def test_invalid_capability_state_is_rejected(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"][0]["capabilities"]["streaming"] = "probably"
        self.assert_registry_error(value, "invalid state")

    def test_numeric_capability_state_is_rejected(self) -> None:
        value = deepcopy(self.registry)
        value["frameworks"][0]["capabilities"]["streaming"] = 1
        self.assert_registry_error(value, "invalid state")

    def test_generator_is_deterministic_and_carries_no_support_claim(self) -> None:
        first = compatibility.render_markdown(self.registry)
        second = compatibility.render_markdown(self.registry)
        self.assertEqual(first, second)
        self.assertIn("does not mean supported compatibility", first)
        self.assertIn("## Capability matrix", first)
        self.assertIn("Canonical source: compatibility/frameworks.yaml", first)
        self.assertNotIn("| Supported |", first)
        self.assertIn("Experimental", first)
        self.assertIn("Unsupported", first)


if __name__ == "__main__":
    unittest.main()
