from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import public_reference as reference


class PublicReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admin = reference.load_admin_contract()
        self.errors = reference.load_error_registry()
        self.config = reference.load_config_schema()

    def test_repository_generated_references_are_current(self) -> None:
        rendered = reference.validate_repository(check_generated=True)
        self.assertEqual(
            set(rendered),
            {
                reference.ADMIN_OUTPUT,
                reference.ERROR_OUTPUT,
                reference.CONFIG_OUTPUT,
                reference.COMPATIBILITY_OUTPUT,
                reference.MANIFEST_OUTPUT,
            },
        )

    def test_generated_manifest_binds_normative_sources_and_outputs(self) -> None:
        rendered = reference.render_all()
        manifest = json.loads(rendered[reference.MANIFEST_OUTPUT])
        self.assertEqual(manifest["format"], 1)
        self.assertEqual(manifest["generator"], "scripts/public_reference.py")
        self.assertEqual(
            [entry["path"] for entry in manifest["sources"]],
            [
                "api/admin.openapi.yaml",
                "api/config.schema.json",
                "api/error-codes.yaml",
                "compatibility/frameworks.schema.json",
                "compatibility/frameworks.yaml",
            ],
        )
        self.assertEqual(
            [entry["path"] for entry in manifest["outputs"]],
            [
                "reference/admin-api.mdx",
                "reference/compatibility.mdx",
                "reference/config-schema.mdx",
                "reference/errors.mdx",
            ],
        )

    def test_rendering_is_deterministic(self) -> None:
        self.assertEqual(
            reference.render_admin_reference(self.admin),
            reference.render_admin_reference(self.admin),
        )
        self.assertEqual(
            reference.render_error_reference(self.errors),
            reference.render_error_reference(self.errors),
        )
        self.assertEqual(
            reference.render_config_reference(self.config),
            reference.render_config_reference(self.config),
        )

    def test_admin_reference_contains_every_operation_once(self) -> None:
        rendered = reference.render_admin_reference(self.admin)
        operations = []
        for path_item in self.admin["paths"].values():
            for method in reference.HTTP_METHODS:
                operation = path_item.get(method)
                if isinstance(operation, dict):
                    operations.append(operation["operationId"])
        self.assertEqual(len(operations), 62)
        for operation_id in operations:
            self.assertEqual(rendered.count(f"`{operation_id}`"), 1, operation_id)
        for exact_path in (
            "/admin/v1/installation-families",
            "/admin/v1/installation-families/{familyId}",
            "/admin/v1/installation-families/{familyId}/revoke",
            "/admin/v1/installation-families/{familyId}/require-renewal",
            "/admin/v1/client-components",
            "/admin/v1/client-components/{componentId}",
            "/admin/v1/client-components/{componentId}/revoke",
            "/admin/v1/client-components/{componentId}/require-reattestation",
        ):
            self.assertIn(f"`{exact_path}`", rendered)
        self.assertIn("intentionally embeds no interactive API", rendered)
        self.assertIn("without changing siblings or revoking already-issued access", rendered)

    def test_error_reference_contains_every_stable_code_once(self) -> None:
        rendered = reference.render_error_reference(self.errors)
        self.assertEqual(len(self.errors["codes"]), 59)
        for code in self.errors["codes"]:
            self.assertEqual(rendered.count(f"| `{code}` |"), 1, code)
        self.assertIn("`operation_id` is required only for `operation_indeterminate`", rendered)

    def test_config_reference_contains_every_definition(self) -> None:
        rendered = reference.render_config_reference(self.config)
        self.assertEqual(len(self.config["$defs"]), 39)
        for name in self.config["$defs"]:
            self.assertEqual(rendered.count(f"### {name}\n"), 1, name)
        self.assertIn("unknown properties rejected", rendered)
        self.assertIn("`componentDefinitions`", rendered)
        self.assertIn("`inputAccountingProfiles`", rendered)

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "errors.yaml"
            path.write_text("registry_version: 1\nregistry_version: 1\n", encoding="utf-8")
            with self.assertRaisesRegex(reference.ReferenceError, "duplicate YAML key"):
                reference._load_yaml(path)

    def test_unresolved_config_reference_is_rejected(self) -> None:
        modified = deepcopy(self.config)
        modified["properties"]["spec"] = {"$ref": "#/$defs/Absent"}
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "config.schema.json"
            path.write_text(json.dumps(modified), encoding="utf-8")
            with self.assertRaisesRegex(reference.ReferenceError, "unresolved local reference"):
                reference.load_config_schema(path)


if __name__ == "__main__":
    unittest.main()
