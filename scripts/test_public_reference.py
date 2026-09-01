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
        self.client = reference.load_client_contract()
        self.errors = reference.load_error_registry()
        self.sdk_errors = reference.load_sdk_error_registry()
        self.config = reference.load_config_schema()

    def test_repository_generated_references_are_current(self) -> None:
        rendered = reference.validate_repository(check_generated=True)
        expected = {
            reference.ADMIN_OUTPUT,
            reference.CLIENT_OUTPUT,
            reference.ERROR_OUTPUT,
            reference.CONFIG_OUTPUT,
            reference.COMPATIBILITY_OUTPUT,
            reference.MANIFEST_OUTPUT,
        }
        expected.update(
            reference.ERROR_PAGE_ROOT / f"{reference.error_slug(code)}.mdx"
            for code in self.errors["codes"]
        )
        expected.update(
            reference.ERROR_PAGE_ROOT / f"{reference.error_slug(code)}.mdx"
            for code in self.sdk_errors["codes"]
        )
        self.assertEqual(set(rendered), expected)

    def test_generated_manifest_binds_normative_sources_and_outputs(self) -> None:
        rendered = reference.render_all()
        manifest = json.loads(rendered[reference.MANIFEST_OUTPUT])
        self.assertEqual(manifest["format"], 1)
        self.assertEqual(manifest["generator"], "scripts/public_reference.py")
        self.assertEqual(
            [entry["path"] for entry in manifest["sources"]],
            [
                "api/admin.openapi.yaml",
                "api/client.openapi.yaml",
                "api/config.schema.json",
                "api/error-codes.yaml",
                "api/sdk-error-codes.yaml",
                "compatibility/frameworks.schema.json",
                "compatibility/frameworks.yaml",
            ],
        )
        output_paths = [entry["path"] for entry in manifest["outputs"]]
        self.assertEqual(
            len(output_paths),
            5 + len(self.errors["codes"]) + len(self.sdk_errors["codes"]),
        )
        self.assertIn("reference/errors.mdx", output_paths)
        self.assertIn("errors/quota-exceeded.mdx", output_paths)
        self.assertIn("errors/component-parent-trust-expired.mdx", output_paths)
        self.assertIn("errors/root-keychain-migration-required.mdx", output_paths)
        self.assertIn("errors/response-invalid.mdx", output_paths)

    def test_rendering_is_deterministic(self) -> None:
        self.assertEqual(
            reference.render_admin_reference(self.admin),
            reference.render_admin_reference(self.admin),
        )
        self.assertEqual(
            reference.render_client_reference(self.client),
            reference.render_client_reference(self.client),
        )
        self.assertEqual(
            reference.render_error_reference(self.errors),
            reference.render_error_reference(self.errors),
        )
        for code, definition in self.errors["codes"].items():
            self.assertEqual(
                reference.render_error_page(code, definition),
                reference.render_error_page(code, definition),
            )
        for code, definition in self.sdk_errors["codes"].items():
            self.assertEqual(
                reference.render_sdk_error_page(code, definition),
                reference.render_sdk_error_page(code, definition),
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
        self.assertEqual(len(operations), 77)
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
        self.assertIn("The public site disables request submission", rendered)
        self.assertIn("LATCHWAY_ADMIN_TOKEN", rendered)
        self.assertIn("Do not paste a production administrator token", rendered)
        self.assertIn("without changing siblings or revoking already-issued access", rendered)

    def test_client_reference_contains_every_operation_once(self) -> None:
        rendered = reference.render_client_reference(self.client)
        operations = []
        for path_item in self.client["paths"].values():
            for method in reference.HTTP_METHODS:
                operation = path_item.get(method)
                if isinstance(operation, dict):
                    operations.append(operation["operationId"])
        self.assertEqual(len(operations), 23)
        for operation_id in operations:
            self.assertEqual(rendered.count(f"`{operation_id}`"), 1, operation_id)
        for exact_path in (
            "/.well-known/latchway",
            "/client/v1/session-challenges",
            "/client/v1/installation-families/current/components",
            "/client/v1/diagnostics",
            "/v1/responses",
            "/v1/chat/completions",
            "/v1/embeddings",
            "/v1/messages",
            "/proxy/{feature}/{remainingPath}",
        ):
            self.assertIn(f"`{exact_path}`", rendered)
        self.assertIn("Canonical source: api/client.openapi.yaml", rendered)
        self.assertIn("intentionally embeds no interactive API", rendered)
        self.assertIn("static bearer field cannot reproduce", rendered)
        self.assertIn("version-matched SDK or the signed sample application", rendered)
        self.assertIn("`DPoPAccessToken` + `DPoPProof`", rendered)

    def test_error_reference_contains_every_stable_code_once(self) -> None:
        rendered = reference.render_error_reference(self.errors)
        self.assertEqual(len(self.errors["codes"]), 59)
        for code in self.errors["codes"]:
            self.assertEqual(
                rendered.count(f"| [`{code}`](/errors/{reference.error_slug(code)}) |"),
                1,
                code,
            )
            self.assertEqual(rendered.count(f"### `{code}`\n"), 1, code)
        self.assertIn("`operation_id` is required only for `operation_indeterminate`", rendered)
        self.assertEqual(
            set(self.sdk_errors["codes"]),
            {
                "attestation_provider_missing",
                "cancelled",
                "client_configuration_invalid",
                "crypto_unavailable",
                "foundation_models_gateway_error",
                "foundation_models_gateway_stream_invalid",
                "foundation_models_invalid_transcript",
                "foundation_models_sampling_unsupported",
                "key_unavailable",
                "keychain_access_group_unavailable",
                "network_error",
                "network_unavailable",
                "protocol_response_invalid",
                "request_not_replayable",
                "response_invalid",
                "root_keychain_migration_required",
                "secure_state_unavailable",
                "server_response_invalid",
                "session_unavailable",
                "storage_unavailable",
                "transport_failure",
            },
        )
        for code in self.sdk_errors["codes"]:
            self.assertEqual(
                rendered.count(f"| [`{code}`](/errors/{reference.error_slug(code)}) |"),
                1,
                code,
            )
            self.assertEqual(rendered.count(f"### `{code}`\n"), 1, code)
        sdk_page = reference.render_sdk_error_page(
            "network_error", self.sdk_errors["codes"]["network_error"]
        )
        self.assertIn("not an HTTP Problem", sdk_page)
        self.assertNotIn('"status":', sdk_page)

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
