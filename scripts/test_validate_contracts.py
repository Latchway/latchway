from __future__ import annotations

import importlib.util
import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "validate_contracts", ROOT / "scripts" / "validate-contracts.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ContractReleaseStateTests(unittest.TestCase):
    def test_release_workflow_runs_release_state_regression_tests(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        validation = workflow.index("python3 scripts/validate-contracts.py")
        regression = workflow.index("scripts/test_validate_contracts.py")
        bundle = workflow.index("python3 scripts/build-contract-bundle.py")
        self.assertLess(validation, regression)
        self.assertLess(regression, bundle)

    def test_accepts_coherent_draft_and_released_states(self) -> None:
        MODULE.validate_contract_release_state(
            {"contract_status": "draft", "released_at": None}
        )
        MODULE.validate_contract_release_state(
            {
                "contract_status": "released",
                "released_at": "2026-09-02T00:00:00Z",
            }
        )

    def test_rejects_mixed_or_noncanonical_states(self) -> None:
        invalid = (
            {"contract_status": "draft", "released_at": "2026-09-02T00:00:00Z"},
            {"contract_status": "released", "released_at": None},
            {"contract_status": "released", "released_at": "2026-09-02T00:00:00+00:00"},
            {"contract_status": "candidate", "released_at": None},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.validate_contract_release_state(value)


class ContractDocumentVersionTests(unittest.TestCase):
    def test_bundle_edition_can_preserve_client_contract(self) -> None:
        manifest = {
            "contract_version": "1.1.1",
            "client_contract_version": "1.1.0",
            "bundle": {"file_name": "latchway-contract-1.1.1.tar.gz"},
        }
        self.assertEqual(
            MODULE.contract_document_versions(manifest), ("1.1.1", "1.1.0")
        )

    def test_historical_manifest_retains_single_coordinate(self) -> None:
        self.assertEqual(
            MODULE.contract_document_versions({
                "contract_version": "1.1.0",
                "bundle": {"file_name": "latchway-contract-1.1.0.tar.gz"},
            }),
            ("1.1.0", "1.1.0"),
        )

    def test_rejects_invalid_coordinates_and_reused_bundle_name(self) -> None:
        manifest = {
            "contract_version": "1.1.1",
            "client_contract_version": "1.1.0",
            "bundle": {"file_name": "latchway-contract-1.1.1.tar.gz"},
        }
        for key in ("contract_version", "client_contract_version"):
            for value in (None, 1, "1.1", "01.1.0", "1.1.0\n", "1.1.0-draft"):
                invalid = copy.deepcopy(manifest)
                invalid[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    MODULE.contract_document_versions(invalid)
        manifest["bundle"]["file_name"] = "latchway-contract-1.1.0.tar.gz"
        with self.assertRaises(ValueError):
            MODULE.contract_document_versions(manifest)

    def test_current_documents_use_their_own_coordinates(self) -> None:
        manifest = MODULE.load_document(ROOT / "api/protocol-version.json")
        bundle_version, client_version = MODULE.contract_document_versions(manifest)
        self.assertEqual((bundle_version, client_version), ("1.1.1", "1.1.0"))
        for filename, expected in (
            ("client.openapi.yaml", client_version),
            ("admin.openapi.yaml", bundle_version),
        ):
            document = MODULE.load_document(ROOT / "api" / filename)
            self.assertEqual(document["info"]["version"], expected)
        for filename in ("error-codes.yaml", "sdk-error-codes.yaml"):
            registry = MODULE.load_document(ROOT / "api" / filename)
            self.assertEqual(registry["contract_version"], client_version)


if __name__ == "__main__":
    unittest.main()
