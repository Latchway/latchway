"""Focused schema regression coverage without changing release-workflow policy."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("validate_contracts", ROOT / "scripts" / "validate-contracts.py")
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
SCHEMA_PATH = ROOT / "api" / "config.schema.json"


class DevelopmentAttestationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = VALIDATOR.load_json(SCHEMA_PATH)
        self.document = copy.deepcopy(self.schema["examples"][0])

    def apple(self) -> dict:
        for policy in self.document["spec"]["attestationPolicies"]:
            for selection in policy["platforms"].values():
                if "appAttest" in selection:
                    return selection["appAttest"]
        self.fail("normative example must contain an App Attest policy")

    def errors(self) -> list:
        return VALIDATOR.schema_errors(SCHEMA_PATH, self.schema, self.document, "config")

    def test_accepts_all_three_server_acceptance_policies(self) -> None:
        for environment in ("development", "production", "any"):
            with self.subTest(environment=environment):
                self.apple()["environment"] = environment
                self.apple()["allowedValidationCategories"] = [2, 3]
                self.assertEqual(self.errors(), [])

    def test_rejects_unknown_environment_and_empty_category_list(self) -> None:
        for unsupported in ("sandbox", "both"):
            self.apple()["environment"] = unsupported
            self.assertTrue(self.errors())
        self.apple()["environment"] = "any"
        self.apple()["allowedValidationCategories"] = []
        self.assertTrue(self.errors())

    def test_play_testing_is_explicit_boolean_not_a_client_debug_token(self) -> None:
        definition = self.schema["$defs"]["PlayIntegrityConfiguration"]
        self.assertIn("allowTestingResponses", definition["required"])
        self.assertEqual(definition["properties"]["allowTestingResponses"]["type"], "boolean")
        self.assertIn("only in a development", definition["properties"]["allowTestingResponses"]["description"])


if __name__ == "__main__":
    unittest.main()
