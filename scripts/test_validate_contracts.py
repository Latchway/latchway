from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
