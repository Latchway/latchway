from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).with_name("check-docs-pr-policy.py")
SPEC = importlib.util.spec_from_file_location("check_docs_pr_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def event(*, body: str | None, labels: list[str]) -> dict[str, object]:
    return {
        "pull_request": {
            "body": body,
            "labels": [{"name": label} for label in labels],
        }
    }


class DocumentationPullRequestPolicyTests(unittest.TestCase):
    def test_accepts_pull_request_without_exemption_label(self) -> None:
        self.assertIsNone(MODULE.validate_event(event(body=None, labels=[])))

    def test_accepts_written_reason_with_case_normalized_label(self) -> None:
        reason = MODULE.validate_event(
            event(
                labels=["Docs-Not-Required"],
                body=(
                    "## Documentation disposition\n\n"
                    "Docs-Not-Required-Reason: Internal test fixture only; no public behavior changes.\n"
                ),
            )
        )
        self.assertIn("Internal test fixture", reason or "")

    def test_rejects_missing_empty_or_placeholder_reason(self) -> None:
        bodies = (
            "No disposition field.\n",
            "Docs-Not-Required-Reason: <!-- explain why -->\n",
            "Docs-Not-Required-Reason: not applicable\n",
            "Docs-Not-Required-Reason: too short\n",
        )
        for body in bodies:
            with self.subTest(body=body):
                with self.assertRaises(MODULE.PolicyError):
                    MODULE.validate_event(event(body=body, labels=[MODULE.LABEL]))

    def test_rejects_malformed_label_shape(self) -> None:
        with self.assertRaisesRegex(MODULE.PolicyError, "label is malformed"):
            MODULE.validate_event(
                {"pull_request": {"body": "", "labels": [{"color": "fff"}]}}
            )


if __name__ == "__main__":
    unittest.main()
