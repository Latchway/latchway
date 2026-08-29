from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("verify-oci-alias-transition.py")
SPEC = importlib.util.spec_from_file_location("verify_oci_alias_transition", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OCIAliasTransitionTests(unittest.TestCase):
    def test_sequential_patch_and_minor_releases_advance_expected_aliases(self) -> None:
        states: dict[str, str] = {}
        for candidate in ("1.0.0", "1.0.1", "1.1.0"):
            for alias in MODULE.expected_aliases(candidate):
                current = states.get(alias)
                if current is not None:
                    self.assertEqual(MODULE.authorize(alias, current, candidate), "advance")
                states[alias] = candidate
        self.assertEqual(states, {"1.0": "1.0.1", "1": "1.1.0", "latest": "1.1.0", "1.1": "1.1.0"})

    def test_retry_is_idempotent_but_old_release_cannot_roll_back(self) -> None:
        for alias in ("1.1", "1", "latest"):
            self.assertEqual(MODULE.authorize(alias, "1.1.0", "1.1.0"), "already_current")
        for alias in ("1", "latest"):
            with self.assertRaisesRegex(MODULE.TransitionError, "oci_alias_rollback_rejected"):
                MODULE.authorize(alias, "1.1.0", "1.0.1")

    def test_rejects_cross_scope_and_prerelease_transitions(self) -> None:
        with self.assertRaisesRegex(MODULE.TransitionError, "oci_alias_current_scope_invalid"):
            MODULE.authorize("1.1", "1.0.9", "1.1.0")
        with self.assertRaisesRegex(MODULE.TransitionError, "oci_alias_version_invalid"):
            MODULE.authorize("latest", "1.0.0", "1.1.0-rc.1")


if __name__ == "__main__":
    unittest.main()
