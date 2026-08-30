from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("require-gh-version.py")
SPEC = importlib.util.spec_from_file_location("require_gh_version", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RequireGitHubCLIVersionTests(unittest.TestCase):
    def test_accepts_fixed_and_later_versions(self) -> None:
        self.assertEqual(MODULE.require_version("gh version 2.97.0 (2026-08-01)\n"), (2, 97, 0))
        self.assertEqual(MODULE.require_version("gh version 3.0.1\n"), (3, 0, 1))

    def test_rejects_both_known_vulnerable_ranges(self) -> None:
        for value in ("2.74.2", "2.92.9", "2.93.0", "2.96.9"):
            with self.subTest(value=value), self.assertRaisesRegex(
                MODULE.VersionError, "github_cli_version_vulnerable"
            ):
                MODULE.require_version(f"gh version {value}\n")

    def test_rejects_ambiguous_output(self) -> None:
        for value in ("", "github cli 2.97.0", "gh version 2.97", "gh version 02.97.0"):
            with self.subTest(value=value), self.assertRaisesRegex(
                MODULE.VersionError, "github_cli_version_invalid"
            ):
                MODULE.require_version(value)

    def test_installed_version_normalizes_spawn_failures(self) -> None:
        with mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/gh"), mock.patch.object(
            MODULE.subprocess, "run", side_effect=subprocess.TimeoutExpired("gh", 10)
        ), self.assertRaisesRegex(MODULE.VersionError, "github_cli_unavailable"):
            MODULE.installed_version()


if __name__ == "__main__":
    unittest.main()
