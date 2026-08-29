#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release-preflight.py")
SPEC = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleasePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-preflight-")
        self.root = Path(self.temporary.name)
        (self.root / "web/console").mkdir(parents=True)
        (self.root / "internal/buildinfo").mkdir(parents=True)
        (self.root / "api").mkdir()
        (self.root / "web/console/package.json").write_text(
            json.dumps({"version": "1.0.0"}), encoding="utf-8"
        )
        (self.root / "internal/buildinfo/buildinfo.go").write_text(
            'var (\n\tVersion = "1.0.0"\n)\nconst (\n\tContractVersion = "1.0.0"\n)\n',
            encoding="utf-8",
        )
        self.now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        self.write_manifest(self.now - timedelta(hours=1))
        (self.root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [1.0.0] - 2026-08-29\n", encoding="utf-8"
        )
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "test@latchway.dev")
        self.run_git("config", "user.name", "Latchway Test")
        self.run_git("add", ".")
        self.run_git("commit", "-q", "-m", "fixture")
        self.commit = self.run_git("rev-parse", "HEAD").stdout.strip()
        self.previous_root = MODULE.ROOT
        MODULE.ROOT = self.root

    def tearDown(self) -> None:
        MODULE.ROOT = self.previous_root
        self.temporary.cleanup()

    def run_git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def write_manifest(self, released_at: datetime, *, status: str = "released") -> None:
        (self.root / "api/protocol-version.json").write_text(
            json.dumps(
                {
                    "contract_version": "1.0.0",
                    "contract_status": status,
                    "released_at": released_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "bundle": {"file_name": "latchway-contract-1.0.0.tar.gz"},
                }
            ),
            encoding="utf-8",
        )

    def validate(self, tag: str = "v1.0.0") -> dict[str, object]:
        return MODULE.validate_candidate(tag, self.commit, self.now)

    def commit_version(self, version: str) -> None:
        (self.root / "web/console/package.json").write_text(
            json.dumps({"version": version}), encoding="utf-8"
        )
        (self.root / "internal/buildinfo/buildinfo.go").write_text(
            f'var (\n\tVersion = "{version}"\n)\n'
            'const (\n\tContractVersion = "1.0.0"\n)\n',
            encoding="utf-8",
        )
        changelog = (self.root / "CHANGELOG.md").read_text(encoding="utf-8")
        changelog = changelog.replace("## [1.0.0]", f"## [{version}]", 1)
        (self.root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        self.run_git(
            "add",
            "web/console/package.json",
            "internal/buildinfo/buildinfo.go",
            "CHANGELOG.md",
        )
        self.run_git("commit", "-q", "-m", f"version {version}")
        self.commit = self.run_git("rev-parse", "HEAD").stdout.strip()

    def test_accepts_clean_untagged_released_candidate(self) -> None:
        report = self.validate()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["candidate_commit"], self.commit)
        self.assertEqual(report["intended_tag"], "v1.0.0")

    def test_accepts_canonical_rc_checkpoint(self) -> None:
        self.commit_version("1.0.0-rc.1")
        report = self.validate("v1.0.0-rc.1")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["candidate_commit"], self.commit)
        self.assertEqual(report["intended_tag"], "v1.0.0-rc.1")
        self.assertEqual(report["version"], "1.0.0-rc.1")

    def test_rejects_prerelease_that_cannot_be_a_canonical_prior_rc(self) -> None:
        for tag in (
            "v1.0.0-alpha.1",
            "v1.0.0-rc.0",
            "v1.0.0-rc.01",
            "v1.0.0-rc.1.extra",
        ):
            with self.subTest(tag=tag):
                with self.assertRaisesRegex(
                    MODULE.PreflightError, "release_tag_not_canonical"
                ):
                    self.validate(tag)

    def test_rejects_draft_contract(self) -> None:
        self.write_manifest(self.now - timedelta(hours=1), status="draft")
        self.run_git("add", "api/protocol-version.json")
        self.run_git("commit", "-q", "-m", "draft")
        self.commit = self.run_git("rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(MODULE.PreflightError, "contract_not_released"):
            self.validate()

    def test_rejects_future_or_expired_release_window(self) -> None:
        for released_at, code in (
            (self.now + timedelta(seconds=1), "contract_released_at_in_future"),
            (self.now - timedelta(days=8), "contract_release_window_expired"),
        ):
            with self.subTest(code=code):
                self.write_manifest(released_at)
                self.run_git("add", "api/protocol-version.json")
                self.run_git("commit", "-q", "-m", code)
                self.commit = self.run_git("rev-parse", "HEAD").stdout.strip()
                with self.assertRaisesRegex(MODULE.PreflightError, code):
                    self.validate()

    def test_rejects_existing_tag(self) -> None:
        self.run_git("tag", "-a", "v1.0.0", "-m", "already public")
        with self.assertRaisesRegex(MODULE.PreflightError, "candidate_tag_already_exists"):
            self.validate()

    def test_rejects_wrong_commit_and_dirty_tree(self) -> None:
        with self.assertRaisesRegex(MODULE.PreflightError, "candidate_commit_not_at_head"):
            MODULE.validate_candidate("v1.0.0", "0" * 40, self.now)
        (self.root / "untracked").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.PreflightError, "dirty_worktree"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
