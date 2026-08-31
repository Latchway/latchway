#!/usr/bin/env python3
"""Focused tests for the public-documentation ownership boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("sync-public-docs.py")
SPEC = importlib.util.spec_from_file_location("sync_public_docs", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"cannot load {SCRIPT}")
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class SourceFilesTests(unittest.TestCase):
    def test_includes_assistant_and_complete_skill_packages_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            expected = {
                "index.mdx": "home",
                ".mintlify/Assistant.md": "assistant",
                ".mintlify/skills/integrate-web/SKILL.md": "skill",
                ".mintlify/skills/integrate-web/references/browser.md": "reference",
            }
            excluded = {
                ".mintlify/settings.json": "private settings",
                ".mintlify/previews/state.json": "private preview state",
                "nested/.mintlify/skills/not-root/SKILL.md": "nested internals",
                ".git/config": "git internals",
                "node_modules/package/index.js": "dependency",
            }
            for relative, content in (expected | excluded).items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            files = SYNC.source_files(source)

            self.assertEqual(set(files), set(expected))

    def test_rejects_symlinks_inside_a_public_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            target = source / "target.md"
            target.write_text("target", encoding="utf-8")
            link = source / ".mintlify/skills/install-latchway/SKILL.md"
            link.parent.mkdir(parents=True)
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError) as error:  # pragma: no cover
                self.skipTest(f"symlinks unavailable: {error}")

            with self.assertRaisesRegex(ValueError, "source contains a symlink"):
                SYNC.source_files(source)


if __name__ == "__main__":
    unittest.main()
