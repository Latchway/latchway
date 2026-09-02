from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check_metadata.py")
SPEC = importlib.util.spec_from_file_location("check_metadata", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)


class MetadataChecks(unittest.TestCase):
    def test_every_canonical_route_resolves_every_required_field(self) -> None:
        root = SCRIPT.parents[1]
        errors = metadata.validate_repository(root, today=date(2026, 9, 2))
        self.assertEqual(errors, [])
        overlay = metadata.load_overlay(root / "config/generated-page-metadata.json")
        for route, path in metadata.page_files(root).items():
            physical, _ = metadata.parse_frontmatter(path)
            effective = metadata.effective_metadata(route, physical, overlay)
            self.assertEqual(set(effective) & metadata.REQUIRED_FIELDS, metadata.REQUIRED_FIELDS)

    def test_missing_field_and_stale_verification_fail_closed(self) -> None:
        complete = {
            "title": "Title",
            "description": "Description",
            "icon": "rocket",
            "audience": "mixed",
            "pageType": "concept",
            "serverVersion": "1.0.0",
            "sdkVersion": "not-applicable",
            "lastVerified": "2025-01-01",
            "owner": "docs",
        }
        stale = metadata.validate_fields("page", complete, date(2026, 9, 2))
        self.assertTrue(any("more than 183 days old" in error for error in stale))
        del complete["owner"]
        missing = metadata.validate_fields("page", complete, date(2026, 9, 2))
        self.assertEqual(missing, ["page lacks effective metadata: owner"])

    def test_golden_template_and_each_step_fail_closed(self) -> None:
        incomplete = "\n".join(metadata.GOLDEN_HEADINGS) + """
<Steps>
  <Step title="Incomplete">
    Expected result: the command succeeds.
  </Step>
</Steps>
"""
        errors = metadata.validate_golden_body("clients/ios/quickstart", incomplete)
        self.assertTrue(any("Expected time" in error for error in errors))
        self.assertTrue(any("step 1 lacks a diagnostic" in error for error in errors))

        complete = incomplete.replace(
            "<Steps>",
            "**Expected time:** 15 minutes.\n**Mode:** Local.\n**Coordinates:** 1.0.0.\n<Steps>",
        ).replace(
            "Expected result: the command succeeds.",
            "Expected result: the command succeeds. Diagnostic: inspect the safe output.",
        )
        self.assertEqual(metadata.validate_golden_body("clients/ios/quickstart", complete), [])


if __name__ == "__main__":
    unittest.main()
