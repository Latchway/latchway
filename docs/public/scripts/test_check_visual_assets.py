from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-visual-assets.py")
SPEC = importlib.util.spec_from_file_location("check_visual_assets", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class VisualAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "assets").mkdir()
        (self.root / "config").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def svg(*, unsafe: str = "") -> str:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 80" '
            'role="img" aria-labelledby="title description">'
            '<title id="title">Diagram</title>'
            '<desc id="description">A long accessible explanation of the complete diagram relationship.</desc>'
            '<style>@media (prefers-color-scheme: dark){} '
            '@media (forced-colors: active){}</style>'
            f'{unsafe}<rect x="1" y="1" width="20" height="20"/></svg>\n'
        )

    def write_fixture(self, *, unsafe: str = "") -> tuple[Path, dict[str, object]]:
        asset = self.root / "assets/architecture.svg"
        asset.write_text(self.svg(unsafe=unsafe), encoding="utf-8")
        alt = "A complete accessible text alternative for the architecture diagram."
        page = self.root / "index.mdx"
        page.write_text(
            f'<Frame caption="Architecture"><img src="/assets/architecture.svg" alt="{alt}" /></Frame>\n',
            encoding="utf-8",
        )
        visual = {
            "alt": alt,
            "asset": "assets/architecture.svg",
            "page": "index.mdx",
            "purpose": "homepage-architecture",
            "sha256": hashlib.sha256(asset.read_bytes()).hexdigest(),
        }
        return asset, visual

    def test_svg_validator_accepts_accessible_adaptive_asset(self) -> None:
        asset, _ = self.write_fixture()
        MODULE.validate_svg(asset, "assets/architecture.svg")

    def test_svg_validator_rejects_script_or_fixed_dimensions(self) -> None:
        asset, _ = self.write_fixture(unsafe="<script>alert(1)</script>")
        with self.assertRaisesRegex(MODULE.VisualError, "unsafe SVG element"):
            MODULE.validate_svg(asset, "assets/architecture.svg")
        asset.write_text(self.svg().replace("viewBox=", 'width="100" viewBox='))
        with self.assertRaisesRegex(MODULE.VisualError, "fixed dimensions"):
            MODULE.validate_svg(asset, "assets/architecture.svg")

    def test_manifest_loader_rejects_duplicate_keys(self) -> None:
        (self.root / MODULE.MANIFEST).write_text(
            '{"format":1,"format":1,"visuals":[]}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(MODULE.VisualError, "duplicate JSON key"):
            MODULE.load_manifest(self.root)

    def test_full_verifier_rejects_digest_or_alt_drift(self) -> None:
        asset, visual = self.write_fixture()
        manifest = {"format": 1, "visuals": [visual]}
        (self.root / MODULE.MANIFEST).write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(MODULE.VisualError, "four required"):
            MODULE.verify(self.root)
        visual["sha256"] = "0" * 64
        (self.root / MODULE.MANIFEST).write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(MODULE.VisualError, "digest differs"):
            MODULE.verify(self.root)
        visual["sha256"] = hashlib.sha256(asset.read_bytes()).hexdigest()
        visual["alt"] = "A different accessible alternative that is long enough to pass policy."
        (self.root / MODULE.MANIFEST).write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(MODULE.VisualError, "exact accessible page use"):
            MODULE.verify(self.root)


if __name__ == "__main__":
    unittest.main()
