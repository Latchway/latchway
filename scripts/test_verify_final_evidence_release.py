from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("verify-final-evidence-release.py")
SPEC = importlib.util.spec_from_file_location("verify_final_evidence_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

COMMIT = "a" * 40
TAG = "v1.0.0"


class FinalEvidenceReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-prior-final-")
        self.directory = Path(self.temporary.name)
        for name in sorted(MODULE.DURABLE):
            (self.directory / name).write_bytes((name + "\n").encode())
        report = [
            f"| Core repository commit and tag | `{COMMIT}` / `{TAG}` |",
            f"> Evidence publication target: [`evidence/{TAG}`](https://example.invalid).",
        ]
        for name in sorted(MODULE.DURABLE):
            digest = hashlib.sha256((self.directory / name).read_bytes()).hexdigest()
            report.append(f"| `{name}` | `{digest}` |")
        (self.directory / "COMPLETION_REPORT.md").write_text(
            "\n".join(report) + "\n", encoding="utf-8"
        )
        (self.directory / "COMPLETION_REPORT.attestation.sigstore.json").write_text(
            '{"bundle":"valid-in-workflow"}\n', encoding="utf-8"
        )
        self.refresh_checksum_and_release()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def refresh_checksum_and_release(self) -> None:
        lines = []
        for name in sorted(MODULE.EXPECTED - {"SHA256SUMS"}):
            digest = hashlib.sha256((self.directory / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (self.directory / "SHA256SUMS").write_text(
            "\n".join(sorted(lines)) + "\n", encoding="ascii"
        )
        self.release = {
            "assets": [
                {
                    "name": name,
                    "size": (self.directory / name).stat().st_size,
                    "digest": "sha256:"
                    + hashlib.sha256((self.directory / name).read_bytes()).hexdigest(),
                }
                for name in sorted(MODULE.EXPECTED)
            ]
        }

    def test_complete_signed_report_closure_passes(self) -> None:
        result = MODULE.validate(self.directory, self.release, COMMIT, TAG)
        self.assertEqual(set(result), MODULE.EXPECTED)

    def test_arbitrary_asset_with_rewritten_checksum_and_release_digest_fails(self) -> None:
        target = self.directory / "latchway-publication-state.json"
        target.write_text('{"substituted":true}\n', encoding="utf-8")
        self.refresh_checksum_and_release()
        with self.assertRaisesRegex(MODULE.EvidenceError, "report_asset_mismatch"):
            MODULE.validate(self.directory, self.release, COMMIT, TAG)

    def test_api_digest_or_file_set_substitution_fails(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(MODULE.EvidenceError, "release_digest_mismatch"):
            MODULE.validate(self.directory, release, COMMIT, TAG)
        (self.directory / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.EvidenceError, "file_set_invalid"):
            MODULE.validate(self.directory, self.release, COMMIT, TAG)


if __name__ == "__main__":
    unittest.main()
