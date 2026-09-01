from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.framework_observation import observation


class FrameworkObservationTests(unittest.TestCase):
    def test_observation_binds_report_commit_profile_and_sorted_versions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            report = Path(raw_directory) / "report.json"
            report.write_text("{}\n", encoding="utf-8")
            value = observation(
                "latchway-android",
                "newest-compatible",
                "success",
                report,
                "a" * 40,
                ["Koog=1.1.1", "OkHttp=5.3.0"],
                "https://github.com/Latchway/latchway-android/actions/runs/1/attempts/1",
            )
        self.assertEqual(value["observed_versions"], {"Koog": "1.1.1", "OkHttp": "5.3.0"})
        self.assertEqual(len(str(value["framework_report_sha256"])), 64)

    def test_duplicate_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            report = Path(raw_directory) / "report.json"
            report.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                observation(
                    "latchway-ios-sdk",
                    "minimum",
                    "failure",
                    report,
                    "b" * 40,
                    ["SwiftOpenAI=4.6.0", "SwiftOpenAI=4.6.1"],
                    "https://github.com/Latchway/latchway-ios-sdk/actions/runs/1/attempts/1",
                )

    def test_registry_exact_profile_is_explicit_when_minimum_equals_latest(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            report = Path(raw_directory) / "report.json"
            report.write_text("{}\n", encoding="utf-8")
            value = observation(
                "latchway-react-native-sdk",
                "registry-exact",
                "success",
                report,
                "c" * 40,
                ["ReactNative=0.82.0"],
                "https://github.com/Latchway/latchway-react-native-sdk/actions/runs/1/attempts/1",
            )
        self.assertEqual(value["profile"], "registry-exact")


if __name__ == "__main__":
    unittest.main()
