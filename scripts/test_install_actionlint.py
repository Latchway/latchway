#!/usr/bin/env python3

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("install-actionlint.py")
SPEC = spec_from_file_location("install_actionlint", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
INSTALLER = module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def archive(entries: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as value:
        for member, payload in entries:
            member.size = len(payload)
            value.addfile(member, BytesIO(payload))
    return output.getvalue()


class ActionlintInstallerTests(unittest.TestCase):
    def test_extracts_only_the_expected_regular_executable(self) -> None:
        member = tarfile.TarInfo("actionlint")
        member.mode = 0o755
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "actionlint"
            INSTALLER.extract_executable(archive([(member, b"binary")]), destination)
            self.assertEqual(destination.read_bytes(), b"binary")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_ignores_unrequested_archive_members(self) -> None:
        executable = tarfile.TarInfo("actionlint")
        unexpected = tarfile.TarInfo("README.md")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "actionlint"
            INSTALLER.extract_executable(
                archive([(executable, b"binary"), (unexpected, b"text")]),
                destination,
            )
            self.assertEqual(destination.read_bytes(), b"binary")

    def test_rejects_a_link_in_place_of_the_executable(self) -> None:
        member = tarfile.TarInfo("actionlint")
        member.type = tarfile.SYMTYPE
        member.linkname = "/tmp/untrusted"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "actionlint"
            with self.assertRaisesRegex(SystemExit, "expected executable"):
                INSTALLER.extract_executable(archive([(member, b"")]), destination)


if __name__ == "__main__":
    unittest.main()
