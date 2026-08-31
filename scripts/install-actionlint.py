#!/usr/bin/env python3

from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import platform
import shutil
import stat
import tarfile
from urllib.request import urlopen


VERSION = "1.7.12"
ARCHIVE = f"actionlint_{VERSION}_linux_amd64.tar.gz"
EXPECTED_SHA256 = "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
MAXIMUM_ARCHIVE_BYTES = 8 * 1024 * 1024
URL = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/{ARCHIVE}"


def required_absolute_path(name: str) -> Path:
    value = os.environ.get(name)
    if value is None or "\x00" in value:
        raise SystemExit(f"{name} must be an absolute runner-provided path")
    path = Path(value)
    if not path.is_absolute():
        raise SystemExit(f"{name} must be an absolute runner-provided path")
    return path


def download_bounded() -> bytes:
    with urlopen(URL, timeout=120) as response:  # noqa: S310 - pinned digest below
        final_url = response.geturl()
        if not final_url.startswith("https://"):
            raise SystemExit("actionlint download did not remain on HTTPS")
        value = response.read(MAXIMUM_ARCHIVE_BYTES + 1)
    if len(value) > MAXIMUM_ARCHIVE_BYTES:
        raise SystemExit("pinned actionlint archive exceeded its maximum allowed size")
    if sha256(value).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("pinned actionlint archive digest mismatch")
    return value


def extract_executable(value: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=BytesIO(value), mode="r:gz") as archive:
        members = archive.getmembers()
        matches = [member for member in members if member.name == "actionlint"]
        if len(matches) != 1 or not matches[0].isfile():
            raise SystemExit("pinned actionlint archive does not contain the expected executable")
        member = matches[0]
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("pinned actionlint executable could not be read")
        payload = source.read(32 * 1024 * 1024 + 1)
        if not payload or len(payload) > 32 * 1024 * 1024:
            raise SystemExit("pinned actionlint executable has an invalid size")
    destination.write_bytes(payload)
    destination.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def main() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise SystemExit("the CI actionlint installer supports only the pinned ubuntu-24.04 x64 runner")
    runner_temp = required_absolute_path("RUNNER_TEMP").resolve()
    github_path = required_absolute_path("GITHUB_PATH")
    install_directory = (runner_temp / f"latchway-actionlint-{VERSION}").resolve()
    if install_directory.parent != runner_temp:
        raise SystemExit("actionlint install directory escaped RUNNER_TEMP")
    shutil.rmtree(install_directory, ignore_errors=True)
    install_directory.mkdir(mode=0o700)
    executable = install_directory / "actionlint"
    extract_executable(download_bounded(), executable)
    with github_path.open("a", encoding="utf-8") as output:
        output.write(f"{install_directory}\n")
    print(f"Installed actionlint {VERSION} with verified SHA-256.")


if __name__ == "__main__":
    main()
