#!/usr/bin/env python3
"""Build a byte-reproducible Latchway cross-repository contract bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
API_ROOT = REPOSITORY_ROOT / "api"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_tar_info(archive: tarfile.TarFile, path: Path, name: str) -> tarfile.TarInfo:
    info = archive.gettarinfo(str(path), arcname=name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = 0o755 if path.is_dir() else 0o644
    return info


def write_archive(source_root: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(source_root.rglob("*"), key=lambda item: item.relative_to(source_root).as_posix()):
                    relative = path.relative_to(source_root).as_posix()
                    info = normalized_tar_info(archive, path, relative)
                    if path.is_file():
                        with path.open("rb") as payload:
                            archive.addfile(info, payload)
                    else:
                        archive.addfile(info)


def build(output_directory: Path) -> Path:
    manifest = json.loads((API_ROOT / "protocol-version.json").read_text(encoding="utf-8"))
    version = manifest["contract_version"]
    expected_name = f"latchway-contract-{version}.tar.gz"
    if manifest["bundle"]["file_name"] != expected_name:
        raise ValueError("protocol manifest bundle file_name does not match contract_version")

    files = [
        "client.openapi.yaml",
        "admin.openapi.yaml",
        "config.schema.json",
        "attestation-binding.schema.json",
        "release-evidence.schema.json",
        "error-codes.yaml",
        "protocol-version.json",
    ]
    for relative in files:
        if not (API_ROOT / relative).is_file():
            raise FileNotFoundError(f"missing contract source: api/{relative}")
    if not (API_ROOT / "test-vectors").is_dir():
        raise FileNotFoundError("missing contract source: api/test-vectors")

    with tempfile.TemporaryDirectory(prefix="latchway-contract-") as temporary:
        staging = Path(temporary)
        for relative in files:
            shutil.copyfile(API_ROOT / relative, staging / relative)
        shutil.copytree(API_ROOT / "test-vectors", staging / "test-vectors")

        payloads = sorted(
            path for path in staging.rglob("*") if path.is_file() and path.name != "SHA256SUMS"
        )
        checksum_lines = [
            f"{sha256(path)}  {path.relative_to(staging).as_posix()}" for path in payloads
        ]
        (staging / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

        output = output_directory / expected_name
        write_archive(staging, output)
        return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=REPOSITORY_ROOT / "dist",
        help="destination directory (default: repository dist/)",
    )
    args = parser.parse_args()
    output = build(args.output_directory.resolve())
    print(f"{sha256(output)}  {output}")


if __name__ == "__main__":
    main()
