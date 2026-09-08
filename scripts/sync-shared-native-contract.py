#!/usr/bin/env python3
"""Vendor a checksummed shared-native contract overlay with truthful source pins.

The existing contract.lock continues to identify the supported legacy contract.
Draft overlays identify draft bytes; released overlays require an actual core
commit containing every bundled contract input. They do not fabricate public
publication evidence or rewrite the separately retained legacy contract.lock.
Use --check to reject drift after editing the core-owned contract.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATHS = {
    "latchway-ios-sdk": "Tests/ConformanceTests/Fixtures/shared-native",
    "latchway-android": "latchway-core/src/test/resources/contract/shared-native",
    "latchway-react-native-sdk": "test/fixtures/contract/shared-native",
    "latchway-js": "test/fixtures/contract/shared-native",
}
FILES = {
    "protocol-version.json": "api/protocol-version.json",
    "shared-native-v3.json": "api/test-vectors/shared-native/v3.json",
    "sdk-error-codes.yaml": "api/sdk-error-codes.yaml",
    "supplied-identity-v1.json": "api/test-vectors/shared-native/supplied-identity-v1.json",
    "client.openapi.yaml": "api/client.openapi.yaml",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--core-commit", help="actual committed released contract source (required for released manifests)")
    parser.add_argument("--core-release", help="versioned core release tag, e.g. v1.1.0 (required for released manifests)")
    args = parser.parse_args()
    sdk = args.sdk_root.resolve()
    if sdk.name not in PATHS or not (sdk / "contract.lock").is_file():
        parser.error("sdk-root must name a known SDK with its existing legacy contract.lock")
    spec = importlib.util.spec_from_file_location("contract_bundle", ROOT / "scripts/build-contract-bundle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="latchway-shared-contract-") as temp:
        bundle = module.build(Path(temp))
        bundle_hash = hashlib.sha256(bundle.read_bytes()).hexdigest()
    outputs = {sdk / PATHS[sdk.name] / name: (ROOT / source).read_bytes() for name, source in FILES.items()}
    manifest = json.loads(outputs[sdk / PATHS[sdk.name] / "protocol-version.json"])
    status = manifest["contract_status"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if status == "released":
        if not args.core_commit or args.core_release != f"v{manifest['contract_version']}":
            parser.error("released contracts require --core-commit and their exact --core-release tag")
        commit = subprocess.check_output(["git", "rev-parse", "--verify", args.core_commit + "^{commit}"], cwd=ROOT, text=True).strip()
        inputs = [ROOT / "api" / name for name in manifest["bundle"]["required_entries"]
                  if name not in {"compatibility", "test-vectors", "SHA256SUMS"}]
        inputs += [path for path in (ROOT / "api/test-vectors").rglob("*") if path.is_file()]
        inputs += [ROOT / "compatibility" / name for name in ("frameworks.schema.json", "frameworks.yaml")]
        for path in inputs:
            committed = subprocess.check_output(["git", "show", f"{commit}:{path.relative_to(ROOT).as_posix()}"], cwd=ROOT)
            if committed != path.read_bytes():
                raise SystemExit(f"Released contract differs from committed input: {path.relative_to(ROOT)}")
    elif status != "draft" or args.core_commit or args.core_release:
        parser.error("draft contracts cannot receive released source pins")
    lock = {
        "contract_version": manifest["contract_version"], "wire_protocol": manifest["wire_protocol"]["current"],
        "status": status, "core_release": args.core_release if status == "released" else None,
        "core_commit" if status == "released" else "core_base_commit": commit,
        "bundle_sha256": bundle_hash, "minimum_server_version": "1.1.0",
        "maximum_tested_server_version": "1.1.0" if status == "released" else "1.1.0-dev",
        "files": {str(path.relative_to(sdk)): hashlib.sha256(data).hexdigest() for path, data in outputs.items()},
    }
    outputs[sdk / "contract.shared-native.lock.json"] = (json.dumps(lock, indent=2) + "\n").encode()
    for path, data in outputs.items():
        if args.check:
            if not path.is_file() or path.read_bytes() != data:
                raise SystemExit(f"Contract overlay drift: {path.relative_to(sdk)}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(f"{sdk.name}: {status} contract overlay {'verified' if args.check else 'updated'} ({bundle_hash})")


if __name__ == "__main__":
    main()
