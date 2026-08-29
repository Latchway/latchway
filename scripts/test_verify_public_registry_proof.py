from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("verify-public-registry-proof.py")
SPEC = importlib.util.spec_from_file_location("verify_public_registry_proof", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicRegistryProofTests(unittest.TestCase):
    def npm_proof(self) -> dict:
        sha = "a" * 64
        integrity = "sha512-" + "A" * 86 + "=="
        return {
            "schema_version": 1,
            "registry": "npm",
            "package": "@latchway/client",
            "version": "1.0.0",
            "source_commit": "b" * 40,
            "registry_integrity": integrity,
            "tarball": "latchway-client-1.0.0.tgz",
            "sha256": sha,
            "integrity": integrity,
            "registry_tarball_byte_identical": True,
            "registry_signatures_verified": True,
            "provenance": {
                "attestations_sha256": hashlib.sha256(
                    (json.dumps({"attestations": []}, indent=2, sort_keys=True) + "\n").encode()
                ).hexdigest(),
                "attestations": {"attestations": []},
                "source_commit": "b" * 40,
                "workflow": ".github/workflows/release.yml",
                "workflow_ref": "refs/heads/main",
                "run_id": 123,
                "run_attempt": 2,
                "npm_signature_audit": "passed",
            },
            "reviewed_package_evidence": {
                "schema_version": 1,
                "package": "@latchway/client",
                "version": "1.0.0",
                "tarball": "latchway-client-1.0.0.tgz",
                "sha256": sha,
                "integrity": integrity,
                "double_pack_byte_identical": True,
            },
            "reviewed_build_reproducibility": {
                "schema_version": 1,
                "identical": True,
                "sha256": "c" * 64,
            },
            "release_asset_digests": {
                "latchway-client-1.0.0.tgz": "sha256:" + sha,
                "package-evidence.json": "sha256:" + "d" * 64,
                "build-reproducibility.json": "sha256:" + "e" * 64,
            },
            "release_asset_attestation_verifications": {
                "latchway-client-1.0.0.tgz": [{"verified": True}],
                "package-evidence.json": [{"verified": True}],
                "build-reproducibility.json": [{"verified": True}],
            },
        }

    def maven_proof(self) -> dict:
        signature = "-----BEGIN PGP SIGNATURE-----\ntest\n"
        return {
            "schema_version": 1,
            "registry": "maven_central",
            "version": "1.0.0",
            "reviewed_repository": True,
            "primary_artifacts_byte_identical": True,
            "checksum_files_byte_identical": True,
            "signature_files_present": True,
            "signatures_cryptographically_verified": True,
            "signing_fingerprint": "A" * 40,
            "reviewed_public_key_sha256": "c" * 64,
            "release_asset_attestation_verification": [{"verificationResult": "verified"}],
            "files": [
                {
                    "path": path,
                    "sha256": "a" * 64,
                    "bytes": 1,
                    "signature_sha256": hashlib.sha256(signature.encode()).hexdigest(),
                    "signature_armored": signature,
                    "checksums_byte_identical": True,
                }
                for path in sorted(MODULE.expected_maven_paths("1.0.0"))
            ],
        }

    def test_npm_requires_exact_release_asset_names_and_tarball_digest(self) -> None:
        proof = self.npm_proof()
        MODULE.validate_npm(proof, "@latchway/client", {"version": "1.0.0", "commit": "b" * 40})
        for mutation in ("extra", "wrong-tarball-digest", "missing-provenance", "wrong-provenance-source"):
            tampered = copy.deepcopy(proof)
            if mutation == "extra":
                tampered["release_asset_digests"]["unreviewed.json"] = "sha256:" + "f" * 64
            else:
                if mutation == "wrong-tarball-digest":
                    tampered["release_asset_digests"]["latchway-client-1.0.0.tgz"] = "sha256:" + "f" * 64
                elif mutation == "missing-provenance":
                    tampered.pop("provenance")
                else:
                    tampered["provenance"]["source_commit"] = "0" * 40
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ProofError):
                MODULE.validate_npm(tampered, "@latchway/client", {"version": "1.0.0", "commit": "b" * 40})

    def test_maven_requires_exact_unique_coordinates_and_pinned_signature(self) -> None:
        proof = self.maven_proof()
        MODULE.validate_maven(proof, "1.0.0")
        mutations = []
        duplicate = copy.deepcopy(proof)
        duplicate["files"][-1]["path"] = duplicate["files"][0]["path"]
        mutations.append(duplicate)
        unrelated = copy.deepcopy(proof)
        unrelated["files"][-1]["path"] = "other/1.0.0/other-1.0.0.jar"
        mutations.append(unrelated)
        unsigned = copy.deepcopy(proof)
        unsigned["signatures_cryptographically_verified"] = False
        mutations.append(unsigned)
        wrong_key = copy.deepcopy(proof)
        wrong_key["signing_fingerprint"] = "not-a-fingerprint"
        mutations.append(wrong_key)
        for index, tampered in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.ProofError):
                MODULE.validate_maven(tampered, "1.0.0")


if __name__ == "__main__":
    unittest.main()
