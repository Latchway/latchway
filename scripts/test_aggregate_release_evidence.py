#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("aggregate-release-evidence.py")
SPEC = importlib.util.spec_from_file_location("aggregate_release_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


COMMIT = "1" * 40
DIGEST = "sha256:" + "2" * 64
BUNDLE = "3" * 64


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class AggregateReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs: dict[str, Path] = {}
        repositories = [
            {"id": name, "commit": str(index + 4) * 40, "intended_tag": "v1.0.0", "version": "1.0.0"}
            for index, name in enumerate(("core", "javascript", "ios", "android", "react_native"))
        ]
        repositories[0]["commit"] = COMMIT
        for domain in MODULE.PROMOTION_DOMAINS:
            directory = self.root / domain
            artifact = directory / "artifacts" / domain.replace("_", "-") / "result.json"
            artifact.parent.mkdir(parents=True)
            payload = json.dumps({"domain": domain}, sort_keys=True).encode()
            artifact.write_bytes(payload)
            document = {
                "schema_version": 1,
                "kind": "latchway_cross_repository_external_evidence",
                "domain": domain,
                "status": "passed",
                "started_at": "2026-08-29T00:00:00Z",
                "finished_at": "2026-08-29T00:01:00Z",
                "core_commit": COMMIT,
                "core_release": "v1.0.0",
                "contract_version": "0.5.1",
                "bundle_sha256": BUNDLE,
                "oci_image_digest": DIGEST,
                "repositories": repositories,
                "claims": {"verified": True},
                "artifacts": [{
                    "path": artifact.relative_to(directory).as_posix(),
                    "sha256": sha256(payload),
                }],
            }
            (directory / f"{domain}.json").write_text(json.dumps(document), encoding="utf-8")
            (directory / f"{domain}.attestation.sigstore.json").write_text("{}", encoding="utf-8")
            self.inputs[domain] = directory

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_promotion_union_is_collision_free_and_complete(self) -> None:
        output = self.root / "output"
        result = MODULE.aggregate(
            scope="promotion", candidate_commit=COMMIT, inputs=self.inputs, output=output,
        )
        self.assertEqual(result["domains"], list(MODULE.PROMOTION_DOMAINS))
        for domain in MODULE.PROMOTION_DOMAINS:
            self.assertTrue((output / f"{domain}.json").is_file())
            self.assertTrue((output / f"{domain}.attestation.sigstore.json").is_file())
        self.assertTrue((output / "aggregate-manifest.json").is_file())

    def test_rejects_missing_domain_tamper_identity_and_symlink(self) -> None:
        cases = []
        missing = dict(self.inputs)
        missing.pop("supply_chain")
        cases.append(("missing", missing, "aggregate_domain_set_invalid"))

        tampered = dict(self.inputs)
        artifact = tampered["live_provider"] / "artifacts/live-provider/result.json"
        artifact.write_text("tampered", encoding="utf-8")
        cases.append(("tamper", tampered, "domain_artifact_hash_mismatch"))
        with self.assertRaisesRegex(MODULE.AggregateError, cases[0][2]):
            MODULE.aggregate(scope="promotion", candidate_commit=COMMIT, inputs=cases[0][1], output=self.root / "missing")
        with self.assertRaisesRegex(MODULE.AggregateError, cases[1][2]):
            MODULE.aggregate(scope="promotion", candidate_commit=COMMIT, inputs=cases[1][1], output=self.root / "tamper")

        self.setUp_clean_live_provider()
        document_path = self.inputs["cloud_deployments"] / "cloud_deployments.json"
        document = json.loads(document_path.read_text())
        document["core_commit"] = "9" * 40
        document_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.AggregateError, "domain_document_identity_mismatch"):
            MODULE.aggregate(scope="promotion", candidate_commit=COMMIT, inputs=self.inputs, output=self.root / "identity")

    def setUp_clean_live_provider(self) -> None:
        directory = self.inputs["live_provider"]
        artifact = directory / "artifacts/live-provider/result.json"
        payload = json.dumps({"domain": "live_provider"}, sort_keys=True).encode()
        artifact.write_bytes(payload)

    def test_rejects_tree_symlink_and_existing_output(self) -> None:
        target = self.root / "outside"
        target.write_text("outside", encoding="utf-8")
        link = self.inputs["supply_chain"] / "leak"
        link.symlink_to(target)
        with self.assertRaisesRegex(MODULE.AggregateError, "domain_tree_invalid"):
            MODULE.aggregate(scope="promotion", candidate_commit=COMMIT, inputs=self.inputs, output=self.root / "symlink")
        link.unlink()
        output = self.root / "existing"
        output.mkdir()
        with self.assertRaisesRegex(MODULE.AggregateError, "aggregate_output_invalid"):
            MODULE.aggregate(scope="promotion", candidate_commit=COMMIT, inputs=self.inputs, output=output)

    def test_release_requires_publication_domains(self) -> None:
        with self.assertRaisesRegex(MODULE.AggregateError, "aggregate_domain_set_invalid"):
            MODULE.aggregate(scope="release", candidate_commit=COMMIT, inputs=self.inputs, output=self.root / "release")


if __name__ == "__main__":
    unittest.main()
