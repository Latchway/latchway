#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("verify-github-release-attestation.py")
SPEC = importlib.util.spec_from_file_location("verify_github_release_attestation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GitHubReleaseAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = "Latchway/latchway"
        self.tag = "v1.0.0"
        self.ref_sha = "a" * 40
        self.release = {
            "id": 42,
            "tag_name": self.tag,
            "draft": False,
            "immutable": True,
            "assets": [
                {"name": "first.tgz", "digest": "sha256:" + "b" * 64},
                {"name": "SHA256SUMS", "digest": "sha256:" + "c" * 64},
            ],
        }
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "uri": f"pkg:github/{self.repository}@{self.tag}",
                    "digest": {"sha1": self.ref_sha},
                },
                {"name": "first.tgz", "digest": {"sha256": "b" * 64}},
                {"name": "SHA256SUMS", "digest": {"sha256": "c" * 64}},
            ],
            "predicateType": "https://in-toto.io/attestation/release/v0.2",
            "predicate": {
                "databaseId": "42",
                "packageId": "99",
                "purl": f"pkg:github/{self.repository}@{self.tag}",
                "repository": self.repository,
                "tag": self.tag,
            },
        }

    def payload(self, statement: dict | None = None) -> bytes:
        encoded = base64.b64encode(json.dumps(statement or self.statement).encode()).decode()
        return (json.dumps({
            "attestation": {
                "initiator": "github",
                "bundle_url": "https://example.invalid/bundle",
                "bundle": {
                    "dsseEnvelope": {
                        "payload": encoded,
                        "payloadType": "application/vnd.in-toto+json",
                        "signatures": [{"sig": "signed"}],
                    }
                },
            },
            "verificationResult": {"signature": {"verified": True}},
        }) + "\n").encode()

    def validate(self, payload: bytes | None = None) -> dict:
        return MODULE.validate_bytes(
            payload or self.payload(), repository=self.repository, tag=self.tag,
            ref_sha=self.ref_sha, release=self.release,
        )

    def test_exact_release_attestation_passes(self) -> None:
        result = self.validate()
        self.assertEqual(result["release_id"], 42)
        self.assertEqual([item["name"] for item in result["assets"]], ["SHA256SUMS", "first.tgz"])
        self.assertIn("dsseEnvelope", result["attestation_bundle"])

    def test_nondeterministic_cli_wrapper_normalizes_to_same_projection(self) -> None:
        first = self.validate()
        value = json.loads(self.payload())
        value["attestation"]["bundle_url"] = "https://example.invalid/a-different-fetch"
        value["verificationResult"] = {
            "verifiedAt": "2099-01-01T00:00:00Z",
            "signature": {"verified": True, "diagnostic": "different"},
        }
        second = self.validate((json.dumps(value, sort_keys=True) + "\n").encode())
        self.assertEqual(first, second)

    def test_ref_release_and_repository_substitution_fail(self) -> None:
        for field, value in (("databaseId", "43"), ("repository", "attacker/repo"), ("tag", "v9.9.9")):
            statement = copy.deepcopy(self.statement)
            statement["predicate"][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.AttestationError):
                self.validate(self.payload(statement))
        statement = copy.deepcopy(self.statement)
        statement["subject"][0]["digest"]["sha1"] = "f" * 40
        with self.assertRaisesRegex(MODULE.AttestationError, "ref_binding"):
            self.validate(self.payload(statement))

    def test_missing_extra_or_changed_asset_fails_closed(self) -> None:
        cases = []
        missing = copy.deepcopy(self.statement)
        missing["subject"].pop()
        cases.append(missing)
        extra = copy.deepcopy(self.statement)
        extra["subject"].append({"name": "evil", "digest": {"sha256": "d" * 64}})
        cases.append(extra)
        changed = copy.deepcopy(self.statement)
        changed["subject"][1]["digest"]["sha256"] = "d" * 64
        cases.append(changed)
        for statement in cases:
            with self.assertRaises(MODULE.AttestationError):
                self.validate(self.payload(statement))

    def test_old_predicate_and_non_github_initiator_fail(self) -> None:
        statement = copy.deepcopy(self.statement)
        statement["predicateType"] = "https://in-toto.io/attestation/release/v0.1"
        with self.assertRaises(MODULE.AttestationError):
            self.validate(self.payload(statement))
        value = json.loads(self.payload())
        value["attestation"]["initiator"] = "user"
        with self.assertRaises(MODULE.AttestationError):
            self.validate((json.dumps(value) + "\n").encode())


if __name__ == "__main__":
    unittest.main()
