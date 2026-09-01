from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("mintlify-production-proof.py")
SPEC = importlib.util.spec_from_file_location("mintlify_production_proof", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MintlifyProductionProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
        self.documentation = {
            "repository": MODULE.DOCUMENTATION_REPOSITORY_URL,
            "commit": "8" * 40,
            "canonical_core_commit": "a" * 40,
            "source_commit": "7" * 40,
            "source_manifest_sha256": "9" * 64,
            "source_tree_sha256": "b" * 64,
            "owned_file_count": 308,
        }
        self.run_id = 123456789
        self.run_attempt = 2
        self.deployment_id = 6163376314
        self.evidence = self.evidence_fixture()

    @staticmethod
    def encoded(value: object) -> bytes:
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

    @staticmethod
    def http(path: str, content_type: str = "text/html") -> dict:
        url = MODULE.live_url(path)
        return {
            "body_sha256": hashlib.sha256(path.encode()).hexdigest(),
            "bytes": 100,
            "content_type": content_type,
            "final_url": url,
            "path": path,
            "status": 200,
            "url": url,
        }

    def evidence_fixture(self) -> dict:
        pages = []
        for index in range(100):
            path = f"/p{index:03d}"
            pages.append(
                {
                    **self.http(path),
                    "description": f"Description {index}",
                    "h1_count": 1,
                    "image_count": 0,
                    "internal_link_count": 1 if index == 0 else 0,
                    "lang": "en",
                    "main_count": 1,
                    "missing_alt_count": 0,
                    "source_path": f"p{index:03d}.mdx",
                    "source_sha256": hashlib.sha256(
                        f"source-{index}".encode()
                    ).hexdigest(),
                    "title": f"Page {index}",
                }
            )
        relationships = [{"source": "/p000", "target": "/p001"}]
        links = [self.http("/p001")]
        redirects = [
            {
                "source": "/legacy",
                "destination": "/p000",
                "url": MODULE.live_url("/legacy"),
                "status": 308,
                "location": "/p000",
            }
        ]
        ai = []
        for kind, path, content_type, title in (
            ("llms_full_txt", "/llms-full.txt", "text/plain", None),
            ("llms_txt", "/llms.txt", "text/plain", None),
            *(
                (
                    "markdown_page",
                    f"/p{index:03d}.md",
                    "text/markdown",
                    f"Page {index}",
                )
                for index in range(20)
            ),
        ):
            observation = {
                **self.http(path, content_type),
                "kind": kind,
                "title": title,
            }
            if kind == "llms_full_txt":
                observation["bytes"] = 1024
            ai.append(observation)
        pairs = [(item["source"], item["target"]) for item in relationships]
        page_hash = MODULE.result_digest(pages)
        return {
            "schema_version": 1,
            "kind": MODULE.EVIDENCE_KIND,
            "status": "passed",
            "repository": MODULE.DOCUMENTATION_REPOSITORY_URL,
            "source_checkpoint": {
                "documentation_commit": self.documentation["commit"],
                "canonical_core_commit": self.documentation["source_commit"],
                "source_manifest_sha256": self.documentation[
                    "source_manifest_sha256"
                ],
                "source_tree_sha256": self.documentation["source_tree_sha256"],
                "owned_file_count": self.documentation["owned_file_count"],
            },
            "deployment": {
                "id": self.deployment_id,
                "status_id": 17519253886,
                "state": "success",
                "environment": "production",
                "production_environment": True,
                "transient_environment": False,
                "environment_url": "https://latchway.mintlify.app",
                "production_url": MODULE.PRODUCTION_ORIGIN,
                "actor": dict(MODULE.MINTLIFY_ACTOR),
                "created_at": "2026-09-01T00:00:00Z",
                "updated_at": "2026-09-01T00:05:00Z",
            },
            "workflow": {
                "repository": MODULE.DOCUMENTATION_REPOSITORY,
                "path": MODULE.WORKFLOW_PATH,
                "ref": MODULE.WORKFLOW_REF,
                "event": "workflow_dispatch",
                "expected_conclusion": "success",
                "head_sha": self.documentation["commit"],
                "run_id": self.run_id,
                "run_attempt": self.run_attempt,
                "run_url": (
                    "https://github.com/Latchway/latchway-docs/actions/runs/"
                    f"{self.run_id}"
                ),
            },
            "claims": {name: True for name in MODULE.CLAIMS},
            "postdeploy": {
                "pages": {"checked": len(pages), "results_sha256": page_hash},
                "accessibility": {
                    "pages_checked": len(pages),
                    "results_sha256": page_hash,
                    "rules": MODULE.ACCESSIBILITY_RULES,
                },
                "links": {
                    "relationships_checked": len(relationships),
                    "relationships_sha256": MODULE.result_digest(pairs),
                    "targets_checked": len(links),
                    "results_sha256": MODULE.result_digest(links),
                },
                "redirects": {
                    "checked": len(redirects),
                    "results_sha256": MODULE.result_digest(redirects),
                },
                "ai_outputs": {
                    "index_entries_checked": 20,
                    "outputs_checked": len(ai),
                    "results_sha256": MODULE.result_digest(ai),
                    "source_llms_txt_sha256": "c" * 64,
                },
            },
            "observations": {
                "pages": pages,
                "link_relationships": relationships,
                "link_targets": links,
                "redirects": redirects,
                "ai_outputs": ai,
            },
            "started_at": "2026-09-01T00:10:00Z",
            "finished_at": "2026-09-01T00:20:00Z",
            "maximum_age_seconds": 86400,
        }

    def inputs(self, evidence: dict | None = None) -> dict:
        evidence = evidence or self.evidence
        evidence_payload = self.encoded(evidence)
        evidence_sha = hashlib.sha256(evidence_payload).hexdigest()
        artifact_name = (
            f"latchway-mintlify-production-{self.documentation['commit']}-"
            f"{self.deployment_id}-{self.run_id}-{self.run_attempt}"
        )
        artifact_id = 777
        return {
            "documentation": self.documentation,
            "evidence_payload": evidence_payload,
            "checksum_payload": (
                f"{evidence_sha}  {MODULE.EVIDENCE_FILE}\n".encode()
            ),
            "attestation_bundle_payload": self.encoded(
                {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"}
            ),
            "run_payload": self.encoded(
                {
                    "id": self.run_id,
                    "run_attempt": self.run_attempt,
                    "event": evidence["workflow"]["event"],
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": self.documentation["commit"],
                    "head_branch": "main",
                    "path": MODULE.WORKFLOW_PATH,
                    "html_url": evidence["workflow"]["run_url"],
                    "workflow_id": 42,
                    "repository": {"full_name": MODULE.DOCUMENTATION_REPOSITORY},
                    "head_repository": {"full_name": MODULE.DOCUMENTATION_REPOSITORY},
                }
            ),
            "workflow_payload": self.encoded(
                {"id": 42, "path": MODULE.WORKFLOW_PATH, "state": "active"}
            ),
            "artifact_payload": self.encoded(
                {
                    "total_count": 1,
                    "artifacts": [
                        {
                            "id": artifact_id,
                            "name": artifact_name,
                            "size_in_bytes": 1000,
                            "expired": False,
                            "archive_download_url": (
                                "https://api.github.com/repos/Latchway/latchway-docs/"
                                f"actions/artifacts/{artifact_id}/zip"
                            ),
                            "workflow_run": {
                                "id": self.run_id,
                                "head_sha": self.documentation["commit"],
                            },
                        }
                    ],
                }
            ),
            "attestation_verification_payload": self.encoded(
                [{"verificationResult": {"signature": {"verified": True}}}]
            ),
            "expected_run_id": self.run_id,
            "expected_run_attempt": self.run_attempt,
            "now": self.now,
        }

    def test_builds_and_revalidates_exact_proof(self) -> None:
        proof = MODULE.build_proof(**self.inputs())
        self.assertEqual(proof["status"], "passed")
        self.assertEqual(
            set(proof["retained_files"]), MODULE.RETAINED_FILES
        )
        MODULE.validate_retained_proof(
            proof, self.documentation["canonical_core_commit"], now=self.now
        )

    def test_rejects_source_claim_hash_freshness_and_authority_mutations(self) -> None:
        mutations = []
        wrong_source = copy.deepcopy(self.evidence)
        wrong_source["source_checkpoint"]["source_tree_sha256"] = "0" * 64
        mutations.append(self.inputs(wrong_source))
        false_claim = copy.deepcopy(self.evidence)
        false_claim["claims"]["live_redirects_verified"] = False
        mutations.append(self.inputs(false_claim))
        wrong_hash = copy.deepcopy(self.evidence)
        wrong_hash["observations"]["pages"][0]["title"] = "Changed"
        mutations.append(self.inputs(wrong_hash))
        hash_rebound_orphan = copy.deepcopy(self.evidence)
        hash_rebound_orphan["observations"]["link_relationships"][0][
            "source"
        ] = "/p002"
        pairs = [
            (item["source"], item["target"])
            for item in hash_rebound_orphan["observations"][
                "link_relationships"
            ]
        ]
        hash_rebound_orphan["postdeploy"]["links"][
            "relationships_sha256"
        ] = MODULE.result_digest(pairs)
        mutations.append(self.inputs(hash_rebound_orphan))
        stale = self.inputs()
        stale["now"] = self.now + timedelta(days=2)
        mutations.append(stale)
        wrong_run = self.inputs()
        run = json.loads(wrong_run["run_payload"])
        run["head_sha"] = "0" * 40
        wrong_run["run_payload"] = self.encoded(run)
        mutations.append(wrong_run)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ProofError):
                MODULE.build_proof(**mutation)

    def test_retained_proof_rejects_removed_file_and_attestation_drift(self) -> None:
        proof = MODULE.build_proof(**self.inputs())
        for mutation in ("missing", "bundle"):
            changed = copy.deepcopy(proof)
            if mutation == "missing":
                changed["retained_files"].pop("artifact.json")
            else:
                changed["authority"]["subject_attestation"]["bundle_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ProofError):
                MODULE.validate_retained_proof(
                    changed,
                    self.documentation["canonical_core_commit"],
                    now=self.now,
                )


if __name__ == "__main__":
    unittest.main()
