#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/finalize-release-record.yml"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


class FinalizeReleaseRecordWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        value = yaml.safe_load(self.text)
        if not isinstance(value, dict):
            raise AssertionError("finalizer workflow must be a mapping")
        if True in value and "on" not in value:
            value["on"] = value.pop(True)
        self.workflow = value
        self.job = value["jobs"]["finalize"]
        self.steps = self.job["steps"]
        self.names = [item.get("name", "") for item in self.steps]

    def test_is_protected_exact_candidate_postpublication_workflow(self) -> None:
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(self.job["environment"], "release")
        self.assertEqual(self.job["if"], "github.ref == 'refs/heads/main'")
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            set(inputs),
            {
                "candidate_commit",
                "release_tag",
                "candidate_run_id",
                "candidate_run_attempt",
                "security_run_id",
                "security_run_attempt",
                "release_conformance_run_id",
                "release_conformance_run_attempt",
            },
        )
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', self.text)
        self.assertIn('.run_attempt == $attempt', self.text)
        self.assertIn('/actions/runs/$run_id/attempts/$run_attempt', self.text)
        for workflow in (
            ".github/workflows/release.yml",
            ".github/workflows/security.yml",
            ".github/workflows/cross-repository-conformance.yml",
        ):
            self.assertIn(workflow, self.text)

    def test_attested_release_evidence_precedes_render_and_mutation(self) -> None:
        provenance = self.names.index("Authenticate every fixed evidence run and attempt")
        attestations = self.names.index(
            "Verify all evidence signer identities and immutable source bindings"
        )
        public = self.names.index("Verify exact public tag release OCI and npm state")
        render = self.names.index("Render the deterministic final completion report")
        reconcile = self.names.index("Reconcile any existing immutable final assets")
        attest = self.names.index("Attest the exact final completion report when absent")
        upload = self.names.index("Upload only missing exact final assets without clobbering")
        self.assertLess(provenance, attestations)
        self.assertLess(attestations, public)
        self.assertLess(public, render)
        self.assertLess(render, reconcile)
        self.assertLess(reconcile, attest)
        self.assertLess(attest, upload)
        self.assertEqual(self.text.count("--deny-self-hosted-runners"), 8)
        self.assertGreaterEqual(self.text.count('--source-ref refs/heads/main'), 6)
        self.assertGreaterEqual(self.text.count('--source-digest "$CANDIDATE_COMMIT"'), 6)
        self.assertGreaterEqual(self.text.count('--signer-digest "$CANDIDATE_COMMIT"'), 6)

    def test_public_coordinates_are_derived_and_independently_checked(self) -> None:
        for value in (
            'name: latchway-cross-repository-release',
            '.scope == "release"',
            '.release_ready == true',
            '.id == "public_tags" or .id == "public_registries"',
            'git/ref/tags/$RELEASE_TAG',
            '.object.type == "commit"',
            'releases/tags/$RELEASE_TAG',
            'docker buildx imagetools inspect --raw "$image"',
            'gh attestation verify "oci://$image"',
            'npm --userconfig=/dev/null view "@latchway/client@$javascript_version"',
            '.gitHead == $commit',
            '"dev.latchway:latchway-bom:" + $android',
            'scripts/render-completion-report.py',
            'scripts/verify-public-registry-proof.py',
            'latchway-public-registry-byte-proof.json',
            'latchway-release-evidence-v1.tar.gz',
        ):
            self.assertIn(value, self.text)
        self.assertNotIn("registry_coordinates", self.workflow["on"]["workflow_dispatch"]["inputs"])

    def test_rerun_verifies_existing_bytes_and_never_clobbers(self) -> None:
        reconcile = self.steps[
            self.names.index("Reconcile any existing immutable final assets")
        ]["run"]
        upload = self.steps[
            self.names.index("Upload only missing exact final assets without clobbering")
        ]["run"]
        for value in (
            'test "$existing" = "$expected"',
            "cmp --silent",
            "gh attestation verify",
            'echo "report_exists=true"',
            'echo "bundle_exists=true"',
            "attestation bundle exists without its report",
        ):
            self.assertIn(value, reconcile)
        self.assertIn('if [[ "$REPORT_EXISTS" != true ]]', upload)
        self.assertIn('if [[ "$BUNDLE_EXISTS" != true ]]', upload)
        self.assertIn("final release asset missing or duplicated", upload)
        for forbidden in ("--clobber", "gh release delete", "git push --force", "continue-on-error"):
            self.assertNotIn(forbidden, self.text)

    def test_all_third_party_actions_are_commit_pinned(self) -> None:
        actions = [item["uses"] for item in self.steps if "uses" in item]
        self.assertTrue(actions)
        self.assertTrue(all(PINNED_ACTION.fullmatch(item) for item in actions), actions)


if __name__ == "__main__":
    unittest.main()
