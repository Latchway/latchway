#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def load_workflow(name: str) -> dict:
    value = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{name} is not an object")
    # YAML 1.1 parses the key `on` as boolean true. Normalize only that key so
    # these tests work with the same PyYAML dependency as contract validation.
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


def all_steps(workflow: dict) -> list[dict]:
    return [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict)
    ]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_candidate_workflow_cannot_publish_stable_coordinates(self) -> None:
        workflow = load_workflow("release.yml")
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        serialized = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertNotIn("gh release create", serialized)
        self.assertNotIn("refs/tags/", serialized)
        self.assertNotIn("type=semver", serialized)
        self.assertNotIn("value=latest", serialized)
        self.assertIn(":candidate-${{ inputs.candidate_commit }}", serialized)
        self.assertIn("scripts/release-preflight.py", serialized)
        self.assertIn("--candidate", serialized)
        self.assertIn("scripts/run-local-load-gates.sh", serialized)
        self.assertIn("-scope automated", serialized)
        self.assertIn("subject-path: latchway-candidate.json", serialized)
        for job in workflow["jobs"].values():
            self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")

    def test_promotion_verification_precedes_every_public_mutation(self) -> None:
        workflow = load_workflow("promote-release.yml")
        job = workflow["jobs"]["promote"]
        self.assertEqual(job["environment"], "release")
        self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")
        steps = job["steps"]
        names = [step.get("name", "") for step in steps]

        candidate_attestation = names.index("Verify candidate and promotion attestations")
        bindings = names.index("Verify the candidate artifact and exact aggregate bindings")
        image_provenance = names.index("Verify the exact candidate image signature and provenance")
        existing_tag = names.index("Refuse an existing core release tag")
        oci_promotion = names.index("Promote only the verified index digest to stable OCI tags")
        tag_creation = names.index("Create the evidence-gated annotated core tag")
        release_creation = names.index("Publish the immutable release record")
        sdk_dispatch = names.index("Dispatch exact evidence-bound SDK publications")
        self.assertLess(candidate_attestation, bindings)
        self.assertLess(bindings, image_provenance)
        self.assertLess(image_provenance, existing_tag)
        self.assertLess(existing_tag, oci_promotion)
        self.assertLess(oci_promotion, tag_creation)
        self.assertLess(tag_creation, release_creation)
        self.assertLess(release_creation, sdk_dispatch)

        serialized = (WORKFLOWS / "promote-release.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/release-candidate.py", serialized)
        self.assertIn("scripts/verify-promotion.py", serialized)
        self.assertIn("--signer-workflow", serialized)
        self.assertIn("--source-ref refs/heads/main", serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertIn("LATCHWAY_RELEASE_DISPATCH_TOKEN", serialized)
        self.assertNotIn("continue-on-error", serialized)

    def test_cross_repository_promotion_is_mandatory_and_attested(self) -> None:
        workflow = load_workflow("cross-repository-conformance.yml")
        choices = workflow["on"]["workflow_dispatch"]["inputs"]["scope"]["options"]
        self.assertEqual(choices, ["source", "promotion", "release"])
        serialized = (WORKFLOWS / "cross-repository-conformance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("--oci-image-digest", serialized)
        self.assertIn("--external-evidence-dir", serialized)
        self.assertIn("subject-path:", serialized)
        self.assertNotIn("continue-on-error", serialized)
        download = next(
            step
            for step in all_steps(workflow)
            if step.get("name") == "Download independently produced external evidence"
        )
        self.assertEqual(download.get("if"), "inputs.scope != 'source'")

    def test_every_third_party_action_is_commit_pinned(self) -> None:
        for name in (
            "release.yml",
            "promote-release.yml",
            "cross-repository-conformance.yml",
        ):
            for step in all_steps(load_workflow(name)):
                action = step.get("uses")
                if action is not None:
                    self.assertRegex(action, PINNED_ACTION, f"{name}: {action}")


if __name__ == "__main__":
    unittest.main()
