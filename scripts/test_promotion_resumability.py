#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/promote-release.yml"


class PromotionResumabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise AssertionError("promotion workflow must be a mapping")
        self.job = value["jobs"]["promote"]
        self.steps = self.job["steps"]
        self.names = [item.get("name", "") for item in self.steps]
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_existing_exact_tag_is_verified_and_creation_is_conditional(self) -> None:
        state = self.names.index("Verify any existing core release tag")
        image = self.names.index("Promote only the verified index digest to stable OCI tags")
        create = self.names.index("Create the evidence-gated annotated core tag")
        final_tag = self.names.index("Re-fetch and verify the immutable annotated core tag")
        release = self.names.index("Publish the immutable release record")
        self.assertLess(state, image)
        self.assertLess(image, create)
        self.assertLess(create, final_tag)
        self.assertLess(final_tag, release)
        self.assertLess(create, release)
        create_step = self.steps[create]
        self.assertEqual(create_step.get("if"), "steps.release-state.outputs.tag_exists != 'true'")
        state_script = self.steps[state]["run"]
        for value in (
            '.object.type == "commit"',
            '.object.sha == $commit',
            '.message == $message',
            'grep --fixed-strings --quiet "HTTP 404"',
            'echo "tag_exists=true"',
            'echo "tag_exists=false"',
        ):
            self.assertIn(value, state_script)
        self.assertNotIn("refusing to replace existing core tag", self.text)
        final_script = self.steps[final_tag]["run"]
        for value in ('.object.type == "tag"', '.object.type == "commit"', '.object.sha == $commit', '.message == $message'):
            self.assertIn(value, final_script)

    def test_stable_oci_coordinates_are_verify_or_create(self) -> None:
        script = self.steps[
            self.names.index("Promote only the verified index digest to stable OCI tags")
        ]["run"]
        self.assertIn("docker buildx imagetools inspect --raw", script)
        self.assertIn('test "$actual" = "$INDEX_DIGEST"', script)
        self.assertIn("inspect_status=$?", script)
        self.assertIn("manifest unknown|name unknown|not found", script)
        self.assertIn("docker buildx imagetools create", script)
        self.assertLess(script.index("imagetools inspect --raw"), script.index("imagetools create"))

    def test_release_is_reconciled_without_overwriting_assets(self) -> None:
        script = self.steps[self.names.index("Publish the immutable release record")]["run"]
        for value in (
            'gh api "repos/$GITHUB_REPOSITORY/releases/tags/$INTENDED_TAG"',
            'grep --fixed-strings --quiet "HTTP 404"',
            '.tag_name == $tag',
            '.draft == false',
            '.prerelease == $prerelease',
            'existing=$(jq --raw-output',
            'test "$existing" = "$expected"',
            'gh release upload "$INTENDED_TAG" "$asset"',
            "latchway-candidate.attestation.sigstore.json",
            "latchway-cross-repository-promotion.attestation.sigstore.json",
        ):
            self.assertIn(value, script)
        self.assertNotIn("--clobber", script)
        self.assertNotIn("gh release delete", script)
        self.assertNotIn("git push --force", self.text)


if __name__ == "__main__":
    unittest.main()
