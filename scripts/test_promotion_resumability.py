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
        self.workflow = value
        self.job = value["jobs"]["promote"]
        self.steps = self.job["steps"]
        self.names = [item.get("name", "") for item in self.steps]
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_existing_exact_tag_is_verified_and_creation_is_conditional(self) -> None:
        preflight = self.names.index(
            "Preflight immutable releases and every fixed core release asset"
        )
        state = self.names.index("Verify any existing core release tag")
        create = self.names.index("Create the evidence-gated annotated core tag")
        final_tag = self.names.index("Re-fetch and verify the immutable annotated core tag")
        prepare = self.names.index(
            "Prepare the recoverable product release draft and exact assets"
        )
        image = self.names.index("Promote only the verified index digest to stable OCI tags")
        release = self.names.index("Publish the immutable release record")
        self.assertLess(preflight, state)
        self.assertLess(state, create)
        self.assertLess(create, final_tag)
        self.assertLess(final_tag, prepare)
        self.assertLess(prepare, image)
        self.assertLess(image, release)
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

    def test_stable_oci_coordinates_are_immutable_or_monotonic(self) -> None:
        script = self.steps[
            self.names.index("Promote only the verified index digest to stable OCI tags")
        ]["run"]
        self.assertIn("docker buildx imagetools inspect --raw", script)
        self.assertIn('test "$(digest_of "$RUNNER_TEMP/oci-version-final.json")" = "$INDEX_DIGEST"', script)
        self.assertIn("local status=$?", script)
        self.assertIn("manifest unknown|name unknown|not found", script)
        self.assertIn("docker buildx imagetools create", script)
        self.assertIn("verify-oci-alias-transition.py", script)
        self.assertIn("docker pull --platform linux/amd64", script)
        self.assertIn(".immutable == true", script)
        self.assertIn("--certificate-github-workflow-sha \"$current_commit\"", script)
        self.assertIn("oci-alias-$alias-pre-update.json", script)
        self.assertIn('aliases=("$major.$minor" "$major" latest)', script)
        self.assertLess(script.index("imagetools inspect --raw"), script.index("imagetools create"))

    def test_overlapping_release_cannot_advance_unfinalized_aliases(self) -> None:
        finalizer = yaml.safe_load(
            (WORKFLOW.parent / "finalize-release-record.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.workflow["concurrency"]["group"],
            finalizer["concurrency"]["group"],
        )
        self.assertFalse(self.workflow["concurrency"]["cancel-in-progress"])
        self.assertFalse(finalizer["concurrency"]["cancel-in-progress"])
        script = self.steps[
            self.names.index("Promote only the verified index digest to stable OCI tags")
        ]["run"]
        for value in (
            "require_finalized_version()",
            'evidence_tag="evidence/v$prior_version"',
            '.immutable == true',
            'gh release verify "$evidence_tag"',
            "verify-github-release-attestation.py",
            'gh attestation verify "$prefix-assets/COMPLETION_REPORT.md"',
            '.github/workflows/finalize-release-record.yml',
            "verify-final-evidence-release.py",
            "git/matching-refs/tags/v",
            "stable_predecessors",
            'test "$candidate_tag_seen" = true',
            '--plan "$RUNNER_TEMP/oci-alias-transition-plan.json"',
            'for alias in "${aliases[@]}"',
            "OCI alias appeared after absent preflight",
        ):
            self.assertIn(value, script)
        self.assertEqual(script.count('for alias in "${aliases[@]}"'), 2)
        prior_evidence = script.index(
            'require_finalized_version "$current_version" "$current_commit"'
        )
        stable_tag_guard = script.index(
            'require_finalized_version "$prior_version" "$prior_commit"'
        )
        plan_authorization = script.index(
            '--plan "$RUNNER_TEMP/oci-alias-transition-plan.json"'
        )
        mutation_phase = script.index(
            '# Re-close each preflight state immediately before its controlled'
        )
        first_moving_mutation = script.index(
            'docker buildx imagetools create --tag "$target" "$IMAGE@$INDEX_DIGEST"',
            mutation_phase,
        )
        self.assertLess(prior_evidence, mutation_phase)
        self.assertLess(stable_tag_guard, mutation_phase)
        self.assertLess(plan_authorization, mutation_phase)
        self.assertLess(mutation_phase, first_moving_mutation)

    def test_release_is_reconciled_without_overwriting_assets(self) -> None:
        preflight = self.steps[
            self.names.index(
                "Preflight immutable releases and every fixed core release asset"
            )
        ]["run"]
        prepare = self.steps[
            self.names.index(
                "Prepare the recoverable product release draft and exact assets"
            )
        ]["run"]
        script = self.steps[self.names.index("Publish the immutable release record")]["run"]
        for value in (
            'gh release create "$INTENDED_TAG" --draft',
            'existing=$(jq --raw-output',
            'test "$existing" = "$expected"',
            'gh release upload "$INTENDED_TAG" "$asset"',
            "product-expected-assets.txt",
        ):
            self.assertIn(value, prepare)
        for value in (
            "'{draft: false}'",
            '.immutable == $immutable',
            'gh release verify "$INTENDED_TAG"',
            'gh release verify-asset "$INTENDED_TAG"',
            "pre-publish-product-tag-ref.json",
            "product-pre-publish-assets.txt",
            "verify-github-release-attestation.py",
        ):
            self.assertIn(value, script)
        for value in (
            "latchway-candidate.attestation.sigstore.json",
            "latchway-cross-repository-promotion.attestation.sigstore.json",
            'test "$(wc -l < "$RUNNER_TEMP/fixed-core-release-assets.txt" | tr -d \' \')" = 14',
            "oci-alias-promotion.json",
            "gh release download",
            "cmp --silent",
        ):
            self.assertIn(value, preflight)
        self.assertEqual(preflight.count("gh release upload"), 0)
        admin = self.steps[
            self.names.index(
                "Preflight protected immutable-release settings for every release repository"
            )
        ]["run"]
        for value in (
            '"repos/$repository/immutable-releases"',
            'X-GitHub-Api-Version: 2026-03-10',
            '(keys | sort) == ["enabled", "enforced_by_owner"]',
            '.enabled == true',
        ):
            self.assertIn(value, admin)
        self.assertNotIn("--clobber", prepare + script)
        self.assertNotIn("gh release delete", prepare + script)
        self.assertNotIn("git push --force", self.text)


if __name__ == "__main__":
    unittest.main()
