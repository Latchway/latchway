#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/single-maintainer-release.yml"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def load() -> dict:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


class SingleMaintainerReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load()
        self.jobs = self.workflow["jobs"]
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_inputs_are_exact_candidate_compose_and_cloud_run_only(self) -> None:
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            set(inputs),
            {
                "candidate_commit",
                "candidate_run_id",
                "candidate_run_attempt",
                "compose_run_id",
                "compose_run_attempt",
                "cloud_run_run_id",
                "cloud_run_run_attempt",
            },
        )
        self.assertTrue(all(item["required"] for item in inputs.values()))
        for deferred in ("aws", "fly", "cloudflare", "device", "provider", "review"):
            self.assertNotIn(f"{deferred}_run_id", inputs)
        self.assertIn('tag=v1.0.0', self.text)
        self.assertNotIn("inputs.intended_tag", self.text)

    def test_strict_workflow_is_not_called_or_weakened(self) -> None:
        self.assertNotIn("promote-release.yml", self.text)
        self.assertEqual(
            self.workflow["concurrency"],
            {"group": "promote-stable-oci-aliases", "cancel-in-progress": False},
        )
        self.assertEqual(
            set(self.jobs),
            {
                "source-gate",
                "plan",
                "semantic-handoff",
                "supply-chain",
                "attest-handoff",
                "stage-release",
                "promote-oci",
                "publish-release",
            },
        )

    def test_every_external_action_is_commit_pinned(self) -> None:
        actions = [
            step["uses"]
            for job in self.jobs.values()
            for step in job.get("steps", [])
            if "uses" in step
        ]
        self.assertTrue(actions)
        self.assertTrue(all(PINNED_ACTION.fullmatch(item) for item in actions), actions)

    def test_dispatch_inputs_are_never_interpolated_inside_shell(self) -> None:
        for job_name, job in self.jobs.items():
            for step in job.get("steps", []):
                with self.subTest(job=job_name, step=step.get("name", step.get("uses"))):
                    self.assertNotIn("${{ inputs.", step.get("run", ""))

    def test_mutation_jobs_use_distinct_profile_sentinels_and_least_privilege(self) -> None:
        expected = {
            "attest-handoff": ("release-evidence-signing", "attestations"),
            "stage-release": ("release-evidence-signing", "contents"),
            "promote-oci": ("release-image-publishing", "packages"),
            "publish-release": ("release-evidence-signing", "contents"),
        }
        for name, (environment, permission) in expected.items():
            job = self.jobs[name]
            self.assertEqual(job["environment"], environment)
            self.assertEqual(job["permissions"][permission], "write")
            first = job["steps"][0]
            self.assertEqual(
                first["name"],
                f"Verify the exact single-maintainer {environment} policy",
            )
            self.assertEqual(
                first["env"]["OBSERVED_POLICY_ID"],
                "${{ vars.LATCHWAY_RELEASE_PROFILE_POLICY_ID }}",
            )
            self.assertIn(
                f'latchway-release-profile-v1:latchway:single_maintainer_v1:{environment}',
                first["run"],
            )
        for name in ("source-gate", "plan", "semantic-handoff", "supply-chain"):
            self.assertNotIn("write", self.jobs[name]["permissions"].values())

    def test_source_free_handoff_is_stable_attested_and_reverified(self) -> None:
        artifact_name = "latchway-single-maintainer-v1-handoff-${{ github.run_id }}"
        self.assertGreaterEqual(self.text.count(artifact_name), 5)
        self.assertNotIn(
            "latchway-single-maintainer-v1-handoff-${{ github.run_id }}-${{ github.run_attempt }}",
            self.text,
        )
        attestor = self.jobs["attest-handoff"]
        self.assertEqual(
            set(attestor["needs"]), {"plan", "semantic-handoff", "supply-chain"}
        )
        action = next(
            step
            for step in attestor["steps"]
            if step.get("uses", "").startswith("actions/attest-build-provenance@")
        )
        self.assertEqual(
            action["with"]["subject-path"], "${{ runner.temp }}/handoff/*"
        )
        self.assertEqual(
            set(self.jobs["stage-release"]["needs"]), {"plan", "attest-handoff"}
        )
        for name in ("stage-release", "promote-oci", "publish-release"):
            script = "\n".join(
                step.get("run", "") for step in self.jobs[name].get("steps", [])
            )
            self.assertIn(
                "for subject in SHA256SUMS latchway-single-maintainer-v1.json",
                script,
            )
            self.assertIn(
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/single-maintainer-release.yml"',
                script,
            )
            self.assertIn('--source-digest "$CANDIDATE_COMMIT"', script)
            self.assertIn("--deny-self-hosted-runners", script)

    def test_candidate_execution_is_isolated_from_registry_and_attestation_authority(
        self,
    ) -> None:
        source = self.jobs["source-gate"]
        source_text = "\n".join(
            step.get("run", "") for step in source.get("steps", [])
        )
        self.assertIn("go test -count=1 ./...", source_text)
        self.assertNotIn("docker/login-action", str(source))
        self.assertNotIn("id-token", source["permissions"])

        plan = self.jobs["plan"]
        plan_text = "\n".join(step.get("run", "") for step in plan.get("steps", []))
        self.assertIn("scripts/single-maintainer-release.py prepare", plan_text)
        self.assertNotIn("docker/login-action", str(plan))
        self.assertNotIn("cosign", str(plan))
        self.assertNotIn("packages", plan["permissions"])

        semantic = self.jobs["semantic-handoff"]
        semantic_text = "\n".join(
            step.get("run", "") for step in semantic.get("steps", [])
        )
        self.assertIn("scripts/single-maintainer-release.py verify-handoff", semantic_text)
        self.assertNotIn("docker/login-action", str(semantic))
        self.assertNotIn("id-token", semantic["permissions"])

        supply = self.jobs["supply-chain"]
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in supply["steps"]
            )
        )
        self.assertTrue(
            any(
                step.get("uses", "").startswith("docker/login-action@")
                for step in supply["steps"]
            )
        )
        self.assertNotIn("id-token", supply["permissions"])

        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in self.jobs["attest-handoff"]["steps"]
            )
        )
        attestor_text = "\n".join(
            step.get("run", "")
            for step in self.jobs["attest-handoff"].get("steps", [])
        )
        self.assertIn('([.artifacts[].path] | sort)', attestor_text)
        self.assertIn('.deferred_evidence == [', attestor_text)
        self.assertIn('.release_policy == {', attestor_text)
        self.assertIn('jq --exit-status --raw-output ".assets[]', attestor_text.replace("'", '"'))

    def test_all_gates_precede_first_irreversible_mutation(self) -> None:
        all_preflight_names = "\n".join(
            step.get("name", "")
            for name in (
                "source-gate",
                "plan",
                "semantic-handoff",
                "supply-chain",
                "attest-handoff",
            )
            for step in self.jobs[name]["steps"]
        )
        for value in (
            "authenticate exact producer runs",
            "Verify candidate Compose and Cloud Run attestations",
            "Run local core and additive release gates",
            "Re-run complete candidate and deployment semantics",
            "Verify exact multi-architecture digest signature provenance and SBOMs",
            "Retain only the verified source-free mutation handoff",
            "Attest the exact source-free core publication handoff",
        ):
            self.assertIn(value, all_preflight_names)
        stage_names = [step.get("name", "") for step in self.jobs["stage-release"]["steps"]]
        self.assertLess(
            stage_names.index("Preflight exact annotated tag release record and every fixed asset"),
            stage_names.index("Create the exact annotated v1.0.0 tag"),
        )
        oci_names = [step.get("name", "") for step in self.jobs["promote-oci"]["steps"]]
        self.assertLess(
            oci_names.index("Preflight signed candidate provenance SBOMs and every stable coordinate"),
            oci_names.index("Promote only the exact candidate index to v1 stable tags"),
        )

    def test_release_is_honestly_labeled_and_published_after_oci(self) -> None:
        record_script = next(
            step["run"]
            for step in self.jobs["stage-release"]["steps"]
            if step.get("name", "").startswith("Revalidate exact closure")
        )
        for value in (
            '.profile == "single_maintainer_v1"',
            '.profile_status == "incomplete"',
            "release_qualified:false",
            "fully_evidence_gated:false",
            "independently_reviewed:false",
            'contains("not release-qualified")',
        ):
            self.assertIn(value, record_script)
        self.assertEqual(
            set(self.jobs["publish-release"]["needs"]),
            {"plan", "stage-release", "promote-oci"},
        )
        publisher = next(
            step["run"]
            for step in self.jobs["publish-release"]["steps"]
            if step.get("name") == "Publish and verify the profile-labeled GitHub release"
        )
        self.assertIn("printf '{\"draft\":false}\\n'", publisher)
        self.assertIn(".draft == false", publisher)

    def test_workflow_is_resumable_and_never_destroys_coordinates(self) -> None:
        for forbidden in (
            "--clobber",
            "gh release delete",
            "git push --force",
            "docker manifest rm",
            "gh api --method DELETE",
        ):
            self.assertNotIn(forbidden, self.text)
        for value in (
            'tag_exists=true',
            'release_exists=true',
            'state=$(inspect_tag',
            'test "$state" = exact',
            'for tag in 1.0.0 1.0 1 latest',
        ):
            self.assertIn(value, self.text)


if __name__ == "__main__":
    unittest.main()
