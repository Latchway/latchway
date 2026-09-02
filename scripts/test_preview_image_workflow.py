#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/preview-image.yml"
PROMOTION_WORKFLOW_PATH = ROOT / ".github/workflows/promote-release.yml"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def load_workflow() -> dict:
    value = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("preview-image.yml is not an object")
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


class PreviewImageWorkflowTests(unittest.TestCase):
    def test_only_manual_exact_main_mode_can_publish(self) -> None:
        workflow = load_workflow()
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(
            set(workflow["on"]["workflow_dispatch"]["inputs"]),
            {"preview_commit", "publication_mode", "bootstrap_confirmation"},
        )
        mode = workflow["on"]["workflow_dispatch"]["inputs"]["publication_mode"]
        self.assertEqual(mode["type"], "choice")
        self.assertEqual(mode["default"], "draft-preview")
        self.assertEqual(
            mode["options"],
            ["draft-preview", "released-first-package-bootstrap"],
        )
        self.assertEqual(
            workflow["on"]["workflow_dispatch"]["inputs"]["preview_commit"],
            {
                "description": "Exact current main commit to publish at a run-unique non-release coordinate",
                "required": True,
                "type": "string",
            },
        )
        confirmation = workflow["on"]["workflow_dispatch"]["inputs"][
            "bootstrap_confirmation"
        ]
        self.assertFalse(confirmation["required"])
        self.assertEqual(confirmation["type"], "string")
        self.assertEqual(
            workflow["concurrency"],
            {
                "group": "latchway-non-release-ghcr-publication",
                "cancel-in-progress": False,
            },
        )
        for job in workflow["jobs"].values():
            self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn('test "$GITHUB_SHA" = "$PREVIEW_COMMIT"', text)
        self.assertIn('test "$(git rev-parse --verify HEAD)" = "$PREVIEW_COMMIT"', text)
        self.assertIn('test -z "$(git status --porcelain=v1 --untracked-files=all)"', text)

    def test_draft_preview_and_released_bootstrap_are_disjoint(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("draft-preview)", text)
        self.assertIn('test -z "$BOOTSTRAP_CONFIRMATION"', text)
        self.assertIn('test "$contract_status" = draft', text)
        self.assertIn('test "$released_at_json" = null', text)
        self.assertIn("released-first-package-bootstrap)", text)
        self.assertIn(
            'test "$BOOTSTRAP_CONFIRMATION" = bootstrap-ghcr-first-package-only',
            text,
        )
        self.assertIn('test "$contract_status" = released', text)
        self.assertIn('test "$source_version" = 1.0.0', text)
        self.assertIn('test "$contract_version" = 1.0.0', text)
        self.assertIn("latchway_first_package_bootstrap_handoff", text)
        self.assertIn('runtime_version="0.0.0-bootstrap.$short_commit"', text)
        self.assertGreaterEqual(
            text.count(
                'test "$(date --utc --date="$released_at" +%Y-%m-%dT%H:%M:%SZ)" = "$released_at"'
            ),
            2,
        )

    def test_bootstrap_is_serialized_and_requires_authenticated_absence(self) -> None:
        workflow = load_workflow()
        self.assertEqual(
            workflow["concurrency"]["group"],
            "latchway-non-release-ghcr-publication",
        )
        publisher = workflow["jobs"]["publish"]
        absence = next(
            step
            for step in publisher["steps"]
            if step.get("name")
            == "Require the released bootstrap package to be absent"
        )
        self.assertEqual(
            absence["if"],
            "inputs.publication_mode == 'released-first-package-bootstrap'",
        )
        self.assertEqual(absence["env"], {"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"})
        run = absence["run"]
        self.assertIn(
            "https://api.github.com/orgs/Latchway/packages/container/latchway",
            run,
        )
        self.assertIn('test "$status" = 404', run)
        self.assertIn(".message == \"Not Found\"", run)
        names = [step.get("name", "") for step in publisher["steps"]]
        self.assertLess(
            names.index("Validate the closed preview handoff before registry authentication"),
            names.index("Require the released bootstrap package to be absent"),
        )
        self.assertLess(
            names.index("Require the released bootstrap package to be absent"),
            names.index("Authenticate only the source-free preview publisher"),
        )

    def test_non_release_coordinates_cannot_impersonate_release_coordinates(self) -> None:
        workflow = load_workflow()
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        for job in workflow["jobs"].values():
            self.assertNotEqual(job.get("permissions", {}).get("contents"), "write")
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'echo "registry_tag=$tag_prefix-$PREVIEW_COMMIT-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"',
            text,
        )
        self.assertIn("tag_prefix=preview", text)
        self.assertIn("tag_prefix=bootstrap", text)
        self.assertIn(
            'test "$TAG" = "$tag_prefix-$PREVIEW_COMMIT-$PUBLICATION_RUN_ID-$PUBLICATION_RUN_ATTEMPT"',
            text,
        )
        self.assertIn(
            'test "$REGISTRY_TAG" = "$tag_prefix-$PREVIEW_COMMIT-$PUBLICATION_RUN_ID-$PUBLICATION_RUN_ATTEMPT"',
            text,
        )
        self.assertIn(
            '[[ "$REGISTRY_TAG" =~ ^(preview|bootstrap)-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*$ ]]',
            text,
        )
        # One definition, one invocation inside the two-architecture push loop,
        # and one invocation immediately before the index mutation.
        self.assertEqual(text.count("require_exact_registry_tag"), 3)
        self.assertIn(
            '[[ "$remote" =~ ^ghcr\\.io/latchway/latchway:(preview|bootstrap)-',
            text,
        )
        self.assertGreaterEqual(text.count("release_qualified: false"), 2)
        self.assertGreaterEqual(text.count("stable_promotion_eligible: false"), 2)
        for forbidden in (
            "gh release create",
            "gh release upload",
            "git tag",
            "git push",
            "repository_dispatch",
            "refs/tags/",
            "/git/refs",
            "/releases",
            "type=semver",
            "value=latest",
            "$IMAGE:latest",
            "$IMAGE:candidate-",
        ):
            self.assertNotIn(forbidden, text)

    def test_build_has_no_registry_or_oidc_authority(self) -> None:
        workflow = load_workflow()
        build = workflow["jobs"]["build"]
        self.assertNotIn("packages", build["permissions"])
        self.assertNotIn("id-token", build["permissions"])
        serialized = json.dumps(build, sort_keys=True)
        self.assertNotIn("docker/login-action", serialized)
        self.assertNotIn("secrets.GITHUB_TOKEN", serialized)
        checkout = next(
            step
            for step in build["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        )
        self.assertEqual(checkout["with"]["persist-credentials"], False)
        runs = "\n".join(
            step.get("run", "") for step in build["steps"] if isinstance(step, dict)
        )
        self.assertIn('test -z "${GITHUB_TOKEN:-}"', runs)
        self.assertEqual(runs.count("scripts/verify-runtime-image.py"), 2)

    def test_source_free_publish_and_sign_jobs_are_least_privilege(self) -> None:
        workflow = load_workflow()
        publisher = workflow["jobs"]["publish"]
        signer = workflow["jobs"]["sign"]
        self.assertEqual(publisher["environment"], "preview-image-publishing")
        self.assertEqual(signer["environment"], "preview-image-publishing")
        self.assertEqual(publisher["permissions"]["packages"], "write")
        self.assertEqual(publisher["permissions"]["contents"], "read")
        self.assertNotIn("id-token", publisher["permissions"])
        self.assertNotIn("attestations", publisher["permissions"])
        self.assertEqual(signer["permissions"]["packages"], "write")
        self.assertEqual(signer["permissions"]["id-token"], "write")
        self.assertEqual(signer["permissions"]["attestations"], "write")
        for job in (publisher, signer):
            self.assertFalse(
                any(
                    step.get("uses", "").startswith("actions/checkout@")
                    for step in job["steps"]
                )
            )
            self.assertEqual(
                job["steps"][0]["name"],
                "Verify the exact protected preview-image-publishing environment",
            )
        names = [step.get("name", "") for step in publisher["steps"]]
        self.assertLess(
            names.index(
                "Validate the closed preview handoff before registry authentication"
            ),
            names.index("Authenticate only the source-free preview publisher"),
        )
        signer_names = [step.get("name", "") for step in signer["steps"]]
        self.assertLess(
            signer_names.index(
                "Validate the complete unsigned handoff before registry authentication"
            ),
            signer_names.index("Authenticate only the source-free non-release signer"),
        )
        self.assertLess(
            signer_names.index(
                "Revalidate the exact published index before requesting OIDC"
            ),
            signer_names.index("Sign and verify the non-release index with GitHub OIDC"),
        )
        self.assertIn("ghcr-preview-publisher-docker", json.dumps(publisher, sort_keys=True))
        self.assertIn("ghcr-preview-signer-docker", json.dumps(signer, sort_keys=True))
        self.assertIn("docker logout ghcr.io", json.dumps(publisher, sort_keys=True))
        self.assertIn("docker logout ghcr.io", json.dumps(signer, sort_keys=True))

        mutation_actions = [
            index
            for index, step in enumerate(signer["steps"])
            if step.get("uses", "").startswith("actions/attest@")
            and step.get("with", {}).get("push-to-registry") is True
        ]
        self.assertEqual(len(mutation_actions), 3)
        for index in mutation_actions:
            preflight = signer["steps"][index - 1]
            self.assertTrue(preflight["name"].startswith("Revalidate the non-release tag"))
            self.assertIn(
                'test "$TAG" = "$tag_prefix-$PREVIEW_COMMIT-$PUBLICATION_RUN_ID-$PUBLICATION_RUN_ATTEMPT"',
                preflight["run"],
            )
            self.assertIn(
                '[[ "$TAG" =~ ^(preview|bootstrap)-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*$ ]]',
                preflight["run"],
            )

    def test_build_scan_and_sbom_precede_protected_publish(self) -> None:
        workflow = load_workflow()
        build_names = [
            step.get("name", "") for step in workflow["jobs"]["build"]["steps"]
        ]
        handoff_index = build_names.index("Build the closed credential-free preview handoff")
        for required in (
            "Smoke both exact preview children",
            "Scan amd64 vulnerabilities",
            "Scan arm64 vulnerabilities",
            "Generate exact amd64 SPDX SBOM",
            "Generate exact arm64 SPDX SBOM",
        ):
            self.assertLess(build_names.index(required), handoff_index)
        self.assertEqual(workflow["jobs"]["publish"]["needs"], "build")
        self.assertEqual(workflow["jobs"]["sign"]["needs"], "publish")
        self.assertEqual(
            workflow["jobs"]["build"]["outputs"]["publication_run_attempt"],
            "${{ steps.metadata.outputs.publication_run_attempt }}",
        )
        self.assertEqual(
            workflow["jobs"]["publish"]["outputs"]["publication_run_attempt"],
            "${{ steps.publish.outputs.publication_run_attempt }}",
        )
        self.assertEqual(
            workflow["jobs"]["sign"]["outputs"]["publication_run_attempt"],
            "${{ needs.publish.outputs.publication_run_attempt }}",
        )
        serialized = json.dumps(workflow, sort_keys=True)
        self.assertIn("needs.build.outputs.publication_run_attempt", serialized)
        self.assertIn("needs.publish.outputs.publication_run_attempt", serialized)
        public_run = "\n".join(
            step.get("run", "")
            for step in workflow["jobs"]["verify-public"]["steps"]
        )
        self.assertIn(
            'test "$TAG" = "$tag_prefix-$PREVIEW_COMMIT-$PUBLICATION_RUN_ID-$PUBLICATION_RUN_ATTEMPT"',
            public_run,
        )
        self.assertNotIn(
            '$tag_prefix-$PREVIEW_COMMIT-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT',
            public_run,
        )

    def test_supply_chain_and_public_visibility_are_enforced(self) -> None:
        workflow = load_workflow()
        build_names = [
            step.get("name", "") for step in workflow["jobs"]["build"]["steps"]
        ]
        for architecture in ("amd64", "arm64"):
            self.assertIn(f"Scan {architecture} vulnerabilities", build_names)
            self.assertIn(f"Generate exact {architecture} SPDX SBOM", build_names)
        publisher = json.dumps(workflow["jobs"]["publish"], sort_keys=True)
        signer = json.dumps(workflow["jobs"]["sign"], sort_keys=True)
        self.assertNotIn("cosign sign --yes", publisher)
        self.assertNotIn('"uses": "actions/attest@', publisher)
        self.assertIn("cosign sign --yes", signer)
        self.assertEqual(signer.count('"uses": "actions/attest@'), 4)
        public = workflow["jobs"]["verify-public"]
        self.assertNotIn("packages", public["permissions"])
        public_run = "\n".join(
            step.get("run", "") for step in public["steps"] if isinstance(step, dict)
        )
        self.assertIn('export DOCKER_CONFIG="$empty_config"', public_run)
        self.assertIn(
            'docker buildx imagetools inspect --raw "$IMAGE@$DIGEST"', public_run
        )
        self.assertIn(
            'docker pull --platform "linux/$architecture" "$reference"',
            public_run,
        )
        self.assertIn(
            "docker image inspect --format '{{.Os}}/{{.Architecture}}'",
            public_run,
        )
        self.assertNotIn("docker/login-action", json.dumps(public, sort_keys=True))
        self.assertNotIn("gh attestation verify", public_run)
        self.assertIn("cosign verify", public_run)

        verifier = workflow["jobs"]["verify-attestations"]
        self.assertEqual(verifier["permissions"]["packages"], "read")
        self.assertEqual(verifier["needs"], ["sign", "verify-public"])
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in verifier["steps"]
            )
        )
        verifier_run = "\n".join(
            step.get("run", "")
            for step in verifier["steps"]
            if isinstance(step, dict)
        )
        self.assertEqual(verifier_run.count("gh attestation verify"), 2)
        self.assertIn("https://slsa.dev/provenance/v1", verifier_run)
        self.assertIn("https://spdx.dev/Document/v2.3", verifier_run)
        self.assertGreaterEqual(
            verifier_run.count('--source-digest "$PREVIEW_COMMIT"'), 2
        )
        self.assertGreaterEqual(
            verifier_run.count('--signer-digest "$PREVIEW_COMMIT"'), 2
        )
        self.assertIn("--bundle-from-oci", verifier_run)
        self.assertIn("docker logout ghcr.io", verifier_run)
        self.assertIn("ghcr-preview-verifier-docker", verifier_run)

        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            workflow_text.count(
                '--certificate-github-workflow-sha "$PREVIEW_COMMIT"'
            ),
            2,
        )

    def test_stable_promotion_cannot_adopt_preview_or_bootstrap(self) -> None:
        promotion = PROMOTION_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'verify_run candidate "$CANDIDATE_RUN_ID" "$CANDIDATE_RUN_ATTEMPT" .github/workflows/release.yml',
            promotion,
        )
        self.assertIn("latchway-candidate-", promotion)
        self.assertIn('.kind == "latchway_release_candidate"', promotion)
        self.assertIn('.status == "passed"', promotion)
        self.assertNotIn("preview-image.yml", promotion)
        self.assertNotIn("latchway_first_package_bootstrap", promotion)

    def test_every_action_is_commit_pinned(self) -> None:
        workflow = load_workflow()
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses") if isinstance(step, dict) else None
                if uses:
                    self.assertRegex(uses, PINNED_ACTION, f"{job_name}: {uses}")


if __name__ == "__main__":
    unittest.main()
