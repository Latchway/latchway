#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/preview-image.yml"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def load_workflow() -> dict:
    value = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("preview-image.yml is not an object")
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


class PreviewImageWorkflowTests(unittest.TestCase):
    def test_only_manual_exact_main_draft_can_publish(self) -> None:
        workflow = load_workflow()
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(
            set(workflow["on"]["workflow_dispatch"]["inputs"]), {"preview_commit"}
        )
        for job in workflow["jobs"].values():
            self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn('test "$GITHUB_SHA" = "$PREVIEW_COMMIT"', text)
        self.assertIn(
            'test "$(jq --raw-output .contract_status api/protocol-version.json)" = draft',
            text,
        )
        self.assertIn(
            "test \"$(jq --raw-output '.released_at == null' "
            'api/protocol-version.json)" = true',
            text,
        )

    def test_preview_coordinate_cannot_impersonate_release_coordinates(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'echo "registry_tag=preview-$PREVIEW_COMMIT-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"',
            text,
        )
        self.assertGreaterEqual(text.count("release_qualified: false"), 2)
        self.assertGreaterEqual(text.count("stable_promotion_eligible: false"), 2)
        for forbidden in (
            "gh release create",
            "refs/tags/",
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

    def test_source_free_publisher_validates_before_authentication(self) -> None:
        workflow = load_workflow()
        publisher = workflow["jobs"]["publish_and_sign"]
        self.assertEqual(publisher["permissions"]["packages"], "write")
        self.assertEqual(publisher["permissions"]["id-token"], "write")
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in publisher["steps"]
            )
        )
        names = [step.get("name", "") for step in publisher["steps"]]
        self.assertLess(
            names.index(
                "Validate the closed preview handoff before registry authentication"
            ),
            names.index("Authenticate only the source-free preview publisher"),
        )
        self.assertIn("docker logout ghcr.io", json.dumps(publisher, sort_keys=True))

    def test_supply_chain_and_public_visibility_are_enforced(self) -> None:
        workflow = load_workflow()
        build_names = [
            step.get("name", "") for step in workflow["jobs"]["build"]["steps"]
        ]
        for architecture in ("amd64", "arm64"):
            self.assertIn(f"Scan {architecture} vulnerabilities", build_names)
            self.assertIn(f"Generate exact {architecture} SPDX SBOM", build_names)
        publisher = json.dumps(workflow["jobs"]["publish_and_sign"], sort_keys=True)
        self.assertIn("cosign sign --yes", publisher)
        self.assertEqual(publisher.count('"uses": "actions/attest@'), 4)
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
        self.assertEqual(verifier["needs"], ["publish_and_sign", "verify-public"])
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

        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            workflow_text.count(
                '--certificate-github-workflow-sha "$PREVIEW_COMMIT"'
            ),
            2,
        )

    def test_every_action_is_commit_pinned(self) -> None:
        workflow = load_workflow()
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses") if isinstance(step, dict) else None
                if uses:
                    self.assertRegex(uses, PINNED_ACTION, f"{job_name}: {uses}")


if __name__ == "__main__":
    unittest.main()
