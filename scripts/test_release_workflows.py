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
    def test_sensitive_github_cli_operations_require_fixed_version_first(self) -> None:
        sensitive = ("gh release verify", "gh attestation verify")
        guarded: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            offsets = [text.index(command) for command in sensitive if command in text]
            if not offsets:
                continue
            guarded.append(path.name)
            self.assertIn("require-gh-version.py", text, path.name)
            self.assertLess(text.index("require-gh-version.py"), min(offsets), path.name)
        self.assertEqual(
            guarded,
            [
                "aggregate-release-evidence.yml",
                "cloud-deployment-aggregate.yml",
                "cross-repository-conformance.yml",
                "deployment-evidence.yml",
                "finalize-release-record.yml",
                "operational-resilience-evidence.yml",
                "promote-release.yml",
                "release-domain-evidence.yml",
                "release-domain-observations.yml",
                "release-failure-evidence.yml",
                "release-load-evidence.yml",
                "security.yml",
            ],
        )
        observer = (ROOT / "scripts/release-domain-observer.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("require_github_cli()", observer)
        self.assertLess(
            observer.index("require_github_cli()\n        observer = Observer"),
            observer.index("observer.observe()"),
        )
        for script_name, guarded_branch in (
            ("deployment-evidence.py", 'if args.command == "finalize":'),
            ("release-domain-evidence.py", "if arguments.output_directory is None:"),
        ):
            script = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
            self.assertIn("GH_VERSION.installed_version()", script, script_name)
            self.assertLess(
                script.index("GH_VERSION.installed_version()", script.index(guarded_branch)),
                script.index("finalize(", script.index(guarded_branch)),
                script_name,
            )

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
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
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
        immutable_preflight = names.index(
            "Preflight immutable releases and every fixed core release asset"
        )
        existing_tag = names.index("Verify any existing core release tag")
        tag_creation = names.index("Create the evidence-gated annotated core tag")
        draft = names.index("Prepare the recoverable product release draft and exact assets")
        oci_promotion = names.index("Promote only the verified index digest to stable OCI tags")
        release_creation = names.index("Publish the immutable release record")
        sdk_dispatch = names.index("Dispatch exact evidence-bound SDK publications")
        self.assertLess(candidate_attestation, bindings)
        self.assertLess(bindings, image_provenance)
        self.assertLess(image_provenance, immutable_preflight)
        self.assertLess(immutable_preflight, existing_tag)
        self.assertLess(existing_tag, tag_creation)
        self.assertLess(tag_creation, draft)
        self.assertLess(draft, oci_promotion)
        self.assertLess(oci_promotion, release_creation)
        self.assertLess(release_creation, sdk_dispatch)

        serialized = (WORKFLOWS / "promote-release.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/release-candidate.py", serialized)
        self.assertIn("scripts/verify-promotion.py", serialized)
        self.assertIn("--signer-workflow", serialized)
        self.assertIn("--source-ref refs/heads/main", serialized)
        self.assertGreaterEqual(serialized.count("--source-digest"), 3)
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertIn("LATCHWAY_RELEASE_DISPATCH_TOKEN", serialized)
        self.assertIn("repos/$repository/immutable-releases", serialized)
        self.assertIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", serialized)
        self.assertIn('(keys | sort) == ["enabled", "enforced_by_owner"]', serialized)
        self.assertIn('gh release create "$INTENDED_TAG" --draft', serialized)
        self.assertIn('.immutable == true', serialized)
        self.assertIn('gh release verify "$INTENDED_TAG"', serialized)
        self.assertIn("verify-github-release-attestation.py", serialized)
        self.assertIn("If-None-Match:", serialized)
        self.assertIn("--expected-status 304", serialized)
        self.assertNotIn("If-Match:", serialized)
        self.assertNotIn("--generate-notes", serialized)
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
        self.assertIn(
            "Verify protected producer attestations for release-domain documents",
            serialized,
        )
        self.assertIn("${domain}.attestation.sigstore.json", serialized)
        self.assertIn(
            ".github/workflows/release-domain-evidence.yml", serialized
        )
        self.assertIn("--signer-digest \"$candidate_commit\"", serialized)
        self.assertIn("--source-digest \"$candidate_commit\"", serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertNotIn("if: inputs.scope != 'source'\n        uses: actions/attest@", serialized)
        self.assertIn('test "$GITHUB_SHA" = "$core_commit"', serialized)
        self.assertNotIn("continue-on-error", serialized)
        download = next(
            step
            for step in all_steps(workflow)
            if step.get("name") == "Download independently produced external evidence"
        )
        self.assertEqual(download.get("if"), "inputs.scope != 'source'")

    def test_external_domain_evidence_is_protected_attested_and_candidate_bound(self) -> None:
        workflow = load_workflow("release-domain-evidence.yml")
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        domains = workflow["on"]["workflow_dispatch"]["inputs"]["domain"]["options"]
        self.assertEqual(
            domains,
            [
                "live_sdk_conformance",
                "physical_devices",
                "live_provider",
                "supply_chain",
                "public_tags",
                "public_registries",
            ],
        )
        job = workflow["jobs"]["evidence"]
        self.assertEqual(job["environment"], "release-evidence")
        self.assertEqual(job["if"], "github.ref == 'refs/heads/main'")
        names = [step.get("name", "") for step in job["steps"]]
        producer_run = names.index("Verify every input run and attempt belongs to its fixed producer")
        bundles = names.index("Verify all three exact attestation bundles before finalization")
        finalized = names.index("Finalize the external release-domain document")
        document_attested = names.index("Attest the exact external evidence document")
        bundle_retained = names.index("Retain the external evidence attestation bundle")
        artifact_retained = names.index(
            "Retain the domain document and all hash-bound raw results"
        )
        self.assertLess(producer_run, bundles)
        self.assertLess(bundles, finalized)
        self.assertLess(finalized, document_attested)
        self.assertLess(document_attested, bundle_retained)
        self.assertLess(bundle_retained, artifact_retained)
        serialized = (WORKFLOWS / "release-domain-evidence.yml").read_text(encoding="utf-8")
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        self.assertIn("--receipt-attestation", serialized)
        self.assertIn("verify_run machine \"$MACHINE_RESULTS_RUN_ID\" \"$MACHINE_RESULTS_RUN_ATTEMPT\" .github/workflows/release-domain-observations.yml", serialized)
        self.assertEqual(serialized.count("--signer-digest"), 3)
        self.assertEqual(serialized.count("--source-digest"), 3)
        self.assertEqual(serialized.count("--deny-self-hosted-runners"), 3)
        self.assertNotIn("machine_results_artifact", serialized)
        self.assertNotIn("continue-on-error", serialized)
        self.assertNotIn("secrets.", serialized)
        self.assertIn("$EVIDENCE_DOMAIN.attestation.sigstore.json", serialized)

        producer = load_workflow("release-domain-observations.yml")
        producer_domains = producer["on"]["workflow_dispatch"]["inputs"]["domain"][
            "options"
        ]
        self.assertIn("physical_devices", producer_domains)
        producer_job = producer["jobs"]["observe"]
        self.assertEqual(producer_job["environment"], "release-evidence")
        self.assertEqual(producer_job["if"], "github.ref == 'refs/heads/main'")
        producer_names = [step.get("name", "") for step in producer_job["steps"]]
        sdk_executed = producer_names.index(
            "Execute the fixed SDK or physical-device observation plan"
        )
        other_executed = producer_names.index(
            "Execute the fixed non-SDK domain observation plan"
        )
        manifested = producer_names.index("Produce the exact machine-results manifest")
        attested = producer_names.index("Attest the exact machine-results manifest")
        retained = producer_names.index("Retain only the attested machine-result set")
        self.assertLess(sdk_executed, manifested)
        self.assertLess(other_executed, manifested)
        self.assertLess(manifested, attested)
        self.assertLess(attested, retained)
        producer_text = (WORKFLOWS / "release-domain-observations.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/release-domain-observer.py", producer_text)
        self.assertNotIn("Refuse hosted substitution", producer_text)
        for value in (
            "ios_physical_run_id",
            "ios_physical_run_attempt",
            "android_physical_run_id",
            "android_physical_run_attempt",
            "react_native_physical_run_id",
            "react_native_physical_run_attempt",
            "LATCHWAY_RELEASE_EVIDENCE_ACTIONS_READ_TOKEN",
            "app-attest-physical-${{ inputs.ios_physical_run_id }}-${{ inputs.ios_physical_run_attempt }}",
            "play-integrity-physical-${{ inputs.android_physical_run_id }}-${{ inputs.android_physical_run_attempt }}",
            "react-native-ios-physical-${{ inputs.react_native_physical_run_id }}-${{ inputs.react_native_physical_run_attempt }}",
            "react-native-android-physical-${{ inputs.react_native_physical_run_id }}-${{ inputs.react_native_physical_run_attempt }}",
            "repository: Latchway/latchway-ios-sdk",
            "repository: Latchway/latchway-android",
            "repository: Latchway/latchway-react-native-sdk",
            "pnpm build",
        ):
            self.assertIn(value, producer_text)
        observer_text = (ROOT / "scripts" / "release-domain-observer.py").read_text(
            encoding="utf-8"
        )
        for workflow in (
            ".github/workflows/physical-app-attest.yml",
            ".github/workflows/physical-play-integrity.yml",
            ".github/workflows/physical-device-evidence.yml",
        ):
            self.assertIn(workflow, observer_text)
        self.assertIn('"--source-digest"', observer_text)
        self.assertIn('"--signer-digest"', observer_text)
        self.assertIn('"refs/heads/main"', observer_text)
        self.assertIn("scripts/live-conformance.mjs", observer_text)
        self.assertIn("latchway_retained_physical_device_receipt", observer_text)
        self.assertIn('"retained_inputs": item["receipt"]["payloads"]', observer_text)
        self.assertIn('"X-GitHub-Api-Version: 2026-03-10"', observer_text)
        self.assertIn('"release", "verify"', observer_text)
        self.assertNotIn("machine_results_run_id", producer_text)
        self.assertNotIn("continue-on-error", producer_text)
        sdk_step = producer_job["steps"][sdk_executed]
        other_step = producer_job["steps"][other_executed]
        self.assertEqual(
            sdk_step["env"]["GH_TOKEN"],
            "${{ secrets.LATCHWAY_RELEASE_EVIDENCE_ACTIONS_READ_TOKEN }}",
        )
        self.assertNotIn("LATCHWAY_ADMIN_API_TOKEN", sdk_step["env"])
        self.assertEqual(other_step["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertNotIn("LATCHWAY_LIVE_SDK_IDENTITY_TOKEN", other_step["env"])

        release_text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        source_text = (WORKFLOWS / "cross-repository-conformance.yml").read_text(encoding="utf-8")
        self.assertIn("latchway-candidate.attestation.sigstore.json", release_text)
        self.assertIn("latchway-cross-repository.attestation.sigstore.json", source_text)

    def test_every_third_party_action_is_commit_pinned(self) -> None:
        for name in (
            "release.yml",
            "promote-release.yml",
            "cross-repository-conformance.yml",
            "release-domain-observations.yml",
            "release-domain-evidence.yml",
        ):
            for step in all_steps(load_workflow(name)):
                action = step.get("uses")
                if action is not None:
                    self.assertRegex(action, PINNED_ACTION, f"{name}: {action}")


if __name__ == "__main__":
    unittest.main()
