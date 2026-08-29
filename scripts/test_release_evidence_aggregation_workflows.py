#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def workflow(name: str) -> dict:
    value = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{name} must be a mapping")
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


def steps(value: dict, job: str) -> list[dict]:
    result = value["jobs"][job].get("steps")
    if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
        raise AssertionError("workflow steps are invalid")
    return result


def assert_pinned(test: unittest.TestCase, value: dict) -> None:
    uses = [
        item["uses"]
        for job in value["jobs"].values()
        for item in job.get("steps", [])
        if isinstance(item, dict) and "uses" in item
    ]
    test.assertTrue(uses)
    test.assertTrue(all(PINNED_ACTION.fullmatch(item) for item in uses), uses)


class ReleaseEvidenceAggregationWorkflowTests(unittest.TestCase):
    def test_cloud_finalizer_authenticates_all_five_platform_producers(self) -> None:
        value = workflow("cloud-deployment-aggregate.yml")
        self.assertEqual(set(value["on"]), {"workflow_dispatch"})
        self.assertEqual(set(value["jobs"]), {"aggregate"})
        job = value["jobs"]["aggregate"]
        self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")
        self.assertEqual(job.get("environment"), "release-evidence")
        assert_pinned(self, value)

        names = [item.get("name", "") for item in steps(value, "aggregate")]
        provenance = names.index("Verify every platform run belongs to the fixed producer")
        authority = names.index("Verify candidate and source-conformance attestations")
        finalizer = names.index("Verify and finalize the five signed cloud captures")
        attestation = names.index("Attest the finalized cloud-deployments domain")
        retained = names.index("Retain only the authenticated cloud-deployment domain")
        self.assertLess(provenance, authority)
        self.assertLess(authority, finalizer)
        self.assertLess(finalizer, attestation)
        self.assertLess(attestation, retained)

        text = (WORKFLOWS / "cloud-deployment-aggregate.yml").read_text(encoding="utf-8")
        for platform in ("compose", "cloud_run", "aws", "fly_io", "cloudflare_containers"):
            self.assertIn(f"latchway-deployment-{platform}-${{{{ inputs.candidate_commit }}}}", text)
            self.assertIn(f"verify_run {platform}", text)
        for required in (
            'expected_workflow="${4:-.github/workflows/deployment-evidence.yml}"',
            ".github/workflows/cross-repository-conformance.yml",
            ".github/workflows/release.yml",
            "gh attestation trusted-root",
            "scripts/deployment-evidence.py finalize",
            "cloud_deployments.attestation.sigstore.json",
            "--signer-digest \"$CANDIDATE_COMMIT\"",
            "--deny-self-hosted-runners",
        ):
            self.assertIn(required, text)
        self.assertNotIn("continue-on-error", text)

    def test_domain_aggregate_requires_every_scope_domain_and_fixed_signer(self) -> None:
        value = workflow("aggregate-release-evidence.yml")
        self.assertEqual(set(value["on"]), {"workflow_dispatch"})
        self.assertEqual(
            value["on"]["workflow_dispatch"]["inputs"]["scope"]["options"],
            ["promotion", "release"],
        )
        job = value["jobs"]["aggregate"]
        self.assertEqual(job.get("environment"), "release-evidence")
        self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")
        assert_pinned(self, value)

        names = [item.get("name", "") for item in steps(value, "aggregate")]
        provenance = names.index("Verify every domain run belongs to its fixed producer")
        attestations = names.index("Verify every exact domain attestation")
        union = names.index("Build collision-free hash-bound evidence union")
        aggregate_attestation = names.index("Attest the exact aggregate manifest")
        upload = names.index("Retain only the authenticated release-evidence aggregate")
        self.assertLess(provenance, attestations)
        self.assertLess(attestations, union)
        self.assertLess(union, aggregate_attestation)
        self.assertLess(aggregate_attestation, upload)

        text = (WORKFLOWS / "aggregate-release-evidence.yml").read_text(encoding="utf-8")
        for domain in (
            "live_sdk_conformance",
            "physical_devices",
            "live_provider",
            "cloud_deployments",
            "operational_resilience",
            "supply_chain",
            "public_tags",
            "public_registries",
        ):
            self.assertIn(domain, text)
        for producer in (
            ".github/workflows/release-domain-evidence.yml",
            ".github/workflows/cloud-deployment-aggregate.yml",
            ".github/workflows/operational-resilience-evidence.yml",
        ):
            self.assertIn(producer, text)
        for required in (
            "scripts/aggregate-release-evidence.py",
            "aggregate-manifest.attestation.sigstore.json",
            "name: latchway-v1-external-evidence",
            "--source-digest \"$CANDIDATE_COMMIT\"",
            "--signer-digest \"$CANDIDATE_COMMIT\"",
            "--deny-self-hosted-runners",
        ):
            self.assertIn(required, text)
        self.assertNotIn("continue-on-error", text)

    def test_cross_repository_gate_reverifies_aggregate_and_each_domain(self) -> None:
        value = workflow("cross-repository-conformance.yml")
        names = [item.get("name", "") for item in steps(value, "evidence")]
        run_provenance = names.index("Verify the fixed authenticated aggregate producer run")
        download = names.index("Download independently produced external evidence")
        attestations = names.index("Verify protected producer attestations for release-domain documents")
        conformance = names.index("Produce source or release evidence")
        self.assertLess(run_provenance, download)
        self.assertLess(download, attestations)
        self.assertLess(attestations, conformance)

        text = (WORKFLOWS / "cross-repository-conformance.yml").read_text(encoding="utf-8")
        for required in (
            'name: latchway-v1-external-evidence-${{ inputs.external_evidence_run_id }}-${{ inputs.external_evidence_run_attempt }}',
            '.path == ".github/workflows/aggregate-release-evidence.yml"',
            "aggregate-manifest.attestation.sigstore.json",
            "domains=(live_sdk_conformance physical_devices live_provider cloud_deployments operational_resilience supply_chain)",
            "signer=.github/workflows/cloud-deployment-aggregate.yml",
            "signer=.github/workflows/operational-resilience-evidence.yml",
            "--signer-digest \"$candidate_commit\"",
            "--source-digest \"$candidate_commit\"",
            "--deny-self-hosted-runners",
        ):
            self.assertIn(required, text)
        self.assertNotIn("continue-on-error", text)


if __name__ == "__main__":
    unittest.main()
