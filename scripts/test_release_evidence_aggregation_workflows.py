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


def embedded_python(run: str) -> str:
    marker = "<<'PY'\n"
    if marker not in run:
        raise AssertionError("fixed inline Python heredoc is missing")
    body = run.split(marker, 1)[1].split("\nPY\n", 1)[0]
    compile(body, "cloud-deployment-aggregate-inline.py", "exec")
    return body


class ReleaseEvidenceAggregationWorkflowTests(unittest.TestCase):
    def test_cloud_finalizer_authenticates_all_five_platform_producers(self) -> None:
        value = workflow("cloud-deployment-aggregate.yml")
        self.assertEqual(set(value["on"]), {"workflow_dispatch"})
        self.assertEqual(set(value["jobs"]), {"authenticate", "finalize", "attest"})
        authentication = value["jobs"]["authenticate"]
        finalizer = value["jobs"]["finalize"]
        attestation_job = value["jobs"]["attest"]
        self.assertEqual(authentication.get("if"), "github.ref == 'refs/heads/main'")
        self.assertEqual(authentication.get("environment"), "release-evidence")
        self.assertEqual(attestation_job.get("environment"), "release-evidence-signing")
        self.assertEqual(finalizer.get("needs"), "authenticate")
        self.assertEqual(attestation_job.get("needs"), "finalize")
        self.assertNotIn("id-token", authentication["permissions"])
        self.assertNotIn("id-token", finalizer["permissions"])
        self.assertEqual(attestation_job["permissions"]["id-token"], "write")
        assert_pinned(self, value)

        authentication_names = [
            item.get("name", "") for item in steps(value, "authenticate")
        ]
        provenance = authentication_names.index(
            "Verify every platform run belongs to the fixed producer"
        )
        authority = authentication_names.index(
            "Verify candidate and source-conformance attestations without candidate code"
        )
        self.assertLess(provenance, authority)
        platform_authentication = authentication_names.index(
            "Independently authenticate and validate every signed platform capture"
        )
        authority_handoff = authentication_names.index(
            "Retain the fixed authenticated cloud-capture closure for the signer"
        )
        self.assertLess(authority, platform_authentication)
        self.assertLess(platform_authentication, authority_handoff)

        finalizer_names = [item.get("name", "") for item in steps(value, "finalize")]
        finalization = finalizer_names.index(
            "Verify and finalize the five signed cloud captures"
        )
        unsigned = finalizer_names.index(
            "Retain the unsigned cloud-deployments domain for a fresh attestation runner"
        )
        self.assertLess(finalization, unsigned)

        attestation_names = [
            item.get("name", "") for item in steps(value, "attest")
        ]
        fixed_validation = attestation_names.index(
            "Validate the complete cloud-deployments document without candidate code"
        )
        closure_comparison = attestation_names.index(
            "Compare final claims with the independently authenticated capture closure"
        )
        attestation = attestation_names.index(
            "Attest the finalized cloud-deployments domain"
        )
        retained = attestation_names.index(
            "Retain only the authenticated cloud-deployment domain"
        )
        self.assertLess(fixed_validation, closure_comparison)
        self.assertLess(closure_comparison, attestation)
        self.assertLess(attestation, retained)
        self.assertFalse(
            any(
                item.get("uses", "").startswith("actions/checkout@")
                for item in authentication["steps"] + attestation_job["steps"]
            )
        )
        self.assertNotIn("scripts/", str(attestation_job))

        authentication_step = authentication["steps"][platform_authentication]
        authentication_python = embedded_python(authentication_step["run"])
        signer_step = attestation_job["steps"][closure_comparison]
        signer_python = embedded_python(signer_step["run"])
        for required in (
            "signed archive entry closure is invalid",
            "latchway_authenticated_deployment_capture",
            "raw capture closure is incomplete",
            "migration semantics are invalid",
            "Compose deployment semantics are invalid",
            "Cloud Run deployment semantics are invalid",
            "AWS deployment semantics are invalid",
            "Fly.io deployment semantics are invalid",
            "Cloudflare Containers deployment semantics are invalid",
            "latchway_authenticated_cloud_capture_closure",
        ):
            self.assertIn(required, authentication_python)
        for required in (
            "final cloud claims are not derived from the authenticated platform set",
            "final artifact hash is not authenticated",
            "candidate attestation summary does not match independent verification",
            "latchway_authenticated_cloud_capture_closure",
        ):
            self.assertIn(required, signer_python)
        self.assertNotIn("gh ", signer_step["run"])
        self.assertNotIn("scripts/", signer_step["run"])

        text = (WORKFLOWS / "cloud-deployment-aggregate.yml").read_text(encoding="utf-8")
        for platform in ("compose", "cloud_run", "aws", "fly_io", "cloudflare_containers"):
            self.assertIn(f"latchway-deployment-{platform}-${{{{ inputs.candidate_commit }}}}", text)
            self.assertIn(f"verify_run {platform}", text)
        for required in (
            'expected_workflow="${4:-.github/workflows/deployment-evidence.yml}"',
            ".github/workflows/cross-repository-conformance.yml",
            ".github/workflows/release.yml",
            "gh attestation trusted-root",
            'gh attestation verify "$archive"',
            "latchway-cloud-capture-authority-${{ inputs.candidate_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
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
        self.assertEqual(set(value["jobs"]), {"authenticate", "aggregate", "attest"})
        authentication = value["jobs"]["authenticate"]
        aggregate = value["jobs"]["aggregate"]
        attestation = value["jobs"]["attest"]
        self.assertEqual(authentication.get("environment"), "release-evidence")
        self.assertEqual(attestation.get("environment"), "release-evidence-signing")
        self.assertEqual(authentication.get("if"), "github.ref == 'refs/heads/main'")
        self.assertEqual(aggregate.get("needs"), "authenticate")
        self.assertEqual(set(attestation.get("needs", [])), {"authenticate", "aggregate"})
        self.assertNotIn("id-token", authentication["permissions"])
        self.assertNotIn("id-token", aggregate["permissions"])
        self.assertEqual(attestation["permissions"]["id-token"], "write")
        assert_pinned(self, value)

        authentication_names = [
            item.get("name", "") for item in steps(value, "authenticate")
        ]
        provenance = authentication_names.index(
            "Verify every domain run belongs to its fixed producer"
        )
        attestations = authentication_names.index(
            "Verify every exact domain attestation"
        )
        self.assertLess(provenance, attestations)

        aggregate_names = [item.get("name", "") for item in steps(value, "aggregate")]
        union = aggregate_names.index(
            "Build collision-free hash-bound evidence union without credentials or OIDC"
        )
        unsigned = aggregate_names.index(
            "Retain the unsigned aggregate for a fresh attestation runner"
        )
        self.assertLess(union, unsigned)

        attestation_names = [item.get("name", "") for item in steps(value, "attest")]
        fixed_validation = attestation_names.index(
            "Validate the complete aggregate manifest without candidate code"
        )
        aggregate_attestation = attestation_names.index(
            "Attest the exact aggregate manifest"
        )
        upload = attestation_names.index(
            "Retain only the authenticated release-evidence aggregate"
        )
        self.assertLess(fixed_validation, aggregate_attestation)
        self.assertLess(aggregate_attestation, upload)
        serialized = str(attestation)
        for marker in (
            "Download the original authority-authenticated domains without a checkout",
            "authenticated-domain-union.tsv",
            'cmp --silent "$identity" "$RUNNER_TEMP/aggregate-identity.json"',
            'cmp --silent "$expected_union" "$manifest_union"',
            "$domain.attestation.sigstore.json",
        ):
            self.assertIn(marker, serialized)
        self.assertFalse(
            any(
                item.get("uses", "").startswith("actions/checkout@")
                for item in authentication["steps"] + attestation["steps"]
            )
        )
        self.assertNotIn("scripts/", str(attestation))

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
        authority = value["jobs"]["authenticate-inputs"]
        names = [item.get("name", "") for item in steps(value, "authenticate-inputs")]
        run_provenance = names.index("Verify the fixed authenticated aggregate producer run")
        download = names.index("Download independently produced external evidence")
        attestations = names.index("Verify protected producer attestations for release-domain documents")
        self.assertLess(run_provenance, download)
        self.assertLess(download, attestations)
        self.assertLess(
            attestations,
            names.index("Retain only authenticated inputs for candidate-code execution"),
        )
        evidence = value["jobs"]["evidence"]
        self.assertEqual(evidence["needs"], "authenticate-inputs")
        evidence_names = [item.get("name", "") for item in steps(value, "evidence")]
        self.assertLess(
            evidence_names.index("Download authenticated conformance inputs"),
            evidence_names.index("Produce source or release evidence"),
        )
        self.assertNotIn("secrets.", str(evidence))
        self.assertFalse(
            any(
                item.get("uses", "").startswith("actions/checkout@")
                for item in authority["steps"] + evidence["steps"]
            )
        )

        text = (WORKFLOWS / "cross-repository-conformance.yml").read_text(encoding="utf-8")
        for required in (
            'name: latchway-v1-external-evidence-${{ inputs.external_evidence_run_id }}-${{ inputs.external_evidence_run_attempt }}',
            '.path == ".github/workflows/aggregate-release-evidence.yml"',
            "aggregate-manifest.attestation.sigstore.json",
            "domains=(live_sdk_conformance physical_devices live_provider cloud_deployments operational_resilience supply_chain)",
            "signer=.github/workflows/cloud-deployment-aggregate.yml",
            "signer=.github/workflows/operational-resilience-evidence.yml",
            "--signer-digest \"$CANDIDATE_COMMIT\"",
            "--source-digest \"$CANDIDATE_COMMIT\"",
            "--deny-self-hosted-runners",
            "source-archives.sha256",
            "LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN",
        ):
            self.assertIn(required, text)
        self.assertNotIn("continue-on-error", text)


if __name__ == "__main__":
    unittest.main()
