#!/usr/bin/env python3

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/finalize-single-maintainer-profile.yml"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def load() -> dict:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("workflow must be an object")
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


class FinalizeSingleMaintainerProfileWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load()
        self.jobs = self.workflow["jobs"]
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.attestor = "\n".join(
            step.get("run", "") for step in self.jobs["attest"]["steps"]
        )

    def test_inputs_bind_only_exact_required_authenticated_publications(self) -> None:
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            set(inputs),
            {
                "candidate_commit",
                "source_run_id",
                "source_run_attempt",
                "candidate_run_id",
                "candidate_run_attempt",
                "core_release_run_id",
                "core_release_run_attempt",
                "public_tags_run_id",
                "public_tags_run_attempt",
                "public_registries_run_id",
                "public_registries_run_attempt",
                "supply_chain_run_id",
                "supply_chain_run_attempt",
            },
        )
        self.assertTrue(all(item["required"] for item in inputs.values()))
        for deferred in (
            "aws",
            "fly",
            "cloudflare",
            "mintlify",
            "device",
            "provider",
            "resilience",
            "review",
        ):
            self.assertNotIn(f"{deferred}_run_id", inputs)

    def test_authentication_evaluation_and_fresh_attestation_are_isolated(self) -> None:
        self.assertEqual(set(self.jobs), {"authenticate", "evaluate", "attest"})
        self.assertEqual(self.jobs["authenticate"]["environment"], "release-evidence-signing")
        self.assertEqual(self.jobs["attest"]["environment"], "release-evidence-signing")
        self.assertNotIn("environment", self.jobs["evaluate"])
        self.assertEqual(self.jobs["evaluate"]["needs"], "authenticate")
        self.assertEqual(set(self.jobs["attest"]["needs"]), {"authenticate", "evaluate"})
        for name in ("authenticate", "evaluate"):
            self.assertFalse(
                any(value == "write" for value in self.jobs[name]["permissions"].values()),
                name,
            )
            self.assertNotIn("id-token", self.jobs[name]["permissions"])
        self.assertEqual(self.jobs["attest"]["permissions"]["id-token"], "write")
        for name in ("authenticate", "attest"):
            self.assertFalse(
                any(
                    step.get("uses", "").startswith("actions/checkout@")
                    for step in self.jobs[name]["steps"]
                ),
                name,
            )
        self.assertNotIn("scripts/", str(self.jobs["attest"]))

    def test_profile_signers_require_exact_profile_sentinel_first(self) -> None:
        expected = (
            "latchway-release-profile-v1:latchway:single_maintainer_v1:"
            "release-evidence-signing"
        )
        for name in ("authenticate", "attest"):
            first = self.jobs[name]["steps"][0]
            self.assertEqual(
                first["name"],
                "Verify the exact single-maintainer release-evidence-signing policy",
            )
            self.assertEqual(
                first["env"]["OBSERVED_POLICY_ID"],
                "${{ vars.LATCHWAY_RELEASE_PROFILE_POLICY_ID }}",
            )
            self.assertEqual(
                first["run"].splitlines(),
                ["set -Eeuo pipefail", f'test "$OBSERVED_POLICY_ID" = "{expected}"'],
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

    def test_profile_does_not_reuse_or_weaken_strict_aggregators(self) -> None:
        for strict_workflow in (
            "aggregate-release-evidence.yml",
            "cloud-deployment-aggregate.yml",
            "finalize-release-record.yml",
            "promote-release.yml",
        ):
            self.assertNotIn(strict_workflow, self.text)
        self.assertIn("scripts/release-profile.py evaluate --profile single_maintainer_v1", self.text)
        self.assertIn("scripts/finalize-release-profile.py finalize", self.text)
        self.assertIn('test "$status" = 1', self.text)
        self.assertIn('.release_ready == false', self.text)

    def test_all_required_producers_and_exact_attempts_are_authenticated(self) -> None:
        for path in (
            ".github/workflows/cross-repository-conformance.yml",
            ".github/workflows/release.yml",
            ".github/workflows/single-maintainer-release.yml",
            ".github/workflows/release-domain-evidence.yml",
            ".github/workflows/deployment-evidence.yml",
        ):
            self.assertIn(path, self.text)
        self.assertIn("/attempts/$attempt", self.text)
        self.assertIn("require_certificate_identity", self.text)
        self.assertIn(".signature.certificate", self.text)
        self.assertIn("$certificate.runInvocationURI", self.text)
        self.assertNotIn(".predicate.runDetails.metadata.invocationId", self.text)
        for field in (
            "buildSignerURI",
            "buildSignerDigest",
            "sourceRepositoryDigest",
            "sourceRepositoryRef",
            "runnerEnvironment",
        ):
            self.assertIn(field, self.text)
        self.assertIn("--deny-self-hosted-runners", self.text)
        self.assertIn('--source-digest "$CANDIDATE_COMMIT"', self.text)
        self.assertIn('--signer-digest "$CANDIDATE_COMMIT"', self.text)
        for subject in (
            "latchway-cross-repository.json",
            "latchway-candidate.json",
            "latchway-single-maintainer-v1.json",
            "compose.tar.gz",
            "cloud_run.tar.gz",
            "public_tags.json",
            "public_registries.json",
            "supply_chain.json",
        ):
            self.assertIn(subject, self.text)

    def test_final_decision_keeps_every_deferred_and_forbidden_claim_explicit(self) -> None:
        attestor = self.attestor
        for marker in (
            '"v1_profile_publication_ready_with_deferred_assurance"',
            '.release_qualified == false',
            '.fully_evidence_gated == false',
            '.independently_reviewed == false',
            '"independent_human_review"',
            '"live_sdk_conformance"',
            '"physical_devices"',
            '"live_provider"',
            '"cloud_deployments.aws_verified"',
            '"cloud_deployments.fly_io_verified"',
            '"cloud_deployments.cloudflare_containers_verified"',
            '"operational_resilience"',
            '"public_registries.documentation_production_verified"',
            '"mintlify_production"',
        ):
            self.assertIn(marker, attestor)
        self.assertIn(
            '["cocoapods_verified","maven_central_verified","npm_javascript_verified","npm_react_native_verified","oci_digest_verified","swift_package_verified"]',
            attestor,
        )
        self.assertIn(
            '.claims == {cloud_run_verified:true,compose_verified:true}', attestor
        )

    def test_final_handoff_retains_and_rehashes_all_selected_external_documents(self) -> None:
        attestor = self.attestor
        for domain in (
            "cloud_deployments",
            "public_registries",
            "public_tags",
            "supply_chain",
        ):
            self.assertIn(f"external/{domain}.json", self.text)
            self.assertIn(f"external_{domain}", attestor)
        self.assertIn("sha256sum --strict --check SHA256SUMS", attestor)
        self.assertIn("test \"$input_count\" = 6", attestor)
        self.assertIn("latchway-cross-repository-release-strict.json", attestor)
        self.assertIn("latchway-single-maintainer-v1-profile-input.json", attestor)

    def test_raw_strict_failure_and_only_profile_local_transformation_are_closed(self) -> None:
        for marker in (
            '.scope == "release" and .verdict == "failed"',
            '.promotion_ready == false and .release_ready == false',
            '.evidence_window == null',
            'reason:"prerequisite_evidence_failed"',
            '"external_evidence_claims_invalid"',
            '"external_evidence_missing"',
            'reconstructed-profile-input.json',
            'select(.id == "local_promotion") | .status',
            'cmp --silent "$profile_report"',
            '.evidence_domains == $domains[0] and .checks == $checks[0]',
        ):
            self.assertIn(marker, self.attestor)

    def test_gate_objects_and_projection_are_exactly_reconstructed(self) -> None:
        for marker in (
            'source:"cross_repository_release_report"',
            'source:"external_evidence_document"',
            'source:"external_evidence_documents"',
            'required_claims:$required',
            'observed_claims:$required',
            'document_sha256:$sha',
            'artifact_sha256:',
            '.required_gates == $gates[0]',
            '.deferred_evidence == $deferred[0]',
            '.status_claim == "v1_profile_projection_passed_with_deferred_assurance"',
            '.profile_requirements_satisfied == true',
        ):
            self.assertIn(marker, self.attestor)

    def test_projection_policy_rejects_nested_gate_provenance_injection(self) -> None:
        section = self.attestor.split("# BEGIN PROFILE_PROJECTION_POLICY\n", 1)[1]
        policy = section.split("<<'JQ' || true\n", 1)[1].split("\nJQ\n", 1)[0]
        commit = "a" * 40
        image = "ghcr.io/latchway/latchway@sha256:" + "b" * 64
        gates = [
            {
                "id": "local_source",
                "status": "passed",
                "source": "cross_repository_release_report",
            }
        ]
        deferred = [
            {
                "id": "physical_devices",
                "status": "unverified",
                "source": "release_profile_policy",
                "reason": "deferred_by_profile",
            }
        ]
        projection = {
            "schema_version": 1,
            "kind": "latchway_release_profile_evaluation",
            "evaluation_scope": "cross_repository_publication_profile",
            "profile": "single_maintainer_v1",
            "status": "passed",
            "status_claim": "v1_profile_projection_passed_with_deferred_assurance",
            "profile_requirements_satisfied": True,
            "authentication_status": "not_performed",
            "publication_ready": False,
            "strict_cross_repository_ready": False,
            "release_qualified": False,
            "requires_independent_human_review": False,
            "candidate": {
                "core_commit": commit,
                "release_tag": "v1.0.0",
                "oci_image_digest": image,
            },
            "required_gates": gates,
            "deferred_evidence": deferred,
            "forbidden_claims": [
                "release_qualified",
                "fully_evidence_gated",
                "independently_reviewed",
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate_path = root / "gates.json"
            deferred_path = root / "deferred.json"
            gate_path.write_text(json.dumps(gates), encoding="utf-8")
            deferred_path.write_text(json.dumps(deferred), encoding="utf-8")
            command = [
                "jq",
                "--exit-status",
                "--arg",
                "commit",
                commit,
                "--arg",
                "image",
                image,
                "--slurpfile",
                "gates",
                str(gate_path),
                "--slurpfile",
                "deferred",
                str(deferred_path),
                policy,
            ]
            accepted = subprocess.run(
                command, input=json.dumps(projection), text=True, capture_output=True
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            projection["required_gates"][0]["details"] = {
                "forged_provenance": True
            }
            rejected = subprocess.run(
                command, input=json.dumps(projection), text=True, capture_output=True
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_certificate_policy_rejects_wrong_run_attempt_even_with_forged_predicate(self) -> None:
        section = self.attestor.split("# BEGIN CERTIFICATE_IDENTITY_POLICY\n", 1)[1]
        policy = section.split("<<'JQ' || true\n", 1)[1].split("\nJQ\n", 1)[0]
        repository = "Latchway/latchway"
        commit = "a" * 40
        workflow = ".github/workflows/release-domain-evidence.yml"
        signer = f"https://github.com/{repository}/{workflow}@refs/heads/main"
        expected_run = f"https://github.com/{repository}/actions/runs/123/attempts/1"
        certificate = {
            "issuer": "https://token.actions.githubusercontent.com",
            "subjectAlternativeName": signer,
            "githubWorkflowRepository": repository,
            "githubWorkflowRef": "refs/heads/main",
            "githubWorkflowTrigger": "workflow_dispatch",
            "buildSignerURI": signer,
            "buildSignerDigest": commit,
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": f"https://github.com/{repository}",
            "sourceRepositoryDigest": commit,
            "sourceRepositoryRef": "refs/heads/main",
            "buildConfigURI": signer,
            "buildConfigDigest": commit,
            "buildTrigger": "workflow_dispatch",
            "runInvocationURI": expected_run,
            "sourceRepositoryVisibilityAtSigning": "public",
        }
        fixture = [
            {
                "verificationResult": {
                    "signature": {"certificate": certificate},
                    "statement": {
                        "predicate": {
                            "runDetails": {
                                "metadata": {"invocationId": expected_run}
                            }
                        }
                    },
                }
            }
        ]
        command = [
            "jq",
            "--exit-status",
            "--arg",
            "expected_run",
            expected_run,
            "--arg",
            "expected_signer",
            signer,
            "--arg",
            "repository",
            repository,
            "--arg",
            "expected_repository",
            f"https://github.com/{repository}",
            "--arg",
            "commit",
            commit,
            policy,
        ]
        accepted = subprocess.run(
            command, input=json.dumps(fixture), text=True, capture_output=True
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        certificate["runInvocationURI"] = (
            f"https://github.com/{repository}/actions/runs/123/attempts/2"
        )
        rejected = subprocess.run(
            command, input=json.dumps(fixture), text=True, capture_output=True
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_source_free_json_policy_rejects_duplicate_and_noncanonical_bytes(self) -> None:
        section = self.attestor.split("# BEGIN FINALIZATION_CANONICAL_JSON_POLICY\n", 1)[1]
        script = section.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        final_names = {
            "authority.json",
            "external/cloud_deployments.json",
            "external/public_registries.json",
            "external/public_tags.json",
            "external/supply_chain.json",
            "latchway-cross-repository-release-strict.json",
            "latchway-single-maintainer-v1-final.json",
            "latchway-single-maintainer-v1-profile-input.json",
            "latchway-single-maintainer-v1-projection.json",
        }
        authenticated_names = {
            "source/latchway-cross-repository.json",
            "core/latchway-candidate.json",
            "core/latchway-single-maintainer-v1.json",
            "public_tags/public_tags.json",
            "public_registries/public_registries.json",
            "supply_chain/supply_chain.json",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            final = root / "final"
            authenticated = root / "authenticated"
            canonical = json.dumps({}, indent=2, sort_keys=True) + "\n"
            for base, names in ((final, final_names), (authenticated, authenticated_names)):
                for name in names:
                    path = base / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(canonical, encoding="utf-8")
            command = [sys.executable, "-", str(final), str(authenticated)]
            accepted = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            target = final / "latchway-single-maintainer-v1-final.json"
            target.write_text('{"status":false,"status":true}\n', encoding="utf-8")
            duplicate = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(duplicate.returncode, 0)
            target.write_text('{"status": true}\n', encoding="utf-8")
            noncanonical = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(noncanonical.returncode, 0)

    def test_source_free_time_policy_rejects_stale_selected_evidence(self) -> None:
        section = self.attestor.split("# BEGIN FINALIZATION_EVIDENCE_TIME_POLICY\n", 1)[1]
        script = section.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        now = datetime.now(timezone.utc).replace(microsecond=0)

        def stamp(value: datetime) -> str:
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            final = root / "final"
            source = root / "source.json"
            def write(path: Path, value: object) -> None:
                path.write_text(json.dumps(value), encoding="utf-8")
            source.write_text(
                json.dumps({"contract": {"released_at": stamp(now - timedelta(days=2))}}),
                encoding="utf-8",
            )
            for domain in (
                "cloud_deployments",
                "public_registries",
                "public_tags",
                "supply_chain",
            ):
                path = final / "external" / f"{domain}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                write(
                    path,
                    {
                        "started_at": stamp(now - timedelta(hours=1)),
                        "finished_at": stamp(now - timedelta(minutes=30)),
                    },
                )
            command = [sys.executable, "-", str(final), str(source)]
            accepted = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            stale = final / "external/public_tags.json"
            write(
                stale,
                {
                    "started_at": stamp(now - timedelta(days=8, minutes=1)),
                    "finished_at": stamp(now - timedelta(days=8)),
                },
            )
            rejected = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_trusted_workflow_oidc_job_environment_closure_is_behavioral(self) -> None:
        marker = "# jobs/environments that can request OIDC in every trusted workflow.\n"
        section = self.attestor.split(marker, 1)[1]
        script = section.split("<<'RUBY'\n", 1)[1].split("\nRUBY\n", 1)[0]
        names = (
            "cross-repository-conformance.yml",
            "release.yml",
            "single-maintainer-release.yml",
            "release-domain-evidence.yml",
            "finalize-single-maintainer-profile.yml",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in names:
                shutil.copyfile(ROOT / ".github/workflows" / name, root / name)
            command = ["ruby", "-", str(root)]
            accepted = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            producer = root / "release-domain-evidence.yml"
            producer.write_text(
                producer.read_text(encoding="utf-8")
                + "\n  impostor-sign:\n    environment: deployment-evidence-signing\n"
                + "    permissions:\n      id-token: write\n",
                encoding="utf-8",
            )
            rejected = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(rejected.returncode, 0)

            producer.write_text(
                (ROOT / ".github/workflows/release-domain-evidence.yml").read_text(
                    encoding="utf-8"
                )
                + '\n  "impostor-sign":\n'
                + "    environment: deployment-evidence-signing\n"
                + "    permissions:\n      id-token: write\n",
                encoding="utf-8",
            )
            quoted_key = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(quoted_key.returncode, 0)

            producer.write_text(
                (ROOT / ".github/workflows/release-domain-evidence.yml").read_text(
                    encoding="utf-8"
                )
                + "\njobs:\n  impostor-sign:\n"
                + "    environment: deployment-evidence-signing\n"
                + "    permissions:\n      id-token: write\n",
                encoding="utf-8",
            )
            duplicate_jobs = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(duplicate_jobs.returncode, 0)

            producer.write_text(
                (ROOT / ".github/workflows/release-domain-evidence.yml").read_text(
                    encoding="utf-8"
                )
                + "\n  benign:\n    env: &oidc_permissions\n"
                + "      id-token: write\n  impostor-sign:\n"
                + "    environment: deployment-evidence-signing\n"
                + "    permissions: *oidc_permissions\n",
                encoding="utf-8",
            )
            alias_permissions = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(alias_permissions.returncode, 0)

            producer.write_text(
                (ROOT / ".github/workflows/release-domain-evidence.yml").read_text(
                    encoding="utf-8"
                )
                + "\n  impostor-sign:\n"
                + "    environment: deployment-evidence-signing\n"
                + '    permissions:\n      "id\\u002dtoken": write\n',
                encoding="utf-8",
            )
            escaped_permission = subprocess.run(
                command, input=script, text=True, capture_output=True
            )
            self.assertNotEqual(escaped_permission.returncode, 0)

    def test_profile_release_domains_are_explicitly_scoped(self) -> None:
        for path in (
            ROOT / ".github/workflows/release-domain-observations.yml",
            ROOT / ".github/workflows/release-domain-evidence.yml",
        ):
            text = path.read_text(encoding="utf-8")
            value = yaml.safe_load(text)
            if True in value and "on" not in value:
                value["on"] = value.pop(True)
            profile = value["on"]["workflow_dispatch"]["inputs"]["release_profile"]
            self.assertEqual(profile["default"], "strict_full")
            self.assertEqual(profile["options"], ["strict_full", "single_maintainer_v1"])
            self.assertIn("single_maintainer_v1:public_tags", text)
            self.assertIn("single_maintainer_v1:public_registries", text)
            self.assertIn("--release-profile single_maintainer_v1", text)


if __name__ == "__main__":
    unittest.main()
