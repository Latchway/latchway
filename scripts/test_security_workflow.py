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
    if True in value and "on" not in value:
        value["on"] = value.pop(True)
    return value


def steps(workflow: dict, job: str) -> list[dict]:
    return [step for step in workflow["jobs"][job]["steps"] if isinstance(step, dict)]


class SecurityWorkflowTests(unittest.TestCase):
    def test_license_exception_is_limited_to_wrangler_tooling(self) -> None:
        policy = yaml.safe_load(
            (ROOT / ".trivyignore.yaml").read_text(encoding="utf-8")
        )
        licenses = policy.get("licenses", [])
        self.assertEqual(len(licenses), 1)
        exception = licenses[0]
        self.assertEqual(exception["id"], "LGPL-3.0-or-later")
        self.assertEqual(
            set(exception["paths"]),
            {
                ".github/toolchains/wrangler/package-lock.json",
                "deploy/cloudflare/pnpm-lock.yaml",
            },
        )
        self.assertIn("tooling-only", exception["statement"])
        self.assertIn("never copied into or distributed", exception["statement"])

    def test_candidate_gate_is_protected_fixed_and_candidate_bound(self) -> None:
        workflow = load_workflow("security.yml")
        dispatch = workflow["on"]["workflow_dispatch"]
        self.assertEqual(
            set(dispatch["inputs"]),
            {
                "candidate_commit",
                "intended_tag",
                "candidate_run_id",
                "candidate_run_attempt",
                "promotion_evidence_run_id",
                "promotion_evidence_run_attempt",
                "independent_review_run_id",
                "independent_review_run_attempt",
            },
        )
        authentication = workflow["jobs"]["authenticate-candidate"]
        job = workflow["jobs"]["candidate"]
        attestation_job = workflow["jobs"]["candidate-attestation"]
        self.assertEqual(
            job["if"],
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",
        )
        self.assertEqual(authentication["environment"], "security-evidence")
        self.assertEqual(
            attestation_job["environment"], "release-evidence-signing"
        )
        self.assertEqual(authentication["needs"], "candidate-scans")
        self.assertEqual(job["needs"], "authenticate-candidate")
        self.assertEqual(attestation_job["needs"], "candidate")
        self.assertEqual(attestation_job["permissions"]["attestations"], "write")
        self.assertEqual(attestation_job["permissions"]["id-token"], "write")

        authentication_names = [
            step.get("name", "") for step in steps(workflow, "authenticate-candidate")
        ]
        run_check = authentication_names.index(
            "Authenticate exact candidate and promotion producer runs without candidate code"
        )
        review_run = authentication_names.index(
            "Authenticate the separately controlled independent-review producer"
        )
        review_download = authentication_names.index(
            "Download the exact independent-review artifact"
        )
        review_verify = authentication_names.index(
            "Verify the independent-review attestation before snapshotting"
        )
        promotion_verify = authentication_names.index(
            "Verify candidate and promotion attestations before snapshotting"
        )
        packaged = authentication_names.index(
            "Package only authenticated evidence for candidate validation"
        )
        self.assertLess(run_check, review_run)
        self.assertLess(review_run, review_download)
        self.assertLess(review_download, review_verify)
        self.assertLess(promotion_verify, review_verify)
        self.assertLess(review_verify, packaged)

        seal_names = [step.get("name", "") for step in steps(workflow, "candidate")]
        sealed = seal_names.index(
            "Snapshot, validate, seal, and reverify without credentials or OIDC"
        )
        sealed_upload = seal_names.index(
            "Retain the sealed candidate evidence for the fresh attestation runner"
        )
        self.assertLess(sealed, sealed_upload)

        attestation_names = [
            step.get("name", "") for step in steps(workflow, "candidate-attestation")
        ]
        coordinates = attestation_names.index(
            "Independently validate the authenticated closure and exact summary bytes without candidate code"
        )
        summary_attested = attestation_names.index(
            "Attest the exact redacted security summary"
        )
        retained = attestation_names.index("Retain candidate-bound security evidence")
        self.assertLess(coordinates, summary_attested)
        self.assertLess(summary_attested, retained)

        serialized = (WORKFLOWS / "security.yml").read_text(encoding="utf-8")
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        self.assertIn('test -z "$(git status --porcelain=v1 --untracked-files=all)"', serialized)
        self.assertIn('.path == ".github/workflows/release.yml"', serialized)
        self.assertIn("--signer-digest \"$CANDIDATE_COMMIT\"", serialized)
        self.assertIn("--source-digest \"$CANDIDATE_COMMIT\"", serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertIn("scripts/security-evidence.py", serialized)
        self.assertIn("--verify-review", serialized)
        self.assertIn("INDEPENDENT_SECURITY_REVIEW_TOKEN", serialized)
        self.assertIn("INDEPENDENT_SECURITY_REVIEW_REPOSITORY", serialized)
        self.assertIn("INDEPENDENT_SECURITY_REVIEW_WORKFLOW", serialized)
        self.assertIn("INDEPENDENT_SECURITY_REVIEWER_IDENTITY", serialized)
        self.assertIn("INDEPENDENT_SECURITY_REVIEWER_ORGANIZATION", serialized)
        self.assertIn("reviewer_identity: $reviewer_identity", serialized)
        self.assertIn("reviewer_organization: $reviewer_organization", serialized)
        self.assertIn("REVIEWER_IDENTITY=$(jq --exit-status --raw-output '.reviewer_identity", serialized)
        self.assertIn("REVIEWER_ORGANIZATION=$(jq --exit-status --raw-output '.reviewer_organization", serialized)
        self.assertNotIn("REVIEWER_IDENTITY=$(jq --exit-status --raw-output '.reviewer.identity", serialized)
        self.assertIn("INDEPENDENT_SECURITY_REVIEWER_LOGIN", serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertIn("test \"${owner,,}\" != latchway", serialized)
        self.assertIn("test \"${REVIEWER_ORGANIZATION,,}\" != latchway", serialized)
        self.assertIn("--review-directory \"$inputs/independent-review\"", serialized)
        self.assertIn("--promotion-directory \"$inputs/promotion-conformance\"", serialized)
        self.assertIn("--promotion-run-id \"$PROMOTION_RUN_ID\"", serialized)
        self.assertIn(".actor.login == $login", serialized)
        self.assertIn(".triggering_actor.login == $login", serialized)
        for check in (
            "source_go_vulnerability",
            "source_static_analysis",
            "source_fuzz_smoke",
            "source_race",
        ):
            self.assertIn(check, serialized)
        self.assertIn("scanners: vuln,secret,misconfig", serialized)
        self.assertIn("scanners: license", serialized)
        self.assertNotIn("continue-on-error", serialized)
        self.assertNotIn("external_status", serialized)
        self.assertNotIn("claims:", serialized)

    def test_branch_and_scheduled_scans_cannot_be_substituted_for_candidate(self) -> None:
        workflow = load_workflow("security.yml")
        self.assertEqual(workflow["jobs"]["source"]["if"], "github.event_name != 'workflow_dispatch'")
        self.assertEqual(workflow["jobs"]["container"]["if"], "github.event_name != 'workflow_dispatch'")
        authentication = workflow["jobs"]["authenticate-candidate"]
        candidate = workflow["jobs"]["candidate"]
        attestation = workflow["jobs"]["candidate-attestation"]
        scans = workflow["jobs"]["candidate-scans"]
        final_upload = next(
            step
            for step in attestation["steps"]
            if step.get("name") == "Retain candidate-bound security evidence"
        )
        self.assertEqual(
            final_upload["with"]["name"],
            "latchway-security-${{ inputs.candidate_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        raw_upload = next(
            step
            for step in scans["steps"]
            if step.get("name") == "Retain protected raw failure evidence"
        )
        self.assertEqual(raw_upload["if"], "always()")
        self.assertIn("github.run_id", raw_upload["with"]["name"])
        self.assertEqual(authentication["needs"], "candidate-scans")
        self.assertEqual(candidate["needs"], "authenticate-candidate")
        self.assertEqual(attestation["needs"], "candidate")

    def test_candidate_credentials_are_isolated_from_candidate_execution(self) -> None:
        workflow = load_workflow("security.yml")
        scans = workflow["jobs"]["candidate-scans"]
        authentication = workflow["jobs"]["authenticate-candidate"]
        seal = workflow["jobs"]["candidate"]
        attestation = workflow["jobs"]["candidate-attestation"]

        self.assertNotIn("environment", scans)
        self.assertNotIn("id-token", scans["permissions"])
        self.assertNotIn("attestations", scans["permissions"])
        self.assertEqual(authentication["environment"], "security-evidence")
        self.assertNotIn("id-token", authentication["permissions"])
        self.assertNotIn("attestations", authentication["permissions"])
        self.assertNotIn("environment", seal)
        self.assertNotIn("id-token", seal["permissions"])
        self.assertNotIn("attestations", seal["permissions"])
        self.assertEqual(attestation["permissions"]["id-token"], "write")
        self.assertEqual(attestation["permissions"]["attestations"], "write")

        checkout = next(
            step for step in seal["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        self.assertFalse(checkout["with"]["persist-credentials"])

        credential_steps = {
            "Authenticate exact candidate and promotion producer runs without candidate code",
            "Authenticate the separately controlled independent-review producer",
            "Download the exact candidate artifact",
            "Download the exact promotion-scope conformance artifact",
            "Download the exact independent-review artifact",
            "Verify candidate and promotion attestations before snapshotting",
            "Verify the independent-review attestation before snapshotting",
        }
        forbidden_candidate_commands = (
            "python3 scripts/",
            "python scripts/",
            "make ",
            "go run ",
            "go test ",
            "pnpm ",
            "npm ",
        )
        for step in authentication["steps"]:
            if step.get("name") not in credential_steps:
                continue
            command = str(step.get("run", ""))
            for forbidden in forbidden_candidate_commands:
                self.assertNotIn(forbidden, command, step.get("name"))

        tokenless = next(
            step
            for step in seal["steps"]
            if step.get("name")
            == "Snapshot, validate, seal, and reverify without credentials or OIDC"
        )
        tokenless_serialized = str(tokenless)
        self.assertIn('test -z "${GH_TOKEN:-}"', tokenless["run"])
        self.assertIn('test -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}"', tokenless["run"])
        self.assertNotIn("secrets.", tokenless_serialized)
        self.assertNotIn("github.token", tokenless_serialized)

        self.assertFalse(
            any(
                str(step.get("uses", "")).startswith("actions/checkout@")
                for step in attestation["steps"]
            )
        )
        attestation_serialized = str(attestation)
        for forbidden in forbidden_candidate_commands:
            self.assertNotIn(forbidden, attestation_serialized)

    def test_promotion_reverifies_security_before_any_public_mutation(self) -> None:
        workflow = load_workflow("promote-release.yml")
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertIn("security_evidence_run_id", inputs)
        self.assertTrue(inputs["security_evidence_run_id"]["required"])
        self.assertIn("security_evidence_run_attempt", inputs)
        self.assertTrue(inputs["security_evidence_run_attempt"]["required"])
        authority = workflow["jobs"]["authenticate-inputs"]
        candidate = workflow["jobs"]["candidate-gates"]
        planner = workflow["jobs"]["plan-promotion"]
        stage = workflow["jobs"]["stage-github-release"]
        oci = workflow["jobs"]["promote-oci"]
        publisher = workflow["jobs"]["publish-github-release"]
        self.assertEqual(candidate["needs"], "authenticate-inputs")
        self.assertEqual(
            set(planner["needs"]),
            {"authenticate-inputs", "candidate-gates", "immutable-release-settings"},
        )
        authority_names = [step.get("name", "") for step in authority["steps"]]
        run_check = authority_names.index(
            "Authenticate exact producer runs without candidate code"
        )
        download = authority_names.index(
            "Download exact current-candidate security evidence"
        )
        attestation = authority_names.index(
            "Verify top-level and nested Latchway attestations without candidate code"
        )
        independent = authority_names.index(
            "Verify nested independent-review attestation on the credential-isolated runner"
        )
        packaged = authority_names.index(
            "Package exact candidate source objects without a checkout"
        )
        planner_names = [step.get("name", "") for step in planner["steps"]]
        binding = planner_names.index(
            "Verify exact candidate security and aggregate bindings without source"
        )
        handoff = planner_names.index("Build the exact source-free mutation handoff")
        stage_names = [step.get("name", "") for step in stage["steps"]]
        stage_validation = stage_names.index(
            "Validate exact closure hashes and attestations before any GitHub mutation"
        )
        first_stage_mutation = stage_names.index(
            "Create the evidence-gated annotated core tag"
        )
        oci_names = [step.get("name", "") for step in oci["steps"]]
        oci_validation = oci_names.index(
            "Validate exact closure hashes attestations tag and draft before registry authentication"
        )
        first_oci_mutation = oci_names.index(
            "Promote only the verified index digest to stable OCI tags"
        )
        publisher_names = [step.get("name", "") for step in publisher["steps"]]
        publisher_validation = publisher_names.index(
            "Validate exact closure hashes and attestations before release publication"
        )
        first_publication = publisher_names.index("Publish the immutable release record")
        self.assertLess(run_check, download)
        self.assertLess(download, attestation)
        self.assertLess(attestation, independent)
        self.assertLess(independent, packaged)
        self.assertLess(binding, handoff)
        self.assertLess(stage_validation, first_stage_mutation)
        self.assertLess(oci_validation, first_oci_mutation)
        self.assertLess(publisher_validation, first_publication)
        self.assertFalse(
            any(
                str(step.get("uses", "")).startswith("actions/checkout@")
                for job in (authority, planner, stage, oci, publisher)
                for step in job["steps"]
            )
        )
        self.assertNotIn("id-token", candidate["permissions"])
        self.assertNotIn("secrets.", str(candidate))

        serialized = (WORKFLOWS / "promote-release.yml").read_text(encoding="utf-8")
        self.assertIn(".path == $path and .state == \"active\"", serialized)
        self.assertIn(
            'verify_run security "$SECURITY_RUN_ID" "$SECURITY_RUN_ATTEMPT" .github/workflows/security.yml',
            serialized,
        )
        self.assertIn(
            "--signer-workflow \"$GITHUB_REPOSITORY/.github/workflows/security.yml\"",
            serialized,
        )
        self.assertIn("--signer-digest \"${{ inputs.candidate_commit }}\"", serialized)
        self.assertIn("--source-digest \"${{ inputs.candidate_commit }}\"", serialized)
        self.assertIn("latchway/scripts/security-evidence.py", serialized)
        self.assertIn(
            '--review-directory "$root/latchway-security/independent-review"',
            serialized,
        )
        self.assertIn('"$SECURITY_DIR/security-summary.json"', serialized)
        self.assertIn(
            '"$SECURITY_DIR/security-summary.attestation.sigstore.json"', serialized
        )
        self.assertNotIn("security_evidence_artifact", serialized)

    def test_security_workflow_actions_are_commit_pinned(self) -> None:
        workflow = load_workflow("security.yml")
        for job in workflow["jobs"]:
            for step in steps(workflow, job):
                action = step.get("uses")
                if action is not None:
                    self.assertRegex(action, PINNED_ACTION, f"{job}: {action}")


if __name__ == "__main__":
    unittest.main()
