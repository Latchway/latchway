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
    def test_candidate_gate_is_protected_fixed_and_candidate_bound(self) -> None:
        workflow = load_workflow("security.yml")
        dispatch = workflow["on"]["workflow_dispatch"]
        self.assertEqual(
            set(dispatch["inputs"]),
            {"candidate_commit", "intended_tag", "candidate_run_id"},
        )
        job = workflow["jobs"]["candidate"]
        self.assertEqual(
            job["if"],
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",
        )
        self.assertEqual(job["environment"], "security-evidence")
        self.assertEqual(job["permissions"]["attestations"], "write")
        self.assertEqual(job["permissions"]["id-token"], "write")
        names = [step.get("name", "") for step in steps(workflow, "candidate")]
        run_check = names.index("Require the exact successful candidate workflow run")
        attestation = names.index(
            "Verify the candidate attestation and complete artifact binding"
        )
        captures = names.index("Capture fixed current-candidate Go security commands")
        source_scan = names.index(
            "Capture current source vulnerability, secret, and static-policy output"
        )
        sealed = names.index(
            "Derive and independently reverify the redacted security summary"
        )
        summary_attested = names.index("Attest the exact redacted security summary")
        retained = names.index("Retain candidate-bound security evidence")
        self.assertLess(run_check, attestation)
        self.assertLess(attestation, captures)
        self.assertLess(captures, source_scan)
        self.assertLess(source_scan, sealed)
        self.assertLess(sealed, summary_attested)
        self.assertLess(summary_attested, retained)

        serialized = (WORKFLOWS / "security.yml").read_text(encoding="utf-8")
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        self.assertIn('test -z "$(git status --porcelain=v1 --untracked-files=all)"', serialized)
        self.assertIn('.path == ".github/workflows/release.yml"', serialized)
        self.assertIn("--signer-digest \"$CANDIDATE_COMMIT\"", serialized)
        self.assertIn("--source-digest \"$CANDIDATE_COMMIT\"", serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertIn("scripts/security-evidence.py", serialized)
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
        candidate = workflow["jobs"]["candidate"]
        final_upload = next(
            step
            for step in candidate["steps"]
            if step.get("name") == "Retain candidate-bound security evidence"
        )
        self.assertEqual(
            final_upload["with"]["name"],
            "latchway-security-${{ inputs.candidate_commit }}",
        )
        raw_upload = next(
            step
            for step in candidate["steps"]
            if step.get("name") == "Retain protected raw failure evidence"
        )
        self.assertEqual(raw_upload["if"], "always()")
        self.assertIn("github.run_id", raw_upload["with"]["name"])

    def test_promotion_reverifies_security_before_any_public_mutation(self) -> None:
        workflow = load_workflow("promote-release.yml")
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertIn("security_evidence_run_id", inputs)
        self.assertTrue(inputs["security_evidence_run_id"]["required"])
        job_steps = steps(workflow, "promote")
        names = [step.get("name", "") for step in job_steps]
        run_check = names.index("Require the fixed successful security workflow run")
        download = names.index("Download exact current-candidate security evidence")
        attestation = names.index("Verify candidate and promotion attestations")
        binding = names.index("Recompute exact current-candidate security evidence")
        first_mutation = names.index(
            "Promote only the verified index digest to stable OCI tags"
        )
        self.assertLess(run_check, download)
        self.assertLess(download, attestation)
        self.assertLess(attestation, binding)
        self.assertLess(binding, first_mutation)

        serialized = (WORKFLOWS / "promote-release.yml").read_text(encoding="utf-8")
        self.assertIn('.path == ".github/workflows/security.yml"', serialized)
        self.assertIn(
            "--signer-workflow \"$GITHUB_REPOSITORY/.github/workflows/security.yml\"",
            serialized,
        )
        self.assertIn("--signer-digest \"${{ inputs.candidate_commit }}\"", serialized)
        self.assertIn("--source-digest \"${{ inputs.candidate_commit }}\"", serialized)
        self.assertIn("latchway/scripts/security-evidence.py", serialized)
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
