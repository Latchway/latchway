#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
PINNED_BUILDX_VERSION = "v0.36.1"
PINNED_BUILDKIT_IMAGE = (
    "docker.io/moby/buildkit@"
    "sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
)
PINNED_BINFMT_IMAGE = (
    "docker.io/tonistiigi/binfmt@"
    "sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
)


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
    def test_every_managed_environment_consumer_asserts_exact_sentinel_first(
        self,
    ) -> None:
        manifest = json.loads(
            (ROOT / ".github/release-controls.json").read_text(encoding="utf-8")
        )
        core = next(
            repository
            for repository in manifest["repositories"]
            if repository["name"] == "latchway"
        )
        policies = {
            environment["name"]: environment["policy_id"]
            for environment in core["environments"]
        }
        self.assertEqual(len(policies), 22)
        declared_secrets = {
            environment["name"]: set(environment["secrets"]["allowed_names"])
            for environment in core["environments"]
        }
        self.assertEqual(
            declared_secrets,
            {
                environment["name"]: set(
                    environment["secrets"]["required_names"]
                )
                for environment in core["environments"]
            },
        )
        declared_variables = {
            environment["name"]: set(
                environment.get("variables", {"allowed_names": []})[
                    "allowed_names"
                ]
            )
            for environment in core["environments"]
        }
        self.assertEqual(
            declared_variables,
            {
                environment["name"]: set(
                    environment.get("variables", {"required_names": []})[
                        "required_names"
                    ]
                )
                for environment in core["environments"]
            },
        )
        consumers = {name: [] for name in policies}
        observed_secrets = {name: set() for name in policies}
        observed_variables = {name: set() for name in policies}
        environment_job_count = 0

        deployment = load_workflow("deployment-evidence.yml")
        platform_input = deployment["on"]["workflow_dispatch"]["inputs"][
            "platform"
        ]
        deployment_platforms = {
            "compose",
            "cloud_run",
            "aws",
            "fly_io",
            "cloudflare_containers",
        }
        self.assertEqual(platform_input["type"], "choice")
        self.assertTrue(platform_input["required"])
        self.assertEqual(set(platform_input["options"]), deployment_platforms)
        deployment_policies = {
            platform: f"deployment-evidence-{platform}"
            for platform in deployment_platforms
        }
        self.assertLessEqual(set(deployment_policies.values()), set(policies))

        live = load_workflow("release-domain-observations.yml")
        live_rows = live["jobs"]["javascript_collect"]["strategy"]["matrix"][
            "include"
        ]
        expected_live_pairs = {
            "release-evidence-firebase-app-check": policies[
                "release-evidence-firebase-app-check"
            ],
            "release-evidence-turnstile": policies[
                "release-evidence-turnstile"
            ],
        }
        self.assertEqual(
            {row["environment"]: row["policy_id"] for row in live_rows},
            expected_live_pairs,
        )

        for path in sorted(WORKFLOWS.glob("*.yml")):
            workflow = load_workflow(path.name)
            raw_workflow = path.read_text(encoding="utf-8")
            for forbidden in manifest["forbidden_secret_names"]:
                self.assertNotIn(forbidden, raw_workflow, path.name)
            for job_name, job in workflow["jobs"].items():
                raw_environment = job.get("environment")
                if isinstance(raw_environment, dict):
                    raw_environment = raw_environment.get("name")
                permissions = job.get("permissions", workflow.get("permissions", {}))
                custom_secrets = {
                    name
                    for name in re.findall(
                        r"secrets\.([A-Z][A-Z0-9_]*)",
                        json.dumps(job, sort_keys=True),
                    )
                    if name != "GITHUB_TOKEN"
                }
                if raw_environment is None:
                    runs_on = job.get("runs-on")
                    self.assertFalse(
                        runs_on == "self-hosted"
                        or (
                            isinstance(runs_on, list)
                            and "self-hosted" in runs_on
                        ),
                        f"self-hosted evidence job lacks a managed environment: {path.name}:{job_name}",
                    )
                    if isinstance(permissions, dict):
                        self.assertFalse(
                            any(value == "write" for value in permissions.values()),
                            f"privileged job lacks a managed environment: {path.name}:{job_name}",
                        )
                    self.assertFalse(
                        custom_secrets,
                        f"custom-secret job lacks a managed environment: {path.name}:{job_name}",
                    )
                    continue

                environment_job_count += 1
                label = f"{path.name}:{job_name}"
                dynamic_kind = None
                if raw_environment == "deployment-evidence-${{ inputs.platform }}":
                    self.assertEqual(path.name, "deployment-evidence.yml", label)
                    self.assertIn(job_name, {"capture", "finalize"}, label)
                    dynamic_kind = "deployment"
                    concrete_environments = set(deployment_policies.values())
                    if job_name == "capture":
                        concrete_environments.remove("deployment-evidence-compose")
                elif raw_environment == "${{ matrix.environment }}":
                    self.assertEqual(
                        (path.name, job_name),
                        ("release-domain-observations.yml", "javascript_collect"),
                        label,
                    )
                    dynamic_kind = "matrix"
                    concrete_environments = set(expected_live_pairs)
                else:
                    self.assertIsInstance(raw_environment, str, label)
                    self.assertNotIn("${{", raw_environment, label)
                    self.assertIn(raw_environment, policies, label)
                    concrete_environments = {raw_environment}

                for environment in concrete_environments:
                    self.assertIn(environment, policies, label)
                    consumers[environment].append(label)

                steps = job.get("steps")
                self.assertIsInstance(steps, list, f"{path.name}:{job_name}")
                self.assertTrue(steps, f"{path.name}:{job_name}")
                first = steps[0]
                self.assertEqual(first.get("shell"), "bash", label)
                self.assertEqual(
                    first.get("env", {}).get("OBSERVED_POLICY_ID"),
                    "${{ vars.LATCHWAY_RELEASE_CONTROL_POLICY_ID }}",
                    label,
                )
                if dynamic_kind == "deployment":
                    self.assertEqual(
                        first.get("name"),
                        "Verify the exact protected deployment provider environment",
                        label,
                    )
                    self.assertEqual(
                        first.get("env", {}).get("PLATFORM"),
                        "${{ inputs.platform }}",
                        label,
                    )
                    script = first.get("run", "")
                    self.assertIn('case "$PLATFORM" in', script, label)
                    self.assertIn("*) exit 1 ;;", script, label)
                    self.assertIn(
                        'test "$OBSERVED_POLICY_ID" = "$expected"', script, label
                    )
                    mappings = dict(
                        re.findall(
                            r"^\s*([a-z_]+)\) expected=\"([^\"]+)\" ;;$",
                            script,
                            flags=re.MULTILINE,
                        )
                    )
                    self.assertEqual(
                        mappings,
                        {
                            platform: policies[environment]
                            for platform, environment in deployment_policies.items()
                            if environment in concrete_environments
                        },
                        label,
                    )
                elif dynamic_kind == "matrix":
                    self.assertEqual(
                        first.get("name"),
                        "Verify the exact protected live JavaScript evidence environment",
                        label,
                    )
                    self.assertEqual(
                        first.get("env", {}).get("EXPECTED_POLICY_ID"),
                        "${{ matrix.policy_id }}",
                        label,
                    )
                    self.assertEqual(
                        first.get("run", "").splitlines(),
                        [
                            "set -Eeuo pipefail",
                            'test "$OBSERVED_POLICY_ID" = "$EXPECTED_POLICY_ID"',
                        ],
                        label,
                    )
                else:
                    environment = next(iter(concrete_environments))
                    self.assertEqual(
                        first.get("name"),
                        f"Verify the exact protected {environment} environment",
                        label,
                    )
                    self.assertEqual(
                        first.get("run", "").splitlines(),
                        [
                            "set -Eeuo pipefail",
                            (
                                'test "$OBSERVED_POLICY_ID" = '
                                f'"{policies[environment]}"'
                            ),
                        ],
                        label,
                    )
                self.assertNotIn("uses", first, label)
                self.assertNotIn("if", first, label)
                self.assertNotIn("continue-on-error", first, label)
                self.assertNotIn("secrets.", json.dumps(first, sort_keys=True), label)

                variable_references = {
                    name
                    for name in re.findall(
                        r"vars\.([A-Z][A-Z0-9_]*)",
                        json.dumps(job, sort_keys=True),
                    )
                    if name != "LATCHWAY_RELEASE_CONTROL_POLICY_ID"
                }
                for environment in concrete_environments:
                    observed_variables[environment].update(variable_references)

                if dynamic_kind == "deployment":
                    non_step_secrets = {
                        name
                        for name in re.findall(
                            r"secrets\.([A-Z][A-Z0-9_]*)",
                            json.dumps(
                                {key: value for key, value in job.items() if key != "steps"},
                                sort_keys=True,
                            ),
                        )
                        if name != "GITHUB_TOKEN"
                    }
                    self.assertFalse(non_step_secrets, label)
                    for step in steps:
                        step_secrets = {
                            name
                            for name in re.findall(
                                r"secrets\.([A-Z][A-Z0-9_]*)",
                                json.dumps(step, sort_keys=True),
                            )
                            if name != "GITHUB_TOKEN"
                        }
                        if not step_secrets:
                            continue
                        match = re.fullmatch(
                            r"inputs\.platform == '([a-z_]+)'", step.get("if", "")
                        )
                        self.assertIsNotNone(match, f"{label}:{step.get('name')}")
                        platform = match.group(1)
                        self.assertIn(platform, deployment_policies, label)
                        observed_secrets[deployment_policies[platform]].update(
                            step_secrets
                        )
                else:
                    for environment in concrete_environments:
                        observed_secrets[environment].update(custom_secrets)

        self.assertEqual(
            {name for name, jobs in consumers.items() if jobs},
            set(policies),
            consumers,
        )
        self.assertEqual(
            consumers["preview-image-publishing"],
            ["preview-image.yml:publish", "preview-image.yml:sign"],
        )
        self.assertEqual(environment_job_count, 44)
        self.assertEqual(observed_secrets, declared_secrets)
        self.assertEqual(observed_variables, declared_variables)

    def test_required_public_docs_check_runs_for_every_pr_and_main_push(self) -> None:
        workflow = load_workflow("public-docs.yml")
        pull_request = workflow["on"].get("pull_request")
        self.assertTrue(
            pull_request is None
            or (
                isinstance(pull_request, dict)
                and "paths" not in pull_request
                and "paths-ignore" not in pull_request
            )
        )
        push = workflow["on"].get("push")
        self.assertIsInstance(push, dict)
        self.assertEqual(push.get("branches"), ["main"])
        self.assertNotIn("paths", push)
        self.assertNotIn("paths-ignore", push)
        self.assertEqual(
            workflow["jobs"]["validate"]["name"],
            "Validate canonical Mintlify source",
        )
        manifest = json.loads(
            (ROOT / ".github/release-controls.json").read_text(encoding="utf-8")
        )
        core = next(
            repository
            for repository in manifest["repositories"]
            if repository["name"] == "latchway"
        )
        branch_ruleset = next(
            ruleset for ruleset in core["rulesets"] if ruleset["target"] == "branch"
        )
        required = next(
            rule
            for rule in branch_ruleset["rules"]
            if rule["type"] == "required_status_checks"
        )
        contexts = {
            item["context"]
            for item in required["parameters"]["required_status_checks"]
        }
        self.assertIn("Validate canonical Mintlify source", contexts)

    def test_privileged_container_build_helpers_are_immutable(self) -> None:
        buildx_steps = 0
        qemu_steps = 0
        for path in sorted(WORKFLOWS.glob("*.yml")):
            workflow = load_workflow(path.name)
            for step in all_steps(workflow):
                uses = step.get("uses", "")
                if uses.startswith("docker/setup-buildx-action@"):
                    buildx_steps += 1
                    configuration = step.get("with", {})
                    self.assertEqual(
                        configuration.get("version"), PINNED_BUILDX_VERSION, path.name
                    )
                    self.assertEqual(
                        configuration.get("driver-opts", "").splitlines(),
                        [f"image={PINNED_BUILDKIT_IMAGE}"],
                        path.name,
                    )
                if uses.startswith("docker/setup-qemu-action@"):
                    qemu_steps += 1
                    configuration = step.get("with", {})
                    self.assertEqual(
                        configuration.get("image"), PINNED_BINFMT_IMAGE, path.name
                    )
                    self.assertEqual(configuration.get("platforms"), "arm64", path.name)
        self.assertGreaterEqual(buildx_steps, 1)
        self.assertGreaterEqual(qemu_steps, 1)

    def test_stable_ghcr_closure_verifies_referrers_and_anonymous_children(self) -> None:
        producer = load_workflow("release-domain-observations.yml")
        authority = producer["jobs"]["github_authority"]
        self.assertEqual(authority["permissions"]["packages"], "read")
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in authority["steps"]
            )
        )
        capture = next(
            step
            for step in authority["steps"]
            if step.get("name")
            == "Capture the fixed GitHub authority set without candidate code"
        )["run"]
        self.assertIn("--bundle-from-oci", capture)
        self.assertIn("--predicate-type https://slsa.dev/provenance/v1", capture)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", capture)
        self.assertIn('all(.[].verificationResult.statement;', capture)
        self.assertIn('any(.[].verificationResult.statement;', capture)
        self.assertIn('printf \'{\"auths\":{}}\\n\' > "$DOCKER_CONFIG/config.json"', capture)
        self.assertIn(
            'env -u GH_TOKEN -u GITHUB_TOKEN docker pull --platform "linux/$architecture"',
            capture,
        )
        for binding in (
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.version",
            ".RepoDigests",
            ".RootFS.Layers",
        ):
            self.assertIn(binding, capture)
        for relative in (
            "public-registries/oci/cosign.json",
            "public-registries/oci/index-$tag.json",
            "public-registries/oci/child-$architecture.json",
            "supply-chain/github-provenance.json",
            "supply-chain/github-spdx-$architecture.json",
        ):
            self.assertIn(relative, capture)

        observer_job = producer["jobs"]["observe_non_sdk"]
        buildx = next(
            step
            for step in observer_job["steps"]
            if step.get("uses", "").startswith("docker/setup-buildx-action@")
        )
        cosign = next(
            step
            for step in observer_job["steps"]
            if step.get("uses", "").startswith("sigstore/cosign-installer@")
        )
        self.assertEqual(buildx["if"], "inputs.domain == 'supply_chain'")
        self.assertEqual(cosign["if"], "inputs.domain == 'supply_chain'")
        observer_text = (ROOT / "scripts/release-domain-observer.py").read_text(
            encoding="utf-8"
        )
        public_registry_body = observer_text[
            observer_text.index("    def observe_public_registries") :
            observer_text.index('        javascript = self.identity["repositories"]["javascript"]')
        ]
        self.assertNotIn("_execute_command", public_registry_body)
        self.assertNotIn('("docker", "buildx"', public_registry_body)
        self.assertNotIn('("cosign", "verify"', public_registry_body)
        self.assertIn("_github_authority_file", public_registry_body)
        self.assertIn("_validate_public_child_inspection", public_registry_body)

        promotion = load_workflow("promote-release.yml")
        publisher = promotion["jobs"]["publish-github-release"]
        self.assertNotIn("packages", publisher["permissions"])
        public_step = next(
            step
            for step in publisher["steps"]
            if step.get("name")
            == "Verify both immutable and moving OCI coordinates before publication"
        )["run"]
        self.assertIn('export DOCKER_CONFIG="$public_docker_config"', public_step)
        self.assertIn('docker pull --platform "linux/$architecture"', public_step)
        self.assertIn("--bundle-from-oci", public_step)
        self.assertIn("https://spdx.dev/Document/v2.3", public_step)
        self.assertIn("https://slsa.dev/provenance/v1", public_step)
        self.assertIn(".RootFS.Layers", public_step)

    def test_release_failure_workflow_runs_repo_owned_disposable_controller(self) -> None:
        workflow = load_workflow("release-failure-evidence.yml")
        serialized = (WORKFLOWS / "release-failure-evidence.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("LATCHWAY_RELEASE_FAILURE_CONTROLLER_PLAN", serialized)
        self.assertNotIn("LATCHWAY_RELEASE_FAILURE_CAPTURE_DIRECTORY", serialized)
        self.assertNotIn("controller-plan-coordinate.json", serialized)
        self.assertIn("scripts/run-release-failure-controller.sh", serialized)
        self.assertIn("--acknowledge-disposable-target", serialized)
        self.assertIn('--output-dir "$RUNNER_TEMP/failure/live-failures"', serialized)
        self.assertIn("docker pull --platform linux/amd64", serialized)
        self.assertIn("docker logout ghcr.io", serialized)
        self.assertNotIn('cp -R -- "$CAPTURE_DIRECTORY/."', serialized)
        failure = workflow["jobs"]["failure"]
        self.assertEqual(
            failure["runs-on"],
            ["self-hosted", "linux", "x64", "latchway-release-failure"],
        )
        self.assertNotIn("id-token", failure.get("permissions", {}))
        self.assertEqual(failure["permissions"]["packages"], "read")
        names = [step.get("name", "") for step in failure["steps"]]
        pull = names.index("Pull and bind the exact authenticated linux amd64 images")
        logout = names.index(
            "Remove registry credentials before repo-owned topology code executes"
        )
        topology = names.index(
            "Provision and execute the repo-owned bounded failure topology"
        )
        self.assertLess(pull, logout)
        self.assertLess(logout, topology)
        controller_step = next(
            step
            for step in failure["steps"]
            if step.get("name")
            == "Provision and execute the repo-owned bounded failure topology"
        )
        self.assertNotIn("continue-on-error", controller_step)

        launcher = ROOT / "scripts/run-release-failure-controller.sh"
        launcher_text = launcher.read_text(encoding="utf-8")
        self.assertNotEqual(launcher.stat().st_mode & 0o111, 0)
        self.assertIn("docker network create", launcher_text)
        self.assertIn("--internal", launcher_text)
        self.assertIn("expected_network_id", launcher_text)
        self.assertIn("expected_container_ids", launcher_text)
        self.assertIn('observed_id" == "$expected_id', launcher_text)
        self.assertIn('observed_network_id" == "$expected_network_id', launcher_text)
        self.assertIn("/tools/latchway-failure-driver serve", launcher_text)
        self.assertIn("python3 \"$repository_root/scripts/fault-controller.py\"", launcher_text)
        self.assertNotIn("LATCHWAY_RELEASE_FAILURE_CONTROLLER_PLAN", launcher_text)

        tools_dockerfile = (ROOT / "tests/load/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("./tests/failure/cmd/latchway-failure-driver", tools_dockerfile)
        self.assertIn("./tests/failure/cmd/latchway-failure-balancer", tools_dockerfile)
        self.assertIn("/tools/latchway-failure-driver", tools_dockerfile)
        self.assertIn("/tools/latchway-failure-balancer", tools_dockerfile)

    def test_sensitive_github_cli_operations_require_fixed_version_first(self) -> None:
        sensitive = ("gh release verify", "gh attestation verify")
        guarded: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            offsets = [text.index(command) for command in sensitive if command in text]
            if not offsets:
                continue
            guarded.append(path.name)
            guard_offsets = [
                text.index(marker)
                for marker in (
                    "require-gh-version.py",
                    "major > 2 || (major == 2 && minor >= 97)",
                )
                if marker in text
            ]
            self.assertTrue(guard_offsets, path.name)
            self.assertLess(min(guard_offsets), min(offsets), path.name)
        self.assertEqual(
            guarded,
            [
                "aggregate-release-evidence.yml",
                "cloud-deployment-aggregate.yml",
                "cross-repository-conformance.yml",
                "deployment-evidence.yml",
                "finalize-release-record.yml",
                "operational-resilience-evidence.yml",
                "preview-image.yml",
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
        self.assertNotIn("require_github_cli()\n        observer = Observer", observer)
        self.assertIn('value.add_argument("--github-authority-directory"', observer)
        self.assertIn('value.add_argument("--live-provider-capture-directory"', observer)
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
        intended_tag = workflow["on"]["workflow_dispatch"]["inputs"]["intended_tag"]
        self.assertIn("canonical vX.Y.Z-rc.N", intended_tag["description"])
        self.assertIn("tags are created only by promotion", intended_tag["description"])
        serialized = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("(-rc\\.([1-9][0-9]*))?", serialized)
        self.assertNotIn("gh release create", serialized)
        self.assertNotIn("refs/tags/", serialized)
        self.assertNotIn("type=semver", serialized)
        self.assertNotIn("value=latest", serialized)
        self.assertIn('$IMAGE:candidate-$CANDIDATE_COMMIT', serialized)
        self.assertIn("scripts/release-preflight.py", serialized)
        self.assertIn("--candidate", serialized)
        self.assertIn("scripts/run-local-load-gates.sh", serialized)
        self.assertIn("-scope automated", serialized)
        self.assertIn(
            "subject-path: ${{ runner.temp }}/candidate/latchway-candidate.json",
            serialized,
        )
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        for job in workflow["jobs"].values():
            self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")

    def test_candidate_image_signing_is_fresh_and_executes_no_candidate_tooling(self) -> None:
        workflow = load_workflow("release.yml")
        self.assertEqual(
            set(workflow["jobs"]), {"verify", "image", "publish-image", "sign"}
        )
        image = workflow["jobs"]["image"]
        publisher = workflow["jobs"]["publish-image"]
        signer = workflow["jobs"]["sign"]
        self.assertEqual(publisher["needs"], "image")
        self.assertEqual(publisher["environment"], "release-image-publishing")
        self.assertEqual(signer["needs"], "publish-image")
        self.assertEqual(signer["environment"], "release-evidence-signing")
        self.assertNotIn("id-token", image["permissions"])
        self.assertNotIn("attestations", image["permissions"])
        self.assertNotIn("artifact-metadata", image["permissions"])
        self.assertNotIn("packages", image["permissions"])
        self.assertEqual(publisher["permissions"]["packages"], "write")
        self.assertNotIn("id-token", publisher["permissions"])
        self.assertNotIn("attestations", publisher["permissions"])
        self.assertEqual(signer["permissions"]["id-token"], "write")
        self.assertEqual(signer["permissions"]["attestations"], "write")
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in publisher["steps"]
            )
        )
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in signer["steps"]
            )
        )
        serialized = json.dumps(signer, sort_keys=True)
        self.assertNotIn("scripts/", serialized)
        self.assertNotIn("python", serialized)
        self.assertNotIn("pnpm", serialized)
        self.assertNotIn("npm ", serialized)
        publisher_serialized = json.dumps(publisher, sort_keys=True)
        self.assertNotIn("scripts/", publisher_serialized)
        self.assertNotIn("python", publisher_serialized)
        self.assertNotIn("pnpm", publisher_serialized)
        self.assertNotIn("npm ", publisher_serialized)
        self.assertIn("docker logout ghcr.io", publisher_serialized)
        self.assertIn("docker logout ghcr.io", serialized)
        image_serialized = json.dumps(image, sort_keys=True)
        self.assertNotIn("docker/login-action", image_serialized)
        self.assertNotIn("secrets.GITHUB_TOKEN", image_serialized)
        image_runs = "\n".join(
            step.get("run", "") for step in image["steps"] if isinstance(step, dict)
        )
        self.assertIn('test -z "${GH_TOKEN:-}"', image_runs)
        self.assertEqual(image_runs.count("python3 scripts/verify-runtime-image.py"), 2)
        self.assertIn("latchway-linux-amd64.image.tar linux/amd64", image_runs)
        self.assertIn("latchway-linux-arm64.image.tar linux/arm64", image_runs)
        publisher_names = [step.get("name", "") for step in publisher["steps"]]
        handoff_validation = publisher_names.index(
            "Validate the exact closed handoff before registry authentication"
        )
        registry_authentication = publisher_names.index(
            "Authenticate only the fresh no-checkout publisher"
        )
        publication = publisher_names.index(
            "Publish exact platform images and assemble the immutable index"
        )
        manifest = publisher_names.index(
            "Construct the exact unsigned candidate manifest without candidate code"
        )
        self.assertLess(handoff_validation, registry_authentication)
        self.assertLess(registry_authentication, publication)
        self.assertLess(publication, manifest)
        names = [step.get("name", "") for step in signer["steps"]]
        validation = names.index(
            "Validate candidate identity, exact artifacts, scan results, and SBOMs without candidate code"
        )
        registry = names.index(
            "Verify the registry index and exact platform children without candidate code"
        )
        signature = names.index(
            "Sign and verify the validated candidate index with GitHub OIDC"
        )
        candidate_attestation = names.index(
            "Attest the exact validated candidate manifest"
        )
        retained = names.index("Retain immutable signed candidate evidence")
        signer_logout = names.index("Remove the source-free signer registry credential")
        self.assertLess(validation, registry)
        self.assertLess(registry, signature)
        self.assertLess(signature, candidate_attestation)
        self.assertLess(candidate_attestation, retained)
        self.assertLess(retained, signer_logout)
        image_names = [step.get("name", "") for step in image["steps"]]
        self.assertIn(
            "Retain the exact credential-free image handoff",
            image_names,
        )

    def test_promotion_verification_precedes_every_public_mutation(self) -> None:
        workflow = load_workflow("promote-release.yml")
        self.assertEqual(
            set(workflow["jobs"]),
            {
                "authenticate-inputs",
                "candidate-gates",
                "immutable-release-settings",
                "plan-promotion",
                "stage-github-release",
                "promote-oci",
                "publish-github-release",
                "dispatch-sdk-publications",
            },
        )
        authority = workflow["jobs"]["authenticate-inputs"]
        candidate_gates = workflow["jobs"]["candidate-gates"]
        immutable_settings = workflow["jobs"]["immutable-release-settings"]
        planner = workflow["jobs"]["plan-promotion"]
        stage = workflow["jobs"]["stage-github-release"]
        oci = workflow["jobs"]["promote-oci"]
        publisher = workflow["jobs"]["publish-github-release"]
        dispatch = workflow["jobs"]["dispatch-sdk-publications"]
        self.assertEqual(authority["environment"], "security-evidence")
        self.assertEqual(
            set(planner["needs"]),
            {"authenticate-inputs", "candidate-gates", "immutable-release-settings"},
        )
        self.assertNotIn("environment", planner)
        self.assertEqual(
            set(stage["needs"]), {"plan-promotion", "immutable-release-settings"}
        )
        self.assertEqual(set(oci["needs"]), {"plan-promotion", "stage-github-release"})
        self.assertEqual(
            set(publisher["needs"]),
            {"plan-promotion", "stage-github-release", "promote-oci"},
        )
        self.assertEqual(
            set(dispatch["needs"]),
            {"authenticate-inputs", "promote-oci", "publish-github-release"},
        )
        for job in (stage, oci, publisher):
            self.assertEqual(job["environment"], "release")
            self.assertEqual(job.get("if"), "github.ref == 'refs/heads/main'")

        planner_names = [step.get("name", "") for step in planner["steps"]]
        candidate_attestation = planner_names.index(
            "Reverify candidate and promotion attestations on the credential-free planner"
        )
        bindings = planner_names.index(
            "Verify exact candidate security and aggregate bindings without source"
        )
        image_provenance = planner_names.index(
            "Verify the exact candidate image signature and provenance"
        )
        immutable_preflight = planner_names.index(
            "Preflight immutable releases and every fixed core release asset"
        )
        handoff = planner_names.index("Build the exact source-free mutation handoff")
        retained = planner_names.index("Retain only the closed source-free mutation handoff")
        self.assertLess(candidate_attestation, bindings)
        self.assertLess(bindings, image_provenance)
        self.assertLess(image_provenance, immutable_preflight)
        self.assertLess(immutable_preflight, handoff)
        self.assertLess(handoff, retained)

        stage_names = [step.get("name", "") for step in stage["steps"]]
        stage_validation = stage_names.index(
            "Validate exact closure hashes and attestations before any GitHub mutation"
        )
        tag_creation = stage_names.index("Create the evidence-gated annotated core tag")
        draft = stage_names.index(
            "Prepare the recoverable product release draft and exact assets"
        )
        self.assertLess(stage_validation, tag_creation)
        self.assertLess(tag_creation, draft)

        oci_names = [step.get("name", "") for step in oci["steps"]]
        oci_validation = oci_names.index(
            "Validate exact closure hashes attestations tag and draft before registry authentication"
        )
        oci_promotion = oci_names.index(
            "Promote only the verified index digest to stable OCI tags"
        )
        self.assertLess(oci_validation, oci_promotion)

        publisher_names = [step.get("name", "") for step in publisher["steps"]]
        publication_validation = publisher_names.index(
            "Validate exact closure hashes and attestations before release publication"
        )
        oci_verification = publisher_names.index(
            "Verify both immutable and moving OCI coordinates before publication"
        )
        release_creation = publisher_names.index("Publish the immutable release record")
        self.assertLess(publication_validation, oci_verification)
        self.assertLess(oci_verification, release_creation)
        self.assertIn(
            "Dispatch exact evidence-bound SDK publications without a checkout",
            [step.get("name", "") for step in dispatch["steps"]],
        )

        self.assertEqual(candidate_gates["needs"], "authenticate-inputs")
        self.assertEqual(candidate_gates["permissions"], {})
        self.assertNotIn("secrets.", str(candidate_gates))
        self.assertNotIn("id-token", candidate_gates["permissions"])
        self.assertNotEqual(candidate_gates["permissions"].get("contents"), "write")
        for source_job in (candidate_gates, planner):
            self.assertNotEqual(source_job["permissions"].get("contents"), "write")
            self.assertNotEqual(source_job["permissions"].get("packages"), "write")
            self.assertNotEqual(source_job["permissions"].get("id-token"), "write")
            self.assertNotIn("secrets.", str(source_job))
        for privileged in (
            authority,
            immutable_settings,
            stage,
            oci,
            publisher,
            dispatch,
        ):
            privileged_text = json.dumps(privileged, sort_keys=True)
            self.assertFalse(
                any(
                    step.get("uses", "").startswith("actions/checkout@")
                    for step in privileged["steps"]
                ),
                privileged,
            )
            self.assertNotIn("python3 latchway/scripts/", privileged_text)
        authority_names = [step.get("name", "") for step in authority["steps"]]
        self.assertLess(
            authority_names.index(
                "Verify nested independent-review attestation on the credential-isolated runner"
            ),
            authority_names.index("Package exact candidate source objects without a checkout"),
        )
        self.assertIn("INDEPENDENT_SECURITY_REVIEW_TOKEN", str(authority))
        self.assertIn("diff --unified=0", str(authority))
        self.assertIn(".review_authority.reviewer", str(authority))
        self.assertIn("LATCHWAY_RELEASE_DISPATCH_TOKEN", str(dispatch))
        self.assertIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", str(immutable_settings))
        for job in (stage, oci, publisher):
            self.assertNotIn("LATCHWAY_RELEASE_DISPATCH_TOKEN", str(job))
            self.assertNotIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", str(job))

        serialized = (WORKFLOWS / "promote-release.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/release-candidate.py", serialized)
        self.assertIn("scripts/verify-promotion.py", serialized)
        self.assertIn("--signer-workflow", serialized)
        self.assertIn("--source-ref refs/heads/main", serialized)
        self.assertGreaterEqual(serialized.count("--source-digest"), 3)
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        self.assertIn("--deny-self-hosted-runners", serialized)
        self.assertIn(
            '--promotion-directory "$root/latchway-security/promotion-conformance"',
            serialized,
        )
        self.assertIn('.promotion_conformance.report_sha256', serialized)
        self.assertIn('.review_authority.producer.repository', serialized)
        self.assertIn(
            'actions/runs/$run_id/attempts/$run_attempt', serialized
        )
        self.assertIn("LATCHWAY_RELEASE_DISPATCH_TOKEN", serialized)
        self.assertIn("repos/$repository/immutable-releases", serialized)
        self.assertIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", serialized)
        self.assertIn('(keys | sort) == ["enabled", "enforced_by_owner"]', serialized)
        self.assertIn('gh release create "$INTENDED_TAG" --draft', serialized)
        self.assertIn('.immutable == true', serialized)
        self.assertIn('gh release verify "$INTENDED_TAG"', serialized)
        self.assertIn("If-None-Match:", serialized)
        self.assertIn("'^HTTP/[0-9.]+ 304( |$)'", serialized)
        self.assertNotIn("If-Match:", serialized)
        self.assertNotIn("--generate-notes", serialized)
        self.assertNotIn("continue-on-error", serialized)

    def test_promotion_mutators_are_source_free_and_validate_closed_handoffs(self) -> None:
        workflow = load_workflow("promote-release.yml")
        jobs = workflow["jobs"]
        planner = jobs["plan-promotion"]
        stage = jobs["stage-github-release"]
        oci = jobs["promote-oci"]
        publisher = jobs["publish-github-release"]
        dispatch = jobs["dispatch-sdk-publications"]

        self.assertEqual(stage["permissions"]["contents"], "write")
        self.assertNotIn("packages", stage["permissions"])
        self.assertEqual(oci["permissions"]["packages"], "write")
        self.assertNotEqual(oci["permissions"].get("contents"), "write")
        self.assertEqual(publisher["permissions"]["contents"], "write")
        self.assertNotIn("packages", publisher["permissions"])
        for job_name in (
            "stage-github-release",
            "promote-oci",
            "publish-github-release",
            "dispatch-sdk-publications",
        ):
            serialized = json.dumps(jobs[job_name], sort_keys=True)
            self.assertNotIn("actions/checkout@", serialized, job_name)
            self.assertNotIn("latchway/scripts/", serialized, job_name)
            self.assertNotIn("python3", serialized, job_name)
            self.assertNotIn("latchway.source.tar", serialized, job_name)
            self.assertNotIn("source.sha256", serialized, job_name)

        for mutator in (stage, oci, publisher):
            serialized = json.dumps(mutator, sort_keys=True)
            self.assertIn("handoff.sha256", serialized)
            self.assertIn("actual-handoff-files.txt", serialized)
            self.assertIn("actual-handoff-hashes.txt", serialized)
            self.assertIn("sha256sum --strict --check handoff.sha256", serialized)
            self.assertGreaterEqual(serialized.count("gh attestation verify"), 3)
            self.assertIn("--deny-self-hosted-runners", serialized)

        planner_text = json.dumps(planner, sort_keys=True)
        self.assertIn(
            "latchway-promote-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
            planner_text,
        )
        self.assertNotIn("latchway-promote-inputs-", planner_text)
        self.assertNotIn("actions/checkout@", planner_text)
        self.assertNotIn("latchway/scripts/", planner_text)
        self.assertNotIn("python3", planner_text)
        self.assertNotIn("latchway.source.tar", planner_text)
        self.assertNotIn("source.sha256", planner_text)
        self.assertIn("latchway-promotion-handoff-${{ github.run_id }}-${{ github.run_attempt }}", planner_text)
        handoff_run = next(
            step["run"]
            for step in planner["steps"]
            if step.get("name") == "Build the exact source-free mutation handoff"
        )
        self.assertIn("test \"$(find \"$root\" -type f | wc -l | tr -d ' ')\" = 16", handoff_run)
        self.assertNotIn("docker/login-action", planner_text)

        stage_text = json.dumps(stage, sort_keys=True)
        oci_text = json.dumps(oci, sort_keys=True)
        publisher_text = json.dumps(publisher, sort_keys=True)
        self.assertNotIn("docker buildx imagetools create", stage_text)
        self.assertNotIn("docker login", stage_text)
        self.assertIn("docker buildx imagetools create", oci_text)
        self.assertIn("${{ secrets.GITHUB_TOKEN }}", oci_text)
        self.assertNotIn("gh release create", oci_text)
        self.assertNotIn("gh release upload", oci_text)
        self.assertNotIn("--method PATCH", oci_text)
        self.assertIn("docker_config=$(mktemp -d", oci_text)
        self.assertIn("trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT", oci_text)
        mutation_run = next(
            step["run"]
            for step in oci["steps"]
            if step.get("name")
            == "Promote only the verified index digest to stable OCI tags"
        )
        self.assertIn(
            'test -z "$(find "$DOCKER_CONFIG" -mindepth 1 -print -quit)"',
            mutation_run,
        )
        self.assertLess(mutation_run.index("trap 'docker logout"), mutation_run.index("docker login"))
        self.assertLess(mutation_run.index("docker login"), mutation_run.index("imagetools create"))
        self.assertNotIn("docker login", publisher_text)
        self.assertNotIn("imagetools create", publisher_text)
        self.assertIn("--method PATCH", publisher_text)
        self.assertNotIn("${{ secrets.GITHUB_TOKEN }}", stage_text)
        self.assertNotIn("${{ secrets.GITHUB_TOKEN }}", publisher_text)
        self.assertIn("latchway-promotion-handoff", json.dumps(dispatch, sort_keys=True))
        self.assertNotIn("latchway-promote-inputs", json.dumps(dispatch, sort_keys=True))

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
        self.assertIn("--signer-digest \"$CANDIDATE_COMMIT\"", serialized)
        self.assertIn("--source-digest \"$CANDIDATE_COMMIT\"", serialized)
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

    def test_oidc_attestors_never_execute_candidate_owned_tooling(self) -> None:
        for workflow_name in (
            "cross-repository-conformance.yml",
            "finalize-release-record.yml",
        ):
            workflow = load_workflow(workflow_name)
            for job_name, job in workflow["jobs"].items():
                permissions = job.get("permissions", {})
                if (
                    permissions.get("id-token") != "write"
                    and permissions.get("attestations") != "write"
                ):
                    continue
                serialized = str(job)
                self.assertNotIn("actions/checkout@", serialized, job_name)
                self.assertNotIn("python3 scripts/", serialized, job_name)
                self.assertNotIn("python3 latchway/scripts/", serialized, job_name)
                self.assertNotIn("cross-repo-conformance.py", serialized, job_name)

    def test_sibling_sources_are_anonymous_and_credentials_are_disabled(self) -> None:
        observations = load_workflow("release-domain-observations.yml")
        sources = observations["jobs"]["sources"]
        sibling_checkouts = [
            step
            for step in sources["steps"]
            if isinstance(step.get("with"), dict)
            and str(step["with"].get("repository", "")).startswith("Latchway/")
            and step.get("uses", "").startswith("actions/checkout@")
        ]
        self.assertEqual(sibling_checkouts, [])
        sources_text = str(sources)
        sources_run = "\n".join(
            step.get("run", "")
            for step in sources["steps"]
            if isinstance(step.get("run"), str)
        )
        self.assertNotIn("LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN", sources_text)
        self.assertNotIn("|| github.token", sources_text)
        self.assertNotIn("secrets.", sources_text)
        self.assertIn("GIT_ASKPASS=/bin/false", sources_run)
        self.assertIn("GIT_TERMINAL_PROMPT=0", sources_run)
        self.assertIn("-c credential.helper=", sources_run)
        self.assertIn("https://github.com/Latchway/$repository.git", sources_run)
        for repository in (
            "latchway-js",
            "latchway-ios-sdk",
            "latchway-android",
            "latchway-react-native-sdk",
        ):
            self.assertIn(f"fetch_public_commit {repository} {repository}", sources_run)

        cross = load_workflow("cross-repository-conformance.yml")
        authority = cross["jobs"]["authenticate-inputs"]
        evidence = cross["jobs"]["evidence"]
        attestor = cross["jobs"]["attest"]
        self.assertEqual(authority["environment"], "private-sibling-read")
        self.assertEqual(attestor["environment"], "release-evidence-signing")
        source_step = next(
            step
            for step in authority["steps"]
            if step.get("id") == "sources"
        )
        source_run = source_step["run"]
        self.assertNotIn("LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN", str(authority))
        self.assertNotIn("SIBLING_TOKEN", source_run)
        self.assertNotIn("curl ", source_run)
        self.assertIn("GIT_ASKPASS=/bin/false GIT_TERMINAL_PROMPT=0", source_run)
        self.assertIn("-c credential.helper=", source_run)
        self.assertIn('"https://github.com/$repository.git" "$requested_ref"', source_run)
        self.assertIn("rev-parse --verify 'FETCH_HEAD^{commit}'", source_run)
        self.assertIn("jq --null-input --arg sha", source_run)
        for repository in (
            "Latchway/latchway-js",
            "Latchway/latchway-ios-sdk",
            "Latchway/latchway-android",
            "Latchway/latchway-react-native-sdk",
            "Latchway/latchway-docs",
        ):
            self.assertIn(repository, source_run)
        for repository_id, repository, ref in (
            ("javascript", "Latchway/latchway-js", "JAVASCRIPT_REF"),
            ("ios", "Latchway/latchway-ios-sdk", "IOS_REF"),
            ("android", "Latchway/latchway-android", "ANDROID_REF"),
            (
                "react_native",
                "Latchway/latchway-react-native-sdk",
                "REACT_NATIVE_REF",
            ),
            ("documentation", "Latchway/latchway-docs", "DOCUMENTATION_REF"),
        ):
            self.assertIn(
                f'package_repository {repository_id} {repository} "${ref}" ""',
                source_run,
            )
        self.assertNotIn("secrets.", str(evidence))
        self.assertNotIn("id-token", evidence["permissions"])
        self.assertEqual(attestor["permissions"]["id-token"], "write")
        self.assertNotIn("scripts/", str(attestor))
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in authority["steps"] + evidence["steps"] + attestor["steps"]
            )
        )
        self.assertIn("Retain only authenticated inputs for candidate-code execution", [
            step.get("name", "") for step in authority["steps"]
        ])

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
        domain_jobs = workflow["jobs"]
        self.assertEqual(set(domain_jobs), {"authenticate", "finalize", "attest"})
        authentication = domain_jobs["authenticate"]
        finalizer = domain_jobs["finalize"]
        attestor = domain_jobs["attest"]
        self.assertEqual(authentication["environment"], "release-evidence")
        self.assertEqual(attestor["environment"], "release-evidence-signing")
        self.assertEqual(authentication["if"], "github.ref == 'refs/heads/main'")
        self.assertEqual(finalizer["needs"], "authenticate")
        self.assertEqual(attestor["needs"], "finalize")
        self.assertNotIn("id-token", authentication["permissions"])
        self.assertNotIn("id-token", finalizer["permissions"])
        self.assertEqual(attestor["permissions"]["id-token"], "write")
        authentication_names = [
            step.get("name", "") for step in authentication["steps"]
        ]
        producer_run = authentication_names.index(
            "Verify every input run and attempt belongs to its fixed producer"
        )
        bundles = authentication_names.index(
            "Verify all three exact attestation bundles before finalization"
        )
        retained_inputs = authentication_names.index(
            "Retain only authenticated inputs for credential-free finalization"
        )
        finalizer_names = [step.get("name", "") for step in finalizer["steps"]]
        finalized = finalizer_names.index("Finalize the external release-domain document")
        unsigned = finalizer_names.index(
            "Retain the unsigned domain for a fresh attestation runner"
        )
        attestor_names = [step.get("name", "") for step in attestor["steps"]]
        fixed_validation = attestor_names.index(
            "Validate the exact domain document and retained file set without candidate code"
        )
        document_attested = attestor_names.index(
            "Attest the exact external evidence document"
        )
        bundle_retained = attestor_names.index(
            "Retain the external evidence attestation bundle"
        )
        artifact_retained = attestor_names.index(
            "Retain the domain document and all hash-bound raw results"
        )
        self.assertLess(producer_run, bundles)
        self.assertLess(bundles, retained_inputs)
        self.assertLess(finalized, unsigned)
        self.assertLess(fixed_validation, document_attested)
        self.assertLess(document_attested, bundle_retained)
        self.assertLess(bundle_retained, artifact_retained)
        self.assertFalse(
            any(
                step.get("uses", "").startswith("actions/checkout@")
                for step in authentication["steps"] + attestor["steps"]
            )
        )
        self.assertNotIn("scripts/", str(attestor))
        self.assertNotIn("python3", str(attestor))
        self.assertIn('.image.repository == "ghcr.io/latchway/latchway"', str(attestor))
        self.assertIn('test("^sha256:[0-9a-f]{64}$")', str(attestor))
        self.assertIn(
            '.image.repository + "@" + .image.index_digest',
            str(attestor),
        )
        checkout = finalizer["steps"][0]
        self.assertTrue(checkout["uses"].startswith("actions/checkout@"))
        self.assertFalse(checkout["with"]["persist-credentials"])
        serialized = (WORKFLOWS / "release-domain-evidence.yml").read_text(encoding="utf-8")
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', serialized)
        self.assertIn("--receipt-attestation", serialized)
        self.assertIn("verify_run machine \"$MACHINE_RESULTS_RUN_ID\" \"$MACHINE_RESULTS_RUN_ATTEMPT\" .github/workflows/release-domain-observations.yml", serialized)
        self.assertEqual(serialized.count("--signer-digest"), 6)
        self.assertEqual(serialized.count("--source-digest"), 6)
        self.assertEqual(serialized.count("--deny-self-hosted-runners"), 6)
        self.assertNotIn("machine_results_artifact", serialized)
        self.assertNotIn("continue-on-error", serialized)
        self.assertNotIn("secrets.", serialized)
        self.assertIn("$EVIDENCE_DOMAIN.attestation.sigstore.json", serialized)

        producer = load_workflow("release-domain-observations.yml")
        producer_domains = producer["on"]["workflow_dispatch"]["inputs"]["domain"][
            "options"
        ]
        self.assertIn("physical_devices", producer_domains)
        jobs = producer["jobs"]
        self.assertEqual(
            set(jobs),
            {
                "authenticate",
                "live_provider_capture",
                "github_authority",
                "sources",
                "physical_authority",
                "javascript_harness",
                "javascript_collect",
                "observe_non_sdk",
                "aggregate",
                "sign",
            },
        )
        self.assertEqual(jobs["authenticate"]["environment"], "release-evidence")
        self.assertEqual(
            jobs["live_provider_capture"]["environment"],
            "release-evidence-live-provider",
        )
        self.assertEqual(
            jobs["github_authority"]["environment"],
            "release-evidence-github-read",
        )
        self.assertEqual(
            jobs["physical_authority"]["environment"], "release-evidence-physical"
        )
        collector = jobs["javascript_collect"]
        self.assertEqual(collector["environment"], "${{ matrix.environment }}")
        self.assertEqual(
            {row["environment"] for row in collector["strategy"]["matrix"]["include"]},
            {"release-evidence-firebase-app-check", "release-evidence-turnstile"},
        )
        self.assertEqual(collector["permissions"], {})
        self.assertIn("latchway-ephemeral-jit", collector["runs-on"])
        self.assertEqual(jobs["aggregate"]["environment"], "release-evidence")
        self.assertEqual(jobs["sign"]["environment"], "release-evidence-signing")
        for job_name in (
            "authenticate",
            "live_provider_capture",
            "github_authority",
            "physical_authority",
            "sign",
        ):
            self.assertFalse(
                any(
                    str(step.get("uses", "")).startswith("actions/checkout@")
                    for step in jobs[job_name]["steps"]
                ),
                job_name,
            )
        for job_name in ("live_provider_capture", "github_authority"):
            serialized_job = json.dumps(jobs[job_name], sort_keys=True)
            self.assertNotIn("scripts/release-domain-observer.py", serialized_job)
            self.assertNotIn("scripts/live-conformance.mjs", serialized_job)
        self.assertEqual(
            jobs["live_provider_capture"]["permissions"],
            {"actions": "read", "contents": "none"},
        )
        self.assertEqual(
            jobs["github_authority"]["permissions"],
            {"actions": "read", "contents": "none", "packages": "read"},
        )
        for job_name in ("observe_non_sdk", "aggregate"):
            serialized_job = json.dumps(jobs[job_name], sort_keys=True)
            self.assertNotIn("secrets.", serialized_job, job_name)
            self.assertNotIn("latchway verify", serialized_job, job_name)
            self.assertNotIn("--server-owned", serialized_job, job_name)
            self.assertIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", serialized_job)
            self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", serialized_job)
            self.assertEqual(
                jobs[job_name]["permissions"],
                {"actions": "read", "contents": "none"},
            )
        aggregate_names = [step.get("name", "") for step in jobs["aggregate"]["steps"]]
        self.assertLess(
            aggregate_names.index("Validate SDK and device observations without credentials"),
            aggregate_names.index("Produce the exact machine-results manifest"),
        )
        sign_names = [step.get("name", "") for step in jobs["sign"]["steps"]]
        self.assertLess(
            sign_names.index("Download validated machine results on a fresh no-checkout runner"),
            sign_names.index("Attest the exact machine-results manifest"),
        )
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
            "--physical-authority-directory",
            "--javascript-firebase-app-check-capture",
            "--javascript-turnstile-capture",
            "--live-provider-capture-directory",
            "--github-authority-directory",
            "LATCHWAY_RELEASE_EVIDENCE_GITHUB_READ_TOKEN",
            "Refuse provider, GitHub, and OIDC credentials before candidate execution",
            "Retain validated unsigned machine results for a fresh signer",
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
        self.assertIn("_github_authority_file", observer_text)
        for removed_online_path in (
            "def _github_token(",
            "def _gh_json(",
            "def _verify_release_attestation(",
            "def _download_release_asset(",
            "def _verify_immutable_release_asset(",
        ):
            self.assertNotIn(removed_online_path, observer_text)
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", producer_text)
        self.assertIn("gh release verify", producer_text)
        self.assertNotIn("machine_results_run_id", producer_text)
        self.assertNotIn("continue-on-error", producer_text)
        collector_step = next(
            step
            for step in jobs["javascript_collect"]["steps"]
            if step.get("name")
            == "Execute the candidate only through the gateway-isolated one-use supervisor"
        )
        physical_step = next(
            step
            for step in jobs["physical_authority"]["steps"]
            if step.get("name") == "Authenticate physical runs, artifacts, and subject attestations"
        )
        other_step = next(
            step
            for step in jobs["observe_non_sdk"]["steps"]
            if step.get("name") == "Validate the isolated non-SDK observations offline"
        )
        github_step = next(
            step
            for step in jobs["github_authority"]["steps"]
            if step.get("name")
            == "Capture the fixed GitHub authority set without candidate code"
        )
        provider_step = next(
            step
            for step in jobs["live_provider_capture"]["steps"]
            if step.get("name")
            == "Capture fixed responses with a run-bound one-use Admin grant"
        )
        self.assertEqual(
            physical_step["env"]["GH_TOKEN"],
            "${{ secrets.LATCHWAY_RELEASE_EVIDENCE_ACTIONS_READ_TOKEN }}",
        )
        self.assertEqual(
            collector_step["env"]["ONE_TIME_GRANT"],
            "${{ secrets.LATCHWAY_ONE_TIME_LIVE_SDK_GRANT }}",
        )
        for forbidden in (
            "LATCHWAY_LIVE_SDK_IDENTITY_TOKEN",
            "LATCHWAY_LIVE_SDK_FIREBASE_APP_CHECK_TOKEN",
            "LATCHWAY_LIVE_SDK_TURNSTILE_TOKEN",
        ):
            self.assertNotIn(forbidden, producer_text)
        self.assertIn("gateway_egress_only:true", producer_text)
        self.assertIn("consumption_count == 1", producer_text)
        self.assertIn("Unconditionally zero the grant", producer_text)
        self.assertIn("latchway.live-sdk-collector-teardown.v1", producer_text)
        self.assertNotIn("LATCHWAY_LIVE_SDK_ATTESTATION_PROVIDER", producer_text)
        self.assertNotIn("LATCHWAY_LIVE_SDK_ATTESTATION_TOKEN", producer_text)
        self.assertNotIn("GH_TOKEN", other_step["env"])
        self.assertNotIn("LATCHWAY_ADMIN_API_TOKEN", other_step["env"])
        self.assertEqual(
            github_step["env"]["GH_TOKEN"],
            "${{ secrets.LATCHWAY_RELEASE_EVIDENCE_GITHUB_READ_TOKEN }}",
        )
        self.assertEqual(
            provider_step["env"]["ONE_TIME_GRANT"],
            "${{ secrets.LATCHWAY_ONE_TIME_LIVE_PROVIDER_GRANT }}",
        )
        self.assertEqual(
            producer_text.count(
                "${{ secrets.LATCHWAY_RELEASE_EVIDENCE_GITHUB_READ_TOKEN }}"
            ),
            1,
        )
        self.assertIn("(( file_count <= 542 ))", producer_text)
        self.assertIn(
            "MAXIMUM_AUTHORITY_FILES = 541",
            (ROOT / "scripts" / "release-domain-observer.py").read_text(
                encoding="utf-8"
            ),
        )
        for marker in (
            "documentation_production_run_id",
            "documentation_production_run_attempt",
            "Latchway/latchway-docs",
            ".github/workflows/mintlify-production-evidence.yml",
            "latchway-mintlify-production-${documentation_commit}",
            "latchway-mintlify-production-evidence.SHA256SUMS",
            "latchway-mintlify-production-evidence.attestation.sigstore.json",
            "--signer-workflow Latchway/latchway-docs/.github/workflows/mintlify-production-evidence.yml",
            "--deny-self-hosted-runners",
            "for package_id in client openai vercel-ai langchain",
            "npm-$package_id-attestations.json",
            "npm-release-adoption-${package_id}",
        ):
            self.assertIn(marker, producer_text)
        observer_text = (ROOT / "scripts/release-domain-observer.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("registry.documentation-production", observer_text)
        self.assertIn("latchway_retained_mintlify_production_evidence", observer_text)
        self.assertIn("raw_artifacts={", observer_text)
        self.assertIn("MAXIMUM_RETAINED_NPM_TARBALL_BYTES", observer_text)
        self.assertNotIn("GH_TOKEN", other_step["env"])
        self.assertEqual(
            producer_text.count(
                "${{ secrets.LATCHWAY_ONE_TIME_LIVE_PROVIDER_GRANT }}"
            ),
            1,
        )
        self.assertNotIn("LATCHWAY_LIVE_PROVIDER_ADMIN_API_TOKEN", producer_text)
        self.assertEqual(
            jobs["live_provider_capture"]["runs-on"],
            ["self-hosted", "linux", "x64", "latchway-live-provider", "latchway-ephemeral-jit"],
        )
        for marker in (
            "latchway.live-provider-collector-lease.v1",
            "latchway.live-provider-one-use-grant.v1",
            "(.grant.expires_at_unix - .grant.issued_at_unix) <= 300",
            "(( capture_finish <= grant_expires ))",
            "latchway.live-provider-grant-consumption.v1",
            "consumption_count == 1",
            "latchway.live-provider-collector-teardown.v1",
            "grant_issuer_independent:true",
            "one_use_verification:true",
            "gateway_egress_only:true",
            "collector-isolation",
            "latchway_retained_live_provider_collector_isolation",
            "Reverify the retained live-provider collector closure without candidate code",
            "LATCHWAY_LIVE_PROVIDER_COLLECTOR_TRUST_ROOT_SHA256",
            "grant-consumption-receipt.sig",
            "openssl dgst -sha256 -verify",
        ):
            self.assertIn(marker, producer_text)
        self.assertNotIn("LATCHWAY_LIVE_SDK_IDENTITY_TOKEN", other_step["env"])

        release_text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        source_text = (WORKFLOWS / "cross-repository-conformance.yml").read_text(encoding="utf-8")
        self.assertIn("latchway-candidate.attestation.sigstore.json", release_text)
        self.assertIn("latchway-cross-repository.attestation.sigstore.json", source_text)

    def test_release_domain_candidate_jobs_are_never_oidc_or_attestation_privileged(self) -> None:
        jobs = load_workflow("release-domain-observations.yml")["jobs"]
        privileged = {
            name
            for name, job in jobs.items()
            if job.get("permissions", {}).get("id-token") == "write"
            or "attestations" in job.get("permissions", {})
        }
        self.assertEqual(privileged, {"sign"})
        for name in privileged:
            serialized = json.dumps(jobs[name], sort_keys=True)
            self.assertNotIn("actions/checkout@", serialized, name)
            self.assertNotIn("scripts/release-domain-observer.py", serialized, name)
            self.assertNotIn("scripts/live-conformance.mjs", serialized, name)
            self.assertNotIn("secrets.", serialized, name)
        for name in (
            "sources",
            "live_provider_capture",
            "github_authority",
            "javascript_harness",
            "javascript_collect",
            "observe_non_sdk",
            "aggregate",
        ):
            permissions = jobs[name].get("permissions", {})
            self.assertNotEqual(permissions.get("id-token"), "write", name)
            self.assertNotIn("attestations", permissions, name)
            self.assertNotIn("artifact-metadata", permissions, name)
        collector = json.dumps(jobs["javascript_collect"], sort_keys=True)
        self.assertNotIn("LATCHWAY_LIVE_SDK_IDENTITY_TOKEN", collector)
        self.assertNotIn("LATCHWAY_LIVE_SDK_FIREBASE_APP_CHECK_TOKEN", collector)
        self.assertNotIn("LATCHWAY_LIVE_SDK_TURNSTILE_TOKEN", collector)
        self.assertIn("LATCHWAY_ONE_TIME_LIVE_SDK_GRANT", collector)

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
