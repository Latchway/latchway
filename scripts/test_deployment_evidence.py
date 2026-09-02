#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("deployment-evidence.py")
SPEC = importlib.util.spec_from_file_location("deployment_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
deployment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deployment
SPEC.loader.exec_module(deployment)


COMMIT = "a" * 40
DIGEST = "b" * 64
BUNDLE = "c" * 64
PLATFORM_DIGEST = "d" * 64
CONFIG_DIGEST = "e" * 64
MIRROR_DIGEST = "f" * 64
IMAGE = f"ghcr.io/latchway/latchway@sha256:{DIGEST}"
STARTED = "2026-08-29T01:00:00Z"
FINISHED = "2026-08-29T01:05:00Z"


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def http_observation(endpoint: str, path: str) -> dict[str, object]:
    if path == "/healthz":
        body = {
            "status": "ok",
            "build": {
                "version": "1.0.0",
                "commit": COMMIT,
                "build_date": "2026-08-29T00:00:00Z",
                "contract_version": "1.0.0",
                "protocol_version": "1",
            },
        }
    else:
        body = {
            "status": "ready",
            "checks": {
                "database": "ok",
                "schema": "ok",
                "active_configuration": "ok",
                "master_key": "ok",
                "signing_key": "ok",
                "worker_heartbeat": "ok",
            },
        }
    return {
        "url": endpoint + path,
        "status_code": 200,
        "observed_at": "2026-08-29T01:03:00Z",
        "tls": not endpoint.startswith("http://127.0.0.1"),
        "body": body,
    }


def shutdown(
    method: str,
    platform_timeout: int,
    app_timeout: int,
    digest: str = DIGEST,
) -> dict[str, object]:
    return {
        "method": method,
        "started_at": "2026-08-29T01:03:10Z",
        "finished_at": "2026-08-29T01:04:10Z",
        "signal": "SIGTERM",
        "platform_timeout_seconds": platform_timeout,
        "application_timeout_seconds": app_timeout,
        "exit_code": 0,
        "readiness_restored": True,
        "before": {"image_digest": f"sha256:{digest}", "resource_id": "before"},
        "after": {"image_digest": f"sha256:{digest}", "resource_id": "after"},
    }


def platform_values(platform: str) -> tuple[str, dict[str, object], dict[str, object], dict[str, object]]:
    migration = {
        "command": ["/latchway", "--output", "json", "migrate", "status"],
        "status": {"current": 16, "available": 16, "up_to_date": True},
        "provider_execution": {},
    }
    if platform == "compose":
        endpoint = "http://127.0.0.1:8080"
        control = {
            "platform": platform,
            "project": "latchway-release",
            "gateway": {
                "Config": {
                    "Image": IMAGE,
                    "Labels": {"com.docker.compose.project": "latchway-release"},
                },
                "State": {"Running": True, "Health": {"Status": "healthy"}},
            },
            "image": {"RepoDigests": [IMAGE]},
        }
        migration["provider_execution"] = {"exit_code": 0, "container_id": "abcdef"}
        stopped = shutdown("compose_sigterm_restart", 35, 30)
    elif platform == "cloud_run":
        endpoint = "https://ai.example.com"
        container = {
            "image": IMAGE,
            "env": [
                {"name": "LATCHWAY_DATABASE_URL", "valueFrom": {"secretKeyRef": {"name": "database"}}},
                {"name": "LATCHWAY_MASTER_KEY", "valueFrom": {"secretKeyRef": {"name": "master"}}},
                {"name": "LATCHWAY_SHUTDOWN_TIMEOUT", "value": "8s"},
            ],
        }
        control = {
            "platform": platform,
            "service": {
                "metadata": {
                    "name": "latchway",
                    "selfLink": "https://run.googleapis.com/apis/serving.knative.dev/v1/namespaces/p/services/latchway",
                },
                "spec": {"template": {"spec": {"containers": [container]}}},
            },
            "revision": {"status": {"imageDigest": f"sha256:{DIGEST}"}},
            "migration_job": {
                "spec": {
                    "template": {
                        "spec": {
                            "template": {
                                "spec": {"containers": [{"image": IMAGE}]}
                            }
                        }
                    }
                }
            },
        }
        migration["provider_execution"] = {
            "metadata": {"name": "migration-execution"},
            "status": {"conditions": [{"type": "Completed", "status": "True"}], "succeededCount": 1},
            "log_record": {
                "execution_name": "migration-execution",
                "insert_ids": ["provider-log-entry"],
                "line_count": 1,
                "timestamp": "2026-08-29T01:02:00Z",
            },
        }
        stopped = shutdown("cloud_run_revision_rollout", 10, 8)
    elif platform == "aws":
        endpoint = "https://ai.example.com"
        container_definition = {
            "name": "latchway",
            "image": f"123.dkr.ecr.test.amazonaws.com/latchway@sha256:{DIGEST}",
            "stopTimeout": 35,
            "readonlyRootFilesystem": True,
            "environment": [{"name": "LATCHWAY_SHUTDOWN_TIMEOUT", "value": "30s"}],
            "secrets": [
                {"name": "LATCHWAY_DATABASE_URL", "valueFrom": "arn:aws:secretsmanager:r:a:secret:db"},
                {"name": "LATCHWAY_MASTER_KEY", "valueFrom": "arn:aws:secretsmanager:r:a:secret:key"},
            ],
        }
        task = {"lastStatus": "RUNNING", "containers": [{"imageDigest": f"sha256:{DIGEST}"}]}
        control = {
            "platform": platform,
            "service": {"serviceArn": "arn:aws:ecs:r:a:service/latchway", "status": "ACTIVE", "desiredCount": 2, "runningCount": 2},
            "task_definition": {"containerDefinitions": [container_definition]},
            "tasks": [task, task],
        }
        migration["provider_execution"] = {
            "stopped_task": {
                "lastStatus": "STOPPED",
                "containers": [{"exitCode": 0, "imageDigest": f"sha256:{DIGEST}"}],
            },
            "log_record": {
                "log_stream": "latchway/latchway/task",
                "timestamp_ms": 1787965320000,
                "ingestion_time_ms": 1787965321000,
                "line_count": 5,
            },
        }
        stopped = shutdown("ecs_task_replacement", 35, 30)
    elif platform == "fly_io":
        endpoint = "https://ai.example.com"
        machine = {
            "id": "machine", "instance_id": "instance-before", "state": "started",
            "image_ref": {"digest": f"sha256:{DIGEST}"}, "checks": [{"status": "passing"}],
        }
        control = {
            "platform": platform,
            "app": {"ID": "fly-app-id", "Name": "latchway"},
            "machines": [machine, {**machine, "id": "machine2", "instance_id": "instance-two"}],
        }
        migration["provider_execution"] = {"exit_code": 0, "machine_id": "machine", "stdout_sha256": "d" * 64}
        stopped = shutdown("fly_machine_restart", 35, 30)
    else:
        endpoint = "https://ai.example.com"
        application_id = "12345678-abcd-1234-abcd-123456789abc"
        mirror_image = f"registry.cloudflare.com/account/latchway@sha256:{MIRROR_DIGEST}"
        layers = [{"digest": f"sha256:{'1' * 64}", "size": 1234}]
        control = {
            "platform": platform,
            "worker": {
                "status": "ready",
                "resource_id": application_id,
                "deployments": [{"id": "deployment"}],
                "versions": [{"id": "version"}],
            },
            "container": {
                "application": {
                    "id": application_id,
                    "name": "latchway",
                    "state": "active",
                    "instances": 1,
                    "image": mirror_image,
                    "version": 7,
                    "updated_at": "2026-08-29T01:00:30Z",
                },
                "instances": [{
                    "id": "instance-id",
                    "name": "instance-0",
                    "state": "running",
                    "location": "sin01",
                    "version": 7,
                    "created": "2026-08-29T01:03:30Z",
                }],
                "canonical": {
                    "index_digest": f"sha256:{DIGEST}",
                    "platform": "linux/amd64",
                    "platform_digest": f"sha256:{PLATFORM_DIGEST}",
                    "config_digest": f"sha256:{CONFIG_DIGEST}",
                    "layers": layers,
                },
                "mirror": {
                    "image": mirror_image,
                    "manifest_digest": f"sha256:{MIRROR_DIGEST}",
                    "config_digest": f"sha256:{CONFIG_DIGEST}",
                    "layers": layers,
                },
            },
        }
        migration["provider_execution"] = {
            "exit_code": 0,
            "evidence_id": "12345-1",
            "instance_name": "instance-0",
            "command": ["/latchway", "--output", "json", "migrate", "status"],
        }
        stopped = shutdown(
            "cloudflare_container_replacement", 900, 30, MIRROR_DIGEST
        )
        stopped.update({"evidence_id": "12345-1", "provider_reason": "runtime_signal"})
    migration["provider_execution"]["reported_status"] = migration["status"]
    return endpoint, control, migration, stopped


def capture(root: Path, platform: str) -> dict[str, object]:
    endpoint, control, migration, stopped = platform_values(platform)
    resource_id = {
        "compose": "latchway-release",
        "cloud_run": "https://run.googleapis.com/apis/serving.knative.dev/v1/namespaces/p/services/latchway",
        "aws": "arn:aws:ecs:r:a:service/latchway",
        "fly_io": "fly-app-id",
        "cloudflare_containers": "12345678-abcd-1234-abcd-123456789abc",
    }[platform]
    values = {
        "identity": {
            "platform": platform,
            "resource_id": resource_id,
            "observed_at": "2026-08-29T01:01:00Z",
            "provider_response": {"id": resource_id},
        },
        "control_plane": control,
        "migration": migration,
        "health": http_observation(endpoint, "/healthz"),
        "readiness": http_observation(endpoint, "/readyz"),
        "secrets": {
            "required_names": sorted(deployment.REQUIRED_SECRET_NAMES),
            "runtime_references": [{"name": name, "reference": f"ref/{name}"} for name in sorted(deployment.REQUIRED_SECRET_NAMES)],
            "provider_resources": [] if platform == "compose" else [{"resource_id": "provider/secret"}],
        },
        "shutdown": stopped,
    }
    observations: dict[str, object] = {}
    for name, value in values.items():
        path = root / f"{name}.json"
        dump(path, value)
        observations[name] = {"path": path.name, "sha256": deployment.sha256_file(path)}
    manifest = {
        "schema_version": 1,
        "kind": "latchway_cloud_deployment_capture",
        "platform": platform,
        "started_at": STARTED,
        "finished_at": FINISHED,
        "core_commit": COMMIT,
        "core_release": "v1.0.0",
        "contract_version": "1.0.0",
        "bundle_sha256": BUNDLE,
        "oci_image_digest": IMAGE,
        "endpoint": endpoint,
        "provider_resource_id": resource_id,
        "collector": {
            "repository": "Latchway/latchway",
            "workflow_ref": "Latchway/latchway/.github/workflows/deployment-evidence.yml@refs/heads/main",
            "ref": "refs/heads/main",
            "sha": "e" * 40,
            "run_id": "12345",
            "run_attempt": 1,
            "runner_environment": "github-hosted",
            "environment": f"deployment-evidence-{platform}",
        },
        "observations": observations,
    }
    dump(root / "manifest.json", manifest)
    return manifest


class DeploymentEvidenceTests(unittest.TestCase):
    @staticmethod
    def embedded_python(run: str) -> str:
        marker = "<<'PY'\n"
        if marker not in run:
            raise AssertionError("fixed inline Python heredoc is missing")
        body = run.split(marker, 1)[1].split("\nPY\n", 1)[0]
        compile(body, "deployment-evidence-workflow-inline.py", "exec")
        return body

    def test_workflow_is_prepublication_and_candidate_attested(self) -> None:
        result = deployment.validate_workflow()
        self.assertGreaterEqual(result["pinned_actions"], 1)
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        text = workflow_path.read_text()
        workflow = deployment.yaml_as_json(workflow_path)
        jobs = workflow["jobs"]
        self.assertEqual(
            workflow["env"],
            {
                "TRUSTED_WRANGLER_PACKAGE_JSON_SHA256": deployment.WRANGLER_PACKAGE_JSON_SHA256,
                "TRUSTED_WRANGLER_PACKAGE_LOCK_SHA256": deployment.WRANGLER_PACKAGE_LOCK_SHA256,
                "TRUSTED_WRANGLER_ALLOWED_PACKAGES_SHA256": deployment.WRANGLER_ALLOWED_PACKAGES_SHA256,
                "TRUSTED_WRANGLER_PACKAGE_COUNT": str(deployment.WRANGLER_PACKAGE_COUNT),
            },
        )
        self.assertEqual(
            set(jobs),
            {
                "static",
                "authenticate",
                "cloudflare-toolchain-source",
                "trusted-cloudflare-tool",
                "prepare",
                "capture",
                "capture_compose",
                "finalize",
                "sign",
            },
        )
        for name in (
            "authenticate",
            "trusted-cloudflare-tool",
            "capture",
            "capture_compose",
            "sign",
        ):
            self.assertFalse(
                any(
                    str(step.get("uses", "")).startswith("actions/checkout@")
                    for step in jobs[name]["steps"]
                ),
                name,
            )
        toolchain_source = jobs["cloudflare-toolchain-source"]
        self.assertEqual(toolchain_source["permissions"], {"contents": "read"})
        toolchain_source_text = json.dumps(toolchain_source, sort_keys=True)
        self.assertIn("${{ github.sha }}", toolchain_source_text)
        self.assertIn("sparse-checkout-cone-mode", toolchain_source_text)
        self.assertNotIn("inputs.candidate_commit", toolchain_source_text)
        self.assertNotIn("scripts/", toolchain_source_text)
        self.assertNotIn("${{ secrets.", toolchain_source_text)
        for name in (
            "authenticate",
            "trusted-cloudflare-tool",
            "prepare",
            "capture_compose",
            "finalize",
            "sign",
        ):
            self.assertNotIn("${{ secrets.", json.dumps(jobs[name], sort_keys=True))
        self.assertNotIn("attestations", jobs["capture"]["permissions"])
        self.assertNotIn("artifact-metadata", jobs["capture"]["permissions"])
        self.assertEqual(jobs["capture"]["permissions"]["id-token"], "write")
        self.assertNotIn("packages", jobs["capture"]["permissions"])
        self.assertNotIn("id-token", jobs["capture_compose"]["permissions"])
        self.assertNotIn("packages", jobs["capture_compose"]["permissions"])
        self.assertEqual(jobs["trusted-cloudflare-tool"]["permissions"], {})
        self.assertEqual(
            jobs["authenticate"]["environment"], "deployment-evidence-authentication"
        )
        self.assertEqual(jobs["sign"]["environment"], "deployment-evidence-signing")
        self.assertNotIn("refs/tags/", text)
        self.assertIn('--source-digest "$CANDIDATE_COMMIT"', text)
        self.assertIn('--core-commit "$CANDIDATE_COMMIT"', text)
        self.assertIn("version: '0.4.89'", text)
        self.assertIn(
            'flyctl config validate --strict --app "$FLY_APP" --config "$RUNNER_TEMP/provider-inputs/fly.toml"',
            text,
        )
        prepare_text = json.dumps(jobs["prepare"], sort_keys=True)
        self.assertNotIn("setup-flyctl", prepare_text)
        self.assertNotIn("flyctl config validate", prepare_text)
        fly_validation = next(
            step
            for step in jobs["capture"]["steps"]
            if step.get("name")
            == "Validate Fly configuration against the authenticated platform"
        )
        self.assertEqual(
            fly_validation["env"],
            {"FLY_API_TOKEN": "${{ secrets.FLY_API_TOKEN }}"},
        )
        self.assertLess(
            text.index("uses: superfly/flyctl-actions/setup-flyctl@"),
            text.index(
                'flyctl config validate --strict --app "$FLY_APP" --config "$RUNNER_TEMP/provider-inputs/fly.toml"'
            ),
        )

    def test_oidc_jobs_never_checkout_or_execute_candidate_helpers(self) -> None:
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        jobs = deployment.yaml_as_json(workflow_path)["jobs"]
        privileged = {
            name
            for name, job in jobs.items()
            if job.get("permissions", {}).get("id-token") == "write"
            or "attestations" in job.get("permissions", {})
        }
        self.assertEqual(privileged, {"capture", "sign"})
        for name in privileged:
            serialized = json.dumps(jobs[name], sort_keys=True)
            self.assertNotIn("actions/checkout@", serialized, name)
        capture = json.dumps(jobs["capture"], sort_keys=True)
        for forbidden in (
            "docker compose",
            "npm ",
            "npx ",
            "pnpm ",
            "yarn ",
            "corepack ",
            "scripts/cloudflare-deployment-capture.py",
            "scripts/deployment-evidence.py",
            "scripts/release-candidate.py",
        ):
            self.assertNotIn(forbidden, capture)
        self.assertNotIn("id-token", jobs["prepare"].get("permissions", {}))
        self.assertNotIn(
            "actions/checkout@",
            json.dumps(jobs["trusted-cloudflare-tool"], sort_keys=True),
        )
        self.assertNotIn(
            "provider-inputs",
            json.dumps(jobs["trusted-cloudflare-tool"], sort_keys=True),
        )
        self.assertNotIn("id-token", jobs["capture_compose"]["permissions"])
        self.assertNotIn("id-token", jobs["finalize"]["permissions"])
        self.assertIn(
            "Build the candidate Cloudflare Worker without provider or OIDC credentials",
            [step.get("name", "") for step in jobs["prepare"]["steps"]],
        )
        self.assertIn(
            "Normalize the pre-captured Cloudflare responses without provider credentials",
            [step.get("name", "") for step in jobs["finalize"]["steps"]],
        )
        compose = json.dumps(jobs["capture_compose"], sort_keys=True)
        self.assertNotIn("docker/login-action", compose)
        self.assertNotIn("compose.review.yaml", compose)
        self.assertNotIn("compose.release.yaml", compose)
        self.assertIn("preloaded-images.tar", compose)
        self.assertIn('pull_policy:\\"never\\"', compose)
        capture_names = [step.get("name", "") for step in jobs["capture"]["steps"]]
        self.assertIn(
            "Validate and unpack only the fixed-integrity Wrangler distribution",
            capture_names,
        )
        self.assertIn(
            "Build a lock-closed Wrangler distribution without candidate inputs",
            [
                step.get("name", "")
                for step in jobs["trusted-cloudflare-tool"]["steps"]
            ],
        )
        trusted_tool = json.dumps(jobs["trusted-cloudflare-tool"], sort_keys=True)
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", trusted_tool)
        self.assertNotIn("npm install", trusted_tool)
        self.assertIn("allowed-packages.json", trusted_tool)
        self.assertIn("WRANGLER_WRITE_LOGS", trusted_tool)
        capture_job = jobs["capture"]
        cloudflare_step = next(
            step
            for step in capture_job["steps"]
            if step.get("name")
            == "Capture Cloudflare Container image, migration, secret, and replacement evidence"
        )
        cloudflare_run = cloudflare_step["run"]
        self.assertIn("TRUSTED_WRANGLER_PACKAGE_LOCK_SHA256", cloudflare_run)
        self.assertIn("TRUSTED_WRANGLER_ALLOWED_PACKAGES_SHA256", cloudflare_run)
        self.assertIn("credential-boundary-wrangler-packages.json", cloudflare_run)
        self.assertNotIn("npm ", cloudflare_run)
        self.assertNotIn("npx ", cloudflare_run)
        self.assertNotIn("pnpm ", cloudflare_run)
        self.assertIn(
            '"${wrangler[@]}" deploy --no-bundle', workflow_path.read_text()
        )
        self.assertIn(
            "docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
            compose,
        )

    def test_cloudflare_application_discovery_is_complete_and_bounded(self) -> None:
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        jobs = deployment.yaml_as_json(workflow_path)["jobs"]
        capture = jobs["capture"]
        cloudflare_step = next(
            step
            for step in capture["steps"]
            if step.get("name")
            == "Capture Cloudflare Container image, migration, secret, and replacement evidence"
        )
        run = cloudflare_step["run"]
        self.assertNotIn('"${wrangler[@]}" containers list', run)
        self.assertNotIn(
            '--header "Authorization: Bearer $CLOUDFLARE_API_TOKEN"', run
        )
        for required in (
            "[[ \"$CLOUDFLARE_API_TOKEN\" =~ ^[A-Za-z0-9._~-]{20,256}$ ]]",
            "umask 077",
            "Authorization: Bearer %s",
            '--header @"$cloudflare_api_headers"',
            "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/containers/dash/applications",
            "cloudflare_application_per_page=100",
            "cloudflare_application_max_pages=100",
            "cloudflare_application_max_records=5000",
            "cloudflare_application_max_page_bytes=1048576",
            "cloudflare_application_max_output_bytes=8388608",
            "page_number=$((page_number + 1))",
            'curl_arguments+=(--data-urlencode "page_token=$page_token")',
            ".result_info.next_page_token",
            "seen_page_token_hashes",
            ".success == true",
            ".errors == []",
            'if .health.instances.failed > 0 then "degraded"',
            'elif .health.instances.starting > 0 or .health.instances.scheduling > 0 then "provisioning"',
            'elif .health.instances.active > 0 then "active"',
            "([.[].id] | length) == ([.[].id] | unique | length)",
            "jq --sort-keys 'sort_by(.id)'",
        ):
            self.assertIn(required, run)
        self.assertEqual(
            run.count(
                "list_cloudflare_applications /tmp/cloudflare-applications-before.json"
            ),
            1,
        )
        self.assertEqual(
            run.count("list_cloudflare_applications /tmp/cloudflare-applications.json"),
            1,
        )
        self.assertEqual(
            run.count("then .[0] | {name, image, state, id, version}"), 2
        )
        cleanup = next(
            step
            for step in capture["steps"]
            if step.get("name")
            == "Remove any temporary Cloudflare registry credential"
        )
        self.assertEqual(
            cleanup["if"], "always() && inputs.platform == 'cloudflare_containers'"
        )
        for path in (
            "$RUNNER_TEMP/cloudflare-container-api.headers",
            "$RUNNER_TEMP/cloudflare-applications-api-response.json",
            "$RUNNER_TEMP/cloudflare-applications-api-normalized.json",
            "$RUNNER_TEMP/cloudflare-applications-api-accumulator.json",
            "$RUNNER_TEMP/cloudflare-applications-api-combined.json",
        ):
            self.assertIn(path, cleanup["run"])

    def test_cloudflare_application_discovery_follows_and_bounds_cursors(self) -> None:
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        jobs = deployment.yaml_as_json(workflow_path)["jobs"]
        run = next(
            step["run"]
            for step in jobs["capture"]["steps"]
            if step.get("name")
            == "Capture Cloudflare Container image, migration, secret, and replacement evidence"
        )
        start = run.index("cloudflare_applications_api=")
        end = run.index("\nevidence_id=", start)
        paginator = run[start:end]
        first_id = "11111111-1111-1111-1111-111111111111"
        second_id = "22222222-2222-2222-2222-222222222222"

        def application(
            identifier: str, name: str, image: str, **health: int
        ) -> dict[str, object]:
            return {
                "id": identifier,
                "name": name,
                "image": image,
                "instances": 1,
                "version": 3,
                "updated_at": "2026-09-02T01:00:00Z",
                "created_at": "2026-09-02T00:00:00Z",
                "health": {
                    "instances": {
                        "failed": health.get("failed", 0),
                        "starting": health.get("starting", 0),
                        "scheduling": health.get("scheduling", 0),
                        "active": health.get("active", 0),
                    }
                },
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.json"
            second = root / "second.json"
            output = root / "applications.json"
            mirror = "registry.cloudflare.com/" + "a" * 32 + "/latchway@sha256:" + "b" * 64
            dump(
                first,
                {
                    "success": True,
                    "errors": [],
                    "messages": [],
                    "result": [
                        application(
                            second_id, "other", "registry.cloudflare.com/other", failed=1
                        )
                    ],
                    "result_info": {"next_page_token": "cursor-2"},
                },
            )
            dump(
                second,
                {
                    "success": True,
                    "errors": [],
                    "messages": [],
                    "result": [application(first_id, "latchway", mirror, active=1)],
                    "result_info": {"next_page_token": None},
                },
            )
            wrapper = f"""set -Eeuo pipefail
curl() {{
  local output_path= cursor= argument
  while (($# > 0)); do
    argument="$1"
    case "$argument" in
      --output)
        output_path="$2"
        shift 2
        ;;
      --data-urlencode)
        if [[ "$2" == page_token=* ]]; then cursor="${{2#page_token=}}"; fi
        shift 2
        ;;
      *) shift ;;
    esac
  done
  case "$cursor" in
    "") install -m 0600 "$PAGE_ONE" "$output_path" ;;
    cursor-2) install -m 0600 "$PAGE_TWO" "$output_path" ;;
    *) return 65 ;;
  esac
}}
{paginator}
list_cloudflare_applications "$DESTINATION"
jq -e --arg first_id "$FIRST_ID" --arg second_id "$SECOND_ID" --arg image "$MIRROR" '
  length == 2 and
  .[0].id == $first_id and .[0].name == "latchway" and .[0].image == $image and .[0].state == "active" and .[0].version == 3 and
  .[1].id == $second_id and .[1].state == "degraded"
' "$DESTINATION" >/dev/null
"""
            environment = {
                "PATH": str(Path("/usr/bin")) + ":/bin:/usr/sbin:/sbin",
                "RUNNER_TEMP": str(root),
                "CLOUDFLARE_ACCOUNT_ID": "a" * 32,
                "cloudflare_api_headers": str(root / "headers"),
                "PAGE_ONE": str(first),
                "PAGE_TWO": str(second),
                "DESTINATION": str(output),
                "FIRST_ID": first_id,
                "SECOND_ID": second_id,
                "MIRROR": mirror,
            }
            success = subprocess.run(
                ["bash", "-c", wrapper],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(success.returncode, 0, success.stderr)

            repeated = json.loads(second.read_text(encoding="utf-8"))
            repeated["result_info"]["next_page_token"] = "cursor-2"
            dump(second, repeated)
            rejected = subprocess.run(
                ["bash", "-c", wrapper],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_fresh_signer_authenticates_raw_capture_and_archive_closure(self) -> None:
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        jobs = deployment.yaml_as_json(workflow_path)["jobs"]
        signer = jobs["sign"]
        names = [step.get("name", "") for step in signer["steps"]]
        raw_download = names.index(
            "Download the exact raw provider artifact on the fresh signer"
        )
        authority_download = names.index(
            "Download authenticated candidate identity on the fresh signer"
        )
        binding_index = names.index(
            "Independently bind the deterministic archive to authenticated raw capture"
        )
        attestation_index = names.index("Attest the bounded provider capture")
        self.assertLess(raw_download, binding_index)
        self.assertLess(authority_download, binding_index)
        self.assertLess(binding_index, attestation_index)
        self.assertFalse(
            any(
                str(step.get("uses", "")).startswith("actions/checkout@")
                for step in signer["steps"]
            )
        )
        serialized = json.dumps(signer, sort_keys=True)
        for forbidden in (
            "scripts/deployment-evidence.py",
            "scripts/cloudflare-deployment-capture.py",
            "scripts/release-candidate.py",
            "${{ secrets.",
        ):
            self.assertNotIn(forbidden, serialized)
        binding_step = signer["steps"][binding_index]
        run = binding_step["run"]
        body = self.embedded_python(run)
        for required in (
            "candidate archive entry closure is invalid",
            "raw provider artifact closure is invalid",
            "normalized capture is not byte-bound to provider raw data",
            "Cloudflare normalized capture is not bound to raw responses",
            "latchway_authenticated_deployment_capture",
            "latchway-deployment-binding.json",
            '"run_id": run_id',
            '"provider_resource_id": raw_resource',
            'info.uid = info.gid = 0',
            'info.mtime = 0',
        ):
            self.assertIn(required, body)
        self.assertIn(
            "latchway-deployment-raw-${{ inputs.platform }}-${{ inputs.candidate_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
            workflow_path.read_text(encoding="utf-8"),
        )

    def test_static_assets_pass(self) -> None:
        checks = deployment.static_checks()
        self.assertTrue(checks)
        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        compose = deployment.yaml_as_json(
            SCRIPT.parent.parent / "deploy/compose/compose.release.yaml"
        )
        postgres = compose["services"]["postgres"]
        self.assertEqual(
            postgres["image"],
            "docker.io/library/postgres@sha256:"
            "d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
        )
        self.assertEqual(postgres["volumes"], ["postgres-data:/var/lib/postgresql"])
        quickstart = deployment.yaml_as_json(SCRIPT.parent.parent / "compose.yaml")
        self.assertEqual(
            quickstart["services"]["postgres"]["image"],
            "docker.io/library/postgres@sha256:"
            "d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
        )
        self.assertEqual(
            quickstart["services"]["postgres"]["volumes"],
            ["postgres-data:/var/lib/postgresql"],
        )

    def test_fly_static_validator_rejects_unknown_fields(self) -> None:
        document = tomllib.loads(
            (SCRIPT.parent.parent / "deploy/fly/fly.toml").read_text(encoding="utf-8")
        )
        result = deployment.validate_fly_document(document)
        self.assertTrue(result["strict_offline_fields"])

        unknown_section = copy.deepcopy(document)
        unknown_section["unrecognized"] = {}
        with self.assertRaises(deployment.EvidenceError) as raised:
            deployment.validate_fly_document(unknown_section)
        self.assertEqual(raised.exception.code, "fly_top_level_fields_invalid")

        unknown_check_key = copy.deepcopy(document)
        unknown_check_key["http_service"]["checks"][0]["unrecognized"] = True
        with self.assertRaises(deployment.EvidenceError) as raised:
            deployment.validate_fly_document(unknown_check_key)
        self.assertEqual(raised.exception.code, "fly_health_check_fields_invalid")

    def test_wrangler_toolchain_closure_is_exact_and_registry_only(self) -> None:
        result = deployment.validate_wrangler_toolchain()
        self.assertEqual(result["wrangler_version"], "4.127.1")
        self.assertEqual(result["package_count"], 91)
        root = SCRIPT.parent.parent / ".github/toolchains/wrangler"
        package = deployment.read_json(root / "package.json")
        lock = deployment.read_json(root / "package-lock.json")
        allowlist = deployment.read_json(root / "allowed-packages.json")

        non_registry = copy.deepcopy(lock)
        non_registry["packages"]["node_modules/wrangler"]["resolved"] = (
            "https://packages.example.invalid/wrangler-4.127.1.tgz"
        )
        with self.assertRaises(deployment.EvidenceError) as raised:
            deployment.validate_wrangler_lock_documents(
                package, non_registry, allowlist
            )
        self.assertEqual(
            raised.exception.code, "cloudflare_toolchain_package_registry_invalid"
        )

        missing_integrity = copy.deepcopy(lock)
        del missing_integrity["packages"]["node_modules/wrangler"]["integrity"]
        with self.assertRaises(deployment.EvidenceError) as raised:
            deployment.validate_wrangler_lock_documents(
                package, missing_integrity, allowlist
            )
        self.assertEqual(
            raised.exception.code, "cloudflare_toolchain_package_integrity_invalid"
        )

        incomplete_allowlist = copy.deepcopy(allowlist)
        incomplete_allowlist["packages"].pop()
        with self.assertRaises(deployment.EvidenceError) as raised:
            deployment.validate_wrangler_lock_documents(
                package, lock, incomplete_allowlist
            )
        self.assertEqual(
            raised.exception.code, "cloudflare_toolchain_allowlist_mismatch"
        )

    def test_each_platform_capture_passes(self) -> None:
        for platform in deployment.PLATFORMS:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                capture(root, platform)
                manifest, checks = deployment.validate_capture(root)
                self.assertEqual(manifest["platform"], platform)
                self.assertTrue(all(item.status == "passed" for item in checks), checks)

    def test_capture_rejects_digest_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "aws")
            control = json.loads((root / "control_plane.json").read_text())
            control["tasks"][0]["containers"][0]["imageDigest"] = "sha256:" + "d" * 64
            dump(root / "control_plane.json", control)
            manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(root / "control_plane.json")
            dump(root / "manifest.json", manifest)
            _, checks = deployment.validate_capture(root)
            failure = next(item for item in checks if item.identifier == "capture.control_plane")
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "aws_task_digest_mismatch")

    def test_capture_separates_trusted_workflow_source_from_candidate_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "compose")
            self.assertNotEqual(manifest["collector"]["sha"], manifest["core_commit"])
            validated, checks = deployment.validate_capture(root)
            self.assertEqual(validated["core_commit"], COMMIT)
            self.assertTrue(all(item.status == "passed" for item in checks), checks)

    def test_duplicate_json_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n')
            with self.assertRaisesRegex(deployment.EvidenceError, "duplicate_json_member"):
                deployment.read_json(path)

    def test_http_observer_rejects_private_cloud_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            deployment.socket,
            "getaddrinfo",
            return_value=[(2, 1, 6, "", ("10.0.0.5", 443))],
        ):
            with self.assertRaisesRegex(deployment.EvidenceError, "non_public_endpoint_forbidden"):
                deployment.observe_http(
                    "https://internal.example.test", Path(temporary), timeout=1
                )

    def test_http_observer_accepts_a_connected_loopback_compose_target(self) -> None:
        responses = []
        for path in ("/healthz", "/readyz"):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.status = 200
            response.url = f"http://127.0.0.1:18080{path}"
            response.read.return_value = json.dumps({"path": path}).encode()
            response.fp.raw._sock.getpeername.return_value = ("127.0.0.1", 18080)
            responses.append(response)
        opener = mock.Mock()
        opener.open.side_effect = responses
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            deployment.urllib.request, "build_opener", return_value=opener
        ):
            deployment.observe_http(
                "http://127.0.0.1:18080",
                Path(temporary),
                timeout=1,
            )
            self.assertEqual(
                json.loads((Path(temporary) / "health.json").read_text())["body"],
                {"path": "/healthz"},
            )

    def test_cloudflare_rejects_provider_status_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "cloudflare_containers")
            migration = json.loads((root / "migration.json").read_text())
            migration["provider_execution"]["reported_status"] = {
                "current": 15,
                "available": 16,
                "up_to_date": False,
            }
            dump(root / "migration.json", migration)
            manifest["observations"]["migration"]["sha256"] = deployment.sha256_file(
                root / "migration.json"
            )
            dump(root / "manifest.json", manifest)
            _, checks = deployment.validate_capture(root)
            failure = next(item for item in checks if item.identifier == "capture.migration")
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "migration_provider_execution_invalid")

    def test_cloudflare_rejects_unrestored_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "cloudflare_containers")
            stopped = json.loads((root / "shutdown.json").read_text())
            stopped["readiness_restored"] = False
            dump(root / "shutdown.json", stopped)
            manifest["observations"]["shutdown"]["sha256"] = deployment.sha256_file(
                root / "shutdown.json"
            )
            dump(root / "manifest.json", manifest)
            _, checks = deployment.validate_capture(root)
            failure = next(
                item for item in checks if item.identifier == "capture.control_plane"
            )
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "shutdown_observation_invalid")

    def test_cloudflare_rejects_non_equivalent_registry_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "cloudflare_containers")
            control = json.loads((root / "control_plane.json").read_text())
            control["container"]["mirror"]["layers"][0]["digest"] = (
                "sha256:" + "9" * 64
            )
            dump(root / "control_plane.json", control)
            manifest["observations"]["control_plane"]["sha256"] = (
                deployment.sha256_file(root / "control_plane.json")
            )
            dump(root / "manifest.json", manifest)
            _, checks = deployment.validate_capture(root)
            failure = next(
                item for item in checks if item.identifier == "capture.control_plane"
            )
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "cloudflare_deployment_invalid")

    def test_seal_is_deterministic_and_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture_dir = root / "capture"
            capture_dir.mkdir()
            capture(capture_dir, "compose")
            first, second = root / "first.tar.gz", root / "second.tar.gz"
            deployment.seal_capture(capture_dir, first)
            deployment.seal_capture(capture_dir, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:gz") as archive:
                self.assertEqual(archive.getnames(), sorted(archive.getnames()))
                self.assertTrue(all(member.mtime == 0 for member in archive.getmembers()))

    def test_finalize_requires_all_attested_platforms_and_emits_cross_repo_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts/cloud-deployments"
            artifacts.mkdir(parents=True)
            for platform in deployment.PLATFORMS:
                capture_dir = root / f"capture-{platform}"
                capture_dir.mkdir()
                capture(capture_dir, platform)
                deployment.seal_capture(capture_dir, artifacts / f"{platform}.tar.gz")
                (artifacts / f"{platform}.attestation.json").write_text("{}\n")
            trusted = root / "trusted-root.jsonl"
            trusted.write_text("{}\n")
            coordinates = {
                name: {"commit": COMMIT, "tag": "v1.0.0", "version": "1.0.0"}
                for name in ("core", "javascript", "ios", "android", "react_native")
            }
            coordinate_path = root / "coordinates.json"
            dump(coordinate_path, coordinates)
            args = argparse.Namespace(
                evidence_root=root,
                coordinates=coordinate_path,
                trusted_root=trusted,
                core_commit=COMMIT,
                core_release="v1.0.0",
                contract_version="1.0.0",
                bundle_sha256=BUNDLE,
                image=IMAGE,
            )
            with mock.patch.object(deployment, "verify_attestation", return_value=[{"verified": True}]):
                result = deployment.finalize(args)
            self.assertEqual(result["domain"], "cloud_deployments")
            self.assertEqual(result["status"], "passed")
            self.assertTrue(all(result["claims"].values()))
            self.assertEqual(len(result["artifacts"]), 11)
            self.assertEqual(json.loads((root / "cloud_deployments.json").read_text()), result)

    def test_finalize_fails_when_one_platform_archive_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifacts/cloud-deployments").mkdir(parents=True)
            coordinates = {
                name: {"commit": COMMIT, "tag": "v1.0.0", "version": "1.0.0"}
                for name in ("core", "javascript", "ios", "android", "react_native")
            }
            coordinate_path = root / "coordinates.json"
            dump(coordinate_path, coordinates)
            trusted = root / "trusted-root.jsonl"
            trusted.write_text("{}\n")
            args = argparse.Namespace(
                evidence_root=root,
                coordinates=coordinate_path,
                trusted_root=trusted,
                core_commit=COMMIT,
                core_release="v1.0.0",
                contract_version="1.0.0",
                bundle_sha256=BUNDLE,
                image=IMAGE,
            )
            with self.assertRaisesRegex(deployment.EvidenceError, "capture_archive_invalid"):
                deployment.finalize(args)


if __name__ == "__main__":
    unittest.main()
