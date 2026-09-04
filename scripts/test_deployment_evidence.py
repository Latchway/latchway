#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import http.server
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
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


def candidate_manifest(
    *, amd64_digest: str = PLATFORM_DIGEST,
) -> dict[str, object]:
    return {
        "status": "passed",
        "candidate_commit": COMMIT,
        "intended_tag": "v1.0.0",
        "image": {
            "repository": "ghcr.io/latchway/latchway",
            "index_digest": f"sha256:{DIGEST}",
            "platforms": {
                "linux/amd64": f"sha256:{amd64_digest}",
                "linux/arm64": "sha256:" + "e" * 64,
            },
        },
    }


def http_observation(endpoint: str, path: str) -> dict[str, object]:
    if path == "/healthz":
        body = {
            "status": "ok",
            "build": {
                "version": "1.0.0",
                "commit": COMMIT,
                "build_date": "2026-08-29T00:00:00Z",
                "contract_version": "1.0.0",
                "protocol_version": "2",
            },
        }
    else:
        body = {
            "status": "ready",
            "checks": {
                "database": "ok",
                "schema": "ok",
                "active_configuration": "ok",
                "quota_completion_pool": "ok",
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


def database_pool(cloudflare: bool = False) -> dict[str, int]:
    aggregate, regular, completion = (5, 3, 2) if cloudflare else (20, 15, 5)
    return {
        "aggregate_max_connections": aggregate,
        "regular_max_connections": regular,
        "completion_max_connections": completion,
    }


def database_pool_environment(cloudflare: bool = False) -> list[dict[str, str]]:
    aggregate, completion = ("5", "2") if cloudflare else ("20", "5")
    return [
        {"name": "LATCHWAY_DB_MAX_CONNECTIONS", "value": aggregate},
        {"name": "LATCHWAY_DB_COMPLETION_CONNECTIONS", "value": completion},
    ]


def cloud_run_startup_probe() -> dict[str, object]:
    return copy.deepcopy(deployment.CLOUD_RUN_STARTUP_PROBE)


def cloud_run_runtime_environment(
    endpoint: str = "https://ai.example.com",
) -> list[dict[str, object]]:
    return [
        {"name": "LATCHWAY_ROLE", "value": "all"},
        {"name": "LATCHWAY_LOG_LEVEL", "value": "info"},
        {"name": "LATCHWAY_MIGRATE_ON_START", "value": "false"},
        {"name": "LATCHWAY_PUBLIC_ORIGIN", "value": endpoint},
        {
            "name": "LATCHWAY_DATABASE_URL",
            "valueFrom": {
                "secretKeyRef": {"name": "latchway-database-url", "key": "7"}
            },
        },
        {
            "name": "LATCHWAY_MASTER_KEY",
            "valueFrom": {
                "secretKeyRef": {"name": "latchway-master-key", "key": "4"}
            },
        },
        {"name": "LATCHWAY_SHUTDOWN_TIMEOUT", "value": "8s"},
        *database_pool_environment(),
    ]


def cloud_run_runtime_spec(endpoint: str, image: str = IMAGE) -> dict[str, object]:
    return {
        "serviceAccountName": deployment.CLOUD_RUN_RUNTIME_SERVICE_ACCOUNT,
        "containerConcurrency": 100,
        "timeoutSeconds": 3600,
        "containers": [{
            "name": "latchway",
            "image": image,
            "command": ["/latchway"],
            "args": ["serve", "--role", "all"],
            "ports": [{"name": "http1", "containerPort": 8080}],
            "resources": {"limits": {"cpu": "2", "memory": "2Gi"}},
            "env": cloud_run_runtime_environment(endpoint),
            "startupProbe": cloud_run_startup_probe(),
            "livenessProbe": copy.deepcopy(deployment.CLOUD_RUN_LIVENESS_PROBE),
        }],
    }


def cloud_run_metadata(collection: str, name: str) -> dict[str, str]:
    return {
        "name": name,
        "selfLink": (
            "https://run.googleapis.com/apis/serving.knative.dev/v1/"
            f"namespaces/latchway/{collection}/{name}"
        ),
        "uid": f"{collection}-{name}-uid",
        "location": deployment.CLOUD_RUN_REGION,
    }


def platform_values(platform: str) -> tuple[str, dict[str, object], dict[str, object], dict[str, object]]:
    migration = {
        "command": ["/latchway", "--output", "json", "migrate", "status"],
        "status": {"current": 29, "available": 29, "up_to_date": True},
        "provider_execution": {},
    }
    if platform == "compose":
        endpoint = "http://127.0.0.1:8080"
        control = {
            "platform": platform,
            "project": "latchway-release",
            "gateway": {
                "Id": "compose-gateway-after",
                "Config": {
                    "Image": IMAGE,
                    "Labels": {"com.docker.compose.project": "latchway-release"},
                    "Env": database_pool_environment(),
                },
                "State": {"Running": True, "Health": {"Status": "healthy"}},
            },
            "image": {"RepoDigests": [IMAGE]},
            "database_pool": database_pool(),
        }
        migration["provider_execution"] = {
            "exit_code": 0,
            "migration_container_exit_code": 0,
            "container_id": "abcdef",
        }
        stopped = shutdown("compose_sigterm_restart", 35, 30)
        stopped["before"]["resource_id"] = "compose-gateway-before"
        stopped["after"]["resource_id"] = "compose-gateway-after"
    elif platform == "cloud_run":
        endpoint = "https://ai.example.com"
        revision_name = "latchway-00002-ready"
        runtime_spec = cloud_run_runtime_spec(endpoint)
        annotations = copy.deepcopy(deployment.CLOUD_RUN_RUNTIME_ANNOTATIONS)
        database_env = [copy.deepcopy(cloud_run_runtime_environment(endpoint)[4])]
        job_container = {
            "name": "latchway-migrate",
            "image": IMAGE,
            "command": ["/latchway"],
            "args": ["migrate", "up"],
            "resources": copy.deepcopy(deployment.CLOUD_RUN_MIGRATION_RESOURCES),
            "env": database_env,
        }
        control = {
            "platform": platform,
            "service": {
                "metadata": cloud_run_metadata("services", "latchway"),
                "spec": {"template": {
                    "metadata": {"annotations": annotations},
                    "spec": copy.deepcopy(runtime_spec),
                }},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "latestReadyRevisionName": revision_name,
                    "traffic": [{
                        "revisionName": revision_name,
                        "percent": 100,
                    }],
                    "url": endpoint,
                },
            },
            "revision": {
                "metadata": {
                    **cloud_run_metadata("revisions", revision_name),
                    "annotations": copy.deepcopy(annotations),
                },
                "spec": copy.deepcopy(runtime_spec),
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "imageDigest": f"sha256:{DIGEST}",
                },
            },
            "migration_job": {
                "metadata": cloud_run_metadata("jobs", "latchway-migrate"),
                "spec": {
                    "executionTemplateAnnotations": copy.deepcopy(
                        deployment.CLOUD_RUN_CLOUD_SQL_ANNOTATIONS
                    ),
                    "taskCount": 1,
                    "parallelism": 1,
                    "serviceAccountName": deployment.CLOUD_RUN_MIGRATOR_SERVICE_ACCOUNT,
                    "timeoutSeconds": 900,
                    "maxRetries": 0,
                    "containers": [job_container],
                }
            },
            "database_pool": database_pool(),
            "network_profile": copy.deepcopy(deployment.CLOUD_RUN_NETWORK_PROFILE),
        }
        execution_name = "latchway-migrate-execution-abc"
        migration["provider_execution"] = {
            "metadata": {
                **cloud_run_metadata("executions", execution_name),
                "annotations": copy.deepcopy(
                    deployment.CLOUD_RUN_CLOUD_SQL_ANNOTATIONS
                ),
            },
            "spec": {"containers": [{
                "name": "latchway-migrate",
                "image": IMAGE,
                "command": ["/latchway"],
                "args": ["--output", "json", "migrate", "status"],
                "resources": copy.deepcopy(deployment.CLOUD_RUN_MIGRATION_RESOURCES),
                "env": copy.deepcopy(database_env),
            }]},
            "status": {
                "conditions": [{"type": "Completed", "status": "True"}],
                "succeededCount": 1,
                "failedCount": 0,
                "completionTime": "2026-08-29T01:02:30Z",
            },
            "log_record": {
                "execution_name": execution_name,
                "insert_ids": ["provider-log-entry"],
                "line_count": 1,
                "timestamp": "2026-08-29T01:02:00Z",
            },
        }
        stopped = {
            "method": "cloud_run_revision_rollout",
            "started_at": "2026-08-29T01:03:10Z",
            "finished_at": "2026-08-29T01:04:10Z",
            "readiness_restored": True,
            "before": {
                "image_digest": f"sha256:{DIGEST}",
                "resource_id": "latchway-00001-before",
            },
            "after": {
                "image_digest": f"sha256:{DIGEST}",
                "resource_id": revision_name,
            },
        }
    elif platform == "aws":
        endpoint = "https://ai.example.com"
        definition_arn = "arn:aws:ecs:r:a:task-definition/latchway:1"
        container_definition = {
            "name": "latchway",
            "image": f"123.dkr.ecr.test.amazonaws.com/latchway@sha256:{DIGEST}",
            "stopTimeout": 35,
            "readonlyRootFilesystem": True,
            "environment": [
                {"name": "LATCHWAY_SHUTDOWN_TIMEOUT", "value": "30s"},
                *database_pool_environment(),
            ],
            "secrets": [
                {"name": "LATCHWAY_DATABASE_URL", "valueFrom": "arn:aws:secretsmanager:r:a:secret:db"},
                {"name": "LATCHWAY_MASTER_KEY", "valueFrom": "arn:aws:secretsmanager:r:a:secret:key"},
            ],
        }
        task = {
            "lastStatus": "RUNNING",
            "taskDefinitionArn": definition_arn,
            "containers": [{"imageDigest": f"sha256:{DIGEST}"}],
        }
        control = {
            "platform": platform,
            "service": {
                "serviceArn": "arn:aws:ecs:r:a:service/latchway",
                "serviceName": "latchway",
                "clusterArn": "arn:aws:ecs:r:a:cluster/latchway",
                "status": "ACTIVE",
                "desiredCount": 2,
                "runningCount": 2,
                "taskDefinition": definition_arn,
                "deployments": [{
                    "id": "ecs-svc/1234567890",
                    "status": "PRIMARY",
                    "taskDefinition": definition_arn,
                    "desiredCount": 2,
                    "pendingCount": 0,
                    "runningCount": 2,
                    "rolloutState": "COMPLETED",
                }],
            },
            "task_definition": {
                "taskDefinitionArn": definition_arn,
                "containerDefinitions": [container_definition],
            },
            "tasks": [task, task],
            "database_pool": database_pool(),
        }
        migration["provider_execution"] = {
            "stopped_task": {
                "lastStatus": "STOPPED",
                "taskDefinitionArn": definition_arn,
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
            "environment": database_pool_environment(),
        }
        control = {
            "platform": platform,
            "app": {"ID": "fly-app-id", "Name": "latchway"},
            "machines": [machine, {**machine, "id": "machine2", "instance_id": "instance-two"}],
            "database_pool": database_pool(),
        }
        migration["provider_execution"] = {"exit_code": 0, "machine_id": "machine", "stdout_sha256": "d" * 64}
        stopped = shutdown("fly_machine_restart", 35, 30)
    else:
        endpoint = "https://ai.example.com"
        application_id = "12345678-abcd-1234-abcd-123456789abc"
        active_version_id = "87654321-abcd-1234-abcd-123456789abc"
        mirror_image = f"registry.cloudflare.com/account/latchway@sha256:{MIRROR_DIGEST}"
        layers = [{"digest": f"sha256:{'1' * 64}", "size": 1234}]
        control = {
            "platform": platform,
            "worker": {
                "status": "ready",
                "resource_id": application_id,
                "active_version_id": active_version_id,
                "deployments": [{
                    "id": "deployment",
                    "created_on": "2026-08-29T01:00:00Z",
                    "versions": [{"version_id": active_version_id, "percentage": 100}],
                }],
                "versions": [{
                    "id": active_version_id,
                    "resources": {"bindings": [
                        {"name": "LATCHWAY_DB_MAX_CONNECTIONS", "type": "plain_text", "text": "5"},
                        {"name": "LATCHWAY_DB_COMPLETION_CONNECTIONS", "type": "plain_text", "text": "2"},
                    ]},
                }],
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
            "database_pool": database_pool(cloudflare=True),
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
        "cloud_run": "https://run.googleapis.com/apis/serving.knative.dev/v1/namespaces/latchway/services/latchway",
        "aws": "arn:aws:ecs:r:a:service/latchway",
        "fly_io": "fly-app-id",
        "cloudflare_containers": "12345678-abcd-1234-abcd-123456789abc",
    }[platform]
    values = {
        "identity": {
            "platform": platform,
            "resource_id": resource_id,
            "observed_at": "2026-08-29T01:01:00Z",
            "provider_response": (
                {
                    "projectId": "latchway",
                    "projectNumber": "123456789",
                    "lifecycleState": "ACTIVE",
                    "gcloud_version": {"Google Cloud SDK": "540.0.0"},
                }
                if platform == "cloud_run"
                else {"id": resource_id}
            ),
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
    def embedded_python_blocks(run: str) -> list[str]:
        marker = "<<'PY'\n"
        blocks: list[str] = []
        for part in run.split(marker)[1:]:
            if "\nPY\n" not in part:
                raise AssertionError("fixed inline Python heredoc is not closed")
            body = part.split("\nPY\n", 1)[0]
            compile(body, "deployment-evidence-workflow-inline.py", "exec")
            blocks.append(body)
        return blocks

    @staticmethod
    def embedded_python(run: str) -> str:
        blocks = DeploymentEvidenceTests.embedded_python_blocks(run)
        if not blocks:
            raise AssertionError("fixed inline Python heredoc is missing")
        return blocks[0]

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
        # Cloudflare normalization plus capture validation and deterministic
        # sealing all consume the authenticated candidate manifest.
        self.assertEqual(text.count('--candidate-manifest "$candidate"'), 3)
        # Keep the release configuration, all five provider reducers, and the
        # independent Cloudflare signer reconstruction in this exact closure.
        self.assertEqual(text.count("LATCHWAY_DB_COMPLETION_CONNECTIONS"), 18)
        self.assertIn('LATCHWAY_DB_COMPLETION_CONNECTIONS: "2"', text)
        self.assertIn(
            'LATCHWAY_DB_COMPLETION_CONNECTIONS:"${LATCHWAY_DB_COMPLETION_CONNECTIONS:-5}"',
            text,
        )
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

    def test_cloud_run_read_only_preflight_precedes_mutation_and_fails_closed(self) -> None:
        jobs = deployment.yaml_as_json(
            SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        )["jobs"]
        capture_job = jobs["capture"]
        step = next(
            item
            for item in capture_job["steps"]
            if item.get("name")
            == "Capture Cloud Run migration, revision, secret, and rollout evidence"
        )
        run = step["run"]
        marker = "# Read-only preflight: no job execution or service mutation is allowed above this point."
        self.assertLess(run.index(marker), run.index("gcloud run jobs execute"))
        self.assertLess(run.index(marker), run.index("gcloud run services update"))
        blocks = self.embedded_python_blocks(run)
        self.assertEqual(len(blocks), 3)
        preflight = compile(blocks[0], "cloud-run-read-only-preflight.py", "exec")
        normalizer = blocks[2]
        self.assertEqual(normalizer.count('"network_profile":'), 1)
        self.assertIn('"mode": "cloud_sql_public_ip_connector"', normalizer)
        self.assertIn(
            'cloud_sql_connection = "latchway:asia-southeast1:latchway-postgres"',
            normalizer,
        )
        self.assertIn(
            'job_execution_annotations = provider_annotations(', normalizer
        )
        self.assertIn(
            'execution_annotations = provider_annotations(', normalizer
        )
        self.assertIn('"name": "latchway-migrate"', normalizer)
        self.assertIn('"resources": {"limits": {"cpu": "1", "memory": "512Mi"}}', normalizer)
        cleanup = next(
            item
            for item in capture_job["steps"]
            if item.get("name") == "Restore Cloud Run steady-state rollout environment"
        )
        self.assertEqual(cleanup["if"], "always() && inputs.platform == 'cloud_run'")
        sentinel = "/tmp/latchway-cloud-run-steady-state-captured"
        self.assertIn(f": > {sentinel}", run)
        self.assertGreater(run.index(f": > {sentinel}"), run.index("trap - EXIT"))
        self.assertIn(f"[[ -f {sentinel} && ! -L {sentinel} ]]", cleanup["run"])
        self.assertLess(
            cleanup["run"].index(f"[[ -f {sentinel} && ! -L {sentinel} ]]"),
            cleanup["run"].index("gcloud run services update"),
        )
        self.assertIn("exit 0", cleanup["run"])
        self.assertIn("--remove-env-vars LATCHWAY_EVIDENCE_RUN_ID", cleanup["run"])
        for exact in (
            'test "$GCP_PROJECT" = "latchway"',
            'test "$GCP_REGION" = "asia-southeast1"',
            'test "$GCP_SERVICE" = "latchway"',
        ):
            self.assertIn(exact, cleanup["run"])

        def raw_documents() -> dict[str, object]:
            endpoint, control, _, _ = platform_values("cloud_run")
            service = copy.deepcopy(control["service"])
            revision = copy.deepcopy(control["revision"])
            job = copy.deepcopy(control["migration_job"])
            for document in (service, revision, job):
                document["metadata"]["labels"] = {
                    "cloud.googleapis.com/location": deployment.CLOUD_RUN_REGION
                }
            service["metadata"]["annotations"] = {
                "run.googleapis.com/ingress": "all",
                "run.googleapis.com/ingress-status": "all",
                "run.googleapis.com/invoker-iam-disabled": "true",
                "run.googleapis.com/creator": "release@example.com",
                "run.googleapis.com/lastModifier": "release@example.com",
            }
            revision["metadata"]["annotations"].update({
                "run.googleapis.com/creator": "release@example.com",
                "run.googleapis.com/lastModifier": "release@example.com",
            })
            job["metadata"]["annotations"] = {
                "run.googleapis.com/creator": "release@example.com",
                "run.googleapis.com/lastModifier": "release@example.com",
            }
            job_spec = job["spec"]
            job["spec"] = {"template": {"metadata": {"annotations": copy.deepcopy(
                job_spec["executionTemplateAnnotations"]
            )}, "spec": {
                "taskCount": job_spec["taskCount"],
                "parallelism": job_spec["parallelism"],
                "template": {"spec": {
                    "serviceAccountName": job_spec["serviceAccountName"],
                    "timeoutSeconds": job_spec["timeoutSeconds"],
                    "maxRetries": job_spec["maxRetries"],
                    "containers": job_spec["containers"],
                }},
            }}}
            return {
                "endpoint": endpoint,
                "service": service,
                "revision": revision,
                "job": job,
                "identity": {
                    "projectId": "latchway",
                    "projectNumber": "123456789",
                    "lifecycleState": "ACTIVE",
                },
            }

        def run_preflight(documents: dict[str, object], root: Path) -> None:
            dump(root / "cloud-run-before.json", documents["service"])
            dump(root / "cloud-run-before-revision.json", documents["revision"])
            dump(root / "cloud-run-migration-job.json", documents["job"])
            dump(root / "gcp-identity.json", documents["identity"])
            with mock.patch.dict(
                "os.environ",
                {
                    "CLOUD_RUN_PREFLIGHT_ROOT": str(root),
                    "RELEASE_IMAGE": IMAGE,
                    "ENDPOINT": str(documents["endpoint"]),
                },
                clear=False,
            ):
                exec(preflight, {"__name__": "__main__"})

        with tempfile.TemporaryDirectory() as temporary:
            run_preflight(raw_documents(), Path(temporary))

        def job_task(documents: dict[str, object]) -> dict[str, object]:
            return documents["job"]["spec"]["template"]["spec"]["template"]["spec"]

        mutations = {
            "job_command": lambda value: job_task(value)["containers"][0].update(command=["/bin/sh"]),
            "job_image": lambda value: job_task(value)["containers"][0].update(image="ghcr.io/other/image@sha256:" + "f" * 64),
            "job_extra_env": lambda value: job_task(value)["containers"][0]["env"].append({"name": "EXTRA", "value": "x"}),
            "job_service_account": lambda value: job_task(value).update(serviceAccountName=deployment.CLOUD_RUN_RUNTIME_SERVICE_ACCOUNT),
            "job_secret_latest": lambda value: job_task(value)["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"].update(key="latest"),
            "job_container_name": lambda value: job_task(value)["containers"][0].update(name="other"),
            "job_resource_request": lambda value: job_task(value)["containers"][0]["resources"].update(requests={"cpu": "1"}),
            "job_volume": lambda value: job_task(value).update(volumes=[{"name": "cloudsql"}]),
            "job_volume_mount": lambda value: job_task(value)["containers"][0].update(volumeMounts=[{"name": "cloudsql", "mountPath": "/cloudsql"}]),
            "job_cloud_sql_missing": lambda value: value["job"]["spec"]["template"]["metadata"]["annotations"].pop("run.googleapis.com/cloudsql-instances"),
            "job_cloud_sql_wrong": lambda value: value["job"]["spec"]["template"]["metadata"]["annotations"].update({"run.googleapis.com/cloudsql-instances": "latchway:us-central1:latchway-postgres"}),
            "job_cloud_sql_multiple": lambda value: value["job"]["spec"]["template"]["metadata"]["annotations"].update({"run.googleapis.com/cloudsql-instances": "latchway:asia-southeast1:latchway-postgres,latchway:asia-southeast1:other"}),
            "job_network_annotation": lambda value: value["job"]["spec"]["template"]["metadata"]["annotations"].update({"run.googleapis.com/vpc-access-connector": "connector"}),
            "job_cloud_sql_misplaced_on_task": lambda value: value["job"]["spec"]["template"]["spec"]["template"].update(metadata={"annotations": copy.deepcopy(deployment.CLOUD_RUN_CLOUD_SQL_ANNOTATIONS)}),
            "service_endpoint": lambda value: value["service"]["status"].update(url="https://wrong.example.com"),
            "service_image": lambda value: value["service"]["spec"]["template"]["spec"]["containers"][0].update(image="ghcr.io/other/image@sha256:" + "f" * 64),
            "service_extra_env": lambda value: value["service"]["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "EXTRA", "value": "x"}),
            "service_ingress": lambda value: value["service"]["metadata"]["annotations"].update({"run.googleapis.com/ingress": "internal"}),
            "service_invoker_missing": lambda value: value["service"]["metadata"]["annotations"].pop("run.googleapis.com/invoker-iam-disabled"),
            "service_invoker_enabled": lambda value: value["service"]["metadata"]["annotations"].update({"run.googleapis.com/invoker-iam-disabled": "false"}),
            "service_execution_environment": lambda value: value["service"]["spec"]["template"]["metadata"]["annotations"].update({"run.googleapis.com/execution-environment": "gen1"}),
            "service_cloud_sql_missing": lambda value: value["service"]["spec"]["template"]["metadata"]["annotations"].pop("run.googleapis.com/cloudsql-instances"),
            "service_cloud_sql_wrong": lambda value: value["service"]["spec"]["template"]["metadata"]["annotations"].update({"run.googleapis.com/cloudsql-instances": "other:asia-southeast1:latchway-postgres"}),
            "revision_cloud_sql_missing": lambda value: value["revision"]["metadata"]["annotations"].pop("run.googleapis.com/cloudsql-instances"),
            "revision_cloud_sql_multiple": lambda value: value["revision"]["metadata"]["annotations"].update({"run.googleapis.com/cloudsql-instances": "latchway:asia-southeast1:latchway-postgres,other"}),
            "service_unknown_runtime_annotation": lambda value: value["service"]["spec"]["template"]["metadata"]["annotations"].update({"run.googleapis.com/network-interfaces": "[]"}),
            "service_container_name": lambda value: value["service"]["spec"]["template"]["spec"]["containers"][0].update(name="other"),
            "service_resource_request": lambda value: value["service"]["spec"]["template"]["spec"]["containers"][0]["resources"].update(requests={"cpu": "1"}),
            "service_volume": lambda value: value["service"]["spec"]["template"]["spec"].update(volumes=[{"name": "cloudsql"}]),
            "service_volume_mount": lambda value: value["service"]["spec"]["template"]["spec"]["containers"][0].update(volumeMounts=[{"name": "cloudsql", "mountPath": "/cloudsql"}]),
            "provider_location": lambda value: value["job"]["metadata"]["labels"].update({"cloud.googleapis.com/location": "us-central1"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                documents = raw_documents()
                mutate(documents)
                with self.assertRaises((KeyError, TypeError, ValueError)):
                    run_preflight(documents, Path(temporary))

    def test_every_workflow_inline_python_block_compiles(self) -> None:
        jobs = deployment.yaml_as_json(
            SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        )["jobs"]
        count = 0
        for job in jobs.values():
            for step in job.get("steps", []):
                run = step.get("run") if isinstance(step, dict) else None
                if isinstance(run, str) and "<<'PY'\n" in run:
                    count += len(self.embedded_python_blocks(run))
        self.assertGreaterEqual(count, 10)

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

    def test_cloudflare_provider_reducer_retains_only_active_pool_allowlist(self) -> None:
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        jobs = deployment.yaml_as_json(workflow_path)["jobs"]
        run = next(
            step["run"]
            for step in jobs["capture"]["steps"]
            if step.get("name")
            == "Capture Cloudflare Container image, migration, secret, and replacement evidence"
        )
        marker = "# Retain a strict allowlist, not Wrangler's historical records."
        self.assertIn(marker, run)
        fragment = run.split(marker, 1)[1]
        reducer = fragment.split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        compile(reducer, "cloudflare-provider-reducer.py", "exec")
        self.assertNotIn(
            "install -m 0644 /tmp/cloudflare-deployments.json",
            run,
        )
        self.assertNotIn(
            "install -m 0644 /tmp/cloudflare-versions.json",
            run,
        )

        active = "87654321-abcd-1234-abcd-123456789abc"
        historical = "11111111-abcd-1234-abcd-123456789abc"
        deployments = [
            {
                "id": "historical-deployment",
                "created_on": "2026-08-29T00:59:00Z",
                "versions": [{"version_id": historical, "percentage": 100}],
            },
            {
                "id": "active-deployment",
                "created_on": "2026-08-29T01:00:00Z",
                "versions": [{"version_id": active, "percentage": 100}],
            },
        ]
        versions = [
            {
                "id": historical,
                "resources": {"bindings": [{
                    "name": "HISTORICAL_PLAIN_TEXT",
                    "type": "plain_text",
                    "text": "must-not-be-retained",
                }]},
            },
            {
                "id": active,
                "metadata": {"created_on": "2026-08-29T01:00:00Z"},
                "resources": {"bindings": [
                    {
                        "name": "LATCHWAY_DB_MAX_CONNECTIONS",
                        "type": "plain_text",
                        "text": "5",
                        "source_metadata": "must-not-be-retained",
                    },
                    {
                        "name": "UNRELATED_ACTIVE_PLAIN_TEXT",
                        "type": "plain_text",
                        "text": "must-not-be-retained",
                    },
                    {
                        "name": "LATCHWAY_DB_COMPLETION_CONNECTIONS",
                        "type": "plain_text",
                        "text": "2",
                    },
                ]},
            },
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deployments_path = root / "deployments-source.json"
            versions_path = root / "versions-source.json"
            output = root / "retained"
            output.mkdir()
            executable = reducer.replace(
                '"/tmp/cloudflare-deployments.json"',
                json.dumps(str(deployments_path)),
            ).replace(
                '"/tmp/cloudflare-versions.json"',
                json.dumps(str(versions_path)),
            ).replace(
                '"/tmp/cloudflare-provider-raw"',
                json.dumps(str(output)),
            )

            def execute(
                deployment_records: list[dict[str, object]],
                version_records: list[dict[str, object]],
            ) -> subprocess.CompletedProcess[str]:
                dump(deployments_path, deployment_records)
                dump(versions_path, version_records)
                return subprocess.run(
                    [sys.executable, "-c", executable],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            result = execute(deployments, versions)
            self.assertEqual(result.returncode, 0, result.stderr)
            retained_deployments = json.loads(
                (output / "deployments.json").read_text(encoding="utf-8")
            )
            retained_versions = json.loads(
                (output / "versions.json").read_text(encoding="utf-8")
            )
            self.assertEqual(retained_deployments, [deployments[1]])
            self.assertEqual(retained_versions, [{
                "id": active,
                "resources": {"bindings": [
                    {
                        "name": "LATCHWAY_DB_MAX_CONNECTIONS",
                        "type": "plain_text",
                        "text": "5",
                    },
                    {
                        "name": "LATCHWAY_DB_COMPLETION_CONNECTIONS",
                        "type": "plain_text",
                        "text": "2",
                    },
                ]},
            }])
            self.assertNotIn(
                "must-not-be-retained",
                (output / "versions.json").read_text(encoding="utf-8"),
            )

            duplicate_binding = copy.deepcopy(versions)
            duplicate_binding[1]["resources"]["bindings"].append(
                copy.deepcopy(duplicate_binding[1]["resources"]["bindings"][0])
            )
            self.assertNotEqual(
                execute(deployments, duplicate_binding).returncode,
                0,
            )
            wrong_profile = copy.deepcopy(versions)
            wrong_profile[1]["resources"]["bindings"][0]["text"] = "6"
            self.assertNotEqual(execute(deployments, wrong_profile).returncode, 0)
            ambiguous_traffic = copy.deepcopy(deployments)
            ambiguous_traffic[1]["versions"].append({
                "version_id": historical,
                "percentage": 0,
            })
            self.assertNotEqual(execute(ambiguous_traffic, versions).returncode, 0)

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
            "Cloudflare raw artifact must retain exactly one active deployment and version",
            "Cloudflare active provider record allowlist is invalid",
            "Cloudflare database pool binding allowlist is invalid",
            "Cloudflare database pool partition is not the release profile",
            "Cloudflare provider record contains forbidden secret material",
            "Cloud Run runtime digest is not bound to the authenticated candidate index or linux/amd64 child",
            '"active_version_id": active_version_id',
            '"database_pool": database_pool',
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

    def test_compose_http_capture_precedes_retention_and_teardown(self) -> None:
        jobs = deployment.yaml_as_json(SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml")["jobs"]
        names = [step.get("name") for step in jobs["capture_compose"]["steps"]]
        self.assertLess(names.index("Capture Compose migration, runtime, and SIGTERM evidence without OIDC"), names.index("Capture bounded Compose health and readiness before teardown"))
        self.assertLess(names.index("Capture bounded Compose health and readiness before teardown"), names.index("Retain raw Compose observations for fresh validation"))
        self.assertLess(names.index("Retain raw Compose observations for fresh validation"), names.index("Tear down the ephemeral Compose deployment"))
        probe = next(step for step in jobs["finalize"]["steps"] if step.get("name") == "Capture bounded HTTPS health and readiness responses")
        self.assertEqual(probe["if"], "inputs.platform != 'compose'")
        self.assertIn("observe-http", probe["run"])
        lifecycle = next(
            step["run"]
            for step in jobs["capture_compose"]["steps"]
            if step.get("name")
            == "Capture Compose migration, runtime, and SIGTERM evidence without OIDC"
        )
        self.assertIn('up -d --wait --force-recreate --no-deps latchway', lifecycle)
        self.assertIn('test "$gateway_id" != "$before_gateway_id"', lifecycle)
        self.assertIn('/tmp/compose-provider-raw', lifecycle)

    def test_compose_inline_http_collector_retains_real_responses_and_fails_closed(self) -> None:
        jobs = deployment.yaml_as_json(SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml")["jobs"]
        step = next(step for step in jobs["capture_compose"]["steps"] if step.get("name") == "Capture bounded Compose health and readiness before teardown")
        collector = self.embedded_python(step["run"])
        self.assertIn("signal.setitimer(signal.ITIMER_REAL, 15)", collector)
        responses = {
            "/healthz": {"status": "ok", "observed_marker": "real-loopback-health"},
            "/readyz": {"status": "ready", "observed_marker": "real-loopback-readiness"},
        }
        requested = []
        scenario = {"status": 200, "payload": None}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requested.append(self.path)
                payload = scenario["payload"]
                if payload is None:
                    payload = json.dumps(responses[self.path]).encode()
                self.send_response(scenario["status"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                if scenario["status"] == 302:
                    self.send_header("Location", "/readyz")
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_port}"
            for label, status, payload, success in (
                ("actual", 200, None, True),
                ("redirect", 302, b"{}", False),
                ("unready", 503, b"{}", False),
                ("duplicate", 200, b'{"status":"ok","status":"other"}', False),
                ("nonfinite", 200, b'{"value":NaN}', False),
                ("invalid", 200, b"not JSON", False),
                ("array", 200, b"[]", False),
                ("oversized", 200, b" " * (1024 * 1024 + 1), False),
            ):
                with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    # Redirect only the fixed artifact directory; execute the
                    # workflow's HTTP collector unchanged against a real socket.
                    code = collector.replace('Path("/tmp/latchway-deployment-capture")', f"Path({str(root)!r})")
                    scenario.update(status=status, payload=payload)
                    requested.clear()
                    result = subprocess.run([sys.executable, "-c", code], env={"ENDPOINT": endpoint, "HTTP_PROXY": "http://unreachable.invalid:1"}, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    if success:
                        self.assertEqual(requested, ["/healthz", "/readyz"])
                        for name, suffix in (("health", "/healthz"), ("readiness", "/readyz")):
                            retained = json.loads((root / f"{name}.json").read_text())
                            self.assertEqual(retained["body"], responses[suffix])
                            self.assertEqual(retained["url"], endpoint + suffix)
                            self.assertEqual(retained["status_code"], 200)
                            self.assertFalse(retained["tls"])
                    else:
                        self.assertEqual(requested, ["/healthz"])
                        self.assertFalse((root / "health.json").exists())
                        self.assertNotIn("observed_marker", result.stderr)
            for endpoint in ("https://127.0.0.1:18080", "http://example.com:18080", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:18080/path"):
                with self.subTest(endpoint=endpoint):
                    result = subprocess.run([sys.executable, "-c", collector], env={"ENDPOINT": endpoint}, capture_output=True, text=True, timeout=20)
                    self.assertNotEqual(result.returncode, 0)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_compose_signer_requires_and_byte_binds_both_raw_http_observations(self) -> None:
        jobs = deployment.yaml_as_json(SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml")["jobs"]
        step = next(step for step in jobs["sign"]["steps"] if step.get("name") == "Independently bind the deterministic archive to authenticated raw capture")
        signer = self.embedded_python(step["run"])
        for platform, mutation in (("compose", None), ("cloud_run", None), ("cloud_run", "amd64_child"), ("cloud_run", "unbound_child"), ("compose", "missing_health"), ("compose", "missing_readiness"), ("compose", "tampered_health"), ("compose", "tampered_readiness"), ("compose", "same_container")):
            with self.subTest(platform=platform, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                capture_root = root / "capture"
                capture_root.mkdir()
                manifest = capture(capture_root, platform)
                manifest["collector"]["sha"] = COMMIT
                seal_candidate = None
                if platform == "cloud_run" and mutation in {
                    "amd64_child",
                    "unbound_child",
                }:
                    runtime_digest = (
                        PLATFORM_DIGEST if mutation == "amd64_child" else "9" * 64
                    )
                    control = json.loads(
                        (capture_root / "control_plane.json").read_text()
                    )
                    control["revision"]["status"]["imageDigest"] = (
                        f"sha256:{runtime_digest}"
                    )
                    dump(capture_root / "control_plane.json", control)
                    stopped = json.loads((capture_root / "shutdown.json").read_text())
                    for phase in ("before", "after"):
                        stopped[phase]["image_digest"] = f"sha256:{runtime_digest}"
                    dump(capture_root / "shutdown.json", stopped)
                    manifest["observations"]["control_plane"]["sha256"] = (
                        deployment.sha256_file(capture_root / "control_plane.json")
                    )
                    manifest["observations"]["shutdown"]["sha256"] = (
                        deployment.sha256_file(capture_root / "shutdown.json")
                    )
                    seal_candidate = candidate_manifest(amd64_digest=runtime_digest)
                dump(capture_root / "manifest.json", manifest)
                validated = root / "validated"
                validated.mkdir()
                deployment.seal_capture(
                    capture_root,
                    validated / f"{platform}.tar.gz",
                    seal_candidate,
                )
                dump(validated / "latchway-deployment-validation.json", {"verdict": "passed", "platform": platform, "oci_image_digest": IMAGE})
                (validated / "latchway-deployment-validation.json.junit.xml").write_text("<testsuites/>\n")
                raw_root = root / "raw"
                raw = raw_root / "latchway-deployment-capture"
                raw.mkdir(parents=True)
                raw_names = deployment.OBSERVATIONS if platform == "compose" else ("identity", "control_plane", "migration", "secrets", "shutdown")
                for name in raw_names:
                    (raw / f"{name}.json").write_bytes((capture_root / f"{name}.json").read_bytes())
                if platform == "compose":
                    provider = raw_root / "compose-provider-raw"
                    provider.mkdir()
                    control = json.loads((capture_root / "control_plane.json").read_text())
                    stopped = json.loads((capture_root / "shutdown.json").read_text())
                    image = control["gateway"]["Config"]["Image"]
                    before_id = stopped["before"]["resource_id"]
                    after_id = stopped["after"]["resource_id"]
                    dump(provider / "gateway-before.json", {
                        "Id": before_id,
                        "Config": {"Image": image},
                        "State": {"Running": True, "ExitCode": 0, "Health": {"Status": "healthy"}},
                    })
                    dump(provider / "gateway-stopped.json", {
                        "Id": before_id,
                        "Config": {"Image": image},
                        "State": {"Running": False, "ExitCode": 0, "Health": {"Status": None}},
                    })
                    dump(provider / "gateway-after.json", {
                        "Id": after_id,
                        "Config": {"Image": image},
                        "State": {"Running": True, "ExitCode": 0, "Health": {"Status": "healthy"}},
                    })
                    if mutation == "same_container":
                        after = json.loads((provider / "gateway-after.json").read_text())
                        after["Id"] = before_id
                        dump(provider / "gateway-after.json", after)
                (raw_root / "latchway-deployment-started-at").write_text(STARTED + "\n")
                (raw_root / "latchway-provider-resource-id").write_text(manifest["provider_resource_id"] + "\n")
                if mutation and mutation not in {"amd64_child", "unbound_child", "same_container"}:
                    kind, name = mutation.split("_")
                    if kind == "missing":
                        (raw / f"{name}.json").unlink()
                    else:
                        altered = json.loads((raw / f"{name}.json").read_text())
                        altered["body"]["unexpected"] = "tampered-response"
                        dump(raw / f"{name}.json", altered)
                candidate = root / "candidate.json"
                dump(candidate, candidate_manifest())
                result = subprocess.run([sys.executable, "-c", signer, str(validated), str(raw_root), str(candidate)], env={"PLATFORM": platform, "CANDIDATE_COMMIT": COMMIT, "INTENDED_TAG": "v1.0.0", "RELEASE_IMAGE": IMAGE, "ENDPOINT": manifest["endpoint"], "GITHUB_REPOSITORY": "Latchway/latchway", "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1", "DEPLOYMENT_ENVIRONMENT": f"deployment-evidence-{platform}"}, capture_output=True, text=True, timeout=20)
                if mutation is None or mutation == "amd64_child":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    with tarfile.open(validated / f"{platform}.tar.gz") as archive:
                        binding = json.load(archive.extractfile("latchway-deployment-binding.json"))
                    retained = {item["path"] for item in binding["raw_capture"]["files"]}
                    self.assertEqual("latchway-deployment-capture/health.json" in retained, platform == "compose")
                    self.assertEqual("latchway-deployment-capture/readiness.json" in retained, platform == "compose")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    expected = (
                        "Cloud Run runtime digest is not bound to the authenticated candidate index or linux/amd64 child"
                        if mutation == "unbound_child"
                        else "raw provider artifact closure is invalid"
                        if mutation.startswith("missing_")
                        else "Compose replacement is not bound to distinct provider container identities"
                        if mutation == "same_container"
                        else "normalized capture is not byte-bound to provider raw data"
                    )
                    self.assertIn(expected, result.stderr)

    def test_all_compose_probes_match_their_exact_database_and_application_contracts(self) -> None:
        jobs = deployment.yaml_as_json(SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml")["jobs"]
        run = next(step["run"] for step in jobs["capture_compose"]["steps"] if step.get("name") == "Capture Compose migration, runtime, and SIGTERM evidence without OIDC")
        model = run.split("jq -n '", 1)[1].split("' > \"$RUNNER_TEMP/trusted-compose.json\"", 1)[0]
        rendered = subprocess.run(["jq", "-n", model], capture_output=True, text=True, check=True)
        expected = {"test": ["CMD-SHELL", deployment.COMPOSE_POSTGRES_HEALTHCHECK], "interval": "2s", "timeout": "5s", "retries": 30}
        trusted_compose = json.loads(rendered.stdout)
        self.assertEqual(trusted_compose["services"]["postgres"]["healthcheck"], expected)
        expected_application = {
            "test": deployment.APPLICATION_READINESS_HEALTHCHECK_COMMAND,
            "interval": "5s",
            "timeout": "5s",
            "retries": 30,
            "start_period": "5s",
        }
        self.assertEqual(
            trusted_compose["services"]["latchway"]["healthcheck"],
            expected_application,
        )
        trusted_environment = trusted_compose["services"]["latchway"]["environment"]
        self.assertEqual(
            trusted_environment["LATCHWAY_DB_MAX_CONNECTIONS"],
            "${LATCHWAY_DB_MAX_CONNECTIONS:-20}",
        )
        self.assertEqual(
            trusted_environment["LATCHWAY_DB_COMPLETION_CONNECTIONS"],
            "${LATCHWAY_DB_COMPLETION_CONNECTIONS:-5}",
        )
        for relative, application_retries in (
            ("compose.yaml", 20),
            ("deploy/compose/compose.release.yaml", 30),
        ):
            services = deployment.yaml_as_json(SCRIPT.parent.parent / relative)["services"]
            self.assertEqual(services["postgres"]["healthcheck"], expected)
            template_application = dict(expected_application)
            template_application["retries"] = application_retries
            self.assertEqual(
                services["latchway"]["healthcheck"], template_application
            )
        probe = deployment.COMPOSE_POSTGRES_HEALTHCHECK.replace("$$", "$")
        wrapper = '''psql() {
  [[ "$PGPASSWORD" == "$POSTGRES_PASSWORD" && "$PGCONNECT_TIMEOUT" == 2 && "$PGOPTIONS" == "-c statement_timeout=2000" ]] || return 81
  [[ "$*" != *"$POSTGRES_PASSWORD"* ]] || return 82
  [[ "$*" == "-X -w -h 127.0.0.1 -p 5432 -U $POSTGRES_USER -d $POSTGRES_DB -At -v ON_ERROR_STOP=1 -c SELECT 1" ]] || return 83
  printf '%s\\n' "$PROBE_OUTPUT"
  return "$PROBE_EXIT"
}
'''
        for output, exit_code, success in (("1", "0", True), ("", "1", False), ("0", "0", False), ("1", "1", False)):
            with self.subTest(output=output, exit_code=exit_code):
                result = subprocess.run(["bash", "-c", wrapper + probe], env={"POSTGRES_USER": "latchway", "POSTGRES_DB": "latchway", "POSTGRES_PASSWORD": "test-authenticated-password", "PROBE_OUTPUT": output, "PROBE_EXIT": exit_code}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success)
                self.assertNotIn("test-authenticated-password", result.stdout + result.stderr)

    def test_static_assets_pass(self) -> None:
        checks = deployment.static_checks()
        self.assertTrue(checks)
        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        compose = deployment.yaml_as_json(
            SCRIPT.parent.parent / "deploy/compose/compose.release.yaml"
        )
        release_environment = compose["services"]["latchway"]["environment"]
        self.assertEqual(
            compose["services"]["latchway"]["healthcheck"]["test"],
            deployment.APPLICATION_READINESS_HEALTHCHECK_COMMAND,
        )
        self.assertEqual(
            release_environment["LATCHWAY_DB_MAX_CONNECTIONS"],
            "${LATCHWAY_DB_MAX_CONNECTIONS:-20}",
        )
        self.assertEqual(
            release_environment["LATCHWAY_DB_COMPLETION_CONNECTIONS"],
            "${LATCHWAY_DB_COMPLETION_CONNECTIONS:-5}",
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
        quickstart_environment = quickstart["services"]["latchway"]["environment"]
        self.assertEqual(
            quickstart["services"]["latchway"]["healthcheck"]["test"],
            deployment.APPLICATION_READINESS_HEALTHCHECK_COMMAND,
        )
        self.assertEqual(
            quickstart_environment["LATCHWAY_DB_MAX_CONNECTIONS"],
            "${LATCHWAY_DB_MAX_CONNECTIONS:-20}",
        )
        self.assertEqual(
            quickstart_environment["LATCHWAY_DB_COMPLETION_CONNECTIONS"],
            "${LATCHWAY_DB_COMPLETION_CONNECTIONS:-5}",
        )
        cloud_run_service = deployment.yaml_as_json(
            SCRIPT.parent.parent / "deploy/cloud-run/service.yaml"
        )
        cloud_run_environment = deployment.env_map(
            deployment.cloud_run_containers(cloud_run_service)[0]
        )
        self.assertEqual(cloud_run_environment["LATCHWAY_DB_MAX_CONNECTIONS"]["value"], "20")
        self.assertEqual(
            cloud_run_environment["LATCHWAY_DB_COMPLETION_CONNECTIONS"]["value"],
            "5",
        )
        terraform_main = (
            SCRIPT.parent.parent / "deploy/cloud-run/terraform/main.tf"
        ).read_text(encoding="utf-8")
        terraform_variables = (
            SCRIPT.parent.parent / "deploy/cloud-run/terraform/variables.tf"
        ).read_text(encoding="utf-8")
        self.assertIn("edition           = var.database_edition", terraform_main)
        self.assertIn(
            "var.db_completion_connections_per_instance < var.db_connections_per_instance",
            terraform_main,
        )
        self.assertIn(
            'name  = "LATCHWAY_DB_COMPLETION_CONNECTIONS"', terraform_main
        )
        self.assertIn('default     = "ENTERPRISE"', terraform_variables)
        self.assertIn(
            'condition     = var.database_edition == "ENTERPRISE"',
            terraform_variables,
        )
        self.assertIn(
            'variable "db_completion_connections_per_instance"',
            terraform_variables,
        )

        fly = tomllib.loads(
            (SCRIPT.parent.parent / "deploy/fly/fly.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(fly["env"]["LATCHWAY_DB_MAX_CONNECTIONS"], "20")
        self.assertEqual(fly["env"]["LATCHWAY_DB_COMPLETION_CONNECTIONS"], "5")

        cloudflare = (
            SCRIPT.parent.parent / "deploy/cloudflare/wrangler.jsonc"
        ).read_text(encoding="utf-8")
        self.assertIn('"LATCHWAY_DB_MAX_CONNECTIONS": "5"', cloudflare)
        self.assertIn('"LATCHWAY_DB_COMPLETION_CONNECTIONS": "2"', cloudflare)

    def test_cloud_run_yaml_network_profile_is_exact_and_shared(self) -> None:
        service_path = SCRIPT.parent.parent / "deploy/cloud-run/service.yaml"
        job_path = SCRIPT.parent.parent / "deploy/cloud-run/migration-job.yaml"
        base_service = deployment.yaml_as_json(service_path)
        base_job = deployment.yaml_as_json(job_path)

        def validate(service: dict[str, object], job: dict[str, object]) -> None:
            def load(path: Path) -> object:
                if path == service_path:
                    return service
                if path == job_path:
                    return job
                raise AssertionError(path)

            with mock.patch.object(deployment, "yaml_as_json", side_effect=load):
                deployment.validate_cloud_run_yaml()

        validate(copy.deepcopy(base_service), copy.deepcopy(base_job))
        service_template_annotations = lambda value: value["spec"]["template"]["metadata"]["annotations"]
        job_template_annotations = lambda value: value["spec"]["template"]["metadata"]["annotations"]
        mutations = {
            "ingress_removed": lambda service, _job: service["metadata"]["annotations"].pop("run.googleapis.com/ingress"),
            "invoker_setting_removed": lambda service, _job: service["metadata"]["annotations"].pop("run.googleapis.com/invoker-iam-disabled"),
            "service_cloud_sql_removed": lambda service, _job: service_template_annotations(service).pop("run.googleapis.com/cloudsql-instances"),
            "service_cloud_sql_mismatch": lambda service, _job: service_template_annotations(service).update({"run.googleapis.com/cloudsql-instances": "different"}),
            "service_vpc_connector_added": lambda service, _job: service_template_annotations(service).update({"run.googleapis.com/vpc-access-connector": "connector"}),
            "service_vpc_egress_added": lambda service, _job: service_template_annotations(service).update({"run.googleapis.com/vpc-access-egress": "all-traffic"}),
            "service_volume_added": lambda service, _job: service["spec"]["template"]["spec"].update(volumes=[{"name": "cloudsql"}]),
            "service_volume_mount_added": lambda service, _job: service["spec"]["template"]["spec"]["containers"][0].update(volumeMounts=[{"name": "cloudsql", "mountPath": "/cloudsql"}]),
            "job_cloud_sql_removed": lambda _service, job: job_template_annotations(job).pop("run.googleapis.com/cloudsql-instances"),
            "job_cloud_sql_mismatch": lambda _service, job: job_template_annotations(job).update({"run.googleapis.com/cloudsql-instances": "different"}),
            "job_vpc_connector_added": lambda _service, job: job_template_annotations(job).update({"run.googleapis.com/vpc-access-connector": "connector"}),
            "job_vpc_egress_added": lambda _service, job: job_template_annotations(job).update({"run.googleapis.com/vpc-access-egress": "private-ranges-only"}),
            "job_volume_added": lambda _service, job: job["spec"]["template"]["spec"]["template"]["spec"].update(volumes=[{"name": "cloudsql"}]),
            "job_volume_mount_added": lambda _service, job: job["spec"]["template"]["spec"]["template"]["spec"]["containers"][0].update(volumeMounts=[{"name": "cloudsql", "mountPath": "/cloudsql"}]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                service, job = copy.deepcopy(base_service), copy.deepcopy(base_job)
                mutate(service, job)
                with self.assertRaises(deployment.EvidenceError):
                    validate(service, job)

    def test_compose_static_validator_rejects_out_of_process_database_healthcheck(self) -> None:
        document = deployment.yaml_as_json(
            SCRIPT.parent.parent / "deploy/compose/compose.release.yaml"
        )
        invalid = copy.deepcopy(document)
        invalid["services"]["latchway"]["healthcheck"]["test"] = [
            "CMD",
            "/latchway",
            "doctor",
            "--output",
            "json",
        ]
        with mock.patch.object(deployment, "yaml_as_json", return_value=invalid):
            with self.assertRaises(deployment.EvidenceError) as raised:
                deployment.validate_compose()
        self.assertEqual(
            raised.exception.code, "compose_serving_process_readiness_required"
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

        invalid_partition = copy.deepcopy(document)
        invalid_partition["env"]["LATCHWAY_DB_COMPLETION_CONNECTIONS"] = "20"
        with self.assertRaises(deployment.EvidenceError) as raised:
            deployment.validate_fly_document(invalid_partition)
        self.assertEqual(raised.exception.code, "fly_environment_invalid")

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

    def test_each_platform_rejects_coherent_but_wrong_database_pool_claim(self) -> None:
        reasons = {
            "compose": "compose_database_pool_invalid",
            "cloud_run": "cloud_run_database_pool_invalid",
            "aws": "aws_database_pool_invalid",
            "fly_io": "fly_database_pool_invalid",
            "cloudflare_containers": "cloudflare_database_pool_invalid",
        }
        for platform in deployment.PLATFORMS:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, platform)
                control = json.loads((root / "control_plane.json").read_text())
                control["database_pool"] = (
                    {
                        "aggregate_max_connections": 6,
                        "regular_max_connections": 4,
                        "completion_max_connections": 2,
                    }
                    if platform == "cloudflare_containers"
                    else {
                        "aggregate_max_connections": 21,
                        "regular_max_connections": 16,
                        "completion_max_connections": 5,
                    }
                )
                dump(root / "control_plane.json", control)
                manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(root / "control_plane.json")
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.control_plane")
                self.assertEqual(failure.status, "failed")
                self.assertEqual(failure.reason, reasons[platform])

    def test_each_platform_requires_database_pool_in_exact_control_plane_closure(self) -> None:
        reasons = {
            "compose": "compose_control_fields_invalid",
            "cloud_run": "cloud_run_control_fields_invalid",
            "aws": "aws_control_fields_invalid",
            "fly_io": "fly_control_fields_invalid",
            "cloudflare_containers": "cloudflare_control_fields_invalid",
        }
        for platform in deployment.PLATFORMS:
            for mutation in ("missing", "extra"):
                with self.subTest(platform=platform, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = capture(root, platform)
                    control = json.loads((root / "control_plane.json").read_text())
                    if mutation == "missing":
                        control.pop("database_pool")
                    else:
                        control["database_pool_alias"] = control["database_pool"]
                    dump(root / "control_plane.json", control)
                    manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(root / "control_plane.json")
                    dump(root / "manifest.json", manifest)
                    _, checks = deployment.validate_capture(root)
                    failure = next(item for item in checks if item.identifier == "capture.control_plane")
                    self.assertEqual(failure.status, "failed")
                    self.assertEqual(failure.reason, reasons[platform])

    def test_each_platform_rejects_coherent_but_wrong_provider_pool(self) -> None:
        reasons = {
            "compose": "compose_database_pool_invalid",
            "cloud_run": "cloud_run_database_pool_invalid",
            "aws": "aws_database_pool_invalid",
            "fly_io": "fly_database_pool_invalid",
            "cloudflare_containers": "cloudflare_database_pool_invalid",
        }
        for platform in deployment.PLATFORMS:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, platform)
                control = json.loads((root / "control_plane.json").read_text())
                if platform == "compose":
                    environment = control["gateway"]["Config"]["Env"]
                elif platform == "cloud_run":
                    environment = control["service"]["spec"]["template"]["spec"]["containers"][0]["env"]
                    revision_environment = control["revision"]["spec"]["containers"][0]["env"]
                    next(
                        item
                        for item in revision_environment
                        if item["name"] == "LATCHWAY_DB_MAX_CONNECTIONS"
                    )["value"] = "21"
                elif platform == "aws":
                    environment = control["task_definition"]["containerDefinitions"][0]["environment"]
                elif platform == "fly_io":
                    environment = control["machines"][0]["environment"]
                else:
                    bindings = control["worker"]["versions"][0]["resources"]["bindings"]
                    next(item for item in bindings if item["name"] == "LATCHWAY_DB_MAX_CONNECTIONS")["text"] = "6"
                    environment = None
                if environment is not None:
                    next(item for item in environment if item["name"] == "LATCHWAY_DB_MAX_CONNECTIONS")["value"] = "21"
                dump(root / "control_plane.json", control)
                manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(root / "control_plane.json")
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.control_plane")
                self.assertEqual(failure.status, "failed")
                self.assertEqual(failure.reason, reasons[platform])

    def test_cloud_run_latest_ready_revision_binding_fails_closed(self) -> None:
        def revision_environment(control: dict[str, object]) -> list[dict[str, object]]:
            return control["revision"]["spec"]["containers"][0]["env"]

        def runtime_item(
            control: dict[str, object],
            name: str,
        ) -> dict[str, object]:
            return next(
                item for item in revision_environment(control) if item["name"] == name
            )

        def remove_runtime_item(control: dict[str, object], name: str) -> None:
            environment = revision_environment(control)
            environment.pop(next(
                index for index, item in enumerate(environment) if item["name"] == name
            ))

        def use_plaintext_database_url(control: dict[str, object]) -> None:
            item = runtime_item(control, "LATCHWAY_DATABASE_URL")
            item.clear()
            item.update({
                "name": "LATCHWAY_DATABASE_URL",
                "value": "postgres://plaintext-must-not-enter-evidence",
            })

        mutations = {
            "revision_pool": (
                lambda control: next(
                    item
                    for item in control["revision"]["spec"]["containers"][0]["env"]
                    if item["name"] == "LATCHWAY_DB_MAX_CONNECTIONS"
                ).update(value="21"),
                "cloud_run_runtime_profile_mismatch",
            ),
            "revision_identity": (
                lambda control: control["service"]["status"].update(
                    latestReadyRevisionName="latchway-00003-other"
                ),
                "cloud_run_latest_ready_revision_identity_invalid",
            ),
            "revision_readiness": (
                lambda control: control["revision"]["status"].update(
                    conditions=[{"type": "Ready", "status": "False"}]
                ),
                "cloud_run_latest_ready_revision_not_ready",
            ),
            "desired_probe_missing": (
                lambda control: control["service"]["spec"]["template"]["spec"]["containers"][0].pop(
                    "startupProbe"
                ),
                "cloud_run_desired_runtime_profile_invalid",
            ),
            "revision_probe_missing": (
                lambda control: control["revision"]["spec"]["containers"][0].pop(
                    "startupProbe"
                ),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "revision_probe_wrong_path": (
                lambda control: control["revision"]["spec"]["containers"][0]["startupProbe"]["httpGet"].update(
                    path="/healthz"
                ),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "revision_shutdown_timeout": (
                lambda control: runtime_item(
                    control, "LATCHWAY_SHUTDOWN_TIMEOUT"
                ).update(value="9s"),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "revision_secret_missing": (
                lambda control: remove_runtime_item(
                    control, "LATCHWAY_DATABASE_URL"
                ),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "revision_secret_reference_missing": (
                lambda control: runtime_item(
                    control, "LATCHWAY_DATABASE_URL"
                ).update(valueFrom={}),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "revision_secret_reference_mismatch": (
                lambda control: runtime_item(
                    control, "LATCHWAY_DATABASE_URL"
                )["valueFrom"]["secretKeyRef"].update(name="other-database"),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "revision_plaintext_secret": (
                use_plaintext_database_url,
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "desired_cloud_sql_missing": (
                lambda control: control["service"]["spec"]["template"]["metadata"]["annotations"].pop(
                    "run.googleapis.com/cloudsql-instances"
                ),
                "cloud_run_desired_runtime_profile_invalid",
            ),
            "desired_cloud_sql_wrong_project": (
                lambda control: control["service"]["spec"]["template"]["metadata"]["annotations"].update({
                    "run.googleapis.com/cloudsql-instances":
                        "other:asia-southeast1:latchway-postgres",
                }),
                "cloud_run_desired_runtime_profile_invalid",
            ),
            "revision_cloud_sql_missing": (
                lambda control: control["revision"]["metadata"]["annotations"].pop(
                    "run.googleapis.com/cloudsql-instances"
                ),
                "cloud_run_revision_runtime_profile_invalid",
            ),
            "job_cloud_sql_missing": (
                lambda control: control["migration_job"]["spec"][
                    "executionTemplateAnnotations"
                ].pop("run.googleapis.com/cloudsql-instances"),
                "cloud_run_migration_job_profile_invalid",
            ),
            "job_cloud_sql_multiple": (
                lambda control: control["migration_job"]["spec"][
                    "executionTemplateAnnotations"
                ].update({
                    "run.googleapis.com/cloudsql-instances":
                        "latchway:asia-southeast1:latchway-postgres,other",
                }),
                "cloud_run_migration_job_profile_invalid",
            ),
            "job_vpc_connector_added": (
                lambda control: control["migration_job"]["spec"][
                    "executionTemplateAnnotations"
                ].update({"run.googleapis.com/vpc-access-connector": "connector"}),
                "cloud_run_migration_job_profile_invalid",
            ),
            "network_profile_reverted_to_direct": (
                lambda control: control["network_profile"].update(mode="direct"),
                "cloud_run_control_invalid",
            ),
            "partial_traffic": (
                lambda control: control["service"]["status"].update(
                    traffic=[{
                        "revisionName": "latchway-00002-ready",
                        "percent": 50,
                    }]
                ),
                "cloud_run_latest_ready_revision_traffic_invalid",
            ),
            "alternate_revision_traffic": (
                lambda control: control["service"]["status"].update(
                    traffic=[{
                        "revisionName": "latchway-00001-old",
                        "percent": 100,
                    }]
                ),
                "cloud_run_latest_ready_revision_traffic_invalid",
            ),
        }
        for name, (mutate, reason) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "cloud_run")
                control = json.loads((root / "control_plane.json").read_text())
                mutate(control)
                dump(root / "control_plane.json", control)
                manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(
                    root / "control_plane.json"
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(
                    item for item in checks if item.identifier == "capture.control_plane"
                )
                self.assertEqual(failure.status, "failed")
                self.assertEqual(failure.reason, reason)

        execution_mutations = {
            "execution_cloud_sql_missing": (
                lambda migration: migration["provider_execution"]["metadata"][
                    "annotations"
                ].pop("run.googleapis.com/cloudsql-instances"),
                "cloud_run_migration_execution_profile_invalid",
            ),
            "execution_cloud_sql_wrong_region": (
                lambda migration: migration["provider_execution"]["metadata"][
                    "annotations"
                ].update({
                    "run.googleapis.com/cloudsql-instances":
                        "latchway:us-central1:latchway-postgres",
                }),
                "cloud_run_migration_execution_profile_invalid",
            ),
            "execution_vpc_connector_added": (
                lambda migration: migration["provider_execution"]["metadata"][
                    "annotations"
                ].update({"run.googleapis.com/vpc-access-connector": "connector"}),
                "cloud_run_migration_execution_profile_invalid",
            ),
        }
        for name, (mutate, reason) in execution_mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "cloud_run")
                migration = json.loads((root / "migration.json").read_text())
                mutate(migration)
                dump(root / "migration.json", migration)
                manifest["observations"]["migration"]["sha256"] = (
                    deployment.sha256_file(root / "migration.json")
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(
                    item for item in checks
                    if item.identifier == "capture.control_plane"
                )
                self.assertEqual(failure.status, "failed")
                self.assertEqual(failure.reason, reason)

    def test_cloud_run_accepts_only_index_or_authenticated_amd64_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "cloud_run")
            control = json.loads((root / "control_plane.json").read_text())
            control["revision"]["status"]["imageDigest"] = (
                f"ghcr.io/latchway/latchway@sha256:{PLATFORM_DIGEST}"
            )
            dump(root / "control_plane.json", control)
            stopped = json.loads((root / "shutdown.json").read_text())
            for phase in ("before", "after"):
                stopped[phase]["image_digest"] = f"sha256:{PLATFORM_DIGEST}"
            dump(root / "shutdown.json", stopped)
            manifest["observations"]["control_plane"]["sha256"] = (
                deployment.sha256_file(root / "control_plane.json")
            )
            manifest["observations"]["shutdown"]["sha256"] = (
                deployment.sha256_file(root / "shutdown.json")
            )
            dump(root / "manifest.json", manifest)

            _, checks = deployment.validate_capture(root, candidate_manifest())
            self.assertTrue(all(item.status == "passed" for item in checks), checks)
            control_check = next(
                item for item in checks if item.identifier == "capture.control_plane"
            )
            self.assertEqual(control_check.details["digest"], DIGEST)
            self.assertEqual(
                control_check.details["runtime_digest"], PLATFORM_DIGEST
            )

            _, checks_without_candidate = deployment.validate_capture(root)
            failure = next(
                item
                for item in checks_without_candidate
                if item.identifier == "capture.control_plane"
            )
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "cloud_run_resolved_digest_mismatch")

            arbitrary = "9" * 64
            control["revision"]["status"]["imageDigest"] = f"sha256:{arbitrary}"
            dump(root / "control_plane.json", control)
            for phase in ("before", "after"):
                stopped[phase]["image_digest"] = f"sha256:{arbitrary}"
            dump(root / "shutdown.json", stopped)
            manifest["observations"]["control_plane"]["sha256"] = (
                deployment.sha256_file(root / "control_plane.json")
            )
            manifest["observations"]["shutdown"]["sha256"] = (
                deployment.sha256_file(root / "shutdown.json")
            )
            dump(root / "manifest.json", manifest)
            _, arbitrary_checks = deployment.validate_capture(
                root, candidate_manifest()
            )
            failure = next(
                item
                for item in arbitrary_checks
                if item.identifier == "capture.control_plane"
            )
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "cloud_run_resolved_digest_mismatch")

    def test_cloud_run_candidate_platform_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture(root, "cloud_run")
            for name, mutate in (
                (
                    "wrong_commit",
                    lambda value: value.update(candidate_commit="f" * 40),
                ),
                (
                    "wrong_index",
                    lambda value: value["image"].update(
                        index_digest="sha256:" + "1" * 64
                    ),
                ),
                (
                    "missing_amd64",
                    lambda value: value["image"]["platforms"].pop(
                        "linux/amd64"
                    ),
                ),
                (
                    "index_as_child",
                    lambda value: value["image"]["platforms"].update(
                        {"linux/amd64": f"sha256:{DIGEST}"}
                    ),
                ),
            ):
                with self.subTest(name=name):
                    candidate = candidate_manifest()
                    mutate(candidate)
                    _, checks = deployment.validate_capture(root, candidate)
                    failure = next(
                        item
                        for item in checks
                        if item.identifier == "capture.control_plane"
                    )
                    self.assertEqual(failure.status, "failed")
                    self.assertEqual(
                        failure.reason, "cloud_run_candidate_image_invalid"
                    )

    def test_cloud_run_tagged_full_traffic_matches_terraform_and_is_reduced(self) -> None:
        workflow_path = SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml"
        jobs = deployment.yaml_as_json(workflow_path)["jobs"]
        run = next(
            step["run"]
            for step in jobs["capture"]["steps"]
            if step.get("name")
            == "Capture Cloud Run migration, revision, secret, and rollout evidence"
        )
        terraform_main = (
            SCRIPT.parent.parent / "deploy/cloud-run/terraform/main.tf"
        ).read_text(encoding="utf-8")
        terraform_values = (
            SCRIPT.parent.parent / "deploy/cloud-run/terraform/terraform.tfvars.example"
        ).read_text(encoding="utf-8")
        self.assertIn('tag      = "candidate"', terraform_main)
        self.assertIn("service_traffic_percent          = 100", terraform_values)
        self.assertIn(
            'safe_traffic = [{"revisionName": revision_name, "percent": 100}]',
            run,
        )
        self.assertIn('traffic_item["percent"] != 100', run)
        self.assertNotIn('traffic_item.get("tag")', run)

    def test_aws_task_definition_arn_cross_binding_fails_closed(self) -> None:
        other = "arn:aws:ecs:r:a:task-definition/latchway:2"

        def mutate_migration(root: Path, manifest: dict[str, object]) -> None:
            migration = json.loads((root / "migration.json").read_text())
            migration["provider_execution"]["stopped_task"]["taskDefinitionArn"] = other
            dump(root / "migration.json", migration)
            manifest["observations"]["migration"]["sha256"] = deployment.sha256_file(
                root / "migration.json"
            )

        mutations = {
            "service": (
                lambda control: control["service"].update(taskDefinition=other),
                "aws_service_not_stable",
            ),
            "primary_deployment": (
                lambda control: control["service"]["deployments"][0].update(
                    taskDefinition=other
                ),
                "aws_service_not_stable",
            ),
            "running_task": (
                lambda control: control["tasks"][0].update(taskDefinitionArn=other),
                "aws_task_digest_mismatch",
            ),
        }
        for name, (mutate, reason) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "aws")
                control = json.loads((root / "control_plane.json").read_text())
                mutate(control)
                dump(root / "control_plane.json", control)
                manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(
                    root / "control_plane.json"
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(
                    item for item in checks if item.identifier == "capture.control_plane"
                )
                self.assertEqual(failure.status, "failed")
                self.assertEqual(failure.reason, reason)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "aws")
            mutate_migration(root, manifest)
            dump(root / "manifest.json", manifest)
            _, checks = deployment.validate_capture(root)
            failure = next(
                item for item in checks if item.identifier == "capture.control_plane"
            )
            self.assertEqual(failure.status, "failed")
            self.assertEqual(failure.reason, "aws_migration_execution_failed")

    def test_database_pool_shape_type_range_sum_and_uniqueness_fail_closed(self) -> None:
        invalid_pools = (
            {"aggregate_max_connections": True, "regular_max_connections": 15, "completion_max_connections": 5},
            {"aggregate_max_connections": 501, "regular_max_connections": 496, "completion_max_connections": 5},
            {"aggregate_max_connections": 20, "regular_max_connections": 14, "completion_max_connections": 5},
            {"aggregate_max_connections": 20, "regular_max_connections": 0, "completion_max_connections": 20},
            {"aggregate_max_connections": 20, "regular_max_connections": 15, "completion_max_connections": 5, "extra": 1},
        )
        for value in invalid_pools:
            with self.subTest(value=value), self.assertRaisesRegex(deployment.EvidenceError, "database_pool_test_failure"):
                deployment.validate_database_pool(value, (20, 15, 5), "database_pool_test_failure")

        invalid_environments = (
            database_pool_environment() + [{"name": "LATCHWAY_DB_MAX_CONNECTIONS", "value": "20"}],
            [{"name": "LATCHWAY_DB_MAX_CONNECTIONS", "value": "020"}, {"name": "LATCHWAY_DB_COMPLETION_CONNECTIONS", "value": "5"}],
            [{"name": "LATCHWAY_DB_MAX_CONNECTIONS", "value": 20}, {"name": "LATCHWAY_DB_COMPLETION_CONNECTIONS", "value": "5"}],
            [{"name": "LATCHWAY_DB_MAX_CONNECTIONS", "value": "20"}],
        )
        for value in invalid_environments:
            with self.subTest(value=value), self.assertRaisesRegex(deployment.EvidenceError, "database_pool_environment_test_failure"):
                deployment.database_pool_from_environment(value, (20, 15, 5), "database_pool_environment_test_failure")

    def test_migration_schema_versions_reject_booleans(self) -> None:
        with self.assertRaisesRegex(deployment.EvidenceError, "migration_status_invalid"):
            deployment.validate_migration({
                "command": ["/latchway", "--output", "json", "migrate", "status"],
                "status": {"current": True, "available": True, "up_to_date": True},
                "provider_execution": {
                    "reported_status": {"current": True, "available": True, "up_to_date": True}
                },
            })

    def test_health_identity_requires_current_canonical_wire_protocol(self) -> None:
        for name, value, remove in (
            ("old string", "1", False),
            ("integer", 2, False),
            ("unknown string", "unknown", False),
            ("missing", None, True),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "compose")
                health = json.loads((root / "health.json").read_text())
                build = health["body"]["build"]
                if remove:
                    build.pop("protocol_version")
                else:
                    build["protocol_version"] = value
                dump(root / "health.json", health)
                manifest["observations"]["health"]["sha256"] = deployment.sha256_file(
                    root / "health.json"
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.health")
                self.assertEqual(failure.status, "failed")
                self.assertIn(
                    failure.reason,
                    {"health_response_invalid", "health_build_identity_mismatch"},
                )

    def test_migration_status_requires_exact_embedded_catalog_version(self) -> None:
        for name, current, available in (
            ("older matched", 28, 28),
            ("future matched", 30, 30),
            ("older current", 28, 29),
            ("boolean current", True, 29),
            ("boolean available", 29, True),
        ):
            with self.subTest(name=name):
                status = {
                    "current": current,
                    "available": available,
                    "up_to_date": True,
                }
                with self.assertRaisesRegex(deployment.EvidenceError, "migration_status_invalid"):
                    deployment.validate_migration({
                        "command": ["/latchway", "--output", "json", "migrate", "status"],
                        "status": status,
                        "provider_execution": {"reported_status": copy.deepcopy(status)},
                    })

    def test_provider_numeric_success_fields_reject_booleans(self) -> None:
        def compose_exit(value: dict[str, object]) -> None:
            value["provider_execution"]["exit_code"] = False

        def aws_exit(value: dict[str, object]) -> None:
            value["provider_execution"]["stopped_task"]["containers"][0]["exitCode"] = False

        def fly_exit(value: dict[str, object]) -> None:
            value["provider_execution"]["exit_code"] = False

        def cloudflare_exit(value: dict[str, object]) -> None:
            value["provider_execution"]["exit_code"] = False

        def cloud_run_failed_count(value: dict[str, object]) -> None:
            value["provider_execution"]["status"]["failedCount"] = False

        migration_cases = {
            "compose": (compose_exit, "compose_migration_execution_failed"),
            "aws": (aws_exit, "aws_migration_execution_failed"),
            "fly_io": (fly_exit, "fly_migration_execution_failed"),
            "cloudflare_containers": (
                cloudflare_exit,
                "cloudflare_migration_execution_failed",
            ),
            "cloud_run": (
                cloud_run_failed_count,
                "cloud_run_migration_execution_failed",
            ),
        }
        for platform, (mutate, reason) in migration_cases.items():
            with self.subTest(platform=platform, field="migration"), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, platform)
                value = json.loads((root / "migration.json").read_text())
                mutate(value)
                dump(root / "migration.json", value)
                manifest["observations"]["migration"]["sha256"] = deployment.sha256_file(
                    root / "migration.json"
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.control_plane")
                self.assertEqual((failure.status, failure.reason), ("failed", reason))

        for platform in ("compose", "aws", "fly_io", "cloudflare_containers"):
            with self.subTest(platform=platform, field="shutdown"), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, platform)
                value = json.loads((root / "shutdown.json").read_text())
                value["exit_code"] = False
                dump(root / "shutdown.json", value)
                manifest["observations"]["shutdown"]["sha256"] = deployment.sha256_file(
                    root / "shutdown.json"
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.control_plane")
                self.assertEqual(
                    (failure.status, failure.reason),
                    ("failed", "shutdown_observation_invalid"),
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture(root, "cloudflare_containers")
            control = json.loads((root / "control_plane.json").read_text())
            control["container"]["canonical"]["layers"][0]["size"] = True
            control["container"]["mirror"]["layers"][0]["size"] = True
            dump(root / "control_plane.json", control)
            manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(
                root / "control_plane.json"
            )
            dump(root / "manifest.json", manifest)
            _, checks = deployment.validate_capture(root)
            failure = next(item for item in checks if item.identifier == "capture.control_plane")
            self.assertEqual(
                (failure.status, failure.reason),
                ("failed", "cloudflare_deployment_invalid"),
            )

    def test_compose_replacement_requires_two_real_container_ids(self) -> None:
        for mutation in ("same_id", "project_as_before", "after_not_gateway"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "compose")
                stopped = json.loads((root / "shutdown.json").read_text())
                if mutation == "same_id":
                    stopped["after"]["resource_id"] = stopped["before"]["resource_id"]
                elif mutation == "project_as_before":
                    stopped["before"]["resource_id"] = "latchway-release"
                else:
                    stopped["after"]["resource_id"] = "different-from-ready-gateway"
                dump(root / "shutdown.json", stopped)
                manifest["observations"]["shutdown"]["sha256"] = deployment.sha256_file(
                    root / "shutdown.json"
                )
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.control_plane")
                self.assertEqual(
                    (failure.status, failure.reason),
                    ("failed", "compose_gateway_not_replaced"),
                )

    def test_manifest_integer_fields_reject_booleans(self) -> None:
        for field in ("schema_version", "collector.run_attempt"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "compose")
                if field == "schema_version":
                    manifest["schema_version"] = True
                else:
                    manifest["collector"]["run_attempt"] = True
                dump(root / "manifest.json", manifest)
                with self.assertRaises(deployment.EvidenceError):
                    deployment.validate_capture(root)

    def test_cloudflare_pool_requires_unique_plain_text_binding_on_active_version(self) -> None:
        for mutation in (
            "duplicate",
            "wrong_type",
            "wrong_active_version",
            "secret_material",
            "historical_deployment",
            "extra_version_field",
            "noncanonical_binding_order",
            "partial_traffic",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = capture(root, "cloudflare_containers")
                control = json.loads((root / "control_plane.json").read_text())
                bindings = control["worker"]["versions"][0]["resources"]["bindings"]
                if mutation == "duplicate":
                    bindings.append(copy.deepcopy(bindings[0]))
                elif mutation == "wrong_type":
                    bindings[0]["type"] = "secret_text"
                elif mutation == "wrong_active_version":
                    control["worker"]["active_version_id"] = "11111111-abcd-1234-abcd-123456789abc"
                elif mutation == "secret_material":
                    control["worker"]["versions"][0]["token"] = "must-not-enter-evidence"
                elif mutation == "historical_deployment":
                    historical = copy.deepcopy(control["worker"]["deployments"][0])
                    historical["id"] = "historical-deployment"
                    historical["created_on"] = "2026-08-28T01:00:00Z"
                    control["worker"]["deployments"].append(historical)
                elif mutation == "extra_version_field":
                    control["worker"]["versions"][0]["metadata"] = {
                        "created_on": "2026-08-29T00:59:00Z"
                    }
                elif mutation == "noncanonical_binding_order":
                    bindings.reverse()
                else:
                    control["worker"]["deployments"][0]["versions"][0]["percentage"] = 50
                dump(root / "control_plane.json", control)
                manifest["observations"]["control_plane"]["sha256"] = deployment.sha256_file(root / "control_plane.json")
                dump(root / "manifest.json", manifest)
                _, checks = deployment.validate_capture(root)
                failure = next(item for item in checks if item.identifier == "capture.control_plane")
                self.assertEqual(failure.status, "failed")
                self.assertEqual(failure.reason, "cloudflare_database_pool_invalid")

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
                "available": 29,
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
            candidate_path = root / "candidate.json"
            dump(candidate_path, candidate_manifest())
            args = argparse.Namespace(
                evidence_root=root,
                coordinates=coordinate_path,
                trusted_root=trusted,
                core_commit=COMMIT,
                core_release="v1.0.0",
                contract_version="1.0.0",
                bundle_sha256=BUNDLE,
                image=IMAGE,
                candidate_manifest=candidate_path,
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
            candidate_path = root / "candidate.json"
            dump(candidate_path, candidate_manifest())
            args = argparse.Namespace(
                evidence_root=root,
                coordinates=coordinate_path,
                trusted_root=trusted,
                core_commit=COMMIT,
                core_release="v1.0.0",
                contract_version="1.0.0",
                bundle_sha256=BUNDLE,
                image=IMAGE,
                candidate_manifest=candidate_path,
            )
            with self.assertRaisesRegex(deployment.EvidenceError, "capture_archive_invalid"):
                deployment.finalize(args)


if __name__ == "__main__":
    unittest.main()
