#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
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
    def test_workflow_is_prepublication_and_candidate_attested(self) -> None:
        result = deployment.validate_workflow()
        self.assertGreaterEqual(result["pinned_actions"], 1)
        text = (SCRIPT.parent.parent / ".github/workflows/deployment-evidence.yml").read_text()
        self.assertNotIn("refs/tags/", text)
        self.assertIn('--source-digest "$CANDIDATE_COMMIT"', text)
        self.assertIn('--core-commit "$CANDIDATE_COMMIT"', text)

    def test_static_assets_pass(self) -> None:
        checks = deployment.static_checks()
        self.assertTrue(checks)
        self.assertTrue(all(item.status == "passed" for item in checks), checks)

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
