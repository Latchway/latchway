from __future__ import annotations

import copy
import base64
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("verify-public-registry-proof.py")
SPEC = importlib.util.spec_from_file_location("verify_public_registry_proof", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicRegistryProofTests(unittest.TestCase):
    @staticmethod
    def dependency_asset(names: set[str]) -> dict:
        return {
            name: {
                "bytes": 1,
                "sha256": hashlib.sha256(name.encode()).hexdigest(),
                "immutable_attestation": {"verified": True},
            }
            for name in names
        }

    def rn_dependency_evidence(self) -> tuple[dict, dict]:
        repositories = {
            name: {"version": "1.0.0", "tag": "v1.0.0", "commit": character * 40}
            for name, character in {
                "core": "a", "javascript": "b", "ios": "c", "android": "d",
            }.items()
        }
        js_fixed, _ = MODULE.expected_npm_release_assets("@latchway/client", "1.0.0")
        js_assets = js_fixed | {
            f"npm-release-adoption-{package_id}-99-2.json"
            for package_id, _ in MODULE.JAVASCRIPT_NPM_PACKAGES
        }
        ios_archive = "latchway-ios-sdk-1.0.0.tar.gz"
        ios_assets = {
            ios_archive, f"{ios_archive}.sha256", "cocoapods-published-podspec.json",
            "cocoapods-reviewed-podspec.json", "cocoapods-release-evidence.json",
            "cocoapods-release-evidence.SHA256SUMS", "docs-bundle-1.0.0.tar.gz",
        }
        android_assets = {
            "latchway-android-1.0.0-maven-repository.zip",
            "latchway-android-1.0.0-central-portal.zip", "SHA256SUMS",
            "docs-bundle-1.0.0.tar.gz",
            "github-release-tag-binding.json", "latchway-maven-signing-public-key.asc",
            "maven-central-upload-intent.json", "maven-central-deployment.json",
            "maven-central-deployment-status.json", "maven-central-release-evidence.json",
        }
        def summary(identifier: str, assets: set[str], registry: dict) -> dict:
            return {
                "repository": {
                    "javascript": "https://github.com/Latchway/latchway-js",
                    "ios": "https://github.com/Latchway/latchway-ios-sdk",
                    "android": "https://github.com/Latchway/latchway-android",
                }[identifier],
                "release_tag": "v1.0.0",
                "source_commit": repositories[identifier]["commit"],
                "github_release_immutable": True,
                "github_release_attestation": {"verified": True},
                "release_assets": self.dependency_asset(assets),
                "public_registry": registry,
            }
        evidence = {
            "schema_version": 1,
            "kind": "latchway_react_native_published_dependency_evidence",
            "dependencies": {
                "core": {
                    "repository": "https://github.com/Latchway/latchway",
                    "source_commit": repositories["core"]["commit"],
                    "release_tag": "v1.0.0",
                },
                "javascript": summary("javascript", js_assets, {
                    "registry": "npm", "integrity": "sha512-AA==",
                    "tarball_sha256": "1" * 64, "provenance_run_id": 1,
                    "provenance_run_attempt": 1,
                }),
                "ios": summary("ios", ios_assets, {
                    "registry": "cocoapods", "source_archive_sha256": "2" * 64,
                    "published_spec_sha256": "3" * 64,
                }),
                "android": summary("android", android_assets, {
                    "registry": "maven_central", "repository_archive_sha256": "4" * 64,
                    "signing_fingerprint": "A" * 40,
                }),
            },
        }
        return evidence, repositories

    def test_cocoapods_spec_requires_complete_safe_subspec_surface(self) -> None:
        coordinate = {"version": "1.0.0", "tag": "v1.0.0", "commit": "c" * 40}
        spec = {
            "name": "Latchway",
            "version": "1.0.0",
            "source": {
                "git": "https://github.com/Latchway/latchway-ios-sdk.git",
                "tag": "v1.0.0",
            },
            "subspecs": [
                {"name": name, "source_files": f"Sources/{name}/**/*.swift"}
                for name in ("Core", "AppAttest", "AppExtensions", "FirebaseAuth")
            ],
        }
        MODULE.validate_cocoapods_spec(spec, coordinate)
        mutations = []
        missing_extensions = copy.deepcopy(spec)
        missing_extensions["subspecs"] = [
            item
            for item in missing_extensions["subspecs"]
            if item["name"] != "AppExtensions"
        ]
        mutations.append(missing_extensions)
        duplicate_core = copy.deepcopy(spec)
        duplicate_core["subspecs"].append({"name": "Core"})
        mutations.append(duplicate_core)
        injected_hook = copy.deepcopy(spec)
        injected_hook["subspecs"][0]["prepare_command"] = "unreviewed"
        mutations.append(injected_hook)
        wrong_source = copy.deepcopy(spec)
        wrong_source["source"]["git"] = "https://example.test/unreviewed.git"
        mutations.append(wrong_source)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                MODULE.ProofError, "cocoapods_spec_invalid"
            ):
                MODULE.validate_cocoapods_spec(mutation, coordinate)

    def test_swift_resolution_requires_exact_ios_source_coordinate(self) -> None:
        coordinate = {"version": "1.0.0", "tag": "v1.0.0", "commit": "c" * 40}
        resolution = {
            "originHash": "d" * 64,
            "pins": [
                {
                    "identity": "latchway-ios-sdk",
                    "kind": "remoteSourceControl",
                    "location": "https://github.com/Latchway/latchway-ios-sdk.git",
                    "state": {"revision": "c" * 40, "version": "1.0.0"},
                }
            ],
            "version": 3,
        }
        MODULE.validate_swift_resolution(resolution, coordinate)
        for mutation in ("commit", "version", "location", "duplicate"):
            changed = copy.deepcopy(resolution)
            if mutation == "duplicate":
                changed["pins"].append(copy.deepcopy(changed["pins"][0]))
            elif mutation == "location":
                changed["pins"][0]["location"] = "https://example.test/replaced.git"
            else:
                changed["pins"][0]["state"][mutation] = "0" * 40
            with self.subTest(mutation=mutation), self.assertRaises(
                MODULE.ProofError
            ):
                MODULE.validate_swift_resolution(changed, coordinate)

    def test_mintlify_retained_container_recomputes_every_raw_authority_file(self) -> None:
        fixture_path = Path(__file__).with_name("test_mintlify_production_proof.py")
        spec = importlib.util.spec_from_file_location(
            "mintlify_fixture_for_public_registry", fixture_path
        )
        assert spec is not None and spec.loader is not None
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        fixture = fixture_module.MintlifyProductionProofTests(methodName="runTest")
        fixture.setUp()
        inputs = fixture.inputs()
        proof = MODULE.MINTLIFY.build_proof(**inputs)
        payloads = {
            MODULE.MINTLIFY.EVIDENCE_FILE: inputs["evidence_payload"],
            MODULE.MINTLIFY.CHECKSUM_FILE: inputs["checksum_payload"],
            MODULE.MINTLIFY.ATTESTATION_FILE: inputs["attestation_bundle_payload"],
            "run.json": inputs["run_payload"],
            "workflow.json": inputs["workflow_payload"],
            "artifact.json": inputs["artifact_payload"],
            "attestation-verification.json": inputs[
                "attestation_verification_payload"
            ],
        }
        container = {
            "schema_version": 1,
            "kind": "latchway_retained_mintlify_production_evidence",
            "observation": "registry.documentation-production",
            "files": [
                {
                    "name": name,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "content_base64": base64.b64encode(payload).decode(),
                }
                for name, payload in sorted(payloads.items())
            ],
        }
        MODULE.validate_mintlify_retained_container(
            container, proof, now=fixture.now
        )
        for mutation in ("missing", "reordered", "changed-run"):
            changed = copy.deepcopy(container)
            if mutation == "missing":
                changed["files"].pop()
            elif mutation == "reordered":
                changed["files"][0], changed["files"][1] = (
                    changed["files"][1],
                    changed["files"][0],
                )
            else:
                run = next(item for item in changed["files"] if item["name"] == "run.json")
                payload = json.loads(base64.b64decode(run["content_base64"]))
                payload["head_sha"] = "0" * 40
                raw = fixture.encoded(payload)
                run["content_base64"] = base64.b64encode(raw).decode()
                run["sha256"] = hashlib.sha256(raw).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ProofError):
                MODULE.validate_mintlify_retained_container(
                    changed, proof, now=fixture.now
                )

    def npm_proof(self) -> dict:
        sha = "a" * 64
        integrity = "sha512-" + "A" * 86 + "=="
        package_evidence = {
            "schema_version": 1,
            "package": "@latchway/client",
            "version": "1.0.0",
            "tarball": "latchway-client-1.0.0.tgz",
            "bytes": 123,
            "sha256": sha,
            "sha512": "1" * 128,
            "integrity": integrity,
            "double_pack_byte_identical": True,
        }

        def encoded(value: dict) -> bytes:
            return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

        def envelope(name: str, payload: bytes) -> dict:
            digest = hashlib.sha256(payload).hexdigest()
            return {
                "name": name, "bytes": len(payload), "sha256": digest,
                "release_digest": "sha256:" + digest,
                "content_base64": base64.b64encode(payload).decode(),
            }

        metadata = {
            # npm does not inject gitHead into a prebuilt package tarball. Source
            # identity is instead bound by trusted-publisher provenance below.
            "name": "@latchway/client", "version": "1.0.0",
            "dist": {"integrity": integrity},
        }
        attestations = encoded({"attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]})
        audit = encoded({"audited": 1})
        version_bytes = encoded(metadata)
        view_bytes = encoded(metadata)
        evidence_payloads = {
            "npm-registry-version.json": version_bytes,
            "npm-registry-view.json": view_bytes,
            "npm-attestations.json": attestations,
            "npm-audit-signatures.json": audit,
        }
        registry_manifest = {
            "schema_version": 1,
            "kind": "latchway_npm_registry_evidence_manifest",
            "package": "@latchway/client",
            "version": "1.0.0",
            "tarball": {
                "name": package_evidence["tarball"], "bytes": package_evidence["bytes"],
                "sha256": sha, "sha512": package_evidence["sha512"], "integrity": integrity,
            },
            "evidence": sorted([
                {"name": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                for name, payload in evidence_payloads.items()
            ], key=lambda item: item["name"]),
        }
        manifest_bytes = encoded(registry_manifest)
        post = {
            "schema_version": 2,
            "kind": "latchway_npm_publication_evidence",
            "package": "@latchway/client",
            "version": "1.0.0",
        }
        raw = {
            **{name: envelope(name, payload) for name, payload in evidence_payloads.items()},
            "npm-registry-evidence-manifest.json": envelope("npm-registry-evidence-manifest.json", manifest_bytes),
            "post-publish-evidence.json": envelope("post-publish-evidence.json", encoded(post)),
        }
        adoption_name = "npm-release-adoption-99-2.json"
        source_binding = {
            "repository": "https://github.com/Latchway/latchway-js",
            "commit": "b" * 40,
            "workflow": ".github/workflows/release.yml",
            "ref": "refs/heads/main",
        }
        adoption = {
            "schema_version": 1,
            "kind": "latchway_npm_release_adoption",
            "package": "@latchway/client",
            "version": "1.0.0",
            "release_tag": "v1.0.0",
            "tarball": registry_manifest["tarball"],
            "source": source_binding,
            "provenance": {
                **source_binding,
                "predicate_type": "https://slsa.dev/provenance/v1",
                "run_id": 123,
                "run_attempt": 1,
                "invocation_id": "https://github.com/Latchway/latchway-js/actions/runs/123/attempts/1",
            },
            "adoption": {
                **source_binding,
                "run_id": 99,
                "run_attempt": 2,
                "mode": "adopted_existing",
            },
            "registry_evidence_manifest": {
                "file": "npm-registry-evidence-manifest.json",
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            },
        }
        adoption_envelope = envelope(adoption_name, encoded(adoption))
        fixed, _ = MODULE.expected_npm_release_assets("@latchway/client", "1.0.0")
        release_names = fixed | {adoption_name}
        raw["source_attestation_verifications"] = {
            name: [{"verified": True}]
            for name in set(raw) - {"source_attestation_verifications"} | {adoption_name}
        }
        proof = {
            "schema_version": 1,
            "registry": "npm",
            "package": "@latchway/client",
            "version": "1.0.0",
            "source_commit": "b" * 40,
            "registry_integrity": integrity,
            "tarball": "latchway-client-1.0.0.tgz",
            "sha256": sha,
            "integrity": integrity,
            "registry_tarball_byte_identical": True,
            "provenance": {
                "attestations_sha256": hashlib.sha256(attestations).hexdigest(),
                "attestations_content_base64": base64.b64encode(attestations).decode(),
                "source_repository": "Latchway/latchway-js",
                "source_commit": "b" * 40,
                "workflow": ".github/workflows/release.yml",
                "workflow_ref": "refs/heads/main",
                "run_id": 123,
                "run_attempt": 1,
                "invocation_id": "https://github.com/Latchway/latchway-js/actions/runs/123/attempts/1",
                "run_conclusion": "failure",
                "authenticated_run": {
                    "id": 123,
                    "run_attempt": 1,
                    "event": "repository_dispatch",
                    "status": "completed",
                    "conclusion": "failure",
                    "head_sha": "b" * 40,
                    "head_branch": "main",
                    "path": ".github/workflows/release.yml",
                    "repository": {"full_name": "Latchway/latchway-js"},
                },
            },
            "registry_evidence": raw,
            "independent_live_registry_evidence": {
                "npm_attestations": {"sha256": hashlib.sha256(attestations).hexdigest(), "content_base64": base64.b64encode(attestations).decode()},
                "npm_audit_signatures": {"sha256": hashlib.sha256(audit).hexdigest(), "content_base64": base64.b64encode(audit).decode()},
                "npm_view": {"sha256": hashlib.sha256(view_bytes).hexdigest(), "content_base64": base64.b64encode(view_bytes).decode()},
            },
            "adoptions": [{
                "asset": adoption_envelope,
                "record": adoption,
                "authenticated_run": {
                    "id": 99, "run_attempt": 2, "status": "completed", "conclusion": "success",
                    "event": "repository_dispatch", "head_sha": "b" * 40,
                    "head_branch": "main", "path": ".github/workflows/release.yml",
                    "repository": {"full_name": "Latchway/latchway-js"},
                },
            }],
            "reviewed_package_evidence": package_evidence,
            "reviewed_build_reproducibility": {
                "schema_version": 1,
                "identical": True,
                "sha256": "c" * 64,
            },
            "release_asset_digests": {
                "latchway-client-1.0.0.tgz": "sha256:" + sha,
                "docs-bundle-1.0.0.tar.gz": "sha256:" + "9" * 64,
                "package-evidence.json": "sha256:" + "d" * 64,
                "build-reproducibility.json": "sha256:" + "e" * 64,
            },
            "release_asset_attestation_verifications": {
                "latchway-client-1.0.0.tgz": [{"verified": True}],
                "docs-bundle-1.0.0.tar.gz": [{"verified": True}],
                "package-evidence.json": [{"verified": True}],
                "build-reproducibility.json": [{"verified": True}],
            },
            "release_asset_set": {
                name: {
                    "name": name,
                    "digest": "sha256:" + (sha if name == package_evidence["tarball"] else hashlib.sha256(name.encode()).hexdigest()),
                    "size": 123,
                }
                for name in release_names
            },
            "immutable_release_asset_verifications": {
                name: {"sha256": "f" * 64, "content_base64": "e30K"}
                for name in release_names
            },
            "compatibility": {"minimum_node": "24.19.0"},
        }
        proof["release_asset_set"][adoption_name]["digest"] = adoption_envelope["release_digest"]
        for name, digest in proof["release_asset_digests"].items():
            proof["release_asset_set"][name]["digest"] = digest
        return proof

    @staticmethod
    def javascript_contract_authority() -> dict:
        return {
            "contract_version": "1.0.0",
            "core_release": "v1.0.0",
            "core_commit": "c" * 40,
            "bundle_sha256": "d" * 64,
            "wire_protocol_version": 2,
            "fixtures": [
                {"name": "protocol-version.json", "sha256": "f" * 64}
            ],
        }

    def javascript_npm_set_proof(self) -> tuple[dict, dict, dict[str, bytes]]:
        version = "1.0.0"
        commit = "b" * 40
        coordinate = {"version": version, "commit": commit, "tag": "v1.0.0"}
        order = [name for _, name in MODULE.JAVASCRIPT_NPM_PACKAGES]

        def encoded(value: dict) -> bytes:
            return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

        def envelope(name: str, payload: bytes) -> dict:
            digest = hashlib.sha256(payload).hexdigest()
            return {
                "name": name,
                "bytes": len(payload),
                "sha256": digest,
                "release_digest": "sha256:" + digest,
                "content_base64": base64.b64encode(payload).decode(),
            }

        reviewed_packages = []
        publish_packages = []
        manifest_packages = []
        post_packages = []
        package_proofs = []
        raw_payloads: dict[str, bytes] = {}
        adoption_payloads: dict[str, bytes] = {}
        retained_tarballs: dict[str, bytes] = {}
        reproducibility_rows: list[dict] = []
        reproducibility_aggregate = hashlib.sha256()
        contract_lock_payload = b'contract_version: "1.0.0"\n'
        contract_lock_sha256 = hashlib.sha256(contract_lock_payload).hexdigest()
        source = {
            "repository": "https://github.com/Latchway/latchway-js",
            "commit": commit,
            "workflow": ".github/workflows/release.yml",
            "ref": "refs/heads/main",
        }
        manifest_placeholder = "f" * 64
        for index, (package_id, package) in enumerate(MODULE.JAVASCRIPT_NPM_PACKAGES, 1):
            tarball_name = f"latchway-{package_id}-{version}.tgz"
            peers = (
                {}
                if package_id == "client"
                else {"@latchway/client": f"^{version}"}
            )
            archive_files = {
                "package/package.json": encoded(
                    {
                        "name": package,
                        "version": version,
                        "peerDependencies": peers,
                    }
                ),
                "package/dist/index.js": (
                    f"export const packageId = {package_id!r};\n".encode()
                ),
            }
            if package_id == "client":
                archive_files["package/contract.lock"] = contract_lock_payload
            buffer = io.BytesIO()
            with tarfile.open(
                fileobj=buffer, mode="w:gz", format=tarfile.USTAR_FORMAT
            ) as archive:
                for archive_name, archive_payload in sorted(archive_files.items()):
                    member = tarfile.TarInfo(archive_name)
                    member.mode = 0o644
                    member.uid = member.gid = member.mtime = 0
                    member.size = len(archive_payload)
                    archive.addfile(member, io.BytesIO(archive_payload))
            tarball_payload = buffer.getvalue()
            retained_tarballs[tarball_name] = tarball_payload
            sha1 = hashlib.sha1(tarball_payload).hexdigest()
            sha256 = hashlib.sha256(tarball_payload).hexdigest()
            sha512 = hashlib.sha512(tarball_payload).hexdigest()
            integrity = "sha512-" + base64.b64encode(
                hashlib.sha512(tarball_payload).digest()
            ).decode()
            repository_path = (
                "dist/index.js"
                if package_id == "client"
                else f"packages/{package_id}/dist/index.js"
            )
            dist_payload = archive_files["package/dist/index.js"]
            reproducibility_rows.append(
                {
                    "package": package,
                    "path": repository_path,
                    "bytes": len(dist_payload),
                    "sha256": hashlib.sha256(dist_payload).hexdigest(),
                }
            )
            reproducibility_aggregate.update(repository_path.encode())
            reproducibility_aggregate.update(b"\0")
            reproducibility_aggregate.update(dist_payload)
            reproducibility_aggregate.update(b"\0")
            reviewed = {
                "id": package_id,
                "package": package,
                "version": version,
                "tarball": tarball_name,
                "bytes": len(tarball_payload),
                "sha1": sha1,
                "sha256": sha256,
                "sha512": sha512,
                "integrity": integrity,
                "double_pack_byte_identical": True,
                "archive_allowlist_verified": True,
                "archive_regular_files_only": True,
                "credential_scan": "passed",
                "entries": sorted(archive_files),
                "unpacked_bytes": sum(map(len, archive_files.values())),
                "published_peer_dependencies": peers,
            }
            reviewed_packages.append(reviewed)
            publish_packages.append({
                key: reviewed[key]
                for key in (
                    "id", "package", "version", "tarball", "bytes", "sha1",
                    "sha256", "sha512", "integrity",
                )
            })
            metadata = {
                "name": package,
                "version": version,
                "dist": {
                    "integrity": integrity,
                    "tarball": (
                        f"https://registry.npmjs.org/{package}/-/"
                        f"{package_id}-{version}.tgz"
                    ),
                },
            }
            raw_names = {
                f"npm-{package_id}-registry-version.json": encoded(metadata),
                f"npm-{package_id}-registry-view.json": encoded(metadata),
                f"npm-{package_id}-attestations.json": encoded({"attestations": []}),
                f"npm-{package_id}-audit-signatures.json": encoded({"audited": True}),
            }
            raw_payloads.update(raw_names)
            evidence = [
                {"name": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                for name, payload in sorted(raw_names.items())
            ]
            tarball = {
                "name": tarball_name,
                "bytes": reviewed["bytes"],
                "sha256": sha256,
                "sha512": sha512,
                "integrity": integrity,
            }
            manifest_packages.append({
                "id": package_id,
                "package": package,
                "version": version,
                "tarball": tarball,
                "evidence": evidence,
            })
            references = {
                item["name"]: {"bytes": item["bytes"], "sha256": item["sha256"]}
                for item in evidence
            }
            origin = {
                "invocation_id": f"https://github.com/Latchway/latchway-js/actions/runs/{100 + index}/attempts/1",
                "run_id": 100 + index,
                "run_attempt": 1,
            }
            post_packages.append({
                "id": package_id,
                "package": package,
                "version": version,
                "publication_mode": "published",
                "tarball": {**tarball, "registry_bytes_sha256": sha256},
                "trusted_publisher": {
                    "provider": "github",
                    "provenance_predicate_type": "https://slsa.dev/provenance/v1",
                    "provenance_origin": origin,
                    "sigstore_bundle": {
                        "file": f"npm-{package_id}-attestations.json",
                        **references[f"npm-{package_id}-attestations.json"],
                    },
                },
                "registry_signature_verification": {
                    "command": "npm audit signatures --json --registry=https://registry.npmjs.org/",
                    "output": {
                        "file": f"npm-{package_id}-audit-signatures.json",
                        **references[f"npm-{package_id}-audit-signatures.json"],
                    },
                },
                "clean_consumer": {
                    "isolated_directory": True,
                    "install_scripts": "disabled",
                    "exact_package_version": version,
                    "matching_client_version": None if package_id == "client" else version,
                    "external_peer_dependencies": {},
                    "node_esm": True,
                    "registry_signatures": True,
                },
                "retained_outputs": references,
            })
            adoption_name = f"npm-release-adoption-{package_id}-{200 + index}-2.json"
            adoption = {
                "schema_version": 1,
                "kind": "latchway_npm_release_adoption",
                "package": package,
                "version": version,
                "release_tag": "v1.0.0",
                "tarball": tarball,
                "source": source,
                "provenance": {
                    **source,
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    **origin,
                },
                "adoption": {
                    **source,
                    "run_id": 200 + index,
                    "run_attempt": 2,
                    "mode": "adopted_existing",
                },
                "registry_evidence_manifest": {
                    "file": "npm-registry-evidence-manifest.json",
                    "sha256": manifest_placeholder,
                },
            }
            adoption_bytes = encoded(adoption)
            adoption_payloads[adoption_name] = adoption_bytes
            provenance_bytes = raw_names[f"npm-{package_id}-attestations.json"]
            package_proofs.append({
                "id": package_id,
                "package": package,
                "version": version,
                "registry_tarball_url": metadata["dist"]["tarball"],
                "registry_integrity": integrity,
                "tarball": tarball_name,
                "bytes": reviewed["bytes"],
                "sha1": reviewed["sha1"],
                "sha256": sha256,
                "sha512": sha512,
                "integrity": integrity,
                "registry_tarball_byte_identical": True,
                "provenance": {
                    "attestations_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
                    "attestations_content_base64": base64.b64encode(provenance_bytes).decode(),
                    "source_repository": "Latchway/latchway-js",
                    "source_commit": commit,
                    "workflow": ".github/workflows/release.yml",
                    "workflow_ref": "refs/heads/main",
                    **origin,
                    "run_conclusion": "failure",
                    "certificate_identity": (
                        "URI:https://github.com/Latchway/latchway-js/"
                        ".github/workflows/release.yml@refs/heads/main"
                    ),
                    "authenticated_run": {
                        "id": origin["run_id"],
                        "run_attempt": 1,
                        "event": "repository_dispatch",
                        "status": "completed",
                        "conclusion": "failure",
                        "head_sha": commit,
                        "head_branch": "main",
                        "path": ".github/workflows/release.yml",
                        "repository": {"full_name": "Latchway/latchway-js"},
                    },
                },
                "registry_evidence": {
                    name: envelope(name, payload) for name, payload in raw_names.items()
                },
                "independent_live_registry_evidence": {
                    "npm_attestations": {
                        "sha256": hashlib.sha256(provenance_bytes).hexdigest(),
                        "content_base64": base64.b64encode(provenance_bytes).decode(),
                    },
                    "npm_audit_signatures": {
                        "sha256": hashlib.sha256(raw_names[f"npm-{package_id}-audit-signatures.json"]).hexdigest(),
                        "content_base64": base64.b64encode(raw_names[f"npm-{package_id}-audit-signatures.json"]).decode(),
                    },
                    "npm_view": {
                        "sha256": hashlib.sha256(raw_names[f"npm-{package_id}-registry-view.json"]).hexdigest(),
                        "content_base64": base64.b64encode(raw_names[f"npm-{package_id}-registry-view.json"]).decode(),
                    },
                },
                "adoptions": [{
                    "asset": envelope(adoption_name, adoption_bytes),
                    "record": adoption,
                    "authenticated_run": {
                        "id": 200 + index,
                        "run_attempt": 2,
                        "event": "repository_dispatch",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": commit,
                        "head_branch": "main",
                        "path": ".github/workflows/release.yml",
                        "repository": {"full_name": "Latchway/latchway-js"},
                    },
                }],
            })

        package_evidence = {
            "schema_version": 2,
            "kind": "latchway_npm_package_set_evidence",
            "version": version,
            "package_count": 4,
            "publish_order": order,
            "packages": reviewed_packages,
            "consumer": {
                "package_count": 4,
                "packages": [{"name": name, "version": version} for name in order],
                "node_esm": True,
                "typescript": True,
                "peer_source": "reviewed",
            },
        }
        candidate = {
            "schema_version": 2,
            "package_count": 4,
            "packages": order,
            "version": version,
            "source_commit": commit,
            "worktree_clean": True,
            "stable_version": True,
            "node": "v24.19.0",
            "pnpm": "10.15.0",
            "gates": [{"name": name, "status": "passed", "duration_ms": 1} for name in (
                "workflow-policy", "contract-lock", "release-policy", "lint", "typecheck",
                "clean-build", "unit-tests", "offline-release-tests", "examples", "exports",
                "web-browser-and-bundler-conformance", "build-reproducibility", "package-conformance",
            )],
        }
        package_evidence_bytes = encoded(package_evidence)
        checksum_payload = (
            "\n".join(
                sorted(
                    f"{item['sha256']}  {item['tarball']}"
                    for item in reviewed_packages
                )
            )
            + "\n"
        ).encode("ascii")
        checksum_sha = hashlib.sha256(checksum_payload).hexdigest()
        publish_input = {
            "schema_version": 2,
            "kind": "latchway_npm_publish_input_evidence",
            "version": version,
            "source_commit": commit,
            "release_tag": "v1.0.0",
            "package_count": 4,
            "publish_order": order,
            "packages": publish_packages,
            "verified_job_evidence": True,
            "package_evidence": {"file": "package-evidence.json", "sha256": hashlib.sha256(package_evidence_bytes).hexdigest()},
            "checksums": {"file": "SHA256SUMS", "sha256": checksum_sha},
            "consumer": {
                "package_count": 4,
                "packages": [{"name": name, "version": version} for name in order],
                "node_esm": True,
                "typescript": False,
                "peer_source": "registry",
            },
        }
        manifest = {
            "schema_version": 2,
            "kind": "latchway_npm_registry_package_set_evidence_manifest",
            "version": version,
            "package_count": 4,
            "publish_order": order,
            "packages": manifest_packages,
        }
        manifest_bytes = encoded(manifest)
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        # Replace the placeholder while preserving a self-consistent manifest:
        # adoption records bind the final manifest, but the manifest does not bind adoptions.
        for proof in package_proofs:
            record = proof["adoptions"][0]["record"]
            record["registry_evidence_manifest"]["sha256"] = manifest_sha
            name = proof["adoptions"][0]["asset"]["name"]
            payload = encoded(record)
            adoption_payloads[name] = payload
            proof["adoptions"][0]["asset"] = envelope(name, payload)
        post = {
            "schema_version": 3,
            "kind": "latchway_npm_package_set_publication_evidence",
            "version": version,
            "package_count": 4,
            "publish_order": order,
            "source": source,
            "release_tag": "v1.0.0",
            "registry": "https://registry.npmjs.org/",
            "packages": post_packages,
            "evidence_manifest": {
                "file": "npm-registry-evidence-manifest.json",
                "bytes": len(manifest_bytes),
                "sha256": manifest_sha,
            },
        }
        aggregate = {
            "package-evidence.json": package_evidence,
            "release-candidate-evidence.json": candidate,
            "publish-input-evidence.json": publish_input,
            "post-publish-evidence.json": post,
            "npm-registry-evidence-manifest.json": manifest,
            "build-reproducibility.json": {
                "schema_version": 1, "identical": True, "package_count": 4,
                "sha256": reproducibility_aggregate.hexdigest(),
                "files": reproducibility_rows,
            },
            "contract-evidence.json": {
                "schema_version": 1,
                "contract_version": "1.0.0",
                "core_release": "v1.0.0",
                "core_commit": "c" * 40,
                "bundle_sha256": "d" * 64,
                "wire_protocol_version": 2,
                "contract_lock_sha256": contract_lock_sha256,
                "fixtures": [
                    {"name": "protocol-version.json", "sha256": "f" * 64}
                ],
            },
            "dependency-vulnerability-scan.json": {
                "schema_version": "latchway.dependency-vulnerability-scan.v1",
                "scanner": {
                    "name": "OSV-Scanner",
                    "version": "2.4.0",
                    "commit": MODULE.JAVASCRIPT_OSV_SCANNER_COMMIT,
                    "mode": "offline",
                },
                "source_commit": commit,
                "inventory_sha256": "1" * 64,
                "database_sha256": "2" * 64,
                "package_count": 4,
                "vulnerability_count": 0,
                "blocking_vulnerability_count": 0,
                "policy": "block-critical-high-and-unknown-severity",
                "status": "passed",
            },
            "tag-evidence.json": {
                "schema_version": 1,
                "tag": "v1.0.0",
                "version": version,
                "commit": commit,
                "annotated": True,
            },
        }
        aggregate_payloads = {name: encoded(document) for name, document in aggregate.items()}
        retained_aggregate = {
            name: envelope(name, payload) for name, payload in aggregate_payloads.items()
        }
        retained_aggregate["SHA256SUMS"] = envelope(
            "SHA256SUMS", checksum_payload
        )
        fixed, _ = MODULE.expected_npm_release_assets("@latchway/client", version)
        release_names = fixed | set(adoption_payloads)
        release_set = {
            name: {
                "name": name,
                "size": 1,
                "digest": "sha256:" + hashlib.sha256(name.encode()).hexdigest(),
            }
            for name in release_names
        }
        release_set["SHA256SUMS"]["digest"] = "sha256:" + checksum_sha
        release_set["SHA256SUMS"]["size"] = len(checksum_payload)
        for package_id, _ in MODULE.JAVASCRIPT_NPM_PACKAGES:
            name = f"latchway-{package_id}-{version}.tgz"
            release_set[name]["digest"] = (
                "sha256:" + hashlib.sha256(retained_tarballs[name]).hexdigest()
            )
            release_set[name]["size"] = len(retained_tarballs[name])
        for name, envelope_ in retained_aggregate.items():
            release_set[name]["digest"] = envelope_["release_digest"]
            release_set[name]["size"] = envelope_["bytes"]
        for name, payload in raw_payloads.items():
            release_set[name]["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
            release_set[name]["size"] = len(payload)
        for name, payload in adoption_payloads.items():
            release_set[name]["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
            release_set[name]["size"] = len(payload)
        proof = {
            "schema_version": 2,
            "kind": "latchway_npm_package_set_registry_proof",
            "registry": "npm",
            "version": version,
            "source_commit": commit,
            "release_tag": "v1.0.0",
            "package_count": 4,
            "publish_order": order,
            "packages": package_proofs,
            "reviewed_aggregate_evidence": aggregate,
            "checksum_verification": {
                "schema_version": 1,
                "algorithm": "sha256",
                "file": "SHA256SUMS",
                "file_sha256": checksum_sha,
                "entries": sorted(
                    (
                        {"name": item["tarball"], "sha256": item["sha256"]}
                        for item in reviewed_packages
                    ),
                    key=lambda item: item["name"],
                ),
            },
            "contract_source_verification": {
                "schema_version": 1,
                "source_repository_commit": commit,
                "contract_version": "1.0.0",
                "core_release": "v1.0.0",
                "core_commit": "c" * 40,
                "bundle_sha256": "d" * 64,
                "wire_protocol_version": 2,
                "contract_lock_sha256": contract_lock_sha256,
                "fixture_count": 1,
                "fixture_set_sha256": hashlib.sha256(
                    encoded(
                        [
                            {
                                "name": "protocol-version.json",
                                "sha256": "f" * 64,
                            }
                        ]
                    )
                ).hexdigest(),
            },
            "reproducibility_archive_verification": {
                "schema_version": 1,
                "algorithm": "sha256",
                "inputs": "ordered-release-tarball-dist-file-bytes",
                "archive_regular_file_closure_verified": True,
                "source_manifests_and_peer_translation_verified": True,
                "independent_source_rebuild_performed": False,
                "file_count": 4,
                "bytes": sum(item["bytes"] for item in reproducibility_rows),
                "sha256": reproducibility_aggregate.hexdigest(),
            },
            "retained_aggregate_evidence": retained_aggregate,
            "release_asset_set": release_set,
            "immutable_release_asset_verifications": {name: {"verified": True} for name in release_names},
            "release_asset_attestation_verifications": {name: [{"verified": True}] for name in release_names},
            "compatibility": {"minimum_node": "24.19.0"},
        }
        return proof, coordinate, retained_tarballs

    def maven_proof(self) -> dict:
        signature = (
            "-----BEGIN PGP SIGNATURE-----\n"
            "test\n"
            "-----END PGP SIGNATURE-----\n"
        )
        version = "1.0.0"
        archive = b"archive"
        portal = b"portal"
        key = b"public-key"
        portal_sha = hashlib.sha256(portal).hexdigest()
        deployment_name = f"latchway-android-v{version}-{'b' * 12}-{portal_sha}"
        purls = sorted(
            f"pkg:maven/dev.latchway/{module}@{version}"
            for module in (
                "latchway-core", "latchway-okhttp", "latchway-play-integrity",
                "latchway-firebase-auth", "latchway-bom",
            )
        )
        intent = {
            "schema": "latchway.maven-central-upload-intent.v2",
            "repository": "Latchway/latchway-android",
            "source_commit": "b" * 40,
            "release_tag": "v1.0.0",
            "version": version,
            "namespace": "dev.latchway",
            "deployment_name": deployment_name,
            "publishing_type": "user_managed",
            "authorization": "recoverable_exact_upload",
            "reviewed_repository_archive_sha256": hashlib.sha256(archive).hexdigest(),
            "reviewed_portal_bundle_sha256": hashlib.sha256(portal).hexdigest(),
            "reviewed_repository_manifest_sha256": "d" * 64,
            "reviewed_repository_file_count": 120,
            "reviewed_portal_bundle_file_count": 144,
            "reviewed_public_key_sha256": hashlib.sha256(key).hexdigest(),
            "expected_purls": purls,
        }
        intent_bytes = (json.dumps(intent, indent=2, sort_keys=True) + "\n").encode()
        deployment = {
            "schema": "latchway.maven-central-deployment.v2",
            "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
            "deployment_name": deployment_name,
            "publishing_type": "user_managed",
            "namespace": "dev.latchway",
            "version": version,
            "source_commit": "b" * 40,
            "expected_purls": purls,
            "reviewed_portal_bundle_sha256": portal_sha,
            "record_kind": "portal_deployment",
            "deployment_id": "38570f16-da32-4c14-bd2e-c1acc0782365",
            "public_manifest_sha256": None,
        }
        deployment_bytes = (json.dumps(deployment, indent=2, sort_keys=True) + "\n").encode()
        status = {
            "schema": "latchway.maven-central-deployment-status.v2",
            "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
            "record_sha256": hashlib.sha256(deployment_bytes).hexdigest(),
            "record_kind": "portal_deployment",
            "deployment_id": deployment["deployment_id"],
            "deployment_name": deployment_name,
            "deployment_state": "PUBLISHED",
            "purls": purls,
            "public_manifest_sha256": None,
        }
        status_bytes = (json.dumps(status, indent=2, sort_keys=True) + "\n").encode()
        files = []
        public_manifest = []
        checksum_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
        signature_bytes = signature.encode("ascii")
        signature_sha256 = hashlib.sha256(signature_bytes).hexdigest()
        for path in sorted(MODULE.expected_maven_paths(version)):
            artifact_bytes = path.encode("utf-8")
            artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            checksums = []
            for algorithm, length in checksum_lengths.items():
                published_digest = hashlib.sha512(
                    f"{algorithm}:{path}".encode()
                ).hexdigest()[:length]
                checksum_bytes = f"{published_digest}\n".encode("ascii")
                checksums.append(
                    {
                        "algorithm": algorithm,
                        "path": f"{path}.{algorithm}",
                        "bytes": len(checksum_bytes),
                        "sha256": hashlib.sha256(checksum_bytes).hexdigest(),
                        "published_digest": published_digest,
                    }
                )
            files.append(
                {
                    "path": path,
                    "sha256": artifact_sha256,
                    "bytes": len(artifact_bytes),
                    "signature_sha256": signature_sha256,
                    "signature_bytes": len(signature_bytes),
                    "signature_armored": signature,
                    "gpg_status": {
                        "schema_version": 1,
                        "primary_fingerprint": "A" * 40,
                        "signing_fingerprint": "A" * 40,
                        "public_key_algorithm": "1",
                        "hash_algorithm": "10",
                        "status_lines": ["[GNUPG:] VALIDSIG test"],
                    },
                    "checksums": checksums,
                    "checksums_byte_identical": True,
                }
            )
            public_manifest.extend(
                [
                    {
                        "path": path,
                        "bytes": len(artifact_bytes),
                        "sha256": artifact_sha256,
                    },
                    {
                        "path": f"{path}.asc",
                        "bytes": len(signature_bytes),
                        "sha256": signature_sha256,
                    },
                    *(
                        {
                            "path": checksum["path"],
                            "bytes": checksum["bytes"],
                            "sha256": checksum["sha256"],
                        }
                        for checksum in checksums
                    ),
                ]
            )
        public_manifest.sort(key=lambda item: item["path"])
        proof = {
            "schema_version": 2,
            "registry": "maven_central",
            "namespace": "dev.latchway",
            "version": version,
            "reviewed_repository": True,
            "primary_artifacts_byte_identical": True,
            "checksum_files_byte_identical": True,
            "signature_files_present": True,
            "signatures_cryptographically_verified": True,
            "signing_fingerprint": "A" * 40,
            "reviewed_public_key_sha256": hashlib.sha256(key).hexdigest(),
            "deployment": {
                "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
                "record_sha256": hashlib.sha256(deployment_bytes).hexdigest(),
                "status_sha256": hashlib.sha256(status_bytes).hexdigest(),
                "record_kind": "portal_deployment",
                "record": deployment,
                "status": status,
            },
            "public_manifest": public_manifest,
            "public_manifest_sha256": hashlib.sha256(
                (json.dumps(public_manifest, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "files": files,
        }
        original = copy.deepcopy(proof)
        proof_bytes = (json.dumps(original, indent=2, sort_keys=True) + "\n").encode()
        tag_binding = {
            "schema": "latchway.github-release-tag-binding.v1",
            "tag": "v1.0.0",
            "tag_object_sha": "d" * 40,
            "commit": "b" * 40,
            "message_sha256": "e" * 64,
        }
        payloads = {
            "latchway-android-1.0.0-maven-repository.zip": archive,
            "latchway-android-1.0.0-central-portal.zip": portal,
            "docs-bundle-1.0.0.tar.gz": b"documentation bundle",
            "github-release-tag-binding.json": (
                json.dumps(tag_binding, indent=2, sort_keys=True) + "\n"
            ).encode(),
            "latchway-maven-signing-public-key.asc": key,
            "maven-central-upload-intent.json": intent_bytes,
            "maven-central-deployment.json": deployment_bytes,
            "maven-central-deployment-status.json": status_bytes,
            "maven-central-release-evidence.json": proof_bytes,
        }
        sums = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(payloads.items())
        ).encode()
        payloads["SHA256SUMS"] = sums
        retained = {}
        for name, payload in payloads.items():
            digest = hashlib.sha256(payload).hexdigest()
            retained[name] = {
                "name": name, "bytes": len(payload), "sha256": digest,
                "release_digest": "sha256:" + digest,
                "content_base64": base64.b64encode(payload).decode(),
            }
        proof.update(
            release_asset_attestation_verification=[{"verificationResult": "verified"}],
            release_asset_source_attestations={name: [{"verified": True}] for name in retained},
            immutable_release_asset_verifications={name: {"verified": True} for name in retained},
            retained_release_assets=retained,
            independent_live_verification=original,
            compatibility={"minimum_android_api": 23},
        )
        return proof

    def test_npm_requires_exact_release_asset_names_and_tarball_digest(self) -> None:
        for package in ("@latchway/client", "@latchway/react-native"):
            expected, _ = MODULE.expected_npm_release_assets(package, "1.0.0")
            self.assertIn("docs-bundle-1.0.0.tar.gz", expected)
        proof = self.npm_proof()
        coordinate = {
            "version": "1.0.0",
            "commit": "b" * 40,
            "tag": "v1.0.0",
        }
        MODULE.validate_npm(proof, "@latchway/client", coordinate)
        for mutation in ("extra", "missing-docs", "wrong-tarball-digest", "missing-provenance", "wrong-provenance-source", "failed-adoption", "mislabelled-adoption", "changed-retained-attestations"):
            tampered = copy.deepcopy(proof)
            if mutation == "extra":
                tampered["release_asset_digests"]["unreviewed.json"] = "sha256:" + "f" * 64
            elif mutation == "missing-docs":
                tampered["release_asset_digests"].pop("docs-bundle-1.0.0.tar.gz")
                tampered["release_asset_attestation_verifications"].pop(
                    "docs-bundle-1.0.0.tar.gz"
                )
            else:
                if mutation == "wrong-tarball-digest":
                    tampered["release_asset_digests"]["latchway-client-1.0.0.tgz"] = "sha256:" + "f" * 64
                elif mutation == "missing-provenance":
                    tampered.pop("provenance")
                else:
                    if mutation == "wrong-provenance-source":
                        tampered["provenance"]["source_commit"] = "0" * 40
                    elif mutation == "failed-adoption":
                        tampered["adoptions"][0]["authenticated_run"]["conclusion"] = "failure"
                    elif mutation == "mislabelled-adoption":
                        item = tampered["adoptions"][0]
                        item["record"]["adoption"]["mode"] = "published"
                        payload = (
                            json.dumps(item["record"], indent=2, sort_keys=True)
                            + "\n"
                        ).encode()
                        name = item["asset"]["name"]
                        sha256 = hashlib.sha256(payload).hexdigest()
                        item["asset"] = {
                            "name": name,
                            "bytes": len(payload),
                            "sha256": sha256,
                            "release_digest": f"sha256:{sha256}",
                            "content_base64": base64.b64encode(payload).decode(),
                        }
                        tampered["release_asset_set"][name] = {
                            "name": name,
                            "size": len(payload),
                            "digest": f"sha256:{sha256}",
                        }
                    else:
                        tampered["independent_live_registry_evidence"]["npm_attestations"]["sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ProofError):
                MODULE.validate_npm(tampered, "@latchway/client", coordinate)

    def test_javascript_package_set_rejects_package_asset_and_adoption_mutations(self) -> None:
        proof, coordinate, retained_tarballs = self.javascript_npm_set_proof()
        MODULE.validate_javascript_npm_set(
            proof,
            coordinate,
            self.javascript_contract_authority(),
            retained_tarballs,
        )
        maximum_tarball = max(map(len, retained_tarballs.values()))
        with mock.patch.object(
            MODULE,
            "MAXIMUM_RETAINED_NPM_TARBALL_BYTES",
            maximum_tarball,
        ):
            MODULE.validate_javascript_npm_set(
                proof,
                coordinate,
                self.javascript_contract_authority(),
                retained_tarballs,
            )
        with (
            mock.patch.object(
                MODULE,
                "MAXIMUM_RETAINED_NPM_TARBALL_BYTES",
                maximum_tarball - 1,
            ),
            self.assertRaisesRegex(
                MODULE.ProofError,
                "npm_reproducibility_retained_tarballs_invalid",
            ),
        ):
            MODULE.validate_javascript_npm_set(
                proof,
                coordinate,
                self.javascript_contract_authority(),
                retained_tarballs,
            )
        mutations: list[tuple[str, dict]] = []

        def rebind_aggregate(changed: dict, name: str) -> None:
            payload = (
                json.dumps(
                    changed["reviewed_aggregate_evidence"][name],
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            sha256 = hashlib.sha256(payload).hexdigest()
            changed["retained_aggregate_evidence"][name] = {
                "name": name,
                "bytes": len(payload),
                "sha256": sha256,
                "release_digest": f"sha256:{sha256}",
                "content_base64": base64.b64encode(payload).decode(),
            }
            changed["release_asset_set"][name] = {
                "name": name,
                "size": len(payload),
                "digest": f"sha256:{sha256}",
            }

        def rebind_retained_bytes(changed: dict, name: str, payload: bytes) -> None:
            sha256 = hashlib.sha256(payload).hexdigest()
            changed["retained_aggregate_evidence"][name] = {
                "name": name,
                "bytes": len(payload),
                "sha256": sha256,
                "release_digest": f"sha256:{sha256}",
                "content_base64": base64.b64encode(payload).decode(),
            }
            changed["release_asset_set"][name] = {
                "name": name,
                "size": len(payload),
                "digest": f"sha256:{sha256}",
            }

        missing_package = copy.deepcopy(proof)
        missing_package["packages"].pop(2)
        mutations.append(("missing-package", missing_package))

        substituted_package = copy.deepcopy(proof)
        substituted_package["publish_order"][1] = "@latchway/substituted"
        mutations.append(("substituted-package", substituted_package))

        reordered_package = copy.deepcopy(proof)
        reordered_package["packages"][1], reordered_package["packages"][2] = (
            reordered_package["packages"][2],
            reordered_package["packages"][1],
        )
        mutations.append(("reordered-package", reordered_package))

        substituted_tarball_url = copy.deepcopy(proof)
        substituted_tarball_url["packages"][0]["registry_tarball_url"] = (
            "https://registry.npmjs.org/@latchway/client/-/substituted.tgz"
        )
        mutations.append(("substituted-tarball-url", substituted_tarball_url))

        substituted_certificate = copy.deepcopy(proof)
        substituted_certificate["packages"][0]["provenance"][
            "certificate_identity"
        ] = "URI:https://example.test/untrusted.yml@refs/heads/main"
        mutations.append(("substituted-certificate", substituted_certificate))

        for package_id, _ in MODULE.JAVASCRIPT_NPM_PACKAGES:
            for asset in (
                f"latchway-{package_id}-1.0.0.tgz",
                f"npm-{package_id}-registry-version.json",
                f"npm-{package_id}-registry-view.json",
                f"npm-{package_id}-attestations.json",
                f"npm-{package_id}-audit-signatures.json",
            ):
                missing_asset = copy.deepcopy(proof)
                missing_asset["release_asset_set"].pop(asset)
                mutations.append((f"missing-{asset}", missing_asset))

        for aggregate_name in proof["retained_aggregate_evidence"]:
            missing_aggregate = copy.deepcopy(proof)
            missing_aggregate["retained_aggregate_evidence"].pop(aggregate_name)
            mutations.append((f"missing-aggregate-{aggregate_name}", missing_aggregate))

        wrong_schema = copy.deepcopy(proof)
        wrong_schema["reviewed_aggregate_evidence"]["post-publish-evidence.json"][
            "schema_version"
        ] = 2
        mutations.append(("wrong-aggregate-schema", wrong_schema))

        retry_variant_fixed_evidence = copy.deepcopy(proof)
        retry_variant_fixed_evidence["reviewed_aggregate_evidence"][
            "post-publish-evidence.json"
        ]["packages"][0]["publication_mode"] = "adopted_existing"
        rebind_aggregate(
            retry_variant_fixed_evidence, "post-publish-evidence.json"
        )
        mutations.append(("retry-variant-fixed-evidence", retry_variant_fixed_evidence))

        fully_rebound_arbitrary_reproducibility_hash = copy.deepcopy(proof)
        fully_rebound_arbitrary_reproducibility_hash[
            "reviewed_aggregate_evidence"
        ]["build-reproducibility.json"]["sha256"] = "f" * 64
        fully_rebound_arbitrary_reproducibility_hash[
            "reproducibility_archive_verification"
        ]["sha256"] = "f" * 64
        rebind_aggregate(
            fully_rebound_arbitrary_reproducibility_hash,
            "build-reproducibility.json",
        )
        mutations.append(
            (
                "fully-rebound-arbitrary-reproducibility-hash",
                fully_rebound_arbitrary_reproducibility_hash,
            )
        )

        false_source_rebuild_claim = copy.deepcopy(proof)
        false_source_rebuild_claim["reproducibility_archive_verification"][
            "independent_source_rebuild_performed"
        ] = True
        mutations.append(("false-independent-source-rebuild-claim", false_source_rebuild_claim))

        failed_vulnerability = copy.deepcopy(proof)
        failed_vulnerability["reviewed_aggregate_evidence"][
            "dependency-vulnerability-scan.json"
        ]["status"] = "failed"
        rebind_aggregate(
            failed_vulnerability, "dependency-vulnerability-scan.json"
        )
        mutations.append(("fully-rebound-failed-vulnerability", failed_vulnerability))

        unannotated_tag = copy.deepcopy(proof)
        unannotated_tag["reviewed_aggregate_evidence"]["tag-evidence.json"][
            "annotated"
        ] = False
        rebind_aggregate(unannotated_tag, "tag-evidence.json")
        mutations.append(("fully-rebound-unannotated-tag", unannotated_tag))

        changed_contract = copy.deepcopy(proof)
        changed_contract["reviewed_aggregate_evidence"]["contract-evidence.json"][
            "bundle_sha256"
        ] = "0" * 64
        changed_contract["contract_source_verification"]["bundle_sha256"] = "0" * 64
        rebind_aggregate(changed_contract, "contract-evidence.json")
        mutations.append(("fully-rebound-contract-drift", changed_contract))

        changed_checksums = copy.deepcopy(proof)
        first = changed_checksums["reviewed_aggregate_evidence"][
            "package-evidence.json"
        ]["packages"][0]
        checksum_payload = (
            f"{'0' * 64}  {first['tarball']}\n"
        ).encode("ascii")
        rebind_retained_bytes(changed_checksums, "SHA256SUMS", checksum_payload)
        changed_checksums["reviewed_aggregate_evidence"][
            "publish-input-evidence.json"
        ]["checksums"]["sha256"] = hashlib.sha256(checksum_payload).hexdigest()
        rebind_aggregate(changed_checksums, "publish-input-evidence.json")
        changed_checksums["checksum_verification"]["file_sha256"] = hashlib.sha256(
            checksum_payload
        ).hexdigest()
        changed_checksums["checksum_verification"]["entries"][0]["sha256"] = (
            "0" * 64
        )
        mutations.append(("fully-rebound-wrong-checksums", changed_checksums))

        missing_sha1 = copy.deepcopy(proof)
        missing_sha1["packages"][0].pop("sha1")
        mutations.append(("missing-recomputed-sha1", missing_sha1))

        def rebind_adoption_mode(changed: dict, mode: object) -> None:
            item = changed["packages"][0]["adoptions"][0]
            item["record"]["adoption"]["mode"] = mode
            name = item["asset"]["name"]
            payload = (
                json.dumps(item["record"], indent=2, sort_keys=True) + "\n"
            ).encode()
            sha256 = hashlib.sha256(payload).hexdigest()
            item["asset"] = {
                "name": name,
                "bytes": len(payload),
                "sha256": sha256,
                "release_digest": f"sha256:{sha256}",
                "content_base64": base64.b64encode(payload).decode(),
            }
            changed["release_asset_set"][name] = {
                "name": name,
                "size": len(payload),
                "digest": f"sha256:{sha256}",
            }

        retry_mislabelled_published = copy.deepcopy(proof)
        rebind_adoption_mode(retry_mislabelled_published, "published")
        mutations.append(
            ("retry-mislabelled-published", retry_mislabelled_published)
        )

        malformed_adoption_mode = copy.deepcopy(proof)
        rebind_adoption_mode(malformed_adoption_mode, {"published": True})
        mutations.append(("malformed-adoption-mode", malformed_adoption_mode))

        reordered_reproducibility = copy.deepcopy(proof)
        rows = reordered_reproducibility["reviewed_aggregate_evidence"][
            "build-reproducibility.json"
        ]["files"]
        rows[0], rows[1] = rows[1], rows[0]
        rebind_aggregate(
            reordered_reproducibility, "build-reproducibility.json"
        )
        mutations.append(("reordered-reproducibility", reordered_reproducibility))

        for package_index, (package_id, _) in enumerate(
            MODULE.JAVASCRIPT_NPM_PACKAGES
        ):
            missing_adoption_id = copy.deepcopy(proof)
            adoption = next(
                name
                for name in missing_adoption_id["release_asset_set"]
                if name.startswith(f"npm-release-adoption-{package_id}-")
            )
            for field in (
                "release_asset_set",
                "immutable_release_asset_verifications",
                "release_asset_attestation_verifications",
            ):
                missing_adoption_id[field].pop(adoption)
            missing_adoption_id["packages"][package_index]["adoptions"].clear()
            mutations.append(
                (f"missing-adoption-id-{package_id}", missing_adoption_id)
            )

        for name, tampered in mutations:
            with self.subTest(name=name), self.assertRaises(MODULE.ProofError):
                MODULE.validate_javascript_npm_set(
                    tampered,
                    coordinate,
                    self.javascript_contract_authority(),
                    retained_tarballs,
                )

    def test_final_verifier_loads_exact_four_manifest_bound_tarball_artifacts(self) -> None:
        version = "1.0.0"
        with tempfile.TemporaryDirectory(prefix="latchway-js-tarballs-") as raw:
            root = Path(raw)
            artifacts = []
            manifest_hashes = {}
            expected = {}
            for package_id, _ in MODULE.JAVASCRIPT_NPM_PACKAGES:
                name = f"latchway-{package_id}-{version}.tgz"
                relative = (
                    "artifacts/public-registries/"
                    "artifacts--registry-npm-javascript--" + name
                )
                payload = f"fixture:{package_id}".encode()
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                sha256 = hashlib.sha256(payload).hexdigest()
                artifacts.append({"path": relative, "sha256": sha256})
                manifest_hashes[relative] = sha256
                expected[name] = payload
            document = {"artifacts": artifacts}
            self.assertEqual(
                MODULE.load_javascript_retained_tarballs(
                    root, document, manifest_hashes, version
                ),
                expected,
            )
            for mutation in ("missing", "extra", "wrong-manifest-hash"):
                changed_document = copy.deepcopy(document)
                changed_hashes = dict(manifest_hashes)
                if mutation == "missing":
                    changed_document["artifacts"].pop()
                elif mutation == "extra":
                    changed_document["artifacts"].append(
                        {
                            "path": (
                                "artifacts/public-registries/"
                                "artifacts--registry-npm-javascript--"
                                "latchway-extra-1.0.0.tgz"
                            ),
                            "sha256": "0" * 64,
                        }
                    )
                else:
                    changed_hashes[artifacts[0]["path"]] = "0" * 64
                with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    MODULE.ProofError,
                    "npm_reproducibility_retained_tarballs_invalid",
                ):
                    MODULE.load_javascript_retained_tarballs(
                        root, changed_document, changed_hashes, version
                    )

    def test_javascript_adoption_mode_is_exactly_bound_to_origin_attempt(self) -> None:
        valid = MODULE.valid_npm_adoption_mode
        self.assertTrue(valid("published", 101, 1, 101, 1))
        self.assertTrue(valid("adopted_existing", 201, 2, 101, 1))
        for mode, run_id, run_attempt, origin_id, origin_attempt in (
            ("published", 201, 2, 101, 1),
            ("adopted_existing", 101, 1, 101, 1),
            ("unexpected", 201, 2, 101, 1),
            ({"published": True}, 101, 1, 101, 1),
        ):
            with self.subTest(mode=mode):
                self.assertFalse(
                    valid(mode, run_id, run_attempt, origin_id, origin_attempt)
                )

    def test_javascript_contract_authority_is_derived_from_source_checks(self) -> None:
        source = {
            "contract": {
                "version": "1.0.0",
                "core_release": "v1.0.0",
                "bundle_sha256": "d" * 64,
                "wire_protocol": 2,
            },
            "document": {
                "checks": [
                    {
                        "id": "source.contract_locks",
                        "details": {
                            "lock_count": 4,
                            "core_release": "v1.0.0",
                            "contract_source_commit": "c" * 40,
                            "minimum_server_version": "1.0.0",
                            "maximum_tested_server_version": "1.0.x",
                        },
                    },
                    {
                        "id": "source.generated_fixtures",
                        "details": {
                            "fixture_count_per_sdk": 1,
                            "sdk_count": 4,
                            "fixture_sha256": {
                                "protocol-version.json": "f" * 64
                            },
                        },
                    },
                ]
            },
        }
        self.assertEqual(
            MODULE.javascript_contract_authority(source),
            self.javascript_contract_authority(),
        )
        for name, changed in (
            (
                "duplicate-lock-check",
                {
                    **copy.deepcopy(source),
                    "document": {
                        "checks": copy.deepcopy(source["document"]["checks"])
                        + [copy.deepcopy(source["document"]["checks"][0])]
                    },
                },
            ),
            (
                "invalid-fixture-hash",
                copy.deepcopy(source),
            ),
        ):
            if name == "invalid-fixture-hash":
                changed["document"]["checks"][1]["details"]["fixture_sha256"][
                    "protocol-version.json"
                ] = "not-a-hash"
            with self.subTest(name=name), self.assertRaisesRegex(
                MODULE.ProofError, "npm_contract_source_authority_invalid"
            ):
                MODULE.javascript_contract_authority(changed)

    def test_maven_requires_exact_unique_coordinates_and_pinned_signature(self) -> None:
        proof = self.maven_proof()
        coordinate = {"version": "1.0.0", "commit": "b" * 40, "tag": "v1.0.0"}
        MODULE.validate_maven(proof, coordinate)
        mutations = []
        duplicate = copy.deepcopy(proof)
        duplicate["files"][-1]["path"] = duplicate["files"][0]["path"]
        mutations.append(duplicate)
        unrelated = copy.deepcopy(proof)
        unrelated["files"][-1]["path"] = "other/1.0.0/other-1.0.0.jar"
        mutations.append(unrelated)
        unsigned = copy.deepcopy(proof)
        unsigned["signatures_cryptographically_verified"] = False
        mutations.append(unsigned)
        wrong_key = copy.deepcopy(proof)
        wrong_key["signing_fingerprint"] = "not-a-fingerprint"
        mutations.append(wrong_key)
        extra_file_field = copy.deepcopy(proof)
        extra_file_field["files"][0]["unreviewed"] = True
        mutations.append(extra_file_field)
        missing_checksum_field = copy.deepcopy(proof)
        missing_checksum_field["files"][0]["checksums"][0].pop("published_digest")
        mutations.append(missing_checksum_field)
        extra_gpg_field = copy.deepcopy(proof)
        extra_gpg_field["files"][0]["gpg_status"]["unreviewed"] = True
        mutations.append(extra_gpg_field)
        manifest_substitution = copy.deepcopy(proof)
        manifest_substitution["public_manifest"][0]["bytes"] += 1
        mutations.append(manifest_substitution)
        extra_deployment_field = copy.deepcopy(proof)
        extra_deployment_field["deployment"]["unreviewed"] = True
        mutations.append(extra_deployment_field)
        missing_docs_bundle = copy.deepcopy(proof)
        for field in (
            "release_asset_source_attestations",
            "immutable_release_asset_verifications",
            "retained_release_assets",
        ):
            missing_docs_bundle[field].pop("docs-bundle-1.0.0.tar.gz")
        mutations.append(missing_docs_bundle)
        for index, tampered in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.ProofError):
                MODULE.validate_maven(tampered, coordinate)

    def test_rn_dependency_evidence_binds_every_exact_sdk_release(self) -> None:
        evidence, repositories = self.rn_dependency_evidence()
        MODULE.validate_rn_published_dependencies(evidence, repositories)
        mutations = []
        missing_android_asset = copy.deepcopy(evidence)
        missing_android_asset["dependencies"]["android"]["release_assets"].pop(
            "latchway-android-1.0.0-central-portal.zip"
        )
        mutations.append(missing_android_asset)
        missing_docs_bundle = copy.deepcopy(evidence)
        missing_docs_bundle["dependencies"]["ios"]["release_assets"].pop(
            "docs-bundle-1.0.0.tar.gz"
        )
        mutations.append(missing_docs_bundle)
        wrong_js_commit = copy.deepcopy(evidence)
        wrong_js_commit["dependencies"]["javascript"]["source_commit"] = "0" * 40
        mutations.append(wrong_js_commit)
        unattested = copy.deepcopy(evidence)
        unattested["dependencies"]["ios"]["release_assets"][
            "cocoapods-release-evidence.json"
        ]["immutable_attestation"] = {}
        mutations.append(unattested)
        for tampered in mutations:
            with self.assertRaisesRegex(MODULE.ProofError, "rn_dependency_evidence_invalid"):
                MODULE.validate_rn_published_dependencies(tampered, repositories)

    def test_oci_proof_binds_version_and_all_moving_aliases(self) -> None:
        digest = "sha256:" + "9" * 64
        coordinate = {"version": "1.1.0", "commit": "a" * 40}
        tags = ("1.1.0", "1.1", "1", "latest")
        proof = {
            "schema_version": 1,
            "registry": "ghcr",
            "repository": "ghcr.io/latchway/latchway",
            "version": "1.1.0",
            "source_commit": "a" * 40,
            "index_digest": digest,
            "immutable_version_reference": "ghcr.io/latchway/latchway:1.1.0",
            "moving_aliases": ["1.1", "1", "latest"],
            "references": {
                tag: {"reference": f"ghcr.io/latchway/latchway:{tag}", "digest": digest}
                for tag in tags
            },
            "signature_verification": [{
                "critical": {
                    "identity": {"docker-reference": "ghcr.io/latchway/latchway"},
                    "image": {"docker-manifest-digest": digest},
                }
            }],
        }
        MODULE.validate_oci(proof, coordinate)
        for tag in tags:
            tampered = copy.deepcopy(proof)
            tampered["references"][tag]["digest"] = "sha256:" + "8" * 64
            with self.subTest(tag=tag), self.assertRaisesRegex(
                MODULE.ProofError, "oci_alias_proof_invalid"
            ):
                MODULE.validate_oci(tampered, coordinate)


if __name__ == "__main__":
    unittest.main()
