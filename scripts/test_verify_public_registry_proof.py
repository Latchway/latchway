from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


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
        js_assets = js_fixed | {"npm-release-adoption-99-2.json"}
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
        for mutation in ("extra", "missing-docs", "wrong-tarball-digest", "missing-provenance", "wrong-provenance-source", "failed-adoption", "changed-retained-attestations"):
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
                    else:
                        tampered["independent_live_registry_evidence"]["npm_attestations"]["sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ProofError):
                MODULE.validate_npm(tampered, "@latchway/client", coordinate)

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
