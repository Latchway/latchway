#!/usr/bin/env python3

from copy import deepcopy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/github-release-controls.py"
MANIFEST = ROOT / ".github/release-controls.json"
SCHEMA = ROOT / ".github/release-controls.schema.json"
FIXTURE = (
    ROOT
    / "scripts/testdata/github-release-controls/compliant-latchway.json"
)

SPEC = spec_from_file_location("github_release_controls", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONTROLS = module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTROLS
SPEC.loader.exec_module(CONTROLS)


class FixtureGitHub:
    def __init__(self, manifest, fixture):
        self.manifest = manifest
        self.fixture = fixture
        self.missing_environment = None
        self.variable_mode = "exact"
        self.broader_variable_scope = None
        self.broader_variable_name = CONTROLS.POLICY_VARIABLE_NAME
        self.broader_variable_visibility = "all"
        self.selected_variable_repositories = []
        self.broader_secret_scope = None
        self.broader_secret_name = "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        self.broader_secret_visibility = "all"
        self.selected_secret_repositories = []
        self.environment_secret_name = None
        self.missing_environment_secret_name = None
        self.missing_environment_variable_name = None
        self.human_ruleset_bypass = False
        self.ruleset_mode = "exact"
        self.branch_mode = "exact"
        self.branch_policy_mode = "exact"
        self.reviewer_mode = "exact"
        self.admins_can_bypass = False
        self.authenticated_actor_id = 999
        self.calls = []
        repository = next(
            item
            for item in manifest["repositories"]
            if item["name"] == fixture["repository"]["name"]
        )
        self.repository = repository
        self.environments = {
            item["name"]: item for item in repository["environments"]
        }
        self.rulesets = {
            item["name"]: item for item in repository["rulesets"]
        }

    def _environment_name(self, path):
        marker = "/environments/"
        if marker not in path:
            return None
        suffix = path.split(marker, 1)[1]
        return suffix.split("/", 1)[0]

    def get(self, path):
        if path == "/apps/github-actions":
            return deepcopy(self.fixture["app"])
        if path == "/users/tiepvuvan":
            return deepcopy(self.fixture["reviewer"])
        if path == "/user":
            return {
                "id": self.authenticated_actor_id,
                "login": "release-operator",
            }
        if path == "/repos/Latchway/latchway":
            return deepcopy(self.fixture["repository"])
        environment = self._environment_name(path)
        if environment is not None and "/rulesets/" not in path:
            if environment == self.missing_environment:
                raise CONTROLS.NotFound("github_resource_not_found")
            desired_environment = self.environments[environment]
            profile_administration = CONTROLS.is_single_maintainer_administration(
                self.fixture["repository"]["name"], desired_environment
            )
            return {
                "can_admins_bypass": self.admins_can_bypass,
                "deployment_branch_policy": (
                    {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    }
                    if self.branch_mode == "exact"
                    else {
                        "protected_branches": True,
                        "custom_branch_policies": False,
                    }
                ),
                "protection_rules": (
                    []
                    if profile_administration
                    else [
                        {
                            "type": "required_reviewers",
                            "prevent_self_review": True,
                            "reviewers": (
                                []
                                if self.reviewer_mode == "missing"
                                else [
                                    {
                                        "type": "User",
                                        "reviewer": {
                                            "id": self.fixture["reviewer"]["id"]
                                        },
                                    }
                                ]
                            ),
                        }
                    ]
                ),
            }
        if path.startswith("/repos/Latchway/latchway/rulesets/"):
            identifier = int(path.rsplit("/", 1)[1])
            name = self.fixture["rulesets"][identifier - 1]
            ruleset = deepcopy(self.rulesets[name])
            ruleset["id"] = identifier
            if (
                self.ruleset_mode == "incomplete"
                and name == "latchway-main-protected"
            ):
                ruleset["rules"] = ruleset["rules"][:-1]
            if (
                self.ruleset_mode == "disabled"
                and name == "latchway-main-protected"
            ):
                ruleset["enforcement"] = "disabled"
            if (
                self.ruleset_mode == "duplicate"
                and name == "latchway-main-protected"
            ):
                ruleset["rules"].append(deepcopy(ruleset["rules"][0]))
            if self.human_ruleset_bypass and name == "latchway-v1-tags-immutable":
                ruleset["bypass_actors"].append(
                    {
                        "actor_id": 5,
                        "actor_type": "OrganizationAdmin",
                        "bypass_mode": "always",
                    }
                )
            if (
                self.ruleset_mode == "unobservable_bypass"
                and name == "latchway-main-protected"
            ):
                del ruleset["bypass_actors"]
            return ruleset
        raise AssertionError(f"unexpected GET {path}")

    def collection(self, path, key=None):
        if path in {
            "/orgs/Latchway/actions/variables",
            "/repos/Latchway/latchway/actions/variables",
        }:
            if (
                self.broader_variable_scope == "organization"
                and path.startswith("/orgs/")
            ) or (
                self.broader_variable_scope == "repository"
                and path.startswith("/repos/")
            ):
                return [
                    {
                        "name": self.broader_variable_name,
                        "value": "fallback",
                        "visibility": self.broader_variable_visibility,
                    }
                ]
            return []
        if "/actions/variables/" in path and path.endswith("/repositories"):
            return [
                {"full_name": full_name}
                for full_name in self.selected_variable_repositories
            ]
        if path in {
            "/orgs/Latchway/actions/secrets",
            "/repos/Latchway/latchway/actions/secrets",
        }:
            if (
                self.broader_secret_scope == "organization"
                and path.startswith("/orgs/")
            ) or (
                self.broader_secret_scope == "repository"
                and path.startswith("/repos/")
            ):
                return [
                    {
                        "name": self.broader_secret_name,
                        "visibility": self.broader_secret_visibility,
                    }
                ]
            return []
        if "/actions/secrets/" in path and path.endswith("/repositories"):
            return [
                {"full_name": full_name}
                for full_name in self.selected_secret_repositories
            ]
        if path.endswith("/commits/main/check-runs"):
            return [
                {
                    "name": context,
                    "app": deepcopy(self.fixture["app"]),
                }
                for context in self.fixture["status_contexts"]
            ]
        if path.endswith("/deployment-branch-policies"):
            if self.branch_policy_mode == "malformed":
                return [{"name": "main", "type": "branch"}, "malformed"]
            return (
                []
                if self.branch_policy_mode == "missing"
                else [{"name": "main", "type": "branch"}]
            )
        if path.endswith("/variables"):
            environment = self._environment_name(path)
            desired = self.environments[environment]["policy_id"]
            if self.variable_mode == "wrong":
                desired = "latchway-release-controls-v1:wrong:environment"
            elif self.variable_mode == "quarantined":
                desired += CONTROLS.QUARANTINE_SUFFIX
            result = []
            if self.variable_mode != "missing":
                result.append(
                    {
                        "name": CONTROLS.environment_policy_variable_name(
                            self.fixture["repository"]["name"],
                            self.environments[environment],
                        ),
                        "value": desired,
                    }
                )
            result.extend(
                {"name": name, "value": "configured"}
                for name in self.environments[environment].get(
                    "variables", {"required_names": []}
                )["required_names"]
                if name != self.missing_environment_variable_name
            )
            if self.variable_mode == "unknown":
                result.append({"name": "UNMANAGED", "value": "present"})
            return result
        if path.endswith("/secrets"):
            if self.environment_secret_name is not None:
                return [{"name": self.environment_secret_name}]
            environment = self._environment_name(path)
            return [
                {"name": name}
                for name in self.environments[environment]["secrets"][
                    "required_names"
                ]
                if name != self.missing_environment_secret_name
            ]
        if "/rulesets?includes_parents=false" in path:
            summaries = [
                {"id": index, "name": name}
                for index, name in enumerate(self.fixture["rulesets"], start=1)
                if not (
                    self.ruleset_mode == "missing"
                    and name == "latchway-main-protected"
                )
            ]
            if self.ruleset_mode == "duplicate_identity":
                summaries.append(
                    {
                        "id": len(summaries) + 1,
                        "name": "latchway-main-protected",
                    }
                )
            return summaries
        raise AssertionError(f"unexpected collection {path} ({key})")

    def put(self, path, body):
        self.calls.append(("PUT", path, deepcopy(body)))

    def post(self, path, body):
        self.calls.append(("POST", path, deepcopy(body)))

    def patch(self, path, body):
        self.calls.append(("PATCH", path, deepcopy(body)))


class MultiRepositoryFixtureGitHub(FixtureGitHub):
    """Exercise repository iteration while reusing the compact core fixture."""

    def __init__(self, manifest, fixture):
        super().__init__(manifest, fixture)
        self.observed_paths = []

    def _core_fixture_path(self, path):
        return path.replace(
            "/repos/Latchway/latchway-js",
            "/repos/Latchway/latchway",
        )

    def get(self, path):
        self.observed_paths.append(path)
        return super().get(self._core_fixture_path(path))

    def collection(self, path, key=None):
        self.observed_paths.append(path)
        return super().collection(self._core_fixture_path(path), key)


class StubGitHub(CONTROLS.GitHubAPI):
    def __init__(self, responses):
        super().__init__("not-a-real-token", "2026-03-10", "http://localhost")
        self.responses = list(responses)

    def request(self, method, path_or_url, body=None):
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)


class GitHubReleaseControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.manifest_sha = CONTROLS.load_manifest(MANIFEST)
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.reviewers = [CONTROLS.ResolvedReviewer("User", 101, "user:tiepvuvan")]

    def inspect(self, client):
        return CONTROLS.inspect_github(
            client, self.manifest, self.reviewers, {"latchway"}
        )

    def test_manifest_has_exact_unique_policy_ids_and_publication_tuples(self):
        self.assertEqual(
            self.manifest["policy_variable_name"],
            CONTROLS.POLICY_VARIABLE_NAME,
        )
        self.assertEqual(
            self.manifest["protected_secret_scope"], "environment_only"
        )
        self.assertEqual(
            self.manifest["forbidden_secret_names"],
            ["LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN"],
        )
        policy_ids = []
        profile_administration_environments = []
        environment_counts = {}
        for repository in self.manifest["repositories"]:
            environment_counts[repository["name"]] = len(repository["environments"])
            for environment in repository["environments"]:
                expected = (
                    CONTROLS.single_maintainer_administration_policy_id(
                        repository["name"]
                    )
                    if CONTROLS.is_single_maintainer_administration(
                        repository["name"], environment
                    )
                    else (
                        f"{self.manifest['control_id']}:{repository['name']}:"
                        f"{environment['name']}"
                    )
                )
                self.assertEqual(environment["policy_id"], expected)
                if CONTROLS.is_single_maintainer_administration(
                    repository["name"], environment
                ):
                    profile_administration_environments.append(
                        (repository["name"], environment["name"])
                    )
                    self.assertEqual(
                        CONTROLS.environment_policy_variable_name(
                            repository["name"], environment
                        ),
                        CONTROLS.PROFILE_POLICY_VARIABLE_NAME,
                    )
                    self.assertEqual(
                        environment["reviewers"],
                        {"minimum": 0, "source": "profile_policy"},
                    )
                    self.assertIs(environment["prevent_self_review"], False)
                    self.assertEqual(
                        environment["secrets"]["required_names"],
                        ["LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"],
                    )
                self.assertEqual(
                    environment["secrets"]["required_names"],
                    environment["secrets"]["allowed_names"],
                )
                variables = environment.get(
                    "variables", {"required_names": [], "allowed_names": []}
                )
                self.assertEqual(
                    variables["required_names"],
                    variables["allowed_names"],
                )
                policy_ids.append(expected)
        self.assertEqual(len(policy_ids), len(set(policy_ids)))
        self.assertEqual(len(policy_ids), 56)
        self.assertEqual(
            profile_administration_environments,
            [
                (repository, "single-maintainer-v1-administration")
                for repository in (
                    "latchway",
                    "latchway-js",
                    "latchway-ios-sdk",
                    "latchway-android",
                    "latchway-react-native-sdk",
                )
            ],
        )
        self.assertEqual(
            environment_counts,
            {
                "latchway": 23,
                "latchway-js": 4,
                "latchway-ios-sdk": 6,
                "latchway-android": 11,
                "latchway-react-native-sdk": 11,
                "latchway-docs": 1,
            },
        )
        self.assertEqual(len(self.manifest["npm_trusted_publishers"]), 5)
        self.assertNotIn(
            "LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN",
            json.dumps(self.manifest["repositories"], sort_keys=True),
        )

    def test_schema_expresses_sentinel_actions_bypass_and_main_rules(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertIn("control_id", schema["required"])
        self.assertEqual(
            schema["properties"]["protected_secret_scope"]["const"],
            "environment_only",
        )
        tag = schema["$defs"]["tagRuleset"]
        self.assertEqual(
            tag["properties"]["bypass_actors"]["const"],
            CONTROLS.GITHUB_ACTIONS_BYPASS,
        )
        branch = schema["$defs"]["branchRuleset"]
        self.assertEqual(branch["properties"]["bypass_actors"]["maxItems"], 0)
        self.assertEqual(branch["properties"]["rules"]["minItems"], 5)
        docs_branch = schema["$defs"]["docsBranchRuleset"]
        docs_pull_request = next(
            item
            for item in docs_branch["properties"]["rules"]["items"]["oneOf"]
            if item["properties"]["type"] == {"const": "pull_request"}
        )
        docs_parameters = docs_pull_request["properties"]["parameters"]["properties"]
        self.assertEqual(docs_parameters["require_code_owner_review"], {"const": True})
        self.assertEqual(
            docs_parameters["required_approving_review_count"], {"const": 1}
        )
        environment = schema["$defs"]["environment"]
        self.assertEqual(
            environment["properties"]["reviewers"]["properties"]["minimum"],
            {"type": "integer", "enum": [0, 1]},
        )
        profile = environment["allOf"][0]
        self.assertEqual(
            profile["then"]["properties"]["reviewers"]["properties"]["minimum"],
            {"const": 0},
        )
        self.assertEqual(
            profile["then"]["properties"]["prevent_self_review"],
            {"const": False},
        )

    def test_manual_validator_rejects_topology_or_secret_weakening(self):
        manifest = deepcopy(self.manifest)
        react_native = next(
            item
            for item in manifest["repositories"]
            if item["name"] == "latchway-react-native-sdk"
        )
        react_native["environments"][0]["secrets"]["allowed_names"] = [
            "LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN"
        ]
        react_native["environments"][0]["secrets"]["required_names"] = [
            "LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN"
        ]
        with self.assertRaisesRegex(CONTROLS.ControlError, "environment_topology_invalid"):
            CONTROLS.validate_manifest(manifest)

        manifest = deepcopy(self.manifest)
        docs = next(
            item
            for item in manifest["repositories"]
            if item["name"] == "latchway-docs"
        )
        docs_pull_request = next(
            rule
            for rule in docs["rulesets"][1]["rules"]
            if rule["type"] == "pull_request"
        )
        docs_pull_request["parameters"]["require_code_owner_review"] = False
        docs_pull_request["parameters"]["required_approving_review_count"] = 0
        with self.assertRaisesRegex(
            CONTROLS.ControlError, "ruleset_not_protected_main"
        ):
            CONTROLS.validate_manifest(manifest)

        manifest = deepcopy(self.manifest)
        product_pull_request = next(
            rule
            for rule in manifest["repositories"][0]["rulesets"][1]["rules"]
            if rule["type"] == "pull_request"
        )
        product_pull_request["parameters"]["require_code_owner_review"] = True
        product_pull_request["parameters"]["required_approving_review_count"] = 1
        with self.assertRaisesRegex(
            CONTROLS.ControlError, "ruleset_not_protected_main"
        ):
            CONTROLS.validate_manifest(manifest)

        manifest = deepcopy(self.manifest)
        manifest["repositories"][0]["environments"][0]["reviewers"]["minimum"] = 2
        with self.assertRaisesRegex(
            CONTROLS.ControlError, "environment_reviewers_invalid"
        ):
            CONTROLS.validate_manifest(manifest)

        manifest = deepcopy(self.manifest)
        javascript = next(
            item
            for item in manifest["repositories"]
            if item["name"] == "latchway-js"
        )
        javascript["environments"] = [
            environment
            for environment in javascript["environments"]
            if environment["name"] != "release-administration"
        ]
        with self.assertRaisesRegex(CONTROLS.ControlError, "environment_topology_invalid"):
            CONTROLS.validate_manifest(manifest)

    def test_compliant_fixture_verifies_without_mutations(self):
        checks, mutations, destructive = self.inspect(
            FixtureGitHub(self.manifest, self.fixture)
        )
        self.assertFalse(destructive)
        self.assertEqual(mutations, [])
        self.assertTrue(checks)
        self.assertTrue(all(check["status"] == "passed" for check in checks))

    def test_missing_environment_plans_ordered_additive_bootstrap(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.missing_environment = "release-image-publishing"
        _, mutations, destructive = self.inspect(client)
        self.assertFalse(destructive)
        selected = [
            mutation
            for mutation in mutations
            if "/release-image-publishing" in mutation["path"]
        ]
        self.assertEqual(
            [mutation["method"] for mutation in selected],
            ["PUT", "POST"],
        )
        self.assertTrue(selected[1]["path"].endswith("/deployment-branch-policies"))
        self.assertFalse(any("/variables" in item["path"] for item in selected))
        sentinel_check = next(
            check
            for check in self.inspect(client)[0]
            if check["name"] == "release-image-publishing"
            and check["control"] == "environment_variable"
        )
        self.assertEqual(
            sentinel_check["code"],
            "release_control_policy_sentinel_withheld_until_environment_exact",
        )
        self.assertIn(
            "administrator_bypass_not_live_verified",
            sentinel_check["blockers"],
        )
        bypass_check = next(
            check
            for check in self.inspect(client)[0]
            if check["name"] == "release-image-publishing"
            and check["control"] == "environment_admin_bypass"
        )
        self.assertEqual(
            bypass_check["code"],
            "disable_administrator_bypass_after_environment_creation",
        )
        self.assertNotIn("can_admins_bypass", selected[0]["body"])

    def test_existing_nonexact_branch_mode_requires_manual_remediation(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.branch_mode = "protected"
        checks, mutations, destructive = self.inspect(client)
        self.assertTrue(destructive)
        self.assertIn(
            "deployment_branch_mode_requires_manual_remediation",
            {check["code"] for check in checks},
        )
        self.assertFalse(
            any(
                item["reason"]
                in {
                    "restrict_environment_to_selected_branches",
                    "add_exact_main_branch_policy",
                }
                for item in mutations
            )
        )

    def test_malformed_branch_policy_collection_fails_closed(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.branch_policy_mode = "malformed"
        with self.assertRaisesRegex(
            CONTROLS.ControlError,
            "environment_branch_policy_list_invalid",
        ):
            self.inspect(client)

    def test_ruleset_completion_emits_each_desired_rule_once(self):
        desired = next(
            ruleset
            for ruleset in self.manifest["repositories"][0]["rulesets"]
            if ruleset["name"] == "latchway-main-protected"
        )
        for mode in ("incomplete", "disabled"):
            with self.subTest(mode=mode):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.ruleset_mode = mode
                client.variable_mode = "missing"
                _, mutations, destructive = self.inspect(client)
                self.assertFalse(destructive)
                update = next(
                    item
                    for item in mutations
                    if item["reason"]
                    == "activate_or_complete_repository_ruleset"
                )
                self.assertEqual(
                    CONTROLS.normalize_rules(update["body"]["rules"]),
                    CONTROLS.normalize_rules(desired["rules"]),
                )
                types = [rule["type"] for rule in update["body"]["rules"]]
                self.assertEqual(len(types), len(set(types)))

        client = FixtureGitHub(self.manifest, self.fixture)
        client.ruleset_mode = "duplicate"
        _, _, destructive = self.inspect(client)
        self.assertTrue(destructive)

    def test_rulesets_must_be_live_exact_before_sentinels_are_sealed(self):
        for ruleset_mode, expected_mutation, expected_blocker in (
            (
                "missing",
                "create_repository_ruleset",
                "repository_ruleset_missing:latchway-main-protected",
            ),
            (
                "incomplete",
                "activate_or_complete_repository_ruleset",
                "repository_ruleset_incomplete:latchway-main-protected",
            ),
        ):
            with self.subTest(ruleset=ruleset_mode, sentinel="missing"):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.ruleset_mode = ruleset_mode
                client.variable_mode = "missing"
                checks, mutations, destructive = self.inspect(client)
                self.assertFalse(destructive)
                self.assertIn(expected_mutation, {item["reason"] for item in mutations})
                self.assertFalse(
                    any(
                        item["reason"]
                        in {
                            "add_release_control_policy_sentinel",
                            "restore_release_control_policy_sentinel",
                        }
                        for item in mutations
                    )
                )
                sentinel_checks = [
                    check
                    for check in checks
                    if check["control"] == "environment_variable"
                    and check["name"] in client.environments
                ]
                self.assertEqual(len(sentinel_checks), len(client.environments))
                self.assertTrue(
                    all(
                        check["code"]
                        == "release_control_policy_sentinel_withheld_until_environment_exact"
                        and expected_blocker in check["blockers"]
                        for check in sentinel_checks
                    )
                )

            with self.subTest(ruleset=ruleset_mode, sentinel="present"):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.ruleset_mode = ruleset_mode
                checks, mutations, destructive = self.inspect(client)
                self.assertTrue(destructive)
                quarantines = [
                    item
                    for item in mutations
                    if item["reason"]
                    == "quarantine_release_control_policy_sentinel"
                ]
                self.assertEqual(len(quarantines), len(client.environments))
                self.assertTrue(
                    all(
                        item["method"] == "PATCH"
                        and item["body"]["value"].endswith(
                            CONTROLS.QUARANTINE_SUFFIX
                        )
                        for item in quarantines
                    )
                )
                sentinel_checks = [
                    check
                    for check in checks
                    if check["control"] == "environment_variable"
                    and check["name"] in client.environments
                ]
                self.assertEqual(len(sentinel_checks), len(client.environments))
                self.assertTrue(
                    all(
                        check["code"]
                        == "release_control_policy_sentinel_quarantine_scheduled"
                        and expected_blocker in check["blockers"]
                        for check in sentinel_checks
                    )
                )

    def test_duplicate_managed_ruleset_identity_quarantines_existing_seals(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.ruleset_mode = "duplicate_identity"
        evidence = CONTROLS.online_evidence(
            "apply",
            self.manifest,
            MANIFEST,
            self.manifest_sha,
            CONTROLS.parse_reviewers(["user:tiepvuvan"]),
            {"latchway"},
            client,
            None,
        )

        self.assertEqual(evidence["status"], "failed")
        identity_check = next(
            check
            for check in evidence["checks"]
            if check["code"]
            == "duplicate_managed_ruleset_identity_requires_manual_remediation"
        )
        self.assertEqual(identity_check["matches"], 2)
        self.assertEqual(len(client.calls), len(client.environments))
        self.assertTrue(
            all(
                method == "PATCH"
                and path.rsplit("/", 1)[-1]
                in {
                    CONTROLS.POLICY_VARIABLE_NAME,
                    CONTROLS.PROFILE_POLICY_VARIABLE_NAME,
                }
                and body["value"].endswith(CONTROLS.QUARANTINE_SUFFIX)
                for method, path, body in client.calls
            )
        )
        self.assertTrue(
            all(
                mutation["reason"]
                == "quarantine_release_control_policy_sentinel"
                for mutation in evidence["applied_mutations"]
            )
        )
        self.assertEqual(evidence["pending_mutations"], [])
        self.assertNotIn(b'"body"', CONTROLS.canonical_bytes(evidence))

    def test_unobservable_managed_ruleset_controls_quarantine_existing_seals(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.ruleset_mode = "unobservable_bypass"
        evidence = CONTROLS.online_evidence(
            "apply",
            self.manifest,
            MANIFEST,
            self.manifest_sha,
            CONTROLS.parse_reviewers(["user:tiepvuvan"]),
            {"latchway"},
            client,
            None,
        )

        self.assertEqual(evidence["status"], "failed")
        self.assertTrue(
            any(
                check["code"]
                == "managed_ruleset_controls_unobservable_requires_manual_remediation"
                for check in evidence["checks"]
            )
        )
        self.assertEqual(len(client.calls), len(client.environments))
        self.assertTrue(
            all(
                method == "PATCH"
                and body["value"].endswith(CONTROLS.QUARANTINE_SUFFIX)
                for method, _path, body in client.calls
            )
        )

    def test_missing_and_wrong_sentinel_are_reconciled_without_delete(self):
        for mode, expected_method in (("missing", "POST"), ("wrong", "PATCH")):
            with self.subTest(mode=mode):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.variable_mode = mode
                _, mutations, destructive = self.inspect(client)
                self.assertFalse(destructive)
                sentinel_mutations = [
                    item
                    for item in mutations
                    if "/variables" in item["path"]
                ]
                self.assertEqual(len(sentinel_mutations), 23)
                self.assertTrue(
                    all(item["method"] == expected_method for item in sentinel_mutations)
                )
                self.assertNotIn("DELETE", {item["method"] for item in mutations})

    def test_sentinel_is_final_seal_after_live_environment_invariants(self):
        cases = (
            (
                "administrator_bypass",
                lambda client: setattr(client, "admins_can_bypass", True),
                "administrator_bypass_not_disabled",
            ),
            (
                "reviewers",
                lambda client: setattr(client, "reviewer_mode", "missing"),
                "reviewer_policy_not_exact",
            ),
            (
                "main_branch",
                lambda client: setattr(client, "branch_policy_mode", "missing"),
                "main_branch_policy_not_exact",
            ),
            (
                "required_secrets",
                lambda client: setattr(
                    client,
                    "missing_environment_secret_name",
                    "LATCHWAY_RELEASE_DISPATCH_TOKEN",
                ),
                "required_environment_secrets_missing",
            ),
        )
        for name, configure, blocker in cases:
            with self.subTest(name=name):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.variable_mode = "missing"
                configure(client)
                checks, mutations, _ = self.inspect(client)
                release_sentinel = next(
                    check
                    for check in checks
                    if check["control"] == "environment_variable"
                    and check["name"] == "release"
                )
                self.assertEqual(
                    release_sentinel["code"],
                    "release_control_policy_sentinel_withheld_until_environment_exact",
                )
                self.assertIn(blocker, release_sentinel["blockers"])
                self.assertFalse(
                    any(
                        item["path"].endswith("/environments/release/variables")
                        for item in mutations
                    )
                )

        client = FixtureGitHub(self.manifest, self.fixture)
        client.missing_environment_secret_name = "LATCHWAY_RELEASE_DISPATCH_TOKEN"
        checks, _, destructive = self.inspect(client)
        self.assertTrue(destructive)
        premature = next(
            check
            for check in checks
            if check["control"] == "environment_variable"
            and check["name"] == "release"
        )
        self.assertEqual(
            premature["code"],
            "release_control_policy_sentinel_quarantine_scheduled",
        )
        self.assertIn(
            "required_environment_secrets_missing", premature["blockers"]
        )

        client = FixtureGitHub(self.manifest, self.fixture)
        client.variable_mode = "missing"
        client.missing_environment_variable_name = (
            "LATCHWAY_MAVEN_SIGNING_FINGERPRINT"
        )
        checks, mutations, _ = self.inspect(client)
        evidence_sentinel = next(
            check
            for check in checks
            if check["control"] == "environment_variable"
            and check["name"] == "release-evidence"
        )
        self.assertEqual(
            evidence_sentinel["code"],
            "release_control_policy_sentinel_withheld_until_environment_exact",
        )
        self.assertIn(
            "required_environment_variables_missing",
            evidence_sentinel["blockers"],
        )
        self.assertFalse(
            any(
                item["path"].endswith(
                    "/environments/release-evidence/variables"
                )
                for item in mutations
            )
        )

    def test_unknown_variable_or_human_bypass_blocks_all_apply(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.variable_mode = "unknown"
        _, _, destructive = self.inspect(client)
        self.assertTrue(destructive)

        client = FixtureGitHub(self.manifest, self.fixture)
        client.human_ruleset_bypass = True
        _, _, destructive = self.inspect(client)
        self.assertTrue(destructive)

    def test_broader_scope_sentinel_fallback_is_rejected(self):
        for scope in ("organization", "repository"):
            with self.subTest(scope=scope):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.broader_variable_scope = scope
                _, _, destructive = self.inspect(client)
                self.assertTrue(destructive)

    def test_broader_scope_configuration_variable_fallback_is_rejected(self):
        variable_name = "LATCHWAY_MAVEN_SIGNING_FINGERPRINT"
        for scope in ("organization", "repository"):
            with self.subTest(scope=scope):
                client = FixtureGitHub(self.manifest, self.fixture)
                client.broader_variable_scope = scope
                client.broader_variable_name = variable_name
                _, _, destructive = self.inspect(client)
                self.assertTrue(destructive)

        client = FixtureGitHub(self.manifest, self.fixture)
        client.broader_variable_scope = "organization"
        client.broader_variable_name = variable_name
        client.broader_variable_visibility = "selected"
        client.selected_variable_repositories = ["Latchway/latchway-js"]
        _, _, destructive = self.inspect(client)
        self.assertFalse(destructive)

        client.selected_variable_repositories = ["Latchway/latchway"]
        _, _, destructive = self.inspect(client)
        self.assertTrue(destructive)

    def test_broader_scope_release_secret_fallback_is_rejected(self):
        manifest = deepcopy(self.manifest)
        core = next(item for item in manifest["repositories"] if item["name"] == "latchway")
        core["environments"][0]["secrets"]["allowed_names"] = [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ]
        core["environments"][0]["secrets"]["required_names"] = [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ]
        client = FixtureGitHub(manifest, self.fixture)
        client.broader_secret_scope = "organization"
        _, _, destructive = CONTROLS.inspect_github(
            client, manifest, self.reviewers, {"latchway"}
        )
        self.assertTrue(destructive)

        client = FixtureGitHub(manifest, self.fixture)
        client.broader_secret_scope = "organization"
        client.broader_secret_visibility = "selected"
        client.selected_secret_repositories = ["Latchway/latchway-js"]
        _, _, destructive = CONTROLS.inspect_github(
            client, manifest, self.reviewers, {"latchway"}
        )
        self.assertFalse(destructive)

        client.selected_secret_repositories = ["Latchway/latchway"]
        _, _, destructive = CONTROLS.inspect_github(
            client, manifest, self.reviewers, {"latchway"}
        )
        self.assertTrue(destructive)

        client = FixtureGitHub(manifest, self.fixture)
        client.broader_secret_scope = "repository"
        _, _, destructive = CONTROLS.inspect_github(
            client, manifest, self.reviewers, {"latchway"}
        )
        self.assertTrue(destructive)

    def test_org_secret_scope_does_not_shadow_repository_selection(self):
        manifest = deepcopy(self.manifest)
        core = next(
            item for item in manifest["repositories"] if item["name"] == "latchway"
        )
        core["environments"][0]["secrets"]["allowed_names"] = [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ]
        core["environments"][0]["secrets"]["required_names"] = [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ]
        javascript = deepcopy(core)
        javascript["name"] = "latchway-js"
        manifest["repositories"] = [core, javascript]
        client = MultiRepositoryFixtureGitHub(manifest, self.fixture)
        client.broader_secret_scope = "organization"

        checks, _, destructive = CONTROLS.inspect_github(
            client,
            manifest,
            self.reviewers,
            {"latchway", "latchway-js"},
        )

        self.assertTrue(destructive)
        self.assertIn(
            "/repos/Latchway/latchway-js",
            client.observed_paths,
        )
        self.assertIn(
            ("latchway-js", "repository", "default_branch_main"),
            {
                (check["repository"], check["control"], check["code"])
                for check in checks
            },
        )

    def test_retired_sibling_secret_is_forbidden_at_every_scope(self):
        retired_name = "LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN"
        for scope in ("organization", "repository", "environment"):
            with self.subTest(scope=scope):
                client = FixtureGitHub(self.manifest, self.fixture)
                if scope == "environment":
                    client.environment_secret_name = retired_name
                else:
                    client.broader_secret_scope = scope
                    client.broader_secret_name = retired_name
                checks, _, destructive = self.inspect(client)
                self.assertTrue(destructive)
                self.assertTrue(
                    any(
                        check["status"] == "drift"
                        and retired_name
                        in check.get("names", check.get("actual", []))
                        for check in checks
                    )
                )

    def test_reviewer_must_be_independent_and_admin_bypass_disabled(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.authenticated_actor_id = 101
        checks, _, destructive = self.inspect(client)
        self.assertTrue(destructive)
        self.assertIn(
            "distinct_release_reviewer_required",
            {check["code"] for check in checks},
        )

        client = FixtureGitHub(self.manifest, self.fixture)
        client.admins_can_bypass = True
        checks, _, destructive = self.inspect(client)
        self.assertTrue(destructive)
        self.assertIn(
            "administrator_bypass_requires_manual_remediation",
            {check["code"] for check in checks},
        )

    def test_quarantine_restricts_admin_and_broader_fallback_drift(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        client.admins_can_bypass = True
        _, mutations, destructive = self.inspect(client)
        self.assertTrue(destructive)
        self.assertEqual(
            len(
                [
                    item
                    for item in mutations
                    if item["reason"]
                    == "quarantine_release_control_policy_sentinel"
                ]
            ),
            len(client.environments),
        )

        client = FixtureGitHub(self.manifest, self.fixture)
        client.variable_mode = "missing"
        client.broader_variable_scope = "repository"
        _, mutations, destructive = self.inspect(client)
        self.assertTrue(destructive)
        quarantines = [
            item
            for item in mutations
            if item["reason"] == "quarantine_release_control_policy_sentinel"
        ]
        self.assertEqual(len(quarantines), len(client.environments))
        self.assertTrue(all(item["method"] == "POST" for item in quarantines))

        client = FixtureGitHub(self.manifest, self.fixture)
        client.variable_mode = "quarantined"
        client.admins_can_bypass = True
        checks, mutations, destructive = self.inspect(client)
        self.assertTrue(destructive)
        self.assertFalse(
            any(
                item["reason"] == "quarantine_release_control_policy_sentinel"
                for item in mutations
            )
        )
        self.assertIn(
            "release_control_policy_quarantine_active_until_environment_exact",
            {check["code"] for check in checks},
        )

        client.admins_can_bypass = False
        _, mutations, destructive = self.inspect(client)
        self.assertFalse(destructive)
        restores = [
            item
            for item in mutations
            if item["reason"] == "restore_release_control_policy_sentinel"
        ]
        self.assertEqual(len(restores), len(client.environments))

    def test_required_context_must_be_observed_from_actions_app(self):
        client = FixtureGitHub(self.manifest, deepcopy(self.fixture))
        client.fixture["status_contexts"].remove("contracts")
        checks, _, destructive = self.inspect(client)
        self.assertTrue(destructive)
        failure = next(
            check
            for check in checks
            if check["code"] == "required_github_actions_context_not_observed"
        )
        self.assertEqual(failure["missing"], ["contracts"])

    def test_plan_is_canonical_and_covers_all_controls(self):
        selectors = CONTROLS.parse_reviewers(["user:tiepvuvan"])
        evidence = CONTROLS.plan_evidence(
            self.manifest,
            MANIFEST,
            self.manifest_sha,
            selectors,
            CONTROLS.repository_selection(self.manifest, []),
            False,
        )
        payload = CONTROLS.canonical_bytes(evidence)
        self.assertEqual(payload, CONTROLS.canonical_bytes(json.loads(payload)))
        actions = [item["action"] for item in evidence["actions"]]
        self.assertEqual(actions.count("ensure_release_control_policy_sentinel"), 56)
        self.assertEqual(actions.count("verify_configuration_variable_names"), 56)
        self.assertEqual(actions.count("ensure_repository_ruleset"), 12)
        self.assertEqual(actions.count("ensure_npm_trusted_publisher"), 5)
        profile_sentinels = {
            item["repository"]
            for item in evidence["actions"]
            if item["action"] == "ensure_release_control_policy_sentinel"
            and item["name"] == "single-maintainer-v1-administration"
            and item["variable"] == CONTROLS.PROFILE_POLICY_VARIABLE_NAME
        }
        self.assertEqual(
            profile_sentinels,
            CONTROLS.SINGLE_MAINTAINER_PRODUCT_REPOSITORIES,
        )
        release_evidence = next(
            action
            for action in evidence["actions"]
            if action["action"] == "verify_configuration_variable_names"
            and action["repository"] == "latchway"
            and action["name"] == "release-evidence"
        )
        self.assertEqual(
            release_evidence["required_names"],
            next(
                environment
                for environment in self.manifest["repositories"][0]["environments"]
                if environment["name"] == "release-evidence"
            )["variables"]["required_names"],
        )

    def test_apply_is_a_noop_for_compliant_fixture(self):
        client = FixtureGitHub(self.manifest, self.fixture)
        evidence = CONTROLS.online_evidence(
            "apply",
            self.manifest,
            MANIFEST,
            self.manifest_sha,
            CONTROLS.parse_reviewers(["user:tiepvuvan"]),
            {"latchway"},
            client,
            None,
        )
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(evidence["applied_mutations"], [])
        self.assertEqual(evidence["pending_mutations"], [])
        self.assertEqual(client.calls, [])

    def test_failed_apply_preserves_github_partial_success_journal(self):
        first = CONTROLS.mutation(
            "PUT", "/repos/Latchway/latchway/environments/one", "first", {"secret": "must-not-appear"}
        )
        second = CONTROLS.mutation(
            "POST", "/repos/Latchway/latchway/rulesets", "second", {"token": "must-not-appear"}
        )
        github = mock.Mock()
        github.put.return_value = None
        github.post.side_effect = CONTROLS.ControlError("github_api_transport_failed")
        checks = [
            {
                "control": "fixture",
                "name": "fixture",
                "repository": "latchway",
                "status": "missing",
                "code": "fixture_missing",
            }
        ]
        with mock.patch.object(
            CONTROLS, "resolve_reviewers", return_value=self.reviewers
        ), mock.patch.object(
            CONTROLS,
            "inspect_github",
            return_value=(checks, [first, second], False),
        ):
            evidence = CONTROLS.online_evidence(
                "apply",
                self.manifest,
                MANIFEST,
                self.manifest_sha,
                CONTROLS.parse_reviewers(["user:tiepvuvan"]),
                {"latchway"},
                github,
                None,
            )

        self.assertEqual(evidence["status"], "error")
        self.assertEqual(
            evidence["error"], {"code": "github_api_transport_failed"}
        )
        self.assertEqual(evidence["repositories"], ["latchway"])
        self.assertEqual(evidence["manifest"]["sha256"], self.manifest_sha)
        self.assertEqual(
            evidence["applied_mutations"], [CONTROLS.mutation_identity(first)]
        )
        self.assertEqual(
            evidence["pending_mutations"], [CONTROLS.mutation_identity(second)]
        )
        payload = CONTROLS.canonical_bytes(evidence)
        self.assertEqual(payload, CONTROLS.canonical_bytes(json.loads(payload)))
        self.assertNotIn(b"must-not-appear", payload)
        self.assertNotIn(b'"body"', payload)

    def test_failed_quarantine_apply_journals_only_restrictive_mutations(self):
        ordinary = CONTROLS.mutation(
            "POST",
            "/repos/Latchway/latchway/rulesets",
            "create_repository_ruleset",
            {"must": "not-run"},
        )
        first = CONTROLS.mutation(
            "PATCH",
            "/repos/Latchway/latchway/environments/one/variables/"
            + CONTROLS.POLICY_VARIABLE_NAME,
            "quarantine_release_control_policy_sentinel",
            {"name": CONTROLS.POLICY_VARIABLE_NAME, "value": "quarantine-one"},
        )
        second = CONTROLS.mutation(
            "PATCH",
            "/repos/Latchway/latchway/environments/two/variables/"
            + CONTROLS.POLICY_VARIABLE_NAME,
            "quarantine_release_control_policy_sentinel",
            {"name": CONTROLS.POLICY_VARIABLE_NAME, "value": "quarantine-two"},
        )
        github = mock.Mock()
        github.patch.side_effect = [
            None,
            CONTROLS.ControlError("github_api_transport_failed"),
        ]
        checks = [
            {
                "control": "environment_variable",
                "name": "one",
                "repository": "latchway",
                "status": "drift",
                "code": "release_control_policy_sentinel_quarantine_scheduled",
            }
        ]
        with mock.patch.object(
            CONTROLS, "resolve_reviewers", return_value=self.reviewers
        ), mock.patch.object(
            CONTROLS,
            "inspect_github",
            return_value=(checks, [ordinary, first, second], True),
        ):
            evidence = CONTROLS.online_evidence(
                "apply",
                self.manifest,
                MANIFEST,
                self.manifest_sha,
                CONTROLS.parse_reviewers(["user:tiepvuvan"]),
                {"latchway"},
                github,
                None,
            )

        self.assertEqual(evidence["status"], "error")
        self.assertEqual(
            evidence["applied_mutations"],
            [CONTROLS.mutation_identity(first)],
        )
        self.assertEqual(
            evidence["pending_mutations"],
            [CONTROLS.mutation_identity(second)],
        )
        github.post.assert_not_called()
        payload = CONTROLS.canonical_bytes(evidence)
        self.assertNotIn(b"quarantine-one", payload)
        self.assertNotIn(b"quarantine-two", payload)
        self.assertNotIn(b'"body"', payload)

    def test_failed_apply_preserves_npm_partial_success_journal(self):
        publishers = CONTROLS.publishers_for_selection(
            self.manifest, {"latchway-js"}
        )[:2]
        preflight = {
            "registry": CONTROLS.NPM_REGISTRY,
            "username": "release-operator",
            "two_factor_authentication": True,
            "packages": [
                {
                    "package": publisher["package"],
                    "exists": True,
                    "write_visible": True,
                }
                for publisher in publishers
            ],
        }

        class PartialNpm:
            def __init__(self):
                self.created = []

            def create(self, publisher):
                if self.created:
                    raise CONTROLS.ControlError("npm_trust_create_failed")
                self.created.append(publisher["package"])

        npm = PartialNpm()
        github = mock.Mock()
        github_checks = [
            {
                "control": "fixture",
                "name": "fixture",
                "repository": "latchway-js",
                "status": "passed",
                "code": "fixture_exact",
            }
        ]
        npm_checks = [
            {
                "control": "npm_trusted_publisher",
                "name": publisher["package"],
                "repository": publisher["repository"],
                "status": "missing",
                "code": "npm_trusted_publisher_missing",
            }
            for publisher in publishers
        ]
        with mock.patch.object(
            CONTROLS, "resolve_reviewers", return_value=self.reviewers
        ), mock.patch.object(
            CONTROLS,
            "inspect_github",
            return_value=(github_checks, [], False),
        ), mock.patch.object(
            CONTROLS,
            "inspect_npm",
            return_value=(npm_checks, publishers, False, preflight),
        ):
            evidence = CONTROLS.online_evidence(
                "apply",
                self.manifest,
                MANIFEST,
                self.manifest_sha,
                CONTROLS.parse_reviewers(["user:tiepvuvan"]),
                {"latchway-js"},
                github,
                npm,
            )

        self.assertEqual(evidence["status"], "error")
        self.assertEqual(
            evidence["npm_publishers_applied"],
            [CONTROLS.npm_publisher_identity(publishers[0])],
        )
        self.assertEqual(
            evidence["npm_publishers_pending"],
            [CONTROLS.npm_publisher_identity(publishers[1])],
        )
        self.assertEqual(evidence["npm_preflight"], preflight)
        payload = CONTROLS.canonical_bytes(evidence)
        self.assertNotIn(b'"body"', payload)
        self.assertNotIn(b"NPM_TOKEN", payload)

    def test_pagination_and_forbidden_responses_fail_closed(self):
        for malformed in (
            {"variables": [], "extra": True},
            {"total_count": 0, "extra": True},
        ):
            with self.subTest(fields=sorted(malformed)):
                client = StubGitHub([(malformed, {})])
                with self.assertRaisesRegex(
                    CONTROLS.ControlError, "github_collection_fields_missing"
                ):
                    client.collection("/variables", "variables")

        client = StubGitHub(
            [
                (
                    {"total_count": 2, "variables": [{"name": "A"}]},
                    {},
                )
            ]
        )
        with self.assertRaisesRegex(
            CONTROLS.ControlError, "github_collection_truncated"
        ):
            client.collection("/variables", "variables")

        client = CONTROLS.GitHubAPI(
            "not-a-real-token", "2026-03-10", "http://localhost"
        )
        forbidden = HTTPError(
            "http://localhost/resource", 403, "Forbidden", {}, None
        )
        with mock.patch.object(CONTROLS, "urlopen", side_effect=forbidden):
            with self.assertRaisesRegex(CONTROLS.ControlError, "github_api_forbidden"):
                client.get("/resource")
        forbidden.close()

    def test_delete_mutation_is_impossible(self):
        with self.assertRaisesRegex(CONTROLS.ControlError, "unsafe_mutation_method"):
            CONTROLS.mutation("DELETE", "/resource", "unsafe", {})

    def test_npm_cli_is_version_gated_and_scrubs_auth_tokens(self):
        responses = [
            subprocess.CompletedProcess(["npm", "--version"], 0, "11.15.0\n", ""),
            subprocess.CompletedProcess(
                ["npm", "trust", "list"],
                0,
                json.dumps(
                    {
                        "type": "github",
                        "repository": "Latchway/latchway-js",
                        "file": "release.yml",
                        "environment": "npm",
                        "permissions": ["createPackage"],
                    }
                ),
                "",
            ),
        ]
        with mock.patch.dict(
            CONTROLS.os.environ,
            {
                "NPM_TOKEN": "must-not-leak",
                "NODE_AUTH_TOKEN": "also-secret",
                "GH_TOKEN": "github-secret",
                "GITHUB_TOKEN": "built-in-secret",
                "CUSTOM_GITHUB_ADMIN_TOKEN": "custom-secret",
                "npm_config_@latchway:registry": "https://example.invalid/",
                "NPM_CONFIG_USERCONFIG": "/tmp/hostile-user-config",
            },
        ), mock.patch.object(CONTROLS.subprocess, "run", side_effect=responses) as run:
            items = CONTROLS.NpmCLI(
                "npm", "CUSTOM_GITHUB_ADMIN_TOKEN"
            ).list("@latchway/client")
        self.assertEqual(len(items), 1)
        for call in run.call_args_list:
            environment = call.kwargs["env"]
            self.assertNotIn("NPM_TOKEN", environment)
            self.assertNotIn("NODE_AUTH_TOKEN", environment)
            self.assertNotIn("GH_TOKEN", environment)
            self.assertNotIn("GITHUB_TOKEN", environment)
            self.assertNotIn("CUSTOM_GITHUB_ADMIN_TOKEN", environment)
        trust_arguments = run.call_args_list[1].args[0]
        self.assertEqual(
            trust_arguments[-3:],
            [
                "--registry",
                CONTROLS.NPM_REGISTRY,
                CONTROLS.NPM_SCOPE_REGISTRY_OPTION,
            ],
        )

    def test_npm_preflight_is_registry_pinned_and_evidence_safe(self):
        package = "@latchway/client"
        responses = [
            subprocess.CompletedProcess(["npm", "--version"], 0, "11.17.0\n", ""),
            subprocess.CompletedProcess(["npm", "whoami"], 0, "release-operator\n", ""),
            subprocess.CompletedProcess(
                ["npm", "profile", "get"],
                0,
                json.dumps(
                    {
                        "name": "release-operator",
                        "email": "must-not-appear@example.invalid",
                        "tfa": {
                            "pending": False,
                            "mode": "auth-and-writes",
                        },
                    }
                ),
                "",
            ),
            subprocess.CompletedProcess(
                ["npm", "access", "get"],
                0,
                json.dumps({package: "public"}),
                "",
            ),
            subprocess.CompletedProcess(
                ["npm", "access", "list"],
                0,
                json.dumps(
                    {
                        package: "read-write",
                        "@private/must-not-appear": "read-only",
                    }
                ),
                "",
            ),
        ]
        with mock.patch.dict(
            CONTROLS.os.environ,
            {
                "NPM_TOKEN": "must-not-leak",
                "NODE_AUTH_TOKEN": "also-secret",
                "npm_config_@latchway:registry": "https://example.invalid/",
                "NPM_CONFIG_USERCONFIG": "/tmp/hostile-user-config",
            },
        ), mock.patch.object(
            CONTROLS.subprocess, "run", side_effect=responses
        ) as run:
            preflight = CONTROLS.NpmCLI("npm").preflight([package])

        self.assertEqual(
            preflight,
            {
                "registry": CONTROLS.NPM_REGISTRY,
                "username": "release-operator",
                "two_factor_authentication": True,
                "packages": [
                    {
                        "package": package,
                        "exists": True,
                        "write_visible": True,
                    }
                ],
            },
        )
        serialized = json.dumps(preflight, sort_keys=True)
        self.assertNotIn("must-not-appear", serialized)
        for call in run.call_args_list:
            self.assertNotIn("NPM_TOKEN", call.kwargs["env"])
            self.assertNotIn("NODE_AUTH_TOKEN", call.kwargs["env"])
        for call in run.call_args_list[1:]:
            arguments = call.args[0]
            registry_index = arguments.index("--registry")
            self.assertEqual(arguments[registry_index + 1], CONTROLS.NPM_REGISTRY)
        for call in run.call_args_list[3:]:
            self.assertIn(
                CONTROLS.NPM_SCOPE_REGISTRY_OPTION,
                call.args[0],
            )

    def test_npm_preflight_blocks_trust_when_account_2fa_is_disabled(self):
        publisher = self.manifest["npm_trusted_publishers"][0]

        class DisabledTfaNpm:
            def preflight(self, packages):
                return {
                    "registry": CONTROLS.NPM_REGISTRY,
                    "username": "release-operator",
                    "two_factor_authentication": False,
                    "packages": [
                        {
                            "package": packages[0],
                            "exists": True,
                            "write_visible": True,
                        }
                    ],
                }

            def list(self, package):
                raise AssertionError("trust list must not run after failed preflight")

        checks, missing, blocked, preflight = CONTROLS.inspect_npm(
            DisabledTfaNpm(), [publisher]
        )
        self.assertTrue(blocked)
        self.assertEqual(missing, [])
        self.assertFalse(preflight["two_factor_authentication"])
        self.assertIn("npm_account_2fa_required", {item["code"] for item in checks})

    def test_npm_trust_create_is_pinned_to_npmjs(self):
        publisher = self.manifest["npm_trusted_publishers"][0]
        responses = [
            subprocess.CompletedProcess(["npm", "--version"], 0, "11.17.0\n", ""),
            subprocess.CompletedProcess(["npm", "trust", "github"], 0, "{}", ""),
        ]
        with mock.patch.object(
            CONTROLS.subprocess, "run", side_effect=responses
        ) as run:
            CONTROLS.NpmCLI("npm").create(publisher)
        arguments = run.call_args_list[1].args[0]
        self.assertEqual(
            arguments[-3:],
            [
                "--registry",
                CONTROLS.NPM_REGISTRY,
                CONTROLS.NPM_SCOPE_REGISTRY_OPTION,
            ],
        )


if __name__ == "__main__":
    unittest.main()
