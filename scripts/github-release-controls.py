#!/usr/bin/env python3
"""Plan, verify, or additively reconcile Latchway release controls.

The desired-state manifest contains identities and secret *names*, never secret
values. Online modes require a token from an environment variable. Apply mode
can create missing controls and add missing restrictions, but never sends a
DELETE request, removes an unknown reviewer, removes a branch policy, removes a
ruleset rule or bypass actor, revokes npm trust, or writes a secret value.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / ".github/release-controls.json"
DEFAULT_API_BASE = "https://api.github.com"
NPM_REGISTRY = "https://registry.npmjs.org/"
NPM_SCOPE_REGISTRY_OPTION = f"--@latchway:registry={NPM_REGISTRY}"
APPLY_CONFIRMATION = "apply-latchway-release-controls-v1"
POLICY_VARIABLE_NAME = "LATCHWAY_RELEASE_CONTROL_POLICY_ID"
PROFILE_POLICY_VARIABLE_NAME = "LATCHWAY_RELEASE_PROFILE_POLICY_ID"
SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT = (
    "single-maintainer-v1-administration"
)
SINGLE_MAINTAINER_PRODUCT_REPOSITORIES = frozenset(
    {
        "latchway",
        "latchway-js",
        "latchway-ios-sdk",
        "latchway-android",
        "latchway-react-native-sdk",
    }
)
QUARANTINE_SUFFIX = ":quarantine-v1"
QUARANTINE_MUTATION_REASONS = {
    "create_environment_for_policy_quarantine",
    "quarantine_release_control_policy_sentinel",
}
GITHUB_ACTIONS_APP = {"id": 15368, "slug": "github-actions"}
GITHUB_ACTIONS_BYPASS = [
    {
        "actor_id": GITHUB_ACTIONS_APP["id"],
        "actor_type": "Integration",
        "bypass_mode": "always",
    }
]
EXPECTED_REPOSITORIES = {
    "latchway",
    "latchway-js",
    "latchway-ios-sdk",
    "latchway-android",
    "latchway-react-native-sdk",
    "latchway-docs",
}
EXPECTED_FORBIDDEN_SECRET_NAMES = [
    "LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN",
]
EXPECTED_NPM_PUBLISHERS = {
    ("@latchway/client", "Latchway/latchway-js"),
    ("@latchway/openai", "Latchway/latchway-js"),
    ("@latchway/vercel-ai", "Latchway/latchway-js"),
    ("@latchway/langchain", "Latchway/latchway-js"),
    ("@latchway/react-native", "Latchway/latchway-react-native-sdk"),
}
EXPECTED_STATUS_CONTEXTS = {
    "latchway": [
        "Core (PostgreSQL 15)",
        "Core (PostgreSQL 18)",
        "Validate canonical Mintlify source",
        "console",
        "container",
        "contracts",
        "deployments",
        "image",
        "lint",
        "reliability",
        "source",
        "static",
    ],
    "latchway-js": [
        "Pinned core Docker and PostgreSQL conformance",
        "Pinned latest framework profile",
        "Pinned minimum framework profile",
        "verify",
    ],
    "latchway-ios-sdk": [
        "Pinned core Docker and PostgreSQL conformance",
        "iOS SDK live debug vertical (native macOS, no Docker claim)",
        "package",
    ],
    "latchway-android": [
        "Pinned core Docker and PostgreSQL conformance",
        "verify",
    ],
    "latchway-react-native-sdk": [
        "Hermetic pull-request policy and source checks",
        "Pinned core plus React Native package/native split conformance",
    ],
    "latchway-docs": [
        "Require a written docs-not-required reason",
        "Validate Mintlify site",
        "Verify synchronized source checkpoint",
    ],
}
EXPECTED_ENVIRONMENTS = {
    "latchway": {
        "deployment-evidence-authentication": [],
        "deployment-evidence-aws": ["AWS_ROLE_TO_ASSUME"],
        "deployment-evidence-cloud_run": [
            "GCP_SERVICE_ACCOUNT",
            "GCP_WORKLOAD_IDENTITY_PROVIDER",
        ],
        "deployment-evidence-cloudflare_containers": [
            "CLOUDFLARE_ACCOUNT_ID",
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_EVIDENCE_TOKEN",
        ],
        "deployment-evidence-compose": [],
        "deployment-evidence-fly_io": ["FLY_API_TOKEN"],
        "deployment-evidence-signing": [],
        "operational-resilience-evidence": [],
        "preview-image-publishing": [],
        "private-sibling-read": [],
        "release": [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN",
            "LATCHWAY_RELEASE_DISPATCH_TOKEN",
        ],
        "release-evidence": [],
        "release-image-publishing": [],
        "release-evidence-signing": [],
        "release-evidence-firebase-app-check": [
            "LATCHWAY_ONE_TIME_LIVE_SDK_GRANT"
        ],
        "release-evidence-github-read": [
            "LATCHWAY_RELEASE_EVIDENCE_GITHUB_READ_TOKEN"
        ],
        "release-evidence-live-provider": [
            "LATCHWAY_ONE_TIME_LIVE_PROVIDER_GRANT"
        ],
        "release-evidence-physical": [
            "LATCHWAY_RELEASE_EVIDENCE_ACTIONS_READ_TOKEN"
        ],
        "release-evidence-turnstile": ["LATCHWAY_ONE_TIME_LIVE_SDK_GRANT"],
        "release-failure-evidence": [],
        "release-load-evidence": [],
        "security-evidence": ["INDEPENDENT_SECURITY_REVIEW_TOKEN"],
        SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT: [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ],
    },
    "latchway-js": {
        "npm": [],
        "release-administration": ["LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"],
        SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT: [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ],
        "github-release": [],
    },
    "latchway-ios-sdk": {
        "app-attest-production": [
            "LATCHWAY_ASSERTION_DEVICE_GRANT",
            "LATCHWAY_IOS_DEVICE_ID",
            "LATCHWAY_REGISTRATION_DEVICE_GRANT",
        ],
        "physical-evidence-signing": [],
        "release-administration": ["LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"],
        SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT: [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ],
        "cocoapods-trunk": ["COCOAPODS_TRUNK_TOKEN"],
        "github-release": [],
    },
    "latchway-android": {
        "physical-evidence-signing": [],
        "play-candidate-build": [],
        "play-candidate-verification": [],
        "play-integrity-production": [
            "LATCHWAY_ANDROID_DEVICE_SERIAL",
            "LATCHWAY_ONE_TIME_DEVICE_GRANT",
        ],
        "play-upload-signing": [
            "LATCHWAY_PLAY_UPLOAD_KEYSTORE_BASE64",
            "LATCHWAY_PLAY_UPLOAD_KEYSTORE_PASSWORD",
            "LATCHWAY_PLAY_UPLOAD_KEY_ALIAS",
            "LATCHWAY_PLAY_UPLOAD_KEY_PASSWORD",
        ],
        "maven-publication-verification": [],
        "release-administration": ["LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"],
        SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT: [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ],
        "maven-central-signing": [
            "LATCHWAY_SIGNING_KEY",
            "LATCHWAY_SIGNING_PASSWORD",
        ],
        "maven-central": [
            "LATCHWAY_MAVEN_CENTRAL_PASSWORD",
            "LATCHWAY_MAVEN_CENTRAL_USERNAME",
        ],
        "github-release": [],
    },
    "latchway-react-native-sdk": {
        "physical-evidence-signing": [],
        "private-sibling-read": [],
        "react-native-android-candidate-build": [],
        "react-native-android-candidate-verification": [],
        "react-native-android-production": [
            "LATCHWAY_ANDROID_DEVICE_SERIAL",
            "LATCHWAY_ONE_TIME_DEVICE_GRANT",
        ],
        "react-native-android-upload-signing": [
            "LATCHWAY_ANDROID_UPLOAD_KEYSTORE_BASE64",
            "LATCHWAY_ANDROID_UPLOAD_KEYSTORE_PASSWORD",
            "LATCHWAY_ANDROID_UPLOAD_KEY_ALIAS",
            "LATCHWAY_ANDROID_UPLOAD_KEY_PASSWORD",
        ],
        "react-native-ios-production": [
            "LATCHWAY_IOS_DEVICE_ID",
            "LATCHWAY_ONE_TIME_DEVICE_GRANT",
        ],
        "npm": [],
        "release-administration": ["LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"],
        SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT: [
            "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN"
        ],
        "github-release": [],
    },
    "latchway-docs": {
        "documentation-production-evidence": ["MINTLIFY_SESSION_TOKEN"],
    },
}
EXPECTED_ENVIRONMENT_VARIABLES = {
    "latchway": {
        "release-evidence": [
            "LATCHWAY_GATEWAY_EVIDENCE_PUBLIC_KEY_PEM",
            "LATCHWAY_GATEWAY_EVIDENCE_PUBLIC_KEY_SHA256",
            "LATCHWAY_LIVE_GATEWAY_BASE_URL",
            "LATCHWAY_LIVE_SDK_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_LIVE_SDK_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_LIVE_SDK_ENVIRONMENT",
            "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE",
            "LATCHWAY_MAVEN_SIGNING_FINGERPRINT",
        ],
        "release-evidence-signing": [
            "INDEPENDENT_SECURITY_REVIEWER_IDENTITY",
            "INDEPENDENT_SECURITY_REVIEWER_LOGIN",
            "INDEPENDENT_SECURITY_REVIEWER_ORGANIZATION",
            "INDEPENDENT_SECURITY_REVIEW_REPOSITORY",
            "INDEPENDENT_SECURITY_REVIEW_WORKFLOW",
            "LATCHWAY_LIVE_PROVIDER_COLLECTOR_TRUST_ROOT_SHA256",
        ],
        "release-evidence-firebase-app-check": [
            "LATCHWAY_GATEWAY_EVIDENCE_PUBLIC_KEY_PEM",
            "LATCHWAY_GATEWAY_EVIDENCE_PUBLIC_KEY_SHA256",
            "LATCHWAY_LIVE_GATEWAY_BASE_URL",
            "LATCHWAY_LIVE_SDK_APPLICATION_ID",
            "LATCHWAY_LIVE_SDK_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_LIVE_SDK_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_LIVE_SDK_ENVIRONMENT",
            "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE",
            "LATCHWAY_LIVE_SDK_FEATURE",
            "LATCHWAY_LIVE_SDK_GRANT_SHA256",
            "LATCHWAY_LIVE_SDK_IDENTITY_PROVIDER",
            "LATCHWAY_LIVE_SDK_MODEL",
        ],
        "release-evidence-live-provider": [
            "LATCHWAY_LIVE_GATEWAY_BASE_URL",
            "LATCHWAY_LIVE_PROVIDER_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_LIVE_PROVIDER_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_LIVE_PROVIDER_ENVIRONMENT_ID",
            "LATCHWAY_LIVE_PROVIDER_GRANT_SHA256",
            "LATCHWAY_LIVE_PROVIDER_MAX_COST_NANO_USD",
            "LATCHWAY_LIVE_PROVIDER_MODEL_ID",
            "LATCHWAY_LIVE_PROVIDER_UPSTREAM_ID",
        ],
        "release-evidence-turnstile": [
            "LATCHWAY_GATEWAY_EVIDENCE_PUBLIC_KEY_PEM",
            "LATCHWAY_GATEWAY_EVIDENCE_PUBLIC_KEY_SHA256",
            "LATCHWAY_LIVE_GATEWAY_BASE_URL",
            "LATCHWAY_LIVE_SDK_APPLICATION_ID",
            "LATCHWAY_LIVE_SDK_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_LIVE_SDK_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_LIVE_SDK_ENVIRONMENT",
            "LATCHWAY_LIVE_SDK_ERROR_MAPPING_FEATURE",
            "LATCHWAY_LIVE_SDK_FEATURE",
            "LATCHWAY_LIVE_SDK_GRANT_SHA256",
            "LATCHWAY_LIVE_SDK_IDENTITY_PROVIDER",
            "LATCHWAY_LIVE_SDK_MODEL",
        ],
        "security-evidence": [
            "INDEPENDENT_SECURITY_REVIEWER_IDENTITY",
            "INDEPENDENT_SECURITY_REVIEWER_LOGIN",
            "INDEPENDENT_SECURITY_REVIEWER_ORGANIZATION",
            "INDEPENDENT_SECURITY_REVIEW_REPOSITORY",
            "INDEPENDENT_SECURITY_REVIEW_WORKFLOW",
        ],
    },
    "latchway-ios-sdk": {
        "app-attest-production": [
            "LATCHWAY_ACTION_COMPONENT_DEFINITION_ID",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_ASSERTION_DEVICE_GRANT_SHA256",
            "LATCHWAY_BASE_URL",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256",
            "LATCHWAY_CONTRACT_VERSION",
            "LATCHWAY_CORE_COMMIT",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_ERROR_MAPPING_FEATURE",
            "LATCHWAY_FEATURE",
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256",
            "LATCHWAY_GATEWAY_IMAGE_DIGEST",
            "LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL",
            "LATCHWAY_GATEWAY_ORIGIN",
            "LATCHWAY_HOST_COMPONENT_DEFINITION_ID",
            "LATCHWAY_IDENTITY_PROVIDER",
            "LATCHWAY_IOS_ACTION_BINARY_SHA256",
            "LATCHWAY_IOS_ACTION_BUNDLE_ID",
            "LATCHWAY_IOS_ACTION_PROVISIONING_PROFILE_UUID",
            "LATCHWAY_IOS_APP_BINARY_SHA256",
            "LATCHWAY_IOS_APP_BUNDLE_PATH",
            "LATCHWAY_IOS_APP_BUNDLE_TREE_SHA256",
            "LATCHWAY_IOS_APP_ID_PREFIX",
            "LATCHWAY_IOS_APP_VERSION",
            "LATCHWAY_IOS_BUILD_NUMBER",
            "LATCHWAY_IOS_BUNDLE_ID",
            "LATCHWAY_IOS_DISTRIBUTION",
            "LATCHWAY_IOS_HOST_PROVISIONING_PROFILE_UUID",
            "LATCHWAY_IOS_INSTALL_MODE",
            "LATCHWAY_IOS_SDK_VERSION",
            "LATCHWAY_IOS_SHARE_BINARY_SHA256",
            "LATCHWAY_IOS_SHARE_BUNDLE_ID",
            "LATCHWAY_IOS_SHARE_PROVISIONING_PROFILE_UUID",
            "LATCHWAY_IOS_SIGNING_CERTIFICATE_SHA256",
            "LATCHWAY_IOS_TEAM_ID",
            "LATCHWAY_IOS_WIDGET_BINARY_SHA256",
            "LATCHWAY_IOS_WIDGET_BUNDLE_ID",
            "LATCHWAY_IOS_WIDGET_PROVISIONING_PROFILE_UUID",
            "LATCHWAY_MODEL",
            "LATCHWAY_REGISTRATION_DEVICE_GRANT_SHA256",
            "LATCHWAY_SHARE_COMPONENT_DEFINITION_ID",
            "LATCHWAY_SOURCE_COMMIT",
            "LATCHWAY_WIDGET_COMPONENT_DEFINITION_ID",
            "LATCHWAY_XCODE_IDENTITY",
        ],
        "physical-evidence-signing": [
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_ASSERTION_DEVICE_GRANT_SHA256",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_IDENTITY_PROVIDER",
            "LATCHWAY_IOS_ACTION_BINARY_SHA256",
            "LATCHWAY_IOS_APP_BINARY_SHA256",
            "LATCHWAY_IOS_APP_BUNDLE_TREE_SHA256",
            "LATCHWAY_IOS_SHARE_BINARY_SHA256",
            "LATCHWAY_IOS_WIDGET_BINARY_SHA256",
            "LATCHWAY_REGISTRATION_DEVICE_GRANT_SHA256",
        ],
    },
    "latchway-android": {
        "maven-central": ["LATCHWAY_MAVEN_SIGNING_FINGERPRINT"],
        "maven-central-signing": ["LATCHWAY_MAVEN_SIGNING_FINGERPRINT"],
        "maven-publication-verification": [
            "LATCHWAY_MAVEN_SIGNING_FINGERPRINT"
        ],
        "physical-evidence-signing": [
            "LATCHWAY_ANDROID_DEVICE_GRANT_SHA256",
            "LATCHWAY_ANDROID_INSTALLED_APK_SET_SHA256",
            "LATCHWAY_ANDROID_PACKAGE_NAME",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_IDENTITY_PROVIDER",
        ],
        "play-candidate-build": [
            "LATCHWAY_ANDROID_APP_VERSION",
            "LATCHWAY_ANDROID_CLOUD_PROJECT_NUMBER",
            "LATCHWAY_ANDROID_PACKAGE_NAME",
            "LATCHWAY_ANDROID_PLAY_TRACK",
            "LATCHWAY_ANDROID_SDK_VERSION",
            "LATCHWAY_ANDROID_SIGNING_CERTIFICATE_SHA256",
            "LATCHWAY_ANDROID_VERSION_CODE",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256",
            "LATCHWAY_CONTRACT_VERSION",
            "LATCHWAY_CORE_COMMIT",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_ERROR_MAPPING_FEATURE",
            "LATCHWAY_FEATURE",
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256",
            "LATCHWAY_GATEWAY_IMAGE_DIGEST",
            "LATCHWAY_GATEWAY_ORIGIN",
            "LATCHWAY_IDENTITY_PROVIDER",
            "LATCHWAY_MODEL",
            "LATCHWAY_SOURCE_COMMIT",
        ],
        "play-candidate-verification": [
            "LATCHWAY_PLAY_AAB_VERIFIER_SHA256",
            "LATCHWAY_PLAY_UPLOAD_CERTIFICATE_SHA256",
        ],
        "play-integrity-production": [
            "LATCHWAY_ADB_VERSION",
            "LATCHWAY_ANDROID_APP_VERSION",
            "LATCHWAY_ANDROID_CLOUD_PROJECT_NUMBER",
            "LATCHWAY_ANDROID_DEVICE_GRANT_SHA256",
            "LATCHWAY_ANDROID_INSTALLED_APK_SET_SHA256",
            "LATCHWAY_ANDROID_PACKAGE_NAME",
            "LATCHWAY_ANDROID_PLAY_TRACK",
            "LATCHWAY_ANDROID_SDK_VERSION",
            "LATCHWAY_ANDROID_SIGNING_CERTIFICATE_SHA256",
            "LATCHWAY_ANDROID_VERSION_CODE",
            "LATCHWAY_APKSIGNER_VERSION",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256",
            "LATCHWAY_CONTRACT_VERSION",
            "LATCHWAY_CORE_COMMIT",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_ERROR_MAPPING_FEATURE",
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256",
            "LATCHWAY_GATEWAY_IMAGE_DIGEST",
            "LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL",
            "LATCHWAY_GATEWAY_ORIGIN",
            "LATCHWAY_IDENTITY_PROVIDER",
            "LATCHWAY_SOURCE_COMMIT",
        ],
        "play-upload-signing": [
            "LATCHWAY_PLAY_AAB_VERIFIER_SHA256",
            "LATCHWAY_PLAY_UPLOAD_CERTIFICATE_SHA256",
            "LATCHWAY_PLAY_UPLOAD_SIGNATURE_ALGORITHM",
        ],
    },
    "latchway-react-native-sdk": {
        "physical-evidence-signing": [
            "LATCHWAY_ANDROID_DEVICE_GRANT_SHA256",
            "LATCHWAY_ANDROID_INSTALLED_APK_SET_SHA256",
            "LATCHWAY_ANDROID_NATIVE_EVIDENCE_SHA256",
            "LATCHWAY_ANDROID_PACKAGE_NAME",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_IOS_APP_BINARY_SHA256",
            "LATCHWAY_IOS_APP_BUNDLE_TREE_SHA256",
            "LATCHWAY_IOS_APP_FILES_MANIFEST_SHA256",
            "LATCHWAY_IOS_BUNDLE_ID",
            "LATCHWAY_IOS_DEVICE_GRANT_SHA256",
            "LATCHWAY_IOS_JAVASCRIPT_BUNDLE_SHA256",
            "LATCHWAY_IOS_NATIVE_EVIDENCE_SHA256",
        ],
        "react-native-android-candidate-build": [
            "LATCHWAY_ANDROID_APP_VERSION",
            "LATCHWAY_ANDROID_CLOUD_PROJECT_NUMBER",
            "LATCHWAY_ANDROID_COMMIT",
            "LATCHWAY_ANDROID_NATIVE_EVIDENCE_PATH",
            "LATCHWAY_ANDROID_NATIVE_EVIDENCE_SHA256",
            "LATCHWAY_ANDROID_PACKAGE_NAME",
            "LATCHWAY_ANDROID_PLAY_TRACK",
            "LATCHWAY_ANDROID_SDK_PATH",
            "LATCHWAY_ANDROID_SDK_VERSION",
            "LATCHWAY_ANDROID_SIGNING_CERTIFICATE_SHA256",
            "LATCHWAY_ANDROID_VERSION_CODE",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256",
            "LATCHWAY_CONTRACT_VERSION",
            "LATCHWAY_CORE_COMMIT",
            "LATCHWAY_CORE_SOURCE_PATH",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_ERROR_MAPPING_FEATURE",
            "LATCHWAY_FEATURE",
            "LATCHWAY_FIREBASE_ANDROID_CONFIG_PATH",
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256",
            "LATCHWAY_GATEWAY_IMAGE_DIGEST",
            "LATCHWAY_GATEWAY_ORIGIN",
            "LATCHWAY_JAVASCRIPT_SDK_PATH",
            "LATCHWAY_MODEL",
            "LATCHWAY_RN_SDK_VERSION",
            "LATCHWAY_SOURCE_COMMIT",
        ],
        "react-native-android-candidate-verification": [
            "LATCHWAY_ANDROID_UPLOAD_CERTIFICATE_SHA256",
            "LATCHWAY_REACT_NATIVE_AAB_VERIFIER_SHA256",
        ],
        "react-native-android-production": [
            "LATCHWAY_ADB_VERSION",
            "LATCHWAY_ANDROID_APP_VERSION",
            "LATCHWAY_ANDROID_CLOUD_PROJECT_NUMBER",
            "LATCHWAY_ANDROID_COMMIT",
            "LATCHWAY_ANDROID_DEVICE_GRANT_SHA256",
            "LATCHWAY_ANDROID_INSTALLED_APK_SET_SHA256",
            "LATCHWAY_ANDROID_NATIVE_EVIDENCE_PATH",
            "LATCHWAY_ANDROID_NATIVE_EVIDENCE_SHA256",
            "LATCHWAY_ANDROID_NATIVE_PROFILE_PATH",
            "LATCHWAY_ANDROID_PACKAGE_NAME",
            "LATCHWAY_ANDROID_PLAY_TRACK",
            "LATCHWAY_ANDROID_SDK_VERSION",
            "LATCHWAY_ANDROID_SIGNING_CERTIFICATE_SHA256",
            "LATCHWAY_ANDROID_VERSION_CODE",
            "LATCHWAY_APKSIGNER_VERSION",
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256",
            "LATCHWAY_CONTRACT_VERSION",
            "LATCHWAY_CORE_COMMIT",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_ERROR_MAPPING_FEATURE",
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256",
            "LATCHWAY_GATEWAY_IMAGE_DIGEST",
            "LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL",
            "LATCHWAY_GATEWAY_ORIGIN",
            "LATCHWAY_RN_SDK_VERSION",
            "LATCHWAY_SOURCE_COMMIT",
        ],
        "react-native-android-upload-signing": [
            "LATCHWAY_ANDROID_UPLOAD_CERTIFICATE_SHA256",
            "LATCHWAY_ANDROID_UPLOAD_SIGNATURE_ALGORITHM",
            "LATCHWAY_REACT_NATIVE_AAB_VERIFIER_SHA256",
        ],
        "react-native-ios-production": [
            "LATCHWAY_APPLICATION_ID",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_PEM",
            "LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256",
            "LATCHWAY_CONTRACT_VERSION",
            "LATCHWAY_CORE_COMMIT",
            "LATCHWAY_ENVIRONMENT",
            "LATCHWAY_ERROR_MAPPING_FEATURE",
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH",
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256",
            "LATCHWAY_GATEWAY_IMAGE_DIGEST",
            "LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL",
            "LATCHWAY_GATEWAY_ORIGIN",
            "LATCHWAY_IOS_APPINTENTS_BUNDLE_ID",
            "LATCHWAY_IOS_APP_BINARY_SHA256",
            "LATCHWAY_IOS_APP_BUNDLE_PATH",
            "LATCHWAY_IOS_APP_BUNDLE_TREE_SHA256",
            "LATCHWAY_IOS_APP_FILES_MANIFEST_SHA256",
            "LATCHWAY_IOS_APP_ID_PREFIX",
            "LATCHWAY_IOS_APP_VERSION",
            "LATCHWAY_IOS_BUILD_NUMBER",
            "LATCHWAY_IOS_BUNDLE_ID",
            "LATCHWAY_IOS_COMMIT",
            "LATCHWAY_IOS_DEVICE_GRANT_SHA256",
            "LATCHWAY_IOS_DISTRIBUTION",
            "LATCHWAY_IOS_INSTALL_MODE",
            "LATCHWAY_IOS_JAVASCRIPT_BUNDLE_SHA256",
            "LATCHWAY_IOS_NATIVE_EVIDENCE_PATH",
            "LATCHWAY_IOS_NATIVE_EVIDENCE_SHA256",
            "LATCHWAY_IOS_NATIVE_PROFILE_PATH",
            "LATCHWAY_IOS_SDK_VERSION",
            "LATCHWAY_IOS_SHARED_KEYCHAIN_ACCESS_GROUP",
            "LATCHWAY_IOS_SIGNING_CERTIFICATE_SHA256",
            "LATCHWAY_IOS_TEAM_ID",
            "LATCHWAY_RN_SDK_VERSION",
            "LATCHWAY_SOURCE_COMMIT",
            "LATCHWAY_XCODE_IDENTITY",
        ],
    }
}
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SECRET_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
REVIEWER_SELECTOR = re.compile(
    r"^(?P<kind>user|team):(?P<name>[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?)$"
)


class ControlError(Exception):
    """A stable, credential-free release-control failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class NotFound(ControlError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControlError(code)
    return value


def require_array(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list):
        raise ControlError(code)
    return value


def require_keys(value: Mapping[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise ControlError(code)


def validate_string_list(
    value: Any, *, pattern: re.Pattern[str], code: str
) -> list[str]:
    result = require_array(value, code)
    if (
        any(not isinstance(item, str) or pattern.fullmatch(item) is None for item in result)
        or len(result) != len(set(result))
    ):
        raise ControlError(code)
    return result


def is_single_maintainer_administration(
    repository: str, environment: Mapping[str, Any]
) -> bool:
    return (
        repository in SINGLE_MAINTAINER_PRODUCT_REPOSITORIES
        and environment.get("name")
        == SINGLE_MAINTAINER_ADMINISTRATION_ENVIRONMENT
    )


def single_maintainer_administration_policy_id(repository: str) -> str:
    if repository not in SINGLE_MAINTAINER_PRODUCT_REPOSITORIES:
        raise ControlError("single_maintainer_administration_repository_invalid")
    return (
        f"latchway-release-profile-v1:{repository}:"
        "single_maintainer_v1:administration"
    )


def environment_policy_variable_name(
    repository: str, environment: Mapping[str, Any]
) -> str:
    if is_single_maintainer_administration(repository, environment):
        return PROFILE_POLICY_VARIABLE_NAME
    return POLICY_VARIABLE_NAME


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = require_object(value, "manifest_not_object")
    require_keys(
        manifest,
        {
            "$schema",
            "schema_version",
            "kind",
            "api_version",
            "control_id",
            "forbidden_secret_names",
            "organization",
            "policy_variable_name",
            "protected_secret_scope",
            "repositories",
            "npm_trusted_publishers",
        },
        "manifest_fields_invalid",
    )
    if (
        not isinstance(manifest["$schema"], str)
        or not manifest["$schema"]
        or manifest["schema_version"] != 1
        or manifest["kind"] != "latchway_github_release_controls"
        or manifest["api_version"] != "2026-03-10"
        or manifest["control_id"] != "latchway-release-controls-v1"
        or manifest["forbidden_secret_names"]
        != EXPECTED_FORBIDDEN_SECRET_NAMES
        or manifest["organization"] != "Latchway"
        or manifest["policy_variable_name"] != POLICY_VARIABLE_NAME
        or manifest["protected_secret_scope"] != "environment_only"
    ):
        raise ControlError("manifest_identity_invalid")

    repositories = require_array(manifest["repositories"], "repositories_invalid")
    if len(repositories) != 6:
        raise ControlError("repository_count_invalid")
    names: set[str] = set()
    for raw_repository in repositories:
        repository = require_object(raw_repository, "repository_invalid")
        require_keys(
            repository,
            {"name", "default_branch", "environments", "rulesets"},
            "repository_fields_invalid",
        )
        name = repository["name"]
        if (
            not isinstance(name, str)
            or NAME.fullmatch(name) is None
            or name in names
            or repository["default_branch"] != "main"
        ):
            raise ControlError("repository_identity_invalid")
        names.add(name)

        environments = require_array(
            repository["environments"], "environments_invalid"
        )
        if not environments:
            raise ControlError("environment_count_invalid")
        environment_names: set[str] = set()
        environment_inventory: dict[str, list[str]] = {}
        environment_variable_inventory: dict[str, list[str]] = {}
        for raw_environment in environments:
            environment = require_object(raw_environment, "environment_invalid")
            environment_fields = {
                "name",
                "policy_id",
                "reviewers",
                "prevent_self_review",
                "deployment",
                "secrets",
            }
            if "variables" in environment:
                environment_fields.add("variables")
            require_keys(
                environment,
                environment_fields,
                "environment_fields_invalid",
            )
            environment_name = environment["name"]
            profile_administration = is_single_maintainer_administration(
                name, environment
            )
            expected_policy_id = (
                single_maintainer_administration_policy_id(name)
                if profile_administration
                else f"{manifest['control_id']}:{name}:{environment_name}"
            )
            expected_prevent_self_review = not profile_administration
            if (
                not isinstance(environment_name, str)
                or NAME.fullmatch(environment_name) is None
                or environment_name in environment_names
                or environment["policy_id"] != expected_policy_id
                or environment["prevent_self_review"]
                is not expected_prevent_self_review
            ):
                raise ControlError("environment_identity_invalid")
            environment_names.add(environment_name)

            reviewers = require_object(
                environment["reviewers"], "environment_reviewers_invalid"
            )
            require_keys(
                reviewers, {"minimum", "source"}, "environment_reviewers_invalid"
            )
            expected_reviewer_policy = (
                (0, "profile_policy")
                if profile_administration
                else (1, "command_line")
            )
            if (
                isinstance(reviewers["minimum"], bool)
                or (reviewers["minimum"], reviewers["source"])
                != expected_reviewer_policy
            ):
                raise ControlError("environment_reviewers_invalid")

            deployment = require_object(
                environment["deployment"], "environment_deployment_invalid"
            )
            require_keys(
                deployment,
                {"mode", "branches", "tags"},
                "environment_deployment_invalid",
            )
            if (
                deployment["mode"] != "selected"
                or deployment["branches"] != ["main"]
                or deployment["tags"] != []
            ):
                raise ControlError("environment_deployment_not_main_only")

            secrets = require_object(
                environment["secrets"], "environment_secrets_invalid"
            )
            require_keys(
                secrets,
                {"required_names", "allowed_names"},
                "environment_secrets_invalid",
            )
            required = set(
                validate_string_list(
                    secrets["required_names"],
                    pattern=SECRET_NAME,
                    code="environment_secret_names_invalid",
                )
            )
            allowed = set(
                validate_string_list(
                    secrets["allowed_names"],
                    pattern=SECRET_NAME,
                    code="environment_secret_names_invalid",
                )
            )
            if required != allowed:
                raise ControlError("environment_secret_inventory_not_exact")
            environment_inventory[environment_name] = sorted(allowed)

            variables = require_object(
                environment.get(
                    "variables", {"required_names": [], "allowed_names": []}
                ),
                "environment_variables_invalid",
            )
            require_keys(
                variables,
                {"required_names", "allowed_names"},
                "environment_variables_invalid",
            )
            required_variables = set(
                validate_string_list(
                    variables["required_names"],
                    pattern=SECRET_NAME,
                    code="environment_variable_names_invalid",
                )
            )
            allowed_variables = set(
                validate_string_list(
                    variables["allowed_names"],
                    pattern=SECRET_NAME,
                    code="environment_variable_names_invalid",
                )
            )
            if required_variables != allowed_variables:
                raise ControlError("environment_variable_inventory_not_exact")
            environment_variable_inventory[environment_name] = sorted(
                allowed_variables
            )

        if environment_inventory != EXPECTED_ENVIRONMENTS[name]:
            raise ControlError("environment_topology_invalid")
        expected_variables = {
            environment_name: EXPECTED_ENVIRONMENT_VARIABLES.get(name, {}).get(
                environment_name, []
            )
            for environment_name in environment_inventory
        }
        if environment_variable_inventory != expected_variables:
            raise ControlError("environment_variable_topology_invalid")

        rulesets = require_array(repository["rulesets"], "rulesets_invalid")
        if len(rulesets) != 2:
            raise ControlError("ruleset_count_invalid")
        by_name: dict[str, dict[str, Any]] = {}
        for raw_ruleset in rulesets:
            ruleset = require_object(raw_ruleset, "ruleset_invalid")
            require_keys(
                ruleset,
                {
                    "name",
                    "target",
                    "enforcement",
                    "bypass_actors",
                    "conditions",
                    "rules",
                },
                "ruleset_fields_invalid",
            )
            ruleset_name = ruleset.get("name")
            if not isinstance(ruleset_name, str) or ruleset_name in by_name:
                raise ControlError("ruleset_identity_invalid")
            by_name[ruleset_name] = ruleset

        tag_ruleset = by_name.get("latchway-v1-tags-immutable")
        if tag_ruleset is None or (
            tag_ruleset["target"] != "tag"
            or tag_ruleset["enforcement"] != "active"
            or tag_ruleset["bypass_actors"] != GITHUB_ACTIONS_BYPASS
            or tag_ruleset["conditions"]
            != {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}}
            or normalize_rules(tag_ruleset["rules"])
            != normalize_rules(
                [
                    {"type": "creation"},
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": False},
                    },
                    {"type": "deletion"},
                ]
            )
        ):
            raise ControlError("ruleset_not_immutable_v1_tags")

        branch_ruleset = by_name.get("latchway-main-protected")
        expected_checks = [
            {"context": context, "integration_id": GITHUB_ACTIONS_APP["id"]}
            for context in EXPECTED_STATUS_CONTEXTS[name]
        ]
        expected_branch_rules = [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["squash", "rebase"],
                    "dismiss_stale_reviews_on_push": False,
                    "require_code_owner_review": name == "latchway-docs",
                    "require_last_push_approval": False,
                    "required_approving_review_count": (
                        1 if name == "latchway-docs" else 0
                    ),
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": expected_checks,
                    "strict_required_status_checks_policy": True,
                },
            },
        ]
        if branch_ruleset is None or (
            branch_ruleset["target"] != "branch"
            or branch_ruleset["enforcement"] != "active"
            or branch_ruleset["bypass_actors"] != []
            or branch_ruleset["conditions"]
            != {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
            or normalize_rules(branch_ruleset["rules"])
            != normalize_rules(expected_branch_rules)
        ):
            raise ControlError("ruleset_not_protected_main")

    if names != EXPECTED_REPOSITORIES:
        raise ControlError("repository_set_invalid")

    publishers = require_array(
        manifest["npm_trusted_publishers"], "npm_publishers_invalid"
    )
    if len(publishers) != 5:
        raise ControlError("npm_publisher_count_invalid")
    coordinates: set[tuple[str, str]] = set()
    for raw_publisher in publishers:
        publisher = require_object(raw_publisher, "npm_publisher_invalid")
        require_keys(
            publisher,
            {
                "package",
                "provider",
                "repository",
                "workflow",
                "environment",
                "permissions",
            },
            "npm_publisher_fields_invalid",
        )
        package = publisher["package"]
        repository = publisher["repository"]
        if (
            not isinstance(package, str)
            or not package.startswith("@latchway/")
            or not isinstance(repository, str)
            or publisher["provider"] != "github"
            or publisher["workflow"] != "release.yml"
            or publisher["environment"] != "npm"
            or publisher["permissions"] != ["createPackage"]
        ):
            raise ControlError("npm_publisher_coordinate_invalid")
        coordinate = (package, repository)
        if coordinate in coordinates:
            raise ControlError("npm_publisher_duplicate")
        coordinates.add(coordinate)
    if coordinates != EXPECTED_NPM_PUBLISHERS:
        raise ControlError("npm_publisher_set_invalid")
    return manifest


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ControlError("manifest_unreadable") from None
    manifest = validate_manifest(value)
    if raw != json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n":
        raise ControlError("manifest_not_canonical_pretty_json")
    return manifest, sha256_bytes(raw)


@dataclass(frozen=True, order=True)
class ReviewerSelector:
    kind: str
    name: str

    @property
    def github_type(self) -> str:
        return "User" if self.kind == "user" else "Team"

    @property
    def text(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(frozen=True, order=True)
class ResolvedReviewer:
    github_type: str
    identifier: int
    selector: str

    def api_value(self) -> dict[str, Any]:
        return {"type": self.github_type, "id": self.identifier}


def parse_reviewers(values: Sequence[str]) -> list[ReviewerSelector]:
    selectors: list[ReviewerSelector] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        match = REVIEWER_SELECTOR.fullmatch(value)
        if match is None:
            raise ControlError("reviewer_selector_invalid")
        selector = ReviewerSelector(match.group("kind"), match.group("name"))
        key = (selector.kind, selector.name.lower())
        if key in seen:
            raise ControlError("reviewer_selector_duplicate")
        seen.add(key)
        selectors.append(selector)
    if not selectors or len(selectors) > 6:
        raise ControlError("reviewer_selector_count_invalid")
    return sorted(selectors)


def with_query(path: str, **values: str) -> str:
    parsed = urlparse(path)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(values)
    return urlunparse(parsed._replace(query=urlencode(query)))


def parse_next_link(
    header: str | None, *, current_url: str, api_base: str
) -> str | None:
    if not header:
        return None
    next_urls: list[str] = []
    for raw_entry in header.split(","):
        pieces = [piece.strip() for piece in raw_entry.split(";")]
        if not pieces or not pieces[0].startswith("<") or not pieces[0].endswith(">"):
            raise ControlError("github_pagination_link_invalid")
        relations = []
        for piece in pieces[1:]:
            if piece.startswith('rel="') and piece.endswith('"'):
                relations.extend(piece[5:-1].split())
        if "next" in relations:
            next_urls.append(pieces[0][1:-1])
    if len(next_urls) > 1:
        raise ControlError("github_pagination_next_ambiguous")
    if not next_urls:
        return None
    candidate = urljoin(current_url, next_urls[0])
    expected = urlparse(api_base)
    parsed = urlparse(candidate)
    if (
        parsed.scheme != expected.scheme
        or parsed.netloc != expected.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (
            expected.path.rstrip("/")
            and parsed.path != expected.path.rstrip("/")
            and not parsed.path.startswith(expected.path.rstrip("/") + "/")
        )
    ):
        raise ControlError("github_pagination_next_untrusted")
    return candidate


class GitHubAPI:
    def __init__(self, token: str, api_version: str, api_base: str = DEFAULT_API_BASE):
        if not token:
            raise ControlError("github_token_missing")
        parsed = urlparse(api_base)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
        ):
            raise ControlError("github_api_base_invalid")
        self.token = token
        self.api_version = api_version
        self.api_base = api_base.rstrip("/")

    def request(
        self, method: str, path_or_url: str, body: Any | None = None
    ) -> tuple[Any, Mapping[str, str]]:
        url = (
            path_or_url
            if path_or_url.startswith("http://") or path_or_url.startswith("https://")
            else self.api_base + "/" + path_or_url.lstrip("/")
        )
        data = None if body is None else canonical_bytes(body).rstrip(b"\n")
        request = Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "latchway-release-controls/1",
                "X-GitHub-Api-Version": self.api_version,
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise ControlError("github_response_too_large")
                try:
                    payload = json.loads(raw) if raw else None
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ControlError("github_response_not_json") from None
                return payload, dict(response.headers.items())
        except HTTPError as error:
            if error.code == 404:
                raise NotFound("github_resource_not_found") from None
            if error.code == 403:
                raise ControlError("github_api_forbidden") from None
            if error.code == 401:
                raise ControlError("github_api_unauthorized") from None
            if error.code == 422:
                raise ControlError("github_api_validation_failed") from None
            raise ControlError(f"github_api_http_{error.code}") from None
        except (URLError, TimeoutError, OSError):
            raise ControlError("github_api_unavailable") from None

    def get(self, path: str) -> Any:
        payload, _ = self.request("GET", path)
        return payload

    def collection(self, path: str, key: str | None = None) -> list[Any]:
        next_url: str | None = self.api_base + "/" + with_query(
            path.lstrip("/"), per_page="100"
        )
        visited: set[str] = set()
        result: list[Any] = []
        declared_total: int | None = None
        pages = 0
        while next_url is not None:
            if next_url in visited or pages >= 100:
                raise ControlError("github_pagination_cycle_or_limit")
            visited.add(next_url)
            pages += 1
            payload, headers = self.request("GET", next_url)
            if key is None:
                items = require_array(payload, "github_collection_invalid")
            else:
                container = require_object(payload, "github_collection_invalid")
                if not {key, "total_count"} <= set(container):
                    raise ControlError("github_collection_fields_missing")
                total = container["total_count"]
                if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                    raise ControlError("github_collection_total_invalid")
                if declared_total is None:
                    declared_total = total
                elif declared_total != total:
                    raise ControlError("github_collection_total_changed")
                items = require_array(container[key], "github_collection_items_invalid")
            if len(items) > 100:
                raise ControlError("github_collection_page_too_large")
            result.extend(items)
            parsed_next = parse_next_link(
                headers.get("Link") or headers.get("link"),
                current_url=next_url,
                api_base=self.api_base,
            )
            if key is None and parsed_next is None and len(items) == 100:
                raise ControlError("github_pagination_completion_ambiguous")
            if parsed_next is not None and not items:
                raise ControlError("github_pagination_empty_page")
            next_url = parsed_next
        if declared_total is not None and declared_total != len(result):
            raise ControlError("github_collection_truncated")
        return result

    def put(self, path: str, body: Any) -> Any:
        payload, _ = self.request("PUT", path, body)
        return payload

    def post(self, path: str, body: Any) -> Any:
        payload, _ = self.request("POST", path, body)
        return payload

    def patch(self, path: str, body: Any) -> Any:
        payload, _ = self.request("PATCH", path, body)
        return payload


def quoted(value: str) -> str:
    return quote(value, safe="")


def resolve_reviewers(
    client: GitHubAPI, organization: str, selectors: Sequence[ReviewerSelector]
) -> list[ResolvedReviewer]:
    result: list[ResolvedReviewer] = []
    identifiers: set[tuple[str, int]] = set()
    for selector in selectors:
        if selector.kind == "user":
            payload = require_object(
                client.get(f"/users/{quoted(selector.name)}"),
                "reviewer_resolution_invalid",
            )
        else:
            payload = require_object(
                client.get(
                    f"/orgs/{quoted(organization)}/teams/{quoted(selector.name)}"
                ),
                "reviewer_resolution_invalid",
            )
        identifier = payload.get("id")
        if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier <= 0:
            raise ControlError("reviewer_identifier_invalid")
        key = (selector.github_type, identifier)
        if key in identifiers:
            raise ControlError("reviewer_identifier_duplicate")
        identifiers.add(key)
        result.append(
            ResolvedReviewer(selector.github_type, identifier, selector.text)
        )
    return sorted(result)


def normalize_rules(value: Any) -> list[dict[str, Any]]:
    rules = require_array(value, "ruleset_rules_invalid")
    normalized: list[dict[str, Any]] = []
    for raw_rule in rules:
        rule = require_object(raw_rule, "ruleset_rule_invalid")
        if not {"type"} <= set(rule) <= {"type", "parameters"}:
            raise ControlError("ruleset_rule_fields_invalid")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str):
            raise ControlError("ruleset_rule_type_invalid")
        item: dict[str, Any] = {"type": rule_type}
        if "parameters" in rule:
            parameters = require_object(
                rule["parameters"], "ruleset_rule_parameters_invalid"
            ).copy()
            if rule_type == "required_status_checks" and isinstance(
                parameters.get("required_status_checks"), list
            ):
                parameters["required_status_checks"] = sorted(
                    parameters["required_status_checks"], key=canonical_bytes
                )
            if rule_type == "pull_request" and isinstance(
                parameters.get("allowed_merge_methods"), list
            ):
                parameters["allowed_merge_methods"] = sorted(
                    parameters["allowed_merge_methods"]
                )
            item["parameters"] = parameters
        normalized.append(item)
    return sorted(normalized, key=lambda item: canonical_bytes(item))


def environment_path(organization: str, repository: str, environment: str) -> str:
    return (
        f"/repos/{quoted(organization)}/{quoted(repository)}/environments/"
        f"{quoted(environment)}"
    )


def quarantine_policy_value(desired: Mapping[str, Any]) -> str:
    policy_id = desired.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        raise ControlError("environment_policy_id_invalid")
    return policy_id + QUARANTINE_SUFFIX


def environment_body(
    desired: Mapping[str, Any], reviewers: Sequence[ResolvedReviewer], wait_timer: int = 0
) -> dict[str, Any]:
    return {
        "wait_timer": wait_timer,
        "prevent_self_review": desired["prevent_self_review"],
        "reviewers": [reviewer.api_value() for reviewer in reviewers],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def actual_reviewers(environment: Mapping[str, Any]) -> tuple[set[tuple[str, int]], bool, int]:
    rules = require_array(
        environment.get("protection_rules", []), "environment_protection_rules_invalid"
    )
    rule_types = {
        rule.get("type") for rule in rules if isinstance(rule, dict)
    }
    if len(rule_types) != len(rules) or not rule_types <= {
        "branch_policy",
        "required_reviewers",
        "wait_timer",
    }:
        raise ControlError("environment_protection_rule_unrecognized")
    reviewer_rules = [rule for rule in rules if isinstance(rule, dict) and rule.get("type") == "required_reviewers"]
    if len(reviewer_rules) > 1:
        raise ControlError("environment_reviewer_rule_ambiguous")
    wait_rules = [rule for rule in rules if isinstance(rule, dict) and rule.get("type") == "wait_timer"]
    if len(wait_rules) > 1:
        raise ControlError("environment_wait_rule_ambiguous")
    wait_timer = 0
    if wait_rules:
        raw_wait = wait_rules[0].get("wait_timer")
        if not isinstance(raw_wait, int) or isinstance(raw_wait, bool) or raw_wait < 0:
            raise ControlError("environment_wait_timer_invalid")
        wait_timer = raw_wait
    if not reviewer_rules:
        return set(), False, wait_timer
    rule = reviewer_rules[0]
    prevent = rule.get("prevent_self_review")
    if not isinstance(prevent, bool):
        raise ControlError("environment_prevent_self_review_invalid")
    raw_reviewers = require_array(rule.get("reviewers"), "environment_reviewers_invalid")
    result: set[tuple[str, int]] = set()
    for raw_reviewer in raw_reviewers:
        reviewer = require_object(raw_reviewer, "environment_reviewer_invalid")
        reviewer_type = reviewer.get("type")
        nested = require_object(reviewer.get("reviewer"), "environment_reviewer_invalid")
        identifier = nested.get("id")
        if reviewer_type not in {"User", "Team"} or not isinstance(identifier, int) or identifier <= 0:
            raise ControlError("environment_reviewer_invalid")
        result.add((reviewer_type, identifier))
    if len(result) != len(raw_reviewers):
        raise ControlError("environment_reviewer_invalid")
    return result, prevent, wait_timer


def finding(
    repository: str,
    control: str,
    name: str,
    status: str,
    code: str,
    **details: Any,
) -> dict[str, Any]:
    value = {
        "repository": repository,
        "control": control,
        "name": name,
        "status": status,
        "code": code,
    }
    value.update(details)
    return value


def listed_control_names(value: Any, code: str) -> list[str]:
    items = require_array(value, code)
    names = sorted(
        item.get("name")
        for item in items
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )
    if len(names) != len(items) or len(names) != len(set(names)):
        raise ControlError(code)
    return names


def mutation(method: str, path: str, reason: str, body: Any) -> dict[str, Any]:
    if method not in {"PUT", "POST", "PATCH"}:
        raise ControlError("unsafe_mutation_method")
    return {"method": method, "path": path, "reason": reason, "body": body}


def inspect_repository_rulesets(
    client: GitHubAPI,
    organization: str,
    repository: str,
    desired_rulesets: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, list[str]]:
    """Inspect repository rules before any environment can receive its final seal."""

    checks: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    destructive_drift = False
    sealing_blockers: list[str] = []
    base = f"/repos/{quoted(organization)}/{quoted(repository)}/rulesets"
    summaries = client.collection(base + "?includes_parents=false")
    for raw_summary in summaries:
        summary = require_object(raw_summary, "ruleset_summary_invalid")
        if (
            not isinstance(summary.get("id"), int)
            or isinstance(summary.get("id"), bool)
            or summary["id"] <= 0
            or not isinstance(summary.get("name"), str)
            or not summary["name"]
        ):
            raise ControlError("ruleset_summary_invalid")

    for desired_ruleset in desired_rulesets:
        name = desired_ruleset["name"]
        kind = (
            "tag_immutability"
            if desired_ruleset["target"] == "tag"
            else "main_branch"
        )
        matches = [summary for summary in summaries if summary.get("name") == name]
        if not matches:
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "missing",
                    f"{kind}_ruleset_missing",
                )
            )
            mutations.append(
                mutation(
                    "POST",
                    base,
                    "create_repository_ruleset",
                    desired_ruleset,
                )
            )
            sealing_blockers.append(f"repository_ruleset_missing:{name}")
            continue
        if len(matches) != 1:
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "drift",
                    "duplicate_managed_ruleset_identity_requires_manual_remediation",
                    matches=len(matches),
                )
            )
            destructive_drift = True
            sealing_blockers.append(f"repository_ruleset_not_exact:{name}")
            continue
        identifier = matches[0]["id"]
        try:
            raw_remote = client.get(f"{base}/{identifier}")
        except NotFound:
            raw_remote = None
        if not isinstance(raw_remote, dict) or "bypass_actors" not in raw_remote:
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "drift",
                    "managed_ruleset_controls_unobservable_requires_manual_remediation",
                )
            )
            destructive_drift = True
            sealing_blockers.append(f"repository_ruleset_not_exact:{name}")
            continue
        remote = raw_remote
        try:
            actual_rules = normalize_rules(remote.get("rules"))
        except ControlError:
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "drift",
                    "managed_ruleset_controls_unobservable_requires_manual_remediation",
                )
            )
            destructive_drift = True
            sealing_blockers.append(f"repository_ruleset_not_exact:{name}")
            continue
        actual_projection = {
            "name": remote.get("name"),
            "target": remote.get("target"),
            "enforcement": remote.get("enforcement"),
            "bypass_actors": remote.get("bypass_actors"),
            "conditions": remote.get("conditions"),
            "rules": actual_rules,
        }
        desired_projection = {
            **desired_ruleset,
            "rules": normalize_rules(desired_ruleset["rules"]),
        }
        immutable_fields_match = all(
            actual_projection[key] == desired_projection[key]
            for key in ("name", "target", "bypass_actors", "conditions")
        )
        actual_rule_bytes = {
            canonical_bytes(rule) for rule in actual_projection["rules"]
        }
        desired_rule_bytes = {
            canonical_bytes(rule) for rule in desired_projection["rules"]
        }
        extra_rules = actual_rule_bytes - desired_rule_bytes
        duplicate_actual_rules = len(actual_rule_bytes) != len(
            actual_projection["rules"]
        )
        if not immutable_fields_match or extra_rules or duplicate_actual_rules:
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "drift",
                    "unknown_or_bypassed_ruleset_requires_manual_remediation",
                    actual=actual_projection,
                    expected=desired_projection,
                )
            )
            destructive_drift = True
            sealing_blockers.append(f"repository_ruleset_not_exact:{name}")
        elif (
            actual_projection["enforcement"] != "active"
            or actual_rule_bytes != desired_rule_bytes
        ):
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "drift",
                    f"{kind}_ruleset_incomplete",
                )
            )
            mutations.append(
                mutation(
                    "PUT",
                    f"{base}/{identifier}",
                    "activate_or_complete_repository_ruleset",
                    {
                        **desired_ruleset,
                        # The actual rules have already been proven to be a strict
                        # subset of the desired set. Sending the desired set once
                        # completes it without duplicating an existing rule type.
                        "rules": desired_projection["rules"],
                    },
                )
            )
            sealing_blockers.append(f"repository_ruleset_incomplete:{name}")
        else:
            checks.append(
                finding(
                    repository,
                    "ruleset",
                    name,
                    "passed",
                    f"{kind}_ruleset_exact",
                )
            )

    return checks, mutations, destructive_drift, sealing_blockers


def inspect_github(
    client: GitHubAPI,
    manifest: Mapping[str, Any],
    reviewers: Sequence[ResolvedReviewer],
    selected_repositories: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    checks: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    destructive_drift = False
    organization = manifest["organization"]
    policy_variable_names = {
        environment_policy_variable_name(repository["name"], environment)
        for repository in manifest["repositories"]
        for environment in repository["environments"]
    }

    actions_app = require_object(
        client.get("/apps/github-actions"), "github_actions_app_response_invalid"
    )
    actual_app = {"id": actions_app.get("id"), "slug": actions_app.get("slug")}
    if actual_app != GITHUB_ACTIONS_APP:
        raise ControlError("github_actions_app_identity_drift")
    checks.append(
        finding(
            organization,
            "integration",
            GITHUB_ACTIONS_APP["slug"],
            "passed",
            "github_actions_app_identity_exact",
            id=GITHUB_ACTIONS_APP["id"],
        )
    )

    organization_variables = client.collection(
        f"/orgs/{quoted(organization)}/actions/variables", "variables"
    )
    organization_variable_scopes: dict[str, tuple[str, set[str]]] = {}
    for raw_variable in organization_variables:
        variable = require_object(
            raw_variable, "organization_variable_list_invalid"
        )
        variable_name = variable.get("name")
        visibility = variable.get("visibility")
        if (
            not isinstance(variable_name, str)
            or not variable_name
            or visibility not in {"all", "private", "selected"}
            or variable_name in organization_variable_scopes
        ):
            raise ControlError("organization_variable_list_invalid")
        visible_repositories: set[str] = set()
        if visibility == "selected":
            selected = client.collection(
                f"/orgs/{quoted(organization)}/actions/variables/"
                f"{quoted(variable_name)}/repositories",
                "repositories",
            )
            for raw_selected_repository in selected:
                selected_repository = require_object(
                    raw_selected_repository,
                    "organization_variable_repository_list_invalid",
                )
                full_name = selected_repository.get("full_name")
                if not isinstance(full_name, str) or not full_name:
                    raise ControlError(
                        "organization_variable_repository_list_invalid"
                    )
                visible_repositories.add(full_name)
            if len(visible_repositories) != len(selected):
                raise ControlError(
                    "organization_variable_repository_list_invalid"
                )
        organization_variable_scopes[variable_name] = (
            visibility,
            visible_repositories,
        )
    organization_variable_names = set(organization_variable_scopes)
    organization_policy_fallbacks = (
        policy_variable_names & organization_variable_names
    )
    organization_policy_fallback_absent = not organization_policy_fallbacks
    for policy_variable_name in sorted(policy_variable_names):
        if policy_variable_name in organization_policy_fallbacks:
            checks.append(
                finding(
                    organization,
                    "organization_variable",
                    policy_variable_name,
                    "drift",
                    "organization_policy_sentinel_fallback_requires_manual_remediation",
                )
            )
            destructive_drift = True
        else:
            checks.append(
                finding(
                    organization,
                    "organization_variable",
                    policy_variable_name,
                    "passed",
                    "organization_policy_sentinel_fallback_absent",
                )
            )

    protected_secret_names = {
        secret_name
        for repository in manifest["repositories"]
        for environment in repository["environments"]
        for secret_name in environment["secrets"]["allowed_names"]
    } | set(manifest["forbidden_secret_names"])
    raw_organization_secrets = client.collection(
        f"/orgs/{quoted(organization)}/actions/secrets", "secrets"
    )
    organization_secret_scopes: dict[str, tuple[str, set[str]]] = {}
    for raw_secret in raw_organization_secrets:
        secret = require_object(raw_secret, "organization_secret_list_invalid")
        secret_name = secret.get("name")
        visibility = secret.get("visibility")
        if (
            not isinstance(secret_name, str)
            or not secret_name
            or secret_name in organization_secret_scopes
            or visibility not in {"all", "private", "selected"}
        ):
            raise ControlError("organization_secret_list_invalid")
        visible_repositories: set[str] = set()
        if visibility == "selected" and secret_name in protected_secret_names:
            raw_repositories = client.collection(
                f"/orgs/{quoted(organization)}/actions/secrets/"
                f"{quoted(secret_name)}/repositories",
                "repositories",
            )
            for raw_repository in raw_repositories:
                selected_repository = require_object(
                    raw_repository, "organization_secret_repository_list_invalid"
                )
                full_name = selected_repository.get("full_name")
                if not isinstance(full_name, str) or not full_name:
                    raise ControlError(
                        "organization_secret_repository_list_invalid"
                    )
                visible_repositories.add(full_name)
            if len(visible_repositories) != len(raw_repositories):
                raise ControlError("organization_secret_repository_list_invalid")
        organization_secret_scopes[secret_name] = (
            visibility,
            visible_repositories,
        )

    authenticated = require_object(
        client.get("/user"), "authenticated_github_actor_invalid"
    )
    authenticated_id = authenticated.get("id")
    authenticated_login = authenticated.get("login")
    if (
        not isinstance(authenticated_id, int)
        or isinstance(authenticated_id, bool)
        or authenticated_id <= 0
        or not isinstance(authenticated_login, str)
        or not authenticated_login
    ):
        raise ControlError("authenticated_github_actor_invalid")
    distinct_reviewers: list[str] = []
    for reviewer in reviewers:
        if reviewer.github_type == "User":
            if reviewer.identifier != authenticated_id:
                distinct_reviewers.append(reviewer.selector)
            continue
        if reviewer.github_type != "Team" or not reviewer.selector.startswith("team:"):
            raise ControlError("resolved_reviewer_type_invalid")
        team_slug = reviewer.selector.split(":", 1)[1]
        members = client.collection(
            f"/orgs/{quoted(organization)}/teams/{quoted(team_slug)}/members"
        )
        member_ids: set[int] = set()
        for raw_member in members:
            member = require_object(raw_member, "reviewer_team_member_invalid")
            member_id = member.get("id")
            if (
                not isinstance(member_id, int)
                or isinstance(member_id, bool)
                or member_id <= 0
            ):
                raise ControlError("reviewer_team_member_invalid")
            member_ids.add(member_id)
        if len(member_ids) != len(members):
            raise ControlError("reviewer_team_member_invalid")
        if any(member_id != authenticated_id for member_id in member_ids):
            distinct_reviewers.append(reviewer.selector)
    if distinct_reviewers:
        checks.append(
            finding(
                organization,
                "reviewer_independence",
                authenticated_login,
                "passed",
                "distinct_release_reviewer_available",
                reviewers=sorted(distinct_reviewers),
            )
        )
    else:
        checks.append(
            finding(
                organization,
                "reviewer_independence",
                authenticated_login,
                "drift",
                "distinct_release_reviewer_required",
            )
        )
        destructive_drift = True
    independent_reviewer_available = bool(distinct_reviewers)

    for desired_repository in manifest["repositories"]:
        repository = desired_repository["name"]
        if repository not in selected_repositories:
            continue
        metadata = require_object(
            client.get(f"/repos/{quoted(organization)}/{quoted(repository)}"),
            "repository_metadata_invalid",
        )
        repository_is_private = metadata.get("private")
        if not isinstance(repository_is_private, bool):
            raise ControlError("repository_visibility_unobservable")
        repository_sealing_blockers: list[str] = []
        if not organization_policy_fallback_absent:
            repository_sealing_blockers.append(
                "organization_policy_sentinel_fallback"
            )
        if not independent_reviewer_available:
            repository_sealing_blockers.append("independent_reviewer_unavailable")
        if metadata.get("default_branch") != desired_repository["default_branch"]:
            checks.append(
                finding(
                    repository,
                    "repository",
                    repository,
                    "drift",
                    "default_branch_drift",
                    actual=metadata.get("default_branch"),
                    expected="main",
                )
            )
            destructive_drift = True
            repository_sealing_blockers.append("default_branch_not_exact")
        else:
            checks.append(
                finding(
                    repository,
                    "repository",
                    repository,
                    "passed",
                    "default_branch_main",
                )
            )

        repository_variables = client.collection(
            f"/repos/{quoted(organization)}/{quoted(repository)}/actions/variables",
            "variables",
        )
        repository_variable_names = {
            variable.get("name")
            for variable in repository_variables
            if isinstance(variable, dict) and isinstance(variable.get("name"), str)
        }
        if len(repository_variable_names) != len(repository_variables):
            raise ControlError("repository_variable_list_invalid")
        repository_policy_variable_names = {
            environment_policy_variable_name(repository, environment)
            for environment in desired_repository["environments"]
        }
        repository_policy_fallbacks = (
            repository_policy_variable_names & repository_variable_names
        )
        for policy_variable_name in sorted(repository_policy_variable_names):
            if policy_variable_name in repository_policy_fallbacks:
                checks.append(
                    finding(
                        repository,
                        "repository_variable",
                        policy_variable_name,
                        "drift",
                        "repository_policy_sentinel_fallback_requires_manual_remediation",
                    )
                )
                destructive_drift = True
            else:
                checks.append(
                    finding(
                        repository,
                        "repository_variable",
                        policy_variable_name,
                        "passed",
                        "repository_policy_sentinel_fallback_absent",
                    )
                )
        if repository_policy_fallbacks:
            repository_sealing_blockers.append(
                "repository_policy_sentinel_fallback"
            )

        desired_repository_variable_names = {
            variable_name
            for environment in desired_repository["environments"]
            for variable_name in environment.get(
                "variables", {"allowed_names": []}
            )["allowed_names"]
        }
        organization_variable_fallbacks: list[str] = []
        for variable_name in sorted(desired_repository_variable_names):
            scope = organization_variable_scopes.get(variable_name)
            if scope is None:
                continue
            visibility, visible_repository_full_names = scope
            applies = (
                visibility == "all"
                or (visibility == "private" and repository_is_private)
                or (
                    visibility == "selected"
                    and f"{organization}/{repository}"
                    in visible_repository_full_names
                )
            )
            if applies:
                organization_variable_fallbacks.append(variable_name)
        if organization_variable_fallbacks:
            checks.append(
                finding(
                    repository,
                    "organization_variable",
                    "release-environments",
                    "drift",
                    "organization_release_variable_fallback_requires_manual_remediation",
                    names=organization_variable_fallbacks,
                )
            )
            destructive_drift = True
            repository_sealing_blockers.append(
                "organization_release_variable_fallback"
            )
        else:
            checks.append(
                finding(
                    repository,
                    "organization_variable",
                    "release-environments",
                    "passed",
                    "organization_release_variable_fallbacks_absent",
                )
            )

        repository_variable_fallbacks = sorted(
            repository_variable_names & desired_repository_variable_names
        )
        if repository_variable_fallbacks:
            checks.append(
                finding(
                    repository,
                    "repository_variable",
                    "release-environments",
                    "drift",
                    "repository_release_variable_fallback_requires_manual_remediation",
                    names=repository_variable_fallbacks,
                )
            )
            destructive_drift = True
            repository_sealing_blockers.append(
                "repository_release_variable_fallback"
            )
        else:
            checks.append(
                finding(
                    repository,
                    "repository_variable",
                    "release-environments",
                    "passed",
                    "repository_release_variable_fallbacks_absent",
                )
            )

        desired_repository_secret_names = {
            secret_name
            for environment in desired_repository["environments"]
            for secret_name in environment["secrets"]["allowed_names"]
        }
        audited_repository_secret_names = (
            desired_repository_secret_names
            | set(manifest["forbidden_secret_names"])
        )
        organization_secret_fallbacks: list[str] = []
        for secret_name in sorted(audited_repository_secret_names):
            scope = organization_secret_scopes.get(secret_name)
            if scope is None:
                continue
            visibility, visible_repository_full_names = scope
            applies = (
                visibility == "all"
                or (visibility == "private" and repository_is_private)
                or (
                    visibility == "selected"
                    and f"{organization}/{repository}"
                    in visible_repository_full_names
                )
            )
            if applies:
                organization_secret_fallbacks.append(secret_name)
        if organization_secret_fallbacks:
            checks.append(
                finding(
                    repository,
                    "organization_secret",
                    "release-environments",
                    "drift",
                    "organization_release_secret_fallback_requires_manual_remediation",
                    names=organization_secret_fallbacks,
                )
            )
            destructive_drift = True
            repository_sealing_blockers.append(
                "organization_release_secret_fallback"
            )
        else:
            checks.append(
                finding(
                    repository,
                    "organization_secret",
                    "release-environments",
                    "passed",
                    "organization_release_secret_fallbacks_absent",
                )
            )
        repository_secret_names = set(
            listed_control_names(
                client.collection(
                    f"/repos/{quoted(organization)}/{quoted(repository)}/actions/secrets",
                    "secrets",
                ),
                "repository_secret_list_invalid",
            )
        )
        repository_secret_fallbacks = sorted(
            repository_secret_names & audited_repository_secret_names
        )
        if repository_secret_fallbacks:
            checks.append(
                finding(
                    repository,
                    "repository_secret",
                    "release-environments",
                    "drift",
                    "repository_release_secret_fallback_requires_manual_remediation",
                    names=repository_secret_fallbacks,
                )
            )
            destructive_drift = True
            repository_sealing_blockers.append(
                "repository_release_secret_fallback"
            )
        else:
            checks.append(
                finding(
                    repository,
                    "repository_secret",
                    "release-environments",
                    "passed",
                    "repository_release_secret_fallbacks_absent",
                )
            )

        branch_ruleset = next(
            ruleset
            for ruleset in desired_repository["rulesets"]
            if ruleset["target"] == "branch"
        )
        status_rule = next(
            rule
            for rule in branch_ruleset["rules"]
            if rule["type"] == "required_status_checks"
        )
        desired_status_checks = status_rule["parameters"]["required_status_checks"]
        expected_context_names = [
            status_check["context"] for status_check in desired_status_checks
        ]
        required_contexts = {
            (
                status_check["context"],
                status_check["integration_id"],
                GITHUB_ACTIONS_APP["slug"],
            )
            for status_check in desired_status_checks
        }
        check_runs = client.collection(
            f"/repos/{quoted(organization)}/{quoted(repository)}/commits/"
            f"{quoted(desired_repository['default_branch'])}/check-runs",
            "check_runs",
        )
        observed_contexts: set[tuple[str, int, str]] = set()
        for raw_check_run in check_runs:
            check_run = require_object(raw_check_run, "check_run_list_invalid")
            app = require_object(check_run.get("app"), "check_run_app_invalid")
            context = check_run.get("name")
            app_id = app.get("id")
            app_slug = app.get("slug")
            if (
                not isinstance(context, str)
                or not context
                or not isinstance(app_id, int)
                or isinstance(app_id, bool)
                or not isinstance(app_slug, str)
            ):
                raise ControlError("check_run_identity_invalid")
            observed_contexts.add((context, app_id, app_slug))
        missing_contexts = sorted(required_contexts - observed_contexts)
        if missing_contexts:
            checks.append(
                finding(
                    repository,
                    "required_status_contexts",
                    "main",
                    "drift",
                    "required_github_actions_context_not_observed",
                    missing=[context for context, _, _ in missing_contexts],
                )
            )
            destructive_drift = True
            repository_sealing_blockers.append(
                "required_status_contexts_not_observed"
            )
        else:
            checks.append(
                finding(
                    repository,
                    "required_status_contexts",
                    "main",
                    "passed",
                    "required_github_actions_contexts_observed",
                    contexts=expected_context_names,
                )
            )

        (
            ruleset_checks,
            ruleset_mutations,
            ruleset_destructive_drift,
            ruleset_sealing_blockers,
        ) = inspect_repository_rulesets(
            client,
            organization,
            repository,
            desired_repository["rulesets"],
        )
        checks.extend(ruleset_checks)
        mutations.extend(ruleset_mutations)
        destructive_drift = destructive_drift or ruleset_destructive_drift
        repository_sealing_blockers.extend(ruleset_sealing_blockers)
        policy_fallback_requires_shadow = any(
            blocker
            in {
                "organization_policy_sentinel_fallback",
                "repository_policy_sentinel_fallback",
            }
            for blocker in repository_sealing_blockers
        )

        for desired_environment in desired_repository["environments"]:
            name = desired_environment["name"]
            profile_administration = is_single_maintainer_administration(
                repository, desired_environment
            )
            environment_reviewers = [] if profile_administration else list(reviewers)
            expected_environment_reviewers = {
                (reviewer.github_type, reviewer.identifier)
                for reviewer in environment_reviewers
            }
            policy_variable_name = environment_policy_variable_name(
                repository, desired_environment
            )
            path = environment_path(organization, repository, name)
            environment_sealing_blockers = [
                blocker
                for blocker in repository_sealing_blockers
                if not (
                    profile_administration
                    and blocker == "independent_reviewer_unavailable"
                )
            ]
            try:
                remote = require_object(
                    client.get(path), "environment_response_invalid"
                )
            except NotFound:
                checks.append(
                    finding(
                        repository,
                        "environment",
                        name,
                        "missing",
                        "environment_missing",
                    )
                )
                mutations.append(
                    mutation(
                        "PUT",
                        path,
                        (
                            "create_environment_for_policy_quarantine"
                            if policy_fallback_requires_shadow
                            else "create_protected_environment"
                        ),
                        environment_body(
                            desired_environment, environment_reviewers
                        ),
                    )
                )
                if policy_fallback_requires_shadow:
                    mutations.append(
                        mutation(
                            "POST",
                            path + "/variables",
                            "quarantine_release_control_policy_sentinel",
                            {
                                "name": policy_variable_name,
                                "value": quarantine_policy_value(
                                    desired_environment
                                ),
                            },
                        )
                    )
                mutations.append(
                    mutation(
                        "POST",
                        path + "/deployment-branch-policies",
                        "add_exact_main_branch_policy",
                        {"name": "main", "type": "branch"},
                    )
                )
                checks.append(
                    finding(
                        repository,
                        "environment_variable",
                        name,
                        "missing",
                        (
                            "release_control_policy_quarantine_required_to_shadow_broader_fallback"
                            if policy_fallback_requires_shadow
                            else "release_control_policy_sentinel_withheld_until_environment_exact"
                        ),
                        variable=policy_variable_name,
                        blockers=sorted(
                            set(
                                environment_sealing_blockers
                                + [
                                    "administrator_bypass_not_live_verified",
                                    "environment_not_live_verified",
                                    "environment_secret_inventory_not_live_verified",
                                    "main_branch_policy_not_live_verified",
                                    "reviewer_policy_not_live_verified",
                                ]
                            )
                        ),
                    )
                )
                checks.append(
                    finding(
                        repository,
                        "environment_admin_bypass",
                        name,
                        "missing",
                        "disable_administrator_bypass_after_environment_creation",
                    )
                )
                required = sorted(desired_environment["secrets"]["required_names"])
                if required:
                    checks.append(
                        finding(
                            repository,
                            "environment_secrets",
                            name,
                            "missing",
                            "required_secret_names_missing",
                            missing=required,
                        )
                    )
                else:
                    checks.append(
                        finding(
                            repository,
                            "environment_secrets",
                            name,
                            "passed",
                            "credential_free_environment_declared",
                            names=[],
                        )
                    )
                required_variables = sorted(
                    desired_environment.get(
                        "variables", {"required_names": []}
                    )["required_names"]
                )
                if required_variables:
                    checks.append(
                        finding(
                            repository,
                            "environment_variables",
                            name,
                            "missing",
                            "required_environment_variable_names_missing",
                            missing=required_variables,
                        )
                    )
                else:
                    checks.append(
                        finding(
                            repository,
                            "environment_variables",
                            name,
                            "passed",
                            "no_environment_configuration_variables_declared",
                            names=[],
                        )
                    )
                continue

            can_admins_bypass = remote.get("can_admins_bypass")
            if not isinstance(can_admins_bypass, bool):
                raise ControlError("environment_admin_bypass_unobservable")
            if can_admins_bypass:
                checks.append(
                    finding(
                        repository,
                        "environment_admin_bypass",
                        name,
                        "drift",
                        "administrator_bypass_requires_manual_remediation",
                    )
                )
                destructive_drift = True
                environment_sealing_blockers.append(
                    "administrator_bypass_not_disabled"
                )
            else:
                checks.append(
                    finding(
                        repository,
                        "environment_admin_bypass",
                        name,
                        "passed",
                        "administrator_bypass_disabled",
                    )
                )

            actual, prevent, wait_timer = actual_reviewers(remote)
            extras = sorted(actual - expected_environment_reviewers)
            missing = sorted(expected_environment_reviewers - actual)
            if extras:
                checks.append(
                    finding(
                        repository,
                        "environment_reviewers",
                        name,
                        "drift",
                        "unknown_reviewer_requires_manual_remediation",
                        actual=[{"type": item[0], "id": item[1]} for item in sorted(actual)],
                        expected=[
                            reviewer.api_value()
                            for reviewer in environment_reviewers
                        ],
                    )
                )
                destructive_drift = True
                environment_sealing_blockers.append("reviewer_policy_not_exact")
            elif missing or prevent != desired_environment["prevent_self_review"]:
                checks.append(
                    finding(
                        repository,
                        "environment_reviewers",
                        name,
                        "drift",
                        "reviewer_policy_drift",
                        actual=[{"type": item[0], "id": item[1]} for item in sorted(actual)],
                        expected=[
                            reviewer.api_value()
                            for reviewer in environment_reviewers
                        ],
                        prevent_self_review=prevent,
                    )
                )
                mutations.append(
                    mutation(
                        "PUT",
                        path,
                        (
                            "remove_required_reviewers_for_profile"
                            if profile_administration
                            else "add_required_reviewers"
                        ),
                        environment_body(
                            desired_environment,
                            environment_reviewers,
                            wait_timer,
                        ),
                    )
                )
                environment_sealing_blockers.append("reviewer_policy_not_exact")
            else:
                checks.append(
                    finding(
                        repository,
                        "environment_reviewers",
                        name,
                        "passed",
                        "reviewer_policy_exact",
                        reviewers=[
                            reviewer.api_value()
                            for reviewer in environment_reviewers
                        ],
                    )
                )

            raw_branch_mode = require_object(
                remote.get("deployment_branch_policy"),
                "environment_deployment_branch_policy_invalid",
            )
            if set(raw_branch_mode) != {
                "protected_branches",
                "custom_branch_policies",
            } or any(
                not isinstance(raw_branch_mode[key], bool)
                for key in ("protected_branches", "custom_branch_policies")
            ):
                raise ControlError("environment_deployment_branch_policy_invalid")
            branch_mode = {
                "protected_branches": raw_branch_mode["protected_branches"],
                "custom_branch_policies": raw_branch_mode[
                    "custom_branch_policies"
                ],
            }
            exact_mode = branch_mode == {
                "protected_branches": False,
                "custom_branch_policies": True,
            }
            policies: list[Any] = []
            if exact_mode:
                policies = client.collection(
                    path + "/deployment-branch-policies", "branch_policies"
                )
            if not exact_mode:
                checks.append(
                    finding(
                        repository,
                        "environment_branches",
                        name,
                        "drift",
                        "deployment_branch_mode_requires_manual_remediation",
                        actual=branch_mode,
                    )
                )
                # GitHub only permits custom branch-policy enumeration while
                # custom_branch_policies is already enabled. Changing an
                # existing non-exact mode could therefore conceal or replace
                # policies that this additive reconciler cannot observe.
                destructive_drift = True
                environment_sealing_blockers.append(
                    "main_branch_policy_not_exact"
                )
            else:
                normalized_policies: list[dict[str, str]] = []
                for raw_policy in policies:
                    policy = require_object(
                        raw_policy, "environment_branch_policy_list_invalid"
                    )
                    policy_name = policy.get("name")
                    policy_type = policy.get("type")
                    if (
                        not isinstance(policy_name, str)
                        or not policy_name
                        or not isinstance(policy_type, str)
                        or policy_type not in {"branch", "tag"}
                    ):
                        raise ControlError(
                            "environment_branch_policy_list_invalid"
                        )
                    normalized_policies.append(
                        {"name": policy_name, "type": policy_type}
                    )
                normalized_policies.sort(key=canonical_bytes)
                if normalized_policies == [{"name": "main", "type": "branch"}]:
                    checks.append(
                        finding(
                            repository,
                            "environment_branches",
                            name,
                            "passed",
                            "main_only_branch_policy_exact",
                        )
                    )
                elif not normalized_policies:
                    checks.append(
                        finding(
                            repository,
                            "environment_branches",
                            name,
                            "drift",
                            "main_branch_policy_missing",
                        )
                    )
                    mutations.append(
                        mutation(
                            "POST",
                            path + "/deployment-branch-policies",
                            "add_exact_main_branch_policy",
                            {"name": "main", "type": "branch"},
                        )
                    )
                    environment_sealing_blockers.append(
                        "main_branch_policy_not_exact"
                    )
                else:
                    checks.append(
                        finding(
                            repository,
                            "environment_branches",
                            name,
                            "drift",
                            "unknown_branch_policy_requires_manual_remediation",
                            actual=normalized_policies,
                        )
                    )
                    destructive_drift = True
                    environment_sealing_blockers.append(
                        "main_branch_policy_not_exact"
                    )

            variables = client.collection(path + "/variables", "variables")
            normalized_variables: list[dict[str, str]] = []
            for raw_variable in variables:
                variable = require_object(
                    raw_variable, "environment_variable_list_invalid"
                )
                variable_name = variable.get("name")
                variable_value = variable.get("value")
                if not isinstance(variable_name, str) or not isinstance(
                    variable_value, str
                ):
                    raise ControlError("environment_variable_list_invalid")
                normalized_variables.append(
                    {"name": variable_name, "value": variable_value}
                )
            variable_names = [
                variable["name"] for variable in normalized_variables
            ]
            if len(variable_names) != len(set(variable_names)):
                raise ControlError("environment_variable_list_invalid")
            desired_variables = desired_environment.get(
                "variables", {"required_names": [], "allowed_names": []}
            )
            required_variable_names = set(desired_variables["required_names"])
            allowed_variable_names = set(desired_variables["allowed_names"])
            actual_variable_names = set(variable_names)
            unknown_variables = sorted(
                actual_variable_names
                - allowed_variable_names
                - {policy_variable_name}
            )
            missing_variables = sorted(
                required_variable_names - actual_variable_names
            )
            sentinel = next(
                (
                    variable
                    for variable in normalized_variables
                    if variable["name"] == policy_variable_name
                ),
                None,
            )
            if unknown_variables:
                checks.append(
                    finding(
                        repository,
                        "environment_variable",
                        name,
                        "drift",
                        "unknown_environment_variable_requires_manual_remediation",
                        actual=sorted(variable_names),
                        allowed=sorted(
                            allowed_variable_names | {policy_variable_name}
                        ),
                    )
                )
                destructive_drift = True
                environment_sealing_blockers.append(
                    "environment_variable_inventory_not_exact"
                )
            elif missing_variables:
                checks.append(
                    finding(
                        repository,
                        "environment_variables",
                        name,
                        "missing",
                        "required_environment_variable_names_missing",
                        missing=missing_variables,
                    )
                )
                environment_sealing_blockers.append(
                    "required_environment_variables_missing"
                )
            else:
                checks.append(
                    finding(
                        repository,
                        "environment_variables",
                        name,
                        "passed",
                        "environment_variable_names_exact",
                        names=sorted(required_variable_names),
                    )
                )

            secrets = client.collection(path + "/secrets", "secrets")
            names = sorted(
                secret.get("name")
                for secret in secrets
                if isinstance(secret, dict) and isinstance(secret.get("name"), str)
            )
            if len(names) != len(secrets) or len(names) != len(set(names)):
                raise ControlError("environment_secret_list_invalid")
            required_names = set(desired_environment["secrets"]["required_names"])
            allowed_names = set(desired_environment["secrets"]["allowed_names"])
            actual_names = set(names)
            missing_names = sorted(required_names - actual_names)
            unknown_names = sorted(actual_names - allowed_names)
            if unknown_names:
                checks.append(
                    finding(
                        repository,
                        "environment_secrets",
                        name,
                        "drift",
                        "unknown_secret_name_requires_manual_remediation",
                        actual=names,
                        allowed=sorted(allowed_names),
                    )
                )
                destructive_drift = True
                environment_sealing_blockers.append(
                    "environment_secret_inventory_not_exact"
                )
            elif missing_names:
                checks.append(
                    finding(
                        repository,
                        "environment_secrets",
                        name,
                        "missing",
                        "required_secret_names_missing",
                        missing=missing_names,
                    )
                )
                environment_sealing_blockers.append(
                    "required_environment_secrets_missing"
                )
            else:
                checks.append(
                    finding(
                        repository,
                        "environment_secrets",
                        name,
                        "passed",
                        "secret_names_exact",
                        names=names,
                    )
                )

            seal_blockers = sorted(set(environment_sealing_blockers))
            if sentinel is None:
                quarantine_required = policy_fallback_requires_shadow
                checks.append(
                    finding(
                        repository,
                        "environment_variable",
                        name,
                        "missing",
                        (
                            "release_control_policy_quarantine_required_to_shadow_broader_fallback"
                            if quarantine_required
                            else (
                                "release_control_policy_sentinel_missing"
                                if not seal_blockers
                                else "release_control_policy_sentinel_withheld_until_environment_exact"
                            )
                        ),
                        variable=policy_variable_name,
                        blockers=seal_blockers,
                    )
                )
                if quarantine_required:
                    destructive_drift = True
                    mutations.append(
                        mutation(
                            "POST",
                            path + "/variables",
                            "quarantine_release_control_policy_sentinel",
                            {
                                "name": policy_variable_name,
                                "value": quarantine_policy_value(
                                    desired_environment
                                ),
                            },
                        )
                    )
                elif not seal_blockers:
                    mutations.append(
                        mutation(
                            "POST",
                            path + "/variables",
                            "add_release_control_policy_sentinel",
                            {
                                "name": policy_variable_name,
                                "value": desired_environment["policy_id"],
                            },
                        )
                    )
            elif sentinel["value"] != desired_environment["policy_id"]:
                quarantine_active = (
                    sentinel["value"]
                    == quarantine_policy_value(desired_environment)
                )
                checks.append(
                    finding(
                        repository,
                        "environment_variable",
                        name,
                        "drift",
                        (
                            "release_control_policy_sentinel_value_drift"
                            if not seal_blockers
                            else (
                                "release_control_policy_quarantine_active_until_environment_exact"
                                if quarantine_active
                                else "release_control_policy_sentinel_restore_withheld_until_environment_exact"
                            )
                        ),
                        variable=policy_variable_name,
                        blockers=seal_blockers,
                    )
                )
                if not seal_blockers:
                    mutations.append(
                        mutation(
                            "PATCH",
                            path + "/variables/" + quoted(policy_variable_name),
                            "restore_release_control_policy_sentinel",
                            {
                                "name": policy_variable_name,
                                "value": desired_environment["policy_id"],
                            },
                        )
                    )
            elif seal_blockers:
                checks.append(
                    finding(
                        repository,
                        "environment_variable",
                        name,
                        "drift",
                        "release_control_policy_sentinel_quarantine_scheduled",
                        variable=policy_variable_name,
                        blockers=seal_blockers,
                    )
                )
                destructive_drift = True
                mutations.append(
                    mutation(
                        "PATCH",
                        path + "/variables/" + quoted(policy_variable_name),
                        "quarantine_release_control_policy_sentinel",
                        {
                            "name": policy_variable_name,
                            "value": quarantine_policy_value(
                                desired_environment
                            ),
                        },
                    )
                )
            else:
                checks.append(
                    finding(
                        repository,
                        "environment_variable",
                        name,
                        "passed",
                        "release_control_policy_sentinel_exact",
                        variable=policy_variable_name,
                    )
                )

    return sorted(checks, key=canonical_bytes), mutations, destructive_drift


class NpmCLI:
    def __init__(self, executable: str, github_token_environment: str = "GH_TOKEN"):
        if not executable:
            raise ControlError("npm_cli_missing")
        if (
            not isinstance(github_token_environment, str)
            or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*", github_token_environment
            )
            is None
        ):
            raise ControlError("github_token_environment_invalid")
        self.executable = executable
        self.github_token_environment = github_token_environment
        self._version_checked = False

    def _environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        for name in {
            "NPM_TOKEN",
            "NODE_AUTH_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            self.github_token_environment,
        }:
            environment.pop(name, None)
        return environment

    def _run(
        self,
        arguments: Sequence[str],
        *,
        timeout: int,
        error_code: str,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                list(arguments),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=self._environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ControlError(error_code) from None
        if result.returncode != 0:
            raise ControlError(error_code)
        return result

    def _require_supported_version(self) -> None:
        if self._version_checked:
            return
        result = self._run(
            [self.executable, "--version"],
            timeout=30,
            error_code="npm_version_check_failed",
        )
        match = re.fullmatch(
            r"(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?",
            result.stdout.strip(),
        )
        if match is None:
            raise ControlError("npm_version_check_failed")
        version = tuple(int(match.group(index)) for index in range(1, 4))
        if version < (11, 15, 0):
            raise ControlError("npm_version_unsupported")
        self._version_checked = True

    def preflight(self, packages: Sequence[str]) -> dict[str, Any]:
        """Prove npmjs account/package prerequisites without leaking profile data."""

        self._require_supported_version()
        identity_result = self._run(
            [self.executable, "whoami", "--registry", NPM_REGISTRY],
            timeout=60,
            error_code="npm_authenticated_identity_unavailable",
        )
        username = identity_result.stdout.strip()
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,213}", username) is None:
            raise ControlError("npm_authenticated_identity_invalid")

        profile_result = self._run(
            [
                self.executable,
                "profile",
                "get",
                "--json",
                "--registry",
                NPM_REGISTRY,
            ],
            timeout=60,
            error_code="npm_profile_unavailable",
        )
        try:
            profile = require_object(
                json.loads(profile_result.stdout), "npm_profile_not_json"
            )
        except json.JSONDecodeError:
            raise ControlError("npm_profile_not_json") from None
        if profile.get("name") != username:
            raise ControlError("npm_profile_identity_mismatch")
        raw_tfa = profile.get("tfa")
        if isinstance(raw_tfa, bool):
            tfa_enabled = raw_tfa
        elif isinstance(raw_tfa, dict):
            pending = raw_tfa.get("pending", False)
            mode = raw_tfa.get("mode")
            if not isinstance(pending, bool) or mode not in {
                "auth-only",
                "auth-and-writes",
            }:
                raise ControlError("npm_account_2fa_unobservable")
            tfa_enabled = not pending
        else:
            raise ControlError("npm_account_2fa_unobservable")

        package_access: list[dict[str, Any]] = []
        for package in sorted(set(packages)):
            status_result = self._run(
                [
                    self.executable,
                    "access",
                    "get",
                    "status",
                    package,
                    "--json",
                    "--registry",
                    NPM_REGISTRY,
                    NPM_SCOPE_REGISTRY_OPTION,
                ],
                timeout=60,
                error_code="npm_package_existence_unavailable",
            )
            try:
                status = require_object(
                    json.loads(status_result.stdout), "npm_package_status_not_json"
                )
            except json.JSONDecodeError:
                raise ControlError("npm_package_status_not_json") from None
            if status.get(package) not in {"public", "private"}:
                raise ControlError("npm_package_status_invalid")

            access_result = self._run(
                [
                    self.executable,
                    "access",
                    "list",
                    "packages",
                    username,
                    package,
                    "--json",
                    "--registry",
                    NPM_REGISTRY,
                    NPM_SCOPE_REGISTRY_OPTION,
                ],
                timeout=60,
                error_code="npm_package_access_unavailable",
            )
            try:
                access = require_object(
                    json.loads(access_result.stdout), "npm_package_access_not_json"
                )
            except json.JSONDecodeError:
                raise ControlError("npm_package_access_not_json") from None
            permission = access.get(package)
            if permission not in {None, "read-only", "read-write"}:
                raise ControlError("npm_package_access_invalid")
            package_access.append(
                {
                    "package": package,
                    "exists": True,
                    "write_visible": permission == "read-write",
                }
            )

        # Only public identity and booleans derived from the npm profile and
        # access responses leave this method. Email, profile fields, access
        # maps, command output, and authentication material are discarded.
        return {
            "registry": NPM_REGISTRY,
            "username": username,
            "two_factor_authentication": tfa_enabled,
            "packages": package_access,
        }

    def list(self, package: str) -> list[dict[str, Any]]:
        self._require_supported_version()
        result = self._run(
            [
                self.executable,
                "trust",
                "list",
                package,
                "--json",
                "--registry",
                NPM_REGISTRY,
                NPM_SCOPE_REGISTRY_OPTION,
            ],
            timeout=60,
            error_code="npm_trust_list_failed",
        )
        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ControlError("npm_trust_list_not_json") from None
        items = payload if isinstance(payload, list) else [payload]
        return [require_object(item, "npm_trust_item_invalid") for item in items]

    def create(self, publisher: Mapping[str, Any]) -> None:
        self._require_supported_version()
        arguments = [
            self.executable,
            "trust",
            "github",
            publisher["package"],
            "--repository",
            publisher["repository"],
            "--file",
            publisher["workflow"],
            "--environment",
            publisher["environment"],
            "--allow-publish",
            "--yes",
            "--json",
            "--registry",
            NPM_REGISTRY,
            NPM_SCOPE_REGISTRY_OPTION,
        ]
        self._run(arguments, timeout=120, error_code="npm_trust_create_failed")


def npm_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    permissions = value.get("permissions", [])
    if not isinstance(permissions, list) or any(
        not isinstance(permission, str) for permission in permissions
    ):
        raise ControlError("npm_trust_permissions_invalid")
    return {
        "type": value.get("type") or value.get("provider"),
        "repository": value.get("repository"),
        "file": value.get("file") or value.get("workflow"),
        "environment": value.get("environment"),
        "permissions": sorted(permissions),
    }


def inspect_npm(
    client: NpmCLI,
    publishers: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]], bool, dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    missing: list[Mapping[str, Any]] = []
    destructive_drift = False
    packages = [publisher["package"] for publisher in publishers]
    preflight = require_object(
        client.preflight(packages), "npm_preflight_invalid"
    )
    if (
        set(preflight)
        != {
            "registry",
            "username",
            "two_factor_authentication",
            "packages",
        }
        or preflight.get("registry") != NPM_REGISTRY
        or not isinstance(preflight.get("username"), str)
        or re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{0,213}", preflight["username"]
        )
        is None
        or not isinstance(preflight.get("two_factor_authentication"), bool)
    ):
        raise ControlError("npm_preflight_invalid")
    raw_access = require_array(
        preflight.get("packages"), "npm_preflight_package_access_invalid"
    )
    access_by_package: dict[str, dict[str, Any]] = {}
    for raw_item in raw_access:
        item = require_object(raw_item, "npm_preflight_package_access_invalid")
        if (
            set(item) != {"package", "exists", "write_visible"}
            or item.get("package") not in packages
            or item["package"] in access_by_package
            or item.get("exists") is not True
            or not isinstance(item.get("write_visible"), bool)
        ):
            raise ControlError("npm_preflight_package_access_invalid")
        access_by_package[item["package"]] = item
    if set(access_by_package) != set(packages):
        raise ControlError("npm_preflight_package_access_invalid")

    safe_preflight = {
        "registry": NPM_REGISTRY,
        "username": preflight["username"],
        "two_factor_authentication": preflight["two_factor_authentication"],
        "packages": [
            access_by_package[package] for package in sorted(access_by_package)
        ],
    }

    username = preflight["username"]
    checks.append(
        {
            "control": "npm_authenticated_identity",
            "name": username,
            "repository": NPM_REGISTRY,
            "status": "passed",
            "code": "npm_authenticated_identity_observed",
        }
    )
    tfa_enabled = preflight["two_factor_authentication"]
    checks.append(
        {
            "control": "npm_account_2fa",
            "name": username,
            "repository": NPM_REGISTRY,
            "status": "passed" if tfa_enabled else "failed",
            "code": (
                "npm_account_2fa_enabled"
                if tfa_enabled
                else "npm_account_2fa_required"
            ),
        }
    )
    if not tfa_enabled:
        destructive_drift = True
    for package in packages:
        write_visible = access_by_package[package]["write_visible"]
        checks.extend(
            [
                {
                    "control": "npm_package_existence",
                    "name": package,
                    "repository": NPM_REGISTRY,
                    "status": "passed",
                    "code": "npm_package_exists",
                },
                {
                    "control": "npm_package_write_access",
                    "name": package,
                    "repository": NPM_REGISTRY,
                    "status": "passed" if write_visible else "failed",
                    "code": (
                        "npm_package_write_access_observed"
                        if write_visible
                        else "npm_package_write_access_required"
                    ),
                },
            ]
        )
        if not write_visible:
            destructive_drift = True

    if destructive_drift:
        return sorted(checks, key=canonical_bytes), [], True, safe_preflight

    for publisher in publishers:
        expected = npm_projection(publisher)
        actual_items = client.list(publisher["package"])
        projections = [npm_projection(item) for item in actual_items]
        if not projections:
            checks.append(
                {
                    "control": "npm_trusted_publisher",
                    "name": publisher["package"],
                    "repository": publisher["repository"],
                    "status": "missing",
                    "code": "npm_trusted_publisher_missing",
                }
            )
            missing.append(publisher)
        elif projections == [expected]:
            checks.append(
                {
                    "control": "npm_trusted_publisher",
                    "name": publisher["package"],
                    "repository": publisher["repository"],
                    "status": "passed",
                    "code": "npm_trusted_publisher_exact",
                }
            )
        else:
            checks.append(
                {
                    "control": "npm_trusted_publisher",
                    "name": publisher["package"],
                    "repository": publisher["repository"],
                    "status": "drift",
                    "code": "npm_trusted_publisher_requires_manual_remediation",
                    "actual": projections,
                    "expected": expected,
                }
            )
            destructive_drift = True
    return (
        sorted(checks, key=canonical_bytes),
        missing,
        destructive_drift,
        safe_preflight,
    )


def repository_selection(
    manifest: Mapping[str, Any], requested: Sequence[str]
) -> set[str]:
    available = {repository["name"] for repository in manifest["repositories"]}
    selected = set(requested) if requested else available
    if not selected or not selected <= available:
        raise ControlError("repository_selection_invalid")
    return selected


def publishers_for_selection(
    manifest: Mapping[str, Any], selected: set[str]
) -> list[Mapping[str, Any]]:
    return [
        publisher
        for publisher in manifest["npm_trusted_publishers"]
        if publisher["repository"].split("/", 1)[1] in selected
    ]


def plan_evidence(
    manifest: Mapping[str, Any],
    manifest_path: Path,
    manifest_sha: str,
    reviewers: Sequence[ReviewerSelector],
    selected: set[str],
    skip_npm: bool,
) -> dict[str, Any]:
    protected_secret_names = sorted(
        {
            secret_name
            for repository in manifest["repositories"]
            for environment in repository["environments"]
            for secret_name in environment["secrets"]["allowed_names"]
        }
        | set(manifest["forbidden_secret_names"])
    )
    protected_variable_names = sorted(
        {
            environment_policy_variable_name(repository["name"], environment)
            for repository in manifest["repositories"]
            for environment in repository["environments"]
        }
        | {
            variable_name
            for repository in manifest["repositories"]
            for environment in repository["environments"]
            for variable_name in environment.get(
                "variables", {"allowed_names": []}
            )["allowed_names"]
        }
    )
    actions: list[dict[str, Any]] = [
        {
            "action": "verify_no_organization_release_fallbacks",
            "repository": manifest["organization"],
            "variable": POLICY_VARIABLE_NAME,
            "variable_names": protected_variable_names,
            "secret_names": protected_secret_names,
        }
    ]
    for repository in manifest["repositories"]:
        if repository["name"] not in selected:
            continue
        repository_secret_names = sorted(
            {
                secret_name
                for environment in repository["environments"]
                for secret_name in environment["secrets"]["allowed_names"]
            }
            | set(manifest["forbidden_secret_names"])
        )
        repository_variable_names = sorted(
            {
                environment_policy_variable_name(repository["name"], environment)
                for environment in repository["environments"]
            }
            | {
                variable_name
                for environment in repository["environments"]
                for variable_name in environment.get(
                    "variables", {"allowed_names": []}
                )["allowed_names"]
            }
        )
        actions.append(
            {
                "action": "verify_no_repository_release_fallbacks",
                "repository": repository["name"],
                "variable": POLICY_VARIABLE_NAME,
                "variable_names": repository_variable_names,
                "secret_names": repository_secret_names,
            }
        )
        for environment in repository["environments"]:
            actions.extend(
                [
                    {
                        "action": "ensure_environment",
                        "repository": repository["name"],
                        "name": environment["name"],
                    },
                    {
                        "action": "ensure_exact_main_branch_policy",
                        "repository": repository["name"],
                        "name": environment["name"],
                    },
                    {
                        "action": "ensure_release_control_policy_sentinel",
                        "repository": repository["name"],
                        "name": environment["name"],
                        "variable": environment_policy_variable_name(
                            repository["name"], environment
                        ),
                        "value": environment["policy_id"],
                    },
                    {
                        "action": "verify_configuration_variable_names",
                        "repository": repository["name"],
                        "name": environment["name"],
                        "required_names": environment.get(
                            "variables", {"required_names": []}
                        )["required_names"],
                        "allowed_names": environment.get(
                            "variables", {"allowed_names": []}
                        )["allowed_names"],
                    },
                    {
                        "action": "verify_secret_names",
                        "repository": repository["name"],
                        "name": environment["name"],
                        "required_names": environment["secrets"]["required_names"],
                        "allowed_names": environment["secrets"]["allowed_names"],
                    },
                ]
            )
        for ruleset in repository["rulesets"]:
            actions.append(
                {
                    "action": "ensure_repository_ruleset",
                    "repository": repository["name"],
                    "name": ruleset["name"],
                }
            )
    if not skip_npm:
        for publisher in publishers_for_selection(manifest, selected):
            actions.append(
                {
                    "action": "ensure_npm_trusted_publisher",
                    "repository": publisher["repository"],
                    "name": publisher["package"],
                    "workflow": publisher["workflow"],
                    "environment": publisher["environment"],
                }
            )
    return {
        "schema_version": 1,
        "kind": "latchway_release_control_evidence",
        "mode": "plan",
        "status": "planned",
        "manifest": {
            "path": str(manifest_path),
            "sha256": manifest_sha,
        },
        "repositories": sorted(selected),
        "reviewer_selectors": [reviewer.text for reviewer in reviewers],
        "npm_included": not skip_npm,
        "actions": sorted(actions, key=canonical_bytes),
    }


def mutation_identity(item: Mapping[str, Any]) -> dict[str, str]:
    identity = {
        "method": item.get("method"),
        "path": item.get("path"),
        "reason": item.get("reason"),
    }
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise ControlError("mutation_identity_invalid")
    return identity


def npm_publisher_identity(publisher: Mapping[str, Any]) -> dict[str, str]:
    identity = {
        "package": publisher.get("package"),
        "repository": publisher.get("repository"),
        "workflow": publisher.get("workflow"),
        "environment": publisher.get("environment"),
    }
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise ControlError("npm_publisher_identity_invalid")
    return identity


def execute_mutations(
    client: GitHubAPI,
    pending: list[Mapping[str, Any]],
    applied: list[dict[str, str]],
) -> None:
    while pending:
        item = pending[0]
        method = item["method"]
        if method == "PUT":
            client.put(item["path"], item["body"])
        elif method == "POST":
            client.post(item["path"], item["body"])
        elif method == "PATCH":
            client.patch(item["path"], item["body"])
        else:
            raise ControlError("unsafe_mutation_method")
        applied.append(mutation_identity(item))
        del pending[0]


def online_evidence_payload(
    *,
    mode: str,
    status: str,
    manifest_path: Path,
    manifest_sha: str,
    selectors: Sequence[ReviewerSelector],
    selected: set[str],
    reviewers: Sequence[ResolvedReviewer],
    npm_included: bool,
    npm_preflight: Mapping[str, Any] | None,
    checks: Sequence[Mapping[str, Any]],
    pending: Sequence[Mapping[str, Any]],
    applied: Sequence[Mapping[str, Any]],
    npm_pending: Sequence[Mapping[str, Any]],
    npm_applied: Sequence[Mapping[str, Any]],
    error_code: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "kind": "latchway_release_control_evidence",
        "mode": mode,
        "status": status,
        "manifest": {"path": str(manifest_path), "sha256": manifest_sha},
        "repositories": sorted(selected),
        "reviewer_selectors": [selector.text for selector in selectors],
        "reviewers": [
            {
                "selector": reviewer.selector,
                "type": reviewer.github_type,
                "id": reviewer.identifier,
            }
            for reviewer in reviewers
        ],
        "npm_included": npm_included,
        "checks": sorted(checks, key=canonical_bytes),
        "pending_mutations": [mutation_identity(item) for item in pending],
        # These arrays are execution journals. The reconciler's traversal is
        # deterministic, so retaining order is canonical and preserves which
        # operation succeeded immediately before a partial failure.
        "applied_mutations": list(applied),
        "npm_publishers_pending": [
            npm_publisher_identity(item) for item in npm_pending
        ],
        "npm_publishers_applied": list(npm_applied),
    }
    if npm_preflight is not None:
        evidence["npm_preflight"] = npm_preflight
    if error_code is not None:
        evidence["error"] = {"code": error_code}
    return evidence


def online_evidence(
    mode: str,
    manifest: Mapping[str, Any],
    manifest_path: Path,
    manifest_sha: str,
    selectors: Sequence[ReviewerSelector],
    selected: set[str],
    github: GitHubAPI,
    npm: NpmCLI | None,
) -> dict[str, Any]:
    reviewers: list[ResolvedReviewer] = []
    github_checks: list[dict[str, Any]] = []
    pending: list[Mapping[str, Any]] = []
    publishers = publishers_for_selection(manifest, selected)
    npm_checks: list[dict[str, Any]] = []
    npm_pending: list[Mapping[str, Any]] = []
    npm_preflight: dict[str, Any] | None = None
    applied: list[dict[str, str]] = []
    npm_applied: list[dict[str, str]] = []
    try:
        reviewers = resolve_reviewers(
            github, manifest["organization"], selectors
        )
        github_checks, github_mutations, destructive = inspect_github(
            github, manifest, reviewers, selected
        )
        pending = list(github_mutations)
        npm_destructive = False
        if npm is not None and publishers:
            (
                npm_checks,
                npm_missing,
                npm_destructive,
                npm_preflight,
            ) = inspect_npm(npm, publishers)
            npm_pending = list(npm_missing)

        if mode == "apply":
            if destructive or npm_destructive:
                # A restrictive quarantine is the only mutation allowed while
                # any destructive drift exists. It invalidates the exact
                # accepting lease (or shadows a broader fallback) without
                # deleting state or attempting ordinary reconciliation.
                pending = [
                    item
                    for item in pending
                    if item["reason"] in QUARANTINE_MUTATION_REASONS
                ]
                npm_pending = []
                execute_mutations(github, pending, applied)
            else:
                execute_mutations(github, pending, applied)
                while npm_pending:
                    assert npm is not None
                    publisher = npm_pending[0]
                    npm.create(publisher)
                    npm_applied.append(npm_publisher_identity(publisher))
                    del npm_pending[0]
                github_checks, remaining, _ = inspect_github(
                    github, manifest, reviewers, selected
                )
                # Idempotent apply must not conceal an API mutation that failed
                # to converge or a required secret name needing operator input.
                pending = list(remaining)
                if npm is not None and publishers:
                    (
                        npm_checks,
                        npm_remaining,
                        _,
                        npm_preflight,
                    ) = inspect_npm(npm, publishers)
                    npm_pending = list(npm_remaining)

        checks = github_checks + npm_checks
        passed = all(check["status"] == "passed" for check in checks)
        return online_evidence_payload(
            mode=mode,
            status="passed" if passed else "failed",
            manifest_path=manifest_path,
            manifest_sha=manifest_sha,
            selectors=selectors,
            selected=selected,
            reviewers=reviewers,
            npm_included=npm is not None,
            npm_preflight=npm_preflight,
            checks=checks,
            pending=pending,
            applied=applied,
            npm_pending=npm_pending,
            npm_applied=npm_applied,
        )
    except ControlError as error:
        return online_evidence_payload(
            mode=mode,
            status="error",
            manifest_path=manifest_path,
            manifest_sha=manifest_sha,
            selectors=selectors,
            selected=selected,
            reviewers=reviewers,
            npm_included=npm is not None,
            npm_preflight=npm_preflight,
            checks=github_checks + npm_checks,
            pending=pending,
            applied=applied,
            npm_pending=npm_pending,
            npm_applied=npm_applied,
            error_code=error.code,
        )


def write_evidence(path: str, evidence: Any) -> None:
    payload = canonical_bytes(evidence)
    if path == "-":
        sys.stdout.buffer.write(payload)
        return
    destination = Path(path)
    if destination.is_symlink():
        raise ControlError("evidence_path_symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ControlError("evidence_temporary_path_exists")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("mode", choices=("plan", "verify", "apply"))
    result.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    result.add_argument(
        "--reviewer",
        action="append",
        required=True,
        help="required reviewer selector: user:LOGIN or team:SLUG; repeat up to six times",
    )
    result.add_argument(
        "--repository",
        action="append",
        default=[],
        help="repository name from the manifest; repeat to select a subset",
    )
    result.add_argument("--output", default="-", help="canonical evidence path or -")
    result.add_argument("--api-base", default=DEFAULT_API_BASE)
    result.add_argument(
        "--token-environment",
        default="GH_TOKEN",
        help="environment variable containing a GitHub token; never pass the token itself",
    )
    result.add_argument(
        "--npm-cli",
        default="npm",
        help="npm 11.15.0-or-newer executable used for trusted-publisher verification",
    )
    result.add_argument(
        "--skip-npm",
        action="store_true",
        help="scope evidence to GitHub controls; npm tuples remain in the manifest",
    )
    result.add_argument(
        "--confirm",
        help=f"apply mode requires the literal {APPLY_CONFIRMATION!r}",
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        manifest, manifest_sha = load_manifest(arguments.manifest)
        selectors = parse_reviewers(arguments.reviewer)
        selected = repository_selection(manifest, arguments.repository)
        if arguments.mode == "plan":
            evidence = plan_evidence(
                manifest,
                arguments.manifest,
                manifest_sha,
                selectors,
                selected,
                arguments.skip_npm,
            )
        else:
            if arguments.mode == "apply" and arguments.confirm != APPLY_CONFIRMATION:
                raise ControlError("apply_confirmation_invalid")
            token = os.environ.get(arguments.token_environment, "")
            github = GitHubAPI(token, manifest["api_version"], arguments.api_base)
            npm = (
                None
                if arguments.skip_npm
                else NpmCLI(arguments.npm_cli, arguments.token_environment)
            )
            evidence = online_evidence(
                arguments.mode,
                manifest,
                arguments.manifest,
                manifest_sha,
                selectors,
                selected,
                github,
                npm,
            )
        write_evidence(arguments.output, evidence)
        if evidence["status"] == "error":
            code = evidence.get("error", {}).get("code", "unknown_error")
            print(f"release controls failed: {code}", file=sys.stderr)
            return 2
        return 0 if evidence["status"] in {"passed", "planned"} else 1
    except ControlError as error:
        try:
            write_evidence(
                arguments.output,
                {
                    "schema_version": 1,
                    "kind": "latchway_release_control_evidence",
                    "mode": arguments.mode,
                    "status": "error",
                    "error": {"code": error.code},
                },
            )
        except ControlError:
            pass
        print(f"release controls failed: {error.code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
