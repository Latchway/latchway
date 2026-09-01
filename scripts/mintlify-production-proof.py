#!/usr/bin/env python3
"""Validate and retain the fixed Mintlify production-deployment proof.

This module is owned by the core release pipeline.  It deliberately does not
import or execute code from the documentation repository: the protected
GitHub-authority job authenticates the foreign run and Sigstore subject, then
this credential-free validator independently replays the bounded evidence
contract and binds it to source-conformance documentation coordinates.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import unquote, urljoin, urlsplit


DOCUMENTATION_REPOSITORY = "Latchway/latchway-docs"
DOCUMENTATION_REPOSITORY_URL = (
    "https://github.com/Latchway/latchway-docs.git"
)
WORKFLOW_PATH = ".github/workflows/mintlify-production-evidence.yml"
WORKFLOW_REF = "refs/heads/main"
PRODUCTION_ORIGIN = "https://docs.latchway.dev"
ALLOWED_ENVIRONMENT_ORIGINS = frozenset(
    {PRODUCTION_ORIGIN, "https://latchway.mintlify.app"}
)
MINTLIFY_ACTOR = {"id": 109931778, "login": "mintlify[bot]", "type": "Bot"}
EVIDENCE_KIND = "latchway_mintlify_production_deployment_evidence"
PROOF_KIND = "latchway_mintlify_production_release_proof"
MAXIMUM_AGE = timedelta(seconds=86_400)
MAXIMUM_CLOCK_SKEW = timedelta(seconds=300)
MAXIMUM_COLLECTION_WINDOW = timedelta(hours=1)
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
CANONICAL_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVIDENCE_FILE = "latchway-mintlify-production-evidence.json"
CHECKSUM_FILE = "latchway-mintlify-production-evidence.SHA256SUMS"
ATTESTATION_FILE = (
    "latchway-mintlify-production-evidence.attestation.sigstore.json"
)
RETAINED_FILES = frozenset(
    {
        EVIDENCE_FILE,
        CHECKSUM_FILE,
        ATTESTATION_FILE,
        "run.json",
        "workflow.json",
        "artifact.json",
        "attestation-verification.json",
    }
)
CLAIMS = frozenset(
    {
        "documentation_commit_verified",
        "github_deployment_success_verified",
        "live_accessibility_baseline_verified",
        "live_ai_outputs_verified",
        "live_internal_links_verified",
        "live_redirects_verified",
        "live_source_checkpoint_verified",
        "mintlify_actor_verified",
        "production_environment_verified",
    }
)
ACCESSIBILITY_RULES = [
    "document-language-en",
    "single-main-landmark",
    "single-source-matched-h1",
    "nonempty-document-title",
    "source-matched-meta-description",
    "image-alt-attribute",
]


class ProofError(ValueError):
    """A stable, redaction-safe production-documentation proof failure."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofError("mintlify_json_duplicate_key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> Any:
    raise ProofError("mintlify_json_nonfinite_number")


def load_json_value(payload: bytes, code: str) -> Any:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
        )
    except ProofError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProofError(code) from None
    return value


def load_json(payload: bytes, code: str) -> dict[str, Any]:
    value = load_json_value(payload, code)
    if not isinstance(value, dict):
        raise ProofError(code)
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def compact_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def result_digest(value: Any) -> str:
    return digest(compact_json(value))


def exact_object(value: Any, fields: set[str] | frozenset[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ProofError(code)
    return value


def positive_integer(value: Any, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ProofError(code)
    return value


def parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or CANONICAL_TIME.fullmatch(value) is None:
        raise ProofError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise ProofError(code) from None


def canonical_path(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ProofError(code)
    decoded = unquote(value)
    if "\\" in decoded or any(ord(character) < 32 for character in decoded):
        raise ProofError(code)
    parts = decoded.split("/")[1:]
    if decoded != "/" and any(part in ("", ".", "..") for part in parts):
        raise ProofError(code)
    normalized = decoded if decoded == "/" else decoded.rstrip("/")
    if normalized != value:
        raise ProofError(code)
    return normalized


def canonical_origin(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise ProofError(code)
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ProofError(code) from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ProofError(code)
    return f"https://{parsed.hostname.lower()}"


def live_url(path: str) -> str:
    return PRODUCTION_ORIGIN + ("/" if path == "/" else path)


def same_route(value: Any, path: str, code: str) -> bool:
    if not isinstance(value, str):
        raise ProofError(code)
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment:
        raise ProofError(code)
    origin = canonical_origin(f"{parsed.scheme}://{parsed.netloc}", code)
    observed_path = canonical_path(parsed.path or "/", code)
    return origin == PRODUCTION_ORIGIN and observed_path == path


def validate_documentation_coordinate(value: Any, expected_core_commit: str | None = None) -> dict[str, Any]:
    coordinate = exact_object(
        value,
        {
            "repository",
            "commit",
            "canonical_core_commit",
            "source_commit",
            "source_manifest_sha256",
            "source_tree_sha256",
            "owned_file_count",
        },
        "mintlify_source_coordinate_invalid",
    )
    if (
        coordinate.get("repository") != DOCUMENTATION_REPOSITORY_URL
        or any(
            COMMIT.fullmatch(str(coordinate.get(field, ""))) is None
            for field in ("commit", "canonical_core_commit", "source_commit")
        )
        or any(
            SHA256.fullmatch(str(coordinate.get(field, ""))) is None
            for field in ("source_manifest_sha256", "source_tree_sha256")
        )
        or not isinstance(coordinate.get("owned_file_count"), int)
        or isinstance(coordinate.get("owned_file_count"), bool)
        or not 1 <= coordinate["owned_file_count"] <= 4096
        or (
            expected_core_commit is not None
            and coordinate.get("canonical_core_commit") != expected_core_commit
        )
    ):
        raise ProofError("mintlify_source_coordinate_invalid")
    return coordinate


def _validate_http_observation(value: Any, *, exact_status: int | None, code: str) -> tuple[dict[str, Any], str]:
    item = exact_object(
        value,
        {"body_sha256", "bytes", "content_type", "final_url", "path", "status", "url"},
        code,
    )
    path = canonical_path(item.get("path"), code)
    status = item.get("status")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or (exact_status is not None and status != exact_status)
        or (exact_status is None and not 200 <= status < 300)
        or not isinstance(item.get("bytes"), int)
        or isinstance(item.get("bytes"), bool)
        or not 1 <= item["bytes"] <= 32 * 1024 * 1024
        or not isinstance(item.get("content_type"), str)
        or not item["content_type"]
        or len(item["content_type"]) > 128
        or SHA256.fullmatch(str(item.get("body_sha256", ""))) is None
        or item.get("url") != live_url(path)
        or not same_route(item.get("final_url"), path, code)
    ):
        raise ProofError(code)
    return item, path


def validate_observations(document: Mapping[str, Any]) -> None:
    observations = exact_object(
        document.get("observations"),
        {"ai_outputs", "link_relationships", "link_targets", "pages", "redirects"},
        "mintlify_observations_invalid",
    )
    bounds = {
        "pages": (100, 4096),
        "link_relationships": (1, 65536),
        "link_targets": (1, 8192),
        "redirects": (1, 4096),
        "ai_outputs": (22, 4098),
    }
    for name, (minimum, maximum) in bounds.items():
        values = observations.get(name)
        if not isinstance(values, list) or not minimum <= len(values) <= maximum:
            raise ProofError("mintlify_observations_invalid")

    pages = observations["pages"]
    page_paths: list[str] = []
    page_by_path: dict[str, dict[str, Any]] = {}
    source_paths: set[str] = set()
    for value in pages:
        item = exact_object(
            value,
            {
                "body_sha256", "bytes", "content_type", "description", "final_url",
                "h1_count", "image_count", "internal_link_count", "lang", "main_count",
                "missing_alt_count", "path", "source_path", "source_sha256", "status",
                "title", "url",
            },
            "mintlify_page_observation_invalid",
        )
        base = {key: item[key] for key in (
            "body_sha256", "bytes", "content_type", "final_url", "path", "status", "url"
        )}
        _, path = _validate_http_observation(
            base, exact_status=200, code="mintlify_page_observation_invalid"
        )
        if (
            item.get("content_type") != "text/html"
            or item.get("lang") != "en"
            or item.get("main_count") != 1
            or item.get("h1_count") != 1
            or item.get("missing_alt_count") != 0
            or any(
                not isinstance(item.get(field), int)
                or isinstance(item.get(field), bool)
                or item[field] < 0
                for field in ("image_count", "internal_link_count")
            )
            or not isinstance(item.get("title"), str)
            or not item["title"]
            or len(item["title"]) > 256
            or not isinstance(item.get("description"), str)
            or not item["description"]
            or len(item["description"]) > 1024
            or not isinstance(item.get("source_path"), str)
            or item["source_path"].startswith("/")
            or not item["source_path"].endswith(".mdx")
            or ".." in item["source_path"].split("/")
            or SHA256.fullmatch(str(item.get("source_sha256", ""))) is None
        ):
            raise ProofError("mintlify_page_observation_invalid")
        page_paths.append(path)
        if item["source_path"] in source_paths:
            raise ProofError("mintlify_page_observation_invalid")
        source_paths.add(item["source_path"])
        page_by_path[path] = item
    if page_paths != sorted(set(page_paths)):
        raise ProofError("mintlify_page_observation_invalid")

    relationship_pairs: list[tuple[str, str]] = []
    for value in observations["link_relationships"]:
        item = exact_object(
            value, {"source", "target"}, "mintlify_link_relationship_invalid"
        )
        relationship_pairs.append(
            (
                canonical_path(item.get("source"), "mintlify_link_relationship_invalid"),
                canonical_path(item.get("target"), "mintlify_link_relationship_invalid"),
            )
        )
    if relationship_pairs != sorted(set(relationship_pairs)):
        raise ProofError("mintlify_link_relationship_invalid")
    relationships_by_source: dict[str, int] = {}
    for source, _ in relationship_pairs:
        if source not in page_by_path:
            raise ProofError("mintlify_link_relationship_invalid")
        relationships_by_source[source] = relationships_by_source.get(source, 0) + 1
    if any(
        page["internal_link_count"] != relationships_by_source.get(path, 0)
        for path, page in page_by_path.items()
    ):
        raise ProofError("mintlify_link_relationship_invalid")

    link_paths: list[str] = []
    for value in observations["link_targets"]:
        _, path = _validate_http_observation(
            value, exact_status=None, code="mintlify_link_observation_invalid"
        )
        link_paths.append(path)
    if link_paths != sorted(set(link_paths)):
        raise ProofError("mintlify_link_observation_invalid")
    if set(link_paths) != {target for _, target in relationship_pairs}:
        raise ProofError("mintlify_link_observation_invalid")
    link_by_path = {
        item["path"]: item for item in observations["link_targets"]
    }
    for path in set(link_paths).intersection(page_by_path):
        page = page_by_path[path]
        if link_by_path[path] != {
            key: page[key]
            for key in (
                "body_sha256", "bytes", "content_type", "final_url", "path",
                "status", "url",
            )
        }:
            raise ProofError("mintlify_link_observation_invalid")

    redirect_sources: list[str] = []
    for value in observations["redirects"]:
        item = exact_object(
            value,
            {"destination", "location", "source", "status", "url"},
            "mintlify_redirect_observation_invalid",
        )
        source = canonical_path(item.get("source"), "mintlify_redirect_observation_invalid")
        destination = canonical_path(
            item.get("destination"), "mintlify_redirect_observation_invalid"
        )
        if (
            item.get("status") not in (301, 308)
            or source == destination
            or item.get("url") != live_url(source)
            or not isinstance(item.get("location"), str)
            or not item["location"]
        ):
            raise ProofError("mintlify_redirect_observation_invalid")
        resolved = urlsplit(urljoin(item["url"], item["location"]))
        if (
            canonical_origin(
                f"{resolved.scheme}://{resolved.netloc}",
                "mintlify_redirect_observation_invalid",
            )
            != PRODUCTION_ORIGIN
            or canonical_path(
                resolved.path or "/", "mintlify_redirect_observation_invalid"
            )
            != destination
            or resolved.query
            or resolved.fragment
        ):
            raise ProofError("mintlify_redirect_observation_invalid")
        redirect_sources.append(source)
    if redirect_sources != sorted(set(redirect_sources)):
        raise ProofError("mintlify_redirect_observation_invalid")
    if set(redirect_sources).intersection(
        target for _, target in relationship_pairs
    ):
        raise ProofError("mintlify_redirect_observation_invalid")

    ai_sequence: list[tuple[str, str]] = []
    markdown_count = 0
    index_outputs: set[tuple[str, str]] = set()
    for value in observations["ai_outputs"]:
        item = exact_object(
            value,
            {
                "body_sha256", "bytes", "content_type", "final_url", "kind",
                "path", "status", "title", "url",
            },
            "mintlify_ai_observation_invalid",
        )
        base = {key: item[key] for key in (
            "body_sha256", "bytes", "content_type", "final_url", "path", "status", "url"
        )}
        _, path = _validate_http_observation(
            base, exact_status=200, code="mintlify_ai_observation_invalid"
        )
        kind = item.get("kind")
        if kind == "markdown_page":
            markdown_count += 1
            page_route = "/" if path == "/index.md" else path.removesuffix(".md")
            if (
                item.get("content_type") != "text/markdown"
                or not path.endswith(".md")
                or page_route not in page_by_path
                or not isinstance(item.get("title"), str)
                or not item["title"]
                or item["title"] != page_by_path[page_route]["title"]
            ):
                raise ProofError("mintlify_ai_observation_invalid")
        elif kind in ("llms_txt", "llms_full_txt"):
            index_outputs.add((kind, path))
            if (
                item.get("content_type") != "text/plain"
                or item.get("title") is not None
                or (kind == "llms_txt" and path != "/llms.txt")
                or (kind == "llms_full_txt" and path != "/llms-full.txt")
                or (kind == "llms_full_txt" and item["bytes"] < 512)
            ):
                raise ProofError("mintlify_ai_observation_invalid")
        else:
            raise ProofError("mintlify_ai_observation_invalid")
        ai_sequence.append((kind, path))
    if ai_sequence != sorted(set(ai_sequence)):
        raise ProofError("mintlify_ai_observation_invalid")
    if index_outputs != {
        ("llms_txt", "/llms.txt"),
        ("llms_full_txt", "/llms-full.txt"),
    }:
        raise ProofError("mintlify_ai_observation_invalid")

    postdeploy = exact_object(
        document.get("postdeploy"),
        {"accessibility", "ai_outputs", "links", "pages", "redirects"},
        "mintlify_postdeploy_summary_invalid",
    )
    page_summary = exact_object(
        postdeploy.get("pages"), {"checked", "results_sha256"},
        "mintlify_postdeploy_summary_invalid",
    )
    accessibility = exact_object(
        postdeploy.get("accessibility"), {"pages_checked", "results_sha256", "rules"},
        "mintlify_postdeploy_summary_invalid",
    )
    links = exact_object(
        postdeploy.get("links"),
        {"relationships_checked", "relationships_sha256", "results_sha256", "targets_checked"},
        "mintlify_postdeploy_summary_invalid",
    )
    redirects = exact_object(
        postdeploy.get("redirects"), {"checked", "results_sha256"},
        "mintlify_postdeploy_summary_invalid",
    )
    ai = exact_object(
        postdeploy.get("ai_outputs"),
        {"index_entries_checked", "outputs_checked", "results_sha256", "source_llms_txt_sha256"},
        "mintlify_postdeploy_summary_invalid",
    )
    page_hash = result_digest(pages)
    if (
        page_summary != {"checked": len(pages), "results_sha256": page_hash}
        or accessibility
        != {
            "pages_checked": len(pages),
            "results_sha256": page_hash,
            "rules": ACCESSIBILITY_RULES,
        }
        or links
        != {
            "relationships_checked": len(relationship_pairs),
            "relationships_sha256": result_digest(relationship_pairs),
            "results_sha256": result_digest(observations["link_targets"]),
            "targets_checked": len(observations["link_targets"]),
        }
        or redirects
        != {
            "checked": len(observations["redirects"]),
            "results_sha256": result_digest(observations["redirects"]),
        }
        or ai.get("index_entries_checked") != markdown_count
        or markdown_count < 20
        or ai.get("outputs_checked") != len(observations["ai_outputs"])
        or ai["outputs_checked"] != markdown_count + 2
        or ai.get("results_sha256") != result_digest(observations["ai_outputs"])
        or SHA256.fullmatch(str(ai.get("source_llms_txt_sha256", ""))) is None
    ):
        raise ProofError("mintlify_postdeploy_summary_invalid")


def validate_evidence(
    value: Any,
    documentation: Mapping[str, Any],
    *,
    expected_run_id: int,
    expected_run_attempt: int,
    now: datetime,
) -> dict[str, Any]:
    document = exact_object(
        value,
        {
            "schema_version", "kind", "status", "repository", "source_checkpoint",
            "deployment", "workflow", "claims", "postdeploy", "observations",
            "started_at", "finished_at", "maximum_age_seconds",
        },
        "mintlify_evidence_fields_invalid",
    )
    if (
        document.get("schema_version") != 1
        or document.get("kind") != EVIDENCE_KIND
        or document.get("status") != "passed"
        or document.get("repository") != DOCUMENTATION_REPOSITORY_URL
        or document.get("maximum_age_seconds") != 86_400
    ):
        raise ProofError("mintlify_evidence_identity_invalid")
    claims = exact_object(document.get("claims"), CLAIMS, "mintlify_claims_invalid")
    if any(value is not True for value in claims.values()):
        raise ProofError("mintlify_claims_invalid")

    coordinate = validate_documentation_coordinate(documentation)
    checkpoint = exact_object(
        document.get("source_checkpoint"),
        {
            "documentation_commit", "canonical_core_commit", "source_manifest_sha256",
            "source_tree_sha256", "owned_file_count",
        },
        "mintlify_source_checkpoint_invalid",
    )
    expected_checkpoint = {
        "documentation_commit": coordinate["commit"],
        # The docs producer reads this value from .latchway-docs-source.json;
        # cross-repository conformance names the same revision source_commit.
        "canonical_core_commit": coordinate["source_commit"],
        "source_manifest_sha256": coordinate["source_manifest_sha256"],
        "source_tree_sha256": coordinate["source_tree_sha256"],
        "owned_file_count": coordinate["owned_file_count"],
    }
    if checkpoint != expected_checkpoint:
        raise ProofError("mintlify_source_checkpoint_invalid")

    workflow = exact_object(
        document.get("workflow"),
        {
            "repository", "path", "ref", "event", "expected_conclusion", "head_sha",
            "run_id", "run_attempt", "run_url",
        },
        "mintlify_workflow_identity_invalid",
    )
    if (
        workflow.get("repository") != DOCUMENTATION_REPOSITORY
        or workflow.get("path") != WORKFLOW_PATH
        or workflow.get("ref") != WORKFLOW_REF
        or workflow.get("event") not in ("deployment_status", "workflow_dispatch")
        or workflow.get("expected_conclusion") != "success"
        or workflow.get("head_sha") != coordinate["commit"]
        or workflow.get("run_id") != expected_run_id
        or workflow.get("run_attempt") != expected_run_attempt
        or workflow.get("run_url")
        != f"https://github.com/{DOCUMENTATION_REPOSITORY}/actions/runs/{expected_run_id}"
    ):
        raise ProofError("mintlify_workflow_identity_invalid")

    deployment = exact_object(
        document.get("deployment"),
        {
            "id", "status_id", "state", "environment", "production_environment",
            "transient_environment", "environment_url", "production_url", "actor",
            "created_at", "updated_at",
        },
        "mintlify_deployment_invalid",
    )
    if (
        positive_integer(deployment.get("id"), "mintlify_deployment_invalid") < 1
        or positive_integer(deployment.get("status_id"), "mintlify_deployment_invalid") < 1
        or deployment.get("state") != "success"
        or deployment.get("environment") != "production"
        or deployment.get("production_environment") is not True
        or deployment.get("transient_environment") is not False
        or deployment.get("production_url") != PRODUCTION_ORIGIN
        or deployment.get("actor") != MINTLIFY_ACTOR
        or deployment.get("environment_url") not in ALLOWED_ENVIRONMENT_ORIGINS
        or canonical_origin(
            deployment.get("environment_url"), "mintlify_deployment_invalid"
        )
        != deployment.get("environment_url")
    ):
        raise ProofError("mintlify_deployment_invalid")

    started = parse_time(document.get("started_at"), "mintlify_time_invalid")
    finished = parse_time(document.get("finished_at"), "mintlify_time_invalid")
    created = parse_time(deployment.get("created_at"), "mintlify_time_invalid")
    updated = parse_time(deployment.get("updated_at"), "mintlify_time_invalid")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    if (
        finished < started
        or finished - started > MAXIMUM_COLLECTION_WINDOW
        or updated < created
        or updated - started > MAXIMUM_CLOCK_SKEW
        or started - updated > MAXIMUM_AGE
        or finished - now > MAXIMUM_CLOCK_SKEW
        or now - finished > MAXIMUM_AGE
        or updated - now > MAXIMUM_CLOCK_SKEW
        or now - updated > MAXIMUM_AGE
    ):
        raise ProofError("mintlify_time_invalid")
    validate_observations(document)
    return document


def _normalize_run(
    value: Any,
    documentation: Mapping[str, Any],
    evidence: Mapping[str, Any],
    expected_run_id: int,
    expected_run_attempt: int,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProofError("mintlify_run_authority_invalid")
    workflow_id = positive_integer(value.get("workflow_id"), "mintlify_run_authority_invalid")
    if (
        value.get("id") != expected_run_id
        or value.get("run_attempt") != expected_run_attempt
        or value.get("event") != evidence["workflow"]["event"]
        or value.get("status") != "completed"
        or value.get("conclusion") != "success"
        or value.get("head_sha") != documentation["commit"]
        or value.get("head_branch") != "main"
        or value.get("path") != WORKFLOW_PATH
        or value.get("html_url") != evidence["workflow"]["run_url"]
        or not isinstance(value.get("repository"), dict)
        or value["repository"].get("full_name") != DOCUMENTATION_REPOSITORY
        or not isinstance(value.get("head_repository"), dict)
        or value["head_repository"].get("full_name") != DOCUMENTATION_REPOSITORY
    ):
        raise ProofError("mintlify_run_authority_invalid")
    return {
        "id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "event": evidence["workflow"]["event"],
        "status": "completed",
        "conclusion": "success",
        "head_sha": documentation["commit"],
        "head_branch": "main",
        "path": WORKFLOW_PATH,
        "html_url": evidence["workflow"]["run_url"],
        "workflow_id": workflow_id,
        "repository": DOCUMENTATION_REPOSITORY,
    }


def _normalize_workflow(value: Any, workflow_id: int) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("id") != workflow_id
        or value.get("path") != WORKFLOW_PATH
        or value.get("state") != "active"
    ):
        raise ProofError("mintlify_workflow_authority_invalid")
    return {"id": workflow_id, "path": WORKFLOW_PATH, "state": "active"}


def _normalize_artifact(
    value: Any,
    documentation: Mapping[str, Any],
    evidence: Mapping[str, Any],
    expected_run_id: int,
    expected_run_attempt: int,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("total_count") != 1
        or not isinstance(value.get("artifacts"), list)
        or len(value["artifacts"]) != 1
        or not isinstance(value["artifacts"][0], dict)
    ):
        raise ProofError("mintlify_artifact_authority_invalid")
    artifact = value["artifacts"][0]
    identifier = positive_integer(
        artifact.get("id"), "mintlify_artifact_authority_invalid"
    )
    size = positive_integer(
        artifact.get("size_in_bytes"), "mintlify_artifact_authority_invalid"
    )
    deployment_id = positive_integer(
        evidence["deployment"].get("id"), "mintlify_artifact_authority_invalid"
    )
    expected_name = (
        f"latchway-mintlify-production-{documentation['commit']}-{deployment_id}-"
        f"{expected_run_id}-{expected_run_attempt}"
    )
    workflow_run = artifact.get("workflow_run")
    if (
        artifact.get("name") != expected_name
        or artifact.get("expired") is not False
        or size > 16 * 1024 * 1024
        or artifact.get("archive_download_url")
        != f"https://api.github.com/repos/{DOCUMENTATION_REPOSITORY}/actions/artifacts/{identifier}/zip"
        or not isinstance(workflow_run, dict)
        or workflow_run.get("id") != expected_run_id
        or workflow_run.get("head_sha") != documentation["commit"]
    ):
        raise ProofError("mintlify_artifact_authority_invalid")
    return {
        "id": identifier,
        "name": expected_name,
        "size_in_bytes": size,
        "expired": False,
        "archive_download_url": artifact["archive_download_url"],
        "workflow_run": {
            "id": expected_run_id,
            "head_sha": documentation["commit"],
        },
    }


def build_proof(
    *,
    documentation: Mapping[str, Any],
    evidence_payload: bytes,
    checksum_payload: bytes,
    attestation_bundle_payload: bytes,
    run_payload: bytes,
    workflow_payload: bytes,
    artifact_payload: bytes,
    attestation_verification_payload: bytes,
    expected_run_id: int,
    expected_run_attempt: int,
    now: datetime,
) -> dict[str, Any]:
    coordinate = validate_documentation_coordinate(documentation)
    expected_run_id = positive_integer(expected_run_id, "mintlify_run_authority_invalid")
    expected_run_attempt = positive_integer(
        expected_run_attempt, "mintlify_run_authority_invalid"
    )
    evidence = load_json(evidence_payload, "mintlify_evidence_json_invalid")
    if canonical_json(evidence) != evidence_payload:
        raise ProofError("mintlify_evidence_not_canonical")
    validate_evidence(
        evidence,
        coordinate,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
        now=now,
    )
    evidence_sha = digest(evidence_payload)
    if checksum_payload != f"{evidence_sha}  {EVIDENCE_FILE}\n".encode("ascii"):
        raise ProofError("mintlify_checksum_invalid")
    attestation_bundle = load_json(
        attestation_bundle_payload, "mintlify_attestation_bundle_invalid"
    )
    if not attestation_bundle:
        raise ProofError("mintlify_attestation_bundle_invalid")
    attestation_verification = load_json_value(
        attestation_verification_payload,
        "mintlify_attestation_verification_invalid",
    )
    # gh may return either a result array at the root or an object containing
    # the verified result set.  The protected command's zero exit is retained
    # by its exact output hash; an empty JSON result is never accepted.
    if not isinstance(attestation_verification, (dict, list)) or not attestation_verification:
        raise ProofError("mintlify_attestation_verification_invalid")
    run = _normalize_run(
        load_json(run_payload, "mintlify_run_authority_invalid"),
        coordinate,
        evidence,
        expected_run_id,
        expected_run_attempt,
    )
    workflow = _normalize_workflow(
        load_json(workflow_payload, "mintlify_workflow_authority_invalid"),
        run["workflow_id"],
    )
    artifact = _normalize_artifact(
        load_json(artifact_payload, "mintlify_artifact_authority_invalid"),
        coordinate,
        evidence,
        expected_run_id,
        expected_run_attempt,
    )
    file_payloads = {
        EVIDENCE_FILE: evidence_payload,
        CHECKSUM_FILE: checksum_payload,
        ATTESTATION_FILE: attestation_bundle_payload,
        "run.json": run_payload,
        "workflow.json": workflow_payload,
        "artifact.json": artifact_payload,
        "attestation-verification.json": attestation_verification_payload,
    }
    proof = {
        "schema_version": 1,
        "kind": PROOF_KIND,
        "status": "passed",
        "documentation": dict(coordinate),
        "production_evidence": evidence,
        "authority": {
            "run": run,
            "workflow": workflow,
            "artifact": artifact,
            "subject_attestation": {
                "repository": DOCUMENTATION_REPOSITORY,
                "workflow": WORKFLOW_PATH,
                "source_ref": WORKFLOW_REF,
                "source_digest": coordinate["commit"],
                "signer_digest": coordinate["commit"],
                "deny_self_hosted_runners": True,
                "bundle_sha256": digest(attestation_bundle_payload),
                "verification_sha256": digest(attestation_verification_payload),
            },
        },
        "retained_files": {
            name: digest(payload) for name, payload in sorted(file_payloads.items())
        },
    }
    validate_retained_proof(proof, coordinate["canonical_core_commit"], now=now)
    return proof


def validate_retained_proof(
    value: Any,
    expected_core_commit: str,
    *,
    now: datetime,
) -> dict[str, Any]:
    proof = exact_object(
        value,
        {
            "schema_version", "kind", "status", "documentation",
            "production_evidence", "authority", "retained_files",
        },
        "mintlify_retained_proof_invalid",
    )
    if (
        proof.get("schema_version") != 1
        or proof.get("kind") != PROOF_KIND
        or proof.get("status") != "passed"
        or COMMIT.fullmatch(expected_core_commit) is None
    ):
        raise ProofError("mintlify_retained_proof_invalid")
    coordinate = validate_documentation_coordinate(
        proof.get("documentation"), expected_core_commit
    )
    authority = exact_object(
        proof.get("authority"),
        {"run", "workflow", "artifact", "subject_attestation"},
        "mintlify_retained_proof_invalid",
    )
    run = exact_object(
        authority.get("run"),
        {
            "id", "run_attempt", "event", "status", "conclusion", "head_sha",
            "head_branch", "path", "html_url", "workflow_id", "repository",
        },
        "mintlify_retained_proof_invalid",
    )
    evidence = validate_evidence(
        proof.get("production_evidence"),
        coordinate,
        expected_run_id=positive_integer(run.get("id"), "mintlify_retained_proof_invalid"),
        expected_run_attempt=positive_integer(
            run.get("run_attempt"), "mintlify_retained_proof_invalid"
        ),
        now=now,
    )
    expected_run = {
        "id": run["id"],
        "run_attempt": run["run_attempt"],
        "event": evidence["workflow"]["event"],
        "status": "completed",
        "conclusion": "success",
        "head_sha": coordinate["commit"],
        "head_branch": "main",
        "path": WORKFLOW_PATH,
        "html_url": evidence["workflow"]["run_url"],
        "workflow_id": positive_integer(
            run.get("workflow_id"), "mintlify_retained_proof_invalid"
        ),
        "repository": DOCUMENTATION_REPOSITORY,
    }
    if run != expected_run:
        raise ProofError("mintlify_retained_proof_invalid")
    if authority.get("workflow") != {
        "id": run["workflow_id"], "path": WORKFLOW_PATH, "state": "active"
    }:
        raise ProofError("mintlify_retained_proof_invalid")
    artifact = authority.get("artifact")
    expected_artifact_name = (
        f"latchway-mintlify-production-{coordinate['commit']}-"
        f"{evidence['deployment']['id']}-{run['id']}-{run['run_attempt']}"
    )
    if (
        not isinstance(artifact, dict)
        or set(artifact)
        != {
            "id", "name", "size_in_bytes", "expired", "archive_download_url",
            "workflow_run",
        }
        or positive_integer(
            artifact.get("id"), "mintlify_retained_proof_invalid"
        )
        < 1
        or artifact.get("name") != expected_artifact_name
        or not isinstance(artifact.get("size_in_bytes"), int)
        or isinstance(artifact.get("size_in_bytes"), bool)
        or not 1 <= artifact["size_in_bytes"] <= 16 * 1024 * 1024
        or artifact.get("expired") is not False
        or artifact.get("archive_download_url")
        != f"https://api.github.com/repos/{DOCUMENTATION_REPOSITORY}/actions/artifacts/{artifact['id']}/zip"
        or artifact.get("workflow_run")
        != {"id": run["id"], "head_sha": coordinate["commit"]}
    ):
        raise ProofError("mintlify_retained_proof_invalid")
    subject = exact_object(
        authority.get("subject_attestation"),
        {
            "repository", "workflow", "source_ref", "source_digest", "signer_digest",
            "deny_self_hosted_runners", "bundle_sha256", "verification_sha256",
        },
        "mintlify_retained_proof_invalid",
    )
    if (
        subject.get("repository") != DOCUMENTATION_REPOSITORY
        or subject.get("workflow") != WORKFLOW_PATH
        or subject.get("source_ref") != WORKFLOW_REF
        or subject.get("source_digest") != coordinate["commit"]
        or subject.get("signer_digest") != coordinate["commit"]
        or subject.get("deny_self_hosted_runners") is not True
        or SHA256.fullmatch(str(subject.get("bundle_sha256", ""))) is None
        or SHA256.fullmatch(str(subject.get("verification_sha256", ""))) is None
    ):
        raise ProofError("mintlify_retained_proof_invalid")
    retained = exact_object(
        proof.get("retained_files"), RETAINED_FILES, "mintlify_retained_proof_invalid"
    )
    if any(SHA256.fullmatch(str(value)) is None for value in retained.values()):
        raise ProofError("mintlify_retained_proof_invalid")
    evidence_payload = canonical_json(evidence)
    evidence_sha = digest(evidence_payload)
    expected_checksum = f"{evidence_sha}  {EVIDENCE_FILE}\n".encode("ascii")
    if (
        retained[EVIDENCE_FILE] != evidence_sha
        or retained[CHECKSUM_FILE] != digest(expected_checksum)
        or retained[ATTESTATION_FILE] != subject["bundle_sha256"]
        or retained["attestation-verification.json"]
        != subject["verification_sha256"]
    ):
        raise ProofError("mintlify_retained_proof_invalid")
    return proof
