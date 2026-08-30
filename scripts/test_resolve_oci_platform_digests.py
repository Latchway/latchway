import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("resolve-oci-platform-digests.py")
SPEC = importlib.util.spec_from_file_location("resolve_oci_platform_digests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def descriptor(os_name, architecture, digest_character, *, size=100, variant=None):
    platform = {"os": os_name, "architecture": architecture}
    if variant is not None:
        platform["variant"] = variant
    return {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": f"sha256:{digest_character * 64}",
        "size": size,
        "platform": platform,
    }


def index(*manifests):
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": list(manifests),
    }


class ResolveOCIPlatformDigestsTests(unittest.TestCase):
    def test_resolves_required_children_and_ignores_attestations(self):
        document = index(
            descriptor("linux", "amd64", "a"),
            descriptor("unknown", "unknown", "c"),
            descriptor("linux", "arm64", "b", variant="v8"),
        )
        self.assertEqual(
            MODULE.resolve_platform_digests(
                document, ["linux/amd64", "linux/arm64"]
            ),
            {
                "linux/amd64": f"sha256:{'a' * 64}",
                "linux/arm64": f"sha256:{'b' * 64}",
            },
        )

    def test_rejects_missing_or_duplicate_platform(self):
        with self.assertRaisesRegex(ValueError, "missing required"):
            MODULE.resolve_platform_digests(
                index(descriptor("linux", "amd64", "a")),
                ["linux/amd64", "linux/arm64"],
            )
        with self.assertRaisesRegex(ValueError, "duplicated"):
            MODULE.resolve_platform_digests(
                index(
                    descriptor("linux", "amd64", "a"),
                    descriptor("linux", "amd64", "b"),
                ),
                ["linux/amd64"],
            )

    def test_rejects_malformed_digest_and_size(self):
        malformed = descriptor("linux", "amd64", "a")
        malformed["digest"] = "sha256:abc"
        with self.assertRaisesRegex(ValueError, "invalid digest"):
            MODULE.resolve_platform_digests(
                index(malformed), ["linux/amd64"]
            )
        with self.assertRaisesRegex(ValueError, "descriptor size"):
            MODULE.resolve_platform_digests(
                index(descriptor("linux", "amd64", "a", size=True)),
                ["linux/amd64"],
            )

    def test_rejects_invalid_index_and_child_media_types(self):
        document = index(descriptor("linux", "amd64", "a"))
        document["mediaType"] = "application/json"
        with self.assertRaisesRegex(ValueError, "index mediaType"):
            MODULE.resolve_platform_digests(document, ["linux/amd64"])
        child = descriptor("linux", "amd64", "a")
        child["mediaType"] = "application/json"
        with self.assertRaisesRegex(ValueError, "unsupported mediaType"):
            MODULE.resolve_platform_digests(index(child), ["linux/amd64"])

    def test_output_keys_are_github_output_safe(self):
        self.assertEqual(MODULE.output_key("linux/arm64/v8"), "linux_arm64_v8")


if __name__ == "__main__":
    unittest.main()
