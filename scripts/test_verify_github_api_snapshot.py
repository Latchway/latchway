from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("verify-github-api-snapshot.py")
SPEC = importlib.util.spec_from_file_location("verify_github_api_snapshot", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GitHubAPISnapshotTests(unittest.TestCase):
    def test_parses_etag_bound_json_and_conditional_304(self) -> None:
        etag, body = MODULE.parse(
            b'HTTP/2 200\r\netag: W/"abc123"\r\ncontent-type: application/json\r\n\r\n{"id":42}\n',
            200,
        )
        self.assertEqual(etag, 'W/"abc123"')
        self.assertEqual(body, b'{"id":42}\n')
        self.assertEqual(
            MODULE.parse(b'HTTP/2 304\r\netag: W/"abc123"\r\n\r\n', 304),
            ('W/"abc123"', b''),
        )

    def test_rejects_status_body_and_etag_substitution(self) -> None:
        cases = (
            (b'HTTP/2 200\r\n\r\n{}', 200),
            (b'HTTP/2 201\r\netag: "x"\r\n\r\n{}', 200),
            (b'HTTP/2 200\r\netag: injected\nheader\r\n\r\n{}', 200),
            (b'HTTP/2 304\r\n\r\n{"changed":true}', 304),
        )
        for payload, status in cases:
            with self.subTest(payload=payload), self.assertRaises(MODULE.SnapshotError):
                MODULE.parse(payload, status)


if __name__ == "__main__":
    unittest.main()
