"""Editor-facing Xila developer manifest schema regression tests."""

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "schemas/developer-manifest.schema.json").read_text(encoding="utf-8")
)
VALIDATOR = Draft202012Validator(SCHEMA)

VALID_SOURCE = {
    "$schema": "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/developer-manifest.schema.json",
    "format_version": 1,
    "name": "community.weather",
    "version": "1.0.0",
    "target": "wasm32-wasip1",
    "minimum_xila_abi": 1,
    "capabilities": [],
    "application": {
        "entrypoint": "bin/weather.wasm",
        "display_name": "Weather",
        "icon": "resources/icon.png",
        "show_in_launcher": True,
    },
}


class DeveloperManifestSchemaTests(unittest.TestCase):
    def test_accepts_editable_metadata_without_generated_hashes(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.assertEqual(SCHEMA["$id"], VALID_SOURCE["$schema"])
        VALIDATOR.validate(VALID_SOURCE)
        standalone = copy.deepcopy(VALID_SOURCE)
        standalone["application"] = None
        VALIDATOR.validate(standalone)

    def test_generated_metadata_is_rejected_in_developer_manifest(self):
        for changes in [
            {"files": []},
            {"signature": "deadbeef"},
            {"sha256": "00" * 32},
            {"$schema": "https://example.org/untrusted-schema"},
            {"name": "../escape"},
            {"application": {"entrypoint": "../escape"}},
            {"format_version": 2},
        ]:
            candidate = copy.deepcopy(VALID_SOURCE)
            candidate.update(changes)
            with self.subTest(changes=changes):
                self.assertFalse(VALIDATOR.is_valid(candidate))


if __name__ == "__main__":
    unittest.main()
