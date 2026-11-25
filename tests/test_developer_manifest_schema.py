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
    "format_version": 2,
    "name": "example.xila.weather",
    "version": "1.0.0",
    "target": "wasm32-wasip1",
    "xila_version": "0.1",
    "capabilities": [],
    "application": {
        "entrypoint": "executables/weather.wasm",
        "display_name": "Weather",
        "icon": "resources/icon.png",
        "show_in_launcher": True,
    },
}


class DeveloperManifestSchemaTests(unittest.TestCase):
    def test_metadata_is_optional_and_validated(self):
        with_metadata = copy.deepcopy(VALID_SOURCE)
        with_metadata["metadata"] = {
            "summary": "Shows the current weather",
            "license": "Apache-2.0 OR MIT",
            "source": "https://github.com/example/weather",
            "homepage": None,
        }
        VALIDATOR.validate(with_metadata)
        for key, value in [("summary", ""), ("license", "MIT; rm"), ("source", "http://insecure"), ("homepage", "ftp://x")]:
            broken = copy.deepcopy(with_metadata)
            broken["metadata"][key] = value
            with self.subTest(key=key):
                self.assertFalse(VALIDATOR.is_valid(broken))
        missing = copy.deepcopy(with_metadata)
        del missing["metadata"]["license"]
        self.assertFalse(VALIDATOR.is_valid(missing))

    def test_metadata_control_characters_and_byte_limits(self):
        with_metadata = copy.deepcopy(VALID_SOURCE)
        with_metadata["metadata"] = {
            "summary": "Shows the current weather",
            "license": "Apache-2.0 OR MIT",
            "source": "https://github.com/example/weather",
            "homepage": None,
        }
        with self.subTest(test="U+0085 in summary is rejected"):
            broken = copy.deepcopy(with_metadata)
            broken["metadata"]["summary"] = "Shows\u0085weather"
            self.assertFalse(VALIDATOR.is_valid(broken))
        with self.subTest(test="129 é in summary is accepted by schema"):
            accepted = copy.deepcopy(with_metadata)
            accepted["metadata"]["summary"] = "é" * 129
            VALIDATOR.validate(accepted)
        with self.subTest(test="U+0085 in source URL is rejected"):
            broken = copy.deepcopy(with_metadata)
            broken["metadata"]["source"] = "https://github.com\u0085example/weather"
            self.assertFalse(VALIDATOR.is_valid(broken))
        with self.subTest(test="U+0085 in homepage URL is rejected"):
            broken = copy.deepcopy(with_metadata)
            broken["metadata"]["homepage"] = "https://example.com\u0085page"
            self.assertFalse(VALIDATOR.is_valid(broken))

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
            {"$schema": "https://xila.example/untrusted-schema"},
            {"name": "../escape"},
            {"application": {"entrypoint": "../escape"}},
            {"format_version": 1},
            {"xila_version": "1.2.3"},
        ]:
            candidate = copy.deepcopy(VALID_SOURCE)
            candidate.update(changes)
            with self.subTest(changes=changes):
                self.assertFalse(VALIDATOR.is_valid(candidate))


if __name__ == "__main__":
    unittest.main()
