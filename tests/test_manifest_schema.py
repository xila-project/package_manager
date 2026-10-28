"""Repository-hosted JSON Schema regression tests for experimental v1 manifests.

Requires: python -m pip install jsonschema==4.25.1
This test checks *editor-facing* structural validation. Runtime trust, hashing,
path uniqueness and cross-file entrypoint resolution are checked in Rust.
"""
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_URL = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/package-manifest.schema.json"
SCHEMA = json.loads((ROOT / "schemas/package-manifest.schema.json").read_text(encoding="utf-8"))
FIXTURE = json.loads((ROOT / "tests/fixtures/package-workflow-manifest.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


class ManifestSchemaTests(unittest.TestCase):
    def test_schema_is_valid_and_points_to_canonical_github_path(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.assertEqual(SCHEMA["$id"], SCHEMA_URL)
        self.assertEqual(FIXTURE["$schema"], SCHEMA_URL)

    def test_standalone_executable_package(self):
        VALIDATOR.validate(FIXTURE)
        self.assertEqual(FIXTURE["format_version"], 1)
        package = copy.deepcopy(FIXTURE)
        package["$schema"] = None
        VALIDATOR.validate(package)

    def test_application_bundle(self):
        bundle = copy.deepcopy(FIXTURE)
        bundle["files"].append({
            "path": "resources/icon.png",
            "size": 3,
            "sha256": "a" * 64,
        })
        bundle["application"] = {
            "entrypoint": "bin/example.wasm",
            "display_name": "Example",
            "icon": "resources/icon.png",
            "show_in_launcher": True,
        }
        VALIDATOR.validate(bundle)

    def test_builtin_native_application_without_embedded_files(self):
        built_in = copy.deepcopy(FIXTURE)
        built_in["files"] = []
        built_in["application"] = {
            "entrypoint": "/system/executables/settings",
            "display_name": "Settings",
            "icon": "",
            "show_in_launcher": True,
        }
        VALIDATOR.validate(built_in)

    def test_rejects_invalid_or_unexpected_fields(self):
        invalid = copy.deepcopy(FIXTURE)
        for changes in [
            {"format_version": 2},
            {"name": "InvalidName"},
            {"name": "../escape"},
            {"version": "foo bar"},
            {"target": "wasm/invalid"},
            {"minimum_xila_abi": -1},
            {"$schema": "https://example.com/untrusted.schema.json"},
            {"application": []},
            {"files": []},
            {"extra": "field"},
        ]:
            candidate = dict(invalid, **changes)
            with self.subTest(changes=changes):
                self.assertFalse(VALIDATOR.is_valid(candidate))

    def test_rejects_unsafe_file_paths_and_invalid_digests(self):
        for path in ["../escape", "/absolute", "bin//bad", "./tool", ".xila/manifest.json", "bin/../escape"]:
            package = copy.deepcopy(FIXTURE)
            package["files"][0]["path"] = path
            with self.subTest(path=path):
                self.assertFalse(VALIDATOR.is_valid(package))
        package = copy.deepcopy(FIXTURE)
        package["files"][0]["sha256"] = "x" * 64
        self.assertFalse(VALIDATOR.is_valid(package))

    def test_rejects_application_invalid_paths_and_properties(self):
        app = {
            "entrypoint": "bin/example.wasm",
            "display_name": "Example",
            "icon": "",
            "show_in_launcher": True,
        }
        for changes in [
            {"entrypoint": "../escape"},
            {"entrypoint": "/etc/passwd"},
            {"icon": "../escape.png"},
            {"display_name": "   "},
            {"show_in_launcher": "yes"},
            {"unsupported": True},
        ]:
            package = copy.deepcopy(FIXTURE)
            package["application"] = dict(app, **changes)
            with self.subTest(changes=changes):
                self.assertFalse(VALIDATOR.is_valid(package))


if __name__ == "__main__":
    unittest.main()
