"""Developer key schema regression tests (fixture: the published xila-project key)."""

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/developer-key.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
KEY = json.loads((ROOT / "tests/fixtures/developer-key.json").read_text(encoding="utf-8"))


class DeveloperKeySchemaTests(unittest.TestCase):
    def test_accepts_published_key(self):
        Draft202012Validator.check_schema(SCHEMA)
        VALIDATOR.validate(KEY)

    def test_rejects_invalid_keys(self):
        for key, value in [
            ("id", "Xila Project"),
            ("algorithm", "rsa"),
            ("public_key", "AAAA"),
            ("public_key", "6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbd="),
            ("namespaces", []),
            ("namespaces", ["Xila"]),
            ("openssh", "ssh-rsa AAAA"),
        ]:
            broken = copy.deepcopy(KEY)
            broken[key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(VALIDATOR.is_valid(broken))


if __name__ == "__main__":
    unittest.main()
