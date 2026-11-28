"""Registry namespace file schema regression tests, and the identifier rule shared by the package schemas."""

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


SCHEMA = load("schemas/registry-namespace.schema.json")
VALIDATOR = Draft202012Validator(SCHEMA)
NAMESPACE = load("tests/fixtures/registry-namespace.json")
IDENTIFIER_SCHEMAS = [
    "schemas/package-manifest.schema.json",
    "schemas/developer-manifest.schema.json",
    "schemas/registry-entry.schema.json",
]

VALID_IDENTIFIERS = [
    "example.xila.weather",
    "io.github.alice.weather",
    "example.xila.tools.clock",
    "example.xila.pixel-painter",
    "example.xila.pixel_painter",
    "dev.xila.calculator",
    "dev.xila.pixel-painter",
]
INVALID_IDENTIFIERS = [
    "weather",
    "example.xila",
    "community.weather",
    "xilax.clock",
    "Example.xila.weather",
    "example.xila.Weather",
    "example..weather",
    "example.xila.weather.",
    "example.xila.-weather",
    "example.xila.weather_",
    "example.xila.wea/ther",
    "xila.clock",
    "xila.Clock",
    "example.xila." + "a" * 96,
]


class RegistryNamespaceSchemaTests(unittest.TestCase):
    def test_accepts_namespace_files(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.assertEqual(SCHEMA["$id"], NAMESPACE["$schema"])
        VALIDATOR.validate(NAMESPACE)
        for namespace, kind, name in [
            ("example.xila.tools", "domain", "tools.xila.example"),
            ("io.github.alice", "github", "alice"),
            ("io.gitlab.alice_b", "gitlab", "alice_b"),
        ]:
            document = copy.deepcopy(NAMESPACE)
            document["namespace"] = namespace
            document["owner"] = {"kind": kind, "name": name}
            with self.subTest(namespace=namespace):
                VALIDATOR.validate(document)

    def test_rejects_invalid_namespace_files(self):
        for change in [
            lambda n: n.update(format_version=1),
            lambda n: n.update(namespace="org"),
            lambda n: n.update(namespace="xila"),
            lambda n: n.update(namespace="Example.Xila"),
            lambda n: n.update(namespace="example.xila."),
            lambda n: n.update(developer_keys=[]),
            lambda n: n.update(extra=True),
            lambda n: n.pop("owner"),
            lambda n: n["owner"].update(kind="email"),
            lambda n: n["owner"].update(extra=True),
            # Account namespaces are owned by the account, never by a domain.
            lambda n: n.update(namespace="io.github", owner={"kind": "domain", "name": "github.io"}),
            lambda n: n.update(namespace="io.gitlab", owner={"kind": "domain", "name": "gitlab.io"}),
            lambda n: n.update(namespace="io.github.alice", owner={"kind": "domain", "name": "alice.github.io"}),
            lambda n: n.update(namespace="example.xila", owner={"kind": "github", "name": "alice"}),
            lambda n: n.update(namespace="io.github.alice.tools", owner={"kind": "github", "name": "alice"}),
            lambda n: n.update(namespace="io.github.alice_b", owner={"kind": "github", "name": "alice_b"}),
            lambda n: n.update(namespace="example.my_site", owner={"kind": "domain", "name": "my_site.example"}),
        ]:
            broken = copy.deepcopy(NAMESPACE)
            change(broken)
            with self.subTest(broken=broken):
                self.assertFalse(VALIDATOR.is_valid(broken))

    def test_package_identifiers_are_reverse_domain(self):
        for path in IDENTIFIER_SCHEMAS:
            name = Draft202012Validator(load(path)["properties"]["name"])
            for identifier in VALID_IDENTIFIERS:
                with self.subTest(schema=path, identifier=identifier):
                    self.assertTrue(name.is_valid(identifier))
            for identifier in INVALID_IDENTIFIERS:
                with self.subTest(schema=path, identifier=identifier):
                    self.assertFalse(name.is_valid(identifier))


if __name__ == "__main__":
    unittest.main()
