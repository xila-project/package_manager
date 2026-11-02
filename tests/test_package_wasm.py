"""Safety and staging regression tests for reusable package workflow inputs."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools" / "package_wasm.py"
spec = importlib.util.spec_from_file_location("package_wasm", MODULE)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class StageTests(unittest.TestCase):
    def test_rejects_escape_absolute_path_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            (root / "example.wasm").write_bytes(b"\0asm\1\0\0\0")
            self.assertEqual(helper.within(root, "example.wasm"), root / "example.wasm")
            for value in ("../escape.wasm", "/tmp/escape.wasm", "./example.wasm", "bad//name"):
                with self.assertRaises(ValueError):
                    helper.within(root, value)
            (root / "linked.wasm").symlink_to(root / "example.wasm")
            with self.assertRaises(ValueError):
                helper.within(root, "linked.wasm")

    def test_rejects_legacy_runtime_manifest_instead_of_developer_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "example.wasm").write_bytes(b"\0asm\1\0\0\0")
            (root / "manifest.json").write_text(json.dumps({
                "files": [{"path": "a.wasm"}, {"path": "b.wasm"}]
            }))
            with self.assertRaisesRegex(ValueError, "developer manifests"):
                helper.pack(
                    wasm_root=root, wasm_path="example.wasm",
                    manifest_root=root, manifest_path="manifest.json",
                    staging=root / "stage", manifest_output=root / "prepared.json",
                    output=root / "dist", builder=root / "nonexistent",
                )


if __name__ == "__main__":
    unittest.main()
