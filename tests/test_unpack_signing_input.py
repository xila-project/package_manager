import importlib.util
from pathlib import Path
import io
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("unpack", Path(__file__).resolve().parents[1] / "tools" / "unpack_signing_input.py")
unpack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(unpack)

class SigningInputTests(unittest.TestCase):
    def test_extracts_only_manifest_and_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.tar"
            with tarfile.open(source, "w") as tar:
                for name, data in [("xila-package-manifest.json", b"{}"), ("xila-package-payload/bin/a.wasm", b"wasm")]:
                    member = tarfile.TarInfo(name); member.size = len(data); tar.addfile(member, io.BytesIO(data))
            output = root / "output"; output.mkdir()
            unpack.extract(source, output)
            self.assertEqual((output / "xila-package-payload/bin/a.wasm").read_bytes(), b"wasm")
    def test_rejects_escape_and_links(self):
        for name, link in [("../escape", False), ("xila-package-payload/link", True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); source = root / "source.tar"
                with tarfile.open(source, "w") as tar:
                    member = tarfile.TarInfo(name)
                    if link: member.type = tarfile.SYMTYPE; member.linkname = "/etc/passwd"
                    tar.addfile(member)
                output = root / "output"; output.mkdir()
                with self.assertRaises(ValueError): unpack.extract(source, output)
