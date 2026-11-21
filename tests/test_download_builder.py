"""Regression tests for downloading and verifying published xila-package binaries."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "tools" / "download_builder.py"
SPECIFICATION = importlib.util.spec_from_file_location("download_builder", MODULE)
assert SPECIFICATION is not None and SPECIFICATION.loader is not None
helper = importlib.util.module_from_spec(SPECIFICATION)
SPECIFICATION.loader.exec_module(helper)


def build_archive(destination: Path, entries: list[tuple[str, bytes, int]]) -> str:
    """Create a gzip-compressed tar archive and return its SHA-256 digest."""
    with tarfile.open(destination, mode="w:gz") as archive:
        for name, payload, mode in entries:
            member = tarfile.TarInfo(name=name)
            member.size = len(payload)
            member.mode = mode
            archive.addfile(member, io.BytesIO(payload))
    return hashlib.sha256(destination.read_bytes()).hexdigest()


class DownloadBuilderTests(unittest.TestCase):
    def test_rejects_missing_or_mismatched_release_inputs(self):
        valid_digest = "a" * 64
        with self.assertRaisesRegex(ValueError, "provided together"):
            helper.parse_release_inputs("xila-package-builder-v0.4.0", "")
        with self.assertRaisesRegex(ValueError, "provided together"):
            helper.parse_release_inputs("", valid_digest)
        with self.assertRaisesRegex(ValueError, "required"):
            helper.parse_release_inputs("", "")
        for bad_tag in (
            "v0.4.0",
            "-xila-package-builder-v0.4.0",
            "xila-package-builder-v0.4",
            "xila-package-builder-v0.4.0/extra",
        ):
            with self.assertRaises(ValueError):
                helper.parse_release_inputs(bad_tag, valid_digest)
        for bad_digest in ("abc", "A" * 64, "g" * 64):
            with self.assertRaises(ValueError):
                helper.parse_release_inputs("xila-package-builder-v0.4.0", bad_digest)

    def test_installs_verified_archive_and_checks_version(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / helper.ARCHIVE_NAME
            script = b"#!/bin/sh\necho 'xila-package 0.4.0'\n"
            digest = build_archive(archive_path, [("xila-package", script, 0o755)])
            output_path = root / "installed" / "xila-package"

            version = helper.install_verified_archive(
                archive_path,
                "xila-package-builder-v0.4.0",
                digest,
                output_path,
            )

            self.assertEqual(version, "xila-package 0.4.0")
            self.assertTrue(output_path.is_file())
            self.assertEqual(output_path.read_bytes(), script)

    def test_rejects_sha256_mismatch_without_extracting(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / helper.ARCHIVE_NAME
            build_archive(archive_path, [("xila-package", b"#!/bin/sh\necho 'xila-package 0.4.0'\n", 0o755)])
            output_path = root / "installed" / "xila-package"

            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                helper.install_verified_archive(
                    archive_path,
                    "xila-package-builder-v0.4.0",
                    "0" * 64,
                    output_path,
                )

            self.assertFalse(output_path.exists())

    def test_rejects_version_mismatch_and_removes_binary(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / helper.ARCHIVE_NAME
            digest = build_archive(
                archive_path,
                [("xila-package", b"#!/bin/sh\necho 'xila-package 0.3.2'\n", 0o755)],
            )
            output_path = root / "installed" / "xila-package"

            with self.assertRaisesRegex(ValueError, "version mismatch"):
                helper.install_verified_archive(
                    archive_path,
                    "xila-package-builder-v0.4.0",
                    digest,
                    output_path,
                )

            self.assertFalse(output_path.exists())

    def test_rejects_unsafe_tar_entries(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "installed" / "xila-package"

            traversal_archive = root / "traversal.tar.gz"
            traversal_digest = build_archive(
                traversal_archive,
                [("../xila-package", b"#!/bin/sh\necho 'xila-package 0.4.0'\n", 0o755)],
            )
            with self.assertRaisesRegex(ValueError, "unexpected archive entry"):
                helper.install_verified_archive(
                    traversal_archive,
                    "xila-package-builder-v0.4.0",
                    traversal_digest,
                    output_path,
                )

            extra_archive = root / "extra.tar.gz"
            extra_digest = build_archive(
                extra_archive,
                [
                    ("xila-package", b"#!/bin/sh\necho 'xila-package 0.4.0'\n", 0o755),
                    ("README.txt", b"unexpected", 0o644),
                ],
            )
            with self.assertRaisesRegex(ValueError, "unexpected archive entry"):
                helper.install_verified_archive(
                    extra_archive,
                    "xila-package-builder-v0.4.0",
                    extra_digest,
                    output_path,
                )

            symlink_archive = root / "symlink.tar.gz"
            with tarfile.open(symlink_archive, mode="w:gz") as archive:
                member = tarfile.TarInfo(name="xila-package")
                member.type = tarfile.SYMTYPE
                member.linkname = "/bin/sh"
                archive.addfile(member)
            symlink_digest = hashlib.sha256(symlink_archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "unsupported archive entry type"):
                helper.install_verified_archive(
                    symlink_archive,
                    "xila-package-builder-v0.4.0",
                    symlink_digest,
                    output_path,
                )

            for entry_type, link_name in ((tarfile.LNKTYPE, "other"), (tarfile.CHRTYPE, "")):
                special_archive = root / f"special-{entry_type!r}.tar.gz"
                with tarfile.open(special_archive, mode="w:gz") as archive:
                    member = tarfile.TarInfo(name="xila-package")
                    member.type = entry_type
                    member.linkname = link_name
                    archive.addfile(member)
                special_digest = hashlib.sha256(special_archive.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError, "unsupported archive entry type"):
                    helper.install_verified_archive(
                        special_archive,
                        "xila-package-builder-v0.4.0",
                        special_digest,
                        output_path,
                    )


if __name__ == "__main__":
    unittest.main()
