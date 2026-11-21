#!/usr/bin/env python3
"""Download, verify, extract, and validate a published xila-package executable."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ARCHIVE_NAME = "xila-package-x86_64-unknown-linux-gnu.tar.gz"
BINARY_NAME = "xila-package"
DEFAULT_REPOSITORY = "xila-project/package_manager"
MAXIMUM_BINARY_BYTES = 64 * 1024 * 1024
RELEASE_TAG_PATTERN = re.compile(
    r"^xila-package-builder-v([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$"
)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def parse_release_inputs(release_tag: str, expected_sha256: str) -> tuple[str, str, str]:
    """Validate release tag and SHA-256 inputs and return (tag, version, digest)."""
    if bool(release_tag) != bool(expected_sha256):
        raise ValueError("both --release and --sha256 must be provided together")
    if not release_tag:
        raise ValueError("--release and --sha256 are required")
    tag_match = RELEASE_TAG_PATTERN.fullmatch(release_tag)
    if tag_match is None:
        raise ValueError(
            f"invalid builder release tag {release_tag!r}; expected xila-package-builder-v<version>"
        )
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ValueError(
            "invalid builder SHA-256 digest; expected 64 lowercase hexadecimal characters"
        )
    return release_tag, tag_match.group(1), expected_sha256


def compute_sha256(path: Path) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of a regular file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_release_archive(
    release_tag: str,
    repository: str,
    destination_directory: Path,
) -> Path:
    """Download the published Linux x86_64 archive via GitHub CLI."""
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError(f"invalid repository slug {repository!r}")
    subprocess.run(
        [
            "gh",
            "release",
            "download",
            release_tag,
            "--repo",
            repository,
            "--pattern",
            ARCHIVE_NAME,
            "--dir",
            str(destination_directory),
        ],
        check=True,
    )
    archive_path = destination_directory / ARCHIVE_NAME
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError(f"downloaded archive missing or invalid: {archive_path}")
    return archive_path


def extract_builder_binary(archive_path: Path, output_path: Path) -> None:
    """Safely extract the single xila-package executable from a verified archive."""
    if output_path.is_symlink() or (output_path.exists() and output_path.is_dir()):
        raise ValueError(f"refusing invalid output path: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staged_path: Path | None = None
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            extracted_count = 0
            for member in archive:
                if not member.isfile():
                    raise ValueError(f"unsupported archive entry type: {member.name!r}")
                normalized_name = (
                    member.name[2:] if member.name.startswith("./") else member.name
                )
                if normalized_name != BINARY_NAME:
                    raise ValueError(f"unexpected archive entry: {member.name!r}")
                if extracted_count > 0:
                    raise ValueError("archive contains duplicate xila-package entries")
                if member.size <= 0 or member.size > MAXIMUM_BINARY_BYTES:
                    raise ValueError("builder executable size is outside allowed bounds")
                source_stream = archive.extractfile(member)
                if source_stream is None:
                    raise ValueError("unreadable builder executable entry")
                descriptor, staged_name = tempfile.mkstemp(
                    prefix=f".{BINARY_NAME}-",
                    dir=output_path.parent,
                )
                staged_path = Path(staged_name)
                bytes_written = 0
                with source_stream, os.fdopen(descriptor, "wb") as target_stream:
                    while True:
                        chunk = source_stream.read(64 * 1024)
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        if bytes_written > MAXIMUM_BINARY_BYTES:
                            raise ValueError("builder executable exceeds maximum allowed size")
                        target_stream.write(chunk)
                if bytes_written != member.size:
                    raise ValueError("builder executable size mismatch during extraction")
                extracted_count += 1
            if extracted_count != 1:
                raise ValueError(f"archive missing {BINARY_NAME} executable")
        assert staged_path is not None
        os.chmod(staged_path, 0o755)
        os.replace(staged_path, output_path)
        staged_path = None
    finally:
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)


def verify_binary_version(executable_path: Path, expected_version: str) -> str:
    """Execute xila-package --version and assert it matches the release version."""
    expected_line = f"{BINARY_NAME} {expected_version}"
    try:
        completed_process = subprocess.run(
            [str(executable_path), "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        executable_path.unlink(missing_ok=True)
        raise ValueError(f"failed to execute {executable_path} --version") from error
    actual_line = completed_process.stdout.strip()
    if actual_line != expected_line:
        executable_path.unlink(missing_ok=True)
        raise ValueError(
            f"builder version mismatch: expected {expected_line!r}, got {actual_line!r}"
        )
    return actual_line


def install_verified_archive(
    archive_path: Path,
    release_tag: str,
    expected_sha256: str,
    output_path: Path,
) -> str:
    """Verify archive digest, extract xila-package, and verify its version output."""
    _, expected_version, normalized_sha256 = parse_release_inputs(
        release_tag,
        expected_sha256,
    )
    actual_sha256 = compute_sha256(archive_path)
    if not hmac.compare_digest(actual_sha256, normalized_sha256):
        raise ValueError(
            f"builder archive SHA-256 mismatch: expected {normalized_sha256}, got {actual_sha256}"
        )
    extract_builder_binary(archive_path, output_path)
    return verify_binary_version(output_path, expected_version)


def install_release_builder(
    *,
    release_tag: str,
    expected_sha256: str,
    output_path: Path,
    repository: str = DEFAULT_REPOSITORY,
) -> str:
    """Download, verify, extract, and validate a published xila-package executable."""
    validated_tag, _, validated_sha256 = parse_release_inputs(
        release_tag,
        expected_sha256,
    )
    with tempfile.TemporaryDirectory(prefix="xila-package-release-") as temporary_directory:
        archive_path = download_release_archive(
            validated_tag,
            repository,
            Path(temporary_directory),
        )
        return install_verified_archive(
            archive_path,
            validated_tag,
            validated_sha256,
            output_path,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, help="Release tag, for example xila-package-builder-v0.4.0")
    parser.add_argument("--sha256", required=True, help="Expected SHA-256 digest of the Linux x86_64 archive")
    parser.add_argument("--output", required=True, type=Path, help="Destination path for the xila-package executable")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY, help="GitHub repository hosting the release")
    arguments = parser.parse_args()
    version_output = install_release_builder(
        release_tag=arguments.release,
        expected_sha256=arguments.sha256,
        output_path=arguments.output,
        repository=arguments.repository,
    )
    print(f"Verified published builder: {version_output} (sha256: {arguments.sha256})")


if __name__ == "__main__":
    main()
