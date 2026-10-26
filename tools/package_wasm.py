#!/usr/bin/env python3
"""Stage a single Wasm and its Xila manifest, then package with xila-package.

No Wasm code is executed. The Rust CLI is the sole authority for validating,
updating and archiving Xila manifests; this script only adapts Actions inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath

SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]*$")
MAX_MANIFEST = 64 * 1024


def within(root: Path, name: str) -> Path:
    """Resolve a relative, non-symlink path beneath a trusted staging root."""
    p = PurePosixPath(name)
    if not name or p.is_absolute() or any(x in ("", ".", "..") for x in name.split("/")):
        raise ValueError(f"unsafe relative path: {name!r}")
    base = root.resolve(strict=True)
    result = base.joinpath(*p.parts)
    for part in (base.joinpath(*p.parts[:i]) for i in range(1, len(p.parts) + 1)):
        if part.is_symlink():
            raise ValueError(f"symlink not allowed: {part}")
    if not result.is_file() or not result.resolve(strict=True).is_relative_to(base):
        raise ValueError(f"file missing or outside staging root: {name!r}")
    return result


def pack(
    *,
    wasm_root: Path,
    wasm_path: str,
    manifest_root: Path,
    manifest_path: str,
    staging: Path,
    manifest_output: Path,
    output: Path,
    builder: Path,
) -> tuple[str, str]:
    manifest_file = within(manifest_root, manifest_path)
    if manifest_file.stat().st_size > MAX_MANIFEST:
        raise ValueError("manifest exceeds 64 KiB")
    metadata = json.loads(manifest_file.read_text(encoding="utf-8"))
    entries = metadata.get("files")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("the reusable workflow currently supports exactly one Wasm file")
    declared_path = entries[0].get("path")
    if not isinstance(declared_path, str) or not declared_path.endswith(".wasm"):
        raise ValueError("manifest must declare exactly one .wasm payload")
    if declared_path.startswith(".xila/") or len(declared_path) > 99:
        raise ValueError("reserved or unsupported TAR payload path")
    rel = PurePosixPath(declared_path)
    if rel.is_absolute() or any(p in ("", ".", "..") for p in declared_path.split("/")):
        raise ValueError("unsafe manifest file path")
    if wasm_path:
        wasm = within(wasm_root, wasm_path)
    else:
        found = sorted(
            p for p in wasm_root.rglob("*.wasm")
            if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(wasm_root.resolve())
        )
        if len(found) != 1:
            raise ValueError("provide wasm-path when the downloaded artifact does not contain exactly one Wasm")
        wasm = found[0]

    name, version, target = (metadata.get(k) for k in ("name", "version", "target"))
    if any(not isinstance(x, str) or not SAFE_FILENAME.fullmatch(x) for x in (name, version, target)):
        raise ValueError("unsafe package identity, version or target")
    if staging.exists():
        raise ValueError("staging directory already exists")
    destination = staging.joinpath(*rel.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(wasm, destination)
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(manifest_file, manifest_output)

    # xila-package is authoritative for both manifest metadata validation and
    # archive integrity. It updates SHA-256 and size without changing identity.
    subprocess.run([str(builder), "manifest", "update", str(staging), str(manifest_output)], check=True)
    updated = json.loads(manifest_output.read_text(encoding="utf-8"))
    if any(updated[k] != metadata[k] for k in ("name", "version", "target")):
        raise ValueError("package identity unexpectedly changed")
    filename = f"{name}-{version}-{target}.xpk"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / filename
    subprocess.run([str(builder), "pack", str(staging), str(manifest_output), str(archive)], check=True)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / (filename + ".sha256")).write_text(f"{digest}  {filename}\n", encoding="ascii")
    return filename, digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasm-root", required=True, type=Path)
    parser.add_argument("--wasm-path", default="")
    parser.add_argument("--manifest-root", required=True, type=Path)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--staging", required=True, type=Path)
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--builder", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    options = parser.parse_args()
    filename, digest = pack(
        wasm_root=options.wasm_root,
        wasm_path=options.wasm_path,
        manifest_root=options.manifest_root,
        manifest_path=options.manifest_path,
        staging=options.staging,
        manifest_output=options.manifest_output,
        output=options.output,
        builder=options.builder,
    )
    print(f"Generated {filename} (sha256: {digest})")
    if options.github_output is not None:
        with options.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"filename={filename}\nsha256={digest}\n")


if __name__ == "__main__":
    main()
