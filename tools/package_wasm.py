#!/usr/bin/env python3
"""Stage a WASI application and emit a verified Xila v1 application bundle.

The source manifest is developer-owned (no hashes/sizes). The native Rust
xila-package builder creates the signed-format runtime manifest and archive.
The reusable Actions workflow uses the exact same pack() API as local tooling.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath

MAX_MANIFEST = 64 * 1024
SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]*$")


def within(root: Path, relative: str) -> Path:
    """Reject traversal, symlinks and missing files from untrusted inputs."""
    p = PurePosixPath(relative)
    if not relative or p.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
        raise ValueError(f"unsafe relative path: {relative!r}")
    root = root.resolve(strict=True)
    current = root
    for part in p.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlink not allowed: {current}")
    if not current.is_file() or not current.resolve(strict=True).is_relative_to(root):
        raise ValueError(f"file missing or outside staging root: {relative!r}")
    return current


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
    shortcut_path: str = "",
) -> tuple[str, str]:
    source_manifest = within(manifest_root, manifest_path)
    if source_manifest.stat().st_size > MAX_MANIFEST:
        raise ValueError("developer manifest exceeds 64 KiB")
    metadata = json.loads(source_manifest.read_text(encoding="utf-8"))
    if "files" in metadata or "sha256" in metadata:
        raise ValueError("use xila developer manifests without generated file hashes")
    application = metadata.get("application")
    if not isinstance(application, dict):
        raise ValueError("the WASI workflow requires an application entrypoint")
    entrypoint = application.get("entrypoint")
    if not isinstance(entrypoint, str) or not entrypoint.startswith("bin/") or not entrypoint.endswith(".wasm"):
        raise ValueError("expected bundle-relative bin/<app>.wasm entrypoint")
    if len(entrypoint) > 99 or any(part in ("", ".", "..") for part in entrypoint.split("/")):
        raise ValueError("unsafe WASI entrypoint")
    for key in ("name", "version", "target"):
        if not isinstance(metadata.get(key), str) or not SAFE_FILENAME.fullmatch(metadata[key]):
            raise ValueError(f"unsafe {key}")
    if metadata.get("format_version") != 1 or metadata["target"] != "wasm32-wasip1":
        raise ValueError("unsupported package format or target")
    if staging.exists():
        raise ValueError("staging directory already exists")
    if wasm_path:
        wasm = within(wasm_root, wasm_path)
    else:
        found = sorted(p for p in wasm_root.rglob("*.wasm") if p.is_file() and not p.is_symlink()
                       and p.resolve().is_relative_to(wasm_root.resolve()))
        if len(found) != 1:
            raise ValueError("set wasm-path when the artifact does not contain exactly one Wasm")
        wasm = found[0]

    # The builder's source input contains only explicitly shipped files, never
    # Rust source, hidden credentials, tests, targets or host build artifacts.
    staging.mkdir(parents=True)
    (staging / "xila-package.json").write_bytes(source_manifest.read_bytes())
    destination = staging.joinpath(*PurePosixPath(entrypoint).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(wasm, destination)

    # Launcher presentation is source-owned by each application, not the
    # package manifest. The built bundle authenticates shortcut.json exactly
    # like every other resource through the runtime SHA-256 inventory.
    if shortcut_path:
        shortcut_file = within(manifest_root, shortcut_path)
        if shortcut_file.stat().st_size > 2048:
            raise ValueError("shortcut.json exceeds graphical Shell's 2048-byte limit")
        shortcut = json.loads(shortcut_file.read_text(encoding="utf-8"))
        if not isinstance(shortcut, dict):
            raise ValueError("application shortcut must be a JSON object")
        schema = "https://raw.githubusercontent.com/xila-project/applications/main/schemas/shell-shortcut.schema.json"
        allowed = {"$schema", "name", "command", "arguments", "terminal", "icon_string", "icon_color"}
        if set(shortcut) - allowed or shortcut.get("$schema") != schema:
            raise ValueError("unexpected launcher shortcut schema or fields")
        if shortcut.get("name") != application.get("display_name"):
            raise ValueError("shortcut name must match application display name")
        if shortcut.get("command") != "/applications/executables/wasm":
            raise ValueError("shortcut must invoke the shared Xila Wasm launcher")
        if shortcut.get("arguments") != ["@bundle/" + entrypoint]:
            raise ValueError("shortcut must launch the bundle-local verified entrypoint")
        if not isinstance(shortcut.get("terminal"), bool):
            raise ValueError("shortcut terminal flag must be boolean")
        icon = shortcut.get("icon_string")
        color = shortcut.get("icon_color")
        if not isinstance(icon, str) or len(icon) > 8 or not icon:
            raise ValueError("invalid shortcut icon string")
        if not isinstance(color, list) or len(color) != 3 or any(
            type(value) is not int or value < 0 or value > 255 for value in color
        ):
            raise ValueError("invalid shortcut RGB color")
        shutil.copyfile(shortcut_file, staging / "shortcut.json")

    # Rust validates identity, manifest, file inventory, paths and content
    # digests. No private key is present on the pull-request runner.
    filename = f"{metadata['name']}-{metadata['version']}-{metadata['target']}.xpk"
    output.mkdir(parents=True, exist_ok=True)
    bundle = output / (filename.removesuffix(".xpk") + ".app")
    archive = output / filename
    subprocess.run([str(builder), "bundle", "build", str(staging), str(bundle)], check=True)
    subprocess.run([str(builder), "bundle", "verify", str(bundle)], check=True)
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundle / ".xila" / "manifest.json", manifest_output)
    subprocess.run([str(builder), "bundle", "archive", str(bundle), str(archive)], check=True)

    # SHA-256 sidecar authenticates downloaded bytes against a trusted digest;
    # it is NOT a publisher signature. Release signing is handled separately.
    digest = hashlib.sha256()
    with archive.open("rb") as src:
        for chunk in iter(lambda: src.read(64 * 1024), b""):
            digest.update(chunk)
    value = digest.hexdigest()
    (output / (filename + ".sha256")).write_text(f"{value}  {filename}\n", encoding="ascii")
    return filename, value


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
    parser.add_argument("--shortcut-path", default="", help="Application-owned shortcut JSON path relative to --manifest-root")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    filename, digest = pack(
        wasm_root=args.wasm_root,
        wasm_path=args.wasm_path,
        manifest_root=args.manifest_root,
        manifest_path=args.manifest_path,
        staging=args.staging,
        manifest_output=args.manifest_output,
        output=args.output,
        builder=args.builder,
        shortcut_path=args.shortcut_path,
    )
    print(f"Generated v1 bundle: {filename} (sha256: {digest})")
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"filename={filename}\nsha256={digest}\n")


if __name__ == "__main__":
    main()
