#!/usr/bin/env python3
"""Extract only regular, bounded package inputs into a fresh signing directory."""
from __future__ import annotations
import argparse
from pathlib import Path, PurePosixPath
import shutil
import tarfile

MAX_BYTES = 256 * 1024 * 1024 + 64 * 1024
MAX_ENTRIES = 512

def extract(archive: Path, output: Path) -> None:
    root = output.resolve(strict=True)
    seen: set[str] = set()
    total = 0
    manifest_seen = False
    with tarfile.open(archive, "r:") as tar:
        for index, member in enumerate(tar):
            if index >= MAX_ENTRIES or not (member.isfile() or member.isdir()):
                raise ValueError("too many entries or unsupported entry type")
            name = member.name.rstrip("/")
            parts = name.split("/")
            if not name or name.startswith("/") or any(part in ("", ".", "..") for part in parts) or name in seen:
                raise ValueError("unsafe or duplicate signing input path")
            seen.add(name)
            if name == "xila-package-manifest.json" and member.isfile():
                manifest_seen = True
                if member.size > 64 * 1024:
                    raise ValueError("manifest too large")
            elif parts[0] != "xila-package-payload" or (len(parts) == 1 and not member.isdir()):
                raise ValueError("unexpected signing input path")
            total += member.size
            if total > MAX_BYTES:
                raise ValueError("signing inputs too large")
            path = root.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError("unreadable signing input")
                with source, path.open("xb") as target:
                    shutil.copyfileobj(source, target, 65536)
    if not manifest_seen:
        raise ValueError("missing package manifest")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    extract(args.archive, args.output)

if __name__ == "__main__":
    main()
