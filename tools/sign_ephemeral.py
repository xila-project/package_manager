#!/usr/bin/env python3
"""Sign an already canonical Xila manifest message using a one-off Ed25519 key.

Only for untrusted CI development artifacts. The raw public key is published
alongside the package, never embedded as a trust assertion. The private key is
created in a restricted temporary directory and deleted after signing.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile

# RFC 8410 SubjectPublicKeyInfo header for an Ed25519 32-byte public key.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def sign(payload: Path, signature: Path, public_key: Path) -> None:
    if payload.is_symlink() or not payload.is_file():
        raise ValueError("signing payload must be an existing regular file")
    if signature == public_key or signature.exists() or public_key.exists():
        raise ValueError("signature/public key output paths must be distinct and absent")

    try:
        with tempfile.TemporaryDirectory(prefix="xila-ephemeral-signing-") as directory:
            private_key = Path(directory) / "private.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin",
                 "-inkey", str(private_key), "-in", str(payload),
                 "-out", str(signature)],
                check=True, capture_output=True,
            )
            der = subprocess.run(
                ["openssl", "pkey", "-in", str(private_key),
                 "-pubout", "-outform", "DER"],
                check=True, capture_output=True,
            ).stdout
            if len(der) != len(ED25519_SPKI_PREFIX) + 32 or not der.startswith(ED25519_SPKI_PREFIX):
                raise ValueError("unexpected Ed25519 public key encoding")
            with public_key.open("xb") as output:
                output.write(der[len(ED25519_SPKI_PREFIX):])
            if signature.stat().st_size != 64:
                raise ValueError("unexpected Ed25519 signature size")
    except Exception:
        signature.unlink(missing_ok=True)
        public_key.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("signature", type=Path)
    parser.add_argument("public_key", type=Path)
    args = parser.parse_args()
    sign(args.payload, args.signature, args.public_key)


if __name__ == "__main__":
    main()
