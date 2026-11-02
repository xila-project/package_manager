#!/usr/bin/env python3
"""Sign development packages with a fixed, temporary Ed25519 CI secret.

XILA_DEV_SIGNING_SEED_B64 contains base64 of a raw 32-byte Ed25519 seed.
Publish the corresponding raw public key alongside the package; never publish
the seed or treat the public key as a trusted publisher identity.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import os
from pathlib import Path
import subprocess
import tempfile

# RFC 8410: PKCS#8 Ed25519 private key and SubjectPublicKeyInfo prefixes.
ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def decode_seed(encoded: str) -> bytes:
    if not encoded:
        raise ValueError("XILA_DEV_SIGNING_SEED_B64 is missing")
    try:
        seed = base64.b64decode(encoded.strip(), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("XILA_DEV_SIGNING_SEED_B64 must be valid base64") from error
    if len(seed) != 32:
        raise ValueError("XILA_DEV_SIGNING_SEED_B64 must encode exactly 32 bytes")
    return seed


def sign(payload: Path, signature: Path, public_key: Path, *, seed_b64: str) -> None:
    if payload.is_symlink() or not payload.is_file():
        raise ValueError("signing payload must be an existing regular file")
    if signature == public_key or any(
        path.exists() or path.is_symlink() for path in (signature, public_key)
    ):
        raise ValueError("signature/public key output paths must be distinct and absent")
    seed = decode_seed(seed_b64)
    # Avoid exporting the signing secret to the OpenSSL subprocesses.
    child_env = {name: value for name, value in os.environ.items()
                 if name != "XILA_DEV_SIGNING_SEED_B64"}

    try:
        with tempfile.TemporaryDirectory(prefix="xila-dev-signing-") as directory:
            private_key = Path(directory) / "private.der"
            descriptor = os.open(private_key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(ED25519_PKCS8_PREFIX + seed)

            subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                 "-inkey", str(private_key), "-in", str(payload),
                 "-out", str(signature)],
                check=True, capture_output=True, env=child_env,
            )
            der = subprocess.run(
                ["openssl", "pkey", "-inform", "DER", "-in", str(private_key),
                 "-pubout", "-outform", "DER"],
                check=True, capture_output=True, env=child_env,
            ).stdout
            if (len(der) != len(ED25519_SPKI_PREFIX) + 32
                    or not der.startswith(ED25519_SPKI_PREFIX)):
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
    sign(args.payload, args.signature, args.public_key,
         seed_b64=os.environ.get("XILA_DEV_SIGNING_SEED_B64", ""))


if __name__ == "__main__":
    main()
