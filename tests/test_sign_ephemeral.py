"""Ephemeral CI signer emits a valid signature and only an untrusted public key."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.sign_ephemeral import ED25519_SPKI_PREFIX, sign


class EphemeralSignerTests(unittest.TestCase):
    def test_random_key_and_signature_are_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            message = root / "signing-payload"
            message.write_bytes(b"Xila signing payload test")
            keys = []
            for index in range(2):
                signature = root / f"signature-{index}"
                public = root / f"public-{index}.pub"
                sign(message, signature, public)
                self.assertEqual(signature.stat().st_size, 64)
                self.assertEqual(public.stat().st_size, 32)
                keys.append(public.read_bytes())
                public_der = root / f"public-{index}.der"
                public_der.write_bytes(ED25519_SPKI_PREFIX + public.read_bytes())
                verified = subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                     "-keyform", "DER", "-inkey", str(public_der),
                     "-sigfile", str(signature), "-in", str(message)],
                    capture_output=True, text=True,
                )
                self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertNotEqual(keys[0], keys[1])
            self.assertEqual(
                list(root.glob("*.pem")), [],
                "temporary private keys must not appear in artifact directory",
            )
            message.write_bytes(b"tampered")
            tampered = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                 "-keyform", "DER", "-inkey", str(root / "public-0.der"),
                 "-sigfile", str(root / "signature-0"), "-in", str(message)],
                capture_output=True,
            )
            self.assertNotEqual(tampered.returncode, 0)

    def test_reject_overwrite_and_missing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            message = root / "payload"
            message.write_bytes(b"test")
            signature = root / "signature"
            public = root / "public"
            sign(message, signature, public)
            with self.assertRaises(ValueError):
                sign(message, signature, public)
            with self.assertRaises(ValueError):
                sign(root / "missing", root / "other-signature", root / "other-public")


if __name__ == "__main__":
    unittest.main()
