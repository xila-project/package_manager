"""A fixed CI seed signs valid packages without exposing private key material."""
import base64
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.sign_with_seed import ED25519_SPKI_PREFIX, decode_seed, sign


class DevSigningTests(unittest.TestCase):
    def test_stable_public_key_and_valid_signature(self):
        seed_b64 = base64.b64encode(bytes(range(32))).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            message = root / "signing-payload"
            message.write_bytes(b"Xila canonical signing payload")
            signatures = []
            public_keys = []

            for index in range(2):
                signature = root / f"signature-{index}"
                public = root / f"public-{index}.pub"
                sign(message, signature, public, seed_b64=seed_b64)
                self.assertEqual(signature.stat().st_size, 64)
                self.assertEqual(public.stat().st_size, 32)
                signatures.append(signature.read_bytes())
                public_keys.append(public.read_bytes())
                public_der = root / f"public-{index}.der"
                public_der.write_bytes(ED25519_SPKI_PREFIX + public.read_bytes())
                verified = subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                     "-keyform", "DER", "-inkey", str(public_der),
                     "-sigfile", str(signature), "-in", str(message)],
                    capture_output=True, text=True,
                )
                self.assertEqual(verified.returncode, 0, verified.stderr)

            self.assertEqual(public_keys[0], public_keys[1])
            self.assertEqual(signatures[0], signatures[1])
            self.assertEqual(list(root.glob("*.der")), sorted(root.glob("public-*.der")))
            message.write_bytes(b"tampered")
            tampered = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                 "-keyform", "DER", "-inkey", str(root / "public-0.der"),
                 "-sigfile", str(root / "signature-0"), "-in", str(message)],
                capture_output=True,
            )
            self.assertNotEqual(tampered.returncode, 0)

    def test_invalid_or_missing_secret_is_rejected(self):
        for value in ("", "invalid@base64", "YQ==", base64.b64encode(b"x" * 64).decode()):
            with self.subTest(value=value[:10]), self.assertRaises(ValueError):
                decode_seed(value)

    def test_refuse_overwrite_or_missing_payload(self):
        seed_b64 = base64.b64encode(bytes(range(32))).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            message = root / "payload"
            message.write_bytes(b"test")
            signature = root / "signature"
            public = root / "public"
            sign(message, signature, public, seed_b64=seed_b64)
            with self.assertRaises(ValueError):
                sign(message, signature, public, seed_b64=seed_b64)
            with self.assertRaises(ValueError):
                sign(root / "missing", root / "other-sig", root / "other-pub",
                     seed_b64=seed_b64)

    def test_different_seed_produces_different_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.write_bytes(b"test")
            keys = []
            for i in range(2):
                public = root / f"public-{i}"
                sign(payload, root / f"signature-{i}", public,
                     seed_b64=base64.b64encode(bytes([i + 1]) * 32).decode())
                keys.append(public.read_bytes())
            self.assertNotEqual(keys[0], keys[1])


if __name__ == "__main__":
    unittest.main()
