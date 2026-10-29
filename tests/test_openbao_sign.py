import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("openbao_sign", Path(__file__).resolve().parents[1] / "tools" / "openbao_sign.py")
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)

class Response:
    def __init__(self, value): self.value = value
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, size=-1): return json.dumps(self.value).encode()

class OpenBaoSigning(unittest.TestCase):
    def test_uses_exact_payload_with_oidc_and_pinned_key_version(self):
        requests = []
        def send(request, **kwargs):
            requests.append(request)
            if len(requests) == 1: return Response({"value": "github-jwt"})
            if len(requests) == 2: return Response({"auth": {"client_token": "bao-token"}})
            return Response({"data": {"signature": "vault:v1:" + base64.b64encode(bytes(range(64))).decode()}})
        with tempfile.TemporaryDirectory() as directory, patch.object(signer, "open_request", side_effect=send):
            payload = Path(directory) / "payload"
            output = Path(directory) / "signature"
            payload.write_bytes(b"exact\x00payload")
            signer.sign(payload, output, address="https://vault.xila.dev", mount="transit", key="xila-applications", version=1, jwt_mount="jwt", role="xila-app-release", oidc_url="https://oidc.example/token", oidc_token="request-token")
            self.assertEqual(output.read_bytes(), bytes(range(64)))
            self.assertEqual(json.loads(requests[2].data)["input"], base64.b64encode(payload.read_bytes()).decode())
            self.assertEqual(json.loads(requests[2].data)["key_version"], 1)
            self.assertEqual(requests[2].get_header("X-vault-token"), "bao-token")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
    def test_rejects_wrong_key_version_and_does_not_write_signature(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(signer, "open_request", side_effect=[Response({"value": "jwt"}), Response({"auth": {"client_token": "token"}}), Response({"data": {"signature": "vault:v2:" + base64.b64encode(bytes(64)).decode()}})]):
            payload, output = Path(directory) / "payload", Path(directory) / "signature"
            payload.write_bytes(b"message")
            with self.assertRaises(ValueError):
                signer.sign(payload, output, address="https://vault.xila.dev", mount="transit", key="xila-applications", version=1, jwt_mount="jwt", role="xila-app-release", oidc_url="https://oidc.example/token", oidc_token="token")
            self.assertFalse(output.exists())
    def test_refuses_insecure_addresses_and_invalid_path_segments(self):
        with self.assertRaises(ValueError): signer.validate_address("http://vault.xila.dev")
        with self.assertRaises(ValueError): signer.validate_segment("../secret")
