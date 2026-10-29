#!/usr/bin/env python3
"""Sign a bounded Xila signing payload with OpenBao Transit via GitHub OIDC."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request

MAX_PAYLOAD = 128 * 1024
MAX_RESPONSE = 64 * 1024
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

_OPENER = urllib.request.build_opener(NoRedirect())

def open_request(request, **kwargs):
    return _OPENER.open(request, **kwargs)

def validate_address(address: str) -> str:
    parsed = urllib.parse.urlsplit(address)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("OpenBao address must be an HTTPS origin")
    return address.rstrip("/")

def validate_segment(segment: str) -> str:
    if not SEGMENT.fullmatch(segment) or segment in (".", ".."):
        raise ValueError("invalid OpenBao path segment")
    return segment

def request_json(url: str, *, data: dict | None = None, headers: dict | None = None) -> dict:
    payload = None if data is None else json.dumps(data, separators=(",", ":")).encode()
    request = urllib.request.Request(url, data=payload, headers={"Accept": "application/json", "Content-Type": "application/json", **(headers or {})})
    with open_request(request, timeout=30) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("OpenBao response too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid JSON response")
    return value

def sign(payload: Path, output: Path, *, address: str, mount: str, key: str, version: int, jwt_mount: str, role: str, oidc_url: str, oidc_token: str) -> None:
    address = validate_address(address)
    mount, key, jwt_mount, role = map(validate_segment, (mount, key, jwt_mount, role))
    if version < 1 or version > 2**31 - 1:
        raise ValueError("invalid Transit key version")
    with payload.open("rb") as stream:
        message = stream.read(MAX_PAYLOAD + 1)
    if not message or len(message) > MAX_PAYLOAD:
        raise ValueError("signing payload is empty or too large")
    parsed_oidc = urllib.parse.urlsplit(oidc_url)
    if parsed_oidc.scheme != "https" or not parsed_oidc.hostname:
        raise ValueError("invalid GitHub OIDC request URL")
    separator = "&" if parsed_oidc.query else "?"
    oidc = request_json(oidc_url + separator + urllib.parse.urlencode({"audience": address}), headers={"Authorization": "Bearer " + oidc_token})
    jwt = oidc["value"]
    login = request_json(f"{address}/v1/auth/{jwt_mount}/login", data={"role": role, "jwt": jwt})
    token = login["auth"]["client_token"]
    response = request_json(f"{address}/v1/{mount}/sign/{key}", data={"input": base64.b64encode(message).decode("ascii"), "key_version": version}, headers={"X-Vault-Token": token})
    signature = response["data"]["signature"]
    prefix = f"vault:v{version}:"
    if not isinstance(signature, str) or not signature.startswith(prefix):
        raise ValueError("unexpected Transit signature or key version")
    raw = base64.b64decode(signature[len(prefix):], validate=True)
    if len(raw) != 64:
        raise ValueError("Transit key did not produce a raw Ed25519 signature")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("signature", type=Path)
    args = parser.parse_args()
    sign(args.payload, args.signature, address=os.environ["OPENBAO_ADDR"], mount=os.environ["OPENBAO_TRANSIT_MOUNT"], key=os.environ["OPENBAO_TRANSIT_KEY"], version=int(os.environ["OPENBAO_KEY_VERSION"]), jwt_mount=os.environ["OPENBAO_JWT_MOUNT"], role=os.environ["OPENBAO_JWT_ROLE"], oidc_url=os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"], oidc_token=os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"])

if __name__ == "__main__":
    main()
