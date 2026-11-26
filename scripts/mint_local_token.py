"""Mint a short-lived local test identity with the MindOS HS256 claims shape.

This is a developer utility, not an identity service. Production tokens are
issued by MindOS (or a platform identity adapter) and verified with the same
``MINDOS_IDENTITY_HMAC_KEY`` / issuer configuration.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
import uuid


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--role", action="append", default=[])
    parser.add_argument("--permission", action="append", default=[])
    parser.add_argument("--ttl", type=int, default=900)
    parser.add_argument("--key-env", default="MINDOS_IDENTITY_HMAC_KEY")
    parser.add_argument("--issuer", default=os.environ.get("MINDOS_IDENTITY_ISSUER"))
    args = parser.parse_args()

    secret = os.environ.get(args.key_env, "")
    if len(secret.encode()) < 32:
        raise SystemExit(f"{args.key_env} must be at least 32 bytes")
    now = int(time.time())
    claims = {
        "sub": args.subject,
        "tenant": args.tenant,
        "iat": now,
        "nbf": now,
        "exp": now + args.ttl,
        "jti": uuid.uuid4().hex,
        "roles": args.role,
        "permissions": args.permission,
    }
    if args.issuer:
        claims["iss"] = args.issuer
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        f"{b64(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64(json.dumps(claims, separators=(',', ':')).encode())}"
    )
    signature = hmac.new(secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    print(f"{signing_input}.{b64(signature)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
