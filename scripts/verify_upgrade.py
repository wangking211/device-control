"""Verify a signed gateway upgrade package with an Ed25519 public key.

    python scripts/verify_upgrade.py \
        --package device-gateway-1.2.0.tar.gz \
        --signature device-gateway-1.2.0.tar.gz.sig \
        --public-key release-public.pem

The signature must cover the exact package bytes. Verification failure exits
non-zero; production deployment must not proceed without a human approval
record.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args()

    package = Path(args.package).read_bytes()
    signature = Path(args.signature).read_bytes()
    try:
        signature = base64.b64decode(signature, validate=True)
    except Exception:  # noqa: BLE001 - raw signature files are allowed too
        pass
    public_key = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
    try:
        public_key.verify(signature, package)  # type: ignore[call-arg]
    except InvalidSignature:
        print("REJECTED: signature does not verify")
        return 1
    print(f"OK: {args.package} sha256={hashlib.sha256(package).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
