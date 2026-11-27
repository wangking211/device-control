"""Sign a gateway manifest with an operator-held Ed25519 private key.

    python scripts/sign_manifest.py --manifest manifest.json --out signed.json \
        --private-key release-private.pem --key-id release-key-1 \
        --tenant tenant-a --gateway gateway-a --endpoint phone-1 \
        --device device-phone-1 --fingerprint <sha256> --revision 1 --valid-days 30

The private key never leaves the signing host; gateways receive only the public
key. The signature covers the canonical manifest payload (excluding
`signature`).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from device_control.canonical import manifest_digest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--endpoint", default=None)
    parser.add_argument("--device", default=None)
    parser.add_argument("--fingerprint", default=None)
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--valid-days", type=int, default=30)
    args = parser.parse_args()

    document = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    document.update({
        "tenant_ref": args.tenant,
        "gateway_id": args.gateway,
        "endpoint_id": args.endpoint,
        "device_id": args.device,
        "device_fingerprint": args.fingerprint,
        "revision": args.revision,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=max(1, args.valid_days))).isoformat(),
        "key_id": args.key_id,
        "signature_algorithm": "ed25519",
    })
    document.pop("signature", None)
    digest = manifest_digest(document)
    private = serialization.load_pem_private_key(
        Path(args.private_key).read_bytes(), password=None
    )
    signature = private.sign(digest.encode("ascii"))  # type: ignore[call-arg]
    document["signature"] = base64.b64encode(signature).decode("ascii")
    Path(args.out).write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    print(f"digest={digest} key_id={args.key_id} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
