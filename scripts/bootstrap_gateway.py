"""Operator bootstrap: enroll and activate a gateway once.

    python scripts/bootstrap_gateway.py \
        --control-url http://127.0.0.1:8085 \
        --admin-token "$DEVICE_CONTROL_ADMIN_TOKEN" \
        --tenant tenant-a \
        --gateway gateway-a

Prints the one-time gateway credential to stdout so the operator can inject it
into the gateway process environment. The credential is never written to disk
by this script and cannot be recovered from the control plane afterwards.
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


def request(url: str, method: str, body: dict | None, token: str | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {payload}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-url", required=True)
    parser.add_argument("--admin-token", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--display-name", default=None)
    args = parser.parse_args()

    base = args.control_url.rstrip("/")
    created = request(f"{base}/v1/gateways", "POST", {
        "gateway_id": args.gateway,
        "tenant_ref": args.tenant,
        "display_name": args.display_name,
        "protocol_version": "v1",
        "adapter_inventory": [],
    }, args.admin_token)
    activated = request(f"{base}/v1/gateways/{args.gateway}/activate", "POST", {
        "enrollment_token": created["enrollment_token"],
        "protocol_version": "v1",
    })
    print("# Inject these into the gateway process (never commit them):")
    print(f"DEVICE_CONTROL_URL={base}")
    print(f"DEVICE_GATEWAY_ID={args.gateway}")
    print(f"DEVICE_GATEWAY_CREDENTIAL={activated['credential']}")
    print(f"# credential expires at {activated['expires_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
