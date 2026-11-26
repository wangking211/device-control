"""Gateway installation preflight (network, config, manifest, disk, time).

    python scripts/gateway_preflight.py --json

Exit code 1 means the gateway must not start. No secret values are printed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway" / "src"))

from device_gateway import manifest as manifest_rules  # noqa: E402


def check(condition: bool, code: str, detail: str | None = None) -> dict:
    return {"ok": bool(condition), "code": code, "detail": detail}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    url = (os.environ.get("DEVICE_CONTROL_URL") or "").strip()
    adapter = (os.environ.get("DEVICE_GATEWAY_ADAPTER") or "null").strip()
    adb_path = (os.environ.get("DEVICE_GATEWAY_ADB_PATH") or "adb").strip()
    serial = (os.environ.get("DEVICE_GATEWAY_SERIAL") or "").strip()
    manifest_path = (os.environ.get("DEVICE_GATEWAY_MANIFEST") or "").strip()
    key = (os.environ.get("DEVICE_GATEWAY_MANIFEST_HMAC_KEY") or "").strip()
    evidence_dir = Path(os.environ.get("DEVICE_GATEWAY_DB") or "./var").parent

    checks = []
    secure = url.startswith("https://") or url.startswith("http://127.0.0.1") \
        or url.startswith("http://localhost")
    checks.append(check(secure, "control_url_transport", url.split(":")[0] if url else None))
    checks.append(check(len(os.environ.get("DEVICE_GATEWAY_CREDENTIAL") or "") >= 32,
                        "gateway_credential_present"))
    if adapter == "android":
        checks.append(check(bool(shutil.which(adb_path)), "adb_binary", adb_path))
        checks.append(check(bool(serial), "device_serial_configured"))
        checks.append(check(bool(os.environ.get("DEVICE_GATEWAY_ENDPOINT_ID")),
                            "endpoint_binding_configured"))
        checks.append(check(bool(os.environ.get("DEVICE_GATEWAY_DEVICE_FINGERPRINT")),
                            "device_fingerprint_configured"))
    try:
        document = manifest_rules.load(manifest_path or None)
        digest = manifest_rules.digest(document)
        if key:
            checks.append(check(manifest_rules.verify(digest, document.get("signature"), key),
                                "manifest_signature"))
        else:
            checks.append(check(adapter != "android", "manifest_signature_required"))
        checks.append(check(bool(document.get("capabilities")), "manifest_capabilities"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        checks.append(check(False, "manifest_load", type(exc).__name__))

    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(evidence_dir).free
        checks.append(check(free > 256 * 1024 * 1024, "disk_free_bytes", str(free)))
    except OSError as exc:
        checks.append(check(False, "disk_check", type(exc).__name__))

    checks.append(check(abs(datetime.now(timezone.utc).timestamp() - datetime.now().timestamp())
                        < 300, "clock_sane"))
    result = {
        "ok": all(item["ok"] for item in checks),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in checks:
            print(f"[{'PASS' if item['ok'] else 'FAIL'}] {item['code']}"
                  + (f" ({item['detail']})" if item["detail"] else ""))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
