"""Run the Windows Computer Control runtime.

Environment (secrets are injected, never CLI args):
  DEVICE_CONTROL_URL, DEVICE_GATEWAY_ID, DEVICE_GATEWAY_CREDENTIAL
  COMPUTER_TENANT, COMPUTER_ENDPOINT_ID, COMPUTER_DEVICE_ID
  COMPUTER_APP_ALLOWLIST (JSON file: {"app_id": "C:/path/app.exe"})
  COMPUTER_PAUSE_FILE, COMPUTER_RUNTIME_LEDGER
  COMPUTER_ALLOW_CLIPBOARD=1 (default off)
  COMPUTER_BROWSER_ALLOWED_HOSTS=example.com,app.example.com
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "gateway" / "src"))

from device_gateway.control_client import ControlPlaneClient  # noqa: E402

from device_control.computer.ledger import ComputerRunLedger  # noqa: E402
from device_control.computer.providers.playwright import PlaywrightProvider  # noqa: E402
from device_control.computer.providers.uia import UiaProvider  # noqa: E402
from device_control.computer.runtime import ComputerRuntime  # noqa: E402


def _required(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _allowed_apps() -> dict[str, str]:
    path = os.environ.get("COMPUTER_APP_ALLOWLIST") or ""
    if not path:
        return {}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit("COMPUTER_APP_ALLOWLIST is unreadable") from exc
    if not isinstance(payload, dict):
        raise SystemExit("COMPUTER_APP_ALLOWLIST must be a JSON object")
    return {str(key): str(value) for key, value in payload.items()
            if str(key).strip() and str(value).strip()}


def main() -> int:
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    client = ControlPlaneClient(
        base_url=_required("DEVICE_CONTROL_URL"),
        gateway_id=_required("DEVICE_GATEWAY_ID"),
        credential=_required("DEVICE_GATEWAY_CREDENTIAL"),
    )
    hosts = {
        item.strip().lower()
        for item in (os.environ.get("COMPUTER_BROWSER_ALLOWED_HOSTS") or "").split(",")
        if item.strip()
    }
    desktop = UiaProvider(
        allowed_apps=_allowed_apps(),
        allow_clipboard=os.environ.get("COMPUTER_ALLOW_CLIPBOARD") == "1",
    )
    browser = PlaywrightProvider(
        headless=os.environ.get("COMPUTER_BROWSER_HEADLESS", "0") == "1",
        allowed_hosts=hosts,
    )
    runtime = ComputerRuntime(
        client=client,
        desktop_provider=desktop,
        browser_provider=browser,
        tenant_ref=_required("COMPUTER_TENANT"),
        endpoint_id=_required("COMPUTER_ENDPOINT_ID"),
        device_id=_required("COMPUTER_DEVICE_ID"),
        gateway_id=_required("DEVICE_GATEWAY_ID"),
        ledger=ComputerRunLedger(os.environ.get("COMPUTER_RUNTIME_LEDGER") or None),
        pause_path=os.environ.get("COMPUTER_PAUSE_FILE") or None,
    )
    stop = threading.Event()

    def _shutdown(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    if args.once:
        print(json.dumps(runtime.run_once(), sort_keys=True))
        return 0
    while not stop.is_set():
        try:
            runtime.run_once()
        except Exception as exc:  # noqa: BLE001 - keep runtime alive
            print(f"computer runtime error: {type(exc).__name__}", file=sys.stderr)
        stop.wait(2)
    desktop.close()
    browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
