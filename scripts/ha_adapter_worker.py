"""Run the Home Assistant pilot worker against a Device Control gateway.

Environment (operator-controlled, no secrets in CLI):
  DEVICE_CONTROL_URL=https://device-control.internal
  DEVICE_GATEWAY_ID=ha-ha-1
  DEVICE_GATEWAY_CREDENTIAL=<one-time adapter credential>
  HA_BASE_URL=https://homeassistant.local:8123
  HA_TOKEN_SECRET=<secret ref name resolved from the process secret injection>
  HA_ALLOWED_ENTITIES=light.kitchen,sensor.living_room_temperature

The token itself must be injected by the secret facility; this script only reads
the process environment. It never calls arbitrary HA services or writes HA
states.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "gateway" / "src"))

from device_gateway.control_client import ControlPlaneClient  # noqa: E402

from device_control.iot.adapters.home_assistant_adapter import HomeAssistantAdapter  # noqa: E402
from device_control.iot.adapters.worker import HomeAssistantPilotWorker  # noqa: E402
from device_control.iot.spi import PlatformConfig  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    token = os.environ.get("HA_TOKEN") or ""
    secret_ref = os.environ.get("HA_TOKEN_SECRET") or ""
    if not token or not secret_ref:
        raise SystemExit("HA_TOKEN and HA_TOKEN_SECRET are required")
    entities = {item.strip() for item in
                (os.environ.get("HA_ALLOWED_ENTITIES") or "").split(",") if item.strip()}
    if not entities:
        raise SystemExit("HA_ALLOWED_ENTITIES is required")
    adapter = HomeAssistantAdapter()
    config = PlatformConfig(
        platform_instance_id=os.environ.get("HA_PLATFORM_INSTANCE_ID") or "ha-1",
        tenant_id=os.environ.get("HA_TENANT") or "",
        adapter_id="home-assistant",
        endpoint=os.environ.get("HA_BASE_URL") or "",
        platform_version=os.environ.get("HA_VERSION") or "",
        secret_refs={"token": secret_ref},
    )
    adapter.connect(config, lambda ref: token)
    client = ControlPlaneClient(
        base_url=os.environ.get("DEVICE_CONTROL_URL") or "",
        gateway_id=os.environ.get("DEVICE_GATEWAY_ID") or "",
        credential=os.environ.get("DEVICE_GATEWAY_CREDENTIAL") or "",
    )
    worker = HomeAssistantPilotWorker(client=client, adapter=adapter,
                                      allowed_entities=entities)
    if args.once:
        print(worker.run_once())
        return 0
    while True:
        try:
            worker.run_once()
        except Exception as exc:  # noqa: BLE001 - keep the worker alive
            print(f"worker error: {type(exc).__name__}", file=sys.stderr)
        time.sleep(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
