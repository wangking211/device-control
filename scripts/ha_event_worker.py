"""Managed Home Assistant event consumer (separate from the API process).

Environment (secrets are injected, never CLI args):
  DEVICE_CONTROL_URL, DEVICE_GATEWAY_ID, DEVICE_GATEWAY_CREDENTIAL
  HA_BASE_URL, HA_TOKEN or HA_TOKEN_FILE
  DEVICE_CONTROL_BINDING_VERIFICATION_KEY, DEVICE_CONTROL_BINDING_KEY_ID
  HA_PLATFORM_INSTANCE_ID, HA_OWNER_ID (optional), HA_BINDING_STATE_PATH

The process loads the signed binding snapshot from Device Control, verifies it,
and ingests only claimed entities. It acquires a durable single-writer owner
lease, persists events before advancing the cursor, and releases the lease on
shutdown. Duplicate replicas exit as ``standby`` without subscribing.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "gateway" / "src"))

from device_gateway.control_client import ControlPlaneClient  # noqa: E402

from device_control.iot.adapters.binding import BindingRegistry  # noqa: E402
from device_control.iot.adapters.home_assistant_adapter import HomeAssistantAdapter  # noqa: E402
from device_control.iot.adapters.ingest import (  # noqa: E402
    HomeAssistantEventPipeline,
    build_websocket,
)
from device_control.iot.spi import PlatformConfig  # noqa: E402


def _token() -> str:
    token = os.environ.get("HA_TOKEN") or ""
    if not token:
        token_file = os.environ.get("HA_TOKEN_FILE") or ""
        if token_file:
            try:
                token = Path(token_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise SystemExit("HA_TOKEN_FILE is unreadable") from exc
    if not token:
        raise SystemExit("HA_TOKEN or HA_TOKEN_FILE is required")
    return token


def main() -> int:
    token = _token()
    base_url = os.environ.get("HA_BASE_URL") or ""
    platform_instance_id = os.environ.get("HA_PLATFORM_INSTANCE_ID") or "ha-1"
    if not base_url:
        raise SystemExit("HA_BASE_URL is required")

    client = ControlPlaneClient(
        base_url=os.environ.get("DEVICE_CONTROL_URL") or "",
        gateway_id=os.environ.get("DEVICE_GATEWAY_ID") or "",
        credential=os.environ.get("DEVICE_GATEWAY_CREDENTIAL") or "",
    )
    document = client.bindings()
    tenant_ref = str(document.get("tenant_ref") or "")
    if not tenant_ref:
        raise SystemExit("binding document has no tenant scope")
    registry = BindingRegistry(
        tenant_ref=tenant_ref,
        gateway_id=str(document.get("gateway_id") or ""),
        platform_instance_id=str(document.get("platform_instance_id")
                                 or platform_instance_id),
        verification_key=os.environ.get("DEVICE_CONTROL_BINDING_VERIFICATION_KEY") or "",
        key_id=os.environ.get("DEVICE_CONTROL_BINDING_KEY_ID") or "",
        state_path=os.environ.get("HA_BINDING_STATE_PATH") or None,
    )
    registry.load_document(document)
    entities = {
        binding["entity_id"]: binding["device_id"]
        for binding in registry.snapshot()
        if not binding.get("revoked")
    }
    if not entities:
        raise SystemExit("no claimed entities in binding snapshot")

    adapter = HomeAssistantAdapter()
    adapter.connect(
        PlatformConfig(
            platform_instance_id=registry.platform_instance_id,
            tenant_id=tenant_ref,
            adapter_id="home-assistant",
            endpoint=base_url,
            platform_version=os.environ.get("HA_VERSION") or "",
            secret_refs={"token": os.environ.get("HA_TOKEN_SECRET") or "env:HA_TOKEN"},
        ),
        lambda _ref: token,
    )
    pipeline = HomeAssistantEventPipeline(
        tenant_ref=tenant_ref,
        platform_instance_id=registry.platform_instance_id,
        entity_devices=entities,
        adapter=adapter,
    )
    stop = threading.Event()

    def _shutdown(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    result = pipeline.run(
        build_websocket(base_url=base_url, token=token),
        stop=stop.is_set,
        owner_ref=os.environ.get("HA_OWNER_ID") or f"ha-worker:{os.getpid()}",
    )
    if result.get("status") == "auth_invalid":
        return 2
    if result.get("status") == "standby":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
