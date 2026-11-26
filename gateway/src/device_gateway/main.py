"""Gateway entrypoint.

    python -m device_gateway.main --manifest
    python -m device_gateway.main --discover
    python -m device_gateway.main --once
    python -m device_gateway.main

Configuration comes from environment variables documented in
``docs/DC-003-GATEWAY-PROTOCOL.md``. ADB path, serial and app allowlist are
operator inputs and are never read from a command envelope.
"""

from __future__ import annotations

import argparse
import json

from . import manifest
from .adapters.android_adb import AdbSettings, AndroidAdbAdapter, discover_devices
from .adapters.base import DeviceAdapter, NullAdapter
from .adapters.fake import FakeAndroidAdapter
from .config import GatewaySettings, from_env
from .control_client import ControlPlaneClient
from .ledger import DedupeLedger
from .queue import BoundedQueue
from .worker import GatewayWorker, WorkerConfig


def build_components(settings: GatewaySettings) -> tuple[GatewayWorker, DedupeLedger]:
    adapter: DeviceAdapter
    if settings.adapter == "android":
        adapter = AndroidAdbAdapter(AdbSettings(
            adb_path=settings.adb_path,
            serial=settings.serial,
            allowed_apps=settings.allowed_apps,
        ))
    elif settings.adapter == "fake":
        adapter = FakeAndroidAdapter(allowed_apps=set(settings.allowed_apps) or None)
    else:
        adapter = NullAdapter()
    ledger = DedupeLedger(settings.db_path)
    worker = GatewayWorker(
        client=ControlPlaneClient(
            base_url=settings.control_url,
            gateway_id=settings.gateway_id,
            credential=settings.credential,
        ),
        adapter=adapter,
        ledger=ledger,
        queue=BoundedQueue(settings.queue_capacity),
        # Learned from the control plane on the first heartbeat. Empty until
        # then, which makes admission fail closed.
        tenant_ref="",
        config=WorkerConfig(
            heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
            poll_interval_seconds=settings.poll_interval_seconds,
            batch_size=settings.batch_size,
        ),
    )
    return worker, ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="device-gateway")
    parser.add_argument("--manifest", action="store_true", help="print the capability manifest")
    parser.add_argument("--discover", action="store_true", help="list attached Android devices")
    parser.add_argument("--once", action="store_true", help="run one heartbeat/poll/execute cycle")
    args = parser.parse_args(argv)

    if args.manifest:
        print(json.dumps(manifest.manifest_document(), indent=2))
        return 0
    if args.discover:
        import os

        print(json.dumps(discover_devices(
            os.environ.get("DEVICE_GATEWAY_ADB_PATH") or "adb"
        ), indent=2))
        return 0

    settings = from_env()
    worker, ledger = build_components(settings)
    try:
        if args.once:
            print(json.dumps(worker.run_once(), indent=2))
        else:
            worker.run_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        ledger.close()
        worker.adapter.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
