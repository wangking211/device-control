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
import os

from . import manifest
from .adapters.android_adb import AdbSettings, AndroidAdbAdapter, discover_devices
from .adapters.base import DeviceAdapter, NullAdapter
from .adapters.fake import FakeAndroidAdapter
from .config import GatewaySettings, from_env
from .control_client import ControlPlaneClient
from .isolation import DirectRunner, ProcessRunner, Runner
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
            redaction_key=settings.redaction_key,
            redaction_key_id=settings.redaction_key_id,
        ))
    elif settings.adapter == "fake":
        adapter = FakeAndroidAdapter(
            allowed_apps=set(settings.allowed_apps) or None,
            device_fingerprint=settings.device_fingerprint or "fake-device-fingerprint",
            redaction_key=settings.redaction_key,
            redaction_key_id=settings.redaction_key_id,
        )
    else:
        adapter = NullAdapter()
    document = manifest.load(settings.manifest_path or None)
    production = (os.environ.get("DEVICE_GATEWAY_ENV") or "").strip().lower() == "production"
    if settings.manifest_public_key:
        if not manifest.verify_ed25519(document, settings.manifest_public_key,
                                       set(settings.manifest_key_ids)) or not manifest.validate_window(document):
            raise ValueError("gateway manifest Ed25519 signature or validity window is invalid")
        if document.get("gateway_id") and document["gateway_id"] != settings.gateway_id:
            raise ValueError("manifest gateway binding mismatch")
        if document.get("endpoint_id") and settings.endpoint_id and document["endpoint_id"] != settings.endpoint_id:
            raise ValueError("manifest endpoint binding mismatch")
        if document.get("device_fingerprint") and settings.device_fingerprint and \
                document["device_fingerprint"] != settings.device_fingerprint:
            raise ValueError("manifest device fingerprint mismatch")
    elif settings.manifest_require_signature or production:
        raise ValueError("production requires an Ed25519 manifest public key")
    elif settings.manifest_hmac_key:
        if not manifest.verify(manifest.digest(document), document.get("signature"),
                               settings.manifest_hmac_key):
            raise ValueError("gateway manifest HMAC signature does not verify")
    ledger = DedupeLedger(settings.db_path)
    runner: Runner
    if settings.process_isolation and settings.adapter == "android":
        runner = ProcessRunner(
            settings.adapter,
            {
                "adb_path": settings.adb_path,
                "serial": settings.serial,
                "allowed_apps": sorted(settings.allowed_apps),
                "device_fingerprint": settings.device_fingerprint,
                "redaction_key": settings.redaction_key,
                "redaction_key_id": settings.redaction_key_id,
                "command_timeout_seconds": 15.0,
            },
            allowed_apps=settings.allowed_apps,
        )
    else:
        runner = DirectRunner(adapter)
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
        endpoint_id=settings.endpoint_id,
        device_id=settings.device_id,
        device_fingerprint=settings.device_fingerprint,
        manifest_document=document,
        state_max_age_seconds=settings.state_max_age_seconds,
        runner=runner,
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
