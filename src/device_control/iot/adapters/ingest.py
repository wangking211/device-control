"""Durable Home Assistant event ingestion.

The WebSocket client is only transport. This pipeline owns the durable part:

* it accepts events only for entities that are claimed on the exact tenant and
  platform instance (unclaimed entities never advance the cursor);
* it normalizes events to a versioned internal shape and delegates persistence
  to :mod:`device_control.store`, which writes the dedupe log, telemetry, twin
  and cursor in one transaction;
* a reconnect triggers REST reconciliation and a persisted gap marker;
* token invalidation stops retries whereas transient network loss backs off.

`observed_at` (source time) and `received_at` (edge time) are kept separate. A
source timestamp too far in the future is clamped and marked ``time_skew`` so a
clock-skewed device cannot pin the twin in the future.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from device_control import store

from .home_assistant_adapter import HomeAssistantAdapter
from .websocket import HomeAssistantWebSocket


def _lag_clock() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def claimed_entity_map(tenant: str, platform_instance_id: str) -> dict[str, str]:
    """Map native entity -> device id for claimed devices only."""

    devices = store.list_iot_devices(
        tenant, platform_instance_id=platform_instance_id, trust_state="claimed"
    )
    return {str(device["native_id"]): str(device["device_id"]) for device in devices}


@dataclass
class HomeAssistantEventPipeline:
    tenant_ref: str
    platform_instance_id: str
    entity_devices: Mapping[str, str]
    adapter: HomeAssistantAdapter | None = None
    max_future_skew_seconds: float = 300.0
    owner_ref: str | None = None
    owner_incarnation: str | None = None
    owner_generation: int | None = None
    owner_ttl_seconds: float = 120.0
    ownership_lost: bool = False
    binding_loader: Callable[[], tuple[Mapping[str, str], str]] | None = None
    binding_refresh_seconds: float = 60.0
    binding_valid_until: datetime | None = None
    binding_expired: bool = False
    health_path: str | None = None

    # -- ingestion ------------------------------------------------------

    def ingest(self, message: Mapping[str, Any],
               *, received_at: datetime | None = None) -> dict[str, Any]:
        received = received_at or _lag_clock()
        raw_event = message.get("event") if isinstance(message, Mapping) else None
        event: Mapping[str, Any] = raw_event if isinstance(raw_event, Mapping) else {}
        raw_data = event.get("data")
        data: Mapping[str, Any] = raw_data if isinstance(raw_data, Mapping) else {}
        entity_id = str(data.get("entity_id") or "")
        if not entity_id:
            return {"ignored": "entity_missing"}
        entities = self.entity_devices
        device_id = entities.get(entity_id)
        if not device_id:
            # Only claimed entities of this tenant/platform are ingested.
            return {"ignored": "entity_not_claimed", "entity_id": entity_id}
        if self.ownership_lost:
            return {"ignored": "ownership_lost", "entity_id": entity_id}
        if self.binding_expired:
            return {"ignored": "binding_expired", "entity_id": entity_id}
        raw_context = event.get("context")
        context: Mapping[str, Any] = raw_context if isinstance(raw_context, Mapping) else {}
        context_id = str(context.get("id") or "")
        new_state = data.get("new_state")
        new_state = new_state if isinstance(new_state, Mapping) else {}
        state = str(new_state["state"]) if "state" in new_state else None
        attributes = new_state.get("attributes")
        attributes = dict(attributes) if isinstance(attributes, Mapping) else {}
        observed = _parse(new_state.get("last_updated") or event.get("time_fired"))
        quality = "good"
        status = "ok"
        if observed is None:
            observed = received
            status = "timestamp_missing"
        elif observed > received + timedelta(seconds=self.max_future_skew_seconds):
            observed = received
            quality = "suspect"
            status = "time_skew"
        observed_at = _iso(observed)
        result = store.record_ha_event(
            tenant=self.tenant_ref,
            platform_instance_id=self.platform_instance_id,
            device_id=device_id,
            entity_id=entity_id,
            state=state,
            attributes=attributes,
            observed_at=observed_at,
            received_at=_iso(received),
            context_id=context_id,
            quality=quality,
            status=status,
            owner_ref=self.owner_ref,
            owner_generation=self.owner_generation,
            owner_incarnation=self.owner_incarnation,
        )
        result["event_type"] = "state_changed"
        return result

    # -- lifecycle ------------------------------------------------------

    def reconcile(self) -> dict[str, Any]:
        """REST reconciliation after a reconnect; records a durable gap."""

        if self.ownership_lost:
            return {"reconciled": 0, "errors": ["ownership_lost"],
                    "platform_instance_id": self.platform_instance_id}
        store.record_ha_gap(
            tenant=self.tenant_ref,
            platform_instance_id=self.platform_instance_id,
            reason="reconnect_reconciliation",
            reconciled=True,
            owner_ref=self.owner_ref,
            owner_generation=self.owner_generation,
            owner_incarnation=self.owner_incarnation,
        )
        reconciled = 0
        errors: list[str] = []
        if self.adapter is not None:
            now = _lag_clock()
            for entity_id, device_id in dict(self.entity_devices).items():
                try:
                    observation = self.adapter.observe(entity_id)
                except Exception as exc:  # noqa: BLE001 - reconcile must not abort others
                    errors.append(f"{entity_id}:{type(exc).__name__}")
                    continue
                properties = dict(observation.properties or {})
                state = properties.pop("state", None)
                observed_at = _iso(_parse(observation.observed_at) or now)
                store.record_ha_event(
                    tenant=self.tenant_ref,
                    platform_instance_id=self.platform_instance_id,
                    device_id=device_id,
                    entity_id=entity_id,
                    state=None if state is None else str(state),
                    attributes=properties,
                    observed_at=observed_at,
                    received_at=_iso(now),
                    context_id="reconcile",
                    quality=observation.quality,
                    status="ok" if observation.quality == "good" else "reconcile_degraded",
                    owner_ref=self.owner_ref,
                    owner_generation=self.owner_generation,
                    owner_incarnation=self.owner_incarnation,
                )
                reconciled += 1
        store.set_ha_connection(
            tenant=self.tenant_ref, platform_instance_id=self.platform_instance_id,
            connected=True,
        )
        return {"reconciled": reconciled, "errors": errors,
                "platform_instance_id": self.platform_instance_id}

    def run(self, websocket: HomeAssistantWebSocket, *,
            stop: Callable[[], bool] | None = None,
            owner_ref: str | None = None,
            owner_ttl_seconds: float | None = None,
            owner_incarnation: str | None = None) -> dict[str, Any]:
        ttl = float(owner_ttl_seconds or self.owner_ttl_seconds)
        incarnation = owner_incarnation or uuid.uuid4().hex
        acquired = False
        if owner_ref:
            lease = store.acquire_ha_ingest_owner(
                tenant=self.tenant_ref,
                platform_instance_id=self.platform_instance_id,
                owner_ref=owner_ref,
                ttl_seconds=ttl,
                incarnation=incarnation,
            )
            if not lease.get("acquired"):
                # Another process owns this subscription; do not duplicate it.
                self._write_health("standby")
                return {"status": "standby", "delivered": 0,
                        "generation": lease.get("generation"),
                        "platform_instance_id": self.platform_instance_id}
            self.owner_ref = owner_ref
            self.owner_incarnation = incarnation
            self.owner_generation = int(lease.get("generation") or 0)
            self.ownership_lost = False
            acquired = True
        stop_event = threading.Event()
        requested_stop = stop or (lambda: False)

        def should_stop() -> bool:
            return stop_event.is_set() or requested_stop()

        if self.binding_loader is not None:
            try:
                self._apply_binding_load()
            except Exception:  # noqa: BLE001 - fall back only until valid_until
                if (self.binding_valid_until is None
                        or _lag_clock() >= self.binding_valid_until):
                    self.binding_expired = True
                    self._write_health("failed", error="binding_expired")
                    return {"status": "binding_expired", "delivered": 0,
                            "generation": self.owner_generation,
                            "platform_instance_id": self.platform_instance_id}

        renewal_thread: threading.Thread | None = None
        if acquired:
            renewal_thread = threading.Thread(
                target=self._renew_loop,
                args=(websocket, stop_event, ttl),
                daemon=True,
                name=f"ha-owner-renew-{self.platform_instance_id}",
            )
            renewal_thread.start()
        binding_thread: threading.Thread | None = None
        if self.binding_loader is not None:
            binding_thread = threading.Thread(
                target=self._binding_loop,
                args=(websocket, stop_event),
                daemon=True,
                name=f"ha-binding-refresh-{self.platform_instance_id}",
            )
            binding_thread.start()
        store.set_ha_connection(
            tenant=self.tenant_ref, platform_instance_id=self.platform_instance_id,
            connected=True,
        )
        self._write_health("connected")
        delivered = 0
        auth_failed = False

        def on_event(message: dict[str, Any]) -> None:
            self.ingest(message)

        def reconcile() -> None:
            self.reconcile()

        try:
            delivered = websocket.run(
                on_event=on_event,
                reconcile=reconcile,
                stop=should_stop,
            )
        except PermissionError as exc:
            # Revoked/invalid token: retrying cannot help and may trip lockouts.
            auth_failed = True
            store.set_ha_connection(
                tenant=self.tenant_ref, platform_instance_id=self.platform_instance_id,
                connected=False, error="auth_invalid",
            )
            self._write_health("failed", error="auth_invalid")
            return {"status": "auth_invalid", "delivered": delivered,
                    "error": str(exc)}
        finally:
            stop_event.set()
            if renewal_thread is not None:
                renewal_thread.join(timeout=5)
            if binding_thread is not None:
                binding_thread.join(timeout=5)
            if not auth_failed:
                store.set_ha_connection(
                    tenant=self.tenant_ref,
                    platform_instance_id=self.platform_instance_id,
                    connected=False,
                )
                self._write_health("stopped")
            if acquired and owner_ref:
                store.release_ha_ingest_owner(
                    tenant=self.tenant_ref,
                    platform_instance_id=self.platform_instance_id,
                    owner_ref=owner_ref,
                    incarnation=incarnation,
                )
        status = ("binding_expired" if self.binding_expired else
                  "ownership_lost" if self.ownership_lost else "stopped")
        return {"status": status, "delivered": delivered,
                "generation": self.owner_generation,
                "reconnects": websocket.reconnects}

    def _renew_loop(self, websocket: HomeAssistantWebSocket,
                    stop_event: threading.Event, ttl_seconds: float) -> None:
        interval = max(5.0, ttl_seconds / 3)
        while not stop_event.wait(interval):
            if self.owner_ref is None or self.owner_generation is None:
                return
            result = store.renew_ha_ingest_owner(
                tenant=self.tenant_ref,
                platform_instance_id=self.platform_instance_id,
                owner_ref=self.owner_ref,
                generation=self.owner_generation,
                ttl_seconds=ttl_seconds,
                incarnation=self.owner_incarnation,
            )
            if not result.get("renewed"):
                # Fencing lost: stop the socket and reject further writes.
                self.ownership_lost = True
                self._write_health("failed", error="ownership_lost")
                stop_event.set()
                websocket.close()
                return

    def _apply_binding_load(self) -> None:
        if self.binding_loader is None:
            return
        entities, valid_until = self.binding_loader()
        parsed = _parse(valid_until)
        if parsed is None:
            raise ValueError("binding snapshot has no valid_until")
        # Single assignment: ingestion either sees the old or the new map.
        self.entity_devices = dict(entities)
        self.binding_valid_until = parsed

    def _binding_loop(self, websocket: HomeAssistantWebSocket,
                      stop_event: threading.Event) -> None:
        interval = max(5.0, self.binding_refresh_seconds)
        while not stop_event.wait(interval):
            try:
                self._apply_binding_load()
            except Exception:  # noqa: BLE001 - fallback only until expiry
                if (self.binding_valid_until is None
                        or _lag_clock() >= self.binding_valid_until):
                    self.binding_expired = True
                    self._write_health("failed", error="binding_expired")
                    stop_event.set()
                    websocket.close()
                    return

    # -- read model -----------------------------------------------------

    def _write_health(self, status: str, *, error: str | None = None) -> None:
        if not self.health_path:
            return
        path = Path(self.health_path)
        payload = {
            "schema_version": "1",
            "status": status,
            "platform_instance_id": self.platform_instance_id,
            "tenant_ref": self.tenant_ref,
            "connected": status == "connected",
            "owner_ref": self.owner_ref,
            "owner_incarnation": self.owner_incarnation,
            "owner_generation": self.owner_generation,
            "ownership_lost": self.ownership_lost,
            "binding_expired": self.binding_expired,
            "binding_valid_until": (self.binding_valid_until.isoformat()
                                    if self.binding_valid_until else None),
            "last_event_at": store.get_ha_ingest_state(
                self.tenant_ref, self.platform_instance_id
            ).get("last_event_at"),
            "last_reconcile_at": store.get_ha_ingest_state(
                self.tenant_ref, self.platform_instance_id
            ).get("last_reconcile_at"),
            "gap_count": store.get_ha_ingest_state(
                self.tenant_ref, self.platform_instance_id
            ).get("gap_count"),
            "updated_at": _iso(_lag_clock()),
            "error": error,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            os.replace(temporary, path)
        except OSError:
            # Health reporting must not break ingestion.
            return

    def metrics(self) -> dict[str, Any]:
        state = store.get_ha_ingest_state(self.tenant_ref, self.platform_instance_id)
        last_event = _parse(state.get("last_event_at"))
        now = _lag_clock()
        state["lag_seconds"] = (
            max(0.0, (now - last_event).total_seconds()) if last_event else None
        )
        state["entity_count"] = len(self.entity_devices)
        state["ownership_lost"] = self.ownership_lost
        return state


def build_websocket(*, base_url: str, token: str,
                    reconnect_max: int = 10) -> HomeAssistantWebSocket:
    """Build a TLS-verified WebSocket client (HTTPS->WSS, HTTP->WS)."""

    return HomeAssistantWebSocket(
        base_url=base_url, token=token, reconnect_max=reconnect_max,
    )


__all__ = [
    "HomeAssistantEventPipeline",
    "build_websocket",
    "claimed_entity_map",
]
