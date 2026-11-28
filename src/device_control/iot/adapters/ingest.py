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

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
        device_id = self.entity_devices.get(entity_id)
        if not device_id:
            # Only claimed entities of this tenant/platform are ingested.
            return {"ignored": "entity_not_claimed", "entity_id": entity_id}
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
        )
        result["event_type"] = "state_changed"
        return result

    # -- lifecycle ------------------------------------------------------

    def reconcile(self) -> dict[str, Any]:
        """REST reconciliation after a reconnect; records a durable gap."""

        store.record_ha_gap(
            tenant=self.tenant_ref,
            platform_instance_id=self.platform_instance_id,
            reason="reconnect_reconciliation",
            reconciled=True,
        )
        reconciled = 0
        errors: list[str] = []
        if self.adapter is not None:
            now = _lag_clock()
            for entity_id, device_id in self.entity_devices.items():
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
                )
                reconciled += 1
        store.set_ha_connection(
            tenant=self.tenant_ref, platform_instance_id=self.platform_instance_id,
            connected=True,
        )
        return {"reconciled": reconciled, "errors": errors,
                "platform_instance_id": self.platform_instance_id}

    def run(self, websocket: HomeAssistantWebSocket, *,
            stop: Callable[[], bool] | None = None) -> dict[str, Any]:
        store.set_ha_connection(
            tenant=self.tenant_ref, platform_instance_id=self.platform_instance_id,
            connected=True,
        )
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
                stop=stop,
            )
        except PermissionError as exc:
            # Revoked/invalid token: retrying cannot help and may trip lockouts.
            auth_failed = True
            store.set_ha_connection(
                tenant=self.tenant_ref, platform_instance_id=self.platform_instance_id,
                connected=False, error="auth_invalid",
            )
            return {"status": "auth_invalid", "delivered": delivered,
                    "error": str(exc)}
        finally:
            if not auth_failed:
                store.set_ha_connection(
                    tenant=self.tenant_ref,
                    platform_instance_id=self.platform_instance_id,
                    connected=False,
                )
        return {"status": "stopped", "delivered": delivered,
                "reconnects": websocket.reconnects}

    # -- read model -----------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        state = store.get_ha_ingest_state(self.tenant_ref, self.platform_instance_id)
        last_event = _parse(state.get("last_event_at"))
        now = _lag_clock()
        state["lag_seconds"] = (
            max(0.0, (now - last_event).total_seconds()) if last_event else None
        )
        state["entity_count"] = len(self.entity_devices)
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
