"""Durable HA WebSocket pipeline tests (synthetic, no live device)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from support import admin_token, bearer, configure, issue_token

from device_control import store
from device_control.app import app
from device_control.errors import DeviceControlError
from device_control.iot.adapters.ingest import (
    HomeAssistantEventPipeline,
    claimed_entity_map,
)

client = TestClient(app)
LIGHT = "light.kitchen"
LIGHT_DEVICE = "ha:tenant-a:light:kitchen"
SENSOR = "sensor.living_room_temperature"
SENSOR_DEVICE = "ha:tenant-a:sensor:living-room-temperature"


def setup_platform(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    created = client.post("/v1/platform-instances", json={
        "platform_instance_id": "ha-1", "adapter_id": "home-assistant",
        "base_url": "https://ha.example", "secret_ref": "vault:ha-token",
        "platform_version": "2026.11",
    }, headers=bearer(admin_token()))
    assert created.status_code == 201, created.text
    discovered = client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": LIGHT_DEVICE, "native_id": LIGHT,
         "display_name": "Kitchen Light", "device_type": "light",
         "capabilities": [{"capability_id": "device.observe"}]},
        {"device_id": SENSOR_DEVICE, "native_id": SENSOR,
         "display_name": "Living Room Temperature", "device_type": "sensor",
         "capabilities": [{"capability_id": "device.observe"}]},
    ]}, headers=bearer(admin_token()))
    assert discovered.status_code == 200, discovered.text
    for device_id in (LIGHT_DEVICE, SENSOR_DEVICE):
        claimed = client.post(f"/v1/iot-devices/{device_id}/claim", json={},
                              headers=bearer(admin_token()))
        assert claimed.status_code == 200, claimed.text
    return claimed_entity_map("tenant-a", "ha-1")


def message(entity_id, state="on", *, attributes=None, observed_at=None,
            context_id="ctx-1"):
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    return {
        "type": "event",
        "event": {
            "event_type": "state_changed",
            "time_fired": observed_at,
            "context": {"id": context_id},
            "data": {
                "entity_id": entity_id,
                "new_state": {
                    "state": state,
                    "attributes": attributes or {},
                    "last_updated": observed_at,
                },
            },
        },
    }


def pipeline(entities, adapter=None):
    return HomeAssistantEventPipeline(
        tenant_ref="tenant-a", platform_instance_id="ha-1",
        entity_devices=entities, adapter=adapter,
    )


def test_claimed_event_persists_telemetry_twin_and_cursor(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    result = pipeline(entities).ingest(message(LIGHT, "on"))
    assert result["duplicate"] is False
    assert result["event_key"]

    twin = store.get_twin("tenant-a", LIGHT_DEVICE)
    assert twin["observed"]["state"] == "on"
    assert twin["observed"]["source"] == "home-assistant-ws"
    assert twin["observed"]["observed_at"] == result["observed_at"]

    telemetry = store.list_telemetry("tenant-a", LIGHT_DEVICE, metric="state")
    assert telemetry[0]["value"] == "on"
    assert telemetry[0]["source"] == "home-assistant-ws"

    state = store.get_ha_ingest_state("tenant-a", "ha-1")
    assert state["connected"] is True
    assert state["last_event_key"] == result["event_key"]
    assert state["last_event_at"] == result["observed_at"]
    assert state["duplicate_count"] == 0

    events = store.list_events("tenant-a", event_type="iot.state.changed")
    assert events[0]["aggregate_id"] == LIGHT_DEVICE


def test_duplicate_event_is_idempotent(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = pipeline(entities)
    payload = message(LIGHT, "on", observed_at="2026-11-25T10:00:00+00:00")
    first = pipe.ingest(payload)
    second = pipe.ingest(payload)
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert second["event_key"] == first["event_key"]
    assert len(store.list_ha_events("tenant-a", "ha-1")) == 1
    state = store.get_ha_ingest_state("tenant-a", "ha-1")
    assert state["duplicate_count"] == 1


def test_attribute_change_is_a_distinct_event(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = pipeline(entities)
    first = pipe.ingest(message(LIGHT, "on", attributes={"brightness": 10}))
    second = pipe.ingest(message(LIGHT, "on", attributes={"brightness": 200}))
    assert first["event_key"] != second["event_key"]
    assert second["duplicate"] is False
    twin = store.get_twin("tenant-a", LIGHT_DEVICE)
    assert twin["observed"]["attributes"]["brightness"] == 200
    assert len(store.list_ha_events("tenant-a", "ha-1")) == 2


def test_unclaimed_entity_is_ignored_and_does_not_advance_cursor(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = pipeline(entities)
    result = pipe.ingest(message("light.unclaimed", "on"))
    assert result["ignored"] == "entity_not_claimed"
    state = store.get_ha_ingest_state("tenant-a", "ha-1")
    assert state["last_event_key"] is None
    assert store.list_ha_events("tenant-a", "ha-1") == []


def test_late_event_does_not_rollback_twin(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = pipeline(entities)
    pipe.ingest(message(LIGHT, "on", observed_at="2026-11-25T10:05:00+00:00"))
    pipe.ingest(message(LIGHT, "off", observed_at="2026-11-25T09:00:00+00:00"))
    twin = store.get_twin("tenant-a", LIGHT_DEVICE)
    assert twin["observed"]["state"] == "on"
    assert twin["observed"]["observed_at"] == "2026-11-25T10:05:00+00:00"
    # Late data is still queryable.
    assert len(store.list_ha_events("tenant-a", "ha-1")) == 2


def test_future_timestamp_is_clamped_and_marked(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = pipeline(entities)
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    result = pipe.ingest(message(LIGHT, "on", observed_at=future))
    assert result["duplicate"] is False
    state = store.get_ha_ingest_state("tenant-a", "ha-1")
    # Clamped to receive time; the twin is not pinned into the future.
    twin = store.get_twin("tenant-a", LIGHT_DEVICE) or {}
    assert twin.get("observed", {}).get("state") != "on"
    events = store.list_ha_events("tenant-a", "ha-1")
    assert events[0]["status"] == "time_skew"
    assert events[0]["quality"] == "suspect"
    assert state["last_event_at"] == result["observed_at"]


class StubAdapter:
    def __init__(self, observed_at, state="off", quality="good"):
        self.observed_at = observed_at
        self.state = state
        self.quality = quality
        self.calls = []

    def observe(self, entity_id):
        from types import SimpleNamespace

        self.calls.append(entity_id)
        return SimpleNamespace(
            properties={"state": self.state, "brightness": 1},
            observed_at=self.observed_at,
            quality=self.quality,
            connectivity="online",
        )


def test_reconcile_records_gap_and_final_state(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    adapter = StubAdapter(datetime.now(timezone.utc).isoformat(), state="off")
    pipe = pipeline(entities, adapter=adapter)
    summary = pipe.reconcile()
    assert summary["reconciled"] == 2
    assert summary["errors"] == []
    state = store.get_ha_ingest_state("tenant-a", "ha-1")
    assert state["gap_count"] == 1
    assert state["last_gap_at"]
    assert state["last_reconcile_at"]
    gaps = store.list_events("tenant-a", event_type="iot.event.gap")
    assert gaps and gaps[0]["payload"]["reason"] == "reconnect_reconciliation"
    twin = store.get_twin("tenant-a", LIGHT_DEVICE)
    assert twin["observed"]["state"] == "off"


class AuthInvalidWebSocket:
    reconnects = 0

    def run(self, **kwargs):
        raise PermissionError("home_assistant_auth_invalid")


class NoopWebSocket:
    reconnects = 0

    def run(self, **kwargs):
        return 0


def test_single_writer_owner_prevents_duplicate_subscription(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    assert store.acquire_ha_ingest_owner(
        tenant="tenant-a", platform_instance_id="ha-1", owner_ref="node-a"
    ) is True
    standby = pipeline(entities).run(NoopWebSocket(), owner_ref="node-b")
    assert standby["status"] == "standby"
    store.release_ha_ingest_owner(
        tenant="tenant-a", platform_instance_id="ha-1", owner_ref="node-a"
    )
    started = pipeline(entities).run(NoopWebSocket(), owner_ref="node-b")
    assert started["status"] == "stopped"


def test_expired_owner_can_be_taken_over(tmp_path, monkeypatch):
    setup_platform(tmp_path, monkeypatch)
    assert store.acquire_ha_ingest_owner(
        tenant="tenant-a", platform_instance_id="ha-1", owner_ref="node-a"
    )
    db = store.connect()
    db.execute("UPDATE ha_ingest_state SET owner_lease_until=?"
               " WHERE tenant_ref='tenant-a' AND platform_instance_id='ha-1'",
               ("2026-01-01T00:00:00+00:00",))
    db.commit()
    db.close()
    assert store.acquire_ha_ingest_owner(
        tenant="tenant-a", platform_instance_id="ha-1", owner_ref="node-b"
    ) is True



def test_auth_invalid_stops_and_is_not_retried(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    result = pipeline(entities).run(AuthInvalidWebSocket())
    assert result["status"] == "auth_invalid"
    state = store.get_ha_ingest_state("tenant-a", "ha-1")
    assert state["connected"] is False
    assert state["last_error"] == "auth_invalid"


def test_metrics_expose_lag_and_counts(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = pipeline(entities)
    pipe.ingest(message(LIGHT, "on"))
    metrics = pipe.metrics()
    assert metrics["connected"] is True
    assert metrics["entity_count"] == 2
    assert metrics["lag_seconds"] is not None
    assert metrics["duplicate_count"] == 0


def test_cross_tenant_event_is_rejected(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipe = HomeAssistantEventPipeline(
        tenant_ref="tenant-b", platform_instance_id="ha-1", entity_devices=entities,
    )
    with pytest.raises(DeviceControlError):
        pipe.ingest(message(LIGHT, "on"))


def test_twin_freshness_is_per_device_type(tmp_path, monkeypatch):
    setup_platform(tmp_path, monkeypatch)
    old = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    for device_id in (SENSOR_DEVICE, LIGHT_DEVICE):
        store.upsert_twin(tenant="tenant-a", device_id=device_id, observed={
            "state": "on", "observed_at": old, "connectivity": "online", "quality": "good",
        })
    sensor = client.get(f"/v1/iot-devices/{SENSOR_DEVICE}/twin",
                        headers=bearer(admin_token())).json()
    light = client.get(f"/v1/iot-devices/{LIGHT_DEVICE}/twin",
                       headers=bearer(admin_token())).json()
    assert sensor["freshness"]["max_age_seconds"] == 60
    assert sensor["freshness"]["stale"] is True
    assert light["freshness"]["max_age_seconds"] == 300
    assert light["freshness"]["stale"] is False


def test_ingest_api_is_tenant_scoped(tmp_path, monkeypatch):
    entities = setup_platform(tmp_path, monkeypatch)
    pipeline(entities).ingest(message(LIGHT, "on"))
    ok = client.get("/v1/platform-instances/ha-1/ingest-state",
                    headers=bearer(admin_token()))
    assert ok.status_code == 200, ok.text
    assert ok.json()["last_event_key"]
    events = client.get("/v1/platform-instances/ha-1/events",
                        headers=bearer(admin_token()))
    assert len(events.json()["items"]) == 1
    other = bearer(issue_token("intruder", "tenant-b", roles=("platform_admin",)))
    assert client.get("/v1/platform-instances/ha-1/ingest-state",
                      headers=other).status_code == 404
    assert client.get("/v1/platform-instances/ha-1/events",
                      headers=other).status_code == 404
