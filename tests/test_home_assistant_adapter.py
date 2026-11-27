import json
from pathlib import Path

import pytest

from device_control.iot.adapters.home_assistant_adapter import HomeAssistantAdapter
from device_control.iot.spi import AdapterError, PlatformConfig

ROOT = Path(__file__).resolve().parents[1]
STATES = json.loads((ROOT / "fixtures" / "home_assistant_states.json").read_text(encoding="utf-8"))
TOKEN = "ha-long-lived-token-0123456789"


class FakeHA:
    def __init__(self):
        self.state = {key: dict(value) for key, value in STATES.items()}
        self.calls = []
        self.fail_auth = False
        self.service_changes = True

    def request(self, method, url, headers, body=None):
        self.calls.append((method, url, headers, body))
        if self.fail_auth:
            return 401, {"message": "unauthorized"}
        if method == "GET" and url.endswith("/api/"):
            return 200, {"message": "API running."}
        if method == "GET" and url.endswith("/api/states"):
            return 200, [self.state["light"], self.state["sensor"]]
        if method == "GET" and "/api/states/" in url:
            entity = url.rsplit("/", 1)[-1]
            key = "light" if entity.startswith("light.") else "sensor"
            return 200, self.state[key]
        if method == "POST" and "/api/services/" in url:
            if self.service_changes:
                self.state["light"]["state"] = "on"
            return 200, [self.state["light"]]
        return 404, {}


def config(endpoint="https://ha.example"):
    return PlatformConfig(
        platform_instance_id="ha-1", tenant_id="tenant-a", adapter_id="home-assistant",
        endpoint=endpoint, platform_version="2026.11",
        secret_refs={"token": "vault:ha-token"},
    )


def connected(transport=None):
    fake = transport or FakeHA()
    adapter = HomeAssistantAdapter(transport=fake)
    adapter.connect(config(), lambda ref: TOKEN)
    return adapter, fake


def test_ha_config_rejects_external_http_and_missing_secret():
    adapter = HomeAssistantAdapter(transport=FakeHA())
    assert adapter.validate_config(config("http://ha.example")) != []
    assert adapter.validate_config(config("https://ha.example")) == []
    missing = PlatformConfig("ha", "tenant-a", "home-assistant", "https://ha", secret_refs={})
    assert adapter.validate_config(missing) != []


def test_ha_auth_health_discovery_and_observation():
    adapter, fake = connected()
    assert adapter.health().status == "ok"
    page = adapter.discover()
    assert len(page.devices) == 2
    assert all(device.trusted is False for device in page.devices)
    light = next(device for device in page.devices if device.native_id == "light.kitchen")
    assert any(cap.risk_tier == "write" for cap in light.capabilities)
    observation = adapter.observe("sensor.living_room_temperature")
    assert observation.properties["state"] == "21.5"
    assert observation.quality == "good"
    assert observation.state_hash
    telemetry, _ = adapter.get_telemetry("sensor.living_room_temperature")
    assert telemetry[0].value == 21.5
    assert telemetry[0].unit == "°C"
    assert TOKEN not in repr(adapter)


def test_ha_execute_requires_readback_verification():
    adapter, fake = connected()
    result = adapter.execute({
        "native_id": "light.kitchen", "native_operation": "light.turn_on",
        "parameters": {"brightness": 120}, "expected_state": "on",
    })
    assert result.accepted and result.executed
    assert result.verified and result.status == "succeeded"
    assert fake.calls[-1][0] == "GET"

    fake.service_changes = False
    result = adapter.execute({
        "native_id": "light.kitchen", "native_operation": "light.turn_on",
        "expected_state": "off",
    })
    assert result.accepted and result.executed
    assert not result.verified
    assert result.status == "executed_unverified"


def test_ha_auth_failure_and_event_subscription_boundary():
    fake = FakeHA()
    fake.fail_auth = True
    adapter = HomeAssistantAdapter(transport=fake)
    with pytest.raises(AdapterError) as exc:
        adapter.connect(config(), lambda ref: TOKEN)
    assert exc.value.code == "authentication_failed"

    adapter, _ = connected()
    events, cursor = adapter.subscribe(["state_changed"], cursor="1")
    assert events == [] and cursor == "1"
