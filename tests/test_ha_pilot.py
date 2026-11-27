
from device_gateway.control_client import ControlPlaneClient
from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    admin_token,
    agent_token,
    approver_token,
    bearer,
    command_body,
    configure,
    issue_token,
)

from device_control import store
from device_control.app import app
from device_control.iot.adapters.home_assistant_adapter import HomeAssistantAdapter
from device_control.iot.adapters.worker import HomeAssistantPilotWorker

client = TestClient(app)
TOKEN = "ha-long-lived-token-0123456789"
STATES = {
    "light": {
        "entity_id": "light.kitchen", "state": "off",
        "attributes": {"friendly_name": "Kitchen Light"},
        "last_updated": "2026-11-27T08:00:00+00:00",
    },
    "sensor": {
        "entity_id": "sensor.living_room_temperature", "state": "21.5",
        "attributes": {"friendly_name": "Living Room Temperature", "unit_of_measurement": "°C"},
        "last_updated": "2026-11-27T08:00:00+00:00",
    },
}


class FakeHA:
    def __init__(self):
        self.state = {key: dict(value) for key, value in STATES.items()}
        self.service_changes = True

    def request(self, method, url, headers, body=None):
        if method == "GET" and url.endswith("/api/"):
            return 200, {"message": "API running."}
        if method == "GET" and url.endswith("/api/states"):
            return 200, list(self.state.values())
        if method == "GET" and "/api/states/" in url:
            key = "light" if "light." in url else "sensor"
            return 200, self.state[key]
        if method == "POST" and "/api/services/" in url:
            if self.service_changes:
                self.state["light"]["state"] = "on"
            return 200, [self.state["light"]]
        return 404, {}


class InProcessTransport:
    def request(self, method, url, body, headers, raw=None):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[1]
        response = client.request(method, path, json=body, headers=headers)
        return response.status_code, response.json()


def platform_payload():
    return {
        "platform_instance_id": "ha-1",
        "adapter_id": "home-assistant",
        "base_url": "https://ha.example",
        "secret_ref": "vault:ha-token",
        "platform_version": "2026.11",
    }


def test_platform_discovery_claim_and_pending_is_not_writable(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    created = client.post("/v1/platform-instances", json=platform_payload(),
                          headers=bearer(admin_token()))
    assert created.status_code == 201, created.text
    platform = created.json()
    assert platform["gateway_credential"]

    discovered = client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": "ha:tenant-a:light:kitchen", "native_id": "light.kitchen",
         "display_name": "Kitchen Light", "device_type": "light",
         "area": "Kitchen", "capabilities": [
             {"capability_id": "device.observe"},
             {"capability_id": "light.turn_on"},
         ]},
        {"device_id": "ha:tenant-a:sensor:living-room-temperature",
         "native_id": "sensor.living_room_temperature",
         "display_name": "Living Room Temperature", "device_type": "sensor",
         "capabilities": [{"capability_id": "device.observe"}]},
    ]}, headers=bearer(admin_token()))
    assert discovered.status_code == 200, discovered.text
    assert all(item["trust_state"] == "pending" for item in discovered.json()["items"])

    device = client.get("/v1/iot-devices/ha:tenant-a:light:kitchen",
                        headers=bearer(admin_token())).json()
    assert device["trust_state"] == "pending"

    claimed = client.post("/v1/iot-devices/ha:tenant-a:light:kitchen/claim", json={
        "capability_ids": ["device.observe", "light.turn_on"],
    }, headers=bearer(admin_token()))
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["trust_state"] == "claimed"
    assert claimed.json()["endpoint_id"].startswith("ep-")
    assert store.get_endpoint("tenant-a", claimed.json()["endpoint_id"])["status"] == "online"


def test_home_assistant_pilot_command_executes_and_verifies(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    created = client.post("/v1/platform-instances", json=platform_payload(),
                          headers=bearer(admin_token())).json()
    client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": "ha:tenant-a:light:kitchen", "native_id": "light.kitchen",
         "display_name": "Kitchen Light", "device_type": "light",
         "capabilities": [
             {"capability_id": "device.observe"}, {"capability_id": "light.turn_on"},
         ]},
    ]}, headers=bearer(admin_token()))
    claimed = client.post("/v1/iot-devices/ha:tenant-a:light:kitchen/claim", json={
        "capability_ids": ["device.observe", "light.turn_on"],
    }, headers=bearer(admin_token())).json()

    fake = FakeHA()
    adapter = HomeAssistantAdapter(transport=fake)
    adapter.connect(
        type("C", (), {"platform_instance_id": "ha-1", "tenant_id": "tenant-a",
                        "adapter_id": "home-assistant", "endpoint": "https://ha.example",
                        "platform_version": "2026.11", "secret_refs": {"token": "vault:ha-token"},
                        "settings": {}})(),
        lambda ref: TOKEN,
    )
    observed = adapter.observe("light.kitchen")
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=claimed["endpoint_id"])
    approval_request = client.post("/v1/approvals", json={
        "endpoint_id": claimed["endpoint_id"], "lease_id": lease["lease_id"],
        "capability_id": "light.turn_on", "capability_version": "1.0.0",
        "input": {"entity_id": "light.kitchen", "expected_state": "on"},
        "intent": "Turn on the kitchen light", "state_hash": observed.state_hash,
        "state_version": observed.state_version,
    }, headers=bearer(agent))
    assert approval_request.status_code == 201, approval_request.text
    approval = approval_request.json()
    assert client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                       json={"approved": True}, headers=bearer(approver_token())).status_code == 200
    body = command_body(
        endpoint_id=claimed["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="ha-light-on-1", capability_id="light.turn_on",
        input_payload={"entity_id": "light.kitchen", "expected_state": "on"},
        state_hash=observed.state_hash, state_version=observed.state_version,
        approval_id=approval["approval_id"], approval_nonce=approval["approval_nonce"],
        intent="Turn on the kitchen light",
    )
    submitted = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert submitted.status_code == 201, submitted.text
    command_id = submitted.json()["command_id"]

    control = ControlPlaneClient(
        base_url="http://testserver", gateway_id=created["gateway_id"],
        credential=created["gateway_credential"], transport=InProcessTransport(),
    )
    worker = HomeAssistantPilotWorker(
        client=control, adapter=adapter, allowed_entities={"light.kitchen"},
    )
    summary = worker.run_once()
    assert summary["executed"] == 1
    command = store.get_command("tenant-a", command_id)
    assert command["status"] == "succeeded", command
    assert command["verification"]["verified"] is True
    assert command["task_ref"] == "task-1"
    assert fake.state["light"]["state"] == "on"


def test_unclaimed_device_has_no_endpoint_and_twin_is_separate(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    client.post("/v1/platform-instances", json=platform_payload(),
                headers=bearer(admin_token()))
    client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": "ha:tenant-a:light:kitchen", "native_id": "light.kitchen",
         "display_name": "Kitchen Light", "device_type": "light",
         "capabilities": [{"capability_id": "device.observe"}]},
    ]}, headers=bearer(admin_token()))
    device = client.get("/v1/iot-devices/ha:tenant-a:light:kitchen",
                        headers=bearer(admin_token())).json()
    assert device["endpoint_id"] is None
    assert client.post("/v1/iot-devices/ha:tenant-a:light:kitchen/twin", json={
        "desired": {"state": "on"}, "reported": {"state": "off"},
        "observed": {"state": "off", "source": "ha"},
    }, headers=bearer(admin_token())).status_code == 200
    twin = client.get("/v1/iot-devices/ha:tenant-a:light:kitchen/twin",
                      headers=bearer(admin_token())).json()
    assert twin["desired"]["state"] == "on"
    assert twin["reported"]["state"] == "off"
    assert twin["observed"]["source"] == "ha"


def test_platform_disable_revokes_adapter_and_resets_devices(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    created = client.post("/v1/platform-instances", json=platform_payload(),
                          headers=bearer(admin_token())).json()
    client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": "ha:tenant-a:light:kitchen", "native_id": "light.kitchen",
         "display_name": "Kitchen Light", "device_type": "light",
         "capabilities": [{"capability_id": "device.observe"}]},
    ]}, headers=bearer(admin_token()))
    claimed = client.post("/v1/iot-devices/ha:tenant-a:light:kitchen/claim",
                          json={}, headers=bearer(admin_token())).json()
    disabled = client.delete("/v1/platform-instances/ha-1?tenant_ref=tenant-a",
                             headers=bearer(admin_token()))
    assert disabled.status_code == 200
    assert store.get_platform_instance("tenant-a", "ha-1")["status"] == "disabled"
    assert client.post(f"/v1/gateways/{created['gateway_id']}/heartbeat", json={
        "status": "online", "protocol_version": "v1",
    }, headers=bearer(created["gateway_credential"])).status_code == 401
    assert store.get_iot_device("tenant-a", "ha:tenant-a:light:kitchen")["trust_state"] == "pending"
    assert store.get_endpoint("tenant-a", claimed["endpoint_id"])["status"] == "offline"


def test_platform_and_device_are_tenant_scoped(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    client.post("/v1/platform-instances", json=platform_payload(),
                headers=bearer(admin_token()))
    client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": "ha:tenant-a:light:kitchen", "native_id": "light.kitchen",
         "display_name": "Kitchen Light", "device_type": "light",
         "capabilities": [{"capability_id": "device.observe"}]},
    ]}, headers=bearer(admin_token()))
    other = bearer(issue_token("intruder", "tenant-b", roles=("platform_admin",)))
    assert client.get("/v1/platform-instances/ha-1", headers=other).status_code == 404
    assert client.get("/v1/iot-devices/ha:tenant-a:light:kitchen",
                      headers=other).status_code == 404
    assert client.get("/v1/iot-devices", headers=other).json()["items"] == []


def test_default_claim_is_read_only(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    client.post("/v1/platform-instances", json=platform_payload(),
                headers=bearer(admin_token()))
    client.post("/v1/platform-instances/ha-1/discover", json={"devices": [
        {"device_id": "ha:tenant-a:light:kitchen", "native_id": "light.kitchen",
         "display_name": "Kitchen Light", "device_type": "light",
         "capabilities": [
             {"capability_id": "device.observe"}, {"capability_id": "light.turn_on"},
         ]},
    ]}, headers=bearer(admin_token()))
    claimed = client.post("/v1/iot-devices/ha:tenant-a:light:kitchen/claim",
                          json={}, headers=bearer(admin_token())).json()
    assert [item["id"] for item in claimed["capabilities"]] == ["device.observe"]
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=claimed["endpoint_id"])
    body = command_body(
        endpoint_id=claimed["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="read-only-1", capability_id="light.turn_on",
        input_payload={"entity_id": "light.kitchen", "expected_state": "on"},
    )
    response = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert response.status_code == 409
    assert response.json()["code"] == "unsupported_capability"
