from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    admin_token,
    agent_token,
    bearer,
    command_body,
    configure,
    create_gateway,
    issue_token,
    setup_stack,
)

from device_control import store
from device_control.app import app

client = TestClient(app)


def _gateway_headers(credential: str) -> dict[str, str]:
    return bearer(credential)


def test_gateway_enrollment_activation_and_rotation(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    platform = bearer(admin_token())
    created = client.post("/v1/gateways", json={
        "gateway_id": "gw-rotate", "protocol_version": "v1",
        "adapter_inventory": [{"adapter_id": "fake", "version": "1", "capabilities": []}],
    }, headers=platform)
    assert created.status_code == 201
    enrollment_token = created.json()["enrollment_token"]

    activated = client.post("/v1/gateways/gw-rotate/activate", json={
        "enrollment_token": enrollment_token, "protocol_version": "v1",
    })
    assert activated.status_code == 200
    credential = activated.json()["credential"]
    assert activated.json()["tenant_ref"] == "tenant-a"

    replay = client.post("/v1/gateways/gw-rotate/activate", json={
        "enrollment_token": enrollment_token, "protocol_version": "v1",
    })
    assert replay.status_code == 401

    rotated = client.post("/v1/gateways/gw-rotate/credentials/rotate", headers=platform)
    assert rotated.status_code == 200
    new_credential = rotated.json()["credential"]
    assert client.post("/v1/gateways/gw-rotate/heartbeat", json={
        "status": "online", "protocol_version": "v1",
    }, headers=_gateway_headers(credential)).status_code == 401
    assert client.post("/v1/gateways/gw-rotate/heartbeat", json={
        "status": "online", "protocol_version": "v1",
    }, headers=_gateway_headers(new_credential)).status_code == 200


def test_gateway_and_endpoint_credentials_are_not_interchangeable(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    endpoint_credential = client.post(f"/v1/endpoints/{stack['endpoint_id']}/credentials/rotate",
                                      headers=stack["platform"]).json()["credential"]
    assert client.post(f"/v1/gateways/{stack['gateway_id']}/heartbeat", json={
        "status": "online", "protocol_version": "v1",
    }, headers=bearer(endpoint_credential)).status_code == 401
    assert client.post(f"/v1/endpoints/{stack['endpoint_id']}/heartbeat", json={
        "status": "online", "capabilities": [],
    }, headers=bearer(stack["gateway_credential"])).status_code == 401


def test_stale_gateway_transitions_offline_and_emits_event(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("DEVICE_CONTROL_STALE_AFTER_SECONDS", "15")
    stack = setup_stack(client)
    db = store.connect()
    stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    db.execute("UPDATE device_gateways SET last_heartbeat_at=? WHERE gateway_id=?",
               (stale, stack["gateway_id"]))
    db.close()

    response = client.post("/v1/maintenance", headers=bearer(admin_token()))
    assert response.status_code == 200, response.text
    gateway = store.get_gateway("tenant-a", stack["gateway_id"])
    assert gateway["status"] == "offline"
    events = store.list_events("tenant-a", event_type="gateway.offline")
    assert any(event["aggregate_id"] == stack["gateway_id"] for event in events)


def test_cross_gateway_and_cross_tenant_delivery_denied(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    platform = bearer(admin_token())
    stack = setup_stack(client)
    other_gateway = create_gateway(client, platform, tenant="tenant-a", gateway_id="gw-other")
    tenant_b_platform = bearer(issue_token("admin-b", "tenant-b", roles=("platform_admin",)))
    tenant_b_gateway = create_gateway(client, tenant_b_platform, tenant="tenant-b", gateway_id="gw-b")

    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    submitted = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="cross-1",
    ), headers=bearer(agent))
    assert submitted.status_code == 201
    command_id = submitted.json()["command_id"]

    assert client.get("/v1/gateways/gw-other/commands",
                      headers=bearer(other_gateway)).json()["items"] == []
    assert client.get("/v1/gateways/gw-b/commands",
                      headers=bearer(tenant_b_gateway)).json()["items"] == []

    wrong_gateway_result = client.post(f"/v1/gateways/gw-other/commands/{command_id}/result",
                                       json={"status": "failed"}, headers=bearer(other_gateway))
    assert wrong_gateway_result.status_code == 404

    pulled = client.get(f"/v1/gateways/{stack['gateway_id']}/commands",
                        headers=bearer(stack["gateway_credential"]))
    assert [item["command_id"] for item in pulled.json()["items"]] == [command_id]
    envelope = pulled.json()["items"][0]
    assert envelope["tenant_ref"] == "tenant-a"
    assert envelope["gateway_id"] == stack["gateway_id"]
    assert envelope["protocol_version"] == "v1"
    assert envelope["policy_decision"] in {"allow", "ask"}


def test_gateway_revocation_invalidates_endpoint_work(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    submitted = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="revoke-1",
    ), headers=bearer(agent))
    assert submitted.status_code == 201

    assert client.delete(f"/v1/gateways/{stack['gateway_id']}",
                         headers=stack["platform"]).status_code == 200
    assert store.get_gateway("tenant-a", stack["gateway_id"])["status"] == "revoked"
    assert store.get_command("tenant-a", submitted.json()["command_id"])["status"] == "cancelled"
    assert store.active_lease("tenant-a", lease["lease_id"], stack["endpoint_id"]) is None
    assert store.get_endpoint("tenant-a", stack["endpoint_id"])["status"] == "offline"
    assert client.post(f"/v1/gateways/{stack['gateway_id']}/heartbeat", json={
        "status": "online", "protocol_version": "v1",
    }, headers=bearer(stack["gateway_credential"])).status_code == 401


def test_gateway_action_requires_online_heartbeat(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    platform = bearer(admin_token())
    created = client.post("/v1/gateways", json={
        "gateway_id": "gw-pending", "protocol_version": "v1", "adapter_inventory": [],
    }, headers=platform)
    activated = client.post("/v1/gateways/gw-pending/activate", json={
        "enrollment_token": created.json()["enrollment_token"],
        "protocol_version": "v1",
    }).json()
    # Activated but never heartbeat: pulling work is refused.
    response = client.get("/v1/gateways/gw-pending/commands",
                          headers=bearer(activated["credential"]))
    assert response.status_code == 409
    assert response.json()["code"] == "gateway_not_online"
