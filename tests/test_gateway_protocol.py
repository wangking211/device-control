from copy import deepcopy
from datetime import datetime, timedelta, timezone

from device_gateway import manifest as manifest_rules
from fastapi.testclient import TestClient
from support import (
    MANIFEST,
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


def test_manifest_signature_is_required_when_configured(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    key = "manifest-signing-key-0123456789abcdef"
    monkeypatch.setenv("DEVICE_CONTROL_MANIFEST_HMAC_KEY", key)
    platform = bearer(admin_token())
    created = client.post("/v1/gateways", json={
        "gateway_id": "gw-signed", "protocol_version": "v1", "adapter_inventory": [],
    }, headers=platform)
    client.post("/v1/gateways/gw-signed/activate", json={
        "enrollment_token": created.json()["enrollment_token"], "protocol_version": "v1",
    })
    unsigned = client.put("/v1/gateways/gw-signed/manifest", json=MANIFEST, headers=platform)
    assert unsigned.status_code == 422
    assert unsigned.json()["code"] == "invalid_manifest_signature"

    signed = deepcopy(MANIFEST)
    signed["signature"] = manifest_rules.sign(manifest_rules.digest(signed), key)
    accepted = client.put("/v1/gateways/gw-signed/manifest", json=signed, headers=platform)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["digest"] == manifest_rules.digest(signed)
    tampered = {**signed, "manifest_version": "9.9.9"}
    rejected = client.put("/v1/gateways/gw-signed/manifest", json=tampered, headers=platform)
    assert rejected.status_code == 422
    assert rejected.json()["code"] == "invalid_manifest_signature"


def test_manifest_digest_drift_blocks_dispatch(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    submitted = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="drift-1",
    ), headers=bearer(agent))
    assert submitted.status_code == 201
    drifted = client.post(f"/v1/gateways/{stack['gateway_id']}/heartbeat", json={
        "status": "online", "protocol_version": "v1",
        "manifest_digest": "0" * 64, "manifest_version": "9.9.9",
        "endpoint_id": stack["endpoint_id"], "device_id": stack["device_id"],
        "device_fingerprint": stack["device_fingerprint"],
    }, headers=bearer(stack["gateway_credential"]))
    assert drifted.json()["status"] == "degraded"
    assert drifted.json()["last_error"] == "manifest_digest_mismatch"
    pull = client.get(f"/v1/gateways/{stack['gateway_id']}/commands",
                      headers=bearer(stack["gateway_credential"]))
    assert pull.status_code == 409
    assert pull.json()["code"] == "manifest_mismatch"


def test_endpoint_device_fingerprint_binding(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    response = client.post("/v1/endpoints", json={
        "endpoint_id": stack["endpoint_id"],
        "tenant_ref": "tenant-a",
        "gateway_id": stack["gateway_id"],
        "protocol_version": "v1",
        "capabilities": [],
        "device_id": "device-other",
        "device_fingerprint": "different-fingerprint",
    }, headers=stack["platform"])
    assert response.status_code == 409
    assert response.json()["code"] == "device_identity_mismatch"


def test_gateway_diagnostics_exposes_health_without_secrets(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    response = client.get(f"/v1/gateways/{stack['gateway_id']}/diagnostics",
                          headers=stack["platform"])
    assert response.status_code == 200
    body = response.json()
    assert body["manifest_digest"] == stack["manifest_digest"]
    assert body["reported_manifest_digest"] == stack["manifest_digest"]
    assert body["heartbeat_age_seconds"] is not None
    assert body["queue_depth"] == 0
    assert "credential" not in response.text


def test_admin_shell_and_alerts(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    page = client.get("/admin")
    assert page.status_code == 200
    assert "Device Control" in page.text
    assert "fetch(" in page.text

    client.post(f"/v1/gateways/{stack['gateway_id']}/heartbeat", json={
        "status": "offline", "protocol_version": "v1",
        "manifest_digest": stack["manifest_digest"], "manifest_version": "1.1.0",
        "endpoint_id": stack["endpoint_id"], "device_id": stack["device_id"],
        "device_fingerprint": stack["device_fingerprint"],
    }, headers=bearer(stack["gateway_credential"]))
    alerts = client.get("/v1/alerts", headers=stack["platform"])
    assert alerts.status_code == 200
    codes = {item["code"] for item in alerts.json()["items"]}
    assert "gateway_offline" in codes



