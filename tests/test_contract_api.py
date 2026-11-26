from fastapi.testclient import TestClient

from device_control.app import app

client = TestClient(app)


def test_health_and_contract_catalog():
    assert client.get("/health/live").json() == {"status": "live"}
    assert client.get("/health/ready").status_code == 200
    assert len(client.get("/v1/contracts").json()["contracts"]) == 6


def test_contract_validation_reports_errors_without_accepting_unknown_contract():
    response = client.post("/v1/contracts/invocation/validate", json={})
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["errors"]
    assert client.post("/v1/contracts/private/validate", json={}).status_code == 404


def test_valid_invocation_shape():
    payload = {
        "request_id": "req-1", "tenant_ref": "tenant-1", "endpoint_id": "endpoint-1",
        "capability_id": "screen.observe", "capability_version": "1.0.0",
        "requested_by": "user-1", "deadline": "2026-11-26T12:00:00Z",
        "idempotency_key": "idem-1", "input": {}, "intent": "Observe current screen"
    }
    assert client.post("/v1/contracts/invocation/validate", json=payload).json()["valid"] is True


def test_endpoint_enrollment_heartbeat_list_and_revoke(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVICE_CONTROL_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("DEVICE_CONTROL_DB", str(tmp_path / "device-control.sqlite3"))
    admin = {"Authorization": "Bearer test-admin-token"}
    payload = {
        "endpoint_id": "phone-1", "tenant_ref": "tenant-a", "node_ref": "node-1",
        "protocol_version": "v1", "capabilities": []
    }
    assert client.post("/v1/endpoints", json=payload).status_code == 401
    created = client.post("/v1/endpoints", json=payload, headers=admin)
    assert created.status_code == 201
    credential = created.json()["credential"]
    assert credential
    assert "credential" not in client.get("/v1/endpoints?tenant_ref=tenant-a", headers=admin).text

    heartbeat = client.post("/v1/endpoints/phone-1/heartbeat", json={"status": "online", "capabilities": []},
                            headers={"Authorization": f"Bearer {credential}"})
    assert heartbeat.status_code == 200
    assert client.get("/v1/endpoints?tenant_ref=tenant-a", headers=admin).json()["items"][0]["status"] == "online"
    assert client.delete("/v1/endpoints/phone-1", headers=admin).json()["status"] == "revoked"
    assert client.post("/v1/endpoints/phone-1/heartbeat", json={"status": "online", "capabilities": []},
                       headers={"Authorization": f"Bearer {credential}"}).status_code == 401


def test_device_lease_is_exclusive_tenant_scoped_and_releasable(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVICE_CONTROL_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("DEVICE_CONTROL_DB", str(tmp_path / "leases.sqlite3"))
    admin = {"Authorization": "Bearer test-admin-token"}
    enrolled = client.post("/v1/endpoints", json={
        "endpoint_id": "phone-lease", "tenant_ref": "tenant-a", "protocol_version": "v1", "capabilities": []
    }, headers=admin).json()
    client.post("/v1/endpoints/phone-lease/heartbeat", json={"status": "online", "capabilities": []},
                headers={"Authorization": f"Bearer {enrolled['credential']}"})
    first = client.post("/v1/device-leases", json={"endpoint_id":"phone-lease","tenant_ref":"tenant-a","task_ref":"task-1","holder_ref":"agent-1","mode":"control","ttl_seconds":60},headers=admin)
    assert first.status_code == 201
    conflict = client.post("/v1/device-leases", json={"endpoint_id":"phone-lease","tenant_ref":"tenant-a","task_ref":"task-2","holder_ref":"agent-2","mode":"read_only","ttl_seconds":60},headers=admin)
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["holder_ref"] == "agent-1"
    wrong_tenant = client.delete(f"/v1/device-leases/{first.json()['lease_id']}?tenant_ref=tenant-b", headers=admin)
    assert wrong_tenant.status_code == 404
    assert client.delete(f"/v1/device-leases/{first.json()['lease_id']}?tenant_ref=tenant-a", headers=admin).status_code == 200
