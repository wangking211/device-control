"""Read/Write lease acceptance matrix (DC-014-CLOSE task 01)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    agent_token,
    approver_token,
    bearer,
    command_body,
    configure,
    issue_token,
    setup_stack,
)

from device_control import store
from device_control.app import app

client = TestClient(app)


def submit(stack, lease_id, *, capability="app.launch", input_payload=None,
           approval_id=None, approval_nonce=None, key="lease-matrix-1",
           state_hash=None, state_version=None, token=None,
           intent="Open the notes app"):
    body = command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease_id,
        idempotency_key=key, capability_id=capability,
        input_payload=input_payload or {"app_id": "com.example.notes"},
        approval_id=approval_id, approval_nonce=approval_nonce,
        state_hash=state_hash, state_version=state_version, intent=intent,
    )
    return client.post("/v1/commands", json=body, headers=bearer(token or agent_token()))


def approve(agent, stack, lease_id, *, capability="ui.tap",
            input_payload=None, state_hash="state-1", state_version="v1:state-1"):
    request = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease_id,
        "capability_id": capability, "capability_version": "1.0.0",
        "input": input_payload or {"target_ref": "node-1"},
        "intent": "tap the test control", "state_hash": state_hash,
        "state_version": state_version,
    }, headers=bearer(agent))
    assert request.status_code == 201, request.text
    approval = request.json()
    decided = client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                          json={"approved": True}, headers=bearer(approver_token()))
    assert decided.status_code == 200, decided.text
    return approval


def test_read_lease_and_read_capability_allow(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="read_only")
    response = submit(stack, lease["lease_id"], capability="device.screenshot",
                      input_payload={"redact": False}, key="read-1", token=agent)
    assert response.status_code == 201, response.text


def test_missing_lease_is_rejected(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    response = submit(stack, "lease_missing", capability="device.screenshot",
                      input_payload={"redact": False}, key="read-nolease")
    assert response.status_code == 409
    assert response.json()["code"] == "active_device_lease_required"


def test_expired_lease_is_rejected(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="read_only")
    db = store.connect()
    db.execute("UPDATE device_leases SET expires_at=? WHERE lease_id=?",
               ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                lease["lease_id"]))
    db.commit()
    db.close()
    response = submit(stack, lease["lease_id"], capability="device.screenshot",
                      input_payload={"redact": False}, key="read-expired", token=agent)
    assert response.status_code == 409
    assert response.json()["code"] == "active_device_lease_required"


def test_cross_tenant_lease_is_rejected(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="read_only")
    other = issue_token("agent-b", "tenant-b", permissions=(
        "device.command.submit", "device.lease.acquire", "device.command.read",
    ))
    response = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="cross-tenant-lease", capability_id="device.screenshot",
        input_payload={"redact": False},
    ), headers=bearer(other))
    assert response.status_code == 404


def test_read_lease_cannot_execute_write_capability(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="read_only")
    response = submit(
        stack, lease["lease_id"], capability="ui.tap",
        input_payload={"target_ref": "node-1"}, key="read-write-1",
        state_hash="state-1", state_version="v1:state-1", token=agent,
    )
    assert response.status_code == 403
    assert response.json()["code"] == "policy_denied"
    assert response.json()["detail"]["reason"] == "read_only_lease"


def test_write_lease_without_approval_or_with_bad_nonce_is_rejected(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="control")
    missing = submit(
        stack, lease["lease_id"], capability="ui.tap",
        input_payload={"target_ref": "node-1"}, key="write-noapproval",
        state_hash="state-1", state_version="v1:state-1", token=agent,
    )
    assert missing.status_code == 409
    assert missing.json()["code"] == "approval_required"

    approval = approve(agent, stack, lease["lease_id"])
    bad = submit(
        stack, lease["lease_id"], capability="ui.tap",
        input_payload={"target_ref": "node-1"}, key="write-badnonce",
        state_hash="state-1", state_version="v1:state-1",
        approval_id=approval["approval_id"], approval_nonce="not-the-nonce",
        token=agent,
    )
    assert bad.status_code == 409
    assert bad.json()["code"] == "approval_binding_mismatch"


def test_valid_write_lease_approval_and_nonce_allow(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="control")
    approval = approve(agent, stack, lease["lease_id"])
    response = submit(
        stack, lease["lease_id"], capability="ui.tap",
        input_payload={"target_ref": "node-1"}, key="write-approved",
        state_hash="state-1", state_version="v1:state-1",
        approval_id=approval["approval_id"], approval_nonce=approval["approval_nonce"],
        token=agent, intent="tap the test control",
    )
    assert response.status_code == 201, response.text
    assert response.json()["policy_decision"] == "ask"


def test_lease_can_be_read_and_is_tenant_scoped(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"],
                          mode="read_only")
    fetched = client.get(f"/v1/device-leases/{lease['lease_id']}",
                         headers=bearer(agent))
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["mode"] == "read_only"
    assert fetched.json()["active"] is True
    other = bearer(issue_token("intruder", "tenant-b", roles=("platform_admin",)))
    assert client.get(f"/v1/device-leases/{lease['lease_id']}",
                      headers=other).status_code == 404


def test_lease_release_is_audited(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="read_only")
    released = client.delete(f"/v1/device-leases/{lease['lease_id']}",
                             headers=bearer(agent))
    assert released.status_code == 200
    audits = store.list_audit("tenant-a", resource_id=lease["lease_id"])
    assert any(item["action"] == "lease.release" for item in audits)
