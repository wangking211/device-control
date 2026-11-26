from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    agent_token,
    approver_token,
    bearer,
    command_body,
    configure,
    setup_stack,
)

from device_control import contracts
from device_control.app import app

client = TestClient(app)


def test_health_and_contract_catalog():
    assert client.get("/health/live").json() == {"status": "live"}
    assert client.get("/health/ready").status_code == 200
    assert len(client.get("/v1/contracts").json()["contracts"]) == len(contracts.SCHEMAS)


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
        "idempotency_key": "idem-1", "input": {}, "intent": "Observe current screen",
    }
    assert client.post("/v1/contracts/invocation/validate", json=payload).json()["valid"] is True


def test_endpoint_enrollment_heartbeat_list_and_revoke(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    admin = {"Authorization": "Bearer test-bootstrap-token-0123456789"}
    payload = {
        "endpoint_id": "phone-1", "tenant_ref": "tenant-a", "node_ref": "node-1",
        "protocol_version": "v1", "capabilities": []
    }
    assert client.post("/v1/endpoints", json=payload).status_code == 401
    created = client.post("/v1/endpoints", json=payload, headers=admin)
    assert created.status_code == 201
    credential = created.json()["credential"]
    assert credential
    listed = client.get("/v1/endpoints?tenant_ref=tenant-a", headers=admin)
    assert listed.status_code == 200
    assert credential not in listed.text
    assert "credential_hash" not in listed.text

    heartbeat = client.post("/v1/endpoints/phone-1/heartbeat", json={"status": "online", "capabilities": []},
                            headers={"Authorization": f"Bearer {credential}"})
    assert heartbeat.status_code == 200
    assert client.get("/v1/endpoints?tenant_ref=tenant-a", headers=admin).json()["items"][0]["status"] == "online"
    assert client.delete("/v1/endpoints/phone-1?tenant_ref=tenant-a", headers=admin).json()["status"] == "revoked"
    assert client.post("/v1/endpoints/phone-1/heartbeat", json={"status": "online", "capabilities": []},
                       headers={"Authorization": f"Bearer {credential}"}).status_code == 401


def test_device_lease_is_exclusive_tenant_scoped_and_releasable(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    token = agent_token()
    first = acquire_lease(client, token, endpoint_id=stack["endpoint_id"])
    conflict = client.post("/v1/device-leases", json={
        "endpoint_id": stack["endpoint_id"], "task_ref": "task-2", "mode": "read_only",
        "ttl_seconds": 60,
    }, headers=bearer(agent_token(subject="agent-2")))
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["holder_ref"] == "agent-1"
    wrong_tenant = client.delete(
        f"/v1/device-leases/{first['lease_id']}?tenant_ref=tenant-b", headers=bearer(token)
    )
    assert wrong_tenant.status_code == 403
    assert client.delete(f"/v1/device-leases/{first['lease_id']}", headers=bearer(token)).status_code == 200


def test_policy_requires_active_lease_and_applies_safe_defaults(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    token = agent_token()
    lease = acquire_lease(client, token, endpoint_id=stack["endpoint_id"], mode="read_only")
    body = {"endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
            "action_type": "tap", "intent": "Tap continue"}
    assert client.post("/v1/policy/evaluate", json={**body, "lease_id": "invalid"},
                       headers=bearer(token)).status_code == 403
    assert client.post("/v1/policy/evaluate", json=body, headers=bearer(token)).json()["decision"] == "deny"
    body["action_type"] = "observe"
    assert client.post("/v1/policy/evaluate", json=body, headers=bearer(token)).json()["decision"] == "allow"
    body.update(action_type="send", app_id="mail", target_type="text")
    assert client.post("/v1/policy/evaluate", json=body, headers=bearer(token)).json()["decision"] == "deny"
    body.update(action_type="observe", app_id="banking-app", target_type="text")
    assert client.post("/v1/policy/evaluate", json=body, headers=bearer(token)).json()["reason"] == "sensitive_app_blocked"


def test_approval_is_bound_to_exact_action_and_single_use(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    request = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
        "capability_id": "ui.type_text", "capability_version": "1.0.0",
        "input": {"target_ref": "field-search", "text": "hello"},
        "intent": "Type into search", "state_hash": "state-1",
        "state_version": "v1:state-1",
    }, headers=bearer(agent))
    assert request.status_code == 201, request.text
    approval_id = request.json()["approval_id"]
    approval_nonce = request.json()["approval_nonce"]
    request2 = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
        "capability_id": "ui.type_text", "capability_version": "1.0.0",
        "input": {"target_ref": "field-search", "text": "again"},
        "intent": "Type into search", "state_hash": "state-1",
        "state_version": "v1:state-1",
    }, headers=bearer(agent))
    assert request2.status_code == 201
    assert client.post(f"/v1/approvals/{request2.json()['approval_id']}/decision",
                       json={"approved": True}, headers=bearer(agent)).status_code == 403
    decided = client.post(f"/v1/approvals/{approval_id}/decision",
                          json={"approved": True, "approver_ref": "forged-human"},
                          headers=bearer(approver_token()))
    assert decided.status_code == 200, decided.text

    body = command_body(endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
                        idempotency_key="send-1", capability_id="ui.type_text",
                        input_payload={"target_ref": "field-search", "text": "hello"},
                        state_hash="state-1", state_version="v1:state-1",
                        approval_id=approval_id, approval_nonce=approval_nonce,
                        intent="Type into search")
    submitted = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert submitted.status_code == 201, submitted.text
    command_id = submitted.json()["command_id"]
    duplicate = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert duplicate.status_code == 201
    assert duplicate.json()["command_id"] == command_id
    assert duplicate.json()["deduplicated"] is True
    other = {**body, "idempotency_key": "send-2"}
    assert client.post("/v1/commands", json=other, headers=bearer(agent)).status_code == 409
