"""DC-015-CLOSE-01 command recovery, idempotency scope and nonce bridge."""

from __future__ import annotations

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


def _write_approval(agent, stack, lease_id, *, task_ref="task-1", run_ref="run-1"):
    response = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease_id,
        "capability_id": "ui.tap", "capability_version": "1.0.0",
        "input": {"target_ref": "node-1"}, "intent": "tap the test control",
        "state_hash": "state-1", "state_version": "v1:state-1",
    }, headers=bearer(agent))
    assert response.status_code == 201, response.text
    return response.json()


def test_idempotency_key_is_scoped_to_task_and_run(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"],
                          task_ref="task-1", run_ref="run-1")
    body = command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="scope-key-1", capability_id="device.screenshot",
        input_payload={"redact": False}, task_ref="task-1", run_ref="run-1",
    )
    created = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert created.status_code == 201, created.text
    command_id = created.json()["command_id"]

    for task_ref, run_ref in (("task-2", "run-1"), ("task-1", "run-2")):
        reuse = {**body, "task_ref": task_ref, "run_ref": run_ref}
        response = client.post("/v1/commands", json=reuse, headers=bearer(agent))
        assert response.status_code == 409
        assert response.json()["code"] == "idempotency_scope_mismatch"

    lookup = client.get("/v1/commands/by-idempotency", params={
        "endpoint_id": stack["endpoint_id"], "capability_id": "device.screenshot",
        "idempotency_key": "scope-key-1", "task_ref": "task-1", "run_ref": "run-1",
    }, headers=bearer(agent))
    assert lookup.status_code == 200, lookup.text
    assert lookup.json()["command_id"] == command_id

    wrong = client.get("/v1/commands/by-idempotency", params={
        "endpoint_id": stack["endpoint_id"], "capability_id": "device.screenshot",
        "idempotency_key": "scope-key-1", "task_ref": "task-1", "run_ref": "run-2",
    }, headers=bearer(agent))
    assert wrong.status_code == 404
    other = bearer(issue_token("intruder", "tenant-b", roles=("platform_admin",)))
    assert client.get("/v1/commands/by-idempotency", params={
        "endpoint_id": stack["endpoint_id"], "capability_id": "device.screenshot",
        "idempotency_key": "scope-key-1", "task_ref": "task-1", "run_ref": "run-1",
    }, headers=other).status_code == 404


def test_approval_nonce_is_scoped_and_audited(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"],
                          task_ref="task-1", run_ref="run-1")
    approval = _write_approval(agent, stack, lease["lease_id"])

    pending = client.get(f"/v1/approvals/{approval['approval_id']}/nonce", params={
        "endpoint_id": stack["endpoint_id"], "capability_id": "ui.tap",
        "task_ref": "task-1", "run_ref": "run-1",
    }, headers=bearer(approver_token()))
    assert pending.status_code == 409
    assert pending.json()["code"] == "approval_not_available"

    assert client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                       json={"approved": True},
                       headers=bearer(approver_token())).status_code == 200
    params = {"endpoint_id": stack["endpoint_id"], "capability_id": "ui.tap",
              "task_ref": "task-1", "run_ref": "run-1"}
    fetched = client.get(f"/v1/approvals/{approval['approval_id']}/nonce",
                         params=params, headers=bearer(approver_token()))
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["approval_nonce"] == approval["approval_nonce"]
    assert fetched.json()["single_use"] is True

    wrong_run = client.get(f"/v1/approvals/{approval['approval_id']}/nonce", params={
        **params, "run_ref": "run-other",
    }, headers=bearer(approver_token()))
    assert wrong_run.status_code == 404
    wrong_cap = client.get(f"/v1/approvals/{approval['approval_id']}/nonce", params={
        **params, "capability_id": "light.turn_on",
    }, headers=bearer(approver_token()))
    assert wrong_cap.status_code == 409

    audits = store.list_audit("tenant-a", resource_id=approval["approval_id"])
    assert any(item["action"] == "approval.nonce_access" for item in audits)
    assert all(approval["approval_nonce"] not in str(item) for item in audits)
