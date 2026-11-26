from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    admin_token,
    agent_token,
    bearer,
    capability,
    command_body,
    configure,
    issue_token,
    setup_stack,
)

from device_control import store
from device_control.app import app

client = TestClient(app)

ASK_CAPABILITIES = [
    capability("app.launch", risk_tier="read"),
    capability("ui.send", risk_tier="write",
               input_schema={"type": "object", "required": ["text"],
                             "properties": {"text": {"type": "string"}},
                             "additionalProperties": True}),
]


def _verification(method: str = "ui_state") -> dict:
    return {
        "method": method,
        "verified": True,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "quality": "high",
        **({"adapter_guarantee": True} if method == "adapter_ack" else {}),
    }


def _submit_and_pull(stack, agent, lease, *, key="cmd-1", capability_id="app.launch",
                     input_payload=None, run_ref="run-1"):
    submitted = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key=key,
        capability_id=capability_id, input_payload=input_payload, run_ref=run_ref,
    ), headers=bearer(agent))
    assert submitted.status_code == 201, submitted.text
    command_id = submitted.json()["command_id"]
    pulled = client.get(f"/v1/gateways/{stack['gateway_id']}/commands",
                        headers=bearer(stack["gateway_credential"]))
    assert pulled.status_code == 200
    assert [item["command_id"] for item in pulled.json()["items"]] == [command_id]
    return command_id


def test_full_command_state_machine_is_audited(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], run_ref="run-9")
    command_id = _submit_and_pull(stack, agent, lease, run_ref="run-9")

    gateway = bearer(stack["gateway_credential"])
    assert client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/progress",
                       json={"status": "accepted"}, headers=gateway).status_code == 200
    assert store.get_command("tenant-a", command_id)["status"] == "accepted"
    assert client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/progress",
                       json={"status": "executing"}, headers=gateway).status_code == 200
    result = client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/result",
                         json={"status": "succeeded", "output": {"foreground_app": "com.example.notes"},
                               "verification": _verification(),
                               "evidence_refs": ["sha256:abc"]}, headers=gateway)
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "succeeded"

    detail = client.get(f"/v1/commands/{command_id}?include=transitions", headers=bearer(agent))
    assert detail.status_code == 200
    assert detail.json()["task_ref"] == "task-1"
    assert detail.json()["run_ref"] == "run-9"
    statuses = [item["to_status"] for item in detail.json()["transitions"]]
    for expected in ("created", "validated", "authorized", "queued", "dispatched",
                     "received", "accepted", "executing", "verifying", "succeeded"):
        assert expected in statuses, statuses

    evidence = client.get(f"/v1/commands/{command_id}/evidence", headers=bearer(agent))
    assert evidence.status_code == 200
    assert evidence.json()["evidence_refs"] == ["sha256:abc"]
    assert evidence.json()["retention"] == "evidence_store_managed"

    events = client.get("/v1/events", headers=bearer(agent)).json()["items"]
    assert any(event["event_type"] == "command.succeeded" and event["run_ref"] == "run-9"
               for event in events)
    assert all(event["event_version"] == "1" for event in events)

    metrics = client.get("/v1/metrics", headers=bearer(admin_token())).json()["counters"]
    assert metrics["command_submitted_total"] >= 1
    assert metrics["commands_dispatched_total"] >= 1
    assert metrics["command_result_succeeded_total"] >= 1


def test_idempotency_same_payload_returns_existing_and_conflict_is_409(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    body = command_body(endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
                        idempotency_key="idem-a")
    first = client.post("/v1/commands", json=body, headers=bearer(agent))
    second = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["command_id"] == second.json()["command_id"]
    assert second.json()["deduplicated"] is True

    conflict = client.post("/v1/commands", json={
        **body, "input": {"app_id": "com.example.other"},
    }, headers=bearer(agent))
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "idempotency_conflict"


def test_succeeded_requires_verification(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _submit_and_pull(stack, agent, lease)
    gateway = bearer(stack["gateway_credential"])
    result = client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/result",
                         json={"status": "succeeded", "output": {}}, headers=gateway)
    assert result.status_code == 200
    assert result.json()["status"] == "uncertain"
    assert store.get_command("tenant-a", command_id)["status_reason"] == "verification_insufficient"


def test_adapter_ack_without_guarantee_is_not_success(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _submit_and_pull(stack, agent, lease)
    gateway = bearer(stack["gateway_credential"])
    verification = {"method": "adapter_ack", "verified": True,
                    "observed_at": datetime.now(timezone.utc).isoformat()}
    result = client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/result",
                         json={"status": "succeeded", "verification": verification},
                         headers=gateway)
    assert result.json()["status"] == "uncertain"


def test_cancel_before_dispatch_and_refusal_after(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    queued = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="cancel-1",
    ), headers=bearer(agent)).json()
    assert client.post(f"/v1/commands/{queued['command_id']}/cancel",
                       headers=bearer(agent)).json()["status"] == "cancelled"

    dispatched_id = _submit_and_pull(stack, agent, lease, key="cancel-2")
    refused = client.post(f"/v1/commands/{dispatched_id}/cancel", headers=bearer(agent))
    assert refused.status_code == 409
    assert refused.json()["code"] == "cancel_not_guaranteed"


def test_timeout_and_late_result_are_reconciled_without_reopening(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _submit_and_pull(stack, agent, lease)
    db = store.connect()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    db.execute("UPDATE device_commands SET deadline=? WHERE command_id=?", (past, command_id))
    db.close()
    summary = store.maintenance()
    assert summary["commands_timed_out"] >= 1
    assert store.get_command("tenant-a", command_id)["status"] == "timed_out"

    late = client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/result",
                       json={"status": "succeeded", "verification": _verification()},
                       headers=bearer(stack["gateway_credential"]))
    assert late.status_code == 200
    assert late.json()["late_result_retained"] is True
    assert store.get_command("tenant-a", command_id)["status"] == "timed_out"
    audit = store.list_audit("tenant-a", resource_id=command_id)
    assert any(record["action"] == "command.late_result" for record in audit)


def test_submission_negative_paths(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])

    missing_approval = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="neg-1",
        capability_id="ui.type_text",
        input_payload={"target_ref": "field-search", "text": "hello"},
        state_hash="state-1", state_version="v1:state-1",
    ), headers=bearer(agent))
    assert missing_approval.status_code == 409
    assert missing_approval.json()["code"] == "approval_required"

    wrong_tenant = issue_token("intruder", "tenant-b", roles=("platform_admin",))
    assert client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="neg-2",
    ), headers=bearer(wrong_tenant)).status_code == 404

    db = store.connect()
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    db.execute("UPDATE device_leases SET expires_at=? WHERE lease_id=?",
               (past, lease["lease_id"]))
    db.close()
    expired = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="neg-3",
    ), headers=bearer(agent))
    assert expired.status_code == 409
    assert expired.json()["code"] == "active_device_lease_required"


def test_offline_endpoint_blocks_command(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    endpoint_credential = client.post(
        f"/v1/endpoints/{stack['endpoint_id']}/credentials/rotate",
        headers=stack["platform"]).json()["credential"]
    assert client.post(f"/v1/endpoints/{stack['endpoint_id']}/heartbeat", json={
        "status": "offline", "capabilities": [capability()],
    }, headers=bearer(endpoint_credential)).status_code == 200
    response = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="offline-1",
    ), headers=bearer(agent))
    assert response.status_code == 409
    assert response.json()["code"] == "endpoint_unavailable"


def test_gateway_pull_expires_overdue_commands(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    queued = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="overdue-1",
    ), headers=bearer(agent)).json()
    db = store.connect()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    db.execute("UPDATE device_commands SET deadline=? WHERE command_id=?",
               (past, queued["command_id"]))
    db.close()
    pulled = client.get(f"/v1/gateways/{stack['gateway_id']}/commands",
                        headers=bearer(stack["gateway_credential"]))
    assert pulled.status_code == 200
    assert pulled.json()["items"] == []
    assert store.get_command("tenant-a", queued["command_id"])["status"] == "expired"


def test_state_dependent_capability_requires_hash_and_version(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    response = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="state-missing", capability_id="ui.tap",
        input_payload={"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
    ), headers=bearer(agent))
    assert response.status_code == 422
    assert response.json()["code"] == "state_hash_and_version_required"


def test_executed_unverified_is_not_success(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _submit_and_pull(stack, agent, lease, key="unverified-1")
    result = client.post(f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/result",
                         json={"status": "executed_unverified", "executed": True,
                               "reason": "tap produced no observable change"},
                         headers=bearer(stack["gateway_credential"]))
    assert result.status_code == 200, result.text
    command = store.get_command("tenant-a", command_id)
    assert command["status"] == "uncertain"
    assert command["status_reason"] == "tap produced no observable change"
