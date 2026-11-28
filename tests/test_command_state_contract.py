"""Cross-repo device command status contract tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from support import acquire_lease, agent_token, bearer, command_body, configure, setup_stack

from device_control import contracts, status_projection
from device_control.app import app

client = TestClient(app)

MAPPING = {
    "created": "queued",
    "validated": "queued",
    "authorized": "queued",
    "queued": "queued",
    "waiting_approval": "waiting_approval",
    "approval_required": "waiting_approval",
    "dispatched": "running",
    "received": "running",
    "accepted": "running",
    "executing": "running",
    "verifying": "running",
    "executed_unverified": "verifying",
    "succeeded": "succeeded",
    "rejected": "failed",
    "failed": "failed",
    "timed_out": "failed",
    "uncertain": "unknown",
    "cancelled": "cancelled",
    "expired": "expired",
}


@pytest.mark.parametrize(("raw", "canonical"), MAPPING.items())
def test_canonical_mapping(raw, canonical):
    assert status_projection.canonical_status(raw) == canonical


@pytest.mark.parametrize("raw", ["", "not-a-status", None, 42, {"status": "succeeded"}])
def test_unknown_status_projects_to_unknown(raw):
    assert status_projection.canonical_status(raw) == "unknown"


def test_executed_unverified_never_becomes_succeeded():
    command = {"status": "uncertain", "provider_status": "executed_unverified",
               "command_id": "cmd-1", "tenant_ref": "tenant-a"}
    projected = status_projection.project(command)
    assert projected["canonical_status"] == "verifying"
    assert projected["provider_status"] == "executed_unverified"


def test_verified_success_preserves_raw_but_requires_authoritative_success():
    verified = status_projection.project(
        {"status": "succeeded", "provider_status": "succeeded", "command_id": "cmd-1"}
    )
    assert verified["canonical_status"] == "succeeded"
    unverified = status_projection.project(
        {"status": "rejected", "provider_status": "succeeded", "command_id": "cmd-1"}
    )
    assert unverified["canonical_status"] == "failed"
    assert unverified["provider_status"] == "succeeded"


def test_projection_contract_schema_is_valid():
    projected = status_projection.project({
        "status": "succeeded", "provider_status": "succeeded", "command_id": "cmd-1",
        "tenant_ref": "tenant-a", "device_id": "device-1", "endpoint_id": "ep-1",
        "task_ref": "task-1", "run_ref": "run-1", "correlation_id": "corr-1",
        "idempotency_key": "idem-1", "status_reason": "verified",
        "verification": {"method": "read_after_write", "verified": True},
        "evidence_refs": ["evd_1"], "created_at": "2026-11-28T00:00:00+00:00",
        "updated_at": "2026-11-28T00:00:00+00:00",
        "completed_at": "2026-11-28T00:00:01+00:00",
    })
    assert contracts.validate_contract("command_state", projected) == []


def test_command_api_exposes_canonical_and_raw_status(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    submitted = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="canonical-api-1",
    ), headers=bearer(agent))
    assert submitted.status_code == 201, submitted.text
    body = submitted.json()
    assert body["provider_status"] == "queued"
    assert body["canonical_status"] == "queued"
    command_id = body["command_id"]

    pulled = client.get(f"/v1/gateways/{stack['gateway_id']}/commands",
                        headers=bearer(stack["gateway_credential"]))
    envelope = pulled.json()["items"][0]
    assert envelope["provider_status"] == "dispatched"
    assert envelope["canonical_status"] == "running"

    headers = {"Authorization": f"Bearer {stack['gateway_credential']}"}
    for progress in ("received", "accepted", "executing"):
        assert client.post(
            f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/progress",
            json={"status": progress}, headers=headers,
        ).status_code == 200

    result = client.post(
        f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/result",
        json={"status": "executed_unverified", "reason": "no_read_back"},
        headers=headers,
    )
    assert result.status_code == 200, result.text
    assert result.json()["canonical_status"] == "verifying"

    detail = client.get(f"/v1/commands/{command_id}?tenant_ref=tenant-a",
                        headers=bearer(agent))
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["provider_status"] == "executed_unverified"
    assert payload["canonical_status"] == "verifying"
    assert payload["status_contract_version"] == "dc-command-state/v1"
