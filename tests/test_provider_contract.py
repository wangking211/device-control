"""Provider/API conformance (DC-014-CLOSE task 04).

The fixture mirrors the body MindOS `DeviceControlProvider.submit` builds.
It must validate against the canonical command schema and the live API.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
FIXTURE = Path(__file__).resolve().parents[1] / "contracts/fixtures/provider-submit.json"


def test_provider_submit_fixture_matches_command_schema():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert contracts.validate_contract("command", payload) == []


def test_provider_payload_round_trip_and_response_fields(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="control")
    request = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
        "capability_id": "ui.tap", "capability_version": "1.0.0",
        "input": {"target_ref": "node-1"}, "intent": "tap the test control",
        "state_hash": "state-1", "state_version": "v1:state-1",
    }, headers=bearer(agent))
    assert request.status_code == 201, request.text
    approval = request.json()
    assert client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                       json={"approved": True},
                       headers=bearer(approver_token())).status_code == 200

    body = json.loads(FIXTURE.read_text(encoding="utf-8"))
    body.update({
        "endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
        "approval_id": approval["approval_id"],
        "approval_nonce": approval["approval_nonce"],
        "idempotency_key": "provider-round-trip-1",
        "deadline": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    })
    submitted = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert submitted.status_code == 201, submitted.text
    command_id = submitted.json()["command_id"]

    detail = client.get(f"/v1/commands/{command_id}", headers=bearer(agent)).json()
    for field in ("command_id", "tenant_ref", "endpoint_id", "correlation_id",
                  "status", "provider_status", "canonical_status", "status_reason",
                  "verification", "evidence_refs"):
        assert field in detail, field
    assert detail["canonical_status"] == "queued"

    evidence = client.get(f"/v1/commands/{command_id}/evidence",
                          headers=bearer(agent)).json()
    assert {"command_id", "status", "evidence_refs", "verification", "items"} <= set(evidence)

    # Cancelling after dispatch is not guaranteed and must not claim rollback.
    headers = {"Authorization": f"Bearer {stack['gateway_credential']}"}
    client.get(f"/v1/gateways/{stack['gateway_id']}/commands", headers=headers)
    cancelled = client.post(f"/v1/commands/{command_id}/cancel", json={"reason": "user"},
                            headers=bearer(agent))
    assert cancelled.status_code == 409
    assert cancelled.json()["code"] == "cancel_not_guaranteed"


def test_stable_error_codes_for_provider_failures(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    body = command_body(
        endpoint_id=stack["endpoint_id"], lease_id="missing-lease",
        idempotency_key="provider-error-1", capability_id="ui.tap",
        input_payload={"target_ref": "node-1"},
        state_hash="state-1", state_version="v1:state-1",
        intent="tap the test control",
    )
    response = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert response.status_code == 409
    assert response.json()["code"] == "active_device_lease_required"

    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"], mode="control")
    body["lease_id"] = lease["lease_id"]
    response = client.post("/v1/commands", json=body, headers=bearer(agent))
    assert response.status_code == 409
    assert response.json()["code"] == "approval_required"
