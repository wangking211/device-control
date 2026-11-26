import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    admin_token,
    agent_token,
    approver_token,
    bearer,
    capability,
    command_body,
    configure,
    create_endpoint,
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


def _approval(client, agent, endpoint_id, lease_id, *, text="hello", state_hash="state-1"):
    response = client.post("/v1/approvals", json={
        "endpoint_id": endpoint_id, "lease_id": lease_id,
        "capability_id": "ui.send", "capability_version": "1.0.0",
        "input": {"text": text}, "intent": "Send a message",
        "action_type": "send", "state_hash": state_hash,
    }, headers=bearer(agent))
    assert response.status_code == 201, response.text
    return response.json()["approval_id"]


def test_forged_approver_identity_is_ignored_and_signature_is_verified(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=ASK_CAPABILITIES)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    approval_id = _approval(client, agent, stack["endpoint_id"], lease["lease_id"])

    forged = client.post(f"/v1/approvals/{approval_id}/decision", json={
        "approved": True, "approver_ref": "admin-1", "approver_type": "admin",
    }, headers=bearer(approver_token()))
    assert forged.status_code == 200
    record = store.get_approval("tenant-a", approval_id)
    assert record["approver_ref"] == "human-approver"
    assert record["approver_type"] == "user"

    tampered = issue_token("agent-1", "tenant-a", secret="wrong-secret-0123456789abcdef")
    assert client.get("/v1/endpoints", headers=bearer(tampered)).status_code == 401


def test_cross_tenant_access_is_hidden(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=ASK_CAPABILITIES)
    other = issue_token("intruder", "tenant-b", roles=("platform_admin",))
    assert client.get(f"/v1/endpoints/{stack['endpoint_id']}", headers=bearer(other)).status_code == 404
    assert client.get("/v1/endpoints", headers=bearer(other)).json()["items"] == []
    assert client.get("/v1/gateways", headers=bearer(other)).json()["items"] == []
    assert client.get("/v1/commands", headers=bearer(other)).json()["items"] == []
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    approval_id = _approval(client, agent, stack["endpoint_id"], lease["lease_id"])
    assert client.post(f"/v1/approvals/{approval_id}/decision", json={"approved": True},
                       headers=bearer(issue_token("other-approver", "tenant-b",
                                                  permissions=("device.approval.decide",)))
                       ).status_code == 404


def test_released_lease_blocks_approval_consumption(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=ASK_CAPABILITIES)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    approval_id = _approval(client, agent, stack["endpoint_id"], lease["lease_id"])
    assert client.post(f"/v1/approvals/{approval_id}/decision", json={"approved": True},
                       headers=bearer(approver_token())).status_code == 200
    assert client.delete(f"/v1/device-leases/{lease['lease_id']}",
                         headers=bearer(agent)).status_code == 200
    body = command_body(endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
                        idempotency_key="after-release", capability_id="ui.send",
                        input_payload={"text": "hello"}, state_hash="state-1",
                        approval_id=approval_id, intent="Send a message")
    assert client.post("/v1/commands", json=body, headers=bearer(agent)).status_code == 409
    assert store.get_approval("tenant-a", approval_id)["status"] == "invalidated"


def test_revoked_endpoint_invalidates_approval_and_queued_commands(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=ASK_CAPABILITIES)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    queued = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key="queued-1",
    ), headers=bearer(agent))
    assert queued.status_code == 201
    approval_id = _approval(client, agent, stack["endpoint_id"], lease["lease_id"])
    assert client.post(f"/v1/approvals/{approval_id}/decision", json={"approved": True},
                       headers=bearer(approver_token())).status_code == 200
    assert client.delete(f"/v1/endpoints/{stack['endpoint_id']}?tenant_ref=tenant-a",
                         headers=stack["platform"]).status_code == 200
    assert store.get_command("tenant-a", queued.json()["command_id"])["status"] == "cancelled"
    assert store.get_approval("tenant-a", approval_id)["status"] == "invalidated"


def test_approval_binds_parameters_version_and_state_hash(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=ASK_CAPABILITIES)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    approval_id = _approval(client, agent, stack["endpoint_id"], lease["lease_id"])
    assert client.post(f"/v1/approvals/{approval_id}/decision", json={"approved": True},
                       headers=bearer(approver_token())).status_code == 200

    tampered = command_body(endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
                            idempotency_key="tamper-1", capability_id="ui.send",
                            input_payload={"text": "different"}, state_hash="state-1",
                            approval_id=approval_id, intent="Send a message")
    response = client.post("/v1/commands", json=tampered, headers=bearer(agent))
    assert response.status_code == 409
    assert response.json()["code"] == "approval_binding_mismatch"

    changed_state = command_body(endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
                                 idempotency_key="tamper-2", capability_id="ui.send",
                                 input_payload={"text": "hello"}, state_hash="state-2",
                                 approval_id=approval_id, intent="Send a message")
    assert client.post("/v1/commands", json=changed_state,
                       headers=bearer(agent)).json()["code"] == "approval_binding_mismatch"


def test_concurrent_approval_consumption_succeeds_at_most_once(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=ASK_CAPABILITIES)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    approval_id = _approval(client, agent, stack["endpoint_id"], lease["lease_id"])
    assert client.post(f"/v1/approvals/{approval_id}/decision", json={"approved": True},
                       headers=bearer(approver_token())).status_code == 200

    def submit(key: str) -> int:
        thread_client = TestClient(app)
        body = command_body(endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
                            idempotency_key=key, capability_id="ui.send",
                            input_payload={"text": "hello"}, state_hash="state-1",
                            approval_id=approval_id, intent="Send a message")
        return thread_client.post("/v1/commands", json=body, headers=bearer(agent)).status_code

    barrier = threading.Barrier(2)

    def run(key: str) -> int:
        barrier.wait()
        return submit(key)

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(run, ["concurrent-1", "concurrent-2"]))
    assert statuses == [201, 409], statuses


def test_production_rejects_bootstrap_token(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path, production=True)
    response = client.post("/v1/endpoints", json={
        "endpoint_id": "phone-prod", "tenant_ref": "tenant-a", "protocol_version": "v1",
        "capabilities": [],
    }, headers={"Authorization": "Bearer test-bootstrap-token-0123456789"})
    assert response.status_code == 401
    platform = bearer(issue_token("admin-1", "tenant-a", roles=("platform_admin",)))
    assert client.post("/v1/endpoints", json={
        "endpoint_id": "phone-prod", "tenant_ref": "tenant-a", "protocol_version": "v1",
        "capabilities": [],
    }, headers=platform).status_code == 201


def test_missing_identity_provider_fails_closed(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path, production=True, admin_token=None)
    monkeypatch.delenv("MINDOS_IDENTITY_HMAC_KEY", raising=False)
    response = client.get("/v1/endpoints", headers={"Authorization": "Bearer arbitrary"})
    assert response.status_code == 503
    assert response.json()["code"] == "identity_provider_unavailable"
    ready = client.get("/health/ready")
    assert ready.status_code == 503


def test_secrets_are_absent_from_responses_and_logs(tmp_path, monkeypatch, caplog):
    configure(monkeypatch, tmp_path)
    caplog.set_level("DEBUG")
    created = client.post("/v1/endpoints", json={
        "endpoint_id": "phone-secret", "tenant_ref": "tenant-a", "protocol_version": "v1",
        "capabilities": [],
    }, headers=stack_headers())
    credential = created.json()["credential"]
    gateway = client.post("/v1/gateways", json={
        "gateway_id": "gw-secret", "tenant_ref": "tenant-a",
        "protocol_version": "v1", "adapter_inventory": [],
    }, headers=stack_headers())
    enrollment_token = gateway.json()["enrollment_token"]
    listed = client.get("/v1/endpoints?tenant_ref=tenant-a", headers=stack_headers()).text
    assert credential not in listed and "credential_hash" not in listed
    assert credential not in caplog.text
    assert enrollment_token not in caplog.text
    assert credential not in json.dumps(gateway.json())


def stack_headers() -> dict[str, str]:
    return bearer(admin_token())


def test_versioned_migration_preserves_legacy_records(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.sqlite3"
    db = sqlite3.connect(legacy)
    db.executescript("""
        CREATE TABLE device_endpoints (
            endpoint_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL, node_ref TEXT,
            credential_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('online','degraded','offline','revoked')),
            capabilities_json TEXT NOT NULL, observed_at TEXT NOT NULL);
        CREATE TABLE device_leases (
            lease_id TEXT PRIMARY KEY,
            endpoint_id TEXT NOT NULL REFERENCES device_endpoints(endpoint_id),
            tenant_ref TEXT NOT NULL, task_ref TEXT NOT NULL, run_ref TEXT,
            holder_ref TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('read_only','control')),
            expires_at TEXT NOT NULL, released_at TEXT);
        CREATE TABLE device_approvals (
            approval_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL, endpoint_id TEXT NOT NULL,
            lease_id TEXT NOT NULL, requester_ref TEXT NOT NULL, action_digest TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','consumed','expired')),
            approver_ref TEXT, expires_at TEXT NOT NULL, decided_at TEXT);
        INSERT INTO device_endpoints VALUES
            ('legacy-phone','tenant-a','node-1','deadbeef','online','[]','2026-01-01T00:00:00+00:00');
        INSERT INTO device_leases VALUES
            ('legacy-lease','legacy-phone','tenant-a','task-1',NULL,'agent-1','control',
             '2099-01-01T00:00:00+00:00',NULL);
        INSERT INTO device_approvals VALUES
            ('legacy-approval','tenant-a','legacy-phone','legacy-lease','agent-1','digest-1',
             'approved','human-1','2099-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00');
    """)
    db.commit()
    db.close()

    monkeypatch.setenv("DEVICE_CONTROL_DB", str(legacy))
    monkeypatch.setenv("DEVICE_CONTROL_ENV", "test")
    apples = store.initialize()
    assert 1 in apples and 4 in apples, apples
    endpoint = store.get_endpoint("tenant-a", "legacy-phone")
    assert endpoint["status"] == "online"
    assert store.active_lease("tenant-a", "legacy-lease", "legacy-phone")["holder_ref"] == "agent-1"
    approval = store.get_approval("tenant-a", "legacy-approval")
    assert approval["status"] == "approved"
    assert approval["approver_ref"] == "human-1"


def test_payload_limit_rejects_oversize_body(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("DEVICE_CONTROL_MAX_REQUEST_BYTES", "4096")
    response = client.post("/v1/contracts/invocation/validate",
                           json={"padding": "x" * 9000})
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"


def test_expired_token_and_issuer_mismatch_rejected(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    assert client.get("/v1/endpoints", headers=bearer(
        issue_token("user-1", "tenant-a", expired=True))).status_code == 401
    assert client.get("/v1/endpoints", headers=bearer(
        issue_token("user-1", "tenant-a", issuer="other-issuer"))).status_code == 401


def test_service_token_shape_and_audience_are_verified(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("DEVICE_CONTROL_IDENTITY_AUDIENCE", "device-control")
    stack = setup_stack(client)
    create_endpoint(client, stack["platform"], tenant="tenant-a", endpoint_id="phone-2")
    extra = {
        "contract_version": "1.0",
        "actor": {"actor_type": "service", "service_id": "mindos"},
        "tenant_id": "tenant-a",
        "capability": "device.endpoint.read",
        "resource": {"type": "device_endpoint", "id": stack["endpoint_id"]},
        "delegation_id": "delegation-1",
        "correlation_id": "corr-1",
    }
    token = issue_token("mindos", "tenant-a", extra=extra, audience="device-control")
    assert client.get("/v1/endpoints", headers=bearer(token)).status_code == 200
    assert client.get(f"/v1/endpoints/{stack['endpoint_id']}",
                      headers=bearer(token)).status_code == 200
    assert client.get("/v1/endpoints/phone-2", headers=bearer(token)).status_code == 403
    wrong_audience = issue_token("mindos", "tenant-a", extra=extra, audience="another-service")
    assert client.get("/v1/endpoints", headers=bearer(wrong_audience)).status_code == 401
    impersonating = issue_token("mindos", "tenant-a", extra={
        **extra, "actor": {"actor_type": "service", "service_id": "other"},
    }, audience="device-control")
    assert client.get("/v1/endpoints", headers=bearer(impersonating)).status_code == 401
