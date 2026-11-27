from datetime import datetime, timedelta, timezone

from device_gateway import manifest as manifest_rules
from device_gateway.adapters.fake import FakeAndroidAdapter
from device_gateway.control_client import ControlPlaneClient
from device_gateway.ledger import DedupeLedger
from device_gateway.queue import BoundedQueue
from device_gateway.worker import GatewayWorker, WorkerConfig
from fastapi.testclient import TestClient
from support import (
    MANIFEST,
    REDACTION_KEY,
    REDACTION_KEY_ID,
    acquire_lease,
    agent_token,
    approver_token,
    bearer,
    command_body,
    configure,
    setup_stack,
)

from device_control import store
from device_control.app import app

client = TestClient(app)
DIGEST = manifest_rules.digest(MANIFEST)
STATE_HASH = "state-hash"
STATE_VERSION = "v1:state-hash"


class InProcessTransport:
    def __init__(self, test_client: TestClient) -> None:
        self.test_client = test_client

    def request(self, method, url, body, headers, raw=None):
        path = url.split("://", 1)[-1]
        path = "/" + path.split("/", 1)[1]
        if raw is not None:
            response = self.test_client.request(method, path, content=raw, headers=headers)
        else:
            response = self.test_client.request(method, path, json=body, headers=headers)
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        return response.status_code, payload


def endpoint_capabilities():
    allowed = {"id", "version", "input_schema", "output_schema", "risk_tier",
               "execution_locality", "permissions", "supports_idempotency", "max_timeout_ms"}
    return [
        {
            **{key: value for key, value in item.items() if key in allowed},
            "execution_locality": "device",
        }
        for item in MANIFEST["capabilities"]
    ]


def build_worker(tmp_path, stack, adapter=None):
    adapter = adapter or FakeAndroidAdapter(
        allowed_apps={"com.example.notes"},
        device_fingerprint=stack["device_fingerprint"],
        redaction_key=REDACTION_KEY,
        redaction_key_id=REDACTION_KEY_ID,
    )
    ledger = DedupeLedger(tmp_path / "gateway-ledger.sqlite3")
    control = ControlPlaneClient(
        base_url="http://testserver",
        gateway_id=stack["gateway_id"],
        credential=stack["gateway_credential"],
        transport=InProcessTransport(client),
    )
    worker = GatewayWorker(
        client=control,
        adapter=adapter,
        ledger=ledger,
        queue=BoundedQueue(4),
        tenant_ref="",
        endpoint_id=stack["endpoint_id"],
        device_id=stack["device_id"],
        device_fingerprint=stack["device_fingerprint"],
        manifest_document=MANIFEST,
        config=WorkerConfig(heartbeat_interval_seconds=0, poll_interval_seconds=0, batch_size=5),
    )
    return worker, adapter, ledger


def submit(stack, agent, lease, *, key, capability_id="app.launch", input_payload=None,
           state_hash=None, state_version=None, approval_id=None, approval_nonce=None,
           intent="Open the notes app"):
    response = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key=key, capability_id=capability_id,
        input_payload=input_payload, state_hash=state_hash, state_version=state_version,
        approval_id=approval_id, approval_nonce=approval_nonce, intent=intent,
    ), headers=bearer(agent))
    assert response.status_code == 201, response.text
    return response.json()["command_id"]


def approve_tap(stack, agent, lease, state):
    request = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
        "capability_id": "ui.tap", "capability_version": "1.0.0",
        "input": {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "intent": "Tap continue", "state_hash": state["state_hash"],
        "state_version": state["state_version"],
    }, headers=bearer(agent))
    assert request.status_code == 201, request.text
    approval = request.json()
    decided = client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                          json={"approved": True}, headers=bearer(approver_token()))
    assert decided.status_code == 200, decided.text
    return approval


def test_end_to_end_fake_android_loop(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = submit(stack, agent, lease, key="e2e-1")
    worker, adapter, ledger = build_worker(tmp_path, stack)

    summary = worker.run_once()
    assert summary["executed"] == 1
    assert worker.tenant_ref == "tenant-a"
    command = store.get_command("tenant-a", command_id)
    assert command["status"] == "succeeded", command
    assert command["verification"]["method"] == "ui_state"
    assert command["manifest_digest"] == DIGEST
    assert adapter.state["foreground_app"] == "com.example.notes"
    assert ledger.is_terminal(command_id)
    ledger.close()


def test_tap_requires_approval_and_verifies_change(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"},
                                 device_fingerprint=stack["device_fingerprint"])
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)
    state = adapter.observe_state()
    approval = approve_tap(stack, agent, lease, state)
    command_id = submit(
        stack, agent, lease, key="tap-1", capability_id="ui.tap",
        input_payload={"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        state_hash=state["state_hash"], state_version=state["state_version"],
        approval_id=approval["approval_id"], approval_nonce=approval["approval_nonce"],
        intent="Tap continue",
    )
    worker.run_once()
    command = store.get_command("tenant-a", command_id)
    assert command["status"] in {"succeeded", "uncertain"}, command
    assert any(call[0] == "ui.tap" for call in adapter.calls)
    ledger.close()


def test_typed_text_is_not_echoed_in_result_or_evidence(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"},
                                 device_fingerprint=stack["device_fingerprint"])
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)
    state = adapter.observe_state()
    request = client.post("/v1/approvals", json={
        "endpoint_id": stack["endpoint_id"], "lease_id": lease["lease_id"],
        "capability_id": "ui.type_text", "capability_version": "1.0.0",
        "input": {"target_ref": "field-search", "text": "sensitive-value"},
        "intent": "Type a value", "state_hash": state["state_hash"],
        "state_version": state["state_version"],
    }, headers=bearer(agent))
    assert request.status_code == 201, request.text
    approval = request.json()
    assert client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                       json={"approved": True}, headers=bearer(approver_token())).status_code == 200
    command_id = submit(
        stack, agent, lease, key="text-1", capability_id="ui.type_text",
        input_payload={"target_ref": "field-search", "text": "sensitive-value"},
        state_hash=state["state_hash"], state_version=state["state_version"],
        approval_id=approval["approval_id"], approval_nonce=approval["approval_nonce"],
        intent="Type a value",
    )
    worker.run_once()
    command = store.get_command("tenant-a", command_id)
    assert "sensitive-value" not in str(command["result"])
    assert "sensitive-value" not in str(command["verification"])
    assert "sensitive-value" not in str(command["evidence_refs"])
    assert "sensitive-value" not in str(store.list_audit("tenant-a", resource_id=command_id))
    events = store.list_events("tenant-a", event_type="command.succeeded")
    assert "sensitive-value" not in str(events)
    ledger.close()


def test_screenshot_artifact_uploads_evidence(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    worker, adapter, ledger = build_worker(tmp_path, stack)
    command_id = submit(stack, agent, lease, key="shot-1", capability_id="device.screenshot",
                        input_payload={"redact": True})
    worker.run_once()
    command = store.get_command("tenant-a", command_id)
    assert command["status"] == "succeeded", command
    evidence = store.list_evidence("tenant-a", command_id)
    assert len(evidence) == 1
    assert evidence[0]["evidence_type"] == "screenshot"
    assert evidence[0]["redaction_status"] == "redacted"
    content = client.get(f"/v1/evidence/{evidence[0]['evidence_id']}/content",
                         headers=bearer(agent))
    assert content.status_code == 200
    assert content.content.startswith(b"\x89PNG")
    assert evidence[0]["evidence_id"] in command["evidence_refs"]
    ledger.close()


def test_adapter_crash_and_timeout_become_uncertain(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"},
                                 device_fingerprint=stack["device_fingerprint"])
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)

    crashed = submit(stack, agent, lease, key="crash-1")
    adapter.fail_next = "driver exploded"
    worker.run_once()
    assert store.get_command("tenant-a", crashed)["status"] == "uncertain"

    timed_out = submit(stack, agent, lease, key="timeout-1",
                       input_payload={"app_id": "com.example.notes"})
    adapter.timeout_next = True
    worker.run_once()
    assert store.get_command("tenant-a", timed_out)["status"] == "uncertain"
    ledger.close()


def test_changed_state_is_rejected_before_execution(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"},
                                 device_fingerprint=stack["device_fingerprint"])
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)
    state = adapter.observe_state()
    approval = approve_tap(stack, agent, lease, state)
    command_id = submit(
        stack, agent, lease, key="state-1", capability_id="ui.tap",
        input_payload={"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        state_hash=state["state_hash"], state_version=state["state_version"],
        approval_id=approval["approval_id"], approval_nonce=approval["approval_nonce"],
        intent="Tap continue",
    )
    adapter.mutate_state()
    worker.run_once()
    command = store.get_command("tenant-a", command_id)
    assert command["status"] == "rejected", command
    assert "state_changed" in (command["status_reason"] or ""), command
    assert not any(call[0] == "ui.tap" for call in adapter.calls)
    ledger.close()


def test_user_takeover_pauses_and_disconnect_is_uncertain(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"},
                                 device_fingerprint=stack["device_fingerprint"])
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)

    takeover_command = submit(stack, agent, lease, key="takeover-1")
    adapter.takeover = True
    worker.run_once()
    assert store.get_command("tenant-a", takeover_command)["status"] == "rejected"
    assert worker.state.paused is True

    worker.resume()
    adapter.takeover = False
    adapter.disconnect_after_action = True
    state = adapter.observe_state()
    approval = approve_tap(stack, agent, lease, state)
    disconnect_command = submit(
        stack, agent, lease, key="disconnect-1", capability_id="ui.tap",
        input_payload={"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        state_hash=state["state_hash"], state_version=state["state_version"],
        approval_id=approval["approval_id"], approval_nonce=approval["approval_nonce"],
        intent="Tap continue",
    )
    worker.run_once()
    assert store.get_command("tenant-a", disconnect_command)["status"] == "uncertain"
    ledger.close()


class StubClient:
    gateway_id = "gw-1"

    def __init__(self, commands):
        self.commands = commands
        self.results = []
        self.progresses = []

    def heartbeat(self, **kwargs):
        return {"tenant_ref": "tenant-a"}

    def pull(self, limit=10):
        return list(self.commands)

    def progress(self, command_id, status):
        self.progresses.append((command_id, status))
        return {}

    def result(self, command_id, payload):
        self.results.append((command_id, payload))
        return {}


def _command(command_id, key, capability_id="app.launch"):
    return {
        "command_id": command_id,
        "tenant_ref": "tenant-a",
        "gateway_id": "gw-1",
        "endpoint_id": "phone-1",
        "capability_id": capability_id,
        "capability_version": "1.0.0",
        "operation": "launch" if capability_id == "app.launch" else "tap",
        "parameters": {"app_id": "com.example.notes"} if capability_id == "app.launch"
                      else {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "intent": "test",
        "deadline": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "idempotency_key": key,
        "lease_id": "lease-1",
        "approval_id": None,
        "approval_nonce": None,
        "policy_version": "device-policy/1",
        "policy_decision": "allow",
        "risk_tier": "read" if capability_id == "app.launch" else "write",
        "state_hash": STATE_HASH if capability_id != "app.launch" else None,
        "state_version": STATE_VERSION if capability_id != "app.launch" else None,
        "manifest_digest": DIGEST,
        "device_id": "device-1",
        "device_fingerprint": "test-device-fingerprint",
        "protocol_version": "v1",
    }


def test_backpressure_rejects_second_command(tmp_path):
    stub = StubClient([_command("cmd-1", "k1"), _command("cmd-2", "k2")])
    ledger = DedupeLedger(tmp_path / "bp.sqlite3")
    worker = GatewayWorker(
        client=stub, adapter=FakeAndroidAdapter(), ledger=ledger,
        queue=BoundedQueue(1), tenant_ref="tenant-a", endpoint_id="phone-1",
        device_fingerprint="test-device-fingerprint", manifest_document=MANIFEST,
        config=WorkerConfig(heartbeat_interval_seconds=999, batch_size=5),
    )
    assert worker.poll_once() == 1
    assert len(worker.queue) == 1
    rejected = [payload for _, payload in stub.results if payload["status"] == "rejected"]
    assert rejected and "backpressure" in rejected[0]["reason"]
    ledger.close()


def test_duplicate_uncertain_non_idempotent_is_not_reexecuted(tmp_path):
    command = _command("cmd-tap", "tap-1", capability_id="ui.tap")
    stub = StubClient([command])
    ledger = DedupeLedger(tmp_path / "dup.sqlite3")
    assert ledger.claim(command).outcome == "new"
    adapter = FakeAndroidAdapter()
    worker = GatewayWorker(
        client=stub, adapter=adapter, ledger=ledger,
        queue=BoundedQueue(4), tenant_ref="tenant-a", endpoint_id="phone-1",
        device_fingerprint="test-device-fingerprint", manifest_document=MANIFEST,
        config=WorkerConfig(heartbeat_interval_seconds=999, batch_size=5),
    )
    assert worker.poll_once() == 0
    assert adapter.calls == []
    assert any(payload["status"] == "uncertain" for _, payload in stub.results)
    ledger.close()

