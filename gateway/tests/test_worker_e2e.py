from datetime import datetime, timedelta, timezone

from device_gateway import manifest
from device_gateway.adapters.fake import FakeAndroidAdapter
from device_gateway.control_client import ControlPlaneClient
from device_gateway.ledger import DedupeLedger
from device_gateway.queue import BoundedQueue
from device_gateway.worker import GatewayWorker, WorkerConfig
from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    agent_token,
    bearer,
    command_body,
    configure,
    setup_stack,
)

from device_control import store
from device_control.app import app

client = TestClient(app)


class InProcessTransport:
    def __init__(self, test_client: TestClient) -> None:
        self.test_client = test_client

    def request(self, method, url, body, headers):
        path = url.split("://", 1)[-1]
        path = "/" + path.split("/", 1)[1]
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
        for item in manifest.CAPABILITIES
    ]


def build_worker(tmp_path, stack, adapter=None):
    adapter = adapter or FakeAndroidAdapter(allowed_apps={"com.example.notes"})
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
        config=WorkerConfig(heartbeat_interval_seconds=0, poll_interval_seconds=0, batch_size=5),
    )
    return worker, adapter, ledger


def submit(stack, agent, lease, *, key, capability_id="app.launch", input_payload=None,
           state_hash=None):
    response = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key=key, capability_id=capability_id,
        input_payload=input_payload, state_hash=state_hash,
    ), headers=bearer(agent))
    assert response.status_code == 201, response.text
    return response.json()["command_id"]


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
    assert adapter.state["foreground_app"] == "com.example.notes"
    assert ledger.is_terminal(command_id)
    ledger.close()


def test_adapter_crash_and_timeout_become_uncertain(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"})
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)

    crashed = submit(stack, agent, lease, key="crash-1")
    adapter.fail_next = "driver exploded"
    worker.run_once()
    assert store.get_command("tenant-a", crashed)["status"] == "uncertain"

    timed_out = submit(stack, agent, lease, key="timeout-1", input_payload={"app_id": "com.example.notes"})
    adapter.timeout_next = True
    worker.run_once()
    assert store.get_command("tenant-a", timed_out)["status"] == "uncertain"
    ledger.close()


def test_changed_state_is_rejected_before_execution(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client, capabilities=endpoint_capabilities())
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"})
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)
    state_hash = adapter.observe_state()["state_hash"]
    command_id = submit(stack, agent, lease, key="state-1", capability_id="ui.tap",
                        input_payload={"target_ref": "Continue", "bounds": [10, 10, 20, 20]},
                        state_hash=state_hash)
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
    adapter = FakeAndroidAdapter(allowed_apps={"com.example.notes"})
    worker, _, ledger = build_worker(tmp_path, stack, adapter=adapter)

    takeover_command = submit(stack, agent, lease, key="takeover-1")
    adapter.takeover = True
    worker.run_once()
    assert store.get_command("tenant-a", takeover_command)["status"] == "rejected"
    assert worker.state.paused is True

    worker.resume()
    adapter.takeover = False
    adapter.disconnect_after_action = True
    state_hash = adapter.observe_state()["state_hash"]
    disconnect_command = submit(stack, agent, lease, key="disconnect-1", capability_id="ui.tap",
                                input_payload={"target_ref": "Continue", "bounds": [0, 0, 10, 10]},
                                state_hash=state_hash)
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
        "parameters": {"app_id": "com.example.notes"} if capability_id == "app.launch"
                      else {"target_ref": "Continue", "bounds": [0, 0, 10, 10]},
        "intent": "test",
        "deadline": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "idempotency_key": key,
        "lease_id": "lease-1",
        "approval_id": None,
        "policy_version": "device-policy/1",
        "policy_decision": "allow",
        "risk_tier": "read" if capability_id == "app.launch" else "write",
        "state_hash": None,
        "protocol_version": "v1",
    }


def test_backpressure_rejects_second_command(tmp_path):
    stub = StubClient([_command("cmd-1", "k1"), _command("cmd-2", "k2")])
    ledger = DedupeLedger(tmp_path / "bp.sqlite3")
    worker = GatewayWorker(
        client=stub, adapter=FakeAndroidAdapter(), ledger=ledger,
        queue=BoundedQueue(1), tenant_ref="tenant-a",
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
        queue=BoundedQueue(4), tenant_ref="tenant-a",
        config=WorkerConfig(heartbeat_interval_seconds=999, batch_size=5),
    )
    assert worker.poll_once() == 0
    assert adapter.calls == []
    assert any(payload["status"] == "uncertain" for _, payload in stub.results)
    ledger.close()
