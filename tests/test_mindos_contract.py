import pytest
from fastapi.testclient import TestClient
from support import (
    acquire_lease,
    agent_token,
    configure,
    setup_stack,
)

from device_control import contracts
from device_control.app import app
from examples.mindos_provider import LEGACY_STATUS_MAP, MindOSDeviceControlProvider, ProviderError

client = TestClient(app)


class TestClientTransport:
    def request(self, method, url, body, headers):
        path = url.split("://", 1)[-1]
        path = "/" + path.split("/", 1)[1]
        response = client.request(method, path, json=body, headers=headers)
        return response.status_code, response.json()


def provider(token: str, *, tenant: str = "tenant-a", subject: str = "agent-1",
             device_id: str = "device-phone-1") -> MindOSDeviceControlProvider:
    return MindOSDeviceControlProvider(
        base_url="http://testserver",
        tenant=tenant,
        subject=subject,
        token_provider=lambda: token,
        endpoint_for_device=lambda device: {"device-phone-1": "phone-1"}.get(device, "missing"),
        transport=TestClientTransport(),
    )


def legacy_intent(**overrides):
    payload = {
        "command_id": "mindos-intent-1",
        "tenant": "tenant-a",
        "device_id": "device-phone-1",
        "capability": "app.launch",
        "operation": "launch",
        "parameters": {"app_id": "com.example.notes"},
        "requested_by": "agent-1",
        "approval_ref": None,
        "idempotency_key": None,
        "timeout_seconds": 30.0,
    }
    payload.update(overrides)
    return payload


def test_mapping_creates_a_schema_valid_command(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    body = provider(agent).build_command(legacy_intent(), lease_id=lease["lease_id"],
                                         task_ref="task-1", run_ref="run-1")
    assert body["endpoint_id"] == stack["endpoint_id"]
    assert body["idempotency_key"] == "mindos-intent-1"
    assert body["correlation_id"] == "mindos-intent-1"
    assert contracts.validate_contract("command", body) == []
    assert LEGACY_STATUS_MAP["uncertain"] == "uncertain"
    assert LEGACY_STATUS_MAP["executing"] == "running"


def test_provider_submit_get_and_cancel(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    provider_client = provider(agent)
    submitted = provider_client.submit(legacy_intent(), lease_id=lease["lease_id"],
                                       task_ref="task-1", run_ref="run-1")
    assert submitted["status"] == "queued"
    assert submitted["provider_command_id"]
    status = provider_client.get(submitted["provider_command_id"])
    assert status["status"] == "queued"
    cancelled = provider_client.cancel(submitted["provider_command_id"], "user cancelled")
    assert cancelled["status"] == "cancelled"


def test_provider_rejects_cross_tenant_and_actor_spoofing(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    with pytest.raises(ProviderError):
        provider(agent).submit(legacy_intent(tenant="tenant-b"), lease_id=lease["lease_id"])
    with pytest.raises(ProviderError):
        provider(agent).submit(legacy_intent(requested_by="other-agent"),
                               lease_id=lease["lease_id"])
