"""Negative binding matrix for the Home Assistant pilot worker.

Every case asserts that the rejection happens before any HA service call, so an
approval denial, forged identity or stale binding cannot produce a physical side
effect. The matrix covers missing, empty, forged, cross-tenant, revoked, expired
and concurrently-revised bindings plus write-authority prerequisites.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from device_control.iot.adapters.binding import BindingRegistry
from device_control.iot.adapters.worker import HomeAssistantPilotWorker


class RecordingAdapter:
    adapter_id = "home-assistant-pilot"

    def __init__(self, *, stale: bool = False) -> None:
        self.service_calls: list[dict] = []
        self.observed = 0
        self.stale = stale

    def observe(self, entity_id: str):
        self.observed += 1
        observed_at = datetime.now(timezone.utc) - (
            timedelta(minutes=5) if self.stale else timedelta(seconds=1)
        )
        return SimpleNamespace(
            state_hash="hash-1", state_version="v1", quality="good",
            connectivity="online", observed_at=observed_at.isoformat(),
            properties={"state": "off"},
        )

    def execute(self, mapped):
        self.service_calls.append(mapped)
        return SimpleNamespace(
            accepted=True, verified=True, status="succeeded", error=None,
            observed=self.observe("light.kitchen"),
        )


class StubControl:
    gateway_id = "ha-ha-1"
    tenant_ref = "tenant-a"

    def __init__(self, commands):
        self.commands = commands
        self.results = []
        self.progresses = []

    def pull(self, limit=10):
        return list(self.commands)

    def progress(self, command_id, status):
        self.progresses.append((command_id, status))
        return {}

    def result(self, command_id, payload):
        self.results.append((command_id, payload))
        return {}


def command(**overrides):
    payload = {
        "command_id": "cmd-1",
        "tenant_ref": "tenant-a",
        "gateway_id": "ha-ha-1",
        "platform_instance_id": "ha-1",
        "endpoint_id": "ep-ha",
        "device_id": "ha:tenant-a:light:kitchen",
        "capability_id": "light.turn_on",
        "capability_version": "1.0.0",
        "operation": "turn_on",
        "parameters": {"entity_id": "light.kitchen", "expected_state": "on"},
        "state_hash": "hash-1",
        "state_version": "v1",
        "lease_id": "lease-1",
        "approval_id": "appr-1",
        "approval_nonce": "nonce-1",
        "policy_decision": "ask",
    }
    payload.update(overrides)
    return payload


def registry(**overrides) -> BindingRegistry:
    bindings = BindingRegistry(
        tenant_ref="tenant-a", gateway_id="ha-ha-1", platform_instance_id="ha-1",
    )
    values = {
        "entity_id": "light.kitchen",
        "endpoint_id": "ep-ha",
        "device_id": "ha:tenant-a:light:kitchen",
        "capabilities": {"device.observe", "light.turn_on"},
    }
    values.update(overrides)
    bindings.bind(**values)
    return bindings


def run(bindings: BindingRegistry, adapter: RecordingAdapter, payload: dict):
    control = StubControl([payload])
    HomeAssistantPilotWorker(client=control, adapter=adapter, bindings=bindings).run_once()
    assert len(control.results) == 1
    return control.results[0][1]


@pytest.mark.parametrize(
    "field",
    ["tenant_ref", "gateway_id", "platform_instance_id", "endpoint_id", "device_id"],
)
def test_missing_identity_field_fails_closed(field):
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(**{field: None}))
    assert outcome["status"] == "rejected"
    assert outcome["reason"] == "claim_field_missing"
    assert adapter.service_calls == []


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tenant_ref", "tenant-b", "tenant_mismatch"),
        ("gateway_id", "ha-other", "gateway_mismatch"),
        ("platform_instance_id", "ha-2", "platform_instance_mismatch"),
        ("endpoint_id", "ep-other", "endpoint_mapping_mismatch"),
        ("device_id", "ha:tenant-a:light:other", "device_mapping_mismatch"),
    ],
)
def test_forged_identity_field_fails_closed(field, value, reason):
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(**{field: value}))
    assert outcome["reason"] == reason
    assert adapter.service_calls == []


def test_unbound_entity_is_rejected_before_ha():
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(
        parameters={"entity_id": "light.unbound", "expected_state": "on"},
    ))
    assert outcome["reason"] == "entity_binding_missing"
    assert adapter.service_calls == []


def test_capability_must_be_granted_by_binding():
    adapter = RecordingAdapter()
    outcome = run(registry(capabilities={"device.observe"}), adapter, command())
    assert outcome["reason"] == "capability_not_granted"
    assert adapter.service_calls == []


def test_revoked_binding_is_rejected():
    bindings = registry()
    bindings.revoke("light.kitchen")
    adapter = RecordingAdapter()
    outcome = run(bindings, adapter, command())
    assert outcome["reason"] == "binding_revoked"
    assert adapter.service_calls == []


def test_expired_binding_is_rejected():
    frozen = datetime.now(timezone.utc)
    bindings = BindingRegistry(
        tenant_ref="tenant-a", gateway_id="ha-ha-1", platform_instance_id="ha-1",
        clock=lambda: frozen,
    )
    bindings.bind(
        entity_id="light.kitchen", endpoint_id="ep-ha",
        device_id="ha:tenant-a:light:kitchen",
        capabilities={"light.turn_on"}, ttl_seconds=-1,
    )
    adapter = RecordingAdapter()
    outcome = run(bindings, adapter, command())
    assert outcome["reason"] == "binding_expired"
    assert adapter.service_calls == []


def test_stale_binding_revision_is_rejected():
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(binding_revision=99))
    assert outcome["reason"] == "binding_revision_mismatch"
    assert adapter.service_calls == []


def test_current_binding_revision_is_accepted():
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(binding_revision=1))
    assert outcome["status"] == "succeeded"
    assert len(adapter.service_calls) == 1


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"policy_decision": "allow"}, "policy_decision_mismatch"),
        ({"policy_decision": None}, "policy_decision_mismatch"),
        ({"lease_id": None}, "lease_missing"),
        ({"approval_id": None}, "approval_missing"),
        ({"approval_nonce": None}, "approval_nonce_missing"),
    ],
)
def test_write_requires_control_plane_authority(overrides, reason):
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(**overrides))
    assert outcome["reason"] == reason
    assert adapter.service_calls == []


def test_read_requires_tenant_identity_but_no_approval():
    adapter = RecordingAdapter()
    payload = command(
        capability_id="device.observe", operation="observe",
        parameters={"entity_id": "light.kitchen"}, policy_decision="allow",
        lease_id=None, approval_id=None, approval_nonce=None,
    )
    outcome = run(registry(), adapter, payload)
    assert outcome["status"] == "succeeded"
    assert adapter.service_calls == []

    forged = {**payload, "tenant_ref": "tenant-b"}
    outcome = run(registry(), adapter, forged)
    assert outcome["reason"] == "tenant_mismatch"
    assert adapter.service_calls == []


def test_write_with_changed_state_is_rejected_before_service_call():
    adapter = RecordingAdapter()
    outcome = run(registry(), adapter, command(state_hash="different"))
    assert outcome["reason"] == "state_changed"
    assert adapter.service_calls == []


def test_binding_document_scope_must_match_edge():
    bindings = BindingRegistry(
        tenant_ref="tenant-a", gateway_id="ha-ha-1", platform_instance_id="ha-1",
    )
    document = {
        "tenant_ref": "tenant-b",
        "gateway_id": "ha-ha-1",
        "platform_instance_id": "ha-1",
        "valid_until": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "bindings": [],
    }
    with pytest.raises(Exception) as exc:
        bindings.load_document(document)
    assert getattr(exc.value, "reason", "") == "binding_document_scope_mismatch"
