import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from device_control import contracts
from device_control.iot.home_assistant import build_command, map_entity, verify_state
from device_control.iot.lifecycle import AdapterLifecycleManager, AdapterState, LifecycleError
from device_control.iot.manifest import AdapterManifest, verify_manifest
from device_control.iot.mqtt_topics import (
    AclRule,
    TopicError,
    build_topic,
    parse_topic,
    validate_retained,
)
from device_control.iot.spi import (
    AdapterHealth,
    CapabilityMapping,
    DiscoveredDevice,
    DiscoveryPage,
    ExecutionResult,
    Observation,
    PlatformConfig,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "home_assistant_states.json"


def manifest_document(**overrides):
    document = {
        "adapter_id": "home-assistant",
        "display_name": "Home Assistant",
        "version": "1.0.0",
        "api_version": "1.0",
        "publisher": "device-control",
        "license": "Apache-2.0",
        "supported_platforms": ["homeassistant"],
        "supported_platform_versions": ["2026.11"],
        "supported_features": ["discover", "observe", "execute", "telemetry"],
        "supported_protocols": ["rest", "websocket"],
        "required_permissions": ["states:read", "services:call"],
        "configuration_schema": {"type": "object"},
        "credential_schema": {"secret_ref": "vault:ha-token"},
        "capability_mappings": [{
            "capability_id": "light.set_state", "version": "1.0.0",
            "native_operation": "light.turn_on", "risk_tier": "write",
            "requires_state": True,
        }],
        "resource_limits": {"cpu": 0.5, "memory_mb": 128, "timeout_seconds": 10,
                            "max_devices": 100, "max_concurrency": 2},
        "schema_versions": {"device": "1", "telemetry": "1", "event": "1", "twin": "1"},
        "health_checks": [{"name": "rest", "timeout_ms": 2000}],
    }
    document.update(overrides)
    return document


class FakeAdapter:
    adapter_id = "home-assistant"
    api_version = "1.0"

    def __init__(self):
        self.hang = False
        self.fail = False
        self.connected = False

    def validate_config(self, config):
        return [] if config.endpoint.startswith("http") else ["bad endpoint"]

    def connect(self, config, resolve_secret):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def health(self):
        return AdapterHealth(status="ok" if self.connected else "unavailable")

    def discover(self, cursor=None, filters=None):
        return DiscoveryPage(devices=(DiscoveredDevice(
            native_id="light.kitchen", native_type="light", display_name="Kitchen Light",
            capabilities=(CapabilityMapping("light.set_state", "1.0.0", "light.turn_on", "write"),),
        ),), cursor=None)

    def get_device(self, native_id):
        return None

    def get_capabilities(self, native_id):
        return []

    def observe(self, native_id):
        return Observation(native_id=native_id, observed_at="2026-11-27T00:00:00+00:00",
                           properties={"state": "off"}, quality="good")

    def execute(self, command):
        if self.hang:
            time.sleep(5)
        if self.fail:
            raise RuntimeError("platform crash")
        return ExecutionResult(native_id="light.kitchen", accepted=True, executed=True,
                               verified=True, status="succeeded")

    def subscribe(self, event_types, cursor=None):
        return [], None

    def get_telemetry(self, native_id, cursor=None, limit=100):
        return [], None

    def reconcile(self, mapping_state):
        return mapping_state


def config():
    return PlatformConfig(
        platform_instance_id="ha-1", tenant_id="tenant-a", adapter_id="home-assistant",
        endpoint="https://ha.example/api", platform_version="2026.11",
    )


def test_adapter_manifest_schema_and_ed25519_signature():
    document = manifest_document()
    manifest = AdapterManifest(document)
    assert manifest.validate() == []
    assert contracts.validate_contract("adapter_manifest", document) == []

    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    payload = {key: value for key, value in document.items() if key != "signature"}
    signature = private.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    document["signature"] = {"algorithm": "Ed25519", "key_id": "release-1",
                             "value": base64.b64encode(signature).decode()}
    signed = AdapterManifest(document)
    assert verify_manifest(signed, public_pem, {"release-1"})
    assert not verify_manifest(signed, public_pem, {"other"})
    tampered = AdapterManifest({**document, "version": "9.9.9"})
    assert not verify_manifest(tampered, public_pem, {"release-1"})


def test_manifest_rejects_literal_secret_and_bad_api_version():
    literal = manifest_document(credential_schema={"token": {"type": "string"}})
    errors = AdapterManifest(literal).validate()
    assert any("secret" in error for error in errors)
    wrong = manifest_document(api_version="2.0")
    errors = AdapterManifest(wrong).validate()
    assert any("api_version" in error for error in errors)


def test_lifecycle_discovers_executes_and_isolates_failure():
    manager = AdapterLifecycleManager(timeout_seconds=0.3, failure_threshold=2)
    manager.install(AdapterManifest(manifest_document()), FakeAdapter)
    manager.enable("home-assistant")
    manager.configure("home-assistant", config())
    manager.authorize("home-assistant")
    manager.connect("home-assistant", lambda ref: "secret")
    assert manager.state("home-assistant") == AdapterState.ACTIVE
    page = manager.discover("home-assistant")
    assert page.devices[0].trusted is False
    result = manager.execute("home-assistant", {"native_id": "light.kitchen"})
    assert result.verified
    manager.disable("home-assistant")
    assert manager.state("home-assistant") == AdapterState.DISABLED


def test_lifecycle_timeout_and_circuit_breaker():
    manager = AdapterLifecycleManager(timeout_seconds=0.1, failure_threshold=2, circuit_seconds=60)
    plugin = FakeAdapter()
    plugin.hang = True
    manager.install(AdapterManifest(manifest_document()), lambda: plugin)
    manager.enable("home-assistant")
    manager.configure("home-assistant", config())
    manager.authorize("home-assistant")
    manager.connect("home-assistant", lambda ref: "secret")
    with pytest.raises(Exception) as first:
        manager.execute("home-assistant", {})
    assert "timeout" in str(first.value)
    with pytest.raises(Exception) as second:
        manager.execute("home-assistant", {})
    assert "timeout" in str(second.value)
    with pytest.raises(Exception) as circuit:
        manager.execute("home-assistant", {})
    assert "circuit" in str(circuit.value)


def test_lifecycle_rejects_invalid_config_and_uninstalled_adapter():
    manager = AdapterLifecycleManager()
    manager.install(AdapterManifest(manifest_document()), FakeAdapter)
    manager.enable("home-assistant")
    with pytest.raises(LifecycleError):
        manager.configure("home-assistant", PlatformConfig(
            platform_instance_id="ha", tenant_id="t", adapter_id="home-assistant",
            endpoint="ftp://bad",
        ))
    with pytest.raises(LifecycleError):
        manager.execute("missing", {})
    manager.uninstall("home-assistant")
    with pytest.raises(LifecycleError):
        manager.state("home-assistant")


def test_home_assistant_mapping_is_pending_and_verification_is_readback():
    states = json.loads(FIXTURE.read_text(encoding="utf-8"))
    device = map_entity("tenant-a", states["light"], area="kitchen")
    assert device.trust_state == "pending"
    assert device.device_type == "light"
    assert any(item["risk_tier"] == "write" for item in device.capabilities)
    command = build_command({
        "native_id": "light.kitchen", "native_operation": "light.turn_on",
        "parameters": {"brightness": 120}, "expected_state": "on",
    }, states["light"])
    assert command["endpoint"] == "/api/services/light/turn_on"
    assert command["payload"]["entity_id"] == "light.kitchen"
    assert verify_state("on", "on")
    assert not verify_state("on", "off")


def test_mqtt_topics_acl_and_retained_command_rules():
    topic = build_topic(tenant="tenant-a", device="dev-1", endpoint="ep-1",
                        channel="telemetry", metric="temperature")
    assert parse_topic(topic)["metric"] == "temperature"
    rule = AclRule(tenant="tenant-a", device="dev-1", endpoint="ep-1",
                   channels=frozenset({"telemetry", "state"}))
    assert rule.allows(topic, action="subscribe")
    assert not rule.allows(topic, action="publish")
    other = build_topic(tenant="tenant-b", device="dev-1", endpoint="ep-1", channel="telemetry")
    assert not rule.allows(other, action="subscribe")
    with pytest.raises(TopicError):
        validate_retained("command", retained=True)
    assert validate_retained("state", retained=True)


def test_canonical_device_telemetry_twin_contracts_validate():
    device = {
        "device_id": "dev-1", "tenant_id": "tenant-a", "platform_instance_id": "ha-1",
        "native_platform": "homeassistant", "native_id": "light.kitchen",
        "display_name": "Kitchen Light", "device_type": "light",
        "connectivity_state": "online", "trust_state": "pending", "schema_version": "1",
        "created_at": "2026-11-27T00:00:00+00:00", "updated_at": "2026-11-27T00:00:00+00:00",
    }
    assert contracts.validate_contract("canonical_device", device) == []
    telemetry = {
        "telemetry_id": "tel-1", "tenant_id": "tenant-a", "device_id": "dev-1",
        "metric": "temperature", "value": 21.5, "unit": "C", "quality": "good",
        "source_timestamp": "2026-11-27T00:00:00+00:00",
        "ingest_timestamp": "2026-11-27T00:00:01+00:00", "sequence": 1,
        "source_adapter": "home-assistant", "schema_version": "1",
    }
    assert contracts.validate_contract("telemetry", telemetry) == []
