"""Production gates: missing secrets fail closed; writes are opt-in."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from support import acquire_lease, agent_token, bearer, command_body, configure, setup_stack

from device_control import config
from device_control.app import app

client = TestClient(app)

SECRET_KEYS = (
    "MINDOS_IDENTITY_HMAC_KEY",
    "DEVICE_CONTROL_REDACTION_HMAC_KEY",
    "DEVICE_CONTROL_MANIFEST_PUBLIC_KEY",
    "DEVICE_CONTROL_MANIFEST_KEY_IDS",
    "DEVICE_CONTROL_MANIFEST_HMAC_KEY",
)


def test_production_rejects_missing_secret_configuration(monkeypatch):
    monkeypatch.setenv("DEVICE_CONTROL_ENV", "production")
    monkeypatch.delenv("DEVICE_CONTROL_MANIFEST_ALLOW_HMAC", raising=False)
    for key in SECRET_KEYS:
        monkeypatch.delenv(key, raising=False)
    errors = set(config.production_configuration_errors())
    assert {"MINDOS_IDENTITY_HMAC_KEY", "DEVICE_CONTROL_REDACTION_HMAC_KEY",
            "DEVICE_CONTROL_MANIFEST_PUBLIC_KEY",
            "DEVICE_CONTROL_MANIFEST_KEY_IDS"} <= errors
    with pytest.raises(RuntimeError, match="production configuration is incomplete"):
        config.validate_production()


def test_writes_default_off_in_production(monkeypatch):
    monkeypatch.setenv("DEVICE_CONTROL_ENV", "production")
    monkeypatch.delenv("DEVICE_CONTROL_ENABLE_WRITES", raising=False)
    assert config.writes_enabled() is False
    monkeypatch.setenv("DEVICE_CONTROL_ENABLE_WRITES", "true")
    assert config.writes_enabled() is True


def test_production_write_submission_fails_closed(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path, production=True)
    monkeypatch.setenv("DEVICE_CONTROL_ENABLE_WRITES", "false")
    monkeypatch.setenv("DEVICE_CONTROL_MANIFEST_REQUIRE_SIGNATURE", "false")
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    response = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"],
        idempotency_key="prod-write-disabled", capability_id="ui.tap",
        input_payload={"target_ref": "node-1"},
    ), headers=bearer(agent))
    assert response.status_code == 503, response.text
    assert response.json()["code"] == "writes_disabled"
