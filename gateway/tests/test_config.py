import pytest
from device_gateway.config import from_env


def env(url="http://device-control:8085", **overrides):
    values = {
        "DEVICE_CONTROL_URL": url,
        "DEVICE_GATEWAY_ID": "gw-1",
        "DEVICE_GATEWAY_CREDENTIAL": "x" * 40,
        "DEVICE_GATEWAY_ADAPTER": "fake",
    }
    values.update(overrides)
    return values


def test_non_loopback_http_is_rejected_outside_dev_profile():
    with pytest.raises(ValueError):
        from_env(env())


def test_dev_profile_can_explicitly_allow_compose_http():
    settings = from_env(env(DEVICE_GATEWAY_ENV="dev", DEVICE_GATEWAY_ALLOW_INSECURE_HTTP="1"))
    assert settings.control_url == "http://device-control:8085"


def test_production_gateway_requires_signed_manifest(monkeypatch):
    from device_gateway.main import build_components

    monkeypatch.setenv("DEVICE_GATEWAY_ENV", "production")
    with pytest.raises(ValueError, match="Ed25519"):
        build_components(from_env(env(url="https://device-control.internal")))


def test_https_and_loopback_http_are_allowed():
    assert from_env(env(url="https://device-control.internal")).gateway_id == "gw-1"
    assert from_env(env(url="http://127.0.0.1:8085")).gateway_id == "gw-1"
