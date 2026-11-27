from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_compose_is_non_root_hardened_and_persistent():
    document = compose()
    control = document["services"]["device-control"]
    gateway = document["services"]["device-gateway"]
    for service in (control, gateway):
        assert service["read_only"] is True
        assert "no-new-privileges:true" in service["security_opt"]
        assert "ALL" in service["cap_drop"]
        assert "/tmp" in service["tmpfs"]
    assert "device-control-data:/data" in control["volumes"]
    assert "device-gateway-data:/data" in gateway["volumes"]


def test_compose_gateway_transport_is_explicit_dev_only():
    document = compose()
    environment = document["services"]["device-gateway"]["environment"]
    assert environment["DEVICE_CONTROL_URL"].startswith("http://")
    assert environment["DEVICE_GATEWAY_ENV"] == "dev"
    assert environment["DEVICE_GATEWAY_ALLOW_INSECURE_HTTP"] == "1"
    assert environment["DEVICE_CONTROL_URL"].startswith("http://device-control")
