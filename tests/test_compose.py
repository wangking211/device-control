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


def ha_compose():
    return yaml.safe_load(
        (ROOT / "docker-compose.ha.yml").read_text(encoding="utf-8")
    )


def test_ha_compose_runs_managed_event_worker():
    document = ha_compose()
    worker = document["services"]["ha-event-worker"]
    assert worker["command"] == ["python", "scripts/ha_event_worker.py"]
    assert worker["restart"] == "unless-stopped"
    assert worker["read_only"] is True
    assert "no-new-privileges:true" in worker["security_opt"]
    assert "ALL" in worker["cap_drop"]
    assert "HA_TOKEN" in worker["environment"]
    assert "HA_ALLOWED_ENTITIES" not in worker["environment"]
    assert worker["environment"]["HA_BINDING_STATE_PATH"].startswith(
        "/var/lib/device-control-ha/"
    )
    assert worker["environment"]["HA_HEALTH_PATH"].startswith(
        "/var/lib/device-control-ha/"
    )
    assert "ha-worker-state:/var/lib/device-control-ha" in worker["volumes"]
    assert worker["healthcheck"]["test"]
    assert "ha-worker-state" in document["volumes"]


def test_ha_compose_wires_signed_binding_keys():
    document = ha_compose()
    control = document["services"]["device-control"]["environment"]
    control_key = control["DEVICE_CONTROL_BINDING_SIGNING_KEY"].split(":-")[-1]
    control_id = control["DEVICE_CONTROL_BINDING_KEY_ID"].split(":-")[-1]
    for name in ("ha-adapter", "ha-event-worker"):
        environment = document["services"][name]["environment"]
        assert environment["DEVICE_CONTROL_BINDING_VERIFICATION_KEY"].split(":-")[-1] == control_key
        assert environment["DEVICE_CONTROL_BINDING_KEY_ID"].split(":-")[-1] == control_id
