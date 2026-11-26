import json
from pathlib import Path

from device_control.app import app

ROOT = Path(__file__).resolve().parents[1]


def test_openapi_covers_consumer_and_gateway_surfaces():
    document = app.openapi()
    paths = set(document["paths"])
    for required in (
        "/v1/commands",
        "/v1/commands/{command_id}",
        "/v1/commands/{command_id}/cancel",
        "/v1/commands/{command_id}/evidence",
        "/v1/gateways/{gateway_id}/commands",
        "/v1/gateways/{gateway_id}/manifest",
        "/v1/gateways/{gateway_id}/diagnostics",
        "/v1/evidence/{evidence_id}/content",
        "/v1/events",
    ):
        assert required in paths


def test_exported_openapi_is_current():
    exported = ROOT / "contracts" / "openapi-v1.json"
    assert exported.is_file(), "run python scripts/export_openapi.py"
    document = json.loads(exported.read_text(encoding="utf-8"))
    assert document["info"]["version"] == "v1"
    assert "/v1/commands" in document["paths"]
