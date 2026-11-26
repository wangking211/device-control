from fastapi.testclient import TestClient

from device_control.app import app

client = TestClient(app)


def test_health_and_contract_catalog():
    assert client.get("/health/live").json() == {"status": "live"}
    assert client.get("/health/ready").status_code == 200
    assert len(client.get("/v1/contracts").json()["contracts"]) == 3


def test_contract_validation_reports_errors_without_accepting_unknown_contract():
    response = client.post("/v1/contracts/invocation/validate", json={})
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["errors"]
    assert client.post("/v1/contracts/private/validate", json={}).status_code == 404


def test_valid_invocation_shape():
    payload = {
        "request_id": "req-1", "tenant_ref": "tenant-1", "endpoint_id": "endpoint-1",
        "capability_id": "screen.observe", "capability_version": "1.0.0",
        "requested_by": "user-1", "deadline": "2026-11-26T12:00:00Z",
        "idempotency_key": "idem-1", "input": {}, "intent": "Observe current screen"
    }
    assert client.post("/v1/contracts/invocation/validate", json=payload).json()["valid"] is True
