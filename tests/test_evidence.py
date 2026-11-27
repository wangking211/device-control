import base64
import hashlib
import io
import json
from datetime import datetime, timedelta, timezone

from device_gateway.redaction import (
    REDACTION_POLICY_VERSION,
    REDACTION_PROCESSOR,
    RedactionResult,
    sign_proof,
)
from fastapi.testclient import TestClient
from PIL import Image
from support import (
    REDACTION_KEY,
    REDACTION_KEY_ID,
    acquire_lease,
    admin_token,
    agent_token,
    bearer,
    command_body,
    configure,
    setup_stack,
)

from device_control import store
from device_control.app import app

client = TestClient(app)
_buffer = io.BytesIO()
Image.new("RGB", (240, 360), (240, 240, 240)).save(_buffer, format="PNG")
PNG = _buffer.getvalue()


def _command(stack, agent, lease, key="evd-1"):
    queued = client.post("/v1/commands", json=command_body(
        endpoint_id=stack["endpoint_id"], lease_id=lease["lease_id"], idempotency_key=key,
    ), headers=bearer(agent))
    assert queued.status_code == 201
    command_id = queued.json()["command_id"]
    pulled = client.get(f"/v1/gateways/{stack['gateway_id']}/commands",
                        headers=bearer(stack["gateway_credential"]))
    assert [item["command_id"] for item in pulled.json()["items"]] == [command_id]
    return command_id


def _upload(stack, command_id, data=PNG, **overrides):
    original = b"original-frame-bytes"
    result = RedactionResult(
        status="redacted",
        original_sha256=hashlib.sha256(original).hexdigest(),
        output_sha256=hashlib.sha256(data).hexdigest(),
        processor=REDACTION_PROCESSOR,
        policy_version=REDACTION_POLICY_VERSION,
        key_id=REDACTION_KEY_ID,
        regions=[{"x1": 0, "y1": 0, "x2": 240, "y2": 20,
                  "reason": "status_bar_notifications"}],
    )
    result = RedactionResult(**{**result.__dict__, "proof": sign_proof(result, REDACTION_KEY)})
    headers = {
        "Authorization": f"Bearer {stack['gateway_credential']}",
        "Content-Type": "image/png",
        "X-Evidence-Type": "screenshot",
        "X-Content-SHA256": hashlib.sha256(data).hexdigest(),
        "X-Redaction-Status": "redacted",
        "X-Original-SHA256": result.original_sha256,
        "X-Redaction-Processor": result.processor,
        "X-Redaction-Policy": result.policy_version,
        "X-Redaction-Key-Id": result.key_id,
        "X-Redaction-Proof": result.proof or "",
        "X-Redaction-Regions": base64.b64encode(
            json.dumps(result.regions, sort_keys=True).encode()
        ).decode(),
    }
    headers.update(overrides)
    return client.post(
        f"/v1/gateways/{stack['gateway_id']}/commands/{command_id}/evidence",
        content=data, headers=headers,
    )


def test_evidence_upload_list_download_and_delete(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _command(stack, agent, lease)

    uploaded = _upload(stack, command_id)
    assert uploaded.status_code == 201, uploaded.text
    metadata = uploaded.json()
    assert metadata["content_sha256"] == hashlib.sha256(PNG).hexdigest()
    assert metadata["size_bytes"] == len(PNG)
    assert metadata["redaction_status"] == "redacted"
    assert metadata["command_id"] == command_id
    assert metadata["storage_ref"].endswith("/content.bin")
    assert (tmp_path / "evidence" / metadata["storage_ref"]).is_file()

    listed = client.get(f"/v1/commands/{command_id}/evidence", headers=bearer(agent))
    assert listed.status_code == 200
    assert listed.json()["items"][0]["evidence_id"] == metadata["evidence_id"]

    content = client.get(f"/v1/evidence/{metadata['evidence_id']}/content",
                         headers=bearer(agent))
    assert content.status_code == 200
    assert content.content == PNG
    assert content.headers["x-content-sha256"] == metadata["content_sha256"]
    assert content.headers["cache-control"] == "private, no-store"

    other = bearer(issue_token("intruder", "tenant-b", roles=("platform_admin",)))
    assert client.get(f"/v1/evidence/{metadata['evidence_id']}",
                      headers=other).status_code == 404

    deleted = client.delete(f"/v1/evidence/{metadata['evidence_id']}",
                            headers=bearer(admin_token()))
    assert deleted.status_code == 200
    assert client.get(f"/v1/evidence/{metadata['evidence_id']}/content",
                      headers=bearer(agent)).status_code == 404


def test_evidence_rejects_hash_mismatch_unredacted_and_bad_type(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _command(stack, agent, lease)

    mismatch = _upload(stack, command_id, **{"X-Content-SHA256": "0" * 64})
    assert mismatch.status_code == 422
    assert mismatch.json()["code"] == "evidence_hash_mismatch"

    tampered = _upload(stack, command_id, **{"X-Redaction-Proof": "0" * 64})
    assert tampered.status_code == 422
    assert tampered.json()["code"] == "redaction_proof_invalid"

    unredacted = _upload(stack, command_id, **{"X-Redaction-Status": "not_required"})
    assert unredacted.status_code == 422
    assert unredacted.json()["code"] == "redaction_required"

    wrong_type = _upload(stack, command_id, **{"Content-Type": "application/zip"})
    assert wrong_type.status_code == 422
    assert wrong_type.json()["code"] == "invalid_evidence_type"


def test_evidence_storage_health_is_available(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    response = client.get("/v1/evidence-storage/health", headers=bearer(admin_token()))
    assert response.status_code == 200
    assert response.json()["backend"] == "local"


def test_evidence_retention_purge(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    stack = setup_stack(client)
    agent = agent_token()
    lease = acquire_lease(client, agent, endpoint_id=stack["endpoint_id"])
    command_id = _command(stack, agent, lease)
    metadata = _upload(stack, command_id).json()
    db = store.connect()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    db.execute("UPDATE device_evidence SET retention_until=? WHERE evidence_id=?",
               (past, metadata["evidence_id"]))
    db.close()
    response = client.post("/v1/maintenance", headers=bearer(admin_token()))
    assert response.status_code == 200
    assert response.json()["summary"]["evidence_purged"] >= 1
    assert not (tmp_path / "evidence" / metadata["storage_ref"]).exists()
    assert client.get(f"/v1/evidence/{metadata['evidence_id']}",
                      headers=bearer(agent)).status_code == 404


def issue_token(*args, **kwargs):  # local import shim to keep the test readable
    from support import issue_token as _issue

    return _issue(*args, **kwargs)
