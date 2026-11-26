"""Shared test helpers: identity tokens, manifest, gateway/endpoint fixtures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from device_gateway import manifest as gateway_manifest

IDENTITY_KEY = "device-control-test-identity-key-0123456789abcdef"
ISSUER = "mindos-test"
MANIFEST = gateway_manifest.default_document()
MANIFEST_DIGEST = gateway_manifest.digest(MANIFEST)
MANIFEST_VERSION = str(MANIFEST["manifest_version"])
DEVICE_FINGERPRINT = "test-device-fingerprint"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def issue_token(
    subject: str,
    tenant: str,
    *,
    roles: tuple[str, ...] = (),
    permissions: tuple[str, ...] = (),
    ttl_seconds: int = 600,
    issuer: str = ISSUER,
    extra: dict[str, Any] | None = None,
    audience: str | None = None,
    secret: str = IDENTITY_KEY,
    expired: bool = False,
) -> str:
    now = int(time.time()) - (7200 if expired else 0)
    claims: dict[str, Any] = {
        "sub": subject,
        "tenant": tenant,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "roles": list(roles),
        "permissions": list(permissions),
        "iss": issuer,
    }
    if extra:
        claims["extra"] = extra
    if audience:
        claims["aud"] = audience
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = hmac.new(secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def configure(monkeypatch, tmp_path, *, production: bool = False,
              admin_token: str | None = "test-bootstrap-token-0123456789") -> None:
    monkeypatch.setenv("DEVICE_CONTROL_ENV", "production" if production else "test")
    monkeypatch.setenv("DEVICE_CONTROL_DB", str(tmp_path / "device-control.sqlite3"))
    monkeypatch.setenv("MINDOS_IDENTITY_HMAC_KEY", IDENTITY_KEY)
    monkeypatch.setenv("MINDOS_IDENTITY_ISSUER", ISSUER)
    monkeypatch.setenv("DEVICE_CONTROL_RATE_LIMIT_PER_MINUTE", "100000")
    monkeypatch.setenv("DEVICE_CONTROL_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("DEVICE_CONTROL_REQUIRE_HTTPS", "false")
    monkeypatch.delenv("DEVICE_CONTROL_MANIFEST_HMAC_KEY", raising=False)
    if admin_token:
        monkeypatch.setenv("DEVICE_CONTROL_ADMIN_TOKEN", admin_token)
    else:
        monkeypatch.delenv("DEVICE_CONTROL_ADMIN_TOKEN", raising=False)


def admin_token() -> str:
    return issue_token("admin-1", "tenant-a", roles=("platform_admin",))


def agent_token(tenant: str = "tenant-a", subject: str = "agent-1",
                scopes: tuple[str, ...] | None = None) -> str:
    return issue_token(
        subject, tenant,
        permissions=scopes or (
            "device.endpoint.read",
            "device.lease.acquire",
            "device.lease.release",
            "device.policy.evaluate",
            "device.approval.request",
            "device.command.submit",
            "device.command.read",
            "device.command.cancel",
            "device.event.read",
        ),
    )


def approver_token(tenant: str = "tenant-a", subject: str = "human-approver") -> str:
    return issue_token(subject, tenant, permissions=("device.approval.decide",
                                                     "device.command.read"))


def observed_capabilities(manifest_document: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    document = manifest_document or MANIFEST
    items = []
    for capability in document["capabilities"]:
        items.append({
            "id": capability["id"],
            "version": capability["version"],
            "input_schema": capability["input_schema"],
            "output_schema": capability["output_schema"],
            "risk_tier": capability["risk_tier"],
            "execution_locality": "device",
            "supports_idempotency": capability.get("supports_idempotency", False),
            "max_timeout_ms": capability.get("timeout_ms", 15000),
        })
    return items


def capability(capability_id: str = "app.launch", *,
               version: str = "1.0.0", risk_tier: str = "read",
               input_schema: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": capability_id,
        "version": version,
        "input_schema": input_schema or {"type": "object", "additionalProperties": True},
        "output_schema": {"type": "object"},
        "risk_tier": risk_tier,
        "execution_locality": "device",
        "supports_idempotency": True,
        "max_timeout_ms": 15000,
    }


def create_gateway(client, headers: dict[str, str], *, tenant: str,
                   gateway_id: str = "gw-1", endpoint_id: str | None = None,
                   device_id: str | None = None,
                   device_fingerprint: str | None = None,
                   manifest_document: dict[str, Any] | None = None) -> str:
    document = manifest_document or MANIFEST
    document_digest = gateway_manifest.digest(document)
    document_version = str(document["manifest_version"])
    created = client.post("/v1/gateways", json={
        "gateway_id": gateway_id,
        "protocol_version": "v1",
        "endpoint_id": endpoint_id,
        "device_id": device_id,
        "device_fingerprint": device_fingerprint,
        "adapter_inventory": [{
            "adapter_id": "fake-android", "version": "1.1.0",
            "capabilities": [item["id"] for item in document["capabilities"]],
        }],
    }, headers=headers)
    assert created.status_code == 201, created.text
    activated = client.post(f"/v1/gateways/{gateway_id}/activate", json={
        "enrollment_token": created.json()["enrollment_token"],
        "protocol_version": "v1",
    })
    assert activated.status_code == 200, activated.text
    credential = activated.json()["credential"]
    registered = client.put(f"/v1/gateways/{gateway_id}/manifest",
                            json=document, headers=headers)
    assert registered.status_code == 200, registered.text
    heartbeat = client.post(f"/v1/gateways/{gateway_id}/heartbeat", json={
        "status": "online",
        "protocol_version": "v1",
        "manifest_digest": document_digest,
        "manifest_version": document_version,
        "endpoint_id": endpoint_id,
        "device_id": device_id,
        "device_fingerprint": device_fingerprint,
        "queue_depth": 0,
    }, headers=bearer(credential))
    assert heartbeat.status_code == 200, heartbeat.text
    return credential


def create_endpoint(client, headers: dict[str, str], *, tenant: str,
                    endpoint_id: str = "phone-1", gateway_id: str = "gw-1",
                    capabilities: list[dict[str, Any]] | None = None,
                    device_id: str | None = None,
                    device_fingerprint: str | None = None) -> str:
    capabilities = capabilities or observed_capabilities()
    created = client.post("/v1/endpoints", json={
        "endpoint_id": endpoint_id,
        "tenant_ref": tenant,
        "gateway_id": gateway_id,
        "protocol_version": "v1",
        "capabilities": capabilities,
        "device_id": device_id,
        "device_fingerprint": device_fingerprint,
    }, headers=headers)
    assert created.status_code == 201, created.text
    credential = created.json()["credential"]
    heartbeat = client.post(f"/v1/endpoints/{endpoint_id}/heartbeat", json={
        "status": "online", "capabilities": capabilities,
    }, headers=bearer(credential))
    assert heartbeat.status_code == 200, heartbeat.text
    return credential


def setup_stack(client, *, tenant: str = "tenant-a", gateway_id: str = "gw-1",
                endpoint_id: str = "phone-1",
                capabilities: list[dict[str, Any]] | None = None,
                device_fingerprint: str = DEVICE_FINGERPRINT,
                manifest_document: dict[str, Any] | None = None) -> dict[str, Any]:
    platform = bearer(admin_token())
    document = manifest_document or MANIFEST
    device_id = f"device-{endpoint_id}"
    gateway_credential = create_gateway(
        client, platform, tenant=tenant, gateway_id=gateway_id,
        endpoint_id=endpoint_id, device_id=device_id,
        device_fingerprint=device_fingerprint, manifest_document=document,
    )
    create_endpoint(client, platform, tenant=tenant, endpoint_id=endpoint_id,
                    gateway_id=gateway_id,
                    capabilities=capabilities or observed_capabilities(document),
                    device_id=device_id, device_fingerprint=device_fingerprint)
    return {"tenant": tenant, "gateway_id": gateway_id, "endpoint_id": endpoint_id,
            "device_id": device_id, "device_fingerprint": device_fingerprint,
            "gateway_credential": gateway_credential, "platform": platform,
            "manifest_digest": gateway_manifest.digest(document)}


def acquire_lease(client, token: str, *, endpoint_id: str, task_ref: str = "task-1",
                  mode: str = "control", ttl_seconds: int = 600,
                  run_ref: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "endpoint_id": endpoint_id,
        "task_ref": task_ref,
        "mode": mode,
        "ttl_seconds": ttl_seconds,
    }
    if run_ref:
        payload["run_ref"] = run_ref
    lease = client.post("/v1/device-leases", json=payload, headers=bearer(token))
    assert lease.status_code == 201, lease.text
    return lease.json()


def command_body(*, endpoint_id: str, lease_id: str, idempotency_key: str = "idem-1",
                 capability_id: str = "app.launch", capability_version: str = "1.0.0",
                 input_payload: dict[str, Any] | None = None,
                 state_hash: str | None = None,
                 state_version: str | None = None,
                 approval_id: str | None = None,
                 approval_nonce: str | None = None,
                 intent: str = "Open the notes app",
                 task_ref: str = "task-1",
                 run_ref: str = "run-1",
                 deadline_seconds: int = 300) -> dict[str, Any]:
    from datetime import datetime, timedelta, timezone

    return {
        "endpoint_id": endpoint_id,
        "capability_id": capability_id,
        "capability_version": capability_version,
        "input": input_payload or {"app_id": "com.example.notes"},
        "intent": intent,
        "deadline": (datetime.now(timezone.utc) + timedelta(seconds=deadline_seconds)).isoformat(),
        "idempotency_key": idempotency_key,
        "lease_id": lease_id,
        "state_hash": state_hash,
        "state_version": state_version,
        "approval_id": approval_id,
        "approval_nonce": approval_nonce,
        "task_ref": task_ref,
        "run_ref": run_ref,
        "correlation_id": "corr-1",
    }
