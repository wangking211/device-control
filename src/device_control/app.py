from __future__ import annotations

import json
import hmac
import hashlib
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from jsonschema import Draft202012Validator, FormatChecker, RefResolver

from device_control import store
from device_control.policy import evaluate

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = ROOT / "contracts" / "v1"
SCHEMAS = {
    "endpoint": "device-endpoint.schema.json",
    "enrollment": "endpoint-enrollment.schema.json",
    "heartbeat": "endpoint-heartbeat.schema.json",
    "enrollment_receipt": "endpoint-receipt.schema.json",
    "invocation": "device-invocation.schema.json",
    "result": "device-result.schema.json",
}


def load_schema(name: str) -> dict[str, Any]:
    filename = SCHEMAS.get(name)
    if filename is None:
        raise KeyError(name)
    return json.loads((CONTRACT_DIR / filename).read_text(encoding="utf-8"))


def validate_contract(name: str, payload: dict[str, Any]) -> list[dict[str, str]]:
    schema = load_schema(name)
    store_schemas = {
        (CONTRACT_DIR / filename).resolve().as_uri(): load_schema(contract_name)
        for contract_name, filename in SCHEMAS.items()
        if (CONTRACT_DIR / filename).is_file()
    }
    resolver = RefResolver(base_uri=(CONTRACT_DIR / SCHEMAS[name]).resolve().as_uri(), referrer=schema, store=store_schemas)
    errors = sorted(
        Draft202012Validator(schema, resolver=resolver, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    return [
        {"path": "/" + "/".join(map(str, error.absolute_path)), "message": error.message}
        for error in errors
    ]


app = FastAPI(
    title="Device Control API",
    version="0.1.0",
    description=(
        "Independent device-control boundary. Device execution endpoints are not enabled "
        "until authenticated endpoint enrollment and policy enforcement are configured."
    ),
)


@app.get("/health/live", tags=["health"])
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready", tags=["health"])
def ready() -> dict[str, str]:
    missing = [filename for filename in SCHEMAS.values() if not (CONTRACT_DIR / filename).is_file()]
    if missing:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "missing_contracts": missing})
    return {"status": "ready", "contract_version": "v1"}


@app.get("/v1/contracts", tags=["contracts"])
def contract_catalog() -> dict[str, Any]:
    return {
        "version": "v1",
        "contracts": [
            {"name": name, "schema": f"/v1/contracts/{name}"} for name in SCHEMAS
        ],
    }


@app.get("/v1/contracts/{name}", tags=["contracts"])
def get_contract(name: str) -> dict[str, Any]:
    try:
        return load_schema(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract_not_found") from exc


@app.post("/v1/contracts/{name}/validate", tags=["contracts"])
def validate(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if name not in SCHEMAS:
        raise HTTPException(status_code=404, detail="contract_not_found")
    errors = validate_contract(name, payload)
    return {"valid": not errors, "errors": errors, "contract_version": "v1"}


def require_admin(authorization: str | None) -> None:
    expected = os.environ.get("DEVICE_CONTROL_ADMIN_TOKEN", "")
    if not expected or not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=503 if not expected else 401, detail="admin_auth_not_configured" if not expected else "unauthorized")
    if not hmac.compare_digest(authorization[7:], expected):
        raise HTTPException(status_code=401, detail="unauthorized")


def endpoint_credential(endpoint_id: str, authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer ") or not store.authenticate(endpoint_id, authorization[7:]):
        raise HTTPException(status_code=401, detail="endpoint_unauthorized")


@app.post("/v1/endpoints", tags=["endpoints"], status_code=201)
def enroll_endpoint(payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin(authorization)
    errors = validate_contract("enrollment", payload)
    if errors:
        raise HTTPException(status_code=422, detail={"code": "invalid_endpoint", "errors": errors})
    try:
        credential = store.enroll(endpoint_id=payload["endpoint_id"], tenant_ref=payload["tenant_ref"],
                                  node_ref=payload.get("node_ref"), capabilities=payload["capabilities"],
                                  observed_at=datetime.now(timezone.utc).isoformat())
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="endpoint_already_exists") from exc
        raise
    return {"endpoint_id": payload["endpoint_id"], "credential": credential, "status": "offline"}


@app.get("/v1/endpoints", tags=["endpoints"])
def endpoints(tenant_ref: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin(authorization)
    return {"items": store.list_endpoints(tenant_ref)}


@app.post("/v1/endpoints/{endpoint_id}/heartbeat", tags=["endpoints"])
def endpoint_heartbeat(endpoint_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    endpoint_credential(endpoint_id, authorization)
    payload = {**payload, "endpoint_id": endpoint_id, "tenant_ref": store.get_endpoint(endpoint_id)["tenant_ref"],
               "protocol_version": "v1", "observed_at": datetime.now(timezone.utc).isoformat()}
    errors = validate_contract("heartbeat", {"status": payload["status"], "capabilities": payload["capabilities"]})
    if errors:
        raise HTTPException(status_code=422, detail={"code": "invalid_endpoint", "errors": errors})
    store.heartbeat(endpoint_id, status=payload["status"], capabilities=payload["capabilities"], observed_at=payload["observed_at"])
    return {"endpoint_id": endpoint_id, "status": "accepted"}


@app.delete("/v1/endpoints/{endpoint_id}", tags=["endpoints"])
def revoke_endpoint(endpoint_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_admin(authorization)
    if not store.revoke(endpoint_id):
        raise HTTPException(status_code=404, detail="endpoint_not_found")
    return {"endpoint_id": endpoint_id, "status": "revoked"}


@app.post("/v1/device-leases", tags=["leases"], status_code=201)
def acquire_device_lease(payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin(authorization)
    required = {"endpoint_id", "tenant_ref", "task_ref", "holder_ref", "mode", "ttl_seconds"}
    if required - payload.keys() or payload.get("mode") not in {"read_only", "control"}:
        raise HTTPException(status_code=422, detail="invalid_lease_request")
    ttl = payload["ttl_seconds"]
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1 or ttl > 3600:
        raise HTTPException(status_code=422, detail="ttl_seconds_must_be_between_1_and_3600")
    now = datetime.now(timezone.utc)
    lease = store.acquire_lease(
        lease_id=secrets.token_urlsafe(18), endpoint_id=payload["endpoint_id"], tenant_ref=payload["tenant_ref"],
        task_ref=payload["task_ref"], run_ref=payload.get("run_ref"), holder_ref=payload["holder_ref"],
        mode=payload["mode"], expires_at=datetime.fromtimestamp(now.timestamp() + ttl, timezone.utc).isoformat(),
    )
    if lease is None:
        raise HTTPException(status_code=404, detail="endpoint_not_found_or_unavailable")
    if lease.get("conflict"):
        raise HTTPException(status_code=409, detail={"code": "device_busy", "holder_ref": lease["holder_ref"], "task_ref": lease["task_ref"]})
    return lease


@app.delete("/v1/device-leases/{lease_id}", tags=["leases"])
def release_device_lease(lease_id: str, tenant_ref: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_admin(authorization)
    if not store.release_lease(lease_id, tenant_ref):
        raise HTTPException(status_code=404, detail="lease_not_found")
    return {"lease_id": lease_id, "status": "released"}


@app.post("/v1/policy/evaluate", tags=["policy"])
def evaluate_policy(payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_admin(authorization)
    lease = store.active_lease(payload.get("lease_id", ""), payload.get("tenant_ref", ""), payload.get("endpoint_id", ""))
    if lease is None:
        raise HTTPException(status_code=403, detail="active_device_lease_required")
    if not payload.get("action_type") or not payload.get("intent"):
        raise HTTPException(status_code=422, detail="action_type_and_intent_required")
    return evaluate(payload, lease_mode=lease["mode"])


@app.post("/v1/approvals", tags=["approvals"], status_code=201)
def request_approval(payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_admin(authorization)
    required = {"tenant_ref", "endpoint_id", "lease_id", "requester_ref", "action"}
    if required - payload.keys() or not isinstance(payload.get("action"), dict):
        raise HTTPException(status_code=422, detail="invalid_approval_request")
    lease = store.active_lease(payload["lease_id"], payload["tenant_ref"], payload["endpoint_id"])
    if not lease:
        raise HTTPException(status_code=403, detail="active_device_lease_required")
    digest = hashlib.sha256(json.dumps(payload["action"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    approval_id = secrets.token_urlsafe(18)
    expires_at = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() + 300, timezone.utc).isoformat()
    store.create_approval(approval_id, payload["tenant_ref"], payload["endpoint_id"], payload["lease_id"], payload["requester_ref"], digest, expires_at)
    return {"approval_id": approval_id, "status": "pending", "action_sha256": digest, "expires_at": expires_at}


@app.post("/v1/approvals/{approval_id}/decision", tags=["approvals"])
def decide_approval(approval_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_admin(authorization)
    if not payload.get("tenant_ref") or not payload.get("approver_ref") or not isinstance(payload.get("approved"), bool):
        raise HTTPException(status_code=422, detail="invalid_approval_decision")
    if not store.decide_approval(approval_id, payload["tenant_ref"], payload["approver_ref"], payload["approved"]):
        raise HTTPException(status_code=409, detail="approval_not_decidable")
    return {"approval_id": approval_id, "status": "approved" if payload["approved"] else "denied"}


@app.post("/v1/approvals/{approval_id}/consume", tags=["approvals"])
def consume_approval(approval_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_admin(authorization)
    action = payload.get("action")
    if not isinstance(action, dict):
        raise HTTPException(status_code=422, detail="action_required")
    digest = hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    consumed = store.consume_approval(approval_id, payload.get("tenant_ref", ""), payload.get("endpoint_id", ""), payload.get("lease_id", ""), digest)
    if not consumed:
        raise HTTPException(status_code=409, detail="approval_stale_or_already_consumed")
    return {"approval_id": approval_id, "status": "consumed"}
