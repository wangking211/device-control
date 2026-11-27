"""FastAPI control plane for Device Control.

Ownership boundary: this process owns device/gateway identity, endpoint
inventory, leases, policy, approvals, command coordination and evidence
metadata. It never runs ADB, drivers or device shell commands.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import secrets
import threading
import time
from datetime import timedelta
from typing import Any, Callable

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response

from device_control import config, contracts, identity, metrics, policy, store
from device_control import evidence as evidence_store
from device_control.canonical import (
    approval_binding_digest,
    manifest_digest,
    sha256_hex,
    verify_manifest_signature,
)
from device_control.commands import (
    RESULT_STATUSES,
    VERIFICATION_METHODS,
)
from device_control.errors import (
    DeviceControlError,
    conflict,
    dependency_unavailable,
    forbidden,
    hidden,
    invalid,
    rate_limited,
    unauthenticated,
)
from device_control.iot import ha_pilot

app = FastAPI(
    title="Device Control API",
    version="0.2.0",
    description=(
        "Governed device-control boundary. Device execution is performed by a "
        "separately deployed gateway, never by this process."
    ),
)


# ---------------------------------------------------------------------------
# Cross-cutting middleware
# ---------------------------------------------------------------------------


class _RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str, *, limit_per_minute: int) -> None:
        now = time.monotonic()
        window_start = now - 60.0
        with self._lock:
            hits = [hit for hit in self._hits.get(key, []) if hit > window_start]
            if len(hits) >= limit_per_minute:
                self._hits[key] = hits
                raise rate_limited(1)
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 4096:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > window_start}


_RATE_LIMITER = _RateLimiter()


@app.middleware("http")
async def limits_middleware(request: Request, call_next: Callable[..., Any]):
    if request.url.path.startswith("/v1/"):
        if config.require_https():
            forwarded = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
            host = request.url.hostname or ""
            if forwarded != "https" and request.url.scheme != "https" and host not in {
                "127.0.0.1", "::1", "localhost", "testserver",
            }:
                return JSONResponse(status_code=426, content={"code": "https_required"})
        declared = request.headers.get("content-length")
        limit = config.max_request_bytes()
        if request.url.path.endswith("/evidence") and request.method == "POST":
            limit = config.evidence_max_bytes()
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse(
                status_code=413,
                content={"code": "payload_too_large",
                         "detail": {"max_bytes": limit}},
            )
        token = request.headers.get("authorization", "")
        rate_key = sha256_hex(token)[:32] if token else (request.client.host if request.client else "anonymous")
        try:
            _RATE_LIMITER.check(rate_key, limit_per_minute=config.rate_limit_per_minute())
        except DeviceControlError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.envelope(),
                                headers=exc.headers)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    metrics.increment("http_requests_total")
    if response.status_code >= 500:
        metrics.increment("http_5xx_total")
    return response


@app.exception_handler(DeviceControlError)
async def device_control_error(_: Request, exc: DeviceControlError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.envelope(), headers=exc.headers)


@app.exception_handler(evidence_store.EvidenceStoreError)
async def evidence_store_error(_: Request, exc: evidence_store.EvidenceStoreError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"code": "evidence_storage_unavailable"})


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise unauthenticated("authentication_required")
    token = authorization[7:].strip()
    if not token:
        raise unauthenticated("authentication_required")
    return token


def _principal(authorization: str | None) -> identity.Principal:
    token = _bearer(authorization)
    if config.bootstrap_allowed() and hmac.compare_digest(token, config.bootstrap_token()):
        return identity.bootstrap_principal()
    if config.is_production() and config.bootstrap_token() and hmac.compare_digest(
        token, config.bootstrap_token()
    ):
        # Never let a provisioning secret survive into production.
        raise unauthenticated("bootstrap_token_rejected")
    try:
        return identity.verify_bearer(token)
    except identity.IdentityUnavailable as exc:
        metrics.increment("identity_unavailable_total")
        raise dependency_unavailable() from exc
    except identity.InvalidIdentity as exc:
        metrics.increment("auth_failure_total")
        raise unauthenticated(exc.code) from exc


def _require_scope(authorization: str | None, scope: str) -> identity.Principal:
    principal = _principal(authorization)
    if not principal.has_scope(scope):
        raise forbidden("insufficient_scope")
    return principal


def _tenant(principal: identity.Principal, claimed: str | None = None) -> str:
    """Derive the tenant from verified claims.

    The bootstrap principal is a local provisioning identity with no tenant;
    it must name the tenant it provisions. Any other principal that supplies a
    different tenant is rejected instead of silently cross-tenant acting.
    """

    if principal.bootstrap:
        if not claimed:
            raise invalid("tenant_ref_required_for_provisioning")
        return claimed
    actual = principal.require_tenant()
    if claimed and claimed != actual:
        raise forbidden("tenant_scope_mismatch")
    return actual


def _gateway_principal(gateway_id: str, authorization: str | None) -> dict[str, Any]:
    gateway = store.authenticate_gateway(gateway_id, _bearer(authorization))
    if gateway is None:
        raise unauthenticated("gateway_unauthorized")
    return gateway


def _enforce_endpoint_scope(principal: identity.Principal, endpoint_id: str) -> None:
    """A service token bound to one endpoint may not act on another."""

    if (principal.principal_type == "service"
            and principal.resource_type == "device_endpoint"
            and principal.resource_id
            and principal.resource_id != endpoint_id):
        raise forbidden("service_token_resource_scope_mismatch")


def _endpoint_record(endpoint_id: str, authorization: str | None) -> dict[str, Any]:
    endpoint = store.authenticate_endpoint(endpoint_id, _bearer(authorization))
    if endpoint is None:
        raise unauthenticated("endpoint_unauthorized")
    return endpoint


def _correlation(payload: dict[str, Any], header: str | None) -> str:
    value = header or payload.get("correlation_id") or ""
    return str(value).strip() or f"corr_{secrets.token_urlsafe(12)}"


# ---------------------------------------------------------------------------
# Health and contracts
# ---------------------------------------------------------------------------


@app.get("/health/live", tags=["health"])
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready", tags=["health"])
def ready() -> dict[str, Any]:
    missing = contracts.missing_contracts()
    reasons: list[str] = []
    if missing:
        reasons.append("missing_contracts")
    try:
        db = store.connect()
        try:
            db.execute("SELECT 1").fetchone()
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - readiness must not leak internals
        reasons.append("database_unavailable")
    if config.is_production() and not config.snapshot().identity_configured:
        reasons.append("identity_not_configured")
    if reasons:
        raise DeviceControlError(503, "not_ready", detail={"reasons": reasons,
                                                           "missing_contracts": missing})
    return {"status": "ready", "contract_version": "v1", "profile": config.profile()}


@app.get("/v1/contracts", tags=["contracts"])
def contract_catalog() -> dict[str, Any]:
    return {
        "version": "v1",
        "contracts": [
            {"name": name, "schema": f"/v1/contracts/{name}"} for name in contracts.SCHEMAS
        ],
    }


@app.get("/v1/contracts/{name}", tags=["contracts"])
def get_contract(name: str) -> dict[str, Any]:
    try:
        return contracts.load_schema(name)
    except KeyError as exc:
        raise hidden() from exc


@app.post("/v1/contracts/{name}/validate", tags=["contracts"])
def validate(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if name not in contracts.SCHEMAS:
        raise hidden()
    errors = contracts.validate_contract(name, payload)
    return {"valid": not errors, "errors": errors, "contract_version": "v1"}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/v1/endpoints", tags=["endpoints"], status_code=201)
def enroll_endpoint(
    payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_WRITE)
    errors = contracts.validate_contract("enrollment", payload)
    if errors:
        raise invalid("invalid_endpoint", errors)
    tenant = _tenant(principal, payload.get("tenant_ref"))
    credential = store.enroll_endpoint(
        tenant=tenant,
        endpoint_id=payload["endpoint_id"],
        node_ref=payload.get("node_ref"),
        gateway_id=payload.get("gateway_id"),
        capabilities=payload["capabilities"],
        metadata=payload.get("metadata"),
        device_id=payload.get("device_id"),
        device_fingerprint=payload.get("device_fingerprint"),
    )
    return {"endpoint_id": payload["endpoint_id"], "credential": credential, "status": "offline"}


@app.get("/v1/endpoints", tags=["endpoints"])
def endpoints(
    tenant_ref: str | None = None,
    gateway_id: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_READ)
    tenant = _tenant(principal, tenant_ref)
    return {"items": store.list_endpoints(tenant, gateway_id=gateway_id)}


@app.get("/v1/endpoints/{endpoint_id}", tags=["endpoints"])
def endpoint_detail(
    endpoint_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_READ)
    _enforce_endpoint_scope(principal, endpoint_id)
    endpoint = store.get_endpoint(_tenant(principal, tenant_ref), endpoint_id)
    if endpoint is None:
        raise hidden()
    return endpoint


@app.get("/v1/endpoints/{endpoint_id}/capabilities", tags=["endpoints"])
def endpoint_capabilities(
    endpoint_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_READ)
    _enforce_endpoint_scope(principal, endpoint_id)
    endpoint = store.get_endpoint(_tenant(principal, tenant_ref), endpoint_id)
    if endpoint is None:
        raise hidden()
    return {"endpoint_id": endpoint_id, "capabilities": endpoint["capabilities"],
            "observed_at": endpoint["observed_at"]}


@app.post("/v1/endpoints/{endpoint_id}/heartbeat", tags=["endpoints"])
def endpoint_heartbeat(
    endpoint_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, str]:
    _endpoint_record(endpoint_id, authorization)
    errors = contracts.validate_contract(
        "heartbeat", {"status": payload.get("status"), "capabilities": payload.get("capabilities")}
    )
    if errors:
        raise invalid("invalid_heartbeat", errors)
    store.heartbeat_endpoint(
        endpoint_id, status=payload["status"], capabilities=payload["capabilities"]
    )
    return {"endpoint_id": endpoint_id, "status": "accepted"}


@app.post("/v1/endpoints/{endpoint_id}/credentials/rotate", tags=["endpoints"])
def rotate_endpoint_credential(
    endpoint_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_WRITE)
    return {"endpoint_id": endpoint_id,
            "credential": store.rotate_endpoint_credential(
                _tenant(principal, tenant_ref), endpoint_id)}


@app.delete("/v1/endpoints/{endpoint_id}", tags=["endpoints"])
def revoke_endpoint(
    endpoint_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_WRITE)
    if not store.revoke_endpoint(_tenant(principal, tenant_ref), endpoint_id):
        raise hidden()
    return {"endpoint_id": endpoint_id, "status": "revoked"}


# ---------------------------------------------------------------------------
# Gateways
# ---------------------------------------------------------------------------


@app.post("/v1/gateways", tags=["gateways"], status_code=201)
def create_gateway(
    payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_WRITE)
    errors = contracts.validate_contract("gateway_enrollment", payload)
    if errors:
        raise invalid("invalid_gateway", errors)
    tenant = _tenant(principal, payload.get("tenant_ref"))
    return store.create_gateway(
        tenant=tenant,
        gateway_id=payload["gateway_id"],
        display_name=payload.get("display_name"),
        protocol_version=payload["protocol_version"],
        adapter_inventory=payload["adapter_inventory"],
        endpoint_id=payload.get("endpoint_id"),
        device_id=payload.get("device_id"),
        device_fingerprint=payload.get("device_fingerprint"),
    )


@app.get("/v1/gateways", tags=["gateways"])
def gateways(
    tenant_ref: str | None = None, authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    return {"items": store.list_gateways(_tenant(principal, tenant_ref))}


@app.get("/v1/gateways/{gateway_id}", tags=["gateways"])
def gateway_detail(
    gateway_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    gateway = store.get_gateway(_tenant(principal, tenant_ref), gateway_id)
    if gateway is None:
        raise hidden()
    return gateway


@app.put("/v1/gateways/{gateway_id}/manifest", tags=["gateways"])
def register_gateway_manifest(
    gateway_id: str,
    payload: dict[str, Any],
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_WRITE)
    errors = contracts.validate_contract("manifest", payload)
    if errors:
        raise invalid("invalid_manifest", errors)
    digest = manifest_digest(payload)
    signature = payload.get("signature")
    algorithm = payload.get("signature_algorithm")
    public_key_pem = config.manifest_public_key()
    require_signature = config.manifest_require_signature()
    key_id = str(payload.get("key_id") or "")
    allowed_keys = config.manifest_allowed_key_ids()
    if allowed_keys and key_id not in allowed_keys:
        raise invalid("manifest_key_unknown")
    if public_key_pem:
        if algorithm != "ed25519" or not isinstance(signature, str):
            raise invalid("manifest_signature_required")
        try:
            from cryptography.hazmat.primitives import serialization

            key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            key.verify(base64.b64decode(signature), digest.encode("ascii"))  # type: ignore[call-arg]
        except Exception as exc:  # noqa: BLE001 - fail closed
            raise invalid("invalid_manifest_signature") from exc
    elif config.manifest_hmac_key() and config.manifest_allow_hmac():
        if algorithm not in {None, "hmac-sha256"}:
            raise invalid("unsupported_manifest_signature_algorithm")
        if not isinstance(signature, str) or not verify_manifest_signature(
            digest, signature, config.manifest_hmac_key()
        ):
            raise invalid("invalid_manifest_signature")
    elif require_signature:
        raise dependency_unavailable("manifest_public_key_unconfigured")
    expires_at = payload.get("expires_at")
    if expires_at:
        try:
            if store.parse_timestamp(expires_at) <= store.now():
                raise invalid("manifest_expired")
        except (ValueError, TypeError) as exc:
            raise invalid("manifest_invalid_expiry") from exc
    issued_at = payload.get("issued_at")
    if issued_at:
        try:
            if store.parse_timestamp(issued_at) > store.now() + timedelta(minutes=5):
                raise invalid("manifest_issued_in_future")
        except (ValueError, TypeError) as exc:
            raise invalid("manifest_invalid_issued_at") from exc
    return store.register_gateway_manifest(
        tenant=_tenant(principal, tenant_ref),
        gateway_id=gateway_id,
        manifest=payload,
        digest=digest,
        signature=signature if isinstance(signature, str) else None,
        actor=principal.subject,
        actor_type=principal.principal_type,
    )


@app.get("/v1/gateways/{gateway_id}/manifest", tags=["gateways"])
def get_gateway_manifest(
    gateway_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    manifest = store.get_gateway_manifest(_tenant(principal, tenant_ref), gateway_id)
    if manifest is None:
        raise hidden()
    return manifest


@app.get("/v1/gateways/{gateway_id}/diagnostics", tags=["gateways"])
def gateway_diagnostics(
    gateway_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    gateway = store.get_gateway(_tenant(principal, tenant_ref), gateway_id)
    if gateway is None:
        raise hidden()
    heartbeat = gateway.get("last_heartbeat_at")
    age = None
    if heartbeat:
        age = max(0.0, (store.now() - store.parse_timestamp(heartbeat)).total_seconds())
    return {
        "gateway_id": gateway_id,
        "status": gateway["status"],
        "heartbeat_age_seconds": age,
        "endpoint_id": gateway.get("endpoint_id"),
        "device_id": gateway.get("device_id"),
        "device_fingerprint": gateway.get("device_fingerprint"),
        "manifest_version": gateway.get("manifest_version"),
        "manifest_digest": gateway.get("manifest_digest"),
        "reported_manifest_digest": gateway.get("reported_manifest_digest"),
        "queue_depth": gateway.get("queue_depth"),
        "queue_age_seconds": gateway.get("queue_age_seconds"),
        "last_error": gateway.get("last_error"),
        "health": gateway.get("health"),
        "adapter_inventory": gateway.get("adapter_inventory"),
        "last_seen_version": gateway.get("last_seen_version"),
    }


@app.post("/v1/gateways/{gateway_id}/activate", tags=["gateways"])
def activate_gateway(gateway_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    errors = contracts.validate_contract("gateway_activation", payload)
    if errors:
        raise invalid("invalid_gateway_activation", errors)
    return store.activate_gateway(
        gateway_id=gateway_id,
        enrollment_token=payload["enrollment_token"],
        platform=payload.get("platform"),
    )


@app.post("/v1/gateways/{gateway_id}/heartbeat", tags=["gateways"])
def gateway_heartbeat(
    gateway_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    _gateway_principal(gateway_id, authorization)
    errors = contracts.validate_contract("gateway_heartbeat", payload)
    if errors:
        raise invalid("invalid_gateway_heartbeat", errors)
    return store.heartbeat_gateway(
        gateway_id=gateway_id,
        status=payload["status"],
        adapter_inventory=payload.get("adapter_inventory"),
        version=payload.get("agent_version"),
        manifest_digest=payload.get("manifest_digest"),
        manifest_version=payload.get("manifest_version"),
        endpoint_id=payload.get("endpoint_id"),
        device_id=payload.get("device_id"),
        device_fingerprint=payload.get("device_fingerprint"),
        health=payload.get("health"),
        queue_depth=payload.get("queue_depth"),
        queue_age_seconds=payload.get("queue_age_seconds"),
    )


@app.post("/v1/gateways/{gateway_id}/credentials/rotate", tags=["gateways"])
def rotate_gateway_credential(
    gateway_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_WRITE)
    return store.rotate_gateway_credential(_tenant(principal, tenant_ref), gateway_id)


@app.delete("/v1/gateways/{gateway_id}", tags=["gateways"])
def revoke_gateway(
    gateway_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_WRITE)
    if not store.revoke_gateway(_tenant(principal, tenant_ref), gateway_id):
        raise hidden()
    return {"gateway_id": gateway_id, "status": "revoked"}


# ---------------------------------------------------------------------------
# Leases
# ---------------------------------------------------------------------------


@app.post("/v1/device-leases", tags=["leases"], status_code=201)
def acquire_device_lease(
    payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_LEASE_ACQUIRE)
    required = {"endpoint_id", "task_ref", "mode", "ttl_seconds"}
    if required - payload.keys() or payload.get("mode") not in {"read_only", "control"}:
        raise invalid("invalid_lease_request")
    ttl = payload["ttl_seconds"]
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1 or ttl > 3600:
        raise invalid("ttl_seconds_must_be_between_1_and_3600")
    tenant = _tenant(principal, payload.get("tenant_ref"))
    holder = payload.get("holder_ref") if principal.bootstrap else principal.subject
    _enforce_endpoint_scope(principal, payload["endpoint_id"])
    return store.acquire_lease(
        tenant=tenant,
        endpoint_id=payload["endpoint_id"],
        task_ref=payload["task_ref"],
        run_ref=payload.get("run_ref"),
        holder_ref=str(holder or principal.subject),
        holder_type=principal.principal_type,
        mode=payload["mode"],
        ttl_seconds=ttl,
    )


@app.delete("/v1/device-leases/{lease_id}", tags=["leases"])
def release_device_lease(
    lease_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    principal = _require_scope(authorization, identity.SCOPE_LEASE_RELEASE)
    if not store.release_lease(_tenant(principal, tenant_ref), lease_id,
                                actor=principal.subject):
        raise hidden()
    return {"lease_id": lease_id, "status": "released"}


# ---------------------------------------------------------------------------
# Policy and approvals
# ---------------------------------------------------------------------------


@app.post("/v1/policy/evaluate", tags=["policy"])
def evaluate_policy(
    payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_POLICY_EVALUATE)
    tenant = _tenant(principal, payload.get("tenant_ref"))
    _enforce_endpoint_scope(principal, str(payload.get("endpoint_id") or ""))
    lease = store.active_lease(tenant, payload.get("lease_id", ""), payload.get("endpoint_id", ""))
    if lease is None:
        raise forbidden("active_device_lease_required")
    if not payload.get("action_type") or not payload.get("intent"):
        raise invalid("action_type_and_intent_required")
    action = {key: value for key, value in payload.items() if key not in {"tenant_ref", "lease_id"}}
    result = policy.evaluate(
        action,
        lease_mode=lease["mode"],
        principal_scopes=principal.scopes,
        risk_tier=payload.get("risk_tier"),
    )
    return {**result, "lease_mode": lease["mode"]}


@app.post("/v1/approvals", tags=["approvals"], status_code=201)
def request_approval(
    payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_APPROVAL_REQUEST)
    enabled = {"endpoint_id", "lease_id", "capability_id", "capability_version", "input", "intent"}
    if enabled - payload.keys():
        raise invalid("invalid_approval_request")
    tenant = _tenant(principal, payload.get("tenant_ref"))
    _enforce_endpoint_scope(principal, payload["endpoint_id"])
    endpoint = store.get_endpoint(tenant, payload["endpoint_id"])
    if endpoint is None:
        raise hidden()
    capability = _find_capability(endpoint, payload["capability_id"], payload["capability_version"])
    resolved = store.resolve_manifest_capability(
        tenant, payload["endpoint_id"], payload["capability_id"], payload["capability_version"]
    )
    if capability is None or resolved is None:
        raise conflict("unsupported_capability")
    gateway, manifest_capability = resolved
    schema_errors = contracts.validate_instance(
        manifest_capability.get("input_schema") or {}, payload["input"]
    )
    if schema_errors:
        raise invalid("invalid_capability_parameters", schema_errors)
    lease = store.active_lease(tenant, payload["lease_id"], payload["endpoint_id"])
    if lease is None:
        raise conflict("active_device_lease_required")
    operation = str(manifest_capability.get("operation") or payload["capability_id"])
    risk_tier = str(manifest_capability.get("risk_tier") or "write")
    requires_state = bool(manifest_capability.get("requires_state"))
    if requires_state and (not payload.get("state_hash") or not payload.get("state_version")):
        raise invalid("state_hash_and_version_required")
    result = policy.evaluate(
        {"action_type": operation, "intent": payload["intent"],
         "app_id": payload["input"].get("app_id"),
         "target_type": payload["input"].get("target_type")},
        lease_mode=lease["mode"],
        principal_scopes=principal.scopes,
        risk_tier=risk_tier,
    )
    if result["decision"] == "deny":
        raise forbidden("policy_denied")
    return store.create_approval(
        tenant=tenant,
        endpoint_id=payload["endpoint_id"],
        lease_id=payload["lease_id"],
        requester=principal.subject,
        requester_type=principal.principal_type,
        capability_id=payload["capability_id"],
        capability_version=payload["capability_version"],
        operation=operation,
        parameters=payload["input"],
        intent=payload["intent"],
        state_hash=payload.get("state_hash"),
        state_version=payload.get("state_version"),
        policy_version=result["policy_version"],
        risk_tier=risk_tier,
        manifest_digest_value=gateway["manifest_digest"],
        require_state=requires_state,
    )


@app.post("/v1/approvals/{approval_id}/decision", tags=["approvals"])
def decide_approval(
    approval_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_APPROVAL_DECIDE)
    if not isinstance(payload.get("approved"), bool):
        raise invalid("invalid_approval_decision")
    # Any caller-supplied approver_ref is ignored: the approver is the verified
    # principal, and a forged value cannot influence the decision.
    return store.decide_approval(
        tenant=_tenant(principal, payload.get("tenant_ref")),
        approval_id=approval_id,
        approver=principal.subject,
        approver_type=principal.principal_type,
        approved=payload["approved"],
        reason=payload.get("reason"),
    )


@app.post("/v1/approvals/{approval_id}/consume", tags=["approvals"])
def consume_approval(
    approval_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_APPROVAL_DECIDE)
    tenant = _tenant(principal, payload.get("tenant_ref"))
    approval = store.get_approval(tenant, approval_id)
    if approval is None:
        raise hidden()
    if approval["capability_id"]:
        required = {"endpoint_id", "lease_id", "capability_id", "capability_version", "input",
                    "intent", "state_hash", "state_version", "approval_nonce"}
        if required - payload.keys():
            raise invalid("approval_binding_required")
        binding = {
            "tenant_ref": tenant,
            "endpoint_id": payload["endpoint_id"],
            "device_id": approval.get("device_id"),
            "device_fingerprint": approval.get("device_fingerprint"),
            "gateway_id": approval["gateway_id"],
            "lease_id": payload["lease_id"],
            "capability_id": payload["capability_id"],
            "capability_version": payload["capability_version"],
            "operation": approval.get("operation", ""),
            "manifest_digest": approval.get("manifest_digest", ""),
            "approval_nonce": payload["approval_nonce"],
            "state_version": payload.get("state_version"),
            "action_digest": approval_binding_digest(
                tenant_ref=tenant,
                endpoint_id=payload["endpoint_id"],
                gateway_id=approval["gateway_id"],
                capability_id=payload["capability_id"],
                capability_version=payload["capability_version"],
                operation=approval.get("operation", ""),
                parameters=payload["input"],
                intent=payload["intent"],
                requester_ref=approval["requester_ref"],
                lease_id=payload["lease_id"],
                policy_version=approval["policy_version"],
                state_hash=payload.get("state_hash"),
                device_id=approval.get("device_id"),
                device_fingerprint=approval.get("device_fingerprint"),
                manifest_digest_value=approval.get("manifest_digest", ""),
                state_version=payload.get("state_version"),
                approval_nonce=payload["approval_nonce"],
            ),
            "state_hash": payload.get("state_hash"),
        }
    else:  # legacy approval created before DC-002; exact action digest only
        action = payload.get("action")
        if not isinstance(action, dict):
            raise invalid("action_required")
        binding = {
            "tenant_ref": tenant,
            "endpoint_id": payload.get("endpoint_id", approval["endpoint_id"]),
            "gateway_id": approval["gateway_id"],
            "lease_id": payload.get("lease_id", approval["lease_id"]),
            "capability_id": "",
            "capability_version": "",
            "action_digest": sha256_hex(
                json.dumps(action, sort_keys=True, separators=(",", ":"))
            ),
            "state_hash": None,
        }
    return store.consume_approval(
        tenant=tenant, approval_id=approval_id, binding=binding,
        actor=principal.subject, actor_type=principal.principal_type,
    )


# ---------------------------------------------------------------------------
# IoT platform pilot (Home Assistant)
# ---------------------------------------------------------------------------


@app.post("/v1/platform-instances", tags=["iot"], status_code=201)
def create_platform_instance(
    payload: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_WRITE)
    tenant = _tenant(principal, payload.get("tenant_ref"))
    required = {"platform_instance_id", "adapter_id", "base_url", "secret_ref"}
    if required - payload.keys():
        raise invalid("invalid_platform_instance")
    if payload["adapter_id"] != "home-assistant":
        raise invalid("unsupported_adapter")
    if config.is_production():
        # DC-012 pilot creation is not enabled in production until the signed
        # manifest/platform workflow and DC-010 gates are approved.
        raise dependency_unavailable("platform_pilot_not_enabled_in_production")
    platform_instance_id = str(payload["platform_instance_id"])
    gateway_id = f"ha-{platform_instance_id}"
    document = ha_pilot.manifest_document()
    digest = manifest_digest(document)
    created = store.create_gateway(
        tenant=tenant, gateway_id=gateway_id,
        display_name=f"Home Assistant {platform_instance_id}",
        protocol_version="v1",
        adapter_inventory=[{"adapter_id": "home-assistant", "version": "1.0.0",
                            "capabilities": list(ha_pilot.CAPABILITY_IDS)}],
    )
    activated = store.activate_gateway(
        gateway_id=gateway_id, enrollment_token=created["enrollment_token"],
        platform={"adapter": "home-assistant"},
    )
    store.register_gateway_manifest(
        tenant=tenant, gateway_id=gateway_id, manifest=document, digest=digest,
        signature=None, actor=principal.subject, actor_type=principal.principal_type,
    )
    store.heartbeat_gateway(
        gateway_id=gateway_id, status="online", adapter_inventory=None, version="1.0.0",
        manifest_digest=digest, manifest_version=str(document["manifest_version"]),
        endpoint_id=None, device_id=None, device_fingerprint=None, health={"adapter": "home-assistant"},
    )
    record = store.create_platform_instance(
        tenant=tenant, platform_instance_id=platform_instance_id,
        adapter_id="home-assistant", base_url=str(payload["base_url"]),
        secret_ref=str(payload["secret_ref"]),
        platform_version=str(payload.get("platform_version") or ""),
        gateway_id=gateway_id,
    )
    return {**record, "gateway_id": gateway_id,
            "gateway_credential": activated["credential"]}


@app.get("/v1/platform-instances", tags=["iot"])
def platform_instances(
    tenant_ref: str | None = None, authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    return {"items": store.list_platform_instances(_tenant(principal, tenant_ref))}


@app.get("/v1/platform-instances/{platform_instance_id}", tags=["iot"])
def platform_instance_detail(
    platform_instance_id: str, tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    record = store.get_platform_instance(_tenant(principal, tenant_ref), platform_instance_id)
    if record is None:
        raise hidden()
    return record


@app.delete("/v1/platform-instances/{platform_instance_id}", tags=["iot"])
def disable_platform_instance(
    platform_instance_id: str, tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_WRITE)
    if not store.disable_platform_instance(_tenant(principal, tenant_ref), platform_instance_id):
        raise hidden()
    return {"platform_instance_id": platform_instance_id, "status": "disabled"}


@app.post("/v1/platform-instances/{platform_instance_id}/discover", tags=["iot"])
def sync_platform_devices(
    platform_instance_id: str,
    payload: dict[str, Any],
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_WRITE)
    devices = payload.get("devices")
    if not isinstance(devices, list) or any(not isinstance(item, dict) for item in devices):
        raise invalid("devices_required")
    items = store.sync_discovered_devices(
        tenant=_tenant(principal, tenant_ref), platform_instance_id=platform_instance_id,
        devices=devices,
    )
    return {"items": items, "trust_state": "pending"}


@app.get("/v1/iot-devices", tags=["iot"])
def iot_devices(
    platform_instance_id: str | None = None,
    trust_state: str | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_READ)
    return {"items": store.list_iot_devices(
        _tenant(principal, tenant_ref), platform_instance_id=platform_instance_id,
        trust_state=trust_state,
    )}


@app.get("/v1/iot-devices/{device_id}", tags=["iot"])
def iot_device_detail(
    device_id: str, tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_READ)
    device = store.get_iot_device(_tenant(principal, tenant_ref), device_id)
    if device is None:
        raise hidden()
    return device


@app.post("/v1/iot-devices/{device_id}/claim", tags=["iot"])
def claim_iot_device(
    device_id: str,
    payload: dict[str, Any] | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_WRITE)
    tenant = _tenant(principal, tenant_ref)
    device = store.get_iot_device(tenant, device_id)
    if device is None:
        raise hidden()
    requested = (payload or {}).get("capability_ids") or list(ha_pilot.READ_CAPABILITIES)
    if not isinstance(requested, list) or any(not isinstance(item, str) for item in requested):
        raise invalid("invalid_capability_ids")
    endpoint_id = f"ep-{device_id.replace(':', '-')}"
    capabilities = ha_pilot.endpoint_capabilities(set(requested))
    if not capabilities:
        raise invalid("no_supported_capabilities")
    platform = store.get_platform_instance(tenant, device["platform_instance_id"])
    if platform is None or platform["status"] != "configured":
        raise conflict("platform_instance_unavailable")
    store.enroll_endpoint(
        tenant=tenant, endpoint_id=endpoint_id, node_ref=None,
        gateway_id=platform["gateway_id"],
        capabilities=capabilities, device_id=device_id,
        device_fingerprint=f"ha:{device['native_id']}",
    )
    store.heartbeat_endpoint(endpoint_id, status="online", capabilities=capabilities)
    claimed = store.claim_iot_device(
        tenant=tenant, device_id=device_id, capability_ids=list(requested),
        endpoint_id=endpoint_id,
    )
    return {**claimed, "endpoint_id": endpoint_id, "capabilities": capabilities}


@app.get("/v1/iot-devices/{device_id}/twin", tags=["iot"])
def iot_device_twin(
    device_id: str, tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_READ)
    twin = store.get_twin(_tenant(principal, tenant_ref), device_id)
    if twin is None:
        raise hidden()
    return twin


@app.post("/v1/iot-devices/{device_id}/twin", tags=["iot"])
def update_iot_device_twin(
    device_id: str,
    payload: dict[str, Any],
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_ENDPOINT_WRITE)
    tenant = _tenant(principal, tenant_ref)
    if store.get_iot_device(tenant, device_id) is None:
        raise hidden()
    return store.upsert_twin(
        tenant=tenant, device_id=device_id,
        desired=payload.get("desired"), reported=payload.get("reported"),
        observed=payload.get("observed"),
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _find_capability(endpoint: dict[str, Any], capability_id: str,
                     capability_version: str) -> dict[str, Any] | None:
    for capability in endpoint["capabilities"]:
        if capability.get("id") == capability_id and capability.get("version") == capability_version:
            return capability
    return None


@app.post("/v1/commands", tags=["commands"], status_code=201)
def submit_command(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_SUBMIT)
    errors = contracts.validate_contract("command", payload)
    if errors:
        raise invalid("invalid_command", errors)
    tenant = _tenant(principal, payload.get("tenant_ref"))
    _enforce_endpoint_scope(principal, payload["endpoint_id"])
    endpoint = store.get_endpoint(tenant, payload["endpoint_id"])
    if endpoint is None:
        raise hidden()
    capability = _find_capability(endpoint, payload["capability_id"], payload["capability_version"])
    resolved = store.resolve_manifest_capability(
        tenant, payload["endpoint_id"], payload["capability_id"], payload["capability_version"]
    )
    if capability is None or resolved is None:
        raise conflict("unsupported_capability")
    _, manifest_capability = resolved
    schema_errors = contracts.validate_instance(
        manifest_capability.get("input_schema") or {}, payload["input"]
    )
    if schema_errors:
        raise invalid("invalid_capability_parameters", schema_errors)
    lease = store.active_lease(tenant, payload["lease_id"], payload["endpoint_id"])
    if lease is None:
        raise conflict("active_device_lease_required")
    correlation_id = _correlation(payload, x_correlation_id)
    store.maintenance()
    result = store.authorize_command(
        principal=principal,
        endpoint_id=payload["endpoint_id"],
        capability_id=payload["capability_id"],
        capability_version=payload["capability_version"],
        parameters=payload["input"],
        intent=payload["intent"],
        deadline=payload["deadline"],
        idempotency_key=payload["idempotency_key"],
        lease_id=payload["lease_id"],
        approval_id=payload.get("approval_id"),
        approval_nonce=payload.get("approval_nonce"),
        state_hash=payload.get("state_hash"),
        state_version=payload.get("state_version"),
        expected_state=payload.get("expected_state"),
        task_ref=payload.get("task_ref"),
        run_ref=payload.get("run_ref"),
        correlation_id=correlation_id,
    )
    command = result["command"]
    metrics.increment("command_submitted_total")
    return {
        "command_id": command["command_id"],
        "status": command["status"],
        "tenant_ref": command["tenant_ref"],
        "endpoint_id": command["endpoint_id"],
        "gateway_id": command["gateway_id"],
        "correlation_id": command["correlation_id"],
        "created_at": command["created_at"],
        "policy_decision": command["policy_decision"],
        "deduplicated": result["deduplicated"],
    }


@app.get("/v1/commands", tags=["commands"])
def commands(
    endpoint_id: str | None = None,
    status: str | None = None,
    limit: int | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_READ)
    return {"items": store.list_commands(
        _tenant(principal, tenant_ref), endpoint_id=endpoint_id, status=status, limit=limit
    )}


@app.get("/v1/commands/{command_id}", tags=["commands"])
def command_detail(
    command_id: str,
    include: str | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_READ)
    tenant = _tenant(principal, tenant_ref)
    command = store.get_command(tenant, command_id)
    if command is None:
        raise hidden()
    _enforce_endpoint_scope(principal, command["endpoint_id"])
    if include == "transitions":
        command["transitions"] = store.command_transitions(tenant, command_id)
    return command


@app.get("/v1/commands/{command_id}/evidence", tags=["commands"])
def command_evidence(
    command_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_READ)
    tenant = _tenant(principal, tenant_ref)
    command = store.get_command(tenant, command_id)
    if command is None:
        raise hidden()
    _enforce_endpoint_scope(principal, command["endpoint_id"])
    return {
        "command_id": command_id,
        "status": command["status"],
        "evidence_refs": command["evidence_refs"],
        "verification": command["verification"],
        "items": store.list_evidence(tenant, command_id),
        "retention": "evidence_store_managed",
    }


EVIDENCE_TYPES = {"screenshot", "node_summary", "artifact_log"}
EVIDENCE_MIME_TYPES = {"image/png", "application/json", "text/plain"}
REDACTION_STATUSES = {"redacted", "not_required", "restricted"}


@app.post("/v1/gateways/{gateway_id}/commands/{command_id}/evidence", tags=["evidence"],
          status_code=201)
async def upload_evidence(
    gateway_id: str,
    command_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
    x_evidence_type: str | None = Header(default=None),
    x_content_sha256: str | None = Header(default=None),
    x_redaction_status: str | None = Header(default=None),
    x_original_sha256: str | None = Header(default=None),
    x_redaction_processor: str | None = Header(default=None),
    x_redaction_policy: str | None = Header(default=None),
    x_redaction_key_id: str | None = Header(default=None),
    x_redaction_proof: str | None = Header(default=None),
    x_redaction_regions: str | None = Header(default=None),
    x_retention_seconds: str | None = Header(default=None),
    x_captured_at: str | None = Header(default=None),
) -> dict[str, Any]:
    gateway = _gateway_principal(gateway_id, authorization)
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    evidence_type = (x_evidence_type or "").strip()
    redaction = (x_redaction_status or "").strip()
    if evidence_type not in EVIDENCE_TYPES or content_type not in EVIDENCE_MIME_TYPES:
        raise invalid("invalid_evidence_type")
    if redaction not in REDACTION_STATUSES:
        raise invalid("redaction_required")
    body = await request.body()
    if len(body) == 0 or len(body) > config.evidence_max_bytes():
        raise invalid("invalid_evidence_size")
    if content_type == "image/png":
        try:
            from PIL import Image

            with Image.open(io.BytesIO(body)) as image:
                image.verify()
                if image.format != "PNG" or image.width < 1 or image.height < 1:
                    raise ValueError("invalid png")
        except Exception as exc:  # noqa: BLE001 - fail closed on any decode error
            raise invalid("invalid_evidence_image") from exc
    digest = sha256_hex(body)
    if not x_content_sha256 or not hmac.compare_digest(digest, x_content_sha256.strip().lower()):
        raise invalid("evidence_hash_mismatch")
    regions: list[dict[str, Any]] = []
    if x_redaction_regions:
        try:
            decoded = base64.b64decode(x_redaction_regions.encode("ascii"), validate=True)
            regions = json.loads(decoded.decode("utf-8"))
            if not isinstance(regions, list):
                raise ValueError("regions must be a list")
        except (ValueError, json.JSONDecodeError) as exc:
            raise invalid("invalid_redaction_regions") from exc
    if evidence_type in {"screenshot", "node_summary"}:
        if redaction != "redacted":
            raise invalid("redaction_required")
        key = config.redaction_hmac_key()
        if len(key.encode("utf-8")) < 32:
            raise dependency_unavailable("redaction_proof_not_configured")
        if not x_original_sha256 or not x_redaction_processor or not x_redaction_policy:
            raise invalid("redaction_proof_incomplete")
        payload = {
            "original_sha256": x_original_sha256,
            "output_sha256": digest,
            "processor": x_redaction_processor,
            "policy_version": x_redaction_policy,
            "key_id": x_redaction_key_id or "",
            "regions": regions,
        }
        expected = hmac.new(
            key.encode("utf-8"),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not x_redaction_proof or not hmac.compare_digest(expected, x_redaction_proof):
            raise invalid("redaction_proof_invalid")
    command = store.get_command(gateway["tenant_ref"], command_id)
    if command is None or command["gateway_id"] != gateway_id:
        raise hidden()
    retention_seconds = config.evidence_default_retention_seconds()
    if x_retention_seconds and x_retention_seconds.isdigit():
        retention_seconds = max(60, min(90 * 86400, int(x_retention_seconds)))
    captured_at = x_captured_at or store.iso()
    evidence_id = f"evd_{secrets.token_urlsafe(18)}"
    storage_ref = f"{digest[:2]}/{evidence_id}/content.bin"
    object_store = evidence_store.get_object_store()
    object_store.put(storage_ref, body)
    try:
        metadata = store.create_evidence(
            tenant=gateway["tenant_ref"],
            gateway_id=gateway_id,
            endpoint_id=command["endpoint_id"],
            device_id=command.get("device_id"),
            command_id=command_id,
            evidence_id=evidence_id,
            storage_ref=storage_ref,
            evidence_type=evidence_type,
            mime_type=content_type,
            content_sha256=digest,
            size_bytes=len(body),
            captured_at=captured_at,
            redaction_status=redaction,
            retention_until=store.iso(store.now() + timedelta(seconds=retention_seconds)),
            task_ref=command.get("task_ref"),
            run_ref=command.get("run_ref"),
            correlation_id=command.get("correlation_id"),
            original_sha256=x_original_sha256,
            redaction_processor=x_redaction_processor,
            redaction_policy_version=x_redaction_policy,
            redaction_key_id=x_redaction_key_id,
            redaction_proof=x_redaction_proof,
            redaction_regions=regions,
        )
    except Exception:
        object_store.delete(storage_ref)
        raise
    return metadata


@app.get("/v1/evidence-storage/health", tags=["evidence"])
def evidence_storage_health(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_scope(authorization, identity.SCOPE_AUDIT_READ)
    try:
        return evidence_store.get_object_store().health()
    except Exception as exc:  # noqa: BLE001 - health must not leak details
        return {"backend": "unavailable", "error": type(exc).__name__}


@app.get("/v1/evidence/{evidence_id}", tags=["evidence"])
def evidence_detail(
    evidence_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_READ)
    metadata = store.get_evidence(_tenant(principal, tenant_ref), evidence_id)
    if metadata is None or metadata.get("deleted_at"):
        raise hidden()
    return metadata


@app.get("/v1/evidence/{evidence_id}/content", tags=["evidence"])
def evidence_content(
    evidence_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> Response:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_READ)
    tenant = _tenant(principal, tenant_ref)
    metadata = store.get_evidence(tenant, evidence_id)
    if metadata is None or metadata.get("deleted_at"):
        raise hidden()
    body = evidence_store.get_object_store().get(metadata["storage_ref"])
    if sha256_hex(body) != metadata["content_sha256"]:
        raise dependency_unavailable("evidence_integrity_failure")
    store.record_evidence_access(tenant, evidence_id,
                                 actor=principal.subject, actor_type=principal.principal_type)
    return Response(
        content=body,
        media_type=metadata["mime_type"],
        headers={
            "X-Content-SHA256": metadata["content_sha256"],
            "Cache-Control": "private, no-store",
            "Content-Disposition": "attachment",
        },
    )


@app.delete("/v1/evidence/{evidence_id}", tags=["evidence"])
def delete_evidence(
    evidence_id: str,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_EVIDENCE_DELETE)
    tenant = _tenant(principal, tenant_ref)
    metadata = store.mark_evidence_deleted(
        tenant, evidence_id, actor=principal.subject, actor_type=principal.principal_type
    )
    if metadata is None:
        raise hidden()
    evidence_store.get_object_store().delete(metadata["storage_ref"])
    return {"evidence_id": evidence_id, "status": "deleted"}


@app.post("/v1/commands/{command_id}/cancel", tags=["commands"])
def cancel_command(
    command_id: str,
    payload: dict[str, Any] | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_COMMAND_CANCEL)
    tenant = _tenant(principal, tenant_ref)
    command = store.get_command(tenant, command_id)
    if command is None:
        raise hidden()
    _enforce_endpoint_scope(principal, command["endpoint_id"])
    return store.cancel_command(
        tenant=tenant,
        command_id=command_id,
        actor=principal.subject,
        actor_type=principal.principal_type,
        reason=(payload or {}).get("reason"),
    )


# ---------------------------------------------------------------------------
# Gateway command channel
# ---------------------------------------------------------------------------


def _envelope(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "command_id": command["command_id"],
        "tenant_ref": command["tenant_ref"],
        "endpoint_id": command["endpoint_id"],
        "gateway_id": command["gateway_id"],
        "task_ref": command.get("task_ref"),
        "run_ref": command.get("run_ref"),
        "correlation_id": command.get("correlation_id"),
        "capability_id": command["capability_id"],
        "capability_version": command["capability_version"],
        "operation": command.get("operation", ""),
        "parameters": command["parameters"],
        "intent": command["intent"],
        "deadline": command["deadline"],
        "idempotency_key": command["idempotency_key"],
        "lease_id": command["lease_id"],
        "approval_id": command.get("approval_id"),
        "approval_nonce": command.get("approval_nonce"),
        "policy_version": command["policy_version"],
        "policy_decision": command["policy_decision"],
        "risk_tier": command["risk_tier"],
        "state_hash": command.get("state_hash"),
        "state_version": command.get("state_version"),
        "manifest_digest": command.get("manifest_digest"),
        "device_id": command.get("device_id"),
        "device_fingerprint": command.get("device_fingerprint"),
        "expected_state": command.get("expected_state"),
        "attempt": max(1, int(command.get("attempt_count") or 1)),
        "protocol_version": "v1",
    }


@app.get("/v1/gateways/{gateway_id}/commands", tags=["gateways"])
def pull_commands(
    gateway_id: str,
    limit: int = 10,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    gateway = _gateway_principal(gateway_id, authorization)
    store.maintenance()
    commands_out = store.dispatch_commands(
        gateway["tenant_ref"], gateway_id, limit=max(1, min(50, limit))
    )
    metrics.increment("gateway_pull_total")
    metrics.increment("commands_dispatched_total", len(commands_out))
    return {"items": [_envelope(command) for command in commands_out]}


@app.post("/v1/gateways/{gateway_id}/commands/{command_id}/progress", tags=["gateways"])
def gateway_progress(
    gateway_id: str,
    command_id: str,
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    gateway = _gateway_principal(gateway_id, authorization)
    status = payload.get("status")
    if status not in {"received", "accepted", "executing"}:
        raise invalid("invalid_progress_status")
    return store.record_command_progress(
        tenant=gateway["tenant_ref"], gateway_id=gateway_id, command_id=command_id,
        status=status, detail=payload.get("detail"),
    )


@app.post("/v1/gateways/{gateway_id}/commands/{command_id}/result", tags=["gateways"])
def gateway_result(
    gateway_id: str,
    command_id: str,
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    gateway = _gateway_principal(gateway_id, authorization)
    errors = contracts.validate_contract("gateway_command_result", payload)
    if errors:
        raise invalid("invalid_command_result", errors)
    if payload["status"] not in RESULT_STATUSES:
        raise invalid("invalid_result_status")
    verification = payload.get("verification")
    if verification and verification.get("method") not in VERIFICATION_METHODS:
        raise invalid("invalid_verification_method")
    result = store.record_command_result(
        tenant=gateway["tenant_ref"],
        gateway_id=gateway_id,
        command_id=command_id,
        status=payload["status"],
        result=payload.get("output"),
        verification=verification,
        evidence_refs=payload.get("evidence_refs"),
        reason=payload.get("reason"),
    )
    metrics.increment(f"command_result_{result['status']}_total")
    return result


# ---------------------------------------------------------------------------
# Events, audit, maintenance
# ---------------------------------------------------------------------------


@app.get("/v1/events", tags=["events"])
def events(
    after_occurred_at: str | None = None,
    after_event_id: str | None = None,
    event_type: str | None = None,
    limit: int | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_EVENT_READ)
    items = store.list_events(
        _tenant(principal, tenant_ref),
        after_occurred_at=after_occurred_at,
        after_event_id=after_event_id,
        event_type=event_type,
        limit=limit,
    )
    return {"items": items, "delivery": "at-least-once",
            "dedupe_key": "event_id", "ordering_scope": "tenant"}


@app.post("/v1/events/ack", tags=["events"])
def acknowledge_events(
    payload: dict[str, Any],
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_EVENT_READ)
    event_ids = payload.get("event_ids")
    if not isinstance(event_ids, list) or not all(isinstance(item, str) for item in event_ids):
        raise invalid("invalid_event_ids")
    return {"acknowledged": store.ack_events(_tenant(principal, tenant_ref), event_ids)}


@app.get("/v1/audit", tags=["audit"])
def audit(
    resource_id: str | None = None,
    limit: int | None = None,
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_AUDIT_READ)
    return {"items": store.list_audit(_tenant(principal, tenant_ref), resource_id=resource_id,
                                      limit=limit)}


@app.post("/v1/maintenance", tags=["maintenance"])
def run_maintenance(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_AUDIT_READ)
    if not principal.is_admin:
        raise forbidden("admin_scope_required")
    summary = store.maintenance()
    purged = 0
    object_store = evidence_store.get_object_store()
    for metadata in store.expired_evidence():
        object_store.delete(metadata["storage_ref"])
        store.purge_evidence_record(metadata["tenant_ref"], metadata["evidence_id"])
        purged += 1
    summary["evidence_purged"] = purged
    return {"summary": summary}


@app.get("/v1/metrics", tags=["observability"])
def metrics_snapshot(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_AUDIT_READ)
    if not principal.is_admin:
        raise forbidden("admin_scope_required")
    return {"profile": config.profile(), "counters": metrics.snapshot()}


@app.get("/v1/alerts", tags=["observability"])
def alerts(
    tenant_ref: str | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_GATEWAY_READ)
    return {"items": store.operation_alerts(_tenant(principal, tenant_ref))}


ADMIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Device Control</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.4rem;text-align:left}
code{background:#f4f4f4;padding:.1rem .3rem}.warn{color:#a60}</style></head>
<body><h1>Device Control</h1>
<p>This page is a static operator shell. Every data call uses the bearer token
below; the backend re-checks tenant, scope and authorization. The token is kept
only in memory and is never stored by the page.</p>
<p><label>Bearer token <input id="token" type="password" size="60"></label>
<button onclick="load()">Load</button></p>
<h2>Gateways</h2><table id="gateways"><thead><tr><th>ID</th><th>Status</th><th>Endpoint</th>
<th>Heartbeat age</th><th>Manifest</th><th>Queue</th></tr></thead><tbody></tbody></table>
<h2>Endpoints</h2><table id="endpoints"><thead><tr><th>ID</th><th>Status</th><th>Gateway</th>
<th>Device</th><th>Capabilities</th></tr></thead><tbody></tbody></table>
<h2>Alerts</h2><ul id="alerts"></ul>
<script>
const token = () => document.getElementById('token').value.trim();
async function api(path){const r=await fetch(path,{headers:{Authorization:'Bearer '+token()}});
 if(!r.ok) throw new Error(path+' '+r.status); return r.json();}
function row(values){const tr=document.createElement('tr');
 for(const v of values){const td=document.createElement('td');td.textContent=v==null?'':String(v);tr.appendChild(td);}return tr;}
async function load(){
 try{
  const g=await api('/v1/gateways');const gb=document.querySelector('#gateways tbody');gb.innerHTML='';
  for(const x of g.items){gb.appendChild(row([x.gateway_id,x.status,x.endpoint_id,x.last_heartbeat_at,x.manifest_version,x.queue_depth]));}
  const e=await api('/v1/endpoints');const eb=document.querySelector('#endpoints tbody');eb.innerHTML='';
  for(const x of e.items){eb.appendChild(row([x.endpoint_id,x.status,x.gateway_id,x.device_id,(x.capabilities||[]).map(c=>c.id).join(', ')]));}
  const a=await api('/v1/alerts');const al=document.getElementById('alerts');al.innerHTML='';
  for(const x of a.items){const li=document.createElement('li');li.className='warn';
   li.textContent=x.code+' '+x.resource_id+' '+JSON.stringify(x.detail);al.appendChild(li);}
 }catch(err){document.getElementById('alerts').textContent=String(err);}
}
</script></body></html>"""


@app.get("/admin", include_in_schema=False)
def admin_page() -> Response:
    return Response(content=ADMIN_PAGE, media_type="text/html")
