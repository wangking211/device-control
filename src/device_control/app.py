"""FastAPI control plane for Device Control.

Ownership boundary: this process owns device/gateway identity, endpoint
inventory, leases, policy, approvals, command coordination and evidence
metadata. It never runs ADB, drivers or device shell commands.
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from typing import Any, Callable

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from device_control import config, contracts, identity, metrics, policy, store
from device_control.canonical import approval_binding_digest, sha256_hex
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
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > config.max_request_bytes():
            return JSONResponse(
                status_code=413,
                content={"code": "payload_too_large",
                         "detail": {"max_bytes": config.max_request_bytes()}},
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
    if capability is None:
        raise conflict("unsupported_capability")
    schema_errors = contracts.validate_instance(capability.get("input_schema") or {}, payload["input"])
    if schema_errors:
        raise invalid("invalid_capability_parameters", schema_errors)
    lease = store.active_lease(tenant, payload["lease_id"], payload["endpoint_id"])
    if lease is None:
        raise conflict("active_device_lease_required")
    risk_tier = str((capability or {}).get("risk_tier") or "write")
    result = policy.evaluate(
        {"action_type": payload.get("action_type", "observe"), "intent": payload["intent"],
         "app_id": payload.get("app_id"), "target_type": payload.get("target_type")},
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
        parameters=payload["input"],
        intent=payload["intent"],
        state_hash=payload.get("state_hash"),
        policy_version=result["policy_version"],
        risk_tier=risk_tier,
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
                    "intent", "state_hash"}
        if required - payload.keys():
            raise invalid("approval_binding_required")
        binding = {
            "tenant_ref": tenant,
            "endpoint_id": payload["endpoint_id"],
            "gateway_id": approval["gateway_id"],
            "lease_id": payload["lease_id"],
            "capability_id": payload["capability_id"],
            "capability_version": payload["capability_version"],
            "action_digest": approval_binding_digest(
                tenant_ref=tenant,
                endpoint_id=payload["endpoint_id"],
                gateway_id=approval["gateway_id"],
                capability_id=payload["capability_id"],
                capability_version=payload["capability_version"],
                parameters=payload["input"],
                intent=payload["intent"],
                requester_ref=approval["requester_ref"],
                lease_id=payload["lease_id"],
                policy_version=approval["policy_version"],
                state_hash=payload.get("state_hash"),
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
    if capability is None:
        raise conflict("unsupported_capability")
    schema_errors = contracts.validate_instance(capability.get("input_schema") or {}, payload["input"])
    if schema_errors:
        raise invalid("invalid_capability_parameters", schema_errors)
    lease = store.active_lease(tenant, payload["lease_id"], payload["endpoint_id"])
    if lease is None:
        raise conflict("active_device_lease_required")
    decision = policy.evaluate(
        {
            "action_type": payload["capability_id"].split(".")[-1],
            "intent": payload["intent"],
            "app_id": payload["input"].get("app_id"),
            "target_type": payload["input"].get("target_type"),
        },
        lease_mode=lease["mode"],
        principal_scopes=principal.scopes,
        risk_tier=capability.get("risk_tier"),
    )
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
        state_hash=payload.get("state_hash"),
        expected_state=payload.get("expected_state"),
        task_ref=payload.get("task_ref"),
        run_ref=payload.get("run_ref"),
        correlation_id=correlation_id,
        policy_decision=decision,
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
    command = store.get_command(_tenant(principal, tenant_ref), command_id)
    if command is None:
        raise hidden()
    _enforce_endpoint_scope(principal, command["endpoint_id"])
    # Metadata only. Screenshots never live in the control plane, and the
    # gateway is responsible for redaction and retention.
    return {
        "command_id": command_id,
        "status": command["status"],
        "evidence_refs": command["evidence_refs"],
        "verification": command["verification"],
        "retention": "gateway_managed",
    }


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
        "parameters": command["parameters"],
        "intent": command["intent"],
        "deadline": command["deadline"],
        "idempotency_key": command["idempotency_key"],
        "lease_id": command["lease_id"],
        "approval_id": command.get("approval_id"),
        "policy_version": command["policy_version"],
        "policy_decision": command["policy_decision"],
        "risk_tier": command["risk_tier"],
        "state_hash": command.get("state_hash"),
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
    return {"summary": store.maintenance()}


@app.get("/v1/metrics", tags=["observability"])
def metrics_snapshot(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal = _require_scope(authorization, identity.SCOPE_AUDIT_READ)
    if not principal.is_admin:
        raise forbidden("admin_scope_required")
    return {"profile": config.profile(), "counters": metrics.snapshot()}
