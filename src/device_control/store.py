"""SQLite persistence for Device Control.

All tenant-scoped reads require a tenant argument; the API derives that value
from a verified principal, never from the request body. Mutating operations
that can invalidate authorization (approval consumption, revocation, command
authorization) run in a single ``BEGIN IMMEDIATE`` transaction and append
their audit/outbox records in that same transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Sequence

from device_control import commands as command_rules
from device_control import config, policy, schema
from device_control.canonical import (
    approval_binding_digest,
    canonical_json,
    command_payload_hash,
    digest_object,
    sha256_hex,
)
from device_control.errors import (
    DeviceControlError,
    conflict,
    dependency_unavailable,
    hidden,
    invalid,
)

EVENT_VERSION = "1"
MAX_LIST_LIMIT = 200


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


_INITIALIZED: set[str] = set()


def connect() -> sqlite3.Connection:
    path = config.database_path()
    key = str(path.resolve())
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    if key not in _INITIALIZED:
        try:
            schema.apply(db)
        except Exception:
            db.close()
            raise
        _INITIALIZED.add(key)
    return db


def initialize() -> list[int]:
    path = config.database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        applied = schema.apply(db)
    finally:
        db.close()
    _INITIALIZED.add(str(path.resolve()))
    return applied


@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except Exception:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")


def hash_credential(credential: str) -> str:
    return sha256_hex(credential)


def _credential(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:  # pragma: no cover - defensive
        return default


def _endpoint(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data.pop("credential_hash", None)
    data["capabilities"] = _json(data.pop("capabilities_json", "[]"), [])
    data["metadata"] = _json(data.pop("metadata_json", "{}"), {})
    return data


def _command(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["parameters"] = _json(data.pop("parameters_json", "{}"), {})
    data["expected_state"] = _json(data.pop("expected_state_json", None), None)
    data["result"] = _json(data.pop("result_json", None), None)
    data["verification"] = _json(data.pop("verification_json", None), None)
    data["evidence_refs"] = _json(data.pop("evidence_refs_json", "[]"), [])
    return data


def _approval(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["parameters"] = _json(data.pop("parameters_json", "{}"), {})
    return data


def _gateway(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["adapter_inventory"] = _json(data.pop("adapter_inventory_json", "[]"), [])
    data["platform"] = _json(data.pop("platform_json", "{}"), {})
    data["health"] = _json(data.pop("health_json", "{}"), {})
    if data.get("manifest_json"):
        data["manifest"] = _json(data.pop("manifest_json"), None)
    else:
        data.pop("manifest_json", None)
    return data


def _audit(
    db: sqlite3.Connection,
    *,
    tenant: str | None,
    actor: str | None,
    actor_type: str | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    outcome: str,
    detail: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> None:
    db.execute(
        "INSERT INTO audit_records (tenant_ref, actor_ref, actor_type, action, resource_type,"
        " resource_id, outcome, detail_json, correlation_id, occurred_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            tenant,
            actor,
            actor_type,
            action,
            resource_type,
            resource_id,
            outcome,
            json.dumps(detail or {}, sort_keys=True, separators=(",", ":")),
            correlation_id,
            iso(),
        ),
    )


def _event(
    db: sqlite3.Connection,
    *,
    tenant: str,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict[str, Any] | None = None,
    task_ref: str | None = None,
    run_ref: str | None = None,
    correlation_id: str | None = None,
    source_ref: str | None = None,
) -> str:
    event_id = f"evt_{secrets.token_urlsafe(18)}"
    db.execute(
        "INSERT INTO command_events (event_id, tenant_ref, event_type, event_version,"
        " occurred_at, source_ref, correlation_id, task_ref, run_ref, aggregate_type,"
        " aggregate_id, payload_json)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event_id,
            tenant,
            event_type,
            EVENT_VERSION,
            iso(),
            source_ref,
            correlation_id,
            task_ref,
            run_ref,
            aggregate_type,
            aggregate_id,
            json.dumps(payload or {}, sort_keys=True, separators=(",", ":")),
        ),
    )
    return event_id


def _list_limit(limit: int | None) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool):
        return 50
    return max(1, min(MAX_LIST_LIMIT, limit))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _gateway_for_binding(db: sqlite3.Connection, tenant: str, gateway_id: str | None) -> dict[str, Any] | None:
    if not gateway_id:
        return None
    row = db.execute(
        "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
        (gateway_id, tenant),
    ).fetchone()
    return _gateway(row) if row else None


def enroll_endpoint(
    *,
    tenant: str,
    endpoint_id: str,
    node_ref: str | None,
    gateway_id: str | None,
    capabilities: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
    device_id: str | None = None,
    device_fingerprint: str | None = None,
) -> str:
    credential = _credential("dc_ep")
    credential_hash = hash_credential(credential)
    timestamp = iso()
    expires_at = iso(now() + timedelta(seconds=config.endpoint_credential_ttl_seconds()))
    db = connect()
    try:
        with transaction(db) as tx:
            gateway = _gateway_for_binding(tx, tenant, gateway_id)
            if gateway_id and gateway is None:
                raise hidden()
            if gateway and gateway["status"] in {"enrollment_pending", "revoked"}:
                raise conflict("gateway_not_trusted")
            if gateway:
                if gateway.get("endpoint_id") and gateway["endpoint_id"] != endpoint_id:
                    raise conflict("gateway_endpoint_binding_mismatch")
                bound_fingerprint = gateway.get("device_fingerprint")
                if bound_fingerprint and device_fingerprint != bound_fingerprint:
                    raise conflict("device_identity_mismatch")
                if bound_fingerprint and not device_fingerprint:
                    raise invalid("device_fingerprint_required")
            try:
                tx.execute(
                    "INSERT INTO device_endpoints (endpoint_id, tenant_ref, node_ref, gateway_id,"
                    " credential_hash, status, capabilities_json, observed_at,"
                    " credential_expires_at, last_heartbeat_at, metadata_json, device_id,"
                    " device_fingerprint, paired_at)"
                    " VALUES (?, ?, ?, ?, ?, 'offline', ?, ?, ?, NULL, ?, ?, ?, ?)",
                    (
                        endpoint_id,
                        tenant,
                        node_ref,
                        gateway_id,
                        credential_hash,
                        json.dumps(capabilities, sort_keys=True),
                        timestamp,
                        expires_at,
                        json.dumps(metadata or {}, sort_keys=True),
                        device_id,
                        device_fingerprint,
                        timestamp if device_fingerprint else None,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise conflict("endpoint_already_exists") from exc
            _audit(
                tx,
                tenant=tenant,
                actor="bootstrap" if not tenant else "principal",
                actor_type="admin",
                action="endpoint.enroll",
                resource_type="device_endpoint",
                resource_id=endpoint_id,
                outcome="allowed",
                detail={
                    "gateway_id": gateway_id,
                    "capability_count": len(capabilities),
                    "device_fingerprint_present": bool(device_fingerprint),
                },
            )
            _event(
                tx,
                tenant=tenant,
                event_type="endpoint.enrolled",
                aggregate_type="device_endpoint",
                aggregate_id=endpoint_id,
                payload={"endpoint_id": endpoint_id, "gateway_id": gateway_id,
                         "device_id": device_id},
            )
    finally:
        db.close()
    return credential


def get_endpoint(tenant: str, endpoint_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
            (endpoint_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _endpoint(row) if row else None


def list_endpoints(tenant: str, *, gateway_id: str | None = None) -> list[dict[str, Any]]:
    db = connect()
    try:
        if gateway_id:
            rows = db.execute(
                "SELECT * FROM device_endpoints WHERE tenant_ref=? AND gateway_id=?"
                " ORDER BY endpoint_id",
                (tenant, gateway_id),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM device_endpoints WHERE tenant_ref=? ORDER BY endpoint_id",
                (tenant,),
            ).fetchall()
    finally:
        db.close()
    return [_endpoint(row) for row in rows]


def authenticate_endpoint(endpoint_id: str, credential: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_endpoints WHERE endpoint_id=?", (endpoint_id,)
        ).fetchone()
    finally:
        db.close()
    if row is None:
        return None
    endpoint = _endpoint(row)
    if endpoint["status"] == "revoked":
        return None
    expires_at = endpoint.get("credential_expires_at")
    if expires_at and parse_timestamp(expires_at) <= now():
        return None
    if not secrets.compare_digest(endpoint_hash(row), hash_credential(credential)):
        return None
    return endpoint


def endpoint_hash(row: sqlite3.Row) -> str:
    return str(row["credential_hash"])


def heartbeat_endpoint(
    endpoint_id: str, *, status: str, capabilities: list[dict[str, Any]]
) -> None:
    timestamp = iso()
    db = connect()
    try:
        with transaction(db) as tx:
            cursor = tx.execute(
                "UPDATE device_endpoints SET status=?, capabilities_json=?, observed_at=?,"
                " last_heartbeat_at=? WHERE endpoint_id=? AND status!='revoked'",
                (status, json.dumps(capabilities, sort_keys=True), timestamp, timestamp, endpoint_id),
            )
            if cursor.rowcount != 1:
                raise hidden()
            row = tx.execute(
                "SELECT tenant_ref FROM device_endpoints WHERE endpoint_id=?", (endpoint_id,)
            ).fetchone()
            _event(
                tx,
                tenant=row["tenant_ref"],
                event_type=f"endpoint.{status}",
                aggregate_type="device_endpoint",
                aggregate_id=endpoint_id,
                payload={"endpoint_id": endpoint_id, "status": status},
            )
    finally:
        db.close()


def rotate_endpoint_credential(tenant: str, endpoint_id: str) -> str:
    credential = _credential("dc_ep")
    timestamp = iso()
    expires_at = iso(now() + timedelta(seconds=config.endpoint_credential_ttl_seconds()))
    db = connect()
    try:
        with transaction(db) as tx:
            cursor = tx.execute(
                "UPDATE device_endpoints SET credential_hash=?, credential_rotated_at=?,"
                " credential_expires_at=? WHERE endpoint_id=? AND tenant_ref=? AND status!='revoked'",
                (hash_credential(credential), timestamp, expires_at, endpoint_id, tenant),
            )
            if cursor.rowcount != 1:
                raise hidden()
            _audit(
                tx,
                tenant=tenant,
                actor=None,
                actor_type="principal",
                action="endpoint.credential_rotate",
                resource_type="device_endpoint",
                resource_id=endpoint_id,
                outcome="allowed",
            )
            _event(
                tx,
                tenant=tenant,
                event_type="endpoint.credential_rotated",
                aggregate_type="device_endpoint",
                aggregate_id=endpoint_id,
                payload={"endpoint_id": endpoint_id},
            )
    finally:
        db.close()
    return credential


def _invalidate_endpoint_state(
    tx: sqlite3.Connection,
    *,
    tenant: str,
    endpoint_id: str,
    reason: str,
    actor: str | None = None,
    actor_type: str | None = "principal",
) -> None:
    """Release leases, invalidate approvals and stop queued work."""

    timestamp = iso()
    leases = tx.execute(
        "SELECT * FROM device_leases WHERE endpoint_id=? AND tenant_ref=? AND released_at IS NULL",
        (endpoint_id, tenant),
    ).fetchall()
    for lease in leases:
        tx.execute(
            "UPDATE device_leases SET released_at=?, released_reason=? WHERE lease_id=?",
            (timestamp, reason, lease["lease_id"]),
        )
        _event(
            tx, tenant=tenant, event_type="lease.released",
            aggregate_type="device_lease", aggregate_id=lease["lease_id"],
            payload={"lease_id": lease["lease_id"], "reason": reason},
            task_ref=lease["task_ref"], run_ref=lease["run_ref"],
        )

    approvals = tx.execute(
        "SELECT approval_id FROM device_approvals WHERE endpoint_id=? AND tenant_ref=?"
        " AND status IN ('pending','approved')",
        (endpoint_id, tenant),
    ).fetchall()
    for approval in approvals:
        tx.execute(
            "UPDATE device_approvals SET status='invalidated', reason=?,"
            " decided_at=COALESCE(decided_at, ?) WHERE approval_id=?",
            (reason, timestamp, approval["approval_id"]),
        )
        _event(
            tx, tenant=tenant, event_type="approval.invalidated",
            aggregate_type="device_approval", aggregate_id=approval["approval_id"],
            payload={"approval_id": approval["approval_id"], "reason": reason},
        )

    rows = tx.execute(
        "SELECT * FROM device_commands WHERE endpoint_id=? AND tenant_ref=?"
        " AND status NOT IN ('succeeded','rejected','failed','timed_out','cancelled','uncertain','expired')",
        (endpoint_id, tenant),
    ).fetchall()
    for row in rows:
        command = _command(row)
        target = "uncertain" if command["status"] in {
            "dispatched", "received", "accepted", "executing", "verifying"
        } else "cancelled"
        try:
            updated = _advance_tx(
                tx, command=command, target=target, reason=f"{reason}:in_flight",
                actor=actor or "system", actor_type=actor_type or "system",
                event_type=f"command.{target}",
            )
        except DeviceControlError:
            continue
        tx.execute(
            "UPDATE device_commands SET completed_at=?, updated_at=? WHERE command_id=?",
            (timestamp, timestamp, updated["command_id"]),
        )

    _audit(
        tx,
        tenant=tenant,
        actor=actor,
        actor_type=actor_type,
        action="endpoint.invalidate_state",
        resource_type="device_endpoint",
        resource_id=endpoint_id,
        outcome="allowed",
        detail={"reason": reason, "leases": len(leases), "approvals": len(approvals),
                "commands": len(rows)},
    )


def revoke_endpoint(tenant: str, endpoint_id: str, *, reason: str = "revoked_by_operator") -> bool:
    timestamp = iso()
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT tenant_ref FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
                (endpoint_id, tenant),
            ).fetchone()
            if row is None:
                return False
            updated = tx.execute(
                "UPDATE device_endpoints SET status='revoked', revoke_reason=?, observed_at=?"
                " WHERE endpoint_id=? AND tenant_ref=? AND status!='revoked'",
                (reason, timestamp, endpoint_id, tenant),
            )
            _invalidate_endpoint_state(
                tx, tenant=tenant, endpoint_id=endpoint_id, reason="endpoint_revoked"
            )
            _event(
                tx,
                tenant=tenant,
                event_type="endpoint.revoked",
                aggregate_type="device_endpoint",
                aggregate_id=endpoint_id,
                payload={"endpoint_id": endpoint_id, "reason": reason},
            )
            return updated.rowcount > 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Gateways
# ---------------------------------------------------------------------------


def _issue_gateway_credential(
    tx: sqlite3.Connection,
    *,
    tenant: str,
    gateway_id: str,
    purpose: str,
    ttl_seconds: int,
    rotated_from: str | None = None,
) -> tuple[str, str, str]:
    credential = _credential("dc_gw_enroll" if purpose == "enrollment" else "dc_gw")
    credential_id = f"gwc_{secrets.token_urlsafe(12)}"
    issued_at = iso()
    expires_at = iso(now() + timedelta(seconds=ttl_seconds))
    tx.execute(
        "INSERT INTO gateway_credentials (credential_id, gateway_id, tenant_ref, purpose,"
        " credential_hash, issued_at, expires_at, rotated_from)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            credential_id,
            gateway_id,
            tenant,
            purpose,
            hash_credential(credential),
            issued_at,
            expires_at,
            rotated_from,
        ),
    )
    return credential, credential_id, expires_at


def create_gateway(
    *,
    tenant: str,
    gateway_id: str,
    display_name: str | None,
    protocol_version: str,
    adapter_inventory: list[dict[str, Any]],
    endpoint_id: str | None = None,
    device_id: str | None = None,
    device_fingerprint: str | None = None,
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            try:
                tx.execute(
                    "INSERT INTO device_gateways (gateway_id, tenant_ref, display_name, status,"
                    " protocol_version, adapter_inventory_json, enrolled_at, endpoint_id,"
                    " device_id, device_fingerprint)"
                    " VALUES (?, ?, ?, 'enrollment_pending', ?, ?, ?, ?, ?, ?)",
                    (
                        gateway_id,
                        tenant,
                        display_name,
                        protocol_version,
                        json.dumps(adapter_inventory, sort_keys=True),
                        iso(),
                        endpoint_id,
                        device_id,
                        device_fingerprint,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise conflict("gateway_already_exists") from exc
            token, credential_id, expires_at = _issue_gateway_credential(
                tx,
                tenant=tenant,
                gateway_id=gateway_id,
                purpose="enrollment",
                ttl_seconds=config.enrollment_token_ttl_seconds(),
            )
            _audit(
                tx,
                tenant=tenant,
                actor=None,
                actor_type="principal",
                action="gateway.enroll",
                resource_type="device_gateway",
                resource_id=gateway_id,
                outcome="allowed",
                detail={"credential_id": credential_id},
            )
            _event(
                tx,
                tenant=tenant,
                event_type="gateway.enrollment_pending",
                aggregate_type="device_gateway",
                aggregate_id=gateway_id,
                payload={"gateway_id": gateway_id},
            )
    finally:
        db.close()
    return {
        "gateway_id": gateway_id,
        "status": "enrollment_pending",
        "enrollment_token": token,
        "enrollment_expires_at": expires_at,
    }


def _find_credential(
    tx: sqlite3.Connection, gateway_id: str, credential: str, purposes: Sequence[str]
) -> sqlite3.Row | None:
    placeholders = ",".join("?" for _ in purposes)
    rows = tx.execute(
        f"SELECT * FROM gateway_credentials WHERE gateway_id=? AND purpose IN ({placeholders})"  # nosec B608
        " AND revoked_at IS NULL",
        (gateway_id, *purposes),
    ).fetchall()
    digest = hash_credential(credential)
    for row in rows:
        if secrets.compare_digest(row["credential_hash"], digest):
            return row
    return None


def activate_gateway(
    *, gateway_id: str, enrollment_token: str, platform: dict[str, Any] | None = None
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            gateway_row = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=?", (gateway_id,)
            ).fetchone()
            if gateway_row is None or gateway_row["status"] == "revoked":
                raise hidden()
            credential_row = _find_credential(tx, gateway_id, enrollment_token, ("enrollment",))
            if credential_row is None:
                raise DeviceControlError(401, "invalid_enrollment_token")
            if parse_timestamp(credential_row["expires_at"]) <= now():
                raise DeviceControlError(401, "enrollment_token_expired")
            if gateway_row["status"] != "enrollment_pending":
                raise conflict("gateway_already_activated")
            tx.execute(
                "UPDATE gateway_credentials SET revoked_at=? WHERE credential_id=?",
                (iso(), credential_row["credential_id"]),
            )
            timestamp = iso()
            tx.execute(
                "UPDATE device_gateways SET status='trusted', activated_at=?, platform_json=?"
                " WHERE gateway_id=?",
                (timestamp, json.dumps(platform or {}, sort_keys=True), gateway_id),
            )
            credential, credential_id, expires_at = _issue_gateway_credential(
                tx,
                tenant=gateway_row["tenant_ref"],
                gateway_id=gateway_id,
                purpose="access",
                ttl_seconds=config.gateway_credential_ttl_seconds(),
                rotated_from=credential_row["credential_id"],
            )
            _audit(
                tx,
                tenant=gateway_row["tenant_ref"],
                actor=gateway_id,
                actor_type="gateway",
                action="gateway.activate",
                resource_type="device_gateway",
                resource_id=gateway_id,
                outcome="allowed",
                detail={"credential_id": credential_id},
            )
            _event(
                tx,
                tenant=gateway_row["tenant_ref"],
                event_type="gateway.activated",
                aggregate_type="device_gateway",
                aggregate_id=gateway_id,
                payload={"gateway_id": gateway_id},
            )
    finally:
        db.close()
    return {
        "gateway_id": gateway_id,
        "status": "trusted",
        "tenant_ref": gateway_row["tenant_ref"],
        "credential": credential,
        "credential_id": credential_id,
        "expires_at": expires_at,
    }


def authenticate_gateway(
    gateway_id: str, credential: str, *, purposes: Sequence[str] = ("access",)
) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_gateways WHERE gateway_id=?", (gateway_id,)
        ).fetchone()
        if row is None or row["status"] == "revoked":
            return None
        credential_row = _find_credential(db, gateway_id, credential, tuple(purposes))
        if credential_row is None:
            return None
        if parse_timestamp(credential_row["expires_at"]) <= now():
            return None
    finally:
        db.close()
    gateway = _gateway(row)
    gateway["credential_id"] = credential_row["credential_id"]
    gateway["credential_expires_at"] = credential_row["expires_at"]
    return gateway


def register_gateway_manifest(
    *,
    tenant: str,
    gateway_id: str,
    manifest: dict[str, Any],
    digest: str,
    signature: str | None,
    actor: str,
    actor_type: str,
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchone()
            if row is None or row["status"] == "revoked":
                raise hidden()
            gateway = _gateway(row)
            if manifest.get("tenant_ref") and manifest["tenant_ref"] != tenant:
                raise conflict("manifest_tenant_binding_mismatch")
            if manifest.get("gateway_id") and manifest["gateway_id"] != gateway_id:
                raise conflict("manifest_gateway_binding_mismatch")
            endpoint_id = manifest.get("endpoint_id")
            device_id = manifest.get("device_id")
            fingerprint = manifest.get("device_fingerprint")
            if endpoint_id and gateway.get("endpoint_id") and endpoint_id != gateway["endpoint_id"]:
                raise conflict("gateway_endpoint_binding_mismatch")
            if fingerprint and gateway.get("device_fingerprint") and fingerprint != gateway["device_fingerprint"]:
                raise conflict("device_identity_mismatch")
            revision = tx.execute(
                "SELECT 1 FROM gateway_manifest_revisions WHERE gateway_id=? AND digest=?",
                (gateway_id, digest),
            ).fetchone()
            if revision is None:
                tx.execute(
                    "INSERT INTO gateway_manifest_revisions (gateway_id, tenant_ref,"
                    " manifest_version, digest, signature, manifest_json, registered_by,"
                    " registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        gateway_id,
                        tenant,
                        str(manifest.get("manifest_version") or ""),
                        digest,
                        signature,
                        json.dumps(manifest, sort_keys=True),
                        actor,
                        iso(),
                    ),
                )
            tx.execute(
                "UPDATE device_gateways SET manifest_version=?, manifest_digest=?,"
                " manifest_json=?, manifest_updated_at=?, endpoint_id=COALESCE(endpoint_id, ?),"
                " device_id=COALESCE(device_id, ?), device_fingerprint=COALESCE(device_fingerprint, ?)"
                " WHERE gateway_id=? AND tenant_ref=?",
                (
                    str(manifest.get("manifest_version") or ""),
                    digest,
                    json.dumps(manifest, sort_keys=True),
                    iso(),
                    endpoint_id,
                    device_id,
                    fingerprint,
                    gateway_id,
                    tenant,
                ),
            )
            _audit(
                tx,
                tenant=tenant,
                actor=actor,
                actor_type=actor_type,
                action="gateway.manifest_register",
                resource_type="device_gateway",
                resource_id=gateway_id,
                outcome="allowed",
                detail={"digest": digest, "version": manifest.get("manifest_version"),
                        "signed": bool(signature)},
            )
            _event(
                tx,
                tenant=tenant,
                event_type="gateway.manifest_registered",
                aggregate_type="device_gateway",
                aggregate_id=gateway_id,
                payload={"gateway_id": gateway_id, "digest": digest,
                         "manifest_version": manifest.get("manifest_version")},
            )
    finally:
        db.close()
    return {
        "gateway_id": gateway_id,
        "manifest_version": manifest.get("manifest_version"),
        "digest": digest,
        "signature": signature,
    }


def get_gateway_manifest(tenant: str, gateway_id: str) -> dict[str, Any] | None:
    gateway = get_gateway(tenant, gateway_id)
    if gateway is None:
        return None
    return {
        "gateway_id": gateway_id,
        "manifest_version": gateway.get("manifest_version"),
        "digest": gateway.get("manifest_digest"),
        "manifest": gateway.get("manifest"),
        "updated_at": gateway.get("manifest_updated_at"),
    }


def heartbeat_gateway(
    *,
    gateway_id: str,
    status: str,
    adapter_inventory: list[dict[str, Any]] | None,
    version: str | None,
    manifest_digest: str | None = None,
    manifest_version: str | None = None,
    endpoint_id: str | None = None,
    device_id: str | None = None,
    device_fingerprint: str | None = None,
    health: dict[str, Any] | None = None,
    queue_depth: int | None = None,
    queue_age_seconds: float | None = None,
) -> dict[str, Any]:
    if status not in {"online", "degraded", "offline"}:
        raise invalid("invalid_gateway_status")
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=?", (gateway_id,)
            ).fetchone()
            if row is None or row["status"] in {"revoked", "enrollment_pending"}:
                raise conflict("gateway_not_activatable")
            timestamp = iso()
            inventory = adapter_inventory if adapter_inventory is not None else _json(
                row["adapter_inventory_json"], []
            )
            health_payload = dict(health or {})
            effective_status = status
            last_error = None
            if row["manifest_digest"] and manifest_digest and manifest_digest != row["manifest_digest"]:
                effective_status = "degraded"
                last_error = "manifest_digest_mismatch"
                health_payload["manifest_mismatch"] = True
            elif row["manifest_digest"] and not manifest_digest:
                effective_status = "degraded"
                last_error = "manifest_digest_missing"
                health_payload["manifest_mismatch"] = True
            if row["endpoint_id"] and endpoint_id and endpoint_id != row["endpoint_id"]:
                effective_status = "degraded"
                last_error = "endpoint_binding_mismatch"
            if row["device_fingerprint"] and device_fingerprint and device_fingerprint != row["device_fingerprint"]:
                effective_status = "degraded"
                last_error = "device_identity_mismatch"
            tx.execute(
                "UPDATE device_gateways SET status=?, last_heartbeat_at=?,"
                " adapter_inventory_json=?, last_seen_version=?, reported_manifest_digest=?,"
                " health_json=?, queue_depth=?, queue_age_seconds=?, last_error=?"
                " WHERE gateway_id=?",
                (
                    effective_status,
                    timestamp,
                    json.dumps(inventory, sort_keys=True),
                    version,
                    manifest_digest,
                    json.dumps(health_payload, sort_keys=True),
                    queue_depth,
                    queue_age_seconds,
                    last_error,
                    gateway_id,
                ),
            )
            previous = row["status"]
            if previous != effective_status:
                _event(
                    tx,
                    tenant=row["tenant_ref"],
                    event_type=f"gateway.{effective_status}",
                    aggregate_type="device_gateway",
                    aggregate_id=gateway_id,
                    payload={"gateway_id": gateway_id, "status": effective_status,
                             "previous": previous, "reason": last_error},
                )
    finally:
        db.close()
    return {"gateway_id": gateway_id, "status": effective_status, "observed_at": timestamp,
            "tenant_ref": row["tenant_ref"], "manifest_version": manifest_version,
            "last_error": last_error}


def rotate_gateway_credential(tenant: str, gateway_id: str) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchone()
            if row is None or row["status"] == "revoked":
                raise hidden()
            now_iso = iso()
            tx.execute(
                "UPDATE gateway_credentials SET revoked_at=? WHERE gateway_id=? AND purpose='access'"
                " AND revoked_at IS NULL",
                (now_iso, gateway_id),
            )
            credential, credential_id, expires_at = _issue_gateway_credential(
                tx,
                tenant=tenant,
                gateway_id=gateway_id,
                purpose="access",
                ttl_seconds=config.gateway_credential_ttl_seconds(),
            )
            _audit(
                tx,
                tenant=tenant,
                actor=gateway_id,
                actor_type="gateway",
                action="gateway.credential_rotate",
                resource_type="device_gateway",
                resource_id=gateway_id,
                outcome="allowed",
            )
            _event(
                tx,
                tenant=tenant,
                event_type="gateway.credential_rotated",
                aggregate_type="device_gateway",
                aggregate_id=gateway_id,
                payload={"gateway_id": gateway_id},
            )
    finally:
        db.close()
    return {"gateway_id": gateway_id, "credential": credential,
            "credential_id": credential_id, "expires_at": expires_at}


def list_gateways(tenant: str) -> list[dict[str, Any]]:
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM device_gateways WHERE tenant_ref=? ORDER BY gateway_id", (tenant,)
        ).fetchall()
    finally:
        db.close()
    return [_gateway(row) for row in rows]


def get_gateway(tenant: str, gateway_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
            (gateway_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _gateway(row) if row else None


def revoke_gateway(tenant: str, gateway_id: str, *, reason: str = "revoked_by_operator") -> bool:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchone()
            if row is None:
                return False
            timestamp = iso()
            tx.execute(
                "UPDATE device_gateways SET status='revoked', revoked_at=?, revoke_reason=?"
                " WHERE gateway_id=? AND tenant_ref=?",
                (timestamp, reason, gateway_id, tenant),
            )
            tx.execute(
                "UPDATE gateway_credentials SET revoked_at=? WHERE gateway_id=? AND revoked_at IS NULL",
                (timestamp, gateway_id),
            )
            endpoints = tx.execute(
                "SELECT endpoint_id FROM device_endpoints WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchall()
            for endpoint in endpoints:
                _invalidate_endpoint_state(
                    tx,
                    tenant=tenant,
                    endpoint_id=endpoint["endpoint_id"],
                    reason="gateway_revoked",
                )
                tx.execute(
                    "UPDATE device_endpoints SET status='offline' WHERE endpoint_id=? AND status!='revoked'",
                    (endpoint["endpoint_id"],),
                )
            _audit(
                tx,
                tenant=tenant,
                actor=None,
                actor_type="principal",
                action="gateway.revoke",
                resource_type="device_gateway",
                resource_id=gateway_id,
                outcome="allowed",
                detail={"reason": reason, "endpoints": len(endpoints)},
            )
            _event(
                tx,
                tenant=tenant,
                event_type="gateway.revoked",
                aggregate_type="device_gateway",
                aggregate_id=gateway_id,
                payload={"gateway_id": gateway_id, "reason": reason},
            )
            return True
    finally:
        db.close()


def mark_stale_gateways(*, stale_after_seconds: int | None = None) -> list[str]:
    threshold = now() - timedelta(seconds=stale_after_seconds or config.stale_after_seconds())
    db = connect()
    stale: list[str] = []
    try:
        with transaction(db) as tx:
            rows = tx.execute(
                "SELECT gateway_id, tenant_ref, last_heartbeat_at FROM device_gateways"
                " WHERE status IN ('online','degraded')"
            ).fetchall()
            for row in rows:
                last = row["last_heartbeat_at"]
                if last and parse_timestamp(last) >= threshold:
                    continue
                tx.execute(
                    "UPDATE device_gateways SET status='offline' WHERE gateway_id=?",
                    (row["gateway_id"],),
                )
                _event(
                    tx,
                    tenant=row["tenant_ref"],
                    event_type="gateway.offline",
                    aggregate_type="device_gateway",
                    aggregate_id=row["gateway_id"],
                    payload={"gateway_id": row["gateway_id"], "reason": "stale_heartbeat"},
                )
                stale.append(row["gateway_id"])
    finally:
        db.close()
    return stale


# ---------------------------------------------------------------------------
# Leases
# ---------------------------------------------------------------------------


def acquire_lease(
    *,
    tenant: str,
    endpoint_id: str,
    task_ref: str,
    run_ref: str | None,
    holder_ref: str,
    holder_type: str,
    mode: str,
    ttl_seconds: int,
) -> dict[str, Any]:
    timestamp = now()
    expires_at = iso(timestamp + timedelta(seconds=ttl_seconds))
    db = connect()
    try:
        with transaction(db) as tx:
            endpoint_row = tx.execute(
                "SELECT * FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
                (endpoint_id, tenant),
            ).fetchone()
            if endpoint_row is None:
                raise hidden()
            endpoint = _endpoint(endpoint_row)
            if endpoint["status"] in {"offline", "revoked"}:
                raise conflict("endpoint_unavailable")
            if endpoint.get("gateway_id"):
                gateway_row = tx.execute(
                    "SELECT status FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                    (endpoint["gateway_id"], tenant),
                ).fetchone()
                if gateway_row is None or gateway_row["status"] not in {"trusted", "online", "degraded"}:
                    raise conflict("gateway_unavailable")
            tx.execute(
                "UPDATE device_leases SET released_at=?, released_reason='expired'"
                " WHERE endpoint_id=? AND released_at IS NULL AND expires_at<=?",
                (iso(timestamp), endpoint_id, iso(timestamp)),
            )
            lease_id = f"lease_{secrets.token_urlsafe(18)}"
            try:
                tx.execute(
                    "INSERT INTO device_leases (lease_id, endpoint_id, tenant_ref, task_ref,"
                    " run_ref, holder_ref, mode, expires_at, holder_type)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (lease_id, endpoint_id, tenant, task_ref, run_ref, holder_ref, mode,
                     expires_at, holder_type),
                )
            except sqlite3.IntegrityError as exc:
                active = tx.execute(
                    "SELECT holder_ref, task_ref FROM device_leases WHERE endpoint_id=?"
                    " AND released_at IS NULL",
                    (endpoint_id,),
                ).fetchone()
                detail = (
                    {"holder_ref": active["holder_ref"], "task_ref": active["task_ref"]}
                    if active else None
                )
                raise conflict("device_busy", detail=detail) from exc
            _audit(
                tx,
                tenant=tenant,
                actor=holder_ref,
                actor_type=holder_type,
                action="lease.acquire",
                resource_type="device_lease",
                resource_id=lease_id,
                outcome="allowed",
                detail={"endpoint_id": endpoint_id, "mode": mode},
            )
            _event(
                tx,
                tenant=tenant,
                event_type="lease.acquired",
                aggregate_type="device_lease",
                aggregate_id=lease_id,
                payload={"lease_id": lease_id, "endpoint_id": endpoint_id, "mode": mode},
                task_ref=task_ref,
                run_ref=run_ref,
            )
    finally:
        db.close()
    return {
        "lease_id": lease_id,
        "endpoint_id": endpoint_id,
        "tenant_ref": tenant,
        "task_ref": task_ref,
        "run_ref": run_ref,
        "holder_ref": holder_ref,
        "mode": mode,
        "expires_at": expires_at,
    }


def release_lease(tenant: str, lease_id: str, *, actor: str | None = None,
                  reason: str = "released") -> bool:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_leases WHERE lease_id=? AND tenant_ref=?",
                (lease_id, tenant),
            ).fetchone()
            if row is None:
                return False
            cursor = tx.execute(
                "UPDATE device_leases SET released_at=?, released_reason=?"
                " WHERE lease_id=? AND tenant_ref=? AND released_at IS NULL",
                (iso(), reason, lease_id, tenant),
            )
            if cursor.rowcount:
                tx.execute(
                    "UPDATE device_approvals SET status='invalidated', reason='lease_released'"
                    " WHERE lease_id=? AND tenant_ref=? AND status IN ('pending','approved')",
                    (lease_id, tenant),
                )
                _audit(
                    tx, tenant=tenant, actor=actor, actor_type="principal",
                    action="lease.release", resource_type="device_lease",
                    resource_id=lease_id, outcome="released",
                    detail={"reason": reason},
                )
                _event(
                    tx,
                    tenant=tenant,
                    event_type="lease.released",
                    aggregate_type="device_lease",
                    aggregate_id=lease_id,
                    payload={"lease_id": lease_id, "reason": reason},
                    task_ref=row["task_ref"],
                    run_ref=row["run_ref"],
                )
            return cursor.rowcount > 0
    finally:
        db.close()


def get_lease(tenant: str, lease_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_leases WHERE lease_id=? AND tenant_ref=?",
            (lease_id, tenant),
        ).fetchone()
    finally:
        db.close()
    if row is None:
        return None
    lease = dict(row)
    lease["active"] = (lease.get("released_at") is None
                       and str(lease.get("expires_at") or "") > iso())
    return lease


def active_lease(tenant: str, lease_id: str, endpoint_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_leases WHERE lease_id=? AND tenant_ref=? AND endpoint_id=?"
            " AND released_at IS NULL AND expires_at>?",
            (lease_id, tenant, endpoint_id, iso()),
        ).fetchone()
    finally:
        db.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


def create_approval(
    *,
    tenant: str,
    endpoint_id: str,
    lease_id: str,
    requester: str,
    requester_type: str,
    capability_id: str,
    capability_version: str,
    operation: str,
    parameters: dict[str, Any],
    intent: str,
    state_hash: str | None,
    state_version: str | None,
    policy_version: str,
    risk_tier: str,
    manifest_digest_value: str,
    require_state: bool = False,
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            endpoint_row = tx.execute(
                "SELECT * FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
                (endpoint_id, tenant),
            ).fetchone()
            if endpoint_row is None:
                raise hidden()
            endpoint = _endpoint(endpoint_row)
            if endpoint["status"] in {"offline", "revoked"}:
                raise conflict("endpoint_unavailable")
            if require_state and (not state_hash or not state_version):
                raise invalid("state_hash_and_version_required")
            device_id = endpoint.get("device_id")
            device_fingerprint = endpoint.get("device_fingerprint")
            gateway_id = endpoint.get("gateway_id") or ""
            if not gateway_id:
                raise conflict("endpoint_has_no_gateway")
            lease = tx.execute(
                "SELECT * FROM device_leases WHERE lease_id=? AND tenant_ref=? AND endpoint_id=?"
                " AND released_at IS NULL AND expires_at>?",
                (lease_id, tenant, endpoint_id, iso()),
            ).fetchone()
            if lease is None:
                raise conflict("active_device_lease_required")
            gateway = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchone()
            if gateway is None or gateway["status"] not in {"online", "degraded"}:
                raise conflict("gateway_unavailable")
            if gateway["manifest_digest"] != manifest_digest_value:
                raise conflict("manifest_mismatch")
            if gateway["device_fingerprint"] and device_fingerprint != gateway["device_fingerprint"]:
                raise conflict("device_identity_mismatch")
            approval_id = f"apr_{secrets.token_urlsafe(18)}"
            approval_nonce = secrets.token_urlsafe(24)
            action_digest = approval_binding_digest(
                tenant_ref=tenant,
                endpoint_id=endpoint_id,
                gateway_id=gateway_id,
                capability_id=capability_id,
                capability_version=capability_version,
                operation=operation,
                parameters=parameters,
                intent=intent,
                requester_ref=requester,
                lease_id=lease_id,
                policy_version=policy_version,
                state_hash=state_hash,
                device_id=device_id,
                device_fingerprint=device_fingerprint,
                manifest_digest_value=manifest_digest_value,
                state_version=state_version,
                approval_nonce=approval_nonce,
            )
            expires_at = iso(now() + timedelta(seconds=config.approval_ttl_seconds()))
            tx.execute(
                "INSERT INTO device_approvals (approval_id, tenant_ref, endpoint_id, gateway_id,"
                " lease_id, requester_ref, requester_type, action_digest, capability_id,"
                " capability_version, operation, intent, parameters_json, state_hash,"
                " state_version, policy_version, risk_tier, manifest_digest, approval_nonce,"
                " device_id, device_fingerprint, status, expires_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                " 'pending', ?, ?)",
                (
                    approval_id, tenant, endpoint_id, gateway_id, lease_id, requester,
                    requester_type, action_digest, capability_id, capability_version, operation,
                    intent, json.dumps(parameters, sort_keys=True, separators=(",", ":")),
                    state_hash, state_version, policy_version, risk_tier, manifest_digest_value,
                    approval_nonce, device_id, device_fingerprint, expires_at, iso(),
                ),
            )
            _audit(
                tx,
                tenant=tenant,
                actor=requester,
                actor_type=requester_type,
                action="approval.request",
                resource_type="device_approval",
                resource_id=approval_id,
                outcome="pending",
                detail={"capability_id": capability_id, "operation": operation,
                        "risk_tier": risk_tier, "manifest_digest": manifest_digest_value},
            )
            _event(
                tx,
                tenant=tenant,
                event_type="approval.requested",
                aggregate_type="device_approval",
                aggregate_id=approval_id,
                payload={
                    "approval_id": approval_id,
                    "endpoint_id": endpoint_id,
                    "capability_id": capability_id,
                    "operation": operation,
                    "risk_tier": risk_tier,
                    "action_digest": action_digest,
                    "manifest_digest": manifest_digest_value,
                },
            )
    finally:
        db.close()
    return {
        "approval_id": approval_id,
        "status": "pending",
        "action_sha256": action_digest,
        "approval_nonce": approval_nonce,
        "expires_at": expires_at,
    }


def get_approval(tenant: str, approval_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_approvals WHERE approval_id=? AND tenant_ref=?",
            (approval_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _approval(row) if row else None


def decide_approval(
    *,
    tenant: str,
    approval_id: str,
    approver: str,
    approver_type: str,
    approved: bool,
    reason: str | None = None,
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_approvals WHERE approval_id=? AND tenant_ref=?",
                (approval_id, tenant),
            ).fetchone()
            if row is None:
                raise hidden()
            approval = _approval(row)
            if approval["status"] != "pending":
                raise conflict("approval_not_decidable")
            if parse_timestamp(approval["expires_at"]) <= now():
                tx.execute(
                    "UPDATE device_approvals SET status='expired' WHERE approval_id=?",
                    (approval_id,),
                )
                raise conflict("approval_expired")
            if approval["requester_ref"] == approver:
                raise DeviceControlError(403, "self_approval_denied")
            # Revalidate the environment at decision time, not only at request
            # time: a revoked endpoint or released lease must not be approvable.
            endpoint = tx.execute(
                "SELECT status FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
                (approval["endpoint_id"], tenant),
            ).fetchone()
            lease = tx.execute(
                "SELECT 1 FROM device_leases WHERE lease_id=? AND tenant_ref=? AND released_at IS NULL"
                " AND expires_at>?",
                (approval["lease_id"], tenant, iso()),
            ).fetchone()
            if endpoint is None or endpoint["status"] in {"offline", "revoked"} or lease is None:
                tx.execute(
                    "UPDATE device_approvals SET status='invalidated', reason=?, decided_at=?"
                    " WHERE approval_id=?",
                    ("endpoint_or_lease_invalid", iso(), approval_id),
                )
                raise conflict("approval_stale")
            status = "approved" if approved else "denied"
            tx.execute(
                "UPDATE device_approvals SET status=?, approver_ref=?, approver_type=?,"
                " decided_at=?, reason=? WHERE approval_id=? AND status='pending'",
                (status, approver, approver_type, iso(), reason, approval_id),
            )
            _audit(
                tx,
                tenant=tenant,
                actor=approver,
                actor_type=approver_type,
                action="approval.decide",
                resource_type="device_approval",
                resource_id=approval_id,
                outcome=status,
                detail={"reason": reason},
            )
            _event(
                tx,
                tenant=tenant,
                event_type=f"approval.{status}",
                aggregate_type="device_approval",
                aggregate_id=approval_id,
                payload={"approval_id": approval_id, "status": status},
            )
            return {"approval_id": approval_id, "status": status}
    finally:
        db.close()


def _binding_matches(approval: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key in (
        "tenant_ref",
        "endpoint_id",
        "device_id",
        "device_fingerprint",
        "gateway_id",
        "lease_id",
        "capability_id",
        "capability_version",
        "operation",
        "manifest_digest",
        "approval_nonce",
        "action_digest",
    ):
        if str(approval.get(key) or "") != str(expected.get(key) or ""):
            return False
    if (approval.get("state_hash") or None) != (expected.get("state_hash") or None):
        return False
    if (approval.get("state_version") or None) != (expected.get("state_version") or None):
        return False
    return True


def _consume_approval_tx(
    tx: sqlite3.Connection,
    *,
    tenant: str,
    approval_id: str,
    expected: dict[str, Any],
    actor: str,
    actor_type: str,
    command_id: str | None = None,
) -> None:
    row = tx.execute(
        "SELECT * FROM device_approvals WHERE approval_id=? AND tenant_ref=?",
        (approval_id, tenant),
    ).fetchone()
    if row is None:
        raise hidden()
    approval = _approval(row)
    if approval["status"] != "approved":
        raise conflict("approval_not_consumable", detail={"status": approval["status"]})
    if parse_timestamp(approval["expires_at"]) <= now():
        tx.execute("UPDATE device_approvals SET status='expired' WHERE approval_id=?", (approval_id,))
        raise conflict("approval_expired")
    if not _binding_matches(approval, expected):
        raise conflict("approval_binding_mismatch")
    endpoint = tx.execute(
        "SELECT status FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
        (approval["endpoint_id"], tenant),
    ).fetchone()
    lease = tx.execute(
        "SELECT 1 FROM device_leases WHERE lease_id=? AND tenant_ref=? AND released_at IS NULL"
        " AND expires_at>?",
        (approval["lease_id"], tenant, iso()),
    ).fetchone()
    if endpoint is None or endpoint["status"] in {"offline", "revoked"} or lease is None:
        tx.execute(
            "UPDATE device_approvals SET status='invalidated', reason='endpoint_or_lease_invalid'"
            " WHERE approval_id=?",
            (approval_id,),
        )
        raise conflict("approval_stale")
    cursor = tx.execute(
        "UPDATE device_approvals SET status='consumed', consumed_at=?, consumed_by=?,"
        " command_id=COALESCE(?, command_id) WHERE approval_id=? AND status='approved'",
        (iso(), actor, command_id, approval_id),
    )
    if cursor.rowcount != 1:
        raise conflict("approval_already_consumed")
    _audit(
        tx,
        tenant=tenant,
        actor=actor,
        actor_type=actor_type,
        action="approval.consume",
        resource_type="device_approval",
        resource_id=approval_id,
        outcome="consumed",
        detail={"command_id": command_id},
    )
    _event(
        tx,
        tenant=tenant,
        event_type="approval.consumed",
        aggregate_type="device_approval",
        aggregate_id=approval_id,
        payload={"approval_id": approval_id, "command_id": command_id},
    )


def consume_approval(
    *,
    tenant: str,
    approval_id: str,
    binding: dict[str, Any],
    actor: str,
    actor_type: str,
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            _consume_approval_tx(
                tx,
                tenant=tenant,
                approval_id=approval_id,
                expected=binding,
                actor=actor,
                actor_type=actor_type,
            )
    finally:
        db.close()
    return {"approval_id": approval_id, "status": "consumed"}


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def find_command_by_idempotency(
    tenant: str, endpoint_id: str, capability_id: str, idempotency_key: str
) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_commands WHERE tenant_ref=? AND endpoint_id=? AND"
            " capability_id=? AND idempotency_key=?",
            (tenant, endpoint_id, capability_id, idempotency_key),
        ).fetchone()
    finally:
        db.close()
    return _command(row) if row else None


def get_command(tenant: str, command_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_commands WHERE command_id=? AND tenant_ref=?",
            (command_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _command(row) if row else None


def list_commands(
    tenant: str,
    *,
    endpoint_id: str | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    clauses = ["tenant_ref=?"]
    values: list[Any] = [tenant]
    if endpoint_id:
        clauses.append("endpoint_id=?")
        values.append(endpoint_id)
    if status:
        clauses.append("status=?")
        values.append(status)
    values.append(_list_limit(limit))
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM device_commands WHERE " + " AND ".join(clauses)  # nosec B608
            + " ORDER BY created_at DESC LIMIT ?",
            values,
        ).fetchall()
    finally:
        db.close()
    return [_command(row) for row in rows]


def _capability(capabilities: list[dict[str, Any]], capability_id: str,
                capability_version: str) -> dict[str, Any] | None:
    for capability in capabilities:
        if capability.get("id") == capability_id and capability.get("version") == capability_version:
            return capability
    return None


def _manifest_capability(manifest: dict[str, Any] | None, capability_id: str,
                         capability_version: str) -> dict[str, Any] | None:
    if not isinstance(manifest, dict):
        return None
    return _capability(list(manifest.get("capabilities") or []), capability_id, capability_version)


def resolve_manifest_capability(
    tenant: str, endpoint_id: str, capability_id: str, capability_version: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return ``(gateway, manifest capability)`` using trusted control state."""

    endpoint = get_endpoint(tenant, endpoint_id)
    if endpoint is None or not endpoint.get("gateway_id"):
        return None
    gateway = get_gateway(tenant, endpoint["gateway_id"])
    if gateway is None:
        return None
    capability = _manifest_capability(gateway.get("manifest"), capability_id, capability_version)
    if capability is None:
        return None
    return gateway, capability


def _advance_tx(
    tx: sqlite3.Connection,
    *,
    command: dict[str, Any],
    target: str,
    reason: str,
    actor: str,
    actor_type: str,
    event_type: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Advance a command along the allowed graph, recording every hop."""

    current = command["status"]
    if current == target:
        return command
    if command_rules.is_terminal(current):
        raise conflict("command_terminal", detail={"status": current})
    path = _transition_path(current, target)
    if path is None:
        raise conflict("illegal_command_transition", detail={"from": current, "to": target})
    timestamp = iso()
    for step in path:
        tx.execute(
            "UPDATE device_commands SET status=?, status_reason=?, updated_at=? WHERE command_id=?",
            (step, reason, timestamp, command["command_id"]),
        )
        tx.execute(
            "INSERT INTO command_transitions (command_id, tenant_ref, from_status, to_status,"
            " reason, actor_ref, actor_type, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (command["command_id"], command["tenant_ref"], command["status"], step, reason,
             actor, actor_type, timestamp),
        )
        _event(
            tx,
            tenant=command["tenant_ref"],
            event_type=event_type if step == target else "command.progress",
            aggregate_type="device_command",
            aggregate_id=command["command_id"],
            payload={"command_id": command["command_id"], "status": step, **(payload or {})},
            task_ref=command.get("task_ref"),
            run_ref=command.get("run_ref"),
            correlation_id=command.get("correlation_id"),
        )
        command = {**command, "status": step}
    return command


def _transition_path(start: str, target: str) -> list[str] | None:
    if start == target:
        return []
    frontier: list[list[str]] = [[start]]
    seen = {start}
    while frontier:
        path = frontier.pop(0)
        for candidate in command_rules.TRANSITIONS.get(path[-1], frozenset()):
            if candidate in seen:
                continue
            next_path = [*path, candidate]
            if candidate == target:
                return next_path[1:]
            seen.add(candidate)
            frontier.append(next_path)
    return None


def authorize_command(
    *,
    principal: Any,
    endpoint_id: str,
    capability_id: str,
    capability_version: str,
    parameters: dict[str, Any],
    intent: str,
    deadline: str,
    idempotency_key: str,
    lease_id: str,
    approval_id: str | None,
    approval_nonce: str | None,
    state_hash: str | None,
    state_version: str | None,
    expected_state: dict[str, Any] | None,
    task_ref: str | None,
    run_ref: str | None,
    correlation_id: str,
) -> dict[str, Any]:
    tenant = principal.require_tenant()
    db = connect()
    try:
        with transaction(db) as tx:
            endpoint_row = tx.execute(
                "SELECT * FROM device_endpoints WHERE endpoint_id=? AND tenant_ref=?",
                (endpoint_id, tenant),
            ).fetchone()
            if endpoint_row is None:
                raise hidden()
            endpoint = _endpoint(endpoint_row)
            gateway_id = endpoint.get("gateway_id") or ""
            if not gateway_id:
                raise conflict("endpoint_has_no_gateway")
            gateway_row = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchone()
            if gateway_row is None or gateway_row["status"] not in {"online", "degraded"}:
                raise conflict("gateway_not_online")
            gateway = _gateway(gateway_row)
            if not gateway.get("manifest_digest") or not gateway.get("manifest"):
                raise conflict("manifest_missing")
            if gateway.get("reported_manifest_digest") != gateway["manifest_digest"]:
                raise conflict("manifest_mismatch")
            if endpoint["status"] not in {"online", "degraded"}:
                raise conflict("endpoint_unavailable", detail={"status": endpoint["status"]})

            capability = _manifest_capability(
                gateway["manifest"], capability_id, capability_version
            )
            if capability is None:
                raise conflict("unsupported_capability", detail={
                    "capability_id": capability_id, "capability_version": capability_version,
                })
            if _capability(endpoint["capabilities"], capability_id, capability_version) is None:
                raise conflict("capability_not_observed")
            operation = str(capability.get("operation") or capability_id)
            risk_tier = str(capability.get("risk_tier") or "write")
            requires_state = bool(capability.get("requires_state"))
            device_id = endpoint.get("device_id")
            device_fingerprint = endpoint.get("device_fingerprint")
            if requires_state and (not state_hash or not state_version):
                raise invalid("state_hash_and_version_required")
            if gateway.get("device_fingerprint") and device_fingerprint != gateway["device_fingerprint"]:
                raise conflict("device_identity_mismatch")
            if principal.principal_type == "service" and principal.resource_type == "device_endpoint":
                if principal.resource_id and principal.resource_id != endpoint_id:
                    raise DeviceControlError(403, "service_token_resource_scope_mismatch")

            payload_hash = command_payload_hash(
                capability_id=capability_id,
                capability_version=capability_version,
                operation=operation,
                parameters=parameters,
                intent=intent,
                deadline=deadline,
                state_hash=state_hash,
                state_version=state_version,
                manifest_digest_value=gateway["manifest_digest"],
            )
            existing = tx.execute(
                "SELECT * FROM device_commands WHERE tenant_ref=? AND endpoint_id=? AND"
                " capability_id=? AND idempotency_key=?",
                (tenant, endpoint_id, capability_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                command = _command(existing)
                if command["payload_hash"] != payload_hash:
                    raise conflict("idempotency_conflict")
                return {"command": command, "deduplicated": True}

            deadline_at = parse_timestamp(deadline)
            if deadline_at <= now():
                raise invalid("deadline_in_past")
            if deadline_at > now() + timedelta(seconds=config.command_max_ttl_seconds()):
                raise invalid("deadline_exceeds_maximum")

            lease = tx.execute(
                "SELECT * FROM device_leases WHERE lease_id=? AND tenant_ref=? AND endpoint_id=?"
                " AND released_at IS NULL AND expires_at>?",
                (lease_id, tenant, endpoint_id, iso()),
            ).fetchone()
            if lease is None:
                raise conflict("active_device_lease_required")
            if lease["holder_ref"] != principal.subject and principal.principal_type != "admin":
                raise DeviceControlError(403, "lease_holder_mismatch")

            decision = policy.evaluate(
                {
                    "action_type": operation,
                    "intent": intent,
                    "app_id": parameters.get("app_id"),
                    "target_type": parameters.get("target_type"),
                },
                lease_mode=lease["mode"],
                principal_scopes=principal.scopes,
                risk_tier=risk_tier,
            )
            if decision["decision"] == "deny":
                _audit(
                    tx, tenant=tenant, actor=principal.subject, actor_type=principal.principal_type,
                    action="command.denied", resource_type="device_endpoint", resource_id=endpoint_id,
                    outcome="denied", detail={"reason": decision.get("reason"),
                                              "operation": operation},
                    correlation_id=correlation_id,
                )
                raise DeviceControlError(403, "policy_denied", detail={
                    "reason": decision.get("reason"),
                })
            if decision["decision"] == "ask":
                if not approval_id:
                    raise conflict("approval_required")
                if not approval_nonce:
                    raise invalid("approval_nonce_required")
            elif approval_id:
                raise invalid("approval_not_required")

            command_id = f"cmd_{secrets.token_urlsafe(18)}"
            timestamp = iso()
            parameters_json = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
            tx.execute(
                "INSERT INTO device_commands (command_id, tenant_ref, endpoint_id, gateway_id,"
                " task_ref, run_ref, correlation_id, capability_id, capability_version,"
                " operation, parameters_json, parameters_digest, intent, risk_tier, deadline,"
                " idempotency_key, payload_hash, lease_id, approval_id, approval_nonce,"
                " policy_version, policy_decision, state_hash, state_version, manifest_digest,"
                " device_id, device_fingerprint, expected_state_json, status, status_reason,"
                " submitted_by, submitter_type, created_at, updated_at, evidence_refs_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                " ?, ?, ?, ?, ?, ?, 'created', NULL, ?, ?, ?, ?, '[]')",
                (
                    command_id, tenant, endpoint_id, gateway_id, task_ref, run_ref,
                    correlation_id, capability_id, capability_version, operation,
                    parameters_json, digest_object(parameters), intent, risk_tier, deadline,
                    idempotency_key, payload_hash, lease_id, approval_id, approval_nonce,
                    decision.get("policy_version", ""), decision["decision"], state_hash,
                    state_version, gateway["manifest_digest"], device_id, device_fingerprint,
                    json.dumps(expected_state, sort_keys=True) if expected_state else None,
                    principal.subject, principal.principal_type, timestamp, timestamp,
                ),
            )
            command = _command(tx.execute(
                "SELECT * FROM device_commands WHERE command_id=?", (command_id,)
            ).fetchone())
            tx.execute(
                "INSERT INTO command_transitions (command_id, tenant_ref, from_status, to_status,"
                " reason, actor_ref, actor_type, occurred_at) VALUES (?, ?, NULL, 'created', ?, ?, ?, ?)",
                (command_id, tenant, "admitted", principal.subject, principal.principal_type, timestamp),
            )
            command = _advance_tx(
                tx, command=command, target="queued", reason="admitted",
                actor=principal.subject, actor_type=principal.principal_type,
                event_type="command.queued",
            )
            if decision["decision"] == "ask":
                expected_binding = {
                    "tenant_ref": tenant,
                    "endpoint_id": endpoint_id,
                    "device_id": device_id,
                    "device_fingerprint": device_fingerprint,
                    "gateway_id": gateway_id,
                    "lease_id": lease_id,
                    "capability_id": capability_id,
                    "capability_version": capability_version,
                    "operation": operation,
                    "manifest_digest": gateway["manifest_digest"],
                    "approval_nonce": approval_nonce,
                    "state_version": state_version,
                    "action_digest": approval_binding_digest(
                        tenant_ref=tenant,
                        endpoint_id=endpoint_id,
                        gateway_id=gateway_id,
                        capability_id=capability_id,
                        capability_version=capability_version,
                        operation=operation,
                        parameters=parameters,
                        intent=intent,
                        requester_ref=principal.subject,
                        lease_id=lease_id,
                        policy_version=decision.get("policy_version", ""),
                        state_hash=state_hash,
                        device_id=device_id,
                        device_fingerprint=device_fingerprint,
                        manifest_digest_value=gateway["manifest_digest"],
                        state_version=state_version,
                        approval_nonce=approval_nonce or "",
                    ),
                    "state_hash": state_hash,
                }
                _consume_approval_tx(
                    tx,
                    tenant=tenant,
                    approval_id=approval_id or "",
                    expected=expected_binding,
                    actor=principal.subject,
                    actor_type=principal.principal_type,
                    command_id=command_id,
                )
            _audit(
                tx, tenant=tenant, actor=principal.subject, actor_type=principal.principal_type,
                action="command.submit", resource_type="device_command", resource_id=command_id,
                outcome="allowed",
                detail={"capability_id": capability_id, "operation": operation,
                        "decision": decision["decision"], "approval_id": approval_id,
                        "manifest_digest": gateway["manifest_digest"]},
                correlation_id=correlation_id,
            )
            command = _command(tx.execute(
                "SELECT * FROM device_commands WHERE command_id=?", (command_id,)
            ).fetchone())
            return {"command": command, "deduplicated": False}
    finally:
        db.close()


def dispatch_commands(tenant: str, gateway_id: str, *, limit: int = 10) -> list[dict[str, Any]]:
    db = connect()
    dispatched: list[dict[str, Any]] = []
    try:
        with transaction(db) as tx:
            gateway = tx.execute(
                "SELECT * FROM device_gateways WHERE gateway_id=? AND tenant_ref=?",
                (gateway_id, tenant),
            ).fetchone()
            if gateway is None:
                raise hidden()
            if gateway["status"] not in {"online", "degraded"}:
                raise conflict("gateway_not_online")
            if not gateway["manifest_digest"]:
                raise conflict("manifest_missing")
            if gateway["reported_manifest_digest"] != gateway["manifest_digest"]:
                raise conflict("manifest_mismatch", detail={
                    "expected": gateway["manifest_digest"],
                    "reported": gateway["reported_manifest_digest"],
                })
            timestamp = iso()
            expired = tx.execute(
                "SELECT * FROM device_commands WHERE gateway_id=? AND tenant_ref=?"
                " AND status IN ('created','validated','authorized','queued') AND deadline<=?",
                (gateway_id, tenant, timestamp),
            ).fetchall()
            for row in expired:
                command = _command(row)
                _advance_tx(
                    tx, command=command, target="expired", reason="deadline_elapsed",
                    actor="system", actor_type="system", event_type="command.expired",
                )
                tx.execute(
                    "UPDATE device_commands SET completed_at=? WHERE command_id=?",
                    (timestamp, command["command_id"]),
                )
            rows = tx.execute(
                "SELECT c.*, (SELECT d.platform_instance_id FROM iot_devices d"
                " WHERE d.device_id=c.device_id AND d.tenant_ref=c.tenant_ref)"
                " AS platform_instance_id, (SELECT d.updated_at FROM iot_devices d"
                " WHERE d.device_id=c.device_id AND d.tenant_ref=c.tenant_ref)"
                " AS binding_updated_at FROM device_commands c"
                " WHERE c.gateway_id=? AND c.tenant_ref=?"
                " AND c.status='queued' AND c.deadline>? ORDER BY c.created_at LIMIT ?",
                (gateway_id, tenant, timestamp, _list_limit(limit)),
            ).fetchall()
            for row in rows:
                command = _command(row)
                _advance_tx(
                    tx, command=command, target="dispatched", reason="gateway_pull",
                    actor=gateway_id, actor_type="gateway", event_type="command.dispatched",
                )
                tx.execute(
                    "UPDATE device_commands SET dispatched_at=?, attempt_count=attempt_count+1"
                    " WHERE command_id=?",
                    (timestamp, command["command_id"]),
                )
                dispatched.append(_command(tx.execute(
                    "SELECT c.*, (SELECT d.platform_instance_id FROM iot_devices d"
                    " WHERE d.device_id=c.device_id AND d.tenant_ref=c.tenant_ref)"
                    " AS platform_instance_id, (SELECT d.updated_at FROM iot_devices d"
                    " WHERE d.device_id=c.device_id AND d.tenant_ref=c.tenant_ref)"
                    " AS binding_updated_at FROM device_commands c WHERE c.command_id=?",
                    (command["command_id"],),
                ).fetchone()))
    finally:
        db.close()
    return dispatched


def record_command_progress(
    *,
    tenant: str,
    gateway_id: str,
    command_id: str,
    status: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in command_rules.GATEWAY_PROGRESS_STATUSES:
        raise invalid("invalid_progress_status")
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_commands WHERE command_id=? AND tenant_ref=?",
                (command_id, tenant),
            ).fetchone()
            if row is None:
                raise hidden()
            command = _command(row)
            if command["gateway_id"] != gateway_id:
                raise hidden()
            if command["status"] == status:
                tx.execute(
                    "UPDATE device_commands SET provider_status=? WHERE command_id=?",
                    (status, command_id),
                )
                return {"command_id": command_id, "status": status, "deduplicated": True}
            updated = _advance_tx(
                tx, command=command, target=status, reason="gateway_progress",
                actor=gateway_id, actor_type="gateway", event_type="command.progress",
                payload=detail or {},
            )
            tx.execute(
                "UPDATE device_commands SET provider_status=? WHERE command_id=?",
                (status, command_id),
            )
            return {"command_id": command_id, "status": updated["status"], "deduplicated": False}
    finally:
        db.close()


def record_command_result(
    *,
    tenant: str,
    gateway_id: str,
    command_id: str,
    status: str,
    result: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
    evidence_refs: list[str] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    if status not in command_rules.RESULT_STATUSES:
        raise invalid("invalid_result_status")
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_commands WHERE command_id=? AND tenant_ref=?",
                (command_id, tenant),
            ).fetchone()
            if row is None:
                raise hidden()
            command = _command(row)
            if command["gateway_id"] != gateway_id:
                raise hidden()
            if command_rules.is_terminal(command["status"]):
                if command["status"] == status:
                    return {"command_id": command_id, "status": status, "deduplicated": True}
                # Late or conflicting result: retain it for reconciliation but
                # never reopen a terminal command.
                _audit(
                    tx, tenant=tenant, actor=gateway_id, actor_type="gateway",
                    action="command.late_result", resource_type="device_command",
                    resource_id=command_id, outcome="retained",
                    detail={"current": command["status"], "reported": status,
                            "result": result or {}, "verification": verification or {}},
                    correlation_id=command["correlation_id"],
                )
                _event(
                    tx, tenant=tenant, event_type="command.late_result",
                    aggregate_type="device_command", aggregate_id=command_id,
                    payload={"command_id": command_id, "current": command["status"],
                             "reported": status},
                    task_ref=command.get("task_ref"), run_ref=command.get("run_ref"),
                    correlation_id=command["correlation_id"],
                )
                return {"command_id": command_id, "status": command["status"],
                        "late_result_retained": True}

            effective_status = status
            effective_reason = reason
            if status == "executed_unverified":
                effective_status = "uncertain"
                effective_reason = reason or "executed_unverified"
            elif status == "succeeded" and not command_rules.verification_is_sufficient(verification):
                effective_status = "uncertain"
                effective_reason = "verification_insufficient"

            timestamp = iso()
            if effective_status == "succeeded":
                updated = _advance_tx(
                    tx, command=command, target="verifying", reason="gateway_result",
                    actor=gateway_id, actor_type="gateway", event_type="command.verifying",
                )
                updated = _advance_tx(
                    tx, command=updated, target="succeeded", reason="verified",
                    actor=gateway_id, actor_type="gateway", event_type="command.succeeded",
                )
            else:
                updated = _advance_tx(
                    tx, command=command, target=effective_status,
                    reason=effective_reason or "gateway_result",
                    actor=gateway_id, actor_type="gateway",
                    event_type=f"command.{effective_status}",
                )
            evidence = command_rules.redact_evidence(evidence_refs)
            tx.execute(
                "UPDATE device_commands SET result_json=?, verification_json=?,"
                " evidence_refs_json=?, completed_at=?, updated_at=?, status_reason=?,"
                " provider_status=?"
                " WHERE command_id=?",
                (
                    json.dumps(result, sort_keys=True) if result is not None else None,
                    json.dumps(verification, sort_keys=True) if verification is not None else None,
                    json.dumps(evidence),
                    timestamp,
                    timestamp,
                    effective_reason,
                    status,
                    command_id,
                ),
            )
            _audit(
                tx, tenant=tenant, actor=gateway_id, actor_type="gateway",
                action="command.result", resource_type="device_command", resource_id=command_id,
                outcome=effective_status,
                detail={"reported_status": status, "verification_method":
                        (verification or {}).get("method")},
                correlation_id=command["correlation_id"],
            )
            final = _command(tx.execute(
                "SELECT * FROM device_commands WHERE command_id=?", (command_id,)
            ).fetchone())
            return {"command_id": command_id, "status": final["status"]}
    finally:
        db.close()


def cancel_command(
    *, tenant: str, command_id: str, actor: str, actor_type: str, reason: str | None = None
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_commands WHERE command_id=? AND tenant_ref=?",
                (command_id, tenant),
            ).fetchone()
            if row is None:
                raise hidden()
            command = _command(row)
            if command_rules.is_terminal(command["status"]):
                raise conflict("command_terminal", detail={"status": command["status"]})
            if command["status"] not in {"created", "validated", "authorized", "queued"}:
                raise conflict("cancel_not_guaranteed", detail={"status": command["status"]})
            _advance_tx(
                tx, command=command, target="cancelled", reason=reason or "cancelled_by_requester",
                actor=actor, actor_type=actor_type, event_type="command.cancelled",
            )
            tx.execute(
                "UPDATE device_commands SET completed_at=?, updated_at=? WHERE command_id=?",
                (iso(), iso(), command_id),
            )
            _audit(
                tx, tenant=tenant, actor=actor, actor_type=actor_type,
                action="command.cancel", resource_type="device_command", resource_id=command_id,
                outcome="cancelled", correlation_id=command["correlation_id"],
            )
            return {"command_id": command_id, "status": "cancelled"}
    finally:
        db.close()


def command_transitions(tenant: str, command_id: str) -> list[dict[str, Any]]:
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM command_transitions WHERE command_id=? AND tenant_ref=?"
            " ORDER BY transition_id",
            (command_id, tenant),
        ).fetchall()
    finally:
        db.close()
    return [dict(row) for row in rows]


def operation_alerts(tenant: str) -> list[dict[str, Any]]:
    """Tenant-scoped operational alerts computed from authoritative state."""

    alerts: list[dict[str, Any]] = []
    db = connect()
    try:
        gateways = db.execute(
            "SELECT gateway_id, status, last_heartbeat_at, last_error, queue_depth"
            " FROM device_gateways WHERE tenant_ref=? AND status!='revoked'",
            (tenant,),
        ).fetchall()
        for gateway in gateways:
            if gateway["status"] in {"offline", "degraded"}:
                alerts.append({
                    "severity": "warning" if gateway["status"] == "degraded" else "critical",
                    "code": f"gateway_{gateway['status']}",
                    "resource_type": "device_gateway",
                    "resource_id": gateway["gateway_id"],
                    "detail": {"last_error": gateway["last_error"],
                               "queue_depth": gateway["queue_depth"]},
                })
            if gateway["last_heartbeat_at"]:
                age = (now() - parse_timestamp(gateway["last_heartbeat_at"])).total_seconds()
                if age > config.stale_after_seconds():
                    alerts.append({
                        "severity": "critical",
                        "code": "gateway_heartbeat_stale",
                        "resource_type": "device_gateway",
                        "resource_id": gateway["gateway_id"],
                        "detail": {"heartbeat_age_seconds": age},
                    })
        uncertain = db.execute(
            "SELECT COUNT(*) AS count FROM device_commands WHERE tenant_ref=?"
            " AND status='uncertain' AND updated_at>=?",
            (tenant, iso(now() - timedelta(hours=24))),
        ).fetchone()
        if uncertain and uncertain["count"]:
            alerts.append({
                "severity": "warning",
                "code": "uncertain_commands",
                "resource_type": "device_command",
                "resource_id": None,
                "detail": {"count": uncertain["count"], "window_hours": 24},
            })
    finally:
        db.close()
    return alerts


# ---------------------------------------------------------------------------
# IoT platform pilot
# ---------------------------------------------------------------------------


def _platform(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["health"] = _json(data.pop("health_json", "{}"), {})
    return data


def _iot_device(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["capabilities"] = _json(data.pop("capabilities_json", "[]"), [])
    data["metadata"] = _json(data.pop("metadata_json", "{}"), {})
    return data


def create_platform_instance(*, tenant: str, platform_instance_id: str, adapter_id: str,
                             base_url: str, secret_ref: str, platform_version: str,
                             gateway_id: str) -> dict[str, Any]:
    timestamp = iso()
    db = connect()
    try:
        with transaction(db) as tx:
            try:
                tx.execute(
                    "INSERT INTO platform_instances (platform_instance_id, tenant_ref,"
                    " adapter_id, base_url, secret_ref, platform_version, gateway_id,"
                    " status, health_json, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, 'configured', '{}', ?, ?)",
                    (platform_instance_id, tenant, adapter_id, base_url, secret_ref,
                     platform_version, gateway_id, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise conflict("platform_instance_exists") from exc
            _audit(tx, tenant=tenant, actor=None, actor_type="principal",
                   action="platform_instance.create", resource_type="platform_instance",
                   resource_id=platform_instance_id, outcome="allowed",
                   detail={"adapter_id": adapter_id, "base_url": base_url})
            _event(tx, tenant=tenant, event_type="platform_instance.created",
                   aggregate_type="platform_instance", aggregate_id=platform_instance_id,
                   payload={"adapter_id": adapter_id, "gateway_id": gateway_id})
    finally:
        db.close()
    return get_platform_instance(tenant, platform_instance_id) or {}


def get_platform_instance(tenant: str, platform_instance_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM platform_instances WHERE platform_instance_id=? AND tenant_ref=?",
            (platform_instance_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _platform(row) if row else None


def list_platform_instances(tenant: str) -> list[dict[str, Any]]:
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM platform_instances WHERE tenant_ref=? ORDER BY platform_instance_id",
            (tenant,),
        ).fetchall()
    finally:
        db.close()
    return [_platform(row) for row in rows]


def set_platform_health(tenant: str, platform_instance_id: str, health: dict[str, Any],
                        status: str) -> None:
    db = connect()
    try:
        with transaction(db) as tx:
            tx.execute(
                "UPDATE platform_instances SET health_json=?, status=?, updated_at=?"
                " WHERE platform_instance_id=? AND tenant_ref=?",
                (json.dumps(health, sort_keys=True), status, iso(),
                 platform_instance_id, tenant),
            )
    finally:
        db.close()


def disable_platform_instance(tenant: str, platform_instance_id: str) -> bool:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT gateway_id FROM platform_instances WHERE platform_instance_id=?"
                " AND tenant_ref=?",
                (platform_instance_id, tenant),
            ).fetchone()
            if row is None:
                return False
            tx.execute(
                "UPDATE platform_instances SET status='disabled', updated_at=?"
                " WHERE platform_instance_id=? AND tenant_ref=?",
                (iso(), platform_instance_id, tenant),
            )
            tx.execute(
                "UPDATE gateway_credentials SET revoked_at=? WHERE gateway_id=? AND revoked_at IS NULL",
                (iso(), row["gateway_id"]),
            )
            tx.execute(
                "UPDATE device_gateways SET status='offline' WHERE gateway_id=? AND tenant_ref=?",
                (row["gateway_id"], tenant),
            )
            for device in tx.execute(
                "SELECT device_id, endpoint_id FROM iot_devices WHERE platform_instance_id=?"
                " AND tenant_ref=?",
                (platform_instance_id, tenant),
            ).fetchall():
                tx.execute(
                    "UPDATE iot_devices SET trust_state='pending', connectivity_state='unknown',"
                    " capabilities_json='[]', updated_at=? WHERE device_id=?",
                    (iso(), device["device_id"]),
                )
                if device["endpoint_id"]:
                    _invalidate_endpoint_state(
                        tx, tenant=tenant, endpoint_id=device["endpoint_id"],
                        reason="platform_instance_disabled",
                    )
                    tx.execute(
                        "UPDATE device_endpoints SET status='offline' WHERE endpoint_id=?"
                        " AND tenant_ref=? AND status!='revoked'",
                        (device["endpoint_id"], tenant),
                    )
            _audit(tx, tenant=tenant, actor=None, actor_type="principal",
                   action="platform_instance.disable", resource_type="platform_instance",
                   resource_id=platform_instance_id, outcome="allowed")
            _event(tx, tenant=tenant, event_type="platform_instance.disabled",
                   aggregate_type="platform_instance", aggregate_id=platform_instance_id,
                   payload={"platform_instance_id": platform_instance_id})
            return True
    finally:
        db.close()


def sync_discovered_devices(*, tenant: str, platform_instance_id: str,
                            devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if get_platform_instance(tenant, platform_instance_id) is None:
        raise hidden()
    timestamp = iso()
    result: list[dict[str, Any]] = []
    db = connect()
    try:
        with transaction(db) as tx:
            for device in devices:
                device_id = str(device["device_id"])
                native_id = str(device["native_id"])
                capabilities = [item for item in device.get("capabilities", [])
                                if item.get("capability_id")]
                tx.execute(
                    "INSERT INTO iot_devices (device_id, tenant_ref, platform_instance_id,"
                    " native_platform, native_id, display_name, device_type, area, trust_state,"
                    " connectivity_state, endpoint_id, capabilities_json, metadata_json,"
                    " created_at, updated_at)"
                    " VALUES (?, ?, ?, 'homeassistant', ?, ?, ?, ?, 'pending', 'unknown', NULL,"
                    " ?, ?, ?, ?)"
                    " ON CONFLICT(tenant_ref, platform_instance_id, native_id) DO UPDATE SET"
                    " display_name=excluded.display_name, device_type=excluded.device_type,"
                    " area=excluded.area, capabilities_json=excluded.capabilities_json,"
                    " updated_at=excluded.updated_at",
                    (device_id, tenant, platform_instance_id, native_id,
                     str(device.get("display_name") or native_id),
                     str(device.get("device_type") or "entity"), device.get("area"),
                     json.dumps(capabilities, sort_keys=True),
                     json.dumps(device.get("metadata") or {}, sort_keys=True),
                     timestamp, timestamp),
                )
                row = tx.execute(
                    "SELECT * FROM iot_devices WHERE tenant_ref=? AND platform_instance_id=?"
                    " AND native_id=?", (tenant, platform_instance_id, native_id),
                ).fetchone()
                result.append(_iot_device(row))
            _audit(tx, tenant=tenant, actor=None, actor_type="principal",
                   action="platform_instance.discover", resource_type="platform_instance",
                   resource_id=platform_instance_id, outcome="allowed",
                   detail={"count": len(devices)})
            _event(tx, tenant=tenant, event_type="iot.devices.discovered",
                   aggregate_type="platform_instance", aggregate_id=platform_instance_id,
                   payload={"count": len(devices)})
    finally:
        db.close()
    return result


def list_iot_devices(tenant: str, *, platform_instance_id: str | None = None,
                     trust_state: str | None = None) -> list[dict[str, Any]]:
    clauses = ["tenant_ref=?"]
    values: list[Any] = [tenant]
    if platform_instance_id:
        clauses.append("platform_instance_id=?")
        values.append(platform_instance_id)
    if trust_state:
        clauses.append("trust_state=?")
        values.append(trust_state)
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM iot_devices WHERE " + " AND ".join(clauses)  # nosec B608
            + " ORDER BY device_id", values,
        ).fetchall()
    finally:
        db.close()
    return [_iot_device(row) for row in rows]


def get_iot_device(tenant: str, device_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM iot_devices WHERE device_id=? AND tenant_ref=?",
            (device_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _iot_device(row) if row else None


def claim_iot_device(*, tenant: str, device_id: str, capability_ids: list[str],
                     endpoint_id: str | None = None) -> dict[str, Any]:
    allowed = {item.get("capability_id") for item in
               (get_iot_device(tenant, device_id) or {}).get("capabilities", [])}
    requested = set(capability_ids)
    if not requested:
        raise invalid("at_least_one_capability_required")
    if not requested.issubset(allowed):
        raise conflict("capability_not_discovered")
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM iot_devices WHERE device_id=? AND tenant_ref=?",
                (device_id, tenant),
            ).fetchone()
            if row is None:
                raise hidden()
            if row["trust_state"] == "revoked":
                raise conflict("device_revoked")
            current_caps = json.loads(row["capabilities_json"])
            kept = [item for item in current_caps
                    if item.get("capability_id") in requested]
            tx.execute(
                "UPDATE iot_devices SET trust_state='claimed', capabilities_json=?,"
                " endpoint_id=COALESCE(?, endpoint_id), updated_at=? WHERE device_id=?",
                (json.dumps(kept, sort_keys=True), endpoint_id, iso(), device_id),
            )
            _audit(tx, tenant=tenant, actor=None, actor_type="principal",
                   action="iot_device.claim", resource_type="iot_device", resource_id=device_id,
                   outcome="allowed", detail={"capabilities": sorted(requested)})
            _event(tx, tenant=tenant, event_type="iot.device.claimed",
                   aggregate_type="iot_device", aggregate_id=device_id,
                   payload={"capabilities": sorted(requested), "endpoint_id": endpoint_id})
    finally:
        db.close()
    return get_iot_device(tenant, device_id) or {}


def binding_revision(updated_at: str | None) -> int:
    """Deterministic binding revision from the authoritative device row."""

    value = str(updated_at or "").strip()
    if not value:
        return 0
    parsed = parse_timestamp(value)
    return max(1, int(parsed.timestamp() * 1_000_000))


def _binding_document_signature(document: dict[str, Any], key: str) -> str:
    payload = {k: v for k, v in document.items()
               if k not in {"signature", "signature_algorithm"}}
    return hmac.new(key.encode("utf-8"), canonical_json(payload).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def gateway_binding_document(tenant: str, gateway_id: str, *,
                             ttl_seconds: float | None = None) -> dict[str, Any]:
    """Signed, versioned binding snapshot for one edge gateway.

    Only claimed devices with a materialized endpoint are included. The
    signature covers tenant/gateway/platform, revisions, bindings and validity
    so the edge can reject forged, cross-scope, expired or replayed documents.
    """

    gateway = get_gateway(tenant, gateway_id)
    if gateway is None:
        raise hidden()
    if gateway["status"] not in {"online", "degraded"}:
        raise conflict("gateway_not_online")
    key = config.binding_signing_key()
    key_id = config.binding_key_id()
    if len(key.encode("utf-8")) < 32 or not key_id:
        raise dependency_unavailable("binding_signing_not_configured")
    db = connect()
    try:
        platform_row = db.execute(
            "SELECT * FROM platform_instances WHERE gateway_id=? AND tenant_ref=?",
            (gateway_id, tenant),
        ).fetchone()
    finally:
        db.close()
    if platform_row is None:
        raise conflict("platform_instance_missing")
    platform = _platform(platform_row)
    devices = list_iot_devices(
        tenant, platform_instance_id=platform["platform_instance_id"], trust_state="claimed"
    )
    now = datetime.now(timezone.utc)
    bindings: list[dict[str, Any]] = []
    for device in devices:
        endpoint_id = device.get("endpoint_id")
        capabilities = [str(item.get("capability_id")) for item in device.get("capabilities", [])
                        if item.get("capability_id")]
        if not endpoint_id or not capabilities:
            continue
        revision = binding_revision(str(device.get("updated_at") or ""))
        bindings.append({
            "entity_id": device["native_id"],
            "device_id": device["device_id"],
            "endpoint_id": endpoint_id,
            "capabilities": capabilities,
            "revision": max(1, revision),
            "issued_at": str(device.get("updated_at") or iso(now)),
        })
    if not bindings:
        raise conflict("no_claimed_devices")
    effective_ttl = ttl_seconds if ttl_seconds is not None else float(
        config.binding_document_ttl_seconds()
    )
    document: dict[str, Any] = {
        "schema": "dc-binding-document/v1",
        "tenant_ref": tenant,
        "gateway_id": gateway_id,
        "platform_instance_id": platform["platform_instance_id"],
        # Monotonic document revision so a revocation always supersedes the
        # edge cache even when the revoked device carried the highest binding
        # revision. Command matching still uses each binding's exact revision.
        "revision": max(
            max(item["revision"] for item in bindings),
            int(now.timestamp() * 1_000_000),
        ),
        "nonce": secrets.token_urlsafe(18),
        "issued_at": iso(now),
        "valid_until": iso(now + timedelta(seconds=max(30.0, effective_ttl))),
        "source": "control-plane",
        "bindings": bindings,
        "key_id": key_id,
    }
    document["signature_algorithm"] = "hmac-sha256"
    document["signature"] = _binding_document_signature(document, key)
    return document


def set_iot_device_endpoint(tenant: str, device_id: str, endpoint_id: str) -> None:
    db = connect()
    try:
        with transaction(db) as tx:
            tx.execute(
                "UPDATE iot_devices SET endpoint_id=?, updated_at=? WHERE device_id=?"
                " AND tenant_ref=?", (endpoint_id, iso(), device_id, tenant),
            )
    finally:
        db.close()


def upsert_twin(*, tenant: str, device_id: str, desired: dict[str, Any] | None = None,
                reported: dict[str, Any] | None = None,
                observed: dict[str, Any] | None = None) -> dict[str, Any]:
    device = get_iot_device(tenant, device_id)
    if device is None:
        raise hidden()
    db = connect()
    try:
        with transaction(db) as tx:
            current = tx.execute(
                "SELECT * FROM iot_twins WHERE device_id=? AND tenant_ref=?",
                (device_id, tenant),
            ).fetchone()
            existing = dict(current) if current else {
                "desired_json": "{}", "reported_json": "{}", "observed_json": "{}",
            }
            previous_observed = _json(existing["observed_json"], {})
            next_observed = observed
            if observed is not None:
                next_observed = _keep_newer(previous_observed, observed)
            tx.execute(
                "INSERT INTO iot_twins (device_id, tenant_ref, desired_json, reported_json,"
                " observed_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(device_id) DO UPDATE SET desired_json=excluded.desired_json,"
                " reported_json=excluded.reported_json, observed_json=excluded.observed_json,"
                " updated_at=excluded.updated_at",
                (
                    device_id, tenant,
                    json.dumps(desired, sort_keys=True) if desired is not None else existing["desired_json"],
                    json.dumps(reported, sort_keys=True) if reported is not None else existing["reported_json"],
                    json.dumps(next_observed, sort_keys=True) if next_observed is not None else existing["observed_json"],
                    iso(),
                ),
            )
    finally:
        db.close()
    return get_twin(tenant, device_id) or {}


def _keep_newer(existing: dict[str, Any], incoming: dict[str, Any],
                *, timestamp_key: str = "observed_at") -> dict[str, Any]:
    old_ts = str(existing.get(timestamp_key) or "")
    new_ts = str(incoming.get(timestamp_key) or "")
    if old_ts and new_ts and new_ts < old_ts:
        return existing
    return incoming


def insert_telemetry(*, tenant: str, platform_instance_id: str, device_id: str,
                     entity_id: str | None, metric: str, value: Any, unit: str | None,
                     observed_at: str, source: str, quality: str, status: str,
                     schema_version: str = "1") -> tuple[dict[str, Any], bool]:
    if get_iot_device(tenant, device_id) is None:
        raise hidden()
    telemetry_id = f"tel_{secrets.token_urlsafe(18)}"
    db = connect()
    try:
        with transaction(db) as tx:
            cursor = tx.execute(
                "INSERT OR IGNORE INTO iot_telemetry (telemetry_id, tenant_ref,"
                " platform_instance_id, device_id, entity_id, metric, value_json, unit,"
                " observed_at, received_at, source, quality, status, schema_version)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (telemetry_id, tenant, platform_instance_id, device_id, entity_id, metric,
                 json.dumps(value, sort_keys=True), unit, observed_at, iso(), source,
                 quality, status, schema_version),
            )
            deduplicated = cursor.rowcount == 0
            row = tx.execute(
                "SELECT * FROM iot_telemetry WHERE tenant_ref=? AND device_id=? AND metric=?"
                " AND observed_at=? AND source=?",
                (tenant, device_id, metric, observed_at, source),
            ).fetchone()
            if row is None:
                raise invalid("telemetry_insert_failed")
            result = dict(row)
            result["value"] = _json(result.pop("value_json"), None)
            if not deduplicated:
                _event(tx, tenant=tenant, event_type="iot.telemetry.received",
                       aggregate_type="iot_device", aggregate_id=device_id,
                       payload={"metric": metric, "observed_at": observed_at})
            return result, deduplicated
    finally:
        db.close()


def list_telemetry(tenant: str, device_id: str, *, metric: str | None = None,
                   since: str | None = None, until: str | None = None,
                   limit: int | None = None) -> list[dict[str, Any]]:
    clauses = ["tenant_ref=?", "device_id=?"]
    values: list[Any] = [tenant, device_id]
    if metric:
        clauses.append("metric=?")
        values.append(metric)
    if since:
        clauses.append("observed_at>=?")
        values.append(since)
    if until:
        clauses.append("observed_at<=?")
        values.append(until)
    values.append(_list_limit(limit))
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM iot_telemetry WHERE " + " AND ".join(clauses)  # nosec B608
            + " ORDER BY observed_at DESC LIMIT ?", values,
        ).fetchall()
    finally:
        db.close()
    result = []
    for row in rows:
        item = dict(row)
        item["value"] = _json(item.pop("value_json"), None)
        result.append(item)
    return result


def get_twin(tenant: str, device_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM iot_twins WHERE device_id=? AND tenant_ref=?",
            (device_id, tenant),
        ).fetchone()
    finally:
        db.close()
    if row is None:
        return None
    return {
        "device_id": row["device_id"], "tenant_ref": row["tenant_ref"],
        "desired": _json(row["desired_json"], {}),
        "reported": _json(row["reported_json"], {}),
        "observed": _json(row["observed_json"], {}),
        "updated_at": row["updated_at"],
    }


TWIN_FRESHNESS_SECONDS: dict[str, float] = {
    "sensor": 60.0,
    "binary_sensor": 60.0,
    "light": 300.0,
    "switch": 300.0,
}
DEFAULT_TWIN_FRESHNESS_SECONDS = 300.0


def twin_freshness(device: dict[str, Any], twin: dict[str, Any] | None, *,
                   moment: datetime | None = None) -> dict[str, Any]:
    """Per-device-type freshness; a single global threshold is unsafe."""

    observed = (twin or {}).get("observed") or {}
    max_age = TWIN_FRESHNESS_SECONDS.get(
        str(device.get("device_type") or ""), DEFAULT_TWIN_FRESHNESS_SECONDS
    )
    timestamp = parse_timestamp(str(observed.get("observed_at") or "")) \
        if observed.get("observed_at") else None
    current = moment or now()
    age = max(0.0, (current - timestamp).total_seconds()) if timestamp else None
    stale = (
        timestamp is None
        or age is None
        or age > max_age
        or observed.get("connectivity") != "online"
    )
    return {
        "observed_at": observed.get("observed_at"),
        "age_seconds": age,
        "max_age_seconds": max_age,
        "stale": stale,
        "quality": observed.get("quality"),
        "connectivity": observed.get("connectivity"),
    }


# ---------------------------------------------------------------------------
# Home Assistant durable event ingestion
# ---------------------------------------------------------------------------

HA_ATTRIBUTE_NOISE = frozenset({"friendly_name", "icon"})
HA_EVENT_SCHEMA_VERSION = "1"


def _ha_attributes_hash(attributes: dict[str, Any]) -> str:
    relevant = {key: value for key, value in attributes.items()
                if key not in HA_ATTRIBUTE_NOISE}
    return digest_object(relevant)


def _ha_event_key(*, context_id: str, entity_id: str, state: str | None,
                  attributes_hash: str, observed_at: str) -> str:
    # Attribute and last_updated changes must not be deduplicated: two events
    # with the same entity/state but different attributes are real changes.
    return digest_object({
        "context_id": context_id,
        "entity_id": entity_id,
        "state": state,
        "attributes_hash": attributes_hash,
        "observed_at": observed_at,
    })


def _ha_ingest_row(tx: sqlite3.Connection, tenant: str,
                   platform_instance_id: str) -> sqlite3.Row:
    row = tx.execute(
        "SELECT * FROM ha_ingest_state WHERE tenant_ref=? AND platform_instance_id=?",
        (tenant, platform_instance_id),
    ).fetchone()
    if row is not None:
        return row
    tx.execute(
        "INSERT INTO ha_ingest_state (platform_instance_id, tenant_ref, updated_at)"
        " VALUES (?, ?, ?)",
        (platform_instance_id, tenant, iso()),
    )
    return tx.execute(
        "SELECT * FROM ha_ingest_state WHERE tenant_ref=? AND platform_instance_id=?",
        (tenant, platform_instance_id),
    ).fetchone()


def record_ha_event(*, tenant: str, platform_instance_id: str, device_id: str,
                    entity_id: str, state: str | None,
                    attributes: dict[str, Any] | None = None,
                    observed_at: str, received_at: str,
                    context_id: str = "", quality: str = "good",
                    status: str = "ok", owner_ref: str | None = None,
                    owner_generation: int | None = None) -> dict[str, Any]:
    """Persist one normalized HA state event and advance the tenant cursor.

    The device must already be claimed on this exact platform instance. The
    event log has a deterministic dedupe key, so replay after a crash or a
    reconnect is idempotent. Telemetry and the observed twin are written in the
    same transaction, *before* the persisted cursor advances.
    """

    attributes = attributes or {}
    attrs_hash = _ha_attributes_hash(attributes)
    event_key = _ha_event_key(
        context_id=context_id, entity_id=entity_id, state=state,
        attributes_hash=attrs_hash, observed_at=observed_at,
    )
    db = connect()
    try:
        with transaction(db) as tx:
            device = tx.execute(
                "SELECT * FROM iot_devices WHERE device_id=? AND tenant_ref=?"
                " AND platform_instance_id=?",
                (device_id, tenant, platform_instance_id),
            ).fetchone()
            if device is None:
                raise hidden()
            if device["trust_state"] != "claimed":
                raise conflict("device_not_claimed")
            if owner_ref is not None and owner_generation is not None:
                _assert_ha_ingest_owner(tx, tenant, platform_instance_id,
                                        owner_ref, owner_generation)
            cursor = tx.execute(
                "INSERT OR IGNORE INTO ha_event_log (event_key, tenant_ref,"
                " platform_instance_id, device_id, entity_id, state, attributes_json,"
                " attributes_hash, observed_at, received_at, context_id, quality, status,"
                " schema_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event_key, tenant, platform_instance_id, device_id, entity_id, state,
                 json.dumps(attributes, sort_keys=True), attrs_hash, observed_at,
                 received_at, context_id, quality, status, HA_EVENT_SCHEMA_VERSION),
            )
            duplicate = cursor.rowcount == 0
            ingested = _ha_ingest_row(tx, tenant, platform_instance_id)
            if duplicate:
                tx.execute(
                    "UPDATE ha_ingest_state SET duplicate_count=duplicate_count+1,"
                    " connected=1, last_error=NULL, updated_at=? WHERE tenant_ref=?"
                    " AND platform_instance_id=?",
                    (iso(), tenant, platform_instance_id),
                )
            else:
                tx.execute(
                    "INSERT OR IGNORE INTO iot_telemetry (telemetry_id, tenant_ref,"
                    " platform_instance_id, device_id, entity_id, metric, value_json, unit,"
                    " observed_at, received_at, source, quality, status, schema_version)"
                    " VALUES (?, ?, ?, ?, ?, 'state', ?, NULL, ?, ?,"
                    " 'home-assistant-ws', ?, ?, ?)",
                    (f"tel_{secrets.token_urlsafe(18)}", tenant, platform_instance_id,
                     device_id, entity_id, json.dumps(state), observed_at, received_at,
                     quality, status, HA_EVENT_SCHEMA_VERSION),
                )
                if status == "ok":
                    current = tx.execute(
                        "SELECT observed_json FROM iot_twins WHERE device_id=? AND tenant_ref=?",
                        (device_id, tenant),
                    ).fetchone()
                    previous = _json(current["observed_json"], {}) if current else {}
                    incoming = {
                        "state": state,
                        "attributes": attributes,
                        "observed_at": observed_at,
                        "received_at": received_at,
                        "source": "home-assistant-ws",
                        "quality": quality,
                        "connectivity": "online",
                        "event_key": event_key,
                        "context_id": context_id,
                        "schema_version": HA_EVENT_SCHEMA_VERSION,
                    }
                    next_observed = _keep_newer(previous, incoming)
                    tx.execute(
                        "INSERT INTO iot_twins (device_id, tenant_ref, desired_json,"
                        " reported_json, observed_json, updated_at)"
                        " VALUES (?, ?, '{}', '{}', ?, ?)"
                        " ON CONFLICT(device_id) DO UPDATE SET"
                        " observed_json=excluded.observed_json, updated_at=excluded.updated_at",
                        (device_id, tenant, json.dumps(next_observed, sort_keys=True), iso()),
                    )
                tx.execute(
                    "UPDATE ha_ingest_state SET connected=1, last_event_at=?,"
                    " last_event_key=?, last_received_at=?, last_error=NULL, updated_at=?"
                    " WHERE tenant_ref=? AND platform_instance_id=?",
                    (observed_at, event_key, received_at, iso(), tenant,
                     platform_instance_id),
                )
                _event(
                    tx, tenant=tenant, event_type="iot.state.changed",
                    aggregate_type="iot_device", aggregate_id=device_id,
                    payload={"entity_id": entity_id, "state": state,
                             "event_key": event_key, "observed_at": observed_at,
                             "schema_version": HA_EVENT_SCHEMA_VERSION},
                )
            return {
                "event_key": event_key,
                "device_id": device_id,
                "entity_id": entity_id,
                "state": state,
                "observed_at": observed_at,
                "received_at": received_at,
                "duplicate": duplicate,
                "schema_version": HA_EVENT_SCHEMA_VERSION,
                "cursor": str(ingested["last_event_key"] or ""),
            }
    finally:
        db.close()


def set_ha_connection(*, tenant: str, platform_instance_id: str, connected: bool,
                      error: str | None = None, reconnected: bool = False) -> None:
    db = connect()
    try:
        with transaction(db) as tx:
            _ha_ingest_row(tx, tenant, platform_instance_id)
            tx.execute(
                "UPDATE ha_ingest_state SET connected=?, last_error=?,"
                " reconnect_count=reconnect_count+?, updated_at=?"
                " WHERE tenant_ref=? AND platform_instance_id=?",
                (1 if connected else 0, error, 1 if reconnected else 0, iso(),
                 tenant, platform_instance_id),
            )
    finally:
        db.close()


def acquire_ha_ingest_owner(*, tenant: str, platform_instance_id: str,
                            owner_ref: str, ttl_seconds: float = 120.0
                            ) -> dict[str, Any]:
    """Single-writer guard with a fencing generation.

    A new owner always receives a higher generation. A stale worker's event
    writes are rejected by ``record_ha_event`` even if it keeps running.
    """

    if not str(owner_ref or "").strip():
        return {"acquired": False, "reason": "owner_required", "generation": 0}
    timestamp = iso()
    expires = iso(now() + timedelta(seconds=max(30.0, ttl_seconds)))
    db = connect()
    try:
        with transaction(db) as tx:
            row = _ha_ingest_row(tx, tenant, platform_instance_id)
            current_owner = str(row["owner_ref"] or "")
            current_until = parse_timestamp(str(row["owner_lease_until"] or "")) \
                if row["owner_lease_until"] else None
            generation = int(row["owner_generation"] or 0)
            if current_owner == owner_ref:
                # Same process renewing: keep the generation stable.
                tx.execute(
                    "UPDATE ha_ingest_state SET owner_lease_until=?, updated_at=?"
                    " WHERE tenant_ref=? AND platform_instance_id=?",
                    (expires, timestamp, tenant, platform_instance_id),
                )
                return {"acquired": True, "renewed": True, "generation": generation,
                        "owner_ref": owner_ref, "expires_at": expires}
            if (current_owner and current_until is not None and current_until > now()):
                return {"acquired": False, "reason": "owned_by_other",
                        "generation": generation, "owner_ref": current_owner,
                        "expires_at": iso(current_until)}
            generation += 1
            tx.execute(
                "UPDATE ha_ingest_state SET owner_ref=?, owner_lease_until=?,"
                " owner_generation=?, updated_at=?"
                " WHERE tenant_ref=? AND platform_instance_id=?",
                (owner_ref, expires, generation, timestamp, tenant, platform_instance_id),
            )
            return {"acquired": True, "renewed": False, "generation": generation,
                    "owner_ref": owner_ref, "expires_at": expires}
    finally:
        db.close()


def renew_ha_ingest_owner(*, tenant: str, platform_instance_id: str,
                          owner_ref: str, generation: int,
                          ttl_seconds: float = 120.0) -> dict[str, Any]:
    """Atomically extend ownership only for the exact fencing generation."""

    expires = iso(now() + timedelta(seconds=max(30.0, ttl_seconds)))
    db = connect()
    try:
        with transaction(db) as tx:
            row = _ha_ingest_row(tx, tenant, platform_instance_id)
            current_owner = str(row["owner_ref"] or "")
            current_generation = int(row["owner_generation"] or 0)
            if current_owner != owner_ref or current_generation != generation:
                return {"renewed": False, "reason": "ownership_lost",
                        "owner_ref": current_owner,
                        "generation": current_generation}
            tx.execute(
                "UPDATE ha_ingest_state SET owner_lease_until=?, updated_at=?"
                " WHERE tenant_ref=? AND platform_instance_id=?",
                (expires, iso(), tenant, platform_instance_id),
            )
            return {"renewed": True, "generation": generation,
                    "owner_ref": owner_ref, "expires_at": expires}
    finally:
        db.close()


def _assert_ha_ingest_owner(tx: sqlite3.Connection, tenant: str,
                            platform_instance_id: str, owner_ref: str,
                            generation: int) -> None:
    row = _ha_ingest_row(tx, tenant, platform_instance_id)
    current_until = parse_timestamp(str(row["owner_lease_until"] or "")) \
        if row["owner_lease_until"] else None
    if (str(row["owner_ref"] or "") != owner_ref
            or int(row["owner_generation"] or 0) != generation
            or current_until is None or current_until <= now()):
        raise conflict("stale_ingest_owner")


def release_ha_ingest_owner(*, tenant: str, platform_instance_id: str,
                            owner_ref: str) -> None:
    db = connect()
    try:
        with transaction(db) as tx:
            tx.execute(
                "UPDATE ha_ingest_state SET owner_ref=NULL, owner_lease_until=NULL,"
                " updated_at=? WHERE tenant_ref=? AND platform_instance_id=?"
                " AND owner_ref=?",
                (iso(), tenant, platform_instance_id, owner_ref),
            )
    finally:
        db.close()


def record_ha_gap(*, tenant: str, platform_instance_id: str, reason: str,
                  reconciled: bool = False, owner_ref: str | None = None,
                  owner_generation: int | None = None) -> dict[str, Any]:
    """Record a durable replication gap and reconcile marker."""

    timestamp = iso()
    db = connect()
    try:
        with transaction(db) as tx:
            _ha_ingest_row(tx, tenant, platform_instance_id)
            if owner_ref is not None and owner_generation is not None:
                _assert_ha_ingest_owner(tx, tenant, platform_instance_id,
                                        owner_ref, owner_generation)
            tx.execute(
                "UPDATE ha_ingest_state SET gap_count=gap_count+1, last_gap_at=?,"
                " last_reconcile_at=COALESCE(?, last_reconcile_at), updated_at=?"
                " WHERE tenant_ref=? AND platform_instance_id=?",
                (timestamp, timestamp if reconciled else None, timestamp, tenant,
                 platform_instance_id),
            )
            _event(
                tx, tenant=tenant, event_type="iot.event.gap",
                aggregate_type="platform_instance", aggregate_id=platform_instance_id,
                payload={"reason": reason, "reconciled": reconciled,
                         "schema_version": HA_EVENT_SCHEMA_VERSION},
            )
    finally:
        db.close()
    return {"platform_instance_id": platform_instance_id, "reason": reason,
            "gap_at": timestamp, "reconciled": reconciled}


def get_ha_ingest_state(tenant: str, platform_instance_id: str) -> dict[str, Any]:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM ha_ingest_state WHERE tenant_ref=? AND platform_instance_id=?",
            (tenant, platform_instance_id),
        ).fetchone()
    finally:
        db.close()
    if row is None:
        return {
            "platform_instance_id": platform_instance_id, "tenant_ref": tenant,
            "connected": False, "last_event_at": None, "last_event_key": None,
            "last_received_at": None, "last_reconcile_at": None, "last_gap_at": None,
            "reconnect_count": 0, "duplicate_count": 0, "gap_count": 0,
            "owner_ref": None, "owner_generation": 0, "owner_lease_until": None,
            "last_error": None,
        }
    data = dict(row)
    data["connected"] = bool(data["connected"])
    return data


def list_ha_events(tenant: str, platform_instance_id: str, *,
                   device_id: str | None = None, limit: int | None = None
                   ) -> list[dict[str, Any]]:
    clauses = ["tenant_ref=?", "platform_instance_id=?"]
    values: list[Any] = [tenant, platform_instance_id]
    if device_id:
        clauses.append("device_id=?")
        values.append(device_id)
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM ha_event_log WHERE " + " AND ".join(clauses)  # nosec B608
            + " ORDER BY observed_at DESC, received_at DESC LIMIT ?",
            (*values, _list_limit(limit)),
        ).fetchall()
    finally:
        db.close()
    result = []
    for row in rows:
        item = dict(row)
        item["attributes"] = _json(item.pop("attributes_json", "{}"), {})
        result.append(item)
    return result


# ---------------------------------------------------------------------------
# Evidence metadata
# ---------------------------------------------------------------------------


def _evidence(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return dict(row)


def create_evidence(
    *,
    tenant: str,
    gateway_id: str,
    endpoint_id: str,
    command_id: str,
    evidence_id: str,
    storage_ref: str,
    evidence_type: str,
    mime_type: str,
    content_sha256: str,
    size_bytes: int,
    captured_at: str,
    redaction_status: str,
    retention_until: str,
    device_id: str | None = None,
    task_ref: str | None = None,
    run_ref: str | None = None,
    correlation_id: str | None = None,
    original_sha256: str | None = None,
    redaction_processor: str | None = None,
    redaction_policy_version: str | None = None,
    redaction_key_id: str | None = None,
    redaction_proof: str | None = None,
    redaction_regions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    db = connect()
    try:
        with transaction(db) as tx:
            command = tx.execute(
                "SELECT * FROM device_commands WHERE command_id=? AND tenant_ref=?",
                (command_id, tenant),
            ).fetchone()
            if command is None:
                raise hidden()
            if command["gateway_id"] != gateway_id or command["endpoint_id"] != endpoint_id:
                raise hidden()
            tx.execute(
                "INSERT INTO device_evidence (evidence_id, tenant_ref, gateway_id, endpoint_id,"
                " device_id, command_id, task_ref, run_ref, correlation_id, evidence_type,"
                " mime_type, content_sha256, size_bytes, captured_at, redaction_status,"
                " original_sha256, redaction_processor, redaction_policy_version,"
                " redaction_key_id, redaction_proof, redaction_regions_json,"
                " retention_until, storage_ref, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_id, tenant, gateway_id, endpoint_id, device_id, command_id,
                    task_ref, run_ref, correlation_id, evidence_type, mime_type,
                    content_sha256, size_bytes, captured_at, redaction_status,
                    original_sha256, redaction_processor, redaction_policy_version,
                    redaction_key_id, redaction_proof,
                    json.dumps(redaction_regions or [], sort_keys=True),
                    retention_until, storage_ref, iso(),
                ),
            )
            _audit(
                tx, tenant=tenant, actor=gateway_id, actor_type="gateway",
                action="evidence.create", resource_type="device_evidence",
                resource_id=evidence_id, outcome="allowed",
                detail={"command_id": command_id, "type": evidence_type, "size": size_bytes},
                correlation_id=correlation_id,
            )
            _event(
                tx, tenant=tenant, event_type="evidence.created",
                aggregate_type="device_command", aggregate_id=command_id,
                payload={"evidence_id": evidence_id, "type": evidence_type,
                         "content_sha256": content_sha256},
                task_ref=task_ref, run_ref=run_ref, correlation_id=correlation_id,
            )
    finally:
        db.close()
    return get_evidence(tenant, evidence_id) or {}


def get_evidence(tenant: str, evidence_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            "SELECT * FROM device_evidence WHERE evidence_id=? AND tenant_ref=?",
            (evidence_id, tenant),
        ).fetchone()
    finally:
        db.close()
    return _evidence(row) if row else None


def list_evidence(tenant: str, command_id: str) -> list[dict[str, Any]]:
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM device_evidence WHERE tenant_ref=? AND command_id=?"
            " AND deleted_at IS NULL ORDER BY created_at",
            (tenant, command_id),
        ).fetchall()
    finally:
        db.close()
    return [_evidence(row) for row in rows]


def mark_evidence_deleted(tenant: str, evidence_id: str, *, actor: str,
                          actor_type: str) -> dict[str, Any] | None:
    db = connect()
    try:
        with transaction(db) as tx:
            row = tx.execute(
                "SELECT * FROM device_evidence WHERE evidence_id=? AND tenant_ref=?"
                " AND deleted_at IS NULL",
                (evidence_id, tenant),
            ).fetchone()
            if row is None:
                return None
            tx.execute(
                "UPDATE device_evidence SET deleted_at=? WHERE evidence_id=?",
                (iso(), evidence_id),
            )
            _audit(
                tx, tenant=tenant, actor=actor, actor_type=actor_type,
                action="evidence.delete", resource_type="device_evidence",
                resource_id=evidence_id, outcome="allowed",
            )
            return _evidence(row)
    finally:
        db.close()


def expired_evidence(limit: int = 100) -> list[dict[str, Any]]:
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM device_evidence WHERE deleted_at IS NULL AND retention_until IS NOT NULL"
            " AND retention_until<=? ORDER BY retention_until LIMIT ?",
            (iso(), limit),
        ).fetchall()
    finally:
        db.close()
    return [_evidence(row) for row in rows]


def record_evidence_access(tenant: str, evidence_id: str, *, actor: str,
                           actor_type: str) -> None:
    db = connect()
    try:
        with transaction(db) as tx:
            _audit(
                tx, tenant=tenant, actor=actor, actor_type=actor_type,
                action="evidence.access", resource_type="device_evidence",
                resource_id=evidence_id, outcome="allowed",
            )
    finally:
        db.close()


def purge_evidence_record(tenant: str, evidence_id: str) -> None:
    db = connect()
    try:
        with transaction(db) as tx:
            tx.execute(
                "UPDATE device_evidence SET deleted_at=? WHERE evidence_id=? AND tenant_ref=?"
                " AND deleted_at IS NULL",
                (iso(), evidence_id, tenant),
            )
            _audit(
                tx, tenant=tenant, actor="system", actor_type="system",
                action="evidence.retention_delete", resource_type="device_evidence",
                resource_id=evidence_id, outcome="allowed",
            )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Events, audit, maintenance
# ---------------------------------------------------------------------------


def list_events(
    tenant: str,
    *,
    after_occurred_at: str | None = None,
    after_event_id: str | None = None,
    limit: int | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    clauses = ["tenant_ref=?"]
    values: list[Any] = [tenant]
    if event_type:
        clauses.append("event_type=?")
        values.append(event_type)
    if after_occurred_at and after_event_id:
        clauses.append("(occurred_at, event_id) > (?, ?)")
        values.extend([after_occurred_at, after_event_id])
    values.append(_list_limit(limit))
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM command_events WHERE " + " AND ".join(clauses)  # nosec B608
            + " ORDER BY occurred_at, event_id LIMIT ?",
            values,
        ).fetchall()
    finally:
        db.close()
    events = []
    for row in rows:
        data = dict(row)
        data["payload"] = _json(data.pop("payload_json", "{}"), {})
        events.append(data)
    return events


def ack_events(tenant: str, event_ids: list[str]) -> int:
    if not event_ids:
        return 0
    placeholders = ",".join("?" for _ in event_ids)
    db = connect()
    try:
        with transaction(db) as tx:
            cursor = tx.execute(
                f"UPDATE command_events SET published_at=COALESCE(published_at, ?)"  # nosec B608
                f" WHERE tenant_ref=? AND event_id IN ({placeholders})",
                (iso(), tenant, *event_ids),
            )
            return cursor.rowcount
    finally:
        db.close()


def list_audit(
    tenant: str, *, resource_id: str | None = None, limit: int | None = None
) -> list[dict[str, Any]]:
    clauses = ["tenant_ref=?"]
    values: list[Any] = [tenant]
    if resource_id:
        clauses.append("resource_id=?")
        values.append(resource_id)
    values.append(_list_limit(limit))
    db = connect()
    try:
        rows = db.execute(
            "SELECT * FROM audit_records WHERE " + " AND ".join(clauses)  # nosec B608
            + " ORDER BY audit_id DESC LIMIT ?",
            values,
        ).fetchall()
    finally:
        db.close()
    records = []
    for row in rows:
        data = dict(row)
        data["detail"] = _json(data.pop("detail_json", "{}"), {})
        records.append(data)
    return records


def maintenance() -> dict[str, int]:
    """Expire stale authorization and work. Safe to run repeatedly."""

    timestamp = iso()
    summary = {"leases_expired": 0, "approvals_expired": 0, "commands_expired": 0,
               "commands_timed_out": 0, "events_pruned": 0}
    db = connect()
    try:
        with transaction(db) as tx:
            expiring = tx.execute(
                "SELECT * FROM device_leases WHERE released_at IS NULL AND expires_at<=?",
                (timestamp,),
            ).fetchall()
            for lease in expiring:
                tx.execute(
                    "UPDATE device_leases SET released_at=?, released_reason='expired'"
                    " WHERE lease_id=?",
                    (timestamp, lease["lease_id"]),
                )
                tx.execute(
                    "UPDATE device_approvals SET status='invalidated', reason='lease_expired'"
                    " WHERE lease_id=? AND status IN ('pending','approved')",
                    (lease["lease_id"],),
                )
                _event(
                    tx, tenant=lease["tenant_ref"], event_type="lease.expired",
                    aggregate_type="device_lease", aggregate_id=lease["lease_id"],
                    payload={"lease_id": lease["lease_id"]}, task_ref=lease["task_ref"],
                    run_ref=lease["run_ref"],
                )
                summary["leases_expired"] += 1

            pending = tx.execute(
                "SELECT * FROM device_approvals WHERE status='pending' AND expires_at<=?",
                (timestamp,),
            ).fetchall()
            for approval in pending:
                tx.execute(
                    "UPDATE device_approvals SET status='expired' WHERE approval_id=?",
                    (approval["approval_id"],),
                )
                _event(
                    tx, tenant=approval["tenant_ref"], event_type="approval.expired",
                    aggregate_type="device_approval", aggregate_id=approval["approval_id"],
                    payload={"approval_id": approval["approval_id"]},
                )
                summary["approvals_expired"] += 1

            queued = tx.execute(
                "SELECT * FROM device_commands WHERE status IN ('created','validated','authorized','queued')"
                " AND deadline<=?",
                (timestamp,),
            ).fetchall()
            for row in queued:
                command = _command(row)
                _advance_tx(
                    tx, command=command, target="expired", reason="deadline_elapsed",
                    actor="system", actor_type="system", event_type="command.expired",
                )
                tx.execute(
                    "UPDATE device_commands SET completed_at=? WHERE command_id=?",
                    (timestamp, command["command_id"]),
                )
                summary["commands_expired"] += 1

            in_flight = tx.execute(
                "SELECT * FROM device_commands WHERE status IN ('dispatched','received','accepted','executing')"
                " AND deadline<=?",
                (timestamp,),
            ).fetchall()
            for row in in_flight:
                command = _command(row)
                _advance_tx(
                    tx, command=command, target="timed_out", reason="deadline_elapsed",
                    actor="system", actor_type="system", event_type="command.timed_out",
                )
                tx.execute(
                    "UPDATE device_commands SET completed_at=? WHERE command_id=?",
                    (timestamp, command["command_id"]),
                )
                summary["commands_timed_out"] += 1

            cutoff = iso(now() - timedelta(seconds=config.event_retention_seconds()))
            cursor = tx.execute(
                "DELETE FROM command_events WHERE published_at IS NOT NULL AND occurred_at<?",
                (cutoff,),
            )
            summary["events_pruned"] = max(0, cursor.rowcount)
    finally:
        db.close()

    stale_gateways = mark_stale_gateways()
    summary["gateways_offline"] = len(stale_gateways)
    return summary
